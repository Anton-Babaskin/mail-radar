"""Contracts and failure boundaries, using fixtures and fake command processes."""
import contextlib
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from mailradar import cli
from mailradar.mailstore import collect_mailstore, header_delays
from mailradar.model import finding, finish_report, redact_report, write_private
from mailradar.runner import Result, Runner, permitted


class RunnerTests(unittest.TestCase):
    def test_action_allowlist_and_mutating_actions(self):
        for argv in (["postmap", "-q", "example.org", "hash:/etc/postfix/client_whitelist"], ["postqueue", "-j"], ["apt-mark", "showhold"], ["duplicity", "--version"]):
            self.assertTrue(permitted(argv), argv)
        for argv in (["mailinabox", "--version"], ["mailinabox", "--help"], ["setup/start.sh"], ["postmap", "/etc/postfix/client_whitelist"], ["postqueue", "-f"], ["postsuper", "-d", "ALL"], ["systemctl", "restart", "postfix"], ["apt-mark", "unhold", "duplicity"], ["doveadm", "expunge", "-u", "a@example.org", "ALL"], ["openssl", "s_client", "-connect", "host:25", "-keylogfile", "/tmp/leak"], ["postconf", "-h", "smtp_sasl_password_maps"]):
            self.assertFalse(permitted(argv), argv)
        with self.assertRaises(ValueError):
            Runner().run(["mailinabox", "--version"])
        with self.assertRaises(ValueError):
            Runner().run(["dig", "example.org", "MX"])
        with self.assertRaises(ValueError):
            Runner(offline=True).run(["postqueue", "-j"])

    @unittest.skipUnless(os.name == "posix", "POSIX process-group behavior")
    def test_timeout_kills_pipe_holding_descendant(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = str(Path(tmp)/"child-pid")
            code = "import subprocess,time; p=subprocess.Popen(['sleep','60']); open(%r,'w').write(str(p.pid)); time.sleep(60)" % marker
            runner = Runner()
            result = runner._execute([sys.executable, "-c", code], .3)
            self.assertTrue(result.timed_out)
            pid = int(Path(marker).read_text())
            # A short-lived zombie is already dead; it cannot continue the action.
            status = Path("/proc/%d/status" % pid)
            if status.exists():
                self.assertIn("Z (zombie)", status.read_text())
            self.assertFalse(runner.processes)

    def test_output_limit_is_explicit(self):
        result = Runner(max_output=4096)._execute([sys.executable, "-c", "import sys;sys.stdout.write('x'*1000000)"], 3)
        self.assertTrue(result.truncated)
        self.assertLessEqual(len(result.stdout), 4096)
        self.assertFalse(result.ok)

    @unittest.skipUnless(os.name == "posix", "POSIX fake executable")
    def test_path_override_is_observed_and_wrapper_not_invoked(self):
        with tempfile.TemporaryDirectory() as tmp:
            command = Path(tmp)/"postqueue"
            command.write_text("#!/bin/sh\nprintf 'fakequeue\\n'\n", encoding="utf-8")
            command.chmod(0o700)
            marker = Path(tmp)/"wrapper-ran"
            wrapper = Path(tmp)/"mailinabox"
            wrapper.write_text("#!/bin/sh\ntouch '"+str(marker)+"'\n", encoding="utf-8")
            wrapper.chmod(0o700)
            with patch.dict(os.environ, PATH=tmp+os.pathsep+os.environ["PATH"]):
                self.assertEqual(Runner().run(["postqueue", "-j"]).stdout, "fakequeue\n")
                with self.assertRaises(ValueError):
                    Runner().run(["mailinabox", "--help"])
            self.assertFalse(marker.exists())


class ReportTests(unittest.TestCase):
    def test_unknown_is_not_clean_and_json_has_no_terminal_controls(self):
        report = finish_report(dict(findings=[finding("test.id", "UNKNOWN", "\x1b[31mno data\x1b[0m\r")], completeness=dict(complete=False)))
        self.assertEqual(report["summary"]["exit_code"], 1)
        self.assertEqual(report["summary"]["status"], "UNKNOWN")
        self.assertNotIn("\x1b", json.dumps(report))
        from mailradar.model import clean
        self.assertNotIn(chr(155), clean(chr(155)+"2J"))

    def test_report_size_is_bounded_even_for_nested_details(self):
        report = finish_report(dict(findings=[finding("large.id", "OK", "large", items=["x"*4000]*3000)], completeness=dict(complete=True)))
        self.assertLess(len(json.dumps(report).encode()), 8*1024*1024)
        self.assertFalse(report["completeness"]["complete"])
        self.assertEqual(report["summary"]["status"], "UNKNOWN")

    def test_private_report_refuses_existing_file_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"report.json"
            write_private(path, "{}")
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_private(path, "overwrite")
            self.assertEqual(path.read_text(), "{}")
            if os.name == "posix":
                link = Path(tmp)/"link"
                link.symlink_to(path)
                with self.assertRaises(FileExistsError):
                    write_private(link, "overwrite")
                self.assertEqual(path.read_text(), "{}")

    def test_redaction_keeps_ids_and_cross_field_equality(self):
        report = {"findings": [{"id": "LOG.SOURCES", "status": "UNKNOWN", "title": "a@private.test from 198.51.100.1", "evidence": ["a@private.test from 198.51.100.1"]}]}
        result = redact_report(report)
        self.assertEqual(result["findings"][0]["id"], "LOG.SOURCES")
        self.assertEqual(result["findings"][0]["title"], result["findings"][0]["evidence"][0])
        self.assertNotIn("private.test", json.dumps(result))
        self.assertNotIn("198.51.100.1", json.dumps(result))
        data = redact_report({"statistics": {"top_authenticated_senders": {"a@private.test": 1}, "top_recipient_domains": {"private.test": 2}, "top_auth_failure_ips": {"198.51.100.1": 3}}, "evidence": [{"hdr.message-id": "<one@private.test>", "date.saved": "today"}]})
        self.assertNotIn("private.test", json.dumps(data))
        self.assertNotIn("198.51.100.1", json.dumps(data))
        self.assertIn("hdr.message-id", data["evidence"][0])


class StoreTests(unittest.TestCase):
    def test_empty_directory_tree_respects_deep_budget(self):
        from mailradar.mailstore import physical_usage
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)/"home/user-data/mail/mailboxes/example.org/a"
            for i in range(5):
                (base/str(i)).mkdir(parents=True)
            result = physical_usage(tmp, "a@example.org", max_dirs=2)
            self.assertEqual(result["status"], "UNKNOWN")
            self.assertFalse(result["evidence"][0]["complete"])

    def test_metadata_only_trash_and_untrusted_header_interval(self):
        from argparse import Namespace
        record = {"mailbox": "Trash", "hdr.message-id":"<one@example.org>", "date.received.unixtime":1793611534, "date.received": "2026-11-02 13:25:34", "date.saved": "2026-11-02 13:26:00", "hdr.date": "Mon, 2 Nov 2026 12:19:20 +0300", "hdr.received": "from edge.example by filter.example; Mon, 2 Nov 2026 14:25:32 +0500"}
        class Fake:
            def __init__(self):
                self.calls = []
            def run(self, argv, timeout=8):
                self.calls.append(argv)
                self_outer.assertTrue(permitted(argv), argv)
                if "fetch" in argv:
                    return Result(stdout=json.dumps([record]))
                if "quota" in argv:
                    return Result(stdout="user STORAGE 10 100 10\n")
                return Result(stdout="uid 1000\npassword should-not-leak\nhome /home/example\n")
        self_outer, fake = self, Fake()
        args = Namespace(user="a@example.org", to=None, headers="<one@example.org>", trace=None, deep=False)
        findings = collect_mailstore(fake, args, datetime(2026,11,2,tzinfo=timezone.utc), datetime(2026,11,3,tzinfo=timezone.utc))
        text = json.dumps(findings)
        self.assertIn("Trash", text)
        self.assertNotIn("should-not-leak", text)
        fetch = next(call for call in fake.calls if "fetch" in call)
        self.assertNotIn("body", fetch[6])
        self.assertNotIn("hdr.subject", fetch[6])
        self.assertEqual(header_delays(record)["date_to_earliest_received_seconds"], 372)


class CLITests(unittest.TestCase):
    def test_offline_never_invokes_runner_and_old_numeric_cli(self):
        fixture = Path(__file__).parent/"fixtures/logs/local-seconds.log"
        output = io.StringIO()
        with patch.object(Runner, "run", side_effect=AssertionError("offline command")), contextlib.redirect_stdout(output):
            code = cli.main(["48", "--offline", "--log", str(fixture), "--since", "2026-11-02T09:00:00Z", "--until", "2026-11-02T10:00:00Z", "--json"])
        report = json.loads(output.getvalue())
        self.assertIn(code, (0,1,2))
        self.assertEqual(report["schema_version"], "1.0")
        self.assertEqual(report["commands"], [])

    def test_human_leads_with_delivery_stage_delay_and_evidence(self):
        fixture = Path(__file__).parent/"fixtures/logs/local-seconds.log"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cli.main(["--diagnose", "--offline", "--log", str(fixture), "--since", "2026-11-02T09:00:00Z", "--until", "2026-11-02T10:00:00Z"])
        text = output.getvalue()
        self.assertIn("подтверждено сохранение", text)
        self.assertIn('Postfix delay=2.9 с', text)
        self.assertNotIn('"delay":',text)
        self.assertLess(text.index("подтверждено сохранение"),text.index("Источники:"))

    def test_unsafe_user_and_mutually_incompatible_flags_are_cli_errors(self):
        for argv in (["--diagnose", "--from", "a@example.org;touch /tmp/x"], ["--offline", "--network", "--log", "fixture"], ["--headers", "<one@example.org>"], ["--hours", "nan"], ["--mailboxes", "--user", "*@example.org"], ["--diagnose", "--to", "?@example.org"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                cli.main(argv)
            self.assertEqual(result.exception.code, 2)

    def test_ambiguous_local_time_requires_explicit_offset(self):
        from zoneinfo import ZoneInfo
        with self.assertRaises(ValueError):
            cli.timestamp("2026-11-01T01:30:00", ZoneInfo("America/New_York"))


if __name__ == "__main__":
    unittest.main()
