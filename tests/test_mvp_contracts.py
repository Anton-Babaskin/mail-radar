"""MVP failure boundaries and supported-input contracts."""
import contextlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tempfile
import tracemalloc
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mailradar import checks, cli
from mailradar.logs import _recent_lines, analyze_logs
from mailradar.mailstore import collect_mailstore
from mailradar.model import finding
from mailradar.runner import Result
from mailradar.timeutil import timestamp
from test_checks import FakeRunner


SINCE = datetime(2026, 11, 3, 10, tzinfo=timezone.utc)
UNTIL = datetime(2026, 11, 3, 11, tzinfo=timezone.utc)


class MVPContractTests(unittest.TestCase):
    def test_invalid_requests_fail_before_runner_or_stdin_reads(self):
        cases = (["--mailboxes"], ["--account"], ["--trace", ""], ["--headers", "", "--user", "a@example.org"],
                 ["--watch", "--log", "-"], ["--watch", "--journal"], ["--watch", "--log", "archive.lzma"],
                 ["--mailboxes", "--user", "a@example.org", "--from", "other@example.org"],
                 ["--account", "--user", "a@example.org", "--to", "b@example.org"],
                 ["--dns", "--from", "a@example.org"], ["--dns", "--to", "a@example.org"],
                 ["--whitelist", "--ip", "192.0.2.1"], ["--trace", "ABCDE", "--client-name", "mx.example.org"],
                 ["--queue", "--peer", "192.0.2.1"],
                 ["--flow", "--until", "0001-01-01T00:00:00Z"],
                 ["--flow", "--until", "9999-12-31T23:59:59-23:59"],
                 ["--doctor", "--user", "a@example.org", "--deep"])
        for flags in cases:
            with self.subTest(flags=flags), patch("mailradar.cli.Runner") as runner, patch("mailradar.cli.sys.stdin") as stdin, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    cli.main(flags)
                self.assertEqual(error.exception.code, 2)
                runner.assert_not_called()
                stdin.buffer.read.assert_not_called()

    def test_oversized_watch_finishes_ndjson_with_explicit_incompleteness(self):
        report = dict(findings=[finding("large", "OK", "large", rows=["x" * 4000] * 2500)],
                      completeness=dict(complete=True), sources=[], scope=dict(logs_selected=True), workflow="Наблюдение")
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mail.log"
            path.write_text("", encoding="utf-8")
            with patch("mailradar.cli.analyze", return_value=report), contextlib.redirect_stdout(output):
                code = cli.main(["--watch", "--log", str(path), "--seconds", "0.01", "--json"])
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(code, 1)
        self.assertEqual(events[-1]["type"], "watch_finished")
        final = events[-2]["report"]
        self.assertFalse(final["completeness"]["complete"])
        self.assertIn("8 MiB", final["completeness"]["limitations"][0])
        self.assertEqual(final["scope"], dict(logs_selected=True))
        self.assertEqual(events[-1]["bytes_observed"], 0)

    def test_invalid_offsets_do_not_silently_shift_the_requested_window(self):
        for offset in ("+0060", "+12:99", "-00:60", "+24:00", "+00:00:60", "+000060"):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                timestamp("2026-11-03T10:00:00" + offset, timezone.utc)
        self.assertEqual(timestamp("2026-11-03T14:00:00+0400", timezone.utc), SINCE)

    def test_expired_only_log_keeps_sender_for_typed_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mail.log"
            path.write_text("2026-11-03T10:30:00Z box postfix/qmgr[1]: ABCDE: from=<sender@partner.example>, status=expired, returned to sender\n", encoding="utf-8")
            report = analyze_logs([str(path)], SINCE, UNTIL, filters={"from": "sender@partner.example"})
        self.assertEqual(report["statistics"]["expired"], 1)
        self.assertEqual(report["traces"][0]["senders"], ["sender@partner.example"])

    def test_recent_line_cap_does_not_allocate_all_old_lines(self):
        raw = b"abcdefg\n" * 250000
        with tempfile.TemporaryFile() as stream:
            stream.write(raw)
            tracemalloc.start()
            try:
                lines, omitted = _recent_lines(stream, len(raw), 2)
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
        self.assertTrue(omitted)
        self.assertEqual(lines, [(-1, b"abcdefg\n"), (-2, b"abcdefg\n")])
        self.assertLess(peak, 8 * 1024 * 1024)

    def test_recursive_command_json_becomes_unknown_instead_of_traceback(self):
        nested = "[" * 2000 + "0" + "]" * 2000
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(root=directory, mode="queue", user="a@example.org", to=None, headers=None, trace=None, deep=False)
            ctx = checks.Context(FakeRunner({("postqueue", "-j"): Result(stdout=nested)}), args)
            checks.queue_checks(ctx)
            self.assertEqual(ctx.findings[0]["status"], "UNKNOWN")
            class Store:
                def run(self, argv, timeout=8):
                    return Result(stdout=nested if "fetch" in argv else "uid 1000\n")
            results = collect_mailstore(Store(), args, SINCE, UNTIL)
            self.assertEqual(next(f for f in results if f["id"] == "mailstore.metadata")["status"], "UNKNOWN")

    def test_mailbox_explicit_log_retains_delivery_conclusions(self):
        path = Path(__file__).parent / "fixtures/logs/miab-production-shapes.log"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cli.main(["--mailboxes", "--user", "office@local.example", "--offline", "--log", str(path),
                      "--since", SINCE.isoformat(), "--until", UNTIL.isoformat(), "--timezone", "Asia/Dubai", "--json"])
        report = json.loads(output.getvalue())
        self.assertTrue(any(item["outcome"] == "saved" for item in report["conclusions"]))

    def test_structured_values_in_scalar_metadata_stay_unknown(self):
        args = SimpleNamespace(user="a@example.org", to=None, mode="mailboxes", headers=None, trace=None, deep=False)
        for row in ({"uid": {"untrusted": "nested"}}, {"hdr.date": ["unexpected"]}, {"mailbox": True}):
            class Store:
                def run(self, argv, timeout=8):
                    return Result(stdout=json.dumps([row]) if "fetch" in argv else "uid 1000\n")
            with self.subTest(row=row):
                result = next(f for f in collect_mailstore(Store(), args, SINCE, UNTIL) if f["id"] == "mailstore.metadata")
                self.assertEqual(result["status"], "UNKNOWN")
                self.assertEqual(result["evidence"], [])

    def test_sensitive_index_and_symlink_cycle_never_trigger_postmap(self):
        for cycle in (False, True):
            with self.subTest(cycle=cycle), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory) / "etc/postfix"
                folder.mkdir(parents=True)
                source = folder / "clients"
                if cycle:
                    source.symlink_to(source.name)
                else:
                    source.write_text("partner.example OK\n", encoding="utf-8")
                    (folder / "sasl_passwd.db").write_text("PRIVATE FIXTURE", encoding="utf-8")
                    (folder / "clients.db").symlink_to("sasl_passwd.db")
                runner = FakeRunner()
                args = SimpleNamespace(root=directory, client_name="mx.partner.example", client_ip=None)
                ctx = checks.Context(runner, args)
                checks.whitelist_checks(ctx, {"global": {"smtpd_client_restrictions": "check_client_access hash:/etc/postfix/clients"}})
                self.assertFalse(any(cmd[0] == "postmap" for cmd in runner.history))
                self.assertTrue(any(f["id"] == "WHITELIST.MAP" and f["status"] == "UNKNOWN" for f in ctx.findings))
