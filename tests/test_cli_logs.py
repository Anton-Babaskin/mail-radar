"""Offline executable-level contracts, with no mail stack or network access."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import selectors
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / "tests/fixtures/logs/local-seconds.log"
GREY = ROOT / "tests/fixtures/logs/greylist-retry.log"
WINDOW = ["--since", "2026-11-02T09:00:00Z", "--until", "2026-11-02T10:00:00Z", "--timezone", "Asia/Dubai"]


class OfflineCliTests(unittest.TestCase):
    def cli(self, *args, input_text=None):
        return subprocess.run([sys.executable, "-m", "mailradar.cli", *args],
                              cwd=str(ROOT), input=input_text, capture_output=True,
                              text=True, timeout=15)

    def decoded(self, mode, path=LOCAL, *extra):
        result = self.cli(mode, "--offline", "--json", "--log", str(path), *WINDOW, *extra)
        self.assertIn(result.returncode, (0,1), result.stderr)
        self.assertEqual(result.stderr, "")
        report = json.loads(result.stdout)
        self.assertEqual(report["commands"], [])
        self.assertEqual(report["active_probes"], [])
        self.assertEqual(report["schema_version"], "1.0")
        self.assertNotIn("\x1b", result.stdout)
        return report

    def test_diagnose_filter_links_context_without_external_commands(self):
        report = self.decoded("--diagnose", LOCAL, "--from", "noreply@sender.example", "--to", "office@local.example")
        self.assertEqual(report["statistics"]["observed_messages"], 1)
        self.assertEqual(report["traces"][0]["outcome"], "saved")
        self.assertEqual(report["summary"]["status"], "OK")
        self.assertFalse(report["completeness"]["window_coverage_proven"])

    def test_trace_message_id_and_domain_are_literal_typed_keys(self):
        for value in ("<incident.1@sender.example>", "sender.example", "B830110601A4"):
            with self.subTest(value=value):
                result = self.cli("--trace", value, "--offline", "--json", "--log", str(LOCAL), *WINDOW)
                report = json.loads(result.stdout)
                self.assertEqual(report["statistics"]["queues"], 1)
        result = self.cli("--trace", ".*", "--offline", "--json", "--log", str(LOCAL), *WINDOW)
        report = json.loads(result.stdout)
        self.assertEqual(report["statistics"]["queues"], 0)
        self.assertEqual(report["summary"]["status"], "UNKNOWN")

    def test_flow_reports_delivery_events_separately_from_messages(self):
        report = self.decoded("--flow")
        self.assertEqual(report["statistics"]["observed_messages"], 1)
        self.assertEqual(report["statistics"]["recipient_delivery_events"], 1)
        self.assertEqual(report["statistics"]["saved_log_events"], 1)

    def test_greylist_keeps_early_retry_pass_and_changed_ip_distinct(self):
        report = self.decoded("--greylist", GREY)
        findings = {item["id"]: item for item in report["findings"]}
        self.assertEqual(findings["GREYLIST-RETRY-PASS"]["details"]["observed_wait_seconds"], 360)
        self.assertEqual(findings["GREYLIST-OUTCOME"]["status"], "UNKNOWN")
        self.assertIn("GREYLIST-AWL", findings)
        self.assertIn("GREYLIST-CLIENT-WHITELIST", findings)

    def test_numeric_period_and_non_tty_default_are_stable(self):
        result = self.cli("48", "--offline", "--json", "--log", str(LOCAL), "--until", "2026-11-02T10:00:00Z", "--timezone", "Asia/Dubai")
        report = json.loads(result.stdout)
        self.assertEqual(report["mode"], "doctor")
        since = datetime.fromisoformat(report["window"]["since"])
        until = datetime.fromisoformat(report["window"]["until"])
        self.assertEqual((until - since).total_seconds(), 48 * 3600)
        self.assertIn("MAIL-FLOW", [item["id"] for item in report["findings"]])

    def test_bounded_stdin_is_marked_incomplete(self):
        line = LOCAL.read_text(encoding="utf-8").splitlines()[0] + "\n"
        result = self.cli("--flow", "--offline", "--json", "--log", "-", "--max-bytes", "1024", *WINDOW, input_text=line * 100)
        report = json.loads(result.stdout)
        self.assertFalse(report["completeness"]["complete"])
        self.assertIn("sources.incomplete", [item["id"] for item in report["findings"]])

    def test_offline_current_state_modes_do_not_claim_configuration_proven(self):
        for mode in ("--whitelist", "--post-update", "--mailboxes"):
            with self.subTest(mode=mode):
                report = self.decoded(mode)
                self.assertIn("offline.unavailable", [item["id"] for item in report["findings"]])

    def test_offline_network_or_journal_is_cli_error(self):
        for flag in ("--network", "--journal"):
            result = self.cli("--offline", "--log", str(LOCAL), flag)
            self.assertEqual(result.returncode, 2)
            self.assertIn("--offline", result.stderr)


@unittest.skipUnless(os.name == "posix", "Linux watch lifecycle tests")
class OfflineWatchTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.processes = []
        self.addCleanup(self.stop_processes)

    def stop_processes(self):
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def start(self, paths, seconds="1.8", *extra):
        env = dict(os.environ, TMPDIR=str(self.root))
        args = [sys.executable, "-m", "mailradar.cli", "--watch", "--offline", "--json", "--timezone", "UTC", "--seconds", seconds]
        for path in paths:
            args.extend(["--log", str(path)])
        process = subprocess.Popen(args + list(extra), cwd=str(ROOT), env=env,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        self.processes.append(process)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(5):
                self.fail("watch did not announce startup")
        first = json.loads(process.stdout.readline())
        self.assertEqual(first["type"], "watch_started")
        return process, first

    def collect(self, process, first):
        output, errors = process.communicate(timeout=10)
        self.assertEqual(errors, "")
        records = [first] + [json.loads(line) for line in output.splitlines()]
        self.assertEqual(records[-1]["type"], "watch_finished")
        report = next(record["report"] for record in records if record["type"] == "report")
        return records, report

    def stamp(self):
        return datetime.now(timezone.utc).isoformat()

    def test_watch_follows_rotation_truncation_and_emits_valid_ndjson(self):
        path = self.root / "mail.log"
        path.write_text("")
        process, first = self.start([path])
        path.write_text(self.stamp() + " box postfix/qmgr[1]: ABCDE: from=<sender@partner.example>, size=3, nrcpt=1 (queue active)\n")
        time.sleep(.25)
        path.rename(self.root / "mail.log.1")
        path.write_text(self.stamp() + " box postfix/lmtp[2]: ABCDE: to=<office@local.example>, relay=dovecot, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 2.0.0 Saved)\n")
        time.sleep(.35)
        path.write_text(self.stamp() + " box postfix/qmgr[1]: 4F5E6D7C8B: removed\n")
        records, report = self.collect(process, first)
        self.assertEqual(process.returncode, 1)
        self.assertTrue(any(record["type"] == "watch_progress" for record in records))
        reasons = [record["reason"] for record in records if record["type"] == "source_gap"]
        self.assertTrue(any("rotation" in reason for reason in reasons))
        self.assertTrue(any("truncation" in reason for reason in reasons))
        self.assertFalse(report["completeness"]["complete"])
        self.assertEqual(report["statistics"]["outcomes"].get("saved"), 1)
        self.assertFalse(list(self.root.glob("mail-radar-*")), "watch scratch directories leaked")

    def test_watch_keeps_partial_lines_separate_per_source_and_filters(self):
        one, two = self.root / "one.log", self.root / "two.log"
        one.write_text("")
        two.write_text("")
        process, first = self.start([one, two], "1.0", "--from", "sender@partner.example")
        line = self.stamp() + " box postfix/qmgr[1]: ABCDE: from=<sender@partner.example>, size=3, nrcpt=1 (queue active)\n"
        one.write_text(line[:len(line)//2])
        two.write_text(self.stamp() + " box postfix/qmgr[1]: 4F5E6D7C8B: from=<other@partner.example>, size=3, nrcpt=1 (queue active)\n")
        time.sleep(.2)
        with one.open("a") as stream:
            stream.write(line[len(line)//2:])
        _, report = self.collect(process, first)
        self.assertEqual(report["statistics"]["queues"], 1)
        self.assertEqual(report["traces"][0]["queue_id"], "ABCDE")
        self.assertEqual(report["completeness"]["unparsed_lines"], 0)

    def test_watch_signal_is_explicit_and_cleans_own_scratch(self):
        path = self.root / "mail.log"
        path.write_text("")
        process, first = self.start([path], "10")
        process.send_signal(signal.SIGTERM)
        _, report = self.collect(process, first)
        self.assertEqual(process.returncode, 130)
        self.assertTrue(report["watch"]["interrupted"])
        self.assertEqual(report["watch"]["reason"], "signal")
        self.assertFalse(report["completeness"]["complete"])
        self.assertFalse(list(self.root.glob("mail-radar-*")))


if __name__ == "__main__":
    unittest.main()
