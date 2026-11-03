"""Executable regressions for the operational report and version follow-up."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from mailradar import __version__, cli
from mailradar.display import human
from mailradar.runner import Result


ROOT = Path(__file__).resolve().parents[1]
WINDOW = ["--since", "2026-11-02T09:00:00Z", "--until", "2026-11-02T10:00:00Z", "--timezone", "UTC"]


class RuntimeCliTests(unittest.TestCase):
    def execute(self, text, *flags):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mail.log"
            path.write_text(text, encoding="utf-8")
            return subprocess.run([sys.executable, "-m", "mailradar.cli", "--offline", "--log", str(path), *WINDOW, *flags],
                                  capture_output=True, text=True, timeout=15, cwd=ROOT)

    def test_accepted_only_is_unknown_in_summary_and_exit_status(self):
        run = self.execute("2026-11-02T09:20:00Z box postfix/qmgr[1]: ABCDE: from=<sender@partner.example>, size=3, nrcpt=1 (queue active)\n", "--diagnose", "--json")
        report = json.loads(run.stdout)
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertEqual(report["summary"]["status"], "UNKNOWN")
        self.assertEqual(report["summary"]["conclusion_counts"]["UNKNOWN"], 1)
        self.assertTrue(report["completeness"]["log_sources_complete"])
        self.assertFalse(report["completeness"]["checks_complete"])

    def test_expiry_is_a_failure_in_json_and_exit_status(self):
        run = self.execute("2026-11-02T09:20:00Z box postfix/qmgr[1]: ABCDE: from=<sender@partner.example>, status=expired, returned to sender\n2026-11-02T09:20:01Z box postfix/qmgr[1]: ABCDE: removed\n", "--trace", "ABCDE", "--json")
        report = json.loads(run.stdout)
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertEqual(report["summary"]["status"], "FAIL")
        self.assertEqual(len(report["conclusions"]), 1)
        self.assertEqual(report["conclusions"][0]["outcome"], "expired")

    def test_late_failure_is_aggregated_and_visible_in_human_output(self):
        lines = ["2026-11-02T09:20:00Z box postfix/smtp[1]: %05X: to=<user@remote.example>, relay=mx[192.0.2.5]:25, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 accepted)\n" % (65536 + i) for i in range(20)]
        lines.append("2026-11-02T09:21:00Z box postfix/smtp[1]: ABCDE: to=<lost@remote.example>, relay=mx[192.0.2.5]:25, delay=1, delays=0/0/0/1, dsn=5.1.1, status=bounced (550 No such user)\n")
        run = self.execute("".join(lines), "--diagnose", "--json")
        report = json.loads(run.stdout)
        self.assertEqual(len(report["conclusions"]), 21)
        self.assertEqual(run.returncode, 2)
        self.assertEqual(report["summary"]["conclusion_counts"]["FAIL"], 1)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            human(report)
        self.assertIn("ABCDE", output.getvalue())
        self.assertIn("[FAIL]", output.getvalue())
        self.assertIn("Ещё выводов: 13", output.getvalue())

    def test_standalone_saved_is_visible_without_inventing_queue_or_double_count(self):
        run = self.execute("Nov 02 09:25:36 lmtp(office@local.example)<123><session>: Info: msgid=<one@partner.example>: saved mail to INBOX\n", "--diagnose", "--json")
        report = json.loads(run.stdout)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["statistics"]["queues"], 0)
        self.assertEqual(report["statistics"]["delivery_attempts"], 0)
        self.assertEqual(len(report["conclusions"]), 1)
        self.assertEqual(report["conclusions"][0]["outcome"], "saved")
        self.assertTrue(report["completeness"]["log_sources_complete"])
        self.assertTrue(report["completeness"]["checks_complete"])
        self.assertNotIn("trace_id", report["conclusions"][0])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            human(report)
        self.assertIn("Saved: транспорт 0; журнал Dovecot 1", output.getvalue())
        self.assertIn("подтверждено сохранение", output.getvalue())

    def test_stdin_cut_at_full_line_marks_source_truncation(self):
        line = "2026-11-02T09:20:00Z box postfix/qmgr[1]: ABCDE: removed\n"
        line = line.replace(" box ", " box" + " " * (65 - len(line)))
        self.assertEqual(len(line), 64)
        run = subprocess.run([sys.executable, "-m", "mailradar.cli", "--flow", "--offline", "--log", "-", "--max-bytes", "1024", "--json", *WINDOW],
                             cwd=ROOT, input=line * 17, capture_output=True, text=True, timeout=15)
        report = json.loads(run.stdout)
        self.assertEqual(report["completeness"]["unparsed_lines"], 0)
        self.assertFalse(report["completeness"]["log_sources_complete"])
        self.assertFalse(report["completeness"]["checks_complete"])
        self.assertTrue(report["completeness"]["truncated"])

    def test_truncated_journal_marks_source_incomplete_even_with_valid_rows(self):
        class JournalFake:
            history = []
            def run(self, argv, timeout=8):
                self.history.append(argv)
                return Result(stdout="2026-11-02T09:20:00Z box postfix/qmgr[1]: ABCDE: removed\n", truncated=True)
            def close(self):
                pass
        output = io.StringIO()
        with patch("mailradar.cli.Runner", return_value=JournalFake()), patch("mailradar.cli.default_logs", return_value=[]), contextlib.redirect_stdout(output):
            code = cli.main(["--flow", "--journal", "--json", *WINDOW])
        report = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertFalse(report["completeness"]["log_sources_complete"])
        self.assertTrue(report["completeness"]["truncated"])
        evidence = next(f for f in report["findings"] if f["id"] == "sources.incomplete")["evidence"]
        self.assertTrue(evidence[0]["journal_truncated"])

    def test_help_identifies_running_version_before_any_diagnostics(self):
        run = subprocess.run([sys.executable, "-m", "mailradar.cli", "--help"], cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0)
        self.assertIn("MailRadar " + __version__, run.stdout)
