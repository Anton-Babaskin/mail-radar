"""Menu-to-collector contracts for task-focused reports, without real mail services."""
import contextlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from mailradar import cli
from mailradar.runner import Result, permitted
from test_dig_integration import DigOnlyRunner, LocalDNS


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/logs/miab-production-shapes.log"
SINCE = datetime(2026, 11, 3, 10, tzinfo=timezone.utc)
UNTIL = datetime(2026, 11, 3, 11, tzinfo=timezone.utc)


class Fake:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.history = []
    def run(self, argv, timeout=8):
        if not permitted(argv):
            raise AssertionError(argv)
        self.history.append(list(argv))
        return self.responses.get(tuple(argv), Result(127, missing=True, stderr="fixture unavailable"))
    def close(self):
        pass


class TTY(io.StringIO):
    def isatty(self):
        return True


class WorkflowCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "etc").mkdir()
        (self.root / "etc/hostname").write_text("box.example.org\n", encoding="utf-8")
        (self.root / "etc/os-release").write_text('ID=ubuntu\nVERSION_ID="22.04"\n', encoding="utf-8")
        (self.root / "etc/mailinabox.conf").write_text("PRIMARY_HOSTNAME=box.example.org\nPUBLIC_IP=192.0.2.10\n", encoding="utf-8")
        (self.root / "etc/resolv.conf").write_text("nameserver 127.0.0.1\n", encoding="utf-8")

    def args(self, *flags):
        args = cli.parser().parse_args([*flags, "--timezone", "Asia/Dubai"])
        args.root = str(self.root)
        return args

    def analyze(self, args, runner, paths=None):
        return cli.analyze(args, runner, SINCE, UNTIL, paths or [])


class TaskWorkflowTests(WorkflowCase):
    def test_every_menu_choice_has_the_intended_workflow(self):
        expected = {1: "doctor", 2: "incoming", 3: "outgoing", 4: "delay", 5: "mailboxes", 6: "queue", 7: "greylist", 8: "whitelist", 9: "dns", 10: "account", 11: "post-update", 12: "watch", 13: "trace", 14: "headers"}
        for choice, mode in expected.items():
            def answer(prompt):
                if prompt.startswith("Номер"):
                    return str(choice)
                if prompt.startswith("Локальный адрес"):
                    return "office@local.example"
                if prompt.startswith("Message-ID, Queue ID"):
                    return "ABCDE"
                if prompt.startswith("Message-ID:"):
                    return "<one@example.org>"
                return ""
            with self.subTest(choice=choice), patch("builtins.input", side_effect=answer), contextlib.redirect_stdout(io.StringIO()):
                selected = cli.menu(self.args())
                self.assertEqual(selected.mode, mode)

    def test_empty_current_queue_and_nonempty_history_remain_distinct(self):
        runner = Fake({("postqueue", "-j"): Result(stdout="")})
        report = self.analyze(self.args("--queue"), runner, [str(FIXTURE)])
        snapshot = next(f for f in report["findings"] if f["id"] == "QUEUE.SNAPSHOT")
        self.assertEqual(snapshot["details"]["count"], 0)
        self.assertEqual(report["statistics"]["queues"], 2)
        self.assertFalse(any(f["id"] in {"HOST.RUNTIME", "HOST.MIAB_REVISION"} for f in report["findings"]))
        self.assertEqual(report["summary"]["status"], "OK")
        self.assertFalse(any(f["id"].startswith(("SECURITY.", "BACKUP.", "WHITELIST.", "DNS.")) for f in report["findings"]))
        self.assertEqual([cmd for cmd in runner.history if cmd[0] not in {"postqueue"}], [])

    def test_menu_queue_and_direct_cli_use_identical_collectors(self):
        responses = {("postqueue", "-j"): Result(stdout="")}
        reports = []
        for flags in (["--queue"], ["--menu"]):
            runner, output = Fake(responses), TTY()
            with patch("mailradar.cli.Runner", return_value=runner), patch("sys.stdin.isatty", return_value=True), patch("builtins.input", side_effect=["6", "0"]), contextlib.redirect_stdout(output), patch("mailradar.cli.human", side_effect=lambda report, **kw: reports.append(report)):
                cli.main([*flags, "--log", str(FIXTURE), "--since", SINCE.isoformat(), "--until", UNTIL.isoformat(), "--timezone", "Asia/Dubai"])
            self.assertEqual(reports[-1]["mode"], "queue")
            self.assertEqual(reports[-1]["statistics"]["queues"], 2)
            self.assertFalse(any(cmd[0] in {"sshd", "apt-mark", "duplicity", "dig", "openssl"} for cmd in runner.history))
        self.assertEqual(reports[0]["statistics"], reports[1]["statistics"])

    def test_account_reads_quota_without_fetching_mail_or_scanning_logs(self):
        user = "office@local.example"
        runner = Fake({("doveadm", "user", "-u", user): Result(stdout="uid 1000\nhome /home/user-data/mail/mailboxes/local.example/office\n"),
                       ("doveadm", "quota", "get", "-u", user): Result(stdout="Quota name Type Value Limit %\nUser quota STORAGE 1024 2048 50\n")})
        with patch("mailradar.logs.analyze_logs", side_effect=AssertionError("unselected log scan")):
            report = self.analyze(self.args("--account", "--user", user), runner)
        self.assertFalse(report["scope"]["logs_selected"])
        self.assertEqual(report["statistics"], {})
        self.assertTrue(any(f["id"] == "mailstore.quota" for f in report["findings"]))
        self.assertFalse(any("fetch" in cmd for cmd in runner.history))
        self.assertFalse(any(f["id"].startswith(("DNS.", "SECURITY.", "BACKUP.")) for f in report["findings"]))

    def test_outgoing_does_not_lookup_external_recipient_in_local_dovecot(self):
        runner = Fake()
        self.analyze(self.args("--outgoing", "--to", "one@remote.example"), runner, [str(FIXTURE)])
        self.assertFalse(any(cmd[0] == "doveadm" for cmd in runner.history))

    def test_mailbox_target_also_limits_explicit_log_search(self):
        args = self.args("--mailboxes", "--user", "absent@local.example", "--offline", "--log", str(FIXTURE))
        report = self.analyze(args, Fake(), [str(FIXTURE)])
        self.assertEqual(report["filters"]["to"], "absent@local.example")
        self.assertEqual(report["statistics"]["queues"], 0)

    def test_unselected_auto_logs_are_never_discovered_for_dns(self):
        output, runner = io.StringIO(), Fake()
        with patch("mailradar.cli.Runner", return_value=runner), patch("mailradar.cli.default_logs", side_effect=AssertionError("unselected source discovery")), contextlib.redirect_stdout(output):
            cli.main(["--dns", "--domain", "example.org", "--json"])
        report = json.loads(output.getvalue())
        self.assertFalse(report["scope"]["logs_selected"])
        self.assertEqual(report["sources"], [])
        self.assertFalse(any(f["id"].startswith("LOG-") for f in report["findings"]))

    def test_whitelist_explicit_history_is_scoped_to_selected_smtp_client(self):
        path = self.root / "clients.log"
        path.write_text("\n".join("2026-11-03T10:10:00Z box postfix/smtpd[1]: NOQUEUE: reject: RCPT from %s[%s]: 450 4.2.0 Greylisted; from=<sender@partner.example> to=<office@local.example> proto=ESMTP helo=<mx>" % pair
                                  for pair in (("mx.partner.example", "192.0.2.1"), ("mx.other.example", "192.0.2.2"))) + "\n", encoding="utf-8")
        args = self.args("--whitelist", "--client-name", "MX.PARTNER.EXAMPLE", "--client-ip", "192.0.2.1", "--offline", "--log", str(path))
        report = self.analyze(args, Fake(), [str(path)])
        self.assertEqual(report["statistics"]["rejected_before_queue"], 1)
        self.assertEqual({event["client_ip"] for event in report["evidence"]}, {"192.0.2.1"})


@unittest.skipUnless(shutil.which("dig"), "dnsutils required")
class TaskDNSIntegrationTests(WorkflowCase):
    def test_dns_workflow_runs_real_dig_for_target_without_unrelated_audit(self):
        with LocalDNS() as server:
            runner = DigOnlyRunner(server)
            try:
                report = self.analyze(self.args("--dns", "--domain", "example.org", "--network"), runner)
            finally:
                runner.close()
        self.assertFalse(report["scope"]["logs_selected"])
        self.assertEqual(report["targets"]["dns_domain"], "example.org")
        self.assertEqual(report["targets"]["tls_hostname"], "box.example.org")
        self.assertEqual(next(f for f in report["findings"] if f["id"] == "DNS.MX")["status"], "OK")
        self.assertFalse(any(cmd[0] in {"df", "postqueue", "sshd", "apt-mark", "duplicity"} for cmd in runner.history))
        self.assertTrue(server.queries)
