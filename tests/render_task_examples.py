"""Regenerate anonymized previews through real collectors/renderer, using fake host commands.

Run from the checkout: python3 tests/render_task_examples.py
No public network or mail service is contacted.
"""
import contextlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mailradar import cli  # noqa: E402
from mailradar.display import human  # noqa: E402
from mailradar.runner import Result  # noqa: E402
from test_task_workflows import WorkflowCase, Fake, SINCE, UNTIL, FIXTURE  # noqa: E402
from test_dig_integration import DigOnlyRunner, LocalDNS  # noqa: E402


def main():
    if not shutil.which("dig"):
        raise SystemExit("Install dnsutils to regenerate the loopback DNS preview")
    case = WorkflowCase()
    case.setUp()
    try:
        history = case.root / "history.log"
        lines = []
        for index in range(16):
            qid = "%05X" % (0xABCDE + index)
            lines += ["2026-11-03T10:10:%02dZ box postfix/qmgr[1]: %s: from=<sender@partner.example>, size=4096, nrcpt=1 (queue active)" % (index, qid),
                      "2026-11-03T10:11:%02dZ box postfix/lmtp[2]: %s: to=<office@local.example>, relay=dovecot, delay=2, delays=0.5/0.1/0.1/1.3, dsn=2.0.0, status=sent (250 2.0.0 Saved)" % (index, qid)]
        history.write_text("\n".join(lines) + "\n", encoding="utf-8")

        def write(name, args, responses, paths=None):
            report = cli.analyze(args, Fake(responses), SINCE, UNTIL, paths or [])
            report = cli.source_labels(report, {str(history): "example mail.log", str(FIXTURE): "tests/fixtures/logs/miab-production-shapes.log"})
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                human(report)
            (ROOT / "examples" / name).write_text("Обезличенный пример: системные команды подменены тестовыми ответами.\n" + output.getvalue(), encoding="utf-8")

        now = datetime.now(timezone.utc).timestamp()
        rows = [dict(queue_id="A1B2C3D4E5", queue_name="deferred", arrival_time=now-7200, message_size=8192,
                     sender="orders@local.example", recipients=[dict(address="billing@partner.example", delay_reason="451 4.4.3 MX lookup: SERVFAIL")]),
                dict(queue_id="F1E2D3C4B5", queue_name="hold", arrival_time=now-1800, message_size=4096,
                     sender="", recipients=[dict(address="office@local.example", delay_reason="Held for operator review")])]
        write("queue-now.txt", case.args("--queue"), {("postqueue", "-j"): Result(stdout="\n".join(json.dumps(row) for row in rows))}, [str(history)])
        write("queue-empty-history.txt", case.args("--queue"), {("postqueue", "-j"): Result()}, [str(history)])
        write("miab-output.txt", case.args("--flow", "--offline", "--log", str(FIXTURE)), {}, [str(FIXTURE)])
        # The existing example belongs to a different, explicit historical window.
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cli.main(["--trace", "sender.example", "--offline", "--log", "examples/mail.log", "--since", "2026-11-02T09:00:00Z", "--until", "2026-11-02T10:00:00Z", "--timezone", "UTC"])
        (ROOT / "examples/output.txt").write_text(output.getvalue(), encoding="utf-8")

        user = "office@local.example"
        row = {"mailbox": "Trash", "uid": 42, "guid": "fixture-message", "date.received": "2026-11-03T10:05:00+00:00", "date.saved": "2026-11-03T10:15:00+00:00", "date.received.unixtime": SINCE.timestamp()+300,
               "hdr.message-id": "<invoice.42@partner.example>", "flags": ["\\Seen"], "hdr.date": "Tue, 3 Nov 2026 10:04:00 +0000", "hdr.received": "from mx.partner.example; Tue, 3 Nov 2026 10:05:00 +0000"}
        args = case.args("--mailboxes", "--user", user)
        class StoreFake(Fake):
            def run(self, argv, timeout=8):
                if argv[:4] == ["doveadm", "-f", "json", "fetch"]:
                    self.history.append(argv)
                    return Result(stdout=json.dumps([row]))
                return super().run(argv, timeout)
        responses = {("doveadm", "user", "-u", user): Result(stdout="uid 1000\nhome /home/user-data/mail/mailboxes/local.example/office\n"),
                     ("doveadm", "quota", "get", "-u", user): Result(stdout="Quota name Type Value Limit %\nUser quota STORAGE 1024 2048 50\nUser quota MESSAGE 12 1000 1\n")}
        report = cli.analyze(args, StoreFake(responses), SINCE, UNTIL, [])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            human(report)
        (ROOT / "examples/mailbox-folders.txt").write_text("Обезличенный пример: Dovecot-команды подменены тестовыми ответами.\n" + output.getvalue(), encoding="utf-8")
        with LocalDNS() as server:
            runner = DigOnlyRunner(server)
            try:
                report = cli.analyze(case.args("--dns", "--domain", "example.org", "--network"), runner, SINCE, UNTIL, [])
            finally:
                runner.close()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            human(report)
        (ROOT / "examples/dns-target.txt").write_text("Обезличенный пример: dig использует только loopback DNS; остальные команды подменены.\n" + output.getvalue(), encoding="utf-8")
    finally:
        case.doCleanups()


if __name__ == "__main__":
    main()
