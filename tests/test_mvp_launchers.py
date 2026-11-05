"""Run every menu workflow via source and installed launchers with fake host tools."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/logs/miab-production-shapes.log"
WINDOW = ["--since", "2026-11-03T10:00:00Z", "--until", "2026-11-03T11:00:00Z", "--timezone", "UTC"]
WORKFLOWS = (
    ("doctor", []), ("incoming", []), ("outgoing", []), ("delay", []),
    ("mailboxes", ["--user", "office@local.example"]), ("queue", []), ("greylist", []),
    ("whitelist", []), ("dns", ["--domain", "partner.example"]),
    ("account", ["--user", "office@local.example"]), ("post-update", []),
    ("watch", ["--seconds", "0.01"]), ("trace", ["ABCDE"]),
    ("headers", ["<invoice@partner.example>", "--user", "office@local.example"]),
)
HISTORY = {"doctor", "incoming", "outgoing", "delay", "queue", "greylist", "post-update", "watch", "trace"}
FAKE = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

name, args = Path(sys.argv[0]).name, sys.argv[1:]
with open(os.environ["RADAR_TEST_COMMAND_LOG"], "a") as log:
    log.write(json.dumps([name] + args) + "\n")
if name == "postqueue":
    print(json.dumps(dict(queue_id="ABCDE", queue_name="deferred", arrival_time=1793700300,
                         message_size=100, sender="orders@local.example",
                         recipients=[dict(address="invoice@partner.example", delay_reason="451 Try later")])))
elif name == "postconf":
    config = dict(myhostname="box.local.example", mydomain="local.example",
                  smtpd_relay_restrictions="reject_unauth_destination", queue_directory="/var/spool/postfix")
    print(config.get(args[1], "") if args[:1] == ["-h"] else "")
elif name == "doveadm":
    if "fetch" in args:
        print(json.dumps([dict(mailbox="Trash", uid="42", **{
            "hdr.message-id": "<invoice@partner.example>", "date.received.unixtime": 1793700300,
            "date.received": "2026-11-03T10:05:00Z", "date.saved": "2026-11-03T10:15:00Z",
            "body": "BODY MUST NOT ESCAPE", "hdr.subject": "SUBJECT MUST NOT ESCAPE"})]))
    elif "quota" in args:
        print("Quota name Type Value Limit %\nUser quota STORAGE 50 100 50")
    else:
        print("uid 1000\nhome /home/user-data/mail/mailboxes/local.example/office")
elif name == "systemctl":
    if args[:1] == ["is-active"]:
        print("active")
    elif args[:1] == ["show"]:
        print("LoadState=loaded\nActiveState=active\nSubState=running")
elif name == "df":
    print("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/fixture 100 40 60 40% /")
elif name == "sshd":
    print("port 22\npermitrootlogin no\npasswordauthentication no")
elif name == "duplicity":
    print("duplicity 3.0.5.1")
elif name == "dpkg-query":
    print("3.0.5.1-fixture")
elif name == "doveconf":
    print("yes")
'''


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "Linux launchers required")
class MVPLauncherTests(unittest.TestCase):
    def test_all_fourteen_workflows_through_source_and_staged_install(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            stage, bindir = temp / "stage", temp / "commands"
            bindir.mkdir()
            history = temp / "commands.jsonl"
            commands = {"postqueue", "postconf", "postmap", "doveadm", "systemctl", "df", "sshd",
                        "ss", "fail2ban-client", "apt-mark", "duplicity", "dpkg-query", "doveconf", "ip"}
            for command in commands:
                executable = bindir / command
                executable.write_text(FAKE, encoding="utf-8")
                executable.chmod(0o755)
            env = dict(os.environ, DESTDIR=str(stage), PREFIX="/opt/radar", RADAR_TEST_COMMAND_LOG=str(history),
                       PATH=str(bindir) + os.pathsep + os.environ["PATH"])
            installed = subprocess.run(["bash", str(ROOT / "install.sh")], cwd=temp, env=env,
                                       capture_output=True, text=True, timeout=20)
            self.assertEqual(installed.returncode, 0, installed.stderr)
            for launcher in (ROOT / "mail-radar", stage / "opt/radar/bin/mail-radar"):
                for mode, flags in WORKFLOWS:
                    with self.subTest(launcher=str(launcher), mode=mode):
                        argv = ["bash", str(launcher), "--" + mode, *flags, *WINDOW, "--json"]
                        if mode in HISTORY:
                            argv += ["--log", str(FIXTURE)]
                        run = subprocess.run(argv, cwd=temp, env=env, capture_output=True, text=True, timeout=20)
                        self.assertIn(run.returncode, (0, 1, 2), run.stderr)
                        self.assertNotIn("Traceback", run.stderr)
                        self.assertNotIn("MUST NOT ESCAPE", run.stdout)
                        if mode == "watch":
                            events = [json.loads(line) for line in run.stdout.splitlines()]
                            self.assertEqual(events[-1]["type"], "watch_finished")
                            report = events[-2]["report"]
                        else:
                            report = json.loads(run.stdout)
                        self.assertEqual(report["mode"], mode)
                        self.assertEqual(report["summary"]["exit_code"], run.returncode)
                        if mode == "queue":
                            snapshot = next(f for f in report["findings"] if f["id"] == "QUEUE.SNAPSHOT")
                            self.assertEqual(snapshot["details"]["entries"][0]["queue_id"], "ABCDE")
                        if mode in {"mailboxes", "headers"}:
                            metadata = next(f for f in report["findings"] if f["id"] == "mailstore.metadata")
                            self.assertEqual(metadata["evidence"][0]["mailbox"], "Trash")
                            self.assertEqual(str(metadata["evidence"][0]["uid"]), "42")
                        if mode in {"dns", "account", "mailboxes", "headers", "whitelist"}:
                            self.assertFalse(report["scope"]["logs_selected"])
            actions = [json.loads(line) for line in history.read_text().splitlines()]
            self.assertTrue(any(argv[:2] == ["postqueue", "-j"] for argv in actions))
            self.assertFalse(any("restart" in argv or "reload" in argv or "-e" in argv for argv in actions))
            for argv in actions:
                if argv[0] == "doveadm" and "fetch" in argv:
                    self.assertNotIn("body", argv[5].split())
                    self.assertNotIn("hdr.subject", argv[5].split())
