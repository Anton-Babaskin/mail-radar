"""Actual dnsutils on a loopback DNS fixture; never queries public resolvers."""
import contextlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import shutil
import socket
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch

from mailradar import checks, cli
from mailradar.runner import Result, Runner


def wire_name(name):
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.rstrip(".").split(".")) + b"\0"


class LocalDNS:
    def __enter__(self):
        self.records = {
            ("example.org", 15): (0, [struct.pack("!H", 10) + wire_name("box.example.org")]),
            ("example.org", 16): (0, [b"\x0bv=spf1 -all"]),
            ("box.example.org", 1): (0, [socket.inet_aton("192.0.2.10")]),
            ("box.example.org", 28): (0, [socket.inet_pton(socket.AF_INET6, "2001:db8::10")]),
            ("2.0.0.127.zen.spamhaus.org", 1): (0, [socket.inet_aton("127.0.0.2")]),
            ("test.dbl.spamhaus.org", 1): (0, [socket.inet_aton("127.0.1.2")]),
            ("servfail.example", 1): (2, []),
            ("nodata.example", 1): (0, []),
            ("mixed.example", 1): (0, [socket.inet_aton("127.0.0.2"), socket.inet_aton("127.255.255.254")]),
        }
        self.queries = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(.1)
        self.port = self.sock.getsockname()[1]
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
        return self

    def serve(self):
        while not self.stopped.is_set():
            try:
                packet, peer = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            cursor, labels = 12, []
            while packet[cursor]:
                length = packet[cursor]
                labels.append(packet[cursor + 1:cursor + length + 1].decode("ascii"))
                cursor += length + 1
            cursor += 1
            kind = struct.unpack("!H", packet[cursor:cursor + 2])[0]
            question = packet[12:cursor + 4]
            name = ".".join(labels).lower()
            self.queries.append((name, kind))
            rcode, answers = self.records.get((name, kind), (3, []))
            header = packet[:2] + struct.pack("!HHHHH", 0x8580 | rcode, 1, len(answers), 0, 0)
            records = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 60, len(data)) + data for data in answers)
            self.sock.sendto(header + question + records, peer)

    def __exit__(self, *args):
        self.stopped.set()
        self.thread.join(timeout=2)
        self.sock.close()


class DigOnlyRunner:
    def __init__(self, server):
        self.server = server
        self.real = Runner(network=True)
        self.history = []

    def run(self, argv, timeout=8):
        self.history.append(list(argv))
        if argv[0] == "dig":
            local = [value for value in argv if not value.startswith("@")]
            local += ["@127.0.0.1", "-p", str(self.server.port)]
            return self.real.run(local, timeout)
        if argv == ["postconf", "-h", "myhostname"]:
            return Result(stdout="box.example.org\n")
        if argv == ["postconf", "-h", "mydomain"]:
            return Result(stdout="example.org\n")
        if argv in (["postconf", "-P"], ["postconf", "-M"]):
            return Result(stdout="")
        return Result(127, missing=True, stderr="Host command is stubbed in isolated dig integration")

    def close(self):
        self.real.close()


@unittest.skipUnless(shutil.which("dig"), "dnsutils is required; CI installs it explicitly")
class DigIntegrationTests(unittest.TestCase):
    def test_doctor_network_workflow_uses_real_dig_and_operational_controls(self):
        with LocalDNS() as server, tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc").mkdir()
            (root / "etc/mailinabox.conf").write_text("PRIMARY_HOSTNAME=box.example.org\nPUBLIC_IP=192.0.2.10\n", encoding="utf-8")
            (root / "etc/resolv.conf").write_text("nameserver 127.0.0.1\n", encoding="utf-8")
            args = cli.parser().parse_args(["--doctor", "--network", "--domain", "example.org", "--timezone", "UTC"])
            args.root = str(root)
            runner = DigOnlyRunner(server)
            try:
                report = cli.analyze(args, runner, datetime(2026, 11, 3, tzinfo=timezone.utc), datetime(2026, 11, 4, tzinfo=timezone.utc), [])
            finally:
                runner.close()
            findings = {f["id"]: f for f in report["findings"]}
            for identifier in ("DNS.MX", "DNS.A", "DNS.AAAA", "DNSBL.IP", "DNSBL.DOMAIN", "DNSBL.CONTROL.IP", "DNSBL.CONTROL.DOMAIN"):
                self.assertEqual(findings[identifier]["status"], "OK", findings[identifier])
            self.assertTrue(server.queries)
            self.assertTrue(all("@127.0.0.1" in cmd and "-p" in cmd for cmd in runner.real.history))
            self.assertTrue(all(cmd[0] == "dig" for cmd in runner.real.history))

    def test_real_dig_dns_status_multirecord_errors_and_json_cli(self):
        with LocalDNS() as server:
            runner = DigOnlyRunner(server)
            try:
                for name, expected in (("servfail.example", "SERVFAIL"), ("nodata.example", "NODATA"), ("absent.example", "NXDOMAIN"), ("mixed.example", "NOERROR")):
                    state, answers = checks.parse_dns(runner.run(checks._dig(name, "A")), "A")
                    self.assertEqual(state, expected)
                    if name == "mixed.example":
                        self.assertEqual(len(answers), 2)
                        self.assertEqual(checks.dnsbl_state(state, answers, "ip"), ("UNKNOWN", "mixed_error_response"))
                output = io.StringIO()
                with patch("mailradar.cli.Runner", return_value=runner), patch("mailradar.cli.default_logs", return_value=[]), contextlib.redirect_stdout(output):
                    code = cli.main(["--doctor", "--network", "--domain", "example.org", "--json"])
                self.assertIn(code, (0, 1, 2))
                self.assertEqual(json.loads(output.getvalue())["mode"], "doctor")
            finally:
                runner.close()
