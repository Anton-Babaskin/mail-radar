"""The action-aware boundary for all external diagnostic commands."""
import os
import re
import signal
import subprocess
import threading
import time
from dataclasses import dataclass


@dataclass
class Result:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    truncated: bool = False
    timed_out: bool = False
    missing: bool = False

    @property
    def ok(self):
        return self.returncode == 0 and not (self.truncated or self.timed_out or self.missing)


PARAMS = frozenset("myhostname mydomain mydestination inet_interfaces inet_protocols relayhost smtpd_recipient_restrictions smtpd_relay_restrictions smtpd_client_restrictions smtpd_sender_restrictions parent_domain_matches_subdomains smtpd_tls_cert_file smtpd_tls_chain_files smtpd_tls_security_level smtp_tls_security_level smtpd_sasl_auth_enable transport_maps virtual_alias_maps virtual_mailbox_maps mailbox_transport local_transport content_filter multi_instance_directories smtpd_milters non_smtpd_milters smtpd_restriction_classes smtpd_delay_reject smtpd_tls_auth_only smtpd_sasl_local_domain smtpd_access_maps smtpd_sender_login_maps".split())
PARAMS = PARAMS | {"queue_directory"}
PARAMS = PARAMS | {"smtpd_helo_restrictions", "smtpd_data_restrictions", "smtpd_end_of_data_restrictions",
                   "postscreen_dnsbl_sites", "postscreen_dnsbl_threshold", "postscreen_dnsbl_action", "postscreen_dnsbl_allowlist_threshold"}


def valid_user(value):
    return bool(re.fullmatch(r"[A-Za-z0-9.!#$%&'+=^_`{|}~-]+@[A-Za-z0-9.-]+", value)) and not value.startswith("-") and len(value) < 255


def permitted(argv):
    if not argv or not all(isinstance(a, str) and len(a) <= 4096 and "\0" not in a for a in argv):
        return False
    cmd, args = argv[0], argv[1:]
    if "/" in cmd or "\\" in cmd:
        return False
    if cmd == "postconf":
        return args in (["-P"], ["-M"]) or len(args) == 2 and args[0] == "-h" and args[1] in PARAMS
    if cmd == "postqueue":
        return args in (["-j"], ["-p"])
    if cmd == "postmap":
        return len(args) == 3 and args[0] == "-q" and not args[1].startswith("-") and bool(re.fullmatch(r"(?:hash|btree|lmdb|cdb|cidr|texthash):/[^\x00-\x1f]+", args[2]))
    if cmd == "systemctl":
        if args and args[0] == "is-active":
            return len(args) == 2 and bool(re.fullmatch(r"[\w@.-]+", args[1]))
        if args and args[0] == "show":
            return len(args) >= 3 and bool(re.fullmatch(r"[\w@.-]+", args[1])) and all(a in ("--value", "--no-pager", "--property=LoadState,ActiveState,SubState", "--property=ExecStart", "--property=MainPID", "--property=LoadState", "--property=ActiveState", "--property=SubState") for a in args[2:])
        return args in (["list-unit-files", "--type=service", "--no-legend", "--no-pager"], ["list-unit-files", "--no-legend", "--no-pager"])
    if cmd == "df":
        return len(args) <= 10 and all(a in ("-P", "-Pi", "-h", "-i", "--output=pcent,target", "--output=ipcent,target", "/", "/home", "/home/user-data") for a in args)
    if cmd == "doveconf":
        return len(args) == 2 and args[0] == "-h" and args[1] in ("protocols", "ssl")
    if cmd == "ss":
        return args in (["-tlnp"], ["-ltn"], ["-ltnp"], ["-tln"])
    if cmd == "sshd":
        return args == ["-T"]
    if cmd == "fail2ban-client":
        return args == ["status"] or len(args) == 2 and args[0] == "status" and args[1] in ("postfix-sasl", "dovecot", "sshd", "recidive")
    if cmd == "apt-mark":
        return args == ["showhold"]
    if cmd == "dpkg-query":
        return bool(args) and args[0] in ("-W", "--show") and all(a in ("duplicity", "unattended-upgrades") or a.startswith(("-f=", "--showformat=")) and len(a) < 150 for a in args[1:])
    if cmd == "duplicity":
        return args == ["--version"]
    if cmd == "ip":
        if args in (["rule", "show"], ["route", "show"], ["-j", "route", "show"], ["-j", "rule", "show"]):
            return True
        import ipaddress
        try:
            if args[:2] == ["route", "get"] and len(args) == 3:
                ipaddress.ip_address(args[2])
                return True
        except ValueError:
            pass
        return False
    if cmd == "dig":
        # Explicit port is useful for isolated DNS integration tests. It cannot
        # enable file reads, command execution, or bypass the network gate.
        if "-p" in args:
            i = args.index("-p")
            if args.count("-p") != 1 or i + 1 >= len(args) or not re.fullmatch(r"[0-9]{1,5}", args[i + 1]) or not 1 <= int(args[i + 1]) <= 65535:
                return False
            args = args[:i] + args[i + 2:]
        allowed = {"+time=2", "+time=3", "+tries=1", "+noall", "+comments", "+answer", "+authority", "+short", "+nosearch", "-x", "-t", "A", "AAAA", "MX", "TXT", "PTR", "TLSA", "NS", "SOA", "CNAME"}
        return 2 <= len(args) <= 15 and all(a in allowed or bool(re.fullmatch(r"@?[A-Za-z0-9_.:-]{1,253}", a)) and not a.startswith(("-", "+")) for a in args)
    if cmd == "openssl":
        if args and args[0] == "s_client":
            flags = {"-brief", "-showcerts", "-verify_return_error", "-tls1", "-tls1_1", "-tls1_2", "-tls1_3"}
            values = {"-connect", "-servername", "-verify_hostname", "-starttls"}
            i = 1
            while i < len(args):
                if args[i] in flags:
                    i += 1
                elif args[i] in values and i+1 < len(args) and re.fullmatch(r"[A-Za-z0-9_.:\[\]-]{1,300}", args[i+1]) and not args[i+1].startswith("-"):
                    if args[i] == "-starttls" and args[i+1] != "smtp":
                        return False
                    i += 2
                else:
                    return False
            return "-connect" in args
        return args in (["version"], ["x509", "-noout", "-dates", "-subject"])
    if cmd == "journalctl":
        return len(args) <= 20 and args[:3] == ["--no-pager", "-o", "short-iso-precise"] and all(a in ("--reverse", "--since", "--until", "-u", "postfix", "postfix@*.service", "dovecot", "postgrey") or bool(re.fullmatch(r"[0-9T:.+ Z-]{1,50}", a)) for a in args[3:])
    if cmd == "curl":
        return args == ["--silent", "--show-error", "--output", "/dev/null", "--write-out", "%{http_code}", "--connect-timeout", "2", "--max-time", "4", "http://127.0.0.1:10222/"]
    if cmd == "doveadm":
        if args[:2] == ["user", "-u"]:
            return len(args) == 3 and valid_user(args[2])
        if args[:3] == ["quota", "get", "-u"]:
            return len(args) == 4 and valid_user(args[3])
        if args[:4] == ["-f", "json", "fetch", "-u"] and len(args) >= 9 and valid_user(args[4]):
            if not set(args[5].split()) <= {"mailbox", "uid", "guid", "date.received", "date.saved", "date.received.unixtime", "date.saved.unixtime", "hdr.date", "hdr.received", "hdr.message-id", "flags"}:
                return False
            rest, i = args[6:], 0
            while i < len(rest):
                if rest[i] == "HEADER" and i+2 < len(rest) and rest[i+1] == "Message-ID" and not rest[i+2].startswith("-"):
                    i += 3
                elif rest[i] in ("SINCE", "BEFORE") and i+1 < len(rest) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", rest[i+1]):
                    i += 2
                else:
                    return False
            return bool(rest)
    return False


class Runner:
    def __init__(self, max_output=1024 * 1024, network=False, offline=False):
        self.max_output = max_output
        self.network = network
        self.offline = offline
        self.history = []
        self.processes = set()

    def run(self, argv, timeout=8):
        if not permitted(argv):
            raise ValueError("Diagnostic action denied: " + repr(argv[:2]))
        if self.offline or argv[0] in ("dig", "openssl", "curl") and not self.network:
            raise ValueError("External command/network probe was not selected")
        self.history.append(list(argv))
        return self._execute(argv, min(30, max(.05, timeout)))

    @staticmethod
    def stop(process):
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif process.poll() is None:
            process.kill()

    def close(self):
        for process in list(self.processes):
            self.stop(process)

    def _execute(self, argv, timeout):
        try:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, start_new_session=os.name == "posix", env=dict(os.environ, LC_ALL="C"))
        except FileNotFoundError:
            return Result(127, stderr="Command unavailable", missing=True)
        except OSError as error:
            return Result(126, stderr=str(error))
        self.processes.add(process)
        chunks = [bytearray(), bytearray()]
        limited = threading.Event()
        def read(stream, target):
            try:
                while True:
                    data = stream.read(4096)
                    if not data:
                        break
                    remaining = self.max_output - len(target)
                    target.extend(data[:max(0, remaining)])
                    if len(data) > remaining:
                        limited.set()
                        self.stop(process)
                        break
            finally:
                stream.close()
        threads = [threading.Thread(target=read, args=(process.stdout, chunks[0]), daemon=True), threading.Thread(target=read, args=(process.stderr, chunks[1]), daemon=True)]
        for thread in threads:
            thread.start()
        deadline, timed_out = time.monotonic() + timeout, False
        try:
            while process.poll() is None or any(t.is_alive() for t in threads):
                if time.monotonic() >= deadline:
                    timed_out = True
                    self.stop(process)
                    break
                if limited.is_set():
                    self.stop(process)
                    break
                time.sleep(.01)
            process.wait(timeout=2)
            for thread in threads:
                thread.join(timeout=2)
            return Result(process.returncode, *(bytes(c).decode("utf-8", "replace") for c in chunks), truncated=limited.is_set(), timed_out=timed_out)
        except BaseException:
            self.stop(process)
            process.wait(timeout=2)
            raise
        finally:
            self.processes.discard(process)
