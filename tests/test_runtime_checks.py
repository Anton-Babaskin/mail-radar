"""Real Jammy unit shapes and exact local policy listener evidence."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from mailradar import checks
from mailradar.runner import Result, permitted


class FakeRunner:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.history = []

    def run(self, argv, timeout=8):
        if not permitted(argv):
            raise AssertionError("Action not in read-only contract: " + repr(argv))
        self.history.append(tuple(argv))
        return self.responses.get(tuple(argv), Result(127, stderr="fixture unavailable", missing=True))


class RuntimeChecksTests(unittest.TestCase):
    INVENTORY = ("systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain")
    UNIT_FILES = ("systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager")

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def write(self, path, text):
        target = self.root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def context(self, responses=None):
        return checks.Context(FakeRunner(responses), SimpleNamespace(root=str(self.root), mode="doctor", network=False))

    def one(self, context, identifier):
        return next(item for item in context.findings if item["id"] == identifier)

    def policy(self, endpoint, tcp="", unix=""):
        ctx = self.context({("ss", "-ltnp"): Result(stdout=tcp), ("ss", "-lxnp"): Result(stdout=unix)})
        ctx.postconf["queue_directory"] = "/var/spool/postfix"
        checks.policy_listener_checks(ctx, {"global": {"smtpd_recipient_restrictions": "check_policy_service " + endpoint}})
        return ctx

    @staticmethod
    def tcp(local, peer="0.0.0.0:*"):
        return "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0 128 " + local + " " + peer + " users:((\"policy\",pid=123,fd=1))\n"

    def test_same_port_on_different_bind_address_is_not_ok(self):
        ctx = self.policy("inet:127.0.0.1:10023", self.tcp("192.0.2.10:10023"))
        self.assertEqual(self.one(ctx, "POLICY.LISTENER")["status"], "WARN")

    def test_peer_column_port_cannot_confirm_local_listener(self):
        ctx = self.policy("inet:127.0.0.1:10023", self.tcp("127.0.0.1:12340", "0.0.0.0:10023"))
        self.assertEqual(self.one(ctx, "POLICY.LISTENER")["status"], "WARN")

    def test_ipv6_loopback_does_not_confirm_ipv4_endpoint(self):
        ctx = self.policy("inet:127.0.0.1:10023", self.tcp("[::1]:10023", "[::]:*"))
        self.assertEqual(self.one(ctx, "POLICY.LISTENER")["status"], "WARN")

    def test_ipv6_wildcard_cannot_prove_dual_stack_ipv4(self):
        for local in ("[::]:10023", "*:10023"):
            with self.subTest(local=local):
                ctx = self.policy("inet:127.0.0.1:10023", self.tcp(local))
                self.assertEqual(self.one(ctx, "POLICY.LISTENER")["status"], "UNKNOWN")

    def test_exact_literal_or_same_family_wildcard_confirms_bind(self):
        for endpoint, local in (("inet:127.0.0.1:10023", "127.0.0.1:10023"),
                                ("inet:127.0.0.1:10023", "0.0.0.0:10023"),
                                ("inet:[::1]:10023", "[::1]:10023"),
                                ("inet:[::1]:10023", "[::]:10023")):
            with self.subTest(endpoint=endpoint, local=local):
                ctx = self.policy(endpoint, self.tcp(local))
                item = self.one(ctx, "POLICY.LISTENER")
                self.assertEqual(item["status"], "OK")
                self.assertTrue(item["details"]["address_family_confirmed"])

    def test_remote_hostname_and_ipv4_wildcard_are_not_local_proof(self):
        for endpoint in ("inet:policy.example:10023", "inet:192.0.2.10:10023"):
            ctx = self.policy(endpoint, self.tcp("0.0.0.0:10023"))
            self.assertEqual(self.one(ctx, "POLICY.LISTENER")["status"], "UNKNOWN")

    def test_localhost_requires_deterministic_local_nss_metadata(self):
        ctx = self.policy("inet:localhost:10023", self.tcp("127.0.0.1:10023"))
        self.assertEqual(self.one(ctx, "POLICY.LISTENER")["status"], "UNKNOWN")
        self.write("/etc/nsswitch.conf", "hosts: files dns\n")
        self.write("/etc/hosts", "127.0.0.1 localhost\n")
        ctx = self.policy("inet:localhost:10023", self.tcp("127.0.0.1:10023"))
        self.assertEqual(self.one(ctx, "POLICY.LISTENER")["status"], "OK")

    def test_empty_nss_hosts_and_partial_localhost_families_are_unknown(self):
        self.write("/etc/hosts", "127.0.0.1 localhost\n::1 localhost\n")
        for nss in ("hosts:   # empty\n", "hosts:\n", "hosts: files dns\n", "hosts: files [SUCCESS=continue] dns\n"):
            with self.subTest(nss=nss):
                self.write("/etc/nsswitch.conf", nss)
                ctx = self.policy("inet:localhost:10023", self.tcp("127.0.0.1:10023"))
                self.assertEqual(self.one(ctx, "POLICY.LISTENER")["status"], "UNKNOWN")

    def test_unix_policy_requires_exact_stream_listen_path(self):
        line = 'u_str LISTEN 0 128 /var/spool/postfix/private/policy 1234 * 0 users:(("policy",pid=1,fd=1))\n'
        ctx = self.policy("unix:private/policy", unix=line)
        self.assertEqual(self.one(ctx, "POLICY.LISTENER")["status"], "OK")
        wrong = self.policy("unix:private/other", unix=line)
        self.assertEqual(self.one(wrong, "POLICY.LISTENER")["status"], "WARN")
        dgram = self.policy("unix:private/policy", unix=line.replace("u_str LISTEN", "u_dgr UNCONN"))
        self.assertEqual(self.one(dgram, "POLICY.LISTENER")["status"], "WARN")

    def test_listener_command_failure_remains_unknown(self):
        ctx = self.context()
        checks.policy_listener_checks(ctx, {"global": {"smtpd_recipient_restrictions": "check_policy_service inet:127.0.0.1:10023"}})
        self.assertEqual(self.one(ctx, "POLICY.LISTENER")["status"], "UNKNOWN")

    def postfix_context(self, instances, states, inventory_error=False):
        responses = {
            self.UNIT_FILES: Result(stdout="postfix.service enabled\npostfix@.service indirect\n"),
            ("systemctl", "show", "postfix", "--property=LoadState,ActiveState,SubState", "--value"): Result(stdout="loaded\nactive\nexited\n"),
            self.INVENTORY: Result(1, stderr="no bus") if inventory_error else Result(stdout=instances),
        }
        for name, state in states.items():
            responses[("systemctl", "show", name, "--property=LoadState,ActiveState,SubState", "--value")] = state
        ctx = self.context(responses)
        checks.service_checks(ctx)
        return ctx

    def test_postfix_umbrella_active_exited_does_not_hide_failed_default(self):
        ctx = self.postfix_context("postfix@-.service loaded failed failed Postfix\n", {
            "postfix@-.service": Result(stdout="loaded\nfailed\nfailed\n")})
        self.assertEqual(self.one(ctx, "SERVICE.POSTFIX")["status"], "FAIL")
        self.assertEqual(self.one(ctx, "SERVICE.POSTFIX_INSTANCE")["status"], "FAIL")

    def test_inactive_secondary_unit_is_not_assumed_to_be_a_required_failure(self):
        ctx = self.postfix_context("postfix@-.service loaded active running Postfix\npostfix@optional.service loaded inactive dead Postfix\n", {
            "postfix@-.service": Result(stdout="loaded\nactive\nrunning\n"),
            "postfix@optional.service": Result(stdout="LoadState=loaded\nActiveState=inactive\nSubState=dead\n")})
        self.assertEqual(self.one(ctx, "SERVICE.POSTFIX")["status"], "UNKNOWN")
        instances = {f["details"]["unit"]: f for f in ctx.findings if f["id"] == "SERVICE.POSTFIX_INSTANCE"}
        self.assertEqual(instances["postfix@-.service"]["status"], "OK")
        self.assertEqual(instances["postfix@optional.service"]["status"], "UNKNOWN")

    def test_postfix_missing_or_incomplete_actual_unit_is_unknown(self):
        for result in (Result(stdout="not-found\ninactive\ndead\n"), Result(stdout="active\n"), Result(1, stderr="permission denied")):
            with self.subTest(result=result):
                ctx = self.postfix_context("postfix@-.service loaded active running Postfix\n", {"postfix@-.service": result})
                self.assertEqual(self.one(ctx, "SERVICE.POSTFIX")["status"], "UNKNOWN")

    def test_postfix_running_default_and_secondary_instances_are_checked(self):
        ctx = self.postfix_context("postfix@-.service loaded active running Postfix\npostfix@outbound.service loaded active running Postfix\n", {
            "postfix@-.service": Result(stdout="loaded\nactive\nrunning\n"),
            "postfix@outbound.service": Result(stdout="loaded\nactive\nrunning\n")})
        self.assertEqual(self.one(ctx, "SERVICE.POSTFIX")["status"], "OK")
        self.assertEqual(len([f for f in ctx.findings if f["id"] == "SERVICE.POSTFIX_INSTANCE"]), 2)
        self.assertTrue(all(permitted(list(argv)) for argv in ctx.runner.history))

    def test_postfix_failed_secondary_instance_is_not_hidden(self):
        ctx = self.postfix_context("postfix@-.service loaded active running Postfix\npostfix@outbound.service loaded failed failed Postfix\n", {
            "postfix@-.service": Result(stdout="loaded\nactive\nrunning\n"),
            "postfix@outbound.service": Result(stdout="loaded\nfailed\nfailed\n")})
        self.assertEqual(self.one(ctx, "SERVICE.POSTFIX")["status"], "FAIL")

    def test_postfix_inventory_failure_uses_bounded_default_fallback_without_ok(self):
        ctx = self.postfix_context("", {"postfix@-.service": Result(stdout="loaded\nactive\nrunning\n")}, inventory_error=True)
        self.assertEqual(self.one(ctx, "SERVICE.POSTFIX")["status"], "UNKNOWN")
        self.assertIn(("systemctl", "show", "postfix@-.service", "--property=LoadState,ActiveState,SubState", "--value"), ctx.runner.history)

    def test_postfix_missing_default_cannot_be_hidden_by_running_secondary(self):
        ctx = self.postfix_context("postfix@outbound.service loaded active running Postfix\n", {
            "postfix@outbound.service": Result(stdout="loaded\nactive\nrunning\n"),
            "postfix@-.service": Result(stdout="not-found\ninactive\ndead\n")})
        self.assertEqual(self.one(ctx, "SERVICE.POSTFIX")["status"], "UNKNOWN")

    def test_postfix_instance_inventory_is_bounded(self):
        names = ["postfix@-.service"] + ["postfix@instance" + str(i) + ".service" for i in range(30)]
        ctx = self.postfix_context("".join(name + " loaded active running Postfix\n" for name in names), {
            name: Result(stdout="loaded\nactive\nrunning\n") for name in names})
        self.assertEqual(len([f for f in ctx.findings if f["id"] == "SERVICE.POSTFIX_INSTANCE"]), 20)
        self.assertEqual(self.one(ctx, "SERVICE.POSTFIX")["status"], "UNKNOWN")

    def postgrey_context(self, daemon="/usr/sbin/postgrey", installed=True):
        # Jammy1.36-5.2: generated SysV unit, active(exited), no MainPID;
        # the installed init script uses a literal DAEMON and /etc/default.
        self.write("/etc/init.d/postgrey", "#!/bin/sh\nPATH=/usr/sbin:/usr/bin\nDAEMON=" + daemon + "\nPIDFILE=/var/run/postgrey.pid\n. /etc/default/postgrey\n")
        self.write("/etc/default/postgrey", 'POSTGREY_OPTS="--inet=127.0.0.1:10023 --delay=180"\n')
        if installed:
            self.write("/usr/sbin/postgrey", "my $CONFIG_DIR = '/etc/postgrey';\nwhitelist_clients_files => $opt{'whitelist-clients'} || [\"$CONFIG_DIR/whitelist_clients\", \"$CONFIG_DIR/whitelist_clients.local\"],\n")
        self.write("/etc/postgrey/whitelist_clients", "partner.example\n")
        return self.context({
            ("systemctl", "show", "postgrey", "--property=ExecStart", "--value"): Result(stdout="{ path=/etc/init.d/postgrey ; argv[]=/etc/init.d/postgrey start ; }"),
            ("systemctl", "show", "postgrey", "--property=LoadState,ActiveState,SubState", "--value"): Result(stdout="loaded\nactive\nexited\n"),
            ("systemctl", "show", "postgrey", "--property=MainPID", "--value"): Result(stdout="0\n"),
        })

    def test_postgrey_jammy_sysv_literal_daemon_confirms_installed_defaults(self):
        ctx = self.postgrey_context()
        matches, unknown = checks.postgrey_whitelist_checks(ctx, "mx.partner.example", None)
        self.assertFalse(unknown)
        self.assertEqual(matches[0]["file"], "/etc/postgrey/whitelist_clients")
        sources = [f["details"].get("defaults_source") for f in ctx.findings if f["id"] == "WHITELIST.POSTGREY_FILE"]
        self.assertIn("/usr/sbin/postgrey", sources)
        self.assertTrue(any(f["status"] == "N/A" for f in ctx.findings if f["id"] == "WHITELIST.POSTGREY_FILE"))
        self.assertFalse(any(command[0] in {"postgrey", "sh", "bash", "/etc/init.d/postgrey"} for command in ctx.runner.history))

    def test_postgrey_dynamic_daemon_or_missing_signature_stays_unknown(self):
        for daemon, installed in (("$DAEMON_PATH", True), ('"$(choose-postgrey)"', True), ("/usr/sbin/postgrey", False)):
            with self.subTest(daemon=daemon, installed=installed):
                if not installed:
                    existing = self.root / "usr/sbin/postgrey"
                    if existing.exists():
                        existing.unlink()
                ctx = self.postgrey_context(daemon, installed)
                matches, unknown = checks.postgrey_whitelist_checks(ctx, "mx.partner.example", None)
                self.assertFalse(matches)
                self.assertTrue(unknown)


if __name__ == "__main__":
    unittest.main()
