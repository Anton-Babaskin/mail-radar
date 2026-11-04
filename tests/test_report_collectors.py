"""Collectors honor the selected task and retain useful structured facts."""
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mailradar import checks, mailstore
from mailradar.runner import Result, permitted


class FakeRunner:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.history = []

    def run(self, argv, timeout=8):
        if not permitted(argv):
            raise AssertionError("Action outside read-only contract: " + repr(argv))
        self.history.append(list(argv))
        return self.responses.get(tuple(argv), Result(127, stderr="fixture command unavailable", missing=True))


class ReportCollectorsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.since = datetime(2026, 11, 4, 9, tzinfo=timezone.utc)
        self.until = self.since + timedelta(hours=1)

    def tearDown(self):
        self.directory.cleanup()

    def args(self, mode, **values):
        data = dict(mode=mode, root=str(self.root), network=False, domain=None, peer=None,
                    sender=None, to=None, ip=None, user=None, headers=None, trace=None,
                    client_name=None, client_ip=None, dkim_selector=None, deep=False)
        data.update(values)
        return SimpleNamespace(**data)

    def write(self, name, text):
        path = self.root / name.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def one(self, results, identifier):
        return next(item for item in results if item["id"] == identifier)

    def dispatch(self, mode, **values):
        calls = []
        def stage(name):
            def collect(ctx, **kwargs):
                calls.append(name + (":config" if kwargs.get("config_only") else ""))
                if name == "platform_checks":
                    ctx.metadata["PRIMARY_HOSTNAME"] = "box.local.example"
                if name == "postfix_checks":
                    ctx.postconf.update(myhostname="box.local.example", mydomain="local.example")
                    return {"global": {}}
            return collect
        functions = ("platform_checks", "service_checks", "queue_checks", "disk_checks", "postfix_checks", "whitelist_checks",
                     "dns_checks", "tls_checks", "security_checks", "backup_checks", "route_checks", "post_update_checks")
        with ExitStack() as stack:
            for name in functions:
                stack.enter_context(patch.object(checks, name, side_effect=stage(name)))
            stack.enter_context(patch.object(checks, "dnsbl_filter_checks", side_effect=lambda ctx, contexts: calls.append("dnsbl_filter_checks")))
            # Whitelist accepts the explicit contexts positional argument.
            stack.enter_context(patch.object(checks, "whitelist_checks", side_effect=lambda ctx, contexts: calls.append("whitelist_checks")))
            results = checks.collect_checks(FakeRunner(), self.args(mode, **values))
        return calls, results

    def test_queue_and_account_do_not_dispatch_unrelated_doctor_checks(self):
        for mode, expected in (("queue", ["platform_checks", "queue_checks"]), ("account", ["platform_checks", "disk_checks"])):
            with self.subTest(mode=mode):
                calls, results = self.dispatch(mode, network=True, peer="192.0.2.10")
                self.assertEqual(calls, expected)
                self.assertEqual(self.one(results, "HOST.TARGETS")["details"]["local_hostname"], "box.local.example")

    def test_dns_dispatches_only_dns_tls_postfix_context_and_explicit_peer(self):
        expected = ["platform_checks", "postfix_checks", "dnsbl_filter_checks", "dns_checks", "tls_checks"]
        calls, _ = self.dispatch("dns")
        self.assertEqual(calls, expected)
        calls, _ = self.dispatch("dns", peer="192.0.2.10")
        self.assertEqual(calls, expected + ["route_checks"])

    def test_delivery_tasks_do_not_add_security_backup_or_unselected_dns(self):
        expected = ["platform_checks", "service_checks", "queue_checks", "disk_checks", "postfix_checks", "whitelist_checks"]
        for mode in ("incoming", "outgoing", "delay", "diagnose"):
            with self.subTest(mode=mode):
                calls, _ = self.dispatch(mode)
                self.assertEqual(calls, expected)
                calls, _ = self.dispatch(mode, network=True)
                self.assertEqual(calls, expected + ["dnsbl_filter_checks", "dns_checks", "tls_checks"])

    def test_whitelist_uses_only_context_maps_and_resolver_configuration(self):
        calls, _ = self.dispatch("whitelist", network=True)
        self.assertEqual(calls, ["platform_checks", "postfix_checks", "whitelist_checks", "dns_checks:config"])

    def test_doctor_and_post_update_keep_full_dispatch(self):
        expected = ["platform_checks", "service_checks", "queue_checks", "disk_checks", "postfix_checks", "dnsbl_filter_checks",
                    "whitelist_checks", "dns_checks", "tls_checks", "security_checks", "backup_checks", "route_checks"]
        self.assertEqual(self.dispatch("doctor")[0], expected)
        self.assertEqual(self.dispatch("post-update")[0], expected + ["post_update_checks"])

    def test_real_queue_collector_only_calls_postqueue_even_with_network_flag(self):
        self.write("/etc/mailinabox.conf", "PRIMARY_HOSTNAME=box.local.example\n")
        runner = FakeRunner({("postqueue", "-j"): Result(stdout="")})
        results = checks.collect_checks(runner, self.args("queue", domain="external.example", network=True))
        self.assertEqual(runner.history, [["postqueue", "-j"]])
        targets = self.one(results, "HOST.TARGETS")["details"]
        self.assertEqual(targets, dict(local_hostname="box.local.example", dns_domain="external.example", tls_hostname="box.local.example"))

    def test_real_delivery_service_inventory_excludes_web_and_security_services(self):
        names = ("postfix", "dovecot", "nginx", "fail2ban", "nsd", "mailinabox", "php8.0-fpm", "spampd", "postgrey")
        responses = {("systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"): Result(stdout="".join(name + ".service enabled\n" for name in names)), ("postqueue", "-j"): Result()}
        for name in names:
            responses[("systemctl", "show", name, "--property=LoadState,ActiveState,SubState", "--value")] = Result(stdout="loaded\nactive\nrunning\n")
        runner = FakeRunner(responses)
        checks.collect_checks(runner, self.args("incoming"))
        queried = {argv[2] for argv in runner.history if argv[:2] == ["systemctl", "show"]}
        self.assertTrue({"postfix", "dovecot", "postgrey"}.issubset(queried))
        self.assertTrue(queried.isdisjoint({"nginx", "php8.0-fpm", "fail2ban", "nsd", "mailinabox"}))
        self.assertTrue({argv[0] for argv in runner.history}.isdisjoint({"dig", "openssl", "curl", "sshd", "fail2ban-client", "apt-mark", "duplicity", "ip"}))

    def test_selected_dns_domain_does_not_become_remote_tls_target(self):
        self.write("/etc/mailinabox.conf", "PRIMARY_HOSTNAME=box.local.example\n")
        responses = {("postconf", "-h", name): Result(stdout="") for name in checks._PARAMS}
        responses.update({("postconf", "-h", "myhostname"): Result(stdout="box.local.example\n"),
                          ("postconf", "-h", "mydomain"): Result(stdout="local.example\n"),
                          ("postconf", "-P"): Result(), ("postconf", "-M"): Result()})
        runner = FakeRunner(responses)
        results = checks.collect_checks(runner, self.args("dns", network=True, domain="external.example"))
        targets = self.one(results, "HOST.TARGETS")["details"]
        self.assertEqual(targets["dns_domain"], "external.example")
        probes = [argv for argv in runner.history if argv[0] == "openssl"]
        self.assertEqual(len(probes), 5)
        self.assertTrue(all(argv[argv.index("-connect") + 1].startswith("box.local.example:") for argv in probes))
        self.assertTrue({argv[0] for argv in runner.history}.isdisjoint({"systemctl", "df", "sshd", "apt-mark", "postmap", "postqueue", "ip"}))

    def queue(self, rows, **values):
        runner = FakeRunner({("postqueue", "-j"): Result(stdout="\n".join(json.dumps(row) for row in rows))})
        ctx = checks.Context(runner, self.args("queue", **values))
        checks.queue_checks(ctx)
        return self.one(ctx.findings, "QUEUE.SNAPSHOT"), ctx.findings

    def row(self, identifier, state="active", **values):
        data = dict(queue_id=identifier, queue_name=state, arrival_time=datetime.now(timezone.utc).timestamp() - 60,
                    message_size=1234, sender="sender@from.example", recipients=[dict(address="office@recipient.example", delay_reason="")])
        data.update(values)
        return data

    def test_current_queue_is_not_failed_based_on_active_message_count(self):
        snapshot, _ = self.queue([self.row("Q" + str(i)) for i in range(75)])
        self.assertEqual(snapshot["status"], "OK")
        self.assertEqual(snapshot["details"]["count"], 75)
        self.assertEqual(snapshot["details"]["entries_omitted"], 25)

    def test_queue_retains_old_deferred_before_limit_with_every_recipient(self):
        recipients = [dict(address="r" + str(i) + "@other.example", delay_reason="4.4.3 DNS failure") for i in range(30)]
        rows = [self.row("ACTIVE" + str(i)) for i in range(55)]
        rows.append(self.row("OLDEST", "deferred", arrival_time=datetime.now(timezone.utc).timestamp() - 49 * 3600, recipients=recipients))
        snapshot, findings = self.queue(rows)
        self.assertEqual(snapshot["status"], "WARN")
        details = snapshot["details"]
        self.assertEqual(details["count"], 56)
        self.assertEqual(details["entries_omitted"], 6)
        entry = details["entries"][0]
        self.assertEqual(entry["queue_id"], "OLDEST")
        self.assertEqual(entry["message_size"], 1234)
        self.assertTrue(entry["arrival_iso"].endswith("+00:00"))
        self.assertEqual(len(entry["recipients"]), 30)
        self.assertEqual(entry["recipients_omitted"], 0)
        self.assertEqual(details["recipient_domains"]["other.example"], 30)
        self.assertEqual(self.one(findings, "QUEUE.AGE")["status"], "WARN")

    def test_queue_envelope_filters_apply_before_retention_and_ip_is_not_invented(self):
        rows = [self.row("OTHER" + str(i)) for i in range(60)]
        rows.append(self.row("MATCH", "hold", sender="sender@partner.example", recipients=[dict(address="office@target.example", delay_reason="held")]))
        snapshot, findings = self.queue(rows, sender="sender@partner.example", to="office@target.example", domain="target.example", ip="192.0.2.10")
        details = snapshot["details"]
        self.assertEqual((details["count"], details["matched_count"], details["entries_omitted"]), (61, 1, 0))
        self.assertEqual(details["entries"][0]["queue_id"], "MATCH")
        self.assertTrue(details["filtered"])
        self.assertEqual(details["ignored_filters"], ["ip"])
        self.assertEqual(self.one(findings, "QUEUE.FILTERS")["status"], "UNKNOWN")

    def test_text_fallback_preserves_header_recipients_and_per_recipient_reason(self):
        text = ("----Queue ID----- --Size-- ---Arrival Time---- --Sender/Recipient------\n"
                "LONG4bYzQueue! 1024 Wed Nov  4 09:00:00 sender@partner.example\n"
                "           (connect to mx.example[192.0.2.10]:25: Connection timed out)\n"
                "                                         first@target.example\n"
                "                                         second@target.example\n"
                "                                                       (reason unavailable)\n"
                "                                         third@other.example\n\n"
                "BOUNCE4bYzQueue*# 42 Wed Nov  4 09:01:00 \n"
                "                                         bounce@target.example\n\n"
                "-- 1 Kbytes in 2 Requests.\n")
        ctx = checks.Context(FakeRunner({("postqueue", "-p"): Result(stdout=text)}), self.args("queue"))
        checks.queue_fallback(ctx)
        details = self.one(ctx.findings, "QUEUE.SNAPSHOT")["details"]
        self.assertTrue(details["complete"])
        first = next(row for row in details["entries"] if row["queue_id"] == "LONG4bYzQueue")
        self.assertEqual(first["sender"], "sender@partner.example")
        self.assertEqual(first["message_size"], 1024)
        self.assertEqual(len(first["recipients"]), 3)
        self.assertEqual(first["recipients"][0]["delay_reason"], first["recipients"][1]["delay_reason"])
        self.assertFalse(first["recipients"][2]["reason_known"])
        self.assertEqual(first["arrival_text"], "Wed Nov  4 09:00:00")
        self.assertIsNone(first["arrival_time"])
        self.assertIn("arrival_year", first["unknown_fields"])
        bounce = next(row for row in details["entries"] if row["queue_id"] == "BOUNCE4bYzQueue")
        self.assertEqual(bounce["sender"], "")
        self.assertTrue(bounce["forced_expire"])

    def store_runner(self, quota="User quota STORAGE 95 100 95\nUser quota MESSAGE 2 100 2\n", records=None):
        class StoreRunner(FakeRunner):
            def run(inner, argv, timeout=8):
                super(StoreRunner, inner).run(argv, timeout)
                if argv[1:3] == ["quota", "get"]:
                    return Result(stdout=quota)
                if "fetch" in argv:
                    return Result(stdout=json.dumps(records or []))
                return Result(stdout="uid 1000\ngid 1000\nhome /home/mail/office\n")
        return StoreRunner()

    def test_account_collects_userdb_and_structured_quota_without_message_fetch(self):
        runner = self.store_runner()
        results = mailstore.collect_mailstore(runner, self.args("account", user="office@local.example", headers="<ignored@example>"), self.since, self.until)
        self.assertEqual(len(runner.history), 2)
        self.assertFalse(any("fetch" in argv for argv in runner.history))
        user = self.one(results, "mailstore.user")
        self.assertEqual(user["details"]["user"], "office@local.example")
        self.assertEqual(user["details"]["fields"]["uid"], "1000")
        quota = self.one(results, "mailstore.quota")
        self.assertEqual(quota["status"], "WARN")
        self.assertEqual(quota["details"]["rows"][0], dict(quota_root="User quota", resource="STORAGE", used=95, limit=100, percent=95, unit="KiB", unlimited=False, complete=True))

    def test_account_deep_is_explicit_and_does_not_add_header_fetch(self):
        runner = self.store_runner()
        with patch.object(mailstore, "physical_usage", return_value=dict(id="physical", status="UNKNOWN")) as deep:
            mailstore.collect_mailstore(runner, self.args("account", user="office@local.example", deep=True), self.since, self.until)
        deep.assert_called_once_with(str(self.root), "office@local.example")
        self.assertFalse(any("fetch" in argv for argv in runner.history))

    def test_quota_large_percentage_unlimited_and_malformed_rows_are_truthful(self):
        for text, status in (("User quota STORAGE 100000 1 10000000\nUser quota MESSAGE 0 100 0\n", "FAIL"),
                             ("User quota STORAGE 100 - -\n", "N/A"),
                             ("User quota STORAGE 10 100 10\nbroken 0\n", "UNKNOWN")):
            with self.subTest(text=text):
                results = mailstore.collect_mailstore(self.store_runner(text), self.args("account", user="office@local.example"), self.since, self.until)
                self.assertEqual(self.one(results, "mailstore.quota")["status"], status)

    def test_metadata_exposes_target_user_counts_and_retention_separately(self):
        row = {"mailbox": "Trash", "hdr.message-id": "<one@example>", "date.received.unixtime": self.since.timestamp() + 1}
        rows = [row] * 51 + [dict(row, **{"hdr.message-id": "<other@example>"})]
        results = mailstore.collect_mailstore(self.store_runner(records=rows), self.args("headers", user="office@local.example", headers="<one@example>"), self.since, self.until)
        item = self.one(results, "mailstore.metadata")
        self.assertEqual(item["status"], "UNKNOWN")
        self.assertEqual(item["details"]["user"], "office@local.example")
        self.assertEqual((item["details"]["records_count"], item["details"]["matching_records"], item["details"]["records_scanned"], item["details"]["omitted_records"]), (50, 51, 52, 1))


if __name__ == "__main__":
    unittest.main()
