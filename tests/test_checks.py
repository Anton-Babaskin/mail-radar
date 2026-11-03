import datetime as dt
import json
import os
from pathlib import Path
import shlex
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from mailradar import checks
from mailradar.runner import Result, Runner, permitted


class FakeRunner:
    """All tests are isolated: no command in this runner is executed."""
    def __init__(self, responses=None, default=None):
        self.responses = responses or {}
        self.default = default or Result(127, stderr="fixture unavailable", missing=True)
        self.history = []

    def run(self, argv, timeout=8):
        if not permitted(argv):
            raise AssertionError("collector bypassed the read-only action contract: " + repr(argv))
        self.history.append(tuple(argv))
        response = self.responses.get(tuple(argv), self.default)
        return response(argv) if callable(response) else response


class ChecksTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def write(self, name, content=""):
        path = self.root / name.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def context(self, responses=None, **kwargs):
        args = dict(root=str(self.root), mode="doctor", network=False,
                    client_name=None, client_ip=None, domain=None, peer=None, dkim_selector=None)
        args.update(kwargs)
        return checks.Context(FakeRunner(responses), SimpleNamespace(**args))

    def find(self, context, identifier):
        return [f for f in context.findings if f["id"] == identifier]

    def base_postfix(self, **values):
        config = {p: "" for p in checks._PARAMS}
        config.update(myhostname="box.example.org", mydomain="example.org",
                      smtpd_relay_restrictions="permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination")
        config.update(values)
        responses = {("postconf", "-h", p): Result(stdout=v + "\n") for p, v in config.items()}
        responses[("postconf", "-P")] = Result()
        return responses

    def test_queue_command_error_is_unknown_not_empty(self):
        ctx = self.context({("postqueue", "-j"): Result(1, stderr="permission denied")})
        checks.queue_checks(ctx)
        self.assertEqual(self.find(ctx, "QUEUE.SNAPSHOT")[0]["status"], "UNKNOWN")
        self.assertNotIn(("postqueue", "-p"), ctx.runner.history)

    def test_queue_json_long_ids_hold_duplicates_and_arrival(self):
        now = dt.datetime.now(dt.timezone.utc).timestamp()
        row = dict(queue_id="4bYzQabc9Z017V", queue_name="hold", arrival_time=now - 49*3600,
                   sender="", recipients=[{"address": "user@example.org", "delay_reason": "4.4.3 MX SERVFAIL"}])
        ctx = self.context({("postqueue", "-j"): Result(stdout=json.dumps(row) + "\n" + json.dumps(row) + "\n")})
        checks.queue_checks(ctx)
        result = self.find(ctx, "QUEUE.SNAPSHOT")[0]
        self.assertEqual(result["details"]["count"], 1)
        self.assertEqual(result["details"]["duplicates"], 1)
        self.assertEqual(result["details"]["queues"], {"hold": 1})
        self.assertFalse(result["details"]["snapshot_atomic"])
        self.assertEqual(self.find(ctx, "QUEUE.AGE")[0]["status"], "WARN")
        self.assertEqual(result["details"]["entries"][0]["sender"], "")

    def test_queue_truncated_and_malformed_not_empty(self):
        for result in (Result(stdout="", truncated=True), Result(stdout="{malformed}\n")):
            ctx = self.context({("postqueue", "-j"): result})
            checks.queue_checks(ctx)
            self.assertEqual(self.find(ctx, "QUEUE.SNAPSHOT")[0]["status"], "UNKNOWN")

    def test_queue_incomplete_schema_and_non_finite_json_are_unknown(self):
        row = dict(queue_id="ABC123", queue_name="deferred", arrival_time=1, sender="", recipients=[])
        for text in (json.dumps({"queue_id": "ABC123"}), json.dumps(dict(row, arrival_time=float("nan"))),
                     json.dumps(row).replace('"arrival_time": 1', '"arrival_time": 1e999'),
                     json.dumps(dict(row, arrival_time=10**500))):
            ctx = self.context({("postqueue", "-j"): Result(stdout=text + "\n")})
            checks.queue_checks(ctx)
            self.assertEqual(self.find(ctx, "QUEUE.SNAPSHOT")[0]["status"], "UNKNOWN")

    def test_queue_fallback_only_when_json_option_unsupported(self):
        text = ("-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------\n"
                "4bYzQabc9Z017V!    123 Mon Nov  2 10:00:00 sender@example.org\n"
                "                                         user@example.org\n\n"
                "-- 0 Kbytes in 1 Request.\n")
        ctx = self.context({("postqueue", "-j"): Result(1, stderr="postqueue: invalid option -- j"),
                            ("postqueue", "-p"): Result(stdout=text)})
        checks.queue_checks(ctx)
        result = self.find(ctx, "QUEUE.SNAPSHOT")[0]
        self.assertEqual(result["details"]["count"], 1)
        self.assertEqual(result["details"]["queues"], {"hold": 1})
        self.assertTrue(result["details"]["fallback"])
        self.assertTrue(result["details"]["complete"])

    def test_queue_fallback_footer_mismatch_or_bad_date_is_unknown(self):
        for text in (
                "4bYzQabc9Z017V! 123 Mon Nov  2 10:00:00 sender@example.org\n-- 0 Kbytes in 2 Requests.\n",
                "4bYzQabc9Z017V! 123 INVALID DATE sender@example.org\n-- 0 Kbytes in 1 Request.\n",
                "Mail queue is empty\n4bYzQabc9Z017V! 123 Mon Nov  2 10:00:00 sender@example.org\n-- 0 Kbytes in 1 Request.\n"):
            ctx = self.context({("postqueue", "-p"): Result(stdout=text)})
            checks.queue_fallback(ctx)
            self.assertEqual(self.find(ctx, "QUEUE.SNAPSHOT")[0]["status"], "UNKNOWN")
            self.assertFalse(self.find(ctx, "QUEUE.SNAPSHOT")[0]["details"]["complete"])

    def test_queue_stderr_warning_means_snapshot_incomplete(self):
        ctx = self.context({("postqueue", "-j"): Result(stdout="", stderr="warning: partial showq output")})
        checks.queue_checks(ctx)
        self.assertEqual(self.find(ctx, "QUEUE.SNAPSHOT")[0]["status"], "UNKNOWN")

    def test_text_queue_duplicates_count_unique_messages(self):
        row = "4bYzQabc9Z017V 123 Mon Nov  2 10:00:00 sender@example.org\n"
        ctx = self.context({("postqueue", "-p"): Result(stdout=row + row + "-- 0 Kbytes in 2 Requests.\n")})
        checks.queue_fallback(ctx)
        result = self.find(ctx, "QUEUE.SNAPSHOT")[0]
        self.assertEqual(result["details"]["count"], 1)
        self.assertEqual(result["details"]["duplicates"], 1)

    def test_relay_guard_in_relay_chain_is_accepted(self):
        ctx = self.context(self.base_postfix(smtpd_recipient_restrictions="check_policy_service inet:127.0.0.1:10023"))
        checks.postfix_checks(ctx)
        guard = self.find(ctx, "POSTFIX.RELAY_GUARD")[0]
        self.assertEqual(guard["status"], "OK")
        self.assertEqual(guard["details"]["guard_chains"], ["relay"])
        self.assertFalse(guard["details"]["external_relay_test"])

    def test_master_override_without_guard_is_separate_context(self):
        responses = self.base_postfix()
        responses[("postconf", "-P")] = Result(stdout="submission/inet/smtpd_relay_restrictions=permit\n")
        ctx = self.context(responses)
        checks.postfix_checks(ctx)
        guards = self.find(ctx, "POSTFIX.RELAY_GUARD")
        self.assertEqual({g["details"]["context"]: g["status"] for g in guards}, {"global": "OK", "submission/inet": "WARN"})

    def test_unconditional_permit_before_guard_is_not_safe(self):
        ctx = self.context(self.base_postfix(smtpd_relay_restrictions="permit, reject_unauth_destination"))
        checks.postfix_checks(ctx)
        self.assertEqual(self.find(ctx, "POSTFIX.RELAY_GUARD")[0]["status"], "WARN")

    def test_missing_master_command_does_not_assert_service_overrides(self):
        responses = self.base_postfix()
        responses[("postconf", "-P")] = Result(1, stderr="unsupported")
        ctx = self.context(responses)
        checks.postfix_checks(ctx)
        self.assertEqual(self.find(ctx, "POSTFIX.MASTER_COVERAGE")[0]["status"], "UNKNOWN")

    def test_default_whitelist_files_survive_but_wiring_lost(self):
        self.write("/etc/postfix/client_whitelist", "partner.example OK\n")
        self.write("/etc/postfix/client_whitelist.db", "fixture index")
        ctx = self.context(self.base_postfix())
        contexts = checks.postfix_checks(ctx)
        checks.whitelist_checks(ctx, contexts)
        self.assertEqual(self.find(ctx, "WHITELIST.DISCONNECTED")[0]["status"], "WARN")
        self.assertTrue(self.root.joinpath("etc/postfix/client_whitelist").is_file())

    def test_ip_hash_hit_cidr_miss_is_success(self):
        self.write("/etc/postfix/client_whitelist", "198.51.100.8 OK\n")
        self.write("/etc/postfix/client_whitelist.db", "fixture index")
        self.write("/etc/postfix/client_whitelist_cidr", "")
        chain = "check_client_access hash:/etc/postfix/client_whitelist, check_client_access cidr:/etc/postfix/client_whitelist_cidr, check_policy_service inet:127.0.0.1:10023"
        responses = self.base_postfix(smtpd_recipient_restrictions=chain)
        responses[("postmap", "-q", "198.51.100.8", "hash:/etc/postfix/client_whitelist")] = Result(stdout="OK\n")
        responses[("postmap", "-q", "198.51.100.8", "cidr:/etc/postfix/client_whitelist_cidr")] = Result(1)
        ctx = self.context(responses, client_ip="198.51.100.8")
        checks.whitelist_checks(ctx, checks.postfix_checks(ctx))
        self.assertEqual(self.find(ctx, "WHITELIST.RESULT")[0]["status"], "OK")
        self.assertFalse(any(f["status"] == "FAIL" for f in self.find(ctx, "WHITELIST.LOOKUP")))

    def test_domain_cidr_is_not_applicable_and_never_queried(self):
        self.write("/etc/postfix/client_whitelist_cidr", "198.51.100.0/24 OK\n")
        responses = self.base_postfix(smtpd_recipient_restrictions="check_client_access cidr:/etc/postfix/client_whitelist_cidr")
        ctx = self.context(responses, client_name="mx.partner.example")
        checks.whitelist_checks(ctx, checks.postfix_checks(ctx))
        self.assertEqual(self.find(ctx, "WHITELIST.LOOKUP")[0]["status"], "N/A")
        self.assertFalse(any(c[0] == "postmap" for c in ctx.runner.history))

    def test_domain_parent_matching_obeys_postconf(self):
        self.write("/etc/postfix/clients", "partner.example OK\n.partner.example OK\n")
        self.write("/etc/postfix/clients.db", "index")
        for setting, expected in (("smtpd_access_maps", "partner.example"), ("", ".partner.example")):
            responses = self.base_postfix(smtpd_recipient_restrictions="check_client_access hash:/etc/postfix/clients", parent_domain_matches_subdomains=setting)
            responses[("postmap", "-q", "mx.partner.example", "hash:/etc/postfix/clients")] = Result(1)
            responses[("postmap", "-q", expected, "hash:/etc/postfix/clients")] = Result(stdout="OK\n")
            ctx = self.context(responses, client_name="mx.partner.example")
            checks.whitelist_checks(ctx, checks.postfix_checks(ctx))
            self.assertIn(("postmap", "-q", expected, "hash:/etc/postfix/clients"), ctx.runner.history)
            matches = self.find(ctx, "WHITELIST.RESULT")[0]["details"]["matches"]
            self.assertEqual(matches[0]["key"], expected)

    def test_two_policy_services_and_early_reject_are_preserved(self):
        chain = ("reject_rbl_client zen.spamhaus.org=127.0.0.[2..11], reject_unlisted_recipient, "
                 "check_client_access hash:/etc/postfix/clients, "
                 "check_policy_service inet:127.0.0.1:10023, check_policy_service inet:127.0.0.1:12340")
        responses = self.base_postfix(smtpd_recipient_restrictions=chain)
        ctx = self.context(responses)
        checks.whitelist_checks(ctx, checks.postfix_checks(ctx))
        details = self.find(ctx, "WHITELIST.WIRING")[0]["details"]
        self.assertEqual(details["following_policy_services"], ["inet:127.0.0.1:10023", "inet:127.0.0.1:12340"])
        self.assertEqual(details["earlier_rejects"], ["reject_rbl_client", "reject_unlisted_recipient"])
        self.assertIn("все последующие policy", self.find(ctx, "WHITELIST.WIRING")[0]["next_step"])

    def test_map_after_first_policy_warns_without_claiming_earlier_bypass(self):
        chain = ("check_policy_service inet:127.0.0.1:10023, "
                 "check_client_access hash:/etc/postfix/clients, "
                 "check_policy_service inet:127.0.0.1:12340")
        ctx = self.context(self.base_postfix(smtpd_recipient_restrictions=chain))
        checks.whitelist_checks(ctx, checks.postfix_checks(ctx))
        item = self.find(ctx, "WHITELIST.WIRING")[0]
        self.assertEqual(item["status"], "WARN")
        self.assertEqual(item["details"]["preceding_policy_services"], ["inet:127.0.0.1:10023"])
        self.assertEqual(item["details"]["following_policy_services"], ["inet:127.0.0.1:12340"])
        self.assertIn("не отменяет уже выполненные", item["next_step"])

    def test_map_before_rbl_reject_describes_bypass_scope(self):
        chain = "check_client_access hash:/etc/postfix/clients, reject_rbl_client zen.spamhaus.org, reject_unlisted_recipient, check_policy_service inet:127.0.0.1:10023"
        ctx = self.context(self.base_postfix(smtpd_recipient_restrictions=chain))
        checks.whitelist_checks(ctx, checks.postfix_checks(ctx))
        item = self.find(ctx, "WHITELIST.WIRING")[0]
        self.assertEqual(item["status"], "WARN")
        self.assertEqual(item["details"]["following_rejects"], ["reject_rbl_client", "reject_unlisted_recipient"])
        self.assertIn("reject/defer restrictions тоже могут быть обойдены", item["next_step"])

    def test_postgrey_domain_whitelist_independent_of_postfix_maps(self):
        self.write("/etc/postgrey/custom_clients", "partner.example\n")
        responses = self.base_postfix()
        responses[("systemctl", "show", "postgrey", "--property=ExecStart", "--value")] = Result(stdout="argv[]=/usr/sbin/postgrey --whitelist-clients=/etc/postgrey/custom_clients ;")
        responses[("systemctl", "show", "postgrey", "--property=LoadState,ActiveState,SubState", "--value")] = Result(stdout="loaded\nactive\nrunning\n")
        ctx = self.context(responses, client_name="mx.partner.example")
        checks.whitelist_checks(ctx, checks.postfix_checks(ctx))
        result = self.find(ctx, "WHITELIST.RESULT")[0]
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["details"]["matches"][0]["layer"], "postgrey")
        self.assertEqual(result["details"]["applicable_postfix_maps"], 0)

    def test_postgrey_regex_is_not_executed_or_misreported(self):
        self.write("/etc/postgrey/custom_clients", "/(?{ system('touch MARKER') })/\n")
        ctx = self.context({("systemctl", "show", "postgrey", "--property=ExecStart", "--value"): Result(stdout="--whitelist-clients=/etc/postgrey/custom_clients")}, client_name="mx.partner.example")
        matches, uncertain = checks.postgrey_whitelist_checks(ctx, "mx.partner.example", None)
        self.assertFalse(matches)
        self.assertTrue(uncertain)
        self.assertFalse(self.root.joinpath("MARKER").exists())

    def test_postgrey_inactive_does_not_prove_effective_whitelist(self):
        self.write("/etc/postgrey/custom_clients", "partner.example\n")
        responses = {("systemctl", "show", "postgrey", "--property=ExecStart", "--value"): Result(stdout="--whitelist-clients=/etc/postgrey/custom_clients"),
                     ("systemctl", "show", "postgrey", "--property=LoadState,ActiveState,SubState", "--value"): Result(stdout="loaded\ninactive\ndead\n")}
        ctx = self.context(responses, client_name="mx.partner.example")
        matches, uncertain = checks.postgrey_whitelist_checks(ctx, "mx.partner.example", None)
        self.assertFalse(matches)
        self.assertTrue(uncertain)
        self.assertEqual(self.find(ctx, "WHITELIST.POSTGREY_MATCH")[0]["status"], "UNKNOWN")

    def test_postgrey_two_octet_legacy_rule_is_unknown_not_false_allow(self):
        self.write("/etc/postgrey/custom_clients", "198.51\n")
        responses = {("systemctl", "show", "postgrey", "--property=ExecStart", "--value"): Result(stdout="--whitelist-clients=/etc/postgrey/custom_clients"),
                     ("systemctl", "show", "postgrey", "--property=LoadState,ActiveState,SubState", "--value"): Result(stdout="loaded\nactive\nrunning\n")}
        ctx = self.context(responses)
        matches, uncertain = checks.postgrey_whitelist_checks(ctx, "", checks.ipaddress.ip_address("198.51.1.2"))
        self.assertFalse(matches)
        self.assertTrue(uncertain)
        self.assertTrue(self.find(ctx, "WHITELIST.POSTGREY_FILE")[0]["details"]["regex_rules_unmodeled"])

    def test_postgrey_three_octet_rule_is_a_24_network(self):
        self.write("/etc/postgrey/custom_clients", "198.51.100\n")
        responses = {("systemctl", "show", "postgrey", "--property=ExecStart", "--value"): Result(stdout="--whitelist-clients=/etc/postgrey/custom_clients"),
                     ("systemctl", "show", "postgrey", "--property=LoadState,ActiveState,SubState", "--value"): Result(stdout="loaded\nactive\nrunning\n")}
        ctx = self.context(responses)
        matches, uncertain = checks.postgrey_whitelist_checks(ctx, "", checks.ipaddress.ip_address("198.51.100.2"))
        self.assertEqual(len(matches), 1)
        self.assertFalse(uncertain)

    def test_inferred_postgrey_file_without_match_remains_unknown(self):
        self.write("/etc/postgrey/whitelist_clients.local", "different.example\n")
        ctx = self.context(client_name="mx.partner.example")
        matches, uncertain = checks.postgrey_whitelist_checks(ctx, "mx.partner.example", None)
        self.assertFalse(matches)
        self.assertTrue(uncertain)
        self.assertEqual(self.find(ctx, "WHITELIST.POSTGREY_FILE")[0]["status"], "UNKNOWN")

    def test_sensitive_map_is_not_read_or_queried(self):
        self.write("/etc/postfix/sasl_passwd", "smtp.example SECRET\n")
        ctx = self.context(self.base_postfix(smtpd_recipient_restrictions="check_client_access hash:/etc/postfix/sasl_passwd"), client_name="mx.partner.example")
        checks.whitelist_checks(ctx, checks.postfix_checks(ctx))
        self.assertFalse(any(c[0] == "postmap" for c in ctx.runner.history))
        self.assertNotIn("SECRET", json.dumps(ctx.findings))

    def test_dns_states_and_dnsbl_service_codes(self):
        for state in ("NXDOMAIN", "SERVFAIL", "REFUSED"):
            result = Result(stdout=";; ->>HEADER<<- opcode: QUERY, status: " + state + ", id: 1\n")
            self.assertEqual(checks.parse_dns(result, "A")[0], state)
        self.assertEqual(checks.parse_dns(Result(stdout=";; status: NOERROR\n"), "A")[0], "NODATA")
        self.assertEqual(checks.parse_dns(Result(9, stderr="no servers could be reached"), "A")[0], "TIMEOUT")
        self.assertEqual(checks.dnsbl_state("NXDOMAIN", [], "ip"), ("OK", "not_listed"))
        self.assertEqual(checks.dnsbl_state("SERVFAIL", [], "ip")[0], "UNKNOWN")
        self.assertEqual(checks.dnsbl_state("NOERROR", ["127.255.255.254"], "ip")[0], "UNKNOWN")
        self.assertEqual(checks.dnsbl_state("NOERROR", ["127.0.0.2"], "ip"), ("WARN", "listed"))
        self.assertEqual(checks.dnsbl_state("NOERROR", ["127.0.1.255"], "domain")[0], "UNKNOWN")
        for code in (250, 251, 252, 253, 254, 255):
            self.assertEqual(checks.dnsbl_state("NOERROR", ["127.255.255." + str(code)], "ip")[0], "UNKNOWN")
        for code in (5, 6, 7, 8, 30):
            self.assertEqual(checks.dnsbl_state("NOERROR", ["127.0.0." + str(code)], "ip")[0], "UNKNOWN")

    def test_dnsbl_public_resolver_all_nxdomain_is_unknown(self):
        ctx = self.context()
        ctx.runner.default = Result(stdout=";; status: NXDOMAIN\n")
        checks._dnsbl(ctx, "2.100.51.198.zen.spamhaus.org", "ip", family=4)
        item = self.find(ctx, "DNSBL.IP")[0]
        self.assertEqual(item["status"], "UNKNOWN")
        self.assertEqual(item["details"]["outcome"], "operational_controls_failed")

    def test_dnsbl_both_controls_required_for_negative_and_positive_conclusions(self):
        positive = "test.dbl.spamhaus.org"
        negative = "example.com.dbl.spamhaus.org"
        target = "sender.example.dbl.spamhaus.org"
        yes = Result(stdout=";; status: NOERROR\n" + positive + ". 60 IN A 127.0.1.2\n")
        no = Result(stdout=";; status: NXDOMAIN\n")
        responses = {tuple(checks._dig(positive, "A")): yes,
                     tuple(checks._dig(negative, "A")): no,
                     tuple(checks._dig(target, "A")): no}
        ctx = self.context(responses)
        checks._dnsbl(ctx, target, "domain")
        self.assertEqual(self.find(ctx, "DNSBL.DOMAIN")[0]["status"], "OK")
        self.assertTrue(self.find(ctx, "DNSBL.DOMAIN")[0]["details"]["operational_controls_passed"])
        responses[tuple(checks._dig(target, "A"))] = Result(stdout=";; status: NOERROR\n" + target + ". 60 IN A 127.0.1.2\n")
        responses[tuple(checks._dig(negative, "A"))] = Result(stdout=";; status: NOERROR\n" + negative + ". 60 IN A 127.0.1.2\n")
        ctx = self.context(responses)
        checks._dnsbl(ctx, target, "domain")
        self.assertEqual(self.find(ctx, "DNSBL.DOMAIN")[0]["status"], "UNKNOWN")

    def test_spamhaus_error_codes_are_named_and_never_listed(self):
        for kind in ("ip", "domain"):
            for code, outcome in (("252", "zone_name_error"), ("254", "public_resolver_blocked"), ("255", "query_limit_exceeded")):
                with self.subTest(kind=kind, code=code):
                    self.assertEqual(checks.dnsbl_state("NOERROR", ["127.255.255." + code], kind), ("UNKNOWN", outcome))
        self.assertEqual(checks.dnsbl_state("NOERROR", ["127.0.1.255"], "domain"), ("UNKNOWN", "ip_query_on_domain_list"))
        self.assertEqual(checks.dnsbl_state("NOERROR", ["127.0.1.255"], "ip")[1], "service_or_unrecognized_response")
        self.assertEqual(checks.dnsbl_state("NOERROR", ["127.0.0.2", "127.255.255.254"], "ip"), ("UNKNOWN", "mixed_error_response"))
        self.assertEqual(checks.dnsbl_state("NOERROR", ["127.255.255.253"], "ip")[1], "service_or_unrecognized_response")
        self.assertEqual(checks.dnsbl_state("NOERROR", ["127.0.0.2", "127.0.0.4", "127.0.0.10"], "ip"), ("WARN", "listed"))

    def test_public_resolver_refusal_is_a_confirmed_control_warning(self):
        ctx = self.context()
        ctx.runner.default = Result(stdout=";; status: NOERROR\nx. 60 IN A 127.255.255.254\n")
        checks._dnsbl(ctx, "2.100.51.198.zen.spamhaus.org", "ip", family=4)
        target = self.find(ctx, "DNSBL.IP")[0]
        self.assertEqual((target["status"], target["details"]["outcome"]), ("UNKNOWN", "public_resolver_blocked"))
        self.assertIn("127.255.255.254", target["next_step"])
        control = self.find(ctx, "DNSBL.CONTROL.IP")[0]
        self.assertEqual(control["status"], "WARN")
        self.assertEqual(control["details"]["operator_error"], "public_resolver_blocked")
        self.assertIn("bind9", control["next_step"])
        self.assertFalse(control["details"]["positive_ok"])

    def test_rate_limited_target_with_passing_controls_stays_unknown(self):
        positive, negative = "2.0.0.127.zen.spamhaus.org", "1.0.0.127.zen.spamhaus.org"
        target = "2.100.51.198.zen.spamhaus.org"
        responses = {tuple(checks._dig(positive, "A")): Result(stdout=";; status: NOERROR\n" + positive + ". 60 IN A 127.0.0.2\n"),
                     tuple(checks._dig(negative, "A")): Result(stdout=";; status: NXDOMAIN\n"),
                     tuple(checks._dig(target, "A")): Result(stdout=";; status: NOERROR\n" + target + ". 60 IN A 127.255.255.255\n")}
        ctx = self.context(responses)
        checks._dnsbl(ctx, target, "ip", family=4)
        self.assertEqual(self.find(ctx, "DNSBL.CONTROL.IP")[0]["status"], "OK")
        item = self.find(ctx, "DNSBL.IP")[0]
        self.assertEqual((item["status"], item["details"]["outcome"]), ("UNKNOWN", "query_limit_exceeded"))
        self.assertTrue(item["details"]["operational_controls_passed"])

    def test_postfix_reply_filter_syntax(self):
        cases = (("127.0.0.[2..11]", "127.0.0.10", True), ("127.0.0.[2..11]", "127.255.255.254", False),
                 ("127.0.0.[2;4;9..11]", "127.0.0.4", True), ("127.0.0.[2;4;9..11]", "127.0.0.5", False),
                 ("127.0.1.[2..99]", "127.0.1.255", False), ("127.[0..255].[0..255].[0..255]", "127.255.255.255", True),
                 ("127.0.0.2", "127.0.0.2", True), ("127.0.0.[x]", "127.0.0.2", None), ("127.0.0", "127.0.0.2", None),
                 ("127.0.0.[2...4]", "127.0.0.2", None))
        for pattern, address, expected in cases:
            with self.subTest(pattern=pattern, address=address):
                self.assertIs(checks.rbl_filter_matches(pattern, address), expected)

    def test_unfiltered_spamhaus_zone_in_postfix_would_reject_on_error_codes(self):
        chain = ("permit_sasl_authenticated, reject_rbl_client zen.spamhaus.org, "
                 "reject_rbl_client bl.example.net, reject_unlisted_recipient")
        responses = self.base_postfix(smtpd_recipient_restrictions=chain,
                                      smtpd_sender_restrictions="reject_rhsbl_sender dbl.spamhaus.org=127.0.1.[2..255]")
        responses[("postconf", "-P")] = Result(stdout="submission/inet/smtpd_recipient_restrictions = " + chain + "\n")
        ctx = self.context(responses)
        checks.dnsbl_filter_checks(ctx, checks.postfix_checks(ctx))
        items = {f["details"].get("zone"): f for f in self.find(ctx, "DNSBL.POSTFIX_FILTER")}
        self.assertEqual(set(items), {"zen.spamhaus.org", "dbl.spamhaus.org"})
        zen = items["zen.spamhaus.org"]
        self.assertEqual(zen["status"], "WARN")
        self.assertEqual(zen["details"]["error_codes_accepted"], ["127.255.255.252", "127.255.255.254", "127.255.255.255"])
        self.assertEqual(zen["details"]["contexts"], ["global/smtpd_recipient_restrictions", "submission/inet/smtpd_recipient_restrictions"])
        self.assertEqual(items["dbl.spamhaus.org"]["details"]["error_codes_accepted"], ["127.0.1.255"])

    def test_miab_reply_filters_pass_and_dqs_zone_is_not_judged(self):
        responses = self.base_postfix(
            smtpd_sender_restrictions="reject_non_fqdn_sender, reject_rhsbl_sender dbl.spamhaus.org=127.0.1.[2..99]",
            smtpd_recipient_restrictions="permit_sasl_authenticated, reject_rbl_client zen.spamhaus.org=127.0.0.[2..11], "
                                         "reject_rbl_client abcdefghijk123456789.zen.dq.spamhaus.net")
        ctx = self.context(responses)
        checks.dnsbl_filter_checks(ctx, checks.postfix_checks(ctx))
        items = self.find(ctx, "DNSBL.POSTFIX_FILTER")
        self.assertEqual([(f["details"]["zone"], f["status"]) for f in items], [("zen.spamhaus.org", "OK"), ("dbl.spamhaus.org", "OK")])
        self.assertNotIn("abcdefghijk123456789", json.dumps(ctx.findings))

    def test_postfix_filter_without_spamhaus_or_readable_chains(self):
        ctx = self.context(self.base_postfix(smtpd_recipient_restrictions="reject_rbl_client bl.example.net"))
        checks.dnsbl_filter_checks(ctx, checks.postfix_checks(ctx))
        self.assertEqual([f["status"] for f in self.find(ctx, "DNSBL.POSTFIX_FILTER")], ["N/A"])
        ctx = self.context()
        checks.dnsbl_filter_checks(ctx, checks.postfix_checks(ctx))
        self.assertEqual([f["status"] for f in self.find(ctx, "DNSBL.POSTFIX_FILTER")], ["UNKNOWN"])

    def test_postfix_chroot_resolver_is_checked_separately(self):
        self.write("/etc/resolv.conf", "nameserver 127.0.0.1\n")
        self.write("/var/spool/postfix/etc/resolv.conf", "nameserver 127.0.0.2\n")
        ctx = self.context({("postconf", "-M"): Result(stdout="smtp inet n - y - - smtpd\n")}, network=True, domain="example.org")
        ctx.postconf["queue_directory"] = "/var/spool/postfix"
        ctx.runner.default = Result(stdout=";; status: SERVFAIL\n")
        checks.dns_checks(ctx)
        results = self.find(ctx, "DNS.RESOLVER_QUERY")
        self.assertEqual({r["details"]["resolver"] for r in results}, {"127.0.0.1", "127.0.0.2"})
        self.assertEqual(self.find(ctx, "DNS.RESOLVER_DIFFERENCE")[0]["status"], "WARN")
        self.assertTrue(any("@127.0.0.2" in command for command in ctx.runner.history))

    def test_no_network_flag_means_no_dns_tls_http_process(self):
        self.write("/etc/resolv.conf", "nameserver 127.0.0.53\n")
        ctx = self.context()
        checks.dns_checks(ctx)
        checks.tls_checks(ctx)
        ctx.miab = True
        checks.post_update_checks(ctx)
        self.assertFalse(any(c[0] in {"dig", "openssl", "curl"} for c in ctx.runner.history))
        self.assertEqual(self.find(ctx, "NETWORK.PROBES")[0]["status"], "N/A")

    def test_real_local_resolver_servfail_and_no_guessed_dkim(self):
        self.write("/etc/resolv.conf", "nameserver 127.0.0.1\n")
        failure = Result(stdout=";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1\n")
        ctx = self.context(network=True, domain="example.org")
        ctx.runner.default = failure
        checks.dns_checks(ctx)
        self.assertEqual(self.find(ctx, "DNS.RESOLVER_QUERY")[0]["status"], "FAIL")
        self.assertTrue(any("@127.0.0.1" in cmd for cmd in ctx.runner.history))
        self.assertEqual(self.find(ctx, "DNS.DKIM")[0]["status"], "UNKNOWN")
        self.assertFalse(any("_domainkey" in " ".join(cmd) for cmd in ctx.runner.history))
        self.assertEqual(self.find(ctx, "DNSBL.DOMAIN")[0]["status"], "UNKNOWN")

    def test_ipv6_ptr_and_dnsbl_are_independent_from_ipv4(self):
        ctx = self.context(network=True, domain="example.org")
        ctx.postconf["myhostname"] = "box.example.org"
        ctx.metadata.update(PUBLIC_IP="198.51.100.2", PUBLIC_IPV6="2001:db8::2")
        ctx.runner.default = Result(stdout=";; status: NXDOMAIN\n")
        checks.dns_checks(ctx)
        self.assertEqual(len(self.find(ctx, "DNSBL.IP")), 1)
        self.assertEqual(len(self.find(ctx, "DNSBL.IPV6")), 1)
        ipv6 = self.find(ctx, "DNSBL.IPV6")[0]
        self.assertEqual(ipv6["details"]["family"], 6)
        self.assertTrue(ipv6["details"]["query"].startswith("2.0.0.0."))
        self.assertEqual(self.find(ctx, "DNS.PTR_IPV6")[0]["details"]["address"], "2001:db8::2")
        self.assertTrue(any("ip6.arpa" in argument for command in ctx.runner.history for argument in command))

    def test_each_tls_port_has_its_own_unknown_when_client_cannot_probe(self):
        ctx = self.context(network=True)
        ctx.postconf["myhostname"] = "box.example.org"
        ctx.runner.default = Result(1, stderr="no protocols available: local crypto policy")
        checks.tls_checks(ctx)
        self.assertEqual({f["details"]["port"] for f in ctx.findings}, {25, 587, 465, 993, 443})
        self.assertTrue(all(f["status"] == "UNKNOWN" for f in ctx.findings))
        self.assertFalse(any(c in {"MAIL", "RCPT", "DATA", "AUTH"} for cmd in ctx.runner.history for c in cmd))

    def test_successful_tls_checks_all_ports_and_uses_private_temp_certificate(self):
        ctx = self.context(network=True)
        ctx.postconf["myhostname"] = "box.example.org"
        ctx.runner.default = Result(stdout="-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\nVerify return code: 0 (ok)\n")
        paths = []
        def decode(path):
            paths.append(path)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(str(Path(path).parent)).st_mode & 0o777, 0o700)
            return {"notAfter": "Jan  1 00:00:00 2039 GMT"}
        with mock.patch.object(checks.ssl._ssl, "_test_decode_cert", side_effect=decode):
            checks.tls_checks(ctx)
        self.assertEqual(len(ctx.findings), 5)
        self.assertTrue(all(f["status"] == "OK" for f in ctx.findings))
        self.assertTrue(all(not Path(path).exists() for path in paths))

    def test_hold_retained_historical_update_error_not_mail_failure(self):
        self.write("/var/log/apt/term.log", "The following held packages will be changed: duplicity\nE: Held packages were changed and -y was used without --allow-change-held-packages.\n")
        ctx = self.context({("apt-mark", "showhold"): Result(stdout="duplicity\n"),
                            ("dpkg-query", "-W", "-f=${Version}\n", "duplicity"): Result(stdout="3.0.5.1-ppa202506251611~ubuntu22.04.1\n"),
                            ("duplicity", "--version"): Result(stdout="duplicity 3.0.5.1 June 25, 2025\n")})
        checks.backup_checks(ctx)
        self.assertTrue(self.find(ctx, "BACKUP.TOOLING")[0]["details"]["held"])
        conflict = self.find(ctx, "UPDATE.HELD_PACKAGE_CONFLICT")[0]
        self.assertEqual(conflict["status"], "WARN")
        self.assertTrue(conflict["details"]["historical"])
        self.assertFalse(any("unhold" in cmd or "--allow-change-held-packages" in cmd for cmd in ctx.runner.history))

    def test_backup_directory_mtime_never_proves_last_success(self):
        self.write("/home/user-data/backup/encrypted/duplicity-full.20261102T000000Z.manifest.gpg", "fixture")
        ctx = self.context()
        checks.backup_checks(ctx)
        result = self.find(ctx, "BACKUP.LAST_SUCCESS")[0]
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertFalse(result["details"]["success_proven"])

    def test_apt_different_transactions_do_not_create_false_duplicity_conflict(self):
        text = ("Log started: 2026-11-01 10:00:00\nSetting up duplicity (3.0.5.1) ...\nLog ended: 2026-11-01 10:00:01\n"
                "Log started: 2026-11-02 10:00:00\nThe following held packages will be changed:\n  linux-image-generic\n"
                "E: Held packages were changed and -y was used without --allow-change-held-packages.\nLog ended: 2026-11-02 10:00:01\n")
        self.assertEqual(checks._held_duplicity_conflicts(text), ([], []))
        self.write("/var/log/apt/term.log", text)
        ctx = self.context()
        checks.backup_checks(ctx)
        self.assertFalse(any(f["status"] == "WARN" for f in self.find(ctx, "UPDATE.HELD_PACKAGE_CONFLICT")))

    def test_apt_adjacent_package_change_block_proves_specific_held_conflict(self):
        text = ("Log started: 2026-11-02 10:00:00\nThe following held packages will be changed:\n  duplicity\n"
                "E: Held packages were changed and -y was used without --allow-change-held-packages.\nLog ended: 2026-11-02 10:00:01\n")
        confirmed, ambiguous = checks._held_duplicity_conflicts(text)
        self.assertEqual(confirmed, [4])
        self.assertFalse(ambiguous)

    def test_apt_ambiguous_error_is_unknown_candidate(self):
        text = "apt_install duplicity python3-pip\nE: Held packages were changed and -y was used without --allow-change-held-packages.\n"
        self.write("/var/log/apt/term.log", text)
        ctx = self.context()
        checks.backup_checks(ctx)
        item = self.find(ctx, "UPDATE.HELD_PACKAGE_CONFLICT")[0]
        self.assertEqual(item["status"], "UNKNOWN")
        self.assertTrue(item["details"]["candidate"])

    def test_runtime_route_and_yaml_comment_do_not_prove_reboot_persistence(self):
        self.write("/etc/netplan/01-network.yaml", "# to 203.0.113.9 via 198.51.100.1\nnetwork:\n  version: 2\n")
        ctx = self.context({("ip", "route", "get", "203.0.113.9"): Result(stdout="203.0.113.9 via 198.51.100.1 dev eth0 src 198.51.100.2\n"),
                            ("ip", "rule", "show"): Result(stdout="32766: from all lookup main\n")}, peer="203.0.113.9")
        checks.route_checks(ctx)
        runtime = self.find(ctx, "ROUTE.RUNTIME")[0]
        self.assertEqual(runtime["status"], "OK")
        self.assertEqual(runtime["details"]["interface"], "eth0")
        persistence = self.find(ctx, "ROUTE.PERSISTENCE")[0]
        self.assertEqual(persistence["status"], "UNKNOWN")
        self.assertIn("/etc/netplan/01-network.yaml", persistence["details"]["candidates"])

    def test_platform_metadata_is_read_without_shell_expansion_or_wrapper(self):
        self.write("/etc/os-release", 'ID=ubuntu\nVERSION_ID="22.04"\n')
        self.write("/etc/mailinabox.conf", "PRIMARY_HOSTNAME=box.example.org\nSTORAGE_ROOT=/home/user-data\nAPI_TOKEN=secret-token\nMALICIOUS=$(touch MARKER)\n")
        self.write("/root/mailinabox/.git/HEAD", "ref: refs/heads/main\n")
        self.write("/root/mailinabox/.git/refs/heads/main", "a"*40 + "\n")
        ctx = self.context()
        checks.platform_checks(ctx)
        self.assertEqual(self.find(ctx, "HOST.PLATFORM")[0]["status"], "OK")
        self.assertEqual(self.find(ctx, "HOST.MIAB_REVISION")[0]["status"], "OK")
        self.assertFalse(ctx.runner.history)
        self.assertNotIn("secret-token", json.dumps(ctx.findings))
        self.assertFalse(self.root.joinpath("MARKER").exists())

    def test_hostname_uptime_and_load_preserved_as_bounded_metadata(self):
        self.write("/etc/hostname", "box.example.org\n")
        self.write("/proc/uptime", "12345.12 567890.00\n")
        self.write("/proc/loadavg", "0.01 0.02 0.03 1/100 123\n")
        ctx = self.context()
        checks.platform_checks(ctx)
        item = self.find(ctx, "HOST.RUNTIME")[0]
        self.assertEqual(item["status"], "OK")
        self.assertEqual(item["details"]["hostname"], "box.example.org")
        self.assertEqual(item["details"]["uptime_seconds"], 12345.12)
        self.assertEqual(item["details"]["load_average"], [0.01, 0.02, 0.03])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "Unix FIFO test")
    def test_config_reader_rejects_fifo_without_blocking(self):
        path = self.root / "etc" / "hostname"
        path.parent.mkdir(parents=True)
        os.mkfifo(str(path))
        ctx = self.context()
        content, error = ctx.read("/etc/hostname")
        self.assertIsNone(content)
        self.assertIn("not a regular", error)

    def test_host_budget_exhaustion_does_not_execute_more_commands(self):
        ctx = self.context()
        ctx.deadline = 0
        result = ctx.run(["postqueue", "-j"])
        self.assertTrue(result.timed_out)
        self.assertTrue(ctx.budget_exhausted)
        self.assertFalse(ctx.runner.history)

    def test_spamhaus_dqs_key_in_restrictions_is_redacted(self):
        chain = "reject_rbl_client abcdefghijk123456789.zen.dq.spamhaus.net"
        ctx = self.context(self.base_postfix(smtpd_recipient_restrictions=chain))
        checks.postfix_checks(ctx)
        self.assertNotIn("abcdefghijk123456789", json.dumps(ctx.findings))
        self.assertIn("[DQS-key]", json.dumps(ctx.findings))

    def test_missing_optional_units_are_not_failures(self):
        command = ("systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager")
        ctx = self.context({command: Result(stdout="postfix.service enabled\ndovecot.service enabled\n")})
        checks.service_checks(ctx)
        self.assertEqual(self.find(ctx, "SERVICE.OPENDKIM")[0]["status"], "N/A")
        self.assertFalse(any(f["status"] == "FAIL" for f in ctx.findings))

    def test_service_partial_active_output_is_unknown(self):
        responses = {("systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"): Result(stdout="postfix.service enabled\n"),
                     ("systemctl", "show", "postfix", "--property=LoadState,ActiveState,SubState", "--value"): Result(stdout="active\n")}
        ctx = self.context(responses)
        checks.service_checks(ctx)
        self.assertEqual(self.find(ctx, "SERVICE.POSTFIX")[0]["status"], "UNKNOWN")
        self.assertIsNone(ctx.unit_states["postfix"])

    def test_systemd_named_and_unordered_values_are_accepted_only_when_complete(self):
        for text in ("ActiveState=active\nSubState=running\nLoadState=loaded\n", "active\nloaded\nrunning\n"):
            self.assertEqual(checks._unit_state(Result(stdout=text)), (True, True, False))
        self.assertEqual(checks._unit_state(Result(stdout="LoadState=loaded\nActiveState=active\n")), (False, False, False))

    def test_df_failure_does_not_become_free_disk(self):
        ctx = self.context()
        checks.disk_checks(ctx)
        self.assertEqual({f["status"] for f in ctx.findings}, {"UNKNOWN"})

    def test_host_collector_all_actions_pass_real_allowlist_with_no_external_execution(self):
        self.write("/etc/os-release", 'ID=ubuntu\nVERSION_ID="22.04"\n')
        self.write("/etc/mailinabox.conf", "PRIMARY_HOSTNAME=box.example.org\nPUBLIC_IP=198.51.100.2\n")
        self.write("/etc/resolv.conf", "nameserver 127.0.0.1\n")
        runner = FakeRunner(self.base_postfix())
        args = SimpleNamespace(root=str(self.root), mode="post-update", network=True, domain="example.org",
                               dkim_selector="selector1", peer="203.0.113.1", client_name="mx.partner.example", client_ip="198.51.100.9")
        results = checks.collect_checks(runner, args)
        self.assertGreater(len(results), 30)
        self.assertTrue(all(permitted(list(command)) for command in runner.history))
        self.assertFalse(any(command[0] in {"mailinabox", "bash", "sh", "apt", "postsuper"} for command in runner.history))
        self.assertFalse(any("restart" in command or "reload" in command for command in runner.history))

    @unittest.skipUnless(os.name == "posix", "POSIX fake executable fixture")
    def test_full_host_collector_never_executes_setup_wrapper_on_path(self):
        bindir = self.root / "bin"
        bindir.mkdir()
        marker = self.root / "wrapper-executed"
        wrapper = bindir / "mailinabox"
        wrapper.write_text("#!/bin/sh\nprintf forbidden > " + shlex.quote(str(marker)) + "\n", encoding="utf-8")
        wrapper.chmod(0o755)
        for name in ("postconf", "postqueue", "systemctl", "df", "ss", "sshd", "fail2ban-client", "dpkg-query", "apt-mark", "duplicity"):
            path = bindir / name
            path.write_text("#!/bin/sh\nexit 127\n", encoding="utf-8")
            path.chmod(0o755)
        args = SimpleNamespace(root=str(self.root), mode="doctor", network=False, domain=None,
                               peer=None, client_name=None, client_ip=None, dkim_selector=None)
        runner = Runner()
        try:
            with mock.patch.dict(os.environ, {"PATH": str(bindir)}):
                results = checks.collect_checks(runner, args)
        finally:
            runner.close()
        self.assertTrue(results)
        self.assertTrue(runner.history)
        self.assertFalse(marker.exists())
        self.assertTrue(all(c[0] != "mailinabox" for c in runner.history))


if __name__ == "__main__":
    unittest.main()
