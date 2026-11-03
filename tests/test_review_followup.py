"""Regressions for the remaining DNSBL and structured-log review findings."""
import contextlib
from datetime import datetime, timezone
import io
from pathlib import Path
import tempfile
import unittest

from mailradar import checks, cli
from mailradar.logs import analyze_logs
from mailradar.runner import Result, Runner, permitted
from test_checks import FakeRunner


class ReviewFollowupTests(unittest.TestCase):
    def context(self, sites, threshold="1", action="enforce", master=None, overrides=""):
        runner = FakeRunner({("postconf", "-M"): Result(stdout=master if master is not None else "smtp inet n - n - 1 postscreen\n"),
                             ("postconf", "-P"): Result(stdout=overrides)})
        ctx = checks.Context(runner, cli.parser().parse_args([]))
        ctx.postconf.update(postscreen_dnsbl_sites=sites, postscreen_dnsbl_threshold=threshold, postscreen_dnsbl_action=action, postscreen_dnsbl_allowlist_threshold="0")
        return ctx

    def test_domain_rejects_ip_literals_before_any_probe(self):
        for address in ("192.0.2.5", "192.0.2.5.", "2001:db8::1", "::ffff:192.0.2.5"):
            with self.subTest(address=address), contextlib.redirect_stderr(io.StringIO()) as err:
                parser = cli.parser()
                with self.assertRaises(SystemExit) as raised:
                    cli.validate(parser, parser.parse_args(["--domain", address]))
                self.assertEqual(raised.exception.code, 2)
                self.assertIn("--ip", err.getvalue())

    def test_dqs_codes_are_classified_without_public_mirror_meanings(self):
        for octet in (0, 250, 251, 252, 254, 255):
            self.assertEqual(checks.dnsbl_state("NOERROR", ["127.255.255." + str(octet)], "ip", "dqs"), ("UNKNOWN", "dqs_error_response"))
        self.assertEqual(checks.dnsbl_state("NOERROR", ["127.0.0.2", "127.0.1.102"], "domain", "dqs"), ("WARN", "listed"))
        for replies in (["127.0.1.255"], ["127.0.0.2", "127.255.255.250"], ["192.0.2.1"], ["malformed"]):
            self.assertEqual(checks.dnsbl_state("NOERROR", replies, "domain", "dqs")[0], "UNKNOWN")

    def test_filter_validation_does_not_accept_invalid_octets_or_ranges(self):
        for pattern in ("127.0.0.[11..2]", "127.0.0.999", "127.0.999.2", "127.0.0.[2;]", "127.0.0.[]", "127.0.0.[" + "9" * 5000 + "]"):
            self.assertIsNone(checks.rbl_filter_matches(pattern, "127.255.255.254"))
        for port in ("0", "65536", "-1", "53;id", "--output"):
            self.assertFalse(permitted(["dig", "example.org", "A", "-p", port]))
        self.assertTrue(permitted(["dig", "example.org", "A", "-p", "5300"]))
        with self.assertRaises(ValueError):
            Runner(network=False).run(["dig", "example.org", "A", "-p", "5300"])

    def test_postscreen_weights_count_once_and_preserve_threshold_context(self):
        ctx = self.context("zen.spamhaus.org*2, dbl.spamhaus.org=127.0.1.[2..99]*1", threshold="3")
        checks.postscreen_dnsbl_checks(ctx)
        item = ctx.findings[0]
        self.assertEqual(item["status"], "WARN")  # even a partial error score can combine with another listing
        self.assertEqual(item["details"]["maximum_positive_error_score"], 2)
        self.assertFalse(item["details"]["errors_alone_may_reach_threshold"])
        ctx = self.context("zen.spamhaus.org*2, dbl.spamhaus.org*1", threshold="3", action="drop")
        checks.postscreen_dnsbl_checks(ctx)
        self.assertEqual(ctx.findings[0]["details"]["maximum_positive_error_score"], 3)
        self.assertTrue(ctx.findings[0]["details"]["errors_alone_may_reach_threshold"])

    def test_postscreen_ignore_inactive_negative_weight_and_override(self):
        for ctx, status in ((self.context("zen.spamhaus.org", action="ignore"), "OK"),
                            (self.context("zen.spamhaus.org", master="smtp inet n - n - - smtpd\n"), "N/A"),
                            (self.context("key.zen.dq.spamhaus.net*-2"), "WARN"),
                            (self.context("zen.spamhaus.org", overrides="smtp/inet/postscreen_dnsbl_sites=zen.spamhaus.org=127.0.0.[2..11]\n"), "OK"),
                            (self.context("zen.spamhaus.org*bad"), "UNKNOWN")):
            with self.subTest(status=status):
                checks.postscreen_dnsbl_checks(ctx)
                self.assertEqual(ctx.findings[0]["status"], status)
                self.assertNotIn("key.zen", str(ctx.findings))

    def test_dqs_filters_helo_data_and_indirect_coverage(self):
        ctx = self.context("")
        contexts = {"global": {"smtpd_helo_restrictions": "reject_rhsbl_helo key.dbl.dq.spamhaus.net=127.0.1.[2..99]",
                               "smtpd_data_restrictions": "reject_rbl_client key.zen.dq.spamhaus.net=127.255.255.250, check_client_access hash:/etc/postfix/clients"}}
        checks.dnsbl_filter_checks(ctx, contexts)
        filters = [f for f in ctx.findings if f["id"] == "DNSBL.POSTFIX_FILTER"]
        self.assertEqual(sorted(f["status"] for f in filters), ["OK", "WARN"])
        self.assertIn("DNSBL.INDIRECT_COVERAGE", [f["id"] for f in ctx.findings])
        self.assertNotIn("key.zen", str(ctx.findings))
        self.assertNotIn("key.dbl", str(ctx.findings))

    def test_postscreen_error_allowlisting_applies_even_with_ignore(self):
        ctx = self.context("key.sbl-xbl.dq.spamhaus.net*-2", action="ignore")
        ctx.postconf["postscreen_dnsbl_allowlist_threshold"] = "-1"
        checks.postscreen_dnsbl_checks(ctx)
        self.assertEqual(ctx.findings[0]["status"], "WARN")
        self.assertNotIn("key.sbl-xbl", str(ctx.findings))

    def test_postfix_reads_additional_chains_and_master_overrides(self):
        responses = {("postconf", "-h", key): Result(stdout="") for key in checks._PARAMS}
        responses[("postconf", "-P")] = Result(stdout="submission/inet/smtpd_helo_restrictions=reject_rhsbl_helo dbl.spamhaus.org\nsubmission/inet/smtpd_restriction_classes=custom_rbl\n")
        ctx = checks.Context(FakeRunner(responses), cli.parser().parse_args([]))
        contexts = checks.postfix_checks(ctx)
        self.assertIn("smtpd_data_restrictions", contexts["global"])
        self.assertEqual(contexts["submission/inet"]["smtpd_helo_restrictions"], "reject_rhsbl_helo dbl.spamhaus.org")
        checks.dnsbl_filter_checks(ctx, contexts)
        self.assertIn("DNSBL.INDIRECT_COVERAGE", [f["id"] for f in ctx.findings])
        self.assertTrue(all(permitted(list(cmd)) for cmd in ctx.runner.history))

    def test_policy_header_and_standalone_reply_do_not_invent_delivery(self):
        prefix = "2026-11-03T10:30:00Z box postfix/"
        lines = [prefix + "smtpd[1]: NOQUEUE: " + action + ': RCPT from unknown[192.0.2.5]: reason; text; from=<"a>b"@example.org> to=<office@local.example> proto=ESMTP helo=<x>' for action in ("filter", "hold", "discard")]
        lines += [prefix + "cleanup[2]: ABCDE: warning: header Subject: private status=sent queued as BCDEF from mx[192.0.2.5]; from=<a@example.org> to=<office@local.example>",
                  prefix + "smtp[3]: ABCDE: host mx.example[192.0.2.6] said: 550 5.1.1 No such user (in reply to RCPT TO command)"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mail.log"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            report = analyze_logs([str(path)], datetime(2026, 11, 3, 10, tzinfo=timezone.utc), datetime(2026, 11, 3, 11, tzinfo=timezone.utc))
        self.assertEqual(report["completeness"]["unparsed_lines"], 0)
        self.assertEqual(report["statistics"]["prequeue_policy_actions"], {"filter": 1, "hold": 1, "discard": 1})
        self.assertEqual(report["statistics"]["delivery_attempts"], 0)
        self.assertEqual(report["statistics"]["accepted_queue_events"], 0)
        self.assertEqual(report["statistics"]["hold"], 0)
        self.assertEqual(report["statistics"]["outcomes"], {})
        self.assertNotIn("private status=sent", str(report))
        replies = [e for e in report["evidence"] if e["kind"] == "remote_reply"]
        self.assertEqual(replies[0]["dsn"], "5.1.1")
        self.assertNotIn("recipient", replies[0])
