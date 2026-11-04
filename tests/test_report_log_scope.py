"""Report-window scope without discarding queue context or hiding read losses."""
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from mailradar.logs import analyze_logs


class ReportLogScopeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "mail.log"
        self.since = datetime(2026, 11, 2, 9, tzinfo=timezone.utc)
        self.until = datetime(2026, 11, 2, 10, tzinfo=timezone.utc)

    def analyze(self, text, **kwargs):
        self.path.write_text(text, encoding="utf-8")
        return analyze_logs([str(self.path)], self.since, self.until, **kwargs)

    def current_saved(self):
        return (
            "2026-11-02T09:20:00Z box postfix/qmgr[1]: ABCDE: from=<sender@partner.example>, size=3, nrcpt=1 (queue active)\n"
            "2026-11-02T09:20:01Z box postfix/lmtp[2]: ABCDE: to=<office@local.example>, relay=dovecot, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 2.0.0 Saved)\n")

    def unsupported(self, stamp):
        return stamp + " box postfix/smtp[2]: F1234: to=<old@remote.example>, status=deferred (unsupported structured grammar)\n"

    def test_known_outside_window_grammar_failure_is_separate_context(self):
        text = self.unsupported("2026-11-02T08:30:00Z") + self.current_saved() + self.unsupported("2026-11-02T11:00:00Z")
        for recent in (False, True):
            with self.subTest(recent=recent):
                result = self.analyze(text, recent=recent)
                self.assertTrue(result["completeness"]["complete"])
                self.assertEqual(result["completeness"]["unparsed_lines"], 0)
                self.assertEqual(result["completeness"]["unparsed_context"], 2)
                self.assertEqual(result["sources"][0]["unparsed_context"], 2)
                self.assertNotIn("LOG-SOURCE-INCOMPLETE", [f["id"] for f in result["findings"]])
                self.assertFalse(result["completeness"]["window_coverage_proven"])

    def test_current_window_grammar_failure_still_incomplete(self):
        for stamp in ("2026-11-02T09:00:00Z", "2026-11-02T09:30:00Z", "2026-11-02T10:00:00Z"):
            with self.subTest(stamp=stamp):
                result = self.analyze(self.current_saved() + self.unsupported(stamp))
                self.assertFalse(result["completeness"]["complete"])
                self.assertEqual(result["completeness"]["unparsed_lines"], 1)
                self.assertEqual(result["completeness"]["unparsed_context"], 0)
                self.assertIn("LOG-SOURCE-INCOMPLETE", [f["id"] for f in result["findings"]])

    def test_unknown_or_invalid_timestamp_cannot_be_scoped_away(self):
        for line in ("no timestamp available\n", self.unsupported("2026-02-30T08:30:00Z")):
            with self.subTest(line=line):
                result = self.analyze(line + self.current_saved())
                self.assertFalse(result["completeness"]["complete"])
                self.assertEqual(result["completeness"]["unparsed_lines"], 1)
                self.assertEqual(result["completeness"]["unparsed_context"], 0)

    def test_pre_window_queue_context_is_retained_for_current_delivery(self):
        text = (
            "2026-11-02T08:59:00Z box postfix/cleanup[1]: ABCDE: message-id=<earlier@partner.example>\n"
            "2026-11-02T08:59:01Z box postfix/qmgr[1]: ABCDE: from=<sender@partner.example>, size=3, nrcpt=1 (queue active)\n"
            + self.unsupported("2026-11-02T08:59:02Z")
            + "2026-11-02T09:20:01Z box postfix/lmtp[2]: ABCDE: to=<office@local.example>, relay=dovecot, delay=1260, delays=1259/0/0/1, dsn=2.0.0, status=sent (250 2.0.0 Saved)\n")
        result = self.analyze(text, filters={"from": "sender@partner.example"})
        self.assertTrue(result["completeness"]["complete"])
        self.assertEqual(result["statistics"]["queues"], 1)
        self.assertEqual(result["traces"][0]["senders"], ["sender@partner.example"])
        self.assertEqual(result["traces"][0]["message_ids"], ["<earlier@partner.example>"])
        self.assertEqual([e["in_window"] for e in result["traces"][0]["events"]], [False, False, True])
        self.assertEqual(result["traces"][0]["outcome"], "saved")

    def test_raw_limits_stay_incomplete_even_when_first_events_are_old(self):
        old = "2026-11-02T08:30:00Z box postfix/qmgr[1]: F1234: removed\n"
        result = self.analyze(old * 20 + self.current_saved(), max_lines=1)
        self.assertTrue(result["completeness"]["truncated"])
        self.assertFalse(result["completeness"]["complete"])
        self.assertEqual(result["statistics"]["delivery_attempts"], 0)
        self.assertIn("LOG-SOURCE-INCOMPLETE", [f["id"] for f in result["findings"]])

    def test_missing_source_stays_unknown_with_valid_current_events(self):
        self.path.write_text(self.current_saved(), encoding="utf-8")
        result = analyze_logs([str(self.path), str(self.path.parent / "missing.log")], self.since, self.until)
        self.assertFalse(result["completeness"]["complete"])
        self.assertIn("LOG-SOURCE-INCOMPLETE", [f["id"] for f in result["findings"]])

    def test_address_groups_count_observed_events_not_messages(self):
        text = (
            "2026-11-02T08:30:00Z box postfix/qmgr[1]: F1234: from=<old@partner.example>, size=3, nrcpt=1 (queue active)\n"
            "2026-11-02T09:20:00Z box postfix/qmgr[1]: ABCDE: from=<sender@partner.example>, size=3, nrcpt=1 (queue active)\n"
            "2026-11-02T09:20:01Z box postfix/lmtp[2]: ABCDE: to=<office@local.example>, relay=none, delay=1, delays=0/0/0/1, dsn=4.3.0, status=deferred (temporary failure)\n"
            "2026-11-02T09:21:01Z box postfix/lmtp[2]: ABCDE: to=<office@local.example>, relay=dovecot, delay=61, delays=60/0/0/1, dsn=2.0.0, status=sent (250 2.0.0 Saved)\n"
            "2026-11-02T09:21:01Z box dovecot: lmtp(office@local.example)<123><session>: Info: msgid=<one@partner.example>: saved mail to INBOX\n")
        stats = self.analyze(text)["statistics"]
        self.assertEqual(stats["observed_sender_addresses"], {"sender@partner.example": 1})
        self.assertEqual(stats["observed_recipient_addresses"], {"office@local.example": 3})
        self.assertEqual(stats["address_group_basis"], "structured_events_in_window")
        self.assertEqual(stats["sender_address_count"], 1)
        self.assertEqual(stats["recipient_address_count"], 1)
        self.assertEqual(stats["observed_messages"], 1)

    def test_untrusted_header_text_cannot_create_address_groups(self):
        text = self.current_saved() + "2026-11-02T09:21:00Z box postfix/cleanup[1]: F1234: warning: header Subject: from=<forged@evil.example> to=<victim@evil.example>\n"
        stats = self.analyze(text)["statistics"]
        self.assertEqual(stats["observed_sender_addresses"], {"sender@partner.example": 1})
        self.assertEqual(stats["observed_recipient_addresses"], {"office@local.example": 1})


if __name__ == "__main__":
    unittest.main()
