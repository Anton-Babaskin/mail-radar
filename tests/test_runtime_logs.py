"""Operational regression cases found independently after the 4.0.1 release."""
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from mailradar.logs import analyze_logs


class RuntimeLogTests(unittest.TestCase):
    def analyze(self, text, filters=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mail.log"
            path.write_text(text, encoding="utf-8")
            return analyze_logs([str(path)], datetime(2026, 11, 2, 9, tzinfo=timezone.utc),
                                datetime(2026, 11, 2, 10, tzinfo=timezone.utc), filters=filters)

    def test_expiry_notification_removed_share_one_lifecycle(self):
        result = self.analyze(
            "2026-11-02T09:20:00Z box postfix/qmgr[1]: ABCDE: from=<sender@partner.example>, size=3, nrcpt=1 (queue active)\n"
            "2026-11-02T09:59:57Z box postfix/qmgr[1]: ABCDE: from=<sender@partner.example>, status=expired, returned to sender\n"
            "2026-11-02T09:59:58Z box postfix/bounce[2]: ABCDE: sender non-delivery notification: F1234\n"
            "2026-11-02T09:59:59Z box postfix/qmgr[1]: ABCDE: removed\n")
        self.assertEqual(result["statistics"]["queues"], 1)
        self.assertEqual(result["statistics"]["observed_messages"], 1)
        self.assertEqual(result["traces"][0]["outcome"], "expired")
        self.assertEqual([e["kind"] for e in result["traces"][0]["events"]],
                         ["accepted", "expired", "notification", "removed"])

    def test_repeated_removed_record_does_not_invent_a_new_message(self):
        result = self.analyze(
            "2026-11-02T09:20:00Z box postfix/qmgr[1]: ABCDE: from=<sender@partner.example>, size=3, nrcpt=1 (queue active)\n"
            "2026-11-02T09:20:01Z box postfix/qmgr[1]: ABCDE: removed\n"
            "2026-11-02T09:20:02Z box postfix/qmgr[1]: ABCDE: removed\n")
        self.assertEqual(result["statistics"]["queues"], 1)

    def test_same_queue_and_message_ids_reused_after_removal_stay_separate(self):
        lines = []
        for minute in (20, 30):
            lines.extend([
                "2026-11-02T09:%d:00Z box postfix/cleanup[2]: ABCDE: message-id=<repeated@partner.example>" % minute,
                "2026-11-02T09:%d:01Z box postfix/qmgr[1]: ABCDE: from=<sender@partner.example>, size=3, nrcpt=1 (queue active)" % minute,
                "2026-11-02T09:%d:02Z box postfix/qmgr[1]: ABCDE: from=<sender@partner.example>, status=expired, returned to sender" % minute,
                "2026-11-02T09:%d:03Z box postfix/qmgr[1]: ABCDE: removed" % minute])
        result = self.analyze("\n".join(lines) + "\n")
        self.assertEqual(result["statistics"]["queues"], 2)
        self.assertEqual([q["generation"] for q in result["traces"]], [1, 2])
        self.assertEqual([q["outcome"] for q in result["traces"]], ["expired", "expired"])

    def test_new_ingress_after_expiry_without_removed_is_separate(self):
        result = self.analyze(
            "2026-11-02T09:20:00Z box postfix/qmgr[1]: ABCDE: from=<old@partner.example>, size=3, nrcpt=1 (queue active)\n"
            "2026-11-02T09:20:01Z box postfix/qmgr[1]: ABCDE: status=expired, returned to sender\n"
            "2026-11-02T09:30:00Z box postfix/qmgr[1]: ABCDE: from=<new@partner.example>, size=3, nrcpt=1 (queue active)\n")
        self.assertEqual(result["statistics"]["queues"], 2)
        self.assertEqual([q["senders"] for q in result["traces"]],
                         [["old@partner.example"], ["new@partner.example"]])

    def test_same_id_in_adjacent_instances_keeps_expiry_tail_separate(self):
        result = self.analyze(
            "2026-11-02T09:20:00Z box postfix/qmgr[1]: ABCDE: from=<one@partner.example>, size=3, nrcpt=1 (queue active)\n"
            "2026-11-02T09:20:01Z box postfix-out/qmgr[2]: ABCDE: from=<two@partner.example>, size=3, nrcpt=1 (queue active)\n"
            "2026-11-02T09:20:02Z box postfix/qmgr[1]: ABCDE: status=expired, returned to sender\n"
            "2026-11-02T09:20:03Z box postfix-out/qmgr[2]: ABCDE: removed\n"
            "2026-11-02T09:20:04Z box postfix/qmgr[1]: ABCDE: removed\n")
        self.assertEqual(result["statistics"]["queues"], 2)
        self.assertEqual({q["instance"]: q["outcome"] for q in result["traces"]},
                         {"postfix": "expired", "postfix-out": "accepted"})

    def test_delivery_after_expiry_without_ingress_does_not_revive_old_message(self):
        result = self.analyze(
            "2026-11-02T09:20:00Z box postfix/qmgr[1]: ABCDE: from=<old@partner.example>, size=3, nrcpt=1 (queue active)\n"
            "2026-11-02T09:20:01Z box postfix/qmgr[1]: ABCDE: status=expired, returned to sender\n"
            "2026-11-02T09:30:00Z box postfix/smtp[2]: ABCDE: to=<new@remote.example>, relay=mx.remote.example[192.0.2.1]:25, delay=2, delays=1/0/0/1, dsn=2.0.0, status=sent (250 accepted)\n")
        self.assertEqual(result["statistics"]["queues"], 2)
        first, second = result["traces"]
        self.assertEqual(first["outcome"], "expired")
        self.assertEqual(first["senders"], ["old@partner.example"])
        self.assertEqual(second["outcome"], "next_smtp_accepted")
        self.assertEqual(second["senders"], [])
        filtered = self.analyze(
            "2026-11-02T09:20:00Z box postfix/qmgr[1]: ABCDE: from=<old@partner.example>, size=3, nrcpt=1 (queue active)\n"
            "2026-11-02T09:20:01Z box postfix/qmgr[1]: ABCDE: status=expired, returned to sender\n"
            "2026-11-02T09:30:00Z box postfix/smtp[2]: ABCDE: to=<new@remote.example>, relay=mx.remote.example[192.0.2.1]:25, delay=2, delays=1/0/0/1, dsn=2.0.0, status=sent (250 accepted)\n",
            {"from": "old@partner.example"})
        self.assertEqual(filtered["statistics"]["queues"], 1)
        self.assertEqual(filtered["statistics"]["delivery_attempts"], 0)

    def test_trace_long_queue_ids_are_case_sensitive(self):
        upper, lower = "4Xp2kT0bcDz12345", "4xp2kT0bcdz12345"
        text = ("2026-11-02T09:20:00Z box postfix/qmgr[1]: %s: from=<one@partner.example>, size=3, nrcpt=1 (queue active)\n" % upper
                + "2026-11-02T09:20:01Z box postfix/qmgr[1]: %s: from=<two@partner.example>, size=3, nrcpt=1 (queue active)\n" % lower)
        for requested, sender in ((upper, "one@partner.example"), (lower, "two@partner.example")):
            with self.subTest(requested=requested):
                result = self.analyze(text, {"trace": requested})
                self.assertEqual(result["statistics"]["queues"], 1)
                self.assertEqual(result["traces"][0]["queue_id"], requested)
                self.assertEqual(result["traces"][0]["senders"], [sender])

    def test_message_id_search_is_case_sensitive_but_domain_filter_is_not(self):
        text = ("2026-11-02T09:20:00Z box postfix/cleanup[1]: ABCDE: message-id=<CaseSensitive@partner.example>\n"
                "2026-11-02T09:20:01Z box postfix/qmgr[1]: ABCDE: from=<sender@partner.example>, size=3, nrcpt=1 (queue active)\n")
        for filters in ({"message_id": "<casesensitive@partner.example>"}, {"trace": "<casesensitive@partner.example>"}):
            with self.subTest(filters=filters):
                self.assertEqual(self.analyze(text, filters)["statistics"]["queues"], 0)
        self.assertEqual(self.analyze(text, {"domain": "PARTNER.EXAMPLE"})["statistics"]["queues"], 1)


if __name__ == "__main__":
    unittest.main()
