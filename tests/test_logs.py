import bz2
from datetime import datetime
import gzip
import json
import lzma
import os
from pathlib import Path
import tempfile
import unittest

from mailradar.logs import analyze_logs


def utc(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class LogAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.since = utc("2026-11-02T09:00:00Z")
        self.until = utc("2026-11-02T10:00:00Z")

    def write(self, text, name="mail.log"):
        path = self.root / name
        data = text.encode("utf-8")
        if name.endswith(".gz"):
            data = gzip.compress(data)
        elif name.endswith(".bz2"):
            data = bz2.compress(data)
        elif name.endswith(".xz"):
            data = lzma.compress(data)
        path.write_bytes(data)
        return str(path)

    def analyze(self, text, **kwargs):
        return analyze_logs([self.write(text)], kwargs.pop("since", self.since),
                            kwargs.pop("until", self.until), **kwargs)

    def test_iso_offsets_and_syslog_same_utc_time(self):
        result = self.analyze(
            "2026-11-02T13:25:33+04:00 box postfix/qmgr[1]: ABCDE: from=<sender@partner.example>, size=3, nrcpt=1 (queue active)\n"
            "2026-11-02T09:25:34Z box postfix/cleanup[2]: ABCDE: message-id=<one@partner.example>\n"
            "Nov 02 13:25:36 box postfix/lmtp[3]: ABCDE: to=<office@local.example>, relay=dovecot, delay=2.9, delays=0.55/0.01/0.04/2.3, dsn=2.0.0, status=sent (250 2.0.0 Saved)\n",
            timezone="Asia/Dubai")
        self.assertEqual(result["statistics"]["delivery_attempts"], 1)
        trace = result["traces"][0]
        self.assertEqual(trace["events"][0]["time"], "2026-11-02T09:25:33+00:00")
        self.assertIn("saved", trace["outcomes"])
        self.assertEqual(trace["events"][-1]["delays"]["message_transmission"], 2.3)

    def test_new_year_and_explicit_historical_year(self):
        result = self.analyze(
            "Dec 31 23:59:59 box postfix/qmgr[1]: ABCDE: from=<sender@partner.example>, size=3, nrcpt=1 (queue active)\n"
            "Jan 01 00:00:01 box postfix/qmgr[1]: ABCDE: removed\n",
            since=utc("2025-12-31T23:00:00Z"), until=utc("2026-01-01T01:00:00Z"))
        self.assertEqual([e["time"][:4] for e in result["traces"][0]["events"]], ["2025", "2026"])
        result = self.analyze("Nov 02 09:25:33 box postfix/qmgr[1]: ABCDE: removed\n",
                              since=utc("2021-11-02T09:00:00Z"), until=utc("2021-11-02T10:00:00Z"), year=2021)
        self.assertEqual(result["statistics"]["queues"], 1)

    def test_explicit_year_forms(self):
        for stamp in ("2026 Nov 02 09:25:33", "Nov 02 2026 09:25:33", "Nov 02 09:25:33 2026"):
            with self.subTest(stamp=stamp):
                result = self.analyze(stamp + " box postfix/qmgr[1]: ABCDE: removed\n")
                self.assertEqual(result["statistics"]["queues"], 1)
                self.assertEqual(result["statistics"]["year_inferred_lines"], 0)

    def test_dst_fold_is_unknown_not_silently_selected(self):
        result = self.analyze("Nov 01 01:30:00 box postfix/qmgr[1]: ABCDE: removed\n",
                              since=utc("2026-11-01T00:00:00Z"), until=utc("2026-11-02T00:00:00Z"), timezone="America/New_York")
        self.assertFalse(result["completeness"]["complete"])
        self.assertEqual(result["completeness"]["unparsed_lines"], 1)

    def test_archives_sorted_and_overlap_preserves_real_repetition(self):
        first = "2026-11-02T09:20:00Z box postfix/smtp[2]: ABCDE: to=<one@remote.example>, relay=mx.remote.example[192.0.2.2]:25, delay=2, delays=1/0/0/1, dsn=4.4.1, status=deferred (connect timeout)\n"
        last = "2026-11-02T09:21:00Z box postfix/smtp[2]: ABCDE: to=<one@remote.example>, relay=mx.remote.example[192.0.2.2]:25, delay=62, delays=61/0/0/1, dsn=2.0.0, status=sent (250 accepted)\n"
        paths = [self.write(last, "z.log.xz"), self.write(first + first, "a.log.bz2"), self.write(first, "b.log.gz")]
        result = analyze_logs(paths, self.since, self.until)
        self.assertEqual(result["statistics"]["delivery_attempts"], 3)
        self.assertEqual(result["statistics"]["overlap_events_removed"], 1)
        self.assertEqual(result["traces"][0]["events"][0]["status"], "deferred")
        self.assertEqual(result["traces"][0]["events"][-1]["status"], "sent")

    def test_unreadable_missing_empty_and_truncated_are_unknown(self):
        missing = analyze_logs([str(self.root / "missing.log")], self.since, self.until)
        self.assertFalse(missing["completeness"]["complete"])
        self.assertIn("LOG-SOURCE-INCOMPLETE", [f["id"] for f in missing["findings"]])
        empty = self.analyze("")
        self.assertIn("LOG-NO-EVIDENCE", [f["id"] for f in empty["findings"]])
        limited = self.analyze("2026-11-02T09:25:33Z box postfix/qmgr[1]: ABCDE: removed\n" * 5, max_lines=1)
        self.assertTrue(limited["completeness"]["truncated"])
        self.assertFalse(limited["completeness"]["complete"])
        bomb = analyze_logs([self.write("x" * 100000, "bomb.gz")], self.since, self.until, max_bytes=1024)
        self.assertTrue(bomb["completeness"]["truncated"])
        self.assertLessEqual(bomb["completeness"]["bytes_read"], 1024)

    def test_sender_context_before_window_and_multiple_recipients(self):
        result = self.analyze(
            "2026-11-02T08:59:00Z box postfix/qmgr[1]: 4Xp2kT0bcDz12345: from=<sender@partner.example>, size=3, nrcpt=2 (queue active)\n"
            "2026-11-02T09:25:36Z box postfix/smtp[3]: 4Xp2kT0bcDz12345: to=<one@remote.example>, relay=mx.remote.example[192.0.2.2]:25, delay=3, delays=1/0/0/2, dsn=2.0.0, status=sent (250 accepted)\n"
            "2026-11-02T09:25:37Z box postfix/smtp[3]: 4Xp2kT0bcDz12345: to=<two@remote.example>, relay=mx.remote.example[192.0.2.2]:25, delay=4, delays=1/0/0/3, dsn=2.0.0, status=sent (250 accepted)\n",
            filters={"from": "sender@partner.example"})
        self.assertEqual(result["statistics"]["observed_messages"], 1)
        self.assertEqual(result["statistics"]["recipient_delivery_events"], 2)
        self.assertFalse(result["traces"][0]["events"][0]["in_window"])
        self.assertEqual(result["statistics"]["outcomes"], {"next_smtp_accepted": 2})

    def test_queue_reuse_instances_and_repeated_message_id_stay_separate(self):
        lines = []
        for minute, instance in ((1, "postfix"), (2, "postfix"), (3, "postfix-out")):
            lines.extend([
                "2026-11-02T09:%02d:00Z box %s/cleanup[2]: ABCDE: message-id=<repeat@partner.example>" % (minute, instance),
                "2026-11-02T09:%02d:01Z box %s/qmgr[1]: ABCDE: from=<>, size=3, nrcpt=1 (queue active)" % (minute, instance),
                "2026-11-02T09:%02d:02Z box %s/qmgr[1]: ABCDE: removed" % (minute, instance)])
        result = self.analyze("\n".join(lines) + "\n", filters={"message_id": "<repeat@partner.example>"})
        self.assertEqual(result["statistics"]["queues"], 3)
        self.assertEqual(result["statistics"]["observed_messages"], 3)
        self.assertEqual(result["traces"][0]["senders"], [""])

    def test_localhost_reinjection_links_not_two_messages(self):
        result = self.analyze(
            "2026-11-02T09:20:00Z box postfix/qmgr[1]: 1F2A3B4C5D: from=<sender@partner.example>, size=3, nrcpt=1 (queue active)\n"
            "2026-11-02T09:20:01Z box postfix/smtp[3]: 1F2A3B4C5D: to=<office@local.example>, relay=127.0.0.1[127.0.0.1]:10025, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 2E3D4C5B6A)\n"
            "2026-11-02T09:20:01Z box postfix/qmgr[2]: 2E3D4C5B6A: from=<sender@partner.example>, size=3, nrcpt=1 (queue active)\n"
            "2026-11-02T09:20:02Z box postfix/lmtp[3]: 2E3D4C5B6A: to=<office@local.example>, relay=dovecot, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 2.0.0 Saved)\n")
        self.assertEqual(result["statistics"]["observed_messages"], 1)
        self.assertEqual(result["statistics"]["queues"], 2)
        self.assertEqual(result["statistics"]["outcomes"], {"internal_smtp_accepted": 1, "saved": 1})

    def test_noqueue_rejection_is_visible_without_queue(self):
        result = self.analyze("2026-11-02T09:20:00Z box postfix/smtpd[2]: NOQUEUE: reject: RCPT from mx.partner.example[192.0.2.5]: 450 4.2.0 Try later; from=<sender@partner.example> to=<office@local.example> proto=ESMTP helo=<mx.partner.example>\n", filters={"from": "sender@partner.example"})
        self.assertEqual(result["statistics"]["rejected_before_queue"], 1)
        self.assertEqual(result["statistics"]["queues"], 0)
        self.assertEqual(result["statistics"]["top_rejection_reasons"], {"4.2.0 Try later": 1})

    def test_greylisting_triplets_retry_and_distinct_pass_reasons(self):
        prefix = "2026-11-02T09:%02d:00Z box postgrey[2]: action=%s, reason=%s, client_name=mx.partner.example, client_address=%s, sender=sender@partner.example, recipient=office@local.example\n"
        result = self.analyze(
            prefix % (1, "greylist", "new", "192.0.2.1") + prefix % (2, "greylist", "early-retry", "192.0.2.1")
            + prefix % (7, "pass", "triplet found", "192.0.2.1")
            + prefix % (8, "greylist", "new", "192.0.2.2")
            + prefix % (9, "pass", "client AWL", "192.0.2.3")
            + prefix % (10, "pass", "client whitelist", "192.0.2.4"))
        findings = {f["id"]: f for f in result["findings"]}
        self.assertEqual(findings["GREYLIST-RETRY-PASS"]["details"]["observed_wait_seconds"], 360)
        self.assertEqual(findings["GREYLIST-OUTCOME"]["status"], "UNKNOWN")
        self.assertIn("GREYLIST-AWL", findings)
        self.assertIn("GREYLIST-CLIENT-WHITELIST", findings)

    def test_dovecot_without_syslog_hostname_saved_not_current_folder(self):
        result = self.analyze("Nov 02 13:25:36 lmtp(office@local.example)<123><session>: Info: msgid=<one@partner.example>: saved mail to INBOX\n", timezone="Asia/Dubai", filters={"message_id": "<one@partner.example>"})
        self.assertEqual(result["evidence"][0]["kind"], "saved")
        self.assertEqual(result["evidence"][0]["mailbox"], "INBOX")
        self.assertNotIn("current_mailbox", result["evidence"][0])

    def test_adversarial_fields_cannot_forge_delivery_or_identity(self):
        result = self.analyze(
            "2026-11-02T09:20:00Z box postfix/smtpd[2]: NOQUEUE: reject: RCPT from mx.partner.example[192.0.2.5]: 450 rejected status=sent message-id=<forged@evil.example>; from=<sender@partner.example> to=<office@local.example> proto=ESMTP helo=<from=attacker@evil.example status=sent>\n"
            "2026-11-02T09:20:01Z box postfix/cleanup[2]: ABCDE: warning: header Subject: message-id=<forged@evil.example> status=sent from x\n"
            "2026-11-02T09:20:02Z box postfix/smtp[2]: ABCDE: warning: status=sent to=<forged@evil.example>\n"
            "2026-11-02T09:20:03Z box postfix/qmgr[2]: ABCDE: from=<sender@partner.example status=sent>, size=1, nrcpt=1 (queue active)\n")
        self.assertEqual(result["statistics"]["recipient_delivery_events"], 0)
        self.assertEqual(result["statistics"]["accepted_queue_events"], 0)
        self.assertTrue(all(not q["message_ids"] for q in result["traces"]))
        forged = self.analyze("2026-11-02T09:20:00Z box postfix/cleanup[2]: ABCDE: warning: header message-id=<forged@evil.example>\n", filters={"message_id": "<forged@evil.example>"})
        self.assertEqual(forged["statistics"]["queues"], 0)

    def test_literal_filters_not_regex_substrings_or_shell(self):
        text = "2026-11-02T09:20:00Z box postfix/qmgr[2]: ABCDE: from=<sender@partner.example>, size=1, nrcpt=1 (queue active)\n"
        for value in (".*", "partner.example", "$(touch /tmp/owned)", "sender@partner.example.bad"):
            result = self.analyze(text, filters={"from": value})
            self.assertEqual(result["statistics"]["queues"], 0)
        result = self.analyze(text, filters={"domain": "partner.example"})
        self.assertEqual(result["statistics"]["queues"], 1)

    def test_legacy_statistics_use_one_window_and_structured_fields(self):
        result = self.analyze(
            "2026-11-02T08:59:59Z box postfix/smtpd[2]: 3A4B5C6D7E: client=mx.partner.example[192.0.2.5], sasl_method=PLAIN, sasl_username=early@local.example\n"
            "2026-11-02T09:20:00Z box postfix/smtpd[2]: ABCDE: client=mx.partner.example[192.0.2.5], sasl_method=PLAIN, sasl_username=office@local.example\n"
            "2026-11-02T09:20:01Z box postfix/smtpd[2]: warning: unknown[192.0.2.5]: SASL LOGIN authentication failed: authentication failure\n"
            "2026-11-02T09:20:02Z box postfix/smtp[2]: ABCDE: to=<one@remote.example>, relay=none, delay=2, delays=1/0/0/1, dsn=5.1.1, status=bounced (User unknown)\n")
        stats = result["statistics"]
        self.assertEqual(stats["top_authenticated_senders"], {"office@local.example": 1})
        self.assertEqual(stats["auth_failures"], 1)
        self.assertEqual(stats["delivery_reasons"]["bounced"], {"User unknown": 1})

    def test_terminal_sequences_removed_and_json_serializable(self):
        result = self.analyze("2026-11-02T09:20:00Z box postfix/smtpd[2]: warning: \x1b[31munsafe\x1b[0m\n")
        encoded = json.dumps(result)
        self.assertNotIn("\\u001b", encoded)
        self.assertFalse(result["completeness"]["window_coverage_proven"])

    def test_changed_message_id_without_removed_starts_new_lifecycle(self):
        result = self.analyze(
            "2026-11-02T09:20:00Z box postfix/cleanup[2]: ABCDE: message-id=<one@partner.example>\n"
            "2026-11-02T09:21:00Z box postfix/cleanup[2]: ABCDE: message-id=<two@partner.example>\n")
        self.assertEqual(result["statistics"]["observed_messages"], 2)

    def test_greylist_context_before_window_retained(self):
        result = analyze_logs([str(Path(__file__).parent / "fixtures/logs/greylist-retry.log")],
                              utc("2026-11-02T09:05:00Z"), self.until)
        passed = next(f for f in result["findings"] if f["id"] == "GREYLIST-RETRY-PASS")
        self.assertEqual(passed["details"]["observed_wait_seconds"], 360)
        self.assertFalse(passed["evidence"][0]["in_window"])

    def test_anonymized_incident_proves_seconds_without_greylist_blame(self):
        result = analyze_logs([str(Path(__file__).parent / "fixtures/logs/local-seconds.log")],
                              self.since, self.until, timezone="Asia/Dubai")
        deliveries = [e for trace in result["traces"] for e in trace["events"] if e["kind"] == "delivery"]
        self.assertEqual(deliveries[0]["delay"], 2.9)
        self.assertEqual(deliveries[0]["outcome"], "saved")
        self.assertNotIn("GREYLIST-RETRY-PASS", [f["id"] for f in result["findings"]])

    def test_recipient_outcomes_do_not_hide_a_failed_recipient(self):
        result = self.analyze(
            "2026-11-02T09:20:00Z box postfix/smtp[2]: ABCDE: to=<one@remote.example>, relay=none, delay=2, delays=1/0/0/1, dsn=5.1.1, status=bounced (User unknown)\n"
            "2026-11-02T09:20:01Z box postfix/smtp[2]: ABCDE: to=<two@remote.example>, relay=mx.remote.example[192.0.2.1]:25, delay=3, delays=1/0/0/2, dsn=2.0.0, status=sent (250 accepted)\n")
        self.assertEqual(result["traces"][0]["outcome"], "mixed")
        self.assertEqual(result["traces"][0]["recipient_outcomes"]["one@remote.example"], "bounced")

    def test_fixed_offset_timezone_for_local_fallback(self):
        result = self.analyze("Nov 02 13:25:33 box postfix/qmgr[1]: ABCDE: removed\n", timezone="UTC+04:00")
        self.assertEqual(result["traces"][0]["events"][0]["time"], "2026-11-02T09:25:33+00:00")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO preflight")
    def test_fifo_directory_and_device_rejected_without_opening(self):
        fifo = self.root / "events.fifo"
        os.mkfifo(fifo)
        for path in (fifo, self.root, Path("/dev/zero")):
            with self.subTest(path=path):
                result = analyze_logs([str(path)], self.since, self.until)
                self.assertFalse(result["completeness"]["complete"])
                self.assertFalse(result["sources"][0]["readable"])
                self.assertIn("regular file", result["sources"][0]["errors"][0])

    def test_huge_individual_line_is_bounded_and_incomplete(self):
        result = self.analyze("2026-11-02T09:20:00Z " + "x" * 1000000 + "\n", max_bytes=4096)
        self.assertEqual(result["statistics"]["queues"], 0)
        self.assertTrue(result["completeness"]["truncated"])
        self.assertLessEqual(result["completeness"]["bytes_read"], 4096)

    def test_unsupported_delivery_grammar_marks_source_incomplete(self):
        result = self.analyze("2026-11-02T09:20:00Z box postfix/smtp[2]: ABCDE: to=<one@remote.example>, relay=none, status=deferred (unknown grammar)\n")
        self.assertEqual(result["statistics"]["delivery_attempts"], 0)
        self.assertEqual(result["sources"][0]["unparsed_lines"], 1)
        self.assertFalse(result["completeness"]["complete"])

    def test_forged_from_in_helo_cannot_override_real_sender(self):
        text = "2026-11-02T09:20:00Z box postfix/smtpd[2]: NOQUEUE: reject: RCPT from mx.partner.example[192.0.2.5]: 450 rejected; from=<real@partner.example> to=<office@local.example> proto=ESMTP helo=<from=forged@evil.example status=sent>\n"
        real = self.analyze(text, filters={"from": "real@partner.example"})
        forged = self.analyze(text, filters={"from": "forged@evil.example"})
        self.assertEqual(real["statistics"]["rejected_before_queue"], 1)
        self.assertEqual(forged["statistics"]["rejected_before_queue"], 0)
        self.assertEqual(real["statistics"]["recipient_delivery_events"], 0)

    def test_remote_localhost_prefix_and_diagnostic_saved_word_not_storage_proof(self):
        result = self.analyze(
            "2026-11-02T09:20:00Z box postfix/smtp[2]: ABCDE: to=<one@remote.example>, relay=localhost.evil.example[203.0.113.1]:25, delay=2, delays=1/0/0/1, dsn=2.0.0, status=sent (250 2.0.0 Saved)\n"
            "2026-11-02T09:20:01Z box postfix/lmtp[2]: 4F5E6D7C8B: to=<office@local.example>, relay=dovecot, delay=3, delays=1/0/0/2, dsn=2.0.0, status=sent (250 2.0.0 Not Saved)\n")
        self.assertEqual(result["statistics"]["outcomes"], {"next_smtp_accepted": 1, "local_transport_accepted": 1})

    def test_later_greylist_rejection_not_hidden_by_an_earlier_pass(self):
        prefix = "2026-11-02T%sZ box postgrey[2]: action=%s, reason=%s, client_name=mx.partner.example, client_address=192.0.2.1, sender=sender@partner.example, recipient=office@local.example\n"
        text = (prefix % ("09:01:00", "greylist", "new") + prefix % ("09:06:00", "pass", "triplet found")
                + prefix % ("09:59:00", "greylist", "new") + prefix % ("10:06:00", "pass", "triplet found"))
        result = self.analyze(text)
        ids = [item["id"] for item in result["findings"]]
        self.assertIn("GREYLIST-RETRY-PASS", ids)
        self.assertIn("GREYLIST-OUTCOME", ids)

    def test_detectable_rotation_gap_is_unknown_and_contiguous_not_coverage_proof(self):
        line = "2026-11-02T09:20:00Z box postfix/qmgr[1]: ABCDE: removed\n"
        one = self.write(line, "mail.log.1")
        three = self.write(line, "mail.log.3.gz")
        result = analyze_logs([three, one], self.since, self.until)
        self.assertFalse(result["completeness"]["complete"])
        self.assertEqual(result["completeness"]["rotation_gaps"][0]["missing_indices"], [2])
        self.assertIn("LOG-ROTATION-GAP", [f["id"] for f in result["findings"]])
        two = self.write(line, "mail.log.2.bz2")
        complete_names = analyze_logs([three, one, two], self.since, self.until)
        self.assertEqual(complete_names["completeness"]["rotation_gaps"], [])
        self.assertFalse(complete_names["completeness"]["window_coverage_proven"])

    def test_large_rotation_gap_enumeration_is_bounded(self):
        line = "2026-11-02T09:20:00Z box postfix/qmgr[1]: ABCDE: removed\n"
        result = analyze_logs([self.write(line, "mail.log.1"), self.write(line, "mail.log.99999999.gz")], self.since, self.until)
        gap = result["completeness"]["rotation_gaps"][0]
        self.assertEqual(gap["missing_count"], 99999997)
        self.assertEqual(len(gap["missing_indices"]), 20)

    def test_calendar_dates_are_not_numeric_rotation_indexes(self):
        line = "2026-11-02T09:20:00Z box postfix/qmgr[1]: ABCDE: removed\n"
        result = analyze_logs([self.write(line), self.write(line, "mail.log.20261101.gz")], self.since, self.until)
        self.assertEqual(result["completeness"]["rotation_gaps"], [])

    def test_direct_api_strips_c1_controls_from_evidence_and_statistics(self):
        result = self.analyze("2026-11-02T09:20:00Z box postfix/smtp[2]: ABCDE: to=<one@remote.example>, relay=none, delay=2, delays=1/0/0/1, dsn=4.4.1, status=deferred (temporary\x9b31m failure\x85)\n")
        encoded = json.dumps(result, ensure_ascii=False)
        self.assertFalse(any(127 <= ord(char) <= 159 for char in encoded))
        self.assertEqual(result["statistics"]["delivery_reasons"]["deferred"], {"temporary31m failure": 1})

    def test_expired_and_hold_events_have_distinct_lifecycle_evidence(self):
        result = self.analyze(
            "2026-11-02T09:20:00Z box postfix/qmgr[2]: ABCDE: from=<sender@partner.example>, status=expired, returned to sender\n"
            "2026-11-02T09:20:01Z box postfix/cleanup[2]: 4F5E6D7C8B: hold: header Subject: sensitive content from x\n")
        self.assertEqual(result["statistics"]["expired"], 1)
        self.assertEqual(result["statistics"]["hold"], 1)
        self.assertNotIn("sensitive content", json.dumps(result))
        self.assertIn("MAIL-QUEUE-LIFECYCLE", [f["id"] for f in result["findings"]])

    def test_expiry_dominates_deferred_but_preserves_successful_recipient(self):
        result = self.analyze(
            "2026-11-02T09:20:00Z box postfix/lmtp[2]: ABCDE: to=<office@local.example>, relay=dovecot, delay=2, delays=1/0/0/1, dsn=2.0.0, status=sent (250 2.0.0 Saved)\n"
            "2026-11-02T09:20:01Z box postfix/smtp[2]: ABCDE: to=<one@remote.example>, relay=none, delay=3, delays=1/0/0/2, dsn=4.4.1, status=deferred (timeout)\n"
            "2026-11-02T09:59:59Z box postfix/qmgr[2]: ABCDE: from=<sender@partner.example>, status=expired, returned to sender\n"
            "2026-11-02T09:20:01Z box postfix/smtp[2]: 4F5E6D7C8B: to=<two@remote.example>, relay=none, delay=3, delays=1/0/0/2, dsn=4.4.1, status=deferred (timeout)\n"
            "2026-11-02T09:59:59Z box postfix/qmgr[2]: 4F5E6D7C8B: status=expired, returned to sender\n")
        traces = {q["queue_id"]: q for q in result["traces"]}
        self.assertEqual(traces["ABCDE"]["outcome"], "mixed")
        self.assertEqual(traces["ABCDE"]["recipient_outcomes"], {"office@local.example": "saved", "one@remote.example": "expired"})
        self.assertEqual(traces["4F5E6D7C8B"]["outcome"], "expired")

    def test_long_window_does_not_push_old_month_into_future_year(self):
        result = self.analyze("Jan 02 09:25:33 box postfix/qmgr[1]: ABCDE: removed\n",
                              since=utc("2025-11-02T00:00:00Z"), until=utc("2026-11-02T10:00:00Z"))
        self.assertEqual(result["traces"][0]["events"][0]["time"][:4], "2026")

    def test_leap_day_inferred_even_when_reference_year_not_leap(self):
        result = self.analyze("Feb 29 09:25:33 box postfix/qmgr[1]: ABCDE: removed\n",
                              since=utc("2024-02-01T00:00:00Z"), until=utc("2025-01-01T10:00:00Z"))
        self.assertEqual(result["traces"][0]["events"][0]["time"][:10], "2024-02-29")
        self.assertEqual(result["completeness"]["unparsed_lines"], 0)

    def test_journald_249_offsets_and_long_fractions_parse_on_python_39(self):
        # journalctl -o short-iso-precise before systemd 255 prints +0300 (strftime %z).
        result = self.analyze(
            "2026-11-02T12:20:00.123456+0300 box postfix/qmgr[1]: ABCDE: removed\n"
            "2026-11-02T09:21:00.123456789Z box postfix/qmgr[1]: BCDEF: removed\n"
            "2026-11-02T09:22:00+2500 box postfix/qmgr[1]: CDEF0: removed\n")
        times = sorted(e["time"] for trace in result["traces"] for e in trace["events"])
        self.assertEqual(times, ["2026-11-02T09:20:00.123456+00:00", "2026-11-02T09:21:00.123456+00:00"])
        self.assertEqual(result["completeness"]["unparsed_lines"], 1)

    def test_rbl_reject_reason_with_semicolons_and_reject_warning(self):
        result = self.analyze(
            "2026-11-02T09:20:00Z box postfix/smtpd[2]: NOQUEUE: reject: RCPT from unknown[192.0.2.5]: 554 5.7.1 Service unavailable; "
            "Client host [192.0.2.5] blocked using zen.spamhaus.org; https://www.spamhaus.org/query/ip/192.0.2.5; "
            "from=<sender@partner.example> to=<office@local.example> proto=ESMTP helo=<mx.partner.example>\n"
            "2026-11-02T09:20:01Z box postfix/smtpd[2]: NOQUEUE: reject_warning: RCPT from unknown[192.0.2.6]: 450 4.7.1 Client host rejected: cannot find your hostname; "
            "from=<sender@partner.example> to=<office@local.example> proto=ESMTP helo=<x.partner.example>\n"
            "2026-11-02T09:20:02Z box postfix/smtpd[2]: NOQUEUE: reject: CONNECT from unknown[192.0.2.7]: 554 5.7.1 <unknown[192.0.2.7]>: Client host rejected: Access denied; proto=SMTP\n")
        stats = result["statistics"]
        self.assertEqual(stats["rejected_before_queue"], 2)
        self.assertEqual(stats["reject_warnings"], 1)
        self.assertIn("5.7.1 Service unavailable; Client host [192.0.2.5] blocked using zen.spamhaus.org; https://www.spamhaus.org/query/ip/192.0.2.5",
                      stats["top_rejection_reasons"])
        connect = [e for e in result["evidence"] if e.get("stage") == "CONNECT"][0]
        self.assertNotIn("sender", connect)
        self.assertTrue(result["completeness"]["complete"])

    def test_tail_inside_quoted_sender_does_not_replace_the_real_fields(self):
        text = ('2026-11-02T09:20:00Z box postfix/smtpd[2]: NOQUEUE: reject: RCPT from unknown[192.0.2.5]: 450 4.2.0 Greylisted; '
                'from=<"q; from=<forged@evil.example> to=<victim@other.example> proto=ESMTP helo=<h>"@evil.example> '
                'to=<office@local.example> proto=ESMTP helo=<mx.evil.example>\n')
        result = self.analyze(text, filters={"to": "office@local.example"})
        self.assertEqual(result["statistics"]["rejected_before_queue"], 1)
        self.assertEqual(self.analyze(text, filters={"to": "victim@other.example"})["statistics"]["rejected_before_queue"], 0)
        self.assertEqual(self.analyze(text, filters={"from": "forged@evil.example"})["statistics"]["rejected_before_queue"], 0)

    def test_quoted_local_parts_cannot_shift_queue_fields(self):
        result = self.analyze(
            '2026-11-02T09:20:00Z box postfix/qmgr[1]: ABCDE: from=<"x>, size=1, nrcpt=9 (queue active)"@evil.example>, size=5, nrcpt=1 (queue active)\n'
            '2026-11-02T09:20:01Z box postfix/lmtp[3]: ABCDE: to=<"odd>name"@local.example>, orig_to=<"alias>x"@local.example>, relay=dovecot, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 2.0.0 Saved)\n')
        events = {e["kind"]: e for e in result["traces"][0]["events"]}
        self.assertEqual((events["accepted"]["size"], events["accepted"]["recipient_count"]), (5, 1))
        self.assertEqual(events["accepted"]["sender"], '"x>, size=1, nrcpt=9 (queue active)"@evil.example')
        self.assertEqual(events["delivery"]["recipient"], '"odd>name"@local.example')
        self.assertEqual(events["delivery"]["orig_to"], '"alias>x"@local.example')
        self.assertTrue(result["completeness"]["complete"])

    def test_queue_ids_follow_postfix_grammar_so_daemon_faults_are_visible(self):
        result = self.analyze(
            "2026-11-02T09:20:00Z box postfix/smtpd[2]: warning: hostname mx.partner.example does not resolve to address 192.0.2.9\n"
            "2026-11-02T09:20:01Z box postfix/smtpd[2]: fatal: open /etc/postfix/main.cf: Permission denied\n"
            "2026-11-02T09:20:02Z box postfix/smtpd[2]: NOQUEUE: filter: RCPT from unknown[192.0.2.5]: <office@local.example>: Recipient address triggers FILTER smtp:[127.0.0.1]:10025; from=<a@partner.example> to=<office@local.example> proto=ESMTP helo=<x>\n")
        self.assertEqual(result["statistics"]["queues"], 0)
        self.assertEqual(result["statistics"]["daemon_warnings"], 1)
        self.assertIn("MAIL-DAEMON-ERROR", [f["id"] for f in result["findings"]])
        self.assertEqual(result["completeness"]["unparsed_lines"], 0)

    def test_client_port_logging_and_sasl_sender(self):
        result = self.analyze(
            "2026-11-02T09:20:00Z box postfix/smtpd[2]: ABCDE: client=mx.partner.example[192.0.2.5]:41234\n"
            "2026-11-02T09:20:01Z box postfix/smtpd[2]: BCDEF: client=laptop.partner.example[192.0.2.7], sasl_method=PLAIN, sasl_username=office@local.example, sasl_sender=office@local.example\n")
        self.assertEqual(result["statistics"]["top_authenticated_senders"], {"office@local.example": 1})
        self.assertEqual(sorted(e["client_ip"] for e in result["evidence"]), ["192.0.2.5", "192.0.2.7"])

    def test_miab_submission_syslog_name_joins_one_trace(self):
        result = self.analyze(
            "2026-11-02T09:20:00Z box postfix/submission/smtpd[7]: warning: unknown[192.0.2.5]: SASL LOGIN authentication failed: UGFzc3dvcmQ6\n"
            "2026-11-02T09:20:01Z box postfix/submission/smtpd[7]: ABCDE: client=laptop.partner.example[192.0.2.7], sasl_method=PLAIN, sasl_username=office@local.example\n"
            "2026-11-02T09:20:02Z box postfix/cleanup[8]: ABCDE: message-id=<one@local.example>\n"
            "2026-11-02T09:20:03Z box postfix/qmgr[9]: ABCDE: from=<office@local.example>, size=3, nrcpt=1 (queue active)\n"
            "2026-11-02T09:20:04Z box postfix/smtp[10]: ABCDE: to=<one@remote.example>, relay=mx.remote.example[192.0.2.2]:25, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 ok)\n")
        stats = result["statistics"]
        self.assertEqual((stats["queues"], stats["auth_failures"]), (1, 1))
        self.assertEqual(stats["top_authenticated_senders"], {"office@local.example": 1})
        trace = result["traces"][0]
        self.assertEqual(trace["instance"], "postfix")
        self.assertEqual(trace["events"][0]["service"], "submission")
        self.assertEqual(trace["events"][0]["component"], "smtpd")

    def test_local_submission_notifications_and_session_problems_are_known(self):
        result = self.analyze(
            "2026-11-02T09:20:00Z box postfix/pickup[4]: ABCDE: uid=0 from=<root>\n"
            "2026-11-02T09:20:01Z box postfix/bounce[5]: ABCDE: sender non-delivery notification: BCDEF\n"
            "2026-11-02T09:20:02Z box postfix/smtp[6]: CDEF0: lost connection with mx.remote.example[192.0.2.2] while sending end of data -- message may be sent more than once\n"
            "2026-11-02T09:20:03Z box postfix/smtp[6]: DEF01: conversation with mx.remote.example[192.0.2.2] timed out while receiving the initial server greeting\n")
        kinds = sorted(e["kind"] for trace in result["traces"] for e in trace["events"])
        self.assertEqual(kinds, ["notification", "pickup", "session_problem", "session_problem"])
        pickup = next(e for trace in result["traces"] for e in trace["events"] if e["kind"] == "pickup")
        self.assertEqual((pickup["sender"], pickup["uid"]), ("root", 0))
        self.assertTrue(result["completeness"]["complete"])


if __name__ == "__main__":
    unittest.main()
