"""Task reports expose useful facts without requiring the detail flag."""
import contextlib
from datetime import datetime, timezone
import io
import unittest

from mailradar.display import _date, human


def finding(identifier, title, status="OK", evidence=None, **details):
    return dict(id=identifier, title=title, status=status, evidence=evidence or [], details=details)


def report(mode, findings=None, **extra):
    return dict(mode=mode, findings=findings or [], summary=dict(status="OK"),
                generated_at="2026-11-04T10:00:00+00:00",
                window=dict(since="2026-11-04T09:00:00+00:00", until="2026-11-04T10:00:00+00:00", timezone="UTC"),
                sources=[], completeness=dict(complete=True, checks_complete=True, log_sources_complete=True), **extra)


class TaskDisplayTests(unittest.TestCase):
    def test_account_successful_disk_and_queue_scoped_targets_are_visible(self):
        account = report("account", [finding("DISK.SPACE", "root space", mount="/", used_percent=24)])
        output = self.render(account)
        self.assertIn("Место и inode", output)
        self.assertIn("24", output)
        queue = report("queue", [finding("HOST.TARGETS", "targets", local_hostname="box.local.example", dns_domain="unused.example", tls_hostname="unused-tls.example")])
        output = self.render(queue)
        self.assertIn("box.local.example", output)
        self.assertNotIn("unused.example", output)
        self.assertNotIn("unused-tls.example", output)

    def render(self, data, details=False):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            human(data, details)
        return output.getvalue()

    def test_queue_all_retained_ids_recipients_and_causes_are_primary(self):
        entries = [dict(queue_id="QUEUE%d" % i, queue_name="hold" if i == 4 else "deferred",
                        sender="sender%d@partner.example" % i, message_size=4096,
                        age_seconds=3600, arrival_iso="2026-11-04T09:00:00+00:00",
                        recipients=[dict(address="user%d@remote.example" % i, delay_reason="451 recipient %d temporarily unavailable" % i),
                                    dict(address="copy%d@other.example" % i, delay_reason="550 recipient %d quota exceeded" % i)]) for i in range(6)]
        data = report("queue", [finding("QUEUE.SNAPSHOT", "queue snapshot", "WARN", count=9, matched_count=6, filtered=True,
                                       complete=True, entries=entries, entries_omitted=0)], statistics=dict(queues=16, observed_messages=15))
        output = self.render(data)
        for i in range(6):
            for expected in ("QUEUE%d" % i, "sender%d@partner.example" % i, "user%d@remote.example" % i,
                             "copy%d@other.example" % i, "451 recipient %d" % i, "550 recipient %d" % i):
                self.assertIn(expected, output)
        self.assertIn("Очередь СЕЙЧАС", output)
        self.assertIn("Всего в текущем снимке: 9", output)
        self.assertIn("Совпало с фильтром: 6", output)
        self.assertIn("показано 6 из 6", output)
        self.assertIn("4 KiB", output)
        self.assertIn("1.0 ч", output)
        self.assertIn("Queue ID/lifecycle: 16", output)
        self.assertNotIn("Поток: очередей", output)

    def test_queue_empty_now_is_not_historical_success_and_omissions_are_explicit(self):
        empty = self.render(report("queue", [finding("QUEUE.SNAPSHOT", "empty", count=0, complete=True, entries=[])], statistics=dict(queues=16)))
        self.assertIn("Очередь пуста СЕЙЧАС", empty)
        self.assertIn("Queue ID/lifecycle: 16", empty)
        partial = self.render(report("queue", [finding("QUEUE.SNAPSHOT", "partial", "UNKNOWN", count=60, complete=False,
                                                       entries=[dict(queue_id="FIRST", queue_name="deferred", sender="", message_size=None,
                                                                     recipients=[dict(address="one@example.org", delay_reason="reason")], recipients_omitted=2)], entries_omitted=59)]))
        self.assertIn("полнота чтения: не подтверждена", partial)
        self.assertIn("показано 1 из 60", partial)
        self.assertIn("показано 1 из 3", partial)
        self.assertIn("<> (bounce sender)", partial)
        self.assertIn("Возраст / размер: неизвестен / неизвестен", partial)

    def test_queue_and_mailstore_display_caps_differ_from_collection_omissions(self):
        entries = [dict(queue_id="CURRENT%d" % i, queue_name="deferred", sender="sender@example.org", message_size=3,
                        recipients=[dict(address="user%d@example.org" % j, delay_reason="451 wait") for j in range(12)]) for i in range(12)]
        data = report("queue", [finding("QUEUE.SNAPSHOT", "queue", count=15, complete=True, entries=entries, entries_omitted=3)])
        basic, expanded = self.render(data), self.render(data, True)
        self.assertIn("Текущие записи: показано 10 из 15", basic)
        self.assertIn("Записи, скрытые лимитом экрана: 2", basic)
        self.assertIn("Не сохранено записей текущего снимка: 3", basic)
        self.assertIn("Получатели записи CURRENT0: показано 10 из 12", basic)
        self.assertIn("Получатели, скрытые лимитом экрана: 2", basic)
        self.assertNotIn("CURRENT10 |", basic)
        self.assertIn("CURRENT10 |", expanded)
        self.assertIn("user11@example.org", expanded)
        records = [dict(mailbox="INBOX", uid=i, **{"hdr.message-id": "<record%d@example.org>" % i}) for i in range(25)]
        data = report("mailboxes", [finding("mailstore.metadata", "records", evidence=records, user="office@example.org", matching_records=30, omitted_records=5)])
        basic, expanded = self.render(data), self.render(data, True)
        self.assertIn("Письма: показано 20 из 30", basic)
        self.assertIn("Письма, скрытые лимитом экрана: 5", basic)
        self.assertIn("Не сохранено кандидатов сверх лимита: 5", basic)
        self.assertNotIn("<record24@example.org>", basic)
        self.assertIn("<record24@example.org>", expanded)

    def test_dns_scope_success_answers_expiry_and_relay_are_visible(self):
        findings = [finding("HOST.TARGETS", "targets", local_hostname="box.local.example", dns_domain="selected.example", tls_hostname="smtp.local.example"),
                    finding("DNS.MX", "MX resolved", query="selected.example", record_type="MX", dns_state="NOERROR", answers=["10 mx.selected.example."]),
                    finding("DNS.RESOLVER_CONFIG", "host resolver", nameservers=["127.0.0.53"]),
                    finding("TLS.PORT_587", "certificate checked", port=587, hostname="smtp.local.example", mode="STARTTLS", not_after="Dec 20 2026 GMT", days_remaining=46),
                    finding("POSTFIX.TRANSPORT", "transport", relayhost="[relay.partner.example]:587"),
                    finding("SECURITY.SSH", "UNRELATED_SSH", "WARN"), finding("BACKUP.TOOLING", "UNRELATED_BACKUP", "UNKNOWN")]
        output = self.render(report("dns", findings, scope=dict(logs_selected=False)))
        for expected in ("box.local.example", "selected.example", "smtp.local.example", "10 mx.selected.example.",
                         "127.0.0.53", "STARTTLS", "Dec 20 2026 GMT", "46", "[relay.partner.example]:587"):
            self.assertIn(expected, output)
        self.assertIn("[OK] MX resolved", output)
        self.assertNotIn("UNRELATED_SSH", output)
        self.assertNotIn("UNRELATED_BACKUP", output)
        self.assertIn("Логи в этой задаче не выбирались", output)

    def test_account_quota_and_every_retained_mail_record_have_concrete_fields(self):
        records = [dict(mailbox="Trash" if i == 5 else "INBOX", uid=100+i,
                        **{"date.received": "2026-11-04 09:20", "date.saved": "2026-11-04 09:30", "hdr.message-id": "<id%d@partner.example>" % i,
                           "flags": ["\\Seen"], "hdr.date": "Wed, 4 Nov 2026 09:19:00 +0000", "hdr.received": ["from mx.example; Wed, 4 Nov 2026 09:20:00 +0000"]}) for i in range(6)]
        findings = [finding("mailstore.user", "userdb found", user="office@local.example", fields=dict(uid="1000", home="/mail/office")),
                    finding("mailstore.quota", "quota", user="office@local.example", rows=[dict(quota_root="User", resource="STORAGE", used=90, limit=100, percent=90, unit="KiB", complete=True),
                                                                                           dict(quota_root="User", resource="MESSAGE", used=4, limit=0, percent=None, unit="messages", unlimited=True, complete=True)], rows_omitted=1),
                    finding("mailstore.metadata", "metadata", evidence=records, user="office@local.example", matching_records=9, omitted_records=3, precise_time_confirmed=False)]
        output = self.render(report("headers", findings, scope=dict(logs_selected=False)))
        for expected in ("office@local.example", "STORAGE", "90", "KiB", "MESSAGE", "без лимита", "Trash", "UID 105", "<id5@partner.example>", "\\Seen", "получено", "Date", "Received"):
            self.assertIn(expected.casefold(), output.casefold())
        self.assertIn("показано 6 из 9", output)
        self.assertIn("показано 2 из 3", output)
        self.assertIn("Точное время части кандидатов не подтверждено", output)
        self.assertNotIn("{'", output)

    def test_message_rows_show_time_addresses_mid_relay_delay_reason_without_details(self):
        trace = dict(id="box/postfix/ABCDE#1", queue_id="ABCDE", host="box", instance="postfix", generation=1,
                     senders=["sender@partner.example"], recipients=["office@local.example"], message_ids=["<one@partner.example>"],
                     outcome="deferred", recipient_outcomes={"office@local.example": "deferred"},
                     events=[dict(kind="delivery", time="2026-11-04T09:25:00+00:00", recipient="office@local.example", outcome="deferred",
                                  relay="mx.local.example[192.0.2.1]:25", delay=372, delays=dict(before_queue=1, queue=360, connect=1, transmission=10),
                                  dsn="4.4.3", reason="DNS lookup failed", source="mail.log", line=7)])
        data = report("delay", traces=[trace], statistics=dict(queues=1, observed_sender_addresses={"sender@partner.example": 2},
                                                             observed_recipient_addresses={"office@local.example": 1}, sender_address_count=1, recipient_address_count=1))
        output = self.render(data)
        for expected in ("ABCDE", "04.11 09:25", "sender@partner.example", "office@local.example", "<one@partner.example>", "mx.local.example", "6.2 мин", "DNS lookup failed", "4.4.3", "mail.log:7", "Домены отправителей"):
            self.assertIn(expected, output)
        self.assertNotIn("Timeline:", output)
        self.assertIn("Timeline:", self.render(data, True))
        self.assertNotIn("{'", output)

    def test_greylist_and_whitelist_show_triplet_timeline_maps_match_and_policy(self):
        events = [dict(kind="greylist", time="2026-11-04T09:20:00Z", client_ip="203.0.113.8", sender="sender@partner.example", recipient="office@local.example", action="greylist", reason="new", source="mail.log", line=1),
                  dict(kind="greylist", time="2026-11-04T09:24:00Z", client_ip="203.0.113.8", sender="sender@partner.example", recipient="office@local.example", action="pass", reason="client AWL", source="mail.log", line=2)]
        grey = self.render(report("greylist", [finding("GREYLIST-RETRY-PASS", "retry passed", evidence=events,
                                                       triplet=["203.0.113.8", "sender@partner.example", "office@local.example"], observed_wait_seconds=240)]))
        for expected in ("203.0.113.8", "sender@partner.example", "office@local.example", "09:20", "09:24", "client AWL", "4.0 мин"):
            self.assertIn(expected, grey)
        white = self.render(report("whitelist", [finding("WHITELIST.LOOKUP", "exact match", map="hash:/etc/postfix/client_whitelist", key="mx.partner.example", match=True, permits=True),
                                                        finding("WHITELIST.WIRING", "wired", chain="smtpd_recipient_restrictions", following_policy_services=["inet:127.0.0.1:10023"]),
                                                        finding("POLICY.LISTENER", "listener", endpoint="inet:127.0.0.1:10023")]))
        for expected in ("hash:/etc/postfix/client_whitelist", "mx.partner.example", "Совпадение: да", "smtpd_recipient_restrictions", "inet:127.0.0.1:10023"):
            self.assertIn(expected, white)

    def test_critical_late_message_is_shown_and_human_limits_are_explicit(self):
        traces = [dict(queue_id="GOOD%d" % i, outcome="next_smtp_accepted", events=[], senders=[], recipients=[]) for i in range(21)]
        traces.append(dict(queue_id="LATEFAIL", outcome="bounced", events=[], senders=[], recipients=[]))
        output = self.render(report("outgoing", traces=traces))
        self.assertIn("LATEFAIL", output)
        self.assertIn("показано 20 из 22", output)
        self.assertNotIn("GOOD20", output)
        self.assertIn("GOOD20", self.render(report("outgoing", traces=traces), True))

    def test_inline_fields_cannot_forge_new_status_lines_and_numeric_unknowns_do_not_crash(self):
        entry = dict(queue_id="SAFE\n[FAIL] forged", queue_name="deferred", sender="sender@example.org", age_seconds=float("nan"), message_size=True,
                     recipients=[dict(address="office@example.org\tother", delay_reason="451 wait\n[OK] forged")])
        output = self.render(report("queue", [finding("QUEUE.SNAPSHOT", "current", count=1, complete=True, entries=[entry])]))
        self.assertNotIn("\n[FAIL] forged", output)
        self.assertNotIn("\n[OK] forged", output)
        self.assertNotIn("\t", output)
        self.assertIn("Возраст / размер: неизвестен / неизвестен", output)
        self.assertTrue(all(len(line) <= 118 for line in output.splitlines()))

    def test_coverage_distinguishes_window_failures_context_and_source_losses(self):
        data = report("incoming", [finding("LOG-SOURCE-INCOMPLETE", "missing evidence", "UNKNOWN")])
        data["sources"] = [dict(path="mail.log.2", lines=10, errors=["permission denied"], unparsed_lines=2, unparsed_context=8)]
        data["completeness"] = dict(log_sources_complete=False, checks_complete=False, lines_read=10, unparsed_lines=2, unparsed_context=8, truncated=True)
        output = self.render(data)
        for expected in ("не разобрано для отчёта: 2; вне окна: 8", "mail.log.2", "permission denied", "[UNKNOWN] missing evidence", "Полнота чтения выбранных логов: нет"):
            self.assertIn(expected, output)

    def test_doctor_includes_successful_sections_and_existing_date_api(self):
        items = [finding("SERVICE.POSTFIX", "Postfix active"), finding("DISK.SPACE", "root space", mount="/", used_percent=20),
                 finding("DNS.MX", "MX present", answers=["10 mx.local.example."]), finding("SECURITY.SSH", "SSH baseline: {'passwordauthentication': 'no'}", values=dict(passwordauthentication="no")),
                 finding("BACKUP.TOOLING", "duplicity version", package_version="3.0.5.1", held=True)]
        output = self.render(report("doctor", items))
        for expected in ("Почтовые службы", "Postfix active", "Место и inode", "20", "10 mx.local.example.", "passwordauthentication: no", "3.0.5.1", "Пакет удерживается: да"):
            self.assertIn(expected, output)
        self.assertNotIn("{'", output)
        self.assertEqual(_date(datetime(2026, 11, 4, 10, tzinfo=timezone.utc).isoformat(), "Asia/Dubai"), "04.11 14:00 +0400")


if __name__ == "__main__":
    unittest.main()
