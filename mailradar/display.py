"""Task-oriented terminal reports over the unchanged structured report model."""
from collections import Counter
from datetime import datetime, timezone
import math
import textwrap

from . import __version__
from .model import clean
from .terminal import brand_header, formatted_line, is_terminal, panel, presentation, rule, viewport, wrap_cells


ORDER = {"FAIL": 0, "WARN": 1, "UNKNOWN": 2, "OK": 3, "N/A": 4}
OUTCOMES = {
    "saved": "сохранено в момент события", "next_smtp_accepted": "принято следующим SMTP",
    "internal_smtp_accepted": "принято внутренним SMTP; дальнейший исход неизвестен",
    "local_transport_accepted": "принято локальным транспортом",
    "deferred": "временно отложено", "bounced": "постоянный отказ",
    "expired": "истёк срок очереди", "hold": "удерживается", "accepted": "принято в очередь; исход неизвестен",
    "discarded": "удалено транспортом discard", "mixed": "разные исходы получателей",
    "unknown": "исход неизвестен",
}
MODES = {
    "doctor": "Общий обзор", "post-update": "Проверка после обновления",
    "queue": "Текущая очередь", "dns": "DNS / TLS / resolver / relay",
    "account": "Аккаунт и квота", "mailboxes": "Письма в локальном ящике",
    "headers": "Заголовки выбранного письма", "incoming": "Входящее письмо",
    "outgoing": "Исходящее письмо", "delay": "Задержка письма",
    "diagnose": "Диагностика доставки", "trace": "Путь письма", "flow": "История доставки",
    "greylist": "Greylisting и повторные попытки", "whitelist": "Whitelist SMTP-клиента",
    "watch": "Результат наблюдения",
}


def _text(value, limit=1200):
    if value is None:
        return "неизвестно"
    if isinstance(value, bool):
        return "да" if value else "нет"
    if isinstance(value, dict):
        value = "; ".join("%s=%s" % (k, _text(v, 180)) for k, v in list(value.items())[:20])
    elif isinstance(value, (list, tuple)):
        value = ", ".join(_text(v, 250) for v in value)
    return " ".join(clean(value, limit).split())


def _line(value="", indent=0, role=None):
    value = _text(value, 6000)
    terminal = is_terminal()
    width = min(118, viewport()[0]) if terminal else 118
    indent = min(indent, max(0, width-12))
    hanging = 2 if terminal else 0
    lines = wrap_cells(value, max(1, width-indent-hanging)) if terminal else textwrap.wrap(value, width=width-indent, break_long_words=True, break_on_hyphens=False) or [""]
    for index, part in enumerate(lines):
        # A wrapped continuation is evidence, never a new trusted status badge.
        line_role = "plain" if index and role is None else role
        prefix = " " * (indent + (hanging if index else 0))
        print(prefix + formatted_line(part, line_role))


def _field(label, value, indent=2):
    _line(label + ": " + _text(value), indent, role="field")


def _section(title):
    print()
    if is_terminal():
        print(rule(title, width=min(118, viewport()[0])))
    else:
        _line(title, role="section")


def _date(value, zone="UTC"):
    try:
        from .logs import _zone
        return datetime.fromisoformat(value).astimezone(_zone(zone)).strftime("%d.%m %H:%M %z")
    except (ValueError, TypeError):
        return str(value)


def _stamp(value, zone):
    return _date(value, zone) if value else "время неизвестно"


def _location(item):
    source = item.get("source", "")
    if item.get("command"):
        source = " ".join(str(v) for v in item["command"])
    if item.get("line") is not None:
        number = item["line"]
        source = str(source) + (":%s" % number if number >= 0 else " (строка с конца %s)" % -number)
    return _text(source, 700)


def _evidence(item):
    if isinstance(item, str):
        return _text(item)
    if not isinstance(item, dict):
        return ""
    if "mailbox" in item and "kind" not in item:
        return "Папка: %s; UID: %s; received: %s; saved: %s; Message-ID: %s" % tuple(
            _text(item.get(k)) for k in ("mailbox", "uid", "date.received", "date.saved", "hdr.message-id"))
    text = item.get("text") or item.get("error") or item.get("stderr")
    if text:
        return _location(item) + (": " if _location(item) else "") + _text(text)
    fields = [(k, v) for k, v in item.items() if k not in {"source", "line", "command", "fields"} and v not in (None, "")]
    return _location(item) + ("; " if fields and _location(item) else "") + "; ".join("%s: %s" % (k, _text(v, 400)) for k, v in fields[:12])


def _shown(label, shown, total, unknown=False):
    _line("%s: показано %d из %s%s." % (label, shown, "не менее " if unknown else "", total), 2)


def _duration(value):
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
        return "неизвестен"
    value = max(0, value)
    if value >= 86400:
        return "%.1f суток" % (value/86400)
    if value >= 3600:
        return "%.1f ч" % (value/3600)
    if value >= 60:
        return "%.1f мин" % (value/60)
    return "%g с" % value


def _size(value):
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value < 0:
        return "неизвестен"
    for unit in ("байт", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return "%g %s" % (round(value, 2), unit)
        value /= 1024


class ReportView:
    def __init__(self, report, details):
        self.report, self.details = report, details
        self.mode = report.get("mode", "doctor")
        self.zone = report.get("window", {}).get("timezone", "UTC")
        self.findings = report.get("findings", [])
        self.used = set()
        self.limit = 80 if details else 20

    def select(self, prefixes):
        return [f for f in self.findings if any(f.get("id", "").startswith(p) for p in prefixes)]

    def one(self, identifier):
        return next((f for f in self.findings if f.get("id") == identifier), None)

    def mark(self, items):
        self.used.update(id(item) for item in items)

    def targets(self):
        finding = self.one("HOST.TARGETS")
        values = self.report.get("targets") or (finding or {}).get("details", {})
        if finding:
            self.mark([finding])
        if values:
            _section("Что проверяется")
            for key, label in (("local_hostname", "Локальный почтовый узел"), ("dns_domain", "Выбранный DNS-домен"), ("tls_hostname", "Имя для проверки TLS")):
                if key != "local_hostname" and self.mode not in {"dns", "doctor", "post-update"} and not self.report.get("active_probes"):
                    continue
                _field(label, values.get(key))

    def item(self, finding, evidence=True):
        self.mark([finding])
        data = finding.get("details", {})
        title = finding.get("title", finding.get("id", "Проверка"))
        if finding.get("id") == "SECURITY.SSH" and data.get("values"):
            title = "SSH: эффективные базовые настройки входа"
        _line("[%s] %s%s" % (finding.get("status", "UNKNOWN"), title, " (" + finding.get("id", "") + ")" if self.details else ""))
        labels = {
            "query": "DNS-запрос", "record_type": "Тип записи", "dns_state": "Ответ DNS",
            "nameservers": "Resolvers", "resolver": "Resolver", "hostname": "Имя узла",
            "relayhost": "Relayhost", "transport_maps": "Transport maps", "context": "Контекст",
            "guard_chains": "Цепочки защиты relay", "not_after": "Сертификат до",
            "days_remaining": "До истечения, суток", "mode": "Протокол", "port": "Порт",
            "map": "Карта", "key": "Ключ клиента", "match": "Совпадение", "permits": "Разрешающее действие",
            "chain": "Цепочка", "following_policy_services": "Policy services после карты",
            "preceding_policy_services": "Policy services до карты", "earlier_rejects": "Предшествующие rejects",
            "backend": "Backend", "source_readable": "Исходный файл читается", "stale_index_evidence": "Признак устаревшего индекса",
            "defaults_source": "Источник defaults", "inferred_path": "Путь только предполагается",
            "endpoint": "Policy endpoint", "address_family_confirmed": "Address family подтверждено",
            "package_version": "Версия пакета", "executable_version": "Версия запускаемой утилиты",
            "held": "Пакет удерживается", "success_proven": "Успех backup доказан",
            "mount": "Файловая система", "used_percent": "Использовано, %",
            "peer": "Узел назначения", "interface": "Интерфейс", "gateway": "Gateway",
            "persistence_proven": "Сохранение после reboot доказано", "source": "Источник",
        }
        facts = False
        for key, label in labels.items():
            if key in data and data[key] not in (None, "", []):
                _field(label, data[key])
                facts = True
        if data.get("answers"):
            for answer in data["answers"]:
                _field("DNS-ответ", answer)
            if data.get("answers_omitted"):
                _shown("DNS-ответы", len(data["answers"]), len(data["answers"])+data["answers_omitted"])
            facts = True
        if data.get("values"):
            for key, value in data["values"].items():
                _field(key, value)
            facts = True
        if data.get("matches"):
            for match in data["matches"][:20]:
                _field("Совпадение", "; ".join("%s=%s" % (k, _text(v)) for k, v in match.items()))
            facts = True
        if evidence:
            retained = finding.get("evidence", [])
            count = 8 if self.details else 2 if not facts else 1 if finding.get("status") in ("FAIL", "WARN", "UNKNOWN") else 0
            for value in retained[:count]:
                if not self.details and facts and isinstance(value, dict) and value.get("command"):
                    # DNS status/answers are already visible. Dig packet headers
                    # and argv add noise; TLS failures still need their reason.
                    rendered = value.get("stderr") or (value.get("text") if finding.get("id", "").startswith("TLS.") else "")
                else:
                    rendered = _evidence(value)
                if rendered:
                    _field("Основание", rendered)
            if len(retained) > count and (self.details or not facts):
                _shown("Основания", min(count, len(retained)), len(retained))
        if finding.get("next_step") and (finding.get("status") in ("FAIL", "WARN", "UNKNOWN") or self.details):
            _field("Далее", finding["next_step"])

    def group(self, title, prefixes, limit=None):
        items = self.select(prefixes)
        if not items:
            return
        _section(title)
        items.sort(key=lambda f: ORDER.get(f.get("status"), 5))
        retained = items[:limit] if limit else items
        for item in retained:
            self.item(item)
        if len(retained) < len(items):
            _shown("Проверки", len(retained), len(items))
        self.mark(items)

    def queue(self):
        snapshot = self.one("QUEUE.SNAPSHOT")
        if not snapshot and self.mode != "queue":
            return
        _section("Очередь СЕЙЧАС — снимок postqueue")
        if not snapshot:
            _line("[UNKNOWN] Текущий снимок очереди не получен.")
            return
        self.mark(self.select(("QUEUE.",)))
        data = snapshot.get("details", {})
        count = data.get("count")
        complete = data.get("complete")
        _line("[%s] Всего в текущем снимке: %s; полнота чтения: %s." % (snapshot.get("status", "UNKNOWN"), count if count is not None else "неизвестно", "полная" if complete is True else "не подтверждена"))
        if data.get("filtered"):
            _field("Совпало с фильтром", data.get("matched_count"))
            if data.get("filters"):
                _field("Фильтр текущей очереди", data["filters"])
        if count == 0 and complete is True:
            _line("Очередь пуста СЕЙЧАС. Это не означает отсутствие задержек или отказов в истории.", 2)
        entries = data.get("entries", [])
        if not entries and data.get("queue_ids"):
            entries = [{"queue_id": value, "unknown_fields": ["sender", "recipients", "arrival_time"]} for value in data["queue_ids"]]
        display_limit = 50 if self.details else 10
        selected = entries[:display_limit]
        omitted = data.get("entries_omitted", 0)
        if entries or omitted:
            _shown("Текущие записи", len(selected), data.get("matched_count", len(entries)+omitted) if data.get("filtered") else count if count is not None else len(entries)+omitted)
        if len(entries) > len(selected):
            _field("Записи, скрытые лимитом экрана", len(entries)-len(selected))
        for entry in selected:
            state = entry.get("queue_name", "состояние неизвестно")
            meaning = {"deferred": "временно отложено", "hold": "удерживается", "active": "отправляется", "incoming": "обрабатывается", "maildrop": "поступает"}.get(state)
            _line("%s | %s%s" % (entry.get("queue_id", "ID неизвестен"), state, " — " + meaning if meaning else ""), 2, role="key")
            age = entry.get("age_seconds")
            if age is None and isinstance(entry.get("arrival_time"), (int, float)):
                try:
                    now = datetime.fromisoformat(self.report["generated_at"]).timestamp() if self.report.get("generated_at") else datetime.now(timezone.utc).timestamp()
                    age = max(0, now-entry["arrival_time"])
                except (ValueError, TypeError, OverflowError):
                    pass
            arrival = entry.get("arrival_iso")
            if not arrival and entry.get("arrival_time") is not None:
                try:
                    arrival = datetime.fromtimestamp(entry["arrival_time"], timezone.utc).isoformat()
                except (ValueError, TypeError, OverflowError, OSError):
                    pass
            _field("Принято", _stamp(arrival, self.zone) if arrival else entry.get("arrival_text", "неизвестно"), 4)
            _field("Возраст / размер", _duration(age) + " / " + _size(entry.get("message_size", entry.get("size"))), 4)
            _field("Отправитель", "<> (bounce sender)" if entry.get("sender") == "" else entry.get("sender"), 4)
            recipients = entry.get("recipients", [])
            selected_recipients = recipients[:display_limit]
            missing = entry.get("recipients_omitted", 0)
            _shown("Получатели записи " + str(entry.get("queue_id", "?")), len(selected_recipients), entry.get("recipients_total", len(recipients)+missing))
            for recipient in selected_recipients:
                _field("Получатель", recipient.get("address"), 4)
                _field("Причина", recipient.get("delay_reason") or "причина в снимке не указана", 6)
            if not recipients:
                _field("Получатели", "не установлены из доступного снимка", 4)
            if missing:
                _field("Получатели, не сохранённые при сборе", missing, 4)
            if len(recipients) > len(selected_recipients):
                _field("Получатели, скрытые лимитом экрана", len(recipients)-len(selected_recipients), 4)
            if entry.get("unknown_fields"):
                _field("Недоступные поля", entry["unknown_fields"], 4)
        if data.get("recipient_domains"):
            self.counts("Домены получателей в текущем снимке", data["recipient_domains"], basis="получателей текущего снимка")
        if omitted:
            _field("Не сохранено записей текущего снимка", omitted)
        for evidence in snapshot.get("evidence", [])[:1]:
            if complete is not True:
                _field("Основание неполноты", _evidence(evidence))
        _line("Снимок не атомарен: очередь могла изменяться во время чтения.", 2)

    def counts(self, title, values, total=None, basis="структурированных событий"):
        if not values:
            return
        _line(title + " (число " + basis + "):")
        rows = sorted(values.items(), key=lambda item: (-item[1], str(item[0])))
        for name, count in rows[:self.limit]:
            _line("%s — %s" % (count, name), 2)
        if len(rows) > self.limit or total and total > len(rows):
            _shown("Группы", min(len(rows), self.limit), max(total or 0, len(rows)))

    def history(self):
        stats = self.report.get("statistics", {})
        if not stats:
            return
        self.mark(self.select(("MAIL-FLOW",)))
        _section("История доставки за выбранный период")
        _line("Наблюдаемые Queue ID/lifecycle: %d; групп сообщений: %d; попыток доставки: %d." % tuple(stats.get(k, 0) for k in ("queues", "observed_messages", "delivery_attempts")))
        _line("Успешных передач получателю: %d; deferred: %d; bounced: %d; expired: %d; hold: %d." % tuple(stats.get(k, 0) for k in ("recipient_delivery_events", "deferred", "bounced", "expired", "hold")))
        outcomes = stats.get("outcomes", {})
        _line("Этапы: следующий SMTP %d; внутренний SMTP %d; локальный транспорт %d. Отказов до очереди: %d." % (outcomes.get("next_smtp_accepted", 0), outcomes.get("internal_smtp_accepted", 0), outcomes.get("local_transport_accepted", 0), stats.get("rejected_before_queue", 0)))
        _line("Saved: транспорт %d; журнал Dovecot %d (события могут относиться к одному письму)." % (outcomes.get("saved", 0), stats.get("saved_log_events", 0)))
        self.counts("Отправители", stats.get("observed_sender_addresses", {}), stats.get("sender_address_count"))
        self.counts("Получатели", stats.get("observed_recipient_addresses", {}), stats.get("recipient_address_count"))
        sender_domains = Counter()
        for address, count in stats.get("observed_sender_addresses", {}).items():
            if "@" in address:
                sender_domains[address.rsplit("@", 1)[1].casefold()] += count
        if sender_domains:
            self.counts("Домены отправителей (по сохранённым группам адресов)", sender_domains)
        self.counts("Домены получателей", stats.get("top_recipient_domains", {}))
        self.counts("Отправляющие аккаунты", stats.get("top_authenticated_senders", {}))
        self.counts("Причины отказов до очереди", stats.get("top_rejection_reasons", {}))
        for kind, reasons in stats.get("delivery_reasons", {}).items():
            self.counts("Причины " + kind, reasons)

    def conclusions(self):
        answers = self.report.get("conclusions", [])
        if not answers:
            return
        _section("Ответ по доставке")
        ordered = sorted(answers, key=lambda item: ORDER.get(item.get("status"), 5))
        for answer in ordered[:self.limit]:
            _line("[%s] %s" % (answer.get("status", "UNKNOWN"), answer.get("title", "Исход неизвестен")))
            for value in answer.get("evidence", [])[:1]:
                _field("Основание", _evidence(value))
            if answer.get("next_step"):
                _field("Далее", answer["next_step"])
        _shown("Выводы", min(len(ordered), self.limit), len(ordered))

    def messages(self, limit=None):
        traces = self.report.get("traces", [])
        if not traces:
            return
        _section("Письма и попытки — наблюдаемые участки пути")
        severity = {"bounced": 0, "expired": 0, "deferred": 1, "hold": 1, "mixed": 1, "unknown": 2, "accepted": 2}
        traces = sorted(traces, key=lambda t: severity.get(t.get("outcome"), 3))
        limit = limit or self.limit
        _shown("Queue ID/lifecycle из истории", min(len(traces), limit), len(traces))
        for trace in traces[:limit]:
            events = trace.get("events", [])
            active = [event for event in events if event.get("in_window", True)]
            first, last = (active[0], active[-1]) if active else (events[0], events[-1]) if events else ({}, {})
            outcome = trace.get("outcome", "unknown")
            _line("%s | %s | %s" % (trace.get("queue_id", "ID неизвестен"), _stamp(first.get("time"), self.zone), OUTCOMES.get(outcome, outcome)), 2, role="key")
            _field("Узел / instance / lifecycle", "%s / %s / %s" % (trace.get("host", "?"), trace.get("instance", "?"), trace.get("generation", "?")), 4)
            _field("Отправитель", ["<> (bounce sender)" if value == "" else value for value in trace.get("senders", [])] or "не установлен", 4)
            recipients = trace.get("recipients", [])
            for address in recipients[:self.limit]:
                state = trace.get("recipient_outcomes", {}).get(address)
                _field("Получатель", address + (" — " + OUTCOMES.get(state, state) if state else " — исход отдельно не установлен"), 4)
            if len(recipients) > self.limit:
                _shown("Получатели " + str(trace.get("queue_id", "?")), self.limit, len(recipients))
            _field("Message-ID", trace.get("message_ids") or "не установлен", 4)
            deliveries = [event for event in active if event.get("kind") == "delivery"]
            for event in deliveries[-self.limit:]:
                _line("%s → %s | %s" % (_stamp(event.get("time"), self.zone), event.get("recipient", "?"), OUTCOMES.get(event.get("outcome"), event.get("status", "?"))), 4)
                _field("Relay / Postfix delay", "%s / %s" % (event.get("relay", "неизвестен"), _duration(event.get("delay"))), 6)
                if self.details and event.get("delays"):
                    _field("Составляющие delays, с", event["delays"], 6)
                if event.get("dsn"):
                    _field("DSN", event["dsn"], 6)
                _field("Ответ / причина", event.get("reason") or "в строке не указана", 6)
                _field("Источник", _location(event), 6)
            if len(deliveries) > self.limit:
                _shown("Попытки " + str(trace.get("queue_id", "?")), self.limit, len(deliveries))
            if not deliveries:
                _field("Последнее событие", _stamp(last.get("time"), self.zone) + "; " + str(last.get("kind", "неизвестно")), 4)
                if last:
                    _field("Источник", _location(last), 4)
            if self.details:
                _line("Timeline:", 4)
                for event in events[:100]:
                    self.event(event, 6)
                if len(events) > 100:
                    _shown("События timeline", 100, len(events))

    def event(self, event, indent=2):
        _line("%s | %s%s" % (_stamp(event.get("time"), self.zone), event.get("kind", "событие"), " (контекст до окна)" if event.get("in_window") is False else ""), indent)
        for key, label in (("client_ip", "IP клиента"), ("sender", "Отправитель"), ("recipient", "Получатель"), ("action", "Действие"), ("reason", "Причина"), ("relay", "Relay"), ("delay", "Postfix delay, с"), ("message_id", "Message-ID"), ("mailbox", "Папка")):
            if key in event:
                _field(label, event[key], indent+2)
        _field("Источник", _location(event), indent+2)

    def standalone(self):
        events = list(self.report.get("evidence", []))
        events += [e for f in self.findings if f.get("id") in {"MAIL-SAVED-EVENT", "MAIL-PREQUEUE-REJECT", "MAIL-PREQUEUE-POLICY"} for e in f.get("evidence", []) if isinstance(e, dict)]
        selected, seen = [], set()
        for event in events:
            if not isinstance(event, dict) or event.get("kind") not in {"saved", "rejected", "policy_action", "session_problem"}:
                continue
            key = (event.get("source"), event.get("line"), event.get("time"), event.get("kind"))
            if key not in seen:
                seen.add(key)
                selected.append(event)
        if selected:
            _section("Отдельные SMTP/Dovecot события")
            for event in selected[:self.limit]:
                self.event(event)
            _shown("События", min(len(selected), self.limit), len(selected))

    def greylist(self):
        items = self.select(("GREYLIST",))
        if not items and self.mode != "greylist":
            return
        _section("Greylisting — IP / отправитель / получатель и повторы")
        if not items:
            _line("[UNKNOWN] Подтверждённые Postgrey эпизоды в просмотренных данных не найдены.")
        for item in items[:self.limit]:
            self.item(item, evidence=False)
            data = item.get("details", {})
            if data.get("triplet"):
                triplet = data["triplet"]
                if len(triplet) == 3:
                    _field("Triplet", "%s | %s → %s" % tuple(triplet))
            if "observed_wait_seconds" in data:
                _field("Наблюдаемое ожидание", _duration(data["observed_wait_seconds"]))
            events = item.get("evidence", [])
            for event in events[:self.limit]:
                if isinstance(event, dict):
                    self.event(event)
                else:
                    _line(event, 2)
            if len(events) > self.limit:
                _shown("События эпизода", self.limit, len(events))
        if len(items) > self.limit:
            _shown("Эпизоды", self.limit, len(items))
        self.mark(items)
        _line("Pass относится к policy stage; он не доказывает сохранение. client AWL и явный client whitelist различаются.", 2)

    def mailstore(self):
        items = self.select(("mailstore.",))
        if not items and self.mode not in {"account", "mailboxes", "headers"}:
            return
        _section("Локальный аккаунт / квота / хранилище")
        user = next((f.get("details", {}).get("user") for f in items if f.get("details", {}).get("user")), None)
        if not user:
            user = next((e.get("user") for f in items for e in f.get("evidence", []) if isinstance(e, dict) and e.get("user")), None)
        user = user or self.report.get("filters", {}).get("user") or self.report.get("filters", {}).get("to")
        _field("Пользователь", user or "не установлен")
        if not items:
            _line("[UNKNOWN] Текущее состояние аккаунта и ящика не получено.")
        for item in items:
            self.mark([item])
            data = item.get("details", {})
            _line("[%s] %s" % (item.get("status", "UNKNOWN"), item.get("title", item.get("id", "Проверка"))))
            if item.get("id") == "mailstore.metadata":
                records = item.get("evidence", [])
                omitted = data.get("omitted_records", 0)
                selected = records[:50 if self.details else 20]
                _shown("Письма", len(selected), data.get("matching_records", len(records)+omitted), bool(data.get("truncated")))
                if len(records) > len(selected):
                    _field("Письма, скрытые лимитом экрана", len(records)-len(selected))
                if data.get("message_id_filter"):
                    _field("Message-ID фильтра", data["message_id_filter"])
                if data.get("precise_time_confirmed") is False:
                    _line("[UNKNOWN] Точное время части кандидатов не подтверждено; полный смысл окна не установлен.", 2)
                for record in selected:
                    if not isinstance(record, dict):
                        continue
                    _line("%s | UID %s | flags: %s" % (_text(record.get("mailbox")), _text(record.get("uid")), _text(record.get("flags", "неизвестно"))), 2, role="key")
                    _field("Получено / сохранено", "%s / %s" % (_text(record.get("date.received")), _text(record.get("date.saved"))), 4)
                    _field("Message-ID", record.get("hdr.message-id"), 4)
                    if self.mode == "headers" or self.details:
                        _field("Date", record.get("hdr.date"), 4)
                        received = record.get("hdr.received") or []
                        received = received if isinstance(received, list) else str(received).splitlines()
                        for value in received[:self.limit]:
                            _field("Received", value, 4)
                        if len(received) > self.limit:
                            _shown("Received", self.limit, len(received))
                    interval = record.get("header_intervals", {}).get("date_to_earliest_received_seconds")
                    if interval is not None:
                        _field("Date → самый ранний Received", _duration(interval) + "; часы заголовков не доказывают причину задержки", 4)
                if omitted:
                    _field("Не сохранено кандидатов сверх лимита", omitted)
            elif item.get("id") == "mailstore.quota" and data.get("rows") is not None:
                _line("Quota root | ресурс | использовано | лимит | % | единица", 2)
                for row in data["rows"]:
                    _line("%s | %s | %s | %s | %s | %s" % (_text(row.get("quota_root")), _text(row.get("resource")), _text(row.get("used")), "без лимита" if row.get("unlimited") else _text(row.get("limit")), _text(row.get("percent")), _text(row.get("unit"))), 2)
                    if row.get("complete") is False:
                        _line("[UNKNOWN] Строка квоты разобрана не полностью.", 4)
                if data.get("rows_omitted"):
                    _shown("Строки квоты", len(data["rows"]), len(data["rows"])+data["rows_omitted"])
            else:
                fields = data.get("fields") or next((e.get("fields") for e in item.get("evidence", []) if isinstance(e, dict) and e.get("fields")), {})
                for key, value in fields.items():
                    _field(key, value)
                for evidence in item.get("evidence", [])[:3]:
                    if isinstance(evidence, dict) and evidence.get("output"):
                        for line in str(evidence["output"]).splitlines()[:50]:
                            _line(line, 2)
                    elif not fields:
                        _field("Основание", _evidence(evidence))
            if data.get("error"):
                _field("Ошибка", data["error"])
            if item.get("next_step") and item.get("status") in {"UNKNOWN", "WARN", "FAIL"}:
                _field("Далее", item["next_step"])
        _line("Userdb lookup не доказывает включённую авторизацию. Физический размер не равен IMAP-квоте; текущая папка не доказывает причину перемещения.", 2)

    def network(self):
        self.group("Resolver / DNS / TLS / репутация", ("DNS.", "DNSBL.", "TLS.", "NETWORK.PROBES"))
        self.group("Маршрут Postfix / защита relay", ("POSTFIX.TRANSPORT", "POSTFIX.RELAY_GUARD", "POSTFIX.CONFIG", "POSTFIX.MASTER_COVERAGE", "ROUTE."))

    def whitelist(self):
        self.group("Whitelist — карты, совпадения и порядок", ("WHITELIST.", "POLICY."), limit=160 if self.details else 80)

    def coverage(self):
        _section("Источники и границы вывода")
        scope = self.report.get("scope", {})
        coverage = self.report.get("completeness", {})
        sources = self.report.get("sources", [])
        if scope.get("logs_selected") is False:
            _line("Логи в этой задаче не выбирались; текущие проверки показаны выше.")
        else:
            _line("Источники: %d; прочитано строк: %d; не разобрано для отчёта: %d; вне окна: %d; лимит достигнут: %s." % (len(sources), coverage.get("lines_read", 0), coverage.get("unparsed_lines", 0), coverage.get("unparsed_context", 0), "да" if coverage.get("truncated") else "нет"))
            _line("Не разобрано для отчёта = строки в окне или с неизвестным временем; ошибки вне окна показаны отдельно.", 2)
            _field("Полнота чтения выбранных логов", coverage.get("log_sources_complete", coverage.get("complete")))
        _field("Полнота необходимых проверок", coverage.get("checks_complete", coverage.get("complete")))
        for source in sources:
            if source.get("truncated") or source.get("errors") or source.get("unparsed_lines") or self.details:
                _field(source.get("path", "источник"), "строк %s; не разобрано %s; вне окна %s; %s" % (source.get("lines", "?"), source.get("unparsed_lines", 0), source.get("unparsed_context", 0), "; ".join(source.get("errors", [])) or ("достигнут лимит" if source.get("truncated") else "чтение завершено")))
        issues = [f for f in self.findings if f.get("status") in {"FAIL", "WARN", "UNKNOWN"} and id(f) not in self.used]
        if self.mode == "dns":
            issues = [f for f in issues if not f.get("id", "").startswith(("SECURITY.", "BACKUP.", "DISK."))]
        for item in sorted(issues, key=lambda f: ORDER.get(f.get("status"), 5))[:self.limit]:
            self.item(item)
        if len(issues) > self.limit:
            _shown("Дополнительные ограничения", self.limit, len(issues))
        limits = coverage.get("limitations", [])
        if self.details:
            for limit in limits[:20]:
                _field("Граница", limit)
        _line("SMTP 250 подтверждает следующий hop; Saved — сохранение в момент события, а не текущую папку.")
        _line("Полный структурированный результат: --json; приватный файл: --report НОВЫЙ_ПУТЬ. --details расширяет timeline и основания.")
        if self.report.get("redaction"):
            _field("Redaction", self.report["redaction"].get("limits"))

    def dashboard_header(self):
        version = self.report.get("tool", {}).get("version", __version__)
        for line in brand_header(version, compact=True):
            print(line)
        status = self.report.get("summary", {}).get("status", "UNKNOWN")
        labels = {"OK": "Проверка завершена", "WARN": "Требует внимания", "FAIL": "Обнаружен отказ",
                  "UNKNOWN": "Недостаточно данных", "N/A": "Проверка неприменима"}
        rows = [("[%s] %s" % (status, labels.get(status, "Результат проверки")), status)]
        window = self.report.get("window", {})
        if window:
            rows.extend([("Период: %s — %s" % (_stamp(window.get("since"), self.zone), _stamp(window.get("until"), self.zone)), "muted"),
                         ("Часовой пояс: " + _text(self.zone), "muted")])
        target = self.report.get("targets", {}).get("local_hostname")
        if target:
            rows.append(("Узел: " + _text(target), "key"))
        if self.report.get("filters"):
            labels = {"from": "отправитель", "to": "получатель", "domain": "домен", "ip": "IP", "client_name": "SMTP-клиент", "trace": "поиск", "message_id": "Message-ID", "user": "пользователь"}
            rows.append(("Фильтры: " + "; ".join("%s: %s" % (labels.get(k, k), _text(v)) for k, v in self.report["filters"].items()), "key"))
        snapshot = self.one("QUEUE.SNAPSHOT")
        if snapshot:
            data = snapshot.get("details", {})
            rows.append(("Очередь СЕЙЧАС: %s%s" % (_text(data.get("count")), "; совпало: " + _text(data.get("matched_count")) if data.get("filtered") else ""), "key"))
        stats = self.report.get("statistics", {})
        if stats:
            rows.append(("История: %s Queue ID/lifecycle; попыток: %s" % (_text(stats.get("queues", 0)), _text(stats.get("delivery_attempts", 0))), "key"))
        counts = self.report.get("summary", {}).get("counts", {})
        if counts:
            rows.append(("Проверки: " + " · ".join("%s %s" % (name, _text(counts.get(name, 0))) for name in ("OK", "WARN", "FAIL", "UNKNOWN")), "muted"))
        for line in panel(self.report.get("workflow") or MODES.get(self.mode, self.mode), rows,
                          width=min(118, viewport()[0]), status=status):
            print(line)

    def render(self):
        if is_terminal():
            self.dashboard_header()
        else:
            _line("MailRadar %s — %s" % (self.report.get("tool", {}).get("version", __version__), self.report.get("summary", {}).get("status", "UNKNOWN")), role="title")
            _line(self.report.get("workflow") or MODES.get(self.mode, self.mode), role="section")
            window = self.report.get("window", {})
            if window:
                _line("Период: %s — %s; часовой пояс: %s" % (_stamp(window.get("since"), self.zone), _stamp(window.get("until"), self.zone), self.zone))
        if self.report.get("filters") and not is_terminal():
            labels = {"from": "отправитель", "to": "получатель", "domain": "домен", "ip": "IP", "client_name": "SMTP-клиент", "trace": "поиск", "message_id": "Message-ID", "user": "пользователь"}
            _field("Фильтры истории" if self.mode == "queue" else "Фильтры", "; ".join("%s: %s" % (labels.get(k, k), _text(v)) for k, v in self.report["filters"].items()))
        self.targets()
        if self.mode == "queue":
            self.queue()
            self.history()
            if self.details:
                self.messages()
        elif self.mode == "dns":
            self.network()
        elif self.mode in {"account", "mailboxes", "headers"}:
            self.mailstore()
            self.group("Место и inode", ("DISK.",))
            self.conclusions()
            self.history()
            if self.report.get("statistics"):
                self.messages()
        elif self.mode == "greylist":
            self.greylist()
            self.history()
            self.messages()
        elif self.mode == "whitelist":
            self.whitelist()
            self.greylist()
        elif self.mode in {"doctor", "post-update"}:
            self.group("Узел и платформа", ("HOST.PLATFORM", "HOST.RUNTIME", "HOST.MIAB_REVISION"))
            self.queue()
            self.history()
            self.messages(8 if not self.details else 40)
            self.group("Почтовые службы", ("SERVICE.",))
            self.group("Место и inode", ("DISK.",))
            self.network()
            self.whitelist()
            self.group("Безопасность и локальные listeners", ("SECURITY.", "NETWORK.LISTENERS"))
            self.group("Backup tooling и последнее подтверждение", ("BACKUP.",))
            self.group("После обновления", ("UPDATE.",))
        else:
            self.conclusions()
            self.messages()
            self.standalone()
            self.history()
            self.queue()
            self.group("Почтовые службы", ("SERVICE.",))
            self.group("Место и inode", ("DISK.",))
            self.mailstore()
            self.greylist()
            self.network()
            self.whitelist()
        self.coverage()


def human(report, details=False, no_color=False):
    with presentation(no_color=no_color):
        ReportView(report, details).render()
