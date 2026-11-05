"""One CLI/menu and shared deterministic workflow."""
import argparse
import copy
import glob
import ipaddress
import json
import os
import re
import signal
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import __version__
from .model import clean, finding, finish_report, redact_report, write_private
from .runner import Runner, valid_user
from .display import human
from .timeutil import local_zone, timestamp
from .terminal import formatted_line, paint, panel, presentation, render_menu, viewport, wrap_cells
from .workflows import BY_MODE, CATALOGUE, HOST_MODES, LOG_MODES, MENU, TITLES


def parser():
    p = argparse.ArgumentParser(prog="mail-radar", description="MailRadar " + __version__ + ": локальная диагностика доставки. Сетевые пробы включаются только --network.")
    p.add_argument("period", nargs="?", type=float, help="старый числовой период в часах (по умолчанию 24)")
    modes = p.add_mutually_exclusive_group()
    for workflow in CATALOGUE:
        if workflow.value_name:
            modes.add_argument("--" + workflow.key, metavar=workflow.value_name, help=workflow.help)
        else:
            modes.add_argument("--" + workflow.key, action="store_const", const=workflow.key, dest="mode", help=workflow.help)
    p.add_argument("--from", dest="sender", metavar="ADDRESS")
    p.add_argument("--to", metavar="ADDRESS")
    p.add_argument("--domain")
    p.add_argument("--ip")
    p.add_argument("--client-name")
    p.add_argument("--client-ip")
    p.add_argument("--peer", help="IP для проверки runtime route и границ persistence")
    p.add_argument("--user", help="один локальный адрес Dovecot")
    p.add_argument("--hours", type=float)
    p.add_argument("--since", help="ISO 8601, offset/Z или локальное время с --timezone")
    p.add_argument("--until", help="ISO 8601")
    p.add_argument("--timezone", default="local", help="IANA zone или UTC; по умолчанию часовой пояс сервера")
    p.add_argument("--year", type=int, help="явный год исторического syslog")
    p.add_argument("--log", action="append", default=[], help="лог/архив; повторяемый флаг, '-' читает stdin")
    p.add_argument("--journal", action="store_true", help="также прочитать bounded journal Postfix/Dovecot/Postgrey")
    p.add_argument("--offline", action="store_true", help="только переданные логи, без внешних команд")
    p.add_argument("--network", action="store_true", help="явно разрешить bounded DNS/TLS/local management пробы")
    p.add_argument("--dkim-selector", help="известный selector; без угадывания")
    p.add_argument("--deep", action="store_true", help="ограниченный физический обход только --user")
    p.add_argument("--seconds", type=float, default=180, help="длительность watch (до 3600 секунд)")
    p.add_argument("--max-bytes", type=int, default=32*1024*1024)
    p.add_argument("--max-lines", type=int, default=150000)
    p.add_argument("--json", action="store_true", help="JSON; watch выводит NDJSON")
    p.add_argument("--report", metavar="NEW_PATH", help="новый приватный JSON-файл, без перезаписи")
    p.add_argument("--redact", action="store_true", help="заменить адреса/IP/домены в экспортируемом отчёте")
    p.add_argument("--details", action="store_true", help="подробные проверки и строки доказательств")
    p.add_argument("--menu", action="store_true", help="интерактивная сессия с возвратом в меню")
    p.add_argument("--no-color", action="store_true", help="отключить цвета меню и отчётов (также NO_COLOR/TERM=dumb)")
    p.add_argument("--version", action="version", version="MailRadar "+__version__)
    return p


def _ask(prompt):
    lines = wrap_cells(prompt, max(1, min(118, viewport()[0])-1))
    for line in lines[:-1]:
        print(paint(line, "prompt"))
    return input(paint(lines[-1].rstrip() + " ", "prompt"))


def _notice(message, role=None):
    for index, line in enumerate(wrap_cells(message, min(118, viewport()[0]))):
        print(formatted_line(line, "plain" if index and role is None else role), flush=True)


def menu(args):
    labels = ("Общий обзор", "Входящее письмо", "Исходящее письмо", "Задержка доставки",
              "Папки / Spam / Trash", "Очередь / SMTP-отказы", "Greylisting / повторы",
              "Whitelist SMTP-клиента", "DNS / TLS / resolver", "Аккаунт / квота / диск",
              "После обновления MIAB", "Наблюдать за доставкой", "Поиск ID / адреса", "Заголовки письма")
    items = [dict(number=number, label=labels[number-1], description=workflow.help) for number, workflow in enumerate(MENU, 1)]
    context = "ОФЛАЙН · источников: %d" % len(args.log) if args.offline else "ЛОКАЛЬНАЯ ДИАГНОСТИКА · сеть по запросу"
    redraw = True
    while True:
        if redraw:
            render_menu(__version__, items, context=context)
            redraw = False
        choice = _ask("Номер [1]: ").strip().lower() or "1"
        if choice in ("0", "q", "quit", "exit", "выход"):
            return None
        if choice in ("r", "обновить"):
            redraw = True
            continue
        if choice in ("?", "h", "help", "справка"):
            help_rows = ["1–5: обзор, расследование письма и его текущая папка.",
                         "6–8: текущая очередь, SMTP-отказы, greylisting и whitelist.",
                         "9–11: DNS/TLS, аккаунт/квота, состояние после обновления.",
                         "12–14: наблюдение, поиск по ID/адресу и выбранные заголовки.",
                         "Enter: общий обзор. r: перерисовать под размер окна. 0/q: выход.",
                         "DNS-домен выбирается отдельно; resolver/TLS относятся к локальному MIAB."]
            for line in panel("Справка по задачам", help_rows):
                print(line)
            continue
        if choice.isdigit() and 1 <= int(choice) <= len(MENU):
            break
        for line in wrap_cells("Введите номер от 0 до %d; ? — справка, r — обновить меню." % len(MENU), viewport()[0]):
            print(paint(line, "error"))
    args.mode = MENU[int(choice)-1].key
    args.trace = args.headers = None
    workflow = BY_MODE[args.mode]
    if workflow.envelope_prompt:
        args.sender = _ask("Отправитель (если известен): ").strip() or None
        args.to = _ask("Получатель (если известен): ").strip() or None
    if args.mode == "trace":
        args.trace = _ask("Message-ID, Queue ID, адрес, домен или IP: ").strip()
        if not args.trace:
            raise ValueError("Для поиска нужно указать известный идентификатор или адрес")
    if workflow.requires_user:
        args.user = _ask("Локальный адрес: ").strip()
        if not valid_user(args.user):
            raise ValueError("Нужен один корректный локальный адрес")
        if args.mode == "headers":
            args.headers = _ask("Message-ID: ").strip()
            if not args.headers:
                raise ValueError("Укажите Message-ID письма")
        elif args.mode == "mailboxes":
            args.headers = _ask("Message-ID (если известен, иначе поиск за период): ").strip() or None
    if workflow.period_prompt:
        args.hours = float(_ask("Период в часах [24]: ").strip() or "24")
        args.timezone = _ask("Часовой пояс [local, часовой пояс сервера]: ").strip() or "local"
        args.since = _ask("Начало ISO 8601 с offset (необязательно): ").strip() or args.since
    if args.mode == "watch":
        args.seconds = float(_ask("Наблюдать секунд [180]: ").strip() or "180")
    if args.mode == "whitelist":
        args.client_name = _ask("Имя SMTP-клиента (если известно): ").strip() or None
        args.client_ip = _ask("IP SMTP-клиента (если известен): ").strip() or None
    if int(choice) == 9:
        args.domain = _ask("Проверяемый домен (пусто — домен сервера): ").strip() or None
        _notice("DNS проверяется для выбранного домена. TLS, resolver и relay относятся к MIAB, где запущен Radar.", "muted")
        args.network = _ask("Выполнить DNS-запросы и TLS-проверки? [y/N]: ").lower() in ("y", "yes", "д", "да")
    if args.mode == "post-update":
        args.network = _ask("Выполнить ограниченные DNS/TLS/HTTP-пробы? [y/N]: ").lower() in ("y", "yes", "д", "да")
    return args

def validate(p, args):
    for field in ("sender", "to", "user"):
        value = getattr(args, field)
        if value and not valid_user(value):
            p.error("Некорректный адрес: --"+("from" if field == "sender" else field))
    for field in ("domain", "client_name", "dkim_selector"):
        value = getattr(args, field)
        if value and field == "domain":
            try:
                ipaddress.ip_address(value.rstrip("."))
            except ValueError:
                pass
            else:
                p.error("--domain принимает доменное имя; для IP используйте --ip")
        if value and (len(value) > 253 or not re.fullmatch(r"[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?", value)):
            p.error("Некорректное имя: --"+field.replace("_", "-"))
    for field in ("ip", "client_ip", "peer"):
        try:
            if getattr(args, field):
                ipaddress.ip_address(getattr(args, field))
        except ValueError:
            p.error("Некорректный IP: --"+field.replace("_", "-"))
    for field in ("trace", "headers"):
        value = getattr(args, field)
        if value is not None and (not value.strip() or len(value) > 998 or any(ord(c) < 32 for c in value) or value.startswith("-")):
            p.error("Недопустимое значение --"+field)
    if not 0 < args.seconds <= 3600 or not 1024 <= args.max_bytes <= 128*1024*1024 or not 1 <= args.max_lines <= 500000:
        p.error("Недопустимый лимит/длительность")
    hours = args.hours if args.hours is not None else args.period if args.period is not None else 24
    if not 0 < hours <= 24*366 or args.year is not None and not 1970 <= args.year <= 9998:
        p.error("Некорректный период/год")
    if args.offline and (args.network or args.journal):
        p.error("--offline запрещает --network и --journal")
    if args.offline and not args.log:
        p.error("Для --offline нужен --log")
    workflow = BY_MODE[args.mode]
    logs_selected = workflow.logs or bool(args.log) or args.journal
    if not logs_selected:
        if args.sender or args.to and not workflow.store:
            p.error("--from/--to фильтруют историю писем; добавьте --log или выберите задачу доставки")
        if (args.domain or args.ip) and args.mode != "dns":
            p.error("--domain/--ip нужны для истории или DNS; SMTP-клиент whitelist задаётся --client-name/--client-ip")
    if (args.client_name or args.client_ip) and args.mode not in {"doctor", "post-update", "incoming", "outgoing", "delay", "diagnose", "whitelist"}:
        p.error("--client-name/--client-ip нужны для whitelist-проверок; для поиска в истории используйте --trace или --ip")
    if args.peer and args.mode not in {"doctor", "post-update", "incoming", "outgoing", "delay", "diagnose", "dns"}:
        p.error("--peer применим к обзору, расследованию доставки или DNS/route")
    if workflow.requires_user and not args.user:
        p.error("Для --" + args.mode + " нужен один --user")
    if workflow.requires_user and args.to and args.to.casefold() != args.user.casefold():
        p.error("--to и --user должны указывать один локальный ящик")
    if workflow.requires_user and not (args.log or args.journal) and any((args.sender, args.domain, args.ip, args.client_name, args.client_ip)):
        p.error("Фильтры адресов/домена/IP применяются к логам; для метаданных выберите --user, Message-ID и период, либо добавьте --log")
    if args.mode == "watch" and (args.journal or "-" in args.log or any(path.endswith((".gz", ".bz2", ".xz", ".lzma")) for path in args.log)):
        p.error("Watch читает обычные файлы; укажите --log /var/log/mail.log")
    if args.deep and not (args.user or args.to):
        p.error("Для --deep нужен --user или --to")
    if args.deep and not workflow.store:
        p.error("--deep применим только к выбранному локальному ящику в mailbox/account/diagnosis задачах")
    if args.user and not workflow.store:
        p.error("--user применим к mailbox/account/headers/diagnosis задачам; для отправителя используйте --from")
    return hours


def default_logs():
    paths = set(glob.glob("/var/log/mail.log*") + glob.glob("/var/log/maillog*"))
    def priority(path):
        m = re.search(r"\.(\d+)(?:\.(?:gz|bz2|xz|lzma))?$",path)
        number = int(m[1]) if m else 0
        return (2,-number,path) if m and len(m[1])==8 else (1,number,path) if m else (0,0,path)
    return sorted(paths,key=priority)


def source_labels(value, mapping):
    if isinstance(value, str):
        for temporary, label in mapping.items():
            value = value.replace(temporary, label)
        return value
    if isinstance(value, dict):
        return {k: source_labels(v, mapping) for k, v in value.items()}
    if isinstance(value, list):
        return [source_labels(v, mapping) for v in value]
    return value


def conclusions(report, recipient=None):
    labels = {
        "saved": ("OK", "подтверждено сохранение; текущая папка требует Dovecot-поиска"),
        "next_smtp_accepted": ("OK", "следующий SMTP-сервер принял письмо; внешний INBOX неизвестен"),
        "internal_smtp_accepted": ("UNKNOWN", "внутренний SMTP-узел принял письмо; нужен следующий участок"),
        "local_transport_accepted": ("OK", "локальный транспорт принял письмо; сохранение не подтверждено"),
        "deferred": ("WARN", "попытка временно отложена; последующий исход неизвестен"),
        "bounced": ("FAIL", "подтверждён постоянный отказ получателю"),
        "expired": ("FAIL", "истёк срок жизни очереди"),
        "hold": ("WARN", "очередь удерживается"),
        "accepted": ("UNKNOWN", "принято в очередь; последующая доставка не подтверждена"),
        "discarded": ("WARN", "транспорт discard подтвердил удаление; это не сохранение в ящик"),
        "unknown": ("UNKNOWN", "исход не установлен по доступным данным"),
    }
    answers = []
    for trace in report.get("traces", []):
        final = {}
        for event in trace["events"]:
            if not event.get("in_window", True):
                continue
            if event["kind"] == "delivery" and (not recipient or recipient.casefold() in (str(event.get("recipient", "")).casefold(), str(event.get("orig_to", "")).casefold())):
                final[event["recipient"]] = event
        for address, outcome in trace.get("recipient_outcomes", {}).items():
            if address in final and outcome in ("expired", "hold"):
                terminal = [e for e in trace["events"] if e.get("in_window") and e["kind"] == outcome]
                final[address] = dict(terminal[-1] if terminal else final[address], outcome=outcome)
        if not final:
            events = [e for e in trace["events"] if e.get("in_window") and e["kind"] in ("expired", "hold", "accepted")]
            final[recipient or ",".join(trace.get("recipients", [])) or "получатель неизвестен"] = events[-1] if events else {}
        for address, event in final.items():
            outcome = event.get("outcome", event.get("kind", "unknown"))
            status, text = labels.get(outcome, labels["unknown"])
            evidence = {k: event[k] for k in ("source", "line", "time", "text", "dsn", "delay", "delays", "relay") if k in event}
            answers.append(dict(trace_id=trace["id"], status=status, outcome=outcome,
                                title="%s → %s: %s" % (trace["queue_id"], address, text), evidence=[evidence] if evidence else [],
                                next_step="Сверьте точный SMTP/DSN response и следующую попытку." if outcome in ("deferred", "bounced") else ""))
    saved = list(report.get("evidence", []))
    saved.extend(e for f in report.get("findings", []) if f["id"] == "MAIL-SAVED-EVENT" for e in f.get("evidence", []))
    seen = set()
    for event in saved:
        if event.get("kind") != "saved" or not event.get("in_window", True):
            continue
        if recipient and recipient.casefold() != str(event.get("recipient", "")).casefold():
            continue
        identity = (event.get("source"), event.get("line"), event.get("time"))
        if identity in seen:
            continue
        seen.add(identity)
        answers.append(dict(status="OK", outcome="saved", message_id=event.get("message_id"),
                            title="Dovecot → %s: подтверждено сохранение; текущая папка требует Dovecot-поиска" % event.get("recipient", "получатель неизвестен"),
                            evidence=[{k: event[k] for k in ("source", "line", "time", "text", "mailbox") if k in event}],
                            next_step="Отдельная запись без Queue ID не связывается автоматически с очередью по одному Message-ID."))
    if not answers:
        relevant = [f for f in report["findings"] if f["id"] in ("MAIL-PREQUEUE-REJECT", "GREYLIST-RETRY-PASS", "GREYLIST-UNRESOLVED")]
        for item in relevant[:5]:
            answers.append({k: item.get(k, "") for k in ("status", "title", "evidence", "next_step")})
    return answers


def analyze(args, runner, since, until, paths):
    from .logs import analyze_logs
    from .checks import collect_checks
    from .mailstore import collect_mailstore
    selected_recipient = args.to or (args.user if args.mode in {"mailboxes", "headers", "account"} else None)
    filters = {k: v for k, v in {"from": args.sender, "to": selected_recipient, "domain": args.domain,
                                "ip": args.ip or (args.client_ip if args.mode == "whitelist" else None),
                                "client_name": args.client_name if args.mode == "whitelist" else None,
                                "trace": args.trace, "message_id": args.headers}.items() if v}
    logs_selected = args.mode in LOG_MODES or bool(paths) or args.journal
    logs = analyze_logs(paths, since, until, timezone=args.timezone, year=args.year, filters=filters, max_bytes=args.max_bytes, max_lines=args.max_lines, recent=getattr(args,"recent_logs",False)) if logs_selected else dict(
        findings=[], sources=[], traces=[], evidence=[], statistics={}, completeness=dict(complete=True, truncated=False, lines_read=0, unparsed_lines=0))
    logs["completeness"]["log_sources_complete"] = logs["completeness"]["complete"]
    logs["completeness"]["checks_complete"] = True
    report = dict(schema_version="1.0", tool=dict(name="MailRadar", version=__version__), mode=args.mode,
                  workflow=TITLES.get(args.mode, args.mode), scope=dict(logs_selected=logs_selected, user=args.user),
                  window=dict(since=since.isoformat(), until=until.isoformat(), timezone=args.timezone, year=args.year), filters=filters, **logs)
    for item in report["findings"]:
        item.setdefault("window", report["window"])
        item.setdefault("check_type", "logs")
    if not args.offline and args.mode in HOST_MODES:
        host = collect_checks(runner, args)
        for item in host:
            item.setdefault("window", report["window"])
            item.setdefault("check_type", "host")
        report["findings"].extend(host)
        report["targets"] = next((item["details"] for item in host if item["id"] == "HOST.TARGETS"), {})
    workflow = BY_MODE[args.mode]
    if not args.offline and (workflow.store == "user" or workflow.store == "recipient" and (args.user or args.to)):
        store_args = copy.copy(args)
        message_ids = {mid for trace in report.get("traces", []) for mid in trace.get("message_ids", [])}
        if not args.headers and len(message_ids) == 1:
            store_args.headers = next(iter(message_ids))
        report["findings"].extend(collect_mailstore(runner, store_args, since, until))
    if args.offline and args.mode in ("headers", "mailboxes", "account", "dns", "queue", "whitelist", "post-update"):
        report["findings"].append(finding("offline.unavailable", "UNKNOWN", "Офлайн-логи не содержат текущую конфигурацию и состояние хранилища"))
    report["active_probes"] = [cmd for cmd in runner.history if cmd[0] in ("dig", "openssl", "curl")]
    report["commands"] = runner.history
    if workflow.conclusions:
        report["conclusions"] = conclusions(report, args.to or args.user)
    if any(f["status"] == "UNKNOWN" for f in report["findings"] + report.get("conclusions", [])):
        report["completeness"]["checks_complete"] = False
        report["completeness"]["complete"] = False
        report["completeness"].setdefault("limitations", []).append("One or more checks or delivery conclusions lack evidence; see UNKNOWN results.")
    report = finish_report(report)
    return report


def watch(args, runner, since, until, paths, interrupted):
    import stat as stat_module
    from .logs import analyze_logs
    started, end = time.monotonic(), time.monotonic()+args.seconds
    handles, snapshots, buffers, observed = {}, {}, {}, {}
    total, last_update = 0, 0
    limitations = []
    capture_truncated = False
    def emit(kind, **values):
        payload = dict(type=kind, time=datetime.now(timezone.utc).isoformat(), **values)
        if args.json:
            print(json.dumps(payload, ensure_ascii=False), flush=True)
        elif kind == "watch_started":
            _notice("Наблюдение начато · %g с · Ctrl+C — завершить" % values["seconds"], "section")
            _notice("Ротация и усечение могут оставлять пробелы; они будут указаны в итоговом отчёте.", "muted")
        elif kind == "watch_progress":
            _notice("Прочитано байт: %d · найдено Queue ID/lifecycle: %d" % (values["bytes_observed"], values["matched_queues"]), "key")
            for item in values.get("findings", []):
                _notice("[%s] %s" % (item["status"], clean(item["title"])))
        elif kind == "source_gap":
            reasons = {
                "Watch source missing, unreadable or not a regular file at start": "Файл отсутствует, недоступен или не является обычным файлом при старте",
                "Watch source missing/unreadable during observation": "Источник недоступен во время наблюдения",
                "Observed source truncation: possible gap": "Файл усечён; возможен пропуск событий",
                "Watch line length limit: partial line discarded": "Достигнут предел длины строки; неполная строка пропущена",
                "Partial line at rotation discarded": "Неполная строка при ротации пропущена",
                "Observed rotation: possible race/gap": "Обнаружена ротация; возможен пропуск событий",
                "Watch byte limit reached": "Достигнут лимит чтения байтов",
                "Trailing partial line discarded": "Незавершённая последняя строка пропущена",
            }
            _notice("[UNKNOWN] " + reasons.get(values["reason"], clean(values["reason"])))
        else:
            _notice(kind + ": " + json.dumps(values, ensure_ascii=False))
    def gap(reason, truncated=False):
        nonlocal capture_truncated
        capture_truncated = capture_truncated or truncated
        if reason not in limitations and len(limitations) < 100:
            limitations.append(reason)
            emit("source_gap", reason=clean(reason))
    with tempfile.TemporaryDirectory(prefix="mail-radar-watch-") as directory:
        def attach(name, at_end=False):
            info = os.stat(name)
            if not stat_module.S_ISREG(info.st_mode):
                raise ValueError("Watch requires regular files")
            fd = os.open(name, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
            stream = os.fdopen(fd, "rb")
            opened = os.fstat(fd)
            if not stat_module.S_ISREG(opened.st_mode):
                stream.close()
                raise ValueError("Watch requires regular files")
            if at_end:
                stream.seek(0, 2)
            handles[name] = (stream, opened.st_dev, opened.st_ino)
            if name not in snapshots:
                path = Path(directory)/(str(len(snapshots))+".log")
                out = open(path, "wb")
                os.chmod(path, 0o600)
                snapshots[name] = (path, out)
                buffers[name] = b""
                observed[name] = 0
        for name in paths:
            try:
                attach(name, at_end=True)
            except (OSError,ValueError):
                gap("Watch source missing, unreadable or not a regular file at start")
        emit("watch_started", seconds=args.seconds, limitations="Rotation/truncation races may lose events; finish with trace over retained logs.")
        try:
            while time.monotonic() < end and not interrupted[0]:
                changed = False
                for name in paths:
                    try:
                        if name not in handles:
                            attach(name)
                        info = os.stat(name)
                        stream, device, inode = handles[name]
                        rotated = (device, inode) != (info.st_dev, info.st_ino)
                        if info.st_size < stream.tell() and not rotated:
                            stream.seek(0)
                            buffers[name] = b""
                            gap("Observed source truncation: possible gap")
                        data = stream.read(min(65536, max(0, args.max_bytes-total)))
                        total += len(data)
                        observed[name] += len(data)
                        pending = buffers[name]+data
                        if b"\n" in pending:
                            complete, tail = pending.rsplit(b"\n", 1)
                            snapshots[name][1].write(complete+b"\n")
                            snapshots[name][1].flush()
                            buffers[name] = tail
                            changed = True
                        else:
                            buffers[name] = pending
                        if len(buffers[name]) > 65536:
                            gap("Watch line length limit: partial line discarded", truncated=True)
                            buffers[name] = b""
                        if rotated and not data:
                            if buffers[name]:
                                gap("Partial line at rotation discarded")
                                buffers[name] = b""
                            stream.close()
                            attach(name)
                            gap("Observed rotation: possible race/gap")
                        if total >= args.max_bytes:
                            gap("Watch byte limit reached", truncated=True)
                            end = time.monotonic()
                    except OSError:
                        gap("Watch source missing/unreadable during observation")
                if changed and time.monotonic()-last_update >= 1:
                    filters = {k: v for k,v in {"from": args.sender,"to": args.to,"trace":args.trace,"domain":args.domain,"ip":args.ip}.items() if v}
                    current = analyze_logs([str(v[0]) for v in snapshots.values()], since, datetime.now(timezone.utc), timezone=args.timezone, year=args.year, filters=filters, max_bytes=args.max_bytes, max_lines=args.max_lines)
                    emit("watch_progress", bytes_observed=total, matched_queues=len(current["traces"]), findings=[dict(id=f["id"],status=f["status"],title=f["title"]) for f in current["findings"] if f["status"] in ("FAIL","WARN")][:10] if not args.redact else [])
                    last_update = time.monotonic()
                time.sleep(.1)
        finally:
            for stream, _, _ in handles.values():
                stream.close()
            for _, out in snapshots.values():
                out.close()
        if any(buffers.values()):
            gap("Trailing partial line discarded")
        analysis_args = copy.copy(args)
        analysis_args.redact = False
        report = analyze(analysis_args, runner, since, datetime.now(timezone.utc), [str(v[0]) for v in snapshots.values()])
        report = source_labels(report, {str(v[0]): name for name, v in snapshots.items()})
        for source in report["sources"]:
            source.update(kind="watch", bytes_observed=observed.get(source["path"], 0))
        report["completeness"]["limitations"] = report["completeness"].get("limitations", []) + limitations + ["Live watch is not a lossless log collector; retained-log trace is recommended."]
        report["completeness"]["truncated"] = report["completeness"].get("truncated", False) or capture_truncated
        if interrupted[0] or limitations:
            report["completeness"]["complete"] = False
            report["completeness"]["log_sources_complete"] = False
            report["completeness"]["checks_complete"] = False
            report["findings"].append(finding("watch.incomplete", "UNKNOWN", "Наблюдение прервано или содержит пробелы", evidence=limitations))
        report["watch"] = dict(elapsed_seconds=round(time.monotonic()-started, 2), interrupted=bool(interrupted[0]), bytes_observed=total, reason="signal" if interrupted[0] else "duration_or_limit")
        report = finish_report(report)
        if args.redact:
            report = redact_report(report)
        return report


def _run_once(args, p):
    try:
        args.mode = args.mode or ("trace" if args.trace is not None else "headers" if args.headers is not None else "doctor")
        hours = validate(p, args)
        zone = local_zone() if args.timezone == "local" else ZoneInfo(args.timezone)
        args.timezone = getattr(zone, "key", str(zone))
        until = timestamp(args.until, zone) if args.until else datetime.now(timezone.utc)
        since = timestamp(args.since, zone) if args.since else until-timedelta(hours=hours)
        if since >= until:
            p.error("--since должен предшествовать --until")
    except (ValueError, ZoneInfoNotFoundError, OverflowError) as error:
        p.error(str(error))
    runner, interrupted = Runner(network=args.network, offline=args.offline), [False]
    def stop(signum, frame):
        interrupted[0] = signum
        runner.close()
        if args.mode != "watch":
            raise KeyboardInterrupt
    previous_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    for sig in previous_handlers:
        signal.signal(sig, stop)
    try:
        if args.report and os.path.lexists(args.report):
            raise FileExistsError("Файл отчёта уже существует: "+args.report)
        with tempfile.TemporaryDirectory(prefix="mail-radar-") as scratch:
            args.recent_logs = not args.log and not args.offline
            paths = list(args.log) or ([] if args.offline or args.mode not in LOG_MODES else default_logs())
            labels = {}
            if "-" in paths:
                target = Path(scratch)/"stdin.log"
                data = sys.stdin.buffer.read(args.max_bytes+1)
                target.write_bytes(data[:args.max_bytes])
                os.chmod(target, 0o600)
                paths = [str(target) if path == "-" else path for path in paths]
                labels[str(target)] = "stdin"
                stdin_truncated = len(data) > args.max_bytes
            else:
                stdin_truncated = False
            journal_result = None
            if args.journal:
                journal_result = runner.run(["journalctl", "--no-pager", "-o", "short-iso-precise", "--reverse", "--since", (since-timedelta(hours=24)).isoformat(), "--until", until.isoformat(), "-u", "postfix", "-u", "postfix@*.service", "-u", "dovecot", "-u", "postgrey"], timeout=15)
                path = Path(scratch)/"journal.log"
                # Capture newest first under the runner's byte cap, restore
                # source order for equal timestamps before event correlation.
                path.write_text("\n".join(reversed(journal_result.stdout.splitlines()))+"\n", encoding="utf-8")
                os.chmod(path, 0o600)
                paths.append(str(path))
                labels[str(path)] = "journal:postfix,dovecot,postgrey"
            if args.mode == "watch":
                paths = args.log or ["/var/log/mail.log"]
                report = watch(args, runner, since, until, paths, interrupted)
            else:
                report = source_labels(analyze(args, runner, since, until, paths), labels)
                if stdin_truncated or journal_result is not None and not journal_result.ok:
                    report["findings"].append(finding("sources.incomplete", "UNKNOWN", "stdin/journal прочитан не полностью", evidence=[dict(stdin_truncated=stdin_truncated, journal_error=journal_result.stderr if journal_result else "", journal_truncated=bool(journal_result and journal_result.truncated), journal_timed_out=bool(journal_result and journal_result.timed_out), journal_missing=bool(journal_result and journal_result.missing))]))
                    report["completeness"]["complete"] = False
                    report["completeness"]["log_sources_complete"] = False
                    report["completeness"]["checks_complete"] = False
                    if stdin_truncated or journal_result is not None and journal_result.truncated:
                        report["completeness"]["truncated"] = True
                    report = finish_report(report)
                if args.redact:
                    report = redact_report(report)
            if args.report:
                write_private(args.report, json.dumps(report, ensure_ascii=False, indent=2)+"\n")
            if args.mode == "watch" and args.json:
                print(json.dumps(dict(type="report",report=report),ensure_ascii=False),flush=True)
                print(json.dumps(dict(type="watch_finished",interrupted=bool(interrupted[0]),bytes_observed=report["watch"]["bytes_observed"])),flush=True)
            elif args.json:
                print(json.dumps(report,ensure_ascii=False))
            else:
                human(report,details=args.details,no_color=args.no_color)
                if args.report:
                    _notice("Приватный отчёт сохранён: "+clean(args.report))
            return 130 if interrupted[0] else report["summary"]["exit_code"]
    except KeyboardInterrupt:
        report = finish_report(dict(mode=args.mode, findings=[finding("run.interrupted", "UNKNOWN", "Диагностика прервана сигналом; результат неполный")], completeness=dict(complete=False)))
        if args.json:
            print(json.dumps(report, ensure_ascii=False))
        else:
            print("Диагностика прервана; результат неполный.", file=sys.stderr)
        return 130
    except (OSError, ValueError, OverflowError) as error:
        message = dict(type="error", error=clean(error), complete=False)
        print(json.dumps(message, ensure_ascii=False) if args.json else "Ошибка: "+clean(error), file=sys.stderr)
        return 3
    finally:
        try:
            runner.close()
        finally:
            for sig, handler in previous_handlers.items():
                signal.signal(sig, handler)


def main(argv=None):
    p = parser()
    raw = list(sys.argv[1:] if argv is None else argv)
    args = p.parse_args(raw)
    args.root = "/"
    tty = sys.stdin.isatty() and sys.stdout.isatty()
    interactive = args.menu or not raw and tty
    if args.menu and not tty:
        p.error("--menu требует интерактивный терминал; для автоматизации используйте CLI-флаги")
    if interactive and args.json:
        p.error("--menu и --json несовместимы")
    if interactive and "-" in args.log:
        p.error("--menu и --log - используют один stdin; укажите файл логов")
    with presentation(no_color=args.no_color or args.json):
        if not interactive:
            return _run_once(args, p)
        return _session(args, p)


def _session(args, p):
    last_code = 0
    def menu_error(message):
        raise ValueError(message)
    p.error = menu_error
    try:
        while True:
            try:
                selected = menu(copy.deepcopy(args))
                if selected is None:
                    return last_code
                print()
                _notice("Проверка: " + TITLES[selected.mode], "section")
                last_code = _run_once(selected, p)
            except (ValueError, ZoneInfoNotFoundError) as error:
                _notice("Ошибка ввода: " + clean(error), "error")
            except SystemExit as error:
                if error.code not in (2,3):
                    raise
                last_code = error.code
            print()
            again = _ask("Enter — вернуться в меню; 0 — выход: ").strip().lower()
            if again in ("0","q","quit","exit","выход"):
                return last_code
            args.report = None  # an explicit create-once report path applies to the first run
    except EOFError:
        return last_code
    except KeyboardInterrupt:
        print("\n" + paint("Сессия завершена.", "muted"))
        return 130


if __name__ == "__main__":
    sys.exit(main())
