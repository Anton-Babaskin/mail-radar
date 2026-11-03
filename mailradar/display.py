"""Terminal presentation: readable summaries, technical evidence on request."""
from datetime import datetime

from . import __version__
from .model import clean


def _evidence(item):
    if isinstance(item, str):
        return clean(item, 240)
    if not isinstance(item, dict):
        return ""
    if "mailbox" in item:
        return clean("Папка: %s; received: %s; saved: %s; Message-ID: %s" % tuple(item.get(k,"неизвестно") for k in ("mailbox","date.received","date.saved","hdr.message-id")),350)
    source = item.get("source", "")
    if item.get("command"):
        source = " ".join(item["command"])
    location = str(source)
    if item.get("line") is not None:
        line = item["line"]
        location += ":%s" % line if line >= 0 else " (строка с конца %d)" % -line
    text = item.get("text") or item.get("error") or item.get("stderr") or ""
    delay = "Postfix delay=%s с; " % item["delay"] if "delay" in item else ""
    return clean(delay + location + (": " + str(text) if text else ""), 350)


def _date(value, zone="UTC"):
    try:
        from .logs import _zone
        return datetime.fromisoformat(value).astimezone(_zone(zone)).strftime("%d.%m %H:%M %z")
    except (ValueError, TypeError):
        return str(value)


def human(report, details=False):
    summary = report["summary"]
    print("\nMailRadar %s — %s" % (__version__, summary["status"]))
    window = report.get("window", {})
    zone=window.get("timezone","UTC")
    print("Период: %s — %s; часовой пояс: %s" % (_date(window.get("since"),zone), _date(window.get("until"),zone),zone))
    if report.get("filters"):
        names = {"from": "отправитель", "to": "получатель", "domain": "домен", "ip": "IP", "trace": "поиск", "message_id": "Message-ID"}
        print("Фильтры: " + "; ".join("%s: %s" % (names.get(k,k),v) for k,v in report["filters"].items()))
    for answer in report.get("conclusions", [])[:8]:
        print("[%s] %s" % (answer["status"], answer["title"]))
        for item in answer.get("evidence", [])[:1]:
            print("  " + _evidence(item))
    stats = report.get("statistics", {})
    if stats:
        print("Поток: очередей %d; попыток доставки %d; успешных передач %d; deferred %d; bounced %d." % tuple(stats.get(k,0) for k in ("queues","delivery_attempts","recipient_delivery_events","deferred","bounced")))
        outcomes = stats.get("outcomes", {})
        print("Этапы: следующий SMTP %d; внутренний SMTP %d; локальный транспорт %d; Saved %d. Отказов до очереди: %d." % (outcomes.get("next_smtp_accepted",0),outcomes.get("internal_smtp_accepted",0),outcomes.get("local_transport_accepted",0),outcomes.get("saved",0),stats.get("rejected_before_queue",0)))
    findings = report.get("findings", [])
    problems = [f for f in findings if f["status"] in ("FAIL","WARN")]
    unknown = [f for f in findings if f["status"] == "UNKNOWN"]
    for group, label in ((problems,"Требует внимания"),(unknown,"Недостаточно данных")):
        if not group:
            continue
        print("\n%s (%d):" % (label,len(group)))
        for f in group[:12]:
            print("  [%s] %s%s" % (f["status"],f["title"]," ("+f["id"]+")" if details else ""))
            if f.get("next_step"):
                print("    " + clean(f["next_step"], 360))
            if details:
                for evidence in f.get("evidence",[])[:3]:
                    print("    " + _evidence(evidence))
            if f["id"]=="QUEUE.SNAPSHOT":
                for entry in f.get("details",{}).get("entries",[])[:3]:
                    for recipient in entry.get("recipients",[])[:2]:
                        print("    %s → %s: %s" % (entry["queue_id"],recipient.get("address","?"),clean(recipient.get("delay_reason","") or entry.get("queue_name","unknown"),250)))
        if len(group)>12:
            print("  Ещё %d: доступны в --json/--report." % (len(group)-12))
    services = [f for f in findings if f["id"].startswith("SERVICE.") and f["status"] == "OK"]
    if services:
        print("\nСлужбы active: " + ", ".join(f["title"].split(":",1)[0] for f in services))
    for identifier in ("QUEUE.SNAPSHOT","HOST.PLATFORM","BACKUP.TOOLING"):
        item = next((f for f in findings if f["id"]==identifier and f["status"] in ("OK","N/A")),None)
        if item:
            print("[%s] %s" % (item["status"],item["title"]))
    store = next((f for f in findings if f["id"]=="mailstore.metadata"),None)
    if store:
        for record in store.get("evidence",[])[:3]:
            print(_evidence(record))
            interval = record.get("header_intervals",{}).get("date_to_earliest_received_seconds")
            if interval is not None:
                print("  Date → самый ранний Received: %s с; внешние часы не доказывают причину задержки." % interval)
    coverage = report.get("completeness",{})
    print("Источники: %d; прочитано строк: %d; не разобрано: %d; лимит достигнут: %s." % (len(report.get("sources",[])),coverage.get("lines_read",0),coverage.get("unparsed_lines",0),"да" if coverage.get("truncated") else "нет"))
    for source in report.get("sources",[]):
        if source.get("truncated") or source.get("errors"):
            print("  %s: %s" % (source.get("path","источник"),"; ".join(source.get("errors",[])) or "достигнут лимит чтения"))
    if details:
        print("\nПодробные проверки:")
        for f in findings:
            print("[%s] %s (%s)" % (f["status"],f["title"],f["id"]))
            for item in f.get("evidence",[])[:3]:
                print("  " + _evidence(item))
        if stats:
            for key,title in (("top_authenticated_senders","Отправляющие аккаунты"),("top_recipient_domains","Домены получателей"),("top_rejection_reasons","Причины отказов")):
                if stats.get(key):
                    print(title+":")
                    for name,count in stats[key].items():
                        print("  %s — %s" % (count,clean(name,250)))
    print("SMTP 250 подтверждает следующий hop; Saved — сохранение в момент события, а не текущую папку.")
    if not details:
        print("Подробности: --details; машинный отчёт: --json; приватный файл: --report НОВЫЙ_ПУТЬ.")
    if report.get("redaction"):
        print("Redaction: " + report["redaction"]["limits"])
