"""Targeted Dovecot metadata adapter; message bodies are never requested."""
import json
import os
import re
import time
from datetime import timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path

from .model import finding

FIELDS = "mailbox uid guid date.received date.saved hdr.date hdr.received hdr.message-id flags"


def header_delays(record):
    """Date and external Received are untrusted clocks, not attribution."""
    try:
        sent = parsedate_to_datetime(record.get("hdr.date", ""))
        headers = record.get("hdr.received", "")
        headers = headers if isinstance(headers, list) else headers.split("\nReceived:")
        received = [parsedate_to_datetime(h.rsplit(";", 1)[-1].strip()) for h in headers if ";" in h]
        if sent.tzinfo and received and all(t.tzinfo for t in received):
            return {"date_to_earliest_received_seconds": (min(received)-sent).total_seconds(), "limitation": "Sender Date/external Received clocks are untrusted; no cause or greylisting attribution follows from this interval."}
    except (TypeError, ValueError, IndexError, OverflowError):
        pass
    return {"limitation": "A comparable Date and Received timestamp pair is unavailable."}


def collect_mailstore(runner, args, since, until):
    user = args.user or args.to
    if not user:
        return [finding("mailstore.scope", "N/A", "Поиск в хранилище требует конкретного --user или --to", next_step="Укажите локального получателя; обход всех ящиков не выполняется.")]
    result = runner.run(["doveadm", "user", "-u", user])
    if not result.ok:
        return [finding("mailstore.user", "UNKNOWN", "Локальный аккаунт не подтверждён", evidence=[dict(returncode=result.returncode, error=result.stderr)], next_step="Проверьте адрес, права и userdb Dovecot.")]
    safe_userdb = {}
    for line in result.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].lower() in ("uid", "gid", "home", "mail", "quota_rule"):
            safe_userdb[parts[0]] = parts[1]
    findings = [finding("mailstore.user", "OK", "Dovecot нашёл локальный аккаунт", evidence=[dict(user=user, fields=safe_userdb)], limitation="Userdb lookup does not prove authentication is enabled or an alias is local.")]
    quota = runner.run(["doveadm", "quota", "get", "-u", user])
    percentages = [int(m[1]) for m in re.finditer(r"\s(\d{1,4})\s*$", quota.stdout, re.M)] if quota.ok else []
    findings.append(finding("mailstore.quota", "FAIL" if any(n >= 100 for n in percentages) else "WARN" if any(n >= 90 for n in percentages) else "OK" if percentages else "UNKNOWN", "Квота Dovecot (не размер du)", evidence=[dict(output=quota.stdout if quota.ok else quota.stderr, returncode=quota.returncode)], next_step="Если quota plugin недоступен, проверьте его конфигурацию отдельно."))
    query = ["SINCE", since.strftime("%Y-%m-%d"), "BEFORE", (until+timedelta(days=1)).strftime("%Y-%m-%d")]
    message_id = args.headers or (args.trace if args.trace and args.trace.startswith("<") else None)
    if message_id:
        query += ["HEADER", "Message-ID", message_id]
    result = runner.run(["doveadm", "-f", "json", "fetch", "-u", user, FIELDS] + query, timeout=15)
    records = []
    if result.ok:
        try:
            decoded = json.loads(result.stdout)
            if isinstance(decoded, list) and all(isinstance(r, dict) for r in decoded):
                records = [{k: v for k, v in r.items() if k in FIELDS.split()} for r in decoded[:50]]
            else:
                raise ValueError("Unsupported Dovecot JSON shape")
        except (ValueError, TypeError):
            result.returncode = 65
    for record in records:
        record["header_intervals"] = header_delays(record)
    findings.append(finding("mailstore.metadata", "UNKNOWN" if result.truncated or len(records) == 50 else "OK" if records and message_id else "WARN" if records else "UNKNOWN", "Текущая папка и даты выбранного Message-ID" if records and message_id else "Кандидаты по получателю и периоду; нужное письмо не идентифицировано" if records else "Сохранённое письмо в выбранном поиске не подтверждено", evidence=records, next_step="Сопоставьте дату, Message-ID и получателя. Текущая папка не доказывает исходную папку или причину перемещения.", returncode=result.returncode, truncated=result.truncated or len(records) == 50, limitation="Date-only Dovecot query includes entire boundary days. Without Message-ID these are candidate messages only; envelope sender filters are not header From. Metadata reads may refresh indexes; flags/messages are not changed. No matches does not prove non-delivery.", error=result.stderr))
    if args.deep:
        findings.append(physical_usage(args.root, user))
    return findings


def physical_usage(root, user, max_files=100000, seconds=5, max_dirs=10000):
    local, domain = user.rsplit("@", 1)
    base = Path(root) / "home/user-data/mail/mailboxes"
    target = base / domain / local
    try:
        target.resolve().relative_to(base.resolve())
        if target.is_symlink() or not target.is_dir():
            raise ValueError("Target Maildir unavailable or symlink")
    except (ValueError, OSError) as error:
        return finding("mailstore.physical", "UNKNOWN", "Физический размер ящика недоступен", evidence=[str(error)])
    count = size = directories = 0
    complete = True
    start = time.monotonic()
    errors = []
    def failed(error):
        if len(errors) < 20:
            errors.append(str(error))
    for parent, dirs, files in os.walk(target, followlinks=False, onerror=failed):
        directories += 1
        if directories > max_dirs or time.monotonic()-start > seconds:
            complete = False
            break
        dirs[:] = [d for d in dirs if not (Path(parent)/d).is_symlink()]
        for name in files:
            path = Path(parent)/name
            if path.is_symlink():
                continue
            try:
                size += path.stat().st_size
                count += 1
            except OSError as error:
                failed(error)
            if count >= max_files or time.monotonic()-start > seconds:
                complete = False
                break
        if not complete:
            break
    return finding("mailstore.physical", "OK" if complete and not errors else "UNKNOWN", "Ограниченный физический обход выбранного ящика", evidence=[dict(bytes=size, files=count, directories=directories, complete=complete and not errors, errors=errors[:5])], limitation="Physical file bytes include indexes and metadata, differ from allocated du blocks and IMAP quota; not a message count.")
