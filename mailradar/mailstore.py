"""Targeted Dovecot metadata adapter; message bodies are never requested."""
import json
import math
import os
import re
import stat
import time
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path

from .model import finding

FIELDS = "mailbox uid guid date.received date.saved date.received.unixtime date.saved.unixtime hdr.date hdr.received hdr.message-id flags"
_FD_TRAVERSAL = os.open in os.supports_dir_fd and os.scandir in os.supports_fd and hasattr(os, "O_NOFOLLOW")


def header_delays(record):
    """Date and external Received are untrusted clocks, not attribution."""
    try:
        date = record.get("hdr.date")
        if not isinstance(date,str):
            raise ValueError("Date is absent or not text")
        sent = parsedate_to_datetime(date)
        headers = record.get("hdr.received") or ""
        headers = headers if isinstance(headers, list) else re.split(r"\r?\n(?=\S)",headers) if isinstance(headers,str) else []
        received = []
        for header in headers:
            if isinstance(header,str) and ";" in header:
                try:
                    stamp = parsedate_to_datetime(header.rsplit(";",1)[-1].strip())
                    if stamp.tzinfo:
                        received.append(stamp)
                except (TypeError, ValueError, IndexError, OverflowError):
                    pass
        if sent.tzinfo and received and all(t.tzinfo for t in received):
            return {"date_to_earliest_received_seconds": (min(received)-sent).total_seconds(), "limitation": "Sender Date/external Received clocks are untrusted; no cause or greylisting attribution follows from this interval."}
    except (TypeError, ValueError, IndexError, OverflowError, AttributeError):
        pass
    return {"limitation": "A comparable Date and Received timestamp pair is unavailable."}


def collect_mailstore(runner, args, since, until):
    user = getattr(args, "user", None) or getattr(args, "to", None)
    if not user:
        return [finding("mailstore.scope", "N/A", "Поиск в хранилище требует конкретного --user или --to", next_step="Укажите локального получателя; обход всех ящиков не выполняется.")]
    result = runner.run(["doveadm", "user", "-u", user])
    if not result.ok:
        return [finding("mailstore.user", "UNKNOWN", "Локальный аккаунт не подтверждён", evidence=[dict(returncode=result.returncode, error=result.stderr)], next_step="Проверьте адрес, права и userdb Dovecot.", user=user, fields={})]
    safe_userdb = {}
    for line in result.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].lower() in ("uid", "gid", "home", "mail", "quota_rule"):
            safe_userdb[parts[0]] = parts[1]
    findings = [finding("mailstore.user", "OK", "Dovecot нашёл локальный аккаунт", evidence=[dict(user=user, fields=safe_userdb)], user=user, fields=safe_userdb, limitation="Userdb lookup does not prove authentication is enabled or an alias is local.")]
    quota = runner.run(["doveadm", "quota", "get", "-u", user])
    rows, invalid, omitted = _quota_rows(quota.stdout)
    complete = quota.ok and not invalid and not omitted and bool(rows) and all(row["complete"] for row in rows)
    percentages = [row["percent"] for row in rows if row["percent"] is not None and not row["unlimited"]]
    status = "UNKNOWN" if not complete else "FAIL" if any(n >= 100 for n in percentages) else "WARN" if any(n >= 90 for n in percentages) else "OK" if percentages else "N/A"
    findings.append(finding("mailstore.quota", status, "Квота Dovecot (не размер du)", evidence=[dict(output=quota.stdout if quota.stdout else quota.stderr, returncode=quota.returncode)],
                            next_step="Если quota plugin недоступен, проверьте его конфигурацию отдельно.",
                            user=user, rows=rows, rows_count=len(rows), rows_omitted=omitted, rows_limit=100,
                            unparsed_rows=invalid, parse_complete=bool(complete), returncode=quota.returncode,
                            truncated=bool(quota.truncated or omitted), error=quota.stderr))
    if getattr(args, "mode", None) == "account":
        if getattr(args, "deep", False):
            findings.append(physical_usage(getattr(args, "root", "/"), user))
        return findings
    # Search dates are interpreted in the server timezone by Dovecot, not the
    # administrator's selected display zone. Epoch fields refine this broad
    # candidate query to the exact UTC interval below.
    from .timeutil import local_zone
    server_zone = local_zone()
    local_since, local_until = since.astimezone(server_zone), until.astimezone(server_zone)
    upper_date = local_until.date() + (timedelta(days=1) if local_until.time().replace(tzinfo=None) != datetime.min.time() else timedelta())
    query = ["SINCE", local_since.date().isoformat(), "BEFORE", upper_date.isoformat()]
    trace = getattr(args, "trace", None)
    message_id = getattr(args, "headers", None) or (trace if trace and trace.startswith("<") else None)
    if message_id:
        query += ["HEADER", "Message-ID", message_id]
    result = runner.run(["doveadm", "-f", "json", "fetch", "-u", user, FIELDS] + query, timeout=15)
    records = []
    omitted = 0
    uncertain_time = False
    records_scanned = matching_records = 0
    if result.ok:
        try:
            def nonfinite(value):
                raise ValueError("Non-finite Dovecot JSON")
            decoded = json.loads(result.stdout,parse_constant=nonfinite)
            if isinstance(decoded, list) and all(isinstance(r, dict) for r in decoded):
                records_scanned = len(decoded)
                for row in decoded:
                    if message_id and str(row.get("hdr.message-id","")).strip() != message_id:
                        continue  # HEADER search is substring based; require exact Message-ID
                    stamp = row.get("date.received.unixtime")
                    try:
                        epoch = float(stamp)
                        if not math.isfinite(epoch) or epoch<0 or isinstance(stamp,bool):
                            raise ValueError("invalid epoch")
                        if not since.timestamp() <= epoch <= until.timestamp():
                            continue
                    except (ValueError,TypeError,OverflowError):
                        uncertain_time = True
                    matching_records += 1
                    if len(records)==50:
                        omitted += 1
                        continue
                    record = {k:v for k,v in row.items() if k in FIELDS.split()}
                    records.append(record)
            else:
                raise ValueError("Unsupported Dovecot JSON shape")
        except (ValueError, TypeError):
            result.returncode = 65
    for record in records:
        record["header_intervals"] = header_delays(record)
    findings.append(finding("mailstore.metadata", "UNKNOWN" if result.truncated or omitted or uncertain_time or not result.ok else "OK" if records and message_id else "WARN" if records else "UNKNOWN", "Текущая папка и даты выбранного Message-ID" if records and message_id else "Кандидаты по получателю и периоду; нужное письмо не идентифицировано" if records else "Сохранённое письмо в выбранном поиске не подтверждено", evidence=records, next_step="Сопоставьте дату, Message-ID и получателя. Текущая папка не доказывает исходную папку или причину перемещения.",
                            user=user, records_count=len(records), records_scanned=records_scanned, matching_records=matching_records, record_limit=50, message_id_filter=message_id,
                            returncode=result.returncode, truncated=bool(result.truncated or omitted), omitted_records=omitted, precise_time_confirmed=not uncertain_time, limitation="Epoch received dates refine the server-local date query. Missing epoch dates leave candidate timing UNKNOWN. Without Message-ID these are candidate messages only; envelope sender filters are not header From. Metadata reads may refresh indexes; flags/messages are not changed. No matches does not prove non-delivery.", error=result.stderr))
    if getattr(args, "deep", False):
        findings.append(physical_usage(getattr(args, "root", "/"), user))
    return findings


def _quota_rows(text):
    """Read the documented table resource columns, not arbitrary final numbers."""
    rows, invalid, omitted = [], 0, 0
    for line in text.splitlines():
        if not line.strip() or re.fullmatch(r"\s*Quota name\s+Type\s+Value\s+Limit\s+%\s*", line, re.I):
            continue
        match = re.fullmatch(r"(.*?)\s+(STORAGE|MESSAGE)\s+(\d{1,18})\s+(\d{1,18}|-)\s+(\d{1,18}|-)\s*", line, re.I)
        if not match:
            invalid += 1
            continue
        name, resource, used, limit, percent = match.groups()
        unlimited = limit == "-" or int(limit) == 0
        row = dict(quota_root=name.strip(), resource=resource.upper(), used=int(used),
                   limit=None if limit == "-" else int(limit), percent=None if percent == "-" or unlimited else int(percent),
                   unit="KiB" if resource.upper() == "STORAGE" else "messages", unlimited=unlimited,
                   complete=unlimited or percent != "-")
        if len(rows) >= 100:
            omitted += 1
        else:
            rows.append(row)
    return rows, invalid, omitted


def physical_usage(root, user, max_files=100000, seconds=5, max_dirs=10000):
    local, domain = user.rsplit("@", 1)
    base = Path(root) / "home/user-data/mail/mailboxes"
    target = base / domain / local
    try:
        if local in {".", ".."} or domain in {".", ".."} or any(c in local + domain for c in "/\\"):
            raise ValueError("Mailbox scope must be two literal path components")
        target.resolve().relative_to(base.resolve())
        if target.is_symlink() or not target.is_dir():
            raise ValueError("Target Maildir unavailable or symlink")
    except (ValueError, OSError, RuntimeError) as error:
        return finding("mailstore.physical", "UNKNOWN", "Физический размер ящика недоступен", evidence=[str(error)])
    if not _FD_TRAVERSAL:
        return finding("mailstore.physical", "UNKNOWN", "Безопасный incremental обход на этой платформе недоступен",
                       limitation="Descriptor-relative directory access with O_NOFOLLOW is required; no unsafe path fallback is used.")
    count = size = directories = entries = 0
    complete = True
    start = time.monotonic()
    deadline = start + max(0, seconds)
    errors = []
    stopped = None
    stack = []
    def failed(error):
        if len(errors) < 20:
            errors.append(str(error))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)

    def push(directory_fd):
        nonlocal directories
        try:
            iterator = os.scandir(directory_fd)
        except BaseException:
            os.close(directory_fd)
            raise
        stack.append((directory_fd, iterator))
        directories += 1

    try:
        if max_files <= 0 or max_dirs <= 0 or time.monotonic() >= deadline:
            stopped = "entry_limit" if max_files <= 0 else "directory_limit" if max_dirs <= 0 else "time_limit"
            complete = False
        else:
            # Keep every user-controlled component descriptor-relative. Even a
            # directory replaced with a symlink between stat/open cannot redirect
            # this traversal into another user's tree.
            base_fd = os.open(str(base.resolve()), flags)
            try:
                domain_fd = os.open(domain, flags, dir_fd=base_fd)
                try:
                    push(os.open(local, flags, dir_fd=domain_fd))
                finally:
                    os.close(domain_fd)
            finally:
                os.close(base_fd)
        while stack:
            if entries >= max_files or time.monotonic() >= deadline:
                complete = False
                stopped = "entry_limit" if entries >= max_files else "time_limit"
                break
            directory_fd, iterator = stack[-1]
            try:
                entry = next(iterator)
            except StopIteration:
                iterator.close()
                os.close(directory_fd)
                stack.pop()
                continue
            except OSError as error:
                failed(error)
                iterator.close()
                os.close(directory_fd)
                stack.pop()
                continue
            entries += 1
            if time.monotonic() >= deadline:
                complete, stopped = False, "time_limit"
                break
            try:
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    continue
                if stat.S_ISDIR(info.st_mode):
                    if directories >= max_dirs or len(stack) >= 128:
                        complete, stopped = False, "directory_limit" if directories >= max_dirs else "depth_limit"
                        break
                    push(os.open(entry.name, flags, dir_fd=directory_fd))
                elif stat.S_ISREG(info.st_mode):
                    size += info.st_size
                    count += 1
            except OSError as error:
                failed(error)
    except (OSError, RuntimeError) as error:
        failed(error)
    finally:
        for directory_fd, iterator in reversed(stack):
            try:
                iterator.close()
            finally:
                os.close(directory_fd)
    return finding("mailstore.physical", "OK" if complete and not errors else "UNKNOWN", "Ограниченный физический обход выбранного ящика",
                   evidence=[dict(bytes=size, files=count, directories=directories, entries_examined=entries,
                                  complete=complete and not errors, stop_reason=stopped, errors=errors[:5],
                                  entry_limit=max_files, directory_limit=max_dirs, time_limit_seconds=seconds)],
                   limitation="Physical regular-file bytes include indexes and metadata, differ from allocated du blocks and IMAP quota; not a message count. Directory entries, including directories and skipped symlinks, consume the entry limit. The deadline is checked between filesystem operations; a blocked kernel I/O call cannot be interrupted here.")
