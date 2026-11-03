"""Bounded, read-only host facts and rules. No service/configuration repairs.

All executable actions pass through the injected runner. File readers select
individual public configuration fields; credential files are never opened.
"""

import collections
import datetime as dt
import ipaddress
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import stat
import socket
import tempfile
from .model import clean as report_clean
import time

from .runner import Result


_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_SENSITIVE = re.compile(r"(?:sasl_passwd|password|secret|credential|private[_.-]?key|token)", re.I)
_HOST = re.compile(r"(?=.{1,253}\Z)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\Z")
_QUEUE_TEXT_HEADER = re.compile(r"^([A-Za-z0-9]+)([*!#]?)\s+(\d+)\s+(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?:0?[1-9]|[12]\d|3[01])\s+(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d\s+(.+)$", re.M)
_PARAMS = (
    "myhostname", "mydomain", "smtpd_recipient_restrictions",
    "smtpd_relay_restrictions", "smtpd_client_restrictions",
    "smtpd_sender_restrictions", "parent_domain_matches_subdomains",
    "smtpd_helo_restrictions", "smtpd_data_restrictions", "smtpd_end_of_data_restrictions",
    "smtpd_restriction_classes", "postscreen_dnsbl_sites", "postscreen_dnsbl_threshold", "postscreen_dnsbl_action",
    "postscreen_dnsbl_allowlist_threshold",
    "relayhost", "transport_maps", "smtpd_sender_login_maps",
    "smtpd_tls_security_level", "smtp_tls_security_level",
    "queue_directory",
)


def clean(value, limit=1500):
    value = report_clean(value, limit)
    value = re.sub(r"(?i)(://)[^/@\s]+:[^/@\s]+@", r"\1[redacted]@", value)
    value = re.sub(r"(?i)((?:password|secret|token)\s*[=:]\s*)\S+", r"\1[redacted]", value)
    value = re.sub(r"(?i)\b[a-z0-9_-]+\.(?=[a-z0-9_-]+\.dq\.spamhaus\.net\b)", "[DQS-key].", value)
    return value[:limit]


def finding(identifier, status, title, evidence=None, next_step="", **details):
    return {"id": identifier, "status": status, "title": clean(title),
            "evidence": evidence or [], "next_step": next_step,
            "details": details}


def command_evidence(argv, result, text=None):
    return {"source": "command", "command": [clean(x, 512) for x in argv],
            "returncode": result.returncode, "text": clean(
                result.stdout if text is None else text),
            "stderr": clean(result.stderr, 300),
            "truncated": bool(getattr(result, "truncated", False)),
            "timed_out": bool(getattr(result, "timed_out", False)),
            "missing": bool(getattr(result, "missing", False))}


class Context:
    def __init__(self, runner, args):
        self.runner, self.args = runner, args
        self.root = Path(getattr(args, "root", "/"))
        self.findings = []
        self.cache = {}
        self.postconf = {}
        self.unit_states = {}
        self.miab = False
        self.metadata = {}
        self.deadline = time.monotonic() + 90
        self.budget_exhausted = False
        self.dnsbl_controls = {}

    def run(self, argv, timeout=8):
        key = tuple(argv)
        if key not in self.cache:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                self.budget_exhausted = True
                self.cache[key] = Result(124, stderr="Host diagnostic time budget exhausted; action not executed", timed_out=True)
            else:
                self.cache[key] = self.runner.run(argv, timeout=min(timeout, remaining))
        return self.cache[key]

    def add(self, *args, **kwargs):
        self.findings.append(finding(*args, **kwargs))

    def path(self, absolute):
        path = PurePosixPath(absolute)
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("Only absolute configuration paths are allowed")
        return self.root / absolute.lstrip("/")

    def read(self, absolute, limit=65536):
        if _SENSITIVE.search(absolute):
            return None, "credential-like path is excluded"
        try:
            path = self.path(absolute)
            if _SENSITIVE.search(str(path.resolve())):
                return None, "credential-like resolved path is excluded"
            # Fixture roots and symlinks cannot redirect readers outside their root.
            if self.root != Path("/") and self.root.resolve() not in (path.resolve(), *path.resolve().parents):
                return None, "path leaves fixture root"
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                return None, "not a regular configuration file"
            if info.st_size > limit:
                return None, "file exceeds read limit"
            descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(descriptor, "rb") as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                    return None, "not a regular configuration file"
                value = handle.read(limit + 1)
            if len(value) > limit:
                return None, "file exceeds read limit"
            return value.decode("utf-8", "replace"), ""
        except (OSError, ValueError, RuntimeError) as exc:
            return None, clean(exc, 180)


def _assignments(text):
    """Read literal NAME=value metadata without shell expansion/source/eval."""
    values = {}
    for line in (text or "").splitlines():
        match = re.fullmatch(r"\s*([A-Z_a-z][A-Z_a-z0-9]*)\s*=\s*(.*?)\s*", line)
        if not match:
            continue
        value = match[2]
        if len(value) > 1024 or any(c in value for c in ("$", "`", "\x00")):
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[match[1]] = value
    return values


def platform_checks(ctx):
    release, error = ctx.read("/etc/os-release")
    osinfo = _assignments(release)
    metadata, _ = ctx.read("/etc/mailinabox.conf")
    if metadata is not None:
        ctx.miab = True
        ctx.metadata = {k: v for k, v in _assignments(metadata).items()
                        if k in {"PRIMARY_HOSTNAME", "STORAGE_ROOT", "PUBLIC_IP", "PUBLIC_IPV6"}}
    distro, version = osinfo.get("ID", "unknown"), osinfo.get("VERSION_ID", "unknown")
    supported = distro == "ubuntu" and version == "22.04" and ctx.miab
    status = "OK" if supported else "WARN" if distro in {"ubuntu", "debian"} else "UNKNOWN"
    ctx.add("HOST.PLATFORM", status,
            "Платформа: {} {}; {}".format(distro, version,
                "MIAB / целевая платформа" if supported else
                "частичная поддержка Postfix/Dovecot" if distro in {"ubuntu", "debian"} else "поддержка не подтверждена"),
            [{"source": "/etc/os-release", "text": clean("ID=" + distro + " VERSION_ID=" + version)},
             {"source": "/etc/mailinabox.conf", "text": "metadata present" if ctx.miab else "not available"}],
            "Сопоставьте версии пакетов и результаты отдельных проверок.",
            support="supported" if supported else "partial" if distro in {"ubuntu", "debian"} else "unknown")
    # Version discovery never invokes the mailinabox setup wrapper.
    head, _ = ctx.read("/root/mailinabox/.git/HEAD", 512)
    revision = None
    if head and re.fullmatch(r"[a-f0-9]{40}\s*", head):
        revision = head.strip()
    elif head and re.fullmatch(r"ref: refs/(?:heads|tags)/[A-Za-z0-9._/-]+\s*", head):
        ref = head.strip()[5:]
        if ".." not in ref.split("/"):
            value, _ = ctx.read("/root/mailinabox/.git/" + ref, 512)
            if value and re.fullmatch(r"[a-f0-9]{40}\s*", value):
                revision = value.strip()
    ctx.add("HOST.MIAB_REVISION", "OK" if revision else "UNKNOWN" if ctx.miab else "N/A",
            "MIAB revision: " + (revision or "не установлена по доступным Git metadata"),
            [{"source": "/root/mailinabox/.git/HEAD", "text": revision or "no verified revision"}],
            "Проверьте checkout MIAB; setup/update wrappers для определения версии не запускаются.")
    hostname, _ = ctx.read("/etc/hostname", 1024)
    uptime, _ = ctx.read("/proc/uptime", 1024)
    load, _ = ctx.read("/proc/loadavg", 1024)
    try:
        seconds = float((uptime or "").split()[0])
        if not math.isfinite(seconds) or seconds<0:
            seconds = None
    except (ValueError, IndexError):
        seconds = None
    try:
        averages = [float(v) for v in (load or "").split()[:3]]
        if len(averages) != 3 or not all(math.isfinite(v) and v>=0 for v in averages):
            averages = None
    except ValueError:
        averages = None
    host = (hostname or "").strip() or socket.gethostname()
    ctx.add("HOST.RUNTIME", "OK" if seconds is not None and averages else "UNKNOWN",
            "Host: {}; uptime: {}; load: {}".format(clean(host), str(round(seconds)) + "s" if seconds is not None else "unknown", clean(averages) if averages else "unknown"),
            [{"source": "/etc/hostname,/proc/uptime,/proc/loadavg", "text": "selected runtime metadata"}],
            hostname=clean(host), uptime_seconds=seconds, load_average=averages, cpu_count=os.cpu_count())


def service_checks(ctx):
    argv = ["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"]
    result = ctx.run(argv)
    installed = set(re.findall(r"^([A-Za-z0-9@_.-]+)\.service\s", result.stdout, re.M)) if result.ok else set()
    enable_states = dict(re.findall(r"^([A-Za-z0-9@_.-]+)\.service\s+(\S+)", result.stdout, re.M)) if result.ok else {}
    names = ["postfix", "dovecot", "nginx", "fail2ban", "nsd", "bind9",
             "systemd-resolved", "opendkim", "opendmarc", "postgrey", "spampd",
             "spamassassin", "rspamd", "amavis", "mailinabox"]
    names += sorted(n for n in installed if re.fullmatch(r"php[0-9.]+-fpm", n))[:10]
    for name in names:
        required = name in {"postfix", "dovecot"} or (ctx.miab and name in {"nginx", "mailinabox"})
        if result.ok and name not in installed:
            ctx.add("SERVICE." + name.upper().replace("-", "_"), "UNKNOWN" if required else "N/A",
                    name + ": unit не найдена" + ("; обязательный компонент не подтверждён" if required else " (необязательный компонент)"),
                    [command_evidence(argv, result, "unit not listed")])
            continue
        cmd = ["systemctl", "show", name, "--property=LoadState,ActiveState,SubState", "--value"]
        state = ctx.run(cmd)
        complete, active, missing = _unit_state(state)
        ctx.unit_states[name] = active if complete else None
        status = "UNKNOWN" if not complete else "N/A" if missing and not required else "UNKNOWN" if missing else "OK" if active else "FAIL" if required else "WARN"
        unused_daemon = complete and not active and not required and ("inactive" in state.stdout.splitlines() or "ActiveState=inactive" in state.stdout.splitlines()) and (enable_states.get(name) in {"disabled","masked","static"} or name == "spamassassin" and ctx.miab and ctx.unit_states.get("spampd") is True)
        if unused_daemon:
            status = "N/A"
        ctx.add("SERVICE." + name.upper().replace("-", "_"), status,
                name + (": отдельный daemon не используется (MIAB фильтрует через spampd)" if unused_daemon and name == "spamassassin" and ctx.unit_states.get("spampd") is True else ": отключённый необязательный daemon" if unused_daemon else ": состояние не подтверждено" if not complete else ": active" if active else ": отсутствует" if missing else ": не active"),
                [command_evidence(cmd, state)],
                "Проверьте журнал и конфигурацию службы; active не доказывает корректную обработку почты.")


def _unit_state(result):
    """systemctl --value ordering varies; incomplete output proves no state."""
    fields = [line.strip() for line in result.stdout.splitlines()]
    named = dict(line.split("=", 1) for line in fields if "=" in line)
    if named:
        complete = result.ok and all(key in named for key in ("LoadState", "ActiveState", "SubState"))
        return complete, complete and named.get("ActiveState") == "active", complete and named.get("LoadState") == "not-found"
    loadstates = {"loaded", "not-found", "error", "masked", "bad-setting", "merged", "stub"}
    activestates = {"active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance", "refreshing"}
    complete = result.ok and len(fields) == 3 and bool(loadstates.intersection(fields)) and bool(activestates.intersection(fields)) and all(fields)
    return complete, complete and "active" in fields, complete and "not-found" in fields


def queue_checks(ctx):
    argv = ["postqueue", "-j"]
    result = ctx.run(argv)
    if not result.ok:
        unsupported = re.search(r"(?:invalid|illegal|unknown|unrecognized) option", result.stderr + result.stdout, re.I)
        if not unsupported or result.missing or result.timed_out or result.truncated:
            ctx.add("QUEUE.SNAPSHOT", "UNKNOWN", "Очередь прочитать не удалось; число писем неизвестно",
                    [command_evidence(argv, result)], "Проверьте права и доступность Postfix showq.")
            return
        return queue_fallback(ctx)
    rows, invalid, duplicates = {}, 0, 0
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        try:
            def reject_constant(value):
                raise ValueError("non-finite JSON constant")
            row = json.loads(line, parse_constant=reject_constant)
            if not isinstance(row, dict) or not isinstance(row.get("queue_id"), str) or not re.fullmatch(r"[A-Za-z0-9]+", row["queue_id"]):
                raise ValueError("invalid queue entry")
            if not isinstance(row.get("queue_name"), str) or not isinstance(row.get("sender"), str) or not isinstance(row.get("recipients"), list):
                raise ValueError("missing typed queue fields")
            arrival = row.get("arrival_time")
            if not isinstance(arrival, (int, float)) or isinstance(arrival, bool) or (isinstance(arrival, float) and not math.isfinite(arrival)) or not 0 < arrival < 253402300800:
                raise ValueError("invalid arrival_time")
            if any(not isinstance(r, dict) or not isinstance(r.get("address"), str) for r in row["recipients"]):
                raise ValueError("invalid recipient record")
            if row["queue_id"] in rows:
                duplicates += 1
            rows[row["queue_id"]] = row
        except (ValueError, TypeError):
            invalid += 1
    counts = collections.Counter(str(row.get("queue_name", "unknown")) for row in rows.values())
    now = dt.datetime.now(dt.timezone.utc).timestamp()
    ages = [max(0, now - row["arrival_time"]) for row in rows.values()
            if isinstance(row.get("arrival_time"), (int, float)) and 0 < row["arrival_time"] <= now + 300]
    incomplete = invalid or result.truncated or result.timed_out or bool(result.stderr.strip())
    status = "UNKNOWN" if incomplete else "FAIL" if len(rows) >= 10 else "WARN" if rows else "OK"
    details = []
    for row in list(rows.values())[:50]:
        recipients = row.get("recipients", [])
        details.append({"queue_id": row["queue_id"], "queue_name": clean(row.get("queue_name", "unknown")),
                        "sender": clean(row.get("sender", ""), 320),
                        "arrival_time": row.get("arrival_time"),
                        "recipients_omitted": max(0, len(recipients) - 20) if isinstance(recipients, list) else 0,
                        "recipients": [{"address": clean(r.get("address", ""), 320),
                                        "delay_reason": clean(r.get("delay_reason", ""), 500)}
                                       for r in recipients[:20] if isinstance(r, dict)]
                        if isinstance(recipients, list) else []})
    ctx.add("QUEUE.SNAPSHOT", status,
            "Очередь: {} видимых сообщений{}".format(len(rows), "; неполный снимок" if incomplete else ""),
            [command_evidence(argv, result, "{} entries; {} invalid; {} duplicates".format(len(rows), invalid, duplicates))],
            "Разберите причины deferred/hold; снимок postqueue не атомарен, remote acceptance не доказывает INBOX.",
            count=len(rows), queues=dict(counts), oldest_age_seconds=max(ages) if ages else None,
            snapshot_atomic=False, duplicates=duplicates, invalid_entries=invalid, entries=details,
            entries_omitted=max(0, len(rows) - 50), complete=not bool(incomplete))
    if ages and max(ages) > 48 * 3600:
        ctx.add("QUEUE.AGE", "WARN", "В очереди есть письмо старше 48 часов по arrival_time showq",
                [{"source": "postqueue -j", "text": str(int(max(ages))) + " seconds"}],
                "Сопоставьте DSN и предыдущие попытки в trace; mtime queue file не используется.")


def queue_fallback(ctx):
    argv = ["postqueue", "-p"]
    result = ctx.run(argv)
    entries = _QUEUE_TEXT_HEADER.findall(result.stdout)
    empty = "Mail queue is empty" in result.stdout
    footer = re.search(r"-- \d+(?:\.\d+)? Kbytes in (\d+) Requests?\.", result.stdout)
    footer_count = int(footer[1]) if footer else None
    invalid = []
    for line in result.stdout.splitlines():
        if not line.strip() or line[0].isspace() or line.startswith(("-Queue ID-", "(", "-- ", "Mail queue is empty")):
            continue
        if not _QUEUE_TEXT_HEADER.fullmatch(line):
            invalid.append(line)
    complete = bool(result.ok and not result.stderr.strip() and not invalid and not (empty and entries) and
                    ((empty and not entries and not footer_count) or footer_count == len(entries)) and not result.truncated)
    unique = list({entry[0]: entry for entry in entries}.values())
    status = "UNKNOWN" if not complete else "FAIL" if len(unique) >= 10 else "WARN" if unique else "OK"
    ctx.add("QUEUE.SNAPSHOT", status, "Очередь (text fallback): {} видимых записей".format(len(unique)),
            [command_evidence(argv, result, "{} parsed entries; empty marker={}".format(len(entries), empty))],
            "Установите поддерживаемый postqueue -j для точных времени и причин; fallback не определяет возраст по mtime.",
            count=len(unique), queue_ids=[e[0] for e in unique], complete=complete, snapshot_atomic=False,
            fallback=True, footer_count=footer_count, invalid_lines=len(invalid), duplicates=len(entries) - len(unique),
            queues=dict(collections.Counter("active" if e[1] == "*" else "hold" if e[1] == "!" else "forced_expire" if e[1] == "#" else "deferred" for e in unique)))


def disk_checks(ctx):
    for flag, kind, critical, warning in (("-P", "SPACE", 95, 80), ("-Pi", "INODES", 90, 70)):
        paths = [p for p in ("/", "/home", "/home/user-data") if ctx.path(p).exists()]
        argv = ["df", flag] + paths
        result = ctx.run(argv)
        found = False
        seen = set()
        for line in result.stdout.splitlines()[1:]:
            match = re.match(r"^\S+\s+\d+\s+\d+\s+\d+\s+(\d+)%\s+(.+)$", line)
            if not match:
                continue
            used, mount = int(match[1]), match[2]
            if mount in seen:
                continue
            seen.add(mount)
            found = True
            ctx.add("DISK." + kind, "FAIL" if used >= critical else "WARN" if used >= warning else "OK",
                    "{} {}: {}%".format("Место" if kind == "SPACE" else "Inode", clean(mount), used),
                    [command_evidence(argv, result, line)], "Проверьте свободное место и рост данных." if used >= warning else "",
                    mount=clean(mount), used_percent=used)
        if not found or not result.ok or result.truncated:
            ctx.add("DISK." + kind + ".COVERAGE", "UNKNOWN", "Сведения df неполны",
                    [command_evidence(argv, result, "partial or no parseable rows")])


def postfix_checks(ctx):
    for param in _PARAMS:
        argv = ["postconf", "-h", param]
        result = ctx.run(argv)
        if result.ok and not result.truncated and len(result.stdout) <= 32768:
            ctx.postconf[param] = result.stdout.strip()
    base = {k: ctx.postconf.get(k) for k in ("smtpd_recipient_restrictions", "smtpd_relay_restrictions", "smtpd_client_restrictions", "smtpd_sender_restrictions", "smtpd_helo_restrictions", "smtpd_data_restrictions", "smtpd_end_of_data_restrictions", "smtpd_restriction_classes")}
    if base["smtpd_recipient_restrictions"] is None or base["smtpd_relay_restrictions"] is None:
        ctx.add("POSTFIX.CONFIG", "UNKNOWN", "Ограничения Postfix прочитаны не полностью",
                [command_evidence(["postconf", "-h", key], ctx.run(["postconf", "-h", key]))
                 for key in ("smtpd_recipient_restrictions", "smtpd_relay_restrictions")],
                "Проверьте доступ к postconf; не считайте отсутствие вывода пустой конфигурацией.")
    else:
        ctx.add("POSTFIX.CONFIG", "OK", "Нужные параметры main.cf разобраны postconf",
                [{"source": "postconf", "text": "selected public parameters parsed"}],
                "Это не полная проверка всех карт, классов ограничений и работающего SMTP-сервиса.")
    contexts = {"global": base}
    argv = ["postconf", "-P"]
    overrides = ctx.run(argv)
    if overrides.ok and not overrides.truncated:
        omitted = 0
        for line in overrides.stdout.splitlines():
            match = re.match(r"^([^\s/=]+/[^\s/=]+)/(smtpd_(?:(?:recipient|relay|client|sender|helo|data|end_of_data)_restrictions|restriction_classes))\s*=\s*(.*)$", line)
            if match and (match[1] in contexts or len(contexts) < 81):
                contexts.setdefault(match[1], dict(base))[match[2]] = match[3]
            elif match:
                omitted += 1
        if omitted:
            ctx.add("POSTFIX.MASTER_COVERAGE", "UNKNOWN", "Достигнут лимит 80 service override contexts",
                    [{"source": "postconf -P", "text": str(omitted) + " override lines omitted"}], omitted=omitted)
    else:
        ctx.add("POSTFIX.MASTER_COVERAGE", "UNKNOWN", "Service overrides master.cf не подтверждены",
                [command_evidence(argv, overrides, "selected restriction overrides unavailable")],
                "Учитывайте отдельные ограничения smtp/submission/smtps в master.cf.")
    for name, config in contexts.items():
        recipient, relay = config["smtpd_recipient_restrictions"], config["smtpd_relay_restrictions"]
        guards = [key for key, value in (("recipient", recipient), ("relay", relay))
                  if value is not None and re.search(r"\b(?:reject|defer)_unauth_destination\b", value)]
        # A literal unconditional permit before the guard defeats that chain.
        usable = []
        for key in guards:
            chain = relay if key == "relay" else recipient
            guard = re.search(r"\b(?:reject|defer)_unauth_destination\b", chain)
            before = chain[:guard.start()]
            if not re.search(r"(?:^|[,\s])permit(?:$|[,\s])", before):
                usable.append(key)
        status = "OK" if usable else "UNKNOWN" if recipient is None or relay is None else "WARN"
        ctx.add("POSTFIX.RELAY_GUARD", status,
                "{}: {}".format(name, "правило защиты relay найдено в " + ", ".join(usable) if usable else "эффективная защита relay не подтверждена"),
                [{"source": "postconf" if name == "global" else "postconf -P", "text": clean(name + ": recipient=" + str(recipient) + "; relay=" + str(relay))}],
                "Локальная проверка наличия guard не является внешним open-relay test; учтите restriction classes и порядок.",
                context=name, guard_chains=usable, external_relay_test=False)
    relay = ctx.postconf.get("relayhost")
    ctx.add("POSTFIX.TRANSPORT", "OK" if relay is not None else "UNKNOWN",
            "Исходящий relayhost: " + (clean(relay) if relay else "не задан (прямой маршрут или transport_maps)" if relay is not None else "неизвестен"),
            [{"source": "postconf -h relayhost", "text": clean(relay or "empty or unavailable")},
             {"source": "postconf -h transport_maps", "text": clean(ctx.postconf.get("transport_maps", "unknown"))}],
            "Relay acceptance не очищает domain reputation и не доказывает внешний INBOX; credential maps не читаются.",
            relayhost=clean(relay or ""), transport_maps=clean(ctx.postconf.get("transport_maps", "")))
    return contexts


def _chain_tokens(text):
    # Brace-valued restriction syntax requires richer parsing. Do not claim it is modeled.
    if any(c in (text or "") for c in "{}$"):
        return None
    tokens = re.findall(r"[^,\s]+", text or "")
    return tokens if len(tokens) <= 500 else None


def _map_refs(text):
    return re.findall(r"\bcheck_client_access\s+([a-z][a-z0-9_]*:/[^,\s{}]+)", text or "")


def whitelist_checks(ctx, contexts):
    client_name = (getattr(ctx.args, "client_name", None) or "").lower().rstrip(".")
    client_ip = getattr(ctx.args, "client_ip", None)
    name_valid = not client_name or bool(_HOST.fullmatch(client_name))
    try:
        address = ipaddress.ip_address(client_ip) if client_ip else None
    except ValueError:
        address = None
        ctx.add("WHITELIST.INPUT", "UNKNOWN", "Некорректный IP SMTP-клиента", next_step="Передайте один IPv4/IPv6-адрес.")
    if not name_valid:
        ctx.add("WHITELIST.INPUT", "UNKNOWN", "Некорректное имя SMTP-клиента")
        client_name = ""
    configured = []
    for name, config in contexts.items():
        for parameter, value in config.items():
            if value is None:
                continue
            tokens = _chain_tokens(value)
            all_maps = _map_refs(value)
            maps = all_maps[:20]
            if len(all_maps) > 20:
                ctx.add("WHITELIST.COVERAGE", "UNKNOWN", "Лимит 20 client access maps в цепочке достигнут", context=name, chain=parameter)
            configured.extend(maps)
            for map_name in maps:
                idx = tokens.index(map_name) - 1 if tokens and map_name in tokens else -1
                policies = [tokens[i + 1] for i, token in enumerate(tokens or []) if token == "check_policy_service" and i + 1 < len(tokens)]
                after = [tokens[i + 1] for i, token in enumerate(tokens or []) if token == "check_policy_service" and i > idx and i + 1 < len(tokens)]
                before = [tokens[i + 1] for i, token in enumerate(tokens or []) if token == "check_policy_service" and i < idx and i + 1 < len(tokens)]
                early = [token for token in (tokens or [])[:max(idx, 0)] if token.startswith("reject_")]
                later_rejects = [token for token in (tokens or [])[idx + 1:] if token.startswith(("reject_", "defer_"))]
                duplicates = maps.count(map_name) > 1
                ctx.add("WHITELIST.WIRING", "WARN" if duplicates or before or later_rejects else "OK" if tokens else "UNKNOWN",
                        "{} / {}: {} подключена{}{}".format(name, parameter, map_name, " несколько раз" if duplicates else "", "; после policy service" if before else ""),
                        [{"source": "postconf" if name == "global" else "postconf -P", "text": clean(value)}],
                        ("OK не отменяет уже выполненные policy services; карта может обойти только следующие сервисы этой цепочки. " if before else "OK из access map завершает эту restriction chain и может обойти все последующие policy services; ") + ("Последующие reject/defer restrictions тоже могут быть обойдены в этой цепочке. " if later_rejects else "") + "Ранние rejects остаются; другие restriction chains оцениваются отдельно.",
                        context=name, chain=parameter, map=map_name, policies=policies,
                        following_policy_services=after, preceding_policy_services=before, earlier_rejects=early,
                        following_rejects=later_rejects, duplicates=duplicates)
    defaults = ("hash:/etc/postfix/client_whitelist", "cidr:/etc/postfix/client_whitelist_cidr")
    for map_name in defaults:
        if ctx.path(map_name.split(":", 1)[1]).exists() and map_name not in configured:
            ctx.add("WHITELIST.DISCONNECTED", "WARN", "Файл есть, но карта не найдена в check_client_access: " + map_name,
                    [{"source": map_name, "text": "source exists; no matching selected restriction reference"}],
                    "Проверьте желаемую схему; при использовании add_whitelists.sh администратор может применить его --setup отдельно.")
    map_names = list(dict.fromkeys(configured + [m for m in defaults if ctx.path(m.split(":", 1)[1]).exists()]))
    if len(map_names) > 20:
        ctx.add("WHITELIST.COVERAGE", "UNKNOWN", "Lookup ограничен первыми 20 уникальными картами", omitted=len(map_names) - 20)
    matched, applicable, uncertain = [], 0, False
    parent = "smtpd_access_maps" in re.split(r"[,\s]+", ctx.postconf.get("parent_domain_matches_subdomains", ""))
    parent_known = "parent_domain_matches_subdomains" in ctx.postconf
    for map_name in map_names[:20]:
        backend, path = map_name.split(":", 1)
        if backend not in {"hash", "btree", "lmdb", "cdb", "cidr", "texthash"} or _SENSITIVE.search(path):
            uncertain = True
            ctx.add("WHITELIST.MAP", "UNKNOWN", "Backend или путь карты исключён из безопасного локального lookup: " + clean(map_name),
                    next_step="Проверьте backend отдельно; сетевые/regexp maps автоматически не выполняются.")
            continue
        source = ctx.path(path)
        if _SENSITIVE.search(str(source.resolve())):
            uncertain = True
            ctx.add("WHITELIST.MAP", "UNKNOWN", "Resolved путь карты похож на credential file и исключён: " + clean(map_name))
            continue
        readable = False
        try:
            if not stat.S_ISREG(source.stat().st_mode):
                raise OSError("not a regular map source")
            descriptor = os.open(str(source), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise OSError("not a regular map source")
            finally:
                os.close(descriptor)
            readable = True
        except OSError:
            pass
        index_error = None
        if backend in {"hash", "btree"}:
            index = ctx.path(path + ".db")
            try:
                if source.stat().st_mtime > index.stat().st_mtime + 1:
                    index_error = "source newer than .db"
            except OSError:
                index_error = "source or .db unavailable"
        ctx.add("WHITELIST.MAP", "WARN" if index_error else "OK" if readable else "UNKNOWN",
                "{}: {}{}".format(map_name, "исходник читается" if readable else "исходник недоступен", "; " + index_error if index_error else ""),
                [{"source": path, "text": "readable={}; index={}".format(readable, index_error or "no stale index evidence")}],
                "postmap rebuild не выполняется; суффикс .db проверяется только для hash/btree.",
                backend=backend, source_readable=readable, stale_index_evidence=index_error)
        if client_name and backend == "cidr":
            ctx.add("WHITELIST.LOOKUP", "N/A", "Домен SMTP-клиента неприменим к CIDR: " + client_name,
                    [{"source": map_name, "text": "domain lookup not applicable"}], map=map_name, key=client_name, match=False)
        keys = []
        if address:
            keys.append(str(address))
        if client_name and backend != "cidr":
            keys.append(client_name)
            if parent_known:
                labels = client_name.split(".")
                keys += [("" if parent else ".") + ".".join(labels[i:]) for i in range(1, len(labels) - 1)]
            else:
                uncertain = True
        if keys:
            applicable += 1
        for key in keys[:12]:
            argv = ["postmap", "-q", key, map_name]
            result = ctx.run(argv)
            # postmap 1 with empty stdout/stderr means no match, not a command error.
            no_match = result.returncode == 1 and not result.stdout.strip() and not result.stderr.strip() and not result.timed_out and not result.truncated and not result.missing
            success = result.ok and not result.truncated
            action = result.stdout.strip()
            is_allow = success and bool(re.fullmatch(r"OK(?:\s+.*)?", action, re.I))
            if is_allow:
                matched.append({"layer": "postfix", "map": map_name, "key": key, "wired": map_name in configured})
            if not (success or no_match):
                uncertain = True
            ctx.add("WHITELIST.LOOKUP", "OK" if success or no_match else "UNKNOWN",
                    "{} [{}]: {}".format(map_name, key, "OK найден" if is_allow else "совпадение отсутствует" if no_match or not action else "найдено действие " + clean(action)),
                    [command_evidence(argv, result)],
                    "Точный postmap -q не является полным моделированием SMTP; имя клиента отличается от домена From.",
                    map=map_name, key=key, match=bool(success and action), permits=is_allow,
                    exact=key in {client_name, str(address) if address else ""}, parent_domain_matching=parent)
    pg_matches, pg_uncertain = postgrey_whitelist_checks(ctx, client_name, address)
    if client_name or address:
        allow = [m for m in matched if m["wired"]] + pg_matches
        ctx.add("WHITELIST.RESULT", "OK" if allow else "UNKNOWN" if uncertain or pg_uncertain else "WARN",
                "Совпадение разрешающего правила найдено" if allow else "Разрешающее совпадение не подтверждено",
                [{"source": "whitelist analysis", "text": "{} active-layer matches".format(len(allow))}],
                "Postgrey может пропустить клиента независимо от Postfix maps, если запрос дошёл до него; ранний reject и другие цепочки остаются.",
                client_name=client_name, client_ip=str(address) if address else None,
                matches=matched + pg_matches, applicable_postfix_maps=applicable,
                scope="SMTP client name/IP; not envelope From authorization")
    policy_listener_checks(ctx, contexts)


def postgrey_whitelist_checks(ctx, name, address):
    argv = ["systemctl", "show", "postgrey", "--property=ExecStart", "--value"]
    result = ctx.run(argv)
    state_cmd = ["systemctl", "show", "postgrey", "--property=LoadState,ActiveState,SubState", "--value"]
    state = ctx.run(state_cmd)
    _, active, _ = _unit_state(state)
    default, _ = ctx.read("/etc/default/postgrey")
    options = result.stdout if result.ok else ""
    options += " " + _assignments(default).get("POSTGREY_OPTS", "")
    pid_result = ctx.run(["systemctl","show","postgrey","--property=MainPID","--value"])
    if pid_result.ok and re.fullmatch(r"[1-9]\d{0,9}\s*",pid_result.stdout):
        runtime, _ = ctx.read("/proc/"+pid_result.stdout.strip()+"/cmdline",16384)
        if runtime:
            options = runtime.replace("\x00"," ")
    configured = re.findall(r"--whitelist-clients(?:=|\s+)([^\s;\"']+)", options)
    configdir = re.search(r"--config-dir(?:=|\s+)([^\s;\"']+)", options)
    paths = [p for p in configured if p.startswith("/") and "$" not in p and ".." not in Path(p).parts]
    defaults_confirmed = False
    defaults_source = None
    if not paths and not configdir:
        executable = re.search(r"(?:path=|^)(/[^\s;{}]+/postgrey)(?:\s|;|$)",result.stdout.strip())
        if executable:
            script, _ = ctx.read(executable[1],256*1024)
            directory = re.search(r"\bmy\s+\$CONFIG_DIR\s*=\s*['\"](/[^'\"$`]+)['\"]\s*;",script or "")
            definition = re.search(r"whitelist_clients_files\s*=>\s*\$opt\{'whitelist-clients'\}\s*\|\|\s*\[([^\]]+)\]",script or "",re.S)
            if directory and definition and "$" not in options:
                suffixes = re.findall(r'"\$CONFIG_DIR/(postgrey_)?whitelist_clients(\.local)?"',definition[1])
                if len(suffixes)==2:
                    paths=[directory[1]+"/"+(prefix or "")+"whitelist_clients"+(suffix or "") for prefix,suffix in suffixes]
                    defaults_confirmed=True
                    defaults_source=executable[1]
    inferred = not paths
    if not paths:
        directories = [configdir[1]] if configdir and configdir[1].startswith("/") else ["/etc/postgrey", "/etc/postfix"]
        for directory in directories:
            paths += [directory + "/whitelist_clients", directory + "/whitelist_clients.local"] if directory.endswith("postgrey") else [directory + "/postgrey_whitelist_clients", directory + "/postgrey_whitelist_clients.local"]
    matches, unknown, readable_count = [], False, 0
    for path in list(dict.fromkeys(paths))[:12]:
        text, error = ctx.read(path)
        if text is None:
            if not inferred:
                unknown = True
                ctx.add("WHITELIST.POSTGREY_FILE", "UNKNOWN", "Файл Postgrey недоступен: " + clean(path),
                        [{"source": path, "text": error}])
            continue
        readable_count += 1
        for lineno, line in enumerate(text.splitlines(), 1):
            token = line.split("#", 1)[0].strip()
            if not token:
                continue
            hit = False
            if token.startswith("/"):
                unknown = True  # Perl regex semantics are not evaluated as Python or shell.
                continue
            ip_rule = False
            try:
                network = ipaddress.ip_network(token, strict=False)
                ip_rule = True
                hit = bool(address and address.version == network.version and address in network)
            except ValueError:
                if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){1,2}", token):
                    ip_rule = True
                    if token.count(".") == 1:
                        # Upstream's comment says /16 but its implementation
                        # passes /24 to NetAddr::IP. Do not invent semantics for
                        # this ambiguous legacy spelling on another version.
                        unknown = True
                    else:
                        try:
                            network = ipaddress.ip_network(token + ".0/24")
                            hit = bool(address and address.version == 4 and address in network)
                        except ValueError:
                            unknown = True
            if not ip_rule and name and _HOST.fullmatch(token):
                candidate = token.lower().rstrip(".")
                hit = hit or name == candidate or name.endswith("." + candidate)
            if hit:
                matches.append({"layer": "postgrey", "file": path, "line": lineno, "rule": clean(token),
                                "active_file_confirmed": bool((configured or configdir or defaults_confirmed) and active)})
        ctx.add("WHITELIST.POSTGREY_FILE", "OK" if configured or configdir or defaults_confirmed else "UNKNOWN",
                "Postgrey whitelist читается: " + path + ("; defaults подтверждены установленным Postgrey" if defaults_confirmed else "; путь найден по options" if configured or configdir else "; использование этого default-файла не подтверждено options"),
                [{"source": path, "text": "{} readable lines; matched rules={}".format(len(text.splitlines()), len([m for m in matches if m["file"] == path]))}],
                "Postgrey plain hostname rules охватывают поддомены; client AWL и явный client whitelist — разные причины pass.",
                inferred_path=inferred, defaults_source=defaults_source, regex_rules_unmodeled=unknown)
    active_matches = [m for m in matches if m["active_file_confirmed"]]
    if not readable_count:
        ctx.add("WHITELIST.POSTGREY_FILE", "UNKNOWN" if result.ok else "N/A",
                "Локальный client whitelist Postgrey не найден или недоступен",
                [{"source": "postgrey options", "text": "{} candidate paths".format(len(paths))}],
                "Проверьте реальный config-dir, process options и возможность чтения; отсутствие файла не доказывает отсутствие AWL.")
    if matches:
        ctx.add("WHITELIST.POSTGREY_MATCH", "OK" if active_matches else "UNKNOWN",
                "В Postgrey whitelist найдено совпадение имени/IP клиента",
                [{"source": m["file"], "line": m["line"], "text": m["rule"]} for m in matches[:20]],
                "Правило применяется независимо от Postfix access maps, только если запрос дошёл до этого Postgrey.", matches=matches)
    return active_matches, unknown or not readable_count or not bool((configured or configdir or defaults_confirmed) and active)


def policy_listener_checks(ctx, contexts):
    endpoints = set()
    for config in contexts.values():
        for value in config.values():
            endpoints.update(re.findall(r"\bcheck_policy_service\s+(inet:[^,\s{}]+|unix:[^,\s{}]+)", value or ""))
    if not endpoints:
        return
    argv = ["ss", "-ltnp"]
    result = ctx.run(argv)
    for endpoint in sorted(endpoints):
        port = re.search(r":(\d+)\Z", endpoint)
        local = bool(re.match(r"inet:(?:127\.[\d.]+|localhost|\[?::1\]?):", endpoint))
        if not port or not local:
            ctx.add("POLICY.LISTENER", "UNKNOWN", "Policy endpoint: " + clean(endpoint),
                    [{"source": "postconf", "text": endpoint}],
                    "Проверьте доступность и назначение сервиса; порт сам по себе не определяет приложение.")
            continue
        lines = [line for line in result.stdout.splitlines() if re.search(r":" + port[1] + r"\s", line)]
        status = "OK" if lines and result.ok else "WARN" if result.ok and not result.truncated else "UNKNOWN"
        ctx.add("POLICY.LISTENER", status, endpoint + (": TCP listener найден" if lines else ": listener не подтверждён"),
                [command_evidence(argv, result, " | ".join(lines) if lines else "no matching listen socket")],
                "Назначение проверяйте по процессу/службе; listener не доказывает корректный policy response.", endpoint=endpoint)


_RBL_RESTRICTIONS = ("reject_rbl_client", "reject_rhsbl_client", "reject_rhsbl_sender",
                     "reject_rhsbl_helo", "reject_rhsbl_recipient", "reject_rhsbl_reverse_client")
_RBL_OCTET = r"(\d{1,3}|\[[0-9.;]+\])"


def rbl_filter_matches(pattern, address):
    """Evaluate a Postfix reply filter ``d.d.d.d`` against one IPv4 reply.

    Each d is a number or, since Postfix 2.8, ``[...]`` with ``;``-separated
    numbers and ``n..m`` ranges. None means the filter is not understood.
    """
    match = re.fullmatch(r"\.".join([_RBL_OCTET] * 4), pattern) if len(pattern) <= 512 else None
    if not match:
        return None
    octets = []
    for part in match.groups():
        ranges = []
        for item in ([part] if part.isdigit() else part[1:-1].split(";")):
            bounds = item.split("..")
            if len(bounds) > 2 or not all(b.isdigit() and len(b) <= 3 for b in bounds):
                return None
            low, high = int(bounds[0]), int(bounds[-1])
            if not 0 <= low <= high <= 255:
                return None
            ranges.append((low, high))
        octets.append(ranges)
    return all(any(low <= value <= high for low, high in ranges)
               for ranges, value in zip(octets, map(int, address.split("."))))


def _spamhaus_zone(zone):
    return zone.endswith((".spamhaus.org", ".dq.spamhaus.net"))


def _zone_error_codes(zone):
    # DQS documents the entire /24 as errors. Public mirror meanings below
    # must not be assigned to a DQS key/account error with the same octet.
    codes = (["127.255.255." + str(n) for n in range(256)]
             if zone.endswith(".dq.spamhaus.net") else sorted(_DNSBL_ERRORS))
    if zone.startswith("dbl.") or ".dbl.dq.spamhaus.net" in zone:
        codes = codes + [_DBL_IP_QUERY]
    return codes


def dnsbl_filter_checks(ctx, contexts):
    """Postfix rejects on any A record unless a reply filter is set, so an
    unfiltered public Spamhaus zone turns error replies into rejections."""
    seen, unparsed = {}, False
    for name, config in contexts.items():
        for parameter, value in config.items():
            if value is None:
                unparsed = True
                continue
            tokens = _chain_tokens(value)
            if tokens is None:
                unparsed = True
                continue
            for i, token in enumerate(tokens[:-1]):
                zone, _, pattern = tokens[i + 1].partition("=")
                zone = zone.lower().rstrip(".")
                if token not in _RBL_RESTRICTIONS or not _spamhaus_zone(zone):
                    continue
                key = (token, zone, pattern)
                if key not in seen and len(seen) >= 80:
                    unparsed = True
                    continue
                places = seen.setdefault(key, [])
                if len(places) < 80:
                    places.append(name + "/" + parameter)
                else:
                    unparsed = True
    for (restriction, zone, pattern), places in sorted(seen.items()):
        codes = _zone_error_codes(zone)
        verdicts = {code: rbl_filter_matches(pattern, code) if pattern else True for code in codes}
        accepted = [code for code, hit in verdicts.items() if hit]
        rule = restriction + " " + zone + ("=" + pattern if pattern else "")
        if None in verdicts.values():
            status, title = "UNKNOWN", rule + ": фильтр кодов ответа не разобран"
            next_step = "Сверьте фильтр с документацией Postfix (reject_rbl_client) и кодами ошибок Spamhaus."
        elif accepted:
            status = "WARN"
            title = rule + ": " + ("нет фильтра кодов ответа" if not pattern else "фильтр пропускает " + ", ".join(accepted)) + "; ошибка Spamhaus станет отказом"
            next_step = ("Без фильтра Postfix считает listing любой A-ответ, включая 127.255.255.252/254/255 публичных зеркал Spamhaus и ошибки DQS из 127.255.255.0/24; "
                         "при заблокированном resolver это может отклонять клиентов, дошедших до данного правила. Задайте фильтр по кодам listing "
                         "(как в MIAB: zen.spamhaus.org=127.0.0.[2..11], dbl.spamhaus.org=127.0.1.[2..99]); Radar конфигурацию не меняет.")
        else:
            status, title = "OK", rule + ": коды ошибок Spamhaus не считаются listing"
            next_step = "Фильтр защищает от ложных отказов, но при заблокированном resolver RBL перестаёт отклонять спам: проверьте DNSBL.CONTROL с --network."
        ctx.add("DNSBL.POSTFIX_FILTER", status, clean(title),
                [{"source": "postconf" if place.startswith("global/") else "postconf -P", "text": clean(place + ": " + rule)} for place in places[:20]],
                next_step, restriction=restriction, zone=clean(zone), filter=clean(pattern),
                contexts=[clean(p) for p in places[:80]], error_codes_accepted=accepted)
    if unparsed or not seen:
        ctx.add("DNSBL.POSTFIX_FILTER", "UNKNOWN" if unparsed else "N/A",
                "Зоны Spamhaus в restrictions Postfix: " + ("часть цепочек не прочитана или не разобрана" if unparsed else "не используются"),
                [{"source": "postconf", "text": "selected smtpd client/sender/recipient/relay/helo/data/end_of_data restrictions"}],
                "Restriction classes и действия access maps не раскрываются; postscreen проверяется отдельно.",
                coverage=True)
    indirect = bool(ctx.postconf.get("smtpd_restriction_classes")) or any(config.get("smtpd_restriction_classes") for config in contexts.values()) or any(
        re.search(r"\bcheck_\w+_access\b", value or "") for config in contexts.values() for value in config.values())
    if indirect:
        ctx.add("DNSBL.INDIRECT_COVERAGE", "UNKNOWN", "DNSBL внутри restriction classes и действий access maps не проверены",
                next_step="Проверьте косвенные ограничения вручную. Карты могут зависеть от клиента; credential maps не читаются.")
    postscreen_dnsbl_checks(ctx)


def postscreen_dnsbl_checks(ctx):
    """Bounded static review; a weight applies once per site, not per A record.

    Negative weights and other listings mean an error score is only a bound,
    never a prediction that every client will be rejected.
    """
    master = ctx.run(["postconf", "-M"])
    rows = master.stdout.splitlines()
    if not master.ok or len(rows) > 200:
        ctx.add("DNSBL.POSTSCREEN", "UNKNOWN", "Сервисы postscreen не подтверждены", [command_evidence(["postconf", "-M"], master)])
        return
    services = [f[0] + "/" + f[1] for row in rows if len(f := row.split()) >= 8 and f[7] == "postscreen"]
    if not services:
        ctx.add("DNSBL.POSTSCREEN", "N/A", "Postscreen не найден в master.cf")
        return
    keys = ("postscreen_dnsbl_sites", "postscreen_dnsbl_threshold", "postscreen_dnsbl_action", "postscreen_dnsbl_allowlist_threshold")
    overrides = ctx.run(["postconf", "-P"])
    for service in services[:80]:
        config = {key: ctx.postconf.get(key) for key in keys}
        for line in overrides.stdout.splitlines() if overrides.ok else []:
            match = re.fullmatch(re.escape(service) + r"/(postscreen_dnsbl_(?:sites|threshold|action|allowlist_threshold))\s*=\s*(.*)", line)
            if match:
                config[match[1]] = match[2]
        sites, threshold, action, allowlist = (config[key] for key in keys)
        complete = overrides.ok and all(value is not None for value in config.values())
        if not complete or not re.fullmatch(r"[1-9][0-9]{0,5}", threshold or "") or not re.fullmatch(r"-?[0-9]{1,6}", allowlist or "") or action not in {"ignore", "enforce", "drop"}:
            ctx.add("DNSBL.POSTSCREEN", "UNKNOWN", service + ": параметры postscreen DNSBL не разобраны полностью")
            continue
        tokens = _chain_tokens(sites)
        if tokens is None or len(tokens) > 80:
            ctx.add("DNSBL.POSTSCREEN", "UNKNOWN", service + ": синтаксис postscreen_dnsbl_sites не разобран")
            continue
        risk, unknown, positive_bound, relevant = [], False, 0, 0
        for site in tokens:
            spec, star, weight_text = site.partition("*")
            if star and not re.fullmatch(r"-?[0-9]{1,6}", weight_text):
                unknown = True
                continue
            weight = int(weight_text) if star else 1
            zone, equals, pattern = spec.partition("=")
            zone = zone.lower().rstrip(".")
            if not _spamhaus_zone(zone):
                continue
            relevant += 1
            hits = [rbl_filter_matches(pattern, code) if equals else True for code in _zone_error_codes(zone)]
            if None in hits:
                unknown = True
            elif any(hits) and weight:
                risk.append({"zone": clean(zone), "weight": weight, "filter": clean(pattern)})
                positive_bound += max(0, weight)
        allowlist_risk = int(allowlist) < 0 and any(site["weight"] < 0 for site in risk)
        status = "UNKNOWN" if unknown else "WARN" if risk and (action != "ignore" or allowlist_risk) else "OK" if relevant else "N/A"
        ctx.add("DNSBL.POSTSCREEN", status, service + ": " + (
            "часть DNSBL-конфигурации не разобрана" if unknown else
            "ошибки Spamhaus влияют на score" if risk else "фильтры исключают ошибки Spamhaus" if relevant else "Spamhaus не используется"),
            [{"source": "postconf / postconf -P / postconf -M", "text": clean(service + ": sites=" + sites + "; threshold=" + threshold + "; action=" + action)}],
            "Вес зоны учитывается один раз. Положительный вес ошибки может привести к ложному отказу, отрицательный — к обходу DNSBL. При action=ignore отказ не применяется. Другие listing/allowlist и порядок тестов требуют отдельного анализа.",
            context=service, action=action, threshold=int(threshold), allowlist_threshold=int(allowlist), error_weight_sites=risk,
            maximum_positive_error_score=positive_bound, errors_alone_may_reach_threshold=positive_bound >= int(threshold),
            score_is_upper_bound=True, complete=not unknown)


def parse_dns(result, record_type):
    """Preserve authoritative DNS response states; empty output is never clean."""
    if result.missing:
        return "MISSING_COMMAND", []
    if result.timed_out or re.search(r"timed out|no servers could be reached", result.stderr + result.stdout, re.I):
        return "TIMEOUT", []
    if not result.ok or result.truncated:
        return "ERROR", []
    match = re.search(r"status:\s*([A-Z]+)", result.stdout)
    if not match:
        return "UNKNOWN", []
    state = match[1]
    answers = re.findall(r"^\S+\s+\d+\s+IN\s+" + re.escape(record_type) + r"\s+(.+)$", result.stdout, re.M | re.I)
    if state != "NOERROR" and answers:
        return "INCONSISTENT_RESPONSE", answers
    return ("NODATA" if state == "NOERROR" and not answers else state), answers


# Public-zone return codes, checked against Spamhaus' own FAQ 2026-11-02.
# .5-.8 are reserved; unknown/future codes stay UNKNOWN until reviewed.
_DNSBL_LISTED = {
    "ip": {"127.0.0." + str(n) for n in (2, 3, 4, 9, 10, 11)},
    "domain": {"127.0.1.2", "127.0.1.4", "127.0.1.5", "127.0.1.6", "127.0.1.102", "127.0.1.103", "127.0.1.104", "127.0.1.105", "127.0.1.106"}}
# Error replies of the public mirrors in any zone (Spamhaus DNSBL usage and DBL
# FAQs, checked 2026-11-03). They describe the query path, never the target.
_DNSBL_ERRORS = {"127.255.255.252": "zone_name_error",
                 "127.255.255.254": "public_resolver_blocked",
                 "127.255.255.255": "query_limit_exceeded"}
_DBL_IP_QUERY = "127.0.1.255"
_DNSBL_NEXT_STEPS = {
    "public_resolver_blocked": "Ответ 127.255.255.254: Spamhaus не обслуживает запросы через публичный или общий resolver; репутация неизвестна. Причина и исправление — в DNSBL.CONTROL.",
    "query_limit_exceeded": "Ответ 127.255.255.255: превышен лимит запросов к публичному зеркалу с этого resolver или адреса; репутация неизвестна. Проверьте объём DNSBL-запросов и условия бесплатного доступа (или DQS).",
    "zone_name_error": "Ответ 127.255.255.252: Spamhaus не распознал имя зоны в запросе; сверьте имя DNSBL-зоны.",
    "ip_query_on_domain_list": "Ответ 127.0.1.255: DBL не принимает IP-адреса; передайте в --domain доменное имя.",
    "mixed_error_response": "В ответе одновременно код ошибки Spamhaus и другие адреса; это не listing. Повторите позже через собственный resolver.",
}


def dnsbl_state(state, answers, kind, access="public"):
    if state == "NXDOMAIN":
        return "OK", "not_listed"
    if state != "NOERROR":
        return "UNKNOWN", "dns_" + state.lower()
    codes = {a.strip() for a in answers}
    if access == "dqs":
        errors = {code for code in codes if code.startswith("127.255.255.") or kind == "domain" and code == _DBL_IP_QUERY}
        if errors:
            return "UNKNOWN", "dqs_error_response"
        try:
            listed = bool(codes) and all(ipaddress.ip_address(code) in ipaddress.ip_network("127.0.0.0/16") for code in codes)
        except ValueError:
            listed = False
        return ("WARN", "listed") if listed else ("UNKNOWN", "service_or_unrecognized_response")
    if codes and codes <= _DNSBL_LISTED[kind]:
        return "WARN", "listed"
    errors = dict(_DNSBL_ERRORS, **({_DBL_IP_QUERY: "ip_query_on_domain_list"} if kind == "domain" else {}))
    if len(codes) == 1 and codes <= errors.keys():
        return "UNKNOWN", errors[codes.pop()]
    if codes & errors.keys():
        return "UNKNOWN", "mixed_error_response"
    return "UNKNOWN", "service_or_unrecognized_response"


def _resolver_addresses(text):
    servers = []
    for value in re.findall(r"^\s*nameserver\s+(\S+)", text or "", re.M):
        try:
            servers.append(str(ipaddress.ip_address(value)))
        except ValueError:
            pass
    return list(dict.fromkeys(servers))


def _postfix_resolver_config(ctx):
    argv = ["postconf", "-M"]
    result = ctx.run(argv)
    services, default_flags = [], False
    for line in result.stdout.splitlines()[:200]:
        fields = line.split()
        if len(fields) < 8 or fields[7] not in {"smtp", "smtpd", "postscreen"}:
            continue
        if fields[4] == "y":
            services.append(fields[0] + "/" + fields[1])
        elif fields[4] == "-":
            default_flags = True
    if not result.ok or result.truncated or len(result.stdout.splitlines()) > 200:
        ctx.add("DNS.POSTFIX_RESOLVER", "UNKNOWN", "Chroot resolver Postfix не установлен по master.cf",
                [command_evidence(argv, result, "selected SMTP service chroot metadata unavailable")],
                "Если Postfix работает в chroot, его resolv.conf может отличаться от /etc/resolv.conf.")
        return []
    if not services:
        ctx.add("DNS.POSTFIX_RESOLVER", "UNKNOWN" if default_flags else "N/A", "Явные chroot=y SMTP-services не найдены в master.cf",
                [command_evidence(argv, result, "explicit chroot SMTP services: none")],
                "Проверьте версионный default master.cf, если chroot использует '-'.", default_flags_present=default_flags)
        return []
    directory = ctx.postconf.get("queue_directory", "")
    if not PurePosixPath(directory).is_absolute() or ".." in PurePosixPath(directory).parts or "$" in directory:
        ctx.add("DNS.POSTFIX_RESOLVER", "UNKNOWN", "Есть chroot SMTP-services, но queue_directory не подтверждён",
                [{"source": "postconf -M", "text": ",".join(services)}])
        return []
    path = directory.rstrip("/") + "/etc/resolv.conf"
    text, error = ctx.read(path)
    servers = _resolver_addresses(text)
    ctx.add("DNS.POSTFIX_RESOLVER", "OK" if servers else "UNKNOWN", "Postfix chroot resolver: " + (", ".join(servers) if servers else "не установлен"),
            [{"source": path, "text": "nameserver=" + ",".join(servers) if servers else error or "no nameserver"},
             {"source": "postconf -M", "text": "explicit chroot services=" + ",".join(services)}],
            "Проверяются серверы из chroot resolv.conf; namespace, libc и per-service execution environment остаются отдельными границами.",
            nameservers=servers, path=path, services=services)
    return [(path, server) for server in servers[:4]]


def dns_checks(ctx):
    resolv, error = ctx.read("/etc/resolv.conf")
    servers = _resolver_addresses(resolv)
    ctx.add("DNS.RESOLVER_CONFIG", "OK" if servers else "UNKNOWN",
            "Resolver из resolv.conf: " + (", ".join(servers) if servers else "не установлен"),
            [{"source": "/etc/resolv.conf", "text": "nameserver=" + ",".join(servers) if servers else error or "no literal nameserver"}],
            "Recursive resolver и авторитетный NSD выполняют разные роли; active службы не доказывает разрешение.", nameservers=servers)
    postfix_resolvers = _postfix_resolver_config(ctx)
    if not getattr(ctx.args, "network", False):
        ctx.add("NETWORK.PROBES", "N/A", "Активные DNS/TLS/HTTP-пробы не выбраны", next_step="Добавьте --network для ограниченных сетевых проверок.")
        return
    domain = (getattr(ctx.args, "domain", None) or ctx.postconf.get("mydomain", "")).rstrip(".")
    hostname = (ctx.postconf.get("myhostname") or ctx.metadata.get("PRIMARY_HOSTNAME", "")).rstrip(".")
    if not _HOST.fullmatch(domain or ""):
        ctx.add("DNS.DOMAIN", "UNKNOWN", "Домен для DNS-проверок не задан или некорректен", next_step="Укажите --domain example.org.")
        return
    queries = [("/etc/resolv.conf", server) for server in servers[:4]] or [("system default", None)]
    queries += postfix_resolvers
    if postfix_resolvers and servers and set(server for _, server in postfix_resolvers) != set(servers):
        ctx.add("DNS.RESOLVER_DIFFERENCE", "WARN", "Resolvers Postfix chroot и host отличаются",
                [{"source": "resolver comparison", "text": "host=" + ",".join(servers) + "; postfix=" + ",".join(server for _, server in postfix_resolvers)}],
                "Отличие может быть осознанным; успешный host query не подтверждает chroot resolver.")
    for source, server in queries:
        argv = _dig(domain, "MX", server)
        result = ctx.run(argv, timeout=5)
        state, answers = parse_dns(result, "MX")
        ctx.add("DNS.RESOLVER_QUERY", "OK" if state == "NOERROR" else "WARN" if state in {"NXDOMAIN", "NODATA"} else "FAIL" if state in {"SERVFAIL", "REFUSED", "TIMEOUT"} else "UNKNOWN",
                "Resolver {}: {} MX → {}".format(server or "system default", domain, state),
                [command_evidence(argv, result)],
                "Сравните с авторитетным DNS отдельно; успешный ответ внешнего resolver не исправляет локальный.",
                resolver=server or "system default", resolver_config=source, dns_state=state, answers=[clean(a) for a in answers])
    requests = [(domain, "MX", "MX"), (domain, "TXT", "SPF"),
                ("_dmarc." + domain, "TXT", "DMARC"),
                ("_mta-sts." + domain, "TXT", "MTA_STS"),
                ("_smtp._tls." + domain, "TXT", "TLS_RPT")]
    if hostname and _HOST.fullmatch(hostname):
        requests += [(hostname, "A", "A"), (hostname, "AAAA", "AAAA"), ("_25._tcp." + hostname, "TLSA", "DANE")]
    selector = getattr(ctx.args, "dkim_selector", None)
    if selector and re.fullmatch(r"[A-Za-z0-9_.-]{1,63}", selector):
        requests.append((selector + "._domainkey." + domain, "TXT", "DKIM"))
    else:
        ctx.add("DNS.DKIM", "UNKNOWN", "DKIM selector не задан; отсутствие DKIM не утверждается",
                next_step="Возьмите selector из реальной DKIM-Signature или signing-конфигурации и укажите --dkim-selector.")
    for query, kind, label in requests:
        argv = _dig(query, kind)
        result = ctx.run(argv, timeout=5)
        state, answers = parse_dns(result, kind)
        joined = [a.replace('" "', "").strip('"') for a in answers]
        valid = answers
        if label == "SPF":
            valid = [a for a in joined if a.lower().startswith("v=spf1")]
        elif label == "DMARC":
            valid = [a for a in joined if a.lower().startswith("v=dmarc1")]
        elif label == "DKIM":
            valid = [a for a in joined if re.search(r"(?:^|;)\s*p=\S+", a, re.I)]
        optional = label in {"MTA_STS", "TLS_RPT", "DANE", "AAAA"}
        status = "OK" if state == "NOERROR" and valid else "N/A" if optional and state in {"NXDOMAIN", "NODATA"} else "WARN" if state in {"NOERROR", "NXDOMAIN", "NODATA"} else "UNKNOWN"
        if label == "SPF" and any(re.search(r"(?:^|\s)\+all(?:\s|$)", a) for a in joined):
            status = "WARN"
        if label == "DMARC" and any(re.search(r"(?:^|;)\s*p=none(?:;|$)", a, re.I) for a in joined):
            status = "WARN"
        ctx.add("DNS." + label, status, "{} {}: {}{}".format(label, query, state, "; нужная запись не найдена" if not valid else ""),
                [command_evidence(argv, result)],
                "Наличие записи не является полной SPF/DKIM/DMARC/DANE/MTA-STS валидацией и не доказывает доставку.",
                query=query, record_type=kind, dns_state=state, answers=[clean(a) for a in answers[:12]])
    for variable, family in (("PUBLIC_IP", 4), ("PUBLIC_IPV6", 6)):
        public = ctx.metadata.get(variable)
        try:
            public_address = ipaddress.ip_address(public) if public else None
            if public_address and public_address.version != family:
                public_address = None
        except ValueError:
            public_address = None
        if public_address:
            argv = _dig(public_address.reverse_pointer, "PTR")
            result = ctx.run(argv, timeout=5)
            state, answers = parse_dns(result, "PTR")
            match = hostname and hostname in [a.rstrip(".") for a in answers]
            ctx.add("DNS.PTR" if family == 4 else "DNS.PTR_IPV6", "OK" if match else "WARN" if state in {"NOERROR", "NXDOMAIN", "NODATA"} else "UNKNOWN",
                    "PTR публичного IPv{}: ".format(family) + state + ("; соответствует myhostname" if match else "; соответствие не подтверждено"),
                    [command_evidence(argv, result)], hostname=hostname, address=str(public_address), family=family, answers=answers)
            reverse = public_address.reverse_pointer.rsplit(".in-addr.arpa" if family == 4 else ".ip6.arpa", 1)[0]
            _dnsbl(ctx, reverse + ".zen.spamhaus.org", "ip", family=family)
        else:
            ctx.add("DNS.PTR" if family == 4 else "DNS.PTR_IPV6", "UNKNOWN" if family == 4 or public else "N/A",
                    "Публичный IPv{} сервера не подтверждён metadata; PTR/IP DNSBL не проверялись".format(family),
                    next_step="Проверьте публичный адрес и NAT; адрес SMTP-клиента не подставляется как адрес сервера.", family=family)
    _dnsbl(ctx, domain + ".dbl.spamhaus.org", "domain")


def _dig(name, record_type, server=None):
    return ["dig", "+time=2", "+tries=1", "+noall", "+comments", "+answer"] + (["@" + server] if server else []) + [name, record_type]


def _dnsbl(ctx, query, kind, family=None):
    argv = _dig(query, "A")
    result = ctx.run(argv, timeout=5)
    state, answers = parse_dns(result, "A")
    status, outcome = dnsbl_state(state, answers, kind)
    controls = None
    # An error reply also runs the controls: they show whether the whole query
    # path is refused, which is what the administrator has to fix.
    if outcome in {"listed", "not_listed"} or outcome in _DNSBL_ERRORS.values():
        controls = _dnsbl_controls(ctx, kind)
        if not controls and outcome in {"listed", "not_listed"}:
            status, outcome = "UNKNOWN", "operational_controls_failed"
    ctx.add("DNSBL." + ("IPV6" if kind == "ip" and family == 6 else kind.upper()), status, "{}{} reputation: {}".format(kind, " IPv" + str(family) if family else "", outcome),
            [command_evidence(argv, result)],
            _DNSBL_NEXT_STEPS.get(outcome, "Проверьте актуальные условия доступа оператора DNSBL; служебный код/ошибка resolver не равны listing. Domain и IP reputation независимы."),
            query=query, family=family, dns_state=state, outcome=outcome,
            operational_controls_passed=controls, answers=[clean(a) for a in answers])


def _dnsbl_controls(ctx, kind):
    if kind in ctx.dnsbl_controls:
        return ctx.dnsbl_controls[kind]
    positive, negative = (("2.0.0.127.zen.spamhaus.org", "1.0.0.127.zen.spamhaus.org") if kind == "ip"
                          else ("test.dbl.spamhaus.org", "example.com.dbl.spamhaus.org"))
    evidence, states = [], []
    for query in (positive, negative):
        argv = _dig(query, "A")
        result = ctx.run(argv, timeout=5)
        state, answers = parse_dns(result, "A")
        states.append((state, answers))
        evidence.append(command_evidence(argv, result))
    outcomes = [dnsbl_state(state, answers, kind)[1] for state, answers in states]
    positive_ok = outcomes[0] == "listed"
    negative_ok = states[1][0] == "NXDOMAIN" and not states[1][1]
    passed = positive_ok and negative_ok
    ctx.dnsbl_controls[kind] = passed
    # A Spamhaus error code on a control is a confirmed refusal of this query
    # path, not merely missing evidence.
    refusal = next((o for o in outcomes if o in _DNSBL_ERRORS.values()), None)
    next_step = {
        "public_resolver_blocked": "Spamhaus отклоняет запросы через resolver этого хоста как публичный/общий (127.255.255.254). Используйте собственный рекурсивный resolver без forwarders на публичные DNS (в MIAB — локальный bind9 на 127.0.0.1) или Spamhaus DQS. Пока так, reject_rbl_client с фильтром кодов (как в MIAB) ничего не отклоняет, а без фильтра может ошибочно отклонять клиентов, дошедших до правила. Resolver Postfix в chroot сверьте с DNS.POSTFIX_RESOLVER.",
        "query_limit_exceeded": "Spamhaus сообщает о превышении лимита запросов (127.255.255.255) для resolver этого хоста. Проверьте объём DNSBL-запросов, общий ли это resolver, и условия бесплатного доступа (или DQS). Postfix RBL в это время работает так же ненадёжно.",
        "zone_name_error": "Spamhaus не распознал имя контрольной зоны (127.255.255.252); проверьте, не переписывает ли resolver или DNS-прокси запросы.",
    }.get(refusal, "Public resolver может возвращать NXDOMAIN для всех запросов; без обоих control results репутационный вывод неизвестен.")
    ctx.add("DNSBL.CONTROL." + kind.upper(), "OK" if passed else "WARN" if refusal else "UNKNOWN",
            "{} DNSBL: positive/negative operational controls {}".format(
                kind, "passed" if passed else "отклонены Spamhaus: " + refusal if refusal else "не подтверждены"),
            evidence, next_step,
            positive_query=positive, negative_query=negative, positive_ok=positive_ok, negative_ok=negative_ok,
            positive_outcome=outcomes[0], negative_outcome=outcomes[1], operator_error=refusal, resolver="system default")
    return passed


def tls_checks(ctx):
    if not getattr(ctx.args, "network", False):
        return
    hostname = (ctx.postconf.get("myhostname") or ctx.metadata.get("PRIMARY_HOSTNAME", "")).rstrip(".")
    if not _HOST.fullmatch(hostname or ""):
        ctx.add("TLS.ENDPOINTS", "UNKNOWN", "SMTP hostname для TLS-проб не установлен")
        return
    for port, starttls in ((25, True), (587, True), (465, False), (993, False), (443, False)):
        argv = ["openssl", "s_client", "-connect", hostname + ":" + str(port), "-servername", hostname,
                "-verify_hostname", hostname, "-verify_return_error", "-showcerts"]
        if starttls:
            argv += ["-starttls", "smtp"]
        result = ctx.run(argv, timeout=6)
        output = result.stdout + "\n" + result.stderr
        certificate = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", output, re.S)
        details = {"port": port, "hostname": hostname, "mode": "STARTTLS" if starttls else "implicit TLS", "external_reachability_proven": False}
        status = "UNKNOWN"
        title = "{}:{}: TLS-проба не завершена успешно".format(hostname, port)
        cert_text = "no decoded certificate"
        if certificate:
            try:
                with tempfile.TemporaryDirectory(prefix="mail-radar-cert-") as folder:
                    os.chmod(folder, 0o700)
                    certpath = Path(folder) / "public.pem"
                    fd = os.open(str(certpath), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "w", encoding="ascii") as stream:
                        stream.write(certificate[0])
                    decoded = ssl._ssl._test_decode_cert(str(certpath))
                expiry = ssl.cert_time_to_seconds(decoded["notAfter"])
                days = (expiry - dt.datetime.now(dt.timezone.utc).timestamp()) / 86400
                details.update(not_after=decoded["notAfter"], days_remaining=round(days, 2))
                cert_text = "notAfter=" + decoded["notAfter"]
                if days <= 0:
                    status, title = "FAIL", "{}:{}: предъявленный сертификат истёк".format(hostname, port)
                elif result.ok and not result.truncated and re.search(r"Verify return code: 0 \(ok\)|Verification: OK", output):
                    status = "FAIL" if days <= 7 else "WARN" if days <= 30 else "OK"
                    title = "{}:{}: chain/hostname проверены этой пробой; до expiry {:.1f} суток".format(hostname, port, days)
            except (ValueError, OSError, KeyError, ssl.SSLError, AttributeError):
                cert_text = "certificate present but decode unavailable"
        # A local crypto-policy/cipher error cannot prove the server disables a protocol.
        if status == "UNKNOWN":
            cert_text += "; " + clean(result.stderr or result.stdout, 400)
        ctx.add("TLS.PORT_" + str(port), status, title,
                [command_evidence(argv, result, cert_text)],
                "Проверка касается одного порта и возможностей локального OpenSSL; локальная/внутренняя доступность не доказывает доступ извне.", **details)


def security_checks(ctx):
    argv = ["sshd", "-T"]
    result = ctx.run(argv)
    values = {}
    for line in result.stdout.splitlines():
        key, _, value = line.partition(" ")
        if key in {"permitrootlogin", "passwordauthentication", "port"}:
            values[key] = value.strip()
    if not result.ok or result.truncated or not values:
        ctx.add("SECURITY.SSH", "UNKNOWN", "Эффективные baseline-настройки SSH недоступны",
                [command_evidence(argv, result, "selected SSH values unavailable")])
    else:
        weak = values.get("permitrootlogin") == "yes" or values.get("passwordauthentication") == "yes"
        ctx.add("SECURITY.SSH", "WARN" if weak else "OK", "SSH baseline: " + clean(str(values)),
                [command_evidence(argv, result, "; ".join(k + "=" + v for k, v in sorted(values.items())))],
                "Match-блоки зависят от пользователя/адреса; этот baseline не доказывает настройки для каждого подключения.", values=values)
    for jail in ("postfix-sasl", "dovecot", "sshd", "recidive"):
        argv = ["fail2ban-client", "status", jail]
        result = ctx.run(argv)
        banned = re.search(r"Currently banned:\s*(\d+)", result.stdout)
        failed = re.search(r"Currently failed:\s*(\d+)", result.stdout)
        status = "N/A" if result.missing else "UNKNOWN" if not result.ok or result.truncated or not banned else "OK"
        ctx.add("SECURITY.FAIL2BAN." + jail.upper().replace("-", "_"), status, "Fail2Ban {}: {}".format(jail, "banned=" + banned[1] if banned else "не подтверждён"),
                [command_evidence(argv, result, "banned={}; failed={}".format(banned[1] if banned else "unknown", failed[1] if failed else "unknown"))],
                "Сопоставьте блокировки с IP клиента и журналом; число bans само по себе не доказывает потерю почты.", jail=jail,
                banned=int(banned[1]) if banned else None, failed=int(failed[1]) if failed else None)
    argv = ["dpkg-query", "-W", "-f=${db:Status-Abbrev}\n", "unattended-upgrades"]
    result = ctx.run(argv)
    ctx.add("SECURITY.UPDATES", "OK" if result.ok and result.stdout.startswith("ii") else "UNKNOWN" if result.missing or result.timed_out else "WARN",
            "unattended-upgrades: " + ("пакет установлен" if result.ok and result.stdout.startswith("ii") else "установка не подтверждена"),
            [command_evidence(argv, result)], "Наличие пакета не доказывает успешность последнего обновления.")
    argv = ["ss", "-ltnp"]
    result = ctx.run(argv)
    ports = sorted(set(int(p) for p in re.findall(r"\S+:(\d+)\s", result.stdout)))
    ctx.add("NETWORK.LISTENERS", "OK" if result.ok and not result.truncated else "UNKNOWN", "Локальные TCP listeners: " + ", ".join(map(str, ports)),
            [command_evidence(argv, result, "ports=" + ",".join(map(str, ports)))],
            "Наличие listener не доказывает внешний доступ через firewall/провайдера.", ports=ports)


def _held_duplicity_conflicts(text):
    """Return confirmed and ambiguous held-package error line numbers.

    APT logs append independent transactions. A duplicity mention from an
    unrelated transaction must not be attached to an error elsewhere.
    """
    lines = text.splitlines()
    error_pattern = re.compile(r"\bHeld packages were changed\b", re.I)
    errors = [i for i, line in enumerate(lines) if error_pattern.search(line)]
    confirmed, ambiguous = [], []
    blocks, start = [], None
    for i, line in enumerate(lines):
        if line.startswith("Log started:"):
            start = i
        elif line.startswith("Log ended:") and start is not None:
            blocks.append((start, i))
            start = None
    for error_index in errors:
        block = next(((a, b) for a, b in blocks if a <= error_index <= b), None)
        floor = block[0] if block else max(0, error_index - 12)
        headers = []
        for i in range(floor, error_index):
            match = re.search(r"The following held packages will be changed:\s*(.*)$", lines[i], re.I)
            if match:
                headers.append((i, match[1]))
        if headers:
            header_index, inline = headers[-1]
            package_lines = [inline]
            for line in lines[header_index + 1:error_index]:
                if line and not line[0].isspace():
                    break
                if line.strip():
                    package_lines.append(line.strip())
            if re.search(r"\bduplicity\b", " ".join(package_lines)):
                confirmed.append(error_index + 1)
            # An explicit held-package list for a different package is not a
            # duplicity conflict even when duplicity appears elsewhere.
        elif block:
            if re.search(r"\bduplicity\b", "\n".join(lines[block[0]:block[1] + 1])):
                ambiguous.append(error_index + 1)
        elif re.search(r"\bduplicity\b", "\n".join(lines[max(0, error_index - 12):error_index + 2])):
            ambiguous.append(error_index + 1)
    return confirmed, ambiguous


def backup_checks(ctx):
    argv = ["apt-mark", "showhold"]
    holds = ctx.run(argv)
    duplicity_held = "duplicity" in holds.stdout.splitlines() if holds.ok else None
    version_cmd = ["dpkg-query", "-W", "-f=${Version}\n", "duplicity"]
    version = ctx.run(version_cmd)
    run_cmd = ["duplicity", "--version"]
    tool = ctx.run(run_cmd)
    ctx.add("BACKUP.TOOLING", "OK" if tool.ok and version.ok and not tool.truncated else "UNKNOWN",
            "Duplicity: {}{}".format(clean(version.stdout.strip() or "версия неизвестна"), "; hold сохранён" if duplicity_held else ""),
            [command_evidence(version_cmd, version), command_evidence(run_cmd, tool), command_evidence(argv, holds, "duplicity held=" + str(duplicity_held))],
            "Hold может быть осознанным; не меняйте пакет/hold автоматически и не выбирайте «хорошую» версию по памяти.",
            package_version=clean(version.stdout.strip()), held=duplicity_held,
            executable_version=clean(tool.stdout.strip()), backup_restore_tested=False)
    conflict = False
    uncertain_conflict = False
    for path in ("/var/log/apt/term.log", "/var/log/apt/term.log.1"):
        text, _ = ctx.read(path, 512 * 1024)
        confirmed, ambiguous = _held_duplicity_conflicts(text or "")
        if confirmed:
            conflict = True
            ctx.add("UPDATE.HELD_PACKAGE_CONFLICT", "WARN", "В APT-журнале найден конфликт удержанного duplicity",
                    [{"source": path, "line": line, "text": "held-package-change error associated with duplicity package-change list; historical evidence"} for line in confirmed[:10]],
                    "Сопоставьте время ошибки с последним update и его завершением. Это не доказывает поломку почты; hold не снимается.", historical=True, package="duplicity")
        elif ambiguous:
            uncertain_conflict = True
            ctx.add("UPDATE.HELD_PACKAGE_CONFLICT", "UNKNOWN", "В APT-журнале есть кандидат held-package ошибки; связь с duplicity не доказана",
                    [{"source": path, "line": line, "text": "ambiguous nearby/same transaction evidence"} for line in ambiguous[:10]],
                    "Найдите исходный package-change block и время update; совпадение слов в разных транзакциях не доказывает конфликт duplicity.", historical=True, candidate=True)
    if not conflict and not uncertain_conflict:
        ctx.add("UPDATE.HELD_PACKAGE_CONFLICT", "OK" if duplicity_held is False else "UNKNOWN",
                "Конфликт update с held duplicity не подтверждён доступным журналом",
                next_step="При незавершённом update проверьте сохранённый setup/APT output; отсутствие строки в текущем журнале не доказывает завершение.")
    storage = ctx.metadata.get("STORAGE_ROOT", "/home/user-data")
    if not storage.startswith("/") or ".." in Path(storage).parts or _SENSITIVE.search(storage):
        storage = "/home/user-data"
    backup = storage.rstrip("/") + "/backup"
    exists = ctx.path(backup).is_dir()
    ctx.add("BACKUP.LAST_SUCCESS", "UNKNOWN" if exists or ctx.miab else "N/A",
            "Последний успешный backup не подтверждён; " + ("локальный каталог существует" if exists else "локальный каталог не найден"),
            [{"source": backup, "text": "directory exists=" + str(exists) + "; directory mtime is not success evidence"}],
            "Проверьте журнал завершения backup и отдельную restore-проверку; Radar не запускает backup/restore/cloud listing.",
            directory_exists=exists, success_proven=False)


def route_checks(ctx):
    peer = getattr(ctx.args, "peer", None)
    if not peer:
        return
    try:
        peer = str(ipaddress.ip_address(peer))
    except ValueError:
        ctx.add("ROUTE.RUNTIME", "UNKNOWN", "--peer должен содержать один IP-адрес")
        return
    argv = ["ip", "route", "get", peer]
    result = ctx.run(argv)
    interface = re.search(r"\bdev\s+(\S+)", result.stdout)
    source = re.search(r"\bsrc\s+(\S+)", result.stdout)
    gateway = re.search(r"\bvia\s+(\S+)", result.stdout)
    ctx.add("ROUTE.RUNTIME", "OK" if result.ok and interface and not result.truncated else "UNKNOWN",
            "Маршрут OS к {}: {}".format(peer, clean(result.stdout) if result.ok else "не установлен"),
            [command_evidence(argv, result)],
            "OS route, policy routing и relayhost/transport_maps Postfix являются разными уровнями.",
            peer=peer, interface=interface[1] if interface else None, source=source[1] if source else None,
            gateway=gateway[1] if gateway else None)
    rules_cmd = ["ip", "rule", "show"]
    rules = ctx.run(rules_cmd)
    ctx.add("ROUTE.POLICY", "OK" if rules.ok and not rules.truncated else "UNKNOWN", "Policy routing: правила прочитаны" if rules.ok else "Policy routing: правила недоступны",
            [command_evidence(rules_cmd, rules)])
    candidates = []
    for directory, suffix in (("/etc/netplan", ".yaml"), ("/etc/systemd/network", ".network"), ("/etc/network/interfaces.d", "")):
        try:
            candidates += [directory + "/" + p.name for p in ctx.path(directory).iterdir() if p.is_file() and (not suffix or p.name.endswith(suffix))][:30]
        except OSError:
            pass
    if ctx.path("/etc/network/interfaces").is_file():
        candidates.append("/etc/network/interfaces")
    ctx.add("ROUTE.PERSISTENCE", "UNKNOWN", "Сохранение маршрута после reboot не доказано",
            [{"source": "persistent network configuration", "text": "candidate=" + clean(p)} for p in candidates[:30]],
            "Сопоставьте активный backend, interface и route с постоянной конфигурацией; комментарий или наличие IP в YAML не является доказательством.",
            candidates=candidates[:30], persistence_proven=False)


def post_update_checks(ctx):
    for parameter in ("protocols", "ssl"):
        argv = ["doveconf", "-h", parameter]
        result = ctx.run(argv)
        ctx.add("UPDATE.DOVECOT_" + parameter.upper(), "OK" if result.ok and result.stdout.strip() and not result.truncated else "UNKNOWN",
                "Dovecot {}: {}".format(parameter, clean(result.stdout.strip() or "не подтверждено")),
                [command_evidence(argv, result)], "Это проверка выбранного параметра, а не всей логики доставки.")
    nginx, error = ctx.read("/etc/nginx/nginx.conf")
    ctx.add("UPDATE.NGINX_CONFIG", "OK" if nginx is not None else "UNKNOWN", "Основной nginx.conf " + ("читается" if nginx is not None else "недоступен"),
            [{"source": "/etc/nginx/nginx.conf", "text": "readable" if nginx is not None else error}],
            "Состояние службы показано отдельно. Полная syntax/include проверка Nginx не выполняется: test mode может открывать log-файлы.", syntax_validated=False)
    if not ctx.miab:
        ctx.add("UPDATE.MANAGEMENT_ENDPOINT", "N/A", "MIAB management endpoint неприменим: MIAB metadata не обнаружены")
    elif not getattr(ctx.args, "network", False):
        ctx.add("UPDATE.MANAGEMENT_ENDPOINT", "UNKNOWN", "Доступность MIAB management endpoint не проверена без --network",
                next_step="Выберите --post-update --network для локальной HTTP-пробы без credentials.")
    else:
        argv = ["curl", "--silent", "--show-error", "--output", "/dev/null", "--write-out", "%{http_code}", "--connect-timeout", "2", "--max-time", "4", "http://127.0.0.1:10222/"]
        result = ctx.run(argv, timeout=5)
        code = result.stdout.strip()
        available = result.ok and re.fullmatch(r"[1-5]\d\d", code)
        ctx.add("UPDATE.MANAGEMENT_ENDPOINT", "OK" if available else "UNKNOWN", "MIAB loopback management: HTTP " + clean(code or "unknown"),
                [command_evidence(argv, result)], "HTTP-ответ доказывает доступность endpoint, а не корректность admin/status, backup и всех функций.", functions_validated=False)


def collect_checks(runner, args):
    ctx = Context(runner, args)
    platform_checks(ctx)
    mode = getattr(args, "mode", "doctor")
    if mode != "whitelist":
        service_checks(ctx)
        queue_checks(ctx)
        disk_checks(ctx)
    contexts = postfix_checks(ctx)
    dnsbl_filter_checks(ctx, contexts)
    whitelist_checks(ctx, contexts)
    dns_checks(ctx)
    tls_checks(ctx)
    if mode in {"doctor", "post-update"}:
        security_checks(ctx)
        backup_checks(ctx)
    route_checks(ctx)
    if mode == "post-update":
        post_update_checks(ctx)
    if ctx.budget_exhausted:
        ctx.add("HOST.BUDGET", "UNKNOWN", "Достигнут общий лимит host-диагностики 90 секунд; часть действий не выполнялась",
                next_step="Сузьте сценарий или повторите целевой раздел; неполный результат не является завершённой проверкой.", complete=False, budget_seconds=90)
    return ctx.findings
