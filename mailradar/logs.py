"""Bounded, literal, evidence-led Postfix/Postgrey/Dovecot log analysis.

No commands run here. Queue identities include host, syslog instance and lifecycle.
Message-ID is a search key, never a unique identity. Unknown grammars stay unknown.
"""
import bz2
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone as dt_timezone
import gzip
import io
import ipaddress
import lzma
import os
import re
import stat
from zoneinfo import ZoneInfo

UTC = dt_timezone.utc
MONTHS = {name: i + 1 for i, name in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}
# Fields are built from groups, not datetime.fromisoformat: before Python 3.11
# it rejects journald <= 252 offsets (+0300) and more than six fraction digits.
ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:?\d{2})?\s+(.*)$")
SYS = re.compile(r"^(?:(\d{4})\s+)?([A-Z][a-z]{2})\s+(\d{1,2})\s+(?:(\d{4})\s+)?(\d{2}:\d{2}:\d{2})(?:\s+(\d{4}))?\s+(.*)$")
# syslog_name may add service levels: MIAB logs submission as postfix/submission/smtpd.
PROGRAM = re.compile(r"^(?:(?P<host>\S+)\s+)?(?P<program>(?:postfix[^\s/]*(?:/[A-Za-z0-9_.-]+)*/[a-z_]+|postgrey|dovecot|spampd)(?:\[\d+\])?):\s*(?P<body>.*)$")
STANDALONE = re.compile(r"^(lmtp|lda)\(([^)]+)\)(?:<[^>]*>)*:\s*(?:Info:\s*)?(.*)$")
# Postfix mail_queue.h: short IDs are upper-case hex; long IDs use a vowel-free
# base-52 time (10 chars), 'z', then a base-51 inode without 'z'. Words such as
# "warning" or "NOQUEUE" are neither.
SHORT_QID = re.compile(r"[0-9A-F]{5,21}")
LONG_QID = re.compile(r"[0-9B-DF-HJ-NP-TV-Zb-df-hj-np-tv-z]{10,11}z[0-9B-DF-HJ-NP-TV-Zb-df-hj-np-tv-y]{1,12}")
ADDRESS = re.compile(r"^[^\s<>;,=\"\x00-\x1f\x7f-\x9f]{1,320}$")
QUOTED_LOCAL = re.compile(r'^"(?:[^"\\\x00-\x1f\x7f-\x9f]|\\[^\x00-\x1f\x7f-\x9f])*"(?:@[^\s<>;,="@\x00-\x1f\x7f-\x9f]+)?$')
DELIVERY_TAIL = re.compile(
    r"^, relay=([^,\s]+), "
    r"(?:conn_use=\d{1,12}, )?delay=([0-9]{1,12}(?:\.[0-9]{1,9})?), "
    r"delays=([0-9]{1,12}(?:\.[0-9]{1,9})?)/([0-9]{1,12}(?:\.[0-9]{1,9})?)/([0-9]{1,12}(?:\.[0-9]{1,9})?)/([0-9]{1,12}(?:\.[0-9]{1,9})?), "
    r"dsn=([245]\.\d+\.\d+), status=(sent|deferred|bounced)(?: \((.*)\))?$")
CLIENT = re.compile(r"client=([^\s\[\]]+)\[([^\]]+)\](?::\d+)?(?:, sasl_method=([^,\s]+), sasl_username=([^,\s]+))?(?:, sasl_sender=.*)?")
REJECT = re.compile(r"^NOQUEUE: (reject|reject_warning): (\S+) from ([^\s\[\]]+)\[([^\]]+)\](?::\d+)?: ([45]\d\d) (.*)$")
POLICY_ACTION = re.compile(r"^NOQUEUE: (filter|hold|discard): (\S+) from ([^\s\[\]]+)\[([^\]]+)\](?::\d+)?: (.*)$")
REJECT_END = re.compile(r"(?:proto=[A-Z]+(?: helo=<[^>]*>)?|helo=<[^>]*>)?")
NOTIFICATION = re.compile(r"(sender|postmaster) (non-delivery|delivery status|delay) notification: (\S+)")
DELAYS = ("arrival_to_last_active", "last_active_to_connection_setup",
          "connection_setup", "message_transmission")


def _clean(value, limit=2000):
    value = re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))", "", str(value))
    return "".join(c for c in value if ord(c) >= 32 and not 127 <= ord(c) <= 159
                   and c not in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")[:limit]


def _clean_tree(value):
    if isinstance(value, str):
        return _clean(value)
    if isinstance(value, dict):
        return {_clean(key): _clean_tree(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean_tree(item) for item in value]
    return value


def _rotation_gaps(paths):
    """Find observable holes only; contiguous names do not prove log coverage."""
    groups = defaultdict(set)
    supplied = {str(path) for path in paths}
    for path in supplied:
        match = re.fullmatch(r"(.+)\.([0-9]{1,8})(?:\.(?:gz|bz2|xz|lzma))?", path)
        if match:
            if len(match[2]) == 8:
                try:
                    datetime.strptime(match[2], "%Y%m%d")
                    continue  # date-based rotations do not have numeric sequence semantics
                except ValueError:
                    pass
            groups[match[1]].add(int(match[2]))
    gaps = []
    for base, indexes in sorted(groups.items()):
        if base in supplied:
            indexes.add(0)
        ordered = sorted(indexes)
        missing, total = [], 0
        for left, right in zip(ordered, ordered[1:]):
            if right - left > 1:
                total += right - left - 1
                missing.extend(range(left + 1, min(right, left + 1 + max(0, 20-len(missing)))))
        if total:
            gaps.append(dict(base=_clean(base), missing_indices=missing,
                             missing_count=total, enumeration_truncated=total > len(missing)))
    return gaps


def _finding(fid, status, title, evidence=None, next_step="", **details):
    return {"id": fid, "status": status, "title": title,
            "evidence": evidence or [], "next_step": next_step, "details": details}


def _local_time(naive, zone):
    """Refuse DST folds/gaps: selecting a fold silently changes incident order."""
    first = naive.replace(tzinfo=zone, fold=0)
    second = naive.replace(tzinfo=zone, fold=1)
    if first.utcoffset() != second.utcoffset():
        raise ValueError("ambiguous/nonexistent local time: use ISO offset")
    if first.astimezone(UTC).astimezone(zone).replace(tzinfo=None) != naive:
        raise ValueError("nonexistent local time: use ISO offset")
    return first.astimezone(UTC)


def _zone(name):
    if name in ("UTC", "GMT", "Z"):
        return UTC
    fixed = re.fullmatch(r"(?:UTC|GMT)([+-])(\d{2}):(\d{2})", name)
    if fixed:
        hours, minutes = int(fixed[2]), int(fixed[3])
        if hours > 23 or minutes > 59:
            raise ValueError("Invalid UTC offset")
        delta = timedelta(hours=hours, minutes=minutes)
        return dt_timezone(delta if fixed[1] == "+" else -delta)
    return ZoneInfo(name)


@contextmanager
def _open_regular(path):
    # Preflight prevents a named pipe/device from turning offline analysis into
    # an indefinitely blocked read. Nonblocking open plus fstat also covers a
    # regular-file-to-FIFO replacement between stat and open.
    info=os.stat(path)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Log source is not a regular file")
    if path.endswith((".gz",".bz2",".xz",".lzma")) and info.st_size>128*1024*1024:
        raise ValueError("Compressed source exceeds 128 MiB input limit")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Log source changed to a non-regular file")
        raw = os.fdopen(fd, "rb")
        fd = None
        with raw:
            if path.endswith(".gz"):
                with gzip.GzipFile(fileobj=raw, mode="rb") as stream:
                    yield stream
            elif path.endswith(".bz2"):
                with bz2.BZ2File(raw, "rb") as stream:
                    yield stream
            elif path.endswith((".xz", ".lzma")):
                with io.BufferedReader(_LimitedLZMA(raw)) as stream:
                    yield stream
            else:
                yield raw
    finally:
        if fd is not None:
            os.close(fd)


class _LimitedLZMA(io.RawIOBase):
    """Bound decoder dictionary memory as well as decompressed output bytes."""
    def __init__(self, source):
        super().__init__()
        self.source = source
        self.decoder = lzma.LZMADecompressor(memlimit=64*1024*1024)
        self.pending = b""
        self.finished = False
    def readable(self):
        return True
    def readinto(self, buffer):
        if self.finished:
            return 0
        while True:
            if self.decoder.eof:
                self.pending = self.decoder.unused_data or self.source.read(16384)
                # XZ permits zero stream padding between concatenated streams.
                while self.pending and not self.pending.strip(b"\0"):
                    self.pending = self.source.read(16384)
                self.pending = self.pending.lstrip(b"\0")
                if not self.pending:
                    self.finished=True
                    return 0
                self.decoder=lzma.LZMADecompressor(memlimit=64*1024*1024)
            data = self.pending or self.source.read(16384) if self.decoder.needs_input else b""
            self.pending=b""
            if not data and self.decoder.needs_input:
                raise EOFError("Compressed source ended before end-of-stream marker")
            result=self.decoder.decompress(data,max_length=len(buffer))
            if result:
                buffer[:len(result)]=result
                return len(result)


def _recent_lines(stream, byte_limit, line_limit):
    """Bounded suffix of a seekable plain file; omitted prefix is explicit."""
    end = stream.seek(0, 2)
    start = max(0, end-byte_limit)
    stream.seek(start)
    data = stream.read(byte_limit)
    omitted = start > 0
    if omitted:
        data = data.partition(b"\n")[2]  # do not parse a partial first line
    lines = data.splitlines(keepends=True)
    if len(lines)>line_limit:
        lines = lines[-line_limit:]
        omitted = True
    return list(zip(range(-1,-len(lines)-1,-1),reversed(lines))), omitted


def _timestamp(line, reference, zone, year):
    match = ISO.match(line)
    if match:
        value = datetime(*map(int, match.group(1, 2, 3, 4, 5, 6)), int((match[7] or "")[:6].ljust(6, "0")))
        offset = match[8]
        if offset is None:
            value = _local_time(value, zone)
        elif offset == "Z":
            value = value.replace(tzinfo=UTC)
        else:
            hours, minutes = int(offset[1:3]), int(offset[-2:])
            if hours > 23 or minutes > 59:
                raise ValueError("Invalid UTC offset")
            delta = timedelta(hours=hours, minutes=minutes)
            value = value.replace(tzinfo=dt_timezone(delta if offset[0] == "+" else -delta))
        return value.astimezone(UTC), match[9], False
    match = SYS.match(line)
    if not match or match[2] not in MONTHS:
        return None
    explicit_year = match[1] or match[4] or match[6]
    hh, mm, ss = map(int, match[5].split(":"))
    if explicit_year or year:
        naive = datetime(int(explicit_year) if explicit_year else year,
                         MONTHS[match[2]], int(match[3]), hh, mm, ss)
        return _local_time(naive, zone), match[7], False
    # These are past incident logs: select the newest calendar occurrence at or
    # before --until, including the previous year across New Year. Nearest-year
    # inference incorrectly moves old events into the future for long windows.
    local_reference = reference.astimezone(zone).replace(tzinfo=None)
    for candidate in range(local_reference.year, max(0, local_reference.year - 5), -1):
        try:
            naive = datetime(candidate, MONTHS[match[2]], int(match[3]), hh, mm, ss)
        except ValueError:
            continue  # e.g. February 29 in a non-leap reference year
        if naive <= local_reference:
            # A fold/gap in the selected calendar occurrence is genuinely
            # ambiguous; do not silently fall back to a different year's date.
            return _local_time(naive, zone), match[7], True
    raise ValueError("Cannot infer a valid historical calendar date")


def _address(value, empty=False):
    if value == "":
        return empty
    return len(value) <= 320 and bool(ADDRESS.fullmatch(value) or QUOTED_LOCAL.fullmatch(value))


def _queue_id(value):
    return bool(SHORT_QID.fullmatch(value) or LONG_QID.fullmatch(value))


def _take_address(text, prefix):
    """Read ``prefix<addr>`` at the start of text; return (address, rest) or None.

    Postfix quotes local parts with special characters, e.g.
    ``to=<"a>b, status=sent"@example.org>``; the closing quote is found first.
    Copied from mail-sec-audit ``logs/postfix.py``; the projects share no package.
    """
    if not text.startswith(prefix + "<"):
        return None
    i = len(prefix) + 1
    local_end = i
    if text[i:i + 1] == '"':
        j = i + 1
        while j < len(text):
            if text[j] == "\\":
                j += 2
                continue
            if text[j] == '"':
                break
            j += 1
        else:
            return None
        local_end = j + 1
    end = text.find(">", local_end)
    if end < 0:
        return None
    return text[i:end], text[end + 1:]


def _reject_fields(tail):
    """Parse ``[from=<A>][ to=<B>][ proto=P][ helo=<H>]`` up to the end of the line."""
    fields = {}
    for key in ("from", "to"):
        taken = _take_address(tail, key + "=")
        if taken is None:
            continue
        fields[key], tail = taken
        if tail.startswith(" "):
            tail = tail[1:]
        elif tail:
            return None
    return fields if REJECT_END.fullmatch(tail) else None


def _parse_reject(body):
    """NOQUEUE reject with the Postfix-generated head and a structured tail.

    RBL and policy texts contain ';', so the reason ends at the rightmost
    '; ' whose remainder parses completely as the fixed field tail.
    """
    head = REJECT.match(body)
    if not head or not _ip(head[4]):
        return None
    tail = _policy_tail(head[6])
    return (head, *tail) if tail else None


def _policy_tail(text):
    """Split the fixed smtpd log_whatsup tail from untrusted policy text."""
    position = len(text)
    for _ in range(64):
        position = text.rfind("; ", 0, position)
        if position < 0:
            return None
        tail = text[position + 2:]
        if tail.startswith(("from=<", "to=<", "proto=")):
            fields = _reject_fields(tail)
            if fields is not None and _address(fields.get("from", ""), True) and (
                    "to" not in fields or _address(fields["to"])):
                return text[:position], fields
    return None  # adversarial separator count: leave this line explicitly unparsed


def _parse_delivery(payload):
    """``to=<A>[, orig_to=<B>]`` read quote-aware, then the fixed delivery fields."""
    taken = _take_address(payload, "to=")
    if not taken or not _address(taken[0]):
        return None
    recipient, rest = taken
    orig_to = None
    if rest.startswith(", orig_to="):
        original = _take_address(rest[2:], "orig_to=")
        if not original or not _address(original[0], True):
            return None
        orig_to, rest = original
    tail = DELIVERY_TAIL.fullmatch(rest)
    return (recipient, orig_to, tail) if tail else None


def _ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _parse_dovecot(body, event):
    m = STANDALONE.match(body)
    if not m:
        return
    rest = m[3]
    if "saved mail to" in rest.casefold() or "stored mail into mailbox" in rest.casefold():
        event["_unparsed"] = True
    # Current-folder claims require doveadm. A Saved log proves the event only.
    saved = re.fullmatch(r"(?:sieve: )?(?:msgid=)?(<[^<>\s]{1,500}>):\s*(?:(?:saved mail to|saved mail to mailbox) (.{1,200})|stored mail into mailbox '([^'\r\n]{1,200})')", rest, re.I)
    if saved and _address(m[2]):
        event.update(kind="saved", recipient=m[2], message_id=saved[1], mailbox=saved[2] or saved[3])
        event.pop("_unparsed", None)


def _parse_event(timestamp, rest, source, line_no, text):
    event = {"time": timestamp.isoformat(), "_time": timestamp,
             "source": source, "line": line_no, "text": _clean(text),
             "kind": "other", "host": "unknown", "instance": "unknown"}
    direct = STANDALONE.match(rest)
    if direct:
        event.update(program="dovecot", component=direct[1])
        _parse_dovecot(rest, event)
        return event
    m = PROGRAM.match(rest)
    if not m:
        event["program"] = "unrecognized"
        return event
    program = re.sub(r"\[\d+\]$", "", m["program"])
    body = m["body"]
    event.update(host=m["host"] or "unknown", program=program)
    if program == "dovecot":
        _parse_dovecot(body, event)
        return event
    if program == "postgrey":
        event["_unparsed"] = body.startswith("action=")
        # Fields are comma-delimited by Postgrey; reject duplicate/forged keys.
        fields = {}
        for part in body.split(", "):
            item = part.split("=", 1)
            if len(item) != 2 or item[0] in fields or not re.fullmatch(r"[a-z_]+", item[0]):
                return event
            fields[item[0]] = item[1]
        if fields.get("action") not in ("greylist", "pass", "reject"):
            return event
        sender, recipient = fields.get("sender", ""), fields.get("recipient", "")
        sender, recipient = sender.strip("<>"), recipient.strip("<>")
        address = _ip(fields.get("client_address", ""))
        if not address or not _address(sender, True) or not _address(recipient):
            return event
        event.update(kind="greylist", action=fields["action"], reason=_clean(fields.get("reason", "unknown")),
                     sender=sender, recipient=recipient, client_ip=address,
                     client_name=fields.get("client_name", "unknown"))
        event.pop("_unparsed", None)
        return event
    if not program.startswith("postfix"):
        return event
    # The first syslog_name level is the Postfix instance; middle levels name the
    # master.cf service, so one message keeps one trace across them.
    parts = program.split("/")
    instance, component = parts[0], parts[-1]
    event.update(instance=instance, component=component)
    if len(parts) > 2:
        event["service"] = "/".join(parts[1:-1])
    connection = re.fullmatch(r"(connect|disconnect) from ([^\s\[\]]+)\[([^\]]+)\](?: .*)?", body)
    if connection and _ip(connection[3]):
        event.update(kind=connection[1], client_name=connection[2], client_ip=_ip(connection[3]))
        return event
    if component in ("smtpd", "submission", "smtps"):
        auth = re.match(r"^warning: [^\s\[\]]+\[([^\]]+)\]: SASL \S+ authentication failed(?::|\s|$)", body)
        if auth and _ip(auth[1]):
            event.update(kind="auth_failure", client_ip=_ip(auth[1]))
            return event
    if body.startswith("NOQUEUE: "):
        event["_unparsed"] = True
        rejection = _parse_reject(body)
        if rejection:
            head, reason, fields = rejection
            event.update(kind="rejected" if head[1] == "reject" else "reject_warning", stage=head[2],
                         client_name=head[3], client_ip=_ip(head[4]), smtp_code=int(head[5]),
                         reason=_clean(reason))
            # CONNECT/HELO-stage rejects carry no envelope; absent fields stay absent.
            event.update({name: fields[key] for name, key in (("sender", "from"), ("recipient", "to")) if key in fields})
            event.pop("_unparsed", None)
        else:
            head = POLICY_ACTION.fullmatch(body)
            tail = _policy_tail(head[5]) if head and _ip(head[4]) else None
            if tail:
                reason, fields = tail
                event.update(kind="policy_action", action=head[1], stage=head[2],
                             client_name=head[3], client_ip=_ip(head[4]), reason=_clean(reason))
                event.update({name: fields[key] for name, key in (("sender", "from"), ("recipient", "to")) if key in fields})
                event.pop("_unparsed", None)
        return event
    qid, separator, payload = body.partition(": ")
    if not separator or not _queue_id(qid):
        severity = re.match(r"^(warning|error|fatal|panic):", body)
        # Warnings are routine (DNS, TLS, client noise); faults are reported.
        operational_warning = bool(re.match(r"^warning: (?:connect to |problem talking to |(?:hash|btree|lmdb):/.*(?:unavailable|older than)|.*Milter service.*(?:refused|timed out))",body,re.I))
        if severity and (severity[1] != "warning" or operational_warning):
            event.update(kind="daemon_error", reason=_clean(body))
        elif severity:
            event["severity"] = "warning"
        return event
    event["queue_id"] = qid
    event["_unparsed"] = True
    remote_reply = re.fullmatch(r"host ([^\s\[\]]+)\[([^\]]+)\](?::\d+)?:? said: ([245]\d\d)(?:[ -]([245]\.\d{1,3}\.\d{1,3}))? .+", payload)
    if component in ("smtp", "lmtp") and remote_reply and _ip(remote_reply[2]):
        # A standalone reply does not identify a recipient or prove delivery.
        event.update(kind="remote_reply", smtp_code=int(remote_reply[3]), remote_host=remote_reply[1], remote_ip=_ip(remote_reply[2]))
        if remote_reply[4]:
            event["dsn"] = remote_reply[4]
    if component == "cleanup":
        mid = re.fullmatch(r"message-id=(<[^<>\s]{0,500}>)", payload)
        if mid:
            event.update(kind="message_id", message_id=mid[1])
    elif component == "qmgr":
        taken = _take_address(payload, "from=")
        accepted = re.fullmatch(r", size=(\d{1,20}), nrcpt=(\d{1,9}) \((queue active|queue held)\)", taken[1]) if taken else None
        if accepted and _address(taken[0], True):
            event.update(kind="accepted", sender=taken[0], size=int(accepted[1]),
                         recipient_count=int(accepted[2]), queue_state=accepted[3])
        elif payload == "removed":
            event["kind"] = "removed"
        elif re.fullmatch(r", (?:status=)?expired(?:, returned to sender)?", taken[1] if taken else ", " + payload):
            event["kind"] = "expired"
    elif component == "smtpd":
        client = CLIENT.fullmatch(payload)
        if client and _ip(client[2]):
            event.update(kind="client", client_name=client[1], client_ip=_ip(client[2]))
            if client[4]:
                event["authenticated_user"] = client[4]
    elif component == "pickup":
        uid = re.match(r"uid=(\d{1,20}) ", payload)
        taken = _take_address(payload[uid.end():], "from=") if uid else None
        if taken and _address(taken[0], True) and re.fullmatch(r"(?: orig_id=\S+)?", taken[1]):
            event.update(kind="pickup", sender=taken[0], uid=int(uid[1]))
    elif component in ("bounce", "defer", "trace"):
        notice = NOTIFICATION.fullmatch(payload)
        if notice and _queue_id(notice[3]):
            event.update(kind="notification", notification=notice[1] + " " + notice[2], notification_queue_id=notice[3])
    if component in ("smtp", "lmtp") and re.fullmatch(r"(?:lost connection with|conversation with) [^\s\[\]]+\[[^\]]+\](?::\d+)? (?:timed out )?while .*", payload):
        event.update(kind="session_problem", reason=_clean(payload))
    if component in ("smtp", "lmtp", "local", "virtual", "pipe", "error", "retry", "discard"):
        delivery = _parse_delivery(payload)
        if delivery:
            recipient, orig_to, delivery = delivery
            event.update(kind="delivery", recipient=recipient, orig_to=orig_to,
                         relay=delivery[1], delay=float(delivery[2]),
                         delays=dict(zip(DELAYS, map(float, delivery.group(3, 4, 5, 6)))),
                         dsn=delivery[7], status=delivery[8], reason=_clean(delivery[9] or ""))
            if delivery[8] == "sent":
                if component == "smtp":
                    relay_address = re.search(r"\[([^\]]+)\]", delivery[1])
                    internal = bool(relay_address and _ip(relay_address[1]) and ipaddress.ip_address(relay_address[1]).is_loopback)
                    event["outcome"] = "internal_smtp_accepted" if internal else "next_smtp_accepted"
                else:
                    event["outcome"] = "local_transport_accepted"
                    if component == "lmtp" and re.fullmatch(r"250 2\.0\.0 (?:<[^<>\s]+> )?(?:[A-Za-z0-9+/=_:-]{16,128} )?Saved",delivery[9] or "",re.I) or component in ("local","virtual") and re.fullmatch(r"delivered to (?:maildir|mailbox)",delivery[9] or "",re.I):
                        event["outcome"] = "saved"
                    if component == "discard":
                        event["outcome"] = "discarded"
                # Only the structured successful SMTP reply supplies a reinjection edge.
                reinject = re.fullmatch(r"2\d\d(?: [245]\.\d+\.\d+)? .*\bqueued as ([A-Za-z0-9]{5,100})\)?", delivery[9] or "", re.I)
                if reinject and event["outcome"] == "internal_smtp_accepted":
                    event["queued_as"] = reinject[1]
            else:
                event["outcome"] = delivery[8]
    if component == "cleanup" and payload.startswith("hold: "):
        event["kind"] = "hold"
        event["text"] = "%s: hold: [header content omitted]" % qid
    if component == "cleanup" and payload.startswith("warning: header "):
        event["kind"] = "header_warning"
        event["text"] = "%s: warning: header [header content omitted]" % qid
    if event["kind"] == "other":
        # Do not turn arbitrary diagnostic/header text into a phantom queue.
        event.pop("queue_id", None)
    else:
        event.pop("_unparsed", None)
    return event


def _event_public(event):
    return _clean_tree({k: v for k, v in event.items() if not k.startswith("_")})


def _literal_match(values, requested, case_sensitive=False):
    if case_sensitive:
        return any(str(v) == str(requested) for v in values if v is not None)
    return any(str(v).casefold() == str(requested).casefold() for v in values if v is not None)


def _matches(events, filters):
    if not filters:
        return True
    fields = {key: [e.get(key) for e in events] for key in
              ("sender", "recipient", "orig_to", "client_ip", "message_id", "queue_id", "client_name")}
    for name, field in (("from", "sender"), ("to", "recipient"), ("ip", "client_ip"), ("client_name", "client_name"), ("message_id", "message_id")):
        requested = filters.get(name)
        values = fields[field] + (fields["orig_to"] if name == "to" else [])
        if requested and not _literal_match(values, requested, case_sensitive=name == "message_id"):
            return False
    domain = filters.get("domain")
    if domain:
        domains = [str(v).rsplit("@", 1)[-1].casefold() for v in fields["sender"] + fields["recipient"] if v and "@" in str(v)]
        if domain.casefold() not in domains:
            return False
    trace = filters.get("trace")
    if trace:
        if trace.startswith("<") and trace.endswith(">"):
            if not _literal_match(fields["message_id"], trace, case_sensitive=True):
                return False
        elif "@" in trace:
            if not _literal_match(fields["sender"] + fields["recipient"] + fields["orig_to"], trace):
                return False
        elif _ip(trace):
            if not _literal_match(fields["client_ip"], str(ipaddress.ip_address(trace))):
                return False
        elif re.fullmatch(r"[A-Za-z0-9]{5,100}", trace):
            if not _literal_match(fields["queue_id"], trace, case_sensitive=True):
                return False
        else:
            domains = [str(v).rsplit("@", 1)[-1].casefold() for v in fields["sender"] + fields["recipient"] if v and "@" in str(v)]
            if trace.casefold().rstrip(".") not in domains and not _literal_match(fields["client_name"], trace):
                return False
    return True


def _queue_traces(events, since, until, filters):
    current, generations, queues = {}, Counter(), []
    for event in events:
        if not event.get("queue_id"):
            continue
        key = (event["host"], event["instance"], event["queue_id"])
        trace = current.get(key)
        # A new cleanup message-id after a closed queue always starts a lifecycle.
        changed_mid = bool(trace and event["kind"] == "message_id" and trace["message_ids"] and event["message_id"] not in trace["message_ids"])
        terminal = trace["_closed"] if trace else False
        # Expiry still has a notification/removal tail in the same lifecycle.
        # Repeated removal/notification records after removal are not new mail.
        # Any other event after expiry/removal starts a separate lifecycle:
        # retained logs may contain a reused ID's delivery but omit its ingress.
        # That later delivery must not revive the already expired message.
        restarted = terminal in ("removed", "expired") and event["kind"] not in ("removed", "notification")
        if trace is None or restarted or changed_mid:
            generations[key] += 1
            trace = {"id": "%s/%s/%s#%d" % (*key, generations[key]),
                     "host": key[0], "instance": key[1], "queue_id": key[2],
                     "generation": generations[key], "message_ids": [], "senders": [],
                     "recipients": [], "events": [], "links": [], "_closed": False}
            queues.append(trace)
            current[key] = trace
        trace["events"].append(event)
        for field, target in (("message_id", "message_ids"), ("sender", "senders"), ("recipient", "recipients")):
            if field in event and event[field] not in trace[target]:
                trace[target].append(event[field])
        if event["kind"] in ("removed", "expired"):
            trace["_closed"] = event["kind"]
    # Explicit localhost reinjection connects lifecycles; never join by Message-ID.
    by_destination = defaultdict(list)
    for trace in queues:
        by_destination[(trace["host"], trace["queue_id"])].append(trace)
    for trace in queues:
        for event in trace["events"]:
            if not event.get("queued_as"):
                continue
            targets = [candidate for candidate in by_destination[(trace["host"], event["queued_as"])]
                       if candidate is not trace
                       and abs((candidate["events"][0]["_time"] - event["_time"]).total_seconds()) <= 300]
            if len(targets) == 1:
                trace["links"].append({"type": "reinjection", "target": targets[0]["id"]})
                targets[0]["links"].append({"type": "reinjected_from", "target": trace["id"]})
    by_id = {q["id"]: q for q in queues}
    selected = []
    component_matches = {}
    for trace in queues:
        if trace["id"] not in component_matches:
            connected, todo = {trace["id"]}, [trace]
            while todo:
                for link in todo.pop()["links"]:
                    if link["target"] not in connected:
                        connected.add(link["target"])
                        todo.append(by_id[link["target"]])
            context = [e for qid in sorted(connected) for e in by_id[qid]["events"]]
            matched = _matches(context, filters)
            for qid in connected:
                component_matches[qid] = matched
        visible = [e for e in trace["events"] if since <= e["_time"] <= until]
        if not visible or not component_matches[trace["id"]]:
            continue
        # Keep pre-window context but explicitly mark it.
        trace["events"] = [_event_public(dict(e, in_window=since <= e["_time"] <= until)) for e in trace["events"]]
        trace.pop("_closed", None)
        trace["outcomes"] = sorted({e.get("outcome", e["kind"]) for e in visible if e["kind"] in ("delivery", "expired", "accepted", "hold")})
        final_recipients = {}
        queue_terminal_state = None
        for event in visible:
            if event["kind"] == "delivery":
                final_recipients[event["recipient"]] = event["outcome"]
            elif event["kind"] in ("expired", "hold"):
                queue_terminal_state = event["kind"]
                for recipient, outcome in list(final_recipients.items()):
                    if outcome in ("deferred", "hold", "expired"):
                        final_recipients[recipient] = event["kind"]
        trace["recipient_outcomes"] = final_recipients
        trace["queue_terminal_state"] = queue_terminal_state
        final_outcomes = set(final_recipients.values())
        expected_recipients = max((e.get("recipient_count", 0) for e in visible), default=0)
        if queue_terminal_state and expected_recipients > len(final_recipients):
            final_outcomes.add(queue_terminal_state)
        if len(final_outcomes) > 1:
            trace["outcome"] = "mixed"
        elif final_outcomes:
            trace["outcome"] = next(iter(final_outcomes))
        else:
            terminal = [e["kind"] for e in visible if e["kind"] in ("expired", "accepted", "hold")]
            trace["outcome"] = terminal[-1] if terminal else "unknown"
        selected.append(trace)
    return selected


def _greylist_findings(events, since, until):
    groups = defaultdict(list)
    for event in events:
        if event["kind"] == "greylist" and event["_time"] <= until:
            groups[(event["client_ip"], event["sender"], event["recipient"])].append(event)
    findings = []
    for triplet, sequence in sorted(groups.items()):
        if not any(since <= e["_time"] <= until for e in sequence):
            continue
        passes = [e for e in sequence if e["action"] == "pass"]
        rejects = []
        for event in sequence:
            if event["action"] in ("greylist", "reject"):
                rejects.append(event)
            elif event["action"] == "pass" and rejects:
                episode = rejects + [event]
                if any(since <= e["_time"] <= until for e in episode):
                    wait = (event["_time"] - rejects[0]["_time"]).total_seconds()
                    evidence = [_event_public(dict(e, in_window=since <= e["_time"] <= until)) for e in episode]
                    findings.append(_finding("GREYLIST-RETRY-PASS", "OK", "Greylist: повторная попытка прошла", evidence,
                                             "SMTP pass не доказывает сохранение письма.", triplet=list(triplet),
                                             observed_wait_seconds=wait, rejected_attempts=len(rejects)))
                rejects = []
        if rejects and any(e["_time"] >= since for e in rejects):
            evidence = [_event_public(dict(e, in_window=since <= e["_time"] <= until)) for e in rejects]
            findings.append(_finding("GREYLIST-OUTCOME", "UNKNOWN", "Greylist: исход после отказа не виден", evidence,
                                     "Расширьте период и проверьте повторную попытку; смена IP создаёт другой triplet.", triplet=list(triplet)))
        for reason, fid, title in (("client AWL", "GREYLIST-AWL", "Postgrey: автоматический client AWL"),
                                  ("client whitelist", "GREYLIST-CLIENT-WHITELIST", "Postgrey: явный client whitelist")):
            matching = [p for p in passes if p["reason"].casefold() == reason.casefold() and p["_time"] >= since]
            if matching:
                findings.append(_finding(fid, "OK", title, [_event_public(e) for e in matching],
                                         "Причина pass относится к SMTP-клиенту, а не к домену From.", triplet=list(triplet)))
    return findings


def analyze_logs(paths, since, until, timezone="UTC", year=None, filters=None,
                 max_bytes=32 * 1024 * 1024, max_lines=150000, recent=False):
    """Analyze supplied sources without assuming their coverage is complete.

    Limits apply globally to decompressed bytes and lines, before time filtering.
    Exact overlap is deduplicated using maximum occurrence count per source; real
    identical repetitions in one source remain separate events.
    Known-time event grammar failures outside the report window are counted as
    unparsed_context, without discarding usable pre-window queue context. Read
    losses and lines whose time cannot be determined remain report-wide gaps.
    """
    if since.tzinfo is None or until.tzinfo is None or since > until:
        raise ValueError("since/until must be ordered timezone-aware datetimes")
    if max_bytes <= 0 or max_lines <= 0:
        raise ValueError("limits must be positive")
    zone = _zone(timezone)
    since, until = since.astimezone(UTC), until.astimezone(UTC)
    filters = filters or {}
    events, sources, issues = [], [], []
    bytes_read, lines_read, inferred, overlap = 0, 0, 0, 0
    occurrences = Counter()
    for path in paths:
        path = str(path)
        source = {"path": _clean(path), "readable": False, "bytes": 0, "lines": 0,
                  "unparsed_lines": 0, "unparsed_context": 0, "ignored_lines": 0,
                  "truncated": False, "errors": [], "first_time": None, "last_time": None}
        sources.append(source)
        local_counts = Counter()
        try:
            with _open_regular(path) as stream:
                source["readable"] = True
                reverse = recent and not path.endswith((".gz",".bz2",".xz",".lzma"))
                suffix, omitted = _recent_lines(stream,max(0,max_bytes-bytes_read),max(0,max_lines-lines_read)) if reverse and bytes_read<max_bytes and lines_read<max_lines else ([],False)
                if reverse:
                    source["read_direction"] = "from_end"
                    source["line_numbering"] = "negative_from_end"
                    if omitted:
                        source["truncated"] = source["prefix_omitted"] = True
                        source["errors"].append("Ограничен старый префикс файла; контекст до просмотренной части не подтверждён.")
                    iterator = iter(suffix)
                while True:
                    remaining = max_bytes - bytes_read
                    if remaining <= 0 or lines_read >= max_lines:
                        # A single-byte probe distinguishes exactly-at-limit EOF.
                        if stream.read(1):
                            source["truncated"] = True
                        break
                    if reverse:
                        item = next(iterator,None)
                        if item is None:
                            break
                        line_no, raw = item
                    else:
                        raw = stream.readline(min(remaining + 1, 65537))
                        line_no = source["lines"]+1
                    if not raw:
                        break
                    source["bytes"] += min(len(raw), remaining)
                    bytes_read += min(len(raw), remaining)
                    source["lines"] += 1
                    lines_read += 1
                    if len(raw) > remaining or len(raw) > 65536 or not raw.endswith(b"\n") and len(raw) == 65537:
                        source["truncated"] = True
                        break
                    text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    if "\ufffd" in text:
                        if len(source["errors"]) < 5:
                            source["errors"].append("Invalid UTF-8 replaced; affected fields may be unavailable.")
                    if not text:
                        continue
                    try:
                        parsed = _timestamp(text, until, zone, year)
                    except (ValueError, OverflowError) as exc:
                        source["unparsed_lines"] += 1
                        if len(source["errors"]) < 5:
                            source["errors"].append(_clean(exc))
                        continue
                    if parsed is None:
                        source["unparsed_lines"] += 1
                        continue
                    stamp, rest, was_inferred = parsed
                    inferred += int(was_inferred)
                    normalized = stamp.isoformat()
                    source["first_time"] = min(source["first_time"] or normalized, normalized)
                    source["last_time"] = max(source["last_time"] or normalized, normalized)
                    # Canonical timestamp + exact remaining bytes, not Message-ID.
                    fingerprint = (normalized, rest)
                    local_counts[fingerprint] += 1
                    if local_counts[fingerprint] <= occurrences[fingerprint]:
                        overlap += 1
                        continue
                    event = _parse_event(stamp, rest, source["path"], line_no, text)
                    if event["kind"] == "other":
                        source["ignored_lines"] += 1
                    if event.get("_unparsed"):
                        if since <= stamp <= until:
                            source["unparsed_lines"] += 1
                        else:
                            source["unparsed_context"] += 1
                    events.append(event)
        except (OSError, EOFError, lzma.LZMAError, ValueError) as exc:
            source["errors"].append(_clean(exc))
        occurrences |= local_counts
        if source["truncated"] or source["errors"] or source["unparsed_lines"] or not source["readable"]:
            issues.append(source["path"])
    events.sort(key=lambda e: (e["_time"], e["source"], e["line"]))
    # Keep raw events separate because traces replace private datetime values.
    traces = _queue_traces(events, since, until, filters)
    selected_ids = {(trace["host"], trace["instance"], trace["queue_id"], e["source"], e["line"])
                    for trace in traces for e in trace["events"]}
    visible = [e for e in events if since <= e["_time"] <= until and
               ((e.get("queue_id") and (e["host"], e["instance"], e["queue_id"], e["source"], e["line"]) in selected_ids)
                or (not e.get("queue_id") and _matches([e], filters)))]
    meaningful = [e for e in visible if e["kind"] != "other"]
    deliveries = [e for e in visible if e["kind"] == "delivery"]
    kinds = Counter(e["kind"] for e in visible)
    statuses = Counter(e["status"] for e in deliveries)
    outcomes = Counter(e["outcome"] for e in deliveries)
    auth_senders = Counter(e["authenticated_user"] for e in visible if e.get("authenticated_user"))
    sender_addresses = Counter(e["sender"] for e in visible if e.get("sender"))
    recipient_addresses = Counter(e["recipient"] for e in visible if e.get("recipient"))
    recipient_domains = Counter(e["recipient"].rsplit("@", 1)[-1].casefold() for e in deliveries if e["status"] == "sent" and "@" in e["recipient"])
    reasons = {status: dict(Counter(e["reason"] for e in deliveries if e["status"] == status).most_common(10)) for status in ("bounced", "deferred")}
    # Connected explicit reinjections form one inferred message group; isolated
    # repeated Message-IDs remain distinct. Missing hop evidence can overcount
    # groups, so this is not a globally unique-message inventory.
    components = []
    seen_ids = set()
    trace_by_id = {trace["id"]: trace for trace in traces}
    for trace in traces:
        if trace["id"] in seen_ids:
            continue
        component, todo = set(), [trace["id"]]
        while todo:
            ident = todo.pop()
            if ident in component:
                continue
            component.add(ident)
            seen_ids.add(ident)
            todo.extend(link["target"] for link in trace_by_id[ident]["links"] if link["target"] in trace_by_id)
        components.append(component)
    statistics = {"events": len(visible), "recognized_events": len(meaningful),
                  "queues": len(traces), "observed_messages": len(components),
                  "delivery_attempts": len(deliveries), "recipient_delivery_events": statuses.get("sent", 0),
                  "accepted_queue_events": kinds.get("accepted", 0), "rejected_before_queue": kinds.get("rejected", 0),
                  "auth_failures": kinds.get("auth_failure", 0), "saved_log_events": kinds.get("saved", 0),
                  "expired": kinds.get("expired", 0), "hold": kinds.get("hold", 0), "bounced": statuses.get("bounced", 0),
                  "deferred": statuses.get("deferred", 0), "outcomes": dict(outcomes),
                  "top_authenticated_senders": dict(auth_senders.most_common(10)),
                  "observed_sender_addresses": dict(sender_addresses.most_common(20)),
                  "observed_recipient_addresses": dict(recipient_addresses.most_common(20)),
                  "sender_address_count": len(sender_addresses), "recipient_address_count": len(recipient_addresses),
                  "address_group_basis": "structured_events_in_window",
                  "top_recipient_domains": dict(recipient_domains.most_common(10)),
                  "delivery_reasons": reasons,
                  "top_rejection_reasons": dict(Counter(e["reason"] for e in visible if e["kind"] == "rejected").most_common(10)),
                  "top_auth_failure_ips": dict(Counter(e["client_ip"] for e in visible if e["kind"] == "auth_failure").most_common(10)),
                  "reject_warnings": kinds.get("reject_warning", 0),
                  "prequeue_policy_actions": dict(Counter(e["action"] for e in visible if e["kind"] == "policy_action")),
                  "daemon_warnings": sum(1 for e in visible if e.get("severity") == "warning"),
                  "overlap_events_removed": overlap, "year_inferred_lines": inferred}
    evidence = [_event_public(e) for e in meaningful[:500]]
    findings = []
    rotation_gaps = _rotation_gaps(paths)
    if rotation_gaps:
        findings.append(_finding("LOG-ROTATION-GAP", "UNKNOWN", "В наборе ротаций обнаружены пропущенные номера", rotation_gaps,
                                 "Добавьте недостающие архивы, если они сохранены; нумерация сама по себе не доказывает полноту периода."))
    if not meaningful:
        findings.append(_finding("LOG-NO-EVIDENCE", "UNKNOWN", "В выбранном окне нет подходящих событий", [],
                                 "Проверьте период, часовой пояс, доступ к архивам и известные адреса."))
    if issues or not paths:
        findings.append(_finding("LOG-SOURCE-INCOMPLETE", "UNKNOWN", "Анализ источников неполон", [{"source":s["path"],"text":"прочитано строк %d; не разобрано %d; лимит %s; %s" % (s["lines"],s["unparsed_lines"],s["truncated"],"; ".join(s["errors"]))} for s in sources if s["path"] in issues][:10],
                                 "Смотрите конкретный источник и причину; для усечения увеличьте --max-lines/--max-bytes или сузьте период.", sources=issues))
    findings.append(_finding("LOG-COVERAGE", "N/A", "Отчёт описывает просмотренные источники; внешний путь и потерянные логи неизвестны", [],
                             "При отсутствии события запросите более ранние архивы или trace соседнего SMTP-узла.",
                             supplied_sources=len(sources), year_inferred_lines=inferred))
    if meaningful:
        findings.append(_finding("MAIL-FLOW", "WARN" if statuses.get("deferred") or statuses.get("bounced") else "OK",
                                 "Наблюдаемый путь почты разобран", evidence[:20],
                                 "Удалённый SMTP 250 не доказывает внешний INBOX; Saved не доказывает текущую папку.", **statistics))
    for status, fid, title in (("deferred", "MAIL-DEFERRED", "Есть временно отложенные попытки"),
                               ("bounced", "MAIL-BOUNCED", "Есть постоянные отказы доставки")):
        matching = [e for e in deliveries if e["status"] == status]
        if matching:
            findings.append(_finding(fid, "WARN", title, [_event_public(e) for e in matching[:10]],
                                     "Разберите точный SMTP/DSN response, transport и relay; повторная попытка может иметь иной исход.", count=len(matching)))
    if kinds.get("rejected"):
        findings.append(_finding("MAIL-PREQUEUE-REJECT", "WARN" if filters else "OK", "Есть отказы до приёма в очередь" if filters else "Отказы до очереди учтены; блокировка relay/спама сама по себе не сбой",
                                 [_event_public(e) for e in visible if e["kind"] == "rejected"][:10],
                                 "Сверьте стадию отказа и restriction chain: Queue ID ещё мог не появиться."))
    if kinds.get("policy_action"):
        findings.append(_finding("MAIL-PREQUEUE-POLICY", "OK", "Postfix запросил FILTER/HOLD/DISCARD до очереди",
                                 [_event_public(e) for e in visible if e["kind"] == "policy_action"][:10],
                                 "Это запрос действия SMTP-политики. Фактический hold/discard, принятие и доставку подтверждайте последующими событиями."))
    if kinds.get("header_warning"):
        findings.append(_finding("MAIL-HEADER-WARNING", "WARN", "Сработало предупреждение cleanup о заголовке",
                                 [_event_public(e) for e in visible if e["kind"] == "header_warning"][:10],
                                 "Содержимое заголовка исключено из отчёта; предупреждение не доказывает отказ доставки."))
    if kinds.get("auth_failure"):
        findings.append(_finding("MAIL-AUTH-FAILURE", "FAIL" if kinds["auth_failure"] > 100 else "WARN",
                                 "Видны неудачные SMTP-аутентификации",
                                 [_event_public(e) for e in visible if e["kind"] == "auth_failure"][:10],
                                 "Проверьте клиента и применимые Fail2ban jails.", count=kinds["auth_failure"]))
    if kinds.get("daemon_error"):
        findings.append(_finding("MAIL-DAEMON-ERROR", "WARN", "Видны ошибки почтовой службы",
                                 [_event_public(e) for e in visible if e["kind"] == "daemon_error"][:10],
                                 "Сопоставьте ошибку со службой и периодом инцидента."))
    if kinds.get("saved"):
        findings.append(_finding("MAIL-SAVED-EVENT", "OK", "Лог Dovecot подтверждает сохранение письма",
                                 [_event_public(e) for e in visible if e["kind"] == "saved"][:10],
                                 "Текущую папку и date.saved проверьте ограниченным Dovecot-поиском: письмо могло быть перемещено."))
    if kinds.get("expired") or kinds.get("hold"):
        findings.append(_finding("MAIL-QUEUE-LIFECYCLE", "WARN", "Видны expiry/hold события очереди",
                                 [_event_public(e) for e in visible if e["kind"] in ("expired", "hold")][:10],
                                 "Сопоставьте Queue ID и получателей с текущим снимком очереди."))
    findings.extend(_greylist_findings([e for e in events if e["kind"] == "greylist" and _matches([e], filters)], since, until))
    complete = bool(paths) and not issues and not rotation_gaps
    completeness = {"complete": complete, "window_coverage_proven": False,
                    "bytes_read": bytes_read, "lines_read": lines_read,
                    "unparsed_lines": sum(s["unparsed_lines"] for s in sources),
                    "unparsed_context": sum(s["unparsed_context"] for s in sources),
                    "rotation_gaps": rotation_gaps,
                    "truncated": any(s["truncated"] for s in sources),
                    "limitations": ["No supplied log set proves absence of earlier attempts or external delivery.",
                                    "Yearless timestamps use the newest calendar occurrence at/before --until unless --year is given; sources older than one year require explicit years.",
                                    "Queue lifecycle is unknown if creation/removal context is missing."]}
    if completeness["unparsed_context"]:
        completeness["limitations"].append("Unparsed dated events outside the report window are counted separately; correlation context may be incomplete.")
    return _clean_tree({"findings": findings, "sources": sources, "completeness": completeness,
                        "statistics": statistics, "traces": traces, "evidence": evidence})
