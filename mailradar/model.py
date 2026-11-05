"""Shared report contract, sanitization and private output."""
import copy
import ipaddress
import json
import math
import os
import re
from datetime import datetime, timezone

STATUSES = ("OK", "WARN", "FAIL", "UNKNOWN", "N/A")
MAILSTORE_FIELDS = ("mailbox", "uid", "guid", "date.received", "date.saved", "date.received.unixtime", "date.saved.unixtime",
                   "hdr.date", "hdr.received", "hdr.message-id", "flags")
ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


def clean(value, limit=4000):
    value = ANSI.sub("", str(value))
    value = "".join(c for c in value if c in "\n\t" or (ord(c) >= 32 and not 127 <= ord(c) <= 159 and c not in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"))
    value = re.sub(r"(?i)\b(password|passwd|secret_key|api[_-]?token|authorization)\s*[=:]\s*[^\s,;]+", r"\1=[REDACTED]", value)
    value = re.sub(r"(://)[^/@\s:]+:[^/@\s]+@", r"\1[REDACTED]@", value)
    value = re.sub(r"(?i)\b[a-z0-9_-]+\.(?=[a-z0-9_-]+\.dq\.spamhaus\.net\b)","[DQS-key].",value)
    return value[:limit] + ("…[truncated]" if len(value) > limit else "")


def finding(identifier, status, title, evidence=None, next_step="", **details):
    if status not in STATUSES:
        raise ValueError("Unknown finding status")
    return dict(id=identifier, status=status, title=title, evidence=evidence or [], next_step=next_step, details=details)


def sanitize(value):
    if isinstance(value,float) and not math.isfinite(value):
        return None
    if isinstance(value, str):
        return clean(value)
    if isinstance(value, dict):
        return {clean(k, 512): sanitize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize(v) for v in value]
    return value


def finish_report(report):
    report = sanitize(report)
    counts = {s: sum(f["status"] == s for f in report["findings"]) for s in STATUSES}
    conclusion_counts = {s: sum(c["status"] == s for c in report.get("conclusions", [])) for s in STATUSES}
    overall = {s: counts[s] + conclusion_counts[s] for s in STATUSES}
    incomplete = report.get("completeness", {}).get("complete") is False
    status = "FAIL" if overall["FAIL"] else "WARN" if overall["WARN"] else "UNKNOWN" if overall["UNKNOWN"] or incomplete else "OK"
    # Counts remain findings-only; conclusions may describe the same evidence.
    report["summary"] = dict(status=status, counts=counts, conclusion_counts=conclusion_counts,
                             exit_code=2 if overall["FAIL"] else 1 if overall["WARN"] or overall["UNKNOWN"] or incomplete else 0)
    report.setdefault("schema_version", "1.0")
    report.setdefault("generated_at", datetime.now(timezone.utc).isoformat())
    if len(json.dumps(report, ensure_ascii=False).encode("utf-8")) > 8 * 1024 * 1024:
        # A hard fallback, rather than only shortening outer arrays whose nested
        # values can still exceed the budget. Keep workflow/stream metadata and
        # a clear gap when message evidence must be omitted.
        summary = report["summary"]
        summary["exit_code"] = max(1, summary["exit_code"])
        if summary["status"] == "OK":
            summary["status"] = "UNKNOWN"
        metadata = {key: report[key] for key in ("workflow", "scope", "targets", "active_probes", "watch", "redaction")
                    if key in report and len(json.dumps(report[key], ensure_ascii=False).encode("utf-8")) <= 65536}
        report = dict(schema_version=report["schema_version"], generated_at=report["generated_at"],
                      tool=report.get("tool", {}), mode=report.get("mode", "unknown"),
                      window=report.get("window", {}), filters=report.get("filters", {}),
                      summary=summary,
                      findings=[{k: f.get(k, "") for k in ("id", "status", "title", "next_step")} | {"evidence": [], "details": {"omitted": True}}
                                for f in report["findings"][:200]],
                      sources=[{k: s[k] for k in ("path", "readable", "truncated") if k in s} for s in report.get("sources", [])[:100]],
                      completeness=dict(complete=False, log_sources_complete=False, checks_complete=False,
                                        limitations=["8 MiB report limit: nested evidence/details/traces omitted. Repeat with narrower filters."]),
                      **metadata)
    return report


def write_private(path, data):
    """Create once; never follow a symlink or overwrite any existing file."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        os.unlink(path)
        raise


def redact_report(report):
    aliases = {}
    counts = {}
    def alias(value, kind):
        key = (kind, value)
        if key not in aliases:
            counts[kind] = counts.get(kind,0)+1
            aliases[key] = "%s%d" % (kind, counts[kind])
        return aliases[key]
    def text(value):
        value = re.sub(r'(?:"(?:[^"\\\r\n]|\\[^\r\n])*"|[A-Za-z0-9.!#$%&\x27*+/=?^_`{|}~-]+)@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}', lambda m: alias(m[0], "address") + "@redacted.example", value)
        def ip(match):
            try:
                ipaddress.ip_address(match[0])
                return alias(match[0], "ip")
            except ValueError:
                return match[0]
        value = re.sub(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])[0-9a-fA-F]*:[0-9a-fA-F:]+(?![\w:])", ip, value)
        value = re.sub(r"(?<![@\w])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![\w])", lambda m: m[0] if m[0].endswith(".example") else alias(m[0], "domain") + ".example", value)
        return value
    def walk(value, path=()):
        if isinstance(value, str):
            return text(value)
        if isinstance(value, dict):
            result = {}
            finding_path = len(path) == 2 and path[0] == "findings" and isinstance(path[1], int)
            for key, child in value.items():
                # Finding identifiers are stable API names. Trace IDs, link
                # targets and trace_id references must use the same aliases.
                exported_key = key if key in MAILSTORE_FIELDS else text(key)
                result[exported_key] = child if key == "id" and finding_path else walk(child, path + (key,))
            return result
        if isinstance(value, list):
            return [walk(v, path + (index,)) for index, v in enumerate(value)]
        return value
    result = walk(sanitize(copy.deepcopy(report)))
    result["redaction"] = {"applied": True, "limits": "Equality aliases apply within this export only. Review paths, queue IDs, Message-IDs and free text before sharing; anonymity is not guaranteed."}
    return finish_report(result) if "findings" in result and "summary" in result else result
