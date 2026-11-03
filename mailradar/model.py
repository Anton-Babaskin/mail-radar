"""Shared report contract, sanitization and private output."""
import copy
import ipaddress
import json
import math
import os
import re
from datetime import datetime, timezone

STATUSES = ("OK", "WARN", "FAIL", "UNKNOWN", "N/A")
ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


def clean(value, limit=4000):
    value = ANSI.sub("", str(value))
    value = "".join(c for c in value if c in "\n\t" or (ord(c) >= 32 and not 127 <= ord(c) <= 159 and c not in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"))
    value = re.sub(r"(?i)\b(password|passwd|secret_key|api[_-]?token|authorization)\s*[=:]\s*[^\s,;]+", r"\1=[REDACTED]", value)
    value = re.sub(r"(://)[^/@\s:]+:[^/@\s]+@", r"\1[REDACTED]@", value)
    value = re.sub(r"(?i)\b[a-z0-9_-]+\.(?=(?:zen|dbl|sbl|xbl|pbl|zrd|authbl)\.dq\.spamhaus\.net\b)","[DQS-key].",value)
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
    incomplete = report.get("completeness", {}).get("complete") is False
    status = "FAIL" if counts["FAIL"] else "WARN" if counts["WARN"] else "UNKNOWN" if counts["UNKNOWN"] or incomplete else "OK"
    report["summary"] = dict(status=status, counts=counts, exit_code=2 if counts["FAIL"] else 1 if counts["WARN"] or counts["UNKNOWN"] or incomplete else 0)
    report.setdefault("schema_version", "1.0")
    report.setdefault("generated_at", datetime.now(timezone.utc).isoformat())
    if len(json.dumps(report, ensure_ascii=False).encode("utf-8")) > 8 * 1024 * 1024:
        # A hard fallback, rather than only shortening outer arrays whose nested
        # values can still exceed the budget. Keep conclusions and a clear gap.
        summary = report["summary"]
        summary["exit_code"] = max(1, summary["exit_code"])
        if summary["status"] == "OK":
            summary["status"] = "UNKNOWN"
        report = dict(schema_version=report["schema_version"], generated_at=report["generated_at"],
                      tool=report.get("tool", {}), mode=report.get("mode", "unknown"),
                      window=report.get("window", {}), filters=report.get("filters", {}),
                      summary=summary,
                      findings=[{k: f.get(k, "") for k in ("id", "status", "title", "next_step")} | {"evidence": [], "details": {"omitted": True}}
                                for f in report["findings"][:200]],
                      sources=[{k: s[k] for k in ("path", "readable", "truncated") if k in s} for s in report.get("sources", [])[:100]],
                      completeness=dict(complete=False, limitations=["8 MiB report limit: nested evidence/details/traces omitted. Repeat with narrower filters."]),
                      **({"redaction":report["redaction"]} if "redaction" in report else {}))
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
        value = re.sub(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}", lambda m: alias(m[0], "address") + "@redacted.example", value)
        def ip(match):
            try:
                ipaddress.ip_address(match[0])
                return alias(match[0], "ip")
            except ValueError:
                return match[0]
        value = re.sub(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])[0-9a-fA-F]*:[0-9a-fA-F:]+(?![\w:])", ip, value)
        value = re.sub(r"(?<![@\w])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![\w])", lambda m: m[0] if m[0].endswith(".example") else alias(m[0], "domain") + ".example", value)
        return value
    def walk(value):
        if isinstance(value, str):
            return text(value)
        if isinstance(value, dict):
            protected = {"hdr.date", "hdr.received", "hdr.message-id", "date.saved", "date.received"}
            return {(k if k in protected else text(k)): v if k in ("id", "status", "schema_version", "mode", "type", "kind", "check_type", "outcome", "component", "program") else walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v) for v in value]
        return value
    result = walk(copy.deepcopy(report))
    result["redaction"] = {"applied": True, "limits": "Equality aliases apply within this export only. Review paths, queue IDs, Message-IDs and free text before sharing; anonymity is not guaranteed."}
    return finish_report(result) if "findings" in result and "summary" in result else result
