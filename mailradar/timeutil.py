"""Shared server timezone and ISO timestamp handling."""
from datetime import datetime, timezone
from pathlib import Path
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def local_zone():
    for source in ("/etc/timezone",):
        try:
            return ZoneInfo(Path(source).read_text().strip())
        except (OSError, ValueError, ZoneInfoNotFoundError):
            pass
    try:
        name = str(Path("/etc/localtime").resolve()).split("/zoneinfo/", 1)[1]
        return ZoneInfo(name)
    except (IndexError, OSError, ZoneInfoNotFoundError):
        return datetime.now().astimezone().tzinfo


def timestamp(value, zone):
    normalized = re.sub(r"([+-]\d{2})(\d{2})$",r"\1:\2",value.replace("Z", "+00:00"))
    normalized = re.sub(r"(\.\d{6})\d+",r"\1",normalized)
    result = datetime.fromisoformat(normalized)
    if result.tzinfo is None:
        # Explicitly reject ambiguous or skipped wall-clock times; require an offset.
        first, second = result.replace(tzinfo=zone, fold=0), result.replace(tzinfo=zone, fold=1)
        if first.utcoffset() != second.utcoffset():
            raise ValueError("Неоднозначное/несуществующее локальное время: укажите UTC offset")
        result = first
    return result.astimezone(timezone.utc)


