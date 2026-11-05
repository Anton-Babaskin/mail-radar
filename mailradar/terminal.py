"""Small, optional terminal palette; untrusted text never supplies escape codes."""
from contextlib import contextmanager
from contextvars import ContextVar
import os
import re
import sys

from .model import clean


_ACTIVE = ContextVar("mailradar_terminal_color", default=False)
_STYLES = {
    "title": "1;36", "section": "1;36", "key": "36", "field": "35",
    "muted": "2", "prompt": "1;36", "error": "1;31",
    "OK": "1;32", "WARN": "1;33", "FAIL": "1;31", "UNKNOWN": "1;34", "N/A": "2",
}
_BADGE = re.compile(r"^(\[(OK|WARN|FAIL|UNKNOWN|N/A)\])")


@contextmanager
def presentation(no_color=False, stream=None, environ=None):
    stream = sys.stdout if stream is None else stream
    environ = os.environ if environ is None else environ
    active = (not no_color and bool(stream.isatty()) and environ.get("TERM", "").lower() != "dumb"
              and not environ.get("NO_COLOR"))
    token = _ACTIVE.set(active)
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def _plain(text):
    return re.sub(r"[\r\n\t]+", " ", clean(text, 6000))


def paint(text, role):
    text = _plain(text)
    code = _STYLES.get(role)
    return "\033[" + code + "m" + text + "\033[0m" if code and text and _ACTIVE.get() else text


def formatted_line(text, role=None):
    text = _plain(text)
    if role == "field" and ": " in text:
        label, value = text.split(": ", 1)
        return paint(label + ":", "field") + " " + value
    if role == "title":
        prefix, separator, status = text.rpartition(" — ")
        if separator and status in _STYLES:
            return paint(prefix + separator, "title") + paint(status, status)
    if role:
        return paint(text, role)
    badge = _BADGE.match(text)
    return paint(badge[1], badge[2]) + text[badge.end():] if badge else text
