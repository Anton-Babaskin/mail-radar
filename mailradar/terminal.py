"""Responsive terminal presentation with a fixed, trusted SGR palette."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import os
import re
import sys
import unicodedata

from .model import clean


_STYLES = {
    "title": "1;36", "section": "1;36", "key": "36", "field": "35",
    "brand": "1;33", "radar": "1;36", "muted": "2", "prompt": "1;36", "error": "1;31",
    "OK": "1;32", "WARN": "1;33", "FAIL": "1;31", "UNKNOWN": "1;34", "N/A": "2",
}
_BADGE = re.compile(r"^(\[(OK|WARN|FAIL|UNKNOWN|N/A)\])")
_STATUSES = frozenset(("OK", "WARN", "FAIL", "UNKNOWN", "N/A"))


@dataclass(frozen=True)
class _Presentation:
    stream: object
    environ: object
    terminal: bool
    colored: bool
    columns: object = None
    rows: object = None


_CURRENT = ContextVar("mailradar_terminal_presentation", default=None)


def _isatty(stream):
    try:
        return bool(stream.isatty())
    except (AttributeError, OSError, ValueError):
        return False


def _dimension(value, lower, upper):
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,4}", str(value)):
        return None
    number = int(value)
    return number if lower <= number <= upper else None


@contextmanager
def presentation(no_color=False, stream=None, environ=None, columns=None, rows=None):
    parent = _CURRENT.get()
    stream = (parent.stream if parent is not None else sys.stdout) if stream is None else stream
    environ = (parent.environ if parent is not None else os.environ) if environ is None else environ
    terminal = _isatty(stream)
    colored = (terminal and not no_color and environ.get("TERM", "").lower() != "dumb"
               and not environ.get("NO_COLOR"))
    columns = parent.columns if columns is None and parent is not None else _dimension(columns, 20, 500)
    rows = parent.rows if rows is None and parent is not None else _dimension(rows, 8, 200)
    state = _Presentation(stream, environ, terminal, colored, columns, rows)
    token = _CURRENT.set(state)
    try:
        yield
    finally:
        _CURRENT.reset(token)


def is_terminal():
    state = _CURRENT.get()
    return state.terminal if state is not None else _isatty(sys.stdout)


def viewport():
    """Read the live output fd, falling back to bounded environment dimensions."""
    state = _CURRENT.get()
    stream = state.stream if state is not None else sys.stdout
    environ = state.environ if state is not None else os.environ
    if not is_terminal():
        columns, rows = 118, 40
    else:
        columns = rows = None
        try:
            size = os.get_terminal_size(stream.fileno())
            columns = _dimension(size.columns, 20, 500)
            rows = _dimension(size.lines, 8, 200)
        except (AttributeError, OSError, ValueError):
            pass
        columns = columns or _dimension(environ.get("COLUMNS"), 20, 500) or 100
        rows = rows or _dimension(environ.get("LINES"), 8, 200) or 30
    if state is not None:
        columns, rows = state.columns or columns, state.rows or rows
    return columns, rows


def unicode_enabled():
    state = _CURRENT.get()
    stream = state.stream if state is not None else sys.stdout
    environ = state.environ if state is not None else os.environ
    if environ.get("TERM", "").lower() == "dumb":
        return False
    try:
        "╭─╮│╰╯●╱".encode(getattr(stream, "encoding", None) or "utf-8")
    except (LookupError, UnicodeError):
        return False
    return True


def _plain(text):
    raw = str(text)
    # Collector/report bounds limit input; layout never drops a long identifier.
    return re.sub(r"[\r\n\t]+", " ", clean(raw, max(6000, len(raw) * 2 + 64)))


def paint(text, role):
    text = _plain(text)
    state = _CURRENT.get()
    code = _STYLES.get(role)
    return "\033[" + code + "m" + text + "\033[0m" if code and text and state is not None and state.colored else text


def formatted_line(text, role=None):
    text = _plain(text)
    if role == "field" and ": " in text:
        label, value = text.split(": ", 1)
        return paint(label + ":", "field") + " " + value
    if role == "title":
        prefix, separator, status = text.rpartition(" — ")
        if separator and status in _STATUSES:
            return paint(prefix + separator, "title") + paint(status, status)
    if role:
        return paint(text, role)
    badge = _BADGE.match(text)
    return paint(badge[1], badge[2]) + text[badge.end():] if badge else text


def _character_width(character):
    if unicodedata.combining(character) or unicodedata.category(character) in {"Mn", "Me", "Cf"}:
        return 0
    return 2 if unicodedata.east_asian_width(character) in {"W", "F"} else 1


def _cells(text):
    return sum(_character_width(character) for character in text)


def cell_width(text):
    return _cells(_plain(text))


def _clusters(text):
    cluster = ""
    for character in text:
        if cluster and _character_width(character):
            yield cluster
            cluster = ""
        cluster += character
    if cluster:
        yield cluster


def _word_parts(word, width):
    part, occupied = "", 0
    for cluster in _clusters(word):
        size = _cells(cluster)
        if part and occupied + size > width:
            yield part
            part, occupied = "", 0
        part += cluster
        occupied += size
    if part:
        yield part


def wrap_cells(text, width):
    """Wrap sanitized words by cells, preserving non-whitespace characters."""
    width = int(width)
    if width < 1:
        raise ValueError("Terminal wrap width must be positive")
    text = _plain(text)
    leading = len(text) - len(text.lstrip(" "))
    indent = " " * min(leading, max(0, width - 2))
    available = width - len(indent)
    words = text.split()
    if not words:
        return [""]
    output, line, occupied = [], "", 0
    for word in words:
        word_size = _cells(word)
        if line and occupied + 1 + word_size <= available:
            line += " " + word
            occupied += 1 + word_size
            continue
        if line:
            output.append(indent + line)
            line, occupied = "", 0
        parts = list(_word_parts(word, available))
        output.extend(indent + part for part in parts[:-1])
        line = parts[-1]
        occupied = _cells(line)
    if line:
        output.append(indent + line)
    return output


def _width(width):
    columns, _ = viewport()
    result = columns if width is None else min(columns, int(width))
    if result < 6:
        raise ValueError("Terminal panel width must be at least six cells")
    return result


def rule(title, width=None):
    width = _width(width)
    horizontal = "─" if unicode_enabled() else "-"
    title = _plain(title).strip()
    if not title:
        return paint(horizontal * width, "section")
    lines = []
    for part in wrap_cells(title, width - 4):
        text = horizontal * 2 + " " + part + " "
        lines.append(paint(text + horizontal * (width - cell_width(text)), "section"))
    return "\n".join(lines)


def panel(title, rows, width=None, status=None):
    """Return framed lines; width includes both borders and inner padding."""
    width = _width(width)
    inner = width - 4
    tl, tr, bl, br, horizontal, vertical = ("╭", "╮", "╰", "╯", "─", "│") if unicode_enabled() else ("+", "+", "+", "+", "-", "|")
    title = _plain(title).strip()
    status = status if status in _STATUSES else None
    label = title + (" [" + status + "]" if status else "")
    lines = []
    if cell_width(label) <= width - 5:
        prefix = tl + horizontal + " "
        top = paint(prefix + title, "section")
        if status:
            top += paint(" [" + status + "]", status)
        lines.append(top + paint(" " + horizontal * (width - cell_width(prefix + label) - 2) + tr, "section"))
    else:
        lines.append(paint(tl + horizontal * (width - 2) + tr, "section"))
        rows = [(label, "section")] + list(rows)
    for row in rows:
        value, role = row if isinstance(row, tuple) else (row, "plain")
        for part in wrap_cells(value, inner):
            body = paint(part, role or "plain")
            lines.append(paint(vertical, "section") + " " + body + " " * (inner - cell_width(part) + 1) + paint(vertical, "section"))
    lines.append(paint(bl + horizontal * (width - 2) + br, "section"))
    return lines


_LETTERING = {
    "M": ("█   █", "██ ██", "█ █ █", "█   █", "█   █"),
    "A": (" ███ ", "█   █", "█████", "█   █", "█   █"),
    "I": ("█████", "  █  ", "  █  ", "  █  ", "█████"),
    "L": ("█    ", "█    ", "█    ", "█    ", "█████"),
    "R": ("████ ", "█   █", "████ ", "█  █ ", "█   █"),
    "D": ("████ ", "█   █", "█   █", "█   █", "████ "),
}


def brand_header(version, compact=False):
    columns, rows = viewport()
    version = _plain(version)
    unicode = unicode_enabled()
    if not compact and columns >= 96 and rows >= 32:
        backslash = chr(92)
        radar = ("   .-╱-.", "  / ╱   " + backslash, " |╱ ●  · |", "  " + backslash + "     /", "   '---'") if unicode else (
            "   .-/-. ", "  / /   " + backslash, " |/ *  . |", "  " + backslash + "     /", "   '---' ")
        lettering = ["  ".join(_LETTERING[letter][row] for letter in "MAILRADAR") for row in range(5)]
        if not unicode:
            lettering = [row.replace("█", "#") for row in lettering]
        logo_width = max(cell_width(row) for row in lettering) + 14
        margin = " " * max(0, (columns - logo_width) // 2)
        result = [margin + paint(mark.ljust(10), "radar") + "    " + paint(row, "brand")
                  for mark, row in zip(radar, lettering)]
        caption = "MAILRADAR v" + version + "  /  Локальная диагностика почты"
        result.extend(paint(part, "title") for part in wrap_cells(caption, columns))
        return result
    marks = ("╭─╱─╮", "│╱● │", "╰───╯") if unicode else (".-/-.", "|/* |", "'---'")
    captions = ("MAILRADAR v" + version, "Локальная диагностика", "Postfix / Dovecot")
    result = []
    for index, (mark, caption) in enumerate(zip(marks, captions)):
        for continuation, part in enumerate(wrap_cells(caption, columns - 7)):
            lead = mark if not continuation else " " * 5
            result.append(paint(lead, "radar") + "  " + paint(part, "brand" if index == 0 else "muted"))
    return result


def _menu_rows(items, width, descriptions):
    rows = []
    available = width - 8
    for item in items:
        label = wrap_cells(item["label"], available)
        rows.append(("%2d. %s" % (item["number"], label[0]), "key"))
        rows.extend(("    " + part, "plain") for part in label[1:])
        if descriptions and item.get("description"):
            rows.extend(("    " + part, "muted") for part in wrap_cells(item["description"], available))
    return rows


def render_menu(version, items, context=""):
    columns, height = viewport()
    print()
    for line in brand_header(version):
        print(line)
    print()
    for line in panel("СЕССИЯ", [context or "Выберите задачу диагностики"]):
        print(line)
    print()
    descriptions = columns >= 110 and height >= 38
    if columns >= 76:
        left_width = (columns - 2) // 2
        right_width = columns - left_width - 2
        left = panel("ДОСТАВКА И SMTP", _menu_rows(items[:7], left_width, descriptions), width=left_width)
        right = panel("СЕРВЕР И ПОИСК", _menu_rows(items[7:], right_width, descriptions), width=right_width)
        for index in range(max(len(left), len(right))):
            first = left[index] if index < len(left) else ""
            second = right[index] if index < len(right) else ""
            print(first + " " * (left_width - cell_width(first) + 2) + second)
    else:
        for line in panel("ЗАДАЧИ", _menu_rows(items, columns, descriptions)):
            print(line)
    print()
    divider = " · " if unicode_enabled() else " | "
    for line in wrap_cells(divider.join(("0. Выход", "?. Справка", "r. Меню")), columns):
        print(paint(line, "prompt"))
    for line in wrap_cells("Enter — общий обзор" if unicode_enabled() else "Enter - общий обзор", columns):
        print(paint(line, "muted"))
