"""Dashboard acceptance: useful content fits real terminal cell widths."""
import contextlib
import copy
import os
import re
import signal
import unittest
from unittest.mock import patch

from mailradar.cli import _ask
from mailradar.display import human
from mailradar.terminal import brand_header, cell_width, panel, presentation, render_menu, rule, viewport, wrap_cells
from test_terminal_ui import SGR, Stream, compact, diagnostic_report, pty_session, unframe


ITEMS = [dict(number=i, label="Task %d" % i, description="Delivery evidence %d" % i) for i in range(1, 15)]
CHOICES = re.compile(r"(?<!\d)(1[0-4]|[1-9])\.\s")


class ASCIIStream(Stream):
    @property
    def encoding(self):
        return "ascii"


class BrandedLayoutTests(unittest.TestCase):
    def assert_fits(self, lines, width):
        for line in lines:
            self.assertLessEqual(cell_width(line), width, repr(SGR.sub("", line)))

    def test_prompt_reserves_the_final_input_space_in_a_narrow_terminal(self):
        output, prompts = Stream(), []
        def answer(prompt):
            prompts.append(prompt)
            return ""
        with contextlib.redirect_stdout(output), presentation(stream=output, environ={"TERM": "xterm-256color"}, columns=32):
            with patch("builtins.input", side_effect=answer):
                _ask("IP SMTP-клиента (если известен): ")
        self.assert_fits(output.getvalue().splitlines() + prompts, 32)
        self.assertTrue(prompts[-1].endswith(" \x1b[0m"))

    def test_viewport_fallbacks_overrides_and_dynamic_environment(self):
        with presentation(stream=Stream(False), environ={"COLUMNS": "32", "LINES": "12"}):
            self.assertEqual(viewport(), (118, 40))
        env = {"TERM": "xterm-256color"}
        with presentation(stream=Stream(), environ=env):
            self.assertEqual(viewport(), (100, 30))
            env.update(COLUMNS="32", LINES="bad")
            self.assertEqual(viewport(), (32, 30))
            env.update(COLUMNS="80", LINES="40")
            self.assertEqual(viewport(), (80, 40))
        for bad in ("0", "-1", "nan", "999999999999999999999"):
            with self.subTest(bad=bad), presentation(stream=Stream(), environ={"COLUMNS": bad, "LINES": bad}):
                self.assertEqual(viewport(), (100, 30))
        with presentation(stream=Stream(False), environ=env, columns=40, rows=20):
            self.assertEqual(viewport(), (40, 20))
        with presentation(stream=Stream(), environ={"COLUMNS": "80", "LINES": "25"}, columns=32):
            self.assertEqual(viewport(), (32, 25))

    def test_brand_art_panels_and_long_values_fit_32_through_120_columns(self):
        sender, recipient = "long.sender@local.example", "long.recipient@partner.example"
        reason = "451 delayed while resolving remote.example; retry is pending"
        for width in (32, 40, 80, 120):
            with self.subTest(width=width), presentation(stream=Stream(), environ={"TERM": "xterm-256color"}, columns=width, rows=40):
                header = brand_header("4.1.3")
                contents = panel("Current queue", [("ABCDE | deferred", "key"), "From: " + sender, "To: " + recipient, reason], width=width, status="WARN")
                horizontal = rule("Queue scope", width=width+20)
                self.assert_fits(header + contents + [horizontal], width)
                visible = SGR.sub("", "\n".join(header))
                self.assertIn("MAILRADAR", compact(visible))
                self.assertTrue(any(marker in visible for marker in ("●", "*")), visible)
                self.assertTrue(any(marker in visible for marker in ("╱", "/")), visible)
                for value in ("ABCDE", sender, recipient, reason):
                    self.assertIn("".join(value.split()), compact("\n".join(contents)))

    def test_menu_all_fourteen_tasks_once_and_columns_adapt(self):
        for width in (32, 40, 80, 120):
            output = Stream()
            with self.subTest(width=width), contextlib.redirect_stdout(output), presentation(stream=output, environ={"TERM": "xterm-256color"}, columns=width, rows=40):
                render_menu("4.1.3", ITEMS, context="offline fixture")
            lines = SGR.sub("", output.getvalue()).splitlines()
            self.assert_fits(lines, width)
            numbers = [int(value) for value in CHOICES.findall("\n".join(lines))]
            self.assertEqual(sorted(numbers), list(range(1, 15)))
            for item in ITEMS:
                self.assertIn("".join(item["label"].split()), compact(output.getvalue()))
            item_counts = [len(CHOICES.findall(line)) for line in lines]
            if width < 76:
                self.assertTrue(all(count <= 1 for count in item_counts))
            else:
                self.assertTrue(any(count == 2 for count in item_counts))

    def test_dumb_or_ascii_encoding_uses_ascii_art_borders_and_no_color_switch_is_plain(self):
        cases = [(Stream(), {"TERM": "dumb"}, False, True),
                 (ASCIIStream(), {"TERM": "xterm-256color"}, False, True),
                 (Stream(), {"TERM": "xterm-256color"}, True, False)]
        for stream, env, disabled, ascii_expected in cases:
            with self.subTest(env=env, no_color=disabled), presentation(stream=stream, environ=env, columns=40, rows=40, no_color=disabled):
                lines = brand_header("4.1.3") + panel("Queue", ["ABCDE | deferred"], status="WARN")
            value = "\n".join(lines)
            if disabled or env["TERM"] == "dumb":
                self.assertNotIn("\x1b", value)
            if ascii_expected:
                for char in "┌┐└┘│─●╱╲":
                    self.assertNotIn(char, SGR.sub("", value))
            self.assert_fits(lines, 40)

    def test_wrap_preserves_wide_and_combining_glyphs_and_sanitizes_controls(self):
        self.assertEqual(cell_width("e\u0301界"), 3)
        self.assertEqual(cell_width("\x1b[1;32me\u0301界\x1b[0m"), 3)
        value = "Queue ABCDE: e\u0301 + 界界 + sender@local.example " + "x"*70
        with presentation(stream=Stream(), environ={"TERM": "xterm-256color"}, columns=32, rows=40):
            lines = wrap_cells(value, 28)
        self.assert_fits(lines, 28)
        self.assertEqual("".join(value.split()), "".join("".join(lines).split()))
        hostile = "text\x1b[2J\x1b]52;c;ZmFrZQ==\x07\x9b2J\r\n[OK] forged"
        with presentation(stream=Stream(), environ={"TERM": "xterm-256color"}, columns=32, rows=40):
            lines = panel("Evidence", [hostile], status="WARN")
        self.assert_fits(lines, 32)
        self.assertNotIn("\x1b", SGR.sub("", "\n".join(lines)))
        self.assertNotIn("\x9b", "\n".join(lines))
        self.assertNotIn("\x1b[1;32m[OK]", "\n".join(lines))

    def test_human_report_facts_survive_narrow_viewports_without_mutation(self):
        data = diagnostic_report()
        unchanged = copy.deepcopy(data)
        for width in (32, 40, 80, 120):
            output = Stream()
            with self.subTest(width=width), patch.dict(os.environ, {"TERM": "xterm-256color", "COLUMNS": str(width), "LINES": "40"}, clear=True), contextlib.redirect_stdout(output):
                human(data)
            self.assert_fits(output.getvalue().splitlines(), width)
            for value in ("ABCDE", "sender@local.example", "office@partner.example", "451 recipient temporarily unavailable"):
                self.assertIn("".join(value.split()), compact(output.getvalue()))
        self.assertEqual(data, unchanged)


@unittest.skipUnless(os.name == "posix", "real adaptive terminal requires POSIX PTY")
class BrandedPTYTests(unittest.TestCase):
    def test_narrow_and_wide_menu_report_return_and_cancel(self):
        for width in (32, 100):
            with self.subTest(width=width), pty_session(self, columns=width) as (process, send, until, _):
                menu = until("Номер [1]: ")
                self.assertEqual(sorted(int(n) for n in CHOICES.findall(SGR.sub("", menu))), list(range(1, 15)))
                self.assertTrue(all(cell_width(line) <= width for line in menu.replace("\r", "").splitlines()))
                send("1\n")
                result = until("Enter — вернуться в меню; 0 — выход:")
                self.assertIn("BCDEF01234", compact(result))
                self.assertIn("office@local.example", compact(result))
                self.assertTrue(all(cell_width(line) <= width for line in result.replace("\r", "").splitlines()))
                send("\n")
                until("Номер [1]: ")
                process.send_signal(signal.SIGINT)
                self.assertEqual(process.wait(timeout=5), 130)

    def test_redraw_rereads_real_fd_size_and_help_remains_navigable(self):
        with pty_session(self, columns=100) as (process, send, until, resize):
            until("Номер [1]: ")
            resize(32)
            send("r\n")
            menu = until("Номер [1]: ")
            self.assertEqual(sorted(int(n) for n in CHOICES.findall(SGR.sub("", menu))), list(range(1, 15)))
            self.assertTrue(all(cell_width(line) <= 32 for line in menu.replace("\r", "").splitlines()))
            send("?\n")
            help_page = until("Номер [1]: ")
            self.assertNotIn("Traceback", help_page)
            self.assertIn("0", unframe(help_page))
            self.assertTrue(all(cell_width(line) <= 32 for line in help_page.replace("\r", "").splitlines()))
            send("0\n")
            self.assertEqual(process.wait(timeout=5), 0)


if __name__ == "__main__":
    unittest.main()
