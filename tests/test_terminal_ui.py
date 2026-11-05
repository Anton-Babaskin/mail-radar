"""Optional terminal styling preserves diagnostics and machine-readable output."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from mailradar import cli
from mailradar.display import _line, human
from mailradar.terminal import formatted_line, paint, presentation


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/logs/miab-production-shapes.log"
WINDOW = ["--since", "2026-11-03T10:00:00Z", "--until", "2026-11-03T11:00:00Z", "--timezone", "Asia/Dubai"]
SGR = re.compile(r"\x1b\[[0-9;]*m")


class Stream(io.StringIO):
    def __init__(self, tty=True):
        super().__init__()
        self.tty = tty

    def isatty(self):
        return self.tty


def diagnostic_report():
    return dict(mode="queue", summary=dict(status="WARN"), sources=[], scope=dict(logs_selected=False),
                completeness=dict(complete=True, checks_complete=True),
                generated_at="2026-11-05T10:00:00+00:00", findings=[dict(
                    id="QUEUE.SNAPSHOT", status="WARN", title="Current queue", evidence=[], details=dict(
                        count=1, complete=True, entries=[dict(queue_id="ABCDE", queue_name="deferred",
                            sender="sender@local.example", message_size=4096, age_seconds=120,
                            recipients=[dict(address="office@partner.example", delay_reason="451 recipient temporarily unavailable")])]))])


class TerminalPresentationTests(unittest.TestCase):
    def assert_only_sgr(self, value):
        self.assertNotIn("\x1b", SGR.sub("", value))
        self.assertNotIn(chr(155), value)

    def test_environment_and_explicit_no_color_precedence(self):
        cases = [
            (True, {"TERM": "xterm-256color"}, False, True),
            (True, {"TERM": "xterm-256color", "NO_COLOR": ""}, False, True),
            (True, {"TERM": "xterm-256color", "NO_COLOR": "1"}, False, False),
            (True, {"TERM": "xterm-256color", "NO_COLOR": "0"}, False, False),
            (True, {"TERM": "dumb"}, False, False),
            (False, {"TERM": "xterm-256color"}, False, False),
            (True, {"TERM": "xterm-256color"}, True, False),
        ]
        for tty, environ, disabled, expected in cases:
            with self.subTest(tty=tty, environ=environ, no_color=disabled):
                with presentation(no_color=disabled, stream=Stream(tty), environ=environ):
                    styled = paint("Important diagnostic", "section")
                self.assertEqual(bool(SGR.search(styled)), expected)
                self.assertEqual(SGR.sub("", styled), "Important diagnostic")
                self.assert_only_sgr(styled)

    def test_roles_and_status_badges_keep_readable_text_and_reset_style(self):
        with presentation(stream=Stream(), environ={"TERM": "xterm-256color"}):
            for role in ("section", "title", "key", "muted", "prompt", "error"):
                styled = paint("Readable label", role)
                self.assertTrue(SGR.search(styled), role)
                self.assertTrue(styled.endswith("\x1b[0m"), role)
                self.assertEqual(SGR.sub("", styled), "Readable label")
            for status in ("OK", "WARN", "FAIL", "UNKNOWN", "N/A"):
                line = "[%s] Delivery result for ABCDE" % status
                styled = formatted_line(line)
                self.assertTrue(SGR.search(styled), status)
                self.assertEqual(SGR.sub("", styled), line)
                self.assert_only_sgr(styled)

    def test_nested_context_and_exception_restore_presentation_state(self):
        self.assertEqual(paint("outside", "error"), "outside")
        with presentation(stream=Stream(), environ={"TERM": "xterm-256color"}):
            self.assertIn("\x1b", paint("outer", "error"))
            with self.assertRaises(RuntimeError):
                with presentation(no_color=True, stream=Stream(), environ={"TERM": "xterm-256color"}):
                    self.assertEqual(paint("plain inner", "error"), "plain inner")
                    raise RuntimeError("fixture")
            self.assertIn("\x1b", paint("outer restored", "error"))
        self.assertEqual(paint("outside again", "error"), "outside again")

    def test_untrusted_controls_cannot_add_terminal_commands_or_status_lines(self):
        hostile = "evidence \x1b[2J\x1b[31mred\x1b[0m\x1b]8;;https://untrusted.example\x07link\x1b]8;;\x07\x1b]52;c;ZmFrZQ==\x07\x9b2J\u202e\r\n[OK] forged\tvalue"
        with presentation(stream=Stream(), environ={"TERM": "xterm-256color"}):
            styled = paint(hostile, "error")
            self.assert_only_sgr(styled)
            plain = SGR.sub("", styled)
            for control in ("\r", "\n", "\t", "\x07", "\u202e"):
                self.assertNotIn(control, plain)
            self.assertIn("[OK] forged", plain)
            self.assertNotIn("\x1b[2J", styled)
            self.assertNotIn("\x1b]", styled)
        data = diagnostic_report()
        data["findings"][0]["details"]["entries"][0]["recipients"][0]["delay_reason"] = hostile
        output = Stream()
        with patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True), contextlib.redirect_stdout(output):
            human(data)
        self.assert_only_sgr(output.getvalue())
        self.assertNotIn("\n[OK] forged", SGR.sub("", output.getvalue()))

    def test_colored_and_plain_human_reports_have_identical_diagnostics(self):
        data, outputs = diagnostic_report(), []
        unchanged = copy.deepcopy(data)
        for disabled in (False, True):
            output = Stream()
            with patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True), contextlib.redirect_stdout(output):
                human(data, no_color=disabled)
            outputs.append(output.getvalue())
        self.assertIn("\x1b", outputs[0])
        self.assertNotIn("\x1b", outputs[1])
        self.assertEqual(SGR.sub("", outputs[0]), outputs[1])
        for value in ("[WARN]", "ABCDE", "sender@local.example", "office@partner.example", "451 recipient temporarily unavailable"):
            self.assertIn(value, outputs[1])
        self.assertEqual(data, unchanged)

    def test_wrapped_evidence_cannot_create_a_second_colored_status(self):
        output = Stream()
        with contextlib.redirect_stdout(output), presentation(stream=output, environ={"TERM": "xterm-256color"}):
            _line("[WARN] " + "x" * 111 + " [OK] forged")
        lines = output.getvalue().splitlines()
        self.assertIn("\x1b[1;33m[WARN]\x1b[0m", lines[0])
        self.assertEqual(lines[1], "[OK] forged")
        self.assertNotIn("\x1b", lines[1])

    def test_cli_no_color_and_non_tty_output_remain_plain(self):
        for tty, flags in ((True, ["--no-color"]), (False, [])):
            output = Stream(tty)
            with self.subTest(tty=tty), patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True), contextlib.redirect_stdout(output):
                code = cli.main(["--flow", "--offline", "--log", str(FIXTURE), *WINDOW, *flags])
            self.assertIn(code, (0, 1))
            self.assertNotIn("\x1b", output.getvalue())
            self.assertIn("BCDEF01234", output.getvalue())

    def test_json_remains_uncolored_with_tty_and_color_capable_environment(self):
        output = Stream()
        with patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True), contextlib.redirect_stdout(output):
            code = cli.main(["--flow", "--offline", "--log", str(FIXTURE), "--json", *WINDOW])
        self.assertIn(code, (0, 1))
        self.assertNotIn("\x1b", output.getvalue())
        self.assertNotIn("\\u001b", output.getvalue())
        report = json.loads(output.getvalue())
        self.assertEqual(report["schema_version"], "1.0")
        self.assertEqual(report["commands"], [])
        self.assertEqual(report["active_probes"], [])

    def test_watch_ndjson_service_events_and_report_remain_uncolored(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mail.log"
            path.write_text("", encoding="utf-8")
            output = Stream()
            with patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True), contextlib.redirect_stdout(output):
                code = cli.main(["--watch", "--offline", "--log", str(path), "--seconds", "0.1", "--json", *WINDOW])
        self.assertIn(code, (0, 1))
        self.assertNotIn("\x1b", output.getvalue())
        self.assertNotIn("\\u001b", output.getvalue())
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(events[0]["type"], "watch_started")
        self.assertEqual(events[-1]["type"], "watch_finished")
        self.assertEqual(next(event["report"] for event in events if event["type"] == "report")["commands"], [])


@unittest.skipUnless(os.name == "posix", "real terminal test requires POSIX PTY")
class TerminalPTYTests(unittest.TestCase):
    @contextlib.contextmanager
    def session(self, flags=(), environ=None):
        import pty
        master, slave = pty.openpty()
        env = dict(os.environ, TERM="xterm-256color")
        env.pop("NO_COLOR", None)
        env.update(environ or {})
        process = subprocess.Popen(["bash", str(ROOT / "mail-radar"), "--menu", "--offline", "--log", str(FIXTURE), *WINDOW, *flags],
                                   cwd=ROOT, stdin=slave, stdout=slave, stderr=slave, env=env)
        os.close(slave)
        pending = bytearray()

        def until(prompt):
            deadline = time.monotonic() + 10
            while prompt not in SGR.sub("", pending.decode("utf-8", "replace")):
                if time.monotonic() >= deadline:
                    self.fail("PTY prompt missing: " + prompt + "; " + pending.decode("utf-8", "replace"))
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        chunk = b""
                    if not chunk:
                        self.fail("PTY closed before prompt: " + pending.decode("utf-8", "replace"))
                    pending.extend(chunk)
            result = pending.decode("utf-8", "replace")
            pending.clear()
            return result

        try:
            yield process, lambda text: os.write(master, text.encode("utf-8")), until
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
            os.close(master)

    def test_real_menu_has_colors_fourteen_choices_and_return_navigation(self):
        with self.session() as (process, send, until):
            menu = until("Номер [1]: ")
            self.assertTrue(SGR.search(menu))
            plain = SGR.sub("", menu)
            for number in range(1, 15):
                self.assertRegex(plain, r"(?<!\d)%d\.\s" % number)
            send("1\n")
            result = until("Enter — вернуться в меню; 0 — выход: ")
            self.assertTrue(SGR.search(result))
            self.assertIn("BCDEF01234", SGR.sub("", result))
            send("\n")
            self.assertIn("Номер [1]: ", SGR.sub("", until("Номер [1]: ")))
            send("0\n")
            self.assertIn(process.wait(timeout=5), (0, 1))

    def test_real_menu_disable_switches_and_cancel_are_plain(self):
        for flags, environ in ((["--no-color"], {}), ([], {"NO_COLOR": "0"}), ([], {"TERM": "dumb"})):
            with self.subTest(flags=flags, environ=environ), self.session(flags, environ) as (process, _, until):
                menu = until("Номер [1]: ")
                self.assertNotIn("\x1b", menu)
                process.send_signal(signal.SIGINT)
                self.assertEqual(process.wait(timeout=5), 130)


if __name__ == "__main__":
    unittest.main()
