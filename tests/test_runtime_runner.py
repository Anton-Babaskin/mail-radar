"""POSIX pipe ownership and command deadline regressions using fake processes."""
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
import time
import unittest

from mailradar.runner import Runner


@unittest.skipUnless(os.name == "posix", "Linux/POSIX nonblocking subprocess pipes")
class RuntimeRunnerTests(unittest.TestCase):
    def test_detached_pipe_holder_does_not_leak_reader_threads_or_delay_return(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "fake-child-pid"
            code = "import subprocess,time; p=subprocess.Popen(['sleep','5'],start_new_session=True); open(%r,'w').write(str(p.pid)); time.sleep(60)" % str(marker)
            before = {thread.ident for thread in threading.enumerate()}
            runner = Runner()
            started = time.monotonic()
            try:
                result = runner._execute([sys.executable, "-c", code], .3)
                elapsed = time.monotonic() - started
                self.assertTrue(result.timed_out)
                self.assertFalse(result.ok)
                self.assertLess(elapsed, 2, "command deadline includes pipe readers; no 2s join per stream")
                self.assertEqual({thread.ident for thread in threading.enumerate()}, before)
                self.assertFalse(runner.processes)
            finally:
                runner.close()
                if marker.exists():
                    # Only this fixture's deliberately detached child; production
                    # process-group cleanup is not a daemon/security sandbox.
                    try:
                        os.killpg(int(marker.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_stdout_and_stderr_are_bounded_independently(self):
        runner = Runner(max_output=4096)
        result = runner._execute([sys.executable, "-c", "import sys; sys.stdout.write('a'*4000); sys.stdout.flush(); sys.stderr.write('b'*50000); sys.stderr.flush()"], 3)
        self.assertTrue(result.truncated)
        self.assertEqual(result.stdout, "a" * 4000)
        self.assertEqual(len(result.stderr), 4096)
        self.assertFalse(result.ok)
