"""Incremental deep inspection over isolated fake Maildirs, never mail bodies."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mailradar.mailstore import physical_usage


@unittest.skipUnless(os.name == "posix" and os.scandir in os.supports_fd and hasattr(os, "O_NOFOLLOW"), "descriptor-relative traversal requires POSIX")
class IncrementalMailstoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.mailboxes = self.root / "home/user-data/mail/mailboxes"
        self.target = self.mailboxes / "example.org" / "a"
        self.target.mkdir(parents=True)

    def tearDown(self):
        self.directory.cleanup()

    def counting_scandir(self, clock=None, fail_after=None, entry_transform=None):
        real_scandir = os.scandir
        stats = {"entries": 0, "iterators": []}
        class CountingIterator:
            def __init__(self, path):
                self.inner = real_scandir(path)
                self.fd = path if isinstance(path, int) else None
                self.closed = False
                stats["iterators"].append(self)
            def __iter__(self):
                return self
            def __next__(self):
                if fail_after is not None and stats["entries"] >= fail_after:
                    raise KeyboardInterrupt("fixture interruption")
                value = next(self.inner)
                stats["entries"] += 1
                if clock is not None:
                    clock[0] += .005
                return entry_transform(value) if entry_transform else value
            def close(self):
                self.closed = True
                self.inner.close()
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.close()
        return CountingIterator, stats

    def assert_closed(self, stats):
        self.assertTrue(stats["iterators"])
        self.assertTrue(all(iterator.closed for iterator in stats["iterators"]))
        for iterator in stats["iterators"]:
            if iterator.fd is not None:
                with self.assertRaises(OSError):
                    os.fstat(iterator.fd)

    def test_large_single_directory_stops_before_enumerating_all_entries(self):
        for i in range(1000):
            (self.target / ("message" + str(i))).write_bytes(b"fixture")
        iterator, stats = self.counting_scandir()
        with patch("mailradar.mailstore.os.scandir", iterator):
            result = physical_usage(self.root, "a@example.org", max_files=7)
        self.assertEqual(stats["entries"], 7)
        self.assertEqual(result["status"], "UNKNOWN")
        evidence = result["evidence"][0]
        self.assertEqual(evidence["files"], 7)
        self.assertEqual(evidence["entries_examined"], 7)
        self.assertEqual(evidence["stop_reason"], "entry_limit")
        self.assertFalse(evidence["complete"])
        self.assert_closed(stats)

    def test_deadline_is_checked_between_entry_reads(self):
        for i in range(100):
            (self.target / ("message" + str(i))).touch()
        clock = [0.0]
        iterator, stats = self.counting_scandir(clock=clock)
        with patch("mailradar.mailstore.os.scandir", iterator), patch("mailradar.mailstore.time.monotonic", side_effect=lambda: clock[0]):
            result = physical_usage(self.root, "a@example.org", seconds=.01)
        self.assertEqual(stats["entries"], 2)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["evidence"][0]["stop_reason"], "time_limit")
        self.assert_closed(stats)

    def test_empty_directory_tree_consumes_entry_and_directory_budgets(self):
        for i in range(50):
            (self.target / ("folder" + str(i))).mkdir()
        iterator, stats = self.counting_scandir()
        with patch("mailradar.mailstore.os.scandir", iterator):
            result = physical_usage(self.root, "a@example.org", max_files=5, max_dirs=100)
        self.assertEqual(stats["entries"], 5)
        self.assertEqual(result["evidence"][0]["files"], 0)
        self.assertEqual(result["evidence"][0]["stop_reason"], "entry_limit")
        self.assert_closed(stats)
        result = physical_usage(self.root, "a@example.org", max_dirs=3)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["evidence"][0]["directories"], 3)
        self.assertEqual(result["evidence"][0]["stop_reason"], "directory_limit")

    def test_completed_small_selected_user_scan_skips_symlinks_and_other_users(self):
        other = self.mailboxes / "example.org" / "b"
        other.mkdir()
        (other / "other-message").write_bytes(b"x" * 10000)
        (self.target / "one-file").write_bytes(b"12345")
        (self.target / "cur").mkdir()
        (self.target / "cur" / "index").write_bytes(b"12")
        (self.target / "linked-user").symlink_to(other, target_is_directory=True)
        (self.target / "linked-file").symlink_to(other / "other-message")
        result = physical_usage(self.root, "a@example.org")
        self.assertEqual(result["status"], "OK")
        evidence = result["evidence"][0]
        self.assertEqual(evidence["bytes"], 7)
        self.assertEqual(evidence["files"], 2)
        self.assertEqual(evidence["directories"], 2)
        self.assertTrue(evidence["complete"])

    def test_target_and_domain_symlinks_or_dot_scope_are_not_traversed(self):
        other = self.mailboxes / "example.org" / "b"
        other.mkdir()
        (other / "secret").write_bytes(b"x" * 10000)
        (self.mailboxes / "example.org" / "linked").symlink_to(other, target_is_directory=True)
        (self.mailboxes / "alias.example").symlink_to(self.mailboxes / "example.org", target_is_directory=True)
        for user in ("linked@example.org", "a@alias.example", "..@example.org", "a@.."):
            with self.subTest(user=user):
                result = physical_usage(self.root, user)
                self.assertEqual(result["status"], "UNKNOWN")
                if result["evidence"] and isinstance(result["evidence"][0], dict):
                    self.assertEqual(result["evidence"][0]["bytes"], 0)
                    self.assertEqual(result["evidence"][0]["files"], 0)

    def test_directory_replaced_by_symlink_between_stat_and_open_is_not_followed(self):
        child = self.target / "folder"
        child.mkdir()
        other = self.mailboxes / "example.org" / "b"
        other.mkdir()
        (other / "secret").write_bytes(b"x" * 10000)
        class RacedEntry:
            def __init__(self, entry):
                self.inner, self.name = entry, entry.name
            def stat(self, **kwargs):
                info = self.inner.stat(**kwargs)
                child.rmdir()
                child.symlink_to(other, target_is_directory=True)
                return info
        iterator, stats = self.counting_scandir(entry_transform=lambda entry: RacedEntry(entry) if entry.name == "folder" else entry)
        with patch("mailradar.mailstore.os.scandir", iterator):
            result = physical_usage(self.root, "a@example.org")
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["evidence"][0]["files"], 0)
        self.assertEqual(result["evidence"][0]["bytes"], 0)
        self.assertTrue(result["evidence"][0]["errors"])
        self.assert_closed(stats)

    def test_symlink_cycles_leave_scope_unknown_on_supported_python_versions(self):
        # pathlib.resolve raises RuntimeError for cycles in Python3.9/3.10,
        # while newer Python versions may report OSError instead.
        (self.mailboxes / "example.org" / "loop").symlink_to("loop")
        (self.mailboxes / "loop.example").symlink_to("loop.example")
        for user in ("loop@example.org", "a@loop.example"):
            with self.subTest(user=user), patch("mailradar.mailstore.os.scandir", side_effect=AssertionError("unsafe scope was enumerated")):
                result = physical_usage(self.root, user)
                self.assertEqual(result["status"], "UNKNOWN")

    def test_interruption_closes_iterators_and_directory_descriptors(self):
        (self.target / "one").touch()
        (self.target / "two").touch()
        iterator, stats = self.counting_scandir(fail_after=1)
        with patch("mailradar.mailstore.os.scandir", iterator), self.assertRaises(KeyboardInterrupt):
            physical_usage(self.root, "a@example.org")
        self.assert_closed(stats)

    def test_zero_entry_or_time_budget_performs_no_enumeration(self):
        for options in ({"max_files": 0}, {"max_dirs": 0}, {"seconds": 0}):
            with self.subTest(options=options), patch("mailradar.mailstore.os.scandir", side_effect=AssertionError("directory was enumerated")):
                result = physical_usage(self.root, "a@example.org", **options)
                self.assertEqual(result["status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
