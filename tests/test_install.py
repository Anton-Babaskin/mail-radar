"""Exercise the actual installer without root, network, or mail services."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "Linux/POSIX Bash required")
class StagedInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="radar install ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stage = self.root / "stage"
        self.env = dict(os.environ, DESTDIR=str(self.stage), PREFIX="/opt/radar app")

    def install(self, **kwargs):
        return subprocess.run(
            ["bash", str(kwargs.get("repo", REPO) / "install.sh")],
            env=kwargs.get("env", self.env), cwd=self.root,
            text=True, capture_output=True, timeout=20,
        )

    def test_install_from_unrelated_working_directory_with_spaces(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        prefix = self.stage / "opt/radar app"
        self.assertTrue((prefix / "lib/mail-radar/mailradar/cli.py").is_file())
        for name in ("mail-radar", "miab-radar"):
            launcher = prefix / "bin" / name
            self.assertEqual(launcher.stat().st_mode & 0o777, 0o755)
            run = subprocess.run(
                [str(launcher), "--help"], cwd=self.root,
                env=dict(os.environ, PYTHONPATH="/nonexistent"),
                text=True, capture_output=True, timeout=10,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("--diagnose", run.stdout)
        self.assertEqual((prefix / "lib/mail-radar/mailradar/cli.py").stat().st_mode & 0o777, 0o644)
        self.assertFalse((prefix / "bin/miab-radar.sh").exists())

    def test_compatibility_launcher_matches_new_version(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        bindir = self.stage / "opt/radar app/bin"
        outputs = []
        for name in ("mail-radar", "miab-radar"):
            run = subprocess.run([str(bindir / name), "--version"], text=True,
                                 capture_output=True, timeout=10, cwd=self.root)
            self.assertEqual(run.returncode, 0, run.stderr)
            outputs.append(run.stdout)
        self.assertEqual(outputs[0], outputs[1])

    def test_source_update_requires_reinstall_to_upgrade_global_copy(self):
        source = self.root / "source checkout"
        source.mkdir()
        for name in ("install.sh", "mail-radar", "miab-radar"):
            shutil.copyfile(REPO / name, source / name)
        shutil.copytree(REPO / "mailradar", source / "mailradar",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        package_version = source / "mailradar/__init__.py"
        package_version.write_text('__version__ = "0.0.1"\n', encoding="utf-8")
        first = self.install(repo=source)
        self.assertEqual(first.returncode, 0, first.stderr)
        bindir = self.stage / "opt/radar app/bin"

        def version(launcher):
            run = subprocess.run(["bash", str(launcher), "--version"], cwd=self.root,
                                 text=True, capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            return run.stdout.strip()

        self.assertEqual(version(bindir / "mail-radar"), "MailRadar 0.0.1")
        package_version.write_text('__version__ = "0.0.200"\n', encoding="utf-8")
        self.assertEqual(version(source / "mail-radar"), "MailRadar 0.0.200")
        self.assertEqual(version(bindir / "mail-radar"), "MailRadar 0.0.1")
        upgraded = self.install(repo=source)
        self.assertEqual(upgraded.returncode, 0, upgraded.stderr)
        for name in ("mail-radar", "miab-radar"):
            self.assertEqual(version(bindir / name), "MailRadar 0.0.200")

    def test_same_size_same_timestamp_upgrade_cannot_load_old_bytecode(self):
        source = self.root / "source checkout"
        source.mkdir()
        for name in ("install.sh", "mail-radar", "miab-radar"):
            shutil.copyfile(REPO / name, source / name)
        shutil.copytree(REPO / "mailradar", source / "mailradar",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        source_init = source / "mailradar/__init__.py"
        source_init.write_text('__version__ = "0.0.1"\n', encoding="utf-8")
        first = self.install(repo=source)
        self.assertEqual(first.returncode, 0, first.stderr)
        prefix = self.stage / "opt/radar app"
        launcher = prefix / "bin/mail-radar"
        installed_init = prefix / "lib/mail-radar/mailradar/__init__.py"

        def version():
            run = subprocess.run(["bash", str(launcher), "--version"], cwd=self.root,
                                 text=True, capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            return run.stdout.strip()

        self.assertEqual(version(), "MailRadar 0.0.1")
        stamp = installed_init.stat().st_mtime_ns
        cache = installed_init.parent / "__pycache__"
        self.assertTrue(list(cache.glob("__init__.*.pyc")), "regression requires old compiled bytecode")
        unrelated = cache / "unrelated.cpython-test.pyc"
        unrelated.write_bytes(b"unrelated file must remain")
        source_init.write_text('__version__ = "0.0.2"\n', encoding="utf-8")
        upgraded = self.install(repo=source)
        self.assertEqual(upgraded.returncode, 0, upgraded.stderr)
        # Deterministic simulation of copying an equal-length source within the
        # timestamp granularity used by Python's timestamp-based .pyc headers.
        os.utime(installed_init, ns=(stamp, stamp))
        self.assertEqual(version(), "MailRadar 0.0.2")
        self.assertEqual(unrelated.read_bytes(), b"unrelated file must remain")

    def test_installer_refuses_symlinked_bytecode_cache_directory(self):
        first = self.install()
        self.assertEqual(first.returncode, 0, first.stderr)
        package = self.stage / "opt/radar app/lib/mail-radar/mailradar"
        victim = self.root / "unrelated-cache"
        victim.mkdir()
        sentinel = victim / "__init__.cpython-test.pyc"
        sentinel.write_bytes(b"unchanged")
        (package / "__pycache__").symlink_to(victim, target_is_directory=True)
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink", result.stderr)
        self.assertEqual(sentinel.read_bytes(), b"unchanged")
        self.assertTrue((package / "__pycache__").is_symlink())

    def test_installed_launcher_ignores_untrusted_cwd_and_pythonpath(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        untrusted = self.root / "untrusted cwd"
        package = untrusted / "mailradar"
        package.mkdir(parents=True)
        marker = untrusted / "unexpected-import-marker"
        (package / "__init__.py").write_text(
            "from pathlib import Path\nPath('unexpected-import-marker').write_text('executed')\n",
            encoding="utf-8",
        )
        (package / "cli.py").write_text("print('hijacked')\n", encoding="utf-8")
        bindir = self.stage / "opt/radar app/bin"
        for name in ("mail-radar", "miab-radar"):
            run = subprocess.run(
                [str(bindir / name), "--version"], cwd=untrusted,
                env=dict(os.environ, PYTHONPATH=str(untrusted)),
                text=True, capture_output=True, timeout=10,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("MailRadar", run.stdout)
            self.assertNotIn("hijacked", run.stdout)
            self.assertFalse(marker.exists(), "launcher imported the caller's package")

    def test_symlink_destination_is_not_overwritten(self):
        bindir = self.stage / "opt/radar app/bin"
        bindir.mkdir(parents=True)
        victim = self.root / "unrelated-file"
        victim.write_text("unchanged", encoding="utf-8")
        (bindir / "mail-radar").symlink_to(victim)
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink", result.stderr)
        self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")
        self.assertFalse((bindir / "miab-radar").exists())

    def test_symlink_parent_is_rejected(self):
        self.stage.mkdir()
        external = self.root / "unrelated-dir"
        external.mkdir()
        (self.stage / "opt").symlink_to(external, target_is_directory=True)
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(external.iterdir()), [])

    def test_relative_prefix_is_rejected(self):
        result = self.install(env=dict(self.env, PREFIX="relative"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("absolute", result.stderr)
        self.assertFalse(self.stage.exists())

    def test_missing_real_source_fails_before_install(self):
        repo = self.root / "incomplete source"
        repo.mkdir()
        shutil.copyfile(REPO / "install.sh", repo / "install.sh")
        result = self.install(repo=repo)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing", result.stderr)
        self.assertFalse(self.stage.exists())


if __name__ == "__main__":
    unittest.main()
