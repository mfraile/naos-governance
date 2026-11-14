"""G1 dashboard outputs retain exact history while refusing aliased writes."""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime
import importlib.util
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(KIT / "scripts"))
SPEC = importlib.util.spec_from_file_location("_dashboard_output_safety", KIT / "scripts/workflows/generate_naos_dashboard.py")
DASHBOARD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DASHBOARD
SPEC.loader.exec_module(DASHBOARD)
HEADER = b"timestamp,done_percent,done,in_progress,total\n"
NOW = datetime(2026, 10, 19, 12, tzinfo=UTC)


class DashboardOutputWriteSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-dashboard-output-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.history = self.base / "history.csv"
        self.victim = self.base / "outside.csv"
        self.victim.write_bytes(HEADER)

    def append(self, path=None, **options):
        diagnostics = io.StringIO()
        with contextlib.redirect_stderr(diagnostics):
            result = DASHBOARD.append_progress_history(path or self.history, done=1, in_progress=0, total=2,
                                                       now=NOW, **options)
        return result, diagnostics.getvalue()

    def link(self, output, victim, hard=False):
        if hard:
            os.link(victim, output)
        else:
            try:
                output.symlink_to(victim)
            except OSError:
                if os.name != "nt":
                    raise
                os.link(victim, output)

    def directory_alias(self, alias, target):
        if os.name == "nt":
            result = subprocess.run([os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", "mklink", "/J", str(alias), str(target)],
                                    capture_output=True, text=True, check=False, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            alias.symlink_to(target, target_is_directory=True)

    def test_csv_leaf_aliases_refuse_without_changing_victim(self):
        for hard in (False, True):
            with self.subTest(hard=hard):
                self.victim.write_bytes(HEADER)
                self.link(self.history, self.victim, hard)
                try:
                    result, diagnostic = self.append()
                    self.assertEqual(self.victim.read_bytes(), HEADER)
                    self.assertEqual(result, "invalid_history")
                    self.assertIn("PROGRESS_HISTORY_INVALID: history not updated:", diagnostic)
                finally:
                    self.history.unlink()

    def test_csv_parent_alias_refuses_without_changing_history(self):
        directory = self.base / "outside"
        directory.mkdir()
        actual = directory / "history.csv"
        actual.write_bytes(HEADER)
        alias = self.base / "alias"
        self.directory_alias(alias, directory)
        result, diagnostic = self.append(alias / "history.csv")
        self.assertEqual(actual.read_bytes(), HEADER)
        self.assertEqual(result, "invalid_history")
        self.assertIn("PROGRESS_HISTORY_INVALID", diagnostic)

    def test_csv_post_validation_alias_swap_refuses(self):
        original_reader = DASHBOARD._read_progress_history
        for hard in (False, True):
            with self.subTest(hard=hard):
                self.history.write_bytes(HEADER)
                self.victim.write_bytes(HEADER)

                def swap(*args, **kwargs):
                    result = original_reader(*args, **kwargs)
                    self.history.unlink()
                    self.link(self.history, self.victim, hard)
                    return result

                try:
                    with patch.object(DASHBOARD, "_read_progress_history", side_effect=swap):
                        result, diagnostic = self.append()
                    self.assertEqual(self.victim.read_bytes(), HEADER)
                    self.assertEqual(result, "invalid_history")
                    self.assertIn("PROGRESS_HISTORY_INVALID", diagnostic)
                finally:
                    self.history.unlink()

    def test_csv_validated_snapshot_change_is_not_silently_adopted(self):
        self.history.write_bytes(HEADER)
        changed = HEADER + b"2026-10-18T12:00:00+00:00,50.00,1,0,2\n"
        original_reader = DASHBOARD._read_progress_history

        def change(*args, **kwargs):
            result = original_reader(*args, **kwargs)
            self.history.write_bytes(changed)
            return result

        with patch.object(DASHBOARD, "_read_progress_history", side_effect=change):
            result, diagnostic = self.append()
        self.assertEqual(self.history.read_bytes(), changed)
        self.assertEqual(result, "invalid_history")
        self.assertIn("PROGRESS_HISTORY_INVALID", diagnostic)

    def test_csv_new_history_collision_preserves_foreign_file(self):
        original_reader = DASHBOARD._read_progress_history
        foreign = b"foreign occupant\r\n"

        def appear(*args, **kwargs):
            result = original_reader(*args, **kwargs)
            self.history.write_bytes(foreign)
            return result

        with patch.object(DASHBOARD, "_read_progress_history", side_effect=appear):
            result, diagnostic = self.append()
        self.assertEqual(self.history.read_bytes(), foreign)
        self.assertEqual(result, "invalid_history")
        self.assertIn("PROGRESS_HISTORY_INVALID", diagnostic)

    def test_csv_exact_prefix_mode_and_separator_contracts(self):
        prefixes = (
            HEADER,
            HEADER.rstrip(b"\n"),
            HEADER.replace(b"\n", b"\r"),
            b"\xef\xbb\xbftotal,in_progress,done,done_percent,timestamp\r\n# retain comment\r\n2,0,1,50,2026-10-18",
        )
        for raw in prefixes:
            with self.subTest(raw=raw):
                self.history.write_bytes(raw)
                self.history.chmod(0o640)
                result, diagnostic = self.append()
                self.assertEqual(result, "appended", diagnostic)
                separator = b"" if raw.endswith((b"\r", b"\n")) else b"\n"
                row = (b"2,0,1,50.00,2026-10-19T12:00:00+00:00\n" if raw.startswith(b"\xef\xbb\xbf")
                       else b"2026-10-19T12:00:00+00:00,50.00,1,0,2\n")
                self.assertEqual(self.history.read_bytes(), raw + separator + row)
                if os.name == "posix":
                    self.assertEqual(stat.S_IMODE(self.history.stat().st_mode), 0o640)
                before = self.history.stat()
                payload = self.history.read_bytes()
                self.assertEqual(self.append()[0], "already_recorded")
                after = self.history.stat()
                self.assertEqual((after.st_ino, after.st_mtime_ns), (before.st_ino, before.st_mtime_ns))
                self.assertEqual(self.history.read_bytes(), payload)

    def test_csv_missing_parent_stays_absent_and_new_file_is_canonical(self):
        missing = self.base / "missing/history.csv"
        result, diagnostic = self.append(missing)
        self.assertEqual(result, "invalid_history")
        self.assertIn("PROGRESS_HISTORY_INVALID", diagnostic)
        self.assertFalse(missing.parent.exists())
        self.assertEqual(self.append()[0], "appended")
        self.assertEqual(self.history.read_bytes(), HEADER + b"2026-10-19T12:00:00+00:00,50.00,1,0,2\n")

    @unittest.skipUnless(os.name == "posix" and os.geteuid() != 0, "POSIX unprivileged directory permissions")
    def test_csv_nonwritable_parent_refuses_with_original_untouched(self):
        directory = self.base / "locked"
        directory.mkdir()
        history = directory / "history.csv"
        history.write_bytes(HEADER)
        history.chmod(0o600)
        before = history.stat()
        directory.chmod(0o500)
        try:
            result, diagnostic = self.append(history)
            self.assertEqual(result, "invalid_history")
            self.assertIn("PROGRESS_HISTORY_INVALID: history not updated:", diagnostic)
            self.assertEqual(history.read_bytes(), HEADER)
            after = history.stat()
            self.assertEqual((after.st_ino, after.st_mtime_ns), (before.st_ino, before.st_mtime_ns))
            self.assertEqual(stat.S_IMODE(after.st_mode), 0o600)
        finally:
            directory.chmod(0o700)

    @unittest.skipUnless(os.name == "posix", "POSIX symlink/parent traversal semantics")
    def test_parent_alias_before_dotdot_is_not_collapsed(self):
        project = self.project()
        outside = self.base / "outside"
        (outside / "child").mkdir(parents=True)
        (project / "alias").symlink_to(outside / "child", target_is_directory=True)
        local = project / "report.md"
        actual = outside / "report.md"
        local.write_bytes(b"LOCAL\n")
        actual.write_bytes(b"OUTSIDE\n")
        result = subprocess.run(
            [sys.executable, "-B", str(project / "scripts/workflows/generate_naos_dashboard.py"),
             "--profile", "quickstart", "--output", "alias/../report.md", "--no-progress-history"],
            cwd=project, capture_output=True, text=True, timeout=60, check=False)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(local.read_bytes(), b"LOCAL\n")
        self.assertEqual(actual.read_bytes(), b"OUTSIDE\n")
        for path in (project / "history.csv", outside / "history.csv"):
            path.write_bytes(HEADER)
        self.assertEqual(self.append(project / "alias/../history.csv")[0], "invalid_history")
        for path in (project / "history.csv", outside / "history.csv"):
            self.assertEqual(path.read_bytes(), HEADER)
        (project / "ordinary").mkdir()
        DASHBOARD.write_text_output(project / "ordinary/../report.md", "REGULAR\n")
        self.assertEqual(local.read_bytes(), b"REGULAR\n")
        self.assertEqual(self.append(project / "ordinary/../history.csv")[0], "appended")

    def project(self):
        project = self.base / "project"
        project.mkdir()
        shutil.copytree(KIT / "scripts", project / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(KIT / "schemas", project / "schemas")
        shutil.copytree(KIT / "templates/structural-seeds", project / "templates/structural-seeds")
        metadata = project / "scripts/naos_posix_metadata"
        metadata.mkdir()
        for name in ("security.py", "linux_primitives.py"):
            shutil.copy2(KIT / "upgrade_contract" / name, metadata / name)
        shutil.copy2(KIT / "upgrade_contract/windows_handles.py", project / "scripts/naos_windows_handles.py")
        shutil.copy2(KIT / "templates/Makefile.naos", project / "Makefile.naos")
        (project / "naos").mkdir()
        (project / "naos/TASK_REGISTRY.yaml").write_text("tasks: []\n", encoding="utf-8")
        (project / "specs").mkdir()
        (project / "specs/03-requirements.md").write_text("### FR-901: Synthetic fixture\n**Status**: Planned\n", encoding="utf-8")
        return project

    def test_actual_make_markdown_alias_refusal_and_regular_lf_output(self):
        project = self.project()
        output = project / "report.md"
        original = b"SYNTHETIC OUTSIDE MARKDOWN\r\n"
        victim = self.base / "outside.md"
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        for key in ("NAOS_ROOT", "NAOS_POLICY", "NAOS_STRICT", "NAOS_PROFILE", "PYTHONPATH"):
            env.pop(key, None)

        def run():
            executable = shutil.which("make")
            if executable:
                argv = [executable, "-f", "Makefile.naos", "naos-dashboard", "PYTHON=" + sys.executable,
                        "NAOS_COMMON_ARGS=--profile quickstart --output report.md --no-progress-history"]
            else:
                argv = [sys.executable, "-B", str(project / "scripts/workflows/generate_naos_dashboard.py"),
                        "--profile", "quickstart", "--output", "report.md", "--no-progress-history"]
            return subprocess.run(argv, cwd=project, env=env, capture_output=True, text=True, check=False, timeout=60)

        for hard in (False, True):
            with self.subTest(hard=hard):
                victim.write_bytes(original)
                self.link(output, victim, hard)
                try:
                    result = run()
                    self.assertEqual(victim.read_bytes(), original)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                finally:
                    output.unlink()
        output.write_bytes(b"old\n")
        output.chmod(0o640)
        result = run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(b"# Project Dashboard", output.read_bytes())
        self.assertNotIn(b"\r\n", output.read_bytes())
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o640)
        self.assertFalse((project / "naos/TASK_PROGRESS_HISTORY.csv").exists())


if __name__ == "__main__":
    unittest.main()
