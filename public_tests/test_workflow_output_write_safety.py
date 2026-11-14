"""G1 scalar workflow output boundaries in disposable copied-script projects."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
REGISTRY = "tasks:\n  - {id: T-901, title: 'Café fixture', requirement: FR-901, phase: 1, priority: P1, status: in_progress}\n"
MANUAL = """# Café fixture
Manual preamble stays.
### FR-901: Fixture
**Status**: Planned
<!-- BEGIN BACKLOG -->
old backlog
<!-- END BACKLOG -->
<!-- BEGIN TASK_MATRIX -->
| ID | Title | Phase | Type | FR/NFR | Status | Owner | Date | Other | Acceptance |
| T-901 | Café fixture | 1 | feature | FR-901 | Planned | Core | TBD | x | observed |
<!-- END TASK_MATRIX -->
| T-901 | Café fixture | FR-901 | P1 | 1 | Planned |
**Task Completion**: 0/9 tasks (0%)
<!-- BEGIN SYNC_EXEC_METRICS -->
old metrics
<!-- END SYNC_EXEC_METRICS -->
Manual tail stays.
"""


class WorkflowOutputWriteSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-workflow-writes-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.project = self.base / "project"
        self.project.mkdir()
        shutil.copytree(KIT / "scripts", self.project / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(KIT / "schemas", self.project / "schemas")
        shutil.copytree(KIT / "templates/structural-seeds", self.project / "templates/structural-seeds")
        metadata = self.project / "scripts/naos_posix_metadata"
        metadata.mkdir()
        for name in ("security.py", "linux_primitives.py"):
            shutil.copy2(KIT / "upgrade_contract" / name, metadata / name)
        shutil.copy2(KIT / "upgrade_contract/windows_handles.py", self.project / "scripts/naos_windows_handles.py")
        shutil.copy2(KIT / "templates/Makefile.naos", self.project / "Makefile.naos")
        for directory in ("naos", "specs", "src"):
            (self.project / directory).mkdir()
        self.write("naos/TASK_REGISTRY.yaml", REGISTRY)
        self.write("src/fixture.py", "# Implements: FR-901\ndef fixture():\n    return True\n")
        self.reset_outputs()
        self.victim = self.base / "outside.md"
        self.original = MANUAL.encode()
        self.victim.write_bytes(self.original)
        self.env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8",
                    "NAOS_ROOT": "naos", "SRC_ROOT": "src"}
        for key in ("PYTHONPATH", "NAOS_POLICY", "NAOS_STRICT", "NAOS_PROFILE"):
            self.env.pop(key, None)

    def write(self, relative, content):
        path = self.project / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def reset_outputs(self):
        for relative in ("naos/BACKLOG.md", "naos/RELEASE_NOTES.md", "naos/DASHBOARD.md",
                         "naos/PROJECT_STATUS.md", "naos/TRACEABILITY_MATRIX.md",
                         "specs/03-requirements.md", "specs/10-execution.md"):
            self.write(relative, MANUAL)
        self.write("naos/.release_cache.json", "{}")

    def cases(self):
        return (
            ("generate_backlog.py", [], "naos/BACKLOG.md"),
            ("generate_release_notes.py", [], "naos/RELEASE_NOTES.md"),
            ("generate_release_notes.py", [], "naos/.release_cache.json"),
            ("generate_traceability_matrix.py", [], "naos/TRACEABILITY_MATRIX.md"),
            ("sync_from_registry.py", ["--backlog"], "naos/BACKLOG.md"),
            ("sync_from_registry.py", ["--execution"], "specs/10-execution.md"),
            ("sync_from_registry.py", ["--dashboard"], "naos/DASHBOARD.md"),
            ("sync_from_registry.py", ["--project-status"], "naos/PROJECT_STATUS.md"),
            ("sync_spec_statuses.py", ["--requirements-only"], "specs/03-requirements.md"),
            ("sync_spec_statuses.py", ["--execution-only"], "specs/10-execution.md"),
        )

    def cli(self, name, *args):
        return subprocess.run([sys.executable, "-B", str(self.project / "scripts/workflows" / name), *args],
                              cwd=self.project, env=self.env, capture_output=True, text=True,
                              encoding="utf-8", check=False, timeout=30)

    def link(self, output, hard=False):
        output.unlink()
        if hard:
            os.link(self.victim, output)
        else:
            try:
                output.symlink_to(self.victim)
            except OSError:
                if os.name != "nt":
                    raise
                os.link(self.victim, output)

    def test_each_cli_sink_refuses_both_leaf_aliases(self):
        for hard in (False, True):
            for name, flags, relative in self.cases():
                with self.subTest(script=name, flags=flags, output=relative, hard=hard):
                    self.reset_outputs()
                    self.victim.write_bytes(self.original)
                    output = self.project / relative
                    self.link(output, hard)
                    try:
                        result = self.cli(name, *flags)
                        self.assertEqual(self.victim.read_bytes(), self.original, "outside victim changed")
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    finally:
                        output.unlink()
                        self.reset_outputs()

    def test_actual_gov_refresh_refuses_backlog_alias(self):
        output = self.project / "naos/BACKLOG.md"
        self.link(output)
        executable = shutil.which("make")
        if executable is None:
            result = self.cli("sync_from_registry.py")
        else:
            result = subprocess.run([executable, "-f", "Makefile.naos", "gov-refresh", "PYTHON=" + sys.executable],
                                    cwd=self.project, env=self.env, capture_output=True, text=True,
                                    check=False, timeout=60)
        self.assertEqual(self.victim.read_bytes(), self.original, "outside victim changed")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_regular_cli_outputs_preserve_mode_and_expected_content(self):
        for name, flags, relative in self.cases():
            with self.subTest(script=name, flags=flags, output=relative):
                self.reset_outputs()
                output = self.project / relative
                output.chmod(0o640)
                result = self.cli(name, *flags)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                text = output.read_text(encoding="utf-8")
                self.assertIn("T-901" if "requirements" not in relative and "TRACEABILITY" not in relative else "FR-901", text)
                if os.name == "posix":
                    self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o640)
                if name == "generate_traceability_matrix.py":
                    self.assertNotIn(b"\r\n", output.read_bytes())
                if relative == "naos/.release_cache.json":
                    self.assertEqual(output.read_bytes(), '{\n  "T-901": "Planned"\n}'.replace("\n", os.linesep).encode())
                elif name in ("generate_backlog.py", "sync_spec_statuses.py") or flags == ["--execution"]:
                    self.assertIn("Manual preamble stays.", text)
                    self.assertIn("Manual tail stays.", text)

    def test_spec_dry_run_and_unchanged_paths_keep_bytes_inode_and_mtime(self):
        paths = [self.project / relative for relative in ("specs/03-requirements.md", "specs/10-execution.md")]
        before = [(path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns) for path in paths]
        result = self.cli("sync_spec_statuses.py", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([(path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns) for path in paths], before)
        result = self.cli("sync_spec_statuses.py")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        before = [(path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns) for path in paths]
        result = self.cli("sync_spec_statuses.py")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([(path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns) for path in paths], before)


if __name__ == "__main__":
    unittest.main()
