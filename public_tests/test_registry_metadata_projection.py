"""Supported registry metadata survives actual refresh without partial crashes."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator
import yaml


ROOT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
SCRIPT = ROOT / "scripts/workflows/sync_from_registry.py"
SCHEMA = json.loads((ROOT / "schemas/naos/task_registry.schema.json").read_text(encoding="utf-8"))
TAGS = ("SYNC_EXEC_METRICS", "SYNC_MILESTONE_GATES", "SYNC_WORK_BREAKDOWN",
        "SYNC_METRICS_SUMMARY", "SYNC_BUDGET")


class RegistryMetadataProjectionTests(unittest.TestCase):
    def project(self, updates=None, *, governance_root="naos"):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        project = Path(temporary.name).resolve()
        governance = project / governance_root
        governance.mkdir()
        shutil.copytree(ROOT / "templates/spec-kit/specs", project / "specs")
        registry = yaml.safe_load((ROOT / "templates/structural-seeds/naos/TASK_REGISTRY.yaml").read_text(encoding="utf-8"))
        if updates:
            registry["tasks"][0].update(updates)
        self.save_registry(governance, registry)
        (governance / "BACKLOG.md").write_text("Original backlog\n", encoding="utf-8")
        (governance / "DASHBOARD.md").write_text("Manual dashboard\n**Task Completion**: 0/5 tasks (0%)\n", encoding="utf-8")
        (governance / "PROJECT_STATUS.md").write_text(
            "Manual preamble.\n" + "\n".join(
                f"<!-- BEGIN {tag} -->\nold projection\n<!-- END {tag} -->" for tag in TAGS
            ) + "\nManual journal remains.\n", encoding="utf-8")
        return project, governance, registry

    def save_registry(self, governance, registry):
        Draft202012Validator(SCHEMA).validate(registry)
        (governance / "TASK_REGISTRY.yaml").write_text(yaml.safe_dump(registry, sort_keys=False), encoding="utf-8")

    def run_sync(self, project, *flags, governance_root="naos"):
        environment = dict(os.environ, NAOS_ROOT=governance_root, PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run([sys.executable, "-B", str(SCRIPT), *flags], cwd=project,
                              env=environment, capture_output=True, text=True, encoding="utf-8", timeout=60)

    def succeeded(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def snapshot(self, project):
        return {p.relative_to(project).as_posix(): (p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns)
                for p in project.rglob("*") if p.is_file()}

    def test_null_owner_is_unspecified_without_inventing_an_owner(self):
        project, governance, _ = self.project({"owner": None})
        before = (governance / "TASK_REGISTRY.yaml").read_bytes()
        self.succeeded(self.run_sync(project))
        execution = (project / "specs/10-execution.md").read_text(encoding="utf-8")
        row = next(line for line in execution.splitlines() if line.startswith("| T-001 |"))
        self.assertEqual(row.split("|")[7].strip(), "—")
        self.assertEqual((governance / "TASK_REGISTRY.yaml").read_bytes(), before)

    def test_numeric_string_estimate_has_numeric_budget_not_repeated_text(self):
        for value in ("2", "0", "0.5", "-0.5"):
            with self.subTest(value=value):
                project, governance, registry = self.project({"estimate_days": value})
                before = (governance / "TASK_REGISTRY.yaml").read_bytes()
                expected = sum(float(task["estimate_days"]) for task in registry["tasks"])
                self.succeeded(self.run_sync(project))
                status = (governance / "PROJECT_STATUS.md").read_text(encoding="utf-8")
                self.assertIn(f"**Total Estimate**: {expected * 8:.0f} hours ({expected:.0f} days)", status)
                self.assertIn(f"| **Hours (total)** | {expected * 8:.0f}h | 0h | {expected * 8:.0f}h |", status)
                self.assertEqual((governance / "TASK_REGISTRY.yaml").read_bytes(), before)

    def test_mixed_numeric_named_and_absent_phases_keep_distinct_identities(self):
        project, governance, registry = self.project()
        phases = (1, "1", "2.5", "2a", None)
        for task, phase in zip(registry["tasks"], phases):
            task["phase"] = phase
        self.save_registry(governance, registry)
        before = (governance / "TASK_REGISTRY.yaml").read_bytes()
        self.succeeded(self.run_sync(project))
        execution = (project / "specs/10-execution.md").read_text(encoding="utf-8")
        for identifier, phase in (("T-001", "1"), ("T-002", "1"), ("T-003", "2.5"), ("T-004", "2a"), ("T-005", "—")):
            row = next(line for line in execution.splitlines() if line.startswith("| " + identifier + " |"))
            self.assertEqual(row.split("|")[3].strip(), phase)
        self.assertLess(execution.index("| T-003 |"), execution.index("| T-004 |"))
        self.assertLess(execution.index("| T-004 |"), execution.index("| T-005 |"))
        status = (governance / "PROJECT_STATUS.md").read_text(encoding="utf-8")
        self.assertIn("| 1 | Phase 1 | TBD | 2 | 0 |", status)
        self.assertIn("| 2 | Phase 2 | TBD | 1 | 0 |", status)
        self.assertIn("| 2a | Phase 2a | TBD | 1 | 0 |", status)
        self.assertNotIn("Phase 99", status)
        self.assertIn("**Tasks without a declared phase**: T-005", status)
        self.assertEqual((governance / "TASK_REGISTRY.yaml").read_bytes(), before)

    def test_unusable_estimates_refuse_before_any_derived_file_write(self):
        for value in (None, True, [], {}, "TBD", "NaN", "Infinity"):
            with self.subTest(value=value):
                project, _, _ = self.project({"estimate_days": value})
                before = self.snapshot(project)
                result = self.run_sync(project)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertIn("T-001", result.stderr)
                self.assertIn("estimate_days", result.stderr)
                self.assertEqual(self.snapshot(project), before)

    def test_team_preview_is_noop_and_repeat_execution_preserves_content(self):
        project, governance, registry = self.project({"phase": "2a", "owner": None, "estimate_days": "2"}, governance_root="pm")
        registry["team_config"] = {"enabled": True, "assignment_mode": "task_scope",
                                   "teams": [{"id": "core", "scope": ["T-001"]}]}
        self.save_registry(governance, registry)
        before = self.snapshot(project)
        result = self.run_sync(project, "--team", "core", governance_root="pm")
        self.succeeded(result)
        self.assertEqual(json.loads(result.stdout.strip().splitlines()[-1])["tasks"][0]["id"], "T-001")
        self.assertEqual(self.snapshot(project), before)
        self.succeeded(self.run_sync(project, governance_root="pm"))
        execution = project / "specs/10-execution.md"
        before = execution.read_bytes()
        self.succeeded(self.run_sync(project, "--execution", governance_root="pm"))
        self.assertEqual(execution.read_bytes(), before)
        status = (governance / "PROJECT_STATUS.md").read_text(encoding="utf-8")
        self.assertTrue(status.startswith("Manual preamble.\n"))
        self.assertTrue(status.endswith("Manual journal remains.\n"))

    def test_existing_omitted_defaults_and_missing_targets_are_preserved(self):
        project, governance, registry = self.project()
        registry["tasks"][0].pop("owner")
        registry["tasks"][0].pop("estimate_days")
        self.save_registry(governance, registry)
        self.succeeded(self.run_sync(project, "--execution"))
        row = next(line for line in (project / "specs/10-execution.md").read_text(encoding="utf-8").splitlines()
                   if line.startswith("| T-001 |"))
        self.assertEqual(row.split("|")[7].strip(), "Eng")
        for relative, flag in (("specs/10-execution.md", "--execution"), ("naos/DASHBOARD.md", "--dashboard"),
                               ("naos/PROJECT_STATUS.md", "--project-status")):
            (project / relative).unlink()
            before = self.snapshot(project)
            self.succeeded(self.run_sync(project, flag))
            self.assertEqual(self.snapshot(project), before)


if __name__ == "__main__":
    unittest.main()
