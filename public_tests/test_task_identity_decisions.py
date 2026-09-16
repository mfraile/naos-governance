"""Portable N01/N05 regression tests, using disposable public CLI fixtures.

Run with ``python -B public_tests/test_task_identity_decisions.py``. Set
NAOS_TEST_KIT to an installed package directory to exercise that candidate.
All human decisions are synthetic test declarations, never real approval.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

KIT = Path(
    os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])
).resolve()
sys.path.insert(0, str(KIT / "scripts"))
from naos_task_lifecycle import complete_task  # noqa: E402


def write(root, path, value):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        value if isinstance(value, str) else yaml.safe_dump(value, sort_keys=False)
    )


def protected(root):
    paths = [root / "naos/TASK_REGISTRY.yaml", root / "naos/completed_history.yaml"]
    paths.extend((root / "specs").glob("*.md"))
    paths.extend(
        root / "naos" / name for name in ("BACKLOG.md", "DASHBOARD.md", "EXECUTION.md")
    )
    for folder in ("active", "completed"):
        paths.extend((root / "naos" / folder).glob("*.md"))
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in paths
        if path.is_file()
    }


class TaskIdentityDecisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="naos-identity-regression-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        for name in ("NAOS_ROOT", "NAOS_PROFILE"):
            self.env.pop(name, None)

    def cli(self, root, command, *args, profile="standard"):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(KIT / "cli.py"),
                command,
                "--profile",
                profile,
                *args,
                "--json",
            ],
            cwd=root,
            env=self.env,
            capture_output=True,
            check=False,
            text=True,
            timeout=90,
        )
        try:
            data = json.loads(result.stdout)
        except ValueError:
            data = None
        return result, data

    def fixture(self, root, target="T-002", other="T-001"):
        write(
            root,
            "src/health.py",
            f'''"""
Module:
    src/health.py
Purpose:
    Return local fixture health.
Implements:
    FR-001
Tasks:
    {target}
Specs:
    specs/03-requirements.md#fr-001
Rationale:
    Deterministic fixture only.
"""
def health():
    return "ok"
''',
        )
        write(
            root,
            "tests/test_health.py",
            '''import unittest
from src.health import health
class HealthTest(unittest.TestCase):
    def test_health(self):
        """AC-001-1: Health returns ok."""
        self.assertEqual(health(), "ok")
''',
        )
        write(
            root,
            "specs/03-requirements.md",
            "# Requirements\n\n## FR-001\nReturn health.\n",
        )
        write(
            root,
            "specs/06-acceptance.md",
            "# Acceptance\n\n## AC-001-1\nHealth is ok.\n",
        )
        tasks = [
            {
                "id": task,
                "title": "Fixture health",
                "requirement": "FR-001",
                "phase": 1,
                "priority": "P1",
                "status": "in_progress",
                "lifecycle_state": "active",
                "delivery_state": "in_progress",
                "verification_state": "unverified",
                "estimate_days": 1,
                "dependencies": [target] if task == other else [],
            }
            for task in (other, target)
        ]
        write(
            root,
            "naos/TASK_REGISTRY.yaml",
            {"schema": "naos.task_registry.v2", "tasks": tasks},
        )
        for task in (other, target):
            write(
                root,
                f"naos/active/{task}_health.md",
                f"# Active Task: {task} - Fixture\n\n"
                f"## Quick Reference\n| Field | Value |\n|---|---|\n| **Task ID** | {task} |\n"
                f"| **Related Tasks** | {target if task == other else 'None'} |\n\n"
                "## Acceptance Criteria\n- [x] AC-001-1: Health returns ok.\n",
            )
        result = subprocess.run(
            [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"],
            cwd=root,
            env=self.env,
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        write(root, "naos/reports/tests.txt", result.stdout + result.stderr)
        decision = {
            "schema": "naos.human_decision_record.v1",
            "decision_id": "DECISION-FIXTURE",
            "decision_type": "task_delivery",
            "outcome": "approved",
            "subject_refs": [target],
            "evidence_refs": ["naos/reports/tests.txt"],
            "decided_by": "Synthetic Fixture Reviewer",
            "decided_at": "2026-09-16T12:00:00Z",
            "rationale": "Actual local test passed.",
            "authority_scope": "This synthetic fixture only.",
            "supersedes": None,
            "not_claimed": ["No genuine human approval or authentication."],
        }
        write(root, "naos/human_decisions/DECISION-FIXTURE.yaml", decision)
        return decision

    def options(self, target="T-002", state="verified"):
        return [
            "--task",
            target,
            "--verification-state",
            state,
            "--test-ref",
            "tests/test_health.py",
            "--evidence-ref",
            "naos/reports/tests.txt",
            "--decision-ref",
            "naos/human_decisions/DECISION-FIXTURE.yaml",
        ]

    def test_generated_profiles_context_completion_recovery(self):
        for profile in ("quickstart", "lite", "standard", "assured"):
            with self.subTest(profile=profile):
                project = self.root / profile
                command = [
                    sys.executable,
                    "-B",
                    str(KIT / "cli.py"),
                    "init",
                    str(self.root / (profile + "-absent")),
                    "--new",
                    "--tier",
                    profile,
                    "--memory",
                    "disabled",
                    "--preview-dir",
                    str(project),
                ]
                if profile != "quickstart":
                    command.extend(
                        ["--archetype", "custom", "--backend", "static_only"]
                    )
                generated = subprocess.run(
                    command,
                    cwd=self.root,
                    env=self.env,
                    capture_output=True,
                    check=False,
                    text=True,
                    timeout=90,
                )
                self.assertEqual(
                    generated.returncode, 0, generated.stdout + generated.stderr
                )
                self.fixture(project)
                before = protected(project)
                _, context = self.cli(
                    project,
                    "task-context",
                    "--task",
                    "T-002",
                    "--recovery-mode",
                    "active",
                    profile=profile,
                )
                self.assertIsNotNone(context)
                self.assertEqual(
                    Path(context["task_resolution"]["selected_card_path"]).name,
                    "T-002_health.md",
                )
                result, preview = self.cli(
                    project,
                    "task-complete",
                    *self.options(),
                    "--dry-run",
                    profile=profile,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(preview["mutated"])
                self.assertEqual(protected(project), before)
                result, report = self.cli(
                    project, "task-complete", *self.options(), profile=profile
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue(report["mutated"])
                self.assertTrue((project / "naos/active/T-001_health.md").is_file())
                self.assertFalse((project / "naos/active/T-002_health.md").exists())
                self.assertEqual(
                    (project / "naos/completed/T-002_health.md").read_bytes(),
                    before["naos/active/T-002_health.md"],
                )
                registry = yaml.safe_load(
                    (project / "naos/TASK_REGISTRY.yaml").read_text()
                )
                self.assertEqual(registry["tasks"][0]["lifecycle_state"], "active")
                self.assertEqual(registry["tasks"][1]["delivery_state"], "delivered")
                result, recovered = self.cli(
                    project,
                    "task-lifecycle",
                    "--task",
                    "T-002",
                    "--recovery-mode",
                    "completed",
                    profile=profile,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(
                    Path(recovered["task_resolution"]["selected_card_path"]).name,
                    "T-002_health.md",
                )

    def test_invalid_ownership_and_decisions_preserve_state(self):
        for variant in (
            "duplicate_card",
            "mismatched_owner",
            "duplicate_registry",
            "wrong_decision",
            "placeholder",
            "missing_decision",
        ):
            with self.subTest(variant=variant):
                root = self.root / variant
                self.fixture(root)
                if variant == "duplicate_card":
                    shutil.copy(
                        root / "naos/active/T-002_health.md",
                        root / "naos/active/T-002_duplicate.md",
                    )
                elif variant == "mismatched_owner":
                    write(
                        root,
                        "naos/active/T-002_health.md",
                        "# Active Task: T-001\n| **Task ID** | T-001 |\n",
                    )
                elif variant == "duplicate_registry":
                    path = root / "naos/TASK_REGISTRY.yaml"
                    data = yaml.safe_load(path.read_text())
                    data["tasks"].append(copy.deepcopy(data["tasks"][1]))
                    write(root, path, data)
                elif variant == "missing_decision":
                    (root / "naos/human_decisions/DECISION-FIXTURE.yaml").unlink()
                else:
                    path = root / "naos/human_decisions/DECISION-FIXTURE.yaml"
                    data = yaml.safe_load(path.read_text())
                    data.update(
                        subject_refs=["T-001"]
                    ) if variant == "wrong_decision" else data.update(decided_by="TBD")
                    write(root, path, data)
                before = protected(root)
                for dry in ([], ["--dry-run"]):
                    result, report = self.cli(
                        root, "task-complete", *self.options(), *dry
                    )
                    self.assertEqual(
                        result.returncode, 2, result.stdout + result.stderr
                    )
                    self.assertFalse(report["mutated"])
                    self.assertEqual(protected(root), before)

    def test_namespaced_unverified_sort_order_and_rollback(self):
        for other in ("LKB-T-001", "LKB-T-003"):
            root = self.root / other
            self.fixture(root, target="LKB-T-002", other=other)
            before = protected(root)
            result, report = self.cli(
                root, "task-complete", *self.options("LKB-T-002", "unverified")
            )
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertTrue(report["human_review_required"])
            self.assertEqual(
                (root / "naos/completed/LKB-T-002_health.md").read_bytes(),
                before["naos/active/LKB-T-002_health.md"],
            )
            self.assertTrue((root / f"naos/active/{other}_health.md").exists())
        root = self.root / "rollback"
        self.fixture(root)
        before = protected(root)
        with (
            patch(
                "naos_task_lifecycle.os.replace",
                side_effect=OSError("fixture write failure"),
            ),
            self.assertRaises(OSError),
        ):
            complete_task(
                root=root,
                naos_root="naos",
                profile="standard",
                task_id="T-002",
                completion_provenance="Synthetic rollback regression",
                completed_by="Synthetic Fixture",
                verification_state="unverified",
                implementation_refs=[],
                test_refs=[],
                evidence_refs=[],
                decision_refs=[],
                unresolved_risks=[],
                dry_run=False,
            )
        self.assertEqual(protected(root), before)

    def test_persisted_identity_rejects_recovery_and_sync(self):
        self.fixture(self.root)
        result, _ = self.cli(self.root, "task-complete", *self.options())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        history_path = self.root / "naos/completed_history.yaml"
        history = yaml.safe_load(history_path.read_text())
        history["records"][0]["completed_card_path"] = "naos/active/T-001_health.md"
        write(self.root, history_path, history)
        before = protected(self.root)
        for command in ("task-lifecycle", "task-context", "session-start"):
            result, _ = self.cli(
                self.root, command, "--task", "T-002", "--recovery-mode", "completed"
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(protected(self.root), before)
        for script in ("sync_from_registry.py", "sync_spec_statuses.py"):
            result = subprocess.run(
                [sys.executable, "-B", str(KIT / "scripts/workflows" / script)],
                cwd=self.root,
                env=self.env,
                capture_output=True,
                check=False,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("identity", (result.stdout + result.stderr).lower())
            self.assertEqual(protected(self.root), before)

    def test_history_ambiguity_digest_and_pruned_compatibility(self):
        self.fixture(self.root)
        result, _ = self.cli(self.root, "task-complete", *self.options())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        history_path = self.root / "naos/completed_history.yaml"
        history = yaml.safe_load(history_path.read_text())
        for variant in (
            "duplicate_history",
            "mismatched_path",
            "wrong_digest",
            "bad_record",
            "bad_container",
        ):
            with self.subTest(variant=variant):
                modified = copy.deepcopy(history)
                if variant == "duplicate_history":
                    modified["records"].append(copy.deepcopy(modified["records"][0]))
                elif variant == "mismatched_path":
                    modified["records"][0]["completed_card_path"] = (
                        "naos/completed/T-001_absent.md"
                    )
                elif variant == "wrong_digest":
                    modified["records"][0]["active_record_digest"]["value"] = "0" * 64
                elif variant == "bad_record":
                    modified["records"][0].pop("task_id")
                else:
                    modified["records"] = {}
                write(self.root, history_path, modified)
                before = protected(self.root)
                result, _ = self.cli(
                    self.root,
                    "task-lifecycle",
                    "--task",
                    "T-002",
                    "--recovery-mode",
                    "completed",
                )
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(protected(self.root), before)
        write(self.root, history_path, history)
        (self.root / "naos/completed/T-002_health.md").unlink()
        result, recovered = self.cli(
            self.root,
            "task-lifecycle",
            "--task",
            "T-002",
            "--recovery-mode",
            "completed",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(recovered["status"], "completed_task")

    def test_native_composed_decision_corruption_and_downstream(self):
        def git(*args):
            result = subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Synthetic Fixture Reviewer",
                    "-c",
                    "user.email=fixture@example.invalid",
                    *args,
                ],
                cwd=self.root,
                env=self.env,
                capture_output=True,
                check=False,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result.stdout.strip()

        git("init", "-q")
        git("commit", "-q", "--allow-empty", "-m", "Synthetic empty fixture baseline")
        base_commit = git("rev-parse", "HEAD")
        self.fixture(self.root, target="T-002")
        registry = yaml.safe_load((self.root / "naos/TASK_REGISTRY.yaml").read_text())
        registry["tasks"] = registry["tasks"][1:]
        write(self.root, "naos/TASK_REGISTRY.yaml", registry)
        for command in ("module-headers", "test-evidence-map"):
            result, _ = self.cli(self.root, command)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        git("add", "src", "tests", "specs", "naos")
        git("commit", "-q", "-m", "Implement and test synthetic health fixture")
        binding = {
            "base_commit": base_commit,
            "subject_commit": git("rev-parse", "HEAD"),
            "subject_tree": git("rev-parse", "HEAD^{tree}"),
        }
        write(
            self.root,
            "naos/ac_completion_evidence.yaml",
            {
                "schema": "naos.ac_completion_evidence_manifest.v1",
                "version": "1.0",
                "completions": [
                    {
                        "ac_id": "AC-001-1",
                        "record_id": "ACE-FIXTURE",
                        "status": "claimed_complete",
                        "repository_binding": binding,
                        "source_ref": "specs/06-acceptance.md#AC-001-1",
                        "evidence": [
                            {
                                "type": "command_output",
                                "path": "naos/reports/tests.txt",
                                "command": "python -m unittest tests/test_health.py -v",
                                "outcome": "pass",
                                "generated_at": "2026-09-16T12:00:00Z",
                            }
                        ],
                    }
                ],
            },
        )
        result, ac_report = self.cli(self.root, "ac-completion-evidence")
        self.assertEqual(ac_report["status"], "pass", ac_report)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result, _ = self.cli(self.root, "task-complete", *self.options())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result, baseline = self.cli(self.root, "composed-traceability")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            baseline["chains"][0]["qualifications"]["attributable_decision"], "recorded"
        )
        self.assertEqual(
            baseline["chains"][0]["qualification_level"], "structural_only"
        )
        baseline_decision = yaml.safe_load(
            (self.root / "naos/human_decisions/DECISION-FIXTURE.yaml").read_text()
        )
        for variant in (
            "timestamp",
            "placeholder",
            "required_field",
            "type",
            "wrong_task",
            "wrong_evidence",
            "schema",
        ):
            with self.subTest(variant=variant):
                decision = copy.deepcopy(baseline_decision)
                if variant == "required_field":
                    decision.pop("rationale")
                else:
                    field, value = {
                        "timestamp": ("decided_at", "not-a-date"),
                        "placeholder": ("decided_by", "TBD"),
                        "type": ("decision_type", "evidence_admission"),
                        "wrong_task": ("subject_refs", ["T-001"]),
                        "wrong_evidence": ("evidence_refs", ["src/health.py"]),
                        "schema": ("schema", "wrong.v1"),
                    }[variant]
                    decision[field] = value
                write(self.root, "naos/human_decisions/DECISION-FIXTURE.yaml", decision)
                before = protected(self.root)
                _, report = self.cli(self.root, "composed-traceability")
                self.assertTrue(report["human_review_required"], variant)
                self.assertEqual(
                    report["chains"][0]["qualifications"]["attributable_decision"],
                    "unresolved",
                )
                self.assertEqual(protected(self.root), before)


if __name__ == "__main__":
    unittest.main()
