"""Reject known invalid RI receipt destinations before enrollment or activation."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()


class RepositoryIntelligenceOutputTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.project = self.base / "project"
        (self.project / "src").mkdir(parents=True)
        (self.project / "README.md").write_text("# Synthetic project\n", encoding="utf-8")
        (self.project / "src/app.py").write_text('def health():\n    return "synthetic"\n', encoding="utf-8")
        self.environment = {key: value for key, value in os.environ.items()
                            if not key.startswith(("GIT_", "GITHUB_", "NAOS_PR_"))}
        self.environment.pop("NAOS_ROOT", None)
        for arguments in (("init",), ("config", "user.name", "Synthetic Reviewer"),
                          ("config", "user.email", "synthetic@example.invalid"),
                          ("add", "."), ("commit", "--no-gpg-sign", "-m", "synthetic base")):
            result = subprocess.run(["git", *arguments], cwd=self.project, env=self.environment,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.sequence = 0

    def snapshot(self):
        return {path.relative_to(self.project).as_posix():
                hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "directory"
                for path in sorted(self.project.rglob("*"))}

    def cli(self, operation, *options, expected_exit=0):
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/naos_repository_intelligence.py"),
             operation, str(self.project), "--profile", "standard", *map(str, options)],
            cwd=self.project, env=self.environment, capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(result.returncode, expected_exit, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        return result

    def plan(self, expected_status):
        self.sequence += 1
        path = self.base / f"plan-{self.sequence}.json"
        result = self.cli("plan", "--component-mode", "baseline", "--output", path)
        report = json.loads(result.stdout)
        self.assertEqual(report, json.loads(path.read_text(encoding="utf-8")))
        self.assertEqual(report["status"], expected_status)
        return ("--plan", path, "--confirm-plan-sha256", report["plan_sha256"],
                "--reviewer-id", "synthetic")

    def assert_refusal_preserves(self, operation, plan, output):
        before = self.snapshot()
        result = self.cli(operation, *plan, "--output", output, expected_exit=2)
        self.assertIn("Repository intelligence refused:", result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(result.stdout, "")

    def test_existing_receipt_refuses_without_mutation_and_same_plan_remains_usable(self):
        existing = self.base / "existing.json"
        existing.write_bytes(b"preserve existing evidence\n")
        for operation, status in (("enroll", "enrollment_required"), ("apply", "confirmation_required")):
            with self.subTest(operation=operation):
                plan = self.plan(status)
                self.assert_refusal_preserves(operation, plan, existing)
                self.assertEqual(existing.read_bytes(), b"preserve existing evidence\n")
                # No replanning is needed after a pre-mutation refusal.
                report = json.loads(self.cli(operation, *plan).stdout)
                self.assertNotIn(report["status"], {"blocked", "recovery_required", "invalid"})
        active = self.project / ".naos/upgrade-v1/state/repository-intelligence/active.json"
        self.assertTrue(active.is_file())
        self.assertEqual((self.project / "README.md").read_text(encoding="utf-8"), "# Synthetic project\n")

    def test_existing_directory_internal_and_bad_ancestor_outputs_refuse_before_mutation(self):
        directory = self.base / "existing-directory"
        directory.mkdir()
        regular = self.base / "regular-parent"
        regular.write_bytes(b"preserve parent\n")
        outputs = (directory, self.project / "receipt.json", regular / "receipt.json")
        for operation, status in (("enroll", "enrollment_required"), ("apply", "confirmation_required")):
            plan = self.plan(status)
            for output in outputs:
                with self.subTest(operation=operation, output=str(output)):
                    self.assert_refusal_preserves(operation, plan, output)
                    self.assertEqual(regular.read_bytes(), b"preserve parent\n")
                    self.assertEqual(list(directory.iterdir()), [])
            self.cli(operation, *plan)

    def test_fresh_external_receipts_and_missing_output_keep_successful_operations(self):
        for operation, status in (("enroll", "enrollment_required"), ("apply", "confirmation_required")):
            with self.subTest(operation=operation):
                plan = self.plan(status)
                output = self.base / operation / "nested" / "receipt.json"
                self.assertFalse(output.parent.exists())
                report = json.loads(self.cli(operation, *plan, "--output", output).stdout)
                raw = output.read_bytes()
                self.assertEqual(report, json.loads(raw))
                self.assertIn("schema", report)
                self.assert_refusal_preserves(operation, plan, output)
                self.assertEqual(output.read_bytes(), raw)
        self.assertEqual(json.loads(self.cli("validate").stdout)["status"], "validated_current")
