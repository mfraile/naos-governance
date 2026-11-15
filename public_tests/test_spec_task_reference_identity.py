"""Spec-pack task references must retain the documented exact task identity."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator
import yaml


ROOT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(ROOT / "scripts"))
import naos_spec_pack_contract as contract  # noqa: E402

SPECS = ROOT / "templates/spec-kit/specs"
SEED = ROOT / "templates/structural-seeds/naos"
PLAIN = re.compile(r"(?<![\w-])T-[0-9]{3,}(?![\w-])")


class SpecTaskReferenceIdentityTests(unittest.TestCase):
    def setUp(self):
        self.manifest = yaml.safe_load((SPECS / "spec_manifest.yaml").read_text(encoding="utf-8"))
        self.task_rule = next(row for row in self.manifest["traceability_codes"] if row["id"] == "TASK")
        execution = next(row for row in self.manifest["files"] if row["path"] == "10-execution.md")
        self.execution_rule = next(row for row in execution["required_patterns"] if row["id"] == "execution_task_link")
        identity = yaml.safe_load((SEED / "task_lifecycle_contract.yaml").read_text(encoding="utf-8"))["identity"]
        self.canonical = re.compile(identity["namespaced_pattern"])
        self.environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        for name in ("NAOS_ROOT", "SPECS_ROOT"):
            self.environment.pop(name, None)

    def project(self, registry_prefix="", reference_prefix="", digits=3):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        project = Path(temporary.name).resolve()
        shutil.copytree(SPECS, project / "specs")
        (project / "naos").mkdir()
        registry = yaml.safe_load((SEED / "TASK_REGISTRY.yaml").read_text(encoding="utf-8"))
        references = {}
        for task in registry["tasks"]:
            original = task["id"]
            number = int(original.removeprefix("T-"))
            task["id"] = f"{registry_prefix}T-{number:0{digits}d}"
            references[original] = f"{reference_prefix}T-{number:0{digits}d}"
            self.assertIsNotNone(self.canonical.fullmatch(task["id"]))
        for path in (project / "specs").glob("*.md"):
            text = path.read_text(encoding="utf-8")
            path.write_text(PLAIN.sub(lambda match: references.get(match.group(), match.group()), text), encoding="utf-8")
        (project / "naos/TASK_REGISTRY.yaml").write_text(yaml.safe_dump(registry, sort_keys=False), encoding="utf-8")
        return project

    def review(self, project, profile):
        inputs = {p: p.read_bytes() for p in (project / "specs").rglob("*") if p.is_file()}
        registry = project / "naos/TASK_REGISTRY.yaml"
        inputs[registry] = registry.read_bytes()
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/naos_spec_pack_contract.py"),
             "--profile", profile, "--json"],
            cwd=project, env=self.environment, capture_output=True, text=True, timeout=60,
        )
        self.assertNotIn("Traceback", result.stderr)
        report = json.loads(result.stdout)
        schema = json.loads((ROOT / "schemas/naos/spec_pack_contract.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(report)
        self.assertIn("approved specifications", report["not_claimed"])
        for path, raw in inputs.items():
            self.assertEqual(path.read_bytes(), raw)
        return result, report

    def test_task_reference_matching_retains_whole_canonical_tokens(self):
        cases = {
            "`T-001`, [LKB-T-001]; TEAM-API7-T-1234.": {"T-001", "LKB-T-001", "TEAM-API7-T-1234"},
            "T-1000 and T-T-001": {"T-1000", "T-T-001"},
            "FOREIGN-T-001": {"FOREIGN-T-001"},
            "TEAM--T-001 T-001-tail XT-001 T-001x": set(),
            "prefix_T-001 T-001_suffix t-001": set(),
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                for value in expected:
                    self.assertIsNotNone(self.canonical.fullmatch(value))
                self.assertEqual(contract.extract_pattern_tokens(text, self.task_rule["reference_patterns"]), expected)

    def test_execution_required_pattern_rejects_fragments_and_accepts_long_ids(self):
        pattern = re.compile(self.execution_rule["pattern"], contract.compile_flags(self.execution_rule.get("flags")))
        for text, expected in (("T-001", True), ("LKB-T-001", True), ("TEAM-API7-T-1234", True),
                               ("T-1000", True), ("TEAM--T-001", False), ("T-001-tail", False),
                               ("prefix_T-001", False), ("t-001", False)):
            with self.subTest(text=text):
                self.assertEqual(bool(pattern.search(text)), expected)

    def test_equivalent_plain_namespaced_and_long_id_packs_pass_all_applicable_profiles(self):
        for prefix, digits in (("", 3), ("LKB-", 3), ("TEAM-API7-", 4), ("", 4)):
            project = self.project(prefix, prefix, digits)
            for profile in ("lite", "standard", "assured"):
                with self.subTest(prefix=prefix, digits=digits, profile=profile):
                    result, report = self.review(project, profile)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(report["status"], "pass")

    def test_unknown_namespace_does_not_borrow_plain_or_other_namespace_identity(self):
        for registered, referenced, digits in (("", "FOREIGN-", 3), ("LKB-", "OTHER-", 4)):
            project = self.project(registered, referenced, digits)
            for profile, code, status in (("lite", 0, "warning"), ("standard", 0, "required_missing"),
                                           ("assured", 1, "blocked")):
                with self.subTest(registered=registered, profile=profile):
                    result, report = self.review(project, profile)
                    self.assertEqual(result.returncode, code, result.stderr)
                    self.assertEqual(report["status"], status)
                    findings = [row for row in report["findings"] if ".TASK:" in row["id"]]
                    self.assertTrue(findings)
                    self.assertTrue(all(row["actual"].startswith(referenced + "T-") for row in findings))
                    self.assertTrue(all(row["human_review_required"] for row in findings))


if __name__ == "__main__":
    unittest.main()
