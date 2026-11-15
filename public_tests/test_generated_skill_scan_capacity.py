"""Default bounded host scanning must cover the portable skills NAOS ships."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from jsonschema import Draft202012Validator
import yaml


ROOT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]
import naos_init  # noqa: E402
import naos_adoption_common as adoption  # noqa: E402
import naos_adapter_coherence as adapter  # noqa: E402


class GeneratedSkillScanCapacityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.fixtures = {}
        for profile in ("standard", "assured"):
            base = Path(cls.temporary.name).resolve() / profile
            host = base / "host"
            host.mkdir(parents=True)
            target = base / "preview"
            naos_init.scaffold_files(host, profile, "custom", "static_only", target,
                                     signals=naos_init._empty_signals(), memory_choice="disabled", emit_progress=False)
            cls.fixtures[profile] = target

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def fixture(self, profile, *, remove_rules=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        project = Path(temporary.name).resolve() / "project"
        shutil.copytree(self.fixtures[profile], project)
        if remove_rules:
            (project / "naos/ai_artifact_inventory_rules.yaml").unlink()
        return project

    def skill_hashes(self, project):
        return {path.relative_to(project).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (project / ".agents/skills").rglob("*") if path.is_file()}

    def adapter(self, project, profile):
        before = self.skill_hashes(project)
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        environment.pop("NAOS_ROOT", None)
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/naos_adapter_coherence.py"), str(project),
             "--scope", "project", "--profile", profile, "--json"],
            cwd=project, env=environment, capture_output=True, text=True, timeout=120,
        )
        report = json.loads(result.stdout)
        schema = json.loads((ROOT / "schemas/naos/adapter_coherence_report.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(report)
        self.assertEqual(report, json.loads((project / "naos/reports/adapter_coherence.json").read_text(encoding="utf-8")))
        self.assertEqual(self.skill_hashes(project), before)
        self.assertEqual(report["review_scope"], "project")
        self.assertFalse(report["source_authority"]["inherited_maintainer_review_is_adopter_evidence"])
        row = next(item for item in report["project_local_adapters"] if item["path"] == ".agents/skills")
        return result, report, row

    def test_fresh_standard_and_assured_seed_cover_all_generated_portable_files(self):
        for profile in self.fixtures:
            with self.subTest(profile=profile):
                project = self.fixture(profile)
                expected = self.skill_hashes(project)
                self.assertGreater(len(expected), 50)
                self.assertLessEqual(len(expected), 128)
                result, report, row = self.adapter(project, profile)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(row["complete"])
                self.assertFalse(row["truncated"])
                self.assertEqual(row["file_count"], len(expected))
                self.assertEqual({item["path"] for item in row["inspected_files"]}, set(expected))
                self.assertEqual(report["status"], "pass")

    def test_missing_optional_rules_use_complete_shared_defaults_in_inventory_and_reconcile(self):
        for profile in self.fixtures:
            with self.subTest(profile=profile):
                project = self.fixture(profile, remove_rules=True)
                before = self.skill_hashes(project)
                result, report, row = self.adapter(project, profile)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(row["complete"])
                self.assertEqual(row["file_count"], len(before))
                args = argparse.Namespace(naos_root="naos", mode="brownfield")
                inventory = adoption.build_ai_artifact_inventory(args, project, profile, {})
                self.assertTrue(inventory["scan_scope"]["complete"])
                self.assertEqual(inventory["scan_scope"]["limits"], {"max_files_per_path": 128, "max_discovery_files": 5000})
                self.assertLessEqual(set(before), {row["path"] for row in inventory["artifacts"]})
                reconciled = adoption.build_ai_artifact_reconcile(args, project, profile, {})
                self.assertFalse(any(f["id"] == "ai_artifact_inventory.incomplete_scan" for f in reconciled["findings"]))
                self.assertEqual(self.skill_hashes(project), before)
                self.assertTrue(report["human_review_required"])

    def test_explicit_old_limit_and_capacity_overflow_stay_incomplete(self):
        project = self.fixture("assured")
        path = project / "naos/ai_artifact_inventory_rules.yaml"
        rules = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules["scan_limits"]["max_files_per_path"] = 50
        path.write_text(yaml.safe_dump(rules), encoding="utf-8")
        before = path.read_bytes()
        result, _, row = self.adapter(project, "assured")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(row["file_count"], 50)
        self.assertFalse(row["complete"])
        self.assertTrue(row["truncated"])
        self.assertEqual(path.read_bytes(), before)
        rules["scan_limits"]["max_files_per_path"] = 128
        path.write_text(yaml.safe_dump(rules), encoding="utf-8")
        count = len(self.skill_hashes(project))
        for index in range(129 - count):
            (project / ".agents/skills" / f"zz-synthetic-{index:03d}.md").write_text("Synthetic guidance.\n", encoding="utf-8")
        result, report, row = self.adapter(project, "assured")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(row["file_count"], 128)
        self.assertFalse(row["complete"])
        self.assertTrue(row["truncated"])
        self.assertTrue(any(f["id"] == "project_adapter_incomplete_agents_skills" for f in report["findings"]))

    def test_windows_metadata_paths_are_portable_for_default_and_nested_roots(self):
        for governance_root in ("naos", "project-metadata/pm"):
            with self.subTest(governance_root=governance_root):
                project = self.fixture("standard")
                rules = yaml.safe_load((project / "naos/adapter_coherence_rules.yaml").read_text(encoding="utf-8"))
                if governance_root != "naos":
                    destination = project / governance_root
                    destination.parent.mkdir(parents=True)
                    (project / "naos").rename(destination)
                before = self.skill_hashes(project)
                with mock.patch.object(adapter, "Path", PureWindowsPath):
                    rows, _ = adapter.inspect_project_host_surfaces(
                        project, governance_root, "standard", {}, rules, "required")
                by_path = {row["path"]: row for row in rows}
                expected = [governance_root + "/" + path[len("naos/"):]
                            for path in rules["project_local_adapter_paths"] if path.startswith("naos/")]
                self.assertEqual(len(expected), 4)
                self.assertTrue(all(path in by_path for path in expected), sorted(by_path))
                for path in expected:
                    self.assertNotIn("\\", path)
                    self.assertTrue(by_path[path]["complete"], by_path[path])
                self.assertEqual(self.skill_hashes(project), before)

    def test_literal_backslash_metadata_stays_invalid_under_windows_composition(self):
        project = self.fixture("standard")
        rules = {"project_local_adapter_paths": [r"naos/integrations\broken.json"]}
        before = self.skill_hashes(project)
        with mock.patch.object(adapter, "Path", PureWindowsPath):
            rows, findings = adapter.inspect_project_host_surfaces(project, "naos", "standard", {}, rules, "required")
        row = next(item for item in rows if "broken.json" in item["path"])
        self.assertIn("\\", row["path"])
        self.assertFalse(row["complete"])
        self.assertEqual(row["inspected_files"], [])
        self.assertTrue(any(finding["status"] == "incomplete_project_surface" for finding in findings))
        self.assertEqual(rules["project_local_adapter_paths"], [r"naos/integrations\broken.json"])
        self.assertEqual(self.skill_hashes(project), before)


if __name__ == "__main__":
    unittest.main()
