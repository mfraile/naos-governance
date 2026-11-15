"""Spec-pack task definitions must come from the selected governance root."""

import copy
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
sys.path.insert(0, str(ROOT / "scripts"))
import naos_spec_pack_contract as contract  # noqa: E402
import naos_plan_coherence as planning  # noqa: E402

SPECS = ROOT / "templates/spec-kit/specs"
REGISTRY = ROOT / "templates/structural-seeds/naos/TASK_REGISTRY.yaml"


class SpecPackGovernanceRootTests(unittest.TestCase):
    def project(self, *, specs=True):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        project = Path(temporary.name).resolve()
        if specs:
            shutil.copytree(SPECS, project / "specs")
        return project

    def registry(self, project, governance_root, *, valid=True):
        path = project / governance_root / "TASK_REGISTRY.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(REGISTRY.read_bytes() if valid else b"tasks: []\n")
        return path

    def policy(self, path, governance_root):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump({"paths": {"default_naos_root": governance_root}}), encoding="utf-8")

    def review(self, project, profile, *args, environment_root=None):
        inputs = {p: p.read_bytes() for p in project.rglob("*")
                  if p.is_file() and "reports" not in p.relative_to(project).parts}
        existing_directories = {p.resolve() for p in project.rglob("*") if p.is_dir()} | {project}
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        for name in ("NAOS_ROOT", "SPECS_ROOT"):
            environment.pop(name, None)
        if environment_root is not None:
            environment["NAOS_ROOT"] = environment_root
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/naos_spec_pack_contract.py"),
             "--profile", profile, "--json", *args],
            cwd=project, env=environment, capture_output=True, text=True, timeout=60,
        )
        self.assertNotIn("Traceback", result.stderr)
        report = json.loads(result.stdout)
        schema = json.loads((ROOT / "schemas/naos/spec_pack_contract.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(report)
        for path, raw in inputs.items():
            self.assertEqual(path.read_bytes(), raw)
        governance_root = project / report["naos_root"]
        saved = governance_root / "reports/spec_pack_contract.json"
        if governance_root.resolve() in existing_directories:
            self.assertEqual(json.loads(saved.read_text(encoding="utf-8")), report)
        else:
            self.assertFalse(governance_root.exists())
            self.assertFalse(saved.exists())
        return result, report

    def assert_selected(self, project, report, governance_root):
        self.assertEqual(report["naos_root"], governance_root)
        entry = next(row for row in report["traceability_codes"] if row["id"] == "TASK")
        self.assertEqual(entry["definitions_count"], 5)
        self.assertEqual((project / entry["definition_source_path"]).resolve(),
                         (project / governance_root / "TASK_REGISTRY.yaml").resolve())

    def test_default_helpers_remain_policy_based_and_do_not_mutate_policy(self):
        project = self.project()
        self.registry(project, "policy-root")
        policy = {"paths": {"default_naos_root": "policy-root"}}
        before = copy.deepcopy(policy)
        self.assertEqual(contract.task_registry_candidates(project, policy), [
            project / "policy-root/TASK_REGISTRY.yaml", project / "TASK_REGISTRY.yaml",
            project / "templates/structural-seeds/naos/TASK_REGISTRY.yaml",
        ])
        ids, source = contract.load_task_ids(project, policy)
        self.assertEqual(len(ids), 5)
        self.assertEqual(Path(source), project / "policy-root/TASK_REGISTRY.yaml")
        self.assertEqual(policy, before)

    def test_cli_environment_and_policy_precedence_use_the_selected_registry(self):
        for case in ("default", "cli", "environment", "policy"):
            project = self.project()
            args = []
            environment_root = None
            selected = "naos" if case == "default" else "policy-root" if case == "policy" else "pm"
            self.registry(project, selected)
            if selected != "naos":
                self.registry(project, "naos", valid=False)
            if case in {"cli", "environment"}:
                self.policy(project / "pm/policy/default_policy.yaml", "policy-root")
                self.registry(project, "policy-root", valid=False)
                environment_root = "pm"
            if case == "cli":
                environment_root = "environment-root"
                self.registry(project, environment_root, valid=False)
                args = ["--naos-root", "pm"]
            if case == "policy":
                policy_path = project / "chosen-policy.yaml"
                self.policy(policy_path, selected)
                args = ["--policy", str(policy_path)]
            for profile in ("lite", "standard", "assured"):
                with self.subTest(case=case, profile=profile):
                    result, report = self.review(project, profile, *args, environment_root=environment_root)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(report["status"], "pass")
                    self.assert_selected(project, report, selected)

    def test_nested_relative_governance_root_is_used(self):
        project = self.project()
        selected = "project-metadata/pm"
        self.registry(project, selected)
        self.registry(project, "naos", valid=False)
        for profile in ("lite", "standard", "assured"):
            with self.subTest(profile=profile):
                result, report = self.review(project, profile, "--naos-root", selected)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(report["status"], "pass")
                self.assert_selected(project, report, selected)

    def test_missing_or_malformed_selected_registry_cannot_borrow_default_registry(self):
        for malformed in (False, True):
            project = self.project()
            self.registry(project, "naos")
            if malformed:
                path = self.registry(project, "pm")
                path.write_text("tasks: [\n", encoding="utf-8")
                shutil.copyfile(REGISTRY, project / "TASK_REGISTRY.yaml")
            for profile, strict, expected_code in (("standard", False, 0), ("standard", True, 1),
                                                    ("assured", False, 1)):
                with self.subTest(malformed=malformed, profile=profile, strict=strict):
                    result, report = self.review(project, profile, "--naos-root", "pm",
                                                 *(["--strict"] if strict else []))
                    self.assertEqual(result.returncode, expected_code, result.stderr)
                    self.assertEqual(report["status"], "blocked" if profile == "assured" else "required_missing")
                    entry = next(row for row in report["traceability_codes"] if row["id"] == "TASK")
                    self.assertEqual(entry["definitions_count"], 0)
                    self.assertTrue(any("TASK" in row["id"] for row in report["findings"]))

    def test_legacy_registry_fallbacks_keep_their_order(self):
        for legacy in ("root", "template"):
            project = self.project()
            template = project / "templates/structural-seeds/naos/TASK_REGISTRY.yaml"
            template.parent.mkdir(parents=True)
            if legacy == "root":
                shutil.copyfile(REGISTRY, project / "TASK_REGISTRY.yaml")
                template.write_text("tasks: []\n", encoding="utf-8")
                expected = project / "TASK_REGISTRY.yaml"
            else:
                shutil.copyfile(REGISTRY, template)
                expected = template
            result, report = self.review(project, "assured", "--naos-root", "pm")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(report["status"], "pass")
            entry = next(row for row in report["traceability_codes"] if row["id"] == "TASK")
            self.assertEqual((project / entry["definition_source_path"]).resolve(), expected.resolve())

    def test_quickstart_without_specs_remains_not_required(self):
        project = self.project(specs=False)
        result, report = self.review(project, "quickstart", "--naos-root", "pm")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["naos_root"], "pm")
        self.assertEqual(report["traceability_codes"], [])

    def test_live_planning_recheck_uses_selected_root_and_keeps_live_refusal(self):
        project = self.project(specs=False)
        registry = self.registry(project, "pm")
        self.registry(project, "naos", valid=False)
        specs = project / "specs"
        specs.mkdir()
        (specs / "03-requirements.md").write_text(
            "# 03 - Requirements Specification\n\n### FR-001: Synthetic requirement\n\nTask: T-001.\n", encoding="utf-8")
        manifest = {
            "schema": contract.MANIFEST_SCHEMA_ID, "version": "1.1",
            "profiles": {"lite": {"required_files": ["03-requirements.md"]}},
            "files": [{"id": "03", "path": "03-requirements.md", "title": "Synthetic root fixture",
                       "required_profiles": ["lite"], "required_sections": ["# 03 - Requirements Specification"]}],
            "traceability_codes": [{"id": "TASK", "required_profiles": ["lite"],
                                    "definition_source": "task_registry", "reference_files": ["03-requirements.md"],
                                    "reference_patterns": [r"\b(T-[0-9]{3})\b"]}],
        }
        (specs / "spec_manifest.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
        policy = contract.load_policy(root=project)
        before = copy.deepcopy(policy)
        producer_policy = copy.deepcopy(policy)
        producer_policy["paths"]["default_naos_root"] = "pm"
        saved = contract.validate_contract(root=project, specs_root=specs,
                                          manifest_path=specs / "spec_manifest.yaml", profile="lite",
                                          policy=producer_policy, mode="filled")
        self.assertEqual(saved["status"], "pass")
        report_path = project / "pm/reports/spec_pack_contract.json"
        report_path.parent.mkdir()
        report_path.write_text(json.dumps(saved), encoding="utf-8")
        baseline = {
            "source_bindings": {"requirements": {"path": "specs/03-requirements.md"}},
            "evidence_refs": {"spec_pack_contract": {"path": "pm/reports/spec_pack_contract.json",
                "sha256": planning.planning_binding_sha256(report_path, "file_sha256"),
                "digest_kind": "file_sha256", "required_by_profile": True}},
        }
        findings, checks, _ = planning.check_evidence_refs(project, "pm", policy, "lite", baseline, "warning")
        check = next(row for row in checks if row["evidence"] == "spec_pack_contract")
        self.assertEqual(check["source_identity_status"], "matched")
        self.assertEqual(check["live_validation_status"], "pass")
        self.assertEqual(check["status"], "ready")
        self.assertFalse(any(row.get("evidence") == "spec_pack_contract" for row in findings))
        self.registry(project, "naos")
        registry.write_text("tasks: [\n", encoding="utf-8")
        findings, checks, _ = planning.check_evidence_refs(project, "pm", policy, "lite", baseline, "warning")
        check = next(row for row in checks if row["evidence"] == "spec_pack_contract")
        self.assertEqual(check["status"], "not_ready")
        self.assertNotEqual(check["live_validation_status"], "pass")
        self.assertTrue(any(row["status"] == "planning_baseline_evidence_live_not_ready"
                            and row.get("evidence") == "spec_pack_contract" for row in findings))
        self.assertEqual(json.loads(report_path.read_text(encoding="utf-8")), saved)
        self.assertEqual(policy, before)


if __name__ == "__main__":
    unittest.main()
