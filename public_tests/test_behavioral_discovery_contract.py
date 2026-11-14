"""First-use behavioral observations retain exact content and bounded coverage."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml
from jsonschema import Draft202012Validator

KIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KIT / "scripts"))

import naos_behavioral_governance_readiness as producer  # noqa: E402
import naos_evidence_contracts as contracts  # noqa: E402
import naos_grader_assessment as assessment  # noqa: E402
import naos_llm_grader_readiness as llm  # noqa: E402
import naos_static_grader as static  # noqa: E402
from naos_ai_surfaces import scan_files  # noqa: E402
from naos_policy import load_policy, report_default_path  # noqa: E402
from naos_report_contracts import validate_current_report  # noqa: E402


class BehavioralDiscoveryContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="naos-discovery-contract-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        directory = self.root / "naos"
        directory.mkdir()
        self.rules = directory / "behavioral_governance_readiness_rules.yaml"
        self.rules.write_bytes(producer.default_rules_template().read_bytes())
        (directory / "capability_state.yaml").write_text(yaml.safe_dump({
            "capabilities": [{"capability_id": "CAP-BEHAVIORAL-GOVERNANCE-READINESS",
                              "enabled": True, "current_maturity": "L0",
                              "target_maturity": "L0", "evidence_refs": []}],
        }), encoding="utf-8")
        reports = directory / "reports"
        reports.mkdir()
        trace = reports / "agent_trace_validation.json"
        events = directory / "agent_trace_events.yaml"
        with patch.dict(os.environ, {"NAOS_FIXED_TIME": "2026-06-22T00:00:00Z"}):
            static_report = static.build_report(
                root=self.root, profile="quickstart", naos_root="naos", policy={},
                trace_report_path=trace, trace_file_path=events)
            (reports / "static_grader_report.json").write_text(
                json.dumps(static_report), encoding="utf-8")
            llm_report = llm.build_report(
                self.root, "naos", "quickstart", {},
                KIT / "templates/structural-seeds/naos/llm_grader_readiness_rules.yaml")
            (reports / "llm_grader_readiness.json").write_text(
                json.dumps(llm_report), encoding="utf-8")
            assessment_report = assessment.build_report(
                root=self.root, profile="quickstart", naos_root="naos", policy={}, mode="audit",
                static_report_path=reports / "static_grader_report.json", trace_report_path=trace,
                trace_file_path=events, baseline_path=None)
            (reports / "grader_assessment.json").write_text(
                json.dumps(assessment_report), encoding="utf-8")
        self.policy = load_policy(root=self.root)
        self.path = report_default_path(
            self.root, "naos", self.policy, "behavioral_governance_readiness_report")

    def cli(self):
        result = subprocess.run(
            [sys.executable, "-B", str(KIT / "scripts/naos_behavioral_governance_readiness.py"),
             "--project-root", str(self.root), "--profile", "lite", "--json"],
            cwd=self.root, text=True, capture_output=True, check=False, timeout=30,
            env={**os.environ, "NAOS_FIXED_TIME": "2026-06-23T00:00:00Z"})
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report, json.loads(self.path.read_text(encoding="utf-8")))
        return report

    def current(self):
        rules, source = producer.resolve_rules_path(self.root, "naos", self.policy)
        baseline = producer.resolve_baseline_path(self.root, "naos", self.policy)
        return producer.build_report(self.root, "naos", "lite", self.policy, rules, source, baseline)

    def reasons(self, report):
        return validate_current_report(
            report, schema_name="behavioral_governance_readiness", source_hash_field="rules_hash",
            expected=self.current)[0]

    def decide(self, report):
        check = {"id": "naos_behavioral_governance_readiness", "returncode": 0,
                 **{key: report[key] for key in ("status", "summary", "findings")}}
        return contracts._self_check_primitive_contract(
            check, root=self.root, profile="lite", naos_root="naos", policy=self.policy)

    @staticmethod
    def discovery(report):
        return next(row for row in report["fingerprinted_paths"]
                    if row["id"] == "instruction_discovery")

    def test_first_cli_publication_is_current_and_is_only_an_inert_observation(self):
        self.assertFalse(self.path.exists())
        report = self.cli()
        self.assertEqual(self.reasons(report), [])
        decision = self.decide(report)
        self.assertIsNotNone(decision)
        self.assertEqual(report["status"], "not_ready")
        for key in ("baseline_readiness_established", "behavioral_adequacy_established",
                    "human_review_recorded"):
            self.assertFalse(decision[key])
        self.assertTrue(decision["human_review_required"])
        self.assertFalse((self.root / "naos/behavioral_baseline_state.yaml").exists())

    def test_first_and_repeat_cli_reports_match_without_warming_the_output(self):
        self.assertFalse(self.path.exists())
        first = self.cli()
        self.assertEqual(self.reasons(first), [])
        self.assertEqual(self.cli(), first)

    def test_new_and_changed_instruction_bytes_still_invalidate_currentness(self):
        first = self.cli()
        path = self.root / "src/AGENTS.md"
        path.parent.mkdir()
        path.write_bytes(b"Synthetic local instruction one\n")
        self.assertIn("content_mismatch", self.reasons(first))
        self.assertIsNone(self.decide(first))
        report = self.cli()
        self.assertEqual(self.discovery(report)["selected_file_count"], 1)
        self.assertEqual(report["current_fingerprints"]["path:src/AGENTS.md"],
                         hashlib.sha256(path.read_bytes()).hexdigest())
        row = next(row for row in report["fingerprinted_paths"] if row["id"] == "path:src/AGENTS.md")
        self.assertEqual(row["file_count"], 1)
        self.assertEqual(self.reasons(report), [])
        path.write_bytes(b"Synthetic local instruction two\n")
        self.assertIn("content_mismatch", self.reasons(report))
        self.assertIsNone(self.decide(report))
        self.assertIsNotNone(self.decide(self.cli()))

    def test_unrelated_file_is_not_an_instruction_and_still_consumes_the_budget(self):
        report = self.cli()
        before, _ = scan_files(self.root, None, 5000)
        (self.root / "notes.txt").write_text("Synthetic project note\n", encoding="utf-8")
        after, metadata = scan_files(self.root, None, 5000)
        self.assertEqual(len(after), len(before) + 1)
        self.assertEqual(metadata["file_count"], len(after))
        self.assertEqual(self.discovery(report)["selected_file_count"], 0)
        self.assertEqual(self.reasons(report), [])

    def test_required_report_byte_changes_are_not_forgiven(self):
        report = self.cli()
        path = self.root / "naos/reports/static_grader_report.json"
        path.write_bytes(path.read_bytes() + b"\n")
        self.assertIn("content_mismatch", self.reasons(report))
        self.assertIsNone(self.decide(report))

    def test_missing_invented_and_unknown_fields_are_not_current_reports(self):
        report = self.cli()
        mutations = [lambda value: value.update(unrecognized_field=True),
                     lambda value: self.discovery(value).update(unrecognized_field=True),
                     lambda value: self.discovery(value).update(selected_file_count=999),
                     lambda value: self.discovery(value).update(discovery_file_limit=99999),
                     lambda value: self.discovery(value).pop("selected_file_count")]
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                altered = copy.deepcopy(report)
                mutation(altered)
                self.assertIn("content_mismatch", self.reasons(altered))
                self.path.write_text(json.dumps(altered), encoding="utf-8")
                self.assertIsNone(self.decide(altered))

    def test_legacy_discovery_shape_is_readable_but_needs_regeneration(self):
        report = self.cli()
        legacy = copy.deepcopy(report)
        row = self.discovery(legacy)
        for key in ("selection_basis", "selected_file_count", "discovery_file_limit"):
            row.pop(key)
        row["file_count"] = len(scan_files(self.root, None, 5000)[0])
        schema = json.loads((KIT / "schemas/naos/behavioral_governance_readiness.schema.json").read_text())
        Draft202012Validator(schema).validate(legacy)
        self.assertIn("content_mismatch", self.reasons(legacy))

    def test_actual_cli_file_budget_keeps_publication_and_oversize_refusals(self):
        rules = self.root / "naos/ai_artifact_inventory_rules.yaml"
        rules.write_text("scan_limits:\n  max_discovery_files: 5000\n", encoding="utf-8")
        for offset in (1, 0, -1):
            with self.subTest(output_budget_offset=offset):
                self.path.unlink(missing_ok=True)
                count = len(scan_files(self.root, None, 5000)[0])
                limit = count + offset
                rules.write_text(f"scan_limits:\n  max_discovery_files: {limit}\n", encoding="utf-8")
                report = self.cli()
                stored = self.discovery(report)
                current = self.discovery(self.current())
                self.assertEqual(stored["discovery_file_limit"], limit)
                if offset == 1:
                    self.assertTrue(stored["complete"])
                    self.assertTrue(current["complete"])
                    self.assertEqual(self.reasons(report), [])
                    self.assertIsNotNone(self.decide(report))
                else:
                    self.assertEqual(stored["complete"], offset == 0)
                    self.assertFalse(current["complete"])
                    self.assertTrue(current["truncated"])
                    self.assertIsNone(self.decide(report))
                    repeated = self.cli()
                    self.assertFalse(self.discovery(repeated)["complete"])
                    self.assertIsNone(self.decide(repeated))

    def test_selected_symlink_retains_incomplete_coverage_and_refusal(self):
        target = self.root / "synthetic-target.txt"
        target.write_text("Synthetic target\n", encoding="utf-8")
        directory = self.root / "src"
        directory.mkdir()
        try:
            (directory / "AGENTS.md").symlink_to(target)
        except OSError as error:
            if sys.platform == "win32" and getattr(error, "winerror", None) == 1314:
                self.skipTest("Windows token lacks symlink privilege")
            raise
        report = self.cli()
        self.assertFalse(self.discovery(report)["complete"])
        self.assertTrue(self.discovery(report)["issues"])
        self.assertIsNone(self.decide(report))

    def test_custom_output_folder_fingerprinting_is_still_self_referential(self):
        (self.root / "naos/ai_artifact_inventory_rules.yaml").write_text(
            "artifact_patterns:\n  - naos/reports\n", encoding="utf-8")
        for _ in range(2):
            report = self.cli()
            self.assertIn("content_mismatch", self.reasons(report))
            self.assertIsNone(self.decide(report))


if __name__ == "__main__":
    unittest.main()
