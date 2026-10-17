"""Provenance for observed input states never turns an unmet gate into approval."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator
import yaml


ROOT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(ROOT / "scripts"))
import naos_behavioral_governance_readiness as behavioral  # noqa: E402
import naos_pr_governance_summary as pr_summary  # noqa: E402
import naos_session_lifecycle as lifecycle  # noqa: E402


class RemainingProducerProvenanceContractTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="naos-provenance-observations-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / "naos/reports").mkdir(parents=True)
        (self.root / "naos/evidence_classification_policy.yaml").write_bytes(
            (ROOT / "templates/structural-seeds/naos/evidence_classification_policy.yaml").read_bytes()
        )
        (self.root / "naos/behavioral_governance_readiness_rules.yaml").write_bytes(
            (ROOT / "templates/structural-seeds/naos/behavioral_governance_readiness_rules.yaml").read_bytes()
        )
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("NAOS_", "GIT_")) and key != "GITHUB_ACTIONS"}
        self.env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1",
                        GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")

    def run_cli(self, command, *args, expected=(0, 1), naos_root="naos"):
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "cli.py"), command, "--profile", "assured",
             "--naos-root", naos_root, *args, "--json"],
            cwd=self.root, env=self.env, text=True, capture_output=True, timeout=60,
        )
        self.assertIn(result.returncode, expected, (command, result.stdout[-1600:], result.stderr[-1600:]))
        self.assertNotIn("Traceback", result.stderr)
        return result.returncode, json.loads(result.stdout)

    def classify(self, *reports, expected=0, naos_root="naos"):
        args = []
        for report in reports:
            args.extend(("--report", str(report)))
        code, data = self.run_cli("evidence-classification", *args,
                                  "--output", str(self.root / "classification.json"),
                                  expected=(expected,), naos_root=naos_root)
        self.assertEqual(code, expected)
        return data

    def assert_real_local_ref(self, item, *, kit_files=()):
        refs = [Path(ref["ref"]) for ref in item["evidence_refs"]
                if ref["type"] == "local_file"]
        self.assertTrue(refs, item)
        for ref in refs:
            boundary = ROOT if ref.as_posix() in kit_files else self.root
            self.assertTrue((ref if ref.is_absolute() else boundary / ref).is_file(), ref)

    def assert_schema(self, data, name):
        schema = json.loads((ROOT / "schemas/naos" / name).read_text())
        Draft202012Validator(schema).validate(data)

    def test_observed_gate_failures_classify_without_clearing_required_findings(self):
        gate = self.root / "naos/reports/gate_evaluation.json"
        output = self.root / "naos/reports/pr_governance_summary.json"
        for source, finding_id in (
            ({"status": "required_missing", "summary": {"required_missing": 1}},
             "pr_governance.gates_failed"),
            ({"status": "blocked", "summary": {"blocked": 1}},
             "pr_governance.gates_failed"),
            ({"status": "invalid_input", "errors": ["invalid gate input"]},
             "pr_governance.gate_evaluation_invalid_input"),
        ):
            with self.subTest(source=source):
                gate.write_text(json.dumps(source), encoding="utf-8")
                before = gate.read_bytes()
                self.run_cli("pr-governance-summary", "--output", str(output))
                report = json.loads(output.read_text(encoding="utf-8"))
                self.assert_schema(report, "pr_governance_summary.schema.json")
                finding = next(item for item in report["findings"] if item["id"] == finding_id)
                self.assertEqual(finding["severity"], "required")
                self.assertEqual(finding["status"], "gates_failed")
                self.assertTrue(finding["human_review_required"])
                self.assertEqual(finding["classification_scope"], "observed_gate_report_failure_only")
                self.assertEqual(Path(finding["source_path"]).resolve(), gate.resolve())
                classified = self.classify(output)
                item = next(item for item in classified["classified_findings"]
                            if item["finding_id"] == finding_id)
                self.assertEqual(item["classification"], "confirmed")
                self.assertEqual(gate.read_bytes(), before)

    def test_selected_capability_absence_and_unassigned_owners_preserve_blocking(self):
        cap_dir = self.root / "naos/capabilities"
        cap_dir.mkdir()
        contract = yaml.safe_load((ROOT / "capabilities/gatekeeper_manifest.yaml").read_text())
        cap_file = cap_dir / "selected.yaml"
        cap_file.write_text(yaml.safe_dump(contract), encoding="utf-8")
        state = self.root / "naos/capability_state.yaml"
        report = self.root / "naos/reports/capability_maturity.json"
        state.write_text("capabilities: []\n", encoding="utf-8")
        code, absent = self.run_cli("capability-maturity", "--state", str(state),
                                    "--capabilities-dir", str(cap_dir), "--output", str(report))
        self.assertEqual(code, 1)
        self.assert_schema(absent, "capability_maturity_report.schema.json")
        missing = next(item for item in absent["findings"] if item["status"] == "not_configured")
        self.assertEqual(missing["evidence_classification"], "confirmed")
        self.assertEqual(Path(missing["source_path"]), cap_file)
        classified = self.classify(report)
        classified_missing = next(item for item in classified["classified_findings"]
                                  if item["status"] == "not_configured")
        self.assertEqual(classified_missing["classification"], "confirmed")
        self.assert_real_local_ref(classified_missing)
        self.assertFalse(absent["capabilities"][0]["ready_for_promotion"])

        state.write_text(yaml.safe_dump({"capabilities": [{
            "capability_id": contract["id"], "enabled": True,
            "current_maturity": "L0", "target_maturity": "L1", "owners": {},
        }]}), encoding="utf-8")
        code, owner = self.run_cli("capability-maturity", "--state", str(state),
                                   "--capabilities-dir", str(cap_dir), "--output", str(report))
        self.assertEqual(code, 1)
        self.assert_schema(owner, "capability_maturity_report.schema.json")
        owner_finding = next(item for item in owner["findings"] if item["status"] == "missing_owner")
        self.assertEqual(owner_finding["evidence_classification"], "confirmed")
        self.assertEqual(Path(owner_finding["source_path"]), state)
        self.assertEqual(owner["capabilities"][0]["promotion_recorded"], False)
        classified = self.classify(report)
        self.assert_real_local_ref(next(item for item in classified["classified_findings"]
                                        if item["status"] == "missing_owner"))

    def test_static_observation_and_hypothesis_forward_without_behavioral_pass(self):
        budget = self.root / "naos/reports/ai_surface_context_budget.json"
        budget.write_text(json.dumps({"status": "warning", "ai_surface_health_posture": "warning"}))
        _, static = self.run_cli("static-grader")
        self.assert_schema(static, "static_grader_report.schema.json")
        missing = next(item for item in static["findings"]
                       if item["id"] == "STATICGRADER_MISSING_DETERMINISTIC_REPORTS")
        hypothesis = next(item for item in static["findings"]
                          if item["id"] == "STATICGRADER_AI_SURFACE_HEALTH_REVIEW")
        self.assertEqual(missing["evidence_classification"], "confirmed")
        self.assertEqual(hypothesis["evidence_classification"], "hypothesized")
        self.assertEqual(Path(hypothesis["source_report"]).resolve(), budget.resolve())
        self.assertTrue(hypothesis["next_review_step"])
        self.assertTrue(static["human_review_required"])
        _, assessment = self.run_cli("grader-assessment")
        copied = {item["id"]: item for item in assessment["findings"]}
        for item in (missing, hypothesis):
            self.assertEqual(copied[item["id"]]["evidence_classification"],
                             item["evidence_classification"])
            self.assertEqual(copied[item["id"]]["severity"], item["severity"])
        classified = self.classify(self.root / "naos/reports/static_grader_report.json",
                                   self.root / "naos/reports/grader_assessment.json", expected=1)
        classified_items = [item for item in classified["classified_findings"]
                            if item["finding_id"] in {missing["id"], hypothesis["id"]}]
        self.assertEqual(len(classified_items), 4)
        self.assertEqual({item["classification"] for item in classified_items},
                         {"confirmed", "hypothesized"})
        self.assertTrue(classified["missing_classification"])  # Other inputs remain strict.
        for item in classified_items:
            # StaticGrader declares this exact executing-kit implementation
            # source; it does not install it into the adopter project.
            self.assert_real_local_ref(item, kit_files={"autoresearch/graders/static.py"})
            self.assertTrue(any(
                ref["type"] == "local_file"
                and ref["ref"] == "autoresearch/graders/static.py"
                and ref["reference_role"] == "unverified_reference"
                for ref in item["evidence_refs"]
            ))

        # A present but malformed file also sets `present=False`; it is not
        # evidence that the selected path was physically absent.
        budget.write_text("{malformed", encoding="utf-8")
        _, malformed = self.run_cli("static-grader")
        missing = next(item for item in malformed["findings"]
                       if item["id"] == "STATICGRADER_MISSING_DETERMINISTIC_REPORTS")
        self.assertNotIn("evidence_classification", missing)
        self.assertTrue(next(item for item in malformed["input_reports"]
                             if item["id"] == "ai_surface_context_budget")["source_path_exists"])
        classified = self.classify(self.root / "naos/reports/static_grader_report.json", expected=1)
        self.assertIn(missing["id"],
                      {item["finding_id"] for item in classified["missing_classification"]})

    def test_unrelated_and_invalid_declarations_still_block_assured(self):
        report = self.root / "naos/reports/unknown.json"
        report.write_text(json.dumps({"findings": [
            {"id": "PROJECT-UNKNOWN", "severity": "warning", "status": "review_required",
             "message": "Project decision has no provenance."},
            {"id": "PROJECT-INVALID", "evidence_classification": "invalid",
             "classification": "confirmed", "severity": "warning", "status": "review_required",
             "message": "Invalid explicit declaration cannot fall back."},
            {"id": "PROJECT-CONFLICT", "evidence_classification": "confirmed",
             "provenance_classification": "hypothesized", "severity": "warning",
             "status": "review_required", "message": "Conflicting declarations."},
        ]}))
        classified = self.classify(report, expected=1)
        self.assertEqual(classified["status"], "review_required")
        self.assertEqual({item["finding_id"] for item in classified["missing_classification"]},
                         {"PROJECT-UNKNOWN", "PROJECT-INVALID", "PROJECT-CONFLICT"})

    def test_missing_input_observations_from_actual_producers_keep_gates_nonzero(self):
        commands = (
            "context-index", "external-evidence-ingest", "operator-attribution",
            "behavioral-readiness", "pr-governance-summary", "audit-log",
            "session-start",
        )
        outcomes = {}
        for command in commands:
            with self.subTest(command=command):
                options = ("--event-type", "report_generated") if command == "audit-log" else ()
                outcomes[command], _ = self.run_cli(command, *options)
        self.assertEqual(outcomes["behavioral-readiness"], 1)
        self.assertEqual(outcomes["session-start"], 1)
        reports = self.root / "naos/reports"
        cases = (
            ("external_evidence_ingest", "external_evidence_ingest.source_missing", "confirmed"),
            ("operator_attribution", "operator_attribution.env_operator_missing", "confirmed"),
            ("behavioral_governance_readiness", "behavioral_readiness.missing_conformance_latest", "confirmed"),
            ("pr_governance_summary", "pr_governance.missing_reports", "confirmed"),
            ("sqlite_write_coordination", "sqlite_write_coordination.session_metadata_unavailable", "confirmed"),
            ("session_lifecycle", "session_lifecycle.task_context_pack.missing", "confirmed"),
            ("audit_log_summary", "audit_log.missing_session_id_events", "confirmed"),
        )
        for report_name, finding_id, declaration in cases:
            report = reports / f"{report_name}.json"
            with self.subTest(report_name=report_name):
                self.assertTrue(report.is_file(), report)
                data = json.loads(report.read_text())
                source = next(item for item in data["findings"] if item["id"] == finding_id)
                self.assertEqual(source["evidence_classification"], declaration)
                self.assertTrue(source["human_review_required"])
                classified = self.classify(report, expected=(
                    1 if report_name == "session_lifecycle" else 0
                ))
                matched = next(item for item in classified["classified_findings"]
                               if item["finding_id"] == finding_id)
                self.assertEqual(matched["classification"], declaration)
                self.assert_real_local_ref(matched)

    def test_parse_failure_and_invalid_environment_are_not_confirmed_as_absence(self):
        # A present malformed report is not evidence that its path was absent.
        (self.root / "naos/reports/gate_status.json").write_text("{invalid", encoding="utf-8")
        _, pr_report = self.run_cli("pr-governance-summary")
        pr_finding = next(item for item in pr_report["findings"]
                          if item["id"] == "pr_governance.missing_reports")
        self.assertNotIn("evidence_classification", pr_finding)
        pr_classified = self.classify(self.root / "naos/reports/pr_governance_summary.json", expected=1)
        self.assertIn("pr_governance.missing_reports",
                      {item["finding_id"] for item in pr_classified["missing_classification"]})

        # A rejected configured ID is a different state from no supplied ID.
        self.env["NAOS_OPERATOR_ID"] = "../unsafe"
        _, operator_report = self.run_cli("operator-attribution")
        self.assertEqual(operator_report["status"], "review_required")
        self.assertNotIn("operator_attribution.env_operator_missing",
                         {item["id"] for item in operator_report["findings"]})
        invalid = next(item for item in operator_report["findings"]
                       if item["id"] == "operator_attribution.invalid_operator_id")
        self.assertNotIn("evidence_classification", invalid)
        classified = self.classify(self.root / "naos/reports/operator_attribution.json", expected=1)
        self.assertIn("operator_attribution.invalid_operator_id",
                      {item["finding_id"] for item in classified["missing_classification"]})

        # A failed Git-config query cannot establish that local hooksPath is unset.
        _, bypass = self.run_cli("governance-bypass-posture")
        self.assertNotIn("governance_bypass.hooks_path_unset",
                         {item["id"] for item in bypass["findings"]})
        hook = next(item for item in bypass["findings"]
                    if item["id"] == "governance_bypass.hooks_path_inspection_failed")
        self.assertEqual(hook["status"], "read_error")
        self.assertNotIn("evidence_classification", hook)
        classified = self.classify(self.root / "naos/reports/governance_bypass_posture.json", expected=1)
        self.assertIn(hook["id"],
                      {item["finding_id"] for item in classified["missing_classification"]})

    def test_remapped_root_and_selected_state_reference_resolve_to_real_files(self):
        remapped = "governance ü"
        folder = self.root / remapped
        folder.mkdir()
        (folder / "evidence_classification_policy.yaml").write_bytes(
            (self.root / "naos/evidence_classification_policy.yaml").read_bytes()
        )
        caps = folder / "capabilities"
        caps.mkdir()
        contract = yaml.safe_load((ROOT / "capabilities/gatekeeper_manifest.yaml").read_text())
        contract_path = caps / "contract.yaml"
        contract_path.write_text(yaml.safe_dump(contract), encoding="utf-8")
        state = folder / "state.yaml"
        state.write_text("capabilities: []\n", encoding="utf-8")
        report = folder / "reports/capability_maturity.json"
        code, produced = self.run_cli("capability-maturity", "--state", str(state),
                                      "--capabilities-dir", str(caps), "--output", str(report),
                                      naos_root=remapped)
        self.assertEqual(code, 1)
        item = next(item for item in produced["findings"] if item["status"] == "not_configured")
        self.assertEqual(Path(item["source_path"]).resolve(), contract_path.resolve())
        self.assertEqual(Path(item["selected_state_path"]).resolve(), state.resolve())
        classified = self.classify(report, naos_root=remapped)
        matched = next(item for item in classified["classified_findings"]
                       if item["status"] == "not_configured")
        self.assert_real_local_ref(matched)

    def test_invalid_loaded_audit_mapping_keeps_invalidity_and_field_observation_separate(self):
        _, initial = self.run_cli("audit-log", "--event-type", "report_generated")
        audit_root = Path(initial["audit_log_root"])
        invalid = audit_root / "2026-09-24/invalid.jsonl"
        invalid.parent.mkdir(parents=True, exist_ok=True)
        invalid.write_text(json.dumps({"event_id": "INVALID-MAPPING", "session_id": None}) + "\n")
        _, report = self.run_cli("audit-log")
        self.assertGreater(report["invalid_event_count"], 0)
        invalid_finding = next(item for item in report["findings"]
                               if item["id"] == "audit_log.invalid_events")
        self.assertNotIn("evidence_classification", invalid_finding)
        missing = next(item for item in report["findings"]
                       if item["id"] == "audit_log.missing_session_id_events")
        self.assertEqual(missing["evidence_classification"], "confirmed")
        self.assertIn("Loaded JSON mapping", missing["reasoning_summary"])
        self.assertNotIn("Validated", missing["reasoning_summary"])
        classified = self.classify(self.root / "naos/reports/audit_log_summary.json", expected=1)
        self.assertIn("audit_log.invalid_events",
                      {item["finding_id"] for item in classified["missing_classification"]})

    def test_absence_helpers_require_file_not_found_and_preserve_unknown_probe_errors(self):
        selected = self.root / "naos/reports/selected.json"
        for helper in (pr_summary.confirmed_absent_path,
                       behavioral.confirmed_absent_path):
            with self.subTest(helper=helper.__module__):
                with patch.object(Path, "lstat", side_effect=FileNotFoundError("absent")):
                    self.assertTrue(helper(selected))
                with patch.object(Path, "lstat", side_effect=PermissionError("unreadable")):
                    self.assertFalse(helper(selected))
                with patch.object(Path, "lstat", return_value=object()):
                    self.assertFalse(helper(selected))
        self.assertFalse(lifecycle.confirmed_absent_path(self.root, None))
        with patch.object(Path, "lstat", side_effect=FileNotFoundError("absent")):
            self.assertTrue(lifecycle.confirmed_absent_path(self.root, "naos/reports/selected.json"))
        with patch.object(Path, "lstat", side_effect=PermissionError("unreadable")):
            self.assertFalse(lifecycle.confirmed_absent_path(self.root, "naos/reports/selected.json"))
        with patch.object(Path, "lstat", return_value=object()):
            self.assertFalse(lifecycle.confirmed_absent_path(self.root, "naos/reports/selected.json"))

    def test_dangling_selected_report_is_not_confirmed_absent_when_links_are_supported(self):
        selected = self.root / "naos/reports/gate_status.json"
        try:
            selected.symlink_to(self.root / "naos/reports/missing-target.json")
        except OSError as exc:
            self.skipTest(f"symlink fixture unavailable: {type(exc).__name__}")
        self.assertTrue(selected.is_symlink())
        self.assertFalse(pr_summary.confirmed_absent_path(selected))
        self.assertFalse(behavioral.confirmed_absent_path(selected))
        self.assertFalse(lifecycle.confirmed_absent_path(self.root, "naos/reports/gate_status.json"))
        _exit_code, report = self.run_cli("pr-governance-summary")
        missing = next(item for item in report["findings"]
                       if item["id"] == "pr_governance.missing_reports")
        self.assertNotIn("evidence_classification", missing)
        classified = self.classify(self.root / "naos/reports/pr_governance_summary.json", expected=1)
        self.assertIn("pr_governance.missing_reports",
                      {item["finding_id"] for item in classified["missing_classification"]})

    def test_generated_candidate_and_open_gap_provenance_does_not_promote_or_unblock(self):
        remapped = "governance ü"
        folder = self.root / remapped
        folder.mkdir()
        (folder / "evidence_classification_policy.yaml").write_bytes(
            (self.root / "naos/evidence_classification_policy.yaml").read_bytes()
        )
        (self.root / "docs").mkdir()
        (self.root / "docs/DEPRECATION_LIST.md").write_text(
            "# Deprecation list\nLegacy labels must be removed.\n", encoding="utf-8"
        )
        candidate_code, candidates = self.run_cli("requirements-reconstruct", naos_root=remapped)
        gap_code, gaps = self.run_cli("traceability-gap-register", naos_root=remapped)
        self.assertEqual(candidate_code, 0)
        self.assertEqual(gap_code, 1)
        self.assert_schema(candidates, "candidate_requirements.schema.json")
        self.assert_schema(gaps, "traceability_gap_register.schema.json")
        self.assertEqual(candidates["status"], "review_required")
        self.assertEqual(gaps["status"], "review_required")
        self.assertEqual(len(candidates["findings"]), 1)
        self.assertEqual(len(gaps["findings"]), 1)
        candidate = candidates["candidates"][0]
        self.assertEqual(candidate["confidence_class"], "supported_by_docs")
        self.assertEqual(candidate["review_state"], "human_review_required")
        self.assertFalse(candidate["promoted_to_authority"])
        self.assertEqual(gaps["gaps"][0]["closure_state"], "open")
        self.assertTrue(gaps["gaps"][0]["human_review_required"])
        findings = (candidates["findings"][0], gaps["findings"][0])
        self.assertEqual([item["severity"] for item in findings], ["advisory", "blocking"])
        for item, scope in zip(findings, (
            "generated_candidate_review_obligation_only",
            "generated_open_candidate_review_gap_only",
        )):
            self.assertEqual(item["evidence_classification"], "confirmed")
            self.assertEqual(item["classification_scope"], scope)
            self.assertTrue(item["human_review_required"])
            self.assertTrue(item["classification_reason"])
            self.assertEqual(Path(item["source_path"]).resolve(),
                             (ROOT / "scripts/naos_adoption_common.py").resolve())
        classified = self.classify(folder / "reports/candidate_requirements.json",
                                   folder / "reports/traceability_gap_register.json",
                                   naos_root=remapped)
        self.assertFalse(classified["missing_classification"])
        self.assertEqual({item["classification"] for item in classified["classified_findings"]},
                         {"confirmed"})
        for item in classified["classified_findings"]:
            self.assert_real_local_ref(item)
        self.assertEqual(gap_code, 1)  # Provenance does not close the gap.

    def test_malformed_or_all_confirmed_candidate_input_keeps_baseline_gap_unclassified(self):
        candidate_path = self.root / "naos/reports/candidate_requirements.json"
        for label, content in (
            ("malformed", "{malformed"),
            ("all_confirmed", json.dumps({"candidates": [
                {"candidate_id": "FR-SPEC-001", "confidence_class": "confirmed_by_existing_spec"}
            ]})),
        ):
            with self.subTest(input=label):
                candidate_path.write_text(content, encoding="utf-8")
                code, report = self.run_cli("traceability-gap-register")
                self.assertEqual(code, 1)
                self.assert_schema(report, "traceability_gap_register.schema.json")
                self.assertEqual(report["status"], "review_required")
                self.assertEqual(report["gaps"][0]["gap_type"], "baseline_review")
                self.assertEqual(report["gaps"][0]["closure_state"], "open")
                finding = report["findings"][0]
                self.assertEqual(finding["severity"], "blocking")
                self.assertNotIn("evidence_classification", finding)
                self.assertNotIn("source_report", finding)
                classified = self.classify(self.root / "naos/reports/traceability_gap_register.json",
                                           expected=1)
                self.assertIn(finding["id"],
                              {item["finding_id"] for item in classified["missing_classification"]})

        # An incomplete loaded record still generates a gap. Confirming that
        # generated obligation cannot imply the upstream record was valid.
        candidate_path = self.root / "naos/reports/candidate_requirements.json"
        candidate_path.write_text(json.dumps({"candidates": [{}]}), encoding="utf-8")
        code, report = self.run_cli("traceability-gap-register")
        self.assertEqual(code, 1)
        self.assert_schema(report, "traceability_gap_register.schema.json")
        self.assertEqual(report["status"], "review_required")
        self.assertEqual(report["gaps"][0]["gap_type"], "candidate_requires_review")
        self.assertEqual(report["gaps"][0]["closure_state"], "open")
        finding = report["findings"][0]
        self.assertEqual(finding["severity"], "blocking")
        self.assertEqual(finding["evidence_classification"], "confirmed")
        self.assertEqual(finding["classification_scope"],
                         "generated_open_candidate_review_gap_only")
        self.assertIn("record validity", finding["classification_reason"])
        self.assertNotIn("source_report", finding)
        classified = self.classify(self.root / "naos/reports/traceability_gap_register.json")
        matched = next(item for item in classified["classified_findings"]
                       if item["finding_id"] == finding["id"])
        self.assertEqual(matched["classification"], "confirmed")
        self.assert_real_local_ref(matched)
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
