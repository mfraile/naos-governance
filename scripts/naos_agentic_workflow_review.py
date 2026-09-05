#!/usr/bin/env python3
"""Review declared NAOS agentic coding workflow controls."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    build_generated_by,
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    load_policy,
    normalize_profile,
    report_output_path,
    report_default_path,
    session_report_default_path,
    sessions_index_path,
    severity_for_profile,
    write_report_with_session,
)


SCHEMA = "naos.agentic_workflow_review.v1"
WORKFLOW_SCHEMA = "naos.agentic_workflow.v1"
REQUIRED_SECTIONS = [
    "context_hygiene",
    "pre_implementation_alignment",
    "vertical_slice_delivery",
    "tdd_feedback",
    "module_design",
    "human_ai_work_split",
    "kanban_dag",
    "push_pull_context",
]
OPTIONAL_SECTIONS = [
    "parallel_lane_opportunity",
    "implementation_readiness_baseline",
]
PARALLEL_LANE_OPPORTUNITIES = {
    "not_applicable",
    "sequential_recommended",
    "parallel_possible",
    "parallel_recommended",
}
PARALLEL_LANE_DECISIONS = {
    "sequential",
    "declared",
    "deferred",
}
PARALLEL_LANE_REASON_CODES = {
    "independent_acceptance_criteria",
    "distinct_path_scopes",
    "dependency_unlocked",
    "frontend_backend_test_docs_split",
    "high_context_load",
    "solo_checkpoint_value",
    "unresolved_dependency",
    "high_scope_overlap",
    "schema_or_api_decision_first",
    "high_risk_tightly_controlled_work",
    "missing_task_or_requirement_link",
    "missing_test_strategy",
}
REQUIRED_NOT_CLAIMED = {
    "behavioral correctness proof",
    "hallucination prevention",
    "autonomous approval",
    "compliance proof",
    "model attention guarantee",
    "human review replacement",
}
RELATED_ARTIFACTS = [
    ("quick_reference", "NAOS quick reference", "NAOS_QUICK_REFERENCE.md", True),
    ("playbook", "Agentic coding playbook", "AGENTIC_CODING_PLAYBOOK.md", True),
    ("pre_implementation_alignment", "Pre-Implementation Alignment artifact", "PRE_IMPLEMENTATION_ALIGNMENT.md", True),
    ("planning_baselines", "Implementation-readiness planning-baseline ledger", "PLANNING_BASELINES.yaml", False),
    ("session_identity", "Session identity report", ("reports", "session_identity_report"), False),
    ("operator_attribution", "Operator attribution report", ("reports", "operator_attribution_report"), False),
    ("task_claims", "Task claims report", ("reports", "task_claim_report"), False),
    ("gate_status", "Gate status report", ("reports", "gate_status_report"), False),
    ("gate_evaluation", "Gate evaluation report", ("reports", "gate_evaluation_report"), False),
    ("evidence_pack", "Evidence pack", ("evidence", "evidence_pack_report"), False),
    ("pr_governance", "PR governance summary", ("reports", "pr_governance_summary_report"), False),
    ("policy_overrides", "Policy override merge report", ("reports", "policy_override_merge_report"), False),
]
LIMITATIONS = [
    "Agentic workflow review inspects declared repo-local artifacts only.",
    "It does not inspect chat history, infer model attention, call models, or observe runtime assistant behavior.",
    "A complete workflow declaration does not prove behavioral correctness, requirements completeness, design approval, implementation approval, or compliance.",
]
NOT_CLAIMED = [
    "behavioral correctness proof",
    "hallucination prevention",
    "model attention guarantee",
    "autonomous approval",
    "requirements completeness proof",
    "design approval",
    "implementation approval",
    "compliance proof",
    "human review replacement",
    "memory write-back",
    "automatic context injection",
]
RESIDUAL_RISKS = [
    "Declared operating practices can drift from actual team behavior.",
    "Alignment artifacts and reports can become stale if not refreshed after scope changes.",
    "Human review quality and risk acceptance remain adopter-owned.",
]


def utc_now() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_yaml(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return None, str(exc)
    if not isinstance(data, dict):
        return None, "workflow file must parse to a YAML mapping"
    return data, None


def relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def latest_session_id(root: Path, naos_root: str, policy: dict[str, Any]) -> str | None:
    index_path = sessions_index_path(root, naos_root, policy)
    if not index_path.exists():
        return None
    try:
        data = json.loads(index_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    value = data.get("latest_session_id") if isinstance(data, dict) else None
    return str(value) if value else None


def workflow_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("agentic_workflow") or "agentic_workflow.yaml")
    project_path = root / naos_root / filename
    if project_path.exists() or not is_kit_repository(root, naos_root):
        return project_path, "project"
    return root / "templates" / "structural-seeds" / "naos" / "agentic_workflow.yaml", "kit_template"


def artifact_path(root: Path, naos_root: str, policy: dict[str, Any], spec: str | tuple[str, str]) -> Path:
    if isinstance(spec, str):
        return root / naos_root / spec
    kind, key = spec
    if kind == "reports":
        return report_default_path(root, naos_root, policy, key)
    if kind == "evidence":
        evidence_dir = str(policy.get("paths", {}).get("evidence_dir") or "evidence")
        filename = str(policy.get("paths", {}).get(key) or key)
        return root / naos_root / evidence_dir / filename
    return root / naos_root / str(key)


def finding(item_id: str, severity: str, status: str, message: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": item_id,
        "severity": severity,
        "status": status,
        "message": message,
        "human_review_required": True,
        **extra,
    }


def section_summary(name: str, data: dict[str, Any]) -> dict[str, Any]:
    section = data.get(name)
    if not isinstance(section, dict):
        return {"section": name, "present": False, "enabled": False, "status": "missing"}
    return {
        "section": name,
        "present": True,
        "enabled": section.get("enabled") is True,
        "status": "enabled" if section.get("enabled") is True else "review_required",
        "keys": sorted(section.keys()),
    }


def truthy_unsafe(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "enabled", "allowed", "allow", "on"}
    return False


def scan_unsafe_flags(data: Any, key_path: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if isinstance(data, dict):
        for key, value in data.items():
            lower = str(key).lower()
            path = (*key_path, str(key))
            if lower in {"auto_approval_allowed", "automatic_approval_allowed"} and truthy_unsafe(value):
                findings.append(
                    finding(
                        "agentic_workflow.auto_approval_allowed",
                        "required",
                        "review_required",
                        "Workflow config appears to allow automatic approval.",
                        path=".".join(path),
                    )
                )
            if lower in {"memory_write_back_allowed", "memory_writeback_allowed"} and truthy_unsafe(value):
                findings.append(
                    finding(
                        "agentic_workflow.memory_write_back_allowed",
                        "required",
                        "review_required",
                        "Workflow config appears to allow memory write-back.",
                        path=".".join(path),
                    )
                )
            if lower == "silent_context_injection_prohibited" and value is not True:
                findings.append(
                    finding(
                        "agentic_workflow.silent_context_injection_allowed",
                        "required",
                        "review_required",
                        "Silent context injection must remain prohibited.",
                        path=".".join(path),
                    )
                )
            findings.extend(scan_unsafe_flags(value, path))
    elif isinstance(data, list):
        for index, value in enumerate(data):
            findings.extend(scan_unsafe_flags(value, (*key_path, str(index))))
    return findings


def validate_workflow(data: dict[str, Any] | None, parse_error: str | None, profile: str, policy: dict[str, Any]) -> tuple[bool, list[dict[str, Any]]]:
    severity = severity_for_profile(profile, policy)
    if data is None:
        return False, [
            finding(
                "agentic_workflow.invalid_config",
                severity,
                "invalid_config",
                f"Agentic workflow config could not be parsed: {parse_error}",
            )
        ]
    findings: list[dict[str, Any]] = []
    valid = True
    if data.get("schema") != WORKFLOW_SCHEMA:
        valid = False
        findings.append(finding("agentic_workflow.schema", severity, "invalid_config", "Workflow schema id is missing or unsupported."))
    allowed_top = set(REQUIRED_SECTIONS) | set(OPTIONAL_SECTIONS) | {"schema", "profile", "updated_at", "not_claimed", "human_review_required", "extensions"}
    unknown = sorted(set(data) - allowed_top)
    if unknown:
        valid = False
        findings.append(
            finding(
                "agentic_workflow.unknown_top_level_fields",
                severity,
                "invalid_config",
                "Workflow config contains unsupported top-level fields.",
                fields=unknown,
            )
        )
    for section in REQUIRED_SECTIONS:
        value = data.get(section)
        if not isinstance(value, dict):
            valid = False
            findings.append(finding(f"agentic_workflow.{section}.missing", severity, "missing_section", f"Missing workflow section: {section}."))
        elif value.get("enabled") is not True:
            findings.append(finding(f"agentic_workflow.{section}.not_enabled", "warning", "review_required", f"Workflow section is not enabled: {section}."))
    context = data.get("context_hygiene") if isinstance(data.get("context_hygiene"), dict) else {}
    if context.get("compacted_chat_not_authoritative") is not True:
        findings.append(
            finding(
                "agentic_workflow.compacted_chat_authority",
                severity,
                "review_required",
                "Compacted chat must be treated as advisory rather than authoritative.",
            )
        )
    alignment = data.get("pre_implementation_alignment") if isinstance(data.get("pre_implementation_alignment"), dict) else {}
    required_questions = alignment.get("required_questions") if isinstance(alignment, dict) else []
    if not isinstance(required_questions, list) or not required_questions:
        findings.append(
            finding(
                "agentic_workflow.alignment_questions_missing",
                severity,
                "review_required",
                "Pre-Implementation Alignment required questions are missing.",
            )
        )
    vertical = data.get("vertical_slice_delivery") if isinstance(data.get("vertical_slice_delivery"), dict) else {}
    if not vertical.get("evidence_required"):
        findings.append(finding("agentic_workflow.vertical_slice_evidence_missing", "warning", "review_required", "Vertical-slice evidence expectations are missing."))
    tdd = data.get("tdd_feedback") if isinstance(data.get("tdd_feedback"), dict) else {}
    if tdd.get("implementation_without_tests_is_review_required") is not True:
        findings.append(finding("agentic_workflow.tdd_feedback_missing", severity, "review_required", "Implementation without tests must route to review."))
    human_ai = data.get("human_ai_work_split") if isinstance(data.get("human_ai_work_split"), dict) else {}
    if not human_ai.get("human_tasks") or not human_ai.get("afk_candidate_tasks"):
        findings.append(finding("agentic_workflow.human_ai_split_missing", severity, "review_required", "Human/AI work split is incomplete."))
    kanban = data.get("kanban_dag") if isinstance(data.get("kanban_dag"), dict) else {}
    if "explicit_dependencies_required" not in kanban:
        findings.append(finding("agentic_workflow.task_dependency_guidance_missing", "warning", "review_required", "Task dependency guidance is missing."))
    lane_raw = data.get("parallel_lane_opportunity")
    lane = lane_raw if isinstance(lane_raw, dict) else {}
    if "parallel_lane_opportunity" in data and not isinstance(lane_raw, dict):
        valid = False
        findings.append(
            finding(
                "agentic_workflow.parallel_lane_opportunity.invalid",
                severity,
                "review_required",
                "parallel_lane_opportunity must be a mapping when present.",
            )
        )
    if lane:
        if lane.get("enabled") is not True:
            findings.append(
                finding(
                    "agentic_workflow.parallel_lane_opportunity.not_enabled",
                    "warning",
                    "review_required",
                    "Parallel-lane opportunity advisory posture is present but not enabled.",
                )
            )
        advisory_values = lane.get("advisory_values")
        if (
            not isinstance(advisory_values, list)
            or any(not isinstance(item, str) for item in advisory_values)
            or set(advisory_values) != PARALLEL_LANE_OPPORTUNITIES
        ):
            findings.append(
                finding(
                    "agentic_workflow.parallel_lane_opportunity.advisory_values",
                    severity,
                    "review_required",
                    "Parallel-lane opportunity advisory values must match the controlled vocabulary.",
                    expected=sorted(PARALLEL_LANE_OPPORTUNITIES),
                )
            )
        decision_values = lane.get("decision_values")
        if (
            not isinstance(decision_values, list)
            or any(not isinstance(item, str) for item in decision_values)
            or set(decision_values) != PARALLEL_LANE_DECISIONS
        ):
            findings.append(
                finding(
                    "agentic_workflow.parallel_lane_opportunity.decision_values",
                    severity,
                    "review_required",
                    "Parallel-lane decision values must be sequential, declared, and deferred.",
                    expected=sorted(PARALLEL_LANE_DECISIONS),
                )
            )
        reason_codes = lane.get("reason_codes")
        if (
            not isinstance(reason_codes, list)
            or any(not isinstance(item, str) for item in reason_codes)
            or not set(reason_codes).issubset(PARALLEL_LANE_REASON_CODES)
        ):
            findings.append(
                finding(
                    "agentic_workflow.parallel_lane_opportunity.reason_codes",
                    severity,
                    "review_required",
                    "Parallel-lane reason codes must use explicit controlled values.",
                    expected=sorted(PARALLEL_LANE_REASON_CODES),
                )
            )
        for key in [
            "declaration_required_for_handoff",
            "suggested_lanes_do_not_activate_handoff",
            "no_silent_activation",
            "no_branch_or_worktree_automation",
        ]:
            if lane.get(key) is not True:
                findings.append(
                    finding(
                        f"agentic_workflow.parallel_lane_opportunity.{key}",
                        severity,
                        "review_required",
                        f"Parallel-lane opportunity boundary must keep {key} true.",
                    )
                )
    baseline_raw = data.get("implementation_readiness_baseline")
    baseline = baseline_raw if isinstance(baseline_raw, dict) else {}
    if "implementation_readiness_baseline" in data and not isinstance(baseline_raw, dict):
        valid = False
        findings.append(
            finding(
                "agentic_workflow.implementation_readiness_baseline.invalid",
                severity,
                "review_required",
                "implementation_readiness_baseline must be a mapping when present.",
            )
        )
    if baseline:
        expected_profile_inputs = {
            "lite": ["requirements", "task_registry", "alignment", "owner_decision"],
            "standard": ["requirements", "architecture", "task_registry", "alignment", "owner_decision"],
            "assured": ["requirements", "architecture", "task_registry", "alignment", "owner_decision"],
        }
        expected = {
            "enabled": True,
            "applicable_profiles": ["lite", "standard", "assured"],
            "required_artifact": "naos/PLANNING_BASELINES.yaml",
            "planning_model": "hybrid_vertical_default",
            "draft_and_discovery_allowed": True,
            "profile_inputs": expected_profile_inputs,
            "structural_evidence": ["spec_pack_contract", "pre_implementation_alignment_review"],
            "replanning_method": "versioned_supersession",
            "routine_task_status_change_requires_rebaseline": False,
            "horizontal_foundation_requires": ["consuming_vertical_slice", "changed_consumed_result"],
        }
        mismatches = [key for key, value in expected.items() if baseline.get(key) != value]
        does_not_authorize = {str(item) for item in baseline.get("does_not_authorize") or []}
        if not {"implementation", "task closure", "merge", "release"}.issubset(does_not_authorize):
            mismatches.append("does_not_authorize")
        if mismatches:
            findings.append(
                finding(
                    "agentic_workflow.implementation_readiness_baseline.contract",
                    severity,
                    "review_required",
                    "Implementation-readiness planning policy does not match the bounded hybrid/profile/replanning contract.",
                    mismatches=sorted(set(mismatches)),
                )
            )
    push_pull = data.get("push_pull_context") if isinstance(data.get("push_pull_context"), dict) else {}
    if not push_pull.get("pull_context") or not push_pull.get("push_context"):
        findings.append(finding("agentic_workflow.push_pull_context_missing", severity, "review_required", "Push/pull context declaration is incomplete."))
    not_claimed = set(str(item) for item in data.get("not_claimed") or [])
    missing_non_claims = sorted(REQUIRED_NOT_CLAIMED - not_claimed)
    if missing_non_claims:
        findings.append(
            finding(
                "agentic_workflow.not_claimed_missing",
                severity,
                "review_required",
                "Required non-claims are missing.",
                missing=missing_non_claims,
            )
        )
    if data.get("human_review_required") is not True:
        findings.append(finding("agentic_workflow.human_review_missing", severity, "review_required", "human_review_required must be true."))
    findings.extend(scan_unsafe_flags(data))
    return valid, findings


def related_artifacts(root: Path, naos_root: str, policy: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    artifacts: list[dict[str, Any]] = []
    missing: list[str] = []
    kit = is_kit_repository(root, naos_root)
    for artifact_id, label, spec, expected in RELATED_ARTIFACTS:
        path = artifact_path(root, naos_root, policy, spec)
        exists = path.exists()
        if expected and not exists and kit and isinstance(spec, str):
            template_path = root / "templates" / "structural-seeds" / "naos" / Path(spec).name
            exists = template_path.exists()
            path = template_path
        item = {
            "id": artifact_id,
            "label": label,
            "path": relative(path, root),
            "exists": exists,
            "expected": expected,
        }
        artifacts.append(item)
        if expected and not exists:
            missing.append(artifact_id)
    return artifacts, missing


def status_for(workflow_present: bool, workflow_valid: bool, findings: list[dict[str, Any]], missing_artifacts: list[str]) -> str:
    if not workflow_present:
        return "missing_config"
    if not workflow_valid:
        return "invalid_config"
    if any(item.get("severity") in {"blocking", "required"} for item in findings):
        return "review_required"
    if missing_artifacts:
        return "missing_artifacts"
    if findings:
        return "advisory"
    return "ready"


def build_report(root: Path, naos_root: str, profile: str, policy: dict[str, Any], explicit_input: str | None = None) -> dict[str, Any]:
    generated_at = utc_now()
    path, source = workflow_path(root, naos_root, policy, explicit_input)
    present = path.exists()
    data: dict[str, Any] | None = None
    parse_error: str | None = None
    if present:
        data, parse_error = load_yaml(path)
    valid, findings = validate_workflow(data, parse_error, profile, policy) if present else (False, [])
    if not present:
        findings.append(
            finding(
                "agentic_workflow.missing_config",
                severity_for_profile(profile, policy),
                "missing_config",
                f"Agentic workflow config not found: {path}",
            )
        )
    artifacts, missing_artifacts = related_artifacts(root, naos_root, policy)
    if missing_artifacts and not is_kit_repository(root, naos_root):
        findings.append(
            finding(
                "agentic_workflow.missing_related_artifacts",
                "warning",
                "missing_artifacts",
                "One or more expected agentic workflow artifacts are missing.",
                missing_artifacts=missing_artifacts,
            )
        )
    sections = [section_summary(name, data or {}) for name in REQUIRED_SECTIONS]
    optional_sections = [section_summary(name, data or {}) for name in OPTIONAL_SECTIONS if isinstance((data or {}).get(name), dict)]
    summary = finding_counts(findings)
    summary.update(
        {
            "sections": len(sections),
            "sections_present": sum(1 for item in sections if item["present"]),
            "sections_enabled": sum(1 for item in sections if item["enabled"]),
            "optional_sections": len(optional_sections),
            "optional_sections_enabled": sum(1 for item in optional_sections if item["enabled"]),
            "related_artifacts": len(artifacts),
            "missing_artifacts": len(missing_artifacts),
            "human_review_required": 1,
        }
    )
    session_id = latest_session_id(root, naos_root, policy)
    generated_by = build_generated_by(root, session_id=session_id, generated_at=generated_at)
    status = status_for(present, valid, findings, missing_artifacts if not is_kit_repository(root, naos_root) else [])
    return {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "session_id": session_id,
        "operator_id": generated_by.get("operator_id"),
        "generated_by": generated_by,
        "workflow_config_path": str(path),
        "workflow_config_source": source,
        "workflow_config_present": present,
        "workflow_config_valid": valid,
        "sections": sections,
        "optional_sections": optional_sections,
        "context_hygiene": section_summary("context_hygiene", data or {}),
        "pre_implementation_alignment": section_summary("pre_implementation_alignment", data or {}),
        "vertical_slice_delivery": section_summary("vertical_slice_delivery", data or {}),
        "tdd_feedback": section_summary("tdd_feedback", data or {}),
        "module_design": section_summary("module_design", data or {}),
        "human_ai_work_split": section_summary("human_ai_work_split", data or {}),
        "kanban_dag": section_summary("kanban_dag", data or {}),
        "parallel_lane_opportunity": section_summary("parallel_lane_opportunity", data or {}),
        "implementation_readiness_baseline": section_summary("implementation_readiness_baseline", data or {}),
        "push_pull_context": section_summary("push_pull_context", data or {}),
        "related_artifacts": artifacts,
        "missing_artifacts": missing_artifacts,
        "findings": findings,
        "known_gaps": [
            "actual_assistant_behavior_not_observed",
            "alignment_quality_requires_human_review",
            "external_tool_context_management_not_enforced",
        ],
        "residual_risks": RESIDUAL_RISKS,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": True,
        "summary": summary,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Review NAOS governed agentic coding workflow controls.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--input", help="Explicit agentic_workflow.yaml path.")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    report = build_report(root, naos_root, profile, policy, args.input)
    latest_path = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "agentic_workflow_review_report")
    session_path = None
    if report.get("session_id"):
        session_path = session_report_default_path(root, naos_root, policy, str(report["session_id"]), "agentic_workflow_review_report")
    write_report_with_session(latest_path, session_path, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        destination = str(latest_path) if latest_path else "stdout only"
        print(f"NAOS agentic workflow review: {report['status']} (output: {destination})")
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
