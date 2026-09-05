#!/usr/bin/env python3
"""Review the NAOS Pre-Implementation Alignment artifact."""

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
    session_report_default_path,
    sessions_index_path,
    severity_for_profile,
    write_report_with_session,
)


SCHEMA = "naos.pre_implementation_alignment_review.v1"
ALIGNMENT_SCHEMA = "naos.pre_implementation_alignment.v1"
QUESTION_FIELDS = [
    "intended_user",
    "problem_statement",
    "first_vertical_slice",
    "input_output_contract",
    "edge_cases",
    "failure_modes",
    "security_privacy_assumptions",
    "existing_interfaces_touched",
    "backward_compatibility_constraints",
    "architecture_assumptions",
    "known_fragile_modules_or_risk_areas",
    "test_strategy",
    "evidence_required",
    "explicit_out_of_scope",
    "human_review_boundary",
]
OPTIONAL_PATH_FIELDS = [
    "planned_change_paths",
    "out_of_scope_paths",
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
LANE_REVIEW_OPPORTUNITIES = {"parallel_possible", "parallel_recommended"}
MODE_REQUIRED = {
    "greenfield": [
        "intended_user",
        "problem_statement",
        "first_vertical_slice",
        "architecture_assumptions",
        "test_strategy",
        "evidence_required",
        "explicit_out_of_scope",
    ],
    "brownfield": [
        "existing_interfaces_touched",
        "backward_compatibility_constraints",
        "test_strategy",
        "known_fragile_modules_or_risk_areas",
        "explicit_out_of_scope",
    ],
    "feature": [
        "input_output_contract",
        "first_vertical_slice",
        "edge_cases",
        "failure_modes",
        "test_strategy",
        "evidence_required",
        "human_review_boundary",
    ],
}
REQUIRED_NOT_CLAIMED = {
    "requirements completeness proof",
    "design approval",
    "implementation approval",
    "compliance proof",
    "human review replacement",
}
LIMITATIONS = [
    "Pre-Implementation Alignment review inspects a structured Markdown artifact only.",
    "It does not ask questions interactively, call models, approve design, approve implementation, or prove requirements completeness.",
    "Human review remains required before relying on the alignment artifact for implementation scope.",
]
NOT_CLAIMED = [
    "requirements completeness proof",
    "design approval",
    "implementation approval",
    "compliance proof",
    "human review replacement",
    "autonomous approval",
    "behavioral correctness proof",
]
RESIDUAL_RISKS = [
    "Answers may be incomplete, stale, or too vague for the actual implementation risk.",
    "Brownfield interface and regression risks may require additional domain review.",
    "Human review quality remains adopter-owned.",
]


def utc_now() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def alignment_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("pre_implementation_alignment") or "PRE_IMPLEMENTATION_ALIGNMENT.md")
    project_path = root / naos_root / filename
    if project_path.exists() or not is_kit_repository(root, naos_root):
        return project_path, "project"
    return root / "templates" / "structural-seeds" / "naos" / "PRE_IMPLEMENTATION_ALIGNMENT.md", "kit_template"


def extract_frontmatter(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        return None, str(exc)
    if not text.startswith("---\n"):
        return None, "alignment file is missing YAML frontmatter"
    end = text.find("\n---", 4)
    if end == -1:
        return None, "alignment file has unterminated YAML frontmatter"
    raw = text[4:end]
    try:
        data = yaml.safe_load(raw) or {}
    except Exception as exc:
        return None, str(exc)
    if not isinstance(data, dict):
        return None, "alignment frontmatter must parse to a mapping"
    return data, None


def has_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip()) and not value.strip().startswith("[ADAPT")
    if isinstance(value, list):
        return any(has_value(item) for item in value)
    return True


def finding(item_id: str, severity: str, status: str, message: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": item_id,
        "severity": severity,
        "status": status,
        "message": message,
        "human_review_required": True,
        **extra,
    }


def validate_alignment(data: dict[str, Any] | None, parse_error: str | None, profile: str, policy: dict[str, Any]) -> tuple[bool, list[dict[str, Any]]]:
    severity = severity_for_profile(profile, policy)
    if data is None:
        return False, [
            finding(
                "pre_implementation_alignment.invalid_alignment",
                severity,
                "invalid_alignment",
                f"Alignment artifact could not be parsed: {parse_error}",
            )
        ]
    findings: list[dict[str, Any]] = []
    allowed_top = {
        "schema",
        "mode",
        "task_id",
        "feature_name",
        "status",
        "parallel_lane_opportunity",
        "parallel_lane_decision",
        "parallel_lane_reasons",
        "parallel_lane_candidate_lanes",
        "questions",
        "not_claimed",
        "human_review_required",
        "extensions",
    }
    unknown = sorted(set(data) - allowed_top)
    if unknown:
        findings.append(
            finding(
                "pre_implementation_alignment.unknown_top_level_fields",
                severity,
                "invalid_alignment",
                "Alignment frontmatter contains unsupported top-level fields.",
                fields=unknown,
            )
        )
    if data.get("schema") != ALIGNMENT_SCHEMA:
        findings.append(finding("pre_implementation_alignment.schema", severity, "invalid_alignment", "Alignment schema id is missing or unsupported."))
    if data.get("mode") not in MODE_REQUIRED:
        findings.append(finding("pre_implementation_alignment.mode", severity, "invalid_alignment", "Alignment mode must be greenfield, brownfield, or feature."))
    questions = data.get("questions")
    if not isinstance(questions, dict):
        findings.append(finding("pre_implementation_alignment.questions", severity, "invalid_alignment", "Alignment questions must be a mapping."))
        questions = {}
    missing_fields = [field for field in QUESTION_FIELDS if field not in questions]
    if missing_fields:
        findings.append(
            finding(
                "pre_implementation_alignment.question_fields_missing",
                severity,
                "invalid_alignment",
                "Required question fields are missing.",
                missing=missing_fields,
            )
        )
    for field in OPTIONAL_PATH_FIELDS:
        if field not in questions:
            continue
        value = questions.get(field)
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            findings.append(
                finding(
                    f"pre_implementation_alignment.{field}.invalid",
                    severity,
                    "invalid_alignment",
                    f"{field} must be a list of path strings when present.",
                    field=field,
                )
            )
    opportunity = data.get("parallel_lane_opportunity")
    if opportunity is not None and opportunity not in PARALLEL_LANE_OPPORTUNITIES:
        findings.append(
            finding(
                "pre_implementation_alignment.parallel_lane_opportunity.invalid",
                severity,
                "invalid_alignment",
                "parallel_lane_opportunity must use the controlled advisory vocabulary.",
                allowed=sorted(PARALLEL_LANE_OPPORTUNITIES),
            )
        )
    decision = data.get("parallel_lane_decision")
    if decision is not None and decision not in PARALLEL_LANE_DECISIONS:
        findings.append(
            finding(
                "pre_implementation_alignment.parallel_lane_decision.invalid",
                severity,
                "invalid_alignment",
                "parallel_lane_decision must be sequential, declared, or deferred.",
                allowed=sorted(PARALLEL_LANE_DECISIONS),
            )
        )
    reasons = data.get("parallel_lane_reasons")
    if reasons is not None:
        invalid_reasons = []
        if not isinstance(reasons, list):
            invalid_reasons = ["parallel_lane_reasons_not_a_list"]
        else:
            invalid_reasons = sorted(str(item) for item in reasons if str(item) not in PARALLEL_LANE_REASON_CODES)
        if invalid_reasons:
            findings.append(
                finding(
                    "pre_implementation_alignment.parallel_lane_reasons.invalid",
                    severity,
                    "invalid_alignment",
                    "parallel_lane_reasons must use explicit reason codes.",
                    invalid=invalid_reasons,
                    allowed=sorted(PARALLEL_LANE_REASON_CODES),
                )
            )
    candidate_lanes = data.get("parallel_lane_candidate_lanes")
    if candidate_lanes is not None and (
        not isinstance(candidate_lanes, list) or any(not isinstance(item, str) for item in candidate_lanes)
    ):
        findings.append(
            finding(
                "pre_implementation_alignment.parallel_lane_candidate_lanes.invalid",
                severity,
                "invalid_alignment",
                "parallel_lane_candidate_lanes must be a list of strings.",
            )
        )
    non_trivial = bool(data.get("mode") in {"greenfield", "brownfield", "feature"} and (data.get("task_id") or data.get("feature_name")))
    if non_trivial and opportunity is None:
        findings.append(
            finding(
                "pre_implementation_alignment.parallel_lane_opportunity.missing",
                "advisory",
                "review_required",
                "Non-trivial alignment is missing advisory parallel_lane_opportunity posture.",
            )
        )
    if non_trivial and decision is None:
        findings.append(
            finding(
                "pre_implementation_alignment.parallel_lane_decision.missing",
                "advisory",
                "review_required",
                "Non-trivial alignment is missing parallel_lane_decision posture.",
            )
        )
    if opportunity in LANE_REVIEW_OPPORTUNITIES and decision == "deferred":
        findings.append(
            finding(
                "pre_implementation_alignment.parallel_lane_decision.deferred_for_parallel_opportunity",
                "advisory",
                "review_required",
                "Parallel-lane opportunity is suggested but the lane decision is deferred.",
                opportunity=opportunity,
            )
        )
    not_claimed = set(str(item) for item in data.get("not_claimed") or [])
    missing_non_claims = sorted(REQUIRED_NOT_CLAIMED - not_claimed)
    if missing_non_claims:
        findings.append(
            finding(
                "pre_implementation_alignment.not_claimed_missing",
                severity,
                "review_required",
                "Required non-claims are missing.",
                missing=missing_non_claims,
            )
        )
    if data.get("human_review_required") is not True:
        findings.append(finding("pre_implementation_alignment.human_review_missing", severity, "review_required", "human_review_required must be true."))
    valid = not any(item.get("status") == "invalid_alignment" for item in findings)
    return valid, findings


def mode_findings(mode: str | None, data: dict[str, Any] | None, profile: str, policy: dict[str, Any]) -> tuple[list[str], dict[str, list[dict[str, Any]]]]:
    questions = data.get("questions") if isinstance(data, dict) and isinstance(data.get("questions"), dict) else {}
    severity = severity_for_profile(profile, policy)
    groups = {"greenfield": [], "brownfield": [], "feature": []}
    missing: list[str] = []
    for mode_name, fields in MODE_REQUIRED.items():
        for field in fields:
            if not has_value(questions.get(field)):
                item = finding(
                    f"pre_implementation_alignment.{mode_name}.{field}.missing",
                    severity if mode == mode_name else "advisory",
                    "missing_required_questions",
                    f"{mode_name} alignment is missing: {field}.",
                    question=field,
                    mode=mode_name,
                )
                if mode == mode_name:
                    missing.append(field)
                groups[mode_name].append(item)
    if mode == "feature" and not (has_value(data.get("task_id") if data else None) or has_value(data.get("feature_name") if data else None)):
        item = finding(
            "pre_implementation_alignment.feature.task_or_feature_missing",
            severity,
            "missing_required_questions",
            "Feature mode requires task_id or feature_name.",
            question="task_id_or_feature_name",
            mode="feature",
        )
        missing.append("task_id_or_feature_name")
        groups["feature"].append(item)
    return sorted(set(missing)), groups


def question_coverage(data: dict[str, Any] | None) -> dict[str, Any]:
    questions = data.get("questions") if isinstance(data, dict) and isinstance(data.get("questions"), dict) else {}
    answered = [field for field in QUESTION_FIELDS if has_value(questions.get(field))]
    missing = [field for field in QUESTION_FIELDS if field not in questions or not has_value(questions.get(field))]
    return {
        "total_questions": len(QUESTION_FIELDS),
        "answered_questions": len(answered),
        "missing_or_unanswered_questions": len(missing),
        "answered": answered,
        "missing_or_unanswered": missing,
    }


def path_declarations(data: dict[str, Any] | None) -> dict[str, list[str]]:
    questions = data.get("questions") if isinstance(data, dict) and isinstance(data.get("questions"), dict) else {}
    declarations: dict[str, list[str]] = {}
    for field in OPTIONAL_PATH_FIELDS:
        value = questions.get(field)
        if isinstance(value, list):
            declarations[field] = [str(item).strip() for item in value if str(item).strip()]
        else:
            declarations[field] = []
    return declarations


def parallel_lane_posture(data: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {
            "present": False,
            "opportunity": None,
            "decision": None,
            "reasons": [],
            "candidate_lanes": [],
            "declaration_required_for_handoff": False,
            "limitations": [
                "No alignment artifact was parsed; lane posture could not be read.",
            ],
        }
    reasons = data.get("parallel_lane_reasons")
    candidate_lanes = data.get("parallel_lane_candidate_lanes")
    opportunity = data.get("parallel_lane_opportunity")
    decision = data.get("parallel_lane_decision")
    present = any(
        key in data
        for key in [
            "parallel_lane_opportunity",
            "parallel_lane_decision",
            "parallel_lane_reasons",
            "parallel_lane_candidate_lanes",
        ]
    )
    return {
        "present": present,
        "opportunity": opportunity if opportunity in PARALLEL_LANE_OPPORTUNITIES else None,
        "decision": decision if decision in PARALLEL_LANE_DECISIONS else None,
        "reasons": [str(item) for item in reasons] if isinstance(reasons, list) else [],
        "candidate_lanes": [str(item) for item in candidate_lanes] if isinstance(candidate_lanes, list) else [],
        "declaration_required_for_handoff": decision == "declared",
        "limitations": [
            "Lane posture is advisory planning evidence only.",
            "Suggested lanes do not require handoff unless a lane is explicitly declared.",
        ],
    }


def status_for(present: bool, valid: bool, missing_required: list[str], findings: list[dict[str, Any]]) -> str:
    if not present:
        return "missing_alignment"
    if not valid:
        return "invalid_alignment"
    if missing_required:
        return "missing_required_questions"
    if any(item.get("severity") in {"blocking", "required"} for item in findings):
        return "review_required"
    if findings:
        return "advisory"
    return "ready"


def build_report(root: Path, naos_root: str, profile: str, policy: dict[str, Any], explicit_input: str | None = None) -> dict[str, Any]:
    generated_at = utc_now()
    path, source = alignment_path(root, naos_root, policy, explicit_input)
    present = path.exists()
    data: dict[str, Any] | None = None
    parse_error: str | None = None
    if present:
        data, parse_error = extract_frontmatter(path)
    valid, findings = validate_alignment(data, parse_error, profile, policy) if present else (False, [])
    if not present:
        findings.append(
            finding(
                "pre_implementation_alignment.missing_alignment",
                severity_for_profile(profile, policy),
                "missing_alignment",
                f"Pre-Implementation Alignment artifact not found: {path}",
            )
        )
    mode = data.get("mode") if isinstance(data, dict) else None
    missing_required, grouped = mode_findings(str(mode) if mode else None, data, profile, policy)
    active_mode_findings = grouped.get(str(mode), []) if mode in grouped else []
    findings.extend(active_mode_findings)
    coverage = question_coverage(data)
    scope_paths = path_declarations(data)
    lane_posture = parallel_lane_posture(data)
    summary = finding_counts(findings)
    summary.update(
        {
            "answered_questions": coverage["answered_questions"],
            "total_questions": coverage["total_questions"],
            "missing_required_questions": len(missing_required),
            "human_review_required": 1,
        }
    )
    session_id = latest_session_id(root, naos_root, policy)
    generated_by = build_generated_by(root, session_id=session_id, generated_at=generated_at)
    status = status_for(present, valid, missing_required, findings)
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
        "alignment_path": str(path),
        "alignment_source": source,
        "alignment_present": present,
        "alignment_valid": valid,
        "mode": mode,
        "task_id": data.get("task_id") if isinstance(data, dict) else None,
        "feature_name": data.get("feature_name") if isinstance(data, dict) else None,
        "question_coverage": coverage,
        "implementation_scope_paths": scope_paths,
        "parallel_lane_opportunity": lane_posture,
        "greenfield_findings": grouped["greenfield"],
        "brownfield_findings": grouped["brownfield"],
        "feature_findings": grouped["feature"],
        "missing_required_questions": missing_required,
        "findings": findings,
        "known_gaps": [
            "alignment_quality_requires_human_review",
            "actual_requirement_completeness_not_proven",
            "assistant_interview_behavior_not_observed",
        ],
        "residual_risks": RESIDUAL_RISKS,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": True,
        "summary": summary,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Review NAOS Pre-Implementation Alignment artifact.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--input", help="Explicit PRE_IMPLEMENTATION_ALIGNMENT.md path.")
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
    latest_path = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "pre_implementation_alignment_review_report")
    session_path = None
    if report.get("session_id"):
        session_path = session_report_default_path(root, naos_root, policy, str(report["session_id"]), "pre_implementation_alignment_review_report")
    write_report_with_session(latest_path, session_path, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        destination = str(latest_path) if latest_path else "stdout only"
        print(f"NAOS Pre-Implementation Alignment review: {report['status']} (output: {destination})")
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
