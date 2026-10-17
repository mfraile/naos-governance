#!/usr/bin/env python3
"""Summarize NAOS pull-request governance evidence for CI review."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    build_generated_by,
    default_naos_root,
    load_policy,
    normalize_profile,
    report_output_path,
    resolve_operator_attribution,
    write_report,
)
from naos_evidence_contracts import classify_evidence  # noqa: E402

SCHEMA = "naos.pr_governance_summary.v1"
REPORT_KEYS = {
    "gate_status": "gate_status_report",
    "gate_evaluation": "gate_evaluation_report",
    "evidence_pack": "evidence_pack_report",
    "dashboard": "dashboard_summary_report",
    "evidence_conflicts": "evidence_conflict_detection_report",
    "task_claims": "task_claim_report",
    "sarif": "sarif_export_summary_report",
    "self_check": "self_check_report",
    "policy_overrides": "policy_override_merge_report",
    "pr_risk_classification": "pr_risk_classification_report",
    "agentic_workflow": "agentic_workflow_review_report",
    "pre_implementation_alignment": "pre_implementation_alignment_review_report",
}
EXPECTED_VALIDATORS = [
    "validate_capability_contracts.py",
    "validate_docs_consistency.py",
    "validate_tutorial_consistency.py",
    "validate_implementation_reality.py",
    "python -m unittest discover -s tests",
]
LIMITATIONS = [
    "PR-time CI summarizes deterministic NAOS evidence and review signals only.",
    "CI environment metadata, TEAM_ID, and NAOS_OPERATOR_ID are governance metadata, not authentication, authorization, or team-membership proof.",
    "Artifact upload settings are adopter-controlled; review report sensitivity before enabling artifact retention.",
    "The default PR governance workflow does not deploy, publish, release, push commits, call model/provider APIs, call memory tools, or write memory.",
]
NOT_CLAIMED = [
    "PR approval",
    "CI approval",
    "deployment authorization",
    "release authorization",
    "legal or regulatory compliance",
    "proof of compliance",
    "certification",
    "separation-of-duties satisfaction",
    "conflict resolution",
    "authentication",
    "authorization",
    "access control",
    "team membership proof",
    "model/API/provider call",
    "memory write-back",
]
RESIDUAL_RISKS = [
    "CI artifacts may contain governance metadata and should be reviewed before upload or long retention.",
    "Passing CI does not replace human review.",
    "Missing reports may indicate a skipped command or an unsupported profile/project shape.",
    "Team and operator metadata can be spoofed without adopter-owned identity controls.",
]


def utc_now() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def git_value(root: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None
    value = result.stdout.strip()
    return value if result.returncode == 0 and value else None


def report_path(root: Path, naos_root: str, policy: dict[str, Any], key: str) -> Path:
    reports_dir = str(policy.get("paths", {}).get("reports_dir") or "reports")
    filename = str(policy.get("paths", {}).get(key) or key)
    if key == "evidence_pack_report":
        evidence_dir = str(policy.get("paths", {}).get("evidence_dir") or "evidence")
        return root / naos_root / evidence_dir / filename
    return root / naos_root / reports_dir / filename


def confirmed_absent_path(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return None, None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        return None, str(exc)
    return data if isinstance(data, dict) else {}, None


def compact_summary(data: dict[str, Any] | None, *keys: str) -> dict[str, Any]:
    if not data:
        return {"status": "missing"}
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    result: dict[str, Any] = {"status": data.get("status", "present"), "summary": summary}
    for key in keys:
        if key in data:
            result[key] = data.get(key)
    if "human_review_required" in data:
        result["human_review_required"] = bool(data.get("human_review_required"))
    return result


def project_gate_readiness(
    root: Path, naos_root: str, profile: str, policy: dict[str, Any],
    label: str, *, source_path: Path | None = None,
) -> dict[str, Any]:
    """Project a bounded source gate report; never infer approval from storage."""
    path = source_path if source_path is not None else report_path(root, naos_root, policy, REPORT_KEYS[label])
    projection: dict[str, Any] = {
        "source_path": str(path),
        "readiness": "not_evaluated",
        "required_readiness": "not_evaluated",
        "required_reason_codes": [],
        "validation": "not_evaluated",
        "scope": "not_established",
        "reason_codes": [],
        "source_finding_refs": [],
        "source_content_sha256": None,
        "evaluation_scope": None,
        "summary": None,
        "gates": [],
        "protected_invariant_violations": [],
        "enforcement": None,
    }
    if not path.is_file():
        projection["reason_codes"] = ["gate_report_missing_or_not_regular"]
        return projection
    try:
        reference = path.relative_to(root.resolve()).as_posix()
        classified = classify_evidence(
            root, reference, profile=profile, naos_root=naos_root,
            policy=policy, consumer="pack",
        )
    except (OSError, ValueError, TypeError) as exc:
        projection.update(readiness="unresolved", validation="invalid", reason_codes=[type(exc).__name__])
        return projection
    projection.update(
        source_content_sha256=classified.get("content_sha256"),
        validation=classified["validation"],
        scope=classified["scope"],
        reason_codes=classified["reason_codes"],
        source_finding_refs=classified["source_findings"],
        readiness="ready" if classified["requirement_outcome"] == "satisfied" else "unresolved",
    )
    if classified.get("report_key") != label:
        projection.update(readiness="unresolved", validation="invalid",
                          reason_codes=[*projection["reason_codes"], "gate_source_type_mismatch"])
        return projection
    if projection["source_finding_refs"] and projection["readiness"] == "ready":
        projection["readiness"] = "unresolved"
        projection["reason_codes"] = [*projection["reason_codes"], "gate_source_findings_present"]
    # Unvalidated content is still in the source artifact, but is not promoted
    # into this review projection as trusted gate structure.
    if classified["validation"] != "valid" or classified["scope"] != "matched":
        return projection
    try:
        content = path.read_bytes()
        data = json.loads(content)
    except (OSError, ValueError, RecursionError):
        data = None
        content = b""
    if not isinstance(data, dict) or hashlib.sha256(content).hexdigest() != classified.get("content_sha256"):
        projection.update(readiness="unresolved", validation="invalid", reason_codes=["gate_report_changed_or_unreadable"])
        return projection
    from naos_evidence_contracts import _maturity_aggregate_outcome

    required_ready, required_codes = _maturity_aggregate_outcome(
        data, label, policy, permit_advisory_gaps=True,
    )
    # Only the exact all-selected-gate gap may receive the advisory projection.
    # Never override freshness, source-binding, or future classifier refusals.
    if (classified["requirement_outcome"] != "satisfied"
            and set(classified["reason_codes"]) != {"selected_gate_unresolved"}):
        required_ready = False
        required_codes = [*required_codes, *classified["reason_codes"], "gate_classifier_refusal_retained"]
    if projection["source_finding_refs"]:
        required_ready = False
        required_codes = [*required_codes, "gate_source_findings_present"]
    projection["required_readiness"] = "ready" if required_ready else "unresolved"
    projection["required_reason_codes"] = required_codes
    projection["evaluation_scope"] = data.get("evaluation_scope")
    projection["summary"] = data.get("summary")
    projection["protected_invariant_violations"] = data.get("protected_invariant_violations", [])
    if label == "gate_evaluation":
        projection["enforcement"] = data.get("enforcement")
    projection["gates"] = [
        {
            "id": gate["id"],
            "status": gate["status"],
            "readiness": gate["readiness"],
            "severity": gate["severity"],
            "unresolved_evidence": gate.get("unresolved_evidence", []),
            "evidence_results": [
                {key: result.get(key) for key in (
                    "reference", "availability", "applicability", "validation",
                    "scope", "freshness", "producer_outcome", "requirement_outcome", "reason_codes",
                )}
                for result in gate.get("evidence_results", [])
            ],
        }
        for gate in data["gates"]
    ]
    return projection


def github_event_value() -> str | None:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return None
    path = Path(event_path)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None
    pr = data.get("pull_request") if isinstance(data, dict) else None
    if isinstance(pr, dict) and pr.get("number") is not None:
        return str(pr.get("number"))
    return None


def latest_session_id(root: Path, naos_root: str, policy: dict[str, Any]) -> str | None:
    path = root / naos_root / str(policy.get("paths", {}).get("sessions_index") or "sessions_index.json")
    data, _ = load_json(path)
    if not data:
        return None
    value = data.get("latest_session_id")
    return str(value) if value else None


def ci_metadata(root: Path) -> dict[str, Any]:
    github_actions = os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
    return {
        "ci_provider": "github_actions" if github_actions else "not_detected",
        "event_name": os.environ.get("GITHUB_EVENT_NAME"),
        "branch": os.environ.get("GITHUB_REF_NAME") or git_value(root, "rev-parse", "--abbrev-ref", "HEAD"),
        "base_ref": os.environ.get("GITHUB_BASE_REF"),
        "head_ref": os.environ.get("GITHUB_HEAD_REF"),
        "commit_sha": os.environ.get("GITHUB_SHA") or git_value(root, "rev-parse", "HEAD"),
        "pull_request_number": os.environ.get("GITHUB_PR_NUMBER") or github_event_value(),
        "ci_detected": github_actions,
    }


def status_for(findings: list[dict[str, Any]], ci_detected: bool) -> str:
    statuses = {str(item.get("status")) for item in findings}
    if "blocked" in statuses:
        return "blocked"
    if not ci_detected:
        return "ci_not_detected"
    if "gates_failed" in statuses:
        return "gates_failed"
    if "conflicts_detected" in statuses:
        return "conflicts_detected"
    if "risk_review_required" in statuses:
        return "review_required"
    if "missing_reports" in statuses:
        return "missing_reports"
    if findings:
        return "review_required"
    return "ready"


def build_report(root: Path, naos_root: str, profile: str, policy: dict[str, Any]) -> dict[str, Any]:
    generated_at = utc_now()
    ci = ci_metadata(root)
    operator = resolve_operator_attribution(root)
    session_id = latest_session_id(root, naos_root, policy)
    generated_by = build_generated_by(root, session_id=session_id, generated_at=generated_at)

    loaded_reports: dict[str, dict[str, Any] | None] = {}
    reports_generated: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for label, key in REPORT_KEYS.items():
        path = report_path(root, naos_root, policy, key)
        data, error = load_json(path)
        loaded_reports[label] = data
        reports_generated.append(
            {
                "id": label,
                "path": str(path),
                "exists": data is not None,
                "status": data.get("status") if data else ("parse_error" if error else "missing"),
                "error": error,
            }
        )
        if error:
            findings.append(
                {
                    "id": f"pr_governance.{label}.parse_error",
                    "severity": "warning",
                    "status": "missing_reports",
                    "message": f"Report could not be parsed: {path}",
                    "path": str(path),
                }
            )

    required_for_ci = {"gate_status", "gate_evaluation", "evidence_pack", "dashboard", "evidence_conflicts", "task_claims", "pr_risk_classification"}
    missing_required = [item for item in reports_generated if item["id"] in required_for_ci and not item["exists"]]
    if missing_required:
        missing_finding = {
                "id": "pr_governance.missing_reports",
                "severity": "warning",
                "status": "missing_reports",
                "message": "One or more expected PR governance reports are missing.",
                "reports": [item["id"] for item in missing_required],
                "human_review_required": True,
        }
        # A parse failure also produces a missing data record, but does not prove
        # that the source file itself is absent.
        if all(confirmed_absent_path(Path(item["path"])) for item in missing_required):
            missing_finding.update(
                evidence_classification="confirmed",
                classification_scope="selected_pr_report_files_absent_at_summary",
                reasoning_summary="Each named required report file was absent at summary time; this does not waive any PR gate or assess the reports that were present.",
                source_path=str(Path(__file__).resolve()),
            )
        findings.append(missing_finding)
    if not ci["ci_detected"]:
        findings.append(
            {
                "id": "pr_governance.ci_not_detected",
                "severity": "advisory",
                "status": "ci_not_detected",
                "message": "CI environment was not detected; this report is a local preview.",
                "evidence_classification": "confirmed",
                "classification_scope": "local_ci_environment_observation",
                "source_path": str(Path(__file__).resolve()),
                "human_review_required": True,
            }
        )

    gate_eval = loaded_reports.get("gate_evaluation") or {}
    gate_readiness = {
        label: project_gate_readiness(root, naos_root, profile, policy, label)
        for label in ("gate_status", "gate_evaluation")
    }
    for label, projection in gate_readiness.items():
        if projection["readiness"] != "ready":
            advisory_only = projection["required_readiness"] == "ready"
            findings.append({
                "id": f"pr_governance.{label}_advisory_unresolved" if advisory_only else f"pr_governance.{label}_unresolved",
                "severity": "advisory" if advisory_only else ("required" if profile in {"standard", "assured"} else "warning"),
                "status": "advisory_gates_unresolved" if advisory_only else "gate_unresolved",
                "message": (f"{label} has advisory gaps; enforcing gate readiness is satisfied."
                            if advisory_only else f"{label} has no validated, applicable ready gate result."),
                "source_path": str(Path(__file__).resolve()),
                "source_report": projection["source_path"],
                "source_report_sha256": projection["source_content_sha256"],
                "reason_codes": projection["reason_codes"],
                "evidence_classification": "confirmed",
                "classification_scope": "generated_gate_projection_unresolved_observation_only",
                "reasoning_summary": "The local gate projection did not yield a validated applicable ready result. This confirms only the evaluator observation, not the source report truth, gate approval, remediation, or completed human review.",
                "observed_gate_projection": {key: projection[key] for key in (
                    "readiness", "required_readiness", "required_reason_codes",
                    "validation", "scope", "reason_codes", "source_content_sha256",
                )},
                "human_review_required": True,
            })
    for label in ("gate_status", "gate_evaluation"):
        data = loaded_reports.get(label) or {}
        if data.get("status") == "invalid_input":
            findings.append({
                "id": f"pr_governance.{label}_invalid_input",
                "severity": "required" if profile in {"standard", "assured"} else "warning",
                "status": "gates_failed",
                "message": f"{label} could not evaluate its requested input scope.",
                "errors": data.get("errors") or [],
                "evidence_classification": "confirmed",
                "classification_scope": "observed_gate_report_failure_only",
                "source_path": str(report_path(root, naos_root, policy, REPORT_KEYS[label])),
                "reasoning_summary": "The loaded gate report declares invalid_input; this observation does not independently validate its inputs or resolve the gate.",
                "human_review_required": True,
            })
    gate_summary = gate_eval.get("summary") if isinstance(gate_eval.get("summary"), dict) else {}
    if (gate_summary.get("blocked") or 0) or (gate_summary.get("required_missing") or 0):
        findings.append(
            {
                "id": "pr_governance.gates_failed",
                "severity": "required" if profile in {"standard", "assured"} else "warning",
                "status": "gates_failed",
                "message": "Gate evaluation reports blocked or required-missing gates.",
                "evidence_classification": "confirmed",
                "classification_scope": "observed_gate_report_failure_only",
                "source_path": str(report_path(root, naos_root, policy, REPORT_KEYS["gate_evaluation"])),
                "reasoning_summary": "The loaded gate summary declares a blocked or required-missing state; this observation does not independently validate its inputs or resolve the gate.",
                "human_review_required": True,
            }
        )

    evidence_conflicts = loaded_reports.get("evidence_conflicts") or {}
    conflict_count = int(evidence_conflicts.get("conflict_count") or 0) if isinstance(evidence_conflicts, dict) else 0
    if conflict_count:
        findings.append(
            {
                "id": "pr_governance.conflicts_detected",
                "severity": "required" if profile in {"standard", "assured"} else "warning",
                "status": "conflicts_detected",
                "message": "Evidence conflict detection reported conflicts.",
                "conflict_count": conflict_count,
                "human_review_required": True,
            }
        )

    pr_risk = loaded_reports.get("pr_risk_classification") or {}
    pr_risk_summary = pr_risk.get("summary") if isinstance(pr_risk.get("summary"), dict) else {}
    pr_risk_findings = int(pr_risk_summary.get("total_findings") or 0)
    if pr_risk_findings:
        findings.append(
            {
                "id": "pr_governance.pr_risk_review_required",
                "severity": "required" if profile in {"standard", "assured"} else "warning",
                "status": "risk_review_required",
                "message": "PR risk classification reported review-required risk surfaces.",
                "finding_count": pr_risk_findings,
                "risk_files": int(pr_risk_summary.get("risk_files") or 0),
                "human_review_required": True,
            }
        )

    gate_status = loaded_reports.get("gate_status") or {}
    team_id = os.environ.get("TEAM_ID") or os.environ.get("NAOS_TEAM_ID") or gate_status.get("team_id") or gate_eval.get("team_id")
    team_resolution_source = (
        "explicit env"
        if os.environ.get("TEAM_ID") or os.environ.get("NAOS_TEAM_ID")
        else gate_status.get("team_resolution_source") or gate_eval.get("team_resolution_source") or "unknown"
    )

    artifact_paths = [
        item["path"]
        for item in reports_generated
        if item["exists"] and "context_index" not in item["path"] and item["path"].endswith((".json", ".sarif"))
    ]
    status = status_for(findings, bool(ci["ci_detected"]))
    return {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": status,
        "ci_provider": ci["ci_provider"],
        "event_name": ci["event_name"],
        "branch": ci["branch"],
        "base_ref": ci["base_ref"],
        "head_ref": ci["head_ref"],
        "commit_sha": ci["commit_sha"],
        "pull_request_number": ci["pull_request_number"],
        "session_id": session_id,
        "operator_id": operator.get("operator_id"),
        "team_id": team_id,
        "team_resolution_source": team_resolution_source,
        "generated_by": generated_by,
        "reports_generated": reports_generated,
        "validators_run": [{"id": item, "status": "expected_in_ci"} for item in EXPECTED_VALIDATORS],
        "gate_status_summary": compact_summary(gate_status, "team_id", "team_resolution_source", "team_overrides_applied"),
        "gate_evaluation_summary": compact_summary(gate_eval, "team_id", "team_resolution_source", "team_overrides_applied"),
        "gate_readiness": gate_readiness,
        "evidence_pack_summary": compact_summary(loaded_reports.get("evidence_pack")),
        "dashboard_summary": compact_summary(loaded_reports.get("dashboard")),
        "evidence_conflict_summary": compact_summary(evidence_conflicts, "conflict_count", "conflict_type_counts"),
        "task_claim_summary": compact_summary(
            loaded_reports.get("task_claims"),
            "claim_count",
            "active_claim_count",
            "conflicting_claim_count",
        ),
        "pr_risk_classification_summary": compact_summary(
            loaded_reports.get("pr_risk_classification"),
            "contributor",
            "changed_files",
        ),
        "sarif_summary": compact_summary(loaded_reports.get("sarif"), "result_count", "rule_count", "sarif_output"),
        "artifact_paths": artifact_paths,
        "findings": findings,
        "known_gaps": [
            "pr_comments_not_implemented",
            "sarif_code_scanning_upload_not_enabled",
            "artifact_sensitivity_review_required_before_retention",
        ],
        "residual_risks": RESIDUAL_RISKS,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": True,
        "summary": {
            "status": status,
            "reports_present": sum(1 for item in reports_generated if item["exists"]),
            "reports_expected": len(reports_generated),
            "missing_reports": len(missing_required),
            "findings": len(findings),
            "ci_detected": bool(ci["ci_detected"]),
            "human_review_required": True,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Summarize NAOS pull-request governance evidence for CI review.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true", help="Accepted for Makefile consistency; PR summaries remain review evidence.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    report = build_report(root, naos_root, profile, policy)
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "pr_governance_summary_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            "NAOS PR governance summary: "
            f"{report['status']} "
            f"({report['summary']['reports_present']}/{report['summary']['reports_expected']} reports present, "
            f"output: {output if output else 'stdout only'})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
