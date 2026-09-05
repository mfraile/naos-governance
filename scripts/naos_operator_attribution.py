#!/usr/bin/env python3
"""Resolve local NAOS operator attribution for a run/session."""

from __future__ import annotations

import argparse
import json
import os
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
    session_report_default_path,
    write_report_with_session,
)
from naos_session_identity import (  # noqa: E402
    ensure_session_context,
    path_text,
    record_session_report_reference,
)
from naos_audit_log import write_audit_event  # noqa: E402


REPORT_SCHEMA = "naos.operator_attribution.v1"
LIMITATIONS = [
    "Operator attribution answers who initiated a NAOS command/session using local signals only.",
    "It does not prove identity, authenticate a user, authorize work, assign task ownership, lock tasks, satisfy separation of duties, provide non-repudiation, approve work, or create an append-only audit log.",
    "Git identity is read from local git config only; no network identity provider, GitHub/GitLab API, provider SDK, token, or credential is consulted.",
]
NOT_CLAIMED = [
    "identity proof",
    "authentication",
    "authorization",
    "task ownership",
    "task locking",
    "separation of duties",
    "non-repudiation",
    "approval",
    "append-only audit log",
    "evidence conflict detection",
    "source of truth",
]
RESIDUAL_RISKS = [
    "local_operator_identifiers_can_be_misconfigured",
    "git_config_identity_may_be_shared_or_stale",
    "os_user_fallback_may_be_ambiguous_on_shared_hosts",
    "operator_attribution_does_not_prove_authentication_or_authorization",
    "privacy_redaction_or_hashing_is_future_option",
]
OPERATOR_AWARE_REPORTS = [
    "operator_attribution_report",
    "session_identity_report",
    "session_lifecycle_report",
]
OPERATOR_PENDING_REPORTS = [
    "agent_trace_validation_report",
    "ai_surface_context_budget_report",
    "static_grader_report",
    "grader_assessment_report",
    "llm_grader_readiness_report",
    "sarif_export_summary",
    "policy_override_merge_report",
    "evidence_pack_report",
    "dashboard_summary_report",
    "gate_status_report",
]


def utc_now() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def finding(finding_id: str, severity: str, status: str, message: str, actions: list[str] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": finding_id,
        "severity": severity,
        "status": status,
        "message": message,
    }
    if actions:
        result["required_next_actions"] = actions
    return result


def build_report(
    root: Path,
    naos_root: str,
    profile: str,
    session_context: dict[str, Any],
) -> dict[str, Any]:
    generated_at = utc_now()
    operator = resolve_operator_attribution(root)
    session_id = session_context.get("session_id")
    status = "ready" if operator.get("operator_attribution_status") == "resolved" else "unknown_operator"
    if operator.get("invalid_operator_findings"):
        status = "review_required"
    if session_context.get("status") == "not_configured":
        status = "not_configured" if status != "unknown_operator" else "advisory"

    findings: list[dict[str, Any]] = []
    for invalid in operator.get("invalid_operator_findings") or []:
        source = invalid.get("source") or "unknown"
        findings.append(
            finding(
                "operator_attribution.invalid_operator_id",
                "warning",
                "review_required",
                f"Rejected unsafe operator identifier from {source}: {invalid.get('reason')}.",
                ["Use a log-safe NAOS_OPERATOR_ID matching ^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$."],
            )
        )
    if not operator.get("env_operator_id_detected"):
        findings.append(
            finding(
                "operator_attribution.env_operator_missing",
                "advisory",
                "recommendation",
                "NAOS_OPERATOR_ID is not set; attribution used the next available local signal.",
                ["Set NAOS_OPERATOR_ID to a project-approved operator identifier if deterministic attribution is required."],
            )
        )
    if operator.get("operator_attribution_status") != "resolved":
        findings.append(
            finding(
                "operator_attribution.unknown_operator",
                "advisory",
                "unknown_operator",
                "No local operator identifier could be resolved.",
                ["Set NAOS_OPERATOR_ID or local git config user.email/user.name."],
            )
        )

    return {
        "schema": REPORT_SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "session_id": session_id,
        "session_report_root": path_text(session_context.get("session_report_root"), root)
        if isinstance(session_context.get("session_report_root"), Path)
        else None,
        "generated_by": build_generated_by(root, session_id=str(session_id) if session_id else None, generated_at=generated_at),
        "operator_id": operator.get("operator_id"),
        "operator_source": operator.get("operator_source"),
        "operator_resolution_order": operator.get("operator_resolution_order") or [],
        "operator_attribution_status": operator.get("operator_attribution_status"),
        "operator_aware_reports": OPERATOR_AWARE_REPORTS,
        "operator_pending_reports": OPERATOR_PENDING_REPORTS,
        "git_user_email_detected": bool(operator.get("git_user_email_detected")),
        "git_user_name_detected": bool(operator.get("git_user_name_detected")),
        "env_operator_id_detected": bool(operator.get("env_operator_id_detected")),
        "os_user_detected": bool(operator.get("os_user_detected")),
        "operator_id_validation": operator.get("operator_id_validation") or {},
        "privacy_posture": operator.get("privacy_posture") or {},
        "pii_warning": str(operator.get("pii_warning") or ""),
        "findings": findings,
        "known_gaps": [
            "authorization_backed_task_locking_deferred",
            "audit_log_full_source_coverage_deferred",
            "evidence_conflict_resolution_workflow_deferred",
            "team_operator_policy_overlays_deferred",
            "operator_attribution.conflicting_operator_detection_deferred",
            "privacy_hash_or_redaction_option_deferred",
        ],
        "residual_risks": RESIDUAL_RISKS,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": True,
        "summary": {
            "operator_resolved": operator.get("operator_attribution_status") == "resolved",
            "operator_source": operator.get("operator_source"),
            "session_id": session_id,
            "session_copy_written": bool(session_id),
            "network_lookup_performed": False,
            "identity_provider_lookup_performed": False,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Resolve local NAOS operator attribution for a run/session.")
    parser.add_argument("--profile", help="Profile name: quickstart, lite, standard, assured.")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"), help="Generated project NAOS root. Default from policy.")
    parser.add_argument("--policy", help="Optional policy file used for path/profile conventions.")
    parser.add_argument("--session-id", help="Use an existing filesystem-safe session id.")
    parser.add_argument("--new-session", action="store_true", help="Create a new session id instead of reusing the latest active session.")
    parser.add_argument("--close-session", action="store_true", help="Mark the selected session as closed after attribution.")
    parser.add_argument("--output", help="Optional JSON report output path.")
    parser.add_argument("--json", action="store_true", help="Print JSON report.")
    parser.add_argument("--strict", action="store_true", help="Accepted for Makefile consistency; operator attribution remains advisory.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = Path.cwd()
        policy = load_policy(args.policy, args.naos_root, root)
        naos_root = args.naos_root or default_naos_root(policy)
        profile = normalize_profile(args.profile, policy)
        session_context = ensure_session_context(
            root=root,
            naos_root=naos_root,
            policy=policy,
            profile=profile,
            requested_session_id=args.session_id,
            new_session=args.new_session,
            close_session=args.close_session,
            task_id=None,
        )
        report = build_report(root, naos_root, profile, session_context)
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    latest_path = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "operator_attribution_report")
    session_path = None
    if report.get("session_id") and args.output is None:
        session_path = session_report_default_path(root, naos_root, policy, str(report["session_id"]), "operator_attribution_report")
    write_report_with_session(latest_path, session_path, report)
    if report.get("session_id") and args.output is None:
        record_session_report_reference(
            root,
            naos_root,
            policy,
            str(report["session_id"]),
            "operator_attribution_report",
            latest_path,
            session_path,
        )
    if args.output is None:
        write_audit_event(
            root=root,
            naos_root=naos_root,
            policy=policy,
            profile=profile,
            event_type="operator_attributed",
            source_report_path=latest_path,
            source_report=report,
            session_id=str(report["session_id"]) if report.get("session_id") else None,
            generated_by=report.get("generated_by"),
            related_artifacts=[str(path) for path in [latest_path, session_path] if path is not None],
        )

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"NAOS operator attribution ({profile}): {report['status']}")
        print(f"operator_id: {report.get('operator_id')}")
        print(f"operator_source: {report.get('operator_source')}")
        print(f"session_id: {report.get('session_id')}")
        if latest_path:
            print(f"latest_report: {path_text(latest_path, root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
