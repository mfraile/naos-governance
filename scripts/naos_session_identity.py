#!/usr/bin/env python3
"""Create/reuse NAOS session identifiers and namespaced report roots."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    default_naos_root,
    build_generated_by,
    is_kit_repository,
    load_policy,
    normalize_profile,
    report_output_path,
    resolve_operator_attribution,
    session_report_default_path,
    sessions_index_path,
    sessions_root_path,
    write_report_with_session,
)
from naos_audit_log import write_audit_event  # noqa: E402


REPORT_SCHEMA = "naos.session_identity.v1"
INDEX_SCHEMA = "naos.session_index.v1"
SESSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
VALID_STATUSES = {
    "ready",
    "advisory",
    "session_created",
    "session_reused",
    "invalid_session_id",
    "index_updated",
    "index_write_failed",
    "not_configured",
    "blocked",
    "unknown",
}
SESSION_AWARE_REPORTS = [
    "session_identity_report",
    "session_lifecycle_report",
    "operator_attribution_report",
]
LATEST_ONLY_REPORTS = [
    "agent_trace_validation_report",
    "ai_surface_context_budget_report",
    "static_grader_report",
    "grader_assessment_report",
    "llm_grader_readiness_report",
    "behavioral_governance_readiness_report",
    "sarif_export_summary_report",
    "policy_override_merge_report",
]
LIMITATIONS = [
    "Session identity isolates report paths but does not implement task claim or release semantics.",
    "sessions_index.json is written atomically when possible, but it is not a full multi-writer lock or distributed coordination mechanism.",
    "Operator attribution records local identity signals only; it does not prove identity, authenticate a user, authorize work, assign task ownership, or satisfy separation of duties.",
    "Latest reports under naos/reports remain compatibility outputs and may be overwritten by later runs.",
]
RESIDUAL_RISKS = [
    "parallel_session_index_writes_can_still_race_without_later_coordination",
    "latest_report_compatibility_paths_can_be_overwritten",
    "missing_operator_attribution_reduces_team_accountability_until_later_group",
]
NOT_CLAIMED = [
    "proof",
    "approval",
    "identity proof",
    "authentication",
    "authorization",
    "task ownership",
    "task locking enabled",
    "complete audit-log coverage",
    "evidence conflict detection complete",
    "multi-user complete",
    "concurrent write safe",
    "source of truth",
]


class SessionIdentityError(ValueError):
    """Raised when session identity input is unsafe or invalid."""


def utc_now_text() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def generate_session_id() -> str:
    uuid7 = getattr(uuid, "uuid7", None)
    value = uuid7() if callable(uuid7) else uuid.uuid4()
    return str(value)


def validate_session_id(session_id: str) -> str:
    value = str(session_id or "").strip()
    if not SESSION_ID_PATTERN.fullmatch(value):
        raise SessionIdentityError(
            "Invalid session id. Use 8-128 filesystem-safe characters: letters, digits, dot, underscore, or hyphen."
        )
    return value


def path_text(path: Path | None, root: Path) -> str | None:
    if path is None:
        return None
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, path)


def empty_index(generated_at: str) -> dict[str, Any]:
    return {
        "schema": INDEX_SCHEMA,
        "generated_at": generated_at,
        "sessions": [],
        "active_session_ids": [],
        "closed_session_ids": [],
        "latest_session_id": None,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": True,
    }


def load_session_index(index_path: Path, generated_at: str) -> dict[str, Any]:
    if not index_path.exists():
        return empty_index(generated_at)
    try:
        data = json.loads(index_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SessionIdentityError(f"Invalid sessions index JSON: {index_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SessionIdentityError(f"Invalid sessions index structure: {index_path}")
    data.setdefault("schema", INDEX_SCHEMA)
    data.setdefault("sessions", [])
    data.setdefault("active_session_ids", [])
    data.setdefault("closed_session_ids", [])
    data.setdefault("latest_session_id", None)
    data.setdefault("limitations", LIMITATIONS)
    data.setdefault("not_claimed", NOT_CLAIMED)
    data.setdefault("human_review_required", True)
    return data


def derive_status_lists(index: dict[str, Any]) -> None:
    sessions = [item for item in index.get("sessions", []) if isinstance(item, dict)]
    index["sessions"] = sorted(sessions, key=lambda item: str(item.get("created_at") or item.get("session_id") or ""))
    index["active_session_ids"] = [str(item["session_id"]) for item in index["sessions"] if item.get("status") == "active" and item.get("session_id")]
    index["closed_session_ids"] = [str(item["session_id"]) for item in index["sessions"] if item.get("status") == "closed" and item.get("session_id")]


def find_session(index: dict[str, Any], session_id: str) -> dict[str, Any] | None:
    for item in index.get("sessions", []):
        if isinstance(item, dict) and item.get("session_id") == session_id:
            return item
    return None


def latest_active_session_id(index: dict[str, Any]) -> str | None:
    active = [item for item in index.get("sessions", []) if isinstance(item, dict) and item.get("status") == "active"]
    if not active:
        return None
    active.sort(key=lambda item: str(item.get("updated_at") or item.get("created_at") or ""))
    return str(active[-1].get("session_id") or "") or None


def build_session_record(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    session_id: str,
    generated_at: str,
    profile: str,
    task_id: str | None,
) -> dict[str, Any]:
    operator = resolve_operator_attribution(root)
    return {
        "session_id": session_id,
        "created_at": generated_at,
        "updated_at": generated_at,
        "status": "active",
        "task_id": task_id,
        "profile": profile,
        "report_root": path_text(sessions_root_path(root, naos_root, policy) / session_id / str(policy.get("paths", {}).get("reports_dir") or "reports"), root),
        "latest_reports": {},
        "operator_id": operator.get("operator_id"),
        "operator_source": operator.get("operator_source"),
        "operator_attribution_status": operator.get("operator_attribution_status"),
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
    }


def ensure_session_context(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    profile: str,
    requested_session_id: str | None = None,
    new_session: bool = False,
    close_session: bool = False,
    task_id: str | None = None,
) -> dict[str, Any]:
    if is_kit_repository(root, naos_root) or not (root / naos_root).is_dir():
        return {
            "status": "not_configured",
            "session_id": None,
            "record": None,
            "index": None,
            "index_path": None,
            "session_root": None,
            "session_report_root": None,
            "findings": [
                {
                    "id": "session_identity.naos_root_missing",
                    "severity": "advisory",
                    "status": "not_configured",
                    "message": "Generated NAOS root is not present; no session directory was created.",
                    "required_next_actions": ["Run inside a generated adopter project to create session-scoped reports."],
                }
            ],
        }

    generated_at = utc_now_text()
    index_path = sessions_index_path(root, naos_root, policy)
    index = load_session_index(index_path, generated_at)
    status = "session_reused"
    findings: list[dict[str, Any]] = []

    if requested_session_id:
        session_id = validate_session_id(requested_session_id)
    elif not new_session:
        session_id = latest_active_session_id(index) or generate_session_id()
        if find_session(index, session_id) is None:
            status = "session_created"
    else:
        session_id = generate_session_id()
        status = "session_created"
    session_id = validate_session_id(session_id)

    record = find_session(index, session_id)
    if record is None:
        record = build_session_record(root, naos_root, policy, session_id, generated_at, profile, task_id)
        index.setdefault("sessions", []).append(record)
        status = "session_created"
    else:
        operator = resolve_operator_attribution(root)
        record["updated_at"] = generated_at
        record["profile"] = profile
        record["operator_id"] = operator.get("operator_id")
        record["operator_source"] = operator.get("operator_source")
        record["operator_attribution_status"] = operator.get("operator_attribution_status")
        if task_id:
            record["task_id"] = task_id
    if close_session:
        record["status"] = "closed"
        status = "index_updated"
    else:
        record.setdefault("status", "active")

    session_root = sessions_root_path(root, naos_root, policy) / session_id
    reports_dir = str(policy.get("paths", {}).get("reports_dir") or "reports")
    session_report_root = session_root / reports_dir
    session_report_root.mkdir(parents=True, exist_ok=True)
    record["report_root"] = path_text(session_report_root, root)
    record.setdefault("latest_reports", {})
    operator = resolve_operator_attribution(root)
    record.setdefault("operator_id", operator.get("operator_id"))
    record.setdefault("operator_source", operator.get("operator_source"))
    record.setdefault("operator_attribution_status", operator.get("operator_attribution_status"))
    record.setdefault("limitations", LIMITATIONS)
    record.setdefault("not_claimed", NOT_CLAIMED)
    index["generated_at"] = generated_at
    index["latest_session_id"] = session_id
    derive_status_lists(index)
    atomic_write_json(index_path, index)

    return {
        "status": status,
        "session_id": session_id,
        "record": record,
        "index": index,
        "index_path": index_path,
        "session_root": session_root,
        "session_report_root": session_report_root,
        "findings": findings,
    }


def record_session_report_reference(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    session_id: str,
    report_key: str,
    latest_path: Path | None,
    session_path: Path | None,
) -> None:
    generated_at = utc_now_text()
    index_path = sessions_index_path(root, naos_root, policy)
    index = load_session_index(index_path, generated_at)
    record = find_session(index, session_id)
    if record is None:
        record = build_session_record(root, naos_root, policy, session_id, generated_at, "quickstart", None)
        index.setdefault("sessions", []).append(record)
    record.setdefault("latest_reports", {})[report_key] = {
        "latest_path": path_text(latest_path, root),
        "session_path": path_text(session_path, root),
        "updated_at": generated_at,
    }
    record["updated_at"] = generated_at
    index["generated_at"] = generated_at
    index["latest_session_id"] = session_id
    derive_status_lists(index)
    atomic_write_json(index_path, index)


def build_identity_report(
    root: Path,
    naos_root: str,
    profile: str,
    context: dict[str, Any],
) -> dict[str, Any]:
    generated_at = utc_now_text()
    operator = resolve_operator_attribution(root)
    session_id = context.get("session_id")
    status = context.get("status") if context.get("status") in VALID_STATUSES else "unknown"
    session_root = context.get("session_root")
    session_report_root = context.get("session_report_root")
    index_path = context.get("index_path")
    configured = status != "not_configured"
    findings = list(context.get("findings") or [])
    return {
        "schema": REPORT_SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": status if configured else "not_configured",
        "session_id": session_id,
        "session_root": path_text(session_root, root) if isinstance(session_root, Path) else None,
        "session_report_root": path_text(session_report_root, root) if isinstance(session_report_root, Path) else None,
        "sessions_index_path": path_text(index_path, root) if isinstance(index_path, Path) else None,
        "generated_by": build_generated_by(root, session_id=str(session_id) if session_id else None, generated_at=generated_at),
        "operator_attribution": {
            "operator_id": operator.get("operator_id"),
            "operator_source": operator.get("operator_source"),
            "operator_attribution_status": operator.get("operator_attribution_status"),
        },
        "latest_report_compatibility": {
            "enabled": True,
            "latest_report_root": path_text(root / naos_root / "reports", root),
            "behavior": "session-aware scripts write both session-scoped reports and compatibility latest reports when a generated NAOS root is present.",
        },
        "session_aware_reports": SESSION_AWARE_REPORTS,
        "latest_only_reports": LATEST_ONLY_REPORTS,
        "findings": findings,
        "known_gaps": [
            "operator_identity_proof_authentication_authorization_deferred",
            "authorization_backed_task_locking_deferred",
            "audit_log_full_source_coverage_deferred",
            "evidence_conflict_resolution_workflow_deferred",
            "team_operator_policy_overlays_deferred",
        ],
        "residual_risks": RESIDUAL_RISKS,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": True,
        "summary": {
            "session_id": session_id,
            "latest_report_compatibility_enabled": True,
            "session_aware_report_count": len(SESSION_AWARE_REPORTS),
            "latest_only_report_count": len(LATEST_ONLY_REPORTS),
            "index_updated": configured,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create or reuse NAOS session identity metadata.")
    parser.add_argument("--profile", help="Profile name: quickstart, lite, standard, assured.")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"), help="Generated project NAOS root. Default from policy.")
    parser.add_argument("--policy", help="Optional policy file used for path/profile conventions.")
    parser.add_argument("--session-id", help="Use an existing filesystem-safe session id.")
    parser.add_argument("--new-session", action="store_true", help="Create a new session id instead of reusing the latest active session.")
    parser.add_argument("--close-session", action="store_true", help="Mark the selected session as closed.")
    parser.add_argument("--task", help="Optional task id to associate with the session record.")
    parser.add_argument("--output", help="Optional JSON report output path.")
    parser.add_argument("--json", action="store_true", help="Print JSON report.")
    parser.add_argument("--strict", action="store_true", help="Accepted for Makefile consistency; session identity remains advisory.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = Path.cwd()
        policy = load_policy(args.policy, args.naos_root, root)
        naos_root = args.naos_root or default_naos_root(policy)
        profile = normalize_profile(args.profile, policy)
        context = ensure_session_context(
            root=root,
            naos_root=naos_root,
            policy=policy,
            profile=profile,
            requested_session_id=args.session_id,
            new_session=args.new_session,
            close_session=args.close_session,
            task_id=args.task,
        )
        report = build_identity_report(root, naos_root, profile, context)
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    latest_path = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "session_identity_report")
    session_path = None
    if report.get("session_id"):
        session_path = session_report_default_path(root, naos_root, policy, str(report["session_id"]), "session_identity_report")
    write_report_with_session(latest_path, session_path, report)
    if report.get("session_id"):
        record_session_report_reference(
            root,
            naos_root,
            policy,
            str(report["session_id"]),
            "session_identity_report",
            latest_path,
            session_path,
        )
    if args.output is None:
        write_audit_event(
            root=root,
            naos_root=naos_root,
            policy=policy,
            profile=profile,
            event_type="session_started" if report.get("status") == "session_created" else "report_generated",
            source_report_path=latest_path,
            source_report=report,
            session_id=str(report["session_id"]) if report.get("session_id") else None,
            generated_by=report.get("generated_by"),
            related_task_id=args.task,
            related_artifacts=[str(path) for path in [latest_path, session_path] if path is not None],
        )

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"NAOS session identity ({profile}): {report['status']}")
        print(f"session_id: {report.get('session_id')}")
        print(f"session_reports: {report.get('session_report_root')}")
        print(f"latest_report: {path_text(latest_path, root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
