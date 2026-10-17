#!/usr/bin/env python3
"""Create/reuse NAOS session identifiers and namespaced report roots."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_self_check_inspection import inspection_active, logical_path  # noqa: E402

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
# A portable identity, not a native path-normalization rule. Never silently
# lowercase an existing identifier or merge its evidence into another session.
SESSION_ID_PATTERN = re.compile(
    r"^(?!(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$))"
    r"[a-z0-9][a-z0-9_-]*(?:\.[a-z0-9_-]+)*(?![\s\S])"
)
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
    value = str(session_id or "")
    if not 8 <= len(value) <= 128 or not SESSION_ID_PATTERN.fullmatch(value):
        raise SessionIdentityError(
            "Invalid session id. Use 8-128 lowercase ASCII letters, digits, "
            "underscores or hyphens, with optional nonempty dot-separated "
            "segments; Windows device names are reserved. Existing noncanonical "
            "IDs require explicit migration, not automatic case conversion."
        )
    return value


def validate_inspection_index_shape(index: Any) -> None:
    """Enforce current session-index schema fields without a runtime dependency."""
    required = {
        "schema", "generated_at", "sessions", "active_session_ids",
        "closed_session_ids", "latest_session_id", "limitations", "not_claimed",
        "human_review_required",
    }
    if type(index) is not dict or not required <= index.keys():
        raise SessionIdentityError("Sessions index required fields are missing")
    if index["schema"] != INDEX_SCHEMA or type(index["generated_at"]) is not str:
        raise SessionIdentityError("Sessions index schema or generated_at is invalid")
    if type(index["human_review_required"]) is not bool:
        raise SessionIdentityError("Sessions index human_review_required is invalid")
    if type(index["latest_session_id"]) not in {str, type(None)}:
        raise SessionIdentityError("Sessions index latest_session_id is invalid")
    for field in ("active_session_ids", "closed_session_ids", "limitations", "not_claimed"):
        value = index[field]
        if type(value) is not list or any(type(item) is not str for item in value):
            raise SessionIdentityError(f"Sessions index {field} is invalid")
        if field in {"active_session_ids", "closed_session_ids"}:
            for session_id in value:
                validate_session_id(session_id)
    if index["latest_session_id"] is not None:
        validate_session_id(index["latest_session_id"])
    records = index["sessions"]
    if type(records) is not list or len(records) > 10000:
        raise SessionIdentityError("Sessions index records are invalid or unbounded")
    record_required = {
        "session_id", "created_at", "updated_at", "status", "profile",
        "report_root", "latest_reports", "operator_id", "limitations", "not_claimed",
    }
    for record in records:
        if type(record) is not dict or not record_required <= record.keys():
            raise SessionIdentityError("Session record required fields are missing")
        for field in ("session_id", "created_at", "updated_at", "status", "profile", "report_root"):
            if type(record[field]) is not str:
                raise SessionIdentityError(f"Session record {field} is invalid")
        validate_session_id(record["session_id"])
        if record["status"] not in {"active", "closed", "unknown"}:
            raise SessionIdentityError("Session record status is invalid")
        if type(record["latest_reports"]) is not dict:
            raise SessionIdentityError("Session record latest_reports is invalid")
        for field in ("operator_id", "task_id"):
            if field in record and type(record[field]) not in {str, type(None)}:
                raise SessionIdentityError(f"Session record {field} is invalid")
        for field in ("limitations", "not_claimed"):
            value = record[field]
            if type(value) is not list or any(type(item) is not str for item in value):
                raise SessionIdentityError(f"Session record {field} is invalid")
        optional_enums = {
            "operator_source": {"env", "git_email", "git_name", "os_user", "unknown", None},
            "operator_attribution_status": {"resolved", "unknown", "conflicting", "not_configured", None},
        }
        for field, allowed in optional_enums.items():
            if field in record and (type(record[field]) not in {str, type(None)} or record[field] not in allowed):
                raise SessionIdentityError(f"Session record {field} is invalid")


def path_text(path: Path | None, root: Path) -> str | None:
    if path is None:
        return None
    path = logical_path(root, path)
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive per-call temporary creation avoids overwriting another writer's
    # temporary file. Atomic replacement still does not provide index locking.
    temp_path: Path | None = None
    pending_error: BaseException | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        for attempt in range(4):
            try:
                os.replace(temp_path, path)
                return
            except PermissionError as exc:
                # A Windows target held without delete sharing can report
                # ACCESS_DENIED (5), not only SHARING/LOCK_VIOLATION (32/33).
                # Repeat only this same replace; never alter access controls.
                if (sys.platform != "win32" or getattr(exc, "winerror", None) not in {5, 32, 33}
                        or attempt == 3):
                    raise
                time.sleep(0.05 * (2 ** attempt))
    except BaseException as error:
        pending_error = error
        raise
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError as cleanup_error:
                if pending_error is None:
                    raise
                pending_error.add_note(
                    "Temporary session JSON cleanup also failed: "
                    + type(cleanup_error).__name__
                )


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
    validate_inspection_index_shape(data)
    ids = [record["session_id"] for record in data["sessions"]]
    if len(set(ids)) != len(ids):
        raise SessionIdentityError("Sessions index contains duplicate session IDs; it was preserved.")
    return data


def _refuse_session_directory_alias(parent: Path, session_id: str) -> None:
    if parent.exists():
        for entry in parent.iterdir():
            if entry.name != session_id and entry.name.casefold() == session_id:
                raise SessionIdentityError(
                    "Existing session directory aliases the requested canonical ID; "
                    "its evidence was preserved. Explicit migration is required."
                )


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
    _refuse_session_directory_alias(sessions_root_path(root, naos_root, policy), session_id)

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


def inspect_session_context(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    requested_session_id: str | None = None,
) -> dict[str, Any]:
    """Observe an existing session index without creating or updating context."""
    if requested_session_id is not None:
        validate_session_id(requested_session_id)

    index_path = sessions_index_path(root, naos_root, policy)
    context: dict[str, Any] = {
        "status": "advisory",
        "session_id": None,
        "record": None,
        "index": None,
        "index_path": index_path,
        "session_root": None,
        "session_report_root": None,
        "findings": [],
        "inspection_only": True,
    }

    def finding(identifier: str, severity: str, status: str, message: str) -> None:
        context["findings"].append({
            "id": identifier,
            "severity": severity,
            "status": status,
            "message": message,
            "required_next_actions": ["Review existing session evidence or explicitly start a session."],
        })

    if is_kit_repository(root, naos_root) or not (root / naos_root).is_dir():
        context["status"] = "not_configured"
        finding("session_identity.naos_root_missing", "advisory", "not_configured",
                "Generated NAOS root is not present; no session context was inspected.")
        return context

    if index_path.is_symlink() or (index_path.exists() and not index_path.is_file()):
        context["status"] = "blocked"
        finding("session_identity.index_invalid", "blocking", "blocked",
                "Sessions index is not a regular, directly named file.")
        return context
    if not index_path.exists():
        context["status"] = "blocked" if requested_session_id else "advisory"
        finding("session_identity.index_missing",
                "blocking" if requested_session_id else "advisory",
                context["status"], "Sessions index is missing; inspection did not create one.")
        return context

    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(index_path, flags)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise SessionIdentityError("Sessions index is not regular")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                raw = handle.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise SessionIdentityError("Sessions index exceeds inspection limit")
        finally:
            os.close(descriptor)

        def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, item in pairs:
                if key in value:
                    raise SessionIdentityError(f"Duplicate sessions-index field: {key}")
                value[key] = item
            return value

        index = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs)
        validate_inspection_index_shape(index)
        sessions = index.get("sessions")
        active: list[str] = []
        closed: list[str] = []
        seen: set[str] = set()
        for record in sessions:
            if not isinstance(record, dict) or not isinstance(record.get("session_id"), str):
                raise SessionIdentityError("Malformed sessions index record")
            session_id = validate_session_id(record["session_id"])
            if session_id in seen or record.get("status") not in {"active", "closed", "unknown"}:
                raise SessionIdentityError("Duplicate session id or invalid status")
            if (not isinstance(record.get("report_root"), str)
                    or not isinstance(record.get("latest_reports"), dict)
                    or not isinstance(record.get("created_at"), str)
                    or not isinstance(record.get("updated_at"), str)):
                raise SessionIdentityError("Malformed sessions index record metadata")
            seen.add(session_id)
            if record["status"] == "active":
                active.append(session_id)
            elif record["status"] == "closed":
                closed.append(session_id)
        if (index.get("active_session_ids") != active
                or index.get("closed_session_ids") != closed
                or index.get("latest_session_id") not in (seen | {None})):
            raise SessionIdentityError("Sessions index summary disagrees with records")
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        context["status"] = "blocked"
        finding("session_identity.index_invalid", "blocking", "blocked",
                f"Sessions index could not be safely inspected: {exc}")
        return context

    context["index"] = index
    session_id = requested_session_id or latest_active_session_id(index)
    record = find_session(index, session_id) if session_id else None
    if record is None:
        context["status"] = "blocked" if requested_session_id else "advisory"
        finding("session_identity.session_missing",
                "blocking" if requested_session_id else "advisory",
                context["status"], "No selected existing active session was found.")
        return context
    context["session_id"] = session_id
    context["record"] = record
    context["session_root"] = sessions_root_path(root, naos_root, policy) / session_id
    context["session_report_root"] = (
        context["session_root"] / str(policy.get("paths", {}).get("reports_dir") or "reports")
    )
    context["status"] = "ready"
    if record["status"] != "active":
        context["status"] = "advisory"
        finding("session_identity.session_not_active", "advisory", "advisory",
                "Selected existing session is not active.")
    if not context["session_report_root"].is_dir():
        context["status"] = "advisory"
        finding("session_identity.report_root_missing", "advisory", "advisory",
                "Selected session report directory is missing; inspection did not create it.")
    return context


def record_session_report_reference(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    session_id: str,
    report_key: str,
    latest_path: Path | None,
    session_path: Path | None,
) -> None:
    session_id = validate_session_id(session_id)
    if inspection_active(root, naos_root):
        return
    _refuse_session_directory_alias(sessions_root_path(root, naos_root, policy), session_id)
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
            "enabled": not context.get("inspection_only"),
            "latest_report_root": path_text(root / naos_root / "reports", root),
            "behavior": (
                "Inspection prints observed evidence without writing a session or compatibility report."
                if context.get("inspection_only") else
                "session-aware scripts write both session-scoped reports and compatibility latest reports when a generated NAOS root is present."
            ),
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
            "latest_report_compatibility_enabled": not context.get("inspection_only"),
            "session_aware_report_count": len(SESSION_AWARE_REPORTS),
            "latest_only_report_count": len(LATEST_ONLY_REPORTS),
            "index_updated": configured and not context.get("inspection_only"),
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
    parser.add_argument("--inspect-session", action="store_true", help="Read existing session context without creating or updating sessions, reports, or audit events.")
    parser.add_argument("--task", help="Optional task id to associate with the session record.")
    parser.add_argument("--output", help="Optional JSON report output path.")
    parser.add_argument("--json", action="store_true", help="Print JSON report.")
    parser.add_argument("--strict", action="store_true", help="Accepted for Makefile consistency; session identity remains advisory.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.inspect_session and (args.new_session or args.close_session or args.output):
        print("ERROR: --inspect-session is stdout-only and cannot create, close, or write a report", file=sys.stderr)
        return 2
    try:
        root = Path.cwd()
        policy = load_policy(args.policy, args.naos_root, root)
        naos_root = args.naos_root or default_naos_root(policy)
        profile = normalize_profile(args.profile, policy)
        context = (
            inspect_session_context(root, naos_root, policy, args.session_id)
            if args.inspect_session else
            ensure_session_context(
                root=root,
                naos_root=naos_root,
                policy=policy,
                profile=profile,
                requested_session_id=args.session_id,
                new_session=args.new_session,
                close_session=args.close_session,
                task_id=args.task,
            )
        )
        report = build_identity_report(root, naos_root, profile, context)
        if args.inspect_session:
            report["inspection_only"] = True
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    latest_path = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "session_identity_report")
    if args.inspect_session:
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(f"NAOS session inspection ({profile}): {report['status']}")
            print(f"session_id: {report.get('session_id')}")
            print("report: stdout only")
        return 0 if report["status"] != "blocked" else 2
    try:
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
    except Exception as exc:  # Report/index publication is part of the CLI boundary.
        print(f"ERROR: session report publication failed: {exc}", file=sys.stderr)
        return 2

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
