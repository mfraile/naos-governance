#!/usr/bin/env python3
"""Append-only NAOS audit log event writer and summary reporter."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    build_generated_by,
    default_naos_root,
    is_kit_repository,
    load_policy,
    normalize_profile,
    report_output_path,
    sessions_index_path,
    write_report,
)


EVENT_SCHEMA = "naos.audit_log_event.v1"
SUMMARY_SCHEMA = "naos.audit_log_summary.v1"
SAFE_FRAGMENT_RE = re.compile(r"[^A-Za-z0-9._:@+-]+")
EVENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{7,160}$")
ALLOWED_EVENT_TYPES = {
    "report_generated",
    "session_started",
    "session_checkpoint",
    "session_ended",
    "operator_attributed",
    "context_index_generated",
    "sqlite_coordination_completed",
    "gate_evaluated",
    "evidence_pack_generated",
    "dashboard_generated",
    "sarif_export_generated",
    "grader_assessment_generated",
    "policy_override_merged",
    "memory_readiness_checked",
    "control_plane_review_generated",
    "task_claimed",
    "task_released",
    "task_claim_conflict_detected",
    "unknown",
}
SECRET_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"OPENAI" + r"_API_KEY",
        r"ANTHROPIC" + r"_API_KEY",
        r"\bAPI key\b",
        r"\bpassword\b",
        r"\btoken\b",
        r"\bprivate key\b",
        r"\.env\b",
        r"private memory payload",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"-----BEGIN CERTIFICATE-----",
    ]
]
AUDIT_LOGGED_SOURCES = [
    "session_identity_report",
    "operator_attribution_report",
    "session_lifecycle_report",
    "local_context_index_report",
    "sqlite_write_coordination_report",
    "task_claim_report",
    "policy_override_merge_report",
]
AUDIT_PENDING_SOURCES = [
    "agent_trace_validation_report",
    "ai_surface_context_budget_report",
    "static_grader_report",
    "grader_assessment_report",
    "llm_grader_readiness_report",
    "behavioral_governance_readiness_report",
    "sarif_export_summary_report",
    "evidence_pack_report",
    "dashboard_summary_report",
    "gate_status_report",
]
LIMITATIONS = [
    "Audit log events are historical records only; they do not approve, certify, prove compliance, prove report truth, or create non-repudiation.",
    "M4 writes one JSONL file per event with temp-file atomic replacement to avoid shared append collisions on local filesystems.",
    "The audit log stores hashes and summaries by default; it does not copy full private report payloads.",
    "The audit log is not evidence conflict detection, task locking, separation-of-duties validation, cryptographic signing, or tamper-proof storage.",
]
NOT_CLAIMED = [
    "approval",
    "certification",
    "compliance approval",
    "non-repudiation",
    "tamper-proof log",
    "cryptographic signing",
    "task locking",
    "evidence conflict detection",
    "source of truth",
    "full multi-user completion",
]
RESIDUAL_RISKS = [
    "audit_events_can_be_deleted_or_modified_by_repository_writers",
    "source_reports_may_be_overwritten_after_event_capture",
    "missing_session_or_operator_metadata_reduces_traceability",
    "event_summary_may_omit_important_detail_without_manual_review",
    "local_filesystem_semantics_may_vary",
    "human_review_required",
]


def utc_now_text() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: str) -> datetime | None:
    try:
        text = value.replace("Z", "+00:00")
        return datetime.fromisoformat(text)
    except Exception:
        return None


def safe_fragment(value: Any, fallback: str = "unknown", max_length: int = 80) -> str:
    cleaned = SAFE_FRAGMENT_RE.sub("_", str(value or "").strip())[:max_length].strip("._-")
    return cleaned or fallback


def safe_timestamp_fragment(value: str) -> str:
    parsed = parse_timestamp(value)
    if parsed is None:
        return safe_fragment(value, "timestamp", 32)
    return parsed.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")


def audit_log_root_path(root: Path, naos_root: str, policy: dict[str, Any]) -> Path:
    configured = str(policy.get("paths", {}).get("audit_log_root") or "audit_log")
    return root / naos_root / configured


def audit_summary_report_path(root: Path, naos_root: str, policy: dict[str, Any]) -> Path | None:
    return report_output_path(root, naos_root, policy, "audit_log_summary_report")


def latest_session_id(root: Path, naos_root: str, policy: dict[str, Any]) -> str | None:
    path = sessions_index_path(root, naos_root, policy)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    value = data.get("latest_session_id")
    return str(value) if value else None


def hash_json(data: Any) -> str:
    payload = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def safe_digest(path: Path | None) -> str | None:
    if path is None or not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def contains_forbidden_payload(data: Any) -> list[str]:
    text = json.dumps(data, sort_keys=True, default=str)
    matches = []
    for pattern in SECRET_PATTERNS:
        if pattern.search(text):
            matches.append(pattern.pattern)
    return sorted(set(matches))


def summarize_source_report(report: dict[str, Any] | None, source_report_path: Path | None) -> dict[str, Any]:
    data = report if isinstance(report, dict) else {}
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    findings = data.get("findings") if isinstance(data.get("findings"), list) else []
    payload = {
        "schema": data.get("schema"),
        "status": data.get("status"),
        "profile": data.get("profile"),
        "mode": data.get("mode"),
        "session_id": data.get("session_id"),
        "operator_id": data.get("operator_id"),
        "task_id": data.get("task_id"),
        "source_report_path": str(source_report_path) if source_report_path else None,
        "summary": summary,
        "finding_count": len(findings),
        "human_review_required": bool(data.get("human_review_required")),
    }
    if data.get("schema") == "naos.policy_override_merge.v1":
        payload["policy_override_scope"] = {
            "global_overlay_files": list(data.get("global_overlay_files") or []),
            "team_overlay_files": list(data.get("team_overlay_files") or []),
            "operator_overlay_files": list(data.get("operator_overlay_files") or []),
            "selected_team_ids": list(data.get("team_ids") or []),
            "team_id": data.get("team_id"),
            "team_resolution_source": data.get("team_resolution_source"),
            "operator_overlay_id": data.get("operator_overlay_id"),
            "operator_overlay_resolution_source": data.get("operator_overlay_resolution_source"),
            "applied_overlay_scopes": list(data.get("applied_overlay_scopes") or []),
            "overlay_precedence": list(data.get("overlay_precedence") or []),
            "protected_invariant_violation_count": len(data.get("protected_invariant_violations") or []),
        }
    if data.get("schema") == "naos.gate_status.v1":
        payload["gate_team_context"] = {
            "team_id": data.get("team_id"),
            "team_resolution_source": data.get("team_resolution_source"),
            "team_overrides_applied": len(data.get("team_overrides_applied") or []),
            "team_overrides_rejected": len(data.get("team_overrides_rejected") or []),
            "effective_severity_summary": {
                str(gate.get("id")): {
                    "severity": gate.get("effective_severity"),
                    "enabled": gate.get("effective_enabled"),
                    "team_override_applied": bool(gate.get("team_override_applied")),
                }
                for gate in data.get("gates") or []
                if isinstance(gate, dict)
            },
        }
    forbidden = contains_forbidden_payload(payload)
    if forbidden:
        return {
            "redacted": True,
            "redaction_reason": "forbidden_payload_indicator",
            "forbidden_payload_indicators": forbidden,
            "source_report_path": str(source_report_path) if source_report_path else None,
            "schema": data.get("schema"),
            "status": data.get("status"),
        }
    return payload


def event_date_dir(generated_at: str) -> str:
    parsed = parse_timestamp(generated_at)
    if parsed is None:
        return datetime.now(UTC).strftime("%Y-%m-%d")
    return parsed.astimezone(UTC).strftime("%Y-%m-%d")


def event_file_path(audit_root: Path, event: dict[str, Any]) -> Path:
    date_dir = audit_root / event_date_dir(str(event.get("generated_at") or ""))
    timestamp = safe_timestamp_fragment(str(event.get("generated_at") or ""))
    session = safe_fragment(event.get("session_id"), "no-session", 48)
    event_type = safe_fragment(event.get("event_type"), "unknown", 48)
    event_id = safe_fragment(event.get("event_id"), uuid.uuid4().hex, 80)
    return date_dir / f"{timestamp}-{session}-{event_type}-{event_id}.jsonl"


def validate_audit_event(event: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    required = [
        "schema",
        "event_id",
        "event_type",
        "generated_at",
        "session_id",
        "operator_id",
        "operator_source",
        "generated_by",
        "profile",
        "project_root",
        "naos_root",
        "source_report",
        "source_report_hash",
        "source_report_path",
        "related_task_id",
        "related_capability_id",
        "related_gate_id",
        "related_artifacts",
        "event_payload_summary",
        "event_payload_hash",
        "authority_layer",
        "human_review_required",
        "limitations",
        "not_claimed",
        "residual_risks",
    ]
    for key in required:
        if key not in event:
            findings.append({"id": "audit_log_event.missing_required_field", "severity": "blocking", "status": "invalid_events", "field": key})
    if event.get("schema") != EVENT_SCHEMA:
        findings.append({"id": "audit_log_event.invalid_schema", "severity": "blocking", "status": "invalid_events"})
    if event.get("event_type") not in ALLOWED_EVENT_TYPES:
        findings.append({"id": "audit_log_event.invalid_event_type", "severity": "blocking", "status": "invalid_events"})
    if not EVENT_ID_PATTERN.fullmatch(str(event.get("event_id") or "")):
        findings.append({"id": "audit_log_event.invalid_event_id", "severity": "blocking", "status": "invalid_events"})
    forbidden = contains_forbidden_payload(event.get("event_payload_summary") or {})
    if forbidden:
        findings.append(
            {
                "id": "audit_log_event.forbidden_payload_indicator",
                "severity": "warning",
                "status": "advisory",
                "message": "Audit event summary contains secret-like or private-payload indicators.",
                "indicators": forbidden,
            }
        )
    return findings


def build_audit_event(
    *,
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
    event_type: str,
    source_report_path: Path | None = None,
    source_report: dict[str, Any] | None = None,
    session_id: str | None = None,
    generated_by: dict[str, Any] | None = None,
    related_task_id: str | None = None,
    related_capability_id: str | None = None,
    related_gate_id: str | None = None,
    related_artifacts: list[str] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    generated_at = generated_at or utc_now_text()
    session_id = session_id or (source_report or {}).get("session_id") or latest_session_id(root, naos_root, policy)
    generated_by = generated_by or (source_report or {}).get("generated_by")
    if not isinstance(generated_by, dict):
        generated_by = build_generated_by(root, session_id=str(session_id) if session_id else None, generated_at=generated_at)
    operator_id = generated_by.get("operator_id") or (source_report or {}).get("operator_id")
    operator_source = generated_by.get("operator_source") or (source_report or {}).get("operator_source") or "unknown"
    event_type = event_type if event_type in ALLOWED_EVENT_TYPES else "unknown"
    summary = summarize_source_report(source_report, source_report_path)
    residual_risks = list(RESIDUAL_RISKS)
    if summary.get("redacted"):
        residual_risks.append("secret_like_payload_indicator_redacted")
    source_report_hash = safe_digest(source_report_path) if source_report_path else None
    return {
        "schema": EVENT_SCHEMA,
        "event_id": f"audit-{safe_timestamp_fragment(generated_at)}-{uuid.uuid4().hex[:12]}",
        "event_type": event_type,
        "generated_at": generated_at,
        "session_id": str(session_id) if session_id else None,
        "operator_id": operator_id,
        "operator_source": operator_source,
        "generated_by": generated_by,
        "profile": profile,
        "project_root": str(root),
        "naos_root": naos_root,
        "source_report": (source_report or {}).get("schema") or (source_report_path.name if source_report_path else None),
        "source_report_hash": source_report_hash,
        "source_report_path": str(source_report_path) if source_report_path else None,
        "related_task_id": related_task_id or (source_report or {}).get("task_id"),
        "related_capability_id": related_capability_id,
        "related_gate_id": related_gate_id,
        "related_artifacts": related_artifacts or [],
        "event_payload_summary": summary,
        "event_payload_hash": hash_json(summary),
        "authority_layer": "historical_record_non_authoritative",
        "human_review_required": True,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "residual_risks": residual_risks,
    }


def write_audit_event(
    *,
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    profile: str,
    event_type: str,
    source_report_path: Path | None = None,
    source_report: dict[str, Any] | None = None,
    session_id: str | None = None,
    generated_by: dict[str, Any] | None = None,
    related_task_id: str | None = None,
    related_capability_id: str | None = None,
    related_gate_id: str | None = None,
    related_artifacts: list[str] | None = None,
) -> dict[str, Any]:
    if is_kit_repository(root, naos_root) or not (root / naos_root).is_dir():
        return {
            "status": "not_configured",
            "event_file": None,
            "findings": [
                {
                    "id": "audit_log.naos_root_missing",
                    "severity": "advisory",
                    "status": "not_configured",
                    "message": "Generated NAOS root is not present; no audit event was written.",
                }
            ],
        }
    if policy.get("audit_log", {}).get("enabled") is False:
        return {
            "status": "disabled",
            "event_file": None,
            "findings": [
                {
                    "id": "audit_log.disabled_by_policy",
                    "severity": "advisory",
                    "status": "not_configured",
                    "message": "Audit log writing is disabled by policy.",
                }
            ],
        }
    event = build_audit_event(
        root=root,
        naos_root=naos_root,
        profile=profile,
        policy=policy,
        event_type=event_type,
        source_report_path=source_report_path,
        source_report=source_report,
        session_id=session_id,
        generated_by=generated_by,
        related_task_id=related_task_id,
        related_capability_id=related_capability_id,
        related_gate_id=related_gate_id,
        related_artifacts=related_artifacts,
    )
    validation_findings = validate_audit_event(event)
    blocking = [item for item in validation_findings if item.get("severity") == "blocking"]
    if blocking:
        return {"status": "blocked", "event_file": None, "event": event, "findings": validation_findings}
    audit_root = audit_log_root_path(root, naos_root, policy)
    path = event_file_path(audit_root, event)
    path.parent.mkdir(parents=True, exist_ok=True)
    while path.exists():
        event["event_id"] = f"audit-{safe_timestamp_fragment(event['generated_at'])}-{uuid.uuid4().hex[:12]}"
        event["event_payload_hash"] = hash_json(event["event_payload_summary"])
        path = event_file_path(audit_root, event)
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temp_path.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except OSError as exc:
        try:
            if temp_path.exists():
                temp_path.unlink()
        except OSError:
            pass
        return {
            "status": "advisory",
            "event_file": None,
            "event": event,
            "findings": validation_findings
            + [
                {
                    "id": "audit_log.event_write_failed",
                    "severity": "warning",
                    "status": "advisory",
                    "message": f"Audit event could not be written: {exc}",
                }
            ],
        }
    return {"status": "written", "event_file": str(path), "event": event, "findings": validation_findings}


def load_event_file(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        return [], [{"path": str(path), "line": None, "error": str(exc), "status": "invalid_events"}]
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except Exception as exc:
            invalid.append({"path": str(path), "line": index, "error": str(exc), "status": "invalid_events"})
            continue
        if not isinstance(data, dict):
            invalid.append({"path": str(path), "line": index, "error": "event is not a mapping", "status": "invalid_events"})
            continue
        findings = validate_audit_event(data)
        if findings:
            invalid.append({"path": str(path), "line": index, "findings": findings, "status": "invalid_events"})
        events.append(data)
    return events, invalid


def build_summary_report(
    *,
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    profile: str,
) -> dict[str, Any]:
    generated_at = utc_now_text()
    audit_root = audit_log_root_path(root, naos_root, policy)
    events: list[dict[str, Any]] = []
    invalid_events: list[dict[str, Any]] = []
    event_files: list[dict[str, Any]] = []
    if audit_root.exists():
        for path in sorted(audit_root.glob("*/*.jsonl")):
            loaded, invalid = load_event_file(path)
            events.extend(loaded)
            invalid_events.extend(invalid)
            event_files.append(
                {
                    "path": str(path),
                    "event_count": len(loaded),
                    "invalid_event_count": len(invalid),
                    "file_hash": safe_digest(path),
                }
            )
    type_counts = Counter(str(event.get("event_type") or "unknown") for event in events)
    session_ids = sorted({str(event.get("session_id")) for event in events if event.get("session_id")})
    operator_ids = sorted({str(event.get("operator_id")) for event in events if event.get("operator_id")})
    timestamps = sorted(str(event.get("generated_at")) for event in events if event.get("generated_at"))
    missing_session = [str(event.get("event_id")) for event in events if not event.get("session_id")]
    missing_operator = [str(event.get("event_id")) for event in events if not event.get("operator_id")]
    findings: list[dict[str, Any]] = []
    if not events:
        findings.append(
            {
                "id": "audit_log.no_events",
                "severity": "advisory",
                "status": "no_events",
                "message": "No audit log events were found.",
            }
        )
    if invalid_events:
        findings.append(
            {
                "id": "audit_log.invalid_events",
                "severity": "warning",
                "status": "invalid_events",
                "message": "One or more audit log events were invalid or unreadable.",
            }
        )
    if missing_session:
        findings.append(
            {
                "id": "audit_log.missing_session_id_events",
                "severity": "advisory",
                "status": "advisory",
                "message": "Some audit events do not have session_id metadata.",
                "event_ids": missing_session[:25],
            }
        )
    if missing_operator:
        findings.append(
            {
                "id": "audit_log.missing_operator_id_events",
                "severity": "advisory",
                "status": "advisory",
                "message": "Some audit events do not have resolved operator_id metadata.",
                "event_ids": missing_operator[:25],
            }
        )
    if invalid_events:
        status = "invalid_events"
    elif not events:
        status = "no_events"
    elif findings:
        status = "advisory"
    else:
        status = "ready"
    return {
        "schema": SUMMARY_SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "audit_log_root": str(audit_root),
        "event_count": len(events),
        "event_type_counts": dict(sorted(type_counts.items())),
        "session_ids": session_ids,
        "operator_ids": operator_ids,
        "date_range": {"start": timestamps[0] if timestamps else None, "end": timestamps[-1] if timestamps else None},
        "latest_event_at": timestamps[-1] if timestamps else None,
        "missing_session_id_events": missing_session,
        "missing_operator_id_events": missing_operator,
        "invalid_event_count": len(invalid_events),
        "invalid_events": invalid_events[:100],
        "event_files": event_files,
        "audit_logged_sources": AUDIT_LOGGED_SOURCES,
        "audit_pending_sources": AUDIT_PENDING_SOURCES,
        "findings": findings,
        "known_gaps": [
            "not_all_report_writers_are_audit_logged_in_m4",
            "evidence_conflict_resolution_workflow_deferred",
            "task_claim_authorization_and_resolution_deferred",
            "team_operator_policy_overlays_deferred",
        ],
        "residual_risks": RESIDUAL_RISKS,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": True,
        "summary": {
            "status": status,
            "events": len(events),
            "event_files": len(event_files),
            "invalid_events": len(invalid_events),
            "missing_session_id_events": len(missing_session),
            "missing_operator_id_events": len(missing_operator),
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Write/read NAOS append-only audit log events.")
    parser.add_argument("--profile", help="Profile name: quickstart, lite, standard, assured.")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"), help="Generated project NAOS root. Default from policy.")
    parser.add_argument("--policy", help="Optional policy file.")
    parser.add_argument("--event-type", choices=sorted(ALLOWED_EVENT_TYPES), help="Optionally write a manual audit event before summarizing.")
    parser.add_argument("--session-id", help="Optional session id for a manual audit event.")
    parser.add_argument("--summary", action="store_true", help="Summarize existing audit log events. Default when no event type is provided.")
    parser.add_argument("--output", help="Optional summary report output path.")
    parser.add_argument("--json", action="store_true", help="Print summary JSON.")
    parser.add_argument("--strict", action="store_true", help="Accepted for Makefile consistency; audit-log summary remains advisory by default.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    write_result: dict[str, Any] | None = None
    if args.event_type:
        write_result = write_audit_event(
            root=root,
            naos_root=naos_root,
            policy=policy,
            profile=profile,
            event_type=args.event_type,
            session_id=args.session_id,
        )
    report = build_summary_report(root=root, naos_root=naos_root, policy=policy, profile=profile)
    if write_result is not None:
        report["manual_event_write"] = {
            "status": write_result.get("status"),
            "event_file": write_result.get("event_file"),
            "findings": write_result.get("findings") or [],
        }
    output = Path(args.output) if args.output else audit_summary_report_path(root, naos_root, policy)
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"NAOS audit log summary ({profile}): {report['status']}")
        print(f"events: {report['event_count']} files: {len(report['event_files'])}")
        print(f"report: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
