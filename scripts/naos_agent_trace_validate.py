#!/usr/bin/env python3
"""Validate declared NAOS agent trace events without runtime capture."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    load_policy,
    normalize_profile,
    report_output_path,
    severity_for_profile,
    write_report,
)


REPORT_SCHEMA = "naos.agent_trace_validation.v1"
EVENT_SCHEMA_PATH = Path("schemas/naos/agent_trace_event.schema.json")
TASK_CONTEXT_PHASES = {"task_start", "implementation", "review", "checkpoint", "session_end", "task_complete"}
LIFECYCLE_PHASES = {
    "session_start",
    "task_start",
    "implementation",
    "review",
    "checkpoint",
    "session_end",
    "task_complete",
    "unknown",
}
ACTION_TYPES = {"read", "write", "generate", "validate", "query", "review", "route", "summarize", "recommend", "unknown"}
TRACE_STATUS_VALUES = {"declared", "review_required", "reviewed", "rejected", "superseded", "unknown"}
AUTHORITY_LAYERS = {"record_only", "deterministic_primary", "advisory_complementary", "unknown"}
TRACE_ORIGINS = {"manual", "agent_declared", "tool_declared", "generated_report", "unknown"}
REVIEW_STATUS_VALUES = {"not_reviewed", "review_pending", "reviewed", "rejected", "unknown"}
ACTION_CONTRACTS = {
    "read",
    "draft",
    "propose",
    "local_write",
    "command_execution",
    "network_call",
    "external_account_action",
    "memory_write_candidate",
    "deploy_release",
    "unknown",
}
SIDE_EFFECT_CLASSES = {
    "none",
    "local_read",
    "local_write",
    "command_execution",
    "network_call",
    "external_account_action",
    "memory_write",
    "deploy_release",
    "unknown",
}
SIDE_EFFECTS_REQUIRING_APPROVAL_REVIEW = {
    "local_write",
    "command_execution",
    "network_call",
    "external_account_action",
    "memory_write",
    "deploy_release",
}
SIDE_EFFECTS_REQUIRING_PERMISSION_SCOPE = {
    "command_execution",
    "network_call",
    "external_account_action",
    "memory_write",
    "deploy_release",
}
APPROVAL_STATUSES = {"not_required", "required_pending", "approved", "denied", "expired", "unknown"}
TOOL_DECISIONS = {"allowed", "blocked", "modified", "deferred", "failed", "unknown"}
MEMORY_OPERATIONS = {"none", "read_candidate", "read_reviewed", "write_candidate", "approved_write", "rejected_write", "unknown"}
MEMORY_TRUST_STATES = {
    "raw_memory_candidate",
    "review_pending_memory",
    "rejected_memory",
    "superseded_memory",
    "supporting_context_memory",
    "instruction_grade_memory",
    "unknown",
}
MEMORY_USE_LEVELS = {"none", "supporting_context", "instruction", "unknown"}
ACTION_RECEIPT_REQUIRED_FIELDS = {
    "intended_action",
    "action_contract",
    "side_effect_class",
    "approval_required",
    "approval_status",
    "tool_decision",
}
ACTION_RECEIPT_OPTIONAL_FIELDS = {
    "permission_scope",
    "approval_ref",
    "blocked_or_escalated_reason",
    "claim_refs",
    "memory_operation",
    "memory_trust_state",
    "memory_use_level",
}
ACTION_RECEIPT_ALLOWED_FIELDS = ACTION_RECEIPT_REQUIRED_FIELDS | ACTION_RECEIPT_OPTIONAL_FIELDS
ACTION_RECEIPT_CONTROLLED_METADATA_PATHS = {
    "$.action_receipt.action_contract",
    "$.action_receipt.side_effect_class",
    "$.action_receipt.approval_required",
    "$.action_receipt.approval_status",
    "$.action_receipt.tool_decision",
    "$.action_receipt.memory_operation",
    "$.action_receipt.memory_trust_state",
    "$.action_receipt.memory_use_level",
}
STRING_LIST_FIELDS = {
    "input_artifacts",
    "output_artifacts",
    "referenced_specs",
    "referenced_tasks",
    "referenced_capabilities",
    "commands_run",
    "files_read",
    "files_modified",
    "reports_generated",
    "evidence_refs",
    "memory_refs",
    "advisory_controls_used",
    "deterministic_controls_used",
    "source_references",
    "residual_risks",
}
OPTIONAL_EVENT_FIELDS = {
    "task_id",
    "source_hashes",
    "profile",
    "authority_layer",
    "trace_origin",
    "trace_status",
    "confidence",
    "forbidden_payload_check",
    "review_status",
    "reviewer",
    "reviewed_at",
    "action_receipt",
}
REQUIRED_EVENT_FIELDS = {
    "event_id",
    "generated_at",
    "session_id",
    "agent_or_surface",
    "lifecycle_phase",
    "action_type",
    "human_review_required",
    "limitations",
    "not_claimed",
}
ALLOWED_EVENT_FIELDS = REQUIRED_EVENT_FIELDS | STRING_LIST_FIELDS | OPTIONAL_EVENT_FIELDS
PATH_FIELDS = {
    "input_artifacts",
    "output_artifacts",
    "files_read",
    "files_modified",
    "reports_generated",
    "evidence_refs",
    "source_references",
}
SECRET_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"\bOPENAI" + r"_API_KEY\b",
        r"\bANTHROPIC" + r"_API_KEY\b",
        r"\bAPI key\b",
        r"\bpassword\b",
        r"\btoken\b",
        r"\bprivate key\b",
        r"\.env(?:\b|$)",
        r"\bengram\.db\b",
        r"\bprivate memory payload\b",
        r"-----BEGIN [A-Z ]+-----",
        r"\bBEGIN CERTIFICATE\b",
    ]
]
OVERCLAIM_PATTERNS = [
    ("trace_claims_proof", re.compile(r"\b(proof|prove|proves|proven)\b", re.IGNORECASE)),
    ("trace_claims_approval", re.compile(r"\b(approval|approved|approves|approve)\b", re.IGNORECASE)),
    ("trace_claims_certification", re.compile(r"\b(certified|certification|certify)\b", re.IGNORECASE)),
    ("trace_claims_compliance_proof", re.compile(r"\bcompliance proof\b", re.IGNORECASE)),
    ("trace_claims_source_of_truth", re.compile(r"\bsource[- ]of[- ]truth\b|\bauthoritative truth\b", re.IGNORECASE)),
    ("trace_claims_hallucination_prevention", re.compile(r"\bhallucination prevention\b|\bhallucination-proof\b", re.IGNORECASE)),
    ("trace_claims_behavioral_safety_proof", re.compile(r"\bbehavioral safety proof\b", re.IGNORECASE)),
]
MEMORY_WRITE_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"\bmemory write\b",
        r"\bwrites? memory\b",
        r"\bmemory write-back\b",
        r"\binstruction-grade memory\b",
    ]
]


def utc_now_text() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def trace_default_path(root: Path, naos_root: str, policy: dict[str, Any]) -> Path:
    trace_file = str(policy.get("paths", {}).get("agent_trace_events") or "agent_trace_events.yaml")
    return root / naos_root / trace_file


def load_trace_events(trace_file: Path) -> tuple[list[dict[str, Any]], str | None]:
    try:
        data = yaml.safe_load(trace_file.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return [], str(exc)
    if isinstance(data, list):
        raw_events = data
    elif isinstance(data, dict):
        raw_events = data.get("events") or []
    else:
        return [], "trace file must be a mapping with events or a list of events"
    events = [item for item in raw_events if isinstance(item, dict)]
    if len(events) != len(raw_events):
        return events, "trace file contains non-mapping event entries"
    return events, None


def event_scalar_values(value: Any, path: str = "$") -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            values.extend(event_scalar_values(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            values.extend(event_scalar_values(child, f"{path}[{index}]"))
    elif value is not None:
        values.append((path, str(value)))
    return values


def finding(
    *,
    event_id: str | None,
    severity: str,
    status: str,
    message: str,
    field: str | None = None,
) -> dict[str, Any]:
    finding_id = f"{event_id or 'trace_event'}.{status}"
    result = {"id": finding_id, "severity": severity, "status": status, "message": message}
    if event_id:
        result["event_id"] = event_id
    if field:
        result["field"] = field
    return result


def parse_datetime(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    raw = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        datetime.fromisoformat(raw)
    except ValueError:
        return False
    return True


def validate_action_receipt_shape(receipt: Any) -> list[str]:
    errors: list[str] = []
    if receipt is None:
        return errors
    if not isinstance(receipt, dict):
        return ["action_receipt must be an object"]

    unknown_fields = sorted(set(receipt) - ACTION_RECEIPT_ALLOWED_FIELDS)
    errors.extend(f"action_receipt unknown field: {field}" for field in unknown_fields)
    missing = sorted(field for field in ACTION_RECEIPT_REQUIRED_FIELDS if receipt.get(field) in (None, ""))
    errors.extend(f"action_receipt missing required field: {field}" for field in missing)

    if "intended_action" in receipt and not isinstance(receipt.get("intended_action"), str):
        errors.append("action_receipt.intended_action must be a string")
    if receipt.get("action_contract") and receipt.get("action_contract") not in ACTION_CONTRACTS:
        errors.append(f"action_receipt.action_contract must be one of {sorted(ACTION_CONTRACTS)}")
    if receipt.get("side_effect_class") and receipt.get("side_effect_class") not in SIDE_EFFECT_CLASSES:
        errors.append(f"action_receipt.side_effect_class must be one of {sorted(SIDE_EFFECT_CLASSES)}")
    if "approval_required" in receipt and not isinstance(receipt.get("approval_required"), bool):
        errors.append("action_receipt.approval_required must be boolean")
    if receipt.get("approval_status") and receipt.get("approval_status") not in APPROVAL_STATUSES:
        errors.append(f"action_receipt.approval_status must be one of {sorted(APPROVAL_STATUSES)}")
    if receipt.get("tool_decision") and receipt.get("tool_decision") not in TOOL_DECISIONS:
        errors.append(f"action_receipt.tool_decision must be one of {sorted(TOOL_DECISIONS)}")
    if receipt.get("memory_operation") and receipt.get("memory_operation") not in MEMORY_OPERATIONS:
        errors.append(f"action_receipt.memory_operation must be one of {sorted(MEMORY_OPERATIONS)}")
    if receipt.get("memory_trust_state") and receipt.get("memory_trust_state") not in MEMORY_TRUST_STATES:
        errors.append(f"action_receipt.memory_trust_state must be one of {sorted(MEMORY_TRUST_STATES)}")
    if receipt.get("memory_use_level") and receipt.get("memory_use_level") not in MEMORY_USE_LEVELS:
        errors.append(f"action_receipt.memory_use_level must be one of {sorted(MEMORY_USE_LEVELS)}")

    for field in {"permission_scope", "approval_ref", "blocked_or_escalated_reason"}:
        if field in receipt and receipt.get(field) is not None and not isinstance(receipt.get(field), str):
            errors.append(f"action_receipt.{field} must be a string or null")

    claim_refs = receipt.get("claim_refs")
    if claim_refs is not None:
        if not isinstance(claim_refs, list):
            errors.append("action_receipt.claim_refs must be a list")
        else:
            for index, claim in enumerate(claim_refs):
                if not isinstance(claim, dict):
                    errors.append(f"action_receipt.claim_refs[{index}] must be an object")
                    continue
                unknown_claim_fields = sorted(set(claim) - {"claim", "evidence_refs"})
                errors.extend(f"action_receipt.claim_refs[{index}] unknown field: {field}" for field in unknown_claim_fields)
                if not isinstance(claim.get("claim"), str) or not claim.get("claim"):
                    errors.append(f"action_receipt.claim_refs[{index}].claim must be a non-empty string")
                evidence_refs = claim.get("evidence_refs")
                if evidence_refs is not None and (
                    not isinstance(evidence_refs, list) or any(not isinstance(item, str) for item in evidence_refs)
                ):
                    errors.append(f"action_receipt.claim_refs[{index}].evidence_refs must be a list of strings")

    return errors


def validate_schema_shape(event: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    unknown_fields = sorted(set(event) - ALLOWED_EVENT_FIELDS)
    errors.extend(f"unknown field: {field}" for field in unknown_fields)
    missing = sorted(field for field in REQUIRED_EVENT_FIELDS if field not in event or event.get(field) in (None, ""))
    errors.extend(f"missing required field: {field}" for field in missing)

    if event.get("generated_at") and not parse_datetime(event.get("generated_at")):
        errors.append("generated_at must be an ISO 8601 date-time")
    if event.get("reviewed_at") and not parse_datetime(event.get("reviewed_at")):
        errors.append("reviewed_at must be an ISO 8601 date-time when present")
    if event.get("lifecycle_phase") and event.get("lifecycle_phase") not in LIFECYCLE_PHASES:
        errors.append(f"lifecycle_phase must be one of {sorted(LIFECYCLE_PHASES)}")
    if event.get("action_type") and event.get("action_type") not in ACTION_TYPES:
        errors.append(f"action_type must be one of {sorted(ACTION_TYPES)}")
    if event.get("authority_layer") and event.get("authority_layer") not in AUTHORITY_LAYERS:
        errors.append(f"authority_layer must be one of {sorted(AUTHORITY_LAYERS)}")
    if event.get("trace_origin") and event.get("trace_origin") not in TRACE_ORIGINS:
        errors.append(f"trace_origin must be one of {sorted(TRACE_ORIGINS)}")
    if event.get("trace_status") and event.get("trace_status") not in TRACE_STATUS_VALUES:
        errors.append(f"trace_status must be one of {sorted(TRACE_STATUS_VALUES)}")
    if event.get("review_status") and event.get("review_status") not in REVIEW_STATUS_VALUES:
        errors.append(f"review_status must be one of {sorted(REVIEW_STATUS_VALUES)}")
    if "human_review_required" in event and not isinstance(event.get("human_review_required"), bool):
        errors.append("human_review_required must be boolean")
    if event.get("confidence") is not None:
        confidence = event.get("confidence")
        if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            errors.append("confidence must be a number between 0 and 1")
    for field in STRING_LIST_FIELDS | {"limitations", "not_claimed"}:
        if field in event:
            value = event.get(field)
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                errors.append(f"{field} must be a list of strings")
    for field in {"limitations", "not_claimed"}:
        if field in event and isinstance(event.get(field), list) and not event.get(field):
            errors.append(f"{field} must not be empty")
    if "source_hashes" in event and not isinstance(event.get("source_hashes"), dict):
        errors.append("source_hashes must be a mapping of source reference to digest")
    errors.extend(validate_action_receipt_shape(event.get("action_receipt")))
    return errors


def path_outside_project(value: str) -> bool:
    path = Path(value)
    if path.is_absolute():
        return True
    return ".." in path.parts


def validate_action_receipt_semantics(event_id: str | None, receipt: dict[str, Any], severity: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    side_effect = str(receipt.get("side_effect_class") or "unknown")
    approval_required = receipt.get("approval_required")
    approval_status = str(receipt.get("approval_status") or "unknown")
    permission_scope = str(receipt.get("permission_scope") or "").strip()
    approval_ref = str(receipt.get("approval_ref") or "").strip()
    memory_operation = str(receipt.get("memory_operation") or "none")
    memory_trust_state = str(receipt.get("memory_trust_state") or "unknown")
    memory_use_level = str(receipt.get("memory_use_level") or "unknown")

    if side_effect in SIDE_EFFECTS_REQUIRING_APPROVAL_REVIEW and approval_required is True and approval_status != "approved":
        findings.append(
            finding(
                event_id=event_id,
                severity=severity,
                status="action_receipt_approval_missing",
                message=(
                    f"Action receipt declares side effect {side_effect!r} with approval required, "
                    f"but approval_status is {approval_status!r}."
                ),
                field="action_receipt.approval_status",
            )
        )

    if side_effect in SIDE_EFFECTS_REQUIRING_PERMISSION_SCOPE and not permission_scope:
        findings.append(
            finding(
                event_id=event_id,
                severity=severity,
                status="action_receipt_permission_scope_missing",
                message=f"Action receipt declares side effect {side_effect!r} without an explicit permission scope.",
                field="action_receipt.permission_scope",
            )
        )

    if approval_required is True and approval_status == "approved" and not approval_ref:
        findings.append(
            finding(
                event_id=event_id,
                severity="advisory",
                status="action_receipt_approval_ref_missing",
                message="Action receipt declares approved status without an approval reference.",
                field="action_receipt.approval_ref",
            )
        )

    if memory_use_level == "instruction" and memory_trust_state != "instruction_grade_memory":
        findings.append(
            finding(
                event_id=event_id,
                severity=severity,
                status="action_receipt_instruction_memory_not_approved",
                message=(
                    "Action receipt declares instruction-level memory use without "
                    "instruction_grade_memory trust state."
                ),
                field="action_receipt.memory_trust_state",
            )
        )

    if memory_trust_state in {"rejected_memory", "superseded_memory"} and memory_use_level in {"supporting_context", "instruction"}:
        findings.append(
            finding(
                event_id=event_id,
                severity=severity,
                status="action_receipt_rejected_or_superseded_memory_used",
                message=f"Action receipt declares {memory_trust_state} used as {memory_use_level}.",
                field="action_receipt.memory_trust_state",
            )
        )

    if memory_operation == "approved_write" and approval_status != "approved":
        findings.append(
            finding(
                event_id=event_id,
                severity=severity,
                status="action_receipt_memory_write_without_approval",
                message="Action receipt declares approved memory write without approved action status.",
                field="action_receipt.memory_operation",
            )
        )

    for index, claim in enumerate(receipt.get("claim_refs") or []):
        if isinstance(claim, dict) and not claim.get("evidence_refs"):
            findings.append(
                finding(
                    event_id=event_id,
                    severity=severity,
                    status="action_receipt_claim_missing_evidence_refs",
                    message=f"Action receipt claim_refs[{index}] declares a claim without evidence refs.",
                    field=f"action_receipt.claim_refs[{index}].evidence_refs",
                )
            )

    return findings


def validate_event(event: dict[str, Any], profile: str, policy: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    event_id = str(event.get("event_id")) if event.get("event_id") else None
    severity = severity_for_profile(profile, policy)
    schema_errors = validate_schema_shape(event)
    findings: list[dict[str, Any]] = []
    for error in schema_errors:
        findings.append(
            finding(
                event_id=event_id,
                severity=severity,
                status="invalid_event_schema",
                message=error,
            )
        )

    phase = str(event.get("lifecycle_phase") or "unknown")
    if phase in TASK_CONTEXT_PHASES and not event.get("task_id"):
        findings.append(
            finding(
                event_id=event_id,
                severity=severity,
                status="missing_task_id",
                message=f"Lifecycle phase {phase} requires task context.",
                field="task_id",
            )
        )

    output_artifacts = event.get("output_artifacts") or []
    source_refs = event.get("source_references") or []
    source_hashes = event.get("source_hashes") or {}
    if output_artifacts and not source_refs and not source_hashes:
        findings.append(
            finding(
                event_id=event_id,
                severity=severity,
                status="missing_source_references",
                message="Trace event declares output artifacts without source references or source hashes.",
                field="source_references",
            )
        )

    if not event.get("limitations"):
        findings.append(
            finding(
                event_id=event_id,
                severity=severity,
                status="missing_limitations",
                message="Trace event must declare limitations.",
                field="limitations",
            )
        )
    if not event.get("not_claimed"):
        findings.append(
            finding(
                event_id=event_id,
                severity=severity,
                status="missing_not_claimed",
                message="Trace event must declare non-claims.",
                field="not_claimed",
            )
        )

    # AC-AUTONOMY-BOUNDARY-01 (indirect): advisory/record-only authority must not perform a
    # mutating action in place of deterministic controls or human approval. Deterministic
    # check over declared trace fields — not a runtime sandbox proof.
    authority = str(event.get("authority_layer") or "")
    action = str(event.get("action_type") or "")
    mutating = action in {"write", "generate"} or bool(event.get("files_modified"))
    non_authoritative = authority in {"record_only", "advisory_complementary"}
    has_deterministic_controls = bool(event.get("deterministic_controls_used"))
    human_reviewed = event.get("human_review_required") is True or str(event.get("review_status") or "") == "reviewed"
    if mutating and non_authoritative and not has_deterministic_controls and not human_reviewed:
        findings.append(
            finding(
                event_id=event_id,
                severity=severity,
                status="autonomy_boundary_violation",
                message=(
                    "Advisory/record-only authority performed a mutating action without deterministic "
                    "controls or human review; model judgement must not replace deterministic controls "
                    "or human approval (AC-AUTONOMY-BOUNDARY-01)."
                ),
                field="authority_layer",
            )
        )

    receipt = event.get("action_receipt")
    if isinstance(receipt, dict):
        findings.extend(validate_action_receipt_semantics(event_id, receipt, severity))

    for field in PATH_FIELDS:
        for value in event.get(field) or []:
            if path_outside_project(value):
                findings.append(
                    finding(
                        event_id=event_id,
                        severity=severity,
                        status="path_outside_project_scope",
                        message=f"Trace event references a path outside project scope: {value}",
                        field=field,
                    )
                )

    for field_path, text in event_scalar_values(event):
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                findings.append(
                    finding(
                        event_id=event_id,
                        severity=severity,
                        status="forbidden_payload_indicator",
                        message=f"Trace event contains a forbidden/private payload indicator at {field_path}.",
                        field=field_path,
                    )
                )
        bounded_nonclaim_field = ".not_claimed" in field_path or ".limitations" in field_path
        controlled_receipt_metadata = field_path in ACTION_RECEIPT_CONTROLLED_METADATA_PATHS
        if bounded_nonclaim_field or controlled_receipt_metadata:
            continue
        for status, pattern in OVERCLAIM_PATTERNS:
            if pattern.search(text):
                findings.append(
                    finding(
                        event_id=event_id,
                        severity=severity,
                        status=status,
                        message=f"Trace event contains authority/proof overclaim wording at {field_path}.",
                        field=field_path,
                    )
                )
        for pattern in MEMORY_WRITE_PATTERNS:
            if pattern.search(text):
                findings.append(
                    finding(
                        event_id=event_id,
                        severity=severity,
                        status="trace_claims_memory_write",
                        message=f"Trace event appears to claim a memory write or instruction-grade memory at {field_path}.",
                        field=field_path,
                    )
                )

    if event.get("memory_refs"):
        findings.append(
            finding(
                event_id=event_id,
                severity="advisory",
                status="memory_reference_review_required",
                message="Trace event references memory; memory references remain advisory and require memory access/use-policy context.",
                field="memory_refs",
            )
        )

    schema_result = {
        "event_index": 0,
        "event_id": event_id,
        "valid": not schema_errors,
        "errors": schema_errors,
    }
    return schema_result, findings


def count_values(events: list[dict[str, Any]], field: str, default: str = "unknown") -> dict[str, int]:
    counter = Counter(str(event.get(field) or default) for event in events)
    return dict(sorted(counter.items()))


def unique_list(values: list[str]) -> list[str]:
    return sorted(dict.fromkeys(str(value) for value in values if str(value)))


def build_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    trace_file: Path,
) -> dict[str, Any]:
    trace_file_present = trace_file.exists()
    events: list[dict[str, Any]] = []
    load_error: str | None = None
    findings: list[dict[str, Any]] = []
    schema_results: list[dict[str, Any]] = []

    if trace_file_present:
        events, load_error = load_trace_events(trace_file)
        if load_error:
            findings.append(
                finding(
                    event_id=None,
                    severity=severity_for_profile(profile, policy),
                    status="invalid_trace_file",
                    message=load_error,
                )
            )
    else:
        findings.append(
            finding(
                event_id=None,
                severity="advisory",
                status="missing_trace_file",
                message="Agent trace events file is not configured; no runtime capture is attempted.",
            )
        )

    for index, event in enumerate(events):
        schema_result, event_findings = validate_event(event, profile, policy)
        schema_result["event_index"] = index
        schema_results.append(schema_result)
        findings.extend(event_findings)

    invalid_event_count = sum(1 for result in schema_results if not result["valid"])
    valid_event_count = len(schema_results) - invalid_event_count
    forbidden_payload_findings = [item for item in findings if item.get("status") == "forbidden_payload_indicator"]
    output_without_source = sum(
        1
        for event in events
        if (event.get("output_artifacts") or []) and not (event.get("source_references") or []) and not (event.get("source_hashes") or {})
    )
    source_hash_count = sum(len(event.get("source_hashes") or {}) for event in events if isinstance(event.get("source_hashes"), dict))
    task_refs = unique_list(
        [str(event.get("task_id")) for event in events if event.get("task_id")]
        + [ref for event in events for ref in (event.get("referenced_tasks") or [])]
    )
    deterministic_controls = unique_list([item for event in events for item in (event.get("deterministic_controls_used") or [])])
    advisory_controls = unique_list([item for event in events for item in (event.get("advisory_controls_used") or [])])
    memory_refs = [item for event in events for item in (event.get("memory_refs") or [])]
    action_receipt_events = sum(1 for event in events if isinstance(event.get("action_receipt"), dict))
    summary = finding_counts(findings)
    summary.update(
        {
            "events": len(events),
            "valid_events": valid_event_count,
            "invalid_events": invalid_event_count,
            "forbidden_payload_findings": len(forbidden_payload_findings),
            "memory_ref_events": sum(1 for event in events if event.get("memory_refs")),
            "action_receipt_events": action_receipt_events,
        }
    )
    if not trace_file_present:
        status = "not_configured"
    elif not events:
        status = "no_events"
    elif invalid_event_count:
        status = "invalid_trace_events"
    elif forbidden_payload_findings or any(item.get("status", "").startswith("trace_claims_") for item in findings):
        status = "blocked" if severity_for_profile(profile, policy) == "blocking" else "review_required"
    elif findings:
        status = "review_required" if profile in {"standard", "assured"} else "advisory"
    else:
        status = "ready"

    return {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "trace_file": str(trace_file),
        "trace_file_present": trace_file_present,
        "event_count": len(events),
        "valid_event_count": valid_event_count,
        "invalid_event_count": invalid_event_count,
        "event_status_counts": count_values(events, "trace_status", "unknown"),
        "lifecycle_phase_counts": count_values(events, "lifecycle_phase", "unknown"),
        "action_type_counts": count_values(events, "action_type", "unknown"),
        "agent_surface_counts": count_values(events, "agent_or_surface", "unknown"),
        "task_refs": task_refs,
        "source_reference_summary": {
            "source_references": sum(len(event.get("source_references") or []) for event in events),
            "source_hashes": source_hash_count,
            "events_with_output_without_source_refs": output_without_source,
        },
        "deterministic_controls_used": deterministic_controls,
        "advisory_controls_used": advisory_controls,
        "memory_reference_summary": {
            "events_with_memory_refs": sum(1 for event in events if event.get("memory_refs")),
            "memory_refs": len(memory_refs),
            "advisory_only": True,
        },
        "forbidden_payload_findings": forbidden_payload_findings,
        "schema_validation_results": schema_results,
        "findings": findings,
        "known_gaps": [
            "Trace validation feeds StaticGrader and deterministic grader assessment, but LLMGrader runtime remains future/deferred.",
            "Trace events are manually declared records unless a future runtime capture design is explicitly approved.",
        ],
        "residual_risks": [
            "Declared trace events can be incomplete, stale, or inaccurate.",
            "Pattern-based payload checks can miss secrets or flag benign text.",
            "Future grading must keep deterministic and advisory results separate and preserve human review boundaries.",
        ],
        "limitations": [
            "Agent trace validation does not capture runtime events.",
            "Agent trace validation does not run commands listed in trace events.",
            "Agent trace validation does not call Engram, MCP, memory tools, models, providers, or external APIs.",
            "Action receipts are declared metadata only; they do not enforce permissions or prove approval.",
            "Agent trace events are records, not proof, approval, evidence authority, memory writes, legal/compliance/regulatory assurance, or behavioral safety proof.",
        ],
        "not_claimed": [
            "runtime trace capture",
            "runtime audit-event capture",
            "command execution",
            "tool-call interception",
            "permission enforcement",
            "memory write",
            "private memory payload read",
            "Engram or MCP call",
            "LLMGrader runtime",
            "behavioral correctness proof",
            "approval",
            "legal/compliance/regulatory assurance",
            "hallucination prevention",
        ],
        "human_review_required": bool(findings or events),
        "summary": summary,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate declared NAOS agent trace events.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--trace-file", help="Trace YAML to validate. Defaults to NAOS_ROOT/agent_trace_events.yaml.")
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
    trace_file = Path(args.trace_file) if args.trace_file else trace_default_path(root, naos_root, policy)
    report = build_report(root=root, profile=profile, naos_root=naos_root, policy=policy, trace_file=trace_file)
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "agent_trace_validation_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            "NAOS agent trace validation: "
            f"{report['status']} "
            f"({report['event_count']} events, {report['invalid_event_count']} invalid) -> {output}"
        )
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    sys.exit(main())
