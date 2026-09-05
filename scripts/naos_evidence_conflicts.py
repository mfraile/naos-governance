#!/usr/bin/env python3
"""Detect deterministic evidence/review conflicts for NAOS."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
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
    evidence_pack_output_path,
    is_kit_repository,
    load_policy,
    normalize_profile,
    report_default_path,
    report_output_path,
    resolve_operator_attribution,
    session_report_default_path,
    sessions_index_path,
    write_report_with_session,
)
from naos_session_identity import record_session_report_reference  # noqa: E402


REPORT_SCHEMA = "naos.evidence_conflict_detection.v1"
SAFE_ID_RE = re.compile(r"[^A-Za-z0-9._:@+-]+")
SECRET_KEY_RE = re.compile(r"(api[_-]?key|password|token|secret|private[_-]?key|credential|\\.env)", re.IGNORECASE)
OUTCOME_MAP = {
    "approved": "approved",
    "approve": "approved",
    "accepted": "approved",
    "acknowledged": "approved",
    "pass": "approved",
    "passed": "approved",
    "ready": "approved",
    "rejected": "rejected",
    "reject": "rejected",
    "failed": "rejected",
    "fail": "rejected",
    "blocked": "rejected",
    "needs_changes": "needs_changes",
    "needs changes": "needs_changes",
    "changes_requested": "needs_changes",
    "review_required": "needs_changes",
    "required": "needs_changes",
    "warning": "needs_changes",
    "missing": "needs_changes",
    "stale": "needs_changes",
    "uncovered": "needs_changes",
    "waived": "waived",
    "waiver": "waived",
    "accepted_risk": "accepted_risk",
    "risk_accepted": "accepted_risk",
    "accepted_with_gaps": "accepted_risk",
    "deferred": "not_reviewed",
    "not_reviewed": "not_reviewed",
    "not reviewed": "not_reviewed",
    "unknown": "unknown",
}
REPORT_LIMITATIONS = [
    "Conflict detection is deterministic and conservative; it does not adjudicate which evidence is correct.",
    "The report uses structured local files only and does not scrape broad unstructured prose.",
    "Audit log inputs are records used for enrichment; they are not source-of-truth evidence.",
    "Operator attribution is local metadata only; it is not authentication or authorization.",
]
NOT_CLAIMED = [
    "conflict resolution",
    "approval",
    "rejection",
    "adjudication",
    "separation-of-duties proof",
    "compliance approval",
    "audit conclusion",
    "task locking",
    "source of truth",
    "full multi-user completion",
]
RESIDUAL_RISKS = [
    "absence_of_conflicts_does_not_prove_evidence_correctness",
    "unsupported_sources_may_hide_conflicts",
    "operator_metadata_is_not_authentication",
    "structured_routes_may_be_incomplete",
    "human_review_required",
]
SUPPORTED_OUTCOMES = [
    "approved",
    "rejected",
    "needs_changes",
    "waived",
    "accepted_risk",
    "not_reviewed",
    "unknown",
]


def utc_now_text() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_id(value: str, fallback: str = "conflict") -> str:
    cleaned = SAFE_ID_RE.sub("_", value.strip())[:140].strip("._-")
    return cleaned or fallback


def load_yaml_mapping(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def load_json_mapping(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"_invalid": True, "_path": str(path)}
    return data if isinstance(data, dict) else {"_invalid": True, "_path": str(path)}


def as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None or value == "":
        return []
    return [value]


def as_str_list(value: Any) -> list[str]:
    return [str(item).strip() for item in as_list(value) if str(item).strip()]


def secret_like_fields(value: Any, prefix: str = "") -> list[str]:
    fields: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            key_text = str(key)
            path = f"{prefix}.{key_text}" if prefix else key_text
            if SECRET_KEY_RE.search(key_text):
                fields.append(path)
            fields.extend(secret_like_fields(nested, path))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            fields.extend(secret_like_fields(nested, f"{prefix}[{index}]" if prefix else f"[{index}]"))
    return fields


def sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def path_text(path: Path | None, root: Path) -> str | None:
    if path is None:
        return None
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def find_first(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, dict):
            nested = find_first(value.get("operator_id"), value.get("id"), value.get("email"), value.get("name"))
            if nested:
                return nested
        text = str(value or "").strip()
        if text:
            return text
    return None


def normalize_outcome(value: Any) -> str:
    text = str(value or "unknown").strip().lower().replace("-", "_")
    return OUTCOME_MAP.get(text, OUTCOME_MAP.get(text.replace("_", " "), "unknown"))


def attestation_id(item: dict[str, Any], index: int) -> str:
    return str(item.get("id") or item.get("attestation_id") or f"attestation_{index}")


def reviewer_id(item: dict[str, Any]) -> str | None:
    return find_first(
        item.get("operator_id"),
        item.get("reviewer_id"),
        item.get("reviewer_operator_id"),
        item.get("reviewer_contact"),
        item.get("reviewer_email"),
        item.get("reviewer_name"),
    )


def creator_id(item: dict[str, Any]) -> str | None:
    return find_first(
        item.get("created_by_operator_id"),
        item.get("generated_by_operator_id"),
        item.get("artifact_operator_id"),
        item.get("created_by"),
        item.get("generated_by"),
    )


def artifact_manifest_by_path(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    manifest = report.get("artifact_manifest") if isinstance(report.get("artifact_manifest"), list) else []
    return {
        str(item.get("path")): item
        for item in manifest
        if isinstance(item, dict) and item.get("path")
    }


def artifact_manifest_by_group(report: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in artifact_manifest_by_path(report).values():
        grouped[str(item.get("artifact_group") or "unknown")].append(item)
    return grouped


def resolve_attestation_artifacts(item: dict[str, Any], manifest_report: dict[str, Any]) -> list[str]:
    refs = []
    refs.extend(as_str_list(item.get("reviewed_artifacts")))
    refs.extend(as_str_list(item.get("artifact_paths")))
    refs.extend(as_str_list(item.get("artifact_path")))
    refs.extend(as_str_list(item.get("artifact_ref")))
    by_group = artifact_manifest_by_group(manifest_report)
    for group_id in as_str_list(item.get("artifact_groups")):
        for artifact in by_group.get(group_id, []):
            refs.append(str(artifact.get("path")))
        if not by_group.get(group_id):
            refs.append(f"group:{group_id}")
    hashes = attestation_hashes(item, None)
    if not refs and hashes:
        refs.extend(f"hash:{digest}" for digest in sorted(hashes))
    return sorted(dict.fromkeys(refs)) or ["unknown_artifact"]


def attestation_hashes(item: dict[str, Any], artifact_ref: str | None) -> set[str]:
    hashes: set[str] = set()
    for key in ("artifact_hash", "artifact_digest", "digest", "expected_hash", "expected_digest", "sha256"):
        hashes.update(as_str_list(item.get(key)))
    value = item.get("artifact_hashes")
    if isinstance(value, dict):
        if artifact_ref and value.get(artifact_ref):
            hashes.update(as_str_list(value.get(artifact_ref)))
        else:
            for nested in value.values():
                hashes.update(as_str_list(nested))
    else:
        hashes.update(as_str_list(value))
    return {digest for digest in hashes if digest}


def current_artifact_hash(root: Path, artifact_ref: str, manifest_by_path: dict[str, dict[str, Any]]) -> str | None:
    if artifact_ref.startswith(("group:", "hash:", "unknown_")):
        return None
    manifest_digest = manifest_by_path.get(artifact_ref, {}).get("digest")
    if manifest_digest:
        return str(manifest_digest)
    candidate = root / artifact_ref
    return sha256_file(candidate)


def current_creator_for_artifact(artifact_ref: str, manifest_by_path: dict[str, dict[str, Any]]) -> str | None:
    artifact = manifest_by_path.get(artifact_ref) or {}
    return find_first(
        artifact.get("operator_id"),
        artifact.get("created_by_operator_id"),
        artifact.get("generated_by_operator_id"),
        artifact.get("created_by"),
        artifact.get("generated_by"),
    )


def raw_attestations(attestations_data: dict[str, Any], evidence_attestation: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    raw = [item for item in attestations_data.get("attestations") or [] if isinstance(item, dict)]
    if raw:
        return raw, "evidence_review_attestations"
    report_items = [
        item
        for item in evidence_attestation.get("reviewer_attestations") or []
        if isinstance(item, dict)
    ]
    return report_items, "evidence_attestation_report"


def resolve_project_path(root: Path, naos_root: str, policy: dict[str, Any], key: str) -> Path:
    return root / naos_root / str(policy.get("paths", {}).get(key) or key)


def input_source(
    name: str,
    path: Path | None,
    data: dict[str, Any],
    supported: bool = True,
    *,
    present_override: bool | None = None,
) -> dict[str, Any]:
    present = bool(path and path.exists()) if present_override is None else present_override
    status = "present" if present else "missing"
    if data.get("_invalid"):
        status = "invalid_input"
    return {
        "name": name,
        "path": str(path) if path else None,
        "present": present,
        "status": status,
        "supported": supported,
        "schema": data.get("schema"),
        "summary": data.get("summary") if isinstance(data.get("summary"), dict) else {},
    }


def route_material(*sources: Any) -> str:
    chunks: list[str] = []
    for source in sources:
        try:
            chunks.append(json.dumps(source, sort_keys=True, default=str).lower())
        except Exception:
            chunks.append(str(source).lower())
    return "\n".join(chunks)


def has_route(conflict: dict[str, Any], material: str) -> bool:
    if not material.strip():
        return False
    needles = [
        conflict.get("conflict_id"),
        conflict.get("conflict_type"),
        conflict.get("artifact_path"),
        conflict.get("artifact_ref"),
        *as_str_list(conflict.get("source_attestations")),
    ]
    return any(str(needle).lower() in material for needle in needles if needle)


def make_conflict(
    *,
    conflict_type: str,
    severity: str,
    artifact_ref: str,
    records: list[dict[str, Any]],
    route_status: str = "unknown",
    recommended_review_action: str | None = None,
) -> dict[str, Any]:
    source_ids = sorted({str(record.get("attestation_id")) for record in records if record.get("attestation_id")})
    artifact_hashes = sorted(
        {
            str(hash_value)
            for record in records
            for hash_value in as_str_list(record.get("artifact_hashes"))
        }
    )
    outcomes = sorted({str(record.get("review_outcome")) for record in records if record.get("review_outcome")})
    reviewers = sorted({str(record.get("reviewer")) for record in records if record.get("reviewer")})
    operators = sorted({str(record.get("operator")) for record in records if record.get("operator")})
    sessions = sorted({str(record.get("session_id")) for record in records if record.get("session_id")})
    tasks = sorted({task for record in records for task in as_str_list(record.get("related_tasks"))})
    capabilities = sorted({cap for record in records for cap in as_str_list(record.get("related_capabilities"))})
    source_reports = sorted({str(record.get("source_report")) for record in records if record.get("source_report")})
    conflict_id = safe_id(f"{conflict_type}:{artifact_ref}:{':'.join(source_ids) or 'records'}")
    return {
        "conflict_id": conflict_id,
        "conflict_type": conflict_type,
        "severity": severity,
        "artifact_ref": artifact_ref,
        "artifact_path": artifact_ref if not artifact_ref.startswith(("group:", "hash:", "unknown_")) else None,
        "artifact_hashes": artifact_hashes,
        "review_outcomes": outcomes,
        "reviewers": reviewers,
        "operators": operators,
        "sessions": sessions,
        "source_reports": source_reports,
        "source_attestations": source_ids,
        "related_tasks": tasks,
        "related_capabilities": capabilities,
        "route_status": route_status,
        "recommended_review_action": recommended_review_action
        or "Route this conflict to human review; do not treat the detector as adjudication.",
        "limitations": REPORT_LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": True,
    }


def finding_for_conflict(conflict: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"evidence_conflict.{conflict['conflict_type']}.{conflict['conflict_id']}",
        "severity": conflict.get("severity", "warning"),
        "status": "review_required",
        "message": f"Evidence conflict requires review: {conflict['conflict_type']} for {conflict.get('artifact_ref')}",
        "conflict_id": conflict.get("conflict_id"),
        "required_next_actions": [conflict.get("recommended_review_action")],
    }


def build_records(
    *,
    root: Path,
    attestations: list[dict[str, Any]],
    attestation_source: str,
    evidence_attestation: dict[str, Any],
    session_id: str | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    manifest_by_path = artifact_manifest_by_path(evidence_attestation)
    records: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    missing_reviewer: list[dict[str, Any]] = []
    missing_operator: list[dict[str, Any]] = []
    for index, item in enumerate(attestations, start=1):
        item_id = attestation_id(item, index)
        reviewer = reviewer_id(item)
        operator = find_first(item.get("operator_id"), item.get("reviewer_operator_id"), reviewer)
        outcome = normalize_outcome(item.get("review_outcome") or item.get("outcome") or item.get("status"))
        if not reviewer:
            missing_reviewer.append({"attestation_id": item_id, "reason": "reviewer metadata missing"})
        if not operator:
            missing_operator.append({"attestation_id": item_id, "reason": "operator attribution missing"})
        for artifact_ref in resolve_attestation_artifacts(item, evidence_attestation):
            expected_hashes = attestation_hashes(item, artifact_ref)
            current_hash = current_artifact_hash(root, artifact_ref, manifest_by_path)
            artifact_hashes = set(expected_hashes)
            if current_hash:
                artifact_hashes.add(current_hash)
            creator = creator_id(item) or current_creator_for_artifact(artifact_ref, manifest_by_path)
            record = {
                "attestation_id": item_id,
                "artifact_ref": artifact_ref,
                "review_outcome": outcome,
                "reviewer": reviewer,
                "operator": operator,
                "creator": creator,
                "session_id": item.get("session_id") or session_id,
                "artifact_hashes": sorted(artifact_hashes),
                "expected_hashes": sorted(expected_hashes),
                "current_hash": current_hash,
                "source_report": attestation_source,
                "related_tasks": as_str_list(item.get("related_tasks") or item.get("tasks")),
                "related_capabilities": as_str_list(item.get("related_capabilities") or item.get("capabilities")),
                "raw": item,
            }
            records.append(record)
            if expected_hashes and current_hash and current_hash not in expected_hashes:
                stale.append(record)
    return records, stale, missing_reviewer, missing_operator


def duplicate_records(records: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        key = (
            str(record.get("artifact_ref")),
            str(record.get("operator") or record.get("reviewer") or "unknown"),
            str(record.get("review_outcome")),
        )
        grouped[key].append(record)
    return [items for items in grouped.values() if len(items) > 1]


def build_findings_from_inputs(input_sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    if all(not source.get("present") for source in input_sources if source.get("name") in {"evidence_review_attestations", "evidence_attestation_report"}):
        findings.append(
            {
                "id": "evidence_conflicts.missing_evidence_inputs",
                "severity": "advisory",
                "status": "no_attestations",
                "message": "No evidence review attestation inputs were available.",
                "required_next_actions": ["Create reviewer attestations or run evidence attestation before relying on conflict detection."],
            }
        )
    for source in input_sources:
        if source.get("status") == "invalid_input":
            findings.append(
                {
                    "id": f"evidence_conflicts.invalid_input.{source['name']}",
                    "severity": "warning",
                    "status": "invalid_input",
                    "message": f"Input source could not be parsed: {source.get('name')}",
                    "required_next_actions": ["Fix the input JSON/YAML before relying on conflict detection."],
                }
            )
    return findings


def latest_session_id(root: Path, naos_root: str, policy: dict[str, Any]) -> str | None:
    index_path = sessions_index_path(root, naos_root, policy)
    data = load_json_mapping(index_path)
    value = data.get("latest_session_id")
    return str(value) if value else None


def audit_events(root: Path, naos_root: str, policy: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    audit_root = root / naos_root / str(policy.get("paths", {}).get("audit_log_root") or "audit_log")
    events = []
    files = []
    if not audit_root.exists():
        return events, files
    for path in sorted(audit_root.glob("*/*.jsonl")):
        files.append(str(path))
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                data = json.loads(line)
            except Exception:
                continue
            if isinstance(data, dict):
                events.append(data)
    return events, files


def build_report(
    *,
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    profile: str,
) -> dict[str, Any]:
    generated_at = utc_now_text()
    session_id = latest_session_id(root, naos_root, policy)
    operator = resolve_operator_attribution(root)
    operator_id = operator.get("operator_id")
    generated_by = build_generated_by(root, session_id=session_id, generated_at=generated_at)
    if operator_id and not generated_by.get("operator_id"):
        generated_by["operator_id"] = operator_id
        generated_by["operator_source"] = operator.get("operator_source")
        generated_by["operator_attribution_status"] = operator.get("operator_attribution_status")

    attestations_path = resolve_project_path(root, naos_root, policy, "evidence_review_attestations")
    evidence_attestation_path = report_default_path(root, naos_root, policy, "evidence_attestation_report")
    evidence_pack_path = evidence_pack_output_path(root, naos_root, policy)
    audit_summary_path = report_default_path(root, naos_root, policy, "audit_log_summary_report")
    operator_report_path = report_default_path(root, naos_root, policy, "operator_attribution_report")
    control_plane_items_path = resolve_project_path(root, naos_root, policy, "control_plane_review_items")
    session_index_path = sessions_index_path(root, naos_root, policy)

    attestations_data = load_yaml_mapping(attestations_path)
    evidence_attestation = load_json_mapping(evidence_attestation_path)
    evidence_pack = load_json_mapping(evidence_pack_path)
    audit_summary = load_json_mapping(audit_summary_path)
    operator_report = load_json_mapping(operator_report_path)
    control_plane_items = load_yaml_mapping(control_plane_items_path)
    session_index = load_json_mapping(session_index_path)
    events, event_files = audit_events(root, naos_root, policy)

    input_sources = [
        input_source("evidence_review_attestations", attestations_path, attestations_data, True),
        input_source("evidence_attestation_report", evidence_attestation_path, evidence_attestation, True),
        input_source("evidence_pack_report", evidence_pack_path, evidence_pack, False),
        input_source("audit_log_summary_report", audit_summary_path, audit_summary, True),
        input_source(
            "audit_log_events",
            None,
            {"summary": {"event_count": len(events), "event_files": len(event_files)}},
            True,
            present_override=bool(event_files),
        ),
        input_source("session_index", session_index_path, session_index, True),
        input_source("operator_attribution_report", operator_report_path, operator_report, True),
        input_source("control_plane_review_items", control_plane_items_path, control_plane_items, True),
    ]
    unsupported_sources = [source for source in input_sources if source.get("present") and not source.get("supported")]

    attestations, attestation_source = raw_attestations(attestations_data, evidence_attestation)
    secret_like_input_fields = []
    for index, item in enumerate(attestations, start=1):
        item_id = attestation_id(item, index)
        for field_path in secret_like_fields(item):
            secret_like_input_fields.append(
                {
                    "source": attestation_source,
                    "attestation_id": item_id,
                    "field": field_path,
                }
            )
    records, stale_records, missing_reviewer, missing_operator = build_records(
        root=root,
        attestations=attestations,
        attestation_source=attestation_source,
        evidence_attestation=evidence_attestation,
        session_id=session_id,
    )
    records_by_artifact: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        records_by_artifact[str(record.get("artifact_ref"))].append(record)

    route_text = route_material(
        control_plane_items.get("items") or [],
        control_plane_items.get("known_gaps") or [],
        control_plane_items.get("residual_risks") or [],
        control_plane_items.get("waivers") or [],
        evidence_attestation.get("known_gaps") or [],
        evidence_attestation.get("residual_risks") or [],
        evidence_attestation.get("waivers") or [],
        audit_summary.get("findings") or [],
    )
    conflicts: list[dict[str, Any]] = []
    for artifact_ref, group in sorted(records_by_artifact.items()):
        outcomes = {str(record.get("review_outcome")) for record in group if record.get("review_outcome")}
        reviewers = {str(record.get("reviewer") or record.get("operator")) for record in group if record.get("reviewer") or record.get("operator")}
        if len(outcomes - {"unknown"}) > 1:
            conflicts.append(
                make_conflict(
                    conflict_type="same_artifact_conflicting_review_outcome",
                    severity="warning",
                    artifact_ref=artifact_ref,
                    records=group,
                    recommended_review_action="Compare the structured attestations and decide the review disposition manually.",
                )
            )
        if len(reviewers) > 1 and len(outcomes - {"unknown"}) > 1:
            conflicts.append(
                make_conflict(
                    conflict_type="same_artifact_multiple_reviewers_disagree",
                    severity="warning",
                    artifact_ref=artifact_ref,
                    records=group,
                    recommended_review_action="Route reviewer disagreement to human governance review.",
                )
            )
        for record in group:
            if record.get("creator") and (record.get("creator") == record.get("operator") or record.get("creator") == record.get("reviewer")):
                conflicts.append(
                    make_conflict(
                        conflict_type="same_operator_reviews_own_artifact",
                        severity="advisory",
                        artifact_ref=artifact_ref,
                        records=[record],
                        recommended_review_action="Review potential separation-of-duties concern; this is not proof of a violation.",
                    )
                )
    for record in stale_records:
        conflicts.append(
            make_conflict(
                conflict_type="stale_attestation",
                severity="warning",
                artifact_ref=str(record.get("artifact_ref")),
                records=[record],
                recommended_review_action="Regenerate or re-review the artifact hash before relying on the attestation.",
            )
        )
    for record_group in duplicate_records(records):
        conflicts.append(
            make_conflict(
                conflict_type="duplicate_attestation",
                severity="advisory",
                artifact_ref=str(record_group[0].get("artifact_ref")),
                records=record_group,
                recommended_review_action="Review duplicate attestations and keep only meaningful reviewer metadata.",
            )
        )
    records_by_attestation = {str(record.get("attestation_id")): record for record in records}
    for item in missing_reviewer:
        record = records_by_attestation.get(str(item["attestation_id"]))
        conflicts.append(
            make_conflict(
                conflict_type="missing_reviewer_metadata",
                severity="advisory",
                artifact_ref=str(record.get("artifact_ref") if record else "unknown_artifact"),
                records=[record] if record else [{"attestation_id": item["attestation_id"], "source_report": attestation_source}],
                recommended_review_action="Add reviewer metadata or record the gap explicitly before relying on the attestation.",
            )
        )
    for item in missing_operator:
        record = records_by_attestation.get(str(item["attestation_id"]))
        conflicts.append(
            make_conflict(
                conflict_type="missing_operator_attribution",
                severity="advisory",
                artifact_ref=str(record.get("artifact_ref") if record else "unknown_artifact"),
                records=[record] if record else [{"attestation_id": item["attestation_id"], "source_report": attestation_source}],
                recommended_review_action="Add operator attribution metadata or record the gap explicitly before relying on the attestation.",
            )
        )

    for conflict in conflicts:
        conflict["route_status"] = "routed" if has_route(conflict, route_text) else "unrouted"

    unrouted_conflicts = [conflict for conflict in conflicts if conflict.get("route_status") == "unrouted"]
    findings = build_findings_from_inputs(input_sources)
    for conflict in conflicts:
        findings.append(finding_for_conflict(conflict))
    for item in missing_reviewer:
        findings.append(
            {
                "id": f"evidence_conflicts.missing_reviewer_metadata.{item['attestation_id']}",
                "severity": "advisory",
                "status": "review_required",
                "message": "Reviewer metadata is missing for an attestation.",
                "required_next_actions": ["Add reviewer metadata or record the gap explicitly."],
            }
        )
    for item in missing_operator:
        findings.append(
            {
                "id": f"evidence_conflicts.missing_operator_attribution.{item['attestation_id']}",
                "severity": "advisory",
                "status": "review_required",
                "message": "Operator attribution is missing for an attestation.",
                "required_next_actions": ["Add operator attribution metadata or record the gap explicitly."],
            }
        )
    for conflict in unrouted_conflicts:
        findings.append(
            {
                "id": f"evidence_conflicts.unrouted_conflict.{conflict['conflict_id']}",
                "severity": "advisory",
                "status": "review_required",
                "message": "A detected conflict does not have a structured route/gap/risk/waiver reference.",
                "conflict_id": conflict["conflict_id"],
                "required_next_actions": ["Add a control-plane review item, known gap, residual risk, or waiver reference."],
            }
        )
    for source in unsupported_sources:
        findings.append(
            {
                "id": f"evidence_conflicts.unsupported_source.{source['name']}",
                "severity": "advisory",
                "status": "advisory",
                "message": f"Input source is visible but not parsed for conflict semantics: {source['name']}",
                "required_next_actions": ["Use a supported structured source before expecting conflict detection coverage."],
            }
        )
    for item in secret_like_input_fields:
        findings.append(
            {
                "id": f"evidence_conflicts.secret_like_input.{item['attestation_id']}.{safe_id(item['field'], 'field')}",
                "severity": "warning",
                "status": "review_required",
                "message": "Secret-like field name found in evidence conflict input; value was not copied into the report.",
                "source": item["source"],
                "attestation_id": item["attestation_id"],
                "field": item["field"],
                "required_next_actions": ["Remove secrets and sensitive payloads from evidence inputs; reference safe artifacts by path/hash only."],
            }
        )

    conflict_type_counts = Counter(str(conflict.get("conflict_type")) for conflict in conflicts)
    if any(source.get("status") == "invalid_input" for source in input_sources):
        status = "invalid_input"
    elif not attestations:
        status = "no_attestations"
    elif conflicts and profile in {"standard", "assured"}:
        status = "review_required"
    elif conflicts:
        status = "conflicts_detected"
    elif findings:
        status = "advisory"
    else:
        status = "ready"

    missing_reviewer_ids = sorted({str(item["attestation_id"]) for item in missing_reviewer})
    missing_operator_ids = sorted({str(item["attestation_id"]) for item in missing_operator})
    report = {
        "schema": REPORT_SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "session_id": session_id,
        "operator_id": operator_id,
        "generated_by": generated_by,
        "input_sources": input_sources,
        "artifact_groups_reviewed": sorted({str(record.get("artifact_ref")) for record in records}),
        "attestation_count": len(attestations),
        "conflict_count": len(conflicts),
        "conflict_type_counts": dict(sorted(conflict_type_counts.items())),
        "separation_of_duties_warnings": [
            conflict for conflict in conflicts if conflict.get("conflict_type") == "same_operator_reviews_own_artifact"
        ],
        "stale_attestations": [conflict for conflict in conflicts if conflict.get("conflict_type") == "stale_attestation"],
        "missing_reviewer_metadata": missing_reviewer_ids,
        "missing_operator_attribution": missing_operator_ids,
        "duplicate_attestations": [conflict for conflict in conflicts if conflict.get("conflict_type") == "duplicate_attestation"],
        "unrouted_conflicts": unrouted_conflicts,
        "conflicts": conflicts,
        "unsupported_sources": unsupported_sources,
        "secret_like_input_fields": secret_like_input_fields,
        "findings": findings,
        "known_gaps": [
            "conflict_detection_is_not_resolution",
            "task_locking_deferred",
            "team_operator_policy_overlays_deferred",
            "separation_of_duties_approval_deferred",
        ],
        "residual_risks": RESIDUAL_RISKS,
        "limitations": REPORT_LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": bool(conflicts or findings or not attestations),
        "summary": {
            "status": status,
            "attestations": len(attestations),
            "conflicts": len(conflicts),
            "conflict_types": dict(sorted(conflict_type_counts.items())),
            "missing_reviewer_metadata": len(missing_reviewer_ids),
            "missing_operator_attribution": len(missing_operator_ids),
            "unrouted_conflicts": len(unrouted_conflicts),
            "unsupported_sources": len(unsupported_sources),
            "secret_like_input_fields": len(secret_like_input_fields),
            "human_review_required": bool(conflicts or findings or not attestations),
        },
    }
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Detect deterministic NAOS evidence conflicts.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true", help="Accepted for Makefile consistency; conflict detection remains review-oriented.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    report = build_report(root=root, naos_root=naos_root, policy=policy, profile=profile)
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "evidence_conflict_detection_report")
    session_output = None
    if report.get("session_id") and output is not None and not is_kit_repository(root, naos_root):
        session_output = session_report_default_path(
            root,
            naos_root,
            policy,
            str(report["session_id"]),
            "evidence_conflict_detection_report",
        )
    write_report_with_session(output, session_output, report)
    if session_output is not None and output is not None:
        record_session_report_reference(
            root,
            naos_root,
            policy,
            str(report["session_id"]),
            "evidence_conflict_detection_report",
            output,
            session_output,
        )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            "NAOS evidence conflicts: "
            f"{report['status']} "
            f"({report['conflict_count']} conflicts, "
            f"{report['attestation_count']} attestations, "
            f"output: {output if output else 'stdout only'})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
