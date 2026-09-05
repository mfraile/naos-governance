#!/usr/bin/env python3
"""Export a deterministic NAOS evidence pack from policy and validator outputs."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    default_naos_root,
    evidence_default_path,
    evidence_pack_output_path,
    evidence_staleness_days,
    exit_code_for_summary,
    external_reference_status,
    finding_counts,
    is_kit_repository,
    load_policy,
    normalize_profile,
    report_default_path,
    severity_for_profile,
    status_from_counts,
    test_map_output_path,
    write_report,
)


URL_RE = re.compile(r"https?://[^\s)'\"<>]+")

VALIDATOR_ARTIFACTS = {
    "validator_results",
    "claims_validation_report",
    "self_check_report",
    "capability_maturity_report",
    "systemic_impact_report",
    "module_header_traceability_report",
    "spec_pack_contract_report",
    "spec_cascade_report",
    "control_plane_review_report",
    "setup_recommendations_report",
    "governance_bypass_posture_report",
    "external_evidence_ingest_report",
    "evidence_attestation_report",
    "evidence_verification_report",
    "evidence_conflict_detection_report",
    "memory_context_readiness_report",
    "memory_provider_access_report",
    "memory_use_policy_report",
    "learning_loop_review_report",
    "failure_mode_observations_report",
    "adapter_coherence_report",
    "task_context_pack_report",
    "task_lifecycle_report",
    "research_record_report",
    "composed_traceability_report",
    "task_claim_report",
    "local_context_index_report",
    "sqlite_write_coordination_report",
    "local_context_query_report",
    "semantic_candidate_layer_report",
    "graph_context_readiness_report",
    "graph_context_query_report",
    "session_identity_report",
    "operator_attribution_report",
    "session_lifecycle_report",
    "audit_log_summary_report",
    "agent_trace_validation_report",
    "harness_trace_import_report",
    "ai_surface_context_budget_report",
    "static_grader_report",
    "grader_assessment_report",
    "llm_grader_readiness_report",
    "behavioral_governance_readiness_report",
    "policy_override_merge_report",
    "plan_coherence_report",
    "pr_risk_classification_report",
    "pr_governance_summary_report",
    "agentic_workflow_review_report",
    "pre_implementation_alignment_review_report",
    "calibration_shadow_report",
    "evidence_classification_report",
    "cross_harness_review_readiness_report",
    "adoption_summary_report",
    "preflight_report",
    "intake_report",
    "install_plan_report",
    "existing_resource_inventory_report",
    "ai_artifact_inventory_report",
    "ai_artifact_reconciliation_report",
    "ai_code_provenance_report",
    "compliance_posture_report",
    "memory_resource_inventory_report",
    "memory_resource_reconciliation_report",
    "mcp_resource_inventory_report",
    "brownfield_baseline_report",
    "candidate_requirements_report",
    "traceability_gap_register_report",
    "install_decision_record_report",
    "context_challenge_report",
    "repo_context_challenge_report",
    "plan_challenge_report",
    "decision_probe_report",
    "planning_gate_review_report",
    "roadmap_crosswalk_report",
    "function_index_report",
    "duplicate_function_hygiene_report",
    "secret_hygiene_report",
    "test_quality_hygiene_report",
    "dependency_integrity_report",
    "api_symbol_reality_report",
    "gate_status_report",
    "gate_evaluation_report",
    "test_evidence_map",
    "test_evidence_health_report",
    "ac_completion_evidence_report",
}


def utc_timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: str | None) -> datetime:
    raw = value or utc_timestamp()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        parsed = datetime.now(UTC)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def timestamp_text(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_structured_file(path: Path) -> tuple[Any, str]:
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8")
    if suffix == ".json":
        return json.loads(text), "json"
    if suffix in {".yaml", ".yml"}:
        return yaml.safe_load(text) or {}, "yaml"
    return text, "text"


def classify_reference(reference: Any, policy: dict[str, Any]) -> dict[str, Any]:
    default_status = external_reference_status(policy)
    if isinstance(reference, dict):
        url = reference.get("url") or reference.get("href") or reference.get("link")
        if url and str(url).startswith(("http://", "https://")):
            return {
                "url": str(url),
                "status": "verified" if reference.get("verified") is True else default_status,
                "verified": reference.get("verified") is True,
            }
    if isinstance(reference, str) and reference.startswith(("http://", "https://")):
        return {"url": reference, "status": default_status, "verified": False}
    return {"url": None, "status": "not_external_reference", "verified": False}


def collect_external_references(data: Any, policy: dict[str, Any], location: str = "$") -> list[dict[str, Any]]:
    references: list[dict[str, Any]] = []
    if isinstance(data, dict):
        classified = classify_reference(data, policy)
        if classified["url"]:
            references.append({**classified, "location": location})
        for key, value in data.items():
            references.extend(collect_external_references(value, policy, f"{location}.{key}"))
    elif isinstance(data, list):
        for index, item in enumerate(data):
            references.extend(collect_external_references(item, policy, f"{location}[{index}]"))
    elif isinstance(data, str):
        for match in URL_RE.finditer(data):
            classified = classify_reference(match.group(0), policy)
            references.append({**classified, "location": location})
    return references


def dedupe_references(references: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[tuple[str, str], dict[str, Any]] = {}
    for reference in references:
        key = (str(reference.get("url")), str(reference.get("status")))
        if key not in deduped:
            deduped[key] = reference
    return sorted(deduped.values(), key=lambda item: (str(item.get("url")), str(item.get("status"))))


def artifact_freshness(path: Path, generated_at: datetime, policy: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return {"status": "not_available"}
    modified = datetime.fromtimestamp(path.stat().st_mtime, UTC)
    age_days = max(0, (generated_at.date() - modified.date()).days)
    stale_after_days = evidence_staleness_days(policy)
    return {
        "modified_at": timestamp_text(modified),
        "age_days": age_days,
        "stale_after_days": stale_after_days,
        "status": "stale" if stale_after_days and age_days > stale_after_days else "fresh",
    }


def read_artifact(
    *,
    key: str,
    label: str,
    path: Path | None,
    required: bool,
    source: str,
    generated_at: datetime,
    policy: dict[str, Any],
    missing_status: str,
) -> dict[str, Any]:
    if path is None:
        return {
            "label": label,
            "path": None,
            "source": source,
            "required_for_pack": required,
            "exists": False,
            "status": "not_configured",
            "data": None,
            "freshness": {"status": "not_available"},
            "external_references": [],
        }
    if not path.exists():
        return {
            "label": label,
            "path": str(path),
            "source": source,
            "required_for_pack": required,
            "exists": False,
            "status": missing_status,
            "data": None,
            "freshness": {"status": "not_available"},
            "external_references": [],
        }
    try:
        data, file_format = load_structured_file(path)
    except Exception as exc:
        return {
            "label": label,
            "path": str(path),
            "source": source,
            "required_for_pack": required,
            "exists": True,
            "status": "parse_error",
            "format": "unknown",
            "error": str(exc),
            "data": None,
            "freshness": artifact_freshness(path, generated_at, policy),
            "external_references": [],
        }
    report_status = data.get("status") if isinstance(data, dict) else None
    return {
        "label": label,
        "path": str(path),
        "source": source,
        "required_for_pack": required,
        "exists": True,
        "status": "present",
        "format": file_format,
        "report_status": report_status,
        "data": data,
        "freshness": artifact_freshness(path, generated_at, policy),
        "external_references": dedupe_references(collect_external_references(data, policy)),
    }


def parse_inline_entries(values: list[str], kind: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for index, raw in enumerate(values, start=1):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"id": f"{kind}-{index}", "description": raw}
        if isinstance(parsed, dict):
            entries.append(parsed)
        else:
            entries.append({"id": f"{kind}-{index}", "description": parsed})
    return entries


def extract_list(data: Any, keys: list[str]) -> list[Any]:
    if not isinstance(data, dict):
        return []
    items: list[Any] = []
    for key in keys:
        value = data.get(key)
        if isinstance(value, list):
            items.extend(value)
        elif value:
            items.append(value)
    return items


def section_lists(artifacts: dict[str, dict[str, Any]], args: argparse.Namespace) -> dict[str, list[Any]]:
    certificate = artifacts.get("completion_certificate", {}).get("data")
    exceptions_data = artifacts.get("exceptions_waivers", {}).get("data")
    control_plane_review = artifacts.get("control_plane_review_report", {}).get("data")
    evidence_attestation = artifacts.get("evidence_attestation_report", {}).get("data")
    evidence_verification = artifacts.get("evidence_verification_report", {}).get("data")
    evidence_conflicts = artifacts.get("evidence_conflict_detection_report", {}).get("data")
    plan_coherence = artifacts.get("plan_coherence_report", {}).get("data")
    task_claims = artifacts.get("task_claim_report", {}).get("data")
    memory_context = artifacts.get("memory_context_readiness_report", {}).get("data")
    memory_provider_access = artifacts.get("memory_provider_access_report", {}).get("data")
    memory_use_policy = artifacts.get("memory_use_policy_report", {}).get("data")
    learning_loop = artifacts.get("learning_loop_review_report", {}).get("data")
    failure_mode_observations = artifacts.get("failure_mode_observations_report", {}).get("data")
    adapter_coherence = artifacts.get("adapter_coherence_report", {}).get("data")
    agent_trace_validation = artifacts.get("agent_trace_validation_report", {}).get("data")
    static_grader = artifacts.get("static_grader_report", {}).get("data")
    llm_grader_readiness = artifacts.get("llm_grader_readiness_report", {}).get("data")
    behavioral_readiness = artifacts.get("behavioral_governance_readiness_report", {}).get("data")
    spec_cascade = artifacts.get("spec_cascade_report", {}).get("data")
    return {
        "exceptions_waivers": [
            *extract_list(certificate, ["exceptions_or_waivers", "exceptions", "waivers"]),
            *extract_list(exceptions_data, ["exceptions_or_waivers", "exceptions", "waivers"]),
            *extract_list(control_plane_review, ["waivers"]),
            *extract_list(evidence_attestation, ["waivers"]),
            *extract_list(evidence_verification, ["waivers"]),
            *extract_list(evidence_conflicts, ["waivers"]),
            *extract_list(memory_context, ["waivers"]),
            *extract_list(memory_provider_access, ["waivers"]),
            *extract_list(memory_use_policy, ["waivers"]),
            *extract_list(learning_loop, ["waivers"]),
            *extract_list(failure_mode_observations, ["waivers"]),
            *extract_list(adapter_coherence, ["waivers"]),
            *extract_list(agent_trace_validation, ["waivers"]),
            *extract_list(static_grader, ["waivers"]),
            *extract_list(llm_grader_readiness, ["waivers"]),
            *extract_list(behavioral_readiness, ["waivers"]),
            *extract_list(spec_cascade, ["waivers"]),
            *parse_inline_entries(args.exception or [], "exception"),
        ],
        "known_gaps": [
            *extract_list(certificate, ["known_gaps"]),
            *extract_list(exceptions_data, ["known_gaps"]),
            *extract_list(control_plane_review, ["known_gaps"]),
            *extract_list(evidence_attestation, ["known_gaps"]),
            *extract_list(evidence_verification, ["known_gaps"]),
            *extract_list(evidence_conflicts, ["known_gaps"]),
            *extract_list(plan_coherence, ["known_gaps"]),
            *extract_list(task_claims, ["known_gaps"]),
            *extract_list(memory_context, ["known_gaps"]),
            *extract_list(memory_provider_access, ["known_gaps"]),
            *extract_list(memory_use_policy, ["known_gaps"]),
            *extract_list(learning_loop, ["known_gaps"]),
            *extract_list(failure_mode_observations, ["known_gaps"]),
            *extract_list(adapter_coherence, ["known_gaps"]),
            *extract_list(agent_trace_validation, ["known_gaps"]),
            *extract_list(static_grader, ["known_gaps"]),
            *extract_list(llm_grader_readiness, ["known_gaps"]),
            *extract_list(behavioral_readiness, ["known_gaps"]),
            *extract_list(spec_cascade, ["known_gaps"]),
            *parse_inline_entries(args.known_gap or [], "known_gap"),
        ],
        "residual_risks": [
            *extract_list(certificate, ["residual_risks", "residual_risk_notes"]),
            *extract_list(exceptions_data, ["residual_risks", "residual_risk_notes"]),
            *extract_list(control_plane_review, ["residual_risks"]),
            *extract_list(evidence_attestation, ["residual_risks"]),
            *extract_list(evidence_verification, ["residual_risks"]),
            *extract_list(evidence_conflicts, ["residual_risks"]),
            *extract_list(plan_coherence, ["residual_risks"]),
            *extract_list(task_claims, ["residual_risks"]),
            *extract_list(memory_context, ["residual_risks"]),
            *extract_list(memory_provider_access, ["residual_risks"]),
            *extract_list(memory_use_policy, ["residual_risks"]),
            *extract_list(learning_loop, ["residual_risks"]),
            *extract_list(failure_mode_observations, ["residual_risks"]),
            *extract_list(adapter_coherence, ["residual_risks"]),
            *extract_list(agent_trace_validation, ["residual_risks"]),
            *extract_list(static_grader, ["residual_risks"]),
            *extract_list(llm_grader_readiness, ["residual_risks"]),
            *extract_list(behavioral_readiness, ["residual_risks"]),
            *extract_list(spec_cascade, ["residual_risks"]),
            *parse_inline_entries(args.residual_risk or [], "residual_risk"),
        ],
    }


def summarize_evidence_attestation(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": summary,
        "digest_algorithm": data.get("digest_algorithm"),
        "artifact_digest_coverage": {
            "artifacts_hashed": summary.get("artifacts_hashed", 0),
            "missing_artifacts": summary.get("missing_artifacts", 0),
            "stale_artifacts": summary.get("stale_artifacts", 0),
            "uncovered_artifacts": summary.get("uncovered_artifacts", 0),
        },
        "reviewer_attestations": summary.get("reviewer_attestations", 0),
        "human_review_required": bool(data.get("human_review_required")),
        "waivers": data.get("waivers") or [],
        "known_gaps": data.get("known_gaps") or [],
        "residual_risks": data.get("residual_risks") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "circularity_note": (
            "If evidence_pack.json is hashed, its digest can represent the pack before "
            "this attestation report is embedded; NAOS does not claim a stable digest "
            "of the final self-containing evidence pack."
        ),
    }


def summarize_ac_completion_evidence(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    completions = data.get("completions") if isinstance(data.get("completions"), list) else []
    return {
        "status": data.get("status") or artifact.get("status"),
        "configured": bool(data.get("configured")),
        "summary": summary,
        "repository_bindings": [
            {
                "record_id": item.get("record_id"),
                "ac_id": item.get("ac_id"),
                "record_state": item.get("record_state"),
                "repository_binding": item.get("repository_binding") or {},
            }
            for item in completions
            if isinstance(item, dict) and (item.get("repository_binding") or {}).get("requested")
        ],
        "supersession": [
            {
                "record_id": item.get("record_id"),
                "ac_id": item.get("ac_id"),
                "record_state": item.get("record_state"),
                "supersedes": item.get("supersedes"),
                "superseded_by": item.get("superseded_by"),
                "correction_reason": item.get("correction_reason"),
            }
            for item in completions
            if isinstance(item, dict) and (item.get("supersedes") or item.get("superseded_by"))
        ],
        "findings": data.get("findings") or [],
        "known_gaps": data.get("known_gaps") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "human_review_required": bool(data.get("human_review_required", True)),
        "rule": (
            "AC completion evidence validates declared local evidence and, when explicitly configured, "
            "Git commit/tree binding, conservative path-shaped command operands, and preserved predecessor "
            "supersession for human review. It does not re-execute commands, prove clean or independent "
            "execution, sign evidence, authenticate identities, approve completion, or authorize release."
        ),
    }


def summarize_evidence_conflicts(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": summary,
        "conflict_count": data.get("conflict_count", 0),
        "conflict_type_counts": data.get("conflict_type_counts") or {},
        "separation_of_duties_warnings": data.get("separation_of_duties_warnings") or [],
        "stale_attestations": data.get("stale_attestations") or [],
        "missing_reviewer_metadata": data.get("missing_reviewer_metadata") or [],
        "missing_operator_attribution": data.get("missing_operator_attribution") or [],
        "duplicate_attestations": data.get("duplicate_attestations") or [],
        "unrouted_conflicts": data.get("unrouted_conflicts") or [],
        "findings": data.get("findings") or [],
        "known_gaps": data.get("known_gaps") or [],
        "residual_risks": data.get("residual_risks") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Evidence conflict detection flags deterministic review conflicts and metadata gaps; it does not resolve conflicts, adjudicate correctness, prove separation-of-duties status, approve work, or prove compliance.",
    }


def summarize_evidence_verification(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    raw_presence = data.get("signature_entries_present")
    legacy_signed = data.get("signed")
    signature_entries_present = (
        raw_presence
        if isinstance(raw_presence, bool)
        else legacy_signed if isinstance(legacy_signed, bool) else False
    )
    raw_validation_claim = data.get("signature_validation_performed")
    signature_validation_claim_rejected = (
        raw_validation_claim is not None and raw_validation_claim is not False
    )
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "tamper_evident": bool(data.get("tamper_evident")),
        "signed": legacy_signed is True,
        "signature_entries_present": signature_entries_present,
        "signature_validation_performed": False,
        "signature_validation_claim_rejected": signature_validation_claim_rejected,
        "artifacts_checked": data.get("artifacts_checked", 0),
        "identity_binding": data.get("identity_binding") or {},
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Evidence verification recomputes local artifact digests and the manifest root, then reports tamper-evidence, signature-entry presence, and best-effort Git HEAD metadata. It does not validate third-party signatures, authenticate identities, sign for NAOS, approve work, provide non-repudiation, certify controls, or prove compliance.",
    }


def summarize_task_claims(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "claim_count": data.get("claim_count", 0),
        "active_claim_count": data.get("active_claim_count", 0),
        "released_claim_count": data.get("released_claim_count", 0),
        "expired_claim_count": data.get("expired_claim_count", 0),
        "stale_claim_count": data.get("stale_claim_count", 0),
        "conflicting_claim_count": data.get("conflicting_claim_count", 0),
        "unknown_operator_claims": data.get("unknown_operator_claims") or [],
        "missing_session_claims": data.get("missing_session_claims") or [],
        "findings": data.get("findings") or [],
        "known_gaps": data.get("known_gaps") or [],
        "residual_risks": data.get("residual_risks") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Task claims coordinate who is working on a task; they are not authorization, approval, ownership proof, task completion, source of truth, or separation-of-duties evidence.",
    }


def summarize_spec_cascade_coherence(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "findings": data.get("findings") or [],
        "orphan_headers": data.get("orphan_headers") or [],
        "overloaded_frs": data.get("overloaded_frs") or [],
        "stale_statuses": data.get("stale_statuses") or [],
        "uncovered_requirements": data.get("uncovered_requirements") or [],
        "untraced_sources": data.get("untraced_sources") or [],
        "unresolved_source_references": data.get("unresolved_source_references") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Spec-cascade coherence records deterministic requirement/task/source traceability findings, including unresolved source spec references. It does not prove code correctness, complete traceability, runtime behavior, approval, certification, or compliance.",
    }


def summarize_spec_pack_contract(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "mode": data.get("mode"),
        "specs_root": data.get("specs_root"),
        "manifest": data.get("manifest"),
        "files": data.get("files") or [],
        "traceability_codes": data.get("traceability_codes") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Spec-pack contract conformance is deterministic template-structure, profile-applicability, and reference-resolution review evidence. It does not prove specification quality, approval, implementation, complete traceability, runtime behavior, certification, or compliance.",
    }


def summarize_spec_pack_materialization(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "dry_run": data.get("dry_run"),
        "force": data.get("force"),
        "source_specs_root": data.get("source_specs_root"),
        "target_specs_root": data.get("target_specs_root"),
        "files": data.get("files") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Spec-pack materialization copies or previews missing profile-required template files only. It does not fill, approve, validate, implement, test, certify, or prove specifications.",
    }


def summarize_spec_assembly_worksheet(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "specs_root": data.get("specs_root"),
        "manifest": data.get("manifest"),
        "specs": data.get("specs") or [],
        "candidate_mappings": data.get("candidate_mappings") or [],
        "gap_mappings": data.get("gap_mappings") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Spec assembly worksheets map adoption evidence and candidates to specs for review only. They do not promote candidates, fill specs, approve requirements, or prove complete traceability.",
    }


def summarize_memory_context_readiness(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": summary,
        "provider_posture": data.get("provider_posture") or {},
        "mcp_tool_access": data.get("mcp_tool_access") or {},
        "project_identity": data.get("project_identity") or {},
        "memory_authorization": data.get("memory_authorization") or {},
        "fallback_readiness": data.get("fallback_readiness") or {},
        "context_pack_readiness": data.get("context_pack_readiness") or {},
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Memory is advisory recall and continuity support. The evidence pack records memory-readiness posture but does not treat memory as evidence, approval, or source of truth.",
    }


def summarize_memory_provider_access(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "provider_declared": bool(data.get("provider_declared")),
        "provider_recommended": bool(data.get("provider_recommended")),
        "provider_name": data.get("provider_name"),
        "provider_name_source": data.get("provider_name_source"),
        "provider_configured": bool(data.get("provider_configured")),
        "provider_access_verified": bool(data.get("provider_access_verified")),
        "provider_access_method": data.get("provider_access_method"),
        "provider_binary_detected": bool(data.get("provider_binary_detected")),
        "provider_data_dir_source": data.get("provider_data_dir_source"),
        "provider_data_dir_exists": bool(data.get("provider_data_dir_exists")),
        "provider_database_exists": bool(data.get("provider_database_exists")),
        "mcp_config_files_detected": data.get("mcp_config_files_detected") or [],
        "mcp_servers_declared": data.get("mcp_servers_declared") or [],
        "mcp_access_verified": bool(data.get("mcp_access_verified")),
        "project_identity": data.get("project_identity") or {},
        "ci_memory_access": data.get("ci_memory_access") or {},
        "fallback_when_unavailable": data.get("fallback_when_unavailable") or {},
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Memory provider access reports distinguish declared/configured/access posture. They do not call memory tools, read payloads, grant MCP access, or treat memory access as evidence or approval.",
    }


def summarize_memory_use_policy(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "memory_trust_ladder": data.get("memory_trust_ladder") or [],
        "state_counts": data.get("state_counts") or {},
        "review_status_counts": data.get("review_status_counts") or {},
        "instruction_grade_items": data.get("instruction_grade_items") or [],
        "supporting_context_items": data.get("supporting_context_items") or [],
        "unsafe_instruction_grade_claims": data.get("unsafe_instruction_grade_claims") or [],
        "unsafe_supporting_context_claims": data.get("unsafe_supporting_context_claims") or [],
        "memory_access_prerequisites": data.get("memory_access_prerequisites") or {},
        "policy_item_access_posture": data.get("policy_item_access_posture") or [],
        "recall_trace_readiness": data.get("recall_trace_readiness") or {},
        "audit_event_readiness": data.get("audit_event_readiness") or {},
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Memory-use policy reports review metadata and joins current schema-validated readiness/provider posture without inventing live access. It does not read private payloads, write memory, execute recall traces, capture runtime audit events, approve memory use, or treat memory as evidence/source authority.",
    }


def summarize_learning_loop_review(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "status_counts": data.get("status_counts") or {},
        "type_counts": data.get("type_counts") or {},
        "retrieval_policy_counts": data.get("retrieval_policy_counts") or {},
        "active_learning_records": data.get("active_learning_records") or [],
        "high_authority_active_records": data.get("high_authority_active_records") or [],
        "inactive_learning_records": data.get("inactive_learning_records") or [],
        "redacted_learning_records": data.get("redacted_learning_records") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Governed learning lifecycle reports candidate, active, and historical learning metadata only. It does not write memory, mutate AI surfaces, approve work, prove semantic truth, or replace repository evidence.",
    }


def summarize_failure_mode_observations(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "enabled": bool(data.get("enabled")),
        "failure_mode_observations_declared": bool(data.get("failure_mode_observations_declared")),
        "summary": data.get("summary") or {},
        "mode_observation_counts": data.get("mode_observation_counts") or {},
        "family_observation_counts": data.get("family_observation_counts") or {},
        "source_report_counts": data.get("source_report_counts") or {},
        "observation_reason_code_counts": data.get("observation_reason_code_counts") or {},
        "severity_counts": data.get("severity_counts") or {},
        "related_gate_counts": data.get("related_gate_counts") or {},
        "mapping_basis_counts": data.get("mapping_basis_counts") or {},
        "review_opportunities": data.get("review_opportunities") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": (
            "Failure-mode observations aggregate local report findings into review statistics only. "
            "They do not create numeric risk score authority, automatic learning, approval, "
            "blocking, MCP/memory activation, provider/model routing, release authority, or compliance proof."
        ),
    }


def summarize_adapter_coherence(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "rules_source": data.get("rules_source"),
        "propagation_state_source": data.get("propagation_state_source"),
        "profile_posture": data.get("profile_posture") or {},
        "canonical_plugin": data.get("canonical_plugin") or {},
        "canonical_plugins": data.get("canonical_plugins") or [],
        "adapter_surfaces": data.get("adapter_surfaces") or [],
        "project_local_adapters": data.get("project_local_adapters") or [],
        "propagation_links": data.get("propagation_links") or [],
        "propagation_reviews": data.get("propagation_reviews") or [],
        "findings": data.get("findings") or [],
        "known_gaps": data.get("known_gaps") or [],
        "residual_risks": data.get("residual_risks") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_task_context_pack(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "task_id": data.get("task_id"),
        "summary": summary,
        "source_artifacts_missing": data.get("source_artifacts_missing") or [],
        "source_artifact_freshness": data.get("source_artifact_freshness") or {},
        "memory_context": data.get("memory_context") or {},
        "human_review_required": bool((data.get("human_review_boundary") or {}).get("required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Task context packs are derived, bounded context for one task. They are not source of truth, evidence authority, approval, or automatic context injection.",
    }


def summarize_native_lifecycle_report(artifact: dict[str, Any], boundary: str) -> dict[str, Any]:
    data = artifact.get("data") or {}
    report = {
        "status": artifact.get("report_status") or artifact.get("status"),
        "task_id": data.get("task_id"),
        "action": data.get("action"),
        "lifecycle_state": data.get("lifecycle_state"),
        "delivery_state": data.get("delivery_state"),
        "requested_verification_state": data.get("requested_verification_state"),
        "effective_verification_state": data.get("effective_verification_state"),
        "verification_prerequisites_met": data.get("verification_prerequisites_met"),
        "completion_verification": data.get("completion_verification") or {},
        "summary": data.get("summary") or {},
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "review_reasons": data.get("review_reasons") or [],
        "review_posture_source": data.get("review_posture_source"),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": boundary,
    }
    for review_key in ("canonical_task_review", "traceability_review"):
        if isinstance(data.get(review_key), dict):
            report[review_key] = data[review_key]
    return report


def summarize_local_context_index(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": summary,
        "sqlite_artifact": data.get("sqlite_artifact") or {},
        "sqlite_write_coordination": data.get("sqlite_write_coordination") or {},
        "fts_available": bool(data.get("fts_available")),
        "artifact_type_counts": data.get("artifact_type_counts") or {},
        "authority_level_counts": data.get("authority_level_counts") or {},
        "query_modes_supported": data.get("query_modes_supported") or {},
        "memory_policy": data.get("memory_policy") or {},
        "future_semantic_layer": data.get("future_semantic_layer") or {},
        "future_graph_layer": data.get("future_graph_layer") or {},
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Local context indexes are generated, derived, cache-like retrieval substrates. The evidence pack records index posture but does not treat retrieval candidates as authority or source artifacts.",
    }


def summarize_sqlite_write_coordination(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "target_db_path": data.get("target_db_path"),
        "lock_path": data.get("lock_path"),
        "lock_acquired": bool(data.get("lock_acquired")),
        "atomic_replace_used": bool(data.get("atomic_replace_used")),
        "tables_verified": data.get("tables_verified") or [],
        "target_db_hash": data.get("target_db_hash"),
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "SQLite write coordination is deterministic infrastructure evidence for local index file integrity; it is not task locking, evidence conflict detection, append-only audit logging, distributed locking, or full multi-user completion.",
    }


def summarize_audit_log(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "event_count": data.get("event_count", 0),
        "event_type_counts": data.get("event_type_counts") or {},
        "missing_session_id_events": data.get("missing_session_id_events") or [],
        "missing_operator_id_events": data.get("missing_operator_id_events") or [],
        "invalid_event_count": data.get("invalid_event_count", 0),
        "audit_logged_sources": data.get("audit_logged_sources") or [],
        "audit_pending_sources": data.get("audit_pending_sources") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "The audit log is historical event evidence only; it is not approval, non-repudiation, tamper-proof storage, task locking, or evidence conflict detection.",
    }


def summarize_local_context_query(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "query": data.get("query") or {},
        "query_mode_used": data.get("query_mode_used") or [],
        "result_count": data.get("result_count", 0),
        "source_artifacts": data.get("source_artifacts") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Local context query results are bounded candidate references. The evidence pack records query posture but does not treat candidates as answers, authority, or source artifacts.",
    }


def summarize_semantic_candidate_layer(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "semantic_runtime_enabled": bool(data.get("semantic_runtime_enabled")),
        "sqlite_vec_enabled": bool(data.get("sqlite_vec_enabled")),
        "embeddings_enabled": bool(data.get("embeddings_enabled")),
        "extension_loading_allowed": bool(data.get("extension_loading_allowed")),
        "external_embedding_calls_allowed": bool(data.get("external_embedding_calls_allowed")),
        "cloud_embedding_allowed": bool(data.get("cloud_embedding_allowed")),
        "candidate_only_policy": data.get("candidate_only_policy") or {},
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Semantic candidate readiness is reporting only. It does not enable vector runtime, embeddings, sqlite-vec, extension loading, memory search, or source authority.",
    }


def summarize_graph_context_readiness(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "graph_runtime_enabled": bool(data.get("graph_runtime_enabled")),
        "explicit_link_traversal_only": bool(data.get("explicit_link_traversal_only", True)),
        "global_graph_scan_allowed": bool(data.get("global_graph_scan_allowed")),
        "graph_database_allowed": bool(data.get("graph_database_allowed")),
        "networkx_enabled": bool(data.get("networkx_enabled")),
        "graphml_enabled": bool(data.get("graphml_enabled")),
        "graph_algorithms_enabled": bool(data.get("graph_algorithms_enabled")),
        "traversal_limits": data.get("traversal_limits") or {},
        "source_authority_policy": data.get("source_authority_policy") or {},
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Graph context readiness is reporting only. It does not enable graph runtime, NetworkX, GraphML, graph databases, graph algorithms, global traversal, memory graphing, or source authority.",
    }


def summarize_graph_context_query(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "query": data.get("query") or {},
        "query_mode_used": data.get("query_mode_used") or [],
        "traversal_depth_used": data.get("traversal_depth_used"),
        "result_count": data.get("result_count", 0),
        "source_artifacts": data.get("source_artifacts") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Graph context query reports are bounded relationship-candidate references. The evidence pack records query posture but does not treat graph candidates as truth, implementation proof, or source authority.",
    }


def summarize_session_lifecycle(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "mode": data.get("mode"),
        "task_id": data.get("task_id"),
        "summary": data.get("summary") or {},
        "freshness_summary": data.get("freshness_summary") or {},
        "context_posture": data.get("context_posture") or {},
        "memory_posture": data.get("memory_posture") or {},
        "memory_candidate_proposals": data.get("memory_candidate_proposals") or [],
        "recommended_commands": data.get("recommended_commands") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Session lifecycle reports are bounded start/checkpoint/end review aids. The evidence pack records lifecycle posture but does not treat it as proof, approval, evidence authority, task completion, automatic context injection, or memory write-back.",
    }


def summarize_session_identity(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "session_id": data.get("session_id"),
        "session_report_root": data.get("session_report_root"),
        "sessions_index_path": data.get("sessions_index_path"),
        "latest_report_compatibility": data.get("latest_report_compatibility") or {},
        "session_aware_reports": data.get("session_aware_reports") or [],
        "latest_only_reports": data.get("latest_only_reports") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Session identity reports describe namespaced report paths, latest-report compatibility, and local operator attribution signals. They do not prove identity, authenticate, authorize, lock tasks, create audit logs, detect evidence conflicts, or establish source-of-truth authority.",
    }


def summarize_operator_attribution(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "operator_id": data.get("operator_id"),
        "operator_source": data.get("operator_source"),
        "operator_attribution_status": data.get("operator_attribution_status"),
        "session_id": data.get("session_id"),
        "privacy_posture": data.get("privacy_posture") or {},
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Operator attribution records local identity signals for who initiated a run; it is not authentication, authorization, task ownership, task locking, separation-of-duties evidence, non-repudiation, approval, or an audit log.",
    }


def summarize_agent_trace_validation(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "event_count": data.get("event_count", 0),
        "valid_event_count": data.get("valid_event_count", 0),
        "invalid_event_count": data.get("invalid_event_count", 0),
        "lifecycle_phase_counts": data.get("lifecycle_phase_counts") or {},
        "action_type_counts": data.get("action_type_counts") or {},
        "forbidden_payload_findings": data.get("forbidden_payload_findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Agent trace validation reports declared records and optional action-receipt metadata only. The evidence pack records trace posture but does not treat trace events or receipts as proof, approval, runtime capture, permission enforcement, tool-call interception, memory writes, legal/compliance/regulatory assurance, or behavioral safety evidence.",
    }


def summarize_harness_trace_import(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "mode": data.get("mode"),
        "source_format": data.get("source_format"),
        "source_present": bool(data.get("source_present")),
        "write_events": bool(data.get("write_events")),
        "events_written": bool(data.get("events_written")),
        "raw_record_count": data.get("raw_record_count", 0),
        "imported_event_count": data.get("imported_event_count", 0),
        "rejected_record_count": data.get("rejected_record_count", 0),
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Harness trace import normalizes explicit local JSONL/NDJSON records into declared trace-event shape. It does not execute harnesses, capture runtime events, call providers, write memory, approve work, or prove behavior.",
    }


def summarize_static_grader(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "dimension_summary": data.get("dimension_summary") or {},
        "cost_posture": data.get("cost_posture") or {},
        "budget_posture": data.get("budget_posture") or {},
        "not_evaluated_dimensions": data.get("not_evaluated_dimensions") or [],
        "deterministic": bool(data.get("deterministic")),
        "advisory": bool(data.get("advisory")),
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "StaticGrader is deterministic structural grading only. The evidence pack records its findings as review inputs, not behavioral safety proof, semantic correctness, approval, maturity promotion, or legal/regulatory assurance.",
    }


def summarize_grader_assessment(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "mode": data.get("mode"),
        "summary": data.get("summary") or {},
        "drift": data.get("drift") or {},
        "cost_budget_posture": data.get("cost_budget_posture") or {},
        "cadence_posture": data.get("cadence_posture") or {},
        "llm_readiness": data.get("llm_readiness") or {},
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Grader assessment audit/drift/assess modes are deterministic review inputs, not audit approval, certification, compliance determination, semantic drift inference, attestation, or maturity promotion.",
    }


def summarize_llm_grader_readiness(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "runtime_enabled": bool(data.get("runtime_enabled")),
        "provider_allowed": bool(data.get("provider_allowed")),
        "external_api_allowed": bool(data.get("external_api_allowed")),
        "model_dependency_allowed": bool(data.get("model_dependency_allowed")),
        "api_keys_allowed": bool(data.get("api_keys_allowed")),
        "cost_posture": data.get("cost_posture") or {},
        "data_exposure_posture": data.get("data_exposure_posture") or {},
        "bias_variance_posture": data.get("bias_variance_posture") or {},
        "advisory_boundary": data.get("advisory_boundary") or {},
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "LLMGrader readiness is governance metadata only. The evidence pack records cost, data, bias, drift, and advisory-boundary posture without enabling runtime grading, provider calls, approval, certification, compliance determination, or maturity promotion.",
    }


def summarize_behavioral_governance_readiness(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "baseline_state_present": bool(data.get("baseline_state_present")),
        "readiness_inputs": data.get("readiness_inputs") or [],
        "impacter_review": data.get("impacter_review") or {},
        "cost_posture": data.get("cost_posture") or {},
        "runtime_posture": data.get("runtime_posture") or {},
        "advisory_boundary": data.get("advisory_boundary") or {},
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Behavioral Governance Readiness is deterministic review metadata only. The evidence pack records first-baseline readiness and baseline impacter posture without behavioral grading, model/provider/API calls, automatic baseline creation, approval, certification, compliance determination, publication/release authority, or maturity promotion.",
    }


def summarize_plan_coherence(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "implementation_readiness": data.get("implementation_readiness") or {},
        "findings": data.get("findings") or [],
        "diff_base": data.get("diff_base"),
        "changed_files": data.get("changed_files") or [],
        "planned_change_paths": data.get("planned_change_paths") or [],
        "out_of_scope_paths": data.get("out_of_scope_paths") or [],
        "unplanned_changed_files": data.get("unplanned_changed_files") or [],
        "out_of_scope_changed_files": data.get("out_of_scope_changed_files") or [],
        "known_gaps": data.get("known_gaps") or [],
        "residual_risks": data.get("residual_risks") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Plan coherence reviews active task claims, task registry dependencies, module-header task linkage, versioned implementation-readiness inputs, and optional diff-base implementation-scope path evidence as deterministic coordination evidence. It does not authorize work, sequence execution, resolve conflicts, prove ownership, prove completion, prove semantic drift, approve implementation, close tasks, merge, or release.",
    }


def summarize_ai_code_provenance(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "manifest": data.get("manifest") or {},
        "supporting_evidence": data.get("supporting_evidence") or [],
        "ai_artifact_evidence": data.get("ai_artifact_evidence") or {},
        "missing_evidence": data.get("missing_evidence") or [],
        "unresolved_questions": data.get("unresolved_questions") or [],
        "authority_boundary": data.get("authority_boundary") or {},
        "runtime_posture": data.get("runtime_posture") or {},
        "cost_posture": data.get("cost_posture") or {},
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "AI code provenance evidence is review packaging only. The evidence pack records local declarations, AI artifact evidence, missing evidence, and unresolved questions without legal opinion, authorship proof, ownership proof, infringement clearance, proof of copyright compliance, AI-output detection, line-level attribution, signing, provider/API/model calls, publication authority, release authority, approval, certification, or proof of compliance.",
    }


def summarize_compliance_posture(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "manifest": data.get("manifest") or {},
        "supporting_evidence": data.get("supporting_evidence") or [],
        "supporting_report_statuses": data.get("supporting_report_statuses") or {},
        "missing_evidence": data.get("missing_evidence") or [],
        "unresolved_questions": data.get("unresolved_questions") or [],
        "authority_boundary": data.get("authority_boundary") or {},
        "runtime_posture": data.get("runtime_posture") or {},
        "cost_posture": data.get("cost_posture") or {},
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Compliance posture evidence is adopter-declared review metadata only. The evidence pack records declared contexts, supporting evidence references, missing evidence, and unresolved questions without legal advice, regulatory applicability decisions, compliance pass/fail, certification, conformity assessment, audit opinion, approval, signing, release/publication authority, or proof of compliance.",
    }


def summarize_policy_overrides(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "override_summary": data.get("override_summary") or {},
        "team_operator_map": data.get("team_operator_map") or {},
        "overlay_scope": data.get("overlay_scope") or {},
        "overlay_scopes": data.get("overlay_scopes") or [],
        "applied_overlay_scopes": data.get("applied_overlay_scopes") or [],
        "team_ids": data.get("team_ids") or [],
        "operator_overlay_id": data.get("operator_overlay_id"),
        "protected_invariant_violations": data.get("protected_invariant_violations") or [],
        "conflicts": data.get("conflicts") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Policy override reports are static YAML customization posture. The evidence pack records global/team/operator overlay scope as review metadata only; overlays cannot weaken protected invariants, approve policy changes, authenticate or authorize operators, or enable plugin/runtime behavior.",
    }


def summarize_pr_governance(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "ci_provider": data.get("ci_provider"),
        "event_name": data.get("event_name"),
        "pull_request_number": data.get("pull_request_number"),
        "team_id": data.get("team_id"),
        "team_resolution_source": data.get("team_resolution_source"),
        "reports_generated": data.get("reports_generated") or [],
        "artifact_paths": data.get("artifact_paths") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "PR governance summaries package CI evidence and review signals only. They do not approve pull requests, authorize deployment or release, prove compliance, satisfy separation of duties, or resolve evidence conflicts.",
    }


def summarize_pr_risk_classification(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    contributor = data.get("contributor") if isinstance(data.get("contributor"), dict) else {}
    git = data.get("git") if isinstance(data.get("git"), dict) else {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": summary,
        "contributor": {
            "trust": contributor.get("trust"),
            "source": contributor.get("source"),
            "fork": contributor.get("fork"),
        },
        "git": {
            "branch": git.get("branch"),
            "base_ref": git.get("base_ref"),
            "head_ref": git.get("head_ref"),
            "diff_source": (git.get("diff_metadata") or {}).get("diff_source"),
        },
        "changed_files": len(data.get("changed_files") or []),
        "risk_files": summary.get("risk_files", 0),
        "total_findings": summary.get("total_findings", 0),
        "category_counts": summary.get("category_counts") or {},
        "findings": data.get("findings") or [],
        "known_gaps": data.get("known_gaps") or [],
        "residual_risks": data.get("residual_risks") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "PR risk classification is deterministic path/diff metadata review evidence. It does not approve pull requests, execute sandboxes, perform malware analysis, prove security, prove compliance, authorize release/deployment, or replace human review.",
    }


def summarize_agentic_workflow(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "workflow_config_valid": bool(data.get("workflow_config_valid")),
        "missing_artifacts": data.get("missing_artifacts") or [],
        "sections": data.get("sections") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Agentic workflow review records declared operating practices only; it does not prove assistant behavior, requirements completeness, design approval, implementation approval, or compliance.",
    }


def summarize_pre_implementation_alignment(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "mode": data.get("mode"),
        "alignment_valid": bool(data.get("alignment_valid")),
        "question_coverage": data.get("question_coverage") or {},
        "missing_required_questions": data.get("missing_required_questions") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Pre-Implementation Alignment is review input only; it does not approve design or implementation, prove requirements completeness, prove compliance, or replace human review.",
    }


def summarize_calibration_shadow(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "calibration_config_valid": bool(data.get("calibration_config_valid")),
        "drift_count": int(data.get("drift_count") or 0),
        "reports_missing": data.get("reports_missing") or [],
        "unexpected_changes": data.get("unexpected_changes") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Calibration shadow compares deterministic report metadata only; it is not model calibration, behavior proof, semantic correctness proof, release approval, or compliance proof.",
    }


def summarize_evidence_classification(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "policy_valid": bool(data.get("policy_valid")),
        "findings_scanned": int(data.get("findings_scanned") or 0),
        "classification_counts": data.get("classification_counts") or {},
        "missing_classification": data.get("missing_classification") or [],
        "unknown_findings": data.get("unknown_findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Evidence classification records finding provenance categories only; it is not truth proof, legal conclusion, approval, issue resolution, certification, or compliance proof.",
    }


def summarize_cross_harness_review_readiness(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "config_valid": bool(data.get("config_valid")),
        "declared_harness_count": int(data.get("declared_harness_count") or 0),
        "readiness_score": int(data.get("readiness_score") or 0),
        "requirements_missing": data.get("requirements_missing") or [],
        "requirements_deferred": data.get("requirements_deferred") or [],
        "runtime_execution_enabled": bool(data.get("runtime_execution_enabled")),
        "provider_api_allowed": bool(data.get("provider_api_allowed")),
        "dsse_readiness": data.get("dsse_readiness") or {},
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Cross-harness review readiness records future governance prerequisites only; it does not execute harnesses, sign artifacts, verify signatures, custody keys, create attestations, approve work, or prove compliance.",
    }


def summarize_professional_adoption(artifacts: dict[str, dict[str, Any]]) -> dict[str, Any]:
    keys = [
        "adoption_summary_report",
        "preflight_report",
        "intake_report",
        "install_plan_report",
        "existing_resource_inventory_report",
        "ai_artifact_inventory_report",
        "ai_artifact_reconciliation_report",
        "memory_resource_inventory_report",
        "memory_resource_reconciliation_report",
        "mcp_resource_inventory_report",
        "brownfield_baseline_report",
        "candidate_requirements_report",
        "traceability_gap_register_report",
        "install_decision_record_report",
        "context_challenge_report",
        "repo_context_challenge_report",
        "plan_challenge_report",
        "decision_probe_report",
        "planning_gate_review_report",
    ]
    statuses: dict[str, Any] = {}
    present = 0
    review_required = 0
    for key in keys:
        artifact = artifacts.get(key, {})
        data = artifact.get("data") if isinstance(artifact, dict) else {}
        if not isinstance(data, dict):
            data = {}
        statuses[key] = data.get("status") or artifact.get("status")
        present += 1 if artifact.get("exists") else 0
        review_required += 1 if data.get("human_review_required") else 0
    return {
        "status": "present" if present else "missing",
        "reports_expected": len(keys),
        "reports_present": present,
        "reports_review_required": review_required,
        "report_statuses": statuses,
        "rule": "Professional adoption evidence is review support only; it does not silently overwrite files, enable providers, write memory, approve work, or prove legal or regulatory compliance.",
    }


def summarize_deterministic_hygiene(artifacts: dict[str, dict[str, Any]]) -> dict[str, Any]:
    keys = [
        "duplicate_function_hygiene_report",
        "secret_hygiene_report",
        "test_quality_hygiene_report",
        "dependency_integrity_report",
        "package_reality_report",
        "api_symbol_reality_report",
    ]
    statuses: dict[str, Any] = {}
    summaries: dict[str, Any] = {}
    present = 0
    total_findings = 0
    for key in keys:
        artifact = artifacts.get(key, {})
        data = artifact.get("data") if isinstance(artifact, dict) else {}
        if not isinstance(data, dict):
            data = {}
        statuses[key] = data.get("status") or artifact.get("status")
        summaries[key] = data.get("summary") or {}
        present += 1 if artifact.get("exists") else 0
        total_findings += int((data.get("summary") or {}).get("total_findings") or 0)
    return {
        "status": "present" if present else "missing",
        "reports_expected": len(keys),
        "reports_present": present,
        "total_findings": total_findings,
        "report_statuses": statuses,
        "summaries": summaries,
        "rule": "Deterministic hygiene reports reduce obvious duplicate, secret, weak-test, undeclared-import, package-reality, and declared API-symbol risk classes. Package-reality can include configured local SBOM, provenance, and hash evidence, but these reports do not prove semantic correctness, secret-free code, behavioral correctness, API behavior, package safety, vulnerability absence, SBOM completeness, provenance authenticity, supply-chain assurance, approval, or compliance.",
    }


def artifact_finding_severity(root: Path, naos_root: str, profile: str, policy: dict[str, Any]) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    return severity_for_profile(profile, policy)


def build_findings(
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    references: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    severity = artifact_finding_severity(root, naos_root, profile, policy)
    findings: list[dict[str, Any]] = []
    for key, artifact in artifacts.items():
        if artifact.get("required_for_pack") and artifact.get("status") in {"missing", "parse_error"}:
            findings.append(
                {
                    "id": key,
                    "severity": severity,
                    "status": artifact["status"],
                    "message": f"Expected evidence artifact is not usable: {artifact.get('path')}",
                }
            )
        freshness = artifact.get("freshness") or {}
        if artifact.get("exists") and freshness.get("status") == "stale":
            findings.append(
                {
                    "id": key,
                    "severity": "warning" if severity == "advisory" else severity,
                    "status": "stale_evidence",
                    "message": f"Evidence artifact is older than the configured freshness threshold: {artifact.get('path')}",
                }
            )
    for reference in references:
        if reference.get("status") == external_reference_status(policy):
            findings.append(
                {
                    "id": "external_reference",
                    "severity": "advisory",
                    "status": "external_reference_unverified",
                    "message": f"External reference is not verified evidence by default: {reference.get('url')}",
                }
            )
    return findings


def default_artifact_paths(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Path | None]:
    return {
        "task_path": evidence_default_path(root, naos_root, policy, "task_path_report"),
        "context_manifest": evidence_default_path(root, naos_root, policy, "context_manifest_report"),
        "validator_results": report_default_path(root, naos_root, policy, "validator_results_report"),
        "claims_validation_report": report_default_path(root, naos_root, policy, "claims_report"),
        "self_check_report": report_default_path(root, naos_root, policy, "self_check_report"),
        "capability_maturity_report": report_default_path(root, naos_root, policy, "capability_maturity_report"),
        "systemic_impact_report": report_default_path(root, naos_root, policy, "systemic_impact_report"),
        "module_header_traceability_report": report_default_path(root, naos_root, policy, "module_header_traceability_report"),
        "spec_pack_contract_report": report_default_path(root, naos_root, policy, "spec_pack_contract_report"),
        "spec_pack_materialization_report": report_default_path(root, naos_root, policy, "spec_pack_materialization_report"),
        "spec_assembly_worksheet_report": report_default_path(root, naos_root, policy, "spec_assembly_worksheet_report"),
        "spec_cascade_report": report_default_path(root, naos_root, policy, "spec_cascade_report"),
        "control_plane_review_report": report_default_path(root, naos_root, policy, "control_plane_review_report"),
        "setup_recommendations_report": report_default_path(root, naos_root, policy, "setup_recommendations_report"),
        "governance_bypass_posture_report": report_default_path(root, naos_root, policy, "governance_bypass_posture_report"),
        "external_evidence_ingest_report": report_default_path(root, naos_root, policy, "external_evidence_ingest_report"),
        "evidence_attestation_report": report_default_path(root, naos_root, policy, "evidence_attestation_report"),
        "evidence_verification_report": report_default_path(root, naos_root, policy, "evidence_verification_report"),
        "evidence_conflict_detection_report": report_default_path(root, naos_root, policy, "evidence_conflict_detection_report"),
        "memory_context_readiness_report": report_default_path(root, naos_root, policy, "memory_context_readiness_report"),
        "memory_provider_access_report": report_default_path(root, naos_root, policy, "memory_provider_access_report"),
        "memory_use_policy_report": report_default_path(root, naos_root, policy, "memory_use_policy_report"),
        "learning_loop_review_report": report_default_path(root, naos_root, policy, "learning_loop_review_report"),
        "failure_mode_observations_report": report_default_path(root, naos_root, policy, "failure_mode_observations_report"),
        "adapter_coherence_report": report_default_path(root, naos_root, policy, "adapter_coherence_report"),
        "task_context_pack_report": report_default_path(root, naos_root, policy, "task_context_pack_report"),
        "task_lifecycle_report": report_default_path(root, naos_root, policy, "task_lifecycle_report"),
        "research_record_report": report_default_path(root, naos_root, policy, "research_record_report"),
        "composed_traceability_report": report_default_path(root, naos_root, policy, "composed_traceability_report"),
        "task_claim_report": report_default_path(root, naos_root, policy, "task_claim_report"),
        "local_context_index_report": report_default_path(root, naos_root, policy, "local_context_index_report"),
        "sqlite_write_coordination_report": report_default_path(root, naos_root, policy, "sqlite_write_coordination_report"),
        "local_context_query_report": report_default_path(root, naos_root, policy, "local_context_query_report"),
        "semantic_candidate_layer_report": report_default_path(root, naos_root, policy, "semantic_candidate_layer_report"),
        "graph_context_readiness_report": report_default_path(root, naos_root, policy, "graph_context_readiness_report"),
        "graph_context_query_report": report_default_path(root, naos_root, policy, "graph_context_query_report"),
        "session_identity_report": report_default_path(root, naos_root, policy, "session_identity_report"),
        "operator_attribution_report": report_default_path(root, naos_root, policy, "operator_attribution_report"),
        "session_lifecycle_report": report_default_path(root, naos_root, policy, "session_lifecycle_report"),
        "audit_log_summary_report": report_default_path(root, naos_root, policy, "audit_log_summary_report"),
        "agent_trace_validation_report": report_default_path(root, naos_root, policy, "agent_trace_validation_report"),
        "harness_trace_import_report": report_default_path(root, naos_root, policy, "harness_trace_import_report"),
        "ai_surface_context_budget_report": report_default_path(root, naos_root, policy, "ai_surface_context_budget_report"),
        "static_grader_report": report_default_path(root, naos_root, policy, "static_grader_report"),
        "grader_assessment_report": report_default_path(root, naos_root, policy, "grader_assessment_report"),
        "llm_grader_readiness_report": report_default_path(root, naos_root, policy, "llm_grader_readiness_report"),
        "behavioral_governance_readiness_report": report_default_path(root, naos_root, policy, "behavioral_governance_readiness_report"),
        "policy_override_merge_report": report_default_path(root, naos_root, policy, "policy_override_merge_report"),
        "plan_coherence_report": report_default_path(root, naos_root, policy, "plan_coherence_report"),
        "pr_risk_classification_report": report_default_path(root, naos_root, policy, "pr_risk_classification_report"),
        "pr_governance_summary_report": report_default_path(root, naos_root, policy, "pr_governance_summary_report"),
        "agentic_workflow_review_report": report_default_path(root, naos_root, policy, "agentic_workflow_review_report"),
        "pre_implementation_alignment_review_report": report_default_path(root, naos_root, policy, "pre_implementation_alignment_review_report"),
        "calibration_shadow_report": report_default_path(root, naos_root, policy, "calibration_shadow_report"),
        "evidence_classification_report": report_default_path(root, naos_root, policy, "evidence_classification_report"),
        "cross_harness_review_readiness_report": report_default_path(root, naos_root, policy, "cross_harness_review_readiness_report"),
        "adoption_summary_report": report_default_path(root, naos_root, policy, "adoption_summary_report"),
        "preflight_report": report_default_path(root, naos_root, policy, "preflight_report"),
        "intake_report": report_default_path(root, naos_root, policy, "intake_report"),
        "install_plan_report": report_default_path(root, naos_root, policy, "install_plan_report"),
        "existing_resource_inventory_report": report_default_path(root, naos_root, policy, "existing_resource_inventory_report"),
        "ai_artifact_inventory_report": report_default_path(root, naos_root, policy, "ai_artifact_inventory_report"),
        "ai_artifact_reconciliation_report": report_default_path(root, naos_root, policy, "ai_artifact_reconciliation_report"),
        "ai_code_provenance_report": report_default_path(root, naos_root, policy, "ai_code_provenance_report"),
        "compliance_posture_report": report_default_path(root, naos_root, policy, "compliance_posture_report"),
        "memory_resource_inventory_report": report_default_path(root, naos_root, policy, "memory_resource_inventory_report"),
        "memory_resource_reconciliation_report": report_default_path(root, naos_root, policy, "memory_resource_reconciliation_report"),
        "mcp_resource_inventory_report": report_default_path(root, naos_root, policy, "mcp_resource_inventory_report"),
        "brownfield_baseline_report": report_default_path(root, naos_root, policy, "brownfield_baseline_report"),
        "candidate_requirements_report": report_default_path(root, naos_root, policy, "candidate_requirements_report"),
        "traceability_gap_register_report": report_default_path(root, naos_root, policy, "traceability_gap_register_report"),
        "install_decision_record_report": report_default_path(root, naos_root, policy, "install_decision_record_report"),
        "context_challenge_report": report_default_path(root, naos_root, policy, "context_challenge_report"),
        "repo_context_challenge_report": report_default_path(root, naos_root, policy, "repo_context_challenge_report"),
        "plan_challenge_report": report_default_path(root, naos_root, policy, "plan_challenge_report"),
        "decision_probe_report": report_default_path(root, naos_root, policy, "decision_probe_report"),
        "planning_gate_review_report": report_default_path(root, naos_root, policy, "planning_gate_review_report"),
        "roadmap_crosswalk_report": report_default_path(root, naos_root, policy, "roadmap_report"),
        "function_index_report": report_default_path(root, naos_root, policy, "function_index_report"),
        "duplicate_function_hygiene_report": report_default_path(root, naos_root, policy, "duplicate_function_hygiene_report"),
        "secret_hygiene_report": report_default_path(root, naos_root, policy, "secret_hygiene_report"),
        "test_quality_hygiene_report": report_default_path(root, naos_root, policy, "test_quality_hygiene_report"),
        "dependency_integrity_report": report_default_path(root, naos_root, policy, "dependency_integrity_report"),
        "package_reality_report": report_default_path(root, naos_root, policy, "package_reality_report"),
        "api_symbol_reality_report": report_default_path(root, naos_root, policy, "api_symbol_reality_report"),
        "gate_status_report": report_default_path(root, naos_root, policy, "gate_status_report"),
        "gate_evaluation_report": report_default_path(root, naos_root, policy, "gate_evaluation_report"),
        "test_evidence_map": test_map_output_path(root, naos_root, policy)
        or evidence_default_path(root, naos_root, policy, "source_to_test_map"),
        "test_evidence_health_report": report_default_path(root, naos_root, policy, "test_evidence_report"),
        "ac_completion_evidence_report": report_default_path(root, naos_root, policy, "ac_completion_evidence_report"),
        "exceptions_waivers": evidence_default_path(root, naos_root, policy, "exceptions_report"),
        "completion_certificate": evidence_default_path(root, naos_root, policy, "completion_certificate_report"),
    }


def selected_path(explicit: str | None, default: Path | None) -> tuple[Path | None, str]:
    if explicit:
        return Path(explicit), "explicit"
    return default, "default"


def build_evidence_pack(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    args: argparse.Namespace,
) -> dict[str, Any]:
    generated_at = parse_timestamp(args.generated_at)
    defaults = default_artifact_paths(root, naos_root, policy)
    artifact_specs = [
        ("task_path", "Task path", args.task_path, False),
        ("context_manifest", "Context manifest", args.context_manifest, False),
        ("validator_results", "Validator results", args.validator_results, True),
        ("claims_validation_report", "Claims validation report", args.claims_report, True),
        ("self_check_report", "Self-check report", args.self_check_report, True),
        ("capability_maturity_report", "Capability maturity readiness report", args.capability_maturity_report, True),
        ("systemic_impact_report", "Systemic impact and coherence review report", args.systemic_impact_report, True),
        ("module_header_traceability_report", "Module-header traceability report", args.module_header_report, True),
        ("spec_pack_contract_report", "Spec-pack template contract conformance report", args.spec_pack_contract_report, True),
        ("spec_pack_materialization_report", "Spec-pack materialization report", args.spec_pack_materialization_report, False),
        ("spec_assembly_worksheet_report", "Spec assembly worksheet report", args.spec_assembly_worksheet_report, False),
        ("spec_cascade_report", "Spec cascade coherence report", args.spec_cascade_report, True),
        ("control_plane_review_report", "Control-plane review and research-routing report", args.control_plane_review_report, True),
        ("setup_recommendations_report", "Setup recommendations report", args.setup_recommendations_report, True),
        ("governance_bypass_posture_report", "Governance bypass posture report", args.governance_bypass_posture_report, False),
        ("external_evidence_ingest_report", "External evidence ingest report", args.external_evidence_ingest_report, False),
        ("evidence_attestation_report", "Evidence integrity and reviewer attestation report", args.evidence_attestation_report, True),
        ("evidence_verification_report", "Evidence tamper-evidence verification report", args.evidence_verification_report, False),
        ("evidence_conflict_detection_report", "Evidence conflict detection report", args.evidence_conflict_detection_report, False),
        ("memory_context_readiness_report", "AI context continuity and memory governance readiness report", args.memory_context_readiness_report, True),
        ("memory_provider_access_report", "Memory provider and MCP access verification report", args.memory_provider_access_report, False),
        ("memory_use_policy_report", "Memory use policy, recall trace, and audit-event readiness report", args.memory_use_policy_report, False),
        ("learning_loop_review_report", "Governed learning lifecycle review report", args.learning_loop_review_report, False),
        ("failure_mode_observations_report", "Failure-mode observations report", args.failure_mode_observations_report, False),
        ("adapter_coherence_report", "Plugin and adapter coherence report", args.adapter_coherence_report, False),
        ("task_context_pack_report", "Task context pack report", args.task_context_pack_report, False),
        ("task_lifecycle_report", "Native task lifecycle report", args.task_lifecycle_report, False),
        ("research_record_report", "Structured research record validation report", args.research_record_report, False),
        ("composed_traceability_report", "Composed traceability report", args.composed_traceability_report, False),
        ("task_claim_report", "Task claim/release coordination report", args.task_claim_report, False),
        ("local_context_index_report", "Local context index report", args.local_context_index_report, True),
        ("sqlite_write_coordination_report", "SQLite write coordination report", args.sqlite_write_coordination_report, False),
        ("local_context_query_report", "Local context query report", args.local_context_query_report, False),
        ("semantic_candidate_layer_report", "Semantic candidate layer readiness report", args.semantic_candidate_layer_report, False),
        ("graph_context_readiness_report", "Graph context readiness report", args.graph_context_readiness_report, False),
        ("graph_context_query_report", "Graph context query report", args.graph_context_query_report, False),
        ("session_identity_report", "Session identity and report namespacing report", args.session_identity_report, False),
        ("operator_attribution_report", "Operator attribution report", args.operator_attribution_report, False),
        ("session_lifecycle_report", "Session lifecycle report", args.session_lifecycle_report, False),
        ("audit_log_summary_report", "Append-only audit log summary report", args.audit_log_summary_report, False),
        ("agent_trace_validation_report", "Agent trace validation report", args.agent_trace_validation_report, False),
        ("harness_trace_import_report", "Harness trace import report", args.harness_trace_import_report, False),
        ("ai_surface_context_budget_report", "AI-surface context budget and health report", args.ai_surface_context_budget_report, False),
        ("static_grader_report", "StaticGrader structural report", args.static_grader_report, False),
        ("grader_assessment_report", "Grader assessment audit/drift/assess report", args.grader_assessment_report, False),
        ("llm_grader_readiness_report", "LLMGrader readiness report", args.llm_grader_readiness_report, False),
        ("behavioral_governance_readiness_report", "Behavioral Governance Readiness report", args.behavioral_governance_readiness_report, False),
        ("policy_override_merge_report", "Policy override merge report", args.policy_override_merge_report, False),
        ("plan_coherence_report", "Plan coherence review report", args.plan_coherence_report, False),
        ("pr_risk_classification_report", "PR risk classification report", args.pr_risk_classification_report, False),
        ("pr_governance_summary_report", "PR governance summary report", args.pr_governance_summary_report, False),
        ("agentic_workflow_review_report", "Agentic workflow review report", args.agentic_workflow_review_report, False),
        ("pre_implementation_alignment_review_report", "Pre-Implementation Alignment review report", args.pre_implementation_alignment_review_report, False),
        ("calibration_shadow_report", "Calibration shadow report", args.calibration_shadow_report, False),
        ("evidence_classification_report", "Evidence classification report", args.evidence_classification_report, False),
        ("cross_harness_review_readiness_report", "Cross-harness review readiness report", args.cross_harness_review_readiness_report, False),
        ("adoption_summary_report", "Professional adoption summary report", args.adoption_summary_report, False),
        ("preflight_report", "Professional adoption preflight report", args.preflight_report, False),
        ("intake_report", "Guided adoption intake report", args.intake_report, False),
        ("install_plan_report", "Professional adoption install plan", args.install_plan_report, False),
        ("existing_resource_inventory_report", "Existing resource inventory report", args.existing_resource_inventory_report, False),
        ("ai_artifact_inventory_report", "AI artifact inventory report", args.ai_artifact_inventory_report, False),
        ("ai_artifact_reconciliation_report", "AI artifact reconciliation report", args.ai_artifact_reconciliation_report, False),
        ("ai_code_provenance_report", "AI code provenance review report", args.ai_code_provenance_report, False),
        ("compliance_posture_report", "Compliance posture review report", args.compliance_posture_report, False),
        ("memory_resource_inventory_report", "Memory resource inventory report", args.memory_resource_inventory_report, False),
        ("memory_resource_reconciliation_report", "Memory resource reconciliation report", args.memory_resource_reconciliation_report, False),
        ("mcp_resource_inventory_report", "MCP resource inventory report", args.mcp_resource_inventory_report, False),
        ("brownfield_baseline_report", "Brownfield baseline report", args.brownfield_baseline_report, False),
        ("candidate_requirements_report", "Candidate requirements report", args.candidate_requirements_report, False),
        ("traceability_gap_register_report", "Traceability gap register report", args.traceability_gap_register_report, False),
        ("install_decision_record_report", "Install/adoption decision record report", args.install_decision_record_report, False),
        ("context_challenge_report", "Context challenge report", args.context_challenge_report, False),
        ("repo_context_challenge_report", "Repo context challenge report", args.repo_context_challenge_report, False),
        ("plan_challenge_report", "Plan challenge report", args.plan_challenge_report, False),
        ("decision_probe_report", "Decision probe report", args.decision_probe_report, False),
        ("planning_gate_review_report", "Planning gate review report", args.planning_gate_review_report, False),
        ("roadmap_crosswalk_report", "Roadmap/crosswalk validation report", args.roadmap_report, True),
        ("function_index_report", "Function-index health report", args.function_index_report, True),
        ("duplicate_function_hygiene_report", "Duplicate-function hygiene report", args.duplicate_function_hygiene_report, False),
        ("secret_hygiene_report", "Secret hygiene report", args.secret_hygiene_report, False),
        ("test_quality_hygiene_report", "Test-quality hygiene report", args.test_quality_hygiene_report, False),
        ("dependency_integrity_report", "Dependency-integrity report", args.dependency_integrity_report, False),
        ("package_reality_report", "Package-reality report", args.package_reality_report, False),
        ("api_symbol_reality_report", "API-symbol reality report", args.api_symbol_reality_report, False),
        ("gate_status_report", "Gatekeeper status report", args.gate_status_report, True),
        ("gate_evaluation_report", "Gatekeeper evaluation report", args.gate_evaluation_report, False),
        ("test_evidence_map", "Source-to-test evidence map", args.test_map, True),
        ("test_evidence_health_report", "Test evidence health report", args.test_evidence_report, True),
        ("ac_completion_evidence_report", "AC completion evidence report", args.ac_completion_evidence_report, False),
        ("exceptions_waivers", "Exceptions and waivers", args.exceptions, False),
        ("completion_certificate", "Completion certificate", args.completion_certificate, False),
    ]

    artifacts: dict[str, dict[str, Any]] = {}
    for key, label, explicit, required in artifact_specs:
        path, source = selected_path(explicit, defaults[key])
        missing_status = "missing" if key in VALIDATOR_ARTIFACTS else "not_configured"
        artifacts[key] = read_artifact(
            key=key,
            label=label,
            path=path,
            required=required,
            source=source,
            generated_at=generated_at,
            policy=policy,
            missing_status=missing_status,
        )

    list_sections = section_lists(artifacts, args)
    external_references = dedupe_references(
        [
            reference
            for artifact in artifacts.values()
            for reference in artifact.get("external_references", [])
        ]
        + collect_external_references(list_sections, policy)
    )
    findings = build_findings(root, naos_root, profile, policy, artifacts, external_references)
    ac_completion_evidence = summarize_ac_completion_evidence(
        artifacts.get("ac_completion_evidence_report", {})
    )
    evidence_attestation = summarize_evidence_attestation(artifacts.get("evidence_attestation_report", {}))
    evidence_verification = summarize_evidence_verification(artifacts.get("evidence_verification_report", {}))
    evidence_conflicts = summarize_evidence_conflicts(artifacts.get("evidence_conflict_detection_report", {}))
    memory_context_readiness = summarize_memory_context_readiness(artifacts.get("memory_context_readiness_report", {}))
    memory_provider_access = summarize_memory_provider_access(artifacts.get("memory_provider_access_report", {}))
    memory_use_policy = summarize_memory_use_policy(artifacts.get("memory_use_policy_report", {}))
    learning_loop_review = summarize_learning_loop_review(artifacts.get("learning_loop_review_report", {}))
    failure_mode_observations = summarize_failure_mode_observations(artifacts.get("failure_mode_observations_report", {}))
    adapter_coherence = summarize_adapter_coherence(artifacts.get("adapter_coherence_report", {}))
    task_context_pack = summarize_task_context_pack(artifacts.get("task_context_pack_report", {}))
    task_lifecycle = summarize_native_lifecycle_report(
        artifacts.get("task_lifecycle_report", {}),
        "Native completion records repository state; it does not approve merge/release or admit evidence.",
    )
    research_record = summarize_native_lifecycle_report(
        artifacts.get("research_record_report", {}),
        "Validated research remains candidate-only until a separate attributable transition.",
    )
    composed_traceability = summarize_native_lifecycle_report(
        artifacts.get("composed_traceability_report", {}),
        "Relationship presence is structural evidence and does not prove semantic correctness.",
    )
    task_claims = summarize_task_claims(artifacts.get("task_claim_report", {}))
    spec_pack_contract = summarize_spec_pack_contract(artifacts.get("spec_pack_contract_report", {}))
    spec_pack_materialization = summarize_spec_pack_materialization(artifacts.get("spec_pack_materialization_report", {}))
    spec_assembly_worksheet = summarize_spec_assembly_worksheet(artifacts.get("spec_assembly_worksheet_report", {}))
    spec_cascade_coherence = summarize_spec_cascade_coherence(artifacts.get("spec_cascade_report", {}))
    local_context_index = summarize_local_context_index(artifacts.get("local_context_index_report", {}))
    sqlite_write_coordination = summarize_sqlite_write_coordination(artifacts.get("sqlite_write_coordination_report", {}))
    local_context_query = summarize_local_context_query(artifacts.get("local_context_query_report", {}))
    semantic_candidate_layer = summarize_semantic_candidate_layer(artifacts.get("semantic_candidate_layer_report", {}))
    graph_context_readiness = summarize_graph_context_readiness(artifacts.get("graph_context_readiness_report", {}))
    graph_context_query = summarize_graph_context_query(artifacts.get("graph_context_query_report", {}))
    session_identity = summarize_session_identity(artifacts.get("session_identity_report", {}))
    operator_attribution = summarize_operator_attribution(artifacts.get("operator_attribution_report", {}))
    session_lifecycle = summarize_session_lifecycle(artifacts.get("session_lifecycle_report", {}))
    audit_log = summarize_audit_log(artifacts.get("audit_log_summary_report", {}))
    agent_trace_validation = summarize_agent_trace_validation(artifacts.get("agent_trace_validation_report", {}))
    harness_trace_import = summarize_harness_trace_import(artifacts.get("harness_trace_import_report", {}))
    static_grader = summarize_static_grader(artifacts.get("static_grader_report", {}))
    grader_assessment = summarize_grader_assessment(artifacts.get("grader_assessment_report", {}))
    llm_grader_readiness = summarize_llm_grader_readiness(artifacts.get("llm_grader_readiness_report", {}))
    behavioral_readiness = summarize_behavioral_governance_readiness(artifacts.get("behavioral_governance_readiness_report", {}))
    policy_overrides = summarize_policy_overrides(artifacts.get("policy_override_merge_report", {}))
    plan_coherence = summarize_plan_coherence(artifacts.get("plan_coherence_report", {}))
    pr_risk_classification = summarize_pr_risk_classification(artifacts.get("pr_risk_classification_report", {}))
    pr_governance = summarize_pr_governance(artifacts.get("pr_governance_summary_report", {}))
    agentic_workflow = summarize_agentic_workflow(artifacts.get("agentic_workflow_review_report", {}))
    pre_implementation_alignment = summarize_pre_implementation_alignment(artifacts.get("pre_implementation_alignment_review_report", {}))
    calibration_shadow = summarize_calibration_shadow(artifacts.get("calibration_shadow_report", {}))
    evidence_classification = summarize_evidence_classification(artifacts.get("evidence_classification_report", {}))
    cross_harness_review_readiness = summarize_cross_harness_review_readiness(artifacts.get("cross_harness_review_readiness_report", {}))
    ai_code_provenance = summarize_ai_code_provenance(artifacts.get("ai_code_provenance_report", {}))
    compliance_posture = summarize_compliance_posture(artifacts.get("compliance_posture_report", {}))
    professional_adoption = summarize_professional_adoption(artifacts)
    deterministic_hygiene = summarize_deterministic_hygiene(artifacts)
    summary = finding_counts(findings)
    summary.update(
        {
            "artifacts": len(artifacts),
            "present_artifacts": sum(1 for artifact in artifacts.values() if artifact.get("exists")),
            "missing_artifacts": sum(1 for artifact in artifacts.values() if artifact.get("status") == "missing"),
            "not_configured_artifacts": sum(1 for artifact in artifacts.values() if artifact.get("status") == "not_configured"),
            "stale_artifacts": sum(1 for artifact in artifacts.values() if (artifact.get("freshness") or {}).get("status") == "stale"),
            "external_references": len(external_references),
            "external_references_unverified": sum(
                1 for reference in external_references if reference.get("status") == external_reference_status(policy)
            ),
        }
    )

    policy_meta = policy.get("_meta", {})
    return {
        "schema": "naos.evidence_pack.v1",
        "generated_at": timestamp_text(generated_at),
        "profile": profile,
        "status": status_from_counts(summary),
        "naos_root": naos_root,
        "project_root": str(root),
        "policy": {
            "version": policy.get("version"),
            "source": policy_meta.get("source"),
            "path": policy_meta.get("path"),
        },
        "semantics": {
            "supports": [
                "governance traceability",
                "review and audit/admissibility discussions",
                "residual-risk review",
            ],
            "does_not_prove": [
                "legal or regulatory compliance",
                "runtime safety",
                "complete test coverage unless evidence supports it",
            ],
            "external_reference_rule": "External URLs are references, not verified evidence, unless explicitly marked verified.",
            "tier3_rule": "Experimental Tier 3 capabilities remain advisory and non-blocking unless project policy explicitly changes them.",
            "maturity_readiness_rule": (
                "NAOS evaluates maturity readiness. It does not automatically promote, "
                "certify, or approve maturity. Final maturity decisions remain project "
                "governance decisions."
            ),
            "systemic_impact_rule": (
                "NAOS evaluates configured artifact-family review obligations. It does "
                "not prove perfect coherence, complete impact analysis, or certification."
            ),
            "module_header_traceability_rule": (
                "NAOS evaluates canonical source-module header evidence. It does not "
                "prove complete source traceability, source correctness, or design correctness."
            ),
            "spec_cascade_coherence_rule": (
                "NAOS evaluates deterministic requirement/task/source cascade evidence, "
                "including unresolved source spec references. "
                "It does not prove code correctness, complete traceability, runtime behavior, "
                "approval, certification, or compliance."
            ),
            "spec_pack_contract_rule": (
                "NAOS evaluates deterministic spec-pack template contract conformance, "
                "profile applicability, and reference resolution. "
                "It does not prove specification quality, approval, implementation, "
                "complete traceability, runtime behavior, certification, or compliance."
            ),
            "spec_pack_materialization_rule": (
                "NAOS copies or previews missing profile-required template files only. "
                "It does not fill, approve, validate, implement, test, certify, or prove specifications."
            ),
            "spec_assembly_worksheet_rule": (
                "NAOS maps adoption evidence and candidates to manifest-declared specs for review only. "
                "It does not promote candidates, fill specs, approve requirements, or prove complete traceability."
            ),
            "control_plane_review_rule": (
                "NAOS evaluates structured governance-surface review and research-routing "
                "items. It does not prove research completeness, routing completeness, "
                "governance correctness, or compliance."
            ),
            "setup_recommendations_rule": (
                "NAOS recommends setup modules, consequences, warnings, and next actions. "
                "It does not automatically enable modules, approve maturity, certify "
                "compliance, or guarantee project readiness."
            ),
            "governance_bypass_posture_rule": (
                "NAOS reports local hook, CI, commit-message, and tier/profile posture. "
                "It does not prevent bypasses, prove CI ran, approve PRs, certify controls, "
                "or prove compliance."
            ),
            "external_evidence_ingest_rule": (
                "NAOS ingests local SARIF as unverified external review evidence. It does not "
                "run scanners, verify findings, approve releases, attest evidence, certify "
                "controls, or prove compliance."
            ),
            "evidence_attestation_rule": (
                "NAOS records local SHA-256 digests and reviewer metadata for configured "
                "evidence artifacts. It does not implement cryptographic signing, signature "
                "verification, tamper-proof storage, legal approval, regulatory approval, "
                "compliance approval, or guaranteed integrity."
            ),
            "ac_completion_evidence_rule": (
                "NAOS validates declared AC/SCEN evidence and can validate explicit Git base/subject "
                "commit and subject-tree bindings, conservative path-shaped command operands, and "
                "preserved predecessor supersession for human review. It does not re-execute commands, "
                "prove clean or independent execution, sign evidence, authenticate identities, approve "
                "completion, or authorize release."
            ),
            "evidence_conflict_detection_rule": (
                "NAOS evidence conflict detection flags deterministic contradictions, metadata "
                "gaps, stale attestations, duplicate attestations, and routing gaps. It does not "
                "resolve conflicts, adjudicate which evidence is correct, prove separation of "
                "duties, approve work, lock tasks, or prove compliance."
            ),
            "evidence_verification_rule": (
                "NAOS evidence verification recomputes local artifact digests and the manifest "
                "root, then reports tamper-evidence, signature-entry presence, and best-effort "
                "Git HEAD metadata. It does not validate adopter signatures, authenticate "
                "identities, sign artifacts, hold keys, approve work, provide non-repudiation, "
                "certify controls, or prove compliance."
            ),
            "memory_context_readiness_rule": (
                "NAOS evaluates AI context-continuity and memory-governance readiness. "
                "Memory is advisory recall only; repository evidence remains authoritative. "
                "The report does not call memory tools, grant MCP access, approve memory "
                "writes, prevent hallucinations, or treat memory as evidence."
            ),
            "memory_provider_access_rule": (
                "NAOS verifies declared memory provider and MCP access posture with safe "
                "local metadata only. Configured providers and MCP config files do not prove "
                "usable access, and read access does not imply write access. The report does "
                "not call memory tools, read private payloads, write memory, approve memory "
                "use, or treat memory access as evidence."
            ),
            "memory_use_policy_rule": (
                "NAOS evaluates memory-use policy and manual review metadata. Unreviewed "
                "memory remains advisory; instruction-grade memory requires explicit approval, "
                "provenance, scope, reviewer, timestamp, and freshness/expiry boundaries. "
                "Recall traces are usage records, audit events are records, and neither is "
                "proof or approval. The report does not execute memory runtime, read private "
                "payloads, write memory, or treat memory as evidence/source authority."
            ),
            "learning_loop_review_rule": (
                "NAOS evaluates candidate, active, and historical learning lifecycle records. "
                "Candidate learning is proposal-only, active learning requires reviewed "
                "metadata, and inactive learning must not be current guidance. The report does "
                "not write memory, mutate skills/prompts/workflows/baselines/gates, approve "
                "work, prove semantic truth, or replace repository evidence."
            ),
            "failure_mode_observations_rule": (
                "NAOS aggregates local report findings into canonical failure-mode observation "
                "statistics for human review. Observation counts may inform learning-loop, "
                "autoresearch, or remediation scoping, but they are not numeric risk score "
                "authority, automatic learning, approval, blocking, MCP/memory activation, "
                "provider/model routing, release authority, or compliance proof."
            ),
            "adapter_coherence_rule": (
                "NAOS evaluates repo-versioned plugin source and optional IDE/tool adapter "
                "guidance for static coherence only. It does not prove live plugin installation, "
                "mutate Codex caches or marketplace files, activate hooks, call MCP, write "
                "memory, propagate changes automatically, approve work, or prove compliance."
            ),
            "task_context_pack_rule": (
                "NAOS task context packs are derived, bounded context snapshots for one task. "
                "They are not source-of-truth artifacts, evidence authority, approval, complete "
                "coherence proof, automatic context injection, or hallucination prevention."
            ),
            "task_claims_rule": (
                "NAOS task claims record coordination metadata for task work. They do not "
                "authorize work, approve tasks, prove task ownership, satisfy separation of "
                "duties, resolve evidence conflicts, or indicate task completion."
            ),
            "local_context_index_rule": (
                "NAOS local context indexes are generated, derived, cache-like retrieval substrates. "
                "They support bounded candidate lookup and do not decide truth, replace source "
                "artifacts, provide semantic proof, perform graph reasoning, or prevent hallucinations."
            ),
            "local_context_query_rule": (
                "NAOS local context queries return bounded candidate references from the generated "
                "index. They are not answers, source-of-truth artifacts, semantic proof, memory "
                "search, automatic context injection, or approval."
            ),
            "semantic_candidate_layer_rule": (
                "NAOS semantic candidate readiness records future semantic/vector posture only. "
                "It does not enable sqlite-vec, embeddings, extension loading, model/API calls, "
                "memory payload search, or semantic candidates as answers or authority."
            ),
            "graph_context_readiness_rule": (
                "NAOS graph context readiness records future relationship-traversal posture only. "
                "It does not enable graph runtime, NetworkX, GraphML, graph databases, graph "
                "algorithms, global traversal, memory payload graphing, or graph links as truth."
            ),
            "graph_context_query_rule": (
                "NAOS graph context queries return bounded relationship candidates from explicit "
                "indexed/report links. They are not truth, implementation correctness proof, graph "
                "runtime, source authority, semantic ranking, memory traversal, or approval."
            ),
            "session_lifecycle_rule": (
                "NAOS session lifecycle reports summarize start, checkpoint, and end posture. "
                "They do not mutate task cards, TASK_REGISTRY, compact files, git state, or memory; "
                "they do not inject context automatically, approve work, prove task completion, or "
                "perform durable memory write-back."
            ),
            "agent_trace_validation_rule": (
                "NAOS validates declared agent trace events as records for future grading/audit flows. "
                "Trace events are not correctness proof, approval, evidence authority, memory writes, "
                "runtime capture, legal/compliance/regulatory assurance, or behavioral safety proof."
            ),
            "static_grader_rule": (
                "NAOS StaticGrader performs deterministic structural checks only. Its report is not "
                "behavioral safety proof, semantic correctness proof, approval, maturity promotion, "
                "runtime behavior proof, LLM judgment, or legal/regulatory assurance."
            ),
            "llm_grader_readiness_rule": (
                "NAOS LLMGrader readiness records future enablement requirements only. It does not "
                "call models, read provider credentials, incur cost, approve work, certify outcomes, "
                "promote maturity, or replace StaticGrader and deterministic evidence."
            ),
            "behavioral_governance_readiness_rule": (
                "NAOS Behavioral Governance Readiness records deterministic readiness and impacter "
                "review metadata only. It does not run behavioral grading, create baselines, call "
                "models/providers/APIs, approve work, certify outcomes, prove compliance, publish, "
                "authorize releases, or promote maturity."
            ),
            "plan_coherence_rule": (
                "NAOS plan coherence reviews active task claims, task registry dependencies, and "
                "module-header task linkage, with optional diff-base implementation-scope path "
                "evidence, as deterministic coordination evidence. It does not authorize work, "
                "sequence execution, resolve conflicts, prove ownership, prove completion, prove "
                "semantic drift, or approve a plan."
            ),
            "kit_vs_adopter_severity_rule": (
                "When run in the NAOS kit repository, missing project evidence is treated as a "
                "calibration/dogfood signal and may be downgraded to advisory. In adopter "
                "projects, profile and policy can produce warning, required, or blocking "
                "findings; kit advisory output is not the maximum adopter severity."
            ),
            "pr_governance_summary_rule": (
                "NAOS PR governance summaries package deterministic CI evidence and review "
                "signals. They do not approve pull requests, authorize deployment or release, "
                "prove compliance, satisfy separation of duties, or resolve conflicts."
            ),
            "pr_risk_classification_rule": (
                "NAOS PR risk classification reviews local path and diff metadata for risky PR "
                "surfaces. It does not execute code, run sandboxes, analyze malware, authenticate "
                "contributors, approve PRs, authorize deployment or release, prove security, or "
                "prove compliance."
            ),
            "agentic_workflow_rule": (
                "NAOS agentic workflow review inspects declared file-first operating controls. "
                "It does not inspect chat history, prove behavior, prevent hallucinations, "
                "approve design or implementation, or replace human review."
            ),
            "pre_implementation_alignment_rule": (
                "NAOS Pre-Implementation Alignment records structured planning answers for "
                "review. It does not prove requirements completeness, approve design, approve "
                "implementation, prove compliance, or replace human review."
            ),
            "calibration_shadow_rule": (
                "NAOS calibration shadow compares deterministic report metadata against "
                "local expectations. It is not model calibration, semantic correctness proof, "
                "behavioral correctness proof, release authorization, or compliance proof."
            ),
            "evidence_classification_rule": (
                "NAOS evidence classification records finding provenance categories. "
                "Confirmed, deduced, hypothesized, and unknown classifications are review "
                "metadata, not truth proof, legal conclusions, issue resolution, approval, "
                "or compliance proof."
            ),
            "cross_harness_review_readiness_rule": (
                "NAOS cross-harness review readiness records future governance prerequisites "
                "for independent review and DSSE-style planning. It does not execute harnesses, "
                "call providers, sign artifacts, verify signatures, custody keys, create "
                "attestations, approve work, certify outcomes, or prove compliance."
            ),
            "ai_code_provenance_rule": (
                "NAOS AI code provenance evidence packages local declarations and existing "
                "AI artifact/adoption evidence for human review. It does not provide legal "
                "opinions, authorship or ownership proof, infringement clearance, proof of "
                "copyright compliance, signing, publication authority, release authority, approval, "
                "certification, or proof of compliance."
            ),
            "compliance_posture_rule": (
                "NAOS compliance posture evidence packages adopter-declared regulated-context "
                "metadata and evidence references for human review. It does not provide legal "
                "advice, regulatory applicability decisions, compliance pass/fail, certification, "
                "conformity assessment, audit opinions, approval, signing, release authority, "
                "publication authority, or proof of compliance."
            ),
            "deterministic_hygiene_rule": (
                "NAOS deterministic hygiene checks inspect local files for exact/normalized "
                "duplicate-function bodies, obvious secret-like patterns, weak assertion "
                "evidence, undeclared imports, package-reality signals, and declared API-symbol signals. "
                "They are review evidence only and do not "
                "prove semantic correctness, secret-free code, behavioral correctness, API behavior, package "
                "safety, vulnerability absence, supply-chain assurance, approval, certification, or compliance."
            ),
        },
        "freshness": {
            "default_staleness_days": evidence_staleness_days(policy),
            "status": "stale_items_present" if summary["stale_artifacts"] else "within_available_metadata",
        },
        "artifacts": artifacts,
        "exceptions_waivers": list_sections["exceptions_waivers"],
        "known_gaps": list_sections["known_gaps"],
        "residual_risks": list_sections["residual_risks"],
        "ac_completion_evidence": ac_completion_evidence,
        "evidence_attestation": evidence_attestation,
        "evidence_verification": evidence_verification,
        "evidence_conflicts": evidence_conflicts,
        "memory_context_readiness": memory_context_readiness,
        "memory_provider_access": memory_provider_access,
        "memory_use_policy": memory_use_policy,
        "learning_loop_review": learning_loop_review,
        "failure_mode_observations": failure_mode_observations,
        "adapter_coherence": adapter_coherence,
        "task_context_pack": task_context_pack,
        "task_lifecycle": task_lifecycle,
        "research_record": research_record,
        "composed_traceability": composed_traceability,
        "task_claims": task_claims,
        "spec_pack_contract": spec_pack_contract,
        "spec_pack_materialization": spec_pack_materialization,
        "spec_assembly_worksheet": spec_assembly_worksheet,
        "spec_cascade_coherence": spec_cascade_coherence,
        "local_context_index": local_context_index,
        "sqlite_write_coordination": sqlite_write_coordination,
        "local_context_query": local_context_query,
        "semantic_candidate_layer": semantic_candidate_layer,
        "graph_context_readiness": graph_context_readiness,
        "graph_context_query": graph_context_query,
        "session_identity": session_identity,
        "operator_attribution": operator_attribution,
        "session_lifecycle": session_lifecycle,
        "audit_log": audit_log,
        "agent_trace_validation": agent_trace_validation,
        "harness_trace_import": harness_trace_import,
        "static_grader": static_grader,
        "grader_assessment": grader_assessment,
        "llm_grader_readiness": llm_grader_readiness,
        "behavioral_governance_readiness": behavioral_readiness,
        "policy_overrides": policy_overrides,
        "plan_coherence": plan_coherence,
        "pr_risk_classification": pr_risk_classification,
        "pr_governance": pr_governance,
        "agentic_workflow": agentic_workflow,
        "pre_implementation_alignment": pre_implementation_alignment,
        "calibration_shadow": calibration_shadow,
        "evidence_classification": evidence_classification,
        "cross_harness_review_readiness": cross_harness_review_readiness,
        "ai_code_provenance": ai_code_provenance,
        "compliance_posture": compliance_posture,
        "professional_adoption": professional_adoption,
        "deterministic_hygiene": deterministic_hygiene,
        "external_references": external_references,
        "summary": summary,
        "findings": findings,
        "limitations": [
            "The pack aggregates available file-first evidence and missing evidence markers.",
            "It supports review and audit/admissibility discussions; it does not prove legal or regulatory compliance.",
            "It does not prove runtime safety.",
            "It does not prove complete test coverage unless source-specific test or coverage evidence supports that claim.",
            "Kit-repo evidence-pack findings are calibration/dogfood signals; adopter-project severity depends on selected profile and policy.",
            "Capability maturity state is an adopter declaration; capability maturity reports evaluate readiness for review, not approval.",
            "Systemic impact rules are project configuration; systemic impact reports support coherence review and do not prove complete consistency.",
            "Module-header traceability reports support review of source-to-requirement/task/spec links; they do not prove code correctness.",
            "Control-plane review reports support routing review for governance-surface changes and research findings; they do not prove complete routing or research coverage.",
            "Setup recommendation reports support adopter orientation; they do not approve setup, maturity, compliance, or project readiness.",
            "Evidence attestation reports provide local digest and reviewer metadata only; they are not signatures, tamper-proof storage, legal approval, regulatory approval, compliance approval, or guaranteed integrity.",
            "Evidence conflict detection reports identify deterministic review conflicts and metadata gaps; they do not resolve conflicts, adjudicate correctness, prove separation of duties, approve work, lock tasks, or prove compliance.",
            "Memory context readiness reports describe advisory recall, MCP/tool access posture, authorization, fallback readiness, and context-pack readiness; they do not treat memory as evidence or approval.",
            "Memory provider access reports describe declared/configured/access posture only; they do not prove live MCP access, call memory tools, read private payloads, write memory, or approve memory use.",
            "Memory use policy reports describe review metadata, instruction-grade requirements, recall-trace readiness, and audit-event readiness only; they do not execute memory runtime, read private payloads, write memory, or approve memory use.",
            "Failure-mode observation reports summarize local report patterns for review only; they do not create learning records, tune thresholds, mutate prompts/skills/gates, activate MCP/memory/provider/model runtimes, approve work, block releases, or prove compliance.",
            "Adapter coherence reports describe repo-versioned plugin source and optional adapter guidance only; they do not prove live installation, mutate tool caches, call MCP, write memory, auto-propagate changes, approve work, or prove compliance.",
            "Task context pack reports summarize bounded task context for handoff and AI use; they do not replace task cards, specs, reports, evidence, or human review.",
            "Local context index reports summarize generated retrieval candidates; they do not replace repository evidence or deterministic NAOS reports.",
            "Local context query reports summarize candidate references; they are not answers or authoritative source artifacts.",
            "Semantic candidate layer reports summarize readiness/configuration posture only; they do not enable semantic/vector runtime, embeddings, sqlite-vec, extension loading, or source authority.",
            "Graph context readiness reports summarize relationship-traversal guardrails only; they do not enable graph runtime, graph databases, graph algorithms, global traversal, or source authority.",
            "Graph context query reports summarize bounded explicit-link relationship candidates; they are not graph truth, implementation proof, global traversal, or source authority.",
            "Session identity reports summarize report namespacing, local operator attribution signals, and latest-report compatibility; they do not authenticate users, authorize work, lock tasks, audit logging, evidence conflict detection, or source authority.",
            "Operator attribution reports summarize local identity signals for who initiated a run; they do not prove identity, authenticate or authorize a user, assign task ownership, satisfy separation of duties, provide non-repudiation, approve work, or create an audit log.",
            "Session lifecycle reports summarize start/checkpoint/end posture; they are not proof, approval, evidence authority, task completion, automatic context injection, or memory write-back.",
            "Agent trace validation reports summarize declared records only; they are not proof, approval, runtime capture, memory writes, legal/compliance/regulatory assurance, or behavioral safety evidence.",
            "PR risk classification reports are deterministic local review evidence only; they do not execute code, perform malware analysis, prove security, approve pull requests, authorize deployment/release, or replace human review.",
            "PR governance summaries package deterministic CI evidence only; they do not approve pull requests, authorize deployment or release, prove compliance, satisfy separation of duties, or resolve evidence conflicts.",
            "Calibration shadow reports deterministic metadata drift only; they do not calibrate models, prove behavior, approve release, or prove compliance.",
            "Evidence classification reports provenance categories only; they do not prove truth, resolve issues, approve work, or prove compliance.",
            "AI code provenance reports package local declarations and AI artifact evidence for review only; they do not prove authorship, ownership, legal sufficiency, infringement clearance, copyright compliance, release readiness, publication readiness, approval, certification, or compliance.",
            "Compliance posture reports package adopter-declared regulated-context metadata and evidence references for review only; they do not provide legal advice, regulatory applicability decisions, compliance pass/fail, certification, conformity assessment, audit opinions, approval, signing, release readiness, publication readiness, or proof of compliance.",
            "Package-reality reports summarize declared package names, lock-style pins, optional documentation install snippets, typo-near names, configured local CycloneDX SBOM/provenance/hash evidence, and explicit opt-in registry metadata as review evidence only; they do not prove package safety, malware absence, vulnerability absence, SBOM completeness, provenance authenticity, registry trust, supply-chain assurance, approval, certification, or compliance.",
            "If evidence_pack.json is hashed by evidence attestation rules, the digest can represent the pack before this attestation report is embedded; this circularity must be reviewed explicitly.",
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export a NAOS evidence pack from validator outputs.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--generated-at", help="Override generated timestamp for deterministic tests.")
    parser.add_argument("--task-path")
    parser.add_argument("--context-manifest")
    parser.add_argument("--validator-results")
    parser.add_argument("--claims-report")
    parser.add_argument("--self-check-report")
    parser.add_argument("--capability-maturity-report")
    parser.add_argument("--systemic-impact-report")
    parser.add_argument("--module-header-report")
    parser.add_argument("--spec-pack-contract-report")
    parser.add_argument("--spec-pack-materialization-report")
    parser.add_argument("--spec-assembly-worksheet-report")
    parser.add_argument("--spec-cascade-report")
    parser.add_argument("--control-plane-review-report")
    parser.add_argument("--setup-recommendations-report")
    parser.add_argument("--governance-bypass-posture-report")
    parser.add_argument("--external-evidence-ingest-report")
    parser.add_argument("--evidence-attestation-report")
    parser.add_argument("--evidence-verification-report")
    parser.add_argument("--evidence-conflict-detection-report")
    parser.add_argument("--task-claim-report")
    parser.add_argument("--memory-context-readiness-report")
    parser.add_argument("--memory-provider-access-report")
    parser.add_argument("--memory-use-policy-report")
    parser.add_argument("--learning-loop-review-report")
    parser.add_argument("--failure-mode-observations-report")
    parser.add_argument("--adapter-coherence-report")
    parser.add_argument("--task-context-pack-report")
    parser.add_argument("--task-lifecycle-report")
    parser.add_argument("--research-record-report")
    parser.add_argument("--composed-traceability-report")
    parser.add_argument("--local-context-index-report")
    parser.add_argument("--sqlite-write-coordination-report")
    parser.add_argument("--local-context-query-report")
    parser.add_argument("--semantic-candidate-layer-report")
    parser.add_argument("--graph-context-readiness-report")
    parser.add_argument("--graph-context-query-report")
    parser.add_argument("--session-identity-report")
    parser.add_argument("--operator-attribution-report")
    parser.add_argument("--session-lifecycle-report")
    parser.add_argument("--audit-log-summary-report")
    parser.add_argument("--agent-trace-validation-report")
    parser.add_argument("--harness-trace-import-report")
    parser.add_argument("--ai-surface-context-budget-report")
    parser.add_argument("--static-grader-report")
    parser.add_argument("--grader-assessment-report")
    parser.add_argument("--llm-grader-readiness-report")
    parser.add_argument("--behavioral-governance-readiness-report")
    parser.add_argument("--policy-override-merge-report")
    parser.add_argument("--plan-coherence-report")
    parser.add_argument("--pr-risk-classification-report")
    parser.add_argument("--pr-governance-summary-report")
    parser.add_argument("--agentic-workflow-review-report")
    parser.add_argument("--pre-implementation-alignment-review-report")
    parser.add_argument("--calibration-shadow-report")
    parser.add_argument("--evidence-classification-report")
    parser.add_argument("--cross-harness-review-readiness-report")
    parser.add_argument("--adoption-summary-report")
    parser.add_argument("--preflight-report")
    parser.add_argument("--intake-report")
    parser.add_argument("--install-plan-report")
    parser.add_argument("--existing-resource-inventory-report")
    parser.add_argument("--ai-artifact-inventory-report")
    parser.add_argument("--ai-artifact-reconciliation-report")
    parser.add_argument("--ai-code-provenance-report")
    parser.add_argument("--compliance-posture-report")
    parser.add_argument("--memory-resource-inventory-report")
    parser.add_argument("--memory-resource-reconciliation-report")
    parser.add_argument("--mcp-resource-inventory-report")
    parser.add_argument("--brownfield-baseline-report")
    parser.add_argument("--candidate-requirements-report")
    parser.add_argument("--traceability-gap-register-report")
    parser.add_argument("--install-decision-record-report")
    parser.add_argument("--context-challenge-report")
    parser.add_argument("--repo-context-challenge-report")
    parser.add_argument("--plan-challenge-report")
    parser.add_argument("--decision-probe-report")
    parser.add_argument("--planning-gate-review-report")
    parser.add_argument("--roadmap-report")
    parser.add_argument("--function-index-report")
    parser.add_argument("--duplicate-function-hygiene-report")
    parser.add_argument("--secret-hygiene-report")
    parser.add_argument("--test-quality-hygiene-report")
    parser.add_argument("--dependency-integrity-report")
    parser.add_argument("--package-reality-report")
    parser.add_argument("--api-symbol-reality-report")
    parser.add_argument("--gate-status-report")
    parser.add_argument("--gate-evaluation-report")
    parser.add_argument("--test-map")
    parser.add_argument("--test-evidence-report")
    parser.add_argument("--ac-completion-evidence-report")
    parser.add_argument("--exceptions")
    parser.add_argument("--completion-certificate")
    parser.add_argument("--exception", action="append", default=[])
    parser.add_argument("--known-gap", action="append", default=[])
    parser.add_argument("--residual-risk", action="append", default=[])
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    report = build_evidence_pack(root=root, profile=profile, naos_root=naos_root, policy=policy, args=args)
    output = Path(args.output) if args.output else evidence_pack_output_path(root, naos_root, policy)
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        destination = str(output) if output else "stdout only"
        print(
            "NAOS evidence pack: "
            f"{report['status']} "
            f"({report['summary']['present_artifacts']}/{report['summary']['artifacts']} artifacts present, "
            f"output: {destination})"
        )
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
