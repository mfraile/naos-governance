#!/usr/bin/env python3
"""Evaluate adopter capability maturity readiness without recording promotion."""

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
    controlled_now_utc,
    controlled_utc_now_text,
    default_naos_root,
    effective_enforcement,
    evidence_staleness_days,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    kit_root,
    load_policy,
    normalize_profile,
    report_default_path,
    report_output_path,
    severity_for_profile,
    status_from_counts,
    write_report,
)


MATURITY_LEVELS = ["L0", "L1", "L2", "L3", "L4", "L5"]
MATURITY_INDEX = {level: index for index, level in enumerate(MATURITY_LEVELS)}
UNASSIGNED_VALUES = {"", "@unassigned", "unassigned", "none", "null", "tbd", "[adapt]"}


def utc_now_text() -> str:
    return controlled_utc_now_text()


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping: {path}")
    return data


def find_capabilities_dir(root: Path, naos_root: str, explicit: str | None = None) -> Path:
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.extend(
        [
            root / naos_root / "capabilities",
            root / "capabilities",
            kit_root() / "capabilities",
        ]
    )
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return candidates[-1]


def load_capability_contracts(root: Path, naos_root: str, explicit: str | None = None) -> dict[str, dict[str, Any]]:
    capabilities_dir = find_capabilities_dir(root, naos_root, explicit)
    contracts: dict[str, dict[str, Any]] = {}
    for path in sorted(capabilities_dir.glob("*.yaml")):
        if path.name.startswith("_"):
            continue
        try:
            data = load_yaml(path)
        except Exception:
            continue
        cap_id = str(data.get("id") or path.stem)
        data["_path"] = str(path)
        contracts[cap_id] = data
    return contracts


def resolve_state_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None = None) -> Path:
    if explicit:
        return Path(explicit)
    filename = str(policy.get("paths", {}).get("capability_state") or "capability_state.yaml")
    return root / naos_root / filename


def normalize_state_entries(state: dict[str, Any]) -> dict[str, dict[str, Any]]:
    entries = state.get("capabilities") or []
    if not isinstance(entries, list):
        return {}
    normalized: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        cap_id = entry.get("capability_id")
        if cap_id:
            normalized[str(cap_id)] = entry
    return normalized


def maturity_index(level: Any) -> int | None:
    if not isinstance(level, str):
        return None
    return MATURITY_INDEX.get(level)


def is_unassigned(value: Any) -> bool:
    return str(value or "").strip().lower() in UNASSIGNED_VALUES


def configured_owners(entry: dict[str, Any]) -> list[str]:
    missing = []
    for field in ("owner_1lod", "owner_2lod", "accountable_reviewer"):
        if is_unassigned(entry.get(field)):
            missing.append(field)
    return missing


def path_matches(root: Path, pattern: str) -> list[Path]:
    if not pattern or "<" in pattern or ">" in pattern:
        return []
    candidate = Path(pattern)
    if not candidate.is_absolute():
        candidate = root / candidate
    if any(ch in str(candidate) for ch in "*?["):
        return [path for path in root.glob(str(candidate.relative_to(root))) if path.exists()]
    return [candidate] if candidate.exists() else []


def evidence_status(root: Path, entry: dict[str, Any], policy: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    refs = [str(item) for item in entry.get("evidence_refs") or []]
    missing: list[str] = []
    stale: list[str] = []
    present: list[str] = []
    window = entry.get("freshness_window_days")
    try:
        freshness_days = int(window)
    except Exception:
        freshness_days = evidence_staleness_days(policy)
    generated_at = controlled_now_utc()
    for ref in refs:
        matches = path_matches(root, ref)
        if not matches:
            missing.append(ref)
            continue
        for path in matches:
            present.append(str(path.relative_to(root)) if path.is_relative_to(root) else str(path))
            if freshness_days > 0:
                mtime = datetime.fromtimestamp(path.stat().st_mtime, UTC)
                if (generated_at - mtime).days > freshness_days:
                    stale.append(str(path.relative_to(root)) if path.is_relative_to(root) else str(path))
    return missing, stale, present


def default_gate_reports(root: Path, naos_root: str, policy: dict[str, Any]) -> list[str]:
    return [
        str(report_default_path(root, naos_root, policy, "gate_status_report").relative_to(root)),
        str(report_default_path(root, naos_root, policy, "gate_evaluation_report").relative_to(root)),
    ]


def default_dashboard_report(root: Path, naos_root: str, policy: dict[str, Any]) -> str:
    return str(report_default_path(root, naos_root, policy, "dashboard_summary_report").relative_to(root))


def related_systemic_impact_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "systemic_impact_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Systemic impact review can support maturity readiness when generated; missing review reports are not treated as pass.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "review_required": summary.get("review_required", 0),
        "human_review_required": summary.get("human_review_required", 0),
        "rule": "Systemic impact review is related evidence for maturity decisions, not automatic approval.",
    }


def related_module_header_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "module_header_traceability_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Module-header traceability can support maturity readiness when generated; missing reports are not treated as pass.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "missing_headers": summary.get("missing_headers", 0),
        "legacy_headers": summary.get("legacy_headers", 0),
        "human_review_required": summary.get("human_review_required", 0),
        "rule": "Module-header traceability is related evidence for maturity decisions, not automatic approval.",
    }


def related_spec_cascade_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "spec_cascade_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Spec-cascade coherence can support maturity readiness when generated; missing reports are not treated as pass.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "orphan_headers": summary.get("orphan_headers", 0),
        "uncovered_requirements": summary.get("uncovered_requirements", 0),
        "untraced_sources": summary.get("untraced_sources", 0),
        "unresolved_source_references": summary.get("unresolved_source_references", 0),
        "stale_statuses": summary.get("stale_statuses", 0),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Spec-cascade coherence is related evidence for maturity decisions, not automatic approval or code-correctness proof.",
    }


def related_spec_pack_contract_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "spec_pack_contract_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Spec-pack contract conformance can support maturity readiness when generated; missing reports are not treated as pass.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "files_missing": summary.get("files_missing", 0),
        "total_findings": summary.get("total_findings", 0),
        "placeholder_findings": summary.get("placeholder_findings", 0),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Spec-pack contract conformance is related evidence for maturity decisions, not automatic approval, requirements-completeness proof, or implementation proof.",
    }


def related_control_plane_review_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "control_plane_review_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Control-plane review routing can support maturity readiness when generated; missing reports are not treated as pass.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "missing_routing": summary.get("missing_routing", 0),
        "review_required": summary.get("review_required", 0),
        "human_review_required": summary.get("human_review_required", 0),
        "rule": "Control-plane review routing is related evidence for maturity decisions, not automatic approval.",
    }


def related_setup_recommendations_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "setup_recommendations_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Setup recommendations can orient maturity planning when generated; missing reports are not treated as pass.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "recommended": summary.get("recommended", 0),
        "readiness_only": summary.get("readiness_only", 0),
        "human_review_required": summary.get("human_review_required", 0),
        "rule": "Setup recommendations are related evidence for planning; they do not approve maturity movement or automatically enable modules.",
    }


def related_governance_bypass_posture_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "governance_bypass_posture_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Governance-bypass posture can support maturity review when generated; missing reports are not treated as bypass prevention, approval, or proof of compliance.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    scans = data.get("scans") if isinstance(data.get("scans"), dict) else {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "hook": scans.get("hook") or {},
        "ci": scans.get("ci") or {},
        "bypass_marker_findings": summary.get("bypass_marker_findings", 0),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Governance-bypass posture is related review evidence only; it does not prevent bypasses, prove CI ran, approve PRs, certify controls, or prove compliance.",
    }


def related_external_evidence_ingest_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "external_evidence_ingest_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "External evidence ingest can support maturity review when generated; missing reports are not treated as scanner coverage, verified findings, approval, attestation, or proof of compliance.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "results": summary.get("results", 0),
        "verification_status": summary.get("verification_status", "unverified"),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "External evidence ingest is unverified external review evidence only; it does not verify findings, approve releases, attest evidence, certify controls, or prove compliance.",
    }


def related_evidence_attestation_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "evidence_attestation_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Evidence attestation can support maturity readiness when generated; missing reports are not treated as pass or approval.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "artifacts_hashed": summary.get("artifacts_hashed", 0),
        "missing_artifacts": summary.get("missing_artifacts", 0),
        "reviewer_attestations": summary.get("reviewer_attestations", 0),
        "human_review_required": summary.get("human_review_required", 0),
        "rule": "Evidence attestation is related evidence for maturity decisions; it is local digest/reviewer metadata, not signing, certification, or automatic approval.",
    }


def related_evidence_conflict_detection_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "evidence_conflict_detection_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Evidence conflict detection can support maturity review when generated; missing reports are not treated as conflict absence, approval, or a pass.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "conflict_count": data.get("conflict_count", 0),
        "unrouted_conflicts": len(data.get("unrouted_conflicts") or []),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Evidence conflict detection is related evidence only; it does not resolve conflicts, adjudicate correctness, approve maturity, prove separation of duties, or prove compliance.",
    }


def related_task_claim_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "task_claim_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Task claim reports can support maturity review when generated; missing reports are not treated as authorization, approval, or proof no claim conflicts exist.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "claim_count": data.get("claim_count", 0),
        "active_claim_count": data.get("active_claim_count", 0),
        "conflicting_claim_count": data.get("conflicting_claim_count", 0),
        "stale_claim_count": data.get("stale_claim_count", 0),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Task claim reports are related evidence only; they coordinate work and do not authorize work, approve tasks, prove ownership, prove separation of duties, mark completion, or promote maturity.",
    }


def related_memory_context_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "memory_context_readiness_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Memory/context readiness can support maturity planning when generated; missing reports are not treated as pass, memory access, or approval.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "platforms": summary.get("platforms", 0),
        "platforms_with_declared_memory": summary.get("platforms_with_declared_memory", 0),
        "human_review_required": summary.get("human_review_required", 0),
        "rule": "Memory/context readiness is related evidence only; memory remains advisory recall and cannot drive maturity promotion.",
    }


def related_memory_provider_access_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "memory_provider_access_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Memory provider access can support maturity planning when generated; missing reports are not treated as pass, usable memory access, or approval.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "provider_access_verified": bool(data.get("provider_access_verified")),
        "mcp_access_verified": bool(data.get("mcp_access_verified")),
        "mcp_config_files_detected": summary.get("mcp_config_files_detected", 0),
        "human_review_required": summary.get("human_review_required", 0),
        "rule": "Memory provider access is related evidence only; configured memory and MCP declarations cannot drive maturity promotion by themselves.",
    }


def related_memory_use_policy_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "memory_use_policy_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Memory-use policy can support maturity planning when generated; missing reports are not treated as pass, instruction-grade approval, or memory authority.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "memory_review_items": summary.get("memory_review_items", 0),
        "instruction_grade_items": summary.get("instruction_grade_items", 0),
        "unsafe_instruction_grade_claims": summary.get("unsafe_instruction_grade_claims", 0),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Memory-use policy is related evidence only; reviewed memory, recall traces, and audit events cannot automatically promote maturity or become approval/source authority.",
    }


def related_task_context_pack_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "task_context_pack_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Task context packs can support maturity planning when generated; missing packs are not treated as pass, source of truth, or approval.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "task_id": data.get("task_id"),
        "summary": summary,
        "source_artifacts_missing": len(data.get("source_artifacts_missing") or []),
        "human_review_required": bool((data.get("human_review_boundary") or {}).get("required")),
        "rule": "Task context packs are related evidence only; they do not promote maturity, approve scope, or replace source artifacts.",
    }


def related_local_context_index_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "local_context_index_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Local context indexes can support maturity planning when generated; missing indexes are not treated as pass, source of truth, or approval.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "indexed_artifacts": summary.get("indexed_artifacts", 0),
        "chunks": summary.get("chunks", 0),
        "fts_available": summary.get("fts_available", False),
        "human_review_required": summary.get("human_review_required", False),
        "rule": "Local context index is related evidence only; retrieval candidates do not promote maturity or replace repository evidence.",
    }


def related_sqlite_write_coordination_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "sqlite_write_coordination_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "SQLite write coordination can support maturity planning for local index file integrity; missing reports are not treated as pass, task locking, or multi-user completion.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "lock_acquired": bool(data.get("lock_acquired")),
        "atomic_replace_used": bool(data.get("atomic_replace_used")),
        "tables_verified": len(data.get("tables_verified") or []),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "SQLite write coordination is related evidence only; it protects local index file integrity and does not promote maturity by itself.",
    }


def related_local_context_query_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "local_context_query_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Local context queries can support maturity planning when generated; missing query reports are not treated as pass, answers, source of truth, or approval.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "result_count": data.get("result_count", 0),
        "query_mode_used": data.get("query_mode_used") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Local context query is related evidence only; candidate references do not promote maturity or replace repository evidence.",
    }


def related_semantic_candidate_layer_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "semantic_candidate_layer_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Semantic candidate readiness can support maturity planning when generated; missing reports are not treated as pass, runtime enablement, or approval.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "semantic_runtime_enabled": bool(data.get("semantic_runtime_enabled")),
        "sqlite_vec_enabled": bool(data.get("sqlite_vec_enabled")),
        "embeddings_enabled": bool(data.get("embeddings_enabled")),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Semantic candidate readiness is related evidence only; it does not promote maturity or enable semantic/vector runtime.",
    }


def related_graph_context_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "graph_context_readiness_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Graph context readiness can support maturity planning when generated; missing reports are not treated as pass, traversal enablement, or approval.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "graph_runtime_enabled": bool(data.get("graph_runtime_enabled")),
        "explicit_link_traversal_only": bool(data.get("explicit_link_traversal_only", True)),
        "global_graph_scan_allowed": bool(data.get("global_graph_scan_allowed")),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Graph context readiness is related evidence only; it does not promote maturity or enable graph traversal runtime.",
    }


def related_graph_context_query_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "graph_context_query_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Graph context queries can support maturity planning when generated; missing query reports are not treated as pass, truth, or approval.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "result_count": data.get("result_count", 0),
        "query_mode_used": data.get("query_mode_used") or [],
        "traversal_depth_used": data.get("traversal_depth_used"),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Graph context query is related evidence only; relationship candidates do not promote maturity or replace source artifacts.",
    }


def related_session_lifecycle_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "session_lifecycle_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Session lifecycle reports can support maturity planning when generated; missing reports are not treated as pass, task completion, approval, or evidence authority.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "mode": data.get("mode"),
        "task_id": data.get("task_id"),
        "summary": data.get("summary") or {},
        "memory_candidate_proposals": len(data.get("memory_candidate_proposals") or []),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Session lifecycle is related evidence only; reports do not promote maturity, approve work, prove task completion, inject context, or write memory.",
    }


def related_session_identity_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "session_identity_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Session identity reports can support multi-user readiness planning when generated; missing reports do not imply task locking, identity proof, authentication, authorization, or audit-log completeness.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "session_id": data.get("session_id"),
        "session_report_root": data.get("session_report_root"),
        "latest_report_compatibility": data.get("latest_report_compatibility") or {},
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Session identity is related evidence only; it does not promote maturity, approve work, authenticate users, authorize work, lock tasks, or provide an append-only audit log.",
    }


def related_operator_attribution_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "operator_attribution_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Operator attribution can support multi-user readiness planning when generated; missing reports do not imply task ownership, locking, authentication, authorization, or audit-log completeness.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "operator_source": data.get("operator_source"),
        "operator_attribution_status": data.get("operator_attribution_status"),
        "session_id": data.get("session_id"),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Operator attribution is related evidence only; it does not promote maturity, prove identity, authenticate or authorize users, assign task ownership, satisfy separation of duties, approve work, or provide non-repudiation.",
    }


def related_audit_log_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "audit_log_summary_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Audit log summaries can support maturity planning when generated; missing summaries do not imply approval, non-repudiation, task locking, or evidence conflict detection.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "event_count": data.get("event_count", 0),
        "invalid_event_count": data.get("invalid_event_count", 0),
        "missing_session_id_events": len(data.get("missing_session_id_events") or []),
        "missing_operator_id_events": len(data.get("missing_operator_id_events") or []),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Audit log events are related evidence only; they do not promote maturity, approve work, prove compliance, provide non-repudiation, or create tamper-proof history.",
    }


def related_agent_trace_validation_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "agent_trace_validation_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Agent trace validation can support future grading readiness when generated; missing reports are not treated as pass, proof, approval, or runtime capture.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "event_count": data.get("event_count", 0),
        "invalid_event_count": data.get("invalid_event_count", 0),
        "forbidden_payload_findings": len(data.get("forbidden_payload_findings") or []),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Agent trace validation is related evidence only; trace events do not promote maturity, approve work, prove behavior, write memory, or capture runtime activity.",
    }


def related_static_grader_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "static_grader_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "StaticGrader can support deterministic structural readiness when generated; missing reports are not treated as pass, behavioral assessment, approval, or maturity promotion.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "dimension_summary": data.get("dimension_summary") or {},
        "cost_usd": (data.get("cost_posture") or {}).get("cost_usd", 0.0),
        "not_evaluated_dimensions": len(data.get("not_evaluated_dimensions") or []),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "StaticGrader is related evidence only; it does not promote maturity, approve work, prove runtime behavior, or evaluate semantic/behavioral safety.",
    }


def related_grader_assessment_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "grader_assessment_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Grader assessment can support review planning when generated; missing reports are not treated as audit approval, certification, drift proof, or maturity promotion.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "mode": data.get("mode"),
        "path": str(path),
        "summary": summary,
        "cost_usd": (data.get("cost_budget_posture") or {}).get("cost_usd", 0.0),
        "changed_dimensions": len((data.get("drift") or {}).get("changed_dimensions") or []),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Audit/drift/assess grader assessment is related evidence only; it does not approve, certify, infer semantic drift, attest, or promote maturity.",
    }


def related_llm_grader_readiness_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "llm_grader_readiness_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "LLMGrader readiness can support maturity planning when generated; missing reports do not enable runtime grading, provider access, cost, approval, certification, or maturity promotion.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "runtime_enabled": bool(data.get("runtime_enabled")),
        "provider_allowed": bool(data.get("provider_allowed")),
        "external_api_allowed": bool(data.get("external_api_allowed")),
        "cost_usd": (data.get("cost_posture") or {}).get("cost_usd", 0.0),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "LLMGrader readiness is related evidence only; it does not promote maturity, approve work, certify, prove compliance, replace StaticGrader, or enable model/provider runtime.",
    }


def related_behavioral_governance_readiness_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "behavioral_governance_readiness_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Behavioral Governance Readiness can support maturity planning when generated; missing reports do not enable behavioral grading, baseline creation, provider access, cost, approval, certification, publication/release authority, or maturity promotion.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "baseline_state_present": bool(data.get("baseline_state_present")),
        "total_impacters": summary.get("total_impacters", 0),
        "high_impacters": summary.get("high_impacters", 0),
        "cost_usd": (data.get("cost_posture") or {}).get("cost_usd", 0.0),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Behavioral Governance Readiness is related evidence only; it does not promote maturity, approve work, certify, prove compliance, publish, authorize releases, create baselines, or run behavioral grading.",
    }


def related_policy_override_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "policy_override_merge_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Policy override merge reports can support maturity planning when generated; missing reports are not treated as pass or policy approval.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "applied_paths": summary.get("applied_paths", 0),
        "team_ids": data.get("team_ids") or summary.get("team_ids") or [],
        "operator_overlay_id": data.get("operator_overlay_id") or summary.get("operator_overlay_id"),
        "applied_overlay_scopes": data.get("applied_overlay_scopes") or [],
        "protected_invariant_violations": summary.get("protected_invariant_violations", 0),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Policy overrides are related evidence only; team/operator overlay scope is static configuration metadata and does not promote maturity, approve policy changes, authenticate or authorize operators, weaken protected invariants, or enable runtime plugins.",
    }


def related_pr_governance_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "pr_governance_summary_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "PR governance summaries can support maturity planning when generated; missing reports are not treated as pass, pull-request approval, deployment authorization, or proof of compliance.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "ci_provider": data.get("ci_provider"),
        "pull_request_number": data.get("pull_request_number"),
        "team_id": data.get("team_id"),
        "reports_present": summary.get("reports_present", 0),
        "findings": summary.get("findings", 0),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "PR governance summaries are related evidence only; CI signals do not promote maturity, approve pull requests, authorize deployment or release, prove compliance, satisfy separation of duties, or resolve conflicts.",
    }


def related_agentic_workflow_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "agentic_workflow_review_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Agentic workflow review can support maturity planning when generated; missing reports are not treated as pass or proof of assistant behavior.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "workflow_config_valid": bool(data.get("workflow_config_valid")),
        "missing_artifacts": len(data.get("missing_artifacts") or []),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Agentic workflow review is related evidence only; it does not promote maturity, approve work, prove behavior, prove requirements completeness, or replace human review.",
    }


def related_pre_implementation_alignment_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "pre_implementation_alignment_review_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Pre-Implementation Alignment review can support maturity planning when generated; missing reports are not treated as pass, design approval, or implementation approval.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    summary = data.get("summary") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "mode": data.get("mode"),
        "missing_required_questions": len(data.get("missing_required_questions") or []),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Pre-Implementation Alignment is related evidence only; it does not prove requirements completeness, approve design, approve implementation, prove compliance, or replace human review.",
    }


def related_calibration_shadow_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "calibration_shadow_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Calibration shadow can support maturity planning when generated; missing reports are not treated as pass, model calibration, release approval, or proof of compliance.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "calibration_config_valid": bool(data.get("calibration_config_valid")),
        "drift_count": int(data.get("drift_count") or 0),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Calibration shadow is related evidence only; it does not promote maturity, calibrate models, prove correctness, approve release, or prove compliance.",
    }


def related_evidence_classification_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "evidence_classification_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Evidence classification can support maturity planning when generated; missing reports are not treated as pass, truth proof, issue resolution, or approval.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "policy_valid": bool(data.get("policy_valid")),
        "classification_counts": data.get("classification_counts") or {},
        "missing_classification": len(data.get("missing_classification") or []),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Evidence classification is related evidence only; it does not promote maturity, prove truth, resolve issues, approve work, or prove compliance.",
    }


def related_cross_harness_review_readiness_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "cross_harness_review_readiness_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Cross-harness review readiness can support maturity planning when generated; missing reports are not treated as pass, signing, attestation, approval, or proof of compliance.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "config_valid": bool(data.get("config_valid")),
        "declared_harness_count": int(data.get("declared_harness_count") or 0),
        "readiness_score": int(data.get("readiness_score") or 0),
        "requirements_missing": len(data.get("requirements_missing") or []),
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Cross-harness review readiness is related evidence only; it does not promote maturity, execute harnesses, sign or verify artifacts, custody keys, approve work, or prove compliance.",
    }


def finding(
    cap_id: str,
    severity: str,
    status: str,
    message: str,
    field: str | None = None,
) -> dict[str, Any]:
    item = {
        "id": cap_id,
        "severity": severity,
        "status": status,
        "message": message,
    }
    if field:
        item["field"] = field
    return item


def blocking_status_for_profile(profile: str) -> str:
    return "blocked" if profile in {"standard", "assured"} else "advisory"


def evaluate_capability(
    *,
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
    cap_id: str,
    contract: dict[str, Any],
    entry: dict[str, Any] | None,
) -> dict[str, Any]:
    severity = "advisory" if is_kit_repository(root, naos_root) else severity_for_profile(profile, policy)
    contract_profile = contract.get("profiles", {}).get(profile, {}) if isinstance(contract.get("profiles"), dict) else {}
    limitations = list(contract.get("known_limitations") or [])
    required_next_actions: list[str] = []
    missing_evidence: list[str] = []
    stale_evidence: list[str] = []
    blocking_findings: list[dict[str, Any]] = []
    advisory_findings: list[dict[str, Any]] = []
    waivers: list[dict[str, Any]] = []

    if entry is None:
        required_next_actions.append("Declare adopter-local state for this capability in naos/capability_state.yaml.")
        advisory_findings.append(
            finding(cap_id, severity, "not_configured", "Capability is present in the kit but has no adopter-local state declaration.")
        )
        return {
            "capability_id": cap_id,
            "enabled": None,
            "current_maturity": contract.get("default_maturity"),
            "target_maturity": contract_profile.get("target_maturity"),
            "evaluated_status": "not_configured",
            "ready_for_promotion": False,
            "human_approval_required": False,
            "promotion_recorded": False,
            "missing_evidence": missing_evidence,
            "stale_evidence": stale_evidence,
            "blocking_findings": blocking_findings,
            "advisory_findings": advisory_findings,
            "waivers": waivers,
            "limitations": limitations,
            "required_next_actions": required_next_actions,
        }

    enabled = bool(entry.get("enabled"))
    current = entry.get("current_maturity")
    target = entry.get("target_maturity")
    current_idx = maturity_index(current)
    target_idx = maturity_index(target)
    waivers = [item for item in entry.get("waivers") or [] if isinstance(item, dict)]

    if not enabled:
        return {
            "capability_id": cap_id,
            "enabled": False,
            "current_maturity": current,
            "target_maturity": target,
            "evaluated_status": "disabled",
            "ready_for_promotion": False,
            "human_approval_required": False,
            "promotion_recorded": False,
            "missing_evidence": missing_evidence,
            "stale_evidence": stale_evidence,
            "blocking_findings": blocking_findings,
            "advisory_findings": advisory_findings,
            "waivers": waivers,
            "limitations": limitations + ["Disabled capabilities remain visible and are not treated as passed."],
            "required_next_actions": ["Enable the capability and configure evidence if the project wants to mature it."],
        }

    if current_idx is None:
        blocking_findings.append(finding(cap_id, severity, "invalid_maturity", "current_maturity must be L0-L5.", "current_maturity"))
    if target_idx is None:
        blocking_findings.append(finding(cap_id, severity, "invalid_maturity", "target_maturity must be L0-L5.", "target_maturity"))

    missing_owners = configured_owners(entry)
    if target_idx is not None and target_idx >= MATURITY_INDEX["L1"] and missing_owners:
        blocking_findings.append(
            finding(
                cap_id,
                severity,
                "missing_owner",
                f"Capability target maturity requires configured owners: {', '.join(missing_owners)}.",
                "owners",
            )
        )
        required_next_actions.append("Assign 1LoD owner, 2LoD owner, and accountable reviewer.")

    missing_refs, stale_refs, present_refs = evidence_status(root, entry, policy)
    if target_idx is not None and target_idx >= MATURITY_INDEX["L2"]:
        if not entry.get("evidence_refs"):
            missing_evidence.append("evidence_refs")
        missing_evidence.extend(missing_refs)
        stale_evidence.extend(stale_refs)
        if missing_refs or not entry.get("evidence_refs"):
            blocking_findings.append(
                finding(cap_id, severity, "missing_evidence", "Operational maturity requires fresh evidence references.")
            )
            required_next_actions.append("Run the relevant validator and add its report path to evidence_refs.")
        if stale_refs:
            blocking_findings.append(
                finding(cap_id, severity, "stale_evidence", "One or more evidence references are older than the configured freshness window.")
            )
            required_next_actions.append("Regenerate stale evidence before reviewing maturity readiness.")

    if target_idx is not None and target_idx >= MATURITY_INDEX["L3"]:
        gate_reports = default_gate_reports(root, naos_root, policy)
        gate_missing = [ref for ref in gate_reports if not path_matches(root, ref)]
        if gate_missing:
            missing_evidence.extend(gate_missing)
            blocking_findings.append(
                finding(cap_id, severity, "missing_gate_evidence", "Enforced maturity requires gate status/evaluation evidence.")
            )
            required_next_actions.append("Run gate status/evaluation before reviewing L3 readiness.")

    if target_idx is not None and target_idx >= MATURITY_INDEX["L4"]:
        dashboard_report = default_dashboard_report(root, naos_root, policy)
        if not path_matches(root, dashboard_report):
            missing_evidence.append(dashboard_report)
            blocking_findings.append(
                finding(cap_id, severity, "missing_dashboard_evidence", "Measured maturity requires dashboard summary evidence.")
            )
            required_next_actions.append("Refresh the NAOS dashboard before reviewing L4 readiness.")

    if target_idx == MATURITY_INDEX["L5"]:
        blocking_findings.append(
            finding(
                cap_id,
                severity,
                "human_review_required",
                "L5 readiness cannot be certified automatically; explicit project governance review is required.",
            )
        )
        required_next_actions.append("Record project governance review before any L5 maturity decision.")

    # CG1: the DECLARED current maturity must itself be evidence-supported. This is
    # distinct from promotion readiness (which concerns moving UP to target). It flags a
    # self-declared current level beyond the scaffold baseline that has no/stale supporting
    # evidence — i.e. a possible false self-promotion. current_maturity is an adopter
    # declaration, not proof. Severity is lattice-aligned (the capability's profile
    # enforcement); it only hard-blocks evaluated_status where that severity is blocking
    # (assured), staying advisory at lower profiles. It does not auto-promote or adjudicate.
    default_idx = maturity_index(contract.get("default_maturity")) or 0
    if current_idx is not None and current_idx >= MATURITY_INDEX["L2"] and current_idx > default_idx:
        if not entry.get("evidence_refs") or missing_refs or stale_refs:
            cg1 = finding(
                cap_id,
                severity,
                "unsupported_current_maturity",
                f"Declared current_maturity {current} is not backed by present, fresh evidence; current_maturity is an adopter declaration, not proof.",
                "current_maturity",
            )
            if severity == "blocking":
                blocking_findings.append(cg1)
            else:
                advisory_findings.append(cg1)
            required_next_actions.append(
                "Add fresh evidence_refs supporting the declared current_maturity, or lower current_maturity to the supported level."
            )

    if waivers:
        advisory_findings.append(
            finding(cap_id, "advisory", "waiver_visible", "Waivers remain visible and do not convert maturity readiness to pass.")
        )

    if blocking_findings:
        evaluated_status = "unknown" if any(item.get("status") == "invalid_maturity" for item in blocking_findings) else blocking_status_for_profile(profile)
    elif advisory_findings:
        evaluated_status = "advisory"
    else:
        evaluated_status = "ready"

    movement_requested = current_idx is not None and target_idx is not None and target_idx > current_idx
    human_approval_required = bool(movement_requested and profile in {"standard", "assured"}) or target == "L5"
    ready_for_promotion = evaluated_status == "ready" and movement_requested and target != "L5"

    # CG2: make the 2-D control lattice (profile severity x maturity) load-bearing.
    # The declared per-profile enforcement only takes effect once the capability has
    # matured to target; below target it downgrades to advisory ("never block a scaffold").
    declared_enforcement = str(contract_profile.get("enforcement") or "advisory")
    effective = effective_enforcement(declared_enforcement, current, target)

    return {
        "capability_id": cap_id,
        "enabled": True,
        "current_maturity": current,
        "target_maturity": target,
        "declared_enforcement": declared_enforcement,
        "effective_enforcement": effective,
        "enforcement_downgraded_by_maturity": effective != declared_enforcement,
        "evaluated_status": evaluated_status,
        "ready_for_promotion": ready_for_promotion,
        "human_approval_required": human_approval_required,
        "promotion_recorded": False,
        "missing_evidence": list(dict.fromkeys(missing_evidence)),
        "stale_evidence": list(dict.fromkeys(stale_evidence)),
        "present_evidence": sorted(set(present_refs)),
        "blocking_findings": blocking_findings,
        "advisory_findings": advisory_findings,
        "waivers": waivers,
        "limitations": limitations,
        "required_next_actions": list(dict.fromkeys(required_next_actions)),
    }


def build_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    state_path: Path,
    capabilities_dir: str | None = None,
) -> dict[str, Any]:
    contracts = load_capability_contracts(root, naos_root, capabilities_dir)
    state_exists = state_path.exists()
    state_data = load_yaml(state_path) if state_exists else {}
    state_entries = normalize_state_entries(state_data)

    capabilities = [
        evaluate_capability(
            root=root,
            naos_root=naos_root,
            profile=profile,
            policy=policy,
            cap_id=cap_id,
            contract=contract,
            entry=state_entries.get(cap_id),
        )
        for cap_id, contract in sorted(contracts.items())
    ]
    findings = [
        finding_item
        for item in capabilities
        for finding_item in (item.get("blocking_findings") or []) + (item.get("advisory_findings") or [])
    ]
    if not state_exists:
        findings.append(
            {
                "id": "capability_state",
                "severity": "advisory" if is_kit_repository(root, naos_root) else severity_for_profile(profile, policy),
                "status": "not_configured",
                "message": f"Adopter capability state file not found: {state_path}",
            }
        )
    summary = finding_counts(findings)
    summary.update(
        {
            "capabilities": len(capabilities),
            "enabled": sum(1 for item in capabilities if item.get("enabled") is True),
            "disabled": sum(1 for item in capabilities if item.get("evaluated_status") == "disabled"),
            "ready": sum(1 for item in capabilities if item.get("evaluated_status") == "ready"),
            "blocked": sum(1 for item in capabilities if item.get("evaluated_status") == "blocked"),
            "advisory_status": sum(1 for item in capabilities if item.get("evaluated_status") == "advisory"),
            "not_configured": sum(1 for item in capabilities if item.get("evaluated_status") == "not_configured"),
            "unknown": sum(1 for item in capabilities if item.get("evaluated_status") == "unknown"),
            "ready_for_promotion": sum(1 for item in capabilities if item.get("ready_for_promotion")),
            "human_approval_required": sum(1 for item in capabilities if item.get("human_approval_required")),
            "promotion_recorded": 0,
            "waivers": sum(len(item.get("waivers") or []) for item in capabilities),
        }
    )
    policy_meta = policy.get("_meta", {})
    return {
        "schema": "naos.capability_maturity.v1",
        "generated_at": utc_now_text(),
        "profile": profile,
        "naos_root": naos_root,
        "project_root": str(root),
        "state": {
            "path": str(state_path),
            "exists": state_exists,
            "source": "project" if state_exists else "missing",
        },
        "policy": {
            "version": policy.get("version"),
            "source": policy_meta.get("source"),
            "path": policy_meta.get("path"),
        },
        "semantics": {
            "state": "Adopter declaration; not proof by itself.",
            "report": "NAOS evaluates maturity readiness from declared state and file-first evidence.",
            "promotion": "NAOS does not automatically promote, certify, or approve maturity. Final maturity decisions remain project governance decisions.",
            "flow": "declare -> evaluate -> report -> review -> approve -> mature",
        },
        "status": status_from_counts(summary),
        "summary": summary,
        "related_evidence": {
            "systemic_impact_review": related_systemic_impact_evidence(root, naos_root, policy),
            "module_header_traceability": related_module_header_evidence(root, naos_root, policy),
            "spec_pack_contract": related_spec_pack_contract_evidence(root, naos_root, policy),
            "spec_cascade_coherence": related_spec_cascade_evidence(root, naos_root, policy),
            "control_plane_review": related_control_plane_review_evidence(root, naos_root, policy),
            "setup_recommendations": related_setup_recommendations_evidence(root, naos_root, policy),
            "governance_bypass_posture": related_governance_bypass_posture_evidence(root, naos_root, policy),
            "external_evidence_ingest": related_external_evidence_ingest_evidence(root, naos_root, policy),
            "evidence_attestation": related_evidence_attestation_evidence(root, naos_root, policy),
            "evidence_conflicts": related_evidence_conflict_detection_evidence(root, naos_root, policy),
            "task_claims": related_task_claim_evidence(root, naos_root, policy),
            "memory_context_readiness": related_memory_context_evidence(root, naos_root, policy),
            "memory_provider_access": related_memory_provider_access_evidence(root, naos_root, policy),
            "memory_use_policy": related_memory_use_policy_evidence(root, naos_root, policy),
            "task_context_pack": related_task_context_pack_evidence(root, naos_root, policy),
            "local_context_index": related_local_context_index_evidence(root, naos_root, policy),
            "sqlite_write_coordination": related_sqlite_write_coordination_evidence(root, naos_root, policy),
            "local_context_query": related_local_context_query_evidence(root, naos_root, policy),
            "semantic_candidate_layer": related_semantic_candidate_layer_evidence(root, naos_root, policy),
            "graph_context_readiness": related_graph_context_evidence(root, naos_root, policy),
            "graph_context_query": related_graph_context_query_evidence(root, naos_root, policy),
            "session_identity": related_session_identity_evidence(root, naos_root, policy),
            "operator_attribution": related_operator_attribution_evidence(root, naos_root, policy),
            "session_lifecycle": related_session_lifecycle_evidence(root, naos_root, policy),
            "audit_log": related_audit_log_evidence(root, naos_root, policy),
            "agent_trace_validation": related_agent_trace_validation_evidence(root, naos_root, policy),
            "static_grader": related_static_grader_evidence(root, naos_root, policy),
            "grader_assessment": related_grader_assessment_evidence(root, naos_root, policy),
            "llm_grader_readiness": related_llm_grader_readiness_evidence(root, naos_root, policy),
            "behavioral_governance_readiness": related_behavioral_governance_readiness_evidence(root, naos_root, policy),
            "policy_overrides": related_policy_override_evidence(root, naos_root, policy),
            "pr_governance": related_pr_governance_evidence(root, naos_root, policy),
            "agentic_workflow": related_agentic_workflow_evidence(root, naos_root, policy),
            "pre_implementation_alignment": related_pre_implementation_alignment_evidence(root, naos_root, policy),
            "calibration_shadow": related_calibration_shadow_evidence(root, naos_root, policy),
            "evidence_classification": related_evidence_classification_evidence(root, naos_root, policy),
            "cross_harness_review_readiness": related_cross_harness_review_readiness_evidence(root, naos_root, policy),
        },
        "capabilities": capabilities,
        "findings": findings,
        "limitations": [
            "Maturity readiness evaluation is deterministic and file-first.",
            "State declarations are not proof by themselves.",
            "Ready status means evidence appears sufficient for review; it is not approval or certification.",
            "Standard and assured maturity movement requires project governance review.",
            "L5 readiness cannot be fully automated by the kit.",
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate NAOS capability maturity readiness.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--state", help="Path to adopter capability_state.yaml.")
    parser.add_argument("--capabilities-dir")
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
    state_path = resolve_state_path(root, naos_root, policy, args.state)
    report = build_report(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        state_path=state_path,
        capabilities_dir=args.capabilities_dir,
    )
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "capability_maturity_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        destination = str(output) if output else "stdout only"
        print(
            "NAOS capability maturity readiness: "
            f"{report['status']} "
            f"({report['summary']['ready']} ready, "
            f"{report['summary']['blocked']} blocked, "
            f"{report['summary']['not_configured']} not configured, "
            f"output: {destination})"
        )
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
