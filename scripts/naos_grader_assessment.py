#!/usr/bin/env python3
"""Build deterministic NAOS grader assessment reports for audit/drift/assess modes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
AUTORESEARCH_PARENT = ROOT_DIR / ".github"
for candidate in (SCRIPT_DIR, ROOT_DIR, AUTORESEARCH_PARENT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

import naos_static_grader as static_runner  # noqa: E402
from naos_policy import (  # noqa: E402
    controlled_now_utc,
    controlled_utc_now_text,
    default_naos_root,
    exit_code_for_summary,
    load_policy,
    normalize_profile,
    report_default_path,
    report_output_path,
    write_report,
)


REPORT_SCHEMA = "naos.grader_assessment.v1"
RUNNER_NAME = "NAOS deterministic grader assessment"
RUNNER_VERSION = "1.0.0"
MODES = ("audit", "drift", "assess")
DEFAULT_CONFIG = {
    "max_runs_per_day": None,
    "cadence": "on_demand",
    "max_cost_usd": 0.0,
    "llm_runtime_enabled": False,
    "provider_allowed": False,
    "manual_approval_required": True,
    "data_exposure_level": "repo_metadata_only",
    "audit_window": "current_project_state",
    "baseline_reference": "naos/reports/grader_assessment_baseline.json",
}
RESIDUAL_RISKS = [
    "static_grading_does_not_prove_behavior",
    "declared_traces_may_be_incomplete",
    "stale_baselines_may_mislead",
    "drift_mode_does_not_infer_semantic_drift",
    "assess_mode_is_not_certification",
    "composite_summary_may_hide_detail_without_review",
    "human_review_required",
    "future_llm_judge_bias_and_cost_risk",
]
LIMITATIONS = [
    "Audit mode is deterministic review input, not audit approval or certification.",
    "Drift mode compares deterministic report metadata; it does not infer semantic drift.",
    "Assess mode summarizes posture only and does not approve work.",
    "Only StaticGrader is used at runtime; LLMGrader remains disabled and unimplemented.",
]
NOT_CLAIMED = [
    "audit approval",
    "certification",
    "attestation",
    "maturity promotion",
    "behavioral compliance determination",
    "semantic drift inference",
    "behavioral safety proof",
    "semantic correctness proof",
    "runtime behavior proof",
    "hallucination prevention",
    "LLMGrader runtime",
    "model/API/provider call",
]


def utc_now_text() -> str:
    return controlled_utc_now_text()


def canonical_hash(data: Any) -> str:
    payload = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def file_hash(path: Path) -> str | None:
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json_report(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def load_autoresearch_config(root: Path) -> tuple[dict[str, Any], Path, bool]:
    candidates = [
        root / ".github" / "configs" / "naos_autoresearch.yaml",
        root / "configs" / "naos_autoresearch.yaml",
        root / "templates" / "structural-seeds" / "configs" / "naos_autoresearch.yaml",
        ROOT_DIR / "templates" / "structural-seeds" / "configs" / "naos_autoresearch.yaml",
    ]
    for path in candidates:
        if not path.exists():
            continue
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            return dict(DEFAULT_CONFIG), path, False
        config = data.get("grader_assessment") if isinstance(data, dict) else {}
        if not isinstance(config, dict):
            config = {}
        merged = {**DEFAULT_CONFIG, **config}
        return merged, path, True
    return dict(DEFAULT_CONFIG), root / ".github" / "configs" / "naos_autoresearch.yaml", False


def assessment_finding(
    *,
    finding_id: str,
    severity: str,
    status: str,
    message: str,
    source: str,
    deterministic: bool = True,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "status": status,
        "message": message,
        "source": source,
        "control_type": "grader_assessment",
        "authority_layer": "deterministic_primary" if deterministic else "readiness_only",
        "human_review_required": True,
        "not_claimed": ["approval", "certification", "compliance determination"],
    }


def severity_for_profile(profile: str, advisory: bool = False) -> str:
    if advisory:
        return "advisory"
    return {"quickstart": "advisory", "lite": "warning", "standard": "required", "assured": "blocking"}.get(profile, "advisory")


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "blocking": sum(1 for item in findings if item.get("severity") == "blocking"),
        "required": sum(1 for item in findings if item.get("severity") == "required"),
        "warnings": sum(1 for item in findings if item.get("severity") == "warning"),
        "advisory": sum(1 for item in findings if item.get("severity") == "advisory"),
        "total_findings": len(findings),
    }


def status_from_findings(mode: str, profile: str, findings: list[dict[str, Any]], drift_status: str | None = None) -> str:
    statuses = {str(item.get("status")) for item in findings}
    if mode == "drift":
        if "missing_baseline" in statuses:
            return "missing_baseline"
        if "invalid_baseline" in statuses:
            return "invalid_baseline"
        if drift_status in {"drift_detected", "no_drift_detected", "stale_baseline"}:
            return drift_status
    if "missing_trace_input" in statuses:
        return "missing_trace" if profile in {"standard", "assured"} else "advisory"
    if "missing_static_grader_report" in statuses:
        return "missing_static_grader_report" if profile in {"standard", "assured"} else "advisory"
    if any(item.get("severity") == "blocking" for item in findings):
        return "blocked"
    if any(item.get("severity") in {"required", "warning"} for item in findings):
        return "review_required"
    if findings:
        return "advisory"
    return "ready"


def static_grader_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    static_report_path: Path,
    trace_report_path: Path,
    trace_file_path: Path,
) -> tuple[dict[str, Any], bool]:
    static_report = load_json_report(static_report_path)
    if static_report is not None:
        return static_report, True
    report = static_runner.build_report(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        trace_report_path=trace_report_path,
        trace_file_path=trace_file_path,
    )
    return report, False


def load_conformance(root: Path) -> tuple[dict[str, Any] | None, Path]:
    path = root / "naos" / "reports" / "conformance_latest.json"
    return load_json_report(path), path


def dimension_map(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    dimensions = report.get("dimensions") or []
    if not isinstance(dimensions, list):
        return {}
    mapped: dict[str, dict[str, Any]] = {}
    for item in dimensions:
        if isinstance(item, dict) and item.get("dimension_id"):
            mapped[str(item["dimension_id"])] = item
    return mapped


def finding_key(item: dict[str, Any]) -> str:
    payload = {
        "id": item.get("id"),
        "status": item.get("status"),
        "dimension_id": item.get("dimension_id"),
        "message": item.get("message"),
        "source": item.get("source"),
    }
    return canonical_hash(payload)


def summarize_finding(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "status": item.get("status"),
        "severity": item.get("severity"),
        "dimension_id": item.get("dimension_id"),
        "message": item.get("message"),
        "source": item.get("source"),
    }


def is_stale(generated_at: str | None, days: int = 30) -> bool:
    if not generated_at:
        return False
    try:
        text = generated_at.replace("Z", "+00:00")
        timestamp = datetime.fromisoformat(text)
    except Exception:
        return False
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return (controlled_now_utc() - timestamp).days > days


def build_drift(
    *,
    baseline_path: Path | None,
    current_report: dict[str, Any],
    current_hash: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], str | None]:
    drift = {
        "baseline_report_path": str(baseline_path) if baseline_path else None,
        "baseline_hash": None,
        "current_report_hash": current_hash,
        "baseline_generated_at": None,
        "current_generated_at": current_report.get("generated_at"),
        "changed_dimensions": [],
        "new_findings": [],
        "resolved_findings": [],
        "unchanged_findings": [],
        "stale_baseline_warning": False,
        "no_semantic_drift_inferred": True,
    }
    findings: list[dict[str, Any]] = []
    if baseline_path is None:
        findings.append(
            assessment_finding(
                finding_id="GRADER_ASSESSMENT_MISSING_BASELINE",
                severity="advisory",
                status="missing_baseline",
                message="Drift mode needs a declared baseline report path; no semantic or behavioral drift is inferred.",
                source="grader_assessment",
            )
        )
        return drift, findings, None
    baseline = load_json_report(baseline_path)
    if baseline is None:
        findings.append(
            assessment_finding(
                finding_id="GRADER_ASSESSMENT_INVALID_BASELINE",
                severity="warning",
                status="invalid_baseline",
                message="Baseline report is missing or not valid JSON; drift comparison remains unavailable.",
                source=str(baseline_path),
            )
        )
        return drift, findings, None

    baseline_static = baseline.get("static_grader") if baseline.get("schema") == REPORT_SCHEMA else baseline
    if isinstance(baseline_static, dict) and isinstance(baseline_static.get("report"), dict):
        baseline_static = baseline_static["report"]
    if not isinstance(baseline_static, dict):
        baseline_static = baseline

    baseline_generated_at = baseline_static.get("generated_at") or baseline.get("generated_at")
    drift["baseline_hash"] = file_hash(baseline_path) or canonical_hash(baseline)
    drift["baseline_generated_at"] = baseline_generated_at
    if is_stale(str(baseline_generated_at) if baseline_generated_at else None):
        drift["stale_baseline_warning"] = True
        findings.append(
            assessment_finding(
                finding_id="GRADER_ASSESSMENT_STALE_BASELINE",
                severity="advisory",
                status="stale_baseline",
                message="Baseline report is older than the freshness window; human review should confirm whether it is still useful.",
                source=str(baseline_path),
            )
        )

    current_dims = dimension_map(current_report)
    baseline_dims = dimension_map(baseline_static)
    for dimension_id in sorted(set(current_dims) | set(baseline_dims)):
        current = current_dims.get(dimension_id, {})
        previous = baseline_dims.get(dimension_id, {})
        if current.get("status") != previous.get("status") or current.get("passed") != previous.get("passed"):
            drift["changed_dimensions"].append(
                {
                    "dimension_id": dimension_id,
                    "baseline_status": previous.get("status"),
                    "current_status": current.get("status"),
                    "baseline_passed": previous.get("passed"),
                    "current_passed": current.get("passed"),
                }
            )

    current_findings = {finding_key(item): summarize_finding(item) for item in current_report.get("findings") or [] if isinstance(item, dict)}
    baseline_findings = {finding_key(item): summarize_finding(item) for item in baseline_static.get("findings") or [] if isinstance(item, dict)}
    drift["new_findings"] = [current_findings[key] for key in sorted(set(current_findings) - set(baseline_findings))]
    drift["resolved_findings"] = [baseline_findings[key] for key in sorted(set(baseline_findings) - set(current_findings))]
    drift["unchanged_findings"] = [current_findings[key] for key in sorted(set(current_findings) & set(baseline_findings))]

    if drift["changed_dimensions"] or drift["new_findings"] or drift["resolved_findings"]:
        findings.append(
            assessment_finding(
                finding_id="GRADER_ASSESSMENT_DETERMINISTIC_DRIFT",
                severity="warning",
                status="deterministic_drift_detected",
                message="Deterministic report differences were found against the declared baseline; this is not semantic drift inference.",
                source=str(baseline_path),
            )
        )
        return drift, findings, "drift_detected"
    return drift, findings, "stale_baseline" if drift["stale_baseline_warning"] else "no_drift_detected"


def cost_posture(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "cost_usd": 0.0,
        "cost_incurred_by_default": False,
        "external_api_required": False,
        "provider_allowed": False,
        "provider_dependency_required": False,
        "model_dependency_required": False,
        "llm_runtime_enabled": False,
        "max_cost_usd": config.get("max_cost_usd"),
        "max_runs_per_day": config.get("max_runs_per_day"),
        "cadence": config.get("cadence"),
        "manual_approval_required": True,
        "human_approval_required_before_cost": True,
        "data_exposure_level": config.get("data_exposure_level"),
        "audit_window": config.get("audit_window"),
        "baseline_reference": config.get("baseline_reference"),
    }


def llm_readiness_report(root: Path, naos_root: str, policy: dict[str, Any]) -> tuple[dict[str, Any], Path, bool]:
    path = report_default_path(root, naos_root, policy, "llm_grader_readiness_report")
    data = load_json_report(path)
    if data is not None:
        return data, path, True
    return (
        {
            "schema": "naos.llm_grader_readiness.v1",
            "status": "not_configured",
            "runtime_enabled": False,
            "provider_allowed": False,
            "external_api_allowed": False,
            "model_dependency_allowed": False,
            "api_keys_allowed": False,
            "cost_posture": {
                "cost_usd": 0.0,
                "cost_incurred_by_default": False,
                "external_api_required": False,
                "provider_dependency_required": False,
                "model_dependency_required": False,
                "cost_budget_required_if_enabled_later": True,
                "human_approval_required_before_cost": True,
                "max_cost_usd": None,
                "max_runs_per_day": None,
            },
            "summary": {"total_findings": 0},
            "findings": [],
            "not_claimed": ["LLMGrader runtime", "approval", "certification", "compliance determination", "maturity promotion"],
            "human_review_required": True,
        },
        path,
        False,
    )


def build_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    mode: str,
    static_report_path: Path,
    trace_report_path: Path,
    trace_file_path: Path,
    baseline_path: Path | None,
) -> dict[str, Any]:
    config, config_path, config_present = load_autoresearch_config(root)
    static_report, static_report_present = static_grader_report(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        static_report_path=static_report_path,
        trace_report_path=trace_report_path,
        trace_file_path=trace_file_path,
    )
    conformance, conformance_path = load_conformance(root)
    llm_readiness, llm_readiness_path, llm_readiness_present = llm_readiness_report(root, naos_root, policy)
    findings: list[dict[str, Any]] = []
    advisory_findings: list[dict[str, Any]] = []
    severity = severity_for_profile(profile)

    if not static_report_present:
        findings.append(
            assessment_finding(
                finding_id="GRADER_ASSESSMENT_MISSING_STATIC_GRADER_REPORT",
                severity=severity if profile in {"standard", "assured"} else "advisory",
                status="missing_static_grader_report",
                message="StaticGrader report was not present on disk; assessment used an in-memory deterministic StaticGrader result.",
                source=str(static_report_path),
            )
        )
    if not (trace_report_path.exists() or trace_file_path.exists()):
        findings.append(
            assessment_finding(
                finding_id="GRADER_ASSESSMENT_MISSING_TRACE",
                severity=severity if profile in {"standard", "assured"} else "advisory",
                status="missing_trace",
                message="No trace validation report or trace file is present; structural grading coverage is limited.",
                source=str(trace_report_path),
            )
        )
    if not config_present:
        advisory_findings.append(
            assessment_finding(
                finding_id="GRADER_ASSESSMENT_COST_CADENCE_CONFIG_MISSING",
                severity="advisory",
                status="cost_cadence_policy_missing",
                message="Autoresearch cost/cadence config was not found; zero-cost defaults are used for assessment posture.",
                source=str(config_path),
                deterministic=False,
            )
        )
    if config.get("llm_runtime_enabled") is not False or config.get("provider_allowed") is not False:
        findings.append(
            assessment_finding(
                finding_id="GRADER_ASSESSMENT_LLM_RUNTIME_UNEXPECTED",
                severity="blocking",
                status="llm_runtime_unexpectedly_enabled",
                message="Grader assessment v1 requires LLM runtime and provider access to remain disabled.",
                source=str(config_path),
            )
        )

    static_findings = [item for item in static_report.get("findings") or [] if isinstance(item, dict)]
    ai_surface_health = static_report.get("ai_surface_health_posture") if isinstance(static_report.get("ai_surface_health_posture"), dict) else {
        "status": "missing",
        "ai_surface_health_posture": "missing",
        "context_budget_posture": "missing",
        "source_report_present": False,
        "can_change_behavioral_scores": False,
    }
    deterministic_findings = static_findings + findings
    current_hash = canonical_hash(static_report)
    drift, drift_findings, drift_status = build_drift(
        baseline_path=baseline_path,
        current_report=static_report,
        current_hash=current_hash,
    ) if mode == "drift" else (
        {
            "baseline_report_path": str(baseline_path) if baseline_path else None,
            "baseline_hash": None,
            "current_report_hash": current_hash,
            "baseline_generated_at": None,
            "current_generated_at": static_report.get("generated_at"),
            "changed_dimensions": [],
            "new_findings": [],
            "resolved_findings": [],
            "unchanged_findings": [],
            "stale_baseline_warning": False,
            "no_semantic_drift_inferred": True,
        },
        [],
        None,
    )
    deterministic_findings.extend(drift_findings)

    all_findings = deterministic_findings + advisory_findings
    summary = summarize_findings(all_findings)
    status = status_from_findings(mode, profile, all_findings, drift_status)
    posture = cost_posture(config)
    input_reports = [
        {
            "id": "static_grader_report",
            "path": str(static_report_path),
            "present": static_report_present,
            "status": static_report.get("status"),
            "schema": static_report.get("schema"),
            "generated_at": static_report.get("generated_at"),
            "findings_count": len(static_findings),
        },
        {
            "id": "ai_surface_context_budget_report",
            "path": str(report_default_path(root, naos_root, policy, "ai_surface_context_budget_report")),
            "present": bool(ai_surface_health.get("source_report_present")),
            "status": ai_surface_health.get("status"),
            "schema": "naos.ai_surface_context_budget.v1" if ai_surface_health.get("source_report_present") else None,
            "generated_at": None,
            "findings_count": int(ai_surface_health.get("findings_count") or 0),
        },
        {
            "id": "agent_trace_validation_report",
            "path": str(trace_report_path),
            "present": trace_report_path.exists(),
            "status": None,
            "schema": None,
            "generated_at": None,
            "findings_count": 0,
        },
        {
            "id": "conformance_latest",
            "path": str(conformance_path),
            "present": conformance is not None,
            "status": conformance.get("mode") if conformance else None,
            "schema": None,
            "generated_at": conformance.get("run_date") if conformance else None,
            "findings_count": 0,
        },
        {
            "id": "autoresearch_config",
            "path": str(config_path),
            "present": config_present,
            "status": "ready" if config_present else "not_configured",
            "schema": None,
            "generated_at": None,
            "findings_count": 0,
        },
        {
            "id": "llm_grader_readiness_report",
            "path": str(llm_readiness_path),
            "present": llm_readiness_present,
            "status": llm_readiness.get("status"),
            "schema": llm_readiness.get("schema"),
            "generated_at": llm_readiness.get("generated_at"),
            "findings_count": len([item for item in llm_readiness.get("findings") or [] if isinstance(item, dict)]),
        },
    ]
    if baseline_path:
        input_reports.append(
            {
                "id": "grader_assessment_baseline",
                "path": str(baseline_path),
                "present": baseline_path.exists(),
                "status": drift_status,
                "schema": None,
                "generated_at": drift.get("baseline_generated_at"),
                "findings_count": len(drift.get("unchanged_findings") or []) + len(drift.get("resolved_findings") or []),
            }
        )

    return {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": status,
        "mode": mode,
        "naos_root": naos_root,
        "project_root": str(root),
        "runner": RUNNER_NAME,
        "runner_version": RUNNER_VERSION,
        "static_grader": {
            "path": str(static_report_path),
            "present": static_report_present,
            "generated_in_memory": not static_report_present,
            "report": static_report,
            "status": static_report.get("status"),
            "generated_at": static_report.get("generated_at"),
            "grader": static_report.get("grader"),
            "grader_version": static_report.get("grader_version"),
            "dimension_summary": static_report.get("dimension_summary") or {},
            "findings_count": len(static_findings),
        },
        "conformance": {
            "path": str(conformance_path),
            "present": conformance is not None,
            "mode": conformance.get("mode") if conformance else None,
            "run_date": conformance.get("run_date") if conformance else None,
            "overall_conformance": conformance.get("overall_conformance") if conformance else None,
            "cost_usd": conformance.get("cost_usd") if conformance else None,
        },
        "deterministic_results": static_report.get("deterministic_results") or [],
        "advisory_results": [
            {
                "id": "llm_readiness",
                "status": llm_readiness.get("status") or "not_configured",
                "authority_layer": "readiness_only",
                "human_review_required": True,
                "runtime_enabled": bool(llm_readiness.get("runtime_enabled")),
                "provider_allowed": bool(llm_readiness.get("provider_allowed")),
                "not_claimed": ["approval", "certification", "compliance determination", "runtime grading"],
            }
        ],
        "not_evaluated_dimensions": static_report.get("not_evaluated_dimensions") or [],
        "llm_readiness": {
            "source_report_path": str(llm_readiness_path),
            "source_report_present": llm_readiness_present,
            "status": llm_readiness.get("status") or "not_configured",
            "runtime_enabled": bool(llm_readiness.get("runtime_enabled")),
            "provider_allowed": bool(llm_readiness.get("provider_allowed")),
            "external_api_allowed": bool(llm_readiness.get("external_api_allowed")),
            "model_dependency_allowed": bool(llm_readiness.get("model_dependency_allowed")),
            "api_keys_allowed": bool(llm_readiness.get("api_keys_allowed")),
            "provider_dependency_required": bool((llm_readiness.get("cost_posture") or {}).get("provider_dependency_required", False)),
            "model_dependency_required": bool((llm_readiness.get("cost_posture") or {}).get("model_dependency_required", False)),
            "external_api_required": bool((llm_readiness.get("cost_posture") or {}).get("external_api_required", False)),
            "cost_posture": llm_readiness.get("cost_posture") or {},
            "findings_count": len([item for item in llm_readiness.get("findings") or [] if isinstance(item, dict)]),
            "cost_incurred_by_default": False,
            "future_enablement_requires": [
                "provider and model declaration",
                "prompt and rubric version",
                "cost budget",
                "data exposure classification",
                "residual risk declaration",
                "human approval",
            ],
            "future_output_authority": "advisory_only",
            "static_grader_remains_primary": True,
        },
        "ai_surface_health_posture": {
            **ai_surface_health,
            "baseline_interpretation_only": True,
            "can_change_behavioral_scores": False,
            "can_auto_tune_thresholds": False,
            "human_review_required_before_baseline_change": True,
            "not_claimed": ["behavioral score", "automatic threshold tuning", "baseline approval"],
        },
        "drift": drift,
        "cost_budget_posture": posture,
        "cadence_posture": {
            "max_runs_per_day": posture["max_runs_per_day"],
            "cadence": posture["cadence"],
            "audit_window": posture["audit_window"],
            "baseline_reference": posture["baseline_reference"],
            "missing_policy_fields": [
                key for key in ("max_runs_per_day", "cadence", "max_cost_usd", "baseline_reference") if config.get(key) in (None, "")
            ],
        },
        "input_reports": input_reports,
        "baseline": {
            "path": str(baseline_path) if baseline_path else None,
            "present": bool(baseline_path and baseline_path.exists()),
            "hash": drift.get("baseline_hash"),
            "generated_at": drift.get("baseline_generated_at"),
        },
        "current": {
            "static_grader_report_path": str(static_report_path),
            "static_grader_report_present": static_report_present,
            "hash": current_hash,
            "generated_at": static_report.get("generated_at"),
        },
        "dimensions": static_report.get("dimensions") or [],
        "dimension_summary": static_report.get("dimension_summary") or {},
        "findings": all_findings,
        "known_gaps": [
            "LLMGrader readiness remains metadata only; runtime is deferred to a future group.",
            "Drift mode compares deterministic report fields only and does not infer semantic or behavioral drift.",
        ],
        "residual_risks": RESIDUAL_RISKS,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": True,
        "summary": {
            **summary,
            "mode": mode,
            "status": status,
            "static_grader_status": static_report.get("status"),
            "deterministic_findings": len(deterministic_findings),
            "advisory_findings": len(advisory_findings),
            "dimensions": len(static_report.get("dimensions") or []),
            "not_evaluated_dimensions": len(static_report.get("not_evaluated_dimensions") or []),
            "changed_dimensions": len(drift.get("changed_dimensions") or []),
            "new_findings": len(drift.get("new_findings") or []),
            "resolved_findings": len(drift.get("resolved_findings") or []),
            "cost_usd": 0.0,
            "llm_runtime_enabled": False,
            "ai_surface_health_posture": ai_surface_health.get("ai_surface_health_posture"),
            "no_semantic_drift_inferred": drift["no_semantic_drift_inferred"],
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build deterministic NAOS grader assessment reports.")
    parser.add_argument("--mode", choices=MODES, default="audit")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--trace-report", help="Agent trace validation report path.")
    parser.add_argument("--trace-file", help="Agent trace YAML path.")
    parser.add_argument("--static-grader-report", help="StaticGrader report path.")
    parser.add_argument("--baseline", help="Baseline report path for drift mode.")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.project_root).resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    trace_report_path = Path(args.trace_report) if args.trace_report else report_default_path(root, naos_root, policy, "agent_trace_validation_report")
    trace_file_path = Path(args.trace_file) if args.trace_file else root / naos_root / str(policy.get("paths", {}).get("agent_trace_events") or "agent_trace_events.yaml")
    static_report_path = Path(args.static_grader_report) if args.static_grader_report else report_default_path(root, naos_root, policy, "static_grader_report")
    baseline_path = Path(args.baseline) if args.baseline else None
    report = build_report(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        mode=args.mode,
        static_report_path=static_report_path,
        trace_report_path=trace_report_path,
        trace_file_path=trace_file_path,
        baseline_path=baseline_path,
    )
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "grader_assessment_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        destination = str(output) if output else "(not written in kit source tree)"
        print(
            "NAOS grader assessment: "
            f"{report['status']} mode={args.mode} "
            f"({report['summary']['total_findings']} findings, cost_usd=0.0) -> {destination}"
        )
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    sys.exit(main())
