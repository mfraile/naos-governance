#!/usr/bin/env python3
"""Export structured NAOS findings to SARIF 2.1.0 without changing authority."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from naos_policy import (  # noqa: E402
    default_naos_root,
    is_kit_repository,
    load_policy,
    normalize_profile,
    report_output_path,
    safe_policy_path,
    write_report,
)


SARIF_VERSION = "2.1.0"
SUMMARY_SCHEMA = "naos.sarif_export.v1"
TOOL_NAME = "NAOS"
TOOL_URI = "https://github.com/mfraile/naos-governance"

NOT_CLAIMED = [
    "SARIF findings are not approvals.",
    "SARIF findings are not certification or compliance proof.",
    "SARIF findings are not source-of-truth authority.",
    "SARIF upload is not attestation.",
    "Advisory findings cannot promote maturity or block without deterministic support and human review.",
]

LIMITATIONS = [
    "The exporter reads structured NAOS reports and does not scrape free-text validator output aggressively.",
    "Generated runtime reports are optional adopter artifacts and are not required in the kit repository.",
    "SARIF consumers may display severity differently from NAOS profile severity.",
    "Human review remains required for durable decisions, approvals, waivers, and maturity changes.",
]

UNSUPPORTED_STRUCTURED_SOURCES = [
    {
        "id": "docs_consistency_validator",
        "command": "python scripts/validators/validate_docs_consistency.py",
        "reason": "Validator is pass/fail text output and does not emit a structured findings report yet.",
    },
    {
        "id": "tutorial_consistency_validator",
        "command": "python scripts/validators/validate_tutorial_consistency.py",
        "reason": "Validator is pass/fail text output and does not emit a structured findings report yet.",
    },
    {
        "id": "implementation_reality_validator",
        "command": "python scripts/validators/validate_implementation_reality.py",
        "reason": "Validator is pass/fail text output and does not emit a structured findings report yet.",
    },
]


@dataclass(frozen=True)
class SourceDef:
    id: str
    label: str
    path_key: str | None
    control_type: str
    authority_layer: str
    advisory: bool = False
    naos_relative: bool = False


DETERMINISTIC_SOURCES = [
    SourceDef("capability_contracts", "Capability Contract Validator", None, "contract_validation", "deterministic_primary"),
    SourceDef("self_check", "Self Check", "self_check_report", "self_conformance", "deterministic_primary"),
    SourceDef("gate_evaluation", "Gate Evaluation", "gate_evaluation_report", "gate_evaluation", "deterministic_primary"),
    SourceDef("module_header_traceability", "Module Header Traceability", "module_header_traceability_report", "traceability", "deterministic_primary"),
    SourceDef("spec_pack_contract", "Spec-Pack Contract", "spec_pack_contract_report", "traceability", "deterministic_primary"),
    SourceDef("spec_pack_materialization", "Spec-Pack Materialization", "spec_pack_materialization_report", "traceability", "deterministic_primary"),
    SourceDef("spec_assembly_worksheet", "Spec Assembly Worksheet", "spec_assembly_worksheet_report", "traceability", "deterministic_primary"),
    SourceDef("spec_cascade_coherence", "Spec Cascade Coherence", "spec_cascade_report", "traceability", "deterministic_primary"),
    SourceDef("function_index_health", "Function-Index Health", "function_index_report", "index_health", "deterministic_primary"),
    SourceDef("test_evidence_health", "Test Evidence Health", "test_evidence_report", "test_evidence", "deterministic_primary"),
    SourceDef("duplicate_function_hygiene", "Duplicate Function Hygiene", "duplicate_function_hygiene_report", "code_hygiene", "deterministic_primary"),
    SourceDef("secret_hygiene", "Secret Hygiene", "secret_hygiene_report", "code_hygiene", "deterministic_primary"),
    SourceDef("test_quality_hygiene", "Test Quality Hygiene", "test_quality_hygiene_report", "test_evidence", "deterministic_primary"),
    SourceDef("dependency_integrity", "Dependency Integrity", "dependency_integrity_report", "code_hygiene", "deterministic_primary"),
    SourceDef("package_reality", "Package Reality", "package_reality_report", "code_hygiene", "deterministic_primary"),
    SourceDef("source_to_test_map", "Source-to-Test Map", "source_to_test_map", "test_evidence", "deterministic_primary", naos_relative=True),
    SourceDef("evidence_attestation", "Evidence Attestation", "evidence_attestation_report", "evidence_integrity", "deterministic_primary"),
    SourceDef("evidence_verification", "Evidence Verification", "evidence_verification_report", "evidence_integrity", "deterministic_primary"),
    SourceDef("evidence_conflicts", "Evidence Conflict Detection", "evidence_conflict_detection_report", "evidence_conflicts", "deterministic_primary"),
    SourceDef("task_claims", "Task Claims", "task_claim_report", "task_claims", "deterministic_primary"),
    SourceDef("claims_validation", "Claims Validation", "claims_report", "claims_validation", "deterministic_primary"),
    SourceDef("agent_trace_validation", "Agent Trace Validation", "agent_trace_validation_report", "agent_trace_validation", "deterministic_primary"),
    SourceDef("ai_surface_context_budget", "AI Surface Context Budget", "ai_surface_context_budget_report", "ai_surface_health", "deterministic_primary"),
    SourceDef("session_identity", "Session Identity", "session_identity_report", "session_identity", "deterministic_primary"),
    SourceDef("operator_attribution", "Operator Attribution", "operator_attribution_report", "operator_attribution", "deterministic_primary"),
    SourceDef("sqlite_write_coordination", "SQLite Write Coordination", "sqlite_write_coordination_report", "sqlite_write_coordination", "deterministic_primary"),
    SourceDef("audit_log", "Append-Only Audit Log", "audit_log_summary_report", "audit_log", "deterministic_primary"),
    SourceDef("policy_overrides", "Policy Overrides", "policy_override_merge_report", "policy_overrides", "deterministic_primary"),
    SourceDef("plan_coherence", "Plan Coherence", "plan_coherence_report", "plan_coherence", "deterministic_primary"),
    SourceDef("governance_bypass_posture", "Governance Bypass Posture", "governance_bypass_posture_report", "governance_bypass", "deterministic_primary"),
    SourceDef("pr_risk_classification", "PR Risk Classification", "pr_risk_classification_report", "pr_risk_classification", "deterministic_primary"),
    SourceDef("pr_governance_summary", "PR Governance Summary", "pr_governance_summary_report", "pr_time_ci", "deterministic_primary"),
    SourceDef("agentic_workflow_review", "Agentic Workflow Review", "agentic_workflow_review_report", "agentic_workflow", "deterministic_primary"),
    SourceDef("pre_implementation_alignment_review", "Pre-Implementation Alignment Review", "pre_implementation_alignment_review_report", "pre_implementation_alignment", "deterministic_primary"),
    SourceDef("calibration_shadow", "Calibration Shadow", "calibration_shadow_report", "calibration_shadow", "deterministic_primary"),
    SourceDef("evidence_classification", "Evidence Classification", "evidence_classification_report", "evidence_classification", "deterministic_primary"),
    SourceDef("failure_mode_observations", "Failure-Mode Observations", "failure_mode_observations_report", "failure_mode_observations", "deterministic_primary"),
    SourceDef("cross_harness_review_readiness", "Cross-Harness Review Readiness", "cross_harness_review_readiness_report", "cross_harness_review_readiness", "readiness_only"),
    SourceDef("static_grader", "StaticGrader", "static_grader_report", "static_grader", "deterministic_primary"),
    SourceDef("grader_assessment", "Grader Assessment", "grader_assessment_report", "grader_assessment", "deterministic_primary"),
    SourceDef("llm_grader_readiness", "LLMGrader Readiness", "llm_grader_readiness_report", "llm_grader_readiness", "readiness_only"),
    SourceDef("behavioral_governance_readiness", "Behavioral Governance Readiness", "behavioral_governance_readiness_report", "behavioral_governance_readiness", "readiness_only"),
]

ADVISORY_SOURCES = [
    SourceDef("task_context_pack", "Task Context Pack", "task_context_pack_report", "task_context", "advisory_complementary", advisory=True),
    SourceDef("local_context_query", "Local Context Query", "local_context_query_report", "context_query", "advisory_complementary", advisory=True),
    SourceDef("graph_context_query", "Graph Context Query", "graph_context_query_report", "graph_query", "advisory_complementary", advisory=True),
    SourceDef("semantic_candidate_layer", "Semantic Candidate Readiness", "semantic_candidate_layer_report", "semantic_readiness", "advisory_complementary", advisory=True),
    SourceDef("memory_context_readiness", "Memory Context Readiness", "memory_context_readiness_report", "memory_readiness", "advisory_complementary", advisory=True),
    SourceDef("memory_provider_access", "Memory Provider Access", "memory_provider_access_report", "memory_access", "advisory_complementary", advisory=True),
    SourceDef("memory_use_policy", "Memory Use Policy", "memory_use_policy_report", "memory_use_policy", "advisory_complementary", advisory=True),
    SourceDef("session_lifecycle", "Session Lifecycle", "session_lifecycle_report", "session_lifecycle", "advisory_complementary", advisory=True),
    SourceDef("external_evidence_ingest", "External Evidence Ingest", "external_evidence_ingest_report", "external_evidence", "advisory_complementary", advisory=True),
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return data


def safe_rule_id(value: Any, fallback: str) -> str:
    raw = str(value or fallback).strip()
    raw = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw)
    return raw.strip("_") or fallback


def sarif_level(severity: str | None, status: str | None, advisory: bool) -> str:
    severity_value = (severity or "").lower()
    status_value = (status or "").lower()
    if advisory:
        if severity_value in {"blocking", "required"} and status_value in {"blocked", "error", "failed"}:
            return "warning"
        return "note" if severity_value in {"advisory", "info", "none", ""} else "warning"
    if severity_value in {"blocking", "error", "critical"} or status_value in {"blocked", "error", "failed"}:
        return "error"
    if severity_value in {"required", "warning", "warnings"} or status_value in {"required_missing", "review_required", "warning", "stale", "missing"}:
        return "warning"
    return "note"


def compact_message(finding: dict[str, Any]) -> str:
    for key in ("message", "summary", "description", "rule", "recommendation", "title"):
        value = finding.get(key)
        if value:
            return str(value)
    status = finding.get("status")
    if status:
        return f"NAOS finding status: {status}"
    return "NAOS structured finding requires review."


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def relative_uri(path_value: Any, root: Path) -> str | None:
    if not path_value:
        return None
    value = str(path_value).strip()
    if not value or value.startswith(("http://", "https://")):
        return None
    if any(char in value for char in "<>{}*"):
        return None
    value = value.split(":", 1)[0] if re.search(r":\d+$", value) else value
    path = Path(value)
    if path.is_absolute():
        try:
            value = path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            return None
    return value.replace("\\", "/").lstrip("./")


def finding_location(finding: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    for key in (
        "file",
        "path",
        "source_path",
        "target_path",
        "artifact_path",
        "artifact",
        "source",
        "reference",
        "report_path",
    ):
        uri = relative_uri(finding.get(key), root)
        if uri:
            return [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]
    return []


def fingerprint(source_id: str, rule_id: str, finding: dict[str, Any], message: str) -> str:
    basis = json.dumps(
        {
            "source": source_id,
            "rule": rule_id,
            "id": finding.get("id") or finding.get("rule_id") or finding.get("status"),
            "message": message,
            "path": finding.get("file") or finding.get("path") or finding.get("source_path") or finding.get("target_path"),
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def iter_structured_findings(data: Any, context: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], dict[str, Any]]]:
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "findings" and isinstance(value, list):
                for index, item in enumerate(value):
                    if isinstance(item, dict):
                        yield (*context, key, str(index)), item
            else:
                yield from iter_structured_findings(value, (*context, str(key)))
    elif isinstance(data, list):
        for index, item in enumerate(data):
            yield from iter_structured_findings(item, (*context, str(index)))


def source_report_path(root: Path, naos_root: str, policy: dict[str, Any], source: SourceDef) -> Path | None:
    if source.path_key is None:
        return None
    value = str(policy.get("paths", {}).get(source.path_key) or source.path_key)
    if source.naos_relative:
        return root / naos_root / value
    reports_dir = str(policy.get("paths", {}).get("reports_dir") or "reports")
    return root / naos_root / reports_dir / value


def default_sarif_output_path(root: Path, naos_root: str, policy: dict[str, Any]) -> Path | None:
    candidate = root / naos_root
    if candidate.is_dir() and not is_kit_repository(root, naos_root):
        reports_dir = str(policy.get("paths", {}).get("reports_dir") or "reports")
        filename = str(policy.get("paths", {}).get("sarif_report") or "naos_findings.sarif")
        return safe_policy_path(candidate, reports_dir, filename, field="sarif_report")
    return None


def load_capability_contract_findings(root: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    validator_path = SCRIPT_DIR / "validators" / "validate_capability_contracts.py"
    if not validator_path.is_file():
        return [], {"status": "unsupported", "reason": "Capability contract validator script is missing."}
    spec = importlib.util.spec_from_file_location("_naos_trusted_capability_contract_validator", validator_path)
    if spec is None or spec.loader is None:
        return [], {"status": "unsupported", "reason": "Capability contract validator could not be loaded."}
    module = importlib.util.module_from_spec(spec)
    sys.modules["_naos_trusted_capability_contract_validator"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    report = module.validate_capability_cards(root)
    findings = report.get("findings") if isinstance(report, dict) else []
    return [item for item in findings if isinstance(item, dict)], {
        "status": "present",
        "path": str(validator_path),
        "report_status": report.get("status") if isinstance(report, dict) else "unknown",
    }


def collect_source_findings(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    source: SourceDef,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if source.id == "capability_contracts":
        findings, metadata = load_capability_contract_findings(root)
        return findings, {
            "id": source.id,
            "label": source.label,
            "status": metadata.get("status", "unknown"),
            "path": metadata.get("path"),
            "authority_layer": source.authority_layer,
            "control_type": source.control_type,
            "included": True,
            "findings_count": len(findings),
            "report_status": metadata.get("report_status"),
        }

    path = source_report_path(root, naos_root, policy, source)
    if path is None:
        return [], {
            "id": source.id,
            "label": source.label,
            "status": "unsupported",
            "authority_layer": source.authority_layer,
            "control_type": source.control_type,
            "included": False,
            "findings_count": 0,
            "reason": "No structured path is configured for this source.",
        }
    if not path.is_file():
        return [], {
            "id": source.id,
            "label": source.label,
            "status": "missing",
            "path": str(path),
            "authority_layer": source.authority_layer,
            "control_type": source.control_type,
            "included": False,
            "findings_count": 0,
            "reason": "Structured report is not present.",
        }
    try:
        report = load_json(path)
    except Exception as exc:
        return [], {
            "id": source.id,
            "label": source.label,
            "status": "unreadable",
            "path": str(path),
            "authority_layer": source.authority_layer,
            "control_type": source.control_type,
            "included": False,
            "findings_count": 0,
            "reason": str(exc),
        }
    findings = []
    for context, item in iter_structured_findings(report):
        item = dict(item)
        item.setdefault("_naos_context_path", ".".join(context))
        findings.append(item)
    return findings, {
        "id": source.id,
        "label": source.label,
        "status": "present",
        "path": str(path),
        "authority_layer": source.authority_layer,
        "control_type": source.control_type,
        "included": True,
        "findings_count": len(findings),
        "report_status": report.get("status"),
    }


def build_rule(rule_id: str, source: SourceDef, finding: dict[str, Any], profile: str) -> dict[str, Any]:
    status = str(finding.get("status") or rule_id)
    name = status.replace("_", " ").replace("-", " ").strip().title() or rule_id
    return {
        "id": rule_id,
        "name": name[:120],
        "shortDescription": {"text": name[:160]},
        "fullDescription": {
            "text": (
                f"NAOS {source.label} finding exported for review. "
                "The SARIF result preserves NAOS authority boundaries and does not create approval, certification, or source authority."
            )
        },
        "help": {
            "text": (
                "Review the source NAOS report and referenced artifacts. "
                "Route durable decisions, waivers, approvals, maturity changes, or advisory discrepancies through human review."
            )
        },
        "properties": {
            "naos_profile": profile,
            "naos_control_type": source.control_type,
            "naos_authority_layer": source.authority_layer,
            "naos_source_report": source.id,
            "naos_human_review_required": bool(source.advisory or finding.get("human_review_required") is True),
            "naos_not_claimed": NOT_CLAIMED,
        },
    }


def build_result(source: SourceDef, finding: dict[str, Any], profile: str, root: Path) -> tuple[str, dict[str, Any]]:
    source_finding_id = str(finding.get("rule_id") or finding.get("id") or finding.get("status") or "NAOS-FINDING")
    rule_id = safe_rule_id(finding.get("rule_id") or finding.get("status") or f"{source.id}.{source_finding_id}", f"{source.id}.finding")
    message = compact_message(finding)
    level = sarif_level(str(finding.get("severity") or ""), str(finding.get("status") or ""), source.advisory)
    properties = {
        "naos_source_report": source.id,
        "naos_source_finding_id": source_finding_id,
        "naos_profile": profile,
        "naos_control_type": source.control_type,
        "naos_authority_layer": source.authority_layer,
        "naos_deterministic_or_advisory": "advisory" if source.advisory else "deterministic",
        "naos_human_review_required": bool(source.advisory or finding.get("human_review_required") is True),
        "can_promote_without_human": False,
        "can_block_without_deterministic_support": False,
        "not_claimed": as_list(finding.get("not_claimed")) or NOT_CLAIMED,
        "residual_risks": as_list(finding.get("residual_risks") or finding.get("residual_risk")),
    }
    for key in ("source_hash", "target_hash", "freshness", "freshness_status", "source_freshness_status", "target_freshness_status"):
        if finding.get(key) is not None:
            properties[key] = finding.get(key)
    for key in ("team_id", "team_resolution_source", "gate_id", "original_severity", "effective_severity", "original_enabled", "effective_enabled"):
        if finding.get(key) is not None:
            properties[key] = finding.get(key)
    if source.advisory:
        properties.update(
            {
                "naos_result_role": "candidate_or_discrepancy",
                "human_review_required": True,
                "naos_authority_layer": "advisory_complementary",
            }
        )

    result = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "partialFingerprints": {"naosFindingFingerprint": fingerprint(source.id, rule_id, finding, message)},
        "properties": properties,
    }
    locations = finding_location(finding, root)
    if locations:
        result["locations"] = locations
    return rule_id, result


def build_sarif(
    *,
    root: Path,
    profile: str,
    sources_and_findings: list[tuple[SourceDef, list[dict[str, Any]]]],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for source, findings in sources_and_findings:
        for finding in findings:
            rule_id, result = build_result(source, finding, profile, root)
            rules.setdefault(rule_id, build_rule(rule_id, source, finding, profile))
            results.append(result)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_URI,
                        "semanticVersion": "1.0.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "naos_profile": profile,
                    "naos_not_claimed": NOT_CLAIMED,
                    "naos_authority_boundary": (
                        "SARIF exports NAOS findings for interoperability; it does not approve, certify, "
                        "promote maturity, or replace repository evidence."
                    ),
                },
            }
        ],
    }
    return sarif, rules


def build_export(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    include_advisory: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    generated_at = utc_now()
    selected_sources = list(DETERMINISTIC_SOURCES)
    if include_advisory:
        selected_sources.extend(ADVISORY_SOURCES)

    input_reports: list[dict[str, Any]] = []
    skipped_sources: list[dict[str, Any]] = []
    sources_and_findings: list[tuple[SourceDef, list[dict[str, Any]]]] = []
    deterministic_count = 0
    advisory_count = 0

    for source in selected_sources:
        findings, metadata = collect_source_findings(root, naos_root, policy, source)
        input_reports.append(metadata)
        if metadata.get("status") != "present":
            skipped_sources.append(metadata)
        sources_and_findings.append((source, findings))
        if source.advisory:
            advisory_count += len(findings)
        else:
            deterministic_count += len(findings)

    if not include_advisory:
        for source in ADVISORY_SOURCES:
            skipped_sources.append(
                {
                    "id": source.id,
                    "label": source.label,
                    "status": "skipped",
                    "authority_layer": source.authority_layer,
                    "control_type": source.control_type,
                    "included": False,
                    "findings_count": 0,
                    "reason": "Advisory findings require --include-advisory.",
                }
            )

    sarif, rules = build_sarif(root=root, profile=profile, sources_and_findings=sources_and_findings)
    summary = {
        "schema": SUMMARY_SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": "ready",
        "output_path": None,
        "sarif_version": SARIF_VERSION,
        "input_reports": input_reports,
        "deterministic_findings_count": deterministic_count,
        "advisory_findings_count": advisory_count,
        "skipped_sources": skipped_sources,
        "unsupported_sources": UNSUPPORTED_STRUCTURED_SOURCES,
        "rules_count": len(rules),
        "results_count": len(sarif["runs"][0]["results"]),
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": bool(advisory_count or deterministic_count),
        "summary": {
            "deterministic_only_by_default": not include_advisory,
            "advisory_included": include_advisory,
            "authority": "SARIF findings remain findings; repository evidence and human review remain authoritative for durable decisions.",
        },
    }
    return sarif, summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export structured NAOS findings to SARIF 2.1.0.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--output", help="SARIF output path. Defaults to NAOS_ROOT/reports/naos_findings.sarif in adopter projects.")
    parser.add_argument("--summary-output", help="Optional JSON summary output path.")
    parser.add_argument("--include-advisory", action="store_true", help="Include advisory/candidate/discrepancy findings with non-authority metadata.")
    parser.add_argument("--strict-deterministic-only", action="store_true", help="Exclude advisory findings even if future defaults change.")
    parser.add_argument("--json", action="store_true", help="Print JSON summary report.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.include_advisory and args.strict_deterministic_only:
        print("ERROR: --include-advisory and --strict-deterministic-only cannot be used together.")
        return 2

    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    include_advisory = bool(args.include_advisory and not args.strict_deterministic_only)

    sarif, summary = build_export(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        include_advisory=include_advisory,
    )

    output = Path(args.output) if args.output else default_sarif_output_path(root, naos_root, policy)
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(sarif, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        summary["output_path"] = str(output)

    summary_output = Path(args.summary_output) if args.summary_output else report_output_path(root, naos_root, policy, "sarif_export_summary_report")
    write_report(summary_output, summary)

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        destination = str(output) if output else "stdout only"
        print(
            "NAOS SARIF export: "
            f"{summary['status']} "
            f"({summary['results_count']} results, {summary['rules_count']} rules, output: {destination})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
