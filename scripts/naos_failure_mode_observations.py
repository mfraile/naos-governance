#!/usr/bin/env python3
"""Aggregate local report findings into failure-mode observation statistics.

This command reads configured local NAOS report files and maps their findings
to the canonical 21 failure modes. It is deterministic review evidence only:
it does not read control_plane_review.json, write learning records, mutate
skills/prompts/workflows, call providers or models, activate MCP/Engram/memory,
run networks or hooks, approve work, block gates, certify, attest, release, or
prove compliance.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    build_generated_by,
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    kit_root,
    load_policy,
    normalize_profile,
    report_output_path,
    status_from_counts,
    write_report,
)


REPORT_SCHEMA = "naos.failure_mode_observations.v1"
CANONICAL_MODES = [
    {"mode_id": "F1", "family": "factual", "name": "API/library fabrication"},
    {"mode_id": "F2", "family": "factual", "name": "Package fabrication"},
    {"mode_id": "F3", "family": "factual", "name": "Config-key fabrication"},
    {"mode_id": "F4", "family": "factual", "name": "Doc/citation fabrication"},
    {"mode_id": "S1", "family": "structural", "name": "Silent duplication"},
    {"mode_id": "S2", "family": "structural", "name": "Context-amnesia duplication"},
    {"mode_id": "S3", "family": "structural", "name": "Interface mismatch"},
    {"mode_id": "S4", "family": "structural", "name": "Cross-module divergence"},
    {"mode_id": "B1", "family": "behavioral", "name": "Test-requirement mismatch"},
    {"mode_id": "B2", "family": "behavioral", "name": "Mock hallucination"},
    {"mode_id": "B3", "family": "behavioral", "name": "Coverage theater"},
    {"mode_id": "B4", "family": "behavioral", "name": "Assertion hallucination"},
    {"mode_id": "D1", "family": "drift", "name": "Attention drift"},
    {"mode_id": "D2", "family": "drift", "name": "Goal drift"},
    {"mode_id": "D3", "family": "drift", "name": "Reasoning drift"},
    {"mode_id": "D4", "family": "drift", "name": "Compaction loss"},
    {"mode_id": "M1", "family": "multi_agent", "name": "State collision"},
    {"mode_id": "M2", "family": "multi_agent", "name": "Handoff hallucination"},
    {"mode_id": "M3", "family": "multi_agent", "name": "Authority hallucination"},
    {"mode_id": "M4", "family": "multi_agent", "name": "Cascade drift"},
    {"mode_id": "M5", "family": "multi_agent", "name": "Consensus cascade"},
]
CANONICAL_INDEX = {item["mode_id"]: item for item in CANONICAL_MODES}
AUTHORITY_FIELDS = {
    "runtime_enabled",
    "provider_calls_allowed",
    "model_calls_allowed",
    "mcp_allowed",
    "memory_allowed",
    "network_calls_allowed",
    "hook_activation_allowed",
    "tool_mutation_allowed",
    "automatic_learning_allowed",
}
REASON_ORDER = [
    "required_source_missing",
    "source_report_malformed",
    "source_report_excluded",
    "unknown_mode_id",
    "unmapped_observation",
    "source_human_review_required",
    "high_severity_observation",
    "runtime_or_provider_authority_attempt",
    "failure_mode_observations_review_required",
]
REASON_GATES = {
    "required_source_missing": ["G6"],
    "source_report_malformed": ["G6"],
    "source_report_excluded": ["G6"],
    "unknown_mode_id": ["G2", "G6"],
    "unmapped_observation": ["G2", "G6"],
    "source_human_review_required": ["G6"],
    "high_severity_observation": ["G6"],
    "runtime_or_provider_authority_attempt": ["G6"],
    "failure_mode_observations_review_required": ["G6"],
}
DEFAULT_EXCLUDED_REFS = {"naos/reports/control_plane_review.json"}
LIMITATIONS = [
    "Failure-mode observations aggregate configured local report findings only.",
    "control_plane_review.json is intentionally excluded as an input to avoid cyclic review evidence.",
    "Observation counts are deterministic review statistics, not a numeric risk score or approval authority.",
    "Observation mappings may inform human review, learning-loop review, or autoresearch scoping, but they do not write learning records or promote guidance.",
    "The report does not call providers, models, APIs, MCP, Engram, memory tools, browsers, networks, hooks, behavioral batteries, or runtime systems.",
    "Findings remain local human-review evidence; they do not approve, block, certify, attest, release, publish, or prove compliance.",
]
NOT_CLAIMED = [
    "self-learning model weights",
    "autonomous skill promotion",
    "automatic memory write-back",
    "automatic context injection",
    "automatic prompt mutation",
    "automatic learning promotion",
    "provider call",
    "model call",
    "API call",
    "network access",
    "MCP activation",
    "Engram activation",
    "memory activation",
    "browser automation",
    "hook activation",
    "runtime orchestration",
    "numeric risk score authority",
    "approval",
    "automatic blocking",
    "merge approval",
    "release authority",
    "publication authority",
    "certification",
    "attestation",
    "legal or regulatory assurance",
    "compliance proof",
]
RESIDUAL_RISKS = [
    "observation_mapping_can_be_incomplete",
    "source_report_findings_can_be_stale",
    "counts_can_be_misread_as_scores_without_human_review",
    "human_review_required",
]


def utc_now_text() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def string_list(value: Any) -> list[str]:
    return list(dict.fromkeys(str(item).strip() for item in as_list(value) if str(item).strip()))


def bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def safe_digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping: {path}")
    return data


def default_declaration_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "failure_mode_observations.yaml"


def resolve_declaration_path(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    explicit: str | None = None,
) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("failure_mode_observations") or "failure_mode_observations.yaml")
    project_declaration = root / naos_root / filename
    if project_declaration.exists():
        return project_declaration, "project"
    return default_declaration_template(), "template"


def relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve(strict=False).relative_to(root.resolve()))
    except ValueError:
        return str(path)


def relative_ref(root: Path, path: Path) -> str:
    return relative_path(path, root)


def review_severity(profile: str, root: Path, naos_root: str) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    if profile == "quickstart":
        return "advisory"
    if profile == "lite":
        return "warning"
    return "required"


def finding(
    identifier: str,
    severity: str,
    reason_code: str,
    message: str,
    **extra: Any,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": identifier,
        "severity": severity,
        "status": reason_code,
        "reason_code": reason_code,
        "related_gates": REASON_GATES.get(reason_code, ["G6"]),
        "gate": ", ".join(REASON_GATES.get(reason_code, ["G6"])),
        "message": message,
        "human_review_required": True,
    }
    item.update({key: value for key, value in extra.items() if value not in (None, [], {})})
    return item


def report_default_path(root: Path, naos_root: str, policy: dict[str, Any], key: str) -> Path:
    reports_dir = str(policy.get("paths", {}).get("reports_dir") or "reports")
    filename = str(policy.get("paths", {}).get(key) or key)
    return root / naos_root / reports_dir / filename


def report_paths_for_source(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    source: dict[str, Any],
) -> list[Path]:
    if source.get("path_key"):
        return [report_default_path(root, naos_root, policy, str(source["path_key"]))]
    raw_path = str(source.get("path") or "").strip()
    if not raw_path:
        return []
    candidate = root / raw_path
    if any(char in raw_path for char in "*?["):
        return [Path(item) for item in sorted(glob.glob(str(candidate)))]
    return [candidate]


def load_json_report(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, str(exc)
    if not isinstance(data, dict):
        return None, "Report root must be a JSON object."
    return data, None


def normalize_mode_ids(value: Any) -> tuple[list[str], list[str]]:
    mode_ids = string_list(value)
    valid = [mode_id for mode_id in mode_ids if mode_id in CANONICAL_INDEX]
    invalid = [mode_id for mode_id in mode_ids if mode_id not in CANONICAL_INDEX]
    return list(dict.fromkeys(valid)), list(dict.fromkeys(invalid))


def explicit_mode_ids(report_finding: dict[str, Any]) -> tuple[list[str], list[str]]:
    for key in ("failure_mode_ids", "mode_ids", "mode_id"):
        if key in report_finding:
            return normalize_mode_ids(report_finding.get(key))
    return [], []


def reason_code_for(report_finding: dict[str, Any]) -> str:
    for key in ("reason_code", "status"):
        value = str(report_finding.get(key) or "").strip()
        if value:
            return value
    identifier = str(report_finding.get("id") or "").strip()
    if "." in identifier:
        return identifier.split(".")[1]
    return "unknown_reason"


def severity_for(report_finding: dict[str, Any]) -> str:
    value = str(report_finding.get("severity") or "").strip()
    return value if value in {"advisory", "warning", "required", "blocking"} else "advisory"


def related_gates_for(report_finding: dict[str, Any]) -> list[str]:
    gates = string_list(report_finding.get("related_gates"))
    if gates:
        return gates
    gate = str(report_finding.get("gate") or "").strip()
    if gate:
        return [item.strip() for item in gate.split(",") if item.strip()]
    return []


def source_mapping_index(mappings: list[Any]) -> dict[tuple[str, str], list[str]]:
    result: dict[tuple[str, str], list[str]] = {}
    for mapping in mappings:
        if not isinstance(mapping, dict):
            continue
        source_type = str(mapping.get("source_type") or "").strip()
        reason_code = str(mapping.get("reason_code") or mapping.get("status") or "").strip()
        mode_ids, _ = normalize_mode_ids(mapping.get("mode_ids"))
        if source_type and reason_code and mode_ids:
            result[(source_type, reason_code)] = mode_ids
    return result


def excluded_source_ref(source_ref: str, declaration: dict[str, Any]) -> bool:
    excluded = set(DEFAULT_EXCLUDED_REFS)
    excluded.update(string_list(declaration.get("excluded_source_report_paths")))
    return source_ref in excluded


def authority_attempts(declaration: dict[str, Any]) -> list[str]:
    attempts: list[str] = []
    for field in AUTHORITY_FIELDS:
        if bool_value(declaration.get(field), False):
            attempts.append(field)
    return sorted(attempts)


def has_authority_language(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in ("runtime_authority", "authority_attempt", "runtime_escalation"))


def build_observations_for_report(
    *,
    root: Path,
    source: dict[str, Any],
    source_path: Path,
    report: dict[str, Any],
    mapping_index: dict[tuple[str, str], list[str]],
    invalid_modes: list[str],
) -> list[dict[str, Any]]:
    source_ref = relative_ref(root, source_path)
    source_id = str(source.get("source_id") or source_path.stem).strip()
    source_type = str(source.get("source_type") or "").strip()
    report_findings = [item for item in report.get("findings") or [] if isinstance(item, dict)]
    observations: list[dict[str, Any]] = []
    for index, report_finding in enumerate(report_findings, start=1):
        reason_code = reason_code_for(report_finding)
        modes, invalid = explicit_mode_ids(report_finding)
        mapping_basis = "explicit_mode"
        if invalid:
            invalid_modes.extend(invalid)
        if not modes:
            modes = mapping_index.get((source_type, reason_code), [])
            mapping_basis = "reason_code_mapping" if modes else "unmapped"
        if not modes:
            default_modes, invalid_defaults = normalize_mode_ids(source.get("default_mode_ids"))
            if default_modes:
                modes = default_modes
                mapping_basis = "source_default_mapping"
            if invalid_defaults:
                invalid_modes.extend(invalid_defaults)
        families = sorted({CANONICAL_INDEX[mode_id]["family"] for mode_id in modes if mode_id in CANONICAL_INDEX})
        severity = severity_for(report_finding)
        human_review_required = bool_value(report_finding.get("human_review_required"), False) or bool_value(
            report.get("human_review_required"), False
        )
        if not modes or severity in {"required", "blocking"}:
            human_review_required = True
        observations.append(
            {
                "id": f"failure_mode_observations.{source_id}.{index}",
                "source_id": source_id,
                "source_type": source_type,
                "source_ref": source_ref,
                "source_schema": report.get("schema"),
                "source_status": report.get("status"),
                "source_finding_id": report_finding.get("id"),
                "reason_code": reason_code,
                "source_severity": severity,
                "mode_ids": modes,
                "families": families,
                "mapping_basis": mapping_basis,
                "mapped": bool(modes),
                "human_review_required": human_review_required,
                "related_gates": related_gates_for(report_finding),
                "message": str(report_finding.get("message") or report_finding.get("summary") or "").strip(),
            }
        )
    return observations


def count_by_mode(observations: list[dict[str, Any]]) -> dict[str, int]:
    counts = {item["mode_id"]: 0 for item in CANONICAL_MODES}
    for observation in observations:
        for mode_id in observation.get("mode_ids") or []:
            if mode_id in counts:
                counts[mode_id] += 1
    return counts


def count_by_family(observations: list[dict[str, Any]]) -> dict[str, int]:
    counts = {item["family"]: 0 for item in CANONICAL_MODES}
    for observation in observations:
        for family in observation.get("families") or []:
            counts[family] = counts.get(family, 0) + 1
    return counts


def counter_dict(values: list[str]) -> dict[str, int]:
    return dict(sorted(Counter(value for value in values if value).items()))


def reason_code_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(item.get("reason_code") or "failure_mode_observations_review_required") for item in findings)
    return {code: counts.get(code, 0) for code in REASON_ORDER}


def build_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    declaration_path: Path,
    declaration_source: str,
) -> dict[str, Any]:
    generated_at = utc_now_text()
    try:
        declaration = load_yaml_mapping(declaration_path)
    except Exception as exc:
        declaration = {
            "enabled": True,
            "failure_mode_observations_declared": True,
            "known_gaps": ["failure_mode_observations_declaration_unreadable"],
        }
        declaration_error = str(exc)
    else:
        declaration_error = None
    enabled = bool_value(declaration.get("enabled"), False)
    declared = bool_value(declaration.get("failure_mode_observations_declared"), False)
    base_severity = review_severity(profile, root, naos_root)
    findings: list[dict[str, Any]] = []
    source_reports: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    invalid_modes: list[str] = []
    mapping_index = source_mapping_index(as_list(declaration.get("reason_mappings")))

    if declaration_error:
        findings.append(
            finding(
                "failure_mode_observations.declaration_unreadable",
                base_severity,
                "source_report_malformed",
                "Failure-mode observations declaration could not be read.",
                error=declaration_error,
            )
        )
    attempts = authority_attempts(declaration)
    if attempts:
        findings.append(
            finding(
                "failure_mode_observations.runtime_or_provider_authority_attempt",
                base_severity,
                "runtime_or_provider_authority_attempt",
                "Failure-mode observations declaration attempted runtime, provider/model, MCP, memory, hook, tool-mutation, or automatic-learning authority.",
                authority_refs=attempts,
            )
        )

    if enabled:
        for source in as_list(declaration.get("source_reports")):
            if not isinstance(source, dict) or not bool_value(source.get("enabled"), True):
                continue
            source_id = str(source.get("source_id") or source.get("path_key") or source.get("path") or "source").strip()
            required = bool_value(source.get("required"), False)
            candidate_paths = report_paths_for_source(root, naos_root, policy, source)
            if not candidate_paths:
                source_reports.append({"source_id": source_id, "present": False, "required": required, "status": "not_configured"})
                if required:
                    findings.append(
                        finding(
                            f"failure_mode_observations.required_source_missing.{source_id}",
                            base_severity,
                            "required_source_missing",
                            "Configured required observation source has no resolved local report path.",
                            source_id=source_id,
                        )
                    )
                continue
            for candidate_path in candidate_paths:
                source_ref = relative_ref(root, candidate_path)
                excluded = excluded_source_ref(source_ref, declaration)
                if excluded:
                    source_reports.append(
                        {"source_id": source_id, "path": source_ref, "present": candidate_path.exists(), "required": required, "excluded": True}
                    )
                    findings.append(
                        finding(
                            f"failure_mode_observations.source_report_excluded.{source_id}",
                            base_severity,
                            "source_report_excluded",
                            "Configured observation source is excluded to prevent cyclic review evidence.",
                            source_id=source_id,
                            source_ref=source_ref,
                        )
                    )
                    continue
                if not candidate_path.exists():
                    source_reports.append({"source_id": source_id, "path": source_ref, "present": False, "required": required})
                    if required:
                        findings.append(
                            finding(
                                f"failure_mode_observations.required_source_missing.{source_id}",
                                base_severity,
                                "required_source_missing",
                                "Configured required observation source report is missing.",
                                source_id=source_id,
                                source_ref=source_ref,
                            )
                        )
                    continue
                data, error = load_json_report(candidate_path)
                source_reports.append(
                    {
                        "source_id": source_id,
                        "path": source_ref,
                        "present": True,
                        "required": required,
                        "schema": data.get("schema") if isinstance(data, dict) else None,
                        "status": data.get("status") if isinstance(data, dict) else "parse_error",
                        "error": error,
                    }
                )
                if error or not isinstance(data, dict):
                    findings.append(
                        finding(
                            f"failure_mode_observations.source_report_malformed.{source_id}",
                            base_severity,
                            "source_report_malformed",
                            "Configured observation source report is present but malformed.",
                            source_id=source_id,
                            source_ref=source_ref,
                            error=error,
                        )
                    )
                    continue
                observations.extend(
                    build_observations_for_report(
                        root=root,
                        source=source,
                        source_path=candidate_path,
                        report=data,
                        mapping_index=mapping_index,
                        invalid_modes=invalid_modes,
                    )
                )

    unmapped = [item for item in observations if not item.get("mapped")]
    if invalid_modes:
        findings.append(
            finding(
                "failure_mode_observations.unknown_mode_id",
                base_severity,
                "unknown_mode_id",
                "Observation source or mapping references unknown failure-mode ids.",
                unknown_mode_ids=sorted(set(invalid_modes)),
            )
        )
    if unmapped:
        findings.append(
            finding(
                "failure_mode_observations.unmapped_observation",
                base_severity,
                "unmapped_observation",
                "One or more source findings could not be mapped to canonical failure modes.",
                observation_count=len(unmapped),
                observation_ids=[item["id"] for item in unmapped],
            )
        )
    review_observations = [item for item in observations if item.get("human_review_required")]
    if review_observations:
        findings.append(
            finding(
                "failure_mode_observations.source_human_review_required",
                base_severity,
                "source_human_review_required",
                "One or more mapped source observations already require human review.",
                observation_count=len(review_observations),
            )
        )
    high_severity = [item for item in observations if item.get("source_severity") in {"required", "blocking"}]
    if high_severity:
        findings.append(
            finding(
                "failure_mode_observations.high_severity_observation",
                base_severity,
                "high_severity_observation",
                "One or more source observations have required/blocking-style severity; this remains review evidence only.",
                observation_count=len(high_severity),
            )
        )
    authority_observations = [
        item
        for item in observations
        if has_authority_language(str(item.get("reason_code") or "")) or has_authority_language(str(item.get("source_finding_id") or ""))
    ]
    if authority_observations and not any(item.get("reason_code") == "runtime_or_provider_authority_attempt" for item in findings):
        findings.append(
            finding(
                "failure_mode_observations.runtime_or_provider_authority_attempt.observed",
                base_severity,
                "runtime_or_provider_authority_attempt",
                "Source observations include runtime/provider/model/authority-attempt reason codes; this report records review evidence only.",
                observation_count=len(authority_observations),
            )
        )

    summary = finding_counts(findings)
    mode_counts = count_by_mode(observations)
    family_counts = count_by_family(observations)
    mapping_counts = counter_dict([str(item.get("mapping_basis") or "unknown") for item in observations])
    source_counts = counter_dict([str(item.get("source_id") or "unknown") for item in observations])
    observation_reason_counts = counter_dict([str(item.get("reason_code") or "unknown_reason") for item in observations])
    severity_counts = counter_dict([str(item.get("source_severity") or "advisory") for item in observations])
    gate_counts = counter_dict([gate for item in observations for gate in string_list(item.get("related_gates"))])
    summary.update(
        {
            "sources_configured": len([item for item in as_list(declaration.get("source_reports")) if isinstance(item, dict)]),
            "source_reports_seen": sum(1 for item in source_reports if item.get("present")),
            "observations": len(observations),
            "mapped_observations": sum(1 for item in observations if item.get("mapped")),
            "unmapped_observations": len(unmapped),
            "human_review_observations": len(review_observations),
            "high_severity_observations": len(high_severity),
            "modes_with_observations": sum(1 for count in mode_counts.values() if count),
            "mode_observation_counts": mode_counts,
            "family_observation_counts": family_counts,
            "source_report_counts": source_counts,
            "observation_reason_code_counts": observation_reason_counts,
            "severity_counts": severity_counts,
            "related_gate_counts": gate_counts,
            "mapping_basis_counts": mapping_counts,
            "reason_code_counts": reason_code_counts(findings),
            "runtime_authority_findings": sum(
                1 for item in findings if item.get("reason_code") == "runtime_or_provider_authority_attempt"
            ),
            "assured_blocking_enabled": False,
            "runtime_enabled": False,
            "provider_calls_allowed": False,
            "model_calls_allowed": False,
            "automatic_learning_allowed": False,
        }
    )
    if not enabled and not declared and not findings:
        status = "not_configured"
    elif findings:
        status = status_from_counts(summary)
    else:
        status = "pass"

    known_gaps = string_list(declaration.get("known_gaps"))
    if not enabled:
        known_gaps = list(dict.fromkeys(known_gaps + ["failure_mode_observations_not_enabled"]))
    residual_risks = list(dict.fromkeys(string_list(declaration.get("residual_risks")) + (RESIDUAL_RISKS if enabled else [])))
    not_claimed = list(dict.fromkeys(string_list(declaration.get("not_claimed")) + NOT_CLAIMED))
    limitations = list(dict.fromkeys(string_list(declaration.get("limitations")) + LIMITATIONS))

    return {
        "schema": REPORT_SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "deterministic": True,
        "declaration_path": relative_path(declaration_path, root),
        "declaration_source": declaration_source,
        "declaration_hash": safe_digest(declaration_path),
        "enabled": enabled,
        "failure_mode_observations_declared": declared,
        "runtime_enabled": False,
        "provider_calls_allowed": False,
        "model_calls_allowed": False,
        "mcp_allowed": False,
        "memory_allowed": False,
        "network_calls_allowed": False,
        "hook_activation_allowed": False,
        "tool_mutation_allowed": False,
        "automatic_learning_allowed": False,
        "control_plane_review_input_allowed": False,
        "profile_posture": as_mapping(declaration.get("profile_posture")),
        "canonical_modes": CANONICAL_MODES,
        "source_reports": source_reports,
        "observations": observations,
        "mode_observation_counts": mode_counts,
        "family_observation_counts": family_counts,
        "source_report_counts": source_counts,
        "observation_reason_code_counts": observation_reason_counts,
        "severity_counts": severity_counts,
        "related_gate_counts": gate_counts,
        "mapping_basis_counts": mapping_counts,
        "findings": findings,
        "reason_code_counts": reason_code_counts(findings),
        "review_opportunities": [
            {
                "type": "unmapped_observations",
                "count": len(unmapped),
                "human_review_required": bool(unmapped),
                "notes": "Review mappings before using these observations for learning-loop or autoresearch scoping.",
            },
            {
                "type": "recurring_mode_observations",
                "mode_counts": {mode_id: count for mode_id, count in mode_counts.items() if count > 1},
                "human_review_required": False,
                "notes": "Recurring observations may inform future human-reviewed learning candidates; no learning record is written.",
            },
        ],
        "known_gaps": known_gaps,
        "residual_risks": residual_risks,
        "limitations": limitations,
        "not_claimed": not_claimed,
        "human_review_required": bool(findings) or bool(review_observations),
        "generated_by": build_generated_by(root),
        "summary": summary,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Aggregate local report findings into failure-mode observation statistics.")
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--failure-mode-observations", help="Explicit failure_mode_observations.yaml path.")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.root).resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    declaration_path, declaration_source = resolve_declaration_path(
        root,
        naos_root,
        policy,
        args.failure_mode_observations,
    )
    report = build_report(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        declaration_path=declaration_path,
        declaration_source=declaration_source,
    )
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "failure_mode_observations_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            "NAOS failure-mode observations: "
            f"{report['status']} "
            f"({report['summary'].get('observations', 0)} observations, "
            f"{report['summary'].get('unmapped_observations', 0)} unmapped, "
            f"output: {output})"
        )
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
