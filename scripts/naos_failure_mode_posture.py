#!/usr/bin/env python3
"""Review local failure-mode posture declarations without runtime authority.

This command reads a repo-local failure-mode taxonomy declaration only. It does
not call providers, models, APIs, MCP, memory tools, browsers, local servers, or
networks; it does not run behavioral batteries; and it does not prove that
hallucinations, drift, duplication, or multi-agent failures are prevented.
Findings are local review evidence only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
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


REPORT_SCHEMA = "naos.failure_mode_posture.v1"
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
ALLOWED_COVERAGE = {"strong", "partial", "weak_partial", "gap", "complementary", "out_of_scope"}
AUTHORITY_FIELDS = {
    "runtime_enabled",
    "provider_calls_allowed",
    "model_calls_allowed",
    "mcp_allowed",
    "memory_allowed",
    "api_calls_allowed",
    "browser_automation_allowed",
    "network_calls_allowed",
    "tool_mutation_allowed",
    "gate_blocking_enabled",
    "assured_blocking_enabled",
    "behavioral_battery_execution",
    "opencode_runtime_enabled",
}
REASON_ORDER = [
    "taxonomy_count_mismatch",
    "unknown_mode_id",
    "duplicate_mode_id",
    "missing_mode_record",
    "invalid_coverage_value",
    "coverage_overclaim",
    "strong_without_evidence",
    "missing_control_ref",
    "missing_evidence_ref",
    "stale_evidence_ref",
    "complementary_claimed_as_core",
    "human_review_posture_missing",
    "behavioral_readiness_duplication",
    "runtime_or_provider_authority_attempt",
]
REASON_GATES = {
    "taxonomy_count_mismatch": ["G2", "G6"],
    "unknown_mode_id": ["G2", "G6"],
    "duplicate_mode_id": ["G2", "G6"],
    "missing_mode_record": ["G2", "G6"],
    "invalid_coverage_value": ["G2", "G6"],
    "coverage_overclaim": ["G6"],
    "strong_without_evidence": ["G6"],
    "missing_control_ref": ["G2", "G6"],
    "missing_evidence_ref": ["G6"],
    "stale_evidence_ref": ["G6"],
    "complementary_claimed_as_core": ["G6"],
    "human_review_posture_missing": ["G6"],
    "behavioral_readiness_duplication": ["G6"],
    "runtime_or_provider_authority_attempt": ["G6"],
}
LIMITATIONS = [
    "Failure-mode posture reports read a local taxonomy declaration only.",
    "Coverage values summarize declared review posture; they are not proof that a failure mode is prevented or fully mitigated.",
    "Per-mode statistics count deterministic report findings and declared records; they are not a risk score or approval authority.",
    "The report does not run behavioral tests, LLM judges, provider calls, model calls, MCP, memory tools, browser automation, hooks, networks, or runtime orchestration.",
    "Findings remain local human-review evidence; they do not approve, block, certify, attest, release, publish, or prove compliance.",
]
NOT_CLAIMED = [
    "hallucination prevention",
    "failure prevention",
    "fully mitigated failure modes",
    "behavioral safety proof",
    "runtime monitoring",
    "runtime orchestration",
    "provider call",
    "model call",
    "API call",
    "network access",
    "MCP activation",
    "memory activation",
    "browser automation",
    "hook activation",
    "automatic approval",
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
    "failure_mode_taxonomy_can_be_incomplete",
    "coverage_values_are_declared_not_proven",
    "human_review_required",
    "adopter_evidence_can_be_stale_or_missing",
    "behavioral_readiness_must_remain_separate",
]
OVERCLAIM_RE = re.compile(
    r"(?i)(fully[- ]mitigated|prevents? hallucination|prevents? failure|"
    r"safety proof|compliance proof|certif(?:y|ication)|attestation|guarantee)"
)


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


def is_adapt_placeholder(value: Any) -> bool:
    return isinstance(value, str) and value.strip().startswith("[ADAPT:")


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


def default_taxonomy_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "failure_mode_taxonomy.yaml"


def resolve_taxonomy_path(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    explicit: str | None = None,
) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("failure_mode_taxonomy") or "failure_mode_taxonomy.yaml")
    project_declaration = root / naos_root / filename
    if project_declaration.exists():
        return project_declaration, "project"
    return default_taxonomy_template(), "template"


def relative_path(path: Path, root: Path) -> str:
    try:
        return path.resolve(strict=False).relative_to(root.resolve(strict=False)).as_posix()
    except ValueError:
        return path.as_posix()


def local_ref_status(root: Path, ref: str) -> dict[str, Any]:
    clean_ref = str(ref).strip()
    if not clean_ref or is_adapt_placeholder(clean_ref):
        return {"ref": clean_ref, "checked": False, "present": None}
    if clean_ref.startswith(("#", "urn:", "http://", "https://")) or "://" in clean_ref:
        return {"ref": clean_ref, "checked": False, "present": None}
    path_text = clean_ref.split("#", 1)[0]
    if not path_text:
        return {"ref": clean_ref, "checked": False, "present": None}
    path = Path(path_text)
    resolved = path if path.is_absolute() else root / path
    return {"ref": clean_ref, "checked": True, "present": resolved.exists(), "path": relative_path(resolved, root)}


def profile_posture(declaration: dict[str, Any], profile: str) -> dict[str, Any]:
    posture = as_mapping(declaration.get("profile_posture")).get(profile)
    if isinstance(posture, dict):
        return posture
    defaults = {
        "quickstart": {"state": "optional", "severity": "advisory", "human_review_required": False},
        "lite": {"state": "optional", "severity": "warning", "human_review_required": False},
        "standard": {"state": "optional", "severity": "required", "human_review_required": True},
        "assured": {"state": "optional", "severity": "required", "human_review_required": True},
    }
    return defaults.get(profile, defaults["quickstart"])


def severity_from_posture(root: Path, naos_root: str, posture: dict[str, Any]) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    value = str(posture.get("severity") or "advisory")
    if value == "blocking":
        return "required"
    return value if value in {"advisory", "warning", "required"} else "advisory"


def finding(
    identifier: str,
    severity: str,
    status: str,
    reason_code: str,
    message: str,
    *,
    mode_id: str | None = None,
    source_ref: str | None = None,
    related_refs: list[str] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": identifier,
        "severity": severity,
        "status": status,
        "reason_code": reason_code,
        "gate": REASON_GATES.get(reason_code, ["G6"])[0],
        "related_gates": REASON_GATES.get(reason_code, ["G6"]),
        "message": message,
        "human_review_required": True,
        "not_claimed": ["hallucination prevention", "failure prevention", "approval", "certification", "compliance proof"],
    }
    if mode_id:
        result["mode_id"] = mode_id
        result["family"] = CANONICAL_INDEX.get(mode_id, {}).get("family", "unknown")
    if source_ref:
        result["source_ref"] = source_ref
    if related_refs:
        result["related_refs"] = related_refs
    return result


def normalized_mode_id(record: dict[str, Any]) -> str:
    return str(record.get("mode_id") or record.get("id") or "").strip()


def text_contains_overclaim(record: dict[str, Any]) -> bool:
    filtered = {
        key: value
        for key, value in record.items()
        if key not in {"not_claimed", "limitations", "known_limitations", "residual_risks"}
    }
    return bool(OVERCLAIM_RE.search(json.dumps(filtered, sort_keys=True)))


def normalize_mode(record: dict[str, Any], index: int) -> dict[str, Any]:
    mode_id = normalized_mode_id(record)
    canonical = CANONICAL_INDEX.get(mode_id, {})
    evidence_refs = string_list(record.get("evidence_refs"))
    evidence_status = [local_ref_status(Path.cwd(), ref) for ref in evidence_refs]
    declared_coverage = str(record.get("coverage") or "gap").strip()
    coverage = declared_coverage if declared_coverage in ALLOWED_COVERAGE else "gap"
    return {
        "index": index,
        "mode_id": mode_id,
        "family": str(record.get("family") or canonical.get("family") or "unknown"),
        "name": str(record.get("name") or canonical.get("name") or ""),
        "coverage": coverage,
        "declared_coverage": declared_coverage,
        "control_refs": string_list(record.get("control_refs")),
        "evidence_refs": evidence_refs,
        "evidence_ref_status": evidence_status,
        "missing_evidence_refs": [item["ref"] for item in evidence_status if item.get("checked") and not item.get("present")],
        "known_gaps": string_list(record.get("known_gaps")),
        "residual_risks": string_list(record.get("residual_risks")),
        "human_review_required": bool_value(record.get("human_review_required")),
        "human_review_declared": "human_review_required" in record,
        "source_index": index,
    }


def synthesized_missing_mode(mode_id: str, index: int) -> dict[str, Any]:
    canonical = CANONICAL_INDEX[mode_id]
    return {
        "index": index,
        "mode_id": mode_id,
        "family": canonical["family"],
        "name": canonical["name"],
        "coverage": "gap",
        "control_refs": [],
        "evidence_refs": [],
        "evidence_ref_status": [],
        "missing_evidence_refs": [],
        "known_gaps": ["missing_mode_record"],
        "residual_risks": [],
        "human_review_required": True,
        "human_review_declared": False,
        "source_index": None,
        "synthesized": True,
    }


def review_modes(
    *,
    root: Path,
    records: list[dict[str, Any]],
    severity: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    normalized_modes: list[dict[str, Any]] = []
    mode_ids = [normalized_mode_id(record) for record in records]
    mode_counts = Counter(mode_id for mode_id in mode_ids if mode_id)
    unique_known_ids = {mode_id for mode_id in mode_counts if mode_id in CANONICAL_INDEX}
    if len(unique_known_ids) != len(CANONICAL_MODES) or len(records) != len(CANONICAL_MODES):
        findings.append(
            finding(
                "failure_mode_posture.taxonomy_count_mismatch",
                severity,
                "review_required",
                "taxonomy_count_mismatch",
                f"Failure-mode taxonomy declares {len(records)} records and {len(unique_known_ids)} known unique modes; expected {len(CANONICAL_MODES)}.",
            )
        )

    for mode_id, count in mode_counts.items():
        if mode_id not in CANONICAL_INDEX:
            findings.append(
                finding(
                    f"failure_mode_posture.unknown_mode_id.{mode_id or 'empty'}",
                    severity,
                    "review_required",
                    "unknown_mode_id",
                    f"Failure-mode taxonomy declares unknown mode_id `{mode_id}`.",
                    mode_id=mode_id or None,
                )
            )
        elif count > 1:
            findings.append(
                finding(
                    f"failure_mode_posture.duplicate_mode_id.{mode_id}",
                    severity,
                    "review_required",
                    "duplicate_mode_id",
                    f"Failure-mode taxonomy declares mode_id `{mode_id}` {count} times.",
                    mode_id=mode_id,
                )
            )

    for missing_mode_id in sorted(set(CANONICAL_INDEX) - unique_known_ids):
        findings.append(
            finding(
                f"failure_mode_posture.missing_mode_record.{missing_mode_id}",
                severity,
                "review_required",
                "missing_mode_record",
                f"Failure-mode taxonomy is missing canonical mode `{missing_mode_id}`.",
                mode_id=missing_mode_id,
            )
        )

    for index, record in enumerate(records, start=1):
        mode_id = normalized_mode_id(record)
        normalized = normalize_mode(record, index)
        normalized["evidence_ref_status"] = [local_ref_status(root, ref) for ref in normalized["evidence_refs"]]
        normalized["missing_evidence_refs"] = [
            item["ref"] for item in normalized["evidence_ref_status"] if item.get("checked") and not item.get("present")
        ]
        normalized_modes.append(normalized)
        declared_coverage = str(record.get("coverage") or "gap").strip()
        coverage = normalized["coverage"]
        source_ref = f"failure_mode_taxonomy.modes[{index}]"

        if declared_coverage not in ALLOWED_COVERAGE:
            findings.append(
                finding(
                    f"failure_mode_posture.invalid_coverage_value.{mode_id or index}",
                    severity,
                    "review_required",
                    "invalid_coverage_value",
                    f"Failure-mode `{mode_id or index}` declares unsupported coverage `{declared_coverage}`.",
                    mode_id=mode_id or None,
                    source_ref=source_ref,
                )
            )
        if declared_coverage in {"fully_mitigated", "mitigated", "prevented"} or text_contains_overclaim(record):
            findings.append(
                finding(
                    f"failure_mode_posture.coverage_overclaim.{mode_id or index}",
                    severity,
                    "review_required",
                    "coverage_overclaim",
                    f"Failure-mode `{mode_id or index}` contains prevention, proof, certification, attestation, guarantee, or fully-mitigated language.",
                    mode_id=mode_id or None,
                    source_ref=source_ref,
                )
            )
        if coverage == "strong" and not normalized["evidence_refs"]:
            findings.append(
                finding(
                    f"failure_mode_posture.strong_without_evidence.{mode_id or index}",
                    severity,
                    "review_required",
                    "strong_without_evidence",
                    f"Failure-mode `{mode_id or index}` declares strong coverage without evidence_refs.",
                    mode_id=mode_id or None,
                    source_ref=source_ref,
                )
            )
        if coverage in {"strong", "partial"} and not normalized["control_refs"]:
            findings.append(
                finding(
                    f"failure_mode_posture.missing_control_ref.{mode_id or index}",
                    severity,
                    "review_required",
                    "missing_control_ref",
                    f"Failure-mode `{mode_id or index}` declares {coverage} coverage without control_refs.",
                    mode_id=mode_id or None,
                    source_ref=source_ref,
                )
            )
        if coverage in {"strong", "partial"} and not normalized["evidence_refs"]:
            findings.append(
                finding(
                    f"failure_mode_posture.missing_evidence_ref.{mode_id or index}",
                    severity,
                    "review_required",
                    "missing_evidence_ref",
                    f"Failure-mode `{mode_id or index}` declares {coverage} coverage without evidence_refs.",
                    mode_id=mode_id or None,
                    source_ref=source_ref,
                )
            )
        if normalized["missing_evidence_refs"]:
            findings.append(
                finding(
                    f"failure_mode_posture.stale_evidence_ref.{mode_id or index}",
                    severity,
                    "review_required",
                    "stale_evidence_ref",
                    f"Failure-mode `{mode_id or index}` references missing local evidence paths.",
                    mode_id=mode_id or None,
                    source_ref=source_ref,
                    related_refs=normalized["missing_evidence_refs"],
                )
            )
        if coverage == "complementary" and (
            bool_value(record.get("claimed_as_core")) or bool_value(record.get("core_coverage_claimed"))
        ):
            findings.append(
                finding(
                    f"failure_mode_posture.complementary_claimed_as_core.{mode_id or index}",
                    severity,
                    "review_required",
                    "complementary_claimed_as_core",
                    f"Failure-mode `{mode_id or index}` marks complementary evidence as core coverage.",
                    mode_id=mode_id or None,
                    source_ref=source_ref,
                )
            )
        if "human_review_required" not in record:
            findings.append(
                finding(
                    f"failure_mode_posture.human_review_posture_missing.{mode_id or index}",
                    severity,
                    "review_required",
                    "human_review_posture_missing",
                    f"Failure-mode `{mode_id or index}` lacks explicit human_review_required posture.",
                    mode_id=mode_id or None,
                    source_ref=source_ref,
                )
            )
        if any(
            bool_value(record.get(field))
            for field in (
                "behavioral_readiness_authority",
                "behavioral_governance_readiness_authority",
                "duplicates_behavioral_governance_readiness",
            )
        ):
            findings.append(
                finding(
                    f"failure_mode_posture.behavioral_readiness_duplication.{mode_id or index}",
                    severity,
                    "review_required",
                    "behavioral_readiness_duplication",
                    f"Failure-mode `{mode_id or index}` attempts to duplicate behavioral-governance readiness authority.",
                    mode_id=mode_id or None,
                    source_ref=source_ref,
                )
            )
        authority_attempt = [field for field in sorted(AUTHORITY_FIELDS) if bool_value(record.get(field))]
        for field in authority_attempt:
            findings.append(
                finding(
                    f"failure_mode_posture.runtime_or_provider_authority_attempt.{mode_id or index}.{field}",
                    severity,
                    "review_required",
                    "runtime_or_provider_authority_attempt",
                    f"Failure-mode `{mode_id or index}` attempts to declare `{field}` authority.",
                    mode_id=mode_id or None,
                    source_ref=source_ref,
                )
            )

    next_index = len(normalized_modes) + 1
    for missing_mode_id in [item["mode_id"] for item in CANONICAL_MODES if item["mode_id"] not in unique_known_ids]:
        normalized_modes.append(synthesized_missing_mode(missing_mode_id, next_index))
        next_index += 1
    return normalized_modes, findings


def count_by_mode(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {item["mode_id"]: 0 for item in CANONICAL_MODES}
    for item in findings:
        mode_id = str(item.get("mode_id") or "")
        if mode_id in counts:
            counts[mode_id] += 1
    return counts


def count_by_family(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {family: 0 for family in ["factual", "structural", "behavioral", "drift", "multi_agent", "unknown"]}
    for item in findings:
        family = str(item.get("family") or "unknown")
        counts[family if family in counts else "unknown"] += 1
    return counts


def coverage_counts(modes: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(item.get("coverage") or "gap") for item in modes)
    return {coverage: counts.get(coverage, 0) for coverage in sorted(ALLOWED_COVERAGE | set(counts))}


def family_coverage_counts(modes: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    for mode in modes:
        family = str(mode.get("family") or "unknown")
        coverage = str(mode.get("coverage") or "gap")
        result.setdefault(family, {value: 0 for value in sorted(ALLOWED_COVERAGE)})
        result[family][coverage] = result[family].get(coverage, 0) + 1
    return result


def build_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    taxonomy_path: Path,
    taxonomy_source: str,
) -> dict[str, Any]:
    declaration = load_yaml_mapping(taxonomy_path)
    posture = profile_posture(declaration, profile)
    severity = severity_from_posture(root, naos_root, posture)
    enabled = bool_value(declaration.get("enabled"))
    declared = bool_value(declaration.get("failure_mode_posture_declared"))
    raw_modes = [item for item in as_list(declaration.get("modes")) if isinstance(item, dict)]
    authority_attempts = [field for field in sorted(AUTHORITY_FIELDS) if bool_value(declaration.get(field))]
    findings: list[dict[str, Any]] = []
    modes: list[dict[str, Any]] = []

    if enabled and declared:
        modes, mode_findings = review_modes(root=root, records=raw_modes, severity=severity)
        findings.extend(mode_findings)
        for field in authority_attempts:
            findings.append(
                finding(
                    f"failure_mode_posture.runtime_or_provider_authority_attempt.{field}",
                    severity,
                    "review_required",
                    "runtime_or_provider_authority_attempt",
                    f"Declaration enables `{field}`; failure-mode posture is local review evidence only.",
                )
            )
        if any(
            bool_value(declaration.get(field))
            for field in (
                "behavioral_readiness_authority",
                "behavioral_governance_readiness_authority",
                "duplicates_behavioral_governance_readiness",
            )
        ):
            findings.append(
                finding(
                    "failure_mode_posture.behavioral_readiness_duplication",
                    severity,
                    "review_required",
                    "behavioral_readiness_duplication",
                    "Declaration attempts to duplicate behavioral-governance readiness authority.",
                )
            )
    else:
        modes = [
            {
                "index": index,
                "mode_id": item["mode_id"],
                "family": item["family"],
                "name": item["name"],
                "coverage": "gap",
                "control_refs": [],
                "evidence_refs": [],
                "evidence_ref_status": [],
                "missing_evidence_refs": [],
                "known_gaps": [],
                "residual_risks": [],
                "human_review_required": False,
                "human_review_declared": True,
                "source_index": None,
                "template_mode": True,
            }
            for index, item in enumerate(CANONICAL_MODES, start=1)
        ]

    reason_counts = Counter(str(item.get("reason_code") or "failure_mode_posture_review_required") for item in findings)
    reason_code_counts = {code: reason_counts.get(code, 0) for code in REASON_ORDER}
    mode_finding_counts = count_by_mode(findings)
    family_finding_counts = count_by_family(findings)
    known_gaps = string_list(declaration.get("known_gaps"))
    if not enabled or not declared:
        known_gaps.append("failure_mode_posture_not_enabled")
    summary = finding_counts(findings)
    coverage_summary = coverage_counts(modes)
    family_coverage_summary = family_coverage_counts(modes)
    summary.update(
        {
            "modes": len(modes),
            "expected_modes": len(CANONICAL_MODES),
            "taxonomy_records": len(raw_modes),
            "taxonomy_count": len({mode.get("mode_id") for mode in modes if mode.get("mode_id") in CANONICAL_INDEX}),
            "modes_with_findings": sum(1 for count in mode_finding_counts.values() if count),
            "mode_finding_counts": mode_finding_counts,
            "family_finding_counts": family_finding_counts,
            "coverage_counts": coverage_summary,
            "runtime_authority_findings": reason_code_counts["runtime_or_provider_authority_attempt"],
            "assured_blocking_enabled": False,
            "runtime_enabled": False,
            "provider_calls_allowed": False,
            "model_calls_allowed": False,
        }
    )
    if not enabled or not declared:
        status = "not_configured"
    elif findings:
        status = status_from_counts(summary)
    else:
        status = "pass"

    return {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "deterministic": True,
        "taxonomy_path": str(taxonomy_path),
        "taxonomy_source": taxonomy_source,
        "taxonomy_hash": safe_digest(taxonomy_path),
        "enabled": enabled,
        "failure_mode_posture_declared": declared,
        "runtime_enabled": False,
        "provider_calls_allowed": False,
        "model_calls_allowed": False,
        "mcp_allowed": False,
        "memory_allowed": False,
        "api_calls_allowed": False,
        "browser_automation_allowed": False,
        "network_calls_allowed": False,
        "tool_mutation_allowed": False,
        "declared_authority_attempts": authority_attempts,
        "capability_maturity": {
            "current": str(declaration.get("capability_maturity") or "L1"),
            "assured_blocking_enabled": False,
            "blocking_requires_l3_plus_and_gate_wiring": True,
        },
        "profile_posture": posture,
        "canonical_modes": CANONICAL_MODES,
        "modes": modes,
        "coverage_counts": coverage_summary,
        "family_coverage_counts": family_coverage_summary,
        "mode_finding_counts": mode_finding_counts,
        "family_finding_counts": family_finding_counts,
        "findings": findings,
        "reason_code_counts": reason_code_counts,
        "known_gaps": list(dict.fromkeys(known_gaps)),
        "residual_risks": list(dict.fromkeys(string_list(declaration.get("residual_risks")) + RESIDUAL_RISKS)),
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": bool(findings) or bool_value(posture.get("human_review_required"), False),
        "generated_by": build_generated_by(root),
        "summary": summary,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Review local NAOS failure-mode posture declarations.")
    parser.add_argument("project", nargs="?", default=".", help="Project root to evaluate.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--failure-mode-taxonomy", help="Path to failure_mode_taxonomy.yaml.")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.project).resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    taxonomy_path, taxonomy_source = resolve_taxonomy_path(root, naos_root, policy, args.failure_mode_taxonomy)
    report = build_report(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        taxonomy_path=taxonomy_path,
        taxonomy_source=taxonomy_source,
    )
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "failure_mode_posture_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            "NAOS failure-mode posture: "
            f"{report['status']} "
            f"({report['summary'].get('total_findings', 0)} findings, "
            f"{report['summary'].get('modes', 0)} modes, "
            f"output: {output})"
        )
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
