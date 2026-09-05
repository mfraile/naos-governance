"""Core model for bounded secure-coding multidimensional reporting."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema

from naos_policy import (
    finding_counts,
    is_kit_repository,
    severity_for_profile,
    status_from_counts,
)

SCHEMA_ID = "naos.secure_coding_reporting.v1"
REFERENCE_VALIDATOR = "validate_secure_coding_control_references"
CONTROLS_SCHEMA_ID = "naos.secure_coding_controls.v1"
DIMENSION_KEYS = (
    "register_validity",
    "reference_integrity",
    "detector_evidence",
    "mapping_verification",
    "human_review",
)
P2_DIMENSION_KEYS = {
    "register_schema_validity",
    "evidence_route_integrity",
    "evidence_availability",
    "evidence_freshness",
    "mapping_verification",
    "human_review",
}
NOT_CLAIMED = [
    "secure code proof",
    "control satisfaction",
    "vulnerability-free proof",
    "complete detector coverage",
    "framework conformance",
    "compliance proof",
    "approval",
    "release authorization",
    "human review replacement",
    "composite security score",
]
LIMITATIONS = [
    "The report presents five independent dimensions and does not calculate a blended or composite score.",
    "Reference integrity establishes bounded structural coherence only; it does not prove secure code or correct runtime behavior.",
    "Detector evidence availability and freshness do not establish evidence validity, completeness, or control satisfaction.",
    "Mapping verification states are metadata for review and do not establish framework conformance.",
    "Human review remains required for applicability, evidence interpretation, exceptions, waivers, approvals, and release decisions.",
]


def timestamp(value: str | None) -> str:
    raw = value or datetime.now(UTC).replace(microsecond=0).isoformat()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return (
        parsed.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def finding(
    fid: str,
    severity: str,
    status: str,
    message: str,
    path: str | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": fid,
        "severity": severity,
        "status": status,
        "message": message,
        "human_review_required": True,
        "not_claimed": NOT_CLAIMED,
    }
    if path:
        item["path"] = path
    return item


def empty_reference() -> dict[str, Any]:
    return {
        "validator": None,
        "status": "unavailable",
        "summary": {"errors": 1},
        "findings": [],
        "boundaries": [],
    }


def empty_controls() -> dict[str, Any]:
    return {
        "schema": None,
        "status": "unavailable",
        "summary": {},
        "dimensions": {
            "register_schema_validity": {"state": "unknown"},
            "evidence_route_integrity": {"state": "unknown"},
            "evidence_availability": {"state_counts": {}},
            "evidence_freshness": {"maximum_age_days": None, "stale_routes": 0},
            "mapping_verification": {"status_counts": {}},
            "human_review": {"outstanding_controls": None},
        },
        "findings": [],
    }


def empty_standards_snapshot(state: str = "unavailable") -> dict[str, Any]:
    return {
        "state": state,
        "source": "P2 secure-coding controls report",
        "register_schema": None,
        "register_version": None,
        "standards": {},
        "human_review_required": True,
        "not_claimed": [
            "framework conformance",
            "control satisfaction",
            "compliance proof",
            "approval",
        ],
    }


def standards_snapshot(controls: dict[str, Any], controls_valid: bool) -> dict[str, Any]:
    raw = controls.get("standards_snapshot")
    if not isinstance(raw, dict):
        return empty_standards_snapshot("unavailable")
    standards = raw.get("standards") if isinstance(raw.get("standards"), dict) else {}
    normalized: dict[str, dict[str, Any]] = {}
    for key in sorted(standards):
        value = standards[key]
        if not isinstance(value, dict):
            continue
        normalized[str(key)] = {
            "name": value.get("name"),
            "version": str(value.get("version") or ""),
            "role": value.get("role"),
            "source": value.get("source"),
            "mapping_default_status": value.get("mapping_default_status"),
        }
        for field in (
            "source_release",
            "source_dataset_sha256",
            "selected_control_ids",
            "claim_posture",
            "decision_use",
            "scope",
            "non_claims",
        ):
            if field in value:
                normalized[str(key)][field] = value[field]
    return {
        "state": "available" if controls_valid and normalized else "unavailable",
        "source": "P2 secure-coding controls report",
        "register_schema": raw.get("register_schema"),
        "register_version": raw.get("register_version"),
        "standards": normalized,
        "human_review_required": True,
        "not_claimed": [
            "framework conformance",
            "control satisfaction",
            "compliance proof",
            "approval",
        ],
    }


def load_source(
    path: Path,
    label: str,
    severity: str,
    findings: list[dict[str, Any]],
    empty: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    if path.is_symlink():
        findings.append(
            finding(
                f"{label}:symlink",
                severity,
                "source_unsafe",
                f"Required P3 source report must not be a symlink: {label}.",
                str(path),
            )
        )
        return empty, "unsafe"
    if not path.is_file():
        findings.append(
            finding(
                f"{label}:missing",
                severity,
                "source_missing",
                f"Required P3 source report is missing: {label}.",
                str(path),
            )
        )
        return empty, "missing"
    try:
        return load_object(path), "artifact"
    except Exception as exc:
        findings.append(
            finding(
                f"{label}:load",
                severity,
                "source_parse_error",
                str(exc),
                str(path),
            )
        )
        return empty, "parse_error"


def detector_evidence_state(
    *,
    source_valid: bool,
    routes: dict[str, Any],
    availability: dict[str, Any],
    freshness: dict[str, Any],
) -> str:
    if not source_valid or routes.get("state") != "valid":
        return "invalid"
    raw_counts = availability.get("state_counts")
    state_counts = raw_counts if isinstance(raw_counts, dict) else {}
    problematic = {
        "missing",
        "parse_error",
        "invalid_path",
        "unknown",
    }
    if any(int(state_counts.get(key, 0) or 0) > 0 for key in problematic):
        return "incomplete"
    if int(freshness.get("stale_routes", 0) or 0) > 0 or int(
        state_counts.get("stale", 0) or 0
    ) > 0:
        return "stale"
    if int(state_counts.get("not_evaluated", 0) or 0) > 0:
        return "not_evaluated"
    if int(state_counts.get("available", 0) or 0) > 0:
        return "available"
    if any(
        int(state_counts.get(key, 0) or 0) > 0
        for key in (
            "optional_missing",
            "not_applicable",
            "not_expected_for_profile",
        )
    ):
        return "no_required_evidence"
    return "unknown"


def build_report(
    *,
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
    reference_path: Path,
    controls_path: Path,
    check_mode: bool,
    generated_at: str | None,
) -> dict[str, Any]:
    severity = (
        "advisory"
        if is_kit_repository(root, naos_root)
        else severity_for_profile(profile, policy)
    )
    findings: list[dict[str, Any]] = []
    reference, reference_kind = load_source(
        reference_path,
        "reference-integrity",
        severity,
        findings,
        empty_reference(),
    )
    controls, controls_kind = load_source(
        controls_path,
        "secure-coding-controls",
        severity,
        findings,
        empty_controls(),
    )

    reference_contract_valid = reference.get("validator") == REFERENCE_VALIDATOR
    if reference_kind == "artifact" and not reference_contract_valid:
        findings.append(
            finding(
                "reference-integrity:contract",
                severity,
                "source_schema_error",
                f"P1 report validator must be {REFERENCE_VALIDATOR!r}.",
                str(reference_path),
            )
        )
    reference_valid = (
        reference_kind == "artifact"
        and reference_contract_valid
        and reference.get("status") == "pass"
    )
    if reference.get("status") != "pass":
        source_findings = reference.get("findings") or []
        if reference_kind == "artifact" and not source_findings:
            findings.append(
                finding(
                    "reference-integrity:status",
                    severity,
                    "reference_integrity_error",
                    f"P1 status is {reference.get('status')!r}.",
                    str(reference_path),
                )
            )
        for index, item in enumerate(source_findings, 1):
            if isinstance(item, dict):
                findings.append(
                    finding(
                        f"reference-integrity:{index}",
                        severity,
                        "reference_integrity_error",
                        str(
                            item.get("message")
                            or item.get("status")
                            or "Reference integrity failed."
                        ),
                        str(item.get("path") or reference_path),
                    )
                )

    controls_contract_valid = controls.get("schema") == CONTROLS_SCHEMA_ID
    if controls_kind == "artifact" and not controls_contract_valid:
        findings.append(
            finding(
                "secure-coding-controls:contract",
                severity,
                "source_schema_error",
                f"P2 report schema must be {CONTROLS_SCHEMA_ID!r}.",
                str(controls_path),
            )
        )
    for index, item in enumerate(controls.get("findings") or [], 1):
        if isinstance(item, dict):
            findings.append(
                {
                    **item,
                    "id": f"p2:{item.get('id') or index}",
                    "severity": item.get("severity") or severity,
                    "human_review_required": True,
                    "not_claimed": item.get("not_claimed") or NOT_CLAIMED,
                }
            )

    p2 = controls.get("dimensions")
    if not isinstance(p2, dict):
        p2 = {}
        findings.append(
            finding(
                "secure-coding-controls:dimensions",
                severity,
                "source_schema_error",
                "The P2 report must contain a dimensions object.",
                str(controls_path),
            )
        )
    missing_p2_dimensions = sorted(P2_DIMENSION_KEYS - set(p2))
    if controls_kind == "artifact" and missing_p2_dimensions:
        findings.append(
            finding(
                "secure-coding-controls:dimension-contract",
                severity,
                "source_schema_error",
                "P2 report is missing dimensions: "
                + ", ".join(missing_p2_dimensions),
                str(controls_path),
            )
        )
    controls_valid = (
        controls_kind == "artifact"
        and controls_contract_valid
        and not missing_p2_dimensions
    )
    if (
        controls_kind == "artifact"
        and controls_contract_valid
        and not isinstance(controls.get("standards_snapshot"), dict)
    ):
        findings.append(
            finding(
                "secure-coding-controls:standards-snapshot",
                severity,
                "source_schema_error",
                "P2 report must contain a standards_snapshot object.",
                str(controls_path),
            )
        )

    def dim(name: str, fallback: dict[str, Any]) -> dict[str, Any]:
        value = p2.get(name)
        return value if isinstance(value, dict) else fallback

    register = dim("register_schema_validity", {"state": "unknown"})
    routes = dim("evidence_route_integrity", {"state": "unknown"})
    availability = dim("evidence_availability", {"state_counts": {}})
    freshness = dim(
        "evidence_freshness",
        {"maximum_age_days": None, "stale_routes": 0},
    )
    mappings = dim("mapping_verification", {"status_counts": {}})
    human = dim("human_review", {"outstanding_controls": None})
    mapping_counts = mappings.get("status_counts")
    if not isinstance(mapping_counts, dict):
        mapping_counts = {}
    mapping_verified = (
        int(mapping_counts.get("verified", 0) or 0) > 0
        and int(mapping_counts.get("draft", 0) or 0) == 0
        and int(mapping_counts.get("deprecated", 0) or 0) == 0
        and int(mapping_counts.get("unknown", 0) or 0) == 0
    )

    dimensions = {
        "register_validity": {
            "state": (
                register.get("state", "unknown")
                if controls_valid
                else "invalid"
            ),
            "source": "P2 secure-coding controls report",
            "details": register,
        },
        "reference_integrity": {
            "state": "valid" if reference_valid else "invalid",
            "source": "P1 secure-coding reference-integrity result",
            "summary": reference.get("summary") or {},
            "findings": reference.get("findings") or [],
            "boundaries": reference.get("boundaries") or [],
        },
        "detector_evidence": {
            "state": detector_evidence_state(
                source_valid=controls_valid,
                routes=routes,
                availability=availability,
                freshness=freshness,
            ),
            "source": "P2 detector-to-evidence routing report",
            "route_integrity": routes,
            "availability": availability,
            "freshness": freshness,
        },
        "mapping_verification": {
            "state": "verified" if mapping_verified else "review_required",
            "source": "P2 canonical-register mapping lifecycle metadata",
            "details": mappings,
        },
        "human_review": {
            "state": "required",
            "source": "P2 outstanding human-review declarations",
            "details": human,
        },
    }
    counts = finding_counts(findings)
    return {
        "schema": SCHEMA_ID,
        "generated_at": timestamp(generated_at),
        "profile": profile,
        "status": status_from_counts(counts),
        "project_root": str(root.resolve()),
        "naos_root": naos_root,
        "deterministic": True,
        "check_mode": check_mode,
        "sources": {
            "reference_integrity": {
                "kind": reference_kind,
                "path": str(reference_path),
                "status": reference.get("status"),
                "contract_valid": reference_contract_valid,
            },
            "secure_coding_controls": {
                "kind": controls_kind,
                "path": str(controls_path),
                "status": controls.get("status"),
                "contract_valid": controls_contract_valid,
            },
        },
        "standards_snapshot": standards_snapshot(controls, controls_valid),
        "summary": {
            **counts,
            "dimensions": 5,
            "dimension_keys": list(DIMENSION_KEYS),
            "human_review_required": True,
        },
        "dimensions": dimensions,
        "projection": {},
        "findings": findings,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": True,
    }


def schema_errors(
    report: dict[str, Any],
    schema_path: Path,
) -> list[dict[str, str]]:
    schema = load_object(schema_path)
    validator = jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    result: list[dict[str, str]] = []
    for error in sorted(
        validator.iter_errors(report),
        key=lambda item: list(item.absolute_path),
    ):
        location = "$" + "".join(
            f"[{part}]" if isinstance(part, int) else f".{part}"
            for part in error.absolute_path
        )
        result.append({"path": location, "message": error.message})
    return result
