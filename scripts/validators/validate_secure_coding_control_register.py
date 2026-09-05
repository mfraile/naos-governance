#!/usr/bin/env python3
"""Validate the NAOS secure/agentic coding register without claiming security."""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REGISTER = ROOT / "configs/secure_coding_control_register.yaml"
DEFAULT_SCHEMA = ROOT / "schemas/naos/secure_coding_control_register.schema.json"
FORBIDDEN = {"enforcement_by_profile", "severity_by_profile", "blocking_by_profile", "exit_code_by_profile"}
BACKBONES = {
    "secure_coding": {"owasp_asvs", "nist_ssdf"},
    "agentic_coding": {"owasp_llm", "owasp_agentic", "nist_ai_rmf"},
}
VERSION_PATTERNS = {
    "owasp_asvs": re.compile(r"^v5\.0\.0-"),
    "owasp_top10": re.compile(r":2025$"),
    "owasp_llm": re.compile(r":2025$"),
    "owasp_agentic": re.compile(r":2026$"),
    "aicm": re.compile(r"^(?:AIS|GRC)-[0-9]{2}$"),
}
AICM_VERSION = "1.1.1"
AICM_SOURCE = "https://cloudsecurityalliance.org/artifacts/aicm-machine-readable-bundle-json-yaml-oscal"
AICM_SOURCE_RELEASE = "2026-08-04"
AICM_SOURCE_DATASET_SHA256 = "864d4bec6d8843c138810f05ea95094f4c7c41e614d3b04f05e010aa2c7f519d"
AICM_SELECTED_CONTROL_IDS = frozenset(
    {"AIS-04", "AIS-11", "AIS-12", "GRC-04", "GRC-06", "GRC-15"}
)
AICM_REQUIRED_REGISTER_VERSION = "1.1.0"
AICM_CLAIM_POSTURE = "relevance_only"
AICM_DECISION_USE = (
    "Bound an adopter's review of which NAOS build-time evidence may support AICM "
    "scoping and which responsibilities require adopter or runtime controls."
)
AICM_SCOPE = (
    "SDLC process, declared agent boundaries, source-management evidence, responsibility "
    "and exception routing, and human-review evidence only."
)
AICM_REQUIRED_NON_CLAIMS = frozenset(
    {
        "AICM compliance",
        "control satisfaction",
        "certification",
        "runtime security",
        "enterprise exception-process operation",
        "enterprise responsibility-model completeness",
        "effective human supervision",
    }
)
AICM_APPROVED_BINDINGS = {
    "SC-DEPENDENCY-01": {
        "ids": frozenset({"AIS-04", "AIS-12"}),
        "note": (
            "Local dependency declaration and review evidence is relevant only to a bounded "
            "part of secure SDLC and source-management practice."
        ),
    },
    "AC-TOOL-AUTHORITY-01": {
        "ids": frozenset({"AIS-11", "GRC-04", "GRC-06", "GRC-15"}),
        "note": (
            "Declared tool authority and human approval routing provide build-time relevance "
            "only; they do not operate runtime boundaries, an enterprise exception process, "
            "an enterprise responsibility model, or effective supervision."
        ),
    },
    "AC-CLAIM-INTEGRITY-01": {
        "ids": frozenset({"AIS-04", "AIS-12"}),
        "note": (
            "Evidence-integrity and review records support only a bounded SDLC and "
            "source-management discussion; they do not prove that either AICM control is "
            "implemented."
        ),
    },
    "AC-AUTONOMY-BOUNDARY-01": {
        "ids": frozenset({"AIS-11", "GRC-15"}),
        "note": (
            "Declared autonomy boundaries and required human review are build-time evidence "
            "only, not runtime boundary enforcement or effective supervision proof."
        ),
    },
}
INDIRECT_ONLY = {
    "AC-DEP-HALLUCINATION-01": {"CAP-DEPENDENCY-INTEGRITY"},
    "AC-CONTEXT-LEAK-01": {"CAP-SECRET-HYGIENE"},
    "AC-CLAIM-INTEGRITY-01": {"CAP-PR-RISK-CLASSIFICATION", "VALIDATOR-CLAIMS"},
    "AC-AUTONOMY-BOUNDARY-01": {"VALIDATOR-AGENT-TRACE"},
}
BOUNDARIES = [
    "Schema validity is not evidence that application code is secure.",
    "Crosswalk mappings are relevance claims, not satisfaction or compliance claims.",
    "The register does not own profile severity, blocking policy, gate decisions, waivers, or approvals.",
]


def load(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    return json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)


def finding(items: list[dict[str, str]], status: str, path: str, message: str) -> None:
    items.append({"status": status, "path": path, "message": message})


def walk_keys(value: Any, path: str = "$"):
    if isinstance(value, dict):
        for key, child in value.items():
            here = f"{path}.{key}"
            yield here, str(key)
            yield from walk_keys(child, here)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_keys(child, f"{path}[{index}]")


def validate_register(register: dict[str, Any], schema: dict[str, Any], root: Path = ROOT) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    schema_validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    for error in sorted(schema_validator.iter_errors(register), key=lambda item: list(item.path)):
        path = "$" + "".join(f"[{part}]" if isinstance(part, int) else f".{part}" for part in error.absolute_path)
        finding(findings, "schema_error", path, error.message)

    for path, key in walk_keys(register):
        if key in FORBIDDEN:
            finding(findings, "forbidden_authority_field", path, f"{key} would create a second policy authority")

    controls = register.get("controls") if isinstance(register.get("controls"), list) else []
    ids = [
        control.get("id")
        for control in controls
        if isinstance(control, dict) and isinstance(control.get("id"), str)
    ]
    for control_id, count in Counter(ids).items():
        if control_id and count > 1:
            finding(findings, "duplicate_control_id", "$.controls", f"{control_id} appears {count} times")

    catalog = register.get("detector_catalog") if isinstance(register.get("detector_catalog"), dict) else {}
    standards = register.get("standards") if isinstance(register.get("standards"), dict) else {}
    planes = register.get("planes") if isinstance(register.get("planes"), dict) else {}
    aicm = standards.get("aicm") if isinstance(standards.get("aicm"), dict) else None
    if (
        register.get("status") == "active"
        and str(register.get("version") or "") == AICM_REQUIRED_REGISTER_VERSION
        and aicm is None
    ):
        finding(
            findings,
            "aicm_required",
            "$.standards.aicm",
            f"active register version {AICM_REQUIRED_REGISTER_VERSION} requires the bounded AICM contract",
        )
    if aicm is not None:
        expected = {
            "name": "CSA AI Controls Matrix",
            "version": AICM_VERSION,
            "role": "reference",
            "source": AICM_SOURCE,
            "source_release": AICM_SOURCE_RELEASE,
            "source_dataset_sha256": AICM_SOURCE_DATASET_SHA256,
            "mapping_default_status": "draft",
        }
        for field, expected_value in expected.items():
            if str(aicm.get(field) or "") != expected_value:
                finding(
                    findings,
                    "aicm_source_mismatch",
                    f"$.standards.aicm.{field}",
                    f"expected {expected_value!r}",
                )
        selected = aicm.get("selected_control_ids")
        selected_ids = set(selected) if isinstance(selected, list) and all(isinstance(item, str) for item in selected) else set()
        if selected_ids != AICM_SELECTED_CONTROL_IDS:
            finding(
                findings,
                "aicm_selection_mismatch",
                "$.standards.aicm.selected_control_ids",
                "selection must be exactly " + ", ".join(sorted(AICM_SELECTED_CONTROL_IDS)),
            )
        posture = {
            "claim_posture": AICM_CLAIM_POSTURE,
            "decision_use": AICM_DECISION_USE,
            "scope": AICM_SCOPE,
        }
        for field, expected_value in posture.items():
            if aicm.get(field) != expected_value:
                finding(
                    findings,
                    "aicm_posture_mismatch",
                    f"$.standards.aicm.{field}",
                    f"expected the approved bounded value {expected_value!r}",
                )
        non_claims = aicm.get("non_claims")
        observed_non_claims = (
            set(non_claims)
            if isinstance(non_claims, list) and all(isinstance(item, str) for item in non_claims)
            else set()
        )
        if observed_non_claims != AICM_REQUIRED_NON_CLAIMS:
            finding(
                findings,
                "aicm_non_claim_mismatch",
                "$.standards.aicm.non_claims",
                "non-claims must be exactly " + ", ".join(sorted(AICM_REQUIRED_NON_CLAIMS)),
            )

    for detector_id, entry in catalog.items():
        if isinstance(entry, dict) and isinstance(entry.get("path"), str) and not (root / entry["path"]).exists():
            finding(findings, "missing_detector_host", f"$.detector_catalog.{detector_id}.path", entry["path"])

    mapped_aicm_ids: set[str] = set()
    mapped_aicm_bindings: dict[str, dict[str, Any]] = {}
    for index, control in enumerate(controls):
        if not isinstance(control, dict):
            continue
        base = f"$.controls[{index}]"
        control_id = str(control.get("id", index))
        evaluation = control.get("evaluation") if isinstance(control.get("evaluation"), dict) else {}
        detectors = evaluation.get("detectors") if isinstance(evaluation.get("detectors"), list) else []
        coverage = evaluation.get("coverage")

        for detector_id in detectors:
            if not isinstance(detector_id, str):
                continue
            if "+" in detector_id:
                finding(findings, "invalid_combined_detector_reference", f"{base}.evaluation.detectors", detector_id)
            elif detector_id not in catalog:
                finding(findings, "unknown_detector", f"{base}.evaluation.detectors", detector_id)
        if coverage == "none" and detectors:
            finding(findings, "coverage_detector_mismatch", f"{base}.evaluation", "none coverage cannot declare detectors")
        if coverage in {"direct", "partial", "indirect"} and not detectors:
            finding(findings, "coverage_detector_mismatch", f"{base}.evaluation", f"{coverage} coverage requires a detector")
        if control_id in INDIRECT_ONLY and coverage == "direct" and set(detectors) & INDIRECT_ONLY[control_id]:
            finding(findings, "detector_scope_overclaim", f"{base}.evaluation.coverage", "declared detector is indirect for this control")

        crosswalk = control.get("crosswalk") if isinstance(control.get("crosswalk"), dict) else {}
        for framework, mapping in crosswalk.items():
            path = f"{base}.crosswalk.{framework}"
            if framework not in standards:
                finding(findings, "unknown_framework", path, framework)
                continue
            if not isinstance(mapping, dict):
                continue
            status = mapping.get("status")
            mapping_ids = mapping.get("ids", [])
            if status == "verified" and not mapping.get("verified_on"):
                finding(findings, "unproven_verified_mapping", path, "verified mapping requires verified_on")
            for mapping_id in mapping_ids if isinstance(mapping_ids, list) else []:
                pattern = VERSION_PATTERNS.get(framework)
                if pattern and not pattern.search(str(mapping_id)):
                    name = "unversioned_asvs_reference" if framework == "owasp_asvs" else "framework_version_mismatch"
                    finding(findings, name, path, str(mapping_id))
                if framework == "owasp_asvs" and status == "verified" and "*" in str(mapping_id):
                    finding(findings, "non_specific_verified_asvs_reference", path, str(mapping_id))
                if framework == "aicm":
                    mapped_aicm_bindings[control_id] = mapping
                    mapped_aicm_ids.add(str(mapping_id))
                    if str(mapping_id) not in AICM_SELECTED_CONTROL_IDS:
                        finding(findings, "aicm_control_not_selected", path, str(mapping_id))
            if framework == "aicm" and mapping.get("claim_posture") != AICM_CLAIM_POSTURE:
                finding(
                    findings,
                    "aicm_mapping_posture_mismatch",
                    path,
                    f"AICM mappings require claim_posture {AICM_CLAIM_POSTURE!r}",
                )
        plane = control.get("plane")
        if plane in BACKBONES and not (set(crosswalk) & BACKBONES[plane]):
            finding(findings, "missing_backbone_mapping", f"{base}.crosswalk", str(plane))

    for plane_id, plane in planes.items():
        for framework in plane.get("backbone_frameworks", []) if isinstance(plane, dict) else []:
            if framework not in standards:
                finding(findings, "unknown_backbone_framework", f"$.planes.{plane_id}", str(framework))

    if aicm is not None and mapped_aicm_ids != AICM_SELECTED_CONTROL_IDS:
        finding(
            findings,
            "aicm_selected_control_unmapped",
            "$.controls[*].crosswalk.aicm",
            "mapped AICM ids must equal the exact selected set",
        )
    if aicm is not None:
        observed_controls = set(mapped_aicm_bindings)
        expected_controls = set(AICM_APPROVED_BINDINGS)
        if observed_controls != expected_controls:
            finding(
                findings,
                "aicm_binding_control_mismatch",
                "$.controls[*].crosswalk.aicm",
                "AICM mappings must be attached exactly to " + ", ".join(sorted(expected_controls)),
            )
        for control_id, expected_binding in AICM_APPROVED_BINDINGS.items():
            mapping = mapped_aicm_bindings.get(control_id)
            if not isinstance(mapping, dict):
                continue
            raw_ids = mapping.get("ids")
            observed_ids = (
                set(raw_ids)
                if isinstance(raw_ids, list) and all(isinstance(item, str) for item in raw_ids)
                else set()
            )
            if observed_ids != expected_binding["ids"]:
                finding(
                    findings,
                    "aicm_binding_mismatch",
                    f"$.controls[{control_id}].crosswalk.aicm.ids",
                    "expected " + ", ".join(sorted(expected_binding["ids"])),
                )
            if mapping.get("status") != "draft":
                finding(
                    findings,
                    "aicm_mapping_status_mismatch",
                    f"$.controls[{control_id}].crosswalk.aicm.status",
                    "AICM relevance mappings remain draft pending independent semantic verification",
                )
            if mapping.get("claim_posture") != AICM_CLAIM_POSTURE:
                finding(
                    findings,
                    "aicm_mapping_posture_mismatch",
                    f"$.controls[{control_id}].crosswalk.aicm.claim_posture",
                    f"expected {AICM_CLAIM_POSTURE!r}",
                )
            if mapping.get("note") != expected_binding["note"]:
                finding(
                    findings,
                    "aicm_mapping_boundary_mismatch",
                    f"$.controls[{control_id}].crosswalk.aicm.note",
                    "mapping note must preserve the approved relevance-only boundary",
                )

    summary = {
        "controls": len(controls),
        "detectors": len(catalog),
        "frameworks": len(standards),
        "findings": len(findings),
        "errors": len(findings),
    }
    return {
        "validator": "validate_secure_coding_control_register",
        "register_schema": register.get("schema"),
        "status": "pass" if not findings else "fail",
        "summary": summary,
        "findings": findings,
        "boundaries": BOUNDARIES,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--register", type=Path, default=DEFAULT_REGISTER)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = validate_register(load(args.register), load(args.schema), args.root)
    except Exception as exc:
        report = {
            "validator": "validate_secure_coding_control_register",
            "status": "error",
            "summary": {"errors": 1},
            "findings": [{"status": "load_error", "path": "$", "message": str(exc)}],
            "boundaries": BOUNDARIES,
        }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"NAOS control-register validation: {report['status']} ({report['summary'].get('errors', 0)} error(s))")
        for item in report.get("findings", []):
            print(f"- {item['status']}: {item['path']}: {item['message']}")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
