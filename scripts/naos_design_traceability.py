#!/usr/bin/env python3
"""Review optional UI spec-object identity and design traceability declarations.

This command is deterministic local review evidence only. It does not call
Figma, MCP, html.to.design, providers, models, memory tools, browsers, APIs, or
networks; it does not mutate design tools or source code; and it does not prove
design quality, accessibility, privacy, brand correctness, compliance, approval,
merge readiness, release readiness, certification, or attestation.
"""

from __future__ import annotations

import argparse
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


REPORT_SCHEMA = "naos.design_traceability.v1"
ALLOWED_OBJECT_TYPES = {
    "screen",
    "screen_section",
    "component",
    "interaction",
    "content_block",
    "data_display",
}
ALLOWED_OBJECT_STATUSES = {
    "planned",
    "designed",
    "implemented",
    "modified",
    "review_required",
    "retired",
}
IMPLEMENTED_STATUSES = {"implemented", "modified", "review_required"}
REASON_ORDER = [
    "duplicate_object_id",
    "missing_object_id",
    "missing_fr_nfr_task_link",
    "missing_screen_spec_path",
    "missing_implementation_path",
    "referenced_path_missing",
    "changed_file_evidence_gap",
    "test_evidence_gap",
    "optional_design_ref_unreviewed",
    "stale_or_conflicting_evidence",
    "human_review_disposition_missing",
]
REASON_GATES = {
    "duplicate_object_id": ["G2", "G6"],
    "missing_object_id": ["G2", "G6"],
    "missing_fr_nfr_task_link": ["G2", "G6"],
    "missing_screen_spec_path": ["G2", "G6"],
    "missing_implementation_path": ["G3", "G4"],
    "referenced_path_missing": ["G3", "G6"],
    "changed_file_evidence_gap": ["G4"],
    "test_evidence_gap": ["G5"],
    "optional_design_ref_unreviewed": ["G6"],
    "stale_or_conflicting_evidence": ["G6"],
    "human_review_disposition_missing": ["G6"],
}
LIMITATIONS = [
    "Design traceability reports evaluate local declarations and local path references only.",
    "Optional design-tool references are treated as references, not proof of design state or sync.",
    "The report does not inspect Figma, MCP, html.to.design, browsers, screenshots, runtime UI, providers, models, memory tools, APIs, or networks.",
    "Path existence and evidence presence do not prove design quality, accessibility, privacy, brand correctness, implementation correctness, or user-experience quality.",
    "Assured-profile blocking is not enabled by this implementation; findings remain review evidence unless a later validated maturity control changes posture.",
]
NOT_CLAIMED = [
    "automatic code-to-design synchronization",
    "automatic design-to-code synchronization",
    "Figma availability",
    "Figma API access",
    "MCP activation",
    "html.to.design fidelity",
    "design quality proof",
    "accessibility compliance proof",
    "privacy compliance proof",
    "brand compliance proof",
    "user-experience correctness proof",
    "approval",
    "merge approval",
    "task completion proof",
    "release authority",
    "publication authority",
    "certification",
    "attestation",
    "legal sufficiency",
    "compliance proof",
    "runtime orchestration",
    "provider calls",
    "model calls",
    "memory activation",
]
RESIDUAL_RISKS = [
    "object_identity_overtrust",
    "manual_design_refs_can_be_stale",
    "local_path_refs_do_not_prove_semantics",
    "design_tool_state_not_inspected",
    "accessibility_privacy_brand_quality_require_separate_review",
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


def is_adapt_placeholder(value: Any) -> bool:
    return isinstance(value, str) and value.strip().startswith("[ADAPT:")


def is_empty_or_placeholder(value: Any) -> bool:
    return value in (None, "") or is_adapt_placeholder(value)


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
    return kit_root() / "templates" / "structural-seeds" / "naos" / "design_traceability.yaml"


def resolve_declaration_path(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    explicit: str | None = None,
) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("design_traceability") or "design_traceability.yaml")
    project_declaration = root / naos_root / filename
    if project_declaration.exists():
        return project_declaration, "project"
    return default_declaration_template(), "template"


def relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve(strict=False).relative_to(root.resolve()))
    except ValueError:
        return str(path)


def path_status(root: Path, value: Any) -> tuple[str | None, bool, bool]:
    text = str(value or "").strip()
    if not text or is_adapt_placeholder(text):
        return text or None, False, False
    candidate = Path(text)
    if candidate.is_absolute() or ".." in candidate.parts:
        return text, False, False
    target = (root / candidate).resolve(strict=False)
    root_resolved = root.resolve()
    if root_resolved not in (target, *target.parents):
        return text, False, False
    return text, True, target.exists()


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
    object_id: str | None = None,
    path: str | None = None,
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
    if object_id:
        item["object_id"] = object_id
    if path:
        item["path"] = path
    item.update({key: value for key, value in extra.items() if value is not None})
    return item


def normalize_design_refs(value: Any) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for item in as_list(value):
        if isinstance(item, dict):
            ref = str(item.get("ref") or item.get("url") or item.get("node_id") or "").strip()
            refs.append(
                {
                    "ref": ref,
                    "kind": item.get("kind"),
                    "reviewed": bool_value(item.get("reviewed"), default=False),
                    "notes": item.get("notes"),
                }
            )
        elif str(item).strip():
            refs.append({"ref": str(item).strip(), "kind": None, "reviewed": False, "notes": None})
    return refs


def normalize_object(raw: dict[str, Any], index: int, root: Path) -> dict[str, Any]:
    object_id = str(raw.get("object_id") or raw.get("id") or "").strip()
    object_type = str(raw.get("object_type") or raw.get("type") or "").strip()
    status = str(raw.get("status") or "").strip()
    screen_spec_path, screen_path_safe, screen_path_exists = path_status(root, raw.get("screen_spec_path"))
    implementation_paths = []
    for item in string_list(raw.get("implementation_paths")):
        text, safe, exists = path_status(root, item)
        implementation_paths.append({"path": text, "safe": safe, "exists": exists})
    return {
        "index": index,
        "object_id": object_id or None,
        "object_type": object_type or None,
        "status": status or None,
        "fr_refs": string_list(raw.get("fr_refs")),
        "nfr_refs": string_list(raw.get("nfr_refs")),
        "task_refs": string_list(raw.get("task_refs")),
        "screen_spec_path": screen_spec_path,
        "screen_spec_path_safe": screen_path_safe,
        "screen_spec_path_exists": screen_path_exists,
        "implementation_paths": implementation_paths,
        "changed_file_refs": string_list(raw.get("changed_file_refs")),
        "test_evidence_refs": string_list(raw.get("test_evidence_refs")),
        "optional_design_refs": normalize_design_refs(raw.get("optional_design_refs")),
        "design_ref_reviewed": bool_value(raw.get("design_ref_reviewed"), default=False),
        "human_review_required": bool_value(raw.get("human_review_required"), default=False),
        "review_disposition": raw.get("review_disposition"),
        "residual_risks": string_list(raw.get("residual_risks")),
        "non_claims": string_list(raw.get("non_claims")),
    }


def evaluate_object(raw: dict[str, Any], normalized: dict[str, Any], root: Path, severity: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    object_id = normalized.get("object_id") or f"object[{normalized['index']}]"
    status = str(normalized.get("status") or "")

    if not normalized.get("object_id") or is_adapt_placeholder(normalized.get("object_id")):
        findings.append(
            finding(
                "design_traceability.missing_object_id",
                severity,
                "missing_object_id",
                "Design traceability object is missing a stable object_id.",
                object_id=str(object_id),
            )
        )

    if normalized.get("object_type") not in ALLOWED_OBJECT_TYPES:
        findings.append(
            finding(
                "design_traceability.invalid_object_type",
                severity,
                "stale_or_conflicting_evidence",
                "Design traceability object has an unsupported object_type.",
                object_id=str(object_id),
                object_type=normalized.get("object_type"),
            )
        )

    if status not in ALLOWED_OBJECT_STATUSES:
        findings.append(
            finding(
                "design_traceability.invalid_status",
                severity,
                "stale_or_conflicting_evidence",
                "Design traceability object has an unsupported status.",
                object_id=str(object_id),
                object_status=normalized.get("status"),
            )
        )

    if not (normalized["fr_refs"] or normalized["nfr_refs"] or normalized["task_refs"]):
        findings.append(
            finding(
                "design_traceability.missing_fr_nfr_task_link",
                severity,
                "missing_fr_nfr_task_link",
                "Object is missing FR, NFR, or task references.",
                object_id=str(object_id),
            )
        )

    if status != "retired" and is_empty_or_placeholder(raw.get("screen_spec_path")):
        findings.append(
            finding(
                "design_traceability.missing_screen_spec_path",
                severity,
                "missing_screen_spec_path",
                "Object is missing a local screen_spec_path.",
                object_id=str(object_id),
            )
        )
    elif normalized.get("screen_spec_path") and (
        not normalized.get("screen_spec_path_safe") or not normalized.get("screen_spec_path_exists")
    ):
        findings.append(
            finding(
                "design_traceability.referenced_path_missing.screen_spec",
                severity,
                "referenced_path_missing",
                "Object screen_spec_path is unsafe or does not exist locally.",
                object_id=str(object_id),
                path=str(normalized.get("screen_spec_path")),
            )
        )

    implementation_paths = normalized["implementation_paths"]
    if status in IMPLEMENTED_STATUSES and not implementation_paths:
        findings.append(
            finding(
                "design_traceability.missing_implementation_path",
                severity,
                "missing_implementation_path",
                "Implemented or review-required object is missing implementation_paths.",
                object_id=str(object_id),
            )
        )
    for path_item in implementation_paths:
        if path_item.get("path") and (not path_item.get("safe") or not path_item.get("exists")):
            findings.append(
                finding(
                    "design_traceability.referenced_path_missing.implementation",
                    severity,
                    "referenced_path_missing",
                    "Object implementation path is unsafe or does not exist locally.",
                    object_id=str(object_id),
                    path=str(path_item.get("path")),
                )
            )

    if status in IMPLEMENTED_STATUSES and not normalized["changed_file_refs"]:
        findings.append(
            finding(
                "design_traceability.changed_file_evidence_gap",
                severity,
                "changed_file_evidence_gap",
                "Implemented or review-required object is missing changed_file_refs.",
                object_id=str(object_id),
            )
        )

    if status in IMPLEMENTED_STATUSES and not normalized["test_evidence_refs"]:
        findings.append(
            finding(
                "design_traceability.test_evidence_gap",
                severity,
                "test_evidence_gap",
                "Implemented or review-required object is missing test_evidence_refs.",
                object_id=str(object_id),
            )
        )

    design_refs = normalized["optional_design_refs"]
    any_ref_unreviewed = any(not item.get("reviewed") for item in design_refs)
    if design_refs and (not normalized.get("design_ref_reviewed") or any_ref_unreviewed):
        findings.append(
            finding(
                "design_traceability.optional_design_ref_unreviewed",
                severity,
                "optional_design_ref_unreviewed",
                "Optional design references are present without explicit local review posture.",
                object_id=str(object_id),
            )
        )

    if (normalized.get("human_review_required") or status == "review_required") and not normalized.get("review_disposition"):
        findings.append(
            finding(
                "design_traceability.human_review_disposition_missing",
                severity,
                "human_review_disposition_missing",
                "Object requires human review but is missing review_disposition.",
                object_id=str(object_id),
            )
        )

    return findings


def evaluate_objects(raw_objects: Any, root: Path, severity: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    normalized: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    if not isinstance(raw_objects, list):
        return [], [
            finding(
                "design_traceability.objects_not_list",
                severity,
                "stale_or_conflicting_evidence",
                "design_traceability objects must be a list.",
            )
        ]

    for index, item in enumerate(raw_objects):
        if not isinstance(item, dict):
            findings.append(
                finding(
                    "design_traceability.object_not_mapping",
                    severity,
                    "stale_or_conflicting_evidence",
                    "Each design traceability object must be a mapping.",
                    object_id=f"object[{index}]",
                )
            )
            continue
        current = normalize_object(item, index, root)
        normalized.append(current)
        findings.extend(evaluate_object(item, current, root, severity))

    ids = [str(item["object_id"]) for item in normalized if item.get("object_id") and not is_adapt_placeholder(item.get("object_id"))]
    duplicate_ids = {object_id for object_id, count in Counter(ids).items() if count > 1}
    for object_id in sorted(duplicate_ids):
        findings.append(
            finding(
                "design_traceability.duplicate_object_id",
                severity,
                "duplicate_object_id",
                "Stable object_id is declared more than once.",
                object_id=object_id,
            )
        )

    return normalized, findings


def reason_code_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    return {code: sum(1 for item in findings if item.get("reason_code") == code) for code in REASON_ORDER}


def build_report(
    *,
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
    declaration_path: Path,
    declaration_source: str,
) -> dict[str, Any]:
    generated_at = utc_now_text()
    declaration = load_yaml_mapping(declaration_path)
    enabled = bool_value(declaration.get("enabled"), default=False)
    object_identity_declared = bool_value(declaration.get("object_identity_declared"), default=enabled)
    severity = review_severity(profile, root, naos_root)
    raw_objects = declaration.get("objects") or []
    objects, findings = evaluate_objects(raw_objects, root, severity) if enabled else ([], [])

    object_type_counts = Counter(str(item.get("object_type") or "unknown") for item in objects)
    object_status_counts = Counter(str(item.get("status") or "unknown") for item in objects)
    referenced_paths = []
    for item in objects:
        if item.get("screen_spec_path"):
            referenced_paths.append(
                {
                    "path": item.get("screen_spec_path"),
                    "kind": "screen_spec_path",
                    "object_id": item.get("object_id"),
                    "safe": item.get("screen_spec_path_safe"),
                    "exists": item.get("screen_spec_path_exists"),
                }
            )
        for impl in item.get("implementation_paths") or []:
            referenced_paths.append(
                {
                    "path": impl.get("path"),
                    "kind": "implementation_path",
                    "object_id": item.get("object_id"),
                    "safe": impl.get("safe"),
                    "exists": impl.get("exists"),
                }
            )

    summary = finding_counts(findings)
    summary.update(
        {
            "enabled": 1 if enabled else 0,
            "object_identity_declared": 1 if object_identity_declared else 0,
            "objects": len(objects),
            "objects_with_fr_refs": sum(1 for item in objects if item.get("fr_refs")),
            "objects_with_nfr_refs": sum(1 for item in objects if item.get("nfr_refs")),
            "objects_with_task_refs": sum(1 for item in objects if item.get("task_refs")),
            "objects_with_optional_design_refs": sum(1 for item in objects if item.get("optional_design_refs")),
            "referenced_paths": len(referenced_paths),
            "referenced_paths_missing": sum(1 for item in referenced_paths if not item.get("exists")),
            "assured_blocking_enabled": 0,
        }
    )

    if not enabled:
        status = "not_configured"
        human_review_required = False
    elif findings:
        status = status_from_counts(summary)
        human_review_required = True
    else:
        status = "pass"
        human_review_required = bool_value(declaration.get("human_review_required"), default=True)

    known_gaps = string_list(declaration.get("known_gaps"))
    if not enabled:
        known_gaps = list(dict.fromkeys(known_gaps + ["design_traceability_not_enabled"]))
    else:
        known_gaps = list(dict.fromkeys(known_gaps + ["design_quality_not_assessed", "design_tool_state_not_inspected"]))

    not_claimed = list(dict.fromkeys(string_list(declaration.get("not_claimed")) + NOT_CLAIMED))
    residual_risks = list(dict.fromkeys(string_list(declaration.get("residual_risks")) + (RESIDUAL_RISKS if enabled else [])))

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
        "object_identity_declared": object_identity_declared,
        "runtime_enabled": False,
        "design_tool_calls_allowed": False,
        "external_api_calls_allowed": False,
        "tool_mutation_allowed": False,
        "capability_maturity": {
            "current": str(declaration.get("capability_maturity") or "L1"),
            "assured_blocking_enabled": False,
            "blocking_requires_l3_plus_and_gate_wiring": True,
        },
        "profile_posture": as_mapping(declaration.get("profile_posture")),
        "object_type_counts": dict(object_type_counts),
        "object_status_counts": dict(object_status_counts),
        "objects": objects,
        "referenced_paths": referenced_paths,
        "findings": findings,
        "reason_code_counts": reason_code_counts(findings),
        "known_gaps": known_gaps,
        "residual_risks": residual_risks,
        "limitations": LIMITATIONS,
        "not_claimed": not_claimed,
        "human_review_required": human_review_required,
        "generated_by": build_generated_by(root, generated_at=generated_at),
        "summary": summary,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Review local design traceability declarations.")
    parser.add_argument("project", nargs="?", default=".", help="Project root to inspect.")
    parser.add_argument("--profile", default=None, help="NAOS profile.")
    parser.add_argument("--naos-root", default=None, help="NAOS root directory.")
    parser.add_argument("--policy", default=None, help="Optional policy file.")
    parser.add_argument("--design-traceability", default=None, help="Explicit design traceability YAML declaration.")
    parser.add_argument("--output", default=None, help="Output report path.")
    parser.add_argument("--json", action="store_true", help="Print JSON report to stdout.")
    parser.add_argument("--strict", action="store_true", help="Use strict exit-code behavior.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.project).resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    profile = normalize_profile(args.profile, policy)
    naos_root = args.naos_root or default_naos_root(policy)
    declaration_path, declaration_source = resolve_declaration_path(
        root,
        naos_root,
        policy,
        explicit=args.design_traceability,
    )
    report = build_report(
        root=root,
        naos_root=naos_root,
        profile=profile,
        policy=policy,
        declaration_path=declaration_path,
        declaration_source=declaration_source,
    )

    if args.output:
        output = Path(args.output)
    else:
        output = report_output_path(root, naos_root, policy, "design_traceability_report")
    write_report(output, report)
    if args.json or output is None:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"NAOS design traceability: {report['status']} ({report['summary']['total_findings']} findings, output: {output})")
    return exit_code_for_summary(profile, report.get("summary", {}), policy, strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
