#!/usr/bin/env python3
"""Validate one profile-proportionate, structured NAOS research record."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    default_naos_root,
    kit_root,
    load_policy,
    normalize_profile,
    report_output_path,
    write_report,
)


REPORT_SCHEMA = "naos.research_record_validation.v1"
RECORD_SCHEMA = "naos.research_record.v1"
CONTRACT_SCHEMA = "naos.research_record_contract.v1"


def load_mapping(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected a mapping: {path}")
    return data


def resolve_project_or_kit(root: Path, naos_root: str, project_name: str, kit_relative: str) -> tuple[Path, str]:
    project_path = root / naos_root / project_name
    if project_path.is_file():
        return project_path, "project"
    return kit_root() / kit_relative, "kit"


def validate_record(
    record: dict[str, Any],
    contract: dict[str, Any],
    schema_path: Path,
    expected_profile: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if record.get("schema") != RECORD_SCHEMA:
        findings.append({"id": "research_record.schema", "message": f"Expected schema {RECORD_SCHEMA}."})
    record_profile = str(record.get("profile") or "")
    if record_profile != expected_profile:
        findings.append(
            {
                "id": "research_record.profile_mismatch",
                "message": f"Record profile {record_profile!r} does not match requested profile {expected_profile!r}.",
            }
        )
    required = ((contract.get("profiles") or {}).get(expected_profile) or {}).get("required_fields") or []
    nullable_required = set(contract.get("nullable_required_fields") or [])
    for field in required:
        if field not in record or (field not in nullable_required and record.get(field) in (None, "", [])):
            findings.append({"id": "research_record.required_field", "field": field, "message": f"Required field is empty: {field}."})

    try:
        import jsonschema

        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        for error in sorted(jsonschema.Draft202012Validator(schema).iter_errors(record), key=lambda item: list(item.path)):
            location = ".".join(str(item) for item in error.absolute_path) or "$"
            findings.append(
                {
                    "id": "research_record.schema_validation",
                    "field": location,
                    "message": error.message,
                }
            )
    except ImportError:
        findings.append(
            {
                "id": "research_record.schema_engine_unavailable",
                "message": "jsonschema is unavailable; only the profile required-field subset was checked.",
                "severity": "advisory",
            }
        )

    source_refs = {
        str(item.get("ref"))
        for item in record.get("sources") or []
        if isinstance(item, dict) and item.get("ref")
    }
    allowed_claim_types = set(contract.get("claim_types") or [])
    allowed_postures = set(contract.get("claim_postures") or [])
    allowed_uncertainty = set(contract.get("uncertainty_levels") or [])
    quality_contract = contract.get("source_quality_dimensions") or {}
    for index, source in enumerate(record.get("sources") or []):
        if not isinstance(source, dict):
            findings.append({"id": "research_record.source_provenance", "field": f"sources.{index}", "message": "Source must be a mapping."})
            continue
        for field in ("ref", "identity", "locator", "kind", "version_or_date_or_commit", "quality"):
            if field not in source or (field != "version_or_date_or_commit" and source.get(field) in (None, "", {})):
                findings.append({"id": "research_record.source_provenance", "field": f"sources.{index}.{field}", "message": f"Source provenance field is missing: {field}."})
        quality = source.get("quality") if isinstance(source.get("quality"), dict) else {}
        for field in ("authority", "recency", "directness"):
            if quality.get(field) not in set(quality_contract.get(field) or []):
                findings.append({"id": "research_record.source_quality", "field": f"sources.{index}.quality.{field}", "message": f"Source quality field is missing or unsupported: {field}."})
    for index, contradiction in enumerate(record.get("contradictions") or []):
        if not isinstance(contradiction, dict):
            continue
        for evidence_ref in contradiction.get("evidence_refs") or []:
            if str(evidence_ref) not in source_refs:
                findings.append(
                    {
                        "id": "research_record.unresolved_contradiction_ref",
                        "field": f"contradictions.{index}.evidence_refs",
                        "message": f"Contradiction evidence ref is not declared in sources: {evidence_ref}.",
                    }
                )
    for index, observation in enumerate(record.get("observations") or []):
        if not isinstance(observation, dict):
            continue
        if observation.get("claim_type") not in allowed_claim_types:
            findings.append({"id": "research_record.claim_type", "field": f"observations.{index}.claim_type", "message": "Claim type is missing or unsupported."})
        if observation.get("posture") not in allowed_postures:
            findings.append({"id": "research_record.claim_posture", "field": f"observations.{index}.posture", "message": "Claim posture is missing or unsupported."})
        if observation.get("uncertainty") not in allowed_uncertainty:
            findings.append({"id": "research_record.uncertainty", "field": f"observations.{index}.uncertainty", "message": "Uncertainty is missing or unsupported."})
        for evidence_ref in observation.get("evidence_refs") or []:
            if str(evidence_ref) not in source_refs:
                findings.append(
                    {
                        "id": "research_record.unresolved_evidence_ref",
                        "field": f"observations.{index}.evidence_refs",
                        "message": f"Observation evidence ref is not declared in sources: {evidence_ref}.",
                    }
                )
    supersedes = record.get("supersedes")
    if supersedes and str(supersedes) == str(record.get("id")):
        findings.append(
            {
                "id": "research_record.self_supersession",
                "field": "supersedes",
                "message": "A research record cannot supersede itself.",
            }
        )
    authority = record.get("authority") if isinstance(record.get("authority"), dict) else {}
    if authority.get("posture") != "candidate_only" or authority.get("explicit_attributable_transition_required") is not True:
        findings.append(
            {
                "id": "research_record.hidden_authority_promotion",
                "field": "authority",
                "message": "Research records must remain candidate_only and require an explicit attributable transition.",
            }
        )
    review = record.get("review") if isinstance(record.get("review"), dict) else {}
    if review.get("state") in {"reviewed_candidate", "rejected", "retired"} and not (
        str(review.get("reviewer") or "").strip() and str(review.get("reviewed_at") or "").strip()
    ):
        findings.append(
            {
                "id": "research_record.unattributed_review",
                "field": "review",
                "message": "A completed review disposition requires reviewer and reviewed_at attribution.",
            }
        )
    record_state = record.get("record_state")
    if record_state == "superseded" and not record.get("superseded_by"):
        findings.append({"id": "research_record.supersession_missing", "field": "superseded_by", "message": "Superseded records require superseded_by."})
    if record_state == "retired" and not record.get("retirement_reason"):
        findings.append({"id": "research_record.retirement_missing", "field": "retirement_reason", "message": "Retired records require retirement_reason."})
    return findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate one structured NAOS research record.")
    parser.add_argument("record", type=Path)
    parser.add_argument("--profile", choices=["quickstart", "lite", "standard", "assured"])
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--contract", type=Path)
    parser.add_argument("--schema", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    contract_path, contract_source = resolve_project_or_kit(
        root,
        naos_root,
        "research_record_contract.yaml",
        "templates/structural-seeds/naos/research_record_contract.yaml",
    )
    if args.contract:
        contract_path, contract_source = args.contract, "explicit"
    schema_path = args.schema or (root / "schemas" / "naos" / "research_record.schema.json")
    if not schema_path.is_file():
        schema_path = kit_root() / "schemas" / "naos" / "research_record.schema.json"
    try:
        record = load_mapping(args.record)
        contract = load_mapping(contract_path)
        if contract.get("schema") != CONTRACT_SCHEMA:
            raise ValueError(f"Unsupported research record contract: {contract.get('schema')!r}")
        findings = validate_record(record, contract, schema_path, profile)
        substantive = [item for item in findings if item.get("severity") != "advisory"]
        outcome = (record.get("outcome") or {}).get("state")
        status = "invalid" if substantive else "valid"
        report = {
            "schema": REPORT_SCHEMA,
            "status": status,
            "profile": profile,
            "record_id": record.get("id"),
            "research_outcome": outcome,
            "record_path": str(args.record),
            "contract": {"path": str(contract_path), "source": contract_source},
            "record_schema_path": str(schema_path),
            "findings": findings,
            "human_review_required": bool((record.get("next_action") or {}).get("requires_human_review")) or outcome == "inconclusive",
            "limitations": list(record.get("limitations") or []),
            "not_claimed": list(record.get("not_claimed") or []) + [
                "implementation, merge, release, evidence admission, or compliance authority"
            ],
            "summary": {
                "status": status,
                "research_outcome": outcome,
                "total_findings": len(findings),
                "required": len(substantive),
                "advisory": len(findings) - len(substantive),
                "warning": 0,
                "blocking": 0,
                "human_review_required": bool((record.get("next_action") or {}).get("requires_human_review")) or outcome == "inconclusive",
            },
        }
    except Exception as exc:
        report = {
            "schema": REPORT_SCHEMA,
            "status": "invalid",
            "profile": profile,
            "record_id": None,
            "research_outcome": None,
            "record_path": str(args.record),
            "findings": [{"id": "research_record.load_error", "message": str(exc)}],
            "human_review_required": True,
            "limitations": ["The research record could not be validated."],
            "not_claimed": ["implementation, merge, release, evidence admission, or compliance authority"],
            "summary": {"status": "invalid", "research_outcome": None, "total_findings": 1, "required": 1, "advisory": 0, "warning": 0, "blocking": 0, "human_review_required": True},
        }
    output = args.output or report_output_path(root, naos_root, policy, "research_record_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"NAOS research record ({profile}): {report['status']} / {report.get('research_outcome')}")
        print(f"report: {output}")
    return 0 if report["status"] == "valid" else 2


if __name__ == "__main__":
    raise SystemExit(main())
