#!/usr/bin/env python3
"""Compose adopter-declared compliance posture evidence for review."""

from __future__ import annotations

import argparse
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
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    load_policy,
    normalize_profile,
    report_default_path,
    report_output_path,
    safe_policy_path,
    severity_for_profile,
    write_report,
)


REPORT_SCHEMA = "naos.compliance_posture.v1"
MANIFEST_SCHEMA = "naos.compliance_posture_manifest.v1"
STATUS_VALUES = {"not_configured", "incomplete", "review_ready", "review_required"}
SUPPORTING_REPORT_KEYS = [
    "claims_report",
    "gate_status_report",
    "evidence_attestation_report",
    "evidence_conflict_detection_report",
    "ai_code_provenance_report",
    "control_plane_review_report",
    "systemic_impact_report",
    "behavioral_governance_readiness_report",
]
NOT_CLAIMED = [
    "legal advice",
    "legal opinion",
    "regulatory applicability decision",
    "legal or regulatory compliance",
    "compliance pass/fail",
    "compliance score",
    "compliance certification",
    "conformity assessment",
    "audit opinion",
    "regulatory approval",
    "customer approval",
    "procurement approval",
    "control completion",
    "DORA implementation",
    "OSFI model-risk approval",
    "operational-resilience execution",
    "runtime monitoring",
    "incident reporting",
    "third-party-risk-register completeness",
    "model validation",
    "release authorization",
    "publication authorization",
    "signing",
    "DSSE attestation",
    "SLSA implementation",
    "C2PA implementation",
    "proof of compliance",
]
LIMITATIONS = [
    "This report reads local files and adopter declarations only.",
    "Declared regimes or regulated contexts are review metadata, not an applicability decision.",
    "Evidence references may be incomplete, stale, or outside repository scope.",
    "Missing evidence is recorded as missing or unresolved; the command does not infer sufficiency.",
    "Legal, regulatory, operational, audit, customer, and release decisions remain adopter-owned.",
    "The command does not call models, providers, APIs, memory tools, MCP, legal research services, or the network.",
]


def utc_now() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def clean_text(value: Any) -> str:
    return str(value or "").strip()


def manifest_path_for(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None = None) -> Path:
    if explicit:
        return Path(explicit)
    filename = str(policy.get("paths", {}).get("compliance_posture_manifest") or "compliance_posture.yaml")
    return safe_policy_path(root / naos_root, filename, field="compliance_posture_manifest")


def load_json_report(path: Path) -> tuple[dict[str, Any], str]:
    if not path.exists():
        return {}, "missing"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}, "parse_error"
    if not isinstance(data, dict):
        return {}, "parse_error"
    return data, str(data.get("status") or "present")


def load_manifest(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return None, None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return None, str(exc)
    if not isinstance(data, dict):
        return None, "Compliance posture manifest must parse to a YAML mapping."
    return data, None


def review_severity(profile: str, policy: dict[str, Any], *, advisory: bool = False) -> str:
    return severity_for_profile(profile, policy, advisory=advisory or profile in {"quickstart", "lite"})


def finding(identifier: str, severity: str, status: str, message: str, *, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "id": identifier,
        "severity": severity,
        "status": status,
        "message": message,
        "evidence": evidence or {},
        "human_review_required": True,
        "authority_layer": "review_input_only",
        "not_claimed": [
            "legal conclusion",
            "regulatory applicability decision",
            "compliance approval",
            "certification",
            "proof of compliance",
        ],
    }


def summarize_report_input(root: Path, naos_root: str, policy: dict[str, Any], key: str) -> tuple[dict[str, Any], dict[str, Any]]:
    path = report_default_path(root, naos_root, policy, key)
    data, status = load_json_report(path)
    return (
        {
            "id": key,
            "path": str(path),
            "present": path.exists(),
            "required": False,
            "status": status,
            "schema": data.get("schema"),
            "generated_at": data.get("generated_at"),
        },
        data,
    )


def collect_supporting_evidence(root: Path, naos_root: str, policy: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    inputs: list[dict[str, Any]] = []
    reports: dict[str, dict[str, Any]] = {}
    for key in SUPPORTING_REPORT_KEYS:
        item, data = summarize_report_input(root, naos_root, policy, key)
        inputs.append(item)
        if data:
            reports[key] = data
    return inputs, reports


def local_ref_status(root: Path, reference: str) -> dict[str, Any]:
    text = reference.strip()
    if not text:
        return {"reference": reference, "kind": "empty", "present": False}
    if text.startswith(("http://", "https://")):
        return {"reference": text, "kind": "external_reference", "present": None, "verified": False}
    ref_path = Path(text.split("#", maxsplit=1)[0])
    if ref_path.is_absolute():
        return {"reference": text, "kind": "local_absolute_path", "present": ref_path.exists()}
    candidate = root / ref_path
    return {"reference": text, "kind": "local_relative_path", "present": candidate.exists(), "path": str(candidate)}


def context_missing_fields(context: dict[str, Any]) -> list[str]:
    required = ["context_id", "regime", "jurisdiction", "declared_basis", "reviewer", "reviewed_at"]
    missing = [field for field in required if not clean_text(context.get(field))]
    if not as_list(context.get("evidence_refs")):
        missing.append("evidence_refs")
    return missing


def evaluate_context_refs(root: Path, context_id: str, refs: list[Any]) -> tuple[list[dict[str, Any]], list[str]]:
    statuses: list[dict[str, Any]] = []
    missing: list[str] = []
    for raw_ref in refs:
        reference = clean_text(raw_ref)
        status = local_ref_status(root, reference)
        statuses.append(status)
        if status.get("kind") == "local_relative_path" and status.get("present") is False:
            missing.append(f"{context_id}:{reference}")
        if status.get("kind") == "local_absolute_path":
            missing.append(f"{context_id}:absolute_path_not_portable:{reference}")
    return statuses, missing


def evaluate_manifest(
    root: Path,
    manifest: dict[str, Any] | None,
    manifest_error: str | None,
    manifest_path: Path,
    profile: str,
    policy: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str], list[str]]:
    findings: list[dict[str, Any]] = []
    missing_evidence: list[str] = []
    unresolved_questions: list[str] = []
    if manifest is None and manifest_error:
        findings.append(
            finding(
                "compliance_posture.manifest_parse_error",
                review_severity(profile, policy),
                "review_required",
                "Compliance posture manifest could not be parsed.",
                evidence={"path": str(manifest_path), "error": manifest_error},
            )
        )
        return {"present": True, "path": str(manifest_path), "valid": False, "error": manifest_error}, findings, missing_evidence, unresolved_questions
    if manifest is None:
        findings.append(
            finding(
                "compliance_posture.not_configured",
                "advisory",
                "not_configured",
                "No adopter-declared compliance posture manifest is configured.",
                evidence={"path": str(manifest_path)},
            )
        )
        return {"present": False, "path": str(manifest_path), "valid": False}, findings, missing_evidence, unresolved_questions

    schema_ok = manifest.get("schema") == MANIFEST_SCHEMA
    if not schema_ok:
        findings.append(
            finding(
                "compliance_posture.manifest_schema",
                review_severity(profile, policy),
                "incomplete",
                f"Compliance posture manifest schema must be `{MANIFEST_SCHEMA}`.",
                evidence={"path": str(manifest_path), "schema": manifest.get("schema")},
            )
        )

    posture_scope = as_mapping(manifest.get("posture_scope"))
    no_regulated_context_asserted = bool(posture_scope.get("no_regulated_context_asserted"))
    contexts = [item for item in as_list(manifest.get("declared_contexts")) if isinstance(item, dict)]
    explicit_no_context_review = as_mapping(manifest.get("no_regulated_context_review"))
    context_summaries: list[dict[str, Any]] = []
    status_counts: Counter[str] = Counter()

    if not contexts and not no_regulated_context_asserted:
        return (
            {
                "present": True,
                "path": str(manifest_path),
                "valid": schema_ok,
                "schema": manifest.get("schema"),
                "updated_at": manifest.get("updated_at"),
                "posture_status": clean_text(manifest.get("status")) or "unknown",
                "no_regulated_context_asserted": False,
                "declared_contexts": [],
                "declared_contexts_count": 0,
            },
            findings
            + [
                finding(
                    "compliance_posture.no_declaration",
                    "advisory",
                    "not_configured",
                    "Manifest is present but no regulated context or explicit no-regulated-context declaration is recorded.",
                    evidence={"path": str(manifest_path)},
                )
            ],
            missing_evidence,
            unresolved_questions,
        )

    if no_regulated_context_asserted:
        missing = [
            field
            for field in ["declared_basis", "reviewer", "reviewed_at"]
            if not clean_text(explicit_no_context_review.get(field))
        ]
        if missing:
            findings.append(
                finding(
                    "compliance_posture.no_regulated_context_review_missing",
                    review_severity(profile, policy),
                    "incomplete",
                    "Explicit no-regulated-context declaration is missing review metadata.",
                    evidence={"missing_fields": missing},
                )
            )

    for index, context in enumerate(contexts):
        context_id = clean_text(context.get("context_id")) or f"context_{index}"
        context_status = clean_text(context.get("status")).lower() or "unknown"
        status_counts[context_status] += 1
        refs = as_list(context.get("evidence_refs"))
        ref_statuses, missing_refs = evaluate_context_refs(root, context_id, refs)
        missing_evidence.extend(missing_refs)
        missing_fields = context_missing_fields(context)
        context_summaries.append(
            {
                "context_id": context_id,
                "regime": clean_text(context.get("regime")) or "unknown",
                "jurisdiction": clean_text(context.get("jurisdiction")) or "unknown",
                "status": context_status,
                "evidence_refs": refs,
                "evidence_ref_statuses": ref_statuses,
                "reviewer_present": bool(clean_text(context.get("reviewer"))),
                "reviewed_at_present": bool(clean_text(context.get("reviewed_at"))),
                "missing_fields": missing_fields,
            }
        )
        if missing_fields:
            findings.append(
                finding(
                    f"compliance_posture.{context_id}.missing_fields",
                    review_severity(profile, policy),
                    "incomplete",
                    "Declared compliance context is missing required review fields.",
                    evidence={"missing_fields": missing_fields},
                )
            )
        if context_status != "reviewed":
            findings.append(
                finding(
                    f"compliance_posture.{context_id}.not_reviewed",
                    review_severity(profile, policy),
                    "review_required",
                    "Declared compliance context is not marked reviewed.",
                    evidence={"status": context_status},
                )
            )
        for question in as_list(context.get("unresolved_questions")):
            if clean_text(question):
                unresolved_questions.append(f"{context_id}: {clean_text(question)}")

    for question in as_list(manifest.get("unresolved_questions")):
        if clean_text(question):
            unresolved_questions.append(clean_text(question))
    if unresolved_questions:
        findings.append(
            finding(
                "compliance_posture.unresolved_questions",
                review_severity(profile, policy),
                "review_required",
                "Compliance posture manifest records unresolved review questions.",
                evidence={"questions": unresolved_questions[:20]},
            )
        )
    if missing_evidence:
        findings.append(
            finding(
                "compliance_posture.missing_evidence_refs",
                review_severity(profile, policy),
                "incomplete",
                "Compliance posture declaration references local evidence that is missing or not portable.",
                evidence={"missing_evidence": sorted(set(missing_evidence))[:20]},
            )
        )

    return (
        {
            "present": True,
            "path": str(manifest_path),
            "valid": schema_ok,
            "schema": manifest.get("schema"),
            "updated_at": manifest.get("updated_at"),
            "posture_status": clean_text(manifest.get("status")) or "unknown",
            "no_regulated_context_asserted": no_regulated_context_asserted,
            "no_regulated_context_review": {
                "reviewer_present": bool(clean_text(explicit_no_context_review.get("reviewer"))),
                "reviewed_at_present": bool(clean_text(explicit_no_context_review.get("reviewed_at"))),
            },
            "declared_contexts": context_summaries,
            "declared_contexts_count": len(context_summaries),
            "declared_context_status_counts": dict(sorted(status_counts.items())),
        },
        findings,
        sorted(set(missing_evidence)),
        sorted(set(unresolved_questions)),
    )


def status_from_findings(manifest_summary: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    if not manifest_summary.get("present"):
        return "not_configured"
    statuses = {str(item.get("status")) for item in findings}
    if statuses == {"not_configured"}:
        return "not_configured"
    if "review_required" in statuses:
        return "review_required"
    if "incomplete" in statuses:
        return "incomplete"
    if "not_configured" in statuses:
        return "not_configured"
    return "review_ready"


def command_item(identifier: str, command: str, reason: str) -> dict[str, Any]:
    return {
        "id": identifier,
        "command": command,
        "reason": reason,
        "trigger": "explicit_user",
        "auto_run_allowed": False,
        "review_input_only": True,
    }


def next_steps(status: str, profile: str) -> tuple[list[dict[str, Any]], list[str]]:
    refresh = [
        command_item(
            "compliance_posture",
            f"naos compliance-posture --profile {profile}",
            "Recompute adopter-declared compliance posture evidence.",
        ),
        command_item(
            "evidence_pack",
            f"naos evidence-pack --profile {profile}",
            "Refresh the broader evidence pack after posture review.",
        ),
        command_item(
            "dashboard",
            f"naos dashboard --profile {profile}",
            "Refresh dashboard visibility after posture review.",
        ),
    ]
    if status == "not_configured":
        return refresh, [
            "Decide whether this project needs an adopter-declared compliance posture record.",
            "If yes, fill `naos/compliance_posture.yaml`; if no regulated context is asserted, record that explicitly with reviewer metadata.",
        ]
    if status == "incomplete":
        return refresh, [
            "Complete missing declaration fields and local evidence references.",
            "Rerun Compliance Posture before using the evidence pack for admissibility discussions.",
        ]
    if status == "review_required":
        return [
            *refresh,
            command_item(
                "control_plane_review",
                f"naos control-plane-review --profile {profile}",
                "Route unresolved compliance posture questions through human control-plane review.",
            ),
        ], [
            "Resolve or explicitly accept unresolved posture questions before relying on the declaration.",
            "Do not treat this report as legal, regulatory, audit, customer, procurement, release, or publication approval.",
        ]
    return refresh, [
        "Use the report as human-review input for admissibility or audit handoff.",
        "Keep legal, regulatory, operational, customer, procurement, release, and publication decisions outside this command.",
    ]


def build_report(
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
    manifest_path: Path,
    generated_at: str | None = None,
) -> dict[str, Any]:
    now_text = generated_at or utc_now()
    supporting_inputs, reports = collect_supporting_evidence(root, naos_root, policy)
    manifest, manifest_error = load_manifest(manifest_path)
    manifest_summary, findings, missing_evidence, unresolved_questions = evaluate_manifest(
        root,
        manifest,
        manifest_error,
        manifest_path,
        profile,
        policy,
    )
    status = status_from_findings(manifest_summary, findings)
    commands, actions = next_steps(status, profile)
    summary = finding_counts(findings)
    summary.update(
        {
            "supporting_inputs": len(supporting_inputs),
            "supporting_inputs_present": sum(1 for item in supporting_inputs if item.get("present")),
            "manifest_present": bool(manifest_summary.get("present")),
            "declared_contexts": int(manifest_summary.get("declared_contexts_count") or 0),
            "no_regulated_context_asserted": bool(manifest_summary.get("no_regulated_context_asserted")),
            "missing_evidence": len(missing_evidence),
            "unresolved_questions": len(unresolved_questions),
        }
    )
    return {
        "schema": REPORT_SCHEMA,
        "generated_at": now_text,
        "profile": profile,
        "status": status,
        "command": "compliance-posture",
        "naos_root": naos_root,
        "project_root": str(root),
        "manifest": manifest_summary,
        "supporting_evidence": supporting_inputs,
        "supporting_report_statuses": {
            key: {
                "status": data.get("status"),
                "schema": data.get("schema"),
                "generated_at": data.get("generated_at"),
            }
            for key, data in sorted(reports.items())
        },
        "missing_evidence": missing_evidence,
        "unresolved_questions": unresolved_questions,
        "authority_boundary": {
            "review_input_only": True,
            "adopter_declared_only": True,
            "evidence_pack_composition_only": True,
            "legal_or_regulatory_decision": False,
            "compliance_pass_fail": False,
            "publication_or_release_authority": False,
            "standalone_capability": False,
        },
        "runtime_posture": {
            "runtime_execution_enabled": False,
            "model_provider_api_calls": False,
            "credential_reads": False,
            "network_calls": False,
            "legal_research_calls": False,
            "memory_payload_reads": False,
            "signing_or_notarization": False,
        },
        "cost_posture": {
            "cost_usd": 0.0,
            "cost_incurred_by_default": False,
        },
        "findings": findings,
        "known_gaps": missing_evidence,
        "residual_risks": [
            "declared_contexts_may_be_incomplete_or_stale",
            "regulatory_applicability_remains_adopter_owned",
            "evidence_sufficiency_requires_human_or_professional_review",
            "external_references_are_not_verified_by_this_command",
            "local_files_can_be_edited_without_external_controls",
        ],
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "recommended_next_commands": commands,
        "next_actions": actions,
        "human_review_required": True,
        "summary": summary,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compose adopter-declared compliance posture evidence for review.")
    parser.add_argument("project_path", nargs="?", default=".")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--manifest", help="Optional compliance posture manifest path.")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--generated-at", help="Override generated timestamp for deterministic tests.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = Path(args.project_path).resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    profile = normalize_profile(args.profile, policy)
    naos_root = args.naos_root or default_naos_root(policy)
    manifest_path = manifest_path_for(root, naos_root, policy, args.manifest)
    report = build_report(root, naos_root, profile, policy, manifest_path, generated_at=args.generated_at)

    output_path = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "compliance_posture_report")
    if output_path is not None:
        write_report(output_path, report)
    if args.json or output_path is None:
        print(json.dumps(report, indent=2, sort_keys=True))
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    sys.exit(main())
