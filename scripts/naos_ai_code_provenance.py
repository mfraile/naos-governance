#!/usr/bin/env python3
"""Compose review-only AI-assisted code provenance evidence."""

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


REPORT_SCHEMA = "naos.ai_code_provenance.v1"
MANIFEST_SCHEMA = "naos.ai_code_provenance_manifest.v1"
STATUS_VALUES = {"not_configured", "incomplete", "review_ready", "review_required"}
REQUIRED_REPORT_KEYS = [
    "ai_artifact_inventory_report",
    "ai_artifact_reconciliation_report",
]
OPTIONAL_REPORT_KEYS = [
    "install_decision_record_report",
    "task_claim_report",
    "operator_attribution_report",
    "audit_log_summary_report",
    "agent_trace_validation_report",
    "evidence_attestation_report",
    "evidence_conflict_detection_report",
    "dependency_integrity_report",
    "claims_report",
]
NOT_CLAIMED = [
    "legal opinion",
    "authorship proof",
    "authorship certification",
    "ownership proof",
    "ownership certification",
    "infringement clearance",
    "proof of copyright compliance",
    "license clearance",
    "AI-output detection",
    "line-level author attribution",
    "prompt completeness proof",
    "private prompt capture",
    "model/provider/API call",
    "credential read",
    "signing",
    "DSSE attestation",
    "SLSA implementation",
    "C2PA implementation",
    "notarization",
    "non-repudiation",
    "approval",
    "certification",
    "publication authorization",
    "release authorization",
    "proof of compliance",
]
LIMITATIONS = [
    "This report composes local files and generated NAOS reports for human review.",
    "Adopter declarations may be incomplete, stale, or outside repository scope.",
    "Prompt references can point to private or external records; absence is recorded as missing evidence, not inferred.",
    "License and ownership questions remain adopter-owned and may require separate legal review.",
    "The command does not call models, providers, APIs, memory tools, MCP, or the network.",
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


def report_path_for(root: Path, naos_root: str, policy: dict[str, Any], key: str) -> Path:
    return report_default_path(root, naos_root, policy, key)


def manifest_path_for(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None = None) -> Path:
    if explicit:
        return Path(explicit)
    filename = str(policy.get("paths", {}).get("ai_code_provenance_manifest") or "ai_code_provenance.yaml")
    return safe_policy_path(root / naos_root, filename, field="ai_code_provenance_manifest")


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
        return None, "AI code provenance manifest must parse to a YAML mapping."
    return data, None


def review_severity(profile: str, policy: dict[str, Any], *, advisory: bool = False) -> str:
    return severity_for_profile(profile, policy, advisory=advisory or profile in {"quickstart", "lite"})


def finding(
    identifier: str,
    severity: str,
    status: str,
    message: str,
    *,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
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
            "authorship proof",
            "ownership proof",
            "infringement clearance",
            "proof of copyright compliance",
            "approval",
        ],
    }


def summarize_report_input(root: Path, naos_root: str, policy: dict[str, Any], key: str, required: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    path = report_path_for(root, naos_root, policy, key)
    data, status = load_json_report(path)
    return (
        {
            "id": key,
            "path": str(path),
            "present": path.exists(),
            "required": required,
            "status": status,
            "schema": data.get("schema"),
            "generated_at": data.get("generated_at"),
        },
        data,
    )


def collect_supporting_evidence(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    profile: str,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], list[dict[str, Any]]]:
    inputs: list[dict[str, Any]] = []
    reports: dict[str, dict[str, Any]] = {}
    findings: list[dict[str, Any]] = []
    for key in REQUIRED_REPORT_KEYS + OPTIONAL_REPORT_KEYS:
        required = key in REQUIRED_REPORT_KEYS
        item, data = summarize_report_input(root, naos_root, policy, key, required)
        inputs.append(item)
        if data:
            reports[key] = data
        if required and not item["present"]:
            findings.append(
                finding(
                    f"ai_code_provenance.missing_{key}",
                    review_severity(profile, policy),
                    "incomplete",
                    f"Required AI provenance input `{key}` is missing.",
                    evidence={"path": item["path"]},
                )
            )
        elif required and item["status"] == "parse_error":
            findings.append(
                finding(
                    f"ai_code_provenance.parse_error_{key}",
                    review_severity(profile, policy),
                    "review_required",
                    f"Required AI provenance input `{key}` could not be parsed.",
                    evidence={"path": item["path"]},
                )
            )
    return inputs, reports, findings


def summarize_ai_artifact_evidence(reports: dict[str, dict[str, Any]], profile: str, policy: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    inventory = reports.get("ai_artifact_inventory_report") or {}
    reconciliation = reports.get("ai_artifact_reconciliation_report") or {}
    artifacts = [item for item in as_list(inventory.get("artifacts")) if isinstance(item, dict)]
    decisions = [item for item in as_list(reconciliation.get("decisions")) if isinstance(item, dict)]
    artifact_status_counts = Counter(str(item.get("status") or "unknown") for item in artifacts)
    decision_counts = Counter(str(item.get("selected_option") or item.get("status") or "unknown") for item in decisions)

    review_artifacts = [
        item
        for item in artifacts
        if item.get("human_review_required") or str(item.get("status")) in {"conflicting", "stale", "review_required"}
    ]
    review_decisions = [
        item
        for item in decisions
        if item.get("human_review_required") or str(item.get("selected_option")) == "review_required"
    ]
    if review_artifacts:
        findings.append(
            finding(
                "ai_code_provenance.ai_artifacts_require_review",
                review_severity(profile, policy),
                "review_required",
                "AI artifact inventory contains artifacts requiring human review before provenance packaging is relied on.",
                evidence={"count": len(review_artifacts), "artifact_ids": [item.get("artifact_id") for item in review_artifacts[:10]]},
            )
        )
    if review_decisions:
        findings.append(
            finding(
                "ai_code_provenance.ai_artifact_decisions_require_review",
                review_severity(profile, policy),
                "review_required",
                "AI artifact reconciliation contains decisions requiring human review.",
                evidence={"count": len(review_decisions), "artifact_ids": [item.get("artifact_id") for item in review_decisions[:10]]},
            )
        )

    return (
        {
            "artifacts_total": len(artifacts),
            "decisions_total": len(decisions),
            "artifact_status_counts": dict(sorted(artifact_status_counts.items())),
            "decision_counts": dict(sorted(decision_counts.items())),
            "review_artifacts": len(review_artifacts),
            "review_decisions": len(review_decisions),
        },
        findings,
    )


def declaration_missing_fields(declaration: dict[str, Any]) -> list[str]:
    required_fields = [
        "declaration_id",
        "tool_or_provider",
        "ai_contribution_summary",
        "human_contribution_summary",
        "reviewer",
        "reviewed_at",
    ]
    missing = [field for field in required_fields if not clean_text(declaration.get(field))]
    if not as_list(declaration.get("code_paths")):
        missing.append("code_paths")
    return missing


def evaluate_manifest(
    manifest: dict[str, Any] | None,
    manifest_error: str | None,
    manifest_path: Path,
    evidence_present: bool,
    profile: str,
    policy: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str], list[str]]:
    findings: list[dict[str, Any]] = []
    missing_evidence: list[str] = []
    unresolved_questions: list[str] = []
    if manifest is None and manifest_error:
        findings.append(
            finding(
                "ai_code_provenance.manifest_parse_error",
                review_severity(profile, policy),
                "review_required",
                "AI code provenance manifest could not be parsed.",
                evidence={"path": str(manifest_path), "error": manifest_error},
            )
        )
        return {"present": True, "path": str(manifest_path), "valid": False, "error": manifest_error}, findings, missing_evidence, unresolved_questions
    if manifest is None:
        if evidence_present:
            findings.append(
                finding(
                    "ai_code_provenance.manifest_missing",
                    review_severity(profile, policy),
                    "incomplete",
                    "AI artifact evidence exists but `naos/ai_code_provenance.yaml` is not present.",
                    evidence={"path": str(manifest_path)},
                )
            )
            missing_evidence.append("naos/ai_code_provenance.yaml")
        else:
            findings.append(
                finding(
                    "ai_code_provenance.not_configured",
                    "advisory",
                    "not_configured",
                    "No AI code provenance manifest or AI artifact evidence is configured.",
                    evidence={"path": str(manifest_path)},
                )
            )
        return {"present": False, "path": str(manifest_path), "valid": False}, findings, missing_evidence, unresolved_questions

    schema_ok = manifest.get("schema") == MANIFEST_SCHEMA
    if not schema_ok:
        findings.append(
            finding(
                "ai_code_provenance.manifest_schema",
                review_severity(profile, policy),
                "incomplete",
                f"AI code provenance manifest schema must be `{MANIFEST_SCHEMA}`.",
                evidence={"path": str(manifest_path), "schema": manifest.get("schema")},
            )
        )

    declarations = [item for item in as_list(manifest.get("ai_use_declarations")) if isinstance(item, dict)]
    scope = as_mapping(manifest.get("provenance_scope"))
    no_ai_assisted_code = bool(scope.get("no_ai_assisted_code"))
    if not declarations and not no_ai_assisted_code:
        findings.append(
            finding(
                "ai_code_provenance.declarations_missing",
                review_severity(profile, policy),
                "incomplete",
                "Manifest must include reviewed AI-use declarations or explicitly declare no AI-assisted code for the reviewed scope.",
                evidence={"path": str(manifest_path)},
            )
        )

    declaration_summaries: list[dict[str, Any]] = []
    for index, declaration in enumerate(declarations):
        declaration_id = clean_text(declaration.get("declaration_id")) or f"declaration_{index}"
        missing = declaration_missing_fields(declaration)
        status = clean_text(declaration.get("status")).lower() or "unknown"
        declaration_summaries.append(
            {
                "declaration_id": declaration_id,
                "status": status,
                "code_paths": as_list(declaration.get("code_paths")),
                "prompt_provenance_refs": as_list(declaration.get("prompt_provenance_refs")),
                "artifact_refs": as_list(declaration.get("artifact_refs")),
                "reviewer_present": bool(clean_text(declaration.get("reviewer"))),
                "reviewed_at_present": bool(clean_text(declaration.get("reviewed_at"))),
                "missing_fields": missing,
            }
        )
        if missing:
            findings.append(
                finding(
                    f"ai_code_provenance.{declaration_id}.missing_fields",
                    review_severity(profile, policy),
                    "incomplete",
                    "AI-use declaration is missing required review fields.",
                    evidence={"missing_fields": missing},
                )
            )
        if status != "reviewed":
            findings.append(
                finding(
                    f"ai_code_provenance.{declaration_id}.not_reviewed",
                    review_severity(profile, policy),
                    "review_required",
                    "AI-use declaration is not marked reviewed.",
                    evidence={"status": status},
                )
            )
        if not as_list(declaration.get("prompt_provenance_refs")):
            missing_evidence.append(f"{declaration_id}:prompt_provenance_refs")

    license_lineage = as_mapping(manifest.get("license_lineage"))
    ownership_limitations = as_mapping(manifest.get("ownership_limitations"))
    for item in as_list(license_lineage.get("unresolved_questions")):
        if clean_text(item):
            unresolved_questions.append(clean_text(item))
    for item in as_list(manifest.get("unresolved_questions")):
        if clean_text(item):
            unresolved_questions.append(clean_text(item))
    if not as_list(license_lineage.get("evidence_refs")):
        missing_evidence.append("license_lineage.evidence_refs")
    if ownership_limitations.get("acknowledged") is not True:
        findings.append(
            finding(
                "ai_code_provenance.ownership_limitations_not_acknowledged",
                review_severity(profile, policy),
                "review_required",
                "Ownership/authorship limitations must be explicitly acknowledged before review-ready provenance packaging.",
                evidence={"path": str(manifest_path)},
            )
        )
    if unresolved_questions:
        findings.append(
            finding(
                "ai_code_provenance.unresolved_questions",
                review_severity(profile, policy),
                "review_required",
                "Manifest records unresolved AI code provenance review questions.",
                evidence={"questions": unresolved_questions[:20]},
            )
        )

    return (
        {
            "present": True,
            "path": str(manifest_path),
            "valid": schema_ok,
            "schema": manifest.get("schema"),
            "updated_at": manifest.get("updated_at"),
            "no_ai_assisted_code": no_ai_assisted_code,
            "declarations": declaration_summaries,
            "declarations_count": len(declaration_summaries),
            "license_lineage": {
                "evidence_refs": as_list(license_lineage.get("evidence_refs")),
                "unresolved_questions": as_list(license_lineage.get("unresolved_questions")),
            },
            "ownership_limitations": {
                "acknowledged": ownership_limitations.get("acknowledged") is True,
                "notes_present": bool(clean_text(ownership_limitations.get("notes"))),
            },
        },
        findings,
        sorted(set(missing_evidence)),
        sorted(set(unresolved_questions)),
    )


def status_from_findings(manifest_summary: dict[str, Any], evidence_present: bool, findings: list[dict[str, Any]]) -> str:
    if not manifest_summary.get("present") and not evidence_present:
        return "not_configured"
    statuses = {str(item.get("status")) for item in findings}
    if "review_required" in statuses:
        return "review_required"
    if "incomplete" in statuses:
        return "incomplete"
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
            "ai_artifact_inventory",
            f"naos ai-artifact-inventory --profile {profile}",
            "Refresh deterministic AI instruction/prompt/rule/hook inventory evidence.",
        ),
        command_item(
            "ai_artifact_reconcile",
            f"naos ai-artifact-reconcile --profile {profile}",
            "Record or refresh AI artifact disposition decisions before provenance review.",
        ),
        command_item(
            "ai_code_provenance",
            f"naos ai-code-provenance --profile {profile}",
            "Recompute review-only AI code provenance evidence.",
        ),
    ]
    if status == "not_configured":
        return refresh, [
            "Decide whether this project needs AI-assisted code provenance evidence.",
            "If yes, run AI artifact inventory/reconciliation and create `naos/ai_code_provenance.yaml` from the seed.",
        ]
    if status == "incomplete":
        return refresh, [
            "Complete missing manifest declarations, prompt/use references, reviewer metadata, and license-lineage evidence references.",
            "Rerun AI Code Provenance before using the evidence pack for admissibility discussions.",
        ]
    if status == "review_required":
        return [
            *refresh,
            command_item(
                "control_plane_review",
                f"naos control-plane-review --profile {profile}",
                "Route unresolved AI provenance review findings through human control-plane review.",
            ),
        ], [
            "Resolve or explicitly accept review findings before relying on the provenance package.",
            "Do not treat this report as legal, ownership, authorship, copyright, release, or compliance approval.",
        ]
    return [
        *refresh,
        command_item(
            "evidence_pack",
            f"naos evidence-pack --profile {profile}",
            "Include AI code provenance posture in the broader evidence pack after review.",
        ),
    ], [
        "Use the report as human-review input for admissibility or audit handoff.",
        "Keep legal, ownership, infringement, release, and publication decisions outside this command.",
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
    inputs, reports, input_findings = collect_supporting_evidence(root, naos_root, policy, profile)
    ai_summary, ai_findings = summarize_ai_artifact_evidence(reports, profile, policy)
    evidence_present = any(item.get("present") for item in inputs)
    manifest, manifest_error = load_manifest(manifest_path)
    manifest_summary, manifest_findings, missing_evidence, unresolved_questions = evaluate_manifest(
        manifest,
        manifest_error,
        manifest_path,
        evidence_present,
        profile,
        policy,
    )
    findings = [*input_findings, *ai_findings, *manifest_findings]
    status = status_from_findings(manifest_summary, evidence_present, findings)
    commands, actions = next_steps(status, profile)
    summary = finding_counts(findings)
    summary.update(
        {
            "supporting_inputs": len(inputs),
            "supporting_inputs_present": sum(1 for item in inputs if item.get("present")),
            "required_inputs_missing": sum(1 for item in inputs if item.get("required") and not item.get("present")),
            "manifest_present": bool(manifest_summary.get("present")),
            "declarations": int(manifest_summary.get("declarations_count") or 0),
            "missing_evidence": len(missing_evidence),
            "unresolved_questions": len(unresolved_questions),
            "review_artifacts": ai_summary.get("review_artifacts", 0),
            "review_decisions": ai_summary.get("review_decisions", 0),
        }
    )
    return {
        "schema": REPORT_SCHEMA,
        "generated_at": now_text,
        "profile": profile,
        "status": status,
        "command": "ai-code-provenance",
        "naos_root": naos_root,
        "project_root": str(root),
        "manifest": manifest_summary,
        "supporting_evidence": inputs,
        "ai_artifact_evidence": ai_summary,
        "missing_evidence": missing_evidence,
        "unresolved_questions": unresolved_questions,
        "authority_boundary": {
            "review_input_only": True,
            "evidence_pack_composition_only": True,
            "legal_or_ownership_decision": False,
            "publication_or_release_authority": False,
            "standalone_capability": False,
        },
        "runtime_posture": {
            "runtime_execution_enabled": False,
            "model_provider_api_calls": False,
            "credential_reads": False,
            "network_calls": False,
            "private_prompt_capture": False,
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
            "prompt_references_may_be_partial_or_private",
            "human_review_may_be_incomplete",
            "license_lineage_requires_project_specific_review",
            "ownership_and_authorship_questions_remain_adopter_owned",
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
    parser = argparse.ArgumentParser(description="Compose review-only AI-assisted code provenance evidence.")
    parser.add_argument("project_path", nargs="?", default=".")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--manifest", help="Optional AI code provenance manifest path.")
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

    output_path = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "ai_code_provenance_report")
    if output_path is not None:
        write_report(output_path, report)
    if args.json or output_path is None:
        print(json.dumps(report, indent=2, sort_keys=True))
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    sys.exit(main())
