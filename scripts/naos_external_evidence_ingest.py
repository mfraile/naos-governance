#!/usr/bin/env python3
"""Ingest bounded external SARIF evidence as unverified review input."""

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

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    load_policy,
    normalize_profile,
    report_output_path,
    severity_for_profile,
    status_from_counts,
    write_report,
)


SCHEMA = "naos.external_evidence_ingest.v2"
SARIF_LEVELS = {"none", "note", "warning", "error"}
NOT_CLAIMED = [
    "external finding verification",
    "security proof",
    "vulnerability absence",
    "PR approval",
    "attestation",
    "certification",
    "proof of compliance",
    "source-of-truth authority",
    "maturity promotion",
    "automatic vocabulary or control mapping",
    "assessed-scope completeness",
    "durable human disposition",
    "automatic task creation or gate decision",
    "release authorization",
]
LIMITATIONS = [
    "External evidence ingest reads local SARIF input only; it does not call scanners, providers, APIs, or the network.",
    "Imported results are unverified by default and remain external review evidence.",
    "The report preserves bounded identity metadata for each result but omits arbitrary result-message text and raw SARIF payloads.",
    "Native levels and source-declared taxonomy references remain unverified; they are not mapped to NAOS risk, severity, controls, or requirements authority.",
    "Source execution status and zero reported results do not establish assessed-scope completeness, scanner correctness, or vulnerability absence.",
    "Human review remains required before using external findings for remediation, waivers, release decisions, or compliance evidence.",
]


def utc_now() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def cost_posture() -> dict[str, Any]:
    return {
        "cost_incurred_by_default": False,
        "cost_usd": 0.0,
        "external_api_required": False,
        "provider_dependency_required": False,
        "model_dependency_required": False,
        "human_approval_required_before_cost": False,
    }


def finding(finding_id: str, severity: str, status: str, message: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "status": status,
        "message": message,
        "human_review_required": True,
        "not_claimed": NOT_CLAIMED,
        **extra,
    }


def result_path(result: dict[str, Any]) -> str | None:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return None
    physical = ((locations[0] or {}).get("physicalLocation") or {}) if isinstance(locations[0], dict) else {}
    artifact = physical.get("artifactLocation") if isinstance(physical, dict) else {}
    if isinstance(artifact, dict) and artifact.get("uri"):
        return str(artifact.get("uri"))
    return None


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def source_identity(result: dict[str, Any], tool_name: str) -> tuple[str, str, str | None]:
    guid = result.get("guid")
    if isinstance(guid, str) and guid.strip():
        return "guid", "source_declared", canonical_sha256({"tool_name": tool_name, "guid": guid})
    partial = result.get("partialFingerprints")
    if partial is not None and not isinstance(partial, dict):
        raise ValueError("SARIF result partialFingerprints must be an object when present")
    if isinstance(partial, dict) and partial:
        normalized: dict[str, str] = {}
        for key, value in sorted(partial.items(), key=lambda item: str(item[0])):
            if (
                not isinstance(key, str)
                or not key.strip()
                or not isinstance(value, str)
                or not value.strip()
            ):
                raise ValueError(
                    "SARIF result partialFingerprints entries must use non-empty string keys and values"
                )
            normalized[key.strip()] = value.strip()
        if normalized:
            return (
                "partial_fingerprints",
                "source_declared",
                canonical_sha256({"tool_name": tool_name, "partial_fingerprints": normalized}),
            )
    return "position", "exact_artifact_position", None


def source_declared_taxonomy_refs(result: dict[str, Any]) -> list[str]:
    taxa = result.get("taxa")
    if taxa is None:
        return []
    if not isinstance(taxa, list):
        raise ValueError("SARIF result taxa must be an array when present")
    refs: list[str] = []
    for item in taxa:
        if not isinstance(item, dict):
            raise ValueError("SARIF result taxa entries must be objects")
        identifier = item.get("id")
        if isinstance(identifier, str) and identifier.strip():
            refs.append(identifier.strip())
    return sorted(set(refs))


def run_execution_status(run: dict[str, Any]) -> str:
    invocations = run.get("invocations")
    if invocations is None or invocations == []:
        return "unknown"
    if not isinstance(invocations, list):
        raise ValueError("SARIF run invocations must be an array when present")
    flags: list[bool] = []
    complete = True
    for invocation in invocations:
        if not isinstance(invocation, dict):
            raise ValueError("SARIF invocation entries must be objects")
        if "executionSuccessful" not in invocation:
            complete = False
            continue
        value = invocation.get("executionSuccessful")
        if not isinstance(value, bool):
            raise ValueError(
                "SARIF invocation executionSuccessful must be boolean when present"
            )
        flags.append(value)
    if any(value is False for value in flags):
        return "reported_failure"
    if complete and flags and all(flags):
        return "reported_success"
    return "unknown"


def summarize_sarif(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    source_bytes = path.read_bytes()
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    payload = json.loads(source_bytes.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("SARIF root must be an object")
    version = str(payload.get("version") or "")
    runs = payload.get("runs")
    if version != "2.1.0":
        raise ValueError(f"Unsupported SARIF version {version!r}; expected 2.1.0")
    if not isinstance(runs, list):
        raise ValueError("SARIF payload must contain a runs array")

    tool_names: list[str] = []
    level_counts: Counter[str] = Counter()
    affected_paths: Counter[str] = Counter()
    rules: Counter[str] = Counter()
    results_total = 0
    run_summaries: list[dict[str, Any]] = []
    result_records: list[dict[str, Any]] = []
    run_execution_statuses: list[str] = []

    for index, run in enumerate(runs):
        if not isinstance(run, dict):
            raise ValueError(f"SARIF run {index} must be an object")
        driver = (((run.get("tool") or {}).get("driver") or {}) if isinstance(run.get("tool"), dict) else {})
        tool_name = str(driver.get("name") or f"run-{index + 1}")
        tool_version = str(driver.get("semanticVersion") or driver.get("version") or "unknown")
        tool_names.append(tool_name)
        if run.get("results") is not None and not isinstance(run.get("results"), list):
            raise ValueError(f"SARIF run {index} results must be an array when present")
        results = run.get("results") or []
        execution_status = run_execution_status(run)
        run_execution_statuses.append(execution_status)
        run_level_counts: Counter[str] = Counter()
        for result_index, result in enumerate(results):
            if not isinstance(result, dict):
                raise ValueError(f"SARIF result {index}:{result_index} must be an object")
            message = result.get("message")
            if not isinstance(message, dict) or not message:
                raise ValueError(f"SARIF result {index}:{result_index} must contain a message object")
            results_total += 1
            level = str(result.get("level") or "unspecified")
            rule_id = str(result.get("ruleId") or "unknown")
            level_counts[level] += 1
            run_level_counts[level] += 1
            rules[rule_id] += 1
            relpath = result_path(result)
            if relpath:
                affected_paths[relpath] += 1
            identity_basis, identity_stability, identity_sha256 = source_identity(result, tool_name)
            taxonomy_refs = source_declared_taxonomy_refs(result)
            external_result_id = "sarif-" + canonical_sha256(
                {
                    "source_sha256": source_sha256,
                    "run_index": index,
                    "result_index": result_index,
                }
            )
            result_records.append(
                {
                    "external_result_id": external_result_id,
                    "origin": "external_unverified",
                    "source_sha256": source_sha256,
                    "run_index": index,
                    "result_index": result_index,
                    "identity_basis": identity_basis,
                    "identity_stability": identity_stability,
                    "source_identity_sha256": identity_sha256,
                    "tool_name": tool_name,
                    "tool_version": tool_version,
                    "native_rule_id": rule_id,
                    "native_level": level,
                    "native_level_status": "recognized_native" if level in SARIF_LEVELS else "unmapped",
                    "artifact_uri": relpath,
                    "source_declared_taxonomy_refs": taxonomy_refs,
                    "control_link_status": "source_declared_unverified" if taxonomy_refs else "missing",
                    "classification": "unknown",
                    "verification_status": "unverified",
                    "review_disposition": "needs_review",
                    "human_review_required": True,
                    "message_retention": "omitted",
                }
            )
        run_summaries.append(
            {
                "run_index": index,
                "tool_name": tool_name,
                "tool_version": tool_version,
                "result_count": len(results),
                "level_counts": dict(sorted(run_level_counts.items())),
                "source_execution_status": execution_status,
            }
        )

    if not runs:
        source_execution_status = "not_assessed"
    elif "reported_failure" in run_execution_statuses:
        source_execution_status = "reported_failure"
    elif run_execution_statuses and all(value == "reported_success" for value in run_execution_statuses):
        source_execution_status = "reported_success"
    else:
        source_execution_status = "unknown"
    if results_total:
        result_posture = "results_reported"
    elif not runs:
        result_posture = "not_assessed"
    elif source_execution_status == "reported_success":
        result_posture = "zero_results_reported"
    else:
        result_posture = "unknown"
    assessment = {
        "source_execution_status": source_execution_status,
        "result_posture": result_posture,
        "coverage_status": "not_declared",
        "human_review_required": True,
    }

    summary = {
        "source_format": "sarif",
        "sarif_version": version,
        "runs": len(runs),
        "tools": sorted(set(tool_names)),
        "results": results_total,
        "level_counts": dict(sorted(level_counts.items())),
        "affected_paths": len(affected_paths),
        "top_affected_paths": [{"path": path, "count": count} for path, count in affected_paths.most_common(20)],
        "top_rules": [{"rule_id": rule_id, "count": count} for rule_id, count in rules.most_common(20)],
        "verification_status": "unverified",
        "source_sha256": source_sha256,
        "source_bytes": len(source_bytes),
        "source_execution_status": source_execution_status,
        "result_posture": result_posture,
        "coverage_status": "not_declared",
    }
    findings = [
        finding(
            "external_evidence_ingest.unverified_external_results",
            "advisory",
            "review_required",
            "External SARIF results were ingested as unverified review evidence.",
            result_count=results_total,
            source=str(path),
        )
    ] if results_total else []
    return {
        "summary": summary,
        "runs": run_summaries,
        "assessment": assessment,
        "result_records": result_records,
    }, findings


def build_report(root: Path, profile: str, naos_root: str, policy: dict[str, Any], source: str | None, source_type: str) -> dict[str, Any]:
    severity = severity_for_profile(profile, policy)
    findings: list[dict[str, Any]] = []
    scans: dict[str, Any] = {
        "source": source,
        "source_format": source_type,
        "verification_default": policy.get("claims", {}).get("external_evidence_verification_default", "unverified"),
    }
    summary_extra: dict[str, Any] = {
        "source_configured": bool(source),
        "source_present": False,
        "source_format": source_type,
        "results": 0,
        "verification_status": "unverified",
    }
    result_records: list[dict[str, Any]] = []
    assessment: dict[str, Any] = {
        "source_execution_status": "not_configured" if not source else "unknown",
        "result_posture": "not_assessed" if not source else "unknown",
        "coverage_status": "not_declared",
        "human_review_required": bool(source),
    }

    if not source:
        findings.append(finding("external_evidence_ingest.source_missing", "advisory", "not_configured", "No external SARIF source was provided; ingest remains not configured."))
    else:
        source_path = Path(source)
        if not source_path.is_absolute():
            source_path = root / source_path
        scans["resolved_source"] = str(source_path)
        if not source_path.exists():
            assessment["source_execution_status"] = "source_missing"
            findings.append(finding("external_evidence_ingest.source_not_found", severity, "missing", "Configured external SARIF source was not found.", path=str(source_path)))
        else:
            summary_extra["source_present"] = True
            try:
                sarif, imported_findings = summarize_sarif(source_path)
                scans.update({"summary": sarif["summary"], "runs": sarif["runs"]})
                summary_extra.update(sarif["summary"])
                assessment = sarif["assessment"]
                result_records = sarif["result_records"]
                findings.extend(imported_findings)
            except Exception as exc:
                assessment["source_execution_status"] = "parse_error"
                findings.append(finding("external_evidence_ingest.parse_error", severity, "parse_error", f"External SARIF source could not be parsed: {exc}", path=str(source_path)))

    summary = finding_counts(findings)
    summary.update(summary_extra)
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "profile": profile,
        "status": status_from_counts(summary),
        "project_root": str(root),
        "naos_root": naos_root,
        "deterministic": True,
        "cost_posture": cost_posture(),
        "summary": summary,
        "scans": scans,
        "assessment": assessment,
        "result_records": result_records,
        "findings": findings,
        "waivers": [],
        "known_gaps": [
            "Imported result records create repeatable human-review prompts only; durable human dispositions, task/writeback linkage, automatic vocabulary/control mapping, and assessed-scope proof remain outside this cycle."
        ],
        "residual_risks": [
            "External scanner results may be stale, incomplete, false-positive, or false-negative.",
            "External findings require human review before remediation, waiver, release, or compliance decisions.",
        ],
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": bool(assessment.get("human_review_required")),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ingest local SARIF as bounded external review evidence.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--source", help="Local SARIF 2.1.0 file to ingest.")
    parser.add_argument("--source-type", default="sarif", choices=["sarif"], help="External evidence format. Only local SARIF is supported in this release.")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    report = build_report(root, profile, naos_root, policy, args.source, args.source_type)
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "external_evidence_ingest_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        destination = str(output) if output else "stdout only"
        print(f"NAOS external evidence ingest: {report['status']} (results: {report['summary'].get('results', 0)}, output: {destination})")
    return exit_code_for_summary(profile, report["summary"], policy, args.strict and not is_kit_repository(root, naos_root))


if __name__ == "__main__":
    raise SystemExit(main())
