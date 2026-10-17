#!/usr/bin/env python3
"""Classify local NAOS finding provenance deterministically."""

from __future__ import annotations

from naos_self_check_inspection import inspection_candidates, inspection_read_path

import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    build_generated_by,
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    load_policy,
    normalize_profile,
    report_output_path,
    session_report_default_path,
    sessions_index_path,
    severity_for_profile,
    write_report_with_session,
)
from naos_schema_validation import validate_json_schema_file  # noqa: E402


SCHEMA = "naos.evidence_classification_report.v1"
POLICY_SCHEMA = "naos.evidence_classification_policy.v1"
POLICY_SCHEMA_PATH = SCRIPT_DIR.parent / "schemas" / "naos" / "evidence_classification_policy.schema.json"
CLASSES = {"confirmed", "deduced", "hypothesized", "unknown"}
REQUIRED_NOT_CLAIMED = {
    "truth proof",
    "legal conclusion",
    "compliance proof",
    "approval",
    "issue resolution",
    "human review replacement",
}
LIMITATIONS = [
    "Evidence classification reviews findings and structured gap/risk records; text-only gap/risk disclosures remain visible unclassified context.",
    "Ready means no outstanding finding classification check; unclassified context still requires review and no risk is resolved by this status.",
    "Inferred classifications are review candidates, not final truth.",
    "Severity and status do not establish provenance; source self-references provide traceability only.",
    "Reference presence does not establish confirmation; reference content is not verified by this classifier.",
    "Aggregate counts combine source-declared labels and inferred candidates; neither count is independently verified evidence.",
    "Classification is orthogonal to severity and does not prove correctness, compliance, approval, or issue resolution.",
    "The script does not call LLMs, providers, APIs, the network, memory tools, MCP, or Engram.",
]
NOT_CLAIMED = [
    "truth proof",
    "legal conclusion",
    "compliance proof",
    "approval",
    "certification",
    "regulator acceptance",
    "issue resolution",
    "human review replacement",
]
RESIDUAL_RISKS = [
    "Reports without structured findings can leave review items unclassified.",
    "A confirmed evidence reference does not prove the finding is correct or resolved.",
    "Human reviewers must decide whether provenance is sufficient for the governance decision.",
]
MAX_SCAN_ITEM_PAYLOAD_BYTES = 16 * 1024
MAX_SCAN_PAYLOAD_BYTES = 256 * 1024


def canonical_item_bytes(value: Any) -> bytes:
    """Bind the parsed JSON item, separately from its raw source report bytes."""
    # Escaping non-ASCII also keeps JSON's escaped lone-surrogate strings
    # hashable without attempting to encode an invalid UTF-8 scalar value.
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def utc_now() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def latest_session_id(root: Path, naos_root: str, policy: dict[str, Any]) -> str | None:
    index_path = sessions_index_path(root, naos_root, policy)
    if not index_path.exists():
        return None
    try:
        data = json.loads(index_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    value = data.get("latest_session_id") if isinstance(data, dict) else None
    return str(value) if value else None


def finding(item_id: str, severity: str, finding_status: str, message: str, **extra: Any) -> dict[str, Any]:
    # This declaration describes only the classifier's observed diagnostic.
    # It does not classify the underlying source finding as true or resolved.
    result = {
        "id": item_id,
        "severity": severity,
        "status": finding_status,
        "message": message,
        "human_review_required": True,
        "evidence_classification": "confirmed",
        "classification_scope": "classifier_diagnostic_observed_at_scan_only",
        "not_claimed": ["source finding truth", "issue resolution", "human review replacement"],
        **extra,
    }
    source_report = extra.get("source_report")
    source_path = extra.get("path")
    if source_report:
        result["evidence_refs"] = [{"type": "generated_report", "ref": str(source_report)}]
    elif source_path:
        result["evidence_refs"] = [{"type": "local_file", "ref": str(source_path)}]
    return result


def assign_diagnostic_ids(findings: list[dict[str, Any]]) -> None:
    """Missing-classification labels scoped to the final diagnostic array.

    Source finding IDs and source/item hashes are separate provenance fields.
    """
    for ordinal, item in enumerate(findings, start=1):
        if item.get("status") == "missing_classification":
            item["id"] = f"EC-{ordinal}"
            item["id_scheme"] = "report_ordinal_v1"


def policy_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("evidence_classification_policy") or "evidence_classification_policy.yaml")
    project_path = root / naos_root / filename
    if project_path.exists() or not is_kit_repository(root, naos_root):
        return project_path, "project"
    return root / "templates" / "structural-seeds" / "naos" / "evidence_classification_policy.yaml", "kit_template"


def load_yaml(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return None, str(exc)
    if not isinstance(data, dict):
        return None, "evidence classification policy must parse to a YAML mapping"
    return data, None


def validate_policy(data: dict[str, Any] | None, parse_error: str | None, profile: str, policy: dict[str, Any]) -> tuple[bool, list[dict[str, Any]]]:
    severity = severity_for_profile(profile, policy)
    if data is None:
        return False, [
            finding(
                "evidence_classification.invalid_policy",
                severity,
                "invalid_policy",
                f"Evidence classification policy could not be parsed: {parse_error}",
            )
        ]
    findings: list[dict[str, Any]] = []
    schema_errors = validate_json_schema_file(data, POLICY_SCHEMA_PATH)
    for index, error in enumerate(schema_errors):
        findings.append(
            finding(
                f"evidence_classification.schema_validation.{index}",
                severity,
                "invalid_policy",
                f"Evidence classification policy failed schema validation: {error}",
            )
        )
    if data.get("schema") != POLICY_SCHEMA:
        findings.append(finding("evidence_classification.schema", severity, "invalid_policy", "Policy schema id is missing or unsupported."))
    levels = data.get("classification_levels")
    if not isinstance(levels, dict) or not CLASSES.issubset(set(levels)):
        findings.append(finding("evidence_classification.levels", severity, "invalid_policy", "Policy must define confirmed, deduced, hypothesized, and unknown levels."))
    if data.get("default_classification") not in CLASSES:
        findings.append(finding("evidence_classification.default", severity, "invalid_policy", "default_classification must be confirmed, deduced, hypothesized, or unknown."))
    if not isinstance(data.get("accepted_evidence_refs"), list) or not data.get("accepted_evidence_refs"):
        findings.append(finding("evidence_classification.accepted_refs", severity, "invalid_policy", "accepted_evidence_refs must be a non-empty list."))
    not_claimed = set(str(item) for item in data.get("not_claimed") or [])
    missing_non_claims = sorted(REQUIRED_NOT_CLAIMED - not_claimed)
    if missing_non_claims:
        findings.append(
            finding(
                "evidence_classification.not_claimed_missing",
                severity,
                "review_required",
                "Required non-claims are missing.",
                missing=missing_non_claims,
            )
        )
    if data.get("human_review_required") is not True:
        findings.append(finding("evidence_classification.human_review_missing", severity, "review_required", "human_review_required must be true."))
    return not any(item.get("status") == "invalid_policy" for item in findings), findings


def report_paths(root: Path, naos_root: str, policy: dict[str, Any]) -> list[Path]:
    reports_root = root / naos_root / str(policy.get("paths", {}).get("reports_dir") or "reports")
    return sorted(
        path for path in inspection_candidates(root, reports_root.relative_to(root).as_posix() + "/*.json", reports_root.glob("*.json"))
        if path.name != str(policy.get("paths", {}).get("evidence_classification_report") or "evidence_classification_report.json")
    )


def load_report(path: Path) -> tuple[dict[str, Any] | None, str | None, bytes | None]:
    try:
        raw = inspection_read_path(path).read_bytes()
    except Exception as exc:
        return None, str(exc), None
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        return None, str(exc), raw
    if not isinstance(data, dict):
        return None, "report must parse to a JSON object", raw
    return data, None, raw


def normalize_evidence_refs(item: dict[str, Any], report_path: Path) -> list[dict[str, Any]]:
    refs = item.get("evidence_refs") or item.get("evidence_references") or item.get("source_reports") or item.get("related_artifacts") or []
    result: list[dict[str, Any]] = []
    if isinstance(refs, str):
        refs = [refs]
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, dict):
                result.append(ref)
            elif str(ref).strip():
                result.append({"type": "generated_report" if str(ref).endswith(".json") else "local_file", "ref": str(ref)})
    for field, ref_type in [
        ("source_path", "local_file"),
        ("source_report", "generated_report"),
        ("source_report_path", "generated_report"),
        ("path", "local_file"),
    ]:
        if item.get(field):
            result.append({"type": ref_type, "ref": str(item[field])})
    if not result:
        result.append({"type": "generated_report", "ref": str(report_path)})
    deduped: dict[tuple[str, str], dict[str, Any]] = {}
    for ref in result:
        key = (str(ref.get("type") or "unknown"), str(ref.get("ref") or ref.get("path") or ref))
        # Lexical comparison only: classify traceability without following paths
        # or claiming that referenced content has been inspected.
        self_reference = os.path.normcase(os.path.abspath(key[1])) == os.path.normcase(os.path.abspath(report_path))
        deduped[key] = {"type": key[0], "ref": key[1],
                        "reference_role": "source_trace" if self_reference else "unverified_reference"}
    return sorted(deduped.values(), key=lambda value: (value["type"], value["ref"]))


def collect_findings(data: dict[str, Any], report_path: Path) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    for key in ("findings", "known_gaps", "residual_risks"):
        if key not in data:
            continue
        values = data.get(key)
        if not isinstance(values, list):
            collected.append({
                "id": f"{report_path.stem}.{key}.invalid_container",
                "message": f"Report field {key} must be an array; found {type(values).__name__}.",
                "status": "invalid_finding_container",
                "classification": "unknown",
                "_source_report": str(report_path),
                "_source_bucket": key,
                "_source_index": None,
            })
            continue
        for index, raw in enumerate(values):
            if key != "findings" and isinstance(raw, str):
                continue
            if isinstance(raw, dict):
                item = dict(raw)
            else:
                item = {"message": str(raw)}
            item.setdefault("id", item.get("finding_id") or f"{report_path.stem}.{key}.{index}")
            item["_source_report"] = str(report_path)
            item["_source_bucket"] = key
            item["_source_index"] = index
            collected.append(item)
    return collected


def collect_unclassified_context(data: dict[str, Any], report_path: Path) -> list[dict[str, Any]]:
    """Retain text disclosures without inventing finding/provenance metadata."""
    context: list[dict[str, Any]] = []
    for bucket in ("known_gaps", "residual_risks"):
        values = data.get(bucket)
        if not isinstance(values, list):
            continue
        for index, raw in enumerate(values):
            if isinstance(raw, str):
                context.append({
                    "source_report": str(report_path),
                    "source_bucket": bucket,
                    "source_index": index,
                    "message": raw,
                    "status": "unclassified_context",
                    "human_review_required": True,
                    "not_claimed": ["truth proof", "approval", "issue resolution"],
                })
    return context


def declared_classification(item: dict[str, Any]) -> str | None:
    # Explicit provenance is distinct from legacy, domain-specific `classification`
    # fields (for example, policy disposition `safe_to_defer`). Presence matters:
    # invalid or conflicting declarations must not fall back to a generic value.
    explicit = [
        str(item[field]).strip().lower()
        for field in ("evidence_classification", "provenance_classification")
        if field in item
    ]
    if explicit:
        return explicit[0] if len(set(explicit)) == 1 and explicit[0] in CLASSES else "unknown"
    if "classification" not in item:
        return None
    cleaned = str(item["classification"]).strip().lower()
    return cleaned if cleaned in CLASSES else "unknown"


def infer_classification(item: dict[str, Any], refs: list[dict[str, Any]]) -> tuple[str, str, bool]:
    if declared_classification(item):
        return declared_classification(item) or "unknown", "declared", False
    text = " ".join(str(item.get(field) or "") for field in ["id", "message", "hypothesis_reason"]).lower()
    has_reasoning = bool(item.get("reasoning_summary"))
    if item.get("hypothesis_reason") or "hypothesis" in text or "plausible" in text:
        return "hypothesized", "inferred_candidate", True
    supporting_refs = [ref for ref in refs if ref.get("reference_role") != "source_trace"]
    if len(supporting_refs) >= 2 and has_reasoning:
        return "deduced", "inferred_candidate", True
    # Reference presence (including a verified flag) is not executed confirmation.
    return "unknown", "inferred_candidate", True


def classify_findings(paths: list[Path], scan_generated_at: str) -> tuple[
    list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]],
    list[dict[str, Any]], list[dict[str, Any]],
]:
    reports_scanned: list[dict[str, Any]] = []
    classified: list[dict[str, Any]] = []
    parse_findings: list[dict[str, Any]] = []
    context: list[dict[str, Any]] = []
    source_finding_snapshots: list[dict[str, Any]] = []
    retained_payload_bytes = 0
    for path in paths:
        data, error, raw_report = load_report(path)
        observed_at = utc_now()
        report_sha256 = hashlib.sha256(raw_report).hexdigest() if raw_report is not None else None
        report_entry = {
            "path": str(path),
            "exists": True if raw_report is not None else None,
            "parse_error": error,
            "findings": 0,
            "unclassified_context": 0,
            "scan_generated_at": scan_generated_at,
            "source_observed_at": observed_at,
            "raw_sha256": report_sha256,
            "raw_byte_count": len(raw_report) if raw_report is not None else None,
            "source_schema": data.get("schema") if data is not None else None,
            "source_generated_at": data.get("generated_at") if data is not None else None,
        }
        if data is None:
            parse_findings.append(
                finding(
                    f"evidence_classification.parse_error.{path.stem}",
                    "warning",
                    "review_required",
                    f"Report could not be parsed for evidence classification: {path.name}.",
                    path=str(path),
                    error=error,
                )
            )
            reports_scanned.append(report_entry)
            continue
        items = collect_findings(data, path)
        disclosures = collect_unclassified_context(data, path)
        for disclosure in disclosures:
            disclosure["scan_generated_at"] = scan_generated_at
            disclosure["source_observed_at"] = observed_at
            disclosure["source_report_sha256"] = report_sha256
            disclosure["source_item_sha256"] = hashlib.sha256(
                canonical_item_bytes(data[disclosure["source_bucket"]][disclosure["source_index"]])
            ).hexdigest()
        context.extend(disclosures)
        report_entry["findings"] = len(items)
        report_entry["unclassified_context"] = len(disclosures)
        reports_scanned.append(report_entry)
        for item in items:
            bucket = item["_source_bucket"]
            index = item["_source_index"]
            raw_source_item = data[bucket] if index is None else data[bucket][index]
            raw_item_bytes = canonical_item_bytes(raw_source_item)
            item_sha256 = hashlib.sha256(raw_item_bytes).hexdigest()
            # Rule-backed disclosures inherit the actual selected rules path.
            # This supplies provenance for remapped --rules inputs without
            # assigning any classification to new or customized records.
            if (item.get("_source_bucket") in {"known_gaps", "residual_risks"}
                    and not item.get("source_path")
                    and isinstance(data.get("rules_path"), str)):
                item["source_path"] = data["rules_path"]
            refs = normalize_evidence_refs(item, path)
            classification, source, candidate = infer_classification(item, refs)
            strict_record = source == "inferred_candidate" or classification == "unknown"
            retained = (strict_record and len(raw_item_bytes) <= MAX_SCAN_ITEM_PAYLOAD_BYTES
                        and retained_payload_bytes + len(raw_item_bytes) <= MAX_SCAN_PAYLOAD_BYTES)
            snapshot_index = len(source_finding_snapshots)
            snapshot = {
                "source_report": str(path),
                "source_bucket": bucket,
                "source_index": index,
                "source_report_sha256": report_sha256,
                "source_observed_at": observed_at,
                "source_item_sha256": item_sha256,
                "canonical_item_byte_count": len(raw_item_bytes),
                "payload_retained": retained,
            }
            if retained:
                snapshot["payload"] = raw_source_item
                retained_payload_bytes += len(raw_item_bytes)
            elif not strict_record:
                snapshot["retention_reason"] = "declared_projection_only"
            else:
                snapshot["retention_limit"] = (
                    "per_item" if len(raw_item_bytes) > MAX_SCAN_ITEM_PAYLOAD_BYTES else "total"
                )
            source_finding_snapshots.append(snapshot)
            classified.append(
                {
                    "finding_id": str(item.get("id")),
                    "source_report": str(path),
                    "source_bucket": bucket,
                    "source_index": index,
                    "source_report_sha256": report_sha256,
                    "source_item_sha256": item_sha256,
                    "scan_generated_at": scan_generated_at,
                    "source_observed_at": observed_at,
                    "scan_payload_index": snapshot_index,
                    "source_payload_retained": retained,
                    "classification": classification,
                    "classification_source": source,
                    "candidate_requires_review": candidate,
                    "severity": item.get("severity"),
                    "status": item.get("status"),
                    "message": (item["message"] if "message" in item else
                                item["description"] if "description" in item else
                                item.get("summary")),
                    "evidence_refs": refs,
                    "reasoning_summary": item.get("reasoning_summary"),
                    "classification_scope": item.get("classification_scope"),
                    "hypothesis_reason": item.get("hypothesis_reason"),
                    "next_review_step": item.get("next_review_step"),
                    "source_path": item.get("source_path"),
                    "human_review_required": True,
                    "not_claimed": ["truth proof", "approval", "issue resolution"],
                }
            )
    return reports_scanned, classified, parse_findings, context, source_finding_snapshots


def status_for_report(profile: str, policy_present: bool, policy_valid: bool, missing: int, unknown: int, parse_findings: int) -> str:
    if not policy_present:
        return "missing_policy"
    if not policy_valid:
        return "invalid_policy"
    if parse_findings:
        return "review_required" if profile in {"standard", "assured"} else "advisory"
    if missing:
        return "missing_classification" if profile in {"quickstart", "lite"} else "review_required"
    if unknown:
        return "review_required" if profile in {"standard", "assured"} else "advisory"
    return "ready"


def build_report(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, int]]:
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    generated_at = utc_now()
    path, source = policy_path(root, naos_root, policy, args.input)
    policy_present = path.exists()
    data: dict[str, Any] | None = None
    parse_error: str | None = None
    findings: list[dict[str, Any]] = []
    policy_valid = False
    reports_scanned: list[dict[str, Any]] = []
    classified: list[dict[str, Any]] = []
    context: list[dict[str, Any]] = []
    source_finding_snapshots: list[dict[str, Any]] = []
    if not policy_present:
        findings.append(
            finding(
                "evidence_classification.missing_policy",
                severity_for_profile(profile, policy, advisory=profile in {"quickstart", "lite"}),
                "missing_policy",
                "Evidence classification policy is missing.",
                path=str(path),
            )
        )
    else:
        data, parse_error = load_yaml(path)
        policy_valid, policy_findings = validate_policy(data, parse_error, profile, policy)
        for diagnostic in policy_findings:
            diagnostic["path"] = str(path)
            diagnostic["evidence_refs"] = [{"type": "local_file", "ref": str(path)}]
        findings.extend(policy_findings)
        if policy_valid:
            scan_paths = [Path(item) for item in args.report] if args.report else report_paths(root, naos_root, policy)
            reports_scanned, classified, parse_findings, context, source_finding_snapshots = classify_findings(
                scan_paths, generated_at
            )
            findings.extend(parse_findings)

    missing_classification = [
        item for item in classified
        if item.get("classification_source") == "inferred_candidate" or item.get("classification") == "unknown"
    ]
    unknown_findings = [item for item in classified if item.get("classification") == "unknown"]
    review_required = [item for item in classified if item.get("candidate_requires_review") or item.get("classification") == "unknown"]
    missing_severity = severity_for_profile(profile, policy, advisory=profile in {"quickstart", "lite"})
    for item in missing_classification:
        findings.append(
            finding(
                f"evidence_classification.missing.{item.get('finding_id')}",
                missing_severity,
                "missing_classification",
                "Finding lacks declared provenance classification; inferred candidate requires human review.",
                finding_id=item.get("finding_id"),
                source_report=item.get("source_report"),
                source_report_sha256=item.get("source_report_sha256"),
                source_item_sha256=item.get("source_item_sha256"),
                source_bucket=item.get("source_bucket"),
                source_index=item.get("source_index"),
                scan_generated_at=item.get("scan_generated_at"),
                source_observed_at=item.get("source_observed_at"),
                inferred_classification=item.get("classification"),
            )
        )
    classification_counts = Counter(str(item.get("classification") or "unknown") for item in classified)
    evidence_ref_counts = Counter(str(ref.get("type") or "unknown") for item in classified for ref in item.get("evidence_refs") or [])
    assign_diagnostic_ids(findings)
    summary = finding_counts(findings)
    status = status_for_report(profile, policy_present, policy_valid, len(missing_classification), len(unknown_findings), sum(1 for item in findings if item.get("id", "").startswith("evidence_classification.parse_error")))
    session_id = latest_session_id(root, naos_root, policy)
    report = {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "session_id": session_id,
        "generated_by": build_generated_by(root, session_id=session_id, generated_at=generated_at),
        "policy_path": str(path),
        "policy_source": source,
        "policy_present": policy_present,
        "policy_valid": policy_valid,
        "reports_scanned": reports_scanned,
        "scan_semantics": "historical_scan_time; source report paths may be replaced after this scan",
        "source_finding_snapshots": source_finding_snapshots,
        "source_finding_snapshot_summary": {
            "retained": sum(bool(item["payload_retained"]) for item in source_finding_snapshots),
            "not_retained": sum(not item["payload_retained"] for item in source_finding_snapshots),
            "declared_projection_only": sum(
                item.get("retention_reason") == "declared_projection_only"
                for item in source_finding_snapshots
            ),
            "not_retained_due_limit": sum("retention_limit" in item for item in source_finding_snapshots),
            "retained_canonical_bytes": sum(
                item["canonical_item_byte_count"] for item in source_finding_snapshots
                if item["payload_retained"]
            ),
            "per_item_limit_bytes": MAX_SCAN_ITEM_PAYLOAD_BYTES,
            "total_limit_bytes": MAX_SCAN_PAYLOAD_BYTES,
        },
        "findings_scanned": len(classified),
        "classified_findings": classified,
        "unclassified_context": context,
        "unclassified_context_counts": dict(Counter(item["source_bucket"] for item in context)),
        "missing_classification": missing_classification,
        "classification_counts": dict(classification_counts),
        "declared_classification_counts": dict(Counter(
            item["classification"] for item in classified if item["classification_source"] == "declared")),
        "inferred_classification_counts": dict(Counter(
            item["classification"] for item in classified if item["classification_source"] == "inferred_candidate")),
        "classification_count_semantics": "provenance_labels_not_verified_evidence",
        "evidence_ref_counts": dict(evidence_ref_counts),
        "unknown_findings": unknown_findings,
        "review_required_findings": review_required,
        "findings": findings,
        "known_gaps": [
            "Finding classification does not classify text-only gap/risk disclosures; these remain in unclassified_context for human review.",
            "Existing report writers are not required to emit classification fields in P4.",
        ],
        "residual_risks": RESIDUAL_RISKS,
        "limitations": [
            *LIMITATIONS,
            "Source report hashes bind bytes read at classification time; paths can change afterward, and this report does not assert current source state.",
            "Only strict inferred or unknown finding snapshots retain parsed JSON values; declared findings and text context retain projections plus hashes, not full original payloads.",
            "Oversized strict finding values retain only hash and size with an explicit not-retained marker; no full original report bytes are archived.",
        ],
        "not_claimed": NOT_CLAIMED,
        "human_review_required": True,
        "summary": {
            **summary,
            "reports_scanned": len(reports_scanned),
            "findings_scanned": len(classified),
            "classified_findings": len(classified),
            "unclassified_context": len(context),
            "missing_classification": len(missing_classification),
            "unknown_findings": len(unknown_findings),
            "policy_source": source,
        },
    }
    return report, summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Classify deterministic NAOS finding provenance.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--input", help="Explicit evidence_classification_policy.yaml path.")
    parser.add_argument("--report", action="append", help="Specific JSON report to scan. Repeat to scan multiple reports.")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report, summary = build_report(args)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    latest_path = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "evidence_classification_report")
    session_path = None
    if report.get("session_id"):
        session_path = session_report_default_path(root, naos_root, policy, str(report["session_id"]), "evidence_classification_report")
    write_report_with_session(latest_path, session_path, report)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"NAOS evidence classification: {report['status']} ({report['findings_scanned']} findings scanned)")
    return exit_code_for_summary(report["profile"], summary, policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
