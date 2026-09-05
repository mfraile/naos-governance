#!/usr/bin/env python3
"""Classify local NAOS finding provenance deterministically."""

from __future__ import annotations

import argparse
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
    "Evidence classification reads structured local findings only.",
    "Inferred classifications are review candidates, not final truth.",
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
    return {
        "id": item_id,
        "severity": severity,
        "status": finding_status,
        "message": message,
        "human_review_required": True,
        **extra,
    }


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
    if not reports_root.exists():
        return []
    return sorted(
        path for path in reports_root.glob("*.json")
        if path.name != str(policy.get("paths", {}).get("evidence_classification_report") or "evidence_classification_report.json")
    )


def load_report(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, str(exc)
    if not isinstance(data, dict):
        return None, "report must parse to a JSON object"
    return data, None


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
        deduped[key] = {"type": key[0], "ref": key[1]}
    return sorted(deduped.values(), key=lambda value: (value["type"], value["ref"]))


def collect_findings(data: dict[str, Any], report_path: Path) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    for key in ("findings", "known_gaps", "residual_risks"):
        values = data.get(key)
        if not isinstance(values, list):
            continue
        for index, raw in enumerate(values):
            if isinstance(raw, dict):
                item = dict(raw)
            else:
                item = {"message": str(raw)}
            item.setdefault("id", item.get("finding_id") or f"{report_path.stem}.{key}.{index}")
            item["_source_report"] = str(report_path)
            item["_source_bucket"] = key
            collected.append(item)
    return collected


def declared_classification(item: dict[str, Any]) -> str | None:
    value = item.get("classification") or item.get("evidence_classification") or item.get("provenance_classification")
    if value is None:
        return None
    cleaned = str(value).strip().lower()
    return cleaned if cleaned in CLASSES else "unknown"


def infer_classification(item: dict[str, Any], refs: list[dict[str, Any]]) -> tuple[str, str, bool]:
    if declared_classification(item):
        return declared_classification(item) or "unknown", "declared", False
    text = " ".join(str(item.get(field) or "") for field in ["id", "message", "status", "severity", "hypothesis_reason"]).lower()
    has_reasoning = bool(item.get("reasoning_summary"))
    if item.get("hypothesis_reason") or "hypothesis" in text or "plausible" in text or "advisory" in text:
        return "hypothesized", "inferred_candidate", True
    if len(refs) >= 2 and has_reasoning:
        return "deduced", "inferred_candidate", True
    if refs and any(ref.get("type") in {"local_file", "json_schema", "validator_output", "generated_report", "test_output", "git_diff", "audit_log_event", "evidence_pack", "sarif_finding"} for ref in refs):
        return "confirmed", "inferred_candidate", True
    return "unknown", "inferred_candidate", True


def classify_findings(paths: list[Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    reports_scanned: list[dict[str, Any]] = []
    classified: list[dict[str, Any]] = []
    parse_findings: list[dict[str, Any]] = []
    for path in paths:
        data, error = load_report(path)
        report_entry = {"path": str(path), "exists": path.exists(), "parse_error": error, "findings": 0}
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
        report_entry["findings"] = len(items)
        reports_scanned.append(report_entry)
        for item in items:
            refs = normalize_evidence_refs(item, path)
            classification, source, candidate = infer_classification(item, refs)
            classified.append(
                {
                    "finding_id": str(item.get("id")),
                    "source_report": str(path),
                    "source_bucket": item.get("_source_bucket"),
                    "classification": classification,
                    "classification_source": source,
                    "candidate_requires_review": candidate,
                    "severity": item.get("severity"),
                    "status": item.get("status"),
                    "message": item.get("message"),
                    "evidence_refs": refs,
                    "reasoning_summary": item.get("reasoning_summary"),
                    "human_review_required": True,
                    "not_claimed": ["truth proof", "approval", "issue resolution"],
                }
            )
    return reports_scanned, classified, parse_findings


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
        findings.extend(policy_findings)
        if policy_valid:
            scan_paths = [Path(item) for item in args.report] if args.report else report_paths(root, naos_root, policy)
            reports_scanned, classified, parse_findings = classify_findings(scan_paths)
            findings.extend(parse_findings)

    missing_classification = [
        item for item in classified
        if item.get("classification_source") == "inferred_candidate" or item.get("classification") == "unknown"
    ]
    unknown_findings = [item for item in classified if item.get("classification") == "unknown"]
    review_required = [item for item in classified if item.get("candidate_requires_review") or item.get("classification") == "unknown"]
    for item in missing_classification:
        findings.append(
            finding(
                f"evidence_classification.missing.{item.get('finding_id')}",
                severity_for_profile(profile, load_policy(args.policy, args.naos_root, Path.cwd()), advisory=profile in {"quickstart", "lite"}),
                "missing_classification",
                "Finding lacks declared provenance classification; inferred candidate requires human review.",
                finding_id=item.get("finding_id"),
                source_report=item.get("source_report"),
                inferred_classification=item.get("classification"),
            )
        )
    classification_counts = Counter(str(item.get("classification") or "unknown") for item in classified)
    evidence_ref_counts = Counter(str(ref.get("type") or "unknown") for item in classified for ref in item.get("evidence_refs") or [])
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
        "findings_scanned": len(classified),
        "classified_findings": classified,
        "missing_classification": missing_classification,
        "classification_counts": dict(classification_counts),
        "evidence_ref_counts": dict(evidence_ref_counts),
        "unknown_findings": unknown_findings,
        "review_required_findings": review_required,
        "findings": findings,
        "known_gaps": [
            "Classification scans structured findings arrays in local NAOS JSON reports only.",
            "Existing report writers are not required to emit classification fields in P4.",
        ],
        "residual_risks": RESIDUAL_RISKS,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": True,
        "summary": {
            **summary,
            "reports_scanned": len(reports_scanned),
            "findings_scanned": len(classified),
            "classified_findings": len(classified),
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
