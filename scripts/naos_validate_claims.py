#!/usr/bin/env python3
"""
Validate NAOS public claims against scoped, time-sensitive evidence.

This script is generic at kit level and project-local at adopter level. The kit
provides claim categories, safe wording checks, validators, and lifecycle rules.
An adopting project provides the actual claims, evidence, scope, toolchain
context, owners, validity periods, and revalidation triggers.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    claim_revalidation_triggers,
    claim_status_values,
    controlled_now_utc,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    load_policy,
    normalize_profile,
    overclaim_patterns,
    report_output_path,
    safe_context_phrases,
    severity_for_profile,
    should_ignore_path,
    status_from_counts,
    write_report,
)


def load_claims(path: Path | None) -> tuple[list[dict[str, Any]], str | None]:
    if path is None or not path.exists():
        return [], None
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if isinstance(data, list):
        claims = data
    elif isinstance(data, dict):
        claims = data.get("claims", [])
    else:
        raise ValueError(f"Claims file must be a mapping or list: {path}")
    if not isinstance(claims, list):
        raise ValueError(f"Claims field must be a list: {path}")
    return [claim for claim in claims if isinstance(claim, dict)], str(path)


def find_claims_file(root: Path, naos_root: str, explicit: str | None) -> Path | None:
    if explicit:
        return Path(explicit)
    candidate = root / naos_root / "claims.yaml"
    return candidate if candidate.exists() else None


def evidence_status(root: Path, evidence: Any, policy: dict[str, Any]) -> str:
    if not evidence:
        return "missing"
    if isinstance(evidence, str):
        if evidence.startswith(("http://", "https://")):
            return str(policy.get("evidence", {}).get("external_reference_default_status") or "external_reference_unverified")
        return "verified" if (root / evidence).exists() or Path(evidence).exists() else "missing"
    if isinstance(evidence, dict):
        ref = evidence.get("path") or evidence.get("file") or evidence.get("url")
        if not ref:
            return "missing"
        if str(ref).startswith(("http://", "https://")):
            return "verified" if evidence.get("verified") is True else str(
                policy.get("evidence", {}).get("external_reference_default_status") or "external_reference_unverified"
            )
        return evidence_status(root, str(ref), policy)
    return "missing"


def evidence_verified(root: Path, evidence: Any, policy: dict[str, Any]) -> bool:
    return evidence_status(root, evidence, policy) == "verified"


def expired(valid_until: Any) -> bool:
    if not valid_until:
        return False
    try:
        valid_until_date = date.fromisoformat(str(valid_until))
    except ValueError:
        return False
    return valid_until_date < controlled_now_utc().date()


def safe_context_for_match(text: str, start: int, end: int, policy: dict[str, Any]) -> str | None:
    window = int(policy.get("claims", {}).get("safe_context_window_chars") or 0)
    context = text[max(0, start - window) : min(len(text), end + window)]
    lower_context = context.lower()
    for phrase in safe_context_phrases(policy):
        if phrase in lower_context:
            return phrase
    return None


def scan_overclaims(text: str, policy: dict[str, Any]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    findings: list[dict[str, str]] = []
    safe_matches: list[dict[str, str]] = []
    for category, patterns in overclaim_patterns(policy).items():
        for pattern in patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                safe_phrase = safe_context_for_match(text, match.start(), match.end(), policy)
                item = {"category": category, "pattern": pattern}
                if safe_phrase:
                    item["safe_context"] = safe_phrase
                    safe_matches.append(item)
                else:
                    findings.append(item)
    return findings, safe_matches


def configured_doc_paths(root: Path, raw_paths: list[str], policy: dict[str, Any]) -> list[Path]:
    paths: list[Path] = []
    for raw in raw_paths:
        path = root / raw
        if path.is_file():
            if not should_ignore_path(path, policy):
                paths.append(path)
        elif path.is_dir():
            paths.extend(sorted(p for p in path.rglob("*.md") if not should_ignore_path(p, policy)))
    return paths


def validate_claims(
    root: Path,
    profile: str,
    claims: list[dict[str, Any]],
    claims_file: str | None,
    scan_paths: list[str],
    policy: dict[str, Any],
    naos_root: str,
) -> dict[str, Any]:
    severity = severity_for_profile(profile, policy)
    findings: list[dict[str, Any]] = []
    safe_disclaimer_matches: list[dict[str, Any]] = []

    if not claims and not scan_paths:
        missing_severity = "advisory" if is_kit_repository(root, naos_root) else severity
        findings.append(
            {
                "id": "CLAIMS-NOT-CONFIGURED",
                "severity": missing_severity,
                "message": "No project-local claims file or doc scan scope is configured.",
                "status": "not_configured",
            }
        )

    for index, claim in enumerate(claims, start=1):
        claim_id = str(claim.get("id") or f"claim-{index}")
        text = str(claim.get("text") or claim.get("claim") or "")
        status = str(claim.get("status") or "candidate").strip().lower()
        evidence = claim.get("evidence") or []
        if isinstance(evidence, (str, dict)):
            evidence_items = [evidence]
        elif isinstance(evidence, list):
            evidence_items = evidence
        else:
            evidence_items = []

        status_values = claim_status_values(policy)
        if status not in status_values:
            findings.append(
                {
                    "id": claim_id,
                    "severity": severity,
                    "message": f"Unsupported claim status: {status}",
                    "status": "invalid_status",
                }
            )

        evidence_statuses = [evidence_status(root, item, policy) for item in evidence_items]
        external_unverified = any(status == "external_reference_unverified" for status in evidence_statuses)
        if external_unverified:
            findings.append(
                {
                    "id": claim_id,
                    "severity": "advisory",
                    "message": "External URL evidence is a reference only unless explicitly marked verified.",
                    "status": "external_reference_unverified",
                }
            )

        if status == "supported" and not any(evidence_verified(root, item, policy) for item in evidence_items):
            findings.append(
                {
                    "id": claim_id,
                    "severity": severity,
                    "message": "Supported claim has no existing evidence reference.",
                    "status": "missing_evidence",
                }
            )

        if status in {"unsupported", "expired", "needs_revalidation"}:
            findings.append(
                {
                    "id": claim_id,
                    "severity": "warning" if profile in {"quickstart", "lite"} else severity,
                    "message": f"Claim status requires attention: {status}",
                    "status": status,
                }
            )

        if expired(claim.get("valid_until")):
            findings.append(
                {
                    "id": claim_id,
                    "severity": severity,
                    "message": "Claim validity period has expired.",
                    "status": "expired",
                }
            )

        triggers = claim.get("revalidation_triggers") or []
        if triggers and isinstance(triggers, list):
            invalid = sorted({str(trigger) for trigger in triggers} - claim_revalidation_triggers(policy))
            if invalid:
                findings.append(
                    {
                        "id": claim_id,
                        "severity": "warning",
                        "message": f"Unknown revalidation triggers: {', '.join(invalid)}",
                        "status": "invalid_revalidation_trigger",
                    }
                )
        elif status == "supported":
            findings.append(
                {
                    "id": claim_id,
                    "severity": "warning",
                    "message": "Supported claim should define revalidation triggers.",
                    "status": "missing_revalidation_triggers",
                }
            )

        overclaims, safe_matches = scan_overclaims(text, policy)
        safe_disclaimer_matches.extend({"id": claim_id, **match} for match in safe_matches)
        for overclaim in overclaims:
            findings.append(
                {
                    "id": claim_id,
                    "severity": severity,
                    "message": f"Potential overclaim: {overclaim['category']}",
                    "status": "overclaim",
                    "category": overclaim["category"],
                }
            )

    for doc_path in configured_doc_paths(root, scan_paths, policy):
        text = doc_path.read_text(encoding="utf-8", errors="replace")
        overclaims, safe_matches = scan_overclaims(text, policy)
        safe_disclaimer_matches.extend({"id": str(doc_path), **match} for match in safe_matches)
        for overclaim in overclaims:
            findings.append(
                {
                    "id": str(doc_path),
                    "severity": severity,
                    "message": f"Potential public-doc overclaim: {overclaim['category']}",
                    "status": "overclaim",
                    "category": overclaim["category"],
                }
            )

    summary = finding_counts(findings)
    status = status_from_counts(summary)

    return {
        "schema": "naos.claims_validation.v1",
        "profile": profile,
        "status": status,
        "claims_file": claims_file,
        "claim_count": len(claims),
        "summary": {
            **summary,
            "safe_disclaimer_matches": len(safe_disclaimer_matches),
        },
        "claim_lifecycle": {
            "status_values": sorted(claim_status_values(policy)),
            "revalidation_triggers": sorted(claim_revalidation_triggers(policy)),
            "time_sensitive": True,
        },
        "scope_model": {
            "kit_level": [
                "schemas",
                "categories",
                "validators",
                "safe wording",
                "lifecycle rules",
            ],
            "adopter_level": [
                "actual claims",
                "evidence",
                "scope",
                "toolchain context",
                "validity period",
                "owners",
                "revalidation triggers",
            ],
        },
        "findings": findings,
        "safe_disclaimer_matches": safe_disclaimer_matches,
        "limitations": policy.get("claims", {}).get("disclaimers", []),
        "heuristic": "Regex-based claim detection identifies potential overclaims, not definitive proof.",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate NAOS claims against scoped evidence.")
    parser.add_argument("--profile", help="quickstart, lite, standard, or assured")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy", help="Explicit NAOS policy YAML path.")
    parser.add_argument("--claims-file", help="Path to claims YAML. Defaults to NAOS_ROOT/claims.yaml when present.")
    parser.add_argument("--scan-doc", action="append", default=[], help="Markdown file or directory to scan for overclaims.")
    parser.add_argument("--output", help="JSON output path. Defaults to NAOS_ROOT/reports inside adopter projects.")
    parser.add_argument("--json", action="store_true", help="Print full JSON report.")
    parser.add_argument("--strict", action="store_true", help="Fail on required findings as well as blocking findings.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or str(policy.get("paths", {}).get("default_naos_root") or "naos")
    profile = normalize_profile(args.profile, policy)
    claims_path = find_claims_file(root, naos_root, args.claims_file)
    claims, claims_file = load_claims(claims_path)
    report = validate_claims(root, profile, claims, claims_file, args.scan_doc, policy, naos_root)
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "claims_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"NAOS claims validation: {report['status']} ({report['summary']['total_findings']} findings)")
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
