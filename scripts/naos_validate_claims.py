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
import stat
import sys
from datetime import date
from pathlib import Path, PurePosixPath, PureWindowsPath
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


def _local_evidence_status(root: Path, reference: str) -> str:
    """Check a project-relative, forward-slash path without following links."""
    raw = reference.strip()
    parts = PurePosixPath(raw).parts
    if (
        not raw
        or "\x00" in raw
        or "\\" in raw
        or raw.startswith("/")
        or PureWindowsPath(raw).drive
        or not parts
        or ".." in parts
        or ":" in raw
    ):
        return "invalid_local_reference"

    try:
        project_root = root.resolve(strict=True)
        candidate = root
        file_mode = None
        for part in parts:
            candidate = candidate / part
            info = candidate.lstat()
            file_mode = info.st_mode
            if stat.S_ISLNK(file_mode) or (
                getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            ):
                return "invalid_local_reference"
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(project_root):
            return "invalid_local_reference"
        return "verified" if file_mode is not None and stat.S_ISREG(file_mode) else "invalid_local_reference"
    except FileNotFoundError:
        return "missing"
    except (OSError, RuntimeError, ValueError):
        return "invalid_local_reference"


def _external_reference_status(policy: dict[str, Any]) -> str:
    configured = str(
        policy.get("evidence", {}).get("external_reference_default_status") or "external_reference_unverified"
    )
    # Configuration may name a review state, but cannot verify an external source.
    return "external_reference_unverified" if configured == "verified" else configured


def evidence_status(root: Path, evidence: Any, policy: dict[str, Any]) -> str:
    external_status = _external_reference_status(policy)
    if isinstance(evidence, str):
        if evidence.startswith(("http://", "https://")):
            return external_status
        return _local_evidence_status(root, evidence)
    if isinstance(evidence, dict):
        kind = str(evidence.get("type") or "").strip().lower()
        local_keys = [key for key in ("path", "file") if key in evidence]
        external_keys = [key for key in ("url", "identifier", "uri") if key in evidence]
        if local_keys and (external_keys or kind in {"external", "url", "uri", "identifier", "external_identifier"}):
            return "invalid_local_reference"
        if kind in {"external", "url", "uri", "identifier", "external_identifier"} or external_keys:
            reference = next((evidence.get(key) for key in ("url", "identifier", "uri", "reference", "value") if key in evidence), None)
            return external_status if isinstance(reference, str) and reference.strip() else "missing"
        if len(local_keys) != 1:
            return "missing" if not evidence else "invalid_local_reference"
        reference = evidence[local_keys[0]]
        return _local_evidence_status(root, reference) if isinstance(reference, str) else "invalid_local_reference"
    return "missing"


def evidence_verified(root: Path, evidence: Any, policy: dict[str, Any]) -> bool:
    return evidence_status(root, evidence, policy) == "verified"


def expired(valid_until: Any) -> bool:
    valid_until_date = _valid_until_date(valid_until)
    return valid_until_date is not None and valid_until_date < controlled_now_utc().date()


def _valid_until_date(value: Any) -> date | None:
    text = str(value)
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", text):
        return None
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


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
        external_status = _external_reference_status(policy)
        external_unverified = external_status in evidence_statuses
        if external_unverified:
            findings.append(
                {
                    "id": claim_id,
                    "severity": "advisory",
                    "message": "External evidence is an unverified reference; a verification flag does not establish support.",
                    "status": "external_reference_unverified",
                }
            )

        if "invalid_local_reference" in evidence_statuses:
            findings.append(
                {
                    "id": claim_id,
                    "severity": severity,
                    "message": "Local evidence reference must name a regular file within the project, without traversal or symlinks.",
                    "status": "invalid_evidence_reference",
                }
            )

        if status == "supported" and "verified" not in evidence_statuses:
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

        valid_until = claim.get("valid_until")
        if "valid_until" in claim and _valid_until_date(valid_until) is None:
            findings.append(
                {
                    "id": claim_id,
                    "severity": severity,
                    "message": "Claim valid_until must be a calendar date in YYYY-MM-DD format.",
                    "status": "invalid_valid_until",
                }
            )
        elif expired(valid_until):
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
        "generated_at": controlled_now_utc().isoformat(),
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
