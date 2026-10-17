#!/usr/bin/env python3
"""Validate source-to-test evidence using profile-aware severity."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    controlled_utc_now_text,
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
from naos_test_evidence_map import COVERAGE_INPUT_FAILURES, build_map  # noqa: E402
from source_roots import resolve_source_roots  # noqa: E402


def load_or_build_map(args: argparse.Namespace, root: Path, profile: str, policy: dict[str, Any]) -> dict[str, Any]:
    if args.map_file:
        return json.loads(Path(args.map_file).read_text(encoding="utf-8"))
    return build_map(
        root,
        profile,
        args.source_root or [str(path) for path in resolve_source_roots(root)],
        args.test_root or ["tests"],
        args.coverage or [],
        policy,
    )


def validate_map(
    root: Path,
    profile: str,
    evidence_map: dict[str, Any],
    advisory: bool,
    policy: dict[str, Any],
    naos_root: str = "naos",
) -> dict[str, Any]:
    base_severity = severity_for_profile(profile, policy, advisory)
    input_severity = base_severity
    if is_kit_repository(root, naos_root) and evidence_map.get("status") == "not_configured":
        base_severity = "advisory"

    findings: list[dict[str, Any]] = []
    mappings = evidence_map.get("mappings") or []
    if not mappings:
        findings.append(
            {
                "id": "TEST-EVIDENCE-NOT-CONFIGURED",
                "severity": base_severity,
                "status": "not_configured",
                "message": "No source files were found in configured source roots.",
            }
        )
    else:
        for item in mappings:
            if not item.get("mapped"):
                findings.append(
                    {
                        "id": item.get("source"),
                        "severity": base_severity,
                        "status": "missing_test_evidence",
                        "message": "No matching test or per-source coverage evidence was mapped for this source file.",
                    }
                )

    coverage_inputs = evidence_map.get("coverage_inputs") or []
    for item in coverage_inputs:
        if item.get("selected") and item.get("status") in COVERAGE_INPUT_FAILURES:
            findings.append({
                "id": f"TEST-EVIDENCE-INPUT.{item['status']}.{item['path']}",
                "severity": input_severity,
                "status": f"coverage_input_{item['status']}",
                "path": item["path"],
                "message": item.get("message") or "Selected coverage input could not be analyzed.",
                "human_review_required": True,
            })
    test_inputs = evidence_map.get("test_inputs") or []
    for item in test_inputs:
        if item.get("status") in {"unreadable", "parse_error"}:
            input_status = item["status"]
            findings.append({
                "id": f"TEST-EVIDENCE-TEST-INPUT.{input_status}.{item['path']}",
                "severity": input_severity,
                "status": f"test_input_{input_status}",
                "path": item["path"],
                "message": item.get("message") or (
                    "Discovered test file could not be read."
                    if input_status == "unreadable"
                    else "Discovered test file has invalid Python syntax."
                ),
                "human_review_required": True,
            })
    map_summary = evidence_map.get("summary") or {}
    test_summary = {key: value for key, value in map_summary.items() if key.startswith("test_input")}
    test_summary.setdefault("test_input_status", "unknown")
    coverage_summary = {key: value for key, value in map_summary.items() if key.startswith("coverage_input")}
    coverage_summary.setdefault("coverage_input_status", "unknown")
    known_gaps = list(evidence_map.get("known_gaps") or [])
    if coverage_summary["coverage_input_status"] == "unknown":
        known_gaps.append("Coverage input completeness was not recorded by this map; regenerate it to verify selected inputs.")
    if test_summary["test_input_status"] == "unknown":
        known_gaps.append("Test input completeness was not recorded by this map; regenerate it to verify discovered files.")
    summary = {**finding_counts(findings), **coverage_summary, **test_summary}
    status = status_from_counts(summary)

    return {
        "schema": "naos.test_evidence_health.v1",
        "generated_at": controlled_utc_now_text(),
        "profile": profile,
        "project_root": str(root.resolve()),
        "naos_root": naos_root,
        "status": status,
        "advisory_mode": advisory,
        "map_summary": evidence_map.get("summary", {}),
        "summary": summary,
        "findings": findings,
        "coverage_inputs": coverage_inputs,
        "test_inputs": test_inputs,
        "known_gaps": known_gaps,
        "limitations": [
            "This validator reports mapped evidence and gaps; it does not prove tests are sufficient.",
            "Complete test coverage must not be claimed unless coverage evidence exists and supports the claim.",
            "Global coverage evidence is not treated as per-source evidence unless parsed coverage references the source.",
            "Profile severity controls whether gaps are advisory, warnings, required, or blocking.",
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate NAOS test evidence.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--map-file")
    parser.add_argument("--source-root", action="append", default=[])
    parser.add_argument("--test-root", action="append", default=[])
    parser.add_argument("--coverage", action="append", default=[])
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--advisory", action="store_true", help="Force advisory findings regardless of profile.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or str(policy.get("paths", {}).get("default_naos_root") or "naos")
    profile = normalize_profile(args.profile, policy)
    evidence_map = load_or_build_map(args, root, profile, policy)
    report = validate_map(root, profile, evidence_map, args.advisory, policy, naos_root)
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "test_evidence_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(
            f"NAOS test evidence validation: {report['status']} "
            f"({report['summary']['total_findings']} findings; "
            f"coverage inputs: {report['summary']['coverage_input_status']}; "
            f"test inputs: {report['summary']['test_input_status']})"
        )
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
