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
from naos_test_evidence_map import build_map  # noqa: E402
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

    summary = finding_counts(findings)
    status = status_from_counts(summary)

    return {
        "schema": "naos.test_evidence_health.v1",
        "profile": profile,
        "status": status,
        "advisory_mode": advisory,
        "map_summary": evidence_map.get("summary", {}),
        "summary": summary,
        "findings": findings,
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
        print(f"NAOS test evidence validation: {report['status']} ({report['summary']['total_findings']} findings)")
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
