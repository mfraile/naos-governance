#!/usr/bin/env python3
"""
Evaluate NAOS gates using profile-aware severity.

By default only blocking gates return a non-zero exit code. Use
--strict-required when a standard-profile workflow wants required-but-missing
evidence to fail the command as well. The emitted JSON preserves related
governance evidence surfaced by gate-status, including governed agentic coding
workflow and Pre-Implementation Alignment review posture, without changing gate
authority or approval semantics.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_gate_status import (  # noqa: E402
    evaluate_manifest,
    load_manifest,
    normalize_profile,
    print_text,
    resolve_manifest,
)
from naos_audit_log import write_audit_event  # noqa: E402
from naos_policy import build_generated_by  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate NAOS gates.")
    parser.add_argument("--manifest", help="Path to gatekeepers.yaml. Defaults to NAOS_ROOT/gatekeepers.yaml or kit template.")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT", "naos"), help="Generated project NAOS root. Default: naos")
    parser.add_argument("--policy", help="Optional policy file used for profile and report path conventions.")
    parser.add_argument("--profile", help="Profile name: quickstart, lite, standard, assured. Default: NAOS_PROFILE or policy default")
    parser.add_argument("--team-id", default=os.environ.get("TEAM_ID") or os.environ.get("NAOS_TEAM_ID"), help="Optional filesystem-safe team id for team-scoped gatekeeper config.")
    parser.add_argument("--gate", action="append", help="Gate ID to evaluate. Repeat to select multiple gates. Defaults to all.")
    parser.add_argument("--strict-required", action="store_true", help="Treat required_missing gates as failures.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of text.")
    parser.add_argument("--output", help="Optional JSON output path.")
    return parser


def filter_gates(report: dict, selected: list[str] | None) -> dict:
    if not selected:
        return report
    wanted = {gate.upper() for gate in selected}
    gates = [gate for gate in report["gates"] if gate["id"] in wanted]
    summary = {
        "ready": sum(1 for gate in gates if gate["status"] == "ready"),
        "blocked": sum(1 for gate in gates if gate["status"] == "blocked"),
        "required_missing": sum(1 for gate in gates if gate["status"] == "required_missing"),
        "warning": sum(1 for gate in gates if gate["status"] == "warning"),
        "advisory_missing": sum(1 for gate in gates if gate["status"] == "advisory_missing"),
        "not_applicable": sum(1 for gate in gates if gate["status"] == "not_applicable"),
        "total": len(gates),
    }
    filtered = dict(report)
    filtered["summary"] = summary
    filtered["gates"] = gates
    filtered["selected_gates"] = sorted(wanted)
    return filtered


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        from naos_policy import load_policy  # imported lazily to preserve standalone script behavior

        policy = load_policy(args.policy, args.naos_root, Path.cwd())
        profile = normalize_profile(args.profile, policy)
        location = resolve_manifest(args.manifest, args.naos_root)
        manifest = load_manifest(location.path)
        report = evaluate_manifest(manifest, profile, location, args.naos_root, policy, explicit_team_id=args.team_id)
        report = filter_gates(report, args.gate)
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        print(f"ERROR: {exc}")
        return 2

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        audit_result = write_audit_event(
            root=Path.cwd(),
            naos_root=args.naos_root,
            policy=policy,
            profile=profile,
            event_type="gate_evaluated",
            source_report_path=output,
            source_report=report,
            generated_by=build_generated_by(Path.cwd(), generated_at=report.get("generated_at")),
            related_artifacts=[str(output)],
        )
        report["audit_log_event"] = {
            "status": audit_result.get("status"),
            "event_file": audit_result.get("event_file"),
            "findings": audit_result.get("findings") or [],
        }
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_text(report)

    if report["summary"]["blocked"]:
        return 1
    if args.strict_required and report["summary"]["required_missing"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
