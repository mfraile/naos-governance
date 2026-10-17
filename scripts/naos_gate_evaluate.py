#!/usr/bin/env python3
"""
Evaluate NAOS gates using profile-aware severity.

Gate exit behavior follows the selected profile's policy transition. A blocked
gate always fails; --strict-required additionally fails required-missing gates.
The emitted JSON preserves related
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
    evaluation_scope,
    emit_input_error,
    load_manifest,
    normalize_profile,
    print_text,
    resolve_manifest,
)
from naos_audit_log import write_audit_event  # noqa: E402
from naos_policy import (  # noqa: E402
    build_generated_by,
    enforcement_transition,
    exit_code_for_summary,
    would_block_for_summary,
)


STATUS_SEVERITY = {
    "blocked": "blocking",
    "required_missing": "required",
    "warning": "warning",
    "advisory_missing": "advisory",
}


def gate_enforcement_counts(gates: list[dict]) -> dict[str, int]:
    """Count each selected gate once per severity across status and override findings."""
    counts = {"blocking": 0, "required": 0, "warnings": 0, "advisory": 0}
    for gate in gates:
        severities = set()
        status_severity = STATUS_SEVERITY.get(gate.get("status"))
        if status_severity:
            severities.add(status_severity)
        severities.update(
            item.get("severity") for item in gate.get("team_override_findings") or []
            if item.get("severity") in {"blocking", "required", "warning", "advisory"}
        )
        for severity in severities:
            counts["warnings" if severity == "warning" else severity] += 1
    return counts


def enforcement_metadata(report: dict, policy: dict, *, strict: bool, strict_required: bool) -> dict:
    counts = gate_enforcement_counts(report["gates"])
    profile = report["profile"]
    blocked = bool(report["summary"]["blocked"])
    required_missing = bool(report["summary"]["required_missing"])
    policy_exit = exit_code_for_summary(profile, counts, policy, strict=strict)
    exit_code = int(blocked or (strict_required and required_missing) or policy_exit)
    if blocked:
        reason = "blocked_gate"
    elif strict_required and required_missing:
        reason = "strict_required"
    elif policy_exit:
        reason = "policy_severity"
    elif would_block_for_summary(profile, counts, policy):
        reason = "transition_warning"
    else:
        reason = "no_failing_selected_gate"
    return {
        "transition": enforcement_transition(policy),
        "strict": strict,
        "strict_required": strict_required,
        "would_block": blocked or would_block_for_summary(profile, counts, policy),
        "reason": reason,
        "exit_code": exit_code,
        "severity_counts": counts,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate NAOS gates.")
    parser.add_argument("--manifest", help="Path to gatekeepers.yaml. Defaults to NAOS_ROOT/gatekeepers.yaml or kit template.")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT", "naos"), help="Generated project NAOS root. Default: naos")
    parser.add_argument("--policy", help="Optional policy file used for profile and report path conventions.")
    parser.add_argument("--profile", help="Profile name: quickstart, lite, standard, assured. Default: NAOS_PROFILE or policy default")
    parser.add_argument("--team-id", default=os.environ.get("NAOS_TEAM_ID"), help="Optional filesystem-safe team id for team-scoped gatekeeper config. Defaults to NAOS_TEAM_ID.")
    parser.add_argument("--gate", action="append", help="Gate ID to evaluate. Repeat to select multiple gates. Defaults to all.")
    parser.add_argument("--strict-required", action="store_true", help="Treat required_missing gates as failures.")
    parser.add_argument("--strict", action="store_true", help="Apply the selected profile's strict policy severities.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of text.")
    parser.add_argument("--output", help="Optional JSON output path.")
    return parser


def filter_gates(report: dict, selected: list[str] | None) -> dict:
    if not selected:
        return report
    wanted = {gate.upper() for gate in selected}
    unknown = wanted - {gate["id"] for gate in report["gates"]}
    if unknown:
        raise ValueError(f"Unknown selected gate identifiers: {', '.join(sorted(unknown))}")
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
    filtered["evaluation_scope"] = evaluation_scope(gates)
    filtered["selected_gates"] = sorted(wanted)
    filtered["effective_gatekeepers"] = [gate["effective_gatekeeper"] for gate in gates]
    filtered["base_gatekeepers"] = [gate["base_gatekeeper"] for gate in gates]
    filtered["team_overrides_applied"] = [
        item for item in report["team_overrides_applied"] if item.get("gate_id") in wanted
    ]
    filtered["team_overrides_rejected"] = [
        item for item in report["team_overrides_rejected"] if item.get("gate_id") in wanted
    ]
    filtered["team_override_findings"] = [
        item for item in report["team_override_findings"]
        if item.get("gate_id") is None or item.get("gate_id") in wanted
    ]
    filtered["protected_invariant_violations"] = [
        item for item in report["protected_invariant_violations"]
        if item.get("gate_id") is None or item.get("gate_id") in wanted
    ]
    filtered["findings"] = filtered["team_override_findings"]
    filtered["override_summary"] = {
        **report["override_summary"],
        "team_overrides_applied": len(filtered["team_overrides_applied"]),
        "team_overrides_rejected": len(filtered["team_overrides_rejected"]),
        "severity_downgrades": sum(
            1 for item in filtered["team_overrides_applied"]
            if item.get("original_severity") != item.get("effective_severity")
        ),
        "enabled_changes": sum(
            1 for item in filtered["team_overrides_applied"]
            if item.get("original_enabled") != item.get("effective_enabled")
        ),
    }
    filtered["human_review_required"] = bool(
        any(gate.get("human_review_required") for gate in gates)
        or any(item.get("human_review_required") for item in filtered["team_override_findings"])
    )
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
        report["enforcement"] = enforcement_metadata(report, policy, strict=args.strict, strict_required=args.strict_required)
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        return emit_input_error(exc, output=args.output, json_output=args.json)

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

    return report["enforcement"]["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
