#!/usr/bin/env python3
"""Run the deterministic NAOS StaticGrader without model or provider runtime."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
AUTORESEARCH_PARENT = ROOT_DIR / ".github"
for candidate in (SCRIPT_DIR, ROOT_DIR, AUTORESEARCH_PARENT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

import naos_agent_trace_validate as trace_validate  # noqa: E402
from autoresearch.graders.static import StaticGrader  # noqa: E402
from naos_policy import (  # noqa: E402
    default_naos_root,
    exit_code_for_summary,
    load_policy,
    normalize_profile,
    report_default_path,
    report_output_path,
    write_report,
)


DETERMINISTIC_INPUT_REPORTS = [
    ("agent_trace_validation_report", "agent_trace_validation", "Agent trace validation"),
    ("ai_surface_context_budget_report", "ai_surface_context_budget", "AI-surface context budget"),
    ("task_context_pack_report", "task_context_pack", "Task context pack"),
    ("local_context_index_report", "local_context_index", "Local context index"),
    ("local_context_query_report", "local_context_query", "Local context query"),
    ("graph_context_query_report", "graph_context_query", "Graph context query"),
    ("memory_context_readiness_report", "memory_context_readiness", "Memory context readiness"),
    ("memory_provider_access_report", "memory_provider_access", "Memory provider access"),
    ("memory_use_policy_report", "memory_use_policy", "Memory use policy"),
    ("evidence_attestation_report", "evidence_attestation", "Evidence attestation"),
    ("gate_evaluation_report", "gate_evaluation", "Gate evaluation"),
    ("policy_override_merge_report", "policy_overrides", "Policy override merge"),
]


def load_json_report(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def collect_input_reports(root: Path, naos_root: str, policy: dict[str, Any]) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    for path_key, report_id, label in DETERMINISTIC_INPUT_REPORTS:
        path = report_default_path(root, naos_root, policy, path_key)
        data = load_json_report(path)
        findings = data.get("findings") if isinstance(data, dict) else None
        report = {
            "id": report_id,
            "label": label,
            "path": str(path),
            "present": data is not None,
            "status": data.get("status") if isinstance(data, dict) else None,
            "schema": data.get("schema") if isinstance(data, dict) else None,
            "generated_at": data.get("generated_at") if isinstance(data, dict) else None,
            "findings_count": len(findings) if isinstance(findings, list) else 0,
        }
        if report_id == "ai_surface_context_budget" and isinstance(data, dict):
            report["ai_surface_health_posture"] = data.get("ai_surface_health_posture")
            report["context_budget_posture"] = data.get("context_budget_posture")
        reports.append(report)
    return reports


def load_trace_report_or_build(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    trace_report_path: Path,
    trace_file_path: Path,
) -> dict[str, Any] | None:
    trace_report = load_json_report(trace_report_path)
    if trace_report is not None:
        return trace_report
    if not trace_file_path.exists():
        return None
    return trace_validate.build_report(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        trace_file=trace_file_path,
    )


def load_trace_events(trace_file_path: Path) -> list[dict[str, Any]]:
    if not trace_file_path.exists():
        return []
    events, _error = trace_validate.load_trace_events(trace_file_path)
    return events


def build_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    trace_report_path: Path,
    trace_file_path: Path,
) -> dict[str, Any]:
    trace_report = load_trace_report_or_build(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        trace_report_path=trace_report_path,
        trace_file_path=trace_file_path,
    )
    trace_events = load_trace_events(trace_file_path)
    input_reports = collect_input_reports(root, naos_root, policy)
    return StaticGrader().grade(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        trace_report=trace_report,
        trace_events=trace_events,
        input_reports=input_reports,
        trace_report_path=trace_report_path if trace_report is not None else None,
        trace_file_path=trace_file_path if trace_file_path.exists() else None,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run deterministic NAOS StaticGrader structural checks.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--trace-report", help="Agent trace validation report. Defaults to NAOS_ROOT/reports/agent_trace_validation.json.")
    parser.add_argument("--trace-file", help="Agent trace YAML. Defaults to NAOS_ROOT/agent_trace_events.yaml.")
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
    trace_report_path = Path(args.trace_report) if args.trace_report else report_default_path(root, naos_root, policy, "agent_trace_validation_report")
    trace_file_path = Path(args.trace_file) if args.trace_file else trace_validate.trace_default_path(root, naos_root, policy)
    report = build_report(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        trace_report_path=trace_report_path,
        trace_file_path=trace_file_path,
    )
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "static_grader_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            "NAOS StaticGrader: "
            f"{report['status']} "
            f"({report['summary']['events']} events, {report['summary']['total_findings']} findings, cost_usd=0.0) -> {output}"
        )
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    sys.exit(main())
