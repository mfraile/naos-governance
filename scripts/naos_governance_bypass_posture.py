#!/usr/bin/env python3
"""Report local governance-bypass posture without claiming bypass prevention."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
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


SCHEMA = "naos.governance_bypass_posture.v1"
NOT_CLAIMED = [
    "bypass prevention",
    "tamper-proof hook enforcement",
    "authentication",
    "authorization",
    "non-repudiation",
    "PR approval",
    "security proof",
    "proof of compliance",
    "certification",
    "release authorization",
]
LIMITATIONS = [
    "This report reads local git configuration, local workflow files, and local commit messages only.",
    "Git hooks can be bypassed with --no-verify or core.hooksPath changes; NAOS reports posture but does not prevent those actions.",
    "Commit-message searches can miss bypasses because git does not record --no-verify by default.",
    "CI workflow presence is configuration evidence only; it does not prove that CI ran or passed for a specific PR.",
    "Human review remains required for bypass disposition, compensating controls, and branch protection decisions.",
]


def utc_now() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run_git(root: Path, args: list[str]) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError:
        return 127, "", "git not found"
    return result.returncode, result.stdout, result.stderr


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
        "human_review_required": severity in {"blocking", "required", "warning"} or status != "not_configured",
        "not_claimed": NOT_CLAIMED,
        **extra,
    }


def local_hook_posture(root: Path) -> dict[str, Any]:
    code, out, _ = run_git(root, ["config", "--local", "--get", "core.hooksPath"])
    configured = out.strip() if code == 0 else ""
    expected = ".githooks"
    hook_file = root / expected / "pre-commit"
    return {
        "configured_hooks_path": configured or None,
        "expected_hooks_path": expected,
        "configured_matches_expected": configured == expected,
        "pre_commit_hook_present": hook_file.is_file(),
        "pre_commit_hook_path": str(hook_file),
    }


def ci_posture(root: Path) -> dict[str, Any]:
    workflow_dir = root / ".github" / "workflows"
    workflows = sorted(path for path in workflow_dir.glob("*.y*ml")) if workflow_dir.exists() else []
    naos_workflows: list[str] = []
    for path in workflows:
        text = path.read_text(encoding="utf-8", errors="replace").lower()
        if "naos" in text or "make -f makefile.naos" in text:
            naos_workflows.append(str(path.relative_to(root)))
    return {
        "workflow_dir_present": workflow_dir.is_dir(),
        "workflow_files": [str(path.relative_to(root)) for path in workflows],
        "naos_workflow_files": naos_workflows,
        "naos_ci_present": bool(naos_workflows),
    }


def bypass_commit_messages(root: Path, days: int) -> list[dict[str, str]]:
    code, out, _ = run_git(
        root,
        ["log", f"--since={days} days ago", "--max-count=200", "--pretty=format:%H%x09%s", "--all"],
    )
    if code != 0:
        return []
    matches: list[dict[str, str]] = []
    needles = ("no-verify", "skip-hook", "skip hook", "bypass hook", "bypass pre-commit")
    for line in out.splitlines():
        commit, _, subject = line.partition("\t")
        if any(needle in subject.lower() for needle in needles):
            matches.append({"commit": commit, "subject": subject})
    return matches


def tier_posture(profile: str) -> dict[str, Any]:
    tier = (os.environ.get("NAOS_TIER") or "").strip().lower()
    return {
        "profile": profile,
        "naos_tier_env": tier or None,
        "tier_env_present": bool(tier),
        "tier_matches_profile": not tier or tier == profile,
    }


def build_report(root: Path, profile: str, naos_root: str, policy: dict[str, Any], days: int) -> dict[str, Any]:
    severity = severity_for_profile(profile, policy)
    hook = local_hook_posture(root)
    ci = ci_posture(root)
    bypass_messages = bypass_commit_messages(root, days)
    tier = tier_posture(profile)
    findings: list[dict[str, Any]] = []

    if not is_kit_repository(root, naos_root):
        if not hook["pre_commit_hook_present"]:
            findings.append(finding("governance_bypass.pre_commit_missing", severity, "missing", "Generated pre-commit hook is missing.", path=hook["pre_commit_hook_path"]))
        if hook["configured_hooks_path"] and not hook["configured_matches_expected"]:
            findings.append(finding("governance_bypass.hooks_path_mismatch", severity, "review_required", "Local core.hooksPath does not point at .githooks.", configured_hooks_path=hook["configured_hooks_path"]))
        if not hook["configured_hooks_path"]:
            findings.append(finding("governance_bypass.hooks_path_unset", "warning" if profile in {"standard", "assured"} else "advisory", "review_required", "Local core.hooksPath is not set; generated hooks may not run."))

    if profile in {"standard", "assured"} and not ci["naos_ci_present"]:
        findings.append(finding("governance_bypass.naos_ci_not_detected", severity, "review_required", "No active .github workflow containing NAOS governance commands was detected."))

    for item in bypass_messages:
        findings.append(
            finding(
                "governance_bypass.commit_message_bypass_marker",
                severity,
                "review_required",
                "Recent commit message contains a hook-bypass marker.",
                commit=item["commit"],
                subject=item["subject"],
            )
        )

    if tier["tier_env_present"] and not tier["tier_matches_profile"]:
        findings.append(finding("governance_bypass.naos_tier_profile_mismatch", severity, "review_required", "NAOS_TIER environment value differs from the selected profile.", tier=tier["naos_tier_env"], profile=profile))

    summary = finding_counts(findings)
    summary.update(
        {
            "hook_findings": sum(1 for item in findings if item["id"].startswith("governance_bypass.hooks") or item["id"].startswith("governance_bypass.pre_commit")),
            "ci_findings": sum(1 for item in findings if "ci" in item["id"]),
            "bypass_marker_findings": len(bypass_messages),
            "tier_findings": sum(1 for item in findings if "tier" in item["id"]),
        }
    )
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
        "scans": {
            "hook": hook,
            "ci": ci,
            "bypass_commit_message_window_days": days,
            "bypass_commit_messages": bypass_messages,
            "tier": tier,
        },
        "findings": findings,
        "waivers": [],
        "known_gaps": [
            "Local git hooks remain bypassable by design; CI and branch protection are adopter-managed compensating controls."
        ],
        "residual_risks": [
            "A bypass can occur without a commit-message marker.",
            "A configured workflow can be disabled, skipped, or fail outside this local report's view.",
        ],
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": bool(findings),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Report local NAOS governance-bypass posture.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--since-days", type=int, default=30)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    report = build_report(root, profile, naos_root, policy, max(args.since_days, 1))
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "governance_bypass_posture_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        destination = str(output) if output else "stdout only"
        print(f"NAOS governance bypass posture: {report['status']} (findings: {report['summary']['total_findings']}, output: {destination})")
    return exit_code_for_summary(profile, report["summary"], policy, args.strict and not is_kit_repository(root, naos_root))


if __name__ == "__main__":
    raise SystemExit(main())
