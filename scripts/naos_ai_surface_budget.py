#!/usr/bin/env python3
"""Evaluate deterministic NAOS AI-surface health, context budget, and baseline drift."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    load_policy,
    normalize_profile,
    report_output_path,
    severity_for_profile,
    status_from_counts,
    write_report,
)


REPORT_SCHEMA = "naos.ai_surface_context_budget.v1"
PROFILE_BASELINE_SCHEMA = "naos.ai_surface_profile_footprint_baseline.v1"
RULES_SCHEMA = "naos.ai_surface_context_budget_rules.v1"
DEFAULT_RULES_PATH = ROOT_DIR / "templates" / "structural-seeds" / "naos" / "ai_surface_context_budget_rules.yaml"
DEFAULT_BASELINE_REL = "baselines/ai_surface_health_baseline.json"
DEFAULT_PROFILE_BASELINE_REL = "baselines/ai_surface_profile_footprint_baseline.json"
PROFILE_ORDER = ("quickstart", "lite", "standard", "assured")
PROFILE_METRICS = (
    "fresh_project_finding_count",
    "resident_context_tokens",
    "generated_file_count",
    "cli_command_count",
)
PROFILE_STATE_CLASSES = (
    "not_configured",
    "not_applicable",
    "disabled",
    "advisory",
    "actionable",
    "satisfied",
    "unknown",
)
DEFAULT_PROFILE_DISPLAY_MAX_ROWS = 24
FRESH_PROFILE_FIXED_TIME = "2026-08-21T00:00:00Z"
FRESH_PROVIDER_METADATA_OVERRIDES = {
    "provider_binary_check_allowed": False,
    "provider_data_dir_metadata_check_allowed": False,
    "provider_database_metadata_check_allowed": False,
    "provider_store_metadata_check_allowed": False,
    "user_mcp_config_metadata_check_allowed": False,
}
FRESH_AUDIT_EVENT_RE = re.compile(r"audit-\d{8}T\d{6}Z-[0-9a-f]{12}", re.IGNORECASE)
FRESH_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
FRESH_DYNAMIC_NORMALIZATIONS = [
    "temporary roots",
    "Python executable",
    "user-home paths",
    "generated session UUIDs",
    "generated audit event IDs",
    "generated input mtimes to the fixed replay instant",
]
FRESH_GENERATED_INPUT_PHASE = "post-isolation-overlay_pre-self-check"
DOWNSTREAM_NON_INPUTS = [
    "naos/reports/static_grader_report.json",
    "naos/reports/grader_assessment.json",
    "naos/reports/gate_status.json",
    "naos/reports/gate_evaluation.json",
    "naos/reports/self_check.json",
    "naos/reports/dashboard_summary.json",
    "naos/DASHBOARD.md",
    "naos/evidence/evidence_pack.json",
    "naos/reports/behavioral_evaluation.json",
]
DOWNSTREAM_CONSUMERS = [
    "static_grader",
    "grader_assessment",
    "autoresearch_runner",
    "self_check",
    "gate_status",
    "dashboard",
    "evidence_pack",
]


DEFAULT_RULES: dict[str, Any] = {
    "schema": RULES_SCHEMA,
    "version": 1,
    "token_estimation": {"chars_per_token": 4},
    "baseline": {
        "default_path": DEFAULT_BASELINE_REL,
        "size_drift_warning_pct": 15,
        "size_drift_blocking_pct": 30,
        "baseline_missing_severity": "advisory",
    },
    "profile_footprint": {
        "controlled_command": "naos ai-surface-budget --fresh-profiles --json",
        "baseline_ref": DEFAULT_PROFILE_BASELINE_REL,
        "default_display_max_rows": DEFAULT_PROFILE_DISPLAY_MAX_ROWS,
        "profiles": list(PROFILE_ORDER),
        "thresholds": {},
    },
    "families": [
        {
            "id": "agents",
            "label": "Agents",
            "patterns": [
                "templates/agents/**/*.md",
                ".github/agents/*.md",
                "AGENTS.md",
            ],
            "warn_tokens": 2000,
            "block_tokens": 5000,
        },
        {
            "id": "instructions",
            "label": "Instructions",
            "patterns": ["templates/instructions/*.md", ".github/instructions/*.md"],
            "warn_tokens": 2500,
            "block_tokens": 4000,
        },
        {
            "id": "instruction_triple",
            "label": "Instruction triple",
            "patterns": [
                "templates/instruction-triple/*.md",
                "profiles/governance-*/.ai/RULES.md",
                "CLAUDE.md",
                ".github/copilot-instructions.md",
                ".ai/RULES.md",
            ],
            "warn_tokens": 3500,
            "block_tokens": 5500,
        },
        {
            "id": "prompts",
            "label": "Prompts",
            "patterns": ["templates/prompts/*.md", ".github/prompts/*.md"],
            "warn_tokens": 2500,
            "block_tokens": 5000,
        },
        {
            "id": "skills",
            "label": "Skills",
            "patterns": ["templates/skills/*/SKILL.md", ".github/skills/*/SKILL.md"],
            "warn_tokens": 2500,
            "block_tokens": 5000,
        },
        {
            "id": "workflows",
            "label": "Workflows",
            "patterns": ["templates/workflows/*.yml", "templates/workflows/*.yaml", ".github/workflows/*.yml", ".github/workflows/*.yaml"],
            "warn_tokens": 2500,
            "block_tokens": 5000,
        },
        {
            "id": "rules_chain",
            "label": "Rules chain",
            "patterns": ["templates/rules-chain/.ai/*", "profiles/governance-*/.ai/RULES.md", ".ai/*"],
            "warn_tokens": 2500,
            "block_tokens": 4000,
        },
        {
            "id": "cursor_rules",
            "label": "Cursor rules",
            "patterns": ["templates/cursor-rules/*.mdc", ".cursor/rules/*.mdc", ".cursorrules"],
            "warn_tokens": 2500,
            "block_tokens": 4000,
        },
    ],
    "combined_scenarios": [
        {
            "id": "claude_base",
            "label": "Claude base governance loadout",
            "profiles": ["lite", "standard", "assured"],
            "files": [
                {"path": "templates/instruction-triple/CLAUDE.md", "optional": True},
                {"path": "CLAUDE.md", "optional": True},
                {"path": "templates/instructions/governance.instructions.md", "optional": True},
                {"path": ".github/instructions/governance.instructions.md", "optional": True},
                {"path": "templates/instructions/context-pressure.instructions.md", "optional": True},
                {"path": ".github/instructions/context-pressure.instructions.md", "optional": True},
            ],
            "warn_tokens": 12000,
            "block_tokens": 18000,
        },
        {
            "id": "copilot_base",
            "label": "Copilot base governance loadout",
            "profiles": ["lite", "standard", "assured"],
            "files": [
                {"path": "templates/instruction-triple/copilot-instructions.md", "optional": True},
                {"path": ".github/copilot-instructions.md", "optional": True},
                {"path": "templates/instruction-triple/project-context.md", "optional": True},
                {"path": ".github/instructions/project-context.md", "optional": True},
                {"path": "templates/instructions/governance.instructions.md", "optional": True},
                {"path": ".github/instructions/governance.instructions.md", "optional": True},
                {"path": "templates/instructions/context-pressure.instructions.md", "optional": True},
                {"path": ".github/instructions/context-pressure.instructions.md", "optional": True},
            ],
            "warn_tokens": 12000,
            "block_tokens": 18000,
        },
        {
            "id": "implement_agent",
            "label": "Implement agent plus task-start prompt",
            "profiles": ["standard", "assured"],
            "files": [
                {"path": "templates/agents/AGENTS.md", "optional": True},
                {"path": ".github/agents/AGENTS.md", "optional": True},
                {"path": "templates/agents/naos-implement.agent.md", "optional": True},
                {"path": ".github/agents/naos-implement.agent.md", "optional": True},
                {"path": "templates/prompts/naos-task-start.prompt.md", "optional": True},
                {"path": ".github/prompts/naos-task-start.prompt.md", "optional": True},
                {"path": "templates/instructions/governance.instructions.md", "optional": True},
            ],
            "warn_tokens": 12000,
            "block_tokens": 18000,
        },
        {
            "id": "review_agent",
            "label": "Review agent plus task-complete prompt",
            "profiles": ["standard", "assured"],
            "files": [
                {"path": "templates/agents/AGENTS.md", "optional": True},
                {"path": ".github/agents/AGENTS.md", "optional": True},
                {"path": "templates/agents/naos-review.agent.md", "optional": True},
                {"path": ".github/agents/naos-review.agent.md", "optional": True},
                {"path": "templates/prompts/naos-task-complete.prompt.md", "optional": True},
                {"path": ".github/prompts/naos-task-complete.prompt.md", "optional": True},
                {"path": "templates/instructions/governance.instructions.md", "optional": True},
            ],
            "warn_tokens": 12000,
            "block_tokens": 18000,
        },
        {
            "id": "systemic_review",
            "label": "Systemic review and wiring loadout",
            "profiles": ["standard", "assured"],
            "files": [
                {"path": "templates/agents/naos-conformance.agent.md", "optional": True},
                {"path": ".github/agents/naos-conformance.agent.md", "optional": True},
                {"path": "templates/skills/systemic-capability-wiring/SKILL.md", "optional": True},
                {"path": ".github/skills/systemic-capability-wiring/SKILL.md", "optional": True},
                {"path": "templates/instructions/governance.instructions.md", "optional": True},
                {"path": "templates/instructions/context-pressure.instructions.md", "optional": True},
            ],
            "warn_tokens": 10000,
            "block_tokens": 16000,
        },
    ],
    "anchors": [
        {
            "id": "non_claim_boundary",
            "label": "Non-claim boundary",
            "phrases": ["does not prove", "not approval", "not certification", "not claimed"],
        },
        {
            "id": "human_review_boundary",
            "label": "Human review boundary",
            "phrases": ["human review", "human approval", "human reviewers"],
        },
        {
            "id": "deterministic_boundary",
            "label": "Deterministic boundary",
            "phrases": ["deterministic", "file-first", "no LLM", "no model"],
        },
        {
            "id": "evidence_hierarchy",
            "label": "Evidence hierarchy",
            "phrases": ["source artifacts remain authoritative", "repository evidence", "evidence"],
        },
        {
            "id": "context_pressure",
            "label": "Context pressure",
            "phrases": ["context pressure", "NAOS_CONTEXT_REMAINING_PCT", "checkpoint", "compact"],
        },
        {
            "id": "profile_gate_boundary",
            "label": "Profile and gate boundary",
            "phrases": ["quickstart", "lite", "standard", "assured", "gate"],
        },
        {
            "id": "tool_neutrality",
            "label": "Tool neutrality",
            "phrases": ["tool-neutral", "Claude", "Codex", "Copilot", "Cursor"],
        },
    ],
}


def utc_now_text() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def default_rules_path(root: Path, naos_root: str, policy: dict[str, Any]) -> Path:
    filename = str(policy.get("paths", {}).get("ai_surface_context_budget_rules") or "ai_surface_context_budget_rules.yaml")
    project_rules = root / naos_root / filename
    return project_rules if project_rules.exists() else DEFAULT_RULES_PATH


def load_rules(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    if not path.exists():
        return DEFAULT_RULES, {"path": str(path), "present": False, "source": "default_fallback"}
    try:
        loaded = load_yaml_mapping(path)
    except Exception as exc:
        return DEFAULT_RULES, {"path": str(path), "present": False, "source": "default_fallback", "error": str(exc)}
    return deep_merge(DEFAULT_RULES, loaded), {"path": str(path), "present": True, "source": "rules_file"}


def estimate_tokens(chars: int, rules: dict[str, Any]) -> int:
    chars_per_token = int((rules.get("token_estimation") or {}).get("chars_per_token") or 4)
    chars_per_token = max(chars_per_token, 1)
    return (chars + chars_per_token - 1) // chars_per_token


def path_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relpath(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def ignored(path: Path) -> bool:
    ignored_parts = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"}
    return any(part in ignored_parts for part in path.parts)


def collect_family_files(root: Path, rules: dict[str, Any]) -> dict[str, list[Path]]:
    families: dict[str, list[Path]] = {}
    for family in rules.get("families") or []:
        if not isinstance(family, dict):
            continue
        family_id = str(family.get("id") or "unknown")
        paths: dict[str, Path] = {}
        for pattern in family.get("patterns") or []:
            if not isinstance(pattern, str):
                continue
            for path in root.glob(pattern):
                if path.is_file() and not ignored(path):
                    paths[relpath(path, root)] = path
        families[family_id] = [paths[key] for key in sorted(paths)]
    return families


def file_metrics(path: Path, root: Path, rules: dict[str, Any]) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    chars = len(text)
    return {
        "path": relpath(path, root),
        "lines": len(text.splitlines()),
        "chars": chars,
        "estimated_tokens": estimate_tokens(chars, rules),
        "sha256": path_hash(path),
    }


def condition_severity(profile: str, policy: dict[str, Any], level: str) -> str:
    if level == "advisory":
        return "advisory"
    if level == "warning":
        return "advisory" if profile == "quickstart" else "warning"
    return {
        "quickstart": "advisory",
        "lite": "warning",
        "standard": "required",
        "assured": "blocking",
    }.get(profile, severity_for_profile(profile, policy))


def finding(
    *,
    finding_id: str,
    severity: str,
    status: str,
    message: str,
    source: str,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "status": status,
        "message": message,
        "source": source,
        "control_type": "ai_surface_health",
        "authority_layer": "deterministic_primary",
        "human_review_required": True,
        "not_claimed": ["approval", "certification", "compliance proof", "behavioral score", "hallucination prevention"],
    }


def threshold_findings(
    *,
    item_id: str,
    item_label: str,
    tokens: int,
    warn_tokens: int,
    block_tokens: int,
    source: str,
    profile: str,
    policy: dict[str, Any],
    scope: str,
) -> list[dict[str, Any]]:
    if block_tokens and tokens > block_tokens:
        return [
            finding(
                finding_id=f"AI_SURFACE_{scope.upper()}_BUDGET_EXCEEDED",
                severity=condition_severity(profile, policy, "blocking"),
                status=f"{scope}_budget_exceeded",
                message=f"{item_label} is estimated at {tokens} tokens, above the configured block threshold {block_tokens}.",
                source=source,
            )
        ]
    if warn_tokens and tokens > warn_tokens:
        return [
            finding(
                finding_id=f"AI_SURFACE_{scope.upper()}_BUDGET_WARNING",
                severity=condition_severity(profile, policy, "warning"),
                status=f"{scope}_budget_warning",
                message=f"{item_label} is estimated at {tokens} tokens, above the configured warning threshold {warn_tokens}.",
                source=source,
            )
        ]
    return []


def build_family_reports(
    root: Path,
    rules: dict[str, Any],
    profile: str,
    policy: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, dict[str, Any]]]:
    collected = collect_family_files(root, rules)
    family_reports: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []
    file_index: dict[str, dict[str, Any]] = {}
    family_by_id = {str(item.get("id")): item for item in rules.get("families") or [] if isinstance(item, dict)}
    for family_id, paths in sorted(collected.items()):
        family_rule = family_by_id.get(family_id, {})
        files = [file_metrics(path, root, rules) for path in paths]
        for item in files:
            file_index[item["path"]] = item
            all_findings.extend(
                threshold_findings(
                    item_id=item["path"],
                    item_label=item["path"],
                    tokens=int(item["estimated_tokens"]),
                    warn_tokens=int(family_rule.get("warn_tokens") or 0),
                    block_tokens=int(family_rule.get("block_tokens") or 0),
                    source=item["path"],
                    profile=profile,
                    policy=policy,
                    scope="file",
                )
            )
        family_reports.append(
            {
                "id": family_id,
                "label": family_rule.get("label") or family_id,
                "file_count": len(files),
                "lines": sum(int(item["lines"]) for item in files),
                "chars": sum(int(item["chars"]) for item in files),
                "estimated_tokens": sum(int(item["estimated_tokens"]) for item in files),
                "warn_tokens": family_rule.get("warn_tokens"),
                "block_tokens": family_rule.get("block_tokens"),
                "files": files,
            }
        )
    return family_reports, all_findings, file_index


def resolve_scenario_file(root: Path, item: Any) -> tuple[Path | None, bool, str]:
    if isinstance(item, str):
        path = item
        optional = False
    elif isinstance(item, dict):
        path = str(item.get("path") or "")
        optional = bool(item.get("optional", False))
    else:
        return None, True, ""
    if not path:
        return None, optional, path
    full = root / path
    return (full if full.is_file() and not ignored(full) else None), optional, path


def build_scenarios(
    root: Path,
    rules: dict[str, Any],
    profile: str,
    policy: dict[str, Any],
    file_index: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    scenarios: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for scenario in rules.get("combined_scenarios") or []:
        if not isinstance(scenario, dict):
            continue
        scenario_id = str(scenario.get("id") or "unknown")
        profiles = [str(item) for item in scenario.get("profiles") or []]
        applicable = not profiles or profile in profiles
        files: list[dict[str, Any]] = []
        missing_required: list[str] = []
        for entry in scenario.get("files") or []:
            path, optional, requested = resolve_scenario_file(root, entry)
            if path is None:
                if not optional:
                    missing_required.append(requested)
                continue
            metric = file_index.get(relpath(path, root)) or file_metrics(path, root, rules)
            files.append(metric)
        tokens = sum(int(item["estimated_tokens"]) for item in files)
        report = {
            "id": scenario_id,
            "label": scenario.get("label") or scenario_id,
            "profiles": profiles,
            "applicable_to_profile": applicable,
            "file_count": len(files),
            "files": [item["path"] for item in files],
            "missing_required_files": missing_required,
            "lines": sum(int(item["lines"]) for item in files),
            "chars": sum(int(item["chars"]) for item in files),
            "estimated_tokens": tokens,
            "warn_tokens": scenario.get("warn_tokens"),
            "block_tokens": scenario.get("block_tokens"),
        }
        if applicable:
            findings.extend(
                threshold_findings(
                    item_id=scenario_id,
                    item_label=str(report["label"]),
                    tokens=tokens,
                    warn_tokens=int(scenario.get("warn_tokens") or 0),
                    block_tokens=int(scenario.get("block_tokens") or 0),
                    source=scenario_id,
                    profile=profile,
                    policy=policy,
                    scope="combined",
                )
            )
        if missing_required:
            findings.append(
                finding(
                    finding_id="AI_SURFACE_COMBINED_MISSING_REQUIRED_FILE",
                    severity=condition_severity(profile, policy, "warning"),
                    status="combined_missing_required_file",
                    message=f"{scenario_id} is missing required scenario file(s): {', '.join(missing_required)}.",
                    source=scenario_id,
                )
            )
        scenarios.append(report)
    return scenarios, findings


def corpus_text(root: Path, file_index: dict[str, dict[str, Any]]) -> str:
    texts: list[str] = []
    for rel in sorted(file_index):
        path = root / rel
        if path.is_file():
            texts.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(texts).lower()


def build_anchors(
    root: Path,
    rules: dict[str, Any],
    profile: str,
    policy: dict[str, Any],
    file_index: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    text = corpus_text(root, file_index)
    anchors: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for anchor in rules.get("anchors") or []:
        if not isinstance(anchor, dict):
            continue
        anchor_id = str(anchor.get("id") or "unknown")
        phrases = [str(item) for item in anchor.get("phrases") or []]
        matched = [phrase for phrase in phrases if phrase.lower() in text]
        missing = [phrase for phrase in phrases if phrase.lower() not in text]
        present = bool(phrases) and not missing
        anchors.append(
            {
                "id": anchor_id,
                "label": anchor.get("label") or anchor_id,
                "present": present,
                "matched_phrases": matched,
                "missing_phrases": missing,
                "required_phrases": phrases,
            }
        )
        if not present:
            missing_text = ", ".join(missing) if missing else "no configured phrases"
            findings.append(
                finding(
                    finding_id="AI_SURFACE_ANCHOR_MISSING",
                    severity=condition_severity(profile, policy, "blocking"),
                    status="anchor_missing",
                    message=(
                        f"Required AI-surface health anchor is incomplete or missing: "
                        f"{anchor.get('label') or anchor_id}; missing phrase(s): {missing_text}."
                    ),
                    source=anchor_id,
                )
            )
    return anchors, findings


def default_baseline_path(root: Path, naos_root: str, rules: dict[str, Any], policy: dict[str, Any]) -> Path:
    configured = str(policy.get("paths", {}).get("ai_surface_health_baseline") or (rules.get("baseline") or {}).get("default_path") or DEFAULT_BASELINE_REL)
    return root / naos_root / configured


def load_baseline(path: Path | None) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    if path is None:
        return None, {"path": None, "present": False, "status": "not_configured"}
    if not path.exists():
        return None, {"path": str(path), "present": False, "status": "missing_baseline"}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, {"path": str(path), "present": True, "status": "invalid_baseline", "error": str(exc)}
    return data if isinstance(data, dict) else None, {"path": str(path), "present": True, "status": "loaded"}


def build_snapshot(
    family_reports: list[dict[str, Any]],
    scenarios: list[dict[str, Any]],
    anchors: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "total_estimated_tokens": sum(int(item["estimated_tokens"]) for item in family_reports),
        "total_files": sum(int(item["file_count"]) for item in family_reports),
        "families": {item["id"]: {"file_count": item["file_count"], "estimated_tokens": item["estimated_tokens"]} for item in family_reports},
        "combined_scenarios": {item["id"]: {"estimated_tokens": item["estimated_tokens"], "file_count": item["file_count"]} for item in scenarios},
        "anchors": {item["id"]: bool(item["present"]) for item in anchors},
    }


def baseline_snapshot(data: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    snapshot = data.get("snapshot")
    if isinstance(snapshot, dict):
        return snapshot
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    return {
        "total_estimated_tokens": summary.get("total_estimated_tokens"),
        "total_files": summary.get("total_files"),
        "families": {item.get("id"): {"file_count": item.get("file_count"), "estimated_tokens": item.get("estimated_tokens")} for item in data.get("families") or [] if isinstance(item, dict)},
        "combined_scenarios": {item.get("id"): {"estimated_tokens": item.get("estimated_tokens"), "file_count": item.get("file_count")} for item in data.get("combined_scenarios") or [] if isinstance(item, dict)},
        "anchors": {item.get("id"): bool(item.get("present")) for item in data.get("anchors") or [] if isinstance(item, dict)},
    }


def compare_baseline(
    current: dict[str, Any],
    baseline_data: dict[str, Any] | None,
    baseline_meta: dict[str, Any],
    rules: dict[str, Any],
    profile: str,
    policy: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    result = {
        **baseline_meta,
        "size_delta_tokens": None,
        "size_delta_pct": None,
        "anchor_regressions": [],
        "scenario_token_drift": [],
        "auto_update_performed": False,
        "human_approval_required_before_update": True,
        "not_claimed": ["automatic baseline approval", "automatic threshold tuning", "maturity promotion"],
    }
    if not baseline_meta.get("present"):
        if baseline_meta.get("status") == "missing_baseline":
            findings.append(
                finding(
                    finding_id="AI_SURFACE_BASELINE_MISSING",
                    severity=str((rules.get("baseline") or {}).get("baseline_missing_severity") or "advisory"),
                    status="missing_baseline",
                    message="No approved AI-surface health baseline is present; posture is still measured from current source artifacts.",
                    source=str(baseline_meta.get("path")),
                )
            )
        return result, findings
    if baseline_meta.get("status") == "invalid_baseline" or baseline_data is None:
        findings.append(
            finding(
                finding_id="AI_SURFACE_BASELINE_INVALID",
                severity=condition_severity(profile, policy, "warning"),
                status="invalid_baseline",
                message="Configured AI-surface health baseline is not valid JSON.",
                source=str(baseline_meta.get("path")),
            )
        )
        return result, findings

    previous = baseline_snapshot(baseline_data)
    previous_tokens = previous.get("total_estimated_tokens")
    current_tokens = current.get("total_estimated_tokens")
    if isinstance(previous_tokens, int) and isinstance(current_tokens, int) and previous_tokens > 0:
        delta = current_tokens - previous_tokens
        pct = (delta / previous_tokens) * 100.0
        result["size_delta_tokens"] = delta
        result["size_delta_pct"] = round(pct, 2)
        baseline_rules = rules.get("baseline") or {}
        if pct > float(baseline_rules.get("size_drift_blocking_pct") or 30):
            findings.append(
                finding(
                    finding_id="AI_SURFACE_BASELINE_SIZE_DRIFT",
                    severity=condition_severity(profile, policy, "blocking"),
                    status="baseline_size_drift",
                    message=f"AI-surface estimated tokens grew {pct:.1f}% above baseline.",
                    source=str(baseline_meta.get("path")),
                )
            )
        elif pct > float(baseline_rules.get("size_drift_warning_pct") or 15):
            findings.append(
                finding(
                    finding_id="AI_SURFACE_BASELINE_SIZE_DRIFT",
                    severity=condition_severity(profile, policy, "warning"),
                    status="baseline_size_drift",
                    message=f"AI-surface estimated tokens grew {pct:.1f}% above baseline.",
                    source=str(baseline_meta.get("path")),
                )
            )

    previous_anchors = previous.get("anchors") if isinstance(previous.get("anchors"), dict) else {}
    current_anchors = current.get("anchors") if isinstance(current.get("anchors"), dict) else {}
    regressions = sorted(anchor_id for anchor_id, was_present in previous_anchors.items() if was_present and current_anchors.get(anchor_id) is False)
    result["anchor_regressions"] = regressions
    for anchor_id in regressions:
        findings.append(
            finding(
                finding_id="AI_SURFACE_BASELINE_ANCHOR_REGRESSION",
                severity=condition_severity(profile, policy, "blocking"),
                status="baseline_anchor_regression",
                message=f"AI-surface baseline anchor was present before and is missing now: {anchor_id}.",
                source=str(baseline_meta.get("path")),
            )
        )
    return result, findings


def health_posture(findings: list[dict[str, Any]]) -> str:
    statuses = {str(item.get("status")) for item in findings}
    if any(status in statuses for status in {"file_budget_exceeded", "combined_budget_exceeded", "anchor_missing", "baseline_anchor_regression"}):
        return "degraded"
    if findings:
        return "warning"
    return "healthy"


def build_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules_path: Path,
    baseline_path: Path | None,
) -> dict[str, Any]:
    rules, rules_meta = load_rules(rules_path)
    families, findings, file_index = build_family_reports(root, rules, profile, policy)
    scenarios, scenario_findings = build_scenarios(root, rules, profile, policy, file_index)
    findings.extend(scenario_findings)
    anchors, anchor_findings = build_anchors(root, rules, profile, policy, file_index)
    findings.extend(anchor_findings)
    snapshot = build_snapshot(families, scenarios, anchors)
    baseline_data, baseline_meta = load_baseline(baseline_path)
    baseline, baseline_findings = compare_baseline(snapshot, baseline_data, baseline_meta, rules, profile, policy)
    findings.extend(baseline_findings)
    summary = finding_counts(findings)
    posture = health_posture(findings)
    summary.update(
        {
            "families": len(families),
            "combined_scenarios": len(scenarios),
            "anchors": len(anchors),
            "anchors_present": sum(1 for item in anchors if item.get("present")),
            "total_files": snapshot["total_files"],
            "total_estimated_tokens": snapshot["total_estimated_tokens"],
            "ai_surface_health_posture": posture,
        }
    )
    return {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": status_from_counts(summary),
        "ai_surface_health_posture": posture,
        "context_budget_posture": posture,
        "naos_root": naos_root,
        "project_root": str(root),
        "deterministic": True,
        "advisory": False,
        "cycle_safe": True,
        "rules": rules_meta,
        "baseline": baseline,
        "input_sources": {
            "rules": rules_meta,
            "source_files": sorted(file_index),
            "optional_baseline": baseline_meta,
        },
        "non_inputs": DOWNSTREAM_NON_INPUTS,
        "downstream_consumers": DOWNSTREAM_CONSUMERS,
        "families": families,
        "combined_scenarios": scenarios,
        "anchors": anchors,
        "snapshot": snapshot,
        "findings": findings,
        "known_gaps": [
            "Token estimation is deterministic chars-per-token approximation, not provider tokenizer output.",
            "AI-surface health reduces hallucination risk factors but does not prevent hallucinations.",
            "Behavioral/model-backed autoresearch remains project-configured and disabled by default.",
        ],
        "residual_risks": [
            "large_or_contradictory_surfaces_can_reduce_model_attention",
            "model_tool_or_ide_changes_can_shift_effective_context_behavior",
            "baseline_staleness_can_mislead_without_human_review",
            "semantic_quality_requires_project_configured_evaluation",
        ],
        "limitations": [
            "Reads source AI surfaces, policy paths, rules, and optional baseline only.",
            "Does not read downstream reports, dashboard output, evidence packs, behavioral results, models, providers, APIs, memory, or MCP tools.",
            "Does not auto-tune thresholds or auto-approve baseline changes.",
        ],
        "not_claimed": [
            "hallucination prevention",
            "behavioral score",
            "semantic correctness proof",
            "approval",
            "certification",
            "compliance proof",
            "maturity promotion",
            "automatic threshold tuning",
        ],
        "human_review_required": bool(findings),
        "summary": summary,
    }


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_module_from_path(module_name: str, path: Path) -> Any:
    if not path.is_file():
        raise FileNotFoundError(f"Required kit module is missing: {path}")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load kit module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def normalize_dynamic_values(value: Any, replacements: list[tuple[str, str]]) -> Any:
    if isinstance(value, dict):
        return {
            str(key): normalize_dynamic_values(item, replacements)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [normalize_dynamic_values(item, replacements) for item in value]
    if isinstance(value, str):
        normalized = value
        for source, target in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
            if source:
                normalized = normalized.replace(source, target)
        normalized = FRESH_AUDIT_EVENT_RE.sub("audit-<fixed-time>-<dynamic-id>", normalized)
        normalized = FRESH_UUID_RE.sub("<dynamic-session-id>", normalized)
        return normalized
    return value


def profile_state_class(status: Any, severity: Any = None) -> str:
    normalized_status = str(status or "unknown").strip().lower().replace("-", "_")
    normalized_severity = str(severity or "unknown").strip().lower().replace("-", "_")
    if normalized_status == "not_configured":
        return "not_configured"
    if normalized_status == "not_applicable":
        return "not_applicable"
    if normalized_status in {
        "disabled",
        "disabled_by_profile",
        "skipped_disabled",
        "waived",
        "waiver_visible",
    }:
        return "disabled"
    if normalized_severity == "advisory" or normalized_status == "advisory":
        return "advisory"
    if normalized_severity in {"blocking", "required", "warning", "error"}:
        return "actionable"
    if normalized_status in {
        "pass",
        "passed",
        "ok",
        "ready",
        "healthy",
        "clean",
        "satisfied",
        "complete",
        "completed",
        "no_findings",
    }:
        return "satisfied"
    if any(
        marker in normalized_status
        for marker in (
            "block",
            "required",
            "warning",
            "error",
            "fail",
            "missing",
            "invalid",
            "degraded",
            "review_required",
        )
    ):
        return "actionable"
    return "unknown"


def empty_profile_state_counts() -> dict[str, int]:
    return {state: 0 for state in PROFILE_STATE_CLASSES}


def flatten_self_check(
    report: dict[str, Any],
    *,
    profile: str,
    replacements: list[tuple[str, str]],
    returncode: int,
    command: list[str],
) -> dict[str, Any]:
    occurrences: list[dict[str, Any]] = []
    check_states: list[dict[str, Any]] = []
    finding_state_counts = empty_profile_state_counts()
    check_state_counts = empty_profile_state_counts()
    checks = report.get("checks") or []
    if not isinstance(checks, list):
        raise RuntimeError(f"Fresh {profile} self-check did not emit a checks list.")
    for check_index, check in enumerate(checks):
        if not isinstance(check, dict):
            raise RuntimeError(f"Fresh {profile} self-check emitted a non-object check at index {check_index}.")
        check_id = str(check.get("id") or "unknown")
        check_status = str(check.get("status") or "unknown")
        check_class = profile_state_class(check_status)
        check_state_counts[check_class] += 1
        raw_findings = check.get("findings") or []
        if not isinstance(raw_findings, list):
            raise RuntimeError(f"Fresh {profile} self-check check {check_id!r} did not emit a findings list.")
        check_states.append(
            {
                "check_index": check_index,
                "id": check_id,
                "returncode": check.get("returncode"),
                "status": check_status,
                "state_class": check_class,
                "finding_count": len(raw_findings),
                "summary": normalize_dynamic_values(check.get("summary") or {}, replacements),
            }
        )
        for finding_index, raw_finding in enumerate(raw_findings):
            if not isinstance(raw_finding, dict):
                raise RuntimeError(
                    f"Fresh {profile} self-check check {check_id!r} emitted a non-object finding at index {finding_index}."
                )
            normalized_finding = normalize_dynamic_values(raw_finding, replacements)
            state_class = profile_state_class(
                normalized_finding.get("status"),
                normalized_finding.get("severity"),
            )
            finding_state_counts[state_class] += 1
            occurrences.append(
                {
                    "identity": (
                        f"fresh-profile/{profile}/check[{check_index}]={check_id}"
                        f"/finding[{finding_index}]"
                    ),
                    "check_index": check_index,
                    "check_id": check_id,
                    "finding_index": finding_index,
                    "state_class": state_class,
                    "finding": normalized_finding,
                }
            )
    summary = normalize_dynamic_values(report.get("summary") or {}, replacements)
    declared_count = summary.get("total_findings")
    if not isinstance(declared_count, int) or declared_count != len(occurrences):
        raise RuntimeError(
            f"Fresh {profile} self-check occurrence mismatch: "
            f"summary={declared_count!r}, flattened={len(occurrences)}."
        )
    return {
        "schema": report.get("schema"),
        "profile": report.get("profile"),
        "status": report.get("status"),
        "returncode": returncode,
        "command": normalize_dynamic_values(command, replacements),
        "summary": summary,
        "check_count": len(check_states),
        "check_states": check_states,
        "check_state_counts": check_state_counts,
        "finding_count": len(occurrences),
        "finding_state_counts": finding_state_counts,
        "finding_occurrences": occurrences,
        "limitations": normalize_dynamic_values(report.get("limitations") or [], replacements),
    }


def run_fresh_self_check(preview_root: Path, profile: str) -> tuple[dict[str, Any], int, list[str]]:
    script = SCRIPT_DIR / "naos_self_check.py"
    output = preview_root / "naos" / "reports" / "self_check.json"
    command = [
        sys.executable,
        str(script),
        "--profile",
        profile,
        "--naos-root",
        "naos",
        "--json",
        "--output",
        str(output),
    ]
    temporary_environment_root = preview_root.parent / "isolated-environment"
    temporary_environment_root.mkdir(parents=True, exist_ok=True)
    environment = {
        key: os.environ[key]
        for key in ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT")
        if key in os.environ
    }
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "NAOS_FIXED_TIME": FRESH_PROFILE_FIXED_TIME,
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
            "TMPDIR": str(temporary_environment_root),
            "TEMP": str(temporary_environment_root),
            "TMP": str(temporary_environment_root),
            "ENGRAM_DATA_DIR": str(temporary_environment_root / "engram"),
            "GIT_CONFIG_GLOBAL": str(temporary_environment_root / "gitconfig"),
            "GIT_CONFIG_NOSYSTEM": "1",
        }
    )
    completed = subprocess.run(
        command,
        cwd=preview_root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=900,
    )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        diagnostic = (completed.stderr or completed.stdout or "No output").strip()
        raise RuntimeError(f"Fresh {profile} self-check did not emit valid JSON: {diagnostic}") from exc
    if not isinstance(report, dict) or report.get("schema") != "naos.self_check.v1":
        raise RuntimeError(f"Fresh {profile} self-check emitted an unexpected report schema.")
    return report, completed.returncode, command


def apply_fresh_self_check_isolation(preview_root: Path) -> dict[str, Any]:
    rules_path = preview_root / "naos" / "memory_provider_access_rules.yaml"
    if not rules_path.is_file():
        raise RuntimeError("Fresh scaffold is missing memory-provider access rules required for isolation.")
    rules = load_yaml_mapping(rules_path)
    prior_values = {
        key: rules.get(key)
        for key in FRESH_PROVIDER_METADATA_OVERRIDES
    }
    rules.update(FRESH_PROVIDER_METADATA_OVERRIDES)
    rules_path.write_text(
        yaml.safe_dump(rules, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return {
        "external_state": "excluded",
        "temporary_rules_overlay": True,
        "rules_path": relpath(rules_path, preview_root),
        "overrides": dict(FRESH_PROVIDER_METADATA_OVERRIDES),
        "prior_values": prior_values,
        "environment": {
            "inherited_scope": ["PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"],
            "naos_fixed_time": FRESH_PROFILE_FIXED_TIME,
            "python_hash_seed": "0",
            "temporary_provider_and_git_metadata_roots": True,
        },
        "normalizations": list(FRESH_DYNAMIC_NORMALIZATIONS),
        "not_claimed": [
            "provider availability",
            "MCP availability",
            "memory access",
            "user-configuration posture",
        ],
    }


def load_script_commands() -> dict[str, str]:
    cli_module = load_module_from_path("_naos_budget_cli", ROOT_DIR / "cli.py")
    commands = getattr(cli_module, "SCRIPT_COMMANDS", None)
    if not isinstance(commands, dict) or not all(
        isinstance(command, str) and isinstance(path, str)
        for command, path in commands.items()
    ):
        raise RuntimeError("cli.SCRIPT_COMMANDS is missing or invalid.")
    return dict(commands)


def global_cli_envelope(script_commands: dict[str, str]) -> dict[str, Any]:
    records = [
        {
            "command": command,
            "script": script,
            "resolvable_in_kit": (ROOT_DIR / script).is_file(),
        }
        for command, script in sorted(script_commands.items())
    ]
    built_ins = ["init", "add", "upgrade", "memory", "doctor", "first-run", "commands", "help"]
    return {
        "basis": "global installed CLI declarations; reported separately from profile-generated script reachability",
        "declared_script_command_count": len(records),
        "resolvable_script_command_count": sum(1 for item in records if item["resolvable_in_kit"]),
        "unresolved_script_commands": [item for item in records if not item["resolvable_in_kit"]],
        "script_commands": records,
        "built_in_commands": built_ins,
        "built_in_command_count": len(built_ins),
    }


def generated_files(preview_root: Path) -> list[str]:
    files: list[str] = []
    for path in preview_root.rglob("*"):
        if path.is_symlink():
            raise RuntimeError(f"Fresh scaffold unexpectedly contains a symlink: {path}")
        if path.is_file() and not ignored(path):
            files.append(path.relative_to(preview_root).as_posix())
    return sorted(set(files))


def normalize_generated_input_mtimes(
    preview_root: Path,
    files: list[str],
) -> dict[str, Any]:
    fixed = datetime.fromisoformat(
        FRESH_PROFILE_FIXED_TIME.replace("Z", "+00:00")
    )
    if fixed.tzinfo is None:
        raise RuntimeError("Fresh-profile fixed time must include a timezone.")
    fixed_ns = int(fixed.timestamp()) * 1_000_000_000
    for relative in files:
        path = preview_root / relative
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(
                f"Fresh-profile generated input cannot be normalized: {relative}"
            )
        os.utime(path, ns=(fixed_ns, fixed_ns), follow_symlinks=False)
    return {
        "scope": "every scaffold-declared regular file",
        "fixed_time": FRESH_PROFILE_FIXED_TIME,
        "normalized_file_count": len(files),
        "copied_source_mtimes_used": False,
    }


def generated_input_manifest(
    preview_root: Path,
    files: list[str],
) -> list[dict[str, str]]:
    return [
        {
            "path": relative,
            "sha256": path_hash(preview_root / relative),
        }
        for relative in files
    ]


def resident_context_metrics(
    preview_root: Path,
    rules: dict[str, Any],
) -> dict[str, Any]:
    collected = collect_family_files(preview_root, rules)
    memberships: dict[str, set[str]] = {}
    paths: dict[str, Path] = {}
    for family_id, family_paths in collected.items():
        for path in family_paths:
            relative = relpath(path, preview_root)
            paths[relative] = path
            memberships.setdefault(relative, set()).add(family_id)
    files: list[dict[str, Any]] = []
    for relative in sorted(paths):
        metrics = file_metrics(paths[relative], preview_root, rules)
        metrics["families"] = sorted(memberships[relative])
        files.append(metrics)
    return {
        "basis": "unique generated files matched by current AI-surface family patterns; overlapping families are deduplicated",
        "file_count": len(files),
        "chars": sum(int(item["chars"]) for item in files),
        "estimated_tokens": sum(int(item["estimated_tokens"]) for item in files),
        "files": files,
    }


def fresh_profile_measurement(
    *,
    profile: str,
    naos_init_module: Any,
    script_commands: dict[str, str],
    self_check_runner: Callable[[Path, str], tuple[dict[str, Any], int, list[str]]],
) -> dict[str, Any]:
    if profile not in PROFILE_ORDER:
        raise ValueError(f"Unsupported fresh profile: {profile}")
    with tempfile.TemporaryDirectory(prefix=f"naos-{profile}-footprint-") as temp_dir:
        temporary_root = Path(temp_dir).resolve()
        project_root = temporary_root / "fresh-project"
        preview_root = temporary_root / "fresh-preview"
        project_root.mkdir(parents=True)
        backend = "disabled" if profile == "quickstart" else "static_only"
        declared = naos_init_module.scaffold_files(
            project_path=project_root,
            tier=profile,
            archetype="custom",
            backend=backend,
            preview_dir=preview_root,
            signals=naos_init_module._empty_signals(),
            memory_choice="disabled",
        )
        if not isinstance(declared, list) or not all(isinstance(item, str) for item in declared):
            raise RuntimeError(f"Fresh {profile} scaffold returned an invalid generated-path manifest.")
        actual_files = generated_files(preview_root)
        declared_unique = sorted(set(declared))
        missing_declared = sorted(set(declared_unique) - set(actual_files))
        unlisted_actual = sorted(set(actual_files) - set(declared_unique))
        if missing_declared or unlisted_actual:
            raise RuntimeError(
                f"Fresh {profile} scaffold manifest differs from actual files: "
                f"missing={missing_declared}, unlisted={unlisted_actual}."
            )
        isolation = apply_fresh_self_check_isolation(preview_root)
        mtime_normalization = normalize_generated_input_mtimes(
            preview_root,
            actual_files,
        )
        content_manifest = generated_input_manifest(preview_root, actual_files)
        rules_path = preview_root / "naos" / "ai_surface_context_budget_rules.yaml"
        if not rules_path.is_file():
            raise RuntimeError(f"Fresh {profile} scaffold is missing its AI-surface budget rules seed.")
        rules, rules_meta = load_rules(rules_path)
        if rules_meta.get("source") != "rules_file":
            raise RuntimeError(f"Fresh {profile} scaffold did not load its generated rules seed.")
        resident = resident_context_metrics(preview_root, rules)
        reachable_commands = [
            {"command": command, "script": script}
            for command, script in sorted(script_commands.items())
            if (preview_root / script).is_file()
        ]
        report, returncode, command = self_check_runner(preview_root, profile)
        replacements = [
            (str(Path(sys.executable).resolve()), "<python>"),
            (str(Path(sys.executable)), "<python>"),
            (str(Path.home().resolve()), "<user-home>"),
            (str(preview_root.resolve()), "<fresh-preview>"),
            (str(project_root.resolve()), "<fresh-project>"),
            (str(temporary_root), "<temporary-root>"),
            (str(ROOT_DIR.resolve()), "<naos-kit-root>"),
        ]
        self_check = flatten_self_check(
            report,
            profile=profile,
            replacements=replacements,
            returncode=returncode,
            command=command,
        )
        self_check["isolation"] = isolation
        metrics = {
            "fresh_project_finding_count": int(self_check["finding_count"]),
            "resident_context_tokens": int(resident["estimated_tokens"]),
            "generated_file_count": len(actual_files),
            "cli_command_count": len(reachable_commands),
        }
        duplicate_declarations = sorted(
            path for path in declared_unique if declared.count(path) > 1
        )
        return {
            "profile": profile,
            "scaffold_contract": {
                "project_name": "fresh-project",
                "archetype": "custom",
                "backend": backend,
                "memory": "disabled",
                "signals": "fixed_empty_greenfield",
                "isolated_temporary_root": True,
            },
            "generated_surface": {
                "declared_entry_count": len(declared),
                "declared_unique_count": len(declared_unique),
                "actual_unique_file_count": len(actual_files),
                "duplicate_declarations": duplicate_declarations,
                "files": actual_files,
                "provenance_phase": FRESH_GENERATED_INPUT_PHASE,
                "content_manifest": content_manifest,
                "content_set_sha256": canonical_sha256(content_manifest),
                "mtime_normalization": mtime_normalization,
            },
            "resident_context": resident,
            "cli_commands": {
                "basis": "cli.SCRIPT_COMMANDS entries whose mapped script exists in the generated profile",
                "count": len(reachable_commands),
                "commands": reachable_commands,
            },
            "self_check": self_check,
            "metrics": metrics,
        }


def profile_threshold_contract(
    rules: dict[str, Any],
    profiles: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    configured = rules.get("profile_footprint") or {}
    thresholds = configured.get("thresholds") or {}
    approval = configured.get("approval") or {}
    findings: list[dict[str, Any]] = []
    configured_status = "approved" if approval.get("status") == "approved" else "unapproved"

    def worsen_contract_status(candidate: str) -> None:
        nonlocal configured_status
        rank = {"approved": 0, "unapproved": 1, "invalid": 2}
        if rank[candidate] > rank[configured_status]:
            configured_status = candidate

    for profile_report in profiles:
        profile = str(profile_report["profile"])
        profile_rules = thresholds.get(profile) if isinstance(thresholds, dict) else None
        evaluations: dict[str, Any] = {}
        for metric in PROFILE_METRICS:
            current = int(profile_report["metrics"][metric])
            metric_rules = profile_rules.get(metric) if isinstance(profile_rules, dict) else None
            if not isinstance(metric_rules, dict):
                evaluations[metric] = {
                    "current": current,
                    "status": "unapproved",
                    "baseline": None,
                    "warn_above": None,
                    "stop_above": None,
                }
                findings.append(
                    {
                        "id": "PROFILE_FOOTPRINT_THRESHOLD_MISSING",
                        "profile": profile,
                        "metric": metric,
                        "status": "unapproved",
                        "message": f"No approved {profile} threshold exists for {metric}.",
                    }
                )
                worsen_contract_status("unapproved")
                continue
            values = {
                key: metric_rules.get(key)
                for key in ("baseline", "warn_above", "stop_above")
            }
            if not all(type(value) is int and value >= 0 for value in values.values()):
                evaluation_status = "invalid"
            elif not (
                int(values["warn_above"]) >= int(values["baseline"])
                and int(values["stop_above"]) > int(values["warn_above"])
            ):
                evaluation_status = "invalid"
            elif current > int(values["stop_above"]):
                evaluation_status = "stop"
            elif current > int(values["warn_above"]):
                evaluation_status = "warn"
            elif current < int(values["baseline"]):
                evaluation_status = "below_baseline"
            else:
                evaluation_status = "within_baseline"
            evaluation = {
                "current": current,
                "status": evaluation_status,
                **values,
                "basis": metric_rules.get("basis"),
                "falsifier": metric_rules.get("falsifier"),
            }
            if type(values["baseline"]) is int:
                evaluation["delta"] = current - values["baseline"]
            evaluations[metric] = evaluation
            if evaluation_status in {"invalid", "stop", "warn"}:
                findings.append(
                    {
                        "id": "PROFILE_FOOTPRINT_THRESHOLD_RESULT",
                        "profile": profile,
                        "metric": metric,
                        "status": evaluation_status,
                        "message": (
                            f"{profile} {metric} is {current}; threshold result is "
                            f"{evaluation_status}."
                        ),
                    }
                )
            if evaluation_status == "invalid":
                worsen_contract_status("invalid")
        profile_report["threshold_evaluations"] = evaluations
    return {
        "status": configured_status,
        "controlled_command": configured.get("controlled_command"),
        "baseline_ref": configured.get("baseline_ref"),
        "default_display_max_rows": configured.get("default_display_max_rows"),
        "approval": approval,
        "methodology": configured.get("methodology"),
        "candidate_freeze": configured.get("candidate_freeze"),
        "auto_tuning_performed": False,
        "human_review_required_before_change": True,
    }, findings


def profile_source_inputs(rules_path: Path) -> list[dict[str, str]]:
    candidates = [
        ROOT_DIR / "naos_init.py",
        ROOT_DIR / "naos_profile_rules.py",
        ROOT_DIR / "cli.py",
        Path(__file__).resolve(),
        SCRIPT_DIR / "naos_policy.py",
        SCRIPT_DIR / "naos_self_check.py",
        SCRIPT_DIR / "naos_validate_claims.py",
        SCRIPT_DIR / "naos_control_plane_review.py",
        SCRIPT_DIR / "naos_capability_maturity.py",
        SCRIPT_DIR / "naos_evidence_attestation.py",
        SCRIPT_DIR / "naos_function_index_health.py",
        SCRIPT_DIR / "naos_grader_assessment.py",
        SCRIPT_DIR / "naos_systemic_impact.py",
        SCRIPT_DIR / "naos_task_context_pack.py",
        SCRIPT_DIR / "naos_memory_use_policy.py",
        SCRIPT_DIR / "naos_learning_loop_review.py",
        SCRIPT_DIR / "naos_session_lifecycle.py",
        SCRIPT_DIR / "naos_task_claims.py",
        SCRIPT_DIR / "naos_behavioral_governance_readiness.py",
        rules_path,
        ROOT_DIR / "configs" / "profile_generated_surface_contract.json",
        ROOT_DIR / "configs" / "profile_rules_source.yaml",
        ROOT_DIR / "policies" / "default_policy.yaml",
        ROOT_DIR / "templates" / "structural-seeds" / "naos" / "memory_provider_access_rules.yaml",
        ROOT_DIR / "templates" / "structural-seeds" / "naos" / "systemic_impact_rules.yaml",
    ]
    inputs: list[dict[str, str]] = []
    for path in candidates:
        if not path.is_file():
            raise FileNotFoundError(f"Required profile-baseline input is missing: {path}")
        inputs.append(
            {
                "path": relpath(path, ROOT_DIR),
                "sha256": path_hash(path),
            }
        )
    return inputs


def build_fresh_profiles_report(
    *,
    rules_path: Path,
    self_check_runner: Callable[
        [Path, str],
        tuple[dict[str, Any], int, list[str]],
    ] = run_fresh_self_check,
    naos_init_module: Any | None = None,
    script_commands: dict[str, str] | None = None,
) -> dict[str, Any]:
    rules, rules_meta = load_rules(rules_path)
    if rules_meta.get("source") != "rules_file":
        raise RuntimeError("Fresh-profile measurement requires an explicit current rules file.")
    init_module = naos_init_module or load_module_from_path(
        "_naos_budget_init",
        ROOT_DIR / "naos_init.py",
    )
    commands = script_commands or load_script_commands()
    profiles = [
        fresh_profile_measurement(
            profile=profile,
            naos_init_module=init_module,
            script_commands=commands,
            self_check_runner=self_check_runner,
        )
        for profile in PROFILE_ORDER
    ]
    threshold_contract, threshold_findings = profile_threshold_contract(rules, profiles)
    evaluation_statuses = [
        evaluation["status"]
        for profile in profiles
        for evaluation in profile["threshold_evaluations"].values()
    ]
    if "invalid" in evaluation_statuses or "stop" in evaluation_statuses:
        status = "stop"
    elif threshold_contract["status"] != "approved" or "unapproved" in evaluation_statuses:
        status = "unapproved"
    elif "warn" in evaluation_statuses:
        status = "warning"
    else:
        status = "pass"
    inputs = profile_source_inputs(rules_path)
    report: dict[str, Any] = {
        "schema": PROFILE_BASELINE_SCHEMA,
        "generated_at": FRESH_PROFILE_FIXED_TIME,
        "status": status,
        "deterministic": True,
        "isolated_temp_scaffolds": True,
        "complete_json": True,
        "legacy_singleton_unchanged": True,
        "profile_order": list(PROFILE_ORDER),
        "source": {
            "content_addressed_before_measurement": True,
            "inputs": inputs,
            "input_set_sha256": canonical_sha256(inputs),
            "generated_input_provenance": {
                "version": "1",
                "coverage": "every scaffold-declared regular file",
                "phase": FRESH_GENERATED_INPUT_PHASE,
                "content_addressed": True,
                "mtime_independent": True,
            },
            "rules": {
                "path": relpath(rules_path, ROOT_DIR),
                "sha256": path_hash(rules_path),
            },
        },
        "command_contract": {
            "controlled_command": "naos ai-surface-budget --fresh-profiles --json",
            "complete_human_command": "naos ai-surface-budget --fresh-profiles --all",
            "default_writes_report": False,
            "explicit_output_required_to_persist": True,
            "fixed_time": FRESH_PROFILE_FIXED_TIME,
            "default_display_max_rows": DEFAULT_PROFILE_DISPLAY_MAX_ROWS,
        },
        "global_cli_envelope": global_cli_envelope(commands),
        "profiles": profiles,
        "threshold_contract": threshold_contract,
        "threshold_findings": threshold_findings,
        "summary": {
            "profiles": len(profiles),
            "finding_occurrences": sum(
                int(profile["self_check"]["finding_count"])
                for profile in profiles
            ),
            "generated_files": sum(
                int(profile["metrics"]["generated_file_count"])
                for profile in profiles
            ),
            "resident_context_tokens": sum(
                int(profile["metrics"]["resident_context_tokens"])
                for profile in profiles
            ),
            "reachable_cli_commands": sum(
                int(profile["metrics"]["cli_command_count"])
                for profile in profiles
            ),
            "threshold_findings": len(threshold_findings),
        },
        "limitations": [
            "Fresh-project finding counts are complete self-check occurrences, not unique finding IDs.",
            "Resident context uses the configured deterministic chars-per-token estimate over unique matching generated files.",
            "Profile CLI command count covers generated-script-reachable SCRIPT_COMMANDS entries; the installed global envelope is separate.",
            "Threshold changes require reviewed source updates; this command never auto-tunes or auto-approves them.",
        ],
        "not_claimed": [
            "candidate approval",
            "pilot closure",
            "runtime behavior",
            "publication approval",
            "automatic threshold tuning",
            "automatic baseline approval",
        ],
        "stable_payload_sha256": "",
    }
    stable_payload = {
        key: value
        for key, value in report.items()
        if key not in {"generated_at", "stable_payload_sha256"}
    }
    report["stable_payload_sha256"] = canonical_sha256(stable_payload)
    validate_fresh_profiles_report(report)
    return report


def validate_fresh_profiles_report(report: dict[str, Any]) -> None:
    if report.get("schema") != PROFILE_BASELINE_SCHEMA:
        raise RuntimeError("Fresh-profile report schema is invalid.")
    profiles = report.get("profiles") or []
    if [profile.get("profile") for profile in profiles] != list(PROFILE_ORDER):
        raise RuntimeError("Fresh-profile report order is not the controlled four-profile order.")
    source = report.get("source") or {}
    generated_provenance = source.get("generated_input_provenance")
    if source.get("content_addressed_before_measurement") is not True:
        raise RuntimeError("Fresh-profile source must be content-addressed before measurement.")
    stable_payload = {
        key: value
        for key, value in report.items()
        if key not in {"generated_at", "stable_payload_sha256"}
    }
    stable_payload_sha256 = canonical_sha256(stable_payload)
    if generated_provenance != {
        "version": "1",
        "coverage": "every scaffold-declared regular file",
        "phase": FRESH_GENERATED_INPUT_PHASE,
        "content_addressed": True,
        "mtime_independent": True,
    }:
        raise RuntimeError("Fresh-profile generated-input provenance contract is invalid.")
    all_occurrence_identities: list[str] = []
    for profile in profiles:
        profile_name = str(profile["profile"])
        generated = profile["generated_surface"]
        files = generated["files"]
        if len(files) != len(set(files)) or len(files) != generated["actual_unique_file_count"]:
            raise RuntimeError(f"Fresh {profile_name} generated-file accounting is inconsistent.")
        if generated["declared_unique_count"] != len(set(files)):
            raise RuntimeError(f"Fresh {profile_name} declared and actual unique file counts differ.")
        manifest = generated.get("content_manifest")
        if not isinstance(manifest, list):
            raise RuntimeError(
                f"Fresh {profile_name} generated-input content manifest is missing."
            )
        manifest_paths = [str(item.get("path")) for item in manifest]
        if manifest_paths != files or len(manifest_paths) != len(set(manifest_paths)):
            raise RuntimeError(
                f"Fresh {profile_name} generated-input manifest path coverage is inconsistent."
            )
        if generated.get("content_set_sha256") != canonical_sha256(manifest):
            raise RuntimeError(
                f"Fresh {profile_name} generated-input manifest digest is inconsistent."
            )
        if generated.get("provenance_phase") != FRESH_GENERATED_INPUT_PHASE:
            raise RuntimeError(
                f"Fresh {profile_name} generated-input provenance phase is invalid."
            )
        normalization = generated.get("mtime_normalization") or {}
        if normalization != {
            "scope": "every scaffold-declared regular file",
            "fixed_time": FRESH_PROFILE_FIXED_TIME,
            "normalized_file_count": len(files),
            "copied_source_mtimes_used": False,
        }:
            raise RuntimeError(
                f"Fresh {profile_name} generated-input mtime normalization is inconsistent."
            )
        resident = profile["resident_context"]
        resident_files = resident["files"]
        if resident["file_count"] != len(resident_files):
            raise RuntimeError(f"Fresh {profile_name} resident-file accounting is inconsistent.")
        if resident["chars"] != sum(int(item["chars"]) for item in resident_files):
            raise RuntimeError(f"Fresh {profile_name} resident-character accounting is inconsistent.")
        if resident["estimated_tokens"] != sum(
            int(item["estimated_tokens"])
            for item in resident_files
        ):
            raise RuntimeError(f"Fresh {profile_name} resident-token accounting is inconsistent.")
        cli_commands = profile["cli_commands"]
        if cli_commands["count"] != len(cli_commands["commands"]):
            raise RuntimeError(f"Fresh {profile_name} CLI-command accounting is inconsistent.")
        self_check = profile["self_check"]
        occurrences = self_check["finding_occurrences"]
        identities = [str(item["identity"]) for item in occurrences]
        if self_check["finding_count"] != len(occurrences) or len(identities) != len(set(identities)):
            raise RuntimeError(f"Fresh {profile_name} finding-occurrence accounting is inconsistent.")
        if sum(int(value) for value in self_check["finding_state_counts"].values()) != len(occurrences):
            raise RuntimeError(f"Fresh {profile_name} finding-state accounting is inconsistent.")
        if self_check["check_count"] != len(self_check["check_states"]):
            raise RuntimeError(f"Fresh {profile_name} check accounting is inconsistent.")
        if sum(int(value) for value in self_check["check_state_counts"].values()) != self_check["check_count"]:
            raise RuntimeError(f"Fresh {profile_name} check-state accounting is inconsistent.")
        if set(profile["threshold_evaluations"]) != set(PROFILE_METRICS):
            raise RuntimeError(f"Fresh {profile_name} threshold evaluation set is incomplete.")
        metrics = profile["metrics"]
        expected_metrics = {
            "fresh_project_finding_count": self_check["finding_count"],
            "resident_context_tokens": resident["estimated_tokens"],
            "generated_file_count": generated["actual_unique_file_count"],
            "cli_command_count": cli_commands["count"],
        }
        if metrics != expected_metrics:
            raise RuntimeError(f"Fresh {profile_name} metric accounting is inconsistent.")
        all_occurrence_identities.extend(identities)
    if len(all_occurrence_identities) != len(set(all_occurrence_identities)):
        raise RuntimeError("Fresh-profile finding identities are not globally unique.")

    global_cli = report["global_cli_envelope"]
    global_commands = global_cli["script_commands"]
    if global_cli["declared_script_command_count"] != len(global_commands):
        raise RuntimeError("Global CLI declaration accounting is inconsistent.")
    resolvable = [item for item in global_commands if item.get("resolvable_in_kit")]
    unresolved = [item for item in global_commands if not item.get("resolvable_in_kit")]
    if global_cli["resolvable_script_command_count"] != len(resolvable):
        raise RuntimeError("Global resolvable CLI-command accounting is inconsistent.")
    if global_cli["unresolved_script_commands"] != unresolved:
        raise RuntimeError("Global unresolved CLI-command accounting is inconsistent.")
    if global_cli["built_in_command_count"] != len(global_cli["built_in_commands"]):
        raise RuntimeError("Global built-in CLI-command accounting is inconsistent.")

    summary = report["summary"]
    expected_summary = {
        "profiles": len(profiles),
        "finding_occurrences": sum(int(profile["metrics"]["fresh_project_finding_count"]) for profile in profiles),
        "generated_files": sum(int(profile["metrics"]["generated_file_count"]) for profile in profiles),
        "resident_context_tokens": sum(int(profile["metrics"]["resident_context_tokens"]) for profile in profiles),
        "reachable_cli_commands": sum(int(profile["metrics"]["cli_command_count"]) for profile in profiles),
        "threshold_findings": len(report["threshold_findings"]),
    }
    if summary != expected_summary:
        raise RuntimeError("Fresh-profile aggregate summary accounting is inconsistent.")
    source = report["source"]
    if source["input_set_sha256"] != canonical_sha256(source["inputs"]):
        raise RuntimeError("Fresh-profile source input-set digest is inconsistent.")
    if report.get("stable_payload_sha256") != stable_payload_sha256:
        raise RuntimeError("Fresh-profile stable payload digest is inconsistent.")


def profile_occurrence_sort_key(occurrence: dict[str, Any]) -> tuple[int, str]:
    finding_data = occurrence.get("finding") or {}
    severity = str(finding_data.get("severity") or "unknown")
    rank = {"blocking": 0, "required": 1, "warning": 2, "error": 3}.get(severity, 4)
    return rank, str(occurrence.get("identity") or "")


def profile_occurrence_text(occurrence: dict[str, Any], *, complete: bool) -> str:
    finding_data = occurrence.get("finding") or {}
    prefix = (
        f"[{occurrence.get('identity')}] "
        f"{finding_data.get('id') or 'unknown-id'} · "
        f"{finding_data.get('severity') or 'unknown'}/"
        f"{finding_data.get('status') or 'unknown'} · "
        f"state={occurrence.get('state_class')}"
    )
    if complete:
        return f"{prefix} — {json.dumps(finding_data, sort_keys=True, ensure_ascii=False)}"
    message = " ".join(str(finding_data.get("message") or "").split())
    return f"{prefix} — {message}"


def profile_footprint_presentation(
    report: dict[str, Any],
    *,
    show_all: bool,
    max_rows: int = DEFAULT_PROFILE_DISPLAY_MAX_ROWS,
) -> dict[str, Any]:
    if max_rows < 1 or max_rows > DEFAULT_PROFILE_DISPLAY_MAX_ROWS:
        raise ValueError(
            f"Fresh-profile default display max_rows must be between 1 and {DEFAULT_PROFILE_DISPLAY_MAX_ROWS}."
        )
    occurrences = [
        occurrence
        for profile in report.get("profiles") or []
        for occurrence in (profile.get("self_check") or {}).get("finding_occurrences") or []
    ]
    buckets = {state: [] for state in PROFILE_STATE_CLASSES}
    for occurrence in occurrences:
        state = str(occurrence.get("state_class") or "unknown")
        buckets[state if state in buckets else "unknown"].append(occurrence)
    counts = {state: len(buckets[state]) for state in PROFILE_STATE_CLASSES}
    if show_all:
        rows = [
            {
                "kind": "finding",
                "state_class": occurrence.get("state_class"),
                "text": profile_occurrence_text(occurrence, complete=True),
            }
            for occurrence in occurrences
        ]
    else:
        non_actionable_states = [
            state
            for state in PROFILE_STATE_CLASSES
            if state != "actionable" and buckets[state]
        ]
        actionable = sorted(buckets["actionable"], key=profile_occurrence_sort_key)
        available = max_rows - len(non_actionable_states)
        needs_actionable_rollup = len(actionable) > max(available, 0)
        detail_limit = max(available - (1 if needs_actionable_rollup else 0), 0)
        displayed = actionable[:detail_limit]
        rows = [
            {
                "kind": "finding",
                "state_class": "actionable",
                "text": profile_occurrence_text(occurrence, complete=False),
            }
            for occurrence in displayed
        ]
        remaining_actionable = actionable[len(displayed) :]
        if remaining_actionable:
            rows.append(
                {
                    "kind": "rollup",
                    "state_class": "actionable",
                    "count": len(remaining_actionable),
                    "text": (
                        f"{len(remaining_actionable)} additional actionable finding occurrences; "
                        "run `naos ai-surface-budget --fresh-profiles --all`."
                    ),
                }
            )
        for state in non_actionable_states:
            profile_counts: dict[str, int] = {}
            for occurrence in buckets[state]:
                profile = str(occurrence.get("identity") or "").split("/")[1]
                profile_counts[profile] = profile_counts.get(profile, 0) + 1
            detail = ", ".join(
                f"{profile}={count}" for profile, count in sorted(profile_counts.items())
            )
            rows.append(
                {
                    "kind": "rollup",
                    "state_class": state,
                    "count": len(buckets[state]),
                    "text": (
                        f"{len(buckets[state])} {state} finding occurrences ({detail}); "
                        "run `naos ai-surface-budget --fresh-profiles --all`."
                    ),
                }
            )
    return {
        "show_all": show_all,
        "occurrences": len(occurrences),
        "counts": counts,
        "rows": rows,
        "displayed_rows": len(rows),
        "default_row_cap": max_rows,
    }


def profile_footprint_lines(report: dict[str, Any], *, show_all: bool) -> list[str]:
    presentation = profile_footprint_presentation(report, show_all=show_all)
    lines = [
        f"NAOS fresh-profile footprint: {report['status']} "
        f"({report['summary']['finding_occurrences']} complete finding occurrences)"
    ]
    for profile in report.get("profiles") or []:
        metrics = profile["metrics"]
        state_counts = profile["self_check"]["finding_state_counts"]
        lines.append(
            f"- {profile['profile']}: findings={metrics['fresh_project_finding_count']}, "
            f"resident_tokens={metrics['resident_context_tokens']}, "
            f"generated_files={metrics['generated_file_count']}, "
            f"cli_commands={metrics['cli_command_count']}; states="
            + ",".join(f"{state}:{state_counts[state]}" for state in PROFILE_STATE_CLASSES)
        )
    lines.append(
        f"Finding occurrence view: {presentation['displayed_rows']} rows "
        f"(complete={presentation['occurrences']}, --all={str(show_all).lower()})"
    )
    lines.extend(f"- {row['text']}" for row in presentation["rows"])
    return lines


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate deterministic NAOS AI-surface context budget and health.")
    parser.add_argument("--profile")
    parser.add_argument(
        "--fresh-profiles",
        action="store_true",
        help=(
            "Measure isolated fresh Quickstart, Lite, Standard, and Assured "
            "scaffolds in one run without changing the legacy singleton report."
        ),
    )
    parser.add_argument("--naos-root")
    parser.add_argument("--policy")
    parser.add_argument("--rules", help="AI-surface context-budget rules YAML. Defaults to NAOS_ROOT rules or kit template.")
    parser.add_argument("--baseline", help="Approved AI-surface health baseline JSON. Defaults to NAOS_ROOT/baselines/ai_surface_health_baseline.json.")
    parser.add_argument("--no-default-baseline", action="store_true", help="Do not look for the default optional baseline.")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--all",
        action="store_true",
        help="Show every fresh-profile finding occurrence; JSON is always complete.",
    )
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.fresh_profiles:
        incompatible = []
        if args.profile:
            incompatible.append("--profile")
        if args.naos_root:
            incompatible.append("--naos-root")
        if args.policy:
            incompatible.append("--policy")
        if args.baseline:
            incompatible.append("--baseline")
        if args.no_default_baseline:
            incompatible.append("--no-default-baseline")
        if incompatible:
            parser.error(
                "--fresh-profiles uses the fixed source-kit scaffold contract and cannot be combined with "
                + ", ".join(incompatible)
            )
        rules_path = Path(args.rules) if args.rules else DEFAULT_RULES_PATH
        try:
            report = build_fresh_profiles_report(rules_path=rules_path)
        except (FileNotFoundError, ImportError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            print(f"NAOS fresh-profile footprint error: {exc}", file=sys.stderr)
            return 2
        if args.output:
            write_report(Path(args.output), report)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            for line in profile_footprint_lines(report, show_all=args.all):
                print(line)
        if report["status"] in {"stop", "unapproved"}:
            return 2
        if report["status"] == "warning" and args.strict:
            return 1
        return 0
    root = Path.cwd()
    configured_naos_root = args.naos_root or os.environ.get("NAOS_ROOT")
    policy = load_policy(args.policy, configured_naos_root, root)
    naos_root = configured_naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    rules_path = Path(args.rules) if args.rules else default_rules_path(root, naos_root, policy)
    rules_preview, _rules_meta = load_rules(rules_path)
    if args.baseline:
        baseline_path: Path | None = Path(args.baseline)
    elif args.no_default_baseline:
        baseline_path = None
    else:
        baseline_path = default_baseline_path(root, naos_root, rules_preview, policy)
    report = build_report(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        rules_path=rules_path,
        baseline_path=baseline_path,
    )
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "ai_surface_context_budget_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        destination = str(output) if output else "(not written in kit source tree)"
        print(
            "NAOS AI-surface health: "
            f"{report['ai_surface_health_posture']} "
            f"({report['summary']['total_estimated_tokens']} estimated tokens, "
            f"{report['summary']['total_findings']} findings) -> {destination}"
        )
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
