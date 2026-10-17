#!/usr/bin/env python3
"""Evaluate deterministic NAOS AI-surface health, context budget, and baseline drift."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import stat
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
PROFILE_BASELINE_SCHEMA = "naos.ai_surface_profile_footprint_baseline.v1"  # Historical artifact contract.
PROFILE_REPORT_SCHEMA = "naos.ai_surface_profile_footprint_baseline.v2"
PROFILE_PROJECTION_VERSION = "classifier_scan_hash_links.v1"
PROFILE_DETERMINISM_SCOPE = "complete_measurement_projection"
PROFILE_RAW_HASH_AUTHORITY = "classifier_emitted_historical_scan_time_hash_declaration"
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
FRESH_AUDIT_REFERENCE_MAX_FILES = 1000
FRESH_AUDIT_REFERENCE_MAX_ENTRIES = 50000
FRESH_DYNAMIC_NORMALIZATIONS = [
    "temporary roots",
    "Python executable",
    "user-home paths",
    "generated session UUIDs",
    "generated audit event IDs (new IDs only in exact verified audit-finding reference slots)",
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
            "id": "claude_code_plugin_base",
            "label": "Claude Code plugin governance loadout",
            "profiles": ["lite", "standard", "assured"],
            "files": [
                {"path": "plugins/naos-governance-claude-code/README.md", "optional": True},
                {"path": "plugins/naos-governance-claude-code/skills/naos-adoption-readiness/SKILL.md", "optional": True},
                {"path": "plugins/naos-governance-claude-code/skills/naos-forensic-review/SKILL.md", "optional": True},
                {"path": "plugins/naos-governance-claude-code/skills/naos-governed-learning/SKILL.md", "optional": True},
                {"path": "plugins/naos-governance-claude-code/skills/naos-adapter-coexistence/SKILL.md", "optional": True},
            ],
            "warn_tokens": 8000,
            "block_tokens": 12000,
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
                {"path": ".github/NAOS_AGENTS.md", "optional": True},
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
                {"path": ".github/NAOS_AGENTS.md", "optional": True},
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
            "phrases": ["context pressure", "checkpoint", "compact"],
        },
        {
            "id": "caller_context_signal",
            "label": "Caller-supplied hook context signal",
            "profiles": ["standard", "assured"],
            "phrases": ["NAOS_CONTEXT_REMAINING_PCT"],
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
    provenance = {
        "evidence_classification": "confirmed",
        "classification_scope": "configured_character_estimate_threshold",
        "classification_reason": (
            "Compares a deterministic character-based token estimate with the selected "
            "configured threshold; does not measure provider tokenization or model behavior."
        ),
        "source_path": str(Path(__file__).resolve()),
    }
    if block_tokens and tokens > block_tokens:
        item = finding(
            finding_id=f"AI_SURFACE_{scope.upper()}_BUDGET_EXCEEDED",
            severity=condition_severity(profile, policy, "blocking"),
            status=f"{scope}_budget_exceeded",
            message=f"{item_label} is estimated at {tokens} tokens, above the configured block threshold {block_tokens}.",
            source=source,
        )
    elif warn_tokens and tokens > warn_tokens:
        item = finding(
            finding_id=f"AI_SURFACE_{scope.upper()}_BUDGET_WARNING",
            severity=condition_severity(profile, policy, "warning"),
            status=f"{scope}_budget_warning",
            message=f"{item_label} is estimated at {tokens} tokens, above the configured warning threshold {warn_tokens}.",
            source=source,
        )
    else:
        return []
    item.update(provenance)
    return [item]


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
            "measurement_basis": "configured_synthetic_bundle",
            "observed_host_loading": False,
            "artifact_presence": "present" if files else "empty",
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
        profiles = anchor.get("profiles", [])
        if "profiles" in anchor and (
            not isinstance(profiles, list) or not profiles
            or any(not isinstance(item, str) or item not in PROFILE_ORDER for item in profiles)
            or len(set(profiles)) != len(profiles)
        ):
            raise ValueError(f"Anchor {anchor_id} profiles must be unique supported profile names.")
        applicable = not profiles or profile in profiles
        phrases = [str(item) for item in anchor.get("phrases") or []]
        matched = [phrase for phrase in phrases if phrase.lower() in text]
        missing = [phrase for phrase in phrases if phrase.lower() not in text]
        present = bool(phrases) and not missing
        anchors.append(
            {
                "id": anchor_id,
                "label": anchor.get("label") or anchor_id,
                "profiles": profiles,
                "applicable_to_profile": applicable,
                "present": present,
                "matched_phrases": matched,
                "missing_phrases": missing,
                "required_phrases": phrases,
            }
        )
        if applicable and not present:
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
        "anchors": {item["id"]: bool(item["present"]) for item in anchors if item.get("applicable_to_profile", True)},
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
        "anchors": {item.get("id"): bool(item.get("present")) for item in data.get("anchors") or [] if isinstance(item, dict) and item.get("applicable_to_profile", True)},
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
            item = finding(
                finding_id="AI_SURFACE_BASELINE_MISSING",
                severity=str((rules.get("baseline") or {}).get("baseline_missing_severity") or "advisory"),
                status="missing_baseline",
                message="No AI-surface health baseline is present at the selected path; posture is still measured from current source artifacts.",
                source=str(baseline_meta.get("path")),
            )
            item.update(
                evidence_classification="confirmed",
                classification_scope="selected_baseline_path_absence",
                classification_reason=(
                    "The selected baseline path was absent at execution time; this does not "
                    "verify approval or establish absence of a baseline elsewhere."
                ),
                source_path=str(Path(__file__).resolve()),
            )
            findings.append(item)
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


def _build_guarded_project_context(
    root: Path, rules: dict[str, Any], *, candidate_host: str | None = None,
) -> dict[str, Any]:
    """Estimate a bounded project-local subset in a stable tree, not host loading."""
    root = root.resolve()
    limits = {"max_files": 64, "max_import_depth": 5, "max_file_bytes": 1048576,
              "max_discovery_entries": 256, "max_directory_depth": 8}
    unresolved: list[dict[str, str]] = []
    startup: dict[str, dict[str, Any]] = {}
    imports: list[dict[str, str]] = []
    conditional: list[dict[str, Any]] = []
    on_demand: list[dict[str, Any]] = []
    active: set[str] = set()
    cache: dict[str, tuple[str, dict[str, Any]] | None] = {}
    discovery_count = 0

    def lexical_identifier(path: Path) -> str:
        relative = path.relative_to(root)
        if ".." in relative.parts:
            raise ValueError("outside_project")
        return relative.as_posix()

    def reject(path: Path, reason: str) -> None:
        try:
            relative = lexical_identifier(path)
        except ValueError:
            relative = str(path)
        unresolved.append({"path": relative, "reason": reason})

    def guarded_stat(path: Path) -> os.stat_result:
        relative = Path(lexical_identifier(path))
        current = root
        observed = root.lstat()
        for part in relative.parts:
            current /= part
            observed = current.lstat()
            if stat.S_ISLNK(observed.st_mode):
                raise ValueError("symlink_path")
        if not path.resolve().is_relative_to(root):
            raise ValueError("outside_project")
        return observed

    def identity(observed: os.stat_result) -> tuple[int, ...]:
        return (observed.st_dev, observed.st_ino, observed.st_mode, observed.st_size,
                observed.st_mtime_ns, observed.st_ctime_ns)

    def same_read_identity(left: os.stat_result, right: os.stat_result) -> bool:
        # Windows can expose different ctime meanings through lstat and fstat.
        fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")
        if any(getattr(left, field) != getattr(right, field) for field in fields):
            return False
        left_birth = getattr(left, "st_birthtime_ns", None)
        right_birth = getattr(right, "st_birthtime_ns", None)
        return left_birth is None or right_birth is None or left_birth == right_birth

    def read(path: Path, relationship: str) -> tuple[str, dict[str, Any]] | None:
        try:
            relative = lexical_identifier(path)
            before = guarded_stat(path)
            if relative in cache:
                loaded = cache[relative]
                return (loaded[0], {**loaded[1], "relationship": relationship}) if loaded else None
            if len(cache) >= limits["max_files"]:
                reject(path, "file_limit")
                return None
            cache[relative] = None
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("not_regular_file")
            with path.open("rb") as stream:
                opened = os.fstat(stream.fileno())
                data = stream.read(limits["max_file_bytes"] + 1)
                consumed = os.fstat(stream.fileno())
            after = guarded_stat(path)
            if len(data) > limits["max_file_bytes"]:
                raise ValueError("byte_limit")
            if (identity(before) != identity(after)
                    or identity(opened) != identity(consumed)
                    or not same_read_identity(before, opened)
                    or not same_read_identity(after, consumed)):
                raise ValueError("changed_during_read")
            if len(data) != before.st_size:
                raise ValueError("size_mismatch")
            # Match legacy universal-newline character estimation using the same bytes.
            text = data.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
            metrics = {"path": relative, "lines": len(text.splitlines()), "chars": len(text),
                       "estimated_tokens": estimate_tokens(len(text), rules),
                       "sha256": hashlib.sha256(data).hexdigest(), "relationship": relationship}
            cache[relative] = (text, metrics)
            return text, metrics
        except FileNotFoundError:
            reject(path, "missing_file")
        except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
            reject(path, str(exc))
        return None

    def visit(path: Path, relationship: str, depth: int) -> None:
        try:
            relative = lexical_identifier(path)
            guarded_stat(path)
        except FileNotFoundError:
            reject(path, "missing_file")
            return
        except (OSError, ValueError, RuntimeError) as exc:
            reject(path, str(exc))
            return
        if relative in active:
            reject(path, "import_cycle")
            return
        if relative in startup:
            return
        if depth > limits["max_import_depth"]:
            reject(path, "depth_limit")
            return
        loaded = read(path, relationship)
        if loaded is None:
            return
        text, metrics = loaded
        startup[relative] = metrics
        active.add(relative)
        fenced = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("```", "~~~")):
                fenced = not fenced
                continue
            if fenced:
                continue
            if stripped.startswith("@"):
                target = stripped[1:]
                if target.startswith("/") or not re.fullmatch(r"[A-Za-z0-9_.\-/]+", target) or Path(target).is_absolute() or ".." in Path(target).parts:
                    reject(path, "unsupported_or_external_import:" + target)
                    continue
                child = path.parent / target
                imports.append({"from": relative, "to": lexical_identifier(child),
                                "syntax": "standalone_relative_import"})
                visit(child, "explicit_import", depth + 1)
            elif re.search(r"(?<!\w)@[A-Za-z0-9_./~-]+", stripped):
                reject(path, "unsupported_inline_import_or_mention")
        active.remove(relative)

    def discover(base: Path, relationship: str, depth: int = 0) -> list[Path]:
        nonlocal discovery_count
        try:
            before = guarded_stat(base)
            if not stat.S_ISDIR(before.st_mode):
                raise ValueError("not_directory")
            if depth > limits["max_directory_depth"]:
                raise ValueError("directory_depth_limit")
            children: list[Path] = []
            with os.scandir(base) as entries:
                for entry in entries:
                    if discovery_count >= limits["max_discovery_entries"]:
                        # Do not publish an order-dependent subset of a truncated directory.
                        raise ValueError("discovery_entry_limit")
                    discovery_count += 1
                    children.append(base / entry.name)
            if identity(guarded_stat(base)) != identity(before):
                raise ValueError("directory_changed_during_discovery")
            found: list[Path] = []
            for child in sorted(children):
                try:
                    observed = guarded_stat(child)
                    if stat.S_ISDIR(observed.st_mode):
                        found.extend(discover(child, relationship, depth + 1))
                    elif stat.S_ISREG(observed.st_mode) and child.suffix == (
                            ".mdc" if relationship == "cursor_rule_candidate" else ".md"):
                        if relationship != "skill_body_on_demand" or child.name == "SKILL.md":
                            found.append(child)
                except (OSError, ValueError, RuntimeError) as exc:
                    reject(child, str(exc))
            return found
        except FileNotFoundError:
            return []
        except (OSError, ValueError, RuntimeError) as exc:
            reject(base, str(exc))
            return []

    if candidate_host is not None:
        if candidate_host not in {"cursor", "copilot_harness", "vscode_local"}:
            raise ValueError("Unsupported project candidate host")
        base_inputs: dict[str, dict[str, Any]] = {}
        conditional_inputs: dict[str, dict[str, Any]] = {}

        def candidate(path: Path, condition: str | None = None) -> None:
            # Optional absence differs from an unsafe path/read. Keep the same
            # guarded stat/read/discovery and fixed bounds as the Claude model.
            try:
                guarded_stat(path)
            except FileNotFoundError:
                return
            except (OSError, ValueError, RuntimeError) as exc:
                reject(path, str(exc))
                return
            relationship = "conditional_instruction_candidate" if condition else "project_instruction_candidate"
            loaded = read(path, relationship)
            if loaded is not None:
                row = loaded[1]
                if condition:
                    row["condition"] = condition
                    conditional_inputs[row["path"]] = row
                else:
                    base_inputs[row["path"]] = row

        def metadata(path: Path, text: str) -> dict[str, Any] | None:
            lines = text.splitlines()
            if not lines or lines[0] != "---":
                return {}
            try:
                closing = next((index for index in range(1, len(lines)) if lines[index] == "---"), None)
                if closing is None:
                    raise ValueError("unterminated_frontmatter")
                value = yaml.safe_load("\n".join(lines[1:closing]))
                if not isinstance(value, dict):
                    raise ValueError("invalid_frontmatter_mapping")
                return value
            except RecursionError:
                reject(path, "unsupported_deep_frontmatter")
            except (ValueError, yaml.YAMLError) as exc:
                reject(path, str(exc))
            return None

        if candidate_host == "cursor":
            candidate(root / "AGENTS.md")
            for path in discover(root / ".cursor" / "rules", "cursor_rule_candidate"):
                loaded = read(path, "conditional_instruction_candidate")
                if loaded is None:
                    continue
                meta = metadata(path, loaded[0])
                if meta is None:
                    continue
                flag = meta.get("alwaysApply")
                if "alwaysApply" in meta and type(flag) is not bool:
                    reject(path, "unsupported_alwaysApply_metadata")
                    continue
                if flag is True:
                    candidate(path)
                else:
                    candidate(path, "glob/relevance/manual rule applicability not evaluated")
        else:
            candidate(root / ".github" / "copilot-instructions.md")
            candidate(root / "AGENTS.md", "Local chat.useAgentsMdFile setting unverified"
                      if candidate_host == "vscode_local" else None)
            for path in discover(root / ".github" / "instructions", "instruction_candidate"):
                if not path.name.endswith(".instructions.md"):
                    continue
                loaded = read(path, "conditional_instruction_candidate")
                if loaded is None:
                    continue
                meta = metadata(path, loaded[0])
                if meta is None:
                    continue
                if "applyTo" in meta and not isinstance(meta["applyTo"], str):
                    reject(path, "unsupported_applyTo_metadata")
                    continue
                # Even universal globs remain candidates until the actual host,
                # settings and request applicability are established.
                candidate(path, "applyTo=" + str(meta.get("applyTo", "manual/description selection"))
                          + "; task paths and host/settings applicability unverified")
            if candidate_host == "vscode_local":
                for name in ("CLAUDE.md", ".claude/CLAUDE.md", "CLAUDE.local.md"):
                    candidate(root / name, "Local chat.useClaudeMdFile compatibility setting unverified; no import expansion assumed")
                for path in discover(root / ".claude" / "rules", "rule_candidate"):
                    loaded = read(path, "conditional_instruction_candidate")
                    if loaded is None:
                        continue
                    meta = metadata(path, loaded[0])
                    if meta is None:
                        continue
                    paths = meta.get("paths")
                    if "paths" in meta and not (isinstance(paths, str) or isinstance(paths, list)
                            and all(isinstance(item, str) for item in paths)):
                        reject(path, "unsupported_paths_metadata")
                        continue
                    candidate(path, "Local Claude-rule compatibility setting and paths applicability unverified")
        union = {**base_inputs, **conditional_inputs}
        rows = [union[key] for key in sorted(union)]
        result = {
            "host": candidate_host,
            "basis": "project_local_conservative_candidate_union",
            "observed_loading": False, "settings_verified": False,
            "status": "partial" if unresolved else "project_local_subset" if rows else "not_present",
            "scope": "Repository-root project candidates only; format alternatives and conditional envelopes are not an assembled request.",
            "limits": limits,
            "base_candidates": [base_inputs[key] for key in sorted(base_inputs)],
            "conditional_candidates": [conditional_inputs[key] for key in sorted(conditional_inputs)],
            "all_candidates": rows,
            "base_candidate_estimated_tokens": sum(row["estimated_tokens"] for row in base_inputs.values()),
            "all_candidate_estimated_tokens": sum(row["estimated_tokens"] for row in rows),
            "input_files": [{key: loaded[1][key] for key in ("path", "lines", "chars", "estimated_tokens", "sha256")}
                            | {"relationship": "source_input"}
                            for _, loaded in sorted(cache.items()) if loaded is not None],
            "unresolved": unresolved,
            "deduplication": "exact contained project path only; distinct files with equal text are counted separately",
            "token_basis": "configured_character_estimate_not_provider_tokenizer",
            "threshold_basis": "metadata_only_no_new_or_retuned_host_thresholds; configured combined_scenarios remain synthetic",
            "excluded": ["Ancestor/nested scope outside this repository-root model", "User/global instructions and custom instruction directories",
                         "Skill/prompt/command/reference bodies loaded on demand", "Runtime tool reads, file mentions and instruction-link expansion",
                         "Actual trust/settings/harness selection and task-specific glob matching", "Semantic deduplication and actual request assembly"],
            "source_refs": (["https://cursor.com/docs/rules"] if candidate_host == "cursor" else
                            ["https://code.visualstudio.com/docs/agent-customization/custom-instructions"]),
            "known_limitations": ["Base candidates include documented format alternatives, not a guarantee all are enabled together.",
                                  "Conditional candidates contribute only to the conservative all-candidate envelope, never a startup total.",
                                  "Local Claude compatibility is not a universal Copilot CLI/cloud loading claim.",
                                  "Stable-tree read checks do not establish a race-proof filesystem sandbox."],
        }
        validate_host_candidate_union(result)
        return result

    for entry_name in ("CLAUDE.md", ".claude/CLAUDE.md", "CLAUDE.local.md"):
        entry = root / entry_name
        try:
            guarded_stat(entry)
        except FileNotFoundError:
            continue
        except (OSError, ValueError, RuntimeError) as exc:
            reject(entry, str(exc))
            continue
        visit(entry, "project_entry", 0)
    for path in discover(root / ".claude" / "rules", "rule"):
        loaded = read(path, "rule")
        if loaded is None:
            continue
        text, metrics = loaded
        metadata: dict[str, Any] = {}
        lines = text.splitlines()
        if lines and lines[0] == "---":
            try:
                closing = next((index for index in range(1, len(lines)) if lines[index] == "---"), None)
                if closing is None:
                    raise ValueError("unterminated_frontmatter")
                value = yaml.safe_load("\n".join(lines[1:closing]))
                if not isinstance(value, dict):
                    raise ValueError("invalid_frontmatter_mapping")
                metadata = value
                paths = metadata.get("paths")
                if "paths" in metadata and not (isinstance(paths, str) or isinstance(paths, list) and all(isinstance(item, str) for item in paths)):
                    raise ValueError("unsupported_paths_metadata")
            except RecursionError:
                reject(path, "unsupported_deep_frontmatter")
                continue
            except (ValueError, yaml.YAMLError) as exc:
                reject(path, str(exc))
                continue
        if "paths" in metadata:
            metrics["relationship"] = "paths_conditioned_rule"
            metrics["paths"] = metadata["paths"]
            conditional.append(metrics)
        else:
            visit(path, "unconditional_project_rule", 0)
    for directory, relationship in (("skills", "skill_body_on_demand"), ("commands", "command_body_on_demand")):
        for path in discover(root / ".claude" / directory, relationship):
            loaded = read(path, relationship)
            if loaded is not None:
                on_demand.append(loaded[1])
    # Reviewed task-time references are input evidence, never inferred startup
    # imports. Reuse bounded custody/read/discovery checks and keep their metric
    # rows separate from the files actually selected by the startup grammar.
    for path in discover(root / ".github" / "naos-guidance", "guidance_reference_on_demand"):
        loaded = read(path, "guidance_reference_on_demand")
        if loaded is not None:
            on_demand.append(loaded[1])
    files = [startup[key] for key in sorted(startup)]
    present = bool(files or conditional or on_demand)
    return {
        "host": "claude_code", "basis": "project_local_static_loading_estimate",
        "observed_loading": False,
        "status": "partial" if unresolved else "project_local_subset" if present else "not_present",
        "scope": "Project CLAUDE.md, .claude/CLAUDE.md, CLAUDE.local.md, supported contained imports and unconditional project rules; excludes ancestors, user settings, runtime reads and activation.",
        "supported_import_grammar": "standalone @relative/path outside fenced code; no absolute, parent traversal or symlink paths",
        "limits": limits,
        "input_files": [{key: loaded[1][key] for key in ("path", "lines", "chars", "estimated_tokens", "sha256")} | {"relationship": "source_input"}
                        for _, loaded in sorted(cache.items()) if loaded is not None],
        "startup_files": files,
        "startup_estimated_tokens": sum(int(item["estimated_tokens"]) for item in files),
        "conditional_rules": conditional, "on_demand_bodies": on_demand,
        "import_edges": imports, "unresolved": unresolved,
        "github_instructions_basis": "manual_or_prose_requested_reads_unless_explicitly_imported",
        "token_basis": "configured_character_estimate_not_provider_tokenizer",
        "known_limitations": ["Stable project tree assumption: post-read identity checks do not establish a race-proof filesystem sandbox.",
                              "Conditional and on-demand presence can have zero startup estimate; activation and actual reads remain unobserved.",
                              "Skill metadata, prose-requested reads, ancestors, settings and unsupported import syntax are not complete startup accounting.",
                              "Absence covers only modeled project candidates; installed host version and settings are not inspected."],
        "vendor_guidance": {"kind": "advisory", "claude_file_target_lines": 200, "hard_token_limit": None,
            "source_refs": ["https://code.claude.com/docs/en/memory", "https://code.claude.com/docs/en/skills"],
            "verified_on": "2026-10-13", "authority": "root_primary_document_review"},
        "local_thresholds_are_vendor_limits": False,
    }


def build_claude_host_context(root: Path, rules: dict[str, Any]) -> dict[str, Any]:
    """Backward-compatible Claude-only static subset and its original fields."""
    return _build_guarded_project_context(root, rules)


def validate_host_candidate_union(view: dict[str, Any]) -> None:
    """Verify reported exact-path partition/accounting; no host execution claim."""
    if view.get("observed_loading") is not False or view.get("settings_verified") is not False:
        raise ValueError("Candidate union cannot assert observed loading/settings")
    bases = view["base_candidates"]
    conditional = view["conditional_candidates"]
    union = view["all_candidates"]
    if (any(row.get("relationship") != "project_instruction_candidate" or "condition" in row for row in bases)
            or any(row.get("relationship") != "conditional_instruction_candidate" or not row.get("condition") for row in conditional)):
        raise ValueError("Host conditional/base classification mismatch")
    names = [row["path"] for row in bases + conditional]
    if len(names) != len(set(names)) or [row["path"] for row in union] != sorted(names):
        raise ValueError("Host candidate partition or exact-path union mismatch")
    inputs = {row["path"]: row for row in view["input_files"]}
    for row in union:
        if any(inputs.get(row["path"], {}).get(key) != row[key]
               for key in ("path", "lines", "chars", "estimated_tokens", "sha256")):
            raise ValueError("Host union candidate is not bound to its source input")
    by_path = {row["path"]: row for row in union}
    for row in bases + conditional:
        if any(by_path[row["path"]][key] != row[key]
               for key in ("path", "lines", "chars", "estimated_tokens", "sha256")):
            raise ValueError("Host partition candidate is not bound to its union/source input")
    if (view["base_candidate_estimated_tokens"] != sum(row["estimated_tokens"] for row in bases)
            or view["all_candidate_estimated_tokens"] != sum(row["estimated_tokens"] for row in union)):
        raise ValueError("Host union token accounting mismatch")


def build_host_contexts(
    root: Path, rules: dict[str, Any], *, claude_context: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    """Project bounded host-specific static candidates, not provider requests."""
    return {"claude_code": claude_context if claude_context is not None else build_claude_host_context(root, rules),
            **{host: _build_guarded_project_context(root, rules, candidate_host=host)
               for host in ("cursor", "copilot_harness", "vscode_local")}}



def host_input_manifest(views: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    """Bind all actually read host inputs, including refused-metadata sources."""
    inputs: dict[str, str] = {}
    for view in views.values():
        for row in view["input_files"]:
            relative, digest = row["path"], row["sha256"]
            if relative in inputs and inputs[relative] != digest:
                raise ValueError("Host input changed between independently guarded views: " + relative)
            inputs[relative] = digest
    return [{"path": relative, "sha256": inputs[relative]} for relative in sorted(inputs)]


def validate_host_input_bindings(
    views: dict[str, dict[str, Any]], manifest: list[dict[str, str]], *,
    generated_manifest: list[dict[str, str]] | None = None,
) -> None:
    if set(views) != {"claude_code", "cursor", "copilot_harness", "vscode_local"}:
        raise ValueError("Host view coverage mismatch")
    for host, view in views.items():
        if host != "claude_code":
            validate_host_candidate_union(view)
    if manifest != host_input_manifest(views):
        raise ValueError("Host input manifest coverage/hash mismatch")
    if generated_manifest is not None:
        generated = {row["path"]: row["sha256"] for row in generated_manifest}
        if any(generated.get(row["path"]) != row["sha256"] for row in manifest):
            raise ValueError("Host input not bound to generated content manifest")



def validate_report_host_contexts(report: dict[str, Any]) -> None:
    """Validate additive host/input bindings without reading historical paths."""
    if "host_contexts" not in report:
        return
    views, inputs = report["host_contexts"], report["input_sources"]
    if views["claude_code"] != report["host_context"]:
        raise ValueError("Legacy Claude host context differs from additive view")
    if inputs["host_union_files"] != {host: view["input_files"] for host, view in views.items()}:
        raise ValueError("Report host input-source coverage/hash mismatch")
    if inputs["host_context_files"] != views["claude_code"]["input_files"]:
        raise ValueError("Legacy Claude input sources differ from additive view")
    validate_host_input_bindings(views, inputs["host_union_content_manifest"])


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
    host_context = build_claude_host_context(root, rules)
    host_contexts = build_host_contexts(root, rules, claude_context=host_context)
    host_manifest = host_input_manifest(host_contexts)
    validate_host_input_bindings(host_contexts, host_manifest)
    families, findings, file_index = build_family_reports(root, rules, profile, policy)
    scenarios, scenario_findings = build_scenarios(root, rules, profile, policy, file_index)
    findings.extend(scenario_findings)
    anchors, anchor_findings = build_anchors(root, rules, profile, policy, file_index)
    findings.extend(anchor_findings)
    snapshot = build_snapshot(families, scenarios, anchors)
    baseline_data, baseline_meta = load_baseline(baseline_path)
    baseline, baseline_findings = compare_baseline(snapshot, baseline_data, baseline_meta, rules, profile, policy)
    findings.extend(baseline_findings)
    # Only explicitly declared observations receive context for the actual rules
    # used. Scenario IDs and absent baseline paths remain subjects, not files
    # asserted to exist. A failed/missing rules load uses module defaults.
    for item in findings:
        if item.get("evidence_classification") == "confirmed":
            item["evidence_refs"] = [{"type": "local_file", "ref": str(Path(__file__).resolve())}]
            if rules_meta.get("present") and rules_meta.get("source") == "rules_file":
                item["evidence_refs"].append({"type": "local_file", "ref": str(rules_path.resolve())})
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
    report = {
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
            "host_context_files": host_context["input_files"],
            "host_union_files": {host: view["input_files"] for host, view in host_contexts.items()},
            "host_union_content_manifest": host_manifest,
            "optional_baseline": baseline_meta,
        },
        "non_inputs": DOWNSTREAM_NON_INPUTS,
        "downstream_consumers": DOWNSTREAM_CONSUMERS,
        "families": families,
        "combined_scenarios": scenarios,
        "host_context": host_context,
        "host_contexts": host_contexts,
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
    validate_report_host_contexts(report)
    return report


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


def fresh_public_audit_event_references(
    preview_root: Path, *, profile: str,
) -> dict[str, dict[str, Any]]:
    """Bound fresh default audit operands; uncertain events remain measured."""
    if profile not in PROFILE_ORDER:
        return {}
    try:
        from naos_secret_public_literals import collect_public_audit_event_references
        from naos_systemic_family_review import AUDIT_PRODUCER_EVENT_TYPES, _audit_output_shape
        from naos_policy import report_default_path
        from naos_ai_surfaces import checked_path
    except ImportError:
        return {}
    audit_root = preview_root / "naos" / "audit_log"
    files: list[Path] = []
    entries = 0
    try:
        audit_root = checked_path(preview_root, "naos/audit_log")
        for ancestor in (preview_root, preview_root / "naos", audit_root):
            metadata = ancestor.lstat()
            if (not stat.S_ISDIR(metadata.st_mode)
                    or getattr(metadata, "st_file_attributes", 0) & 0x400):
                return {}
        with os.scandir(audit_root) as dates:
            for date in dates:
                entries += 1
                if entries > FRESH_AUDIT_REFERENCE_MAX_ENTRIES:
                    return {}
                if not date.is_dir(follow_symlinks=False):
                    continue
                date_path = checked_path(preview_root, Path(date.path).relative_to(preview_root).as_posix())
                with os.scandir(date_path) as candidates:
                    for candidate in candidates:
                        entries += 1
                        if entries > FRESH_AUDIT_REFERENCE_MAX_ENTRIES:
                            return {}
                        if (candidate.name.endswith(".jsonl")
                                and candidate.is_file(follow_symlinks=False)):
                            files.append(checked_path(preview_root,
                                Path(candidate.path).relative_to(preview_root).as_posix()))
                            if len(files) > FRESH_AUDIT_REFERENCE_MAX_FILES:
                                return {}
        references = collect_public_audit_event_references(
            sorted(files), root=preview_root, naos_root="naos")
        policy = load_policy(root=preview_root, naos_root="naos")
        sources = {str(report_default_path(preview_root, "naos", policy, key)): key
                   for key in AUDIT_PRODUCER_EVENT_TYPES}
        selected_operands = {str(path) for path in files}
        verified = {}
        for event_id, reference in references.items():
            event = reference["event"]
            source_key = sources.get(event.get("source_report_path"))
            # Reuse the existing finite producer shapes: authored nested data
            # cannot disappear behind a normalized occurrence reference.
            if (reference["event_file"] in selected_operands
                    and event.get("profile") == profile
                    and event.get("generated_at") == FRESH_PROFILE_FIXED_TIME
                    and event.get("event_type") in AUDIT_PRODUCER_EVENT_TYPES.get(source_key, set())
                    and _audit_output_shape(event, source_key)):
                verified[event_id] = reference
        return verified
    except (OSError, ValueError, TypeError, KeyError):
        return {}


def normalize_fresh_audit_finding(
    finding: dict[str, Any], *, check_id: str,
    references: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Normalize only verified occurrence references in exact producer slots."""
    if check_id != "naos_audit_log":
        return finding
    finding_id = finding.get("id")
    if finding_id == "audit_log.missing_operator_id_events":
        field = "operator_id"
        expected = {"id", "severity", "status", "message", "event_ids"}
        message = "Some audit events do not have resolved operator_id metadata."
    elif finding_id == "audit_log.missing_session_id_events":
        field = "session_id"
        expected = {"id", "severity", "status", "message", "event_ids",
                    "evidence_classification", "classification_scope", "reasoning_summary",
                    "source_path", "human_review_required"}
        message = "Some audit events do not have session_id metadata."
        if (finding.get("evidence_classification") != "confirmed"
                or finding.get("classification_scope") != "observed_audit_event_session_field_absence"
                or finding.get("reasoning_summary") != "Loaded JSON mapping events with the listed identifiers lacked session_id at summary time; event validity is assessed separately and this does not establish audit completeness or session attribution."
                or type(finding.get("source_path")) is not str
                or finding.get("human_review_required") is not True):
            return finding
    else:
        return finding
    event_ids = finding.get("event_ids")
    if (set(finding) != expected or finding.get("severity") != "advisory"
            or finding.get("status") != "advisory" or finding.get("message") != message
            or type(event_ids) is not list or len(event_ids) > 25
            or any(type(event_id) is not str for event_id in event_ids)):
        return finding
    normalized = dict(finding)
    normalized["event_ids"] = [
        "audit-<fixed-time>-<dynamic-id>"
        if event_id in references and not references[event_id]["event"].get(field)
        else event_id
        for event_id in event_ids
    ]
    return normalized


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
    public_audit_references: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    public_audit_references = public_audit_references or {}
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
            normalized_finding = normalize_dynamic_values(
                normalize_fresh_audit_finding(raw_finding, check_id=check_id,
                                             references=public_audit_references), replacements)
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
    isolated_home = (temporary_environment_root / "home").resolve()
    isolated_home.mkdir(parents=True, exist_ok=True)
    home_drive, home_path = os.path.splitdrive(str(isolated_home))
    environment = {
        key: os.environ[key]
        for key in ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT")
        if key in os.environ
    }
    environment.update(
        {
            "HOME": str(isolated_home),
            "USERPROFILE": str(isolated_home),
            "HOMEDRIVE": home_drive,
            "HOMEPATH": home_path,
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
            "temporary_home_and_user_profile": True,
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
        parts = relative.split("/")
        if (not relative or "\\" in relative or ":" in relative
                or any(part in {"", ".", ".."} for part in parts)):
            raise RuntimeError(
                f"Fresh-profile generated input cannot be normalized: {relative}"
            )
        path = preview_root
        for index, part in enumerate([None, *parts]):
            if part is not None:
                path = path / part
            metadata = path.lstat()
            leaf = index == len(parts)
            if (stat.S_ISLNK(metadata.st_mode)
                    or getattr(metadata, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
                    or not (stat.S_ISREG(metadata.st_mode) if leaf else stat.S_ISDIR(metadata.st_mode))
                    or (leaf and metadata.st_nlink != 1)):
                raise RuntimeError(f"Fresh-profile generated input cannot be normalized: {relative}")
        if not path.resolve().is_relative_to(preview_root.resolve()):
            raise RuntimeError(f"Fresh-profile generated input escapes fixture: {relative}")
        identity = (metadata.st_dev, metadata.st_ino)
        # Windows lacks no-follow utime on supported Python versions. This is
        # a private disposable scaffold, not a concurrent-mutation sandbox.
        if os.utime in os.supports_follow_symlinks:
            os.utime(path, ns=(fixed_ns, fixed_ns), follow_symlinks=False)
        else:
            os.utime(path, ns=(fixed_ns, fixed_ns))
        after = path.lstat()
        if ((after.st_dev, after.st_ino) != identity
                or not stat.S_ISREG(after.st_mode)
                or getattr(after, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
                or after.st_nlink != 1 or after.st_mtime_ns != fixed_ns):
            raise RuntimeError(f"Fresh-profile generated input changed during normalization: {relative}")
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
        host_contexts = build_host_contexts(preview_root, rules)
        host_manifest = host_input_manifest(host_contexts)
        validate_host_input_bindings(host_contexts, host_manifest, generated_manifest=content_manifest)
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
            public_audit_references=fresh_public_audit_event_references(preview_root, profile=profile),
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
            "host_contexts": host_contexts,
            "host_union_content_manifest": host_manifest,
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


def profile_raw_hash_declarations(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Describe only known classifier diagnostics, without reading historical paths.

    These are retained producer declarations, not reconstructed source reports or
    verification of original bytes, current path contents, or authenticity.
    """
    declarations: list[dict[str, Any]] = []
    for profile_index, profile in enumerate(report.get("profiles") or []):
        self_check = profile["self_check"]
        checks = self_check["check_states"]
        for occurrence_index, occurrence in enumerate(self_check["finding_occurrences"]):
            item = occurrence["finding"]
            if occurrence["check_id"] != "naos_evidence_classification":
                continue
            identifier = item.get("id")
            legacy_id = (type(identifier) is str
                         and identifier.startswith("evidence_classification.missing."))
            ordinal_id = (type(identifier) is str
                          and identifier.startswith("EC-")
                          and item.get("id_scheme") == "report_ordinal_v1")
            if not (legacy_id or ordinal_id):
                continue
            check_index = occurrence["check_index"]
            finding_index = occurrence["finding_index"]
            expected_identity = (
                f"fresh-profile/{profile['profile']}/check[{check_index}]=naos_evidence_classification"
                f"/finding[{finding_index}]"
            )
            if (type(check_index) is not int or not 0 <= check_index < len(checks)
                    or checks[check_index]["id"] != occurrence["check_id"]
                    or checks[check_index]["check_index"] != check_index
                    or type(finding_index) is not int or finding_index < 0
                    or finding_index >= checks[check_index]["finding_count"]
                    or occurrence["identity"] != expected_identity):
                raise RuntimeError("Classifier raw-hash occurrence ownership is invalid.")
            source_index = item.get("source_index")
            if (not isinstance(item.get("finding_id"), str) or not item["finding_id"]
                    or not ((legacy_id and identifier == "evidence_classification.missing." + item["finding_id"])
                            or (ordinal_id and identifier == f"EC-{finding_index + 1}"))
                    or item.get("status") != "missing_classification"
                    or not isinstance(item.get("source_report"), str) or not item["source_report"]
                    or item.get("source_bucket") not in {"findings", "known_gaps", "residual_risks"}
                    or "source_index" not in item
                    or (source_index is not None and (type(source_index) is not int or source_index < 0))
                    or not isinstance(item.get("scan_generated_at"), str)
                    or not isinstance(item.get("source_observed_at"), str)
                    or not isinstance(item.get("source_report_sha256"), str)
                    or re.fullmatch(r"[0-9a-f]{64}", item["source_report_sha256"]) is None
                    or not isinstance(item.get("source_item_sha256"), str)
                    or re.fullmatch(r"[0-9a-f]{64}", item["source_item_sha256"]) is None):
                raise RuntimeError("Classifier raw-hash diagnostic shape is invalid.")
            pointer = (
                f"/profiles/{profile_index}/self_check/finding_occurrences/{occurrence_index}"
                "/finding/source_report_sha256"
            )
            declarations.append({
                "link_id": pointer,
                "occurrence_identity": occurrence["identity"],
                "source_report": item["source_report"],
                "source_bucket": item["source_bucket"],
                "source_index": source_index,
                "source_item_sha256": item["source_item_sha256"],
                "source_report_sha256": item["source_report_sha256"],
            })
    return declarations


def fresh_profile_measurement_projection(report: dict[str, Any]) -> dict[str, Any]:
    """Complete v2 measurement; only exact owned raw report hashes become links."""
    if (report.get("schema") != PROFILE_REPORT_SCHEMA
            or report.get("measurement_projection_version") != PROFILE_PROJECTION_VERSION
            or report.get("determinism_scope") != PROFILE_DETERMINISM_SCOPE
            or report.get("deterministic") is not True
            or "stable_payload_sha256" in report):
        raise RuntimeError("Fresh-profile v2 measurement scope is invalid.")
    declarations = profile_raw_hash_declarations(report)
    expected_envelope = {
        "authority": PROFILE_RAW_HASH_AUTHORITY,
        "original_report_bytes_archived": False,
        "original_report_bytes_verified": False,
        "current_source_state_verified": False,
        "authenticity_verified": False,
        "declarations": declarations,
    }
    if canonical_sha256(report.get("raw_hash_provenance")) != canonical_sha256(expected_envelope):
        raise RuntimeError("Fresh-profile raw-hash declaration links are inconsistent.")
    projection = copy.deepcopy({
        key: value for key, value in report.items()
        if key not in {"generated_at", "raw_hash_provenance", "measurement_payload_sha256", "report_integrity_sha256"}
    })
    for declaration in declarations:
        parts = declaration["link_id"].split("/")
        item = projection["profiles"][int(parts[2])]["self_check"]["finding_occurrences"][int(parts[5])]["finding"]
        item["source_report_sha256"] = {
            "type": "historical_scan_time_raw_report_hash_link",
            "link_id": declaration["link_id"],
        }
    return projection


def bind_fresh_profile_v2_digests(report: dict[str, Any]) -> None:
    """Builder operation; validators independently recompute without rebinding."""
    report["measurement_payload_sha256"] = canonical_sha256(fresh_profile_measurement_projection(report))
    report["report_integrity_sha256"] = canonical_sha256({
        key: value for key, value in report.items() if key != "report_integrity_sha256"
    })


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
        "schema": PROFILE_REPORT_SCHEMA,
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
            "Determinism applies to the complete measurement projection, not equality of full per-run reports.",
            "Raw report hashes are retained classifier-emitted historical scan-time declarations; original report bytes are not archived or verified here.",
            "Whole-report integrity does not verify current source state or authenticity.",
        ],
        "not_claimed": [
            "candidate approval",
            "pilot closure",
            "runtime behavior",
            "publication approval",
            "automatic threshold tuning",
            "automatic baseline approval",
        ],
        "determinism_scope": PROFILE_DETERMINISM_SCOPE,
        "measurement_projection_version": PROFILE_PROJECTION_VERSION,
        "raw_hash_provenance": {},
    }
    report["raw_hash_provenance"] = {
        "authority": PROFILE_RAW_HASH_AUTHORITY,
        "original_report_bytes_archived": False,
        "original_report_bytes_verified": False,
        "current_source_state_verified": False,
        "authenticity_verified": False,
        "declarations": profile_raw_hash_declarations(report),
    }
    bind_fresh_profile_v2_digests(report)
    validate_fresh_profiles_report(report)
    return report


def validate_fresh_profiles_report(report: dict[str, Any]) -> None:
    if report.get("schema") not in {PROFILE_BASELINE_SCHEMA, PROFILE_REPORT_SCHEMA}:
        raise RuntimeError("Fresh-profile report schema is invalid.")
    if report["schema"] == PROFILE_BASELINE_SCHEMA and any(
        key in report for key in {
            "determinism_scope", "measurement_projection_version", "raw_hash_provenance",
            "measurement_payload_sha256", "report_integrity_sha256",
        }
    ):
        raise RuntimeError("Historical v1 reports cannot contain v2 contract fields.")
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
        # Additive host projections bind to the pre-measurement generated
        # manifest. Historical reports without either additive field remain valid.
        if "host_contexts" in profile or "host_union_content_manifest" in profile:
            try:
                validate_host_input_bindings(profile["host_contexts"], profile["host_union_content_manifest"],
                                             generated_manifest=manifest)
            except (ValueError, KeyError, TypeError) as exc:
                raise RuntimeError(f"Fresh {profile_name} host input provenance is inconsistent: {exc}") from exc
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
    if report["schema"] == PROFILE_BASELINE_SCHEMA:
        if report.get("stable_payload_sha256") != stable_payload_sha256:
            raise RuntimeError("Fresh-profile stable payload digest is inconsistent.")
    else:
        projection = fresh_profile_measurement_projection(report)
        if report.get("measurement_payload_sha256") != canonical_sha256(projection):
            raise RuntimeError("Fresh-profile measurement payload digest is inconsistent.")
        integrity = canonical_sha256({
            key: value for key, value in report.items() if key != "report_integrity_sha256"
        })
        if report.get("report_integrity_sha256") != integrity:
            raise RuntimeError("Fresh-profile whole-report integrity digest is inconsistent.")


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
    if report.get("schema") == PROFILE_REPORT_SCHEMA:
        lines.append("Determinism scope: complete measurement projection; raw hashes are retained historical declarations.")
        lines.append("Whole-report integrity does not verify original report bytes, current source state, or authenticity.")
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


def host_context_lines(report: dict[str, Any]) -> list[str]:
    """Keep human output as explicit as JSON about candidates versus startup."""
    views = report.get("host_contexts") or {}
    result: list[str] = []
    if "claude_code" in views:
        result.append("  Claude project startup subset: " + str(views["claude_code"]["startup_estimated_tokens"])
                      + " estimated tokens; actual loading unobserved")
    for host in ("cursor", "copilot_harness", "vscode_local"):
        if host in views:
            view = views[host]
            result.append(f"  {host}: {view['base_candidate_estimated_tokens']} base candidate tokens; "
                          f"{view['all_candidate_estimated_tokens']} including conditional envelope "
                          f"({view['status']}; settings/loading unverified)")
    return result


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
        for line in host_context_lines(report):
            print(line)
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
