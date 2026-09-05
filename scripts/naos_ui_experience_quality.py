#!/usr/bin/env python3
"""Review optional local UI/UX quality evidence declarations.

This command is deterministic local review evidence only. It does not call
Figma, MCP, Penpot, v0, Lovable, Bolt, providers, models, memory tools,
browsers, APIs, networks, or design tools; it does not mutate design tools,
IDE settings, source code, or screenshots; and it does not prove design
quality, accessibility, privacy, brand correctness, legal sufficiency,
compliance, approval, merge readiness, release readiness, certification, or
attestation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    build_generated_by,
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    kit_root,
    load_policy,
    normalize_profile,
    report_output_path,
    status_from_counts,
    write_report,
)


REPORT_SCHEMA = "naos.ui_experience_quality.v1"
ALLOWED_STAGES = {
    "concept_exploration",
    "wireframe_or_prototype",
    "implementation_ready_design",
    "post_implementation_review",
}
HEAVY_STAGES = {"implementation_ready_design", "post_implementation_review"}
REQUIRED_DYNAMIC_STATES = {"loading", "empty", "error"}
REQUIRED_INTERACTION_STATES = {"focus", "disabled"}
TOOL_AUTHORITY_FIELDS = {
    "runtime_enabled",
    "mcp_allowed",
    "figma_api_allowed",
    "browser_automation_allowed",
    "design_tool_calls_allowed",
    "external_generator_authority",
    "model_judgement_authority",
    "tool_mutation_allowed",
}
REASON_ORDER = [
    "missing_quality_brief",
    "stage_dependency_gap",
    "provisional_dependency_unresolved",
    "missing_object_trace",
    "data_contract_gap",
    "state_model_gap",
    "missing_token_baseline",
    "brand_token_drift",
    "typography_scale_gap",
    "spacing_rhythm_gap",
    "layout_hierarchy_unreviewed",
    "responsive_state_gap",
    "interaction_state_gap",
    "empty_error_loading_state_gap",
    "motion_reduction_gap",
    "accessibility_evidence_gap",
    "visual_regression_unreviewed",
    "screenshot_set_gap",
    "content_clarity_gap",
    "performance_perception_gap",
    "inspiration_provenance_gap",
    "external_generator_provenance_gap",
    "advisory_ai_critique_unbounded",
    "human_design_review_missing",
    "user_validation_missing",
    "mcp_or_tool_mutation_attempt",
]
REASON_GATES = {
    "missing_quality_brief": ["G2", "G6"],
    "stage_dependency_gap": ["G2", "G6"],
    "provisional_dependency_unresolved": ["G2", "G6"],
    "missing_object_trace": ["G2", "G6"],
    "data_contract_gap": ["G2", "G3", "G6"],
    "state_model_gap": ["G4", "G5", "G6"],
    "missing_token_baseline": ["G3", "G4", "G6"],
    "brand_token_drift": ["G3", "G4", "G6"],
    "typography_scale_gap": ["G3", "G4", "G6"],
    "spacing_rhythm_gap": ["G3", "G4", "G6"],
    "layout_hierarchy_unreviewed": ["G6"],
    "responsive_state_gap": ["G5", "G6"],
    "interaction_state_gap": ["G4", "G5", "G6"],
    "empty_error_loading_state_gap": ["G4", "G5", "G6"],
    "motion_reduction_gap": ["G5", "G6"],
    "accessibility_evidence_gap": ["G5", "G6"],
    "visual_regression_unreviewed": ["G5", "G6"],
    "screenshot_set_gap": ["G5", "G6"],
    "content_clarity_gap": ["G2", "G3", "G6"],
    "performance_perception_gap": ["G5", "G6"],
    "inspiration_provenance_gap": ["G6"],
    "external_generator_provenance_gap": ["G3", "G6"],
    "advisory_ai_critique_unbounded": ["G6"],
    "human_design_review_missing": ["G6"],
    "user_validation_missing": ["G2", "G6"],
    "mcp_or_tool_mutation_attempt": ["G3", "G6"],
}
LOCAL_REF_FIELDS = {
    "design_quality_brief_ref": "design_quality_brief",
    "dependency_refs": "dependency_ref",
    "data_model_refs": "data_model_ref",
    "api_contract_refs": "api_contract_ref",
    "state_model_refs": "state_model_ref",
    "screen_spec_refs": "screen_spec_ref",
    "token_refs": "token_ref",
    "component_library_refs": "component_library_ref",
    "typography_refs": "typography_ref",
    "spacing_refs": "spacing_ref",
    "layout_review_refs": "layout_review_ref",
    "content_review_refs": "content_review_ref",
    "privacy_evidence_refs": "privacy_evidence_ref",
    "accessibility_evidence_refs": "accessibility_evidence_ref",
    "visual_regression_refs": "visual_regression_ref",
    "lighthouse_or_performance_refs": "performance_ref",
    "storybook_refs": "storybook_ref",
    "motion_evidence_refs": "motion_evidence_ref",
    "reduced_motion_evidence_refs": "reduced_motion_evidence_ref",
    "brand_review_refs": "brand_review_ref",
    "user_validation_refs": "user_validation_ref",
}
LIMITATIONS = [
    "UI experience quality reports evaluate local declarations and local evidence references only.",
    "The report identifies missing or conflicting review evidence; it does not score or approve UI quality.",
    "Screenshots, visual regression, accessibility, performance, generator, and review references are declared evidence only; this command does not execute those tools.",
    "The report does not call Figma, MCP, Penpot, v0, Lovable, Bolt, browsers, providers, models, memory tools, APIs, networks, or runtime systems.",
    "Evidence presence does not prove design quality, accessibility compliance, privacy compliance, brand approval, usability, delight, implementation correctness, release readiness, certification, attestation, or compliance.",
    "Assured-profile blocking is not enabled by this implementation; findings remain review evidence unless a later validated maturity control changes posture.",
]
NOT_CLAIMED = [
    "Figma MCP replacement",
    "automatic code-to-design synchronization",
    "automatic design-to-code synchronization",
    "Figma availability",
    "Figma API access",
    "MCP activation",
    "design quality proof",
    "user delight proof",
    "brand approval",
    "accessibility certification",
    "privacy compliance determination",
    "legal or regulatory sufficiency",
    "approval",
    "merge approval",
    "release authority",
    "publication authority",
    "certification",
    "attestation",
    "proof of compliance",
    "runtime orchestration",
    "provider calls",
    "model calls",
    "memory activation",
]
RESIDUAL_RISKS = [
    "quality_checklist_theater",
    "polished_speculative_ui_without_dependencies",
    "visual_evidence_can_be_stale",
    "automated_accessibility_checks_are_incomplete",
    "generator_outputs_can_import_unreviewed_assumptions",
    "human_review_required",
]


def utc_now_text() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def string_list(value: Any) -> list[str]:
    return list(dict.fromkeys(str(item).strip() for item in as_list(value) if str(item).strip()))


def bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def is_adapt_placeholder(value: Any) -> bool:
    return isinstance(value, str) and value.strip().startswith("[ADAPT:")


def is_empty_or_placeholder(value: Any) -> bool:
    return value in (None, "") or is_adapt_placeholder(value)


def safe_digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping: {path}")
    return data


def default_declaration_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "ui_experience_quality.yaml"


def resolve_declaration_path(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    explicit: str | None = None,
) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("ui_experience_quality") or "ui_experience_quality.yaml")
    project_declaration = root / naos_root / filename
    if project_declaration.exists():
        return project_declaration, "project"
    return default_declaration_template(), "template"


def relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve(strict=False).relative_to(root.resolve()))
    except ValueError:
        return str(path)


def path_status(root: Path, value: Any) -> tuple[str | None, bool, bool, str]:
    text = str(value or "").strip()
    if not text or is_adapt_placeholder(text):
        return text or None, False, False, "missing_or_placeholder"
    if "://" in text:
        return text, False, False, "external_reference_unverified"
    candidate = Path(text)
    if candidate.is_absolute() or ".." in candidate.parts:
        return text, False, False, "unsafe_path"
    target = (root / candidate).resolve(strict=False)
    root_resolved = root.resolve()
    if root_resolved not in (target, *target.parents):
        return text, False, False, "unsafe_path"
    return text, True, target.exists(), "exists" if target.exists() else "missing"


def review_severity(profile: str, root: Path, naos_root: str) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    if profile == "quickstart":
        return "advisory"
    if profile == "lite":
        return "warning"
    return "required"


def finding(
    identifier: str,
    severity: str,
    reason_code: str,
    message: str,
    object_id: str | None = None,
    path: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": identifier,
        "severity": severity,
        "status": reason_code,
        "reason_code": reason_code,
        "related_gates": REASON_GATES.get(reason_code, ["G6"]),
        "gate": ", ".join(REASON_GATES.get(reason_code, ["G6"])),
        "message": message,
        "human_review_required": True,
    }
    if object_id:
        item["object_id"] = object_id
    if path:
        item["path"] = path
    item.update({key: value for key, value in extra.items() if value is not None})
    return item


def normalize_mapping_refs(value: Any) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for item in as_list(value):
        if isinstance(item, dict):
            refs.append(dict(item))
        elif str(item).strip():
            refs.append({"ref": str(item).strip()})
    return refs


def normalize_screenshot_sets(value: Any, root: Path) -> list[dict[str, Any]]:
    screenshots: list[dict[str, Any]] = []
    for item in as_list(value):
        if isinstance(item, dict):
            text, safe, exists, status = path_status(root, item.get("path") or item.get("ref"))
            screenshots.append(
                {
                    "path": text,
                    "viewport": item.get("viewport"),
                    "state": item.get("state"),
                    "reviewed": bool_value(item.get("reviewed"), default=False),
                    "safe": safe,
                    "exists": exists,
                    "reference_status": status,
                }
            )
        elif str(item).strip():
            text, safe, exists, status = path_status(root, item)
            screenshots.append(
                {
                    "path": text,
                    "viewport": None,
                    "state": None,
                    "reviewed": False,
                    "safe": safe,
                    "exists": exists,
                    "reference_status": status,
                }
            )
    return screenshots


def normalize_screen(raw: dict[str, Any], index: int, root: Path, default_stage: str) -> dict[str, Any]:
    stage = str(raw.get("design_stage") or default_stage or "concept_exploration").strip()
    brief_ref, brief_safe, brief_exists, brief_status = path_status(root, raw.get("design_quality_brief_ref"))
    human_review = as_mapping(raw.get("human_design_review"))
    return {
        "index": index,
        "object_id": str(raw.get("object_id") or raw.get("screen_id") or raw.get("id") or "").strip() or None,
        "design_stage": stage,
        "user_goal": raw.get("user_goal"),
        "primary_user_scenarios": string_list(raw.get("primary_user_scenarios")),
        "design_quality_brief_ref": brief_ref,
        "design_quality_brief_ref_safe": brief_safe,
        "design_quality_brief_ref_exists": brief_exists,
        "design_quality_brief_ref_status": brief_status,
        "fr_refs": string_list(raw.get("fr_refs")),
        "nfr_refs": string_list(raw.get("nfr_refs")),
        "task_refs": string_list(raw.get("task_refs")),
        "acceptance_criteria_refs": string_list(raw.get("acceptance_criteria_refs")),
        "dependency_refs": string_list(raw.get("dependency_refs")),
        "data_model_refs": string_list(raw.get("data_model_refs")),
        "api_contract_refs": string_list(raw.get("api_contract_refs")),
        "state_model_refs": string_list(raw.get("state_model_refs")),
        "open_dependency_questions": string_list(raw.get("open_dependency_questions")),
        "design_traceability_refs": string_list(raw.get("design_traceability_refs")),
        "screen_spec_refs": string_list(raw.get("screen_spec_refs")),
        "token_refs": string_list(raw.get("token_refs")),
        "component_library_refs": string_list(raw.get("component_library_refs")),
        "typography_refs": string_list(raw.get("typography_refs")),
        "spacing_refs": string_list(raw.get("spacing_refs")),
        "layout_review_refs": string_list(raw.get("layout_review_refs")),
        "content_review_refs": string_list(raw.get("content_review_refs")),
        "privacy_evidence_refs": string_list(raw.get("privacy_evidence_refs")),
        "screenshot_sets": normalize_screenshot_sets(raw.get("screenshot_sets"), root),
        "state_coverage": string_list(raw.get("state_coverage")),
        "responsive_breakpoints": string_list(raw.get("responsive_breakpoints")),
        "accessibility_evidence_refs": string_list(raw.get("accessibility_evidence_refs")),
        "visual_regression_refs": string_list(raw.get("visual_regression_refs")),
        "lighthouse_or_performance_refs": string_list(raw.get("lighthouse_or_performance_refs")),
        "storybook_refs": string_list(raw.get("storybook_refs")),
        "motion_evidence_refs": string_list(raw.get("motion_evidence_refs")),
        "reduced_motion_evidence_refs": string_list(raw.get("reduced_motion_evidence_refs")),
        "brand_review_refs": string_list(raw.get("brand_review_refs")),
        "inspiration_refs": normalize_mapping_refs(raw.get("inspiration_refs")),
        "external_generator_refs": normalize_mapping_refs(raw.get("external_generator_refs")),
        "advisory_ai_critique_refs": normalize_mapping_refs(raw.get("advisory_ai_critique_refs")),
        "human_design_review": human_review,
        "human_review_required": bool_value(
            human_review.get("required"),
            default=stage in HEAVY_STAGES or bool_value(raw.get("human_review_required"), default=False),
        ),
        "user_validation_required": bool_value(raw.get("user_validation_required"), default=False),
        "user_validation_refs": string_list(raw.get("user_validation_refs")),
        "review_disposition": raw.get("review_disposition"),
        "residual_risks": string_list(raw.get("residual_risks")),
        "non_claims": string_list(raw.get("non_claims")),
        "token_drift_declared": bool_value(raw.get("token_drift_declared"), default=False),
        "token_drift_rationale": raw.get("token_drift_rationale"),
    }


def has_any_dependency_link(screen: dict[str, Any]) -> bool:
    return bool(screen["fr_refs"] or screen["nfr_refs"] or screen["task_refs"] or screen["acceptance_criteria_refs"])


def review_evidence_present(screen: dict[str, Any], key: str) -> bool:
    return bool(screen.get(key))


def evaluate_screen(raw: dict[str, Any], screen: dict[str, Any], severity: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    object_id = str(screen.get("object_id") or f"screen[{screen['index']}]")
    stage = str(screen.get("design_stage") or "")

    if stage not in ALLOWED_STAGES:
        findings.append(
            finding(
                "ui_experience_quality.invalid_design_stage",
                severity,
                "stage_dependency_gap",
                "UI quality screen has an unsupported design_stage.",
                object_id=object_id,
                design_stage=stage,
            )
        )

    if (
        is_empty_or_placeholder(screen.get("user_goal"))
        and not screen.get("primary_user_scenarios")
        and is_empty_or_placeholder(screen.get("design_quality_brief_ref"))
    ):
        findings.append(
            finding(
                "ui_experience_quality.missing_quality_brief",
                severity,
                "missing_quality_brief",
                "Screen lacks a user goal, primary scenario, or design quality brief reference.",
                object_id=object_id,
            )
        )

    if not (screen.get("object_id") or screen["design_traceability_refs"] or has_any_dependency_link(screen)):
        findings.append(
            finding(
                "ui_experience_quality.missing_object_trace",
                severity,
                "missing_object_trace",
                "Screen lacks object_id, Design Traceability refs, and FR/NFR/task/AC refs.",
                object_id=object_id,
            )
        )

    if stage == "wireframe_or_prototype" and not has_any_dependency_link(screen) and not screen["open_dependency_questions"]:
        findings.append(
            finding(
                "ui_experience_quality.stage_dependency_gap.wireframe",
                severity,
                "stage_dependency_gap",
                "Wireframe/prototype screen lacks FR/NFR/task/AC refs or explicit open dependency questions.",
                object_id=object_id,
            )
        )

    if stage in HEAVY_STAGES:
        if not has_any_dependency_link(screen):
            findings.append(
                finding(
                    "ui_experience_quality.stage_dependency_gap.requirements",
                    severity,
                    "stage_dependency_gap",
                    "Implementation-ready or post-implementation UI lacks FR/NFR/task/AC refs.",
                    object_id=object_id,
                )
            )
        if screen["open_dependency_questions"]:
            findings.append(
                finding(
                    "ui_experience_quality.provisional_dependency_unresolved",
                    severity,
                    "provisional_dependency_unresolved",
                    "Implementation-ready or post-implementation UI still declares unresolved dependency questions.",
                    object_id=object_id,
                )
            )
        if not screen["data_model_refs"] or not screen["api_contract_refs"]:
            findings.append(
                finding(
                    "ui_experience_quality.data_contract_gap",
                    severity,
                    "data_contract_gap",
                    "High-fidelity UI lacks data model or API contract references.",
                    object_id=object_id,
                )
            )
        if not screen["state_model_refs"] and not screen["state_coverage"]:
            findings.append(
                finding(
                    "ui_experience_quality.state_model_gap",
                    severity,
                    "state_model_gap",
                    "High-fidelity UI lacks state model refs or explicit state coverage.",
                    object_id=object_id,
                )
            )
        if not screen["token_refs"]:
            findings.append(
                finding(
                    "ui_experience_quality.missing_token_baseline",
                    severity,
                    "missing_token_baseline",
                    "High-fidelity UI lacks local design-token or brand-token references.",
                    object_id=object_id,
                )
            )
        if screen["token_drift_declared"] and is_empty_or_placeholder(screen.get("token_drift_rationale")):
            findings.append(
                finding(
                    "ui_experience_quality.brand_token_drift",
                    severity,
                    "brand_token_drift",
                    "Token drift is declared without rationale.",
                    object_id=object_id,
                )
            )
        if not screen["typography_refs"]:
            findings.append(
                finding(
                    "ui_experience_quality.typography_scale_gap",
                    severity,
                    "typography_scale_gap",
                    "High-fidelity UI lacks typography scale evidence.",
                    object_id=object_id,
                )
            )
        if not screen["spacing_refs"]:
            findings.append(
                finding(
                    "ui_experience_quality.spacing_rhythm_gap",
                    severity,
                    "spacing_rhythm_gap",
                    "High-fidelity UI lacks spacing rhythm evidence.",
                    object_id=object_id,
                )
            )
        if not screen["layout_review_refs"] and is_empty_or_placeholder(screen.get("review_disposition")):
            findings.append(
                finding(
                    "ui_experience_quality.layout_hierarchy_unreviewed",
                    severity,
                    "layout_hierarchy_unreviewed",
                    "Layout hierarchy, density, or scanning path lacks review disposition.",
                    object_id=object_id,
                )
            )
        screenshot_sets = screen["screenshot_sets"]
        if not screenshot_sets:
            findings.append(
                finding(
                    "ui_experience_quality.screenshot_set_gap",
                    severity,
                    "screenshot_set_gap",
                    "High-fidelity UI lacks screenshot/state evidence references.",
                    object_id=object_id,
                )
            )
        elif any(item.get("reference_status") in {"missing", "unsafe_path", "missing_or_placeholder"} for item in screenshot_sets):
            findings.append(
                finding(
                    "ui_experience_quality.screenshot_set_gap.path",
                    severity,
                    "screenshot_set_gap",
                    "One or more screenshot references are missing, unsafe, or unresolved.",
                    object_id=object_id,
                )
            )
        if not screen["responsive_breakpoints"] or not {item.get("viewport") for item in screenshot_sets if item.get("viewport")}:
            findings.append(
                finding(
                    "ui_experience_quality.responsive_state_gap",
                    severity,
                    "responsive_state_gap",
                    "Responsive breakpoint or viewport screenshot evidence is missing.",
                    object_id=object_id,
                )
            )
        states = set(screen["state_coverage"])
        if not REQUIRED_INTERACTION_STATES.issubset(states):
            findings.append(
                finding(
                    "ui_experience_quality.interaction_state_gap",
                    severity,
                    "interaction_state_gap",
                    "Interactive focus or disabled state coverage is missing.",
                    object_id=object_id,
                )
            )
        if not REQUIRED_DYNAMIC_STATES.issubset(states):
            findings.append(
                finding(
                    "ui_experience_quality.empty_error_loading_state_gap",
                    severity,
                    "empty_error_loading_state_gap",
                    "Loading, empty, or error state coverage is missing.",
                    object_id=object_id,
                )
            )
        if screen["motion_evidence_refs"] and not screen["reduced_motion_evidence_refs"]:
            findings.append(
                finding(
                    "ui_experience_quality.motion_reduction_gap",
                    severity,
                    "motion_reduction_gap",
                    "Motion evidence is declared without reduced-motion posture evidence.",
                    object_id=object_id,
                )
            )
        if not screen["accessibility_evidence_refs"]:
            findings.append(
                finding(
                    "ui_experience_quality.accessibility_evidence_gap",
                    severity,
                    "accessibility_evidence_gap",
                    "Accessibility evidence refs are missing.",
                    object_id=object_id,
                )
            )
        if stage == "post_implementation_review" and not screen["visual_regression_refs"]:
            findings.append(
                finding(
                    "ui_experience_quality.visual_regression_unreviewed",
                    severity,
                    "visual_regression_unreviewed",
                    "Post-implementation UI lacks visual-regression review evidence.",
                    object_id=object_id,
                )
            )
        if not screen["content_review_refs"]:
            findings.append(
                finding(
                    "ui_experience_quality.content_clarity_gap",
                    severity,
                    "content_clarity_gap",
                    "Visible copy, labels, helper text, or error messages lack review evidence.",
                    object_id=object_id,
                )
            )
        if not screen["lighthouse_or_performance_refs"]:
            findings.append(
                finding(
                    "ui_experience_quality.performance_perception_gap",
                    severity,
                    "performance_perception_gap",
                    "Loading or perceived-performance evidence is missing for a high-fidelity UI path.",
                    object_id=object_id,
                )
            )

    for ref in screen["inspiration_refs"]:
        if not bool_value(ref.get("reviewed"), default=False) or not str(ref.get("reuse_boundary") or "").strip():
            findings.append(
                finding(
                    "ui_experience_quality.inspiration_provenance_gap",
                    severity,
                    "inspiration_provenance_gap",
                    "Inspiration or third-party visual reference lacks review or reuse boundary.",
                    object_id=object_id,
                )
            )
            break

    for ref in screen["external_generator_refs"]:
        if (
            not str(ref.get("prompt_log_ref") or "").strip()
            or not bool_value(ref.get("reviewed"), default=False)
            or not str(ref.get("reuse_boundary") or "").strip()
        ):
            findings.append(
                finding(
                    "ui_experience_quality.external_generator_provenance_gap",
                    severity,
                    "external_generator_provenance_gap",
                    "External generator output lacks prompt log, review, or reuse boundary evidence.",
                    object_id=object_id,
                )
            )
            break

    for ref in screen["advisory_ai_critique_refs"]:
        if (
            not str(ref.get("provider_role") or "").strip()
            or not str(ref.get("data_exposure") or "").strip()
            or not str(ref.get("human_disposition") or "").strip()
        ):
            findings.append(
                finding(
                    "ui_experience_quality.advisory_ai_critique_unbounded",
                    severity,
                    "advisory_ai_critique_unbounded",
                    "Advisory AI critique lacks provider role, data-exposure posture, or human disposition.",
                    object_id=object_id,
                )
            )
            break

    human_review = screen["human_design_review"]
    if screen["human_review_required"] and (
        is_empty_or_placeholder(human_review.get("reviewer"))
        or is_empty_or_placeholder(human_review.get("disposition"))
        or not string_list(human_review.get("review_refs"))
    ):
        findings.append(
            finding(
                "ui_experience_quality.human_design_review_missing",
                severity,
                "human_design_review_missing",
                "Human design/product review posture is required but incomplete.",
                object_id=object_id,
            )
        )

    if screen["user_validation_required"] and not screen["user_validation_refs"]:
        findings.append(
            finding(
                "ui_experience_quality.user_validation_missing",
                severity,
                "user_validation_missing",
                "User validation is declared required but no user-validation evidence refs are present.",
                object_id=object_id,
            )
        )

    return findings


def evaluate_screens(
    raw_screens: Any,
    root: Path,
    severity: str,
    default_stage: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    screens: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    if not isinstance(raw_screens, list):
        return [], [
            finding(
                "ui_experience_quality.screens_not_list",
                severity,
                "stage_dependency_gap",
                "ui_experience_quality screens must be a list.",
            )
        ]

    for index, item in enumerate(raw_screens):
        if not isinstance(item, dict):
            findings.append(
                finding(
                    "ui_experience_quality.screen_not_mapping",
                    severity,
                    "stage_dependency_gap",
                    "Each UI quality screen must be a mapping.",
                    object_id=f"screen[{index}]",
                )
            )
            continue
        screen = normalize_screen(item, index, root, default_stage)
        screens.append(screen)
        findings.extend(evaluate_screen(item, screen, severity))

    ids = [str(item["object_id"]) for item in screens if item.get("object_id") and not is_adapt_placeholder(item.get("object_id"))]
    duplicate_ids = {object_id for object_id, count in Counter(ids).items() if count > 1}
    for object_id in sorted(duplicate_ids):
        findings.append(
            finding(
                "ui_experience_quality.duplicate_object_id",
                severity,
                "missing_object_trace",
                "UI quality object_id is declared more than once.",
                object_id=object_id,
            )
        )

    return screens, findings


def collect_evidence_refs(root: Path, screens: list[dict[str, Any]]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for screen in screens:
        object_id = screen.get("object_id")
        for field, kind in LOCAL_REF_FIELDS.items():
            value = screen.get(field)
            values = [value] if isinstance(value, str) else string_list(value)
            for ref in values:
                text, safe, exists, status = path_status(root, ref)
                refs.append(
                    {
                        "object_id": object_id,
                        "kind": kind,
                        "field": field,
                        "ref": text,
                        "safe": safe,
                        "exists": exists,
                        "reference_status": status,
                    }
                )
        for item in screen.get("screenshot_sets") or []:
            refs.append(
                {
                    "object_id": object_id,
                    "kind": "screenshot",
                    "field": "screenshot_sets",
                    "ref": item.get("path"),
                    "safe": item.get("safe"),
                    "exists": item.get("exists"),
                    "reference_status": item.get("reference_status"),
                }
            )
    return [item for item in refs if item.get("ref")]


def reason_code_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    return {code: sum(1 for item in findings if item.get("reason_code") == code) for code in REASON_ORDER}


def build_report(
    *,
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
    declaration_path: Path,
    declaration_source: str,
) -> dict[str, Any]:
    generated_at = utc_now_text()
    declaration = load_yaml_mapping(declaration_path)
    enabled = bool_value(declaration.get("enabled"), default=False)
    ui_quality_declared = bool_value(declaration.get("ui_quality_declared"), default=enabled)
    default_stage = str(declaration.get("design_stage") or "concept_exploration").strip()
    if default_stage not in ALLOWED_STAGES:
        default_stage = "concept_exploration"
    severity = review_severity(profile, root, naos_root)
    raw_screens = declaration.get("screens") or []
    screens, findings = evaluate_screens(raw_screens, root, severity, default_stage) if enabled else ([], [])

    if enabled:
        for field in sorted(TOOL_AUTHORITY_FIELDS):
            if bool_value(declaration.get(field), default=False):
                findings.append(
                    finding(
                        f"ui_experience_quality.{field}",
                        severity,
                        "mcp_or_tool_mutation_attempt",
                        f"Declaration sets {field} true, which is outside this capability boundary.",
                    )
                )

    evidence_refs = collect_evidence_refs(root, screens)
    stage_counts = Counter(str(item.get("design_stage") or "unknown") for item in screens)
    summary = finding_counts(findings)
    summary.update(
        {
            "enabled": 1 if enabled else 0,
            "ui_quality_declared": 1 if ui_quality_declared else 0,
            "screens": len(screens),
            "evidence_refs": len(evidence_refs),
            "evidence_refs_missing": sum(1 for item in evidence_refs if item.get("reference_status") in {"missing", "unsafe_path", "missing_or_placeholder"}),
            "screens_with_fr_refs": sum(1 for item in screens if item.get("fr_refs")),
            "screens_with_task_refs": sum(1 for item in screens if item.get("task_refs")),
            "screens_with_accessibility_refs": sum(1 for item in screens if item.get("accessibility_evidence_refs")),
            "screens_with_human_review": sum(1 for item in screens if as_mapping(item.get("human_design_review")).get("disposition")),
            "assured_blocking_enabled": 0,
        }
    )

    if not enabled:
        status = "not_configured"
        human_review_required = False
    elif findings:
        status = status_from_counts(summary)
        human_review_required = True
    else:
        status = "pass"
        human_review_required = any(bool_value(item.get("human_review_required"), default=False) for item in screens)

    known_gaps = string_list(declaration.get("known_gaps"))
    if not enabled:
        known_gaps = list(dict.fromkeys(known_gaps + ["ui_experience_quality_not_enabled"]))
    else:
        known_gaps = list(dict.fromkeys(known_gaps + ["ui_quality_not_proven", "design_tools_not_inspected"]))

    not_claimed = list(dict.fromkeys(string_list(declaration.get("not_claimed")) + NOT_CLAIMED))
    residual_risks = list(dict.fromkeys(string_list(declaration.get("residual_risks")) + (RESIDUAL_RISKS if enabled else [])))

    return {
        "schema": REPORT_SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "deterministic": True,
        "declaration_path": relative_path(declaration_path, root),
        "declaration_source": declaration_source,
        "declaration_hash": safe_digest(declaration_path),
        "enabled": enabled,
        "ui_quality_declared": ui_quality_declared,
        "design_stage": default_stage,
        "runtime_enabled": False,
        "mcp_allowed": False,
        "figma_api_allowed": False,
        "browser_automation_allowed": False,
        "design_tool_calls_allowed": False,
        "external_generator_authority": False,
        "model_judgement_authority": False,
        "tool_mutation_allowed": False,
        "capability_maturity": {
            "current": str(declaration.get("capability_maturity") or "L1"),
            "assured_blocking_enabled": False,
            "blocking_requires_l3_plus_and_gate_wiring": True,
        },
        "profile_posture": as_mapping(declaration.get("profile_posture")),
        "stage_counts": dict(stage_counts),
        "screens": screens,
        "evidence_refs": evidence_refs,
        "findings": findings,
        "reason_code_counts": reason_code_counts(findings),
        "known_gaps": known_gaps,
        "residual_risks": residual_risks,
        "limitations": LIMITATIONS,
        "not_claimed": not_claimed,
        "human_review_required": human_review_required,
        "generated_by": build_generated_by(root, generated_at=generated_at),
        "summary": summary,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Review local UI experience quality evidence declarations.")
    parser.add_argument("project", nargs="?", default=".", help="Project root to inspect.")
    parser.add_argument("--profile", default=None, help="NAOS profile.")
    parser.add_argument("--naos-root", default=None, help="NAOS root directory.")
    parser.add_argument("--policy", default=None, help="Optional policy file.")
    parser.add_argument("--ui-experience-quality", default=None, help="Explicit UI experience quality YAML declaration.")
    parser.add_argument("--output", default=None, help="Output report path.")
    parser.add_argument("--json", action="store_true", help="Print JSON report to stdout.")
    parser.add_argument("--strict", action="store_true", help="Use strict exit-code behavior.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.project).resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    profile = normalize_profile(args.profile, policy)
    naos_root = args.naos_root or default_naos_root(policy)
    declaration_path, declaration_source = resolve_declaration_path(
        root,
        naos_root,
        policy,
        explicit=args.ui_experience_quality,
    )
    report = build_report(
        root=root,
        naos_root=naos_root,
        profile=profile,
        policy=policy,
        declaration_path=declaration_path,
        declaration_source=declaration_source,
    )

    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "ui_experience_quality_report")
    write_report(output, report)
    if args.json or output is None:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"NAOS UI experience quality: {report['status']} ({report['summary']['total_findings']} findings, output: {output})")
    return exit_code_for_summary(profile, report.get("summary", {}), policy, strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
