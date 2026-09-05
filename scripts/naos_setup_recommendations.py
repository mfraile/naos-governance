#!/usr/bin/env python3
"""Generate deterministic adopter setup recommendations from a module catalog."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
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

_REPOSITORY_INTELLIGENCE_IMPORT_ERROR: ImportError | None = None
try:  # Kit checkout or installed console surface.
    from naos_repository_intelligence import (  # noqa: E402
        RepositoryIntelligenceError,
        build_plan as build_repository_intelligence_plan,
        repository_intelligence_status,
        resolve_rules_path as resolve_repository_intelligence_rules,
    )
except ImportError as exc:
    # Generated project helpers intentionally delegate to the installed command.
    # Importing the packaged engine here would mix it with the generated project's
    # top-level ``naos_policy`` module and resolve kit schemas from the wrong root.
    _REPOSITORY_INTELLIGENCE_IMPORT_ERROR = exc
    RepositoryIntelligenceError = RuntimeError  # type: ignore[misc,assignment]
    build_repository_intelligence_plan = None  # type: ignore[assignment]
    repository_intelligence_status = None  # type: ignore[assignment]
    resolve_repository_intelligence_rules = None  # type: ignore[assignment]


RECOMMENDATIONS = {
    "configured",
    "recommended",
    "optional",
    "defer",
    "readiness_only",
    "experimental",
    "not_configured",
    "disabled",
    "not_applicable",
    "unknown",
}
ADVANCED_READINESS = {
    "optional_similarity_layer",
    "structured_substrate_readiness",
    "advanced_experimental_tracks",
}
PROFILE_ORDER = {
    "quickstart": 0,
    "lite": 1,
    "standard": 2,
    "assured": 3,
}


def utc_now_text() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping: {path}")
    return data


def default_catalog_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "setup_module_catalog.yaml"


def capability_contract_registry(root: Path, naos_root: str) -> tuple[set[str], bool]:
    """Return known bundled, installable-template, and adopter capability ids.

    Generated Quickstart projects intentionally may not carry capability cards.
    The boolean distinguishes that not-configured state from a configured but
    empty or malformed registry. Adopter-local cards extend rather than replace
    bundled ids.
    """
    directories = [
        kit_root() / "capabilities",
        kit_root() / "templates" / "setup-modules" / "capabilities",
        root / "capabilities",
        root / naos_root / "capabilities",
    ]
    contract_ids: set[str] = set()
    contract_files_found = False
    visited: set[Path] = set()
    for directory in directories:
        resolved = directory.resolve()
        if resolved in visited or not directory.is_dir():
            continue
        visited.add(resolved)
        for path in sorted(directory.glob("*.yaml")):
            if path.name.startswith("_"):
                continue
            contract_files_found = True
            try:
                data = load_yaml(path)
            except (OSError, ValueError, yaml.YAMLError):
                continue
            capability_id = data.get("id")
            if isinstance(capability_id, str) and capability_id.strip():
                contract_ids.add(capability_id.strip())
    return contract_ids, contract_files_found


def resolve_catalog_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None = None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("setup_module_catalog") or "setup_module_catalog.yaml")
    project_catalog = root / naos_root / filename
    if project_catalog.exists():
        return project_catalog, "project"
    return default_catalog_template(), "template"


def as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if value:
        return [str(value)]
    return []


def profile_list(module: dict[str, Any], profile: str, key: str) -> list[str]:
    """Return a module list with an explicit selected-profile override."""

    overrides = module.get("profile_overrides")
    if isinstance(overrides, dict):
        profile_override = overrides.get(profile)
        if isinstance(profile_override, dict) and key in profile_override:
            return as_list(profile_override.get(key))
    return as_list(module.get(key))


def dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def any_files(root: Path, patterns: list[str]) -> bool:
    for pattern in patterns:
        try:
            if any(root.glob(pattern)):
                return True
        except (OSError, ValueError):
            continue
    return False


def detect_project_signals(root: Path, naos_root: str, profile: str) -> dict[str, Any]:
    has_specs = any_files(root, ["specs/*.md", "requirements/**/*.md"])
    has_docs = any_files(root, ["README.md", "docs/**/*.md"])
    has_tests = any_files(root, ["tests/test_*.py", "tests/**/*.py", "test/**/*.py"])
    has_python = any_files(root, ["*.py", "src/**/*.py", "app/**/*.py", "scripts/**/*.py"])
    has_ai_surfaces = any_files(
        root,
        [
            "templates/agents/*.md",
            "templates/skills/*/SKILL.md",
            "templates/instructions/*.md",
            "templates/prompts/*.md",
            ".github/instructions/*.md",
            ".github/prompts/*.md",
            ".github/copilot-instructions.md",
            ".ai/*",
            "AGENTS.md",
            "CLAUDE.md",
            "GEMINI.md",
        ],
    )
    has_ci = any_files(root, [".github/workflows/*.yml", ".github/workflows/*.yaml"])
    has_naos_state = (root / naos_root).is_dir()
    brownfield_like = bool(has_python or has_tests or has_specs or has_docs or has_ci)
    greenfield_like = not brownfield_like
    regulated_posture_requested = profile == "assured"
    return {
        "selected_profile": profile,
        "has_specs": has_specs,
        "has_docs": has_docs,
        "has_tests": has_tests,
        "has_python": has_python,
        "has_ai_surfaces": has_ai_surfaces,
        "has_ci": has_ci,
        "has_naos_state": has_naos_state,
        "brownfield_like": brownfield_like,
        "greenfield_like": greenfield_like,
        "regulated_posture_requested": regulated_posture_requested,
        "matched_signals": sorted(
            signal
            for signal, enabled in {
                "has_specs": has_specs,
                "has_docs": has_docs,
                "has_tests": has_tests,
                "has_python": has_python,
                "has_ai_surfaces": has_ai_surfaces,
                "has_ci": has_ci,
                "has_naos_state": has_naos_state,
                "brownfield_like": brownfield_like,
                "greenfield_like": greenfield_like,
                "regulated_posture_requested": regulated_posture_requested,
                "selected_profile": True,
            }.items()
            if enabled
        ),
    }


def build_repository_intelligence_guidance(
    root: Path,
    naos_root: str,
    profile: str,
    required_usage_scopes: list[str] | tuple[str, ...] = (),
) -> dict[str, Any]:
    """Inspect lifecycle state first, planning only when no generation is configured."""

    if (
        build_repository_intelligence_plan is None
        or repository_intelligence_status is None
        or resolve_repository_intelligence_rules is None
    ):
        detail = (
            str(_REPOSITORY_INTELLIGENCE_IMPORT_ERROR)
            if _REPOSITORY_INTELLIGENCE_IMPORT_ERROR is not None
            else "repository-intelligence runtime is unavailable"
        )
        return {
            "applicable": False,
            "applicability_status": "undetermined",
            "lifecycle_status": "blocked",
            "continuation_allowed": False,
            "selected_profile": profile,
            "engine_execution": "refused",
            "plan_status": "blocked_prerequisite",
            "recommendation": "blocked_prerequisite",
            "required_usage_scopes": sorted(
                {str(item) for item in required_usage_scopes if str(item).strip()}
            ),
            "usage_scope_satisfied": False,
            "error": detail,
            "installation": {
                "automatic": False,
                "explicit_digest_confirmation_required": False,
                "capability_enrollment_required": False,
                "transaction_and_recovery_required": True,
                "source_artifacts_remain_authoritative": True,
                "next_action": (
                    "Run the installed `naos repository-intelligence plan .` "
                    "command; the low-noise generated project surface does not "
                    "duplicate this operational runtime."
                ),
            },
            "not_claimed": [
                "repository-intelligence applicability",
                "activation readiness",
            ],
        }

    bundle_parent: Path | None = None
    try:
        required_scopes = sorted(
            {str(item) for item in required_usage_scopes if str(item).strip()}
        )
        status_report = repository_intelligence_status(root, naos_root=naos_root)
        lifecycle = str(status_report.get("status") or "invalid")
        active_context = status_report.get("active")
        if not isinstance(active_context, dict):
            active_context = {}

        if lifecycle == "validated_current":
            active_generation = active_context.get("generation")
            if not isinstance(active_generation, dict):
                raise RepositoryIntelligenceError(
                    "Validated repository intelligence lacks generation metadata."
                )
            authorized_scopes = {
                str(item) for item in (active_context.get("usage_scope") or []) if str(item).strip()
            }
            missing_scopes = sorted(set(required_scopes) - authorized_scopes)
            active_profile = str(active_generation.get("profile") or "quickstart")
            profile_satisfied = PROFILE_ORDER.get(active_profile, -1) >= PROFILE_ORDER.get(profile, -1)
            continuation_allowed = profile_satisfied and not missing_scopes
            lifecycle_status = "validated_current" if continuation_allowed else "refresh_required"
            graph = (active_context.get("components") or {}).get("networkx_graphml") or {}
            graph_basis = graph.get("utility_evidence") or {}
            graph_eligible = bool(graph_basis.get("adds_beyond_direct_lookup"))
            if not profile_satisfied:
                next_action = (
                    f"Refresh and validate repository intelligence at profile {profile}; "
                    f"the active generation was built for {active_profile}."
                )
            elif missing_scopes:
                next_action = (
                    "Refresh and validate repository intelligence with the required ongoing-use scopes: "
                    + ", ".join(missing_scopes)
                )
            else:
                next_action = "Reuse the validated current generation; no new activation is required."
            return {
                "applicable": True,
                "applicability_status": "applicable",
                "lifecycle_status": lifecycle_status,
                "continuation_allowed": continuation_allowed,
                "selected_profile": profile,
                "engine_execution": "completed",
                "plan_status": "active" if continuation_allowed else "refresh_required",
                "effective_source_sha256": active_generation.get("effective_source_sha256"),
                "coverage": active_context.get("coverage") or {},
                "profile_gate": {
                    "requested_profile": profile,
                    "active_profile": active_profile,
                    "satisfied": profile_satisfied,
                },
                "maturity": {
                    "status": "not_an_activation_authority",
                    "authorization_effect": "none",
                },
                "maturity_authorization_effect": "none",
                "provenance_status": "valid",
                "recommendation": (
                    "use_validated_current_generation"
                    if continuation_allowed
                    else "refresh_and_revalidate"
                ),
                "components": active_context.get("components") or {},
                "graph_eligibility": {
                    "eligible": graph_eligible,
                    "basis": graph_basis,
                    "selection_status": graph.get("status"),
                    "next_action": (
                        "Use the selected, validated GraphML component as candidate navigation evidence."
                        if graph.get("selected")
                        else "Continue with the validated SQLite/FTS baseline."
                    ),
                    "effectiveness_over_sqlite_fts": "untested",
                },
                "required_usage_scopes": required_scopes,
                "authorized_usage_scopes": sorted(authorized_scopes),
                "usage_scope_satisfied": not missing_scopes,
                "active_context": active_context,
                "installation": {
                    "automatic": False,
                    "explicit_digest_confirmation_required": not continuation_allowed,
                    "capability_enrollment_required": False,
                    "transaction_and_recovery_required": True,
                    "source_artifacts_remain_authoritative": True,
                    "next_action": next_action,
                },
                "effectiveness_hypothesis": {
                    "status": "not_yet_compared",
                    "claim": "No effectiveness advantage is inferred from activation alone.",
                },
                "finding_ids": [],
                "not_claimed": active_context.get("not_claimed") or [],
            }

        if lifecycle == "stale":
            return {
                "applicable": True,
                "applicability_status": "applicable",
                "lifecycle_status": "refresh_required",
                "continuation_allowed": False,
                "selected_profile": profile,
                "engine_execution": "completed",
                "plan_status": "refresh_required",
                "recommendation": "refresh_and_revalidate",
                "required_usage_scopes": required_scopes,
                "usage_scope_satisfied": False,
                "active_context": active_context,
                "installation": {
                    "automatic": False,
                    "explicit_digest_confirmation_required": True,
                    "capability_enrollment_required": False,
                    "transaction_and_recovery_required": True,
                    "source_artifacts_remain_authoritative": True,
                    "next_action": "Prepare, review, apply, and validate a refresh plan before continuing onboarding.",
                },
                "not_claimed": ["current repository context", "activation readiness"],
            }

        if lifecycle == "recovery_required":
            return {
                "applicable": True,
                "applicability_status": "applicable",
                "lifecycle_status": "recovery_required",
                "continuation_allowed": False,
                "selected_profile": profile,
                "engine_execution": "completed",
                "plan_status": "recovery_required",
                "recommendation": "recover_then_revalidate",
                "required_usage_scopes": required_scopes,
                "usage_scope_satisfied": False,
                "active_context": active_context,
                "installation": {
                    "automatic": False,
                    "explicit_digest_confirmation_required": False,
                    "capability_enrollment_required": False,
                    "transaction_and_recovery_required": True,
                    "source_artifacts_remain_authoritative": True,
                    "next_action": "Run explicit repository-intelligence recovery, then validate current source before onboarding.",
                },
                "not_claimed": ["recoverable active context", "activation readiness"],
            }

        if lifecycle == "invalid":
            return {
                "applicable": False,
                "applicability_status": "undetermined",
                "lifecycle_status": "blocked",
                "continuation_allowed": False,
                "selected_profile": profile,
                "engine_execution": "refused",
                "plan_status": "blocked_prerequisite",
                "recommendation": "blocked_prerequisite",
                "required_usage_scopes": required_scopes,
                "usage_scope_satisfied": False,
                "error": str(active_context.get("error") or "Repository-intelligence state is invalid."),
                "installation": {
                    "automatic": False,
                    "explicit_digest_confirmation_required": False,
                    "capability_enrollment_required": False,
                    "transaction_and_recovery_required": True,
                    "source_artifacts_remain_authoritative": True,
                    "next_action": "Repair the exact invalid operation-owned state before onboarding.",
                },
                "not_claimed": ["repository-intelligence applicability", "activation readiness"],
            }

        if lifecycle != "not_configured":
            raise RepositoryIntelligenceError(
                f"Unsupported repository-intelligence lifecycle status: {lifecycle}."
            )

        bundle_parent = Path(
            tempfile.mkdtemp(prefix="naos-setup-repository-intelligence-")
        ).resolve()
        rules_path, rules_source = resolve_repository_intelligence_rules(root, naos_root)
        plan = build_repository_intelligence_plan(
            root,
            profile=profile,
            naos_root=naos_root,
            rules_path=rules_path,
            rules_source=rules_source,
            purpose="brownfield-onboarding",
            component_mode="auto",
            bundle_dir=bundle_parent / "bundle",
        )
        control = plan["control"]
        components = control["components"]
        graph = components["networkx_graphml"]
        graph_eligible = bool(graph["utility_evidence"]["adds_beyond_direct_lookup"])
        status = str(plan["status"])
        candidate = status != "not_applicable"
        recommendation = {
            "not_applicable": "no_install_recommended",
            "blocked_prerequisite": "blocked_prerequisite",
            "enrollment_required": "capability_enrollment_then_activation",
            "confirmation_required": "digest_review_and_activation",
        }[status]
        if status == "enrollment_required":
            next_action = (
                f"Run `naos repository-intelligence plan . --profile {profile}`, review its exact evidence, "
                "then use the printed digest with the separate `enroll` command. Re-plan before apply."
            )
        elif status == "confirmation_required":
            next_action = (
                f"Run `naos repository-intelligence plan . --profile {profile}`, review its exact evidence, "
                "then use the printed digest with the separate `apply` command."
            )
        elif status == "blocked_prerequisite":
            next_action = "Resolve the exact blocking findings before enrollment or activation."
        else:
            next_action = "Continue ordinary setup; executed inspection found no multi-surface indexing need."
        graph_action = (
            "Graph mode is eligible for digest review; compare it with baseline mode before claiming benefit."
            if graph_eligible
            else "Graph mode is not applicable to the executed relationship model."
        )
        if graph_eligible and graph.get("status") in {
            "prerequisite_missing",
            "available_prerequisite_missing",
        }:
            graph_action = (
                "Graph mode is evidence-eligible but the exact optional runtime is absent; install "
                "`naos-governance[repository-intelligence]`, then re-run the plan."
            )
        return {
            "applicable": candidate,
            "applicability_status": (
                "not_applicable" if status == "not_applicable" else "applicable"
            ),
            "lifecycle_status": (
                "not_applicable" if status == "not_applicable" else "activation_required"
            ),
            "continuation_allowed": status == "not_applicable",
            "selected_profile": profile,
            "engine_execution": "completed",
            "plan_status": status,
            "plan_id": plan["plan_id"],
            "plan_sha256": plan["plan_sha256"],
            "effective_source_sha256": control["effective_source_sha256"],
            "purpose": control["purpose"],
            "component_mode": control["component_mode"],
            "rules_sha256": control["rules"]["sha256"],
            "coverage": control["coverage"],
            "profile_gate": control["profile_gate"],
            "maturity": control["maturity"],
            "maturity_authorization_effect": "none",
            "provenance_status": control["provenance_gate"]["status"],
            "recommendation": recommendation,
            "required_usage_scopes": required_scopes,
            "authorized_usage_scopes": [],
            "usage_scope_satisfied": status == "not_applicable",
            "active_context": None,
            "components": components,
            "graph_eligibility": {
                "eligible": graph_eligible,
                "basis": graph["utility_evidence"],
                "selection_status": graph.get("status"),
                "next_action": graph_action,
                "effectiveness_over_sqlite_fts": "untested",
            },
            "installation": {
                "automatic": False,
                "explicit_digest_confirmation_required": candidate,
                "capability_enrollment_required": status == "enrollment_required",
                "transaction_and_recovery_required": candidate,
                "source_artifacts_remain_authoritative": True,
                "next_action": next_action,
            },
            "effectiveness_hypothesis": plan["effectiveness_hypothesis"],
            "finding_ids": sorted(str(item.get("id")) for item in plan["findings"]),
            "not_claimed": control["not_claimed"],
        }
    except (RepositoryIntelligenceError, OSError, RuntimeError, ValueError) as exc:
        return {
            "applicable": False,
            "applicability_status": "undetermined",
            "lifecycle_status": "blocked",
            "continuation_allowed": False,
            "selected_profile": profile,
            "engine_execution": "refused",
            "plan_status": "blocked_prerequisite",
            "recommendation": "blocked_prerequisite",
            "required_usage_scopes": sorted(
                {str(item) for item in required_usage_scopes if str(item).strip()}
            ),
            "usage_scope_satisfied": False,
            "error": str(exc),
            "installation": {
                "automatic": False,
                "explicit_digest_confirmation_required": False,
                "capability_enrollment_required": False,
                "transaction_and_recovery_required": True,
                "source_artifacts_remain_authoritative": True,
                "next_action": "Resolve the exact engine prerequisite and run the diagnostic again.",
            },
            "not_claimed": ["repository-intelligence applicability", "activation readiness"],
        }
    finally:
        if bundle_parent is not None:
            expected_parent = Path(tempfile.gettempdir()).resolve()
            if (
                bundle_parent.parent == expected_parent
                and bundle_parent.name.startswith("naos-setup-repository-intelligence-")
                and bundle_parent.exists()
                and bundle_parent.is_dir()
                and not bundle_parent.is_symlink()
            ):
                shutil.rmtree(bundle_parent)


def build_profile_guidance(profile: str, signals: dict[str, Any]) -> dict[str, Any]:
    target = "quickstart"
    rationale: list[str] = []

    if signals.get("regulated_posture_requested"):
        target = "assured"
        rationale.append("The selected profile requests an evidence-heavy regulated posture.")
    elif signals.get("has_ci") and signals.get("has_ai_surfaces") and (signals.get("has_tests") or signals.get("has_specs")):
        target = "standard"
        rationale.append("CI, AI governance surfaces, and specs or tests are present, which fits governed team review.")
    elif signals.get("brownfield_like") or signals.get("has_ai_surfaces") or signals.get("has_python") or signals.get("has_tests"):
        target = "lite"
        rationale.append("Existing source, tests, specs, CI, or AI surfaces suggest more than quickstart orientation.")
    else:
        rationale.append("No brownfield source, tests, specs, CI, or AI surfaces were detected; quickstart remains proportionate.")

    selected_rank = PROFILE_ORDER.get(profile, 0)
    target_rank = PROFILE_ORDER.get(target, 0)
    if selected_rank >= target_rank:
        recommendation = "stay_on_profile"
        recommended_profile = profile
        if profile != target:
            rationale.append(f"The selected profile already meets or exceeds the detected baseline of {target}.")
    else:
        recommendation = f"consider_{target}"
        recommended_profile = target

    return {
        "selected_profile": profile,
        "recommended_action": recommendation,
        "recommended_profile": recommended_profile,
        "detected_baseline_profile": target,
        "rationale": rationale,
        "matched_signals": signals.get("matched_signals") or [],
        "automatic_upgrade": False,
        "human_review_required": recommendation != "stay_on_profile" or profile in {"standard", "assured"},
        "not_claimed": [
            "automatic profile upgrade",
            "project readiness approval",
            "compliance determination",
            "maturity promotion",
        ],
    }


def normalize_recommendation(value: Any) -> str:
    text = str(value or "optional").strip().lower()
    return text if text in RECOMMENDATIONS else "unknown"


def recommendation_for_module(module: dict[str, Any], profile: str, signals: dict[str, Any]) -> tuple[str, list[str]]:
    profile_default = module.get("profile_default") if isinstance(module.get("profile_default"), dict) else {}
    recommendation = normalize_recommendation(profile_default.get(profile))
    module_id = str(module.get("id") or "")
    module_status = str(module.get("status") or "active")
    signal_matches = [signal for signal in as_list(module.get("project_signals")) if bool(signals.get(signal))]

    if profile != "quickstart" and recommendation in {"optional", "defer"} and signal_matches and module_status == "active":
        recommendation = "recommended"

    if module_status == "experimental" and recommendation == "recommended":
        recommendation = "experimental"
    if module_status == "readiness_only" and recommendation == "recommended":
        recommendation = "readiness_only"
    if module_id in ADVANCED_READINESS and recommendation == "recommended":
        recommendation = "readiness_only"

    return recommendation, signal_matches


def action_allowed_for_profile(action: dict[str, Any], profile: str) -> bool:
    profiles = as_list(action.get("profiles"))
    return not profiles or profile in profiles


def safe_destination_path(root: Path, destination: Any) -> Path | None:
    text = str(destination or "").strip()
    if not text:
        return None
    rel = Path(text)
    if rel.is_absolute() or ".." in rel.parts or rel == Path(".") or (rel.parts and rel.parts[0] == ".git"):
        return None
    try:
        dest = (root / rel).resolve()
        root_resolved = root.resolve()
    except OSError:
        return None
    if root_resolved not in (dest, *dest.parents):
        return None
    return dest


def installed_action_destinations(root: Path, module: dict[str, Any], profile: str) -> tuple[list[str], list[str]]:
    """Return present and expected destination paths for applicable install actions."""
    present: list[str] = []
    expected: list[str] = []
    for action in [item for item in module.get("install_actions") or [] if isinstance(item, dict)]:
        if not action_allowed_for_profile(action, profile):
            continue
        destination = str(action.get("destination") or "").strip()
        dest_path = safe_destination_path(root, destination)
        if dest_path is None:
            continue
        expected.append(destination)
        if dest_path.exists():
            present.append(destination)
    return dedupe(present), dedupe(expected)


def module_report(
    module: dict[str, Any],
    profile: str,
    recommendation: str,
    signal_matches: list[str],
    configured_destinations: list[str] | None = None,
    expected_destinations: list[str] | None = None,
) -> dict[str, Any]:
    configured = configured_destinations or []
    expected = expected_destinations or []
    if not bool(module.get("installable")) or not expected:
        installation_status = "not_installable"
    elif set(expected) <= set(configured):
        installation_status = "present_unverified"
    elif configured:
        installation_status = "partial_unverified"
    else:
        installation_status = "absent"
    return {
        "module_id": str(module.get("id") or "unknown_module"),
        "name": str(module.get("name") or module.get("id") or "Unknown Module"),
        "category": str(module.get("category") or "uncategorized"),
        "status": str(module.get("status") or "unknown"),
        "recommendation": recommendation,
        "rationale": str(module.get("why_recommended") or ""),
        "benefit": str(module.get("benefit") or ""),
        "warning": str(module.get("warning_if_enabled_too_early") or ""),
        "consequence_if_deferred": str(module.get("consequence_if_deferred") or ""),
        "prerequisites": profile_list(module, profile, "prerequisites"),
        "evidence_outputs": profile_list(module, profile, "evidence_outputs"),
        "commands": profile_list(module, profile, "commands"),
        "dependency_posture": str(module.get("dependency_posture") or ""),
        "noise_risk": str(module.get("noise_risk") or "unknown"),
        "human_review_boundary": str(module.get("human_review_boundary") or ""),
        "not_claimed": as_list(module.get("not_claimed")),
        "related_capabilities": as_list(module.get("related_capabilities")),
        "related_reports": profile_list(module, profile, "related_reports"),
        "related_docs": profile_list(module, profile, "related_docs"),
        "next_actions": profile_list(module, profile, "next_actions"),
        "installable": bool(module.get("installable", False)),
        "requires_confirmation": bool(module.get("requires_confirmation", False)),
        "installation_status": installation_status,
        "not_addable_reason": str(module.get("not_addable_reason") or ""),
        "post_install_next_actions": profile_list(
            module, profile, "post_install_next_actions"
        ),
        "matched_project_signals": signal_matches,
        "configured_destinations": configured,
        "expected_destinations": expected,
    }


def validate_catalog(
    catalog: dict[str, Any],
    known_capability_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    schema_path = kit_root() / "schemas" / "naos" / "setup_module_catalog.schema.json"
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
    except Exception as exc:
        return [
            {
                "id": "setup_module_catalog_schema",
                "severity": "blocking",
                "status": "invalid_catalog_schema",
                "message": f"setup module catalog schema is unavailable or invalid: {exc}",
            }
        ]
    schema_errors = sorted(
        Draft202012Validator(schema).iter_errors(catalog),
        key=lambda item: [str(part) for part in item.absolute_path],
    )
    for index, error in enumerate(schema_errors, start=1):
        pointer = "/" + "/".join(str(part) for part in error.absolute_path)
        findings.append(
            {
                "id": f"setup_module_catalog_schema_{index:03d}",
                "severity": "blocking",
                "status": "invalid_catalog",
                "message": f"{pointer or '/'}: {error.message}",
            }
        )
    modules = catalog.get("modules")
    if not isinstance(modules, list):
        return [
            {
                "id": "setup_module_catalog",
                "severity": "advisory",
                "status": "invalid_catalog",
                "message": "setup module catalog must contain a modules list.",
            }
        ]
    seen: set[str] = set()
    required = {
        "id",
        "name",
        "category",
        "status",
        "profile_default",
        "recommended_profiles",
        "project_signals",
        "why_recommended",
        "benefit",
        "prerequisites",
        "evidence_outputs",
        "commands",
        "warning_if_enabled_too_early",
        "consequence_if_deferred",
        "dependency_posture",
        "noise_risk",
        "human_review_boundary",
        "not_claimed",
        "related_capabilities",
        "related_reports",
        "related_docs",
        "next_actions",
        "installable",
        "install_actions",
        "requires_confirmation",
        "not_addable_reason",
        "post_install_next_actions",
    }
    for index, module in enumerate(modules, start=1):
        if not isinstance(module, dict):
            findings.append(
                {
                    "id": f"module_{index}",
                    "severity": "advisory",
                    "status": "invalid_module",
                    "message": "Module catalog entry must be a mapping.",
                }
            )
            continue
        module_id = str(module.get("id") or f"module_{index}")
        missing = sorted(required - set(module))
        if missing:
            findings.append(
                {
                    "id": module_id,
                    "severity": "advisory",
                    "status": "missing_catalog_fields",
                    "message": f"Module catalog entry is missing fields: {', '.join(missing)}.",
                }
            )
        if module_id in seen:
            findings.append(
                {
                    "id": module_id,
                    "severity": "advisory",
                    "status": "duplicate_module_id",
                    "message": "Duplicate setup module id.",
                }
            )
        seen.add(module_id)
        if known_capability_ids is not None:
            for reference in as_list(module.get("related_capabilities")):
                if (
                    isinstance(reference, str)
                    and reference.startswith("CAP-")
                    and reference not in known_capability_ids
                ):
                    findings.append(
                        {
                            "id": f"{module_id}.related_capabilities.{reference}",
                            "severity": "advisory",
                            "status": "unknown_capability_reference",
                            "message": (
                                "Module catalog related_capabilities reference does not "
                                "resolve to a bundled, installable-template, kit-root, "
                                f"or adopter-local capability card: {reference}."
                            ),
                        }
                    )
    return findings


def bucket_modules(modules: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    buckets = {
        "configured_modules": [],
        "recommended_modules": [],
        "optional_modules": [],
        "deferred_modules": [],
        "not_configured_modules": [],
    }
    for module in modules:
        recommendation = module.get("recommendation")
        if recommendation == "configured":
            buckets["configured_modules"].append(module)
        elif recommendation == "recommended":
            buckets["recommended_modules"].append(module)
        elif recommendation == "optional":
            buckets["optional_modules"].append(module)
        elif recommendation == "not_configured":
            buckets["not_configured_modules"].append(module)
        else:
            buckets["deferred_modules"].append(module)
    return buckets


def aggregate_text(modules: list[dict[str, Any]], key: str) -> list[str]:
    values: list[str] = []
    for module in modules:
        if key in {"prerequisites", "next_actions"}:
            values.extend(as_list(module.get(key)))
        elif module.get(key):
            values.append(str(module.get(key)))
    return dedupe(values)


def build_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    catalog_path: Path,
    catalog_source: str,
) -> dict[str, Any]:
    catalog = load_yaml(catalog_path)
    capability_ids, capability_registry_available = capability_contract_registry(
        root, naos_root
    )
    capability_reference_validation = {
        "status": "validated" if capability_registry_available else "not_configured",
        "contract_ids": len(capability_ids),
        "scope": "bundled, installable-template, kit-root, and adopter-local capability cards",
    }
    policy_meta = policy.get("_meta", {})
    signals = detect_project_signals(root, naos_root, profile)
    profile_guidance = build_profile_guidance(profile, signals)
    repository_intelligence = build_repository_intelligence_guidance(
        root, naos_root, profile
    )
    if catalog.get("enabled") is False:
        return {
            "schema": "naos.setup_recommendations.v1",
            "generated_at": utc_now_text(),
            "profile": profile,
            "status": "disabled",
            "naos_root": naos_root,
            "project_root": str(root),
            "catalog": {
                "path": str(catalog_path),
                "source": catalog_source,
                "capability_reference_validation": capability_reference_validation,
            },
            "policy": {"version": policy.get("version"), "source": policy_meta.get("source"), "path": policy_meta.get("path")},
            "detected_signals": signals,
            "profile_guidance": profile_guidance,
            "repository_intelligence": repository_intelligence,
            "summary": {"modules": 0, "disabled": 1, "total_findings": 0},
            "recommended_modules": [],
            "optional_modules": [],
            "deferred_modules": [],
            "configured_modules": [],
            "not_configured_modules": [],
            "warnings": [],
            "prerequisites": [],
            "next_actions": [],
            "findings": [],
            "limitations": as_list(catalog.get("limitations")),
            "human_review_required": False,
        }

    catalog_findings = validate_catalog(
        catalog,
        capability_ids if capability_registry_available else None,
    )
    evaluated_modules: list[dict[str, Any]] = []
    for module in [item for item in catalog.get("modules") or [] if isinstance(item, dict)]:
        recommendation, signal_matches = recommendation_for_module(module, profile, signals)
        configured_destinations, expected_destinations = installed_action_destinations(root, module, profile)
        evaluated_modules.append(
            module_report(
                module,
                profile,
                recommendation,
                signal_matches,
                configured_destinations,
                expected_destinations,
            )
        )

    buckets = bucket_modules(evaluated_modules)
    warning_modules = [
        module
        for module in evaluated_modules
        if module.get("recommendation") in {"recommended", "readiness_only", "experimental"}
        and module.get("warning")
        and str(module.get("warning")).strip().lower() not in {"none", "none; this is low-noise orientation.", "none; this is low-noise and useful in every profile."}
    ]
    warnings = dedupe([str(module["warning"]) for module in warning_modules])
    prerequisites = aggregate_text([*buckets["recommended_modules"], *buckets["deferred_modules"]], "prerequisites")
    next_actions = aggregate_text(buckets["recommended_modules"], "next_actions")
    summary = finding_counts(catalog_findings)
    rec_counts = {
        recommendation: sum(1 for module in evaluated_modules if module.get("recommendation") == recommendation)
        for recommendation in sorted(RECOMMENDATIONS)
    }
    summary.update(
        {
            "modules": len(evaluated_modules),
            "recommended": rec_counts.get("recommended", 0),
            "configured": rec_counts.get("configured", 0),
            "optional": rec_counts.get("optional", 0),
            "defer": rec_counts.get("defer", 0),
            "readiness_only": rec_counts.get("readiness_only", 0),
            "experimental": rec_counts.get("experimental", 0),
            "not_configured": rec_counts.get("not_configured", 0),
            "disabled": rec_counts.get("disabled", 0),
            "not_applicable": rec_counts.get("not_applicable", 0),
            "unknown": rec_counts.get("unknown", 0),
            "warnings": len(warnings),
            "advanced_readiness_modules": sum(1 for module in evaluated_modules if module.get("module_id") in ADVANCED_READINESS),
            "human_review_required": sum(1 for module in evaluated_modules if module.get("recommendation") in {"recommended", "readiness_only", "experimental"} and module.get("human_review_boundary")),
        }
    )

    return {
        "schema": "naos.setup_recommendations.v1",
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": status_from_counts(summary),
        "naos_root": naos_root,
        "project_root": str(root),
        "catalog": {
            "path": str(catalog_path),
            "source": catalog_source,
            "semantics": catalog.get("semantics") or {},
            "modules": len(evaluated_modules),
            "capability_reference_validation": capability_reference_validation,
        },
        "policy": {
            "version": policy.get("version"),
            "source": policy_meta.get("source"),
            "path": policy_meta.get("path"),
        },
        "detected_signals": signals,
        "profile_guidance": profile_guidance,
        "repository_intelligence": repository_intelligence,
        "summary": summary,
        **buckets,
        "warnings": warnings,
        "prerequisites": prerequisites,
        "next_actions": next_actions,
        "findings": catalog_findings,
        "limitations": [
            "Setup recommendations are guidance and orientation, not automatic setup.",
            "NAOS does not automatically enable modules, approve maturity, certify compliance, or guarantee project readiness.",
            "Simple project signals can miss project-specific context; humans choose final setup posture.",
            "Quickstart remains low-noise; advanced modules stay optional, deferred, experimental, or readiness-only unless explicitly implemented and configured.",
            "No model, API, network, database, daemon, or scheduler dependency is required for this report.",
        ],
        "human_review_required": bool(summary["human_review_required"] and profile in {"standard", "assured"}),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate deterministic NAOS setup recommendations.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--catalog", help="Path to setup_module_catalog.yaml.")
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument("--output")
    output_group.add_argument(
        "--no-write-preview",
        action="store_true",
        help="Print lifecycle guidance without writing a report.",
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    catalog_path, catalog_source = resolve_catalog_path(root, naos_root, policy, args.catalog)
    report = build_report(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        catalog_path=catalog_path,
        catalog_source=catalog_source,
    )
    output = (
        None
        if args.no_write_preview
        else (
            Path(args.output)
            if args.output
            else report_output_path(
                root, naos_root, policy, "setup_recommendations_report"
            )
        )
    )
    if not args.no_write_preview:
        write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        destination = (
            "not written"
            if args.no_write_preview
            else (str(output) if output else "stdout only")
        )
        print(
            "NAOS setup recommendations: "
            f"{report['status']} "
            f"({report['summary'].get('recommended', 0)} recommended, "
            f"{report['summary'].get('optional', 0)} optional, "
            f"{report['summary'].get('defer', 0) + report['summary'].get('readiness_only', 0) + report['summary'].get('experimental', 0)} deferred/readiness-only, "
            f"output: {destination})"
        )
        intelligence = report["repository_intelligence"]
        print(
            "Repository intelligence: "
            f"{intelligence['recommendation']} "
            f"(plan status: {intelligence['plan_status']}, "
            f"maturity: {(intelligence.get('maturity') or {}).get('declared_level', 'unknown')})"
        )
        if not intelligence.get("continuation_allowed"):
            next_action = str(
                (intelligence.get("installation") or {}).get("next_action") or ""
            ).strip()
            if next_action:
                print(f"Repository-intelligence next action: {next_action}")
    return exit_code_for_summary(profile, report["summary"], policy, args.strict and not is_kit_repository(root, naos_root))


if __name__ == "__main__":
    raise SystemExit(main())
