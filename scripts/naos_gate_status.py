#!/usr/bin/env python3
"""
Report NAOS gatekeeper readiness from a file-first manifest.

The script reads an adopter-project manifest at NAOS_ROOT/gatekeepers.yaml when
available. In the kit repository it falls back to the structural seed template,
so source-repo checks do not require creating a generated root naos/ directory.
This script reports required input/evidence presence, bounded declared semantic
requirements, and profile severity; it does not claim the full gate-convergence
model is automated.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_audit_log import write_audit_event  # noqa: E402
from naos_policy import (  # noqa: E402
    build_generated_by,
    effective_enforcement,
    load_policy,
    normalize_profile as normalize_policy_profile,
    report_default_path,
    resolve_operator_attribution,
)


PROFILES = ("quickstart", "lite", "standard", "assured")
BLOCKING_SEVERITIES = {"blocking"}
REQUIRED_SEVERITIES = {"required"}
SEVERITY_ORDER = {"none": 0, "advisory": 1, "warning": 2, "required": 3, "blocking": 4}
ALLOWED_TEAM_OVERRIDE_FIELDS = {"enabled", "severity", "rationale", "profile_scope", "review_required", "limitations"}
TEAM_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
TEAM_GATEKEEPER_NOT_CLAIMED = [
    "team gatekeeper config is not authentication",
    "team gatekeeper config is not authorization or access control",
    "team gatekeeper config does not prove team membership",
    "team gatekeeper config does not approve work or satisfy separation of duties",
    "team gatekeeper config does not prove compliance, certification, or release approval",
    "team gatekeeper config does not approve PR-time CI results or change CI authority boundaries",
]
TEAM_GATEKEEPER_LIMITATIONS = [
    "Team context is resolved from explicit local configuration or local operator mapping only; no identity provider is queried.",
    "Team-specific gatekeeper overrides can change enabled/severity review posture only for allowed fields.",
    "Protected invariants and ADR-0010: Control-Plane Advisory Boundaries remain binding.",
    "Unknown team context is advisory in quickstart and review-required in standard/assured when team-specific config is present.",
]


@dataclass(frozen=True)
class ManifestLocation:
    path: Path
    source: str


def kit_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_template_manifest() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "gatekeepers.yaml"


def resolve_manifest(explicit: str | None, naos_root: str) -> ManifestLocation:
    if explicit:
        path = Path(explicit)
        return ManifestLocation(path=path, source="explicit")

    project_manifest = Path(naos_root) / "gatekeepers.yaml"
    if project_manifest.exists():
        return ManifestLocation(path=project_manifest, source="project")

    template_manifest = default_template_manifest()
    return ManifestLocation(path=template_manifest, source="template")


def load_manifest(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Gatekeeper manifest not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    validate_manifest(data)
    return data


def validate_manifest(data: Any) -> None:
    """Enforce the canonical manifest shape before evaluating any gate."""
    from jsonschema import Draft202012Validator

    schema = json.loads((kit_root() / "schemas/naos/gatekeeper.schema.json").read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(data), key=lambda item: str(list(item.path)))
    if errors:
        detail = "; ".join(f"{'.'.join(map(str, item.path)) or '$'}: {item.message}" for item in errors)
        raise ValueError(f"Invalid gatekeeper manifest: {detail}")
    identifiers = [gate["id"] for gate in data["gates"]]
    duplicate = sorted({identifier for identifier in identifiers if identifiers.count(identifier) > 1})
    if duplicate:
        raise ValueError(f"Duplicate gate identifiers: {', '.join(duplicate)}")


def evaluation_scope(gates: list[dict[str, Any]]) -> dict[str, Any]:
    status = "empty" if not gates else (
        "not_applicable" if all(gate["status"] == "not_applicable" for gate in gates) else "evaluated"
    )
    return {"status": status, "selected_count": len(gates)}


def emit_input_error(exc: Exception, *, output: str | None, json_output: bool) -> int:
    error = {
        "schema": "naos.gate_input_error.v1", "status": "invalid_input",
        "errors": [str(exc)], "human_review_required": True,
        "findings": [{"id": "gate_input_invalid", "status": "invalid_input",
                      "severity": "error", "message": str(exc),
                      "human_review_required": True}],
    }
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(error, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(error, indent=2) if json_output else f"ERROR: {exc}")
    return 2


def normalize_profile(profile: str | None, policy: dict[str, Any] | None = None) -> str:
    """Resolve explicit/env profile first, then the loaded policy default."""

    policy = policy or {
        "profiles": {
            "supported": list(PROFILES),
            "default": "quickstart",
        }
    }
    return normalize_policy_profile(profile, policy)


def validate_team_id(value: str | None) -> tuple[str | None, str | None]:
    cleaned = "" if value is None else str(value).strip()
    if not cleaned:
        return None, "missing"
    if len(cleaned) > 64:
        return None, "too_long"
    if "/" in cleaned or "\\" in cleaned or ".." in cleaned:
        return None, "path_like_or_traversal"
    if any(ord(ch) < 32 for ch in cleaned):
        return None, "control_character"
    if not TEAM_ID_PATTERN.fullmatch(cleaned):
        return None, "invalid_pattern"
    return cleaned, None


def team_operator_map_path(root: Path, naos_root: str, policy: dict[str, Any]) -> Path:
    configured = str(policy.get("paths", {}).get("team_operator_map") or "team_operator_map.yaml")
    return root / naos_root / configured


def normalize_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    cleaned = str(value).strip()
    return [cleaned] if cleaned else []


def team_specific_config_present(manifest: dict[str, Any]) -> bool:
    return any(isinstance(gate, dict) and isinstance(gate.get("team_overrides"), dict) and bool(gate.get("team_overrides")) for gate in manifest.get("gates") or [])


def resolve_team_context(
    *,
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    explicit_team_id: str | None,
    manifest: dict[str, Any],
    profile: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    requested = explicit_team_id or os.environ.get("NAOS_TEAM_ID")
    source = "explicit flag/env" if requested else "unknown"
    team_id: str | None = None
    reason: str | None = None
    if requested:
        team_id, reason = validate_team_id(requested)
        if reason:
            findings.append(
                {
                    "id": "gatekeeper_team_context.invalid_team_id",
                    "severity": "warning",
                    "status": "invalid_team_id",
                    "message": f"Team id was invalid and ignored: {reason}.",
                    "team_id": str(requested),
                    "not_claimed": TEAM_GATEKEEPER_NOT_CLAIMED,
                    "human_review_required": True,
                }
            )
            team_id = None
            source = "unknown"

    operator = resolve_operator_attribution(root)
    map_path = team_operator_map_path(root, naos_root, policy)
    map_present = map_path.exists()
    if team_id is None and map_present:
        try:
            data = yaml.safe_load(map_path.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            findings.append(
                {
                    "id": "gatekeeper_team_context.invalid_team_operator_map",
                    "severity": "warning",
                    "status": "invalid_team_operator_map",
                    "message": f"Team/operator map could not be parsed: {exc}",
                    "path": str(map_path),
                    "human_review_required": True,
                }
            )
            data = {}
        operator_id = operator.get("operator_id")
        if operator_id and isinstance(data.get("operators"), list):
            for entry in data.get("operators") or []:
                if isinstance(entry, dict) and entry.get("operator_id") == operator_id:
                    team_ids = []
                    for raw_team_id in normalize_string_list(entry.get("team_ids") or entry.get("team_id")):
                        mapped_team_id, mapped_reason = validate_team_id(raw_team_id)
                        if mapped_reason:
                            findings.append(
                                {
                                    "id": "gatekeeper_team_context.invalid_mapped_team_id",
                                    "severity": "warning",
                                    "status": "invalid_team_id",
                                    "message": f"Mapped team id was invalid and ignored: {mapped_reason}.",
                                    "team_id": raw_team_id,
                                    "path": str(map_path),
                                    "human_review_required": True,
                                }
                            )
                            continue
                        if mapped_team_id:
                            team_ids.append(mapped_team_id)
                    if len(team_ids) == 1:
                        team_id = team_ids[0]
                        source = "map"
                    elif len(team_ids) > 1:
                        findings.append(
                            {
                                "id": "gatekeeper_team_context.ambiguous_team_mapping",
                                "severity": "warning",
                                "status": "review_required",
                                "message": "Operator maps to multiple teams; pass --team-id/TEAM_ID/NAOS_TEAM_ID to select one gatekeeper context.",
                                "team_ids": team_ids,
                                "human_review_required": True,
                            }
                        )
                        source = "unknown"
                    break

    if team_id is None and team_specific_config_present(manifest):
        severity = "advisory" if profile in {"quickstart", "lite"} else "required"
        findings.append(
            {
                "id": "gatekeeper_team_context.unknown_team",
                "severity": severity,
                "status": "review_required" if profile in {"standard", "assured"} else "advisory",
                "message": "Gatekeeper team overrides are configured, but no team context was resolved.",
                "path": str(map_path),
                "human_review_required": profile in {"standard", "assured"},
                "not_claimed": TEAM_GATEKEEPER_NOT_CLAIMED,
            }
        )

    return {
        "team_id": team_id,
        "team_resolution_source": source if team_id else ("not_configured" if not requested and not map_present else "unknown"),
        "team_operator_map_path": str(map_path),
        "team_operator_map_present": map_present,
        "operator_id": operator.get("operator_id"),
        "operator_source": operator.get("operator_source"),
        "operator_attribution_status": operator.get("operator_attribution_status"),
        "team_gatekeeper_overrides_enabled": True,
        "limitations": TEAM_GATEKEEPER_LIMITATIONS,
        "not_claimed": TEAM_GATEKEEPER_NOT_CLAIMED,
    }, findings


def path_exists(pattern: str, *, root: Path | None = None) -> bool:
    if not pattern or "<" in pattern or ">" in pattern:
        return False
    root = (root or Path.cwd()).resolve()
    path = Path(pattern)
    if path.is_absolute() or ".." in path.parts:
        return False
    if any(ch in pattern for ch in "*?["):
        return any(candidate.resolve(strict=False).is_relative_to(root) for candidate in root.glob(pattern))
    candidate = (root / path).resolve(strict=False)
    if root not in (candidate, *candidate.parents):
        return False
    return candidate.exists()


def severity_lowered(original: str, effective: str) -> bool:
    return SEVERITY_ORDER.get(effective, -1) < SEVERITY_ORDER.get(original, -1)


def apply_team_override(
    gate: dict[str, Any],
    profile: str,
    team_context: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    base_severity = (gate.get("severity_by_profile") or {}).get(profile, "advisory")
    base_enabled = bool(gate.get("enabled", True))
    effective = {
        "severity": base_severity,
        "enabled": base_enabled,
        "rationale": None,
        "review_required": None,
        "limitations": [],
    }
    team_id = team_context.get("team_id")
    findings: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    team_overrides = gate.get("team_overrides") if isinstance(gate.get("team_overrides"), dict) else {}
    selected_override = team_overrides.get(team_id) if team_id and isinstance(team_overrides.get(team_id), dict) else None
    if selected_override is None:
        return effective, {
            "applied": False,
            "source": None,
            "team_id": team_id,
            "rationale": None,
            "fields_applied": [],
            "original_severity": base_severity,
            "effective_severity": base_severity,
            "original_enabled": base_enabled,
            "effective_enabled": base_enabled,
            "severity_lowered": False,
        }, findings, rejected
    profile_scope = normalize_string_list(selected_override.get("profile_scope"))
    if profile_scope and profile not in profile_scope:
        return effective, {
            "applied": False,
            "source": None,
            "team_id": team_id,
            "rationale": selected_override.get("rationale"),
            "fields_applied": [],
            "original_severity": base_severity,
            "effective_severity": base_severity,
            "original_enabled": base_enabled,
            "effective_enabled": base_enabled,
            "severity_lowered": False,
            "profile_scope_skipped": True,
        }, findings, rejected

    fields_applied: list[str] = []
    for key in sorted(selected_override):
        value = selected_override[key]
        if key not in ALLOWED_TEAM_OVERRIDE_FIELDS:
            item = {
                "id": "gatekeeper_team_override.protected_field",
                "severity": "required",
                "status": "protected_invariant_violation",
                "message": f"Team override for gate {gate.get('id')} attempted unsupported/protected field `{key}`.",
                "gate_id": gate.get("id"),
                "team_id": team_id,
                "path": f"gates.{gate.get('id')}.team_overrides.{team_id}.{key}",
                "human_review_required": True,
            }
            findings.append(item)
            rejected.append(item)
            continue
        if key == "severity":
            severity = str(value)
            if severity not in SEVERITY_ORDER:
                item = {
                    "id": "gatekeeper_team_override.invalid_severity",
                    "severity": "warning",
                    "status": "invalid_team_override",
                    "message": f"Team override for gate {gate.get('id')} used invalid severity `{severity}`.",
                    "gate_id": gate.get("id"),
                    "team_id": team_id,
                    "human_review_required": True,
                }
                findings.append(item)
                rejected.append(item)
                continue
            if profile == "assured" and base_severity in {"required", "blocking"} and severity_lowered(base_severity, severity):
                item = {
                    "id": "gatekeeper_team_override.assured_minimum_severity",
                    "severity": "blocking",
                    "status": "protected_invariant_violation",
                    "message": f"Assured profile team override for gate {gate.get('id')} cannot silently lower {base_severity} severity to {severity}.",
                    "gate_id": gate.get("id"),
                    "team_id": team_id,
                    "original_severity": base_severity,
                    "requested_severity": severity,
                    "human_review_required": True,
                }
                findings.append(item)
                rejected.append(item)
                continue
            effective["severity"] = severity
            fields_applied.append(key)
            if severity_lowered(base_severity, severity):
                findings.append(
                    {
                        "id": "gatekeeper_team_override.severity_downgrade",
                        "severity": "required" if profile in {"standard", "assured"} else "warning",
                        "status": "review_required",
                        "message": f"Team override lowered gate {gate.get('id')} severity from {base_severity} to {severity}; human review is required.",
                        "gate_id": gate.get("id"),
                        "team_id": team_id,
                        "original_severity": base_severity,
                        "effective_severity": severity,
                        "human_review_required": True,
                    }
                )
        elif key == "enabled":
            effective["enabled"] = bool(value)
            fields_applied.append(key)
        elif key == "review_required":
            requested = bool(value)
            if requested is False and profile in {"standard", "assured"}:
                item = {
                    "id": "gatekeeper_team_override.human_review_required",
                    "severity": "required",
                    "status": "protected_invariant_violation",
                    "message": f"Team override for gate {gate.get('id')} cannot remove human review in {profile}.",
                    "gate_id": gate.get("id"),
                    "team_id": team_id,
                    "human_review_required": True,
                }
                findings.append(item)
                rejected.append(item)
                continue
            effective["review_required"] = requested
            fields_applied.append(key)
        elif key == "limitations":
            effective["limitations"] = normalize_string_list(value)
            fields_applied.append(key)
        elif key in {"rationale", "profile_scope"}:
            effective[key] = value
            fields_applied.append(key)

    metadata = {
        "applied": bool(fields_applied),
        "source": f"team_overrides.{team_id}" if fields_applied else None,
        "team_id": team_id,
        "rationale": selected_override.get("rationale"),
        "fields_applied": fields_applied,
        "original_severity": base_severity,
        "effective_severity": effective["severity"],
        "original_enabled": base_enabled,
        "effective_enabled": effective["enabled"],
        "severity_lowered": severity_lowered(base_severity, str(effective["severity"])),
    }
    return effective, metadata, findings, rejected


def build_gate_maturity_map(root: Path, naos_root: str, policy: dict[str, Any], profile: str) -> dict[str, dict[str, Any]]:
    """Derive per-gate maturity gating from capability contracts + adopter state.

    Inverts each contract's ``gatekeepers: [Gn]`` linkage and computes, per gate,
    the maturity-gated severity ceiling for the active profile. Downgrade-only:
    a capability below its target maturity contributes only ``advisory`` (its
    ``effective_enforcement``), so a gate can never block on an immature
    capability ("never block a scaffold"). Returns ``{}`` when no contracts/state
    are available (e.g. an adopter project without capability contracts), which
    leaves declared gate severity unchanged.
    """
    # Resolve adopter (naos/capabilities) or kit (capabilities) layout.
    cap_dir = next((c for c in (root / naos_root / "capabilities", root / "capabilities") if c.is_dir()), None)
    if cap_dir is None:
        return {}
    # adopter declared state (current maturity); fall back to seed defaults (L0)
    state_entries: dict[str, dict[str, Any]] = {}
    state_path = root / naos_root / str((policy.get("paths") or {}).get("capability_state") or "capability_state.yaml")
    if state_path.exists():
        try:
            state_doc = yaml.safe_load(state_path.read_text(encoding="utf-8")) or {}
            for entry in state_doc.get("capabilities") or []:
                if isinstance(entry, dict) and entry.get("capability_id"):
                    state_entries[str(entry["capability_id"])] = entry
        except Exception:
            state_entries = {}

    gate_map: dict[str, dict[str, Any]] = {}
    for cap_path in sorted(cap_dir.glob("*.yaml")):
        if cap_path.name.startswith("_"):
            continue
        try:
            data = yaml.safe_load(cap_path.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        cap_id = str(data.get("id") or cap_path.stem)
        gatekeepers = data.get("gatekeepers") or []
        if not isinstance(gatekeepers, list) or not gatekeepers:
            continue
        profile_block = (data.get("profiles") or {}).get(profile) or {}
        declared = str(profile_block.get("enforcement") or "advisory")
        target = profile_block.get("target_maturity")
        current = (state_entries.get(cap_id) or {}).get("current_maturity") or data.get("default_maturity")
        effective = effective_enforcement(declared, current, target)
        satisfied = SEVERITY_ORDER.get(effective, 0) >= SEVERITY_ORDER.get(declared, 0)
        for gate_id in gatekeepers:
            bucket = gate_map.setdefault(str(gate_id), {"capabilities": [], "gated_severity": "none"})
            bucket["capabilities"].append({
                "capability_id": cap_id,
                "current_maturity": current,
                "target_maturity": target,
                "declared_enforcement": declared,
                "effective_enforcement": effective,
                "maturity_satisfied": satisfied,
            })
            if SEVERITY_ORDER.get(effective, 0) > SEVERITY_ORDER.get(bucket["gated_severity"], 0):
                bucket["gated_severity"] = effective
    return gate_map


def nested_value(data: Any, dotted_path: str) -> Any:
    current = data
    for segment in dotted_path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return None
        current = current[segment]
    return current


def live_semantic_source(
    source: str,
    *,
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    profile: str,
    cache: dict[str, tuple[dict[str, Any] | None, str | None]],
) -> tuple[dict[str, Any] | None, str | None]:
    if source in cache:
        return cache[source]
    if source != "plan_coherence_live":
        result = (None, f"unsupported semantic evidence source: {source}")
        cache[source] = result
        return result
    try:
        import naos_plan_coherence as plan_coherence

        result = (
            plan_coherence.build_report(root, naos_root, policy, profile),
            None,
        )
    except Exception as exc:
        result = (None, str(exc))
    cache[source] = result
    return result


def evaluate_semantic_requirements(
    gate: dict[str, Any],
    profile: str,
    *,
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    cache: dict[str, tuple[dict[str, Any] | None, str | None]],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for requirement in gate.get("semantic_requirements") or []:
        if not isinstance(requirement, dict):
            continue
        profiles = {str(item) for item in requirement.get("profiles") or []}
        if profile not in profiles:
            continue
        source = str(requirement.get("source") or "")
        field = str(requirement.get("field") or "")
        allowed_values = [str(item) for item in requirement.get("allowed_values") or []]
        data, error = live_semantic_source(
            source,
            root=root,
            naos_root=naos_root,
            policy=policy,
            profile=profile,
            cache=cache,
        )
        actual_value = nested_value(data, field) if data is not None else None
        status = "source_error" if error else ("pass" if actual_value in allowed_values else "failed")
        item = {
            "id": str(requirement.get("id") or "semantic_requirement"),
            "source": source,
            "field": field,
            "allowed_values": allowed_values,
            "actual_value": actual_value,
            "status": status,
            "human_review_required": status != "pass",
            "not_claimed": [
                "semantic evidence state is not implementation approval",
                "semantic evidence state is not task closure",
                "semantic evidence state is not merge or release authority",
            ],
        }
        if error:
            item["error"] = error
        results.append(item)
    return results


def classify_gate(
    gate: dict[str, Any],
    profile: str,
    team_context: dict[str, Any] | None = None,
    *,
    root: Path | None = None,
    gate_maturity_map: dict[str, dict[str, Any]] | None = None,
    naos_root: str = "naos",
    policy: dict[str, Any] | None = None,
    semantic_cache: dict[str, tuple[dict[str, Any] | None, str | None]] | None = None,
) -> dict[str, Any]:
    team_context = team_context or {}
    root = root or Path.cwd()
    gate_maturity_map = gate_maturity_map or {}
    policy = policy or load_policy(naos_root=naos_root, root=root)
    semantic_cache = semantic_cache if semantic_cache is not None else {}
    required_inputs = gate.get("required_inputs") or []
    required_evidence = gate.get("required_evidence") or []
    missing_inputs = [item for item in required_inputs if not path_exists(str(item), root=root)]
    missing_evidence = [item for item in required_evidence if not path_exists(str(item), root=root)]
    semantic_evidence = evaluate_semantic_requirements(
        gate,
        profile,
        root=root,
        naos_root=naos_root,
        policy=policy,
        cache=semantic_cache,
    )
    validators = gate.get("validators") or []
    validator_counts = {
        "available": 0,
        "planned": 0,
        "manual": 0,
        "external": 0,
        "unknown": 0,
    }
    for validator in validators:
        status = validator.get("status", "unknown") if isinstance(validator, dict) else "unknown"
        validator_counts[status if status in validator_counts else "unknown"] += 1

    base_severity = (gate.get("severity_by_profile") or {}).get(profile, "advisory")
    base_enabled = bool(gate.get("enabled", True))
    effective, override_metadata, team_findings, rejected_overrides = apply_team_override(gate, profile, team_context)
    severity = str(effective["severity"])
    enabled = bool(effective["enabled"])

    # CG2: maturity-gated enforcement (downgrade-only). A gate cannot enforce above
    # the maturity-gated ceiling of the capabilities mapped to it; immature
    # capabilities contribute only advisory ("never block a scaffold"). This never
    # raises severity above the declared/team-resolved value.
    gate_maturity = gate_maturity_map.get(str(gate.get("id"))) or {}
    pre_maturity_severity = severity
    maturity_gated = False
    if gate_maturity.get("capabilities"):
        gated_ceiling = str(gate_maturity.get("gated_severity") or "none")
        if SEVERITY_ORDER.get(gated_ceiling, 0) < SEVERITY_ORDER.get(severity, 0):
            severity = gated_ceiling
            maturity_gated = True

    has_missing = bool(
        missing_inputs
        or missing_evidence
        or any(item.get("status") != "pass" for item in semantic_evidence)
    )
    if not enabled:
        status = "not_applicable"
    elif not has_missing:
        status = "ready"
    elif severity == "none":
        status = "not_applicable"
    elif severity == "advisory":
        status = "advisory_missing"
    elif severity == "warning":
        status = "warning"
    elif severity == "required":
        status = "required_missing"
    elif severity == "blocking":
        status = "blocked"
    else:
        status = "unknown"

    return {
        "id": gate.get("id"),
        "name": gate.get("name"),
        "status": status,
        "severity": severity,
        "enabled": enabled,
        "base_gatekeeper": {
            "id": gate.get("id"),
            "severity": base_severity,
            "enabled": base_enabled,
        },
        "effective_gatekeeper": {
            "id": gate.get("id"),
            "severity": severity,
            "enabled": enabled,
            "team_id": team_context.get("team_id"),
            "team_override_applied": bool(override_metadata.get("applied")),
        },
        "original_severity": base_severity,
        "effective_severity": severity,
        "original_enabled": base_enabled,
        "effective_enabled": enabled,
        "team_id": team_context.get("team_id"),
        "team_resolution_source": team_context.get("team_resolution_source", "unknown"),
        "team_override_applied": bool(override_metadata.get("applied")),
        "team_override_source": override_metadata.get("source"),
        "team_override_rationale": override_metadata.get("rationale"),
        "team_override_fields_applied": override_metadata.get("fields_applied") or [],
        "team_override_findings": team_findings,
        "team_overrides_rejected": rejected_overrides,
        "limitations": TEAM_GATEKEEPER_LIMITATIONS + list(effective.get("limitations") or []),
        "not_claimed": TEAM_GATEKEEPER_NOT_CLAIMED,
        "human_review_required": bool(
            team_findings
            or effective.get("review_required") is True
            or any(item.get("human_review_required") for item in semantic_evidence)
        ),
        "missing_inputs": missing_inputs,
        "missing_evidence": missing_evidence,
        "semantic_evidence": semantic_evidence,
        "validators": validator_counts,
        "experimental": gate.get("id") in {"G7", "G8"},
        "maturity_dependency": gate_maturity or (gate.get("maturity_dependency") or {}),
        "maturity_gated": maturity_gated,
        "pre_maturity_severity": pre_maturity_severity,
        "known_limitations": gate.get("known_limitations") or [],
    }


def load_capability_maturity(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "capability_maturity_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "capabilities": [],
            "rule": "Capability maturity readiness report is visible to gates when generated; missing reports are not treated as pass.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "capabilities": [],
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "capabilities": [
            {
                "capability_id": item.get("capability_id"),
                "evaluated_status": item.get("evaluated_status"),
                "ready_for_promotion": item.get("ready_for_promotion"),
                "human_approval_required": item.get("human_approval_required"),
                "waivers": item.get("waivers") or [],
            }
            for item in data.get("capabilities", [])
            if isinstance(item, dict)
        ],
        "rule": "NAOS evaluates maturity readiness; gates do not convert waivers or human-review requirements into pass.",
    }


def load_systemic_impact(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "systemic_impact_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "artifact_families": [],
            "rule": "Systemic impact review is visible to gates when generated; missing reports are not treated as pass.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "artifact_families": [],
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "artifact_families": [
            {
                "family_id": item.get("family_id"),
                "evaluated_status": item.get("evaluated_status"),
                "configured": item.get("configured"),
                "human_review_required": item.get("human_review_required"),
                "review_obligations": item.get("review_obligations") or [],
            }
            for item in data.get("artifact_families", [])
            if isinstance(item, dict)
        ],
        "rule": "Gates consume implemented systemic-impact reports as review evidence; they do not prove perfect coherence.",
    }


def load_module_header_traceability(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "module_header_traceability_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "scanned_files": [],
            "rule": "Module-header traceability is visible to gates when generated; missing reports are not treated as pass.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "scanned_files": [],
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "scanned_files": [
            {
                "path": item.get("path"),
                "status": item.get("status"),
                "missing_sections": item.get("missing_sections") or [],
                "human_review_required": item.get("human_review_required"),
            }
            for item in data.get("scanned_files", [])
            if isinstance(item, dict)
        ],
        "rule": "Gates consume implemented module-header reports as traceability evidence; they do not prove code correctness.",
    }


def load_spec_cascade_coherence(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "spec_cascade_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "findings": [],
            "rule": "Spec-cascade coherence is visible to gates when generated; missing reports are not treated as pass.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "findings": [],
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "findings": data.get("findings") or [],
        "orphan_headers": data.get("orphan_headers") or [],
        "overloaded_frs": data.get("overloaded_frs") or [],
        "stale_statuses": data.get("stale_statuses") or [],
        "uncovered_requirements": data.get("uncovered_requirements") or [],
        "untraced_sources": data.get("untraced_sources") or [],
        "unresolved_source_references": data.get("unresolved_source_references") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Gates consume implemented spec-cascade reports as bounded traceability evidence; they do not prove code correctness, complete traceability, runtime behavior, approval, or compliance.",
    }


def load_spec_pack_contract(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "spec_pack_contract_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "findings": [],
            "rule": "Spec-pack contract conformance is visible to gates when generated; missing reports are not treated as pass.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "findings": [],
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "findings": data.get("findings") or [],
        "files": data.get("files") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Gates consume implemented spec-pack reports as bounded template contract evidence; they do not prove spec quality, requirements completeness, implementation, approval, or compliance.",
    }


def load_control_plane_review(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "control_plane_review_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "routing_decisions": [],
            "rule": "Control-plane review routing is visible to gates when generated; missing reports are not treated as pass.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "routing_decisions": [],
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "routing_decisions": [
            {
                "id": item.get("id"),
                "source_type": item.get("source_type"),
                "status": item.get("status"),
                "target_surfaces": item.get("target_surfaces") or [],
                "human_review_required": item.get("human_review_required"),
                "known_gap_ref": item.get("known_gap_ref"),
                "residual_risk_ref": item.get("residual_risk_ref"),
                "waiver_ref": item.get("waiver_ref"),
            }
            for item in data.get("routing_decisions", [])
            if isinstance(item, dict)
        ],
        "rule": "Gates consume implemented control-plane review reports as routing evidence; they do not prove research completeness or governance correctness.",
    }


def load_setup_recommendations(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "setup_recommendations_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "recommended_modules": [],
            "rule": "Setup recommendations are visible to gates when generated; missing reports are not treated as pass or as a blocker by default.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "recommended_modules": [],
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "recommended_modules": [
            {
                "module_id": item.get("module_id"),
                "name": item.get("name"),
                "recommendation": item.get("recommendation"),
                "noise_risk": item.get("noise_risk"),
                "human_review_boundary": item.get("human_review_boundary"),
            }
            for item in data.get("recommended_modules", [])
            if isinstance(item, dict)
        ],
        "rule": "Setup recommendations guide module selection; gates do not convert recommendations into approval, certification, or automatic setup.",
    }


def load_governance_bypass_posture(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "governance_bypass_posture_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "findings": [],
            "rule": "Governance-bypass posture is visible to gates when generated; missing reports are not treated as bypass prevention, CI proof, PR approval, or proof of compliance.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "findings": [],
            "error": str(exc),
        }
    scans = data.get("scans") if isinstance(data.get("scans"), dict) else {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "hook": scans.get("hook") or {},
        "ci": scans.get("ci") or {},
        "tier": scans.get("tier") or {},
        "bypass_commit_messages": scans.get("bypass_commit_messages") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Governance-bypass posture is deterministic local review evidence only; gates do not treat it as bypass prevention, CI proof, PR approval, certification, or proof of compliance.",
    }


def load_external_evidence_ingest(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "external_evidence_ingest_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "findings": [],
            "rule": "External evidence ingest is visible to gates when generated; missing reports are not treated as verified scanner evidence, approval, attestation, certification, or proof of compliance.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "findings": [],
            "error": str(exc),
        }
    scans = data.get("scans") if isinstance(data.get("scans"), dict) else {}
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "source": scans.get("source"),
        "resolved_source": scans.get("resolved_source"),
        "verification_status": summary.get("verification_status") or scans.get("verification_default") or "unverified",
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "External evidence ingest is local SARIF summarization only; gates do not treat it as finding verification, approval, attestation, certification, or proof of compliance.",
    }


def load_package_reality(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "package_reality_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "findings": [],
            "rule": "Package-reality review is visible to gates when generated; missing reports are not treated as package safety proof, registry proof, approval, certification, or proof of compliance.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "findings": [],
            "error": str(exc),
        }
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": summary,
        "registry_mode": data.get("registry_mode"),
        "network_used": bool(data.get("network_used")),
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Package-reality review summarizes local package declarations, lock-style pins, optional docs snippets, and explicit opt-in registry checks. Gates do not treat it as package safety, malware, vulnerability, registry-trust, supply-chain assurance, approval, certification, or proof of compliance.",
    }


def load_evidence_attestation(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "evidence_attestation_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "artifact_manifest": [],
            "reviewer_attestations": [],
            "rule": "Evidence attestation is visible to gates when generated; missing reports are not treated as approval or a pass.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "artifact_manifest": [],
            "reviewer_attestations": [],
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "artifact_manifest": [
            {
                "path": item.get("path"),
                "status": item.get("status"),
                "digest": item.get("digest"),
                "freshness": item.get("freshness") or {},
            }
            for item in data.get("artifact_manifest", [])
            if isinstance(item, dict)
        ],
        "reviewer_attestations": [
            {
                "id": item.get("id"),
                "reviewer_role": item.get("reviewer_role"),
                "review_date": item.get("review_date"),
                "review_outcome": item.get("review_outcome"),
                "human_review_required": item.get("human_review_required"),
            }
            for item in data.get("reviewer_attestations", [])
            if isinstance(item, dict)
        ],
        "missing_artifacts": data.get("missing_artifacts") or [],
        "uncovered_artifacts": data.get("uncovered_artifacts") or [],
        "waivers": data.get("waivers") or [],
        "known_gaps": data.get("known_gaps") or [],
        "residual_risks": data.get("residual_risks") or [],
        "rule": "Evidence attestation is local digest plus reviewer metadata; gates do not treat it as signing, tamper-proof evidence, compliance approval, or automatic approval.",
    }


def load_evidence_conflicts(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "evidence_conflict_detection_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "conflict_count": 0,
            "rule": "Evidence conflict detection is visible to gates when generated; missing reports are not treated as conflict absence, approval, or a pass.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "conflict_count": 0,
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "conflict_count": data.get("conflict_count", 0),
        "conflict_type_counts": data.get("conflict_type_counts") or {},
        "unrouted_conflicts": data.get("unrouted_conflicts") or [],
        "stale_attestations": data.get("stale_attestations") or [],
        "missing_reviewer_metadata": data.get("missing_reviewer_metadata") or [],
        "missing_operator_attribution": data.get("missing_operator_attribution") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Evidence conflict detection flags review conflicts and metadata gaps; gates do not treat it as conflict resolution, evidence correctness proof, separation-of-duties proof, task locking, approval, or compliance proof.",
    }


def load_task_claims(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "task_claim_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "claim_count": 0,
            "rule": "Task claims are visible to gates when generated; missing reports are not treated as authorization, approval, task completion, or a pass.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "summary": {}, "claim_count": 0, "error": str(exc)}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "claim_count": data.get("claim_count", 0),
        "active_claim_count": data.get("active_claim_count", 0),
        "released_claim_count": data.get("released_claim_count", 0),
        "expired_claim_count": data.get("expired_claim_count", 0),
        "stale_claim_count": data.get("stale_claim_count", 0),
        "conflicting_claim_count": data.get("conflicting_claim_count", 0),
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Task claims coordinate work and gates do not treat them as authorization, approval, task ownership proof, separation-of-duties evidence, task completion, or conflict resolution.",
    }


def load_memory_context_readiness(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "memory_context_readiness_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "platform_access_matrix": [],
            "project_identity": {},
            "rule": "Memory/context readiness is visible to gates when generated; missing reports are not treated as memory access or approval.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "platform_access_matrix": [],
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "memory_readiness": data.get("memory_readiness") or {},
        "provider_posture": data.get("provider_posture") or {},
        "mcp_tool_access": data.get("mcp_tool_access") or {},
        "project_identity": data.get("project_identity") or {},
        "platform_access_matrix": data.get("platform_access_matrix") or [],
        "memory_authorization": data.get("memory_authorization") or {},
        "fallback_readiness": data.get("fallback_readiness") or {},
        "context_pack_readiness": data.get("context_pack_readiness") or {},
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Memory is advisory recall and continuity support; gates do not treat memory as evidence, approval, or source of truth.",
    }


def load_memory_provider_access(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "memory_provider_access_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "provider_access_verified": False,
            "mcp_access_verified": False,
            "project_identity": {},
            "rule": "Memory provider access verification is visible to gates when generated; missing reports are not treated as memory access or approval.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "provider_access_verified": False,
            "mcp_access_verified": False,
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "provider_name": data.get("provider_name"),
        "provider_configured": bool(data.get("provider_configured")),
        "provider_access_verified": bool(data.get("provider_access_verified")),
        "provider_data_dir_source": data.get("provider_data_dir_source"),
        "provider_data_dir_exists": bool(data.get("provider_data_dir_exists")),
        "provider_database_exists": bool(data.get("provider_database_exists")),
        "mcp_access_verified": bool(data.get("mcp_access_verified")),
        "project_identity": data.get("project_identity") or {},
        "ci_memory_access": data.get("ci_memory_access") or {},
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Memory provider access is posture metadata only; gates do not treat it as evidence, approval, source of truth, or guaranteed tool access.",
    }


def load_memory_use_policy(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "memory_use_policy_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "instruction_grade_items": [],
            "rule": "Memory-use policy is visible to gates when generated; missing reports are not treated as pass, memory approval, or instruction-grade authorization.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "instruction_grade_items": [],
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "instruction_grade_items": data.get("instruction_grade_items") or [],
        "unsafe_instruction_grade_claims": data.get("unsafe_instruction_grade_claims") or [],
        "memory_access_prerequisites": data.get("memory_access_prerequisites") or {},
        "policy_item_access_posture": data.get("policy_item_access_posture") or [],
        "recall_trace_readiness": data.get("recall_trace_readiness") or {},
        "audit_event_readiness": data.get("audit_event_readiness") or {},
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Memory-use policy is metadata/review posture only; gates preserve access-unverified joins and do not treat memory, recall traces, or audit events as evidence, approval, source of truth, compliance determination, or hallucination prevention.",
    }


def load_task_context_pack(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "task_context_pack_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "task_id": None,
            "source_artifacts_missing": [],
            "rule": "Task context packs are visible to gates when generated; missing packs are not treated as pass, approval, or source of truth.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "task_id": None,
            "source_artifacts_missing": [],
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "task_id": data.get("task_id"),
        "source_artifacts_missing": data.get("source_artifacts_missing") or [],
        "source_artifact_freshness": data.get("source_artifact_freshness") or {},
        "memory_context": data.get("memory_context") or {},
        "human_review_required": bool((data.get("human_review_boundary") or {}).get("required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Task context packs are derived, bounded context; gates do not treat them as evidence authority, approval, complete coherence proof, or automatic context injection.",
    }


def load_native_lifecycle_report(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    path_key: str,
    boundary: str,
) -> dict[str, Any]:
    """Expose one optional native lifecycle report without turning it into a gate."""

    path = report_default_path(root, naos_root, policy, path_key)
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "human_review_required": False,
            "rule": f"{boundary} Missing optional reports are not treated as pass or failure.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "human_review_required": True,
            "error": str(exc),
            "rule": boundary,
        }
    report = {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "task_id": data.get("task_id"),
        "action": data.get("action"),
        "lifecycle_state": data.get("lifecycle_state"),
        "delivery_state": data.get("delivery_state"),
        "requested_verification_state": data.get("requested_verification_state"),
        "effective_verification_state": data.get("effective_verification_state"),
        "verification_prerequisites_met": data.get("verification_prerequisites_met"),
        "completion_verification": data.get("completion_verification") or {},
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "review_reasons": data.get("review_reasons") or [],
        "review_posture_source": data.get("review_posture_source"),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": boundary,
    }
    for review_key in ("canonical_task_review", "traceability_review"):
        if isinstance(data.get(review_key), dict):
            report[review_key] = data[review_key]
    return report


def load_local_context_index(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "local_context_index_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "sqlite_artifact": {},
            "fts_available": False,
            "rule": "Local context index is visible to gates when generated; missing reports are not treated as pass, authority, or a blocker by default.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "sqlite_artifact": {},
            "fts_available": False,
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "sqlite_artifact": data.get("sqlite_artifact") or {},
        "fts_available": bool(data.get("fts_available")),
        "query_modes_supported": data.get("query_modes_supported") or {},
        "future_semantic_layer": data.get("future_semantic_layer") or {},
        "future_graph_layer": data.get("future_graph_layer") or {},
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "Local context index is generated, derived, and cache-like; gates do not treat retrieval candidates as source artifacts or truth.",
    }


def load_sqlite_write_coordination(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "sqlite_write_coordination_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "lock_acquired": False,
            "atomic_replace_used": False,
            "rule": "SQLite write coordination is visible to gates when generated; missing reports are not treated as file-integrity proof or multi-user completion.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "lock_acquired": False,
            "atomic_replace_used": False,
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "lock_acquired": bool(data.get("lock_acquired")),
        "atomic_replace_used": bool(data.get("atomic_replace_used")),
        "tables_verified": data.get("tables_verified") or [],
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "rule": "SQLite write coordination protects local index file integrity only; gates do not treat it as task locking, evidence conflict detection, distributed locking, or governance correctness.",
    }


def load_local_context_query(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "local_context_query_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "result_count": 0,
            "rule": "Local context query is visible to gates when generated; missing query reports are not treated as pass, answer, or authority.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "result_count": 0,
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "result_count": data.get("result_count", 0),
        "query_mode_used": data.get("query_mode_used") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Local context query results are bounded candidate references; gates do not treat them as answers or source of truth.",
    }


def load_semantic_candidate_layer(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "semantic_candidate_layer_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "semantic_runtime_enabled": False,
            "rule": "Semantic candidate readiness is visible to gates when generated; missing reports are not treated as pass, runtime enablement, or authority.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "semantic_runtime_enabled": False,
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "semantic_runtime_enabled": bool(data.get("semantic_runtime_enabled")),
        "sqlite_vec_enabled": bool(data.get("sqlite_vec_enabled")),
        "embeddings_enabled": bool(data.get("embeddings_enabled")),
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Semantic candidate readiness is reporting-only; gates do not treat semantic candidates as answers, source artifacts, or truth.",
    }


def load_graph_context_readiness(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "graph_context_readiness_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "graph_runtime_enabled": False,
            "rule": "Graph context readiness is visible to gates when generated; missing reports are not treated as pass, traversal enablement, or authority.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "graph_runtime_enabled": False,
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "graph_runtime_enabled": bool(data.get("graph_runtime_enabled")),
        "explicit_link_traversal_only": bool(data.get("explicit_link_traversal_only", True)),
        "global_graph_scan_allowed": bool(data.get("global_graph_scan_allowed")),
        "networkx_enabled": bool(data.get("networkx_enabled")),
        "graphml_enabled": bool(data.get("graphml_enabled")),
        "graph_algorithms_enabled": bool(data.get("graph_algorithms_enabled")),
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Graph context readiness is reporting-only; gates do not treat graph links as source artifacts, truth, or traversal approval.",
    }


def load_graph_context_query(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "graph_context_query_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "result_count": 0,
            "rule": "Graph context query is visible to gates when generated; missing query reports are not treated as pass, truth, or traversal approval.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "result_count": 0,
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "result_count": data.get("result_count", 0),
        "query_mode_used": data.get("query_mode_used") or [],
        "traversal_depth_used": data.get("traversal_depth_used"),
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Graph context query results are bounded relationship candidates; gates do not treat them as truth, implementation proof, or source authority.",
    }


def load_session_lifecycle(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "session_lifecycle_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "mode": None,
            "task_id": None,
            "rule": "Session lifecycle reports are visible to gates when generated; missing reports are not treated as task completion, approval, evidence authority, or context injection.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "mode": None,
            "task_id": None,
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "mode": data.get("mode"),
        "task_id": data.get("task_id"),
        "memory_candidate_proposals": data.get("memory_candidate_proposals") or [],
        "recommended_commands": data.get("recommended_commands") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Session lifecycle reports are bounded review checklists; gates do not treat them as proof, approval, task completion, source authority, or automatic memory/context behavior.",
    }


def load_session_identity(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "session_identity_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "session_id": None,
            "rule": "Session identity is visible to gates when generated; missing session metadata means latest-report compatibility remains available but report namespacing is not populated.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "session_id": None,
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "session_id": data.get("session_id"),
        "session_report_root": data.get("session_report_root"),
        "latest_report_compatibility": data.get("latest_report_compatibility") or {},
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Session identity reports coordinate namespaced report roots and local operator signals; gates do not treat them as authentication, authorization, task locking, audit logging, approval, or source authority.",
    }


def load_operator_attribution(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "operator_attribution_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "operator_id": None,
            "rule": "Operator attribution is visible to gates when generated; missing attribution is not treated as approval, task ownership, locking, authentication, or authorization.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "operator_id": None,
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "operator_id": data.get("operator_id"),
        "operator_source": data.get("operator_source"),
        "operator_attribution_status": data.get("operator_attribution_status"),
        "session_id": data.get("session_id"),
        "privacy_posture": data.get("privacy_posture") or {},
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Operator attribution records local identity signals only; gates do not treat it as proof of identity, authentication, authorization, task ownership, separation of duties, approval, or non-repudiation.",
    }


def load_audit_log(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "audit_log_summary_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "event_count": 0,
            "rule": "Audit log visibility is advisory until generated; missing audit summaries are not treated as approval, non-repudiation, tamper-proof logging, task locking, or evidence conflict detection.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "event_count": 0,
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "event_count": data.get("event_count", 0),
        "event_type_counts": data.get("event_type_counts") or {},
        "invalid_event_count": data.get("invalid_event_count", 0),
        "missing_session_id_events": data.get("missing_session_id_events") or [],
        "missing_operator_id_events": data.get("missing_operator_id_events") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Audit log events are historical records only; gates do not treat them as approval, non-repudiation, tamper-proof storage, task locking, evidence conflict detection, or source of truth.",
    }


def load_agent_trace_validation(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "agent_trace_validation_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "event_count": 0,
            "rule": "Agent trace validation is visible to gates when generated; missing reports are not treated as trace evidence, proof, approval, or runtime capture.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "event_count": 0,
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "event_count": data.get("event_count", 0),
        "invalid_event_count": data.get("invalid_event_count", 0),
        "forbidden_payload_findings": data.get("forbidden_payload_findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Agent trace events are declared records only; gates do not treat them as correctness proof, approval, legal/compliance/regulatory assurance, memory writes, runtime capture, or behavioral safety evidence.",
    }


def load_static_grader(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "static_grader_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "dimension_summary": {},
            "rule": "StaticGrader reports are visible to gates when generated; missing reports are not treated as behavioral assessment, approval, or maturity promotion.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "dimension_summary": {},
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "dimension_summary": data.get("dimension_summary") or {},
        "cost_posture": data.get("cost_posture") or {},
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "StaticGrader is deterministic structural grading only; gates do not treat it as behavioral safety, semantic correctness, approval, maturity promotion, or legal/regulatory assurance.",
    }


def load_ai_surface_health(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "ai_surface_context_budget_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "ai_surface_health_posture": "missing",
            "context_budget_posture": "missing",
            "rule": "AI-surface health reports are visible to gates when generated; missing reports are not treated as behavioral proof, approval, or maturity promotion.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "ai_surface_health_posture": "unknown",
            "context_budget_posture": "unknown",
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "ai_surface_health_posture": data.get("ai_surface_health_posture"),
        "context_budget_posture": data.get("context_budget_posture"),
        "baseline": data.get("baseline") or {},
        "largest_families": sorted(
            [
                {
                    "id": item.get("id"),
                    "estimated_tokens": item.get("estimated_tokens"),
                    "file_count": item.get("file_count"),
                }
                for item in data.get("families") or []
                if isinstance(item, dict)
            ],
            key=lambda item: int(item.get("estimated_tokens") or 0),
            reverse=True,
        )[:5],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "AI-surface health is deterministic input-quality evidence only; gates do not treat it as hallucination prevention, behavioral scoring, approval, or compliance proof.",
    }


def load_grader_assessment(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "grader_assessment_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "drift": {},
            "rule": "Grader assessment reports are visible to gates when generated; missing reports are not treated as audit approval, certification, semantic drift, or maturity promotion.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "drift": {},
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "mode": data.get("mode"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "drift": data.get("drift") or {},
        "cost_budget_posture": data.get("cost_budget_posture") or {},
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Audit/drift/assess modes are deterministic review inputs; gates do not treat them as approval, certification, compliance determination, semantic drift inference, or maturity promotion.",
    }


def load_llm_grader_readiness(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "llm_grader_readiness_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "runtime_enabled": False,
            "rule": "LLMGrader readiness is visible to gates when generated; missing reports do not enable model, provider, API, cost, or grading runtime.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "runtime_enabled": False,
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "runtime_enabled": bool(data.get("runtime_enabled")),
        "provider_allowed": bool(data.get("provider_allowed")),
        "external_api_allowed": bool(data.get("external_api_allowed")),
        "model_dependency_allowed": bool(data.get("model_dependency_allowed")),
        "cost_posture": data.get("cost_posture") or {},
        "advisory_boundary": data.get("advisory_boundary") or {},
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "LLMGrader readiness is governance metadata only; gates do not treat it as runtime grading, approval, certification, compliance determination, or maturity promotion.",
    }


def load_behavioral_governance_readiness(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "behavioral_governance_readiness_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "review_input_only": True,
            "runtime_enabled": False,
            "rule": "Behavioral Governance Readiness is visible to gates when generated; missing reports do not enable behavioral grading, model/provider/API calls, baseline creation, approval, certification, or publication/release authority.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "review_input_only": True,
            "runtime_enabled": False,
            "error": str(exc),
        }
    runtime = data.get("runtime_posture") or {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "baseline_state_present": bool(data.get("baseline_state_present")),
        "impacter_review": data.get("impacter_review") or {},
        "runtime_enabled": bool(runtime.get("runtime_enabled")),
        "provider_allowed": bool(runtime.get("provider_allowed")),
        "external_api_allowed": bool(runtime.get("external_api_allowed")),
        "model_dependency_allowed": bool(runtime.get("model_dependency_allowed")),
        "cost_posture": data.get("cost_posture") or {},
        "advisory_boundary": data.get("advisory_boundary") or {},
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "review_input_only": True,
        "rule": "Behavioral Governance Readiness is deterministic review metadata only; gates do not treat it as behavioral grading, approval, certification, compliance determination, publication/release authority, baseline creation, or maturity promotion.",
    }


def load_policy_overrides(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "policy_override_merge_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "protected_invariant_violations": [],
            "rule": "Policy override merge reports are visible to gates when generated; missing reports are not treated as approval or effective policy validation.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "protected_invariant_violations": [],
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "override_summary": data.get("override_summary") or {},
        "team_operator_map": data.get("team_operator_map") or {},
        "overlay_scope": data.get("overlay_scope") or {},
        "overlay_scopes": data.get("overlay_scopes") or [],
        "applied_overlay_scopes": data.get("applied_overlay_scopes") or [],
        "team_ids": data.get("team_ids") or [],
        "operator_overlay_id": data.get("operator_overlay_id"),
        "protected_invariant_violations": data.get("protected_invariant_violations") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Static policy overrides are YAML-only customization posture; gates do not allow overlays to weaken ADR-0010: Control-Plane Advisory Boundaries, enable plugin runtime, approve policy changes, authenticate operators, authorize work, or configure gatekeeper severity per team.",
    }


def load_pr_risk_classification(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "pr_risk_classification_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "changed_files": [],
            "rule": "PR risk classification is visible to gates when generated; missing reports are not treated as low risk, PR approval, or security proof.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "changed_files": [],
            "error": str(exc),
        }
    contributor = data.get("contributor") if isinstance(data.get("contributor"), dict) else {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "changed_files": data.get("changed_files") or [],
        "contributor_trust": contributor.get("trust"),
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "PR risk classification is deterministic path/diff metadata review evidence only; gates do not treat it as PR approval, malware analysis, sandbox execution, security proof, compliance proof, or release authorization.",
    }


def load_agentic_workflow_review(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "agentic_workflow_review_report")
    if not path.exists():
        return {
            "source_identifier": "agentic_workflow_review_report",
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "workflow_config_valid": False,
            "rule": "Agentic workflow review is visible to gates when generated; missing reports are not treated as approval, correctness proof, requirements completeness proof, compliance proof, or human-review replacement.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "source_identifier": "agentic_workflow_review_report",
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "workflow_config_valid": False,
            "error": str(exc),
        }
    return {
        "source_identifier": "agentic_workflow_review_report",
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "workflow_config_present": bool(data.get("workflow_config_present")),
        "workflow_config_valid": bool(data.get("workflow_config_valid")),
        "missing_artifacts": data.get("missing_artifacts") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Agentic workflow review records declared operating practices only; gates do not treat it as assistant behavior proof, implementation approval, compliance proof, or human-review replacement.",
    }


def load_pre_implementation_alignment_review(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "pre_implementation_alignment_review_report")
    if not path.exists():
        return {
            "source_identifier": "pre_implementation_alignment_review_report",
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "alignment_valid": False,
            "rule": "Pre-Implementation Alignment review is visible to gates when generated; missing reports are not treated as design approval, implementation approval, requirements completeness proof, compliance proof, or human-review replacement.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "source_identifier": "pre_implementation_alignment_review_report",
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "alignment_valid": False,
            "error": str(exc),
        }
    return {
        "source_identifier": "pre_implementation_alignment_review_report",
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "alignment_present": bool(data.get("alignment_present")),
        "alignment_valid": bool(data.get("alignment_valid")),
        "mode": data.get("mode"),
        "missing_required_questions": data.get("missing_required_questions") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Pre-Implementation Alignment review records structured planning answers only; gates do not treat it as requirements completeness proof, design approval, implementation approval, compliance proof, or human-review replacement.",
    }


def load_agentic_workflow_config(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    filename = str(policy.get("paths", {}).get("agentic_workflow") or "agentic_workflow.yaml")
    path = root / naos_root / filename
    exists = path.exists()
    return {
        "source_identifier": "agentic_workflow_config",
        "status": "present" if exists else "not_configured",
        "path": str(path),
        "exists": exists,
        "rule": "Agentic workflow config visibility is artifact presence only; gates do not treat the file as proof of actual assistant behavior, approval, or compliance.",
    }


def load_pre_implementation_alignment_artifact(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    filename = str(policy.get("paths", {}).get("pre_implementation_alignment") or "PRE_IMPLEMENTATION_ALIGNMENT.md")
    path = root / naos_root / filename
    exists = path.exists()
    return {
        "source_identifier": "pre_implementation_alignment_artifact",
        "status": "present" if exists else "not_configured",
        "path": str(path),
        "exists": exists,
        "rule": "Pre-Implementation Alignment artifact visibility is artifact presence only; gates do not treat the file as requirements completeness proof, design approval, implementation approval, compliance proof, or human-review replacement.",
    }


def load_calibration_shadow(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "calibration_shadow_report")
    if not path.exists():
        return {
            "source_identifier": "calibration_shadow_report",
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "drift_count": 0,
            "rule": "Calibration shadow is related governance evidence only; missing reports are not model calibration, correctness proof, release approval, or proof of compliance.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "source_identifier": "calibration_shadow_report",
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "drift_count": 0,
            "error": str(exc),
        }
    return {
        "source_identifier": "calibration_shadow_report",
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "calibration_config_valid": bool(data.get("calibration_config_valid")),
        "drift_count": int(data.get("drift_count") or 0),
        "reports_missing": data.get("reports_missing") or [],
        "unexpected_changes": data.get("unexpected_changes") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Calibration shadow compares deterministic report metadata only; gates do not treat it as model calibration, semantic correctness proof, approval, certification, or release authorization.",
    }


def load_evidence_classification(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "evidence_classification_report")
    if not path.exists():
        return {
            "source_identifier": "evidence_classification_report",
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "classification_counts": {},
            "rule": "Evidence classification is related governance evidence only; missing reports are not truth proof, issue resolution, approval, or proof of compliance.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "source_identifier": "evidence_classification_report",
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "classification_counts": {},
            "error": str(exc),
        }
    return {
        "source_identifier": "evidence_classification_report",
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "policy_valid": bool(data.get("policy_valid")),
        "findings_scanned": int(data.get("findings_scanned") or 0),
        "classification_counts": data.get("classification_counts") or {},
        "missing_classification": data.get("missing_classification") or [],
        "unknown_findings": data.get("unknown_findings") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Evidence classification records provenance categories only; gates do not treat classifications as truth proof, legal conclusion, issue resolution, approval, certification, or compliance proof.",
    }


def load_failure_mode_observations(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "failure_mode_observations_report")
    if not path.exists():
        return {
            "source_identifier": "failure_mode_observations_report",
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "mode_observation_counts": {},
            "family_observation_counts": {},
            "source_report_counts": {},
            "observation_reason_code_counts": {},
            "severity_counts": {},
            "related_gate_counts": {},
            "mapping_basis_counts": {},
            "review_opportunities": [],
            "findings": [],
            "human_review_required": False,
            "rule": "Failure-mode observations are related governance evidence only; missing reports are not absence of failure patterns, approval, learning activation, blocking, release authority, or proof of compliance.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "source_identifier": "failure_mode_observations_report",
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "mode_observation_counts": {},
            "family_observation_counts": {},
            "source_report_counts": {},
            "observation_reason_code_counts": {},
            "severity_counts": {},
            "related_gate_counts": {},
            "mapping_basis_counts": {},
            "review_opportunities": [],
            "findings": [],
            "human_review_required": True,
            "error": str(exc),
        }
    return {
        "source_identifier": "failure_mode_observations_report",
        "status": data.get("status", "present"),
        "path": str(path),
        "enabled": bool(data.get("enabled")),
        "failure_mode_observations_declared": bool(data.get("failure_mode_observations_declared")),
        "summary": data.get("summary") or {},
        "mode_observation_counts": data.get("mode_observation_counts") or {},
        "family_observation_counts": data.get("family_observation_counts") or {},
        "source_report_counts": data.get("source_report_counts") or {},
        "observation_reason_code_counts": data.get("observation_reason_code_counts") or {},
        "severity_counts": data.get("severity_counts") or {},
        "related_gate_counts": data.get("related_gate_counts") or {},
        "mapping_basis_counts": data.get("mapping_basis_counts") or {},
        "review_opportunities": data.get("review_opportunities") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Failure-mode observations summarize local report patterns for review only; gates do not treat counts as numeric risk authority, learning activation, approval, blocking, release authority, or compliance proof.",
    }


def load_cross_harness_review_readiness(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "cross_harness_review_readiness_report")
    if not path.exists():
        return {
            "source_identifier": "cross_harness_review_readiness_report",
            "status": "not_configured",
            "path": str(path),
            "summary": {},
            "rule": "Cross-harness review readiness is related governance evidence only; missing reports are not cross-harness execution, signing, attestation, approval, or proof of compliance.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "source_identifier": "cross_harness_review_readiness_report",
            "status": "parse_error",
            "path": str(path),
            "summary": {},
            "error": str(exc),
        }
    return {
        "source_identifier": "cross_harness_review_readiness_report",
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "config_valid": bool(data.get("config_valid")),
        "declared_harness_count": int(data.get("declared_harness_count") or 0),
        "readiness_score": int(data.get("readiness_score") or 0),
        "requirements_missing": data.get("requirements_missing") or [],
        "requirements_deferred": data.get("requirements_deferred") or [],
        "runtime_execution_enabled": bool(data.get("runtime_execution_enabled")),
        "provider_api_allowed": bool(data.get("provider_api_allowed")),
        "dsse_readiness": data.get("dsse_readiness") or {},
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Cross-harness review readiness records future governance prerequisites only; gates do not treat it as harness execution, DSSE signing, signature verification, key custody, attestation authority, approval, certification, or compliance proof.",
    }


def evaluate_manifest(
    manifest: dict[str, Any],
    profile: str,
    manifest_location: ManifestLocation,
    naos_root: str = "naos",
    policy: dict[str, Any] | None = None,
    explicit_team_id: str | None = None,
) -> dict[str, Any]:
    validate_manifest(manifest)
    gates = manifest["gates"]

    policy = policy or load_policy(naos_root=naos_root, root=Path.cwd())
    team_context, team_context_findings = resolve_team_context(
        root=Path.cwd(),
        naos_root=naos_root,
        policy=policy,
        explicit_team_id=explicit_team_id,
        manifest=manifest,
        profile=profile,
    )
    root = Path.cwd()
    gate_maturity_map = build_gate_maturity_map(root, naos_root, policy, profile)
    semantic_cache: dict[str, tuple[dict[str, Any] | None, str | None]] = {}
    gate_results = [
        classify_gate(
            gate,
            profile,
            team_context,
            root=root,
            gate_maturity_map=gate_maturity_map,
            naos_root=naos_root,
            policy=policy,
            semantic_cache=semantic_cache,
        )
        for gate in gates
        if isinstance(gate, dict)
    ]
    summary = {
        "ready": sum(1 for gate in gate_results if gate["status"] == "ready"),
        "blocked": sum(1 for gate in gate_results if gate["status"] == "blocked"),
        "required_missing": sum(1 for gate in gate_results if gate["status"] == "required_missing"),
        "warning": sum(1 for gate in gate_results if gate["status"] == "warning"),
        "advisory_missing": sum(1 for gate in gate_results if gate["status"] == "advisory_missing"),
        "not_applicable": sum(1 for gate in gate_results if gate["status"] == "not_applicable"),
        "total": len(gate_results),
    }
    applied = [gate for gate in gate_results if gate.get("team_override_applied")]
    rejected = [item for gate in gate_results for item in gate.get("team_overrides_rejected") or []]
    gate_findings = [item for gate in gate_results for item in gate.get("team_override_findings") or []]
    protected_invariant_violations = [
        item for item in gate_findings + team_context_findings
        if item.get("status") == "protected_invariant_violation"
    ]
    team_override_findings = team_context_findings + gate_findings
    human_review_required = bool(
        protected_invariant_violations
        or rejected
        or any(item.get("human_review_required") for item in team_override_findings)
    )
    return {
        "schema": "naos.gate_status.v1",
        "evaluation_scope": evaluation_scope(gate_results),
        "profile": profile,
        "manifest": str(manifest_location.path),
        "manifest_source": manifest_location.source,
        "team_id": team_context.get("team_id"),
        "team_resolution_source": team_context.get("team_resolution_source"),
        "team_gatekeeper_overrides_enabled": bool(team_context.get("team_gatekeeper_overrides_enabled")),
        "team_operator_map_path": team_context.get("team_operator_map_path"),
        "team_operator_map_present": bool(team_context.get("team_operator_map_present")),
        "operator_id": team_context.get("operator_id"),
        "operator_source": team_context.get("operator_source"),
        "team_overrides_applied": [
            {
                "gate_id": gate.get("id"),
                "team_id": gate.get("team_id"),
                "original_severity": gate.get("original_severity"),
                "effective_severity": gate.get("effective_severity"),
                "original_enabled": gate.get("original_enabled"),
                "effective_enabled": gate.get("effective_enabled"),
                "source": gate.get("team_override_source"),
                "rationale": gate.get("team_override_rationale"),
            }
            for gate in applied
        ],
        "team_overrides_rejected": rejected,
        "effective_gatekeepers": [gate.get("effective_gatekeeper") for gate in gate_results],
        "base_gatekeepers": [gate.get("base_gatekeeper") for gate in gate_results],
        "override_summary": {
            "team_id": team_context.get("team_id"),
            "team_resolution_source": team_context.get("team_resolution_source"),
            "team_overrides_applied": len(applied),
            "team_overrides_rejected": len(rejected),
            "severity_downgrades": sum(1 for gate in applied if severity_lowered(str(gate.get("original_severity")), str(gate.get("effective_severity")))),
            "enabled_changes": sum(1 for gate in applied if gate.get("original_enabled") != gate.get("effective_enabled")),
        },
        "protected_invariant_violations": protected_invariant_violations,
        "team_override_findings": team_override_findings,
        "findings": team_override_findings,
        "capability_maturity": load_capability_maturity(Path.cwd(), naos_root, policy),
        "systemic_impact_review": load_systemic_impact(Path.cwd(), naos_root, policy),
        "module_header_traceability": load_module_header_traceability(Path.cwd(), naos_root, policy),
        "spec_pack_contract": load_spec_pack_contract(Path.cwd(), naos_root, policy),
        "spec_cascade_coherence": load_spec_cascade_coherence(Path.cwd(), naos_root, policy),
        "control_plane_review": load_control_plane_review(Path.cwd(), naos_root, policy),
        "setup_recommendations": load_setup_recommendations(Path.cwd(), naos_root, policy),
        "governance_bypass_posture": load_governance_bypass_posture(Path.cwd(), naos_root, policy),
        "external_evidence_ingest": load_external_evidence_ingest(Path.cwd(), naos_root, policy),
        "package_reality": load_package_reality(Path.cwd(), naos_root, policy),
        "evidence_attestation": load_evidence_attestation(Path.cwd(), naos_root, policy),
        "evidence_conflicts": load_evidence_conflicts(Path.cwd(), naos_root, policy),
        "task_claims": load_task_claims(Path.cwd(), naos_root, policy),
        "memory_context_readiness": load_memory_context_readiness(Path.cwd(), naos_root, policy),
        "memory_provider_access": load_memory_provider_access(Path.cwd(), naos_root, policy),
        "memory_use_policy": load_memory_use_policy(Path.cwd(), naos_root, policy),
        "task_context_pack": load_task_context_pack(Path.cwd(), naos_root, policy),
        "task_lifecycle": load_native_lifecycle_report(
            Path.cwd(),
            naos_root,
            policy,
            "task_lifecycle_report",
            "Native task lifecycle output is repository-state evidence, not merge, release, or evidence-admission authority.",
        ),
        "research_record": load_native_lifecycle_report(
            Path.cwd(),
            naos_root,
            policy,
            "research_record_report",
            "Structured research output remains candidate-only and cannot promote itself into a requirement, decision, evidence, learning, or memory authority.",
        ),
        "composed_traceability": load_native_lifecycle_report(
            Path.cwd(),
            naos_root,
            policy,
            "composed_traceability_report",
            "Composed relationship visibility is structural evidence and does not prove semantic correctness.",
        ),
        "local_context_index": load_local_context_index(Path.cwd(), naos_root, policy),
        "sqlite_write_coordination": load_sqlite_write_coordination(Path.cwd(), naos_root, policy),
        "local_context_query": load_local_context_query(Path.cwd(), naos_root, policy),
        "semantic_candidate_layer": load_semantic_candidate_layer(Path.cwd(), naos_root, policy),
        "graph_context_readiness": load_graph_context_readiness(Path.cwd(), naos_root, policy),
        "graph_context_query": load_graph_context_query(Path.cwd(), naos_root, policy),
        "session_identity": load_session_identity(Path.cwd(), naos_root, policy),
        "operator_attribution": load_operator_attribution(Path.cwd(), naos_root, policy),
        "session_lifecycle": load_session_lifecycle(Path.cwd(), naos_root, policy),
        "audit_log": load_audit_log(Path.cwd(), naos_root, policy),
        "agent_trace_validation": load_agent_trace_validation(Path.cwd(), naos_root, policy),
        "ai_surface_health": load_ai_surface_health(Path.cwd(), naos_root, policy),
        "static_grader": load_static_grader(Path.cwd(), naos_root, policy),
        "grader_assessment": load_grader_assessment(Path.cwd(), naos_root, policy),
        "llm_grader_readiness": load_llm_grader_readiness(Path.cwd(), naos_root, policy),
        "behavioral_governance_readiness": load_behavioral_governance_readiness(Path.cwd(), naos_root, policy),
        "policy_overrides": load_policy_overrides(Path.cwd(), naos_root, policy),
        "pr_risk_classification": load_pr_risk_classification(Path.cwd(), naos_root, policy),
        "agentic_workflow_review": load_agentic_workflow_review(Path.cwd(), naos_root, policy),
        "pre_implementation_alignment_review": load_pre_implementation_alignment_review(Path.cwd(), naos_root, policy),
        "agentic_workflow_config": load_agentic_workflow_config(Path.cwd(), naos_root, policy),
        "pre_implementation_alignment_artifact": load_pre_implementation_alignment_artifact(Path.cwd(), naos_root, policy),
        "calibration_shadow": load_calibration_shadow(Path.cwd(), naos_root, policy),
        "evidence_classification": load_evidence_classification(Path.cwd(), naos_root, policy),
        "failure_mode_observations": load_failure_mode_observations(Path.cwd(), naos_root, policy),
        "cross_harness_review_readiness": load_cross_harness_review_readiness(Path.cwd(), naos_root, policy),
        "summary": summary,
        "gates": gate_results,
        "limitations": TEAM_GATEKEEPER_LIMITATIONS,
        "not_claimed": TEAM_GATEKEEPER_NOT_CLAIMED,
        "human_review_required": human_review_required,
    }


def print_text(report: dict[str, Any]) -> None:
    summary = report["summary"]
    print(f"NAOS gate status ({report['profile']}, manifest: {report['manifest_source']})")
    print(f"team context: {report.get('team_id') or 'none'} ({report.get('team_resolution_source') or 'unknown'})")
    print(
        "summary: "
        f"ready={summary['ready']} "
        f"required_missing={summary['required_missing']} "
        f"blocked={summary['blocked']} "
        f"warnings={summary['warning']} "
        f"advisory={summary['advisory_missing']}"
    )
    for gate in report["gates"]:
        print(f"{gate['id']} {gate['status']} [{gate['severity']}] - {gate['name']}")
        if gate["missing_inputs"]:
            print(f"  missing inputs: {', '.join(gate['missing_inputs'])}")
        if gate["missing_evidence"]:
            print(f"  missing evidence: {', '.join(gate['missing_evidence'])}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Report NAOS gatekeeper readiness.")
    parser.add_argument("--manifest", help="Path to gatekeepers.yaml. Defaults to NAOS_ROOT/gatekeepers.yaml or kit template.")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT", "naos"), help="Generated project NAOS root. Default: naos")
    parser.add_argument("--policy", help="Optional policy file used for profile and report path conventions.")
    parser.add_argument("--profile", help="Profile name: quickstart, lite, standard, assured. Default: NAOS_PROFILE or policy default")
    parser.add_argument("--team-id", default=os.environ.get("TEAM_ID") or os.environ.get("NAOS_TEAM_ID"), help="Optional filesystem-safe team id for team-scoped gatekeeper config.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of text.")
    parser.add_argument("--output", help="Optional JSON output path.")
    parser.add_argument("--fail-on-blocking", action="store_true", help="Exit non-zero if any blocking gate is blocked.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy = load_policy(args.policy, args.naos_root, Path.cwd())
        profile = normalize_profile(args.profile, policy)
        location = resolve_manifest(args.manifest, args.naos_root)
        manifest = load_manifest(location.path)
        report = evaluate_manifest(manifest, profile, location, args.naos_root, policy, explicit_team_id=args.team_id)
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        return emit_input_error(exc, output=args.output, json_output=args.json)

    output = None
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

    if args.fail_on_blocking and report["summary"]["blocked"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
