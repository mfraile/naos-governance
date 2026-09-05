#!/usr/bin/env python3
"""Evaluate configurable systemic impact and coherence review obligations."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    controlled_now_utc,
    controlled_utc_now_text,
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    ignored_scan_dirs,
    is_kit_repository,
    kit_root,
    load_policy,
    normalize_profile,
    report_output_path,
    severity_for_profile,
    status_from_counts,
    write_report,
)


REVIEW_STATUSES = {"ready", "review_required", "blocked", "advisory", "not_configured", "disabled", "unknown"}
SEVERITY_TO_STATUS = {
    "none": "ready",
    "advisory": "advisory",
    "warning": "review_required",
    "required": "review_required",
    "blocking": "blocked",
}

DEFAULT_ACTIONABLE_LIMIT = 20
ACTIONABLE_SEVERITIES = {"blocking", "required", "warning"}
ACTIONABLE_FAMILY_STATUSES = {"blocked", "review_required"}
DISABLED_WAIVED_STATUSES = {"disabled", "waived", "waiver_visible"}
PRESENTATION_SOURCE_ORDER = {
    "dashboard-native": 0,
    "self-check": 1,
    "systemic-impact": 2,
}

CHANGED_PATH_REVIEW_SCHEMA = "naos.systemic_impact_changed_path_review.v1"
CHANGED_PATH_DISPOSITIONS = {
    "updated",
    "reviewed_no_change",
    "not_applicable",
    "update_required",
    "unresolved",
}
CLOSED_CHANGED_PATH_DISPOSITIONS = {
    "updated",
    "reviewed_no_change",
    "not_applicable",
}
CHANGED_PATH_TARGET_KINDS = {
    "artifact_family",
    "review_surface",
    "declared_artifact",
}
CHANGED_PATH_REVIEW_RECORD_KEYS = {"schema", "changed_paths", "reviews"}
CHANGED_PATH_REVIEW_ENTRY_KEYS = {
    "target_kind",
    "target_id",
    "disposition",
    "rationale",
    "evidence_refs",
}


def _compact_text(value: Any) -> str:
    if isinstance(value, (dict, list)):
        text = json.dumps(value, sort_keys=True, ensure_ascii=False)
    else:
        text = str(value)
    return " ".join(text.split())


def _detail_values(finding: dict[str, Any], *keys: str) -> list[Any]:
    values: list[Any] = []
    for key in keys:
        value = finding.get(key)
        if isinstance(value, list):
            values.extend(value)
        elif value not in (None, "", [], {}):
            values.append(value)
    return values


def finding_occurrence(
    *,
    source: str,
    identity: str,
    order: int,
    finding: dict[str, Any],
    family_label: str | None = None,
    family_status: str | None = None,
    parent_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a presentation-only occurrence without mutating report data."""
    parent = parent_evidence or {}
    return {
        "source": source,
        "identity": identity,
        "family_label": family_label or source,
        "order": order,
        "source_rank": PRESENTATION_SOURCE_ORDER.get(source, 99),
        "id": finding.get("id"),
        "family_id": finding.get("family_id"),
        "family_status": family_status,
        "severity": str(finding.get("severity") or "unknown"),
        "status": str(finding.get("status") or "unknown"),
        "message": str(finding.get("message") or "No finding message was provided."),
        "required_next_actions": _detail_values(
            finding,
            "required_next_actions",
            "next_actions",
            "next_action",
        ),
        "evidence": _detail_values(
            finding,
            "evidence",
            "evidence_refs",
            "evidence_ref",
            "source_refs",
        ),
        "waivers": _detail_values(finding, "waivers", "waiver", "waiver_ref")
        + _detail_values(parent, "waivers"),
        "limitations": _detail_values(finding, "limitations", "limitation")
        + _detail_values(parent, "limitations"),
        "residual_risks": _detail_values(
            finding,
            "residual_risks",
            "residual_risk",
            "residual_risk_ref",
            "known_gap_ref",
        )
        + _detail_values(
            parent,
            "residual_risks",
            "residual_risk",
            "residual_risk_ref",
            "known_gaps",
            "known_gap",
            "known_gap_ref",
        ),
        "related_families": _detail_values(finding, "related_families"),
    }


def systemic_finding_occurrences(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Return flat findings with stable family-scoped positional identities."""
    families = [item for item in report.get("artifact_families") or [] if isinstance(item, dict)]
    family_positions = {
        str(item.get("family_id")): (index, item)
        for index, item in enumerate(families)
        if item.get("family_id")
    }
    per_family_indexes: dict[str, int] = {}
    occurrences: list[dict[str, Any]] = []
    for order, item in enumerate(report.get("findings") or []):
        if not isinstance(item, dict):
            continue
        family_id = str(item.get("family_id") or "unknown")
        family_index, family = family_positions.get(family_id, (-1, {}))
        finding_index = per_family_indexes.get(family_id, 0)
        per_family_indexes[family_id] = finding_index + 1
        occurrences.append(
            finding_occurrence(
                source="systemic-impact",
                identity=(
                    f"systemic-impact/family[{family_index}]={family_id}"
                    f"/finding[{finding_index}]"
                ),
                order=order,
                finding=item,
                family_label=f"systemic-impact[{family_index}]:{family_id}",
                family_status=str(family.get("evaluated_status") or "unknown"),
                parent_evidence=family,
            )
        )
    return occurrences


def finding_presentation_bucket(occurrence: dict[str, Any]) -> str:
    """Classify presentation rows without changing detector classifications."""
    status = str(occurrence.get("status") or "unknown")
    severity = str(occurrence.get("severity") or "unknown")
    family_status = occurrence.get("family_status")
    if status in DISABLED_WAIVED_STATUSES:
        return "disabled_waived"
    if family_status is not None:
        if family_status in ACTIONABLE_FAMILY_STATUSES:
            return "actionable"
        if family_status in {"not_configured", "advisory"}:
            return "advisory_not_configured"
        if family_status == "disabled":
            return "disabled_waived"
        return "unknown_other"
    if status in {"advisory", "not_configured"} or severity == "advisory":
        return "advisory_not_configured"
    if severity in ACTIONABLE_SEVERITIES:
        return "actionable"
    return "unknown_other"


def _actionable_sort_key(occurrence: dict[str, Any]) -> tuple[int, int, int]:
    severity = str(occurrence.get("severity") or "unknown")
    family_status = occurrence.get("family_status")
    if severity == "blocking":
        severity_rank = 0
    elif severity == "required":
        severity_rank = 1
    elif severity == "warning":
        severity_rank = 2
    elif family_status == "blocked":
        severity_rank = 0
    elif family_status == "review_required":
        severity_rank = 1
    else:
        severity_rank = 3
    return (
        severity_rank,
        int(occurrence.get("source_rank") or 0),
        int(occurrence.get("order") or 0),
    )


def format_finding_occurrence(
    occurrence: dict[str, Any],
    *,
    concise: bool = False,
) -> str:
    """Render one complete human-readable source occurrence."""
    message = occurrence.get("message")
    if concise and occurrence.get("status") == "script_error":
        message = (
            "A configured check could not run; expand this report with --all "
            "for the captured diagnostic."
        )
    base = (
        f"[{occurrence.get('identity')}] "
        f"{occurrence.get('id') or 'unknown-id'} · "
        f"{occurrence.get('severity')}/{occurrence.get('status')} — "
        f"{_compact_text(message)}"
    )
    detail_groups = (
        ("next", occurrence.get("required_next_actions") or []),
        ("evidence", occurrence.get("evidence") or []),
        ("waiver", occurrence.get("waivers") or []),
        ("limitation", occurrence.get("limitations") or []),
        ("residual risk", occurrence.get("residual_risks") or []),
        ("related", occurrence.get("related_families") or []),
    )
    details = [
        f"{label}: {', '.join(_compact_text(value) for value in values)}"
        for label, values in detail_groups
        if values
    ]
    return " | ".join([base, *details])


def _family_count_text(occurrences: list[dict[str, Any]]) -> tuple[int, str]:
    family_counts: dict[str, int] = {}
    for occurrence in occurrences:
        label = str(occurrence.get("family_label") or occurrence.get("source") or "unknown")
        family_counts[label] = family_counts.get(label, 0) + 1
    details = "; ".join(f"{label}: {count}" for label, count in family_counts.items())
    return len(family_counts), details


def build_actionable_presentation(
    occurrences: list[dict[str, Any]],
    *,
    expansion_command: str,
    show_all: bool = False,
    actionable_limit: int = DEFAULT_ACTIONABLE_LIMIT,
    limitations: list[Any] | None = None,
) -> dict[str, Any]:
    """Build bounded default rows or complete expanded human detail."""
    buckets = {
        "actionable": [],
        "advisory_not_configured": [],
        "disabled_waived": [],
        "unknown_other": [],
    }
    for occurrence in occurrences:
        buckets[finding_presentation_bucket(occurrence)].append(occurrence)
    counts = {key: len(value) for key, value in buckets.items()}
    summary = (
        f"{counts['actionable']} actionable · "
        f"{counts['advisory_not_configured']} advisory/not-configured · "
        f"{counts['disabled_waived']} disabled/waived · "
        f"{counts['unknown_other']} unknown/other "
        f"(run with --all: `{expansion_command}`)"
    )
    if show_all:
        rows = [
            {"kind": "finding", "bucket": finding_presentation_bucket(item), "text": format_finding_occurrence(item)}
            for item in occurrences
        ]
    else:
        actionable = sorted(buckets["actionable"], key=_actionable_sort_key)
        displayed = actionable[:actionable_limit]
        rows = [
            {
                "kind": "finding",
                "bucket": "actionable",
                "text": format_finding_occurrence(item, concise=True),
            }
            for item in displayed
        ]
        rollups = (
            ("actionable", actionable[len(displayed) :], "additional actionable"),
            (
                "advisory_not_configured",
                buckets["advisory_not_configured"],
                "advisory/not-configured",
            ),
            ("disabled_waived", buckets["disabled_waived"], "disabled/waived"),
            ("unknown_other", buckets["unknown_other"], "unknown/other"),
        )
        for bucket, collapsed, label in rollups:
            if not collapsed:
                continue
            count = len(collapsed)
            if bucket == "actionable":
                family_count, family_details = _family_count_text(collapsed)
                rows.append(
                    {
                        "kind": "rollup",
                        "bucket": bucket,
                        "count": count,
                        "family_count": family_count,
                        "family_counts": family_details,
                        "text": (
                            f"{count} {label} findings across {family_count} source "
                            f"families ({family_details}) — expand with "
                            f"`{expansion_command}`"
                        ),
                    }
                )
                continue
            family_count, family_details = _family_count_text(collapsed)
            rows.append(
                {
                    "kind": "rollup",
                    "bucket": bucket,
                    "count": count,
                    "family_count": family_count,
                    "family_counts": family_details,
                    "text": (
                        f"{count} {label} findings across {family_count} source "
                        f"families ({family_details}) — expand with `{expansion_command}`"
                    ),
                }
            )
    return {
        "summary": summary,
        "counts": counts,
        "rows": rows,
        "limitations": [_compact_text(item) for item in limitations or []],
        "show_all": show_all,
        "occurrences": len(occurrences),
    }


def presentation_lines(presentation: dict[str, Any]) -> list[str]:
    """Render a presentation object as console-friendly lines."""
    lines = [str(presentation["summary"])]
    if presentation["rows"]:
        heading = "All finding occurrences:" if presentation["show_all"] else "Actionable findings and retained-evidence rollups:"
        lines.append(heading)
        lines.extend(f"- {row['text']}" for row in presentation["rows"])
    if presentation["show_all"] and presentation["limitations"]:
        lines.append("Report limitations:")
        lines.extend(f"- {item}" for item in presentation["limitations"])
    return lines


def utc_now_text() -> str:
    return controlled_utc_now_text()


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping: {path}")
    return data


def default_rules_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "systemic_impact_rules.yaml"


def resolve_rules_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None = None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("systemic_impact_rules") or "systemic_impact_rules.yaml")
    project_rules = root / naos_root / filename
    if project_rules.exists():
        return project_rules, "project"
    return default_rules_template(), "template"


def as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if value:
        return [str(value)]
    return []


def dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _changed_path_validation_error(value: Any) -> str | None:
    if not isinstance(value, str):
        return "value must be a string"
    if any(separator in value for separator in ("\n", "\r", "\u2028", "\u2029")):
        return "line separators are not allowed"
    raw = value.strip()
    if not raw or "\\" in raw or "\x00" in raw:
        return "value must be a non-empty POSIX path without backslashes or NUL"
    candidate = PurePosixPath(raw)
    if (
        candidate.is_absolute()
        or any(part == ".." for part in candidate.parts)
        or (candidate.parts and candidate.parts[0].endswith(":"))
    ):
        return "value must be repository-relative and cannot traverse a parent"
    normalized = candidate.as_posix()
    if normalized in {"", "."}:
        return "value must name a repository-relative artifact"
    return None


def normalize_changed_path(value: str) -> str:
    """Return a safe repository-relative POSIX path, including for deletions."""
    error = _changed_path_validation_error(value)
    if error:
        raise ValueError(
            "Changed path must be a normalized repository-relative POSIX path "
            f"({error}): {value!r}"
        )
    raw = value.strip()
    candidate = PurePosixPath(raw)
    normalized = candidate.as_posix()
    return normalized.removeprefix("./")


@lru_cache(maxsize=None)
def _glob_regex(pattern: str) -> re.Pattern[str]:
    """Compile the subset of repository globs used by systemic-impact rules."""
    expression = ""
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "*":
            if index + 1 < len(pattern) and pattern[index + 1] == "*":
                index += 2
                if index < len(pattern) and pattern[index] == "/":
                    expression += "(?:.*/)?"
                    index += 1
                else:
                    expression += ".*"
                continue
            expression += "[^/]*"
        elif character == "?":
            expression += "[^/]"
        else:
            expression += re.escape(character)
        index += 1
    return re.compile(f"^{expression}$")


def path_matches_pattern(path: str, pattern: str) -> bool:
    if not pattern or "<" in pattern or ">" in pattern:
        return False
    normalized_pattern = pattern.removeprefix("./")
    return bool(_glob_regex(normalized_pattern).match(path))


def _matching_patterns(path: str, patterns: list[str]) -> list[str]:
    return [pattern for pattern in patterns if path_matches_pattern(path, pattern)]


def classify_changed_path(
    path: str,
    rules: dict[str, Any],
    repository_role: str | None = None,
) -> dict[str, Any]:
    """Classify a supplied path without requiring that the file still exists."""
    normalized = normalize_changed_path(path)
    routing = (
        rules.get("changed_path_routing")
        if isinstance(rules.get("changed_path_routing"), dict)
        else {}
    )
    exclusions = [
        item for item in routing.get("exclusions") or [] if isinstance(item, dict)
    ]
    matched_exclusions = [
        {
            "patterns": _matching_patterns(normalized, as_list(item.get("patterns"))),
            "reason": str(item.get("reason") or "No reason recorded."),
        }
        for item in exclusions
        if _matching_patterns(normalized, as_list(item.get("patterns")))
    ]
    if matched_exclusions:
        return {
            "path": normalized,
            "classification": "excluded",
            "matched_artifact_families": [],
            "matched_routing_families": [],
            "matched_generated_routing_families": [],
            "matched_kit_source_routing_families": [],
            "matched_adopter_generated_routing_families": [],
            "matched_exclusions": matched_exclusions,
            "review_triggers": [],
        }

    artifact_families = [
        item for item in rules.get("artifact_families") or [] if isinstance(item, dict)
    ]
    matched_artifact_families = sorted(
        str(item.get("family_id"))
        for item in artifact_families
        if item.get("family_id")
        and _matching_patterns(normalized, as_list(item.get("file_patterns")))
    )
    routing_families = [
        item for item in routing.get("routing_families") or [] if isinstance(item, dict)
    ]
    matched_routing_families = sorted(
        str(item.get("route_id"))
        for item in routing_families
        if item.get("route_id")
        and _matching_patterns(normalized, as_list(item.get("source_patterns")))
    )
    matched_generated_routing_families = sorted(
        str(item.get("route_id"))
        for item in routing_families
        if item.get("route_id")
        and _matching_patterns(normalized, as_list(item.get("generated_patterns")))
    )
    governed_patterns = as_list(routing.get("governed_patterns"))
    governed = bool(_matching_patterns(normalized, governed_patterns))
    if repository_role == "kit_source":
        matched = bool(matched_routing_families)
    elif repository_role == "adopter_project":
        matched = bool(matched_generated_routing_families)
    else:
        matched = bool(
            matched_artifact_families
            or matched_routing_families
            or matched_generated_routing_families
        )
    return {
        "path": normalized,
        "classification": "governed" if matched else "unclassified",
        "within_governed_scope": governed,
        "matched_artifact_families": matched_artifact_families,
        "matched_routing_families": matched_routing_families,
        "matched_generated_routing_families": matched_generated_routing_families,
        "matched_kit_source_routing_families": matched_routing_families,
        "matched_adopter_generated_routing_families": (
            matched_generated_routing_families
        ),
        "matched_exclusions": [],
        "review_triggers": [],
    }


def _rules_indexes(rules: dict[str, Any]) -> dict[str, Any]:
    artifact_families = [
        item for item in rules.get("artifact_families") or [] if isinstance(item, dict)
    ]
    review_surfaces = [
        item for item in rules.get("review_surfaces") or [] if isinstance(item, dict)
    ]
    routing = (
        rules.get("changed_path_routing")
        if isinstance(rules.get("changed_path_routing"), dict)
        else {}
    )
    routing_families = [
        item for item in routing.get("routing_families") or [] if isinstance(item, dict)
    ]
    artifact_by_id = {
        str(item.get("family_id")): item
        for item in artifact_families
        if item.get("family_id")
    }
    surface_by_id = {
        str(item.get("surface_id")): item
        for item in review_surfaces
        if item.get("surface_id")
    }
    route_by_id = {
        str(item.get("route_id")): item
        for item in routing_families
        if item.get("route_id")
    }
    return {
        "artifact_families": artifact_families,
        "artifact_by_id": artifact_by_id,
        "review_surfaces": review_surfaces,
        "surface_by_id": surface_by_id,
        "routing_families": routing_families,
        "route_by_id": route_by_id,
    }


def _duplicate_identifiers(items: list[str]) -> list[str]:
    counts: dict[str, int] = {}
    for item in items:
        counts[item] = counts.get(item, 0) + 1
    return sorted(item for item, count in counts.items() if count > 1)


def relationship_rule_integrity(rules: dict[str, Any]) -> dict[str, Any]:
    indexes = _rules_indexes(rules)
    artifact_ids = [
        str(item.get("family_id"))
        for item in indexes["artifact_families"]
        if item.get("family_id")
    ]
    surface_ids = [
        str(item.get("surface_id"))
        for item in indexes["review_surfaces"]
        if item.get("surface_id")
    ]
    route_ids = [
        str(item.get("route_id"))
        for item in indexes["routing_families"]
        if item.get("route_id")
    ]
    duplicate_ids = _duplicate_identifiers(artifact_ids + surface_ids + route_ids)
    known_targets = set(artifact_ids) | set(surface_ids)
    referenced_targets: list[str] = []
    empty_routes: list[str] = []
    for family in indexes["artifact_families"]:
        referenced_targets.extend(
            dedupe(
                as_list(family.get("related_families"))
                + as_list(family.get("impact_targets"))
            )
        )
    for route in indexes["routing_families"]:
        targets = as_list(route.get("targets"))
        referenced_targets.extend(targets)
        if not targets:
            empty_routes.append(str(route.get("route_id") or "unknown"))
    unknown_targets = sorted(set(referenced_targets) - known_targets)
    findings = []
    if duplicate_ids:
        findings.append(
            {
                "type": "duplicate_identifier",
                "message": "Identifiers must be unique across artifact families, review surfaces, and routing families.",
                "values": duplicate_ids,
            }
        )
    if unknown_targets:
        findings.append(
            {
                "type": "unknown_relationship_target",
                "message": "Relationship targets must be declared artifact families or typed review surfaces.",
                "values": unknown_targets,
            }
        )
    if empty_routes:
        findings.append(
            {
                "type": "routing_family_without_targets",
                "message": "Every changed-path routing family must declare at least one target.",
                "values": sorted(empty_routes),
            }
        )
    return {
        "status": "fail" if findings else "pass",
        "duplicate_identifiers": duplicate_ids,
        "unknown_relationship_targets": unknown_targets,
        "routing_families_without_targets": sorted(empty_routes),
        "findings": findings,
    }


def _safe_declared_path(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return normalize_changed_path(value)
    except ValueError:
        return None


def capability_declared_relationships(root: Path) -> list[dict[str, Any]]:
    """Load exact capability-declared file relationships without guessing names."""
    groups: list[dict[str, Any]] = []
    capability_roots = [root / "capabilities", root / "naos" / "capabilities"]
    seen_paths: set[str] = set()
    for capability_root in capability_roots:
        if not capability_root.is_dir():
            continue
        for path in sorted(capability_root.glob("*.yaml")):
            relative = relative_text(root, path)
            if path.name.startswith("_") or relative in seen_paths:
                continue
            seen_paths.add(relative)
            try:
                data = load_yaml(path)
            except (OSError, ValueError, yaml.YAMLError):
                continue
            members = [relative]
            for field in ("related_scripts", "related_schemas", "related_docs"):
                members.extend(
                    item
                    for value in data.get(field) or []
                    if (item := _safe_declared_path(value)) is not None
                )
            for validator in data.get("validators") or []:
                if not isinstance(validator, dict):
                    continue
                script = _safe_declared_path(validator.get("script"))
                if script:
                    members.append(script)
            members = dedupe(members)
            if len(members) > 1:
                groups.append(
                    {
                        "relationship_id": str(data.get("id") or path.stem),
                        "kind": "capability_contract",
                        "source": relative,
                        "members": members,
                    }
                )
    return groups


def _target_kind(target_id: str, indexes: dict[str, Any]) -> str | None:
    if target_id in indexes["artifact_by_id"]:
        return "artifact_family"
    if target_id in indexes["surface_by_id"]:
        return "review_surface"
    return None


def _obligation_id(change_set_sha256: str, target_kind: str, target_id: str) -> str:
    payload = "\0".join((change_set_sha256, target_kind, target_id)).encode("utf-8")
    return "impact-" + hashlib.sha256(payload).hexdigest()[:20]


def _review_record_schema_findings(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Enforce the portable review-record schema without needing a schema file."""
    findings: list[dict[str, Any]] = []

    def add(location: str, message: str) -> None:
        findings.append(
            {
                "type": "review_record_schema_validation",
                "location": location,
                "message": message,
            }
        )

    unexpected = sorted(set(data) - CHANGED_PATH_REVIEW_RECORD_KEYS)
    missing = sorted(CHANGED_PATH_REVIEW_RECORD_KEYS - set(data))
    if unexpected:
        add("$", f"Unexpected top-level properties: {', '.join(unexpected)}.")
    if missing:
        add("$", f"Missing required top-level properties: {', '.join(missing)}.")
    if data.get("schema") != CHANGED_PATH_REVIEW_SCHEMA:
        add("schema", f"Value must be {CHANGED_PATH_REVIEW_SCHEMA}.")

    changed_paths = data.get("changed_paths")
    if not isinstance(changed_paths, list) or not changed_paths:
        add("changed_paths", "Value must be a non-empty array of strings.")
    else:
        for index, value in enumerate(changed_paths):
            if not isinstance(value, str) or not value:
                add(f"changed_paths[{index}]", "Value must be a non-empty string.")
                continue
            error = _changed_path_validation_error(value)
            if error:
                add(f"changed_paths[{index}]", f"Invalid changed path: {error}.")

    reviews = data.get("reviews")
    if not isinstance(reviews, list):
        add("reviews", "Value must be an array.")
        return findings
    for index, item in enumerate(reviews):
        location = f"reviews[{index}]"
        if not isinstance(item, dict):
            add(location, "Value must be an object.")
            continue
        unexpected = sorted(set(item) - CHANGED_PATH_REVIEW_ENTRY_KEYS)
        required = {"target_kind", "target_id", "disposition"}
        missing = sorted(required - set(item))
        if unexpected:
            add(location, f"Unexpected properties: {', '.join(unexpected)}.")
        if missing:
            add(location, f"Missing required properties: {', '.join(missing)}.")
        if item.get("target_kind") not in CHANGED_PATH_TARGET_KINDS:
            add(f"{location}.target_kind", "Value is not a supported target kind.")
        target_id = item.get("target_id")
        if not isinstance(target_id, str) or not target_id:
            add(f"{location}.target_id", "Value must be a non-empty string.")
        disposition = item.get("disposition")
        if disposition not in CHANGED_PATH_DISPOSITIONS:
            add(f"{location}.disposition", "Value is not a supported disposition.")
        if "rationale" in item and not isinstance(item.get("rationale"), str):
            add(f"{location}.rationale", "Value must be a string.")
        if "evidence_refs" in item:
            evidence_refs = item.get("evidence_refs")
            if not isinstance(evidence_refs, list):
                add(f"{location}.evidence_refs", "Value must be an array of strings.")
            else:
                for evidence_index, evidence_ref in enumerate(evidence_refs):
                    if not isinstance(evidence_ref, str) or not evidence_ref:
                        add(
                            f"{location}.evidence_refs[{evidence_index}]",
                            "Value must be a non-empty string.",
                        )
        if disposition in CLOSED_CHANGED_PATH_DISPOSITIONS:
            rationale = item.get("rationale")
            evidence_refs = item.get("evidence_refs")
            if not isinstance(rationale, str) or not rationale:
                add(f"{location}.rationale", "Closed dispositions require rationale.")
            if not isinstance(evidence_refs, list) or not evidence_refs:
                add(
                    f"{location}.evidence_refs",
                    "Closed dispositions require at least one evidence reference.",
                )
    return findings


def load_changed_path_review_record(
    path: Path,
) -> tuple[list[str], list[dict[str, Any]], list[dict[str, Any]]]:
    data = load_yaml(path)
    findings = _review_record_schema_findings(data)
    raw_changed_paths = data.get("changed_paths")
    normalized_changed_paths: list[str] = []
    if not isinstance(raw_changed_paths, list) or not raw_changed_paths:
        findings.append(
            {
                "type": "review_record_changed_paths",
                "message": "Review record must bind to a non-empty changed_paths list.",
            }
        )
    else:
        for index, value in enumerate(raw_changed_paths):
            if not isinstance(value, str):
                continue
            try:
                normalized_changed_paths.append(normalize_changed_path(value))
            except ValueError as exc:
                findings.append(
                    {
                        "type": "review_record_changed_path",
                        "message": f"Review-record changed path {index}: {exc}",
                    }
                )
        if len(normalized_changed_paths) != len(set(normalized_changed_paths)):
            findings.append(
                {
                    "type": "duplicate_review_record_changed_path",
                    "message": "Review-record changed_paths must be unique.",
                }
            )

    reviews = data.get("reviews")
    if not isinstance(reviews, list):
        findings.append(
            {
                "type": "review_record_shape",
                "message": "Review record must contain a reviews list.",
            }
        )
        return normalized_changed_paths, [], findings
    normalized_reviews: list[dict[str, Any]] = []
    for index, item in enumerate(reviews):
        if not isinstance(item, dict):
            findings.append(
                {
                    "type": "review_record_entry_shape",
                    "message": f"Review entry {index} must be a mapping.",
                }
            )
            continue
        target_kind = (
            item.get("target_kind") if isinstance(item.get("target_kind"), str) else ""
        )
        target_id = item.get("target_id") if isinstance(item.get("target_id"), str) else ""
        disposition = (
            item.get("disposition") if isinstance(item.get("disposition"), str) else ""
        )
        rationale = item.get("rationale") if isinstance(item.get("rationale"), str) else ""
        rationale = rationale.strip()
        raw_evidence_refs = item.get("evidence_refs")
        evidence_refs = (
            [value for value in raw_evidence_refs if isinstance(value, str) and value]
            if isinstance(raw_evidence_refs, list)
            else []
        )
        if target_kind not in CHANGED_PATH_TARGET_KINDS or not target_id:
            findings.append(
                {
                    "type": "review_record_target",
                    "message": f"Review entry {index} has an invalid target kind or empty target id.",
                }
            )
            continue
        if disposition not in CHANGED_PATH_DISPOSITIONS:
            findings.append(
                {
                    "type": "review_record_disposition",
                    "message": f"Review entry {index} has unsupported disposition {disposition!r}.",
                }
            )
            continue
        if disposition in CLOSED_CHANGED_PATH_DISPOSITIONS and (
            not rationale or not evidence_refs
        ):
            findings.append(
                {
                    "type": "review_record_closure_evidence",
                    "message": f"Review entry {index} requires rationale and evidence_refs for {disposition}.",
                }
            )
        normalized_reviews.append(
            {
                "target_kind": target_kind,
                "target_id": target_id,
                "disposition": disposition,
                "rationale": rationale,
                "evidence_refs": evidence_refs,
            }
        )
    return normalized_changed_paths, normalized_reviews, findings


def build_changed_path_review(
    *,
    root: Path,
    rules: dict[str, Any],
    changed_paths: list[str],
    artifact_results: list[dict[str, Any]],
    repository_role: str,
    review_record_path: Path | None = None,
) -> dict[str, Any]:
    normalized_changed_paths = dedupe(
        [normalize_changed_path(item) for item in changed_paths]
    )
    change_set_sha256 = hashlib.sha256(
        ("\n".join(sorted(normalized_changed_paths)) + "\n").encode("utf-8")
    ).hexdigest()
    indexes = _rules_indexes(rules)
    artifact_result_by_id = {
        str(item.get("family_id")): item
        for item in artifact_results
        if item.get("family_id")
    }
    integrity = relationship_rule_integrity(rules)
    integrity_findings = list(integrity["findings"])
    review_records: list[dict[str, Any]] = []
    review_record_changed_paths: list[str] = []
    if review_record_path is not None:
        try:
            (
                review_record_changed_paths,
                review_records,
                record_findings,
            ) = load_changed_path_review_record(review_record_path)
            integrity_findings.extend(record_findings)
            if sorted(review_record_changed_paths) != sorted(normalized_changed_paths):
                integrity_findings.append(
                    {
                        "type": "review_record_change_set_mismatch",
                        "message": "Review record changed_paths do not exactly match the supplied change set.",
                        "expected": sorted(normalized_changed_paths),
                        "actual": sorted(review_record_changed_paths),
                    }
                )
        except (OSError, ValueError, yaml.YAMLError) as exc:
            integrity_findings.append(
                {
                    "type": "review_record_load",
                    "message": f"Could not load review record {review_record_path}: {exc}",
                }
            )

    record_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for record in review_records:
        key = (record["target_kind"], record["target_id"])
        if key in record_by_key:
            integrity_findings.append(
                {
                    "type": "duplicate_review_record",
                    "message": "A review obligation may have only one review-record entry.",
                    "value": list(key),
                }
            )
            continue
        record_by_key[key] = record

    family_by_id = indexes["artifact_by_id"]
    route_by_id = indexes["route_by_id"]
    declared_groups = capability_declared_relationships(root)
    path_emitted_keys: set[tuple[str, str, str]] = set()
    changed_entries: list[dict[str, Any]] = []

    for supplied_path in normalized_changed_paths:
        classification = classify_changed_path(
            supplied_path,
            rules,
            repository_role=repository_role,
        )
        path = classification["path"]
        classification["active_repository_role"] = repository_role
        if repository_role == "kit_source":
            classification["active_repository_routing_families"] = classification[
                "matched_kit_source_routing_families"
            ]
            classification["cross_role_propagation_candidates"] = classification[
                "matched_adopter_generated_routing_families"
            ]
        else:
            classification["active_repository_routing_families"] = classification[
                "matched_adopter_generated_routing_families"
            ]
            classification["cross_role_propagation_candidates"] = classification[
                "matched_kit_source_routing_families"
            ]
        if classification["classification"] == "unclassified":
            integrity_findings.append(
                {
                    "type": "unclassified_changed_path",
                    "message": "Governed changed path has no semantic artifact or routing family.",
                    "value": path,
                }
            )

        sources_by_target: dict[str, dict[str, list[str]]] = {}
        triggers: list[str] = []
        required_outputs: list[str] = []
        for family_id in classification["matched_artifact_families"]:
            family = family_by_id[family_id]
            triggers.extend(as_list(family.get("review_triggers")))
            required_outputs.extend(as_list(family.get("required_review_outputs")))
            # `related_families` remains the broad current-state context graph.
            # Explicit changed-path review routes only declared downstream
            # `impact_targets`, avoiding symmetric all-to-all review noise.
            targets = dedupe(as_list(family.get("impact_targets")))
            for target_id in targets:
                sources_by_target.setdefault(
                    target_id, {"artifact_families": [], "routing_families": []}
                )["artifact_families"].append(family_id)
        matched_routes = (
            classification["matched_routing_families"]
            if repository_role == "kit_source"
            else classification["matched_generated_routing_families"]
        )
        for route_id in matched_routes:
            route = route_by_id[route_id]
            triggers.extend(as_list(route.get("review_triggers")))
            required_outputs.extend(as_list(route.get("required_review_outputs")))
            for target_id in as_list(route.get("targets")):
                sources_by_target.setdefault(
                    target_id, {"artifact_families": [], "routing_families": []}
                )["routing_families"].append(route_id)

        obligations: list[dict[str, Any]] = []
        for target_id in sorted(sources_by_target):
            target_kind = _target_kind(target_id, indexes)
            if target_kind is None:
                continue
            key = (path, target_kind, target_id)
            path_emitted_keys.add(key)
            target_result = artifact_result_by_id.get(target_id, {})
            surface = indexes["surface_by_id"].get(target_id, {})
            source_groups = sources_by_target[target_id]
            obligations.append(
                {
                    "obligation_id": _obligation_id(
                        change_set_sha256, target_kind, target_id
                    ),
                    "target_kind": target_kind,
                    "target_id": target_id,
                    "target_name": target_result.get("name")
                    or surface.get("name")
                    or target_id,
                    "target_status": target_result.get("evaluated_status")
                    or "human_review_required",
                    "source_artifact_families": sorted(
                        set(source_groups["artifact_families"])
                    ),
                    "source_routing_families": sorted(
                        set(source_groups["routing_families"])
                    ),
                    "review_triggers": dedupe(triggers),
                    "required_review_outputs": dedupe(required_outputs),
                    "disposition": "unresolved",
                    "rationale": "",
                    "evidence_refs": [],
                }
            )

        obligation_by_key = {
            (path, item["target_kind"], item["target_id"]): item
            for item in obligations
        }
        declared_relationship_ids: list[str] = []
        for group in declared_groups:
            if path not in group["members"]:
                continue
            declared_relationship_ids.append(group["relationship_id"])
            target_specs = (
                [
                    ("declared_artifact", item, item)
                    for item in group["members"]
                    if item != path
                ]
                if path == group["source"]
                else [("artifact_family", "capabilities", group["source"])]
            )
            for target_kind, target_id, declared_artifact in target_specs:
                key = (path, target_kind, target_id)
                if key in path_emitted_keys:
                    existing = obligation_by_key.get(key)
                    if existing is not None:
                        existing["declared_relationships"] = dedupe(
                            as_list(existing.get("declared_relationships"))
                            + [group["relationship_id"]]
                        )
                        existing["declared_artifacts"] = dedupe(
                            as_list(existing.get("declared_artifacts"))
                            + [declared_artifact]
                        )
                    continue
                path_emitted_keys.add(key)
                target_result = artifact_result_by_id.get(target_id, {})
                declared_obligation = {
                    "obligation_id": _obligation_id(
                        change_set_sha256, target_kind, target_id
                    ),
                    "target_kind": target_kind,
                    "target_id": target_id,
                    "target_name": (
                        target_id
                        if target_kind == "declared_artifact"
                        else target_result.get("name") or target_id
                    ),
                    "target_status": (
                        "present"
                        if target_kind == "declared_artifact"
                        and (root / target_id).is_file()
                        else "not_present"
                        if target_kind == "declared_artifact"
                        else target_result.get("evaluated_status")
                        or "human_review_required"
                    ),
                    "source_artifact_families": [],
                    "source_routing_families": [],
                    "declared_relationships": [group["relationship_id"]],
                    "declared_artifacts": [declared_artifact],
                    "review_triggers": [
                        "capability_declared_relationship_change"
                    ],
                    "required_review_outputs": [
                        "Review the exact artifacts declared by the capability contract."
                    ],
                    "disposition": "unresolved",
                    "rationale": "",
                    "evidence_refs": [],
                }
                obligations.append(declared_obligation)
                obligation_by_key[key] = declared_obligation
        obligations.sort(key=lambda item: (item["target_kind"], item["target_id"]))
        classification["review_triggers"] = dedupe(
            triggers
            + (
                ["capability_declared_relationship_change"]
                if declared_relationship_ids
                else []
            )
        )
        classification["declared_relationships"] = sorted(declared_relationship_ids)
        classification["obligations"] = obligations
        changed_entries.append(classification)

    aggregated_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in changed_entries:
        changed_path = entry["path"]
        for obligation in entry.get("obligations") or []:
            key = (obligation["target_kind"], obligation["target_id"])
            aggregate = aggregated_by_key.get(key)
            if aggregate is None:
                aggregate = {
                    **obligation,
                    "changed_paths": [changed_path],
                    "source_artifact_families": list(
                        obligation.get("source_artifact_families") or []
                    ),
                    "source_routing_families": list(
                        obligation.get("source_routing_families") or []
                    ),
                    "declared_relationships": list(
                        obligation.get("declared_relationships") or []
                    ),
                    "declared_artifacts": list(
                        obligation.get("declared_artifacts") or []
                    ),
                    "review_triggers": list(
                        obligation.get("review_triggers") or []
                    ),
                    "required_review_outputs": list(
                        obligation.get("required_review_outputs") or []
                    ),
                }
                aggregated_by_key[key] = aggregate
                continue
            aggregate["changed_paths"] = dedupe(
                aggregate["changed_paths"] + [changed_path]
            )
            for field in (
                "source_artifact_families",
                "source_routing_families",
                "declared_relationships",
                "declared_artifacts",
                "review_triggers",
                "required_review_outputs",
            ):
                aggregate[field] = dedupe(
                    as_list(aggregate.get(field))
                    + as_list(obligation.get(field))
                )

    obligations = []
    for key in sorted(aggregated_by_key):
        obligation = aggregated_by_key[key]
        record = record_by_key.get(key, {})
        obligation["changed_paths"] = sorted(obligation["changed_paths"])
        obligation["source_artifact_families"] = sorted(
            obligation["source_artifact_families"]
        )
        obligation["source_routing_families"] = sorted(
            obligation["source_routing_families"]
        )
        obligation["declared_relationships"] = sorted(
            obligation["declared_relationships"]
        )
        obligation["declared_artifacts"] = sorted(
            obligation["declared_artifacts"]
        )
        obligation["disposition"] = record.get("disposition", "unresolved")
        obligation["rationale"] = record.get("rationale", "")
        obligation["evidence_refs"] = record.get("evidence_refs", [])
        obligations.append(obligation)

    for entry in changed_entries:
        for obligation in entry.get("obligations") or []:
            aggregate = aggregated_by_key[
                (obligation["target_kind"], obligation["target_id"])
            ]
            obligation["obligation_id"] = aggregate["obligation_id"]
            obligation["disposition"] = aggregate["disposition"]
            obligation["rationale"] = aggregate["rationale"]
            obligation["evidence_refs"] = aggregate["evidence_refs"]

    stale_review_keys = sorted(set(record_by_key) - set(aggregated_by_key))
    for key in stale_review_keys:
        integrity_findings.append(
            {
                "type": "stale_review_record",
                "message": "Review-record entry does not correspond to an emitted obligation.",
                "value": list(key),
            }
        )

    disposition_counts = {
        disposition: sum(
            1 for item in obligations if item.get("disposition") == disposition
        )
        for disposition in sorted(CHANGED_PATH_DISPOSITIONS)
    }
    integrity_status = "fail" if integrity_findings else "pass"
    unresolved = disposition_counts["unresolved"] + disposition_counts["update_required"]
    closure_status = (
        "resolved" if integrity_status == "pass" and unresolved == 0 else "unresolved"
    )
    return {
        "mode": "explicit_changed_paths",
        "change_set_sha256": change_set_sha256,
        "repository_role": repository_role,
        "role_semantics": rules.get("changed_path_routing", {}).get(
            "semantics", {}
        ),
        "closure_status": closure_status,
        "review_record": {
            "path": str(review_record_path) if review_record_path else None,
            "present": review_record_path is not None,
            "changed_paths": review_record_changed_paths,
        },
        "changed_paths": changed_entries,
        "obligations": obligations,
        "summary": {
            "paths_supplied": len(changed_entries),
            "paths_governed": sum(
                1 for item in changed_entries if item["classification"] == "governed"
            ),
            "paths_excluded": sum(
                1 for item in changed_entries if item["classification"] == "excluded"
            ),
            "paths_unclassified": sum(
                1
                for item in changed_entries
                if item["classification"] == "unclassified"
            ),
            "obligations_total": len(obligations),
            **disposition_counts,
        },
        "integrity": {
            **integrity,
            "status": integrity_status,
            "findings": integrity_findings,
            "stale_review_entries": [list(key) for key in stale_review_keys],
        },
        "limitations": [
            "Changed-path routing is deterministic file classification and declared-link review evidence.",
            "It does not prove semantic completeness, correctness, approval, or certification.",
            "The caller supplies the exact paths; NAOS does not infer or execute a Git diff.",
        ],
    }


def relative_text(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def should_ignore(path: Path, ignored: set[str]) -> bool:
    return any(part in ignored for part in path.parts)


def path_matches(root: Path, pattern: str, ignored: set[str]) -> list[Path]:
    if not pattern or "<" in pattern or ">" in pattern:
        return []
    candidate = Path(pattern)
    has_glob = any(ch in pattern for ch in "*?[")
    try:
        if has_glob:
            matches = list(root.glob(pattern)) if not candidate.is_absolute() else list(candidate.parent.glob(candidate.name))
        else:
            path = candidate if candidate.is_absolute() else root / candidate
            matches = [path] if path.exists() else []
    except (OSError, ValueError):
        return []
    return sorted({path for path in matches if path.exists() and not should_ignore(path, ignored)}, key=lambda item: str(item))


def family_severity(
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
    defaults: dict[str, Any],
    family: dict[str, Any],
) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    profile_mapping = family.get("severity_by_profile") if isinstance(family.get("severity_by_profile"), dict) else {}
    default_mapping = defaults.get("severity_by_profile") if isinstance(defaults.get("severity_by_profile"), dict) else {}
    return str(
        profile_mapping.get(profile)
        or default_mapping.get(profile)
        or family.get("default_severity")
        or severity_for_profile(profile, policy)
        or "advisory"
    )


def configured_from(files_found: list[str], missing_expected: list[str], family: dict[str, Any]) -> bool:
    if files_found:
        return True
    if family.get("minimum_expected"):
        return False
    return False


def preliminary_family(
    *,
    root: Path,
    ignored: set[str],
    family: dict[str, Any],
    defaults: dict[str, Any],
) -> dict[str, Any]:
    enabled = family.get("enabled") is not False
    file_patterns = as_list(family.get("file_patterns"))
    minimum_expected = as_list(family.get("minimum_expected"))
    files_found = dedupe(
        [
            relative_text(root, match)
            for pattern in file_patterns
            for match in path_matches(root, pattern, ignored)
            if match.is_file() or match.is_dir()
        ]
    )
    missing_expected = [
        pattern
        for pattern in minimum_expected
        if not path_matches(root, pattern, ignored)
    ]
    stale_files: list[str] = []
    freshness_window = family.get("freshness_window_days", defaults.get("freshness_window_days", 0))
    try:
        freshness_days = int(freshness_window)
    except Exception:
        freshness_days = 0
    if freshness_days > 0:
        now = controlled_now_utc()
        for item in files_found:
            path = root / item
            try:
                mtime = datetime.fromtimestamp(path.stat().st_mtime, UTC)
            except OSError:
                continue
            if (now - mtime).days > freshness_days:
                stale_files.append(item)
    return {
        "family_id": str(family.get("family_id")),
        "name": family.get("name"),
        "enabled": enabled,
        "file_patterns": file_patterns,
        "minimum_expected": minimum_expected,
        "files_found": files_found,
        "missing_expected": missing_expected,
        "stale_files": stale_files,
        "configured": enabled and configured_from(files_found, missing_expected, family),
        "raw": family,
    }


def next_actions_for_target(
    target_id: str, target_status: str, target_kind: str = "artifact_family"
) -> list[str]:
    if target_kind == "review_surface":
        return [
            f"Review declared surface '{target_id}' and record updated, reviewed-no-change, not-applicable, or unresolved evidence."
        ]
    if target_status == "not_configured":
        return [f"Configure or deliberately disable artifact family '{target_id}', or record a known gap/residual risk."]
    if target_status == "disabled":
        return [f"Confirm disabled artifact family '{target_id}' is intentional for this project/profile."]
    if target_status in {"advisory", "review_required", "blocked", "unknown"}:
        return [f"Review artifact family '{target_id}' before treating the source change as coherent."]
    return [f"Review artifact family '{target_id}' if the source family changed materially."]


def finding(
    *,
    family_id: str,
    severity: str,
    status: str,
    message: str,
    related_families: list[str] | None = None,
    required_next_actions: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": f"{family_id}:{status}",
        "severity": severity,
        "status": status,
        "family_id": family_id,
        "message": message,
        "related_families": related_families or [],
        "required_next_actions": required_next_actions or [],
    }


def status_for_family(severity: str, has_findings: bool, not_configured: bool, disabled: bool) -> str:
    if disabled:
        return "disabled"
    if not_configured:
        return "not_configured"
    if not has_findings:
        return "ready"
    return SEVERITY_TO_STATUS.get(severity, "unknown")


def evaluate_families(
    *,
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    defaults = rules.get("defaults") if isinstance(rules.get("defaults"), dict) else {}
    ignored = ignored_scan_dirs(policy)
    raw_families = [item for item in rules.get("artifact_families") or [] if isinstance(item, dict)]
    review_surfaces = {
        str(item.get("surface_id")): item
        for item in rules.get("review_surfaces") or []
        if isinstance(item, dict) and item.get("surface_id")
    }
    prelim = {
        str(item.get("family_id")): preliminary_family(root=root, ignored=ignored, family=item, defaults=defaults)
        for item in raw_families
        if item.get("family_id")
    }

    results: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []
    for family_id, item in sorted(prelim.items()):
        raw = item["raw"]
        severity = family_severity(root, naos_root, profile, policy, defaults, raw)
        related = dedupe(as_list(raw.get("related_families")) + as_list(raw.get("impact_targets")))
        review_obligations: list[dict[str, Any]] = []
        family_findings: list[dict[str, Any]] = []

        if not item["enabled"]:
            family_findings.append(
                finding(
                    family_id=family_id,
                    severity="advisory",
                    status="disabled",
                    message=f"Artifact family '{family_id}' is disabled and remains visible.",
                    required_next_actions=["Confirm this disabled state is intentional for the project/profile."],
                )
            )
        elif item["missing_expected"]:
            family_findings.append(
                finding(
                    family_id=family_id,
                    severity=severity,
                    status="missing_expected",
                    message=f"Expected artifact patterns are missing for '{family_id}'.",
                    required_next_actions=[
                        "Create the expected artifact, adapt project rules, or record a known gap/residual risk."
                    ],
                )
            )

        if item["enabled"] and not item["configured"]:
            family_findings.append(
                finding(
                    family_id=family_id,
                    severity=severity,
                    status="not_configured",
                    message=f"Artifact family '{family_id}' is enabled but not configured in this project state.",
                    required_next_actions=[
                        "Configure the family, disable it intentionally, or document why it is not applicable."
                    ],
                )
            )

        if item["stale_files"]:
            family_findings.append(
                finding(
                    family_id=family_id,
                    severity="warning" if severity == "advisory" else severity,
                    status="stale_link",
                    message=f"Artifact family '{family_id}' has stale files beyond the configured freshness window.",
                    required_next_actions=["Refresh stale artifacts or record residual risk."],
                )
            )

        for target_id in related:
            target = prelim.get(target_id)
            if target is None:
                surface = review_surfaces.get(target_id)
                if surface is None:
                    target_kind = "unknown"
                    target_status = "unknown"
                    target_configured = False
                    target_enabled = False
                else:
                    target_kind = "review_surface"
                    target_status = "review_required"
                    target_configured = True
                    target_enabled = True
            else:
                target_kind = "artifact_family"
                target_enabled = bool(target["enabled"])
                target_configured = bool(target["configured"])
                if not target_enabled:
                    target_status = "disabled"
                elif not target_configured:
                    target_status = "not_configured"
                elif target["missing_expected"]:
                    target_status = "review_required"
                elif target["stale_files"]:
                    target_status = "advisory"
                else:
                    target_status = "ready"
            obligation = {
                "target_family_id": target_id,
                "target_enabled": target_enabled,
                "target_configured": target_configured,
                "target_status": target_status,
                "required_review_outputs": as_list(raw.get("required_review_outputs")),
                "required_next_actions": next_actions_for_target(
                    target_id, target_status, target_kind
                ),
            }
            if target_kind == "review_surface":
                obligation["target_kind"] = target_kind
            review_obligations.append(obligation)
            if target_status in {"not_configured", "disabled", "unknown", "review_required"}:
                if target_kind == "review_surface":
                    finding_status = "review_surface_review"
                    finding_message = (
                        f"Artifact family '{family_id}' requires human review of "
                        f"declared surface '{target_id}'."
                    )
                else:
                    finding_status = (
                        "missing_link" if target_status != "disabled" else "disabled"
                    )
                    finding_message = (
                        f"Artifact family '{family_id}' requires review of "
                        f"'{target_id}', currently {target_status}."
                    )
                family_findings.append(
                    finding(
                        family_id=family_id,
                        severity=severity if target_status != "disabled" else "advisory",
                        status=finding_status,
                        message=finding_message,
                        related_families=[target_id],
                        required_next_actions=obligation["required_next_actions"],
                    )
                )

        waivers = [entry for entry in raw.get("waivers") or [] if isinstance(entry, dict)]
        if waivers:
            family_findings.append(
                finding(
                    family_id=family_id,
                    severity="advisory",
                    status="waiver_visible",
                    message="Configured waivers remain visible and do not convert coherence review to pass.",
                    required_next_actions=["Review waiver expiry and residual risk before accepting status."],
                )
            )

        disabled = not item["enabled"]
        not_configured = item["enabled"] and not item["configured"]
        blocking_findings = [entry for entry in family_findings if entry["status"] not in {"disabled", "waiver_visible"}]
        evaluated_status = status_for_family(severity, bool(blocking_findings), not_configured, disabled)
        if waivers and evaluated_status == "ready":
            evaluated_status = "advisory"
        if evaluated_status not in REVIEW_STATUSES:
            evaluated_status = "unknown"

        result = {
            "family_id": family_id,
            "name": item.get("name"),
            "enabled": item["enabled"],
            "configured": item["configured"],
            "files_found": item["files_found"],
            "missing_expected": item["missing_expected"],
            "stale_files": item["stale_files"],
            "related_families": related,
            "review_obligations": review_obligations,
            "severity": severity,
            "evaluated_status": evaluated_status,
            "human_review_required": bool(raw.get("human_review_required")) or evaluated_status in {"review_required", "blocked"},
            "waivers": waivers,
            "limitations": as_list(raw.get("limitations")),
            "notes": raw.get("notes"),
            "rationale": raw.get("rationale"),
        }
        results.append(result)
        all_findings.extend(family_findings)
    return results, all_findings


def build_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules_path: Path,
    rules_source: str,
    changed_paths: list[str] | None = None,
    review_record_path: Path | None = None,
) -> dict[str, Any]:
    rules = load_yaml(rules_path)
    artifact_families, findings = evaluate_families(
        root=root,
        naos_root=naos_root,
        profile=profile,
        policy=policy,
        rules=rules,
    )
    summary = finding_counts(findings)
    summary.update(
        {
            "artifact_families": len(artifact_families),
            "configured": sum(1 for item in artifact_families if item.get("configured")),
            "not_configured": sum(1 for item in artifact_families if item.get("evaluated_status") == "not_configured"),
            "disabled": sum(1 for item in artifact_families if item.get("evaluated_status") == "disabled"),
            "ready": sum(1 for item in artifact_families if item.get("evaluated_status") == "ready"),
            "review_required": sum(1 for item in artifact_families if item.get("evaluated_status") == "review_required"),
            "blocked": sum(1 for item in artifact_families if item.get("evaluated_status") == "blocked"),
            "advisory_status": sum(1 for item in artifact_families if item.get("evaluated_status") == "advisory"),
            "unknown": sum(1 for item in artifact_families if item.get("evaluated_status") == "unknown"),
            "human_review_required": sum(1 for item in artifact_families if item.get("human_review_required")),
            "review_obligations": sum(len(item.get("review_obligations") or []) for item in artifact_families),
            "missing_expected": sum(len(item.get("missing_expected") or []) for item in artifact_families),
            "stale_links": sum(len(item.get("stale_files") or []) for item in artifact_families),
            "waivers": sum(len(item.get("waivers") or []) for item in artifact_families),
        }
    )
    policy_meta = policy.get("_meta", {})
    report = {
        "schema": "naos.systemic_impact_review.v1",
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": status_from_counts(summary),
        "naos_root": naos_root,
        "project_root": str(root),
        "rules": {
            "path": str(rules_path),
            "source": rules_source,
            "semantics": rules.get("semantics") or {},
        },
        "policy": {
            "version": policy.get("version"),
            "source": policy_meta.get("source"),
            "path": policy_meta.get("path"),
        },
        "semantics": {
            "rules": "Project-configured artifact-family relationships; not proof by themselves.",
            "report": "NAOS evaluates current configured state and review obligations.",
            "governance_decision": "Human/project governance decides remediation, waiver, and next action.",
            "flow": "configure -> evaluate -> report -> review -> update -> re-evaluate",
        },
        "summary": summary,
        "artifact_families": artifact_families,
        "findings": findings,
        "limitations": [
            "Systemic impact review is a deterministic file-first review aid.",
            "It does not prove perfect coherence, complete impact analysis, or certification.",
            "It does not automatically update related artifacts.",
            "Current-state and explicit caller-supplied changed-path review are implemented; automatic Git-diff inference is not.",
            "Projects should customize artifact-family rules as they mature.",
        ],
    }
    if changed_paths:
        report["changed_path_review"] = build_changed_path_review(
            root=root,
            rules=rules,
            changed_paths=changed_paths,
            artifact_results=artifact_families,
            repository_role=(
                "kit_source"
                if is_kit_repository(root, naos_root)
                else "adopter_project"
            ),
            review_record_path=review_record_path,
        )
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate NAOS systemic impact and coherence review obligations.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--rules", help="Path to systemic_impact_rules.yaml.")
    parser.add_argument("--output")
    parser.add_argument(
        "--changed-path",
        action="append",
        default=[],
        help=(
            "Repository-relative changed path to classify; repeat for each exact "
            "path in the stable change set. Deleted paths are supported."
        ),
    )
    parser.add_argument(
        "--review-record",
        help="YAML review dispositions for exact emitted changed-path obligations.",
    )
    parser.add_argument(
        "--require-resolved",
        action="store_true",
        help=(
            "Return nonzero unless every explicit changed-path obligation is "
            "validly closed. Has no effect without --changed-path."
        ),
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--all",
        action="store_true",
        help="Show every human-readable finding occurrence; JSON is always complete.",
    )
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if (args.review_record or args.require_resolved) and not args.changed_path:
        parser.error("--review-record and --require-resolved require --changed-path")
    try:
        changed_paths = [normalize_changed_path(item) for item in args.changed_path]
    except ValueError as exc:
        parser.error(str(exc))
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    rules_path, rules_source = resolve_rules_path(root, naos_root, policy, args.rules)
    report = build_report(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        rules_path=rules_path,
        rules_source=rules_source,
        changed_paths=changed_paths,
        review_record_path=Path(args.review_record) if args.review_record else None,
    )
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "systemic_impact_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        destination = str(output) if output else "stdout only"
        print(
            "NAOS systemic impact review: "
            f"{report['status']} "
            f"({report['summary']['configured']} configured, "
            f"{report['summary']['review_required']} review required, "
            f"{report['summary']['not_configured']} not configured, "
            f"output: {destination})"
        )
        presentation = build_actionable_presentation(
            systemic_finding_occurrences(report),
            expansion_command="naos systemic-impact --all",
            show_all=args.all,
            limitations=report.get("limitations") or [],
        )
        for line in presentation_lines(presentation):
            print(line)
        changed_review = report.get("changed_path_review")
        if isinstance(changed_review, dict):
            changed_summary = changed_review["summary"]
            print(
                "Changed-path review: "
                f"{changed_review['closure_status']} "
                f"({changed_summary['paths_supplied']} paths, "
                f"{changed_summary['obligations_total']} obligations, "
                f"{changed_summary['unresolved']} unresolved, "
                f"{changed_summary['update_required']} update required)"
            )
    normal_exit = exit_code_for_summary(
        profile, report["summary"], policy, args.strict
    )
    changed_review = report.get("changed_path_review")
    if (
        args.require_resolved
        and isinstance(changed_review, dict)
        and changed_review.get("closure_status") != "resolved"
    ):
        return normal_exit or 2
    return normal_exit


if __name__ == "__main__":
    raise SystemExit(main())
