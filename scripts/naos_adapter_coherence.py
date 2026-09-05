#!/usr/bin/env python3
"""Review NAOS plugin and adapter coherence without mutating tool settings."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

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
    severity_for_profile,
    status_from_counts,
    write_report,
)


REPORT_SCHEMA = "naos.adapter_coherence_report.v1"
NOT_CLAIMED = [
    "live Codex plugin installation proof",
    "live Claude Code plugin installation proof",
    "MCP access proof",
    "memory access proof",
    "automatic adapter propagation",
    "automatic stale-content repair",
    "semantic equivalence proof",
    "automatic memory write-back",
    "hidden context injection",
    "approval",
    "certification",
    "proof of compliance",
]
LIMITATIONS = [
    "This review is deterministic, local, and file-first.",
    "It checks static files and wording; it does not verify live IDE, Codex, Claude Code, or MCP runtime state.",
    "It does not mutate Codex plugin caches, Claude plugin state, marketplace files, MCP configs, memory stores, hooks, or IDE settings.",
]


def utc_now_text() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping: {path}")
    return data


def safe_digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def string_list(value: Any) -> list[str]:
    return [str(item).strip() for item in as_list(value) if str(item).strip()]


def as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def manifest_field_policies(plugin_rules: dict[str, Any], fields: list[str]) -> dict[str, dict[str, Any]]:
    configured = as_mapping(plugin_rules.get("manifest_field_policy"))
    policies: dict[str, dict[str, Any]] = {}
    for field in fields:
        raw = configured.get(field)
        if isinstance(raw, dict):
            policies[field] = raw
        else:
            policies[field] = {
                "disposition": "policy_forbidden",
                "reason": "Field is forbidden by this adapter's reviewed compatibility policy.",
            }
    return policies


def default_rules_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "adapter_coherence_rules.yaml"


def default_propagation_state_template(filename: str = "adapter_propagation_state.yaml") -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / filename


def resolve_rules_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None = None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("adapter_coherence_rules") or "adapter_coherence_rules.yaml")
    project_rules = root / naos_root / filename
    if project_rules.exists():
        return project_rules, "project"
    return default_rules_template(), "template"


def resolve_propagation_state_path(root: Path, naos_root: str, policy: dict[str, Any], rules: dict[str, Any]) -> tuple[Path, str]:
    filename = str(
        rules.get("propagation_state_path")
        or policy.get("paths", {}).get("adapter_propagation_state")
        or "adapter_propagation_state.yaml"
    )
    project_state = root / naos_root / filename
    if project_state.exists():
        return project_state, "project"
    template_state = default_propagation_state_template(filename)
    if template_state.exists():
        return template_state, "template"
    return project_state, "missing"


def profile_posture(rules: dict[str, Any], profile: str) -> dict[str, Any]:
    configured = as_mapping(as_mapping(rules.get("profile_posture")).get(profile))
    if configured:
        return configured
    defaults = {
        "quickstart": {"state": "advisory", "severity": "advisory"},
        "lite": {"state": "advisory", "severity": "warning"},
        "standard": {"state": "required_review", "severity": "required"},
        "assured": {"state": "required_review", "severity": "blocking"},
    }
    return defaults.get(profile, defaults["quickstart"])


def severity_for_rules(root: Path, naos_root: str, profile: str, policy: dict[str, Any], posture: dict[str, Any]) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    configured = str(posture.get("severity") or "").strip()
    if configured in {"advisory", "warning", "required", "blocking"}:
        return configured
    return severity_for_profile(profile, policy)


def rel(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except Exception:
        return path.as_posix()


def finding(identifier: str, severity: str, status: str, message: str, actions: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": identifier,
        "severity": severity,
        "status": status,
        "message": message,
        "required_next_actions": actions or [],
    }
    payload.update({key: value for key, value in extra.items() if value is not None})
    return payload


def parse_skill_frontmatter(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return {}
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}
    data = yaml.safe_load(parts[1]) or {}
    return data if isinstance(data, dict) else {}


def plugin_rules_list(rules: dict[str, Any]) -> list[dict[str, Any]]:
    configured = [item for item in as_list(rules.get("canonical_plugins")) if isinstance(item, dict)]
    if configured:
        return configured
    legacy = as_mapping(rules.get("canonical_plugin"))
    return [legacy] if legacy else []


def propagation_links_list(rules: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in as_list(rules.get("propagation_links")) if isinstance(item, dict)]


def load_propagation_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    return load_yaml_mapping(path)


def review_records(state: dict[str, Any]) -> list[dict[str, Any]]:
    records = state.get("propagation_reviews", state.get("reviews", []))
    return [item for item in as_list(records) if isinstance(item, dict)]


def stable_finding_id(text: str) -> str:
    cleaned = []
    for char in text:
        cleaned.append(char if char.isalnum() else "_")
    return "_".join("".join(cleaned).strip("_").split("_"))


def digest_for_relative_path(base: Path, path_text: str) -> tuple[Path, str | None]:
    path = base / path_text
    return path, safe_digest(path)


def inspect_plugin(kit: Path, plugin_rules: dict[str, Any], severity: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    plugin_id = str(plugin_rules.get("id") or "plugin")
    display_name = str(plugin_rules.get("name") or plugin_id)
    source_path = kit / str(plugin_rules.get("source_path") or "plugins/naos-governance")
    manifest_path = kit / str(plugin_rules.get("manifest_path") or source_path / ".codex-plugin" / "plugin.json")
    required_manifest = as_mapping(plugin_rules.get("required_manifest"))
    required_skills = string_list(plugin_rules.get("required_skills"))
    required_references = string_list(plugin_rules.get("required_references"))
    forbidden_runtime_paths = string_list(plugin_rules.get("forbidden_runtime_paths"))
    unsupported_manifest_fields = string_list(plugin_rules.get("unsupported_manifest_fields")) or ["hooks", "mcpServers"]
    findings: list[dict[str, Any]] = []
    manifest: dict[str, Any] = {}

    if not source_path.is_dir():
        findings.append(finding(
            f"{plugin_id}_source_missing",
            severity,
            "missing",
            f"Canonical {display_name} source is missing: {rel(source_path, kit)}.",
            [f"Create or restore {rel(source_path, kit)} as the canonical plugin source."],
        ))
    if not manifest_path.is_file():
        findings.append(finding(
            f"{plugin_id}_manifest_missing",
            severity,
            "missing",
            f"{display_name} manifest is missing: {rel(manifest_path, kit)}.",
            [f"Restore {rel(manifest_path, kit)} and validate the plugin."],
        ))
    else:
        try:
            loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                manifest = loaded
        except json.JSONDecodeError as exc:
            findings.append(finding(
                f"{plugin_id}_manifest_invalid_json",
                severity,
                "invalid",
                f"{display_name} manifest is not valid JSON: {exc}.",
                ["Fix plugin.json before installing or publishing the plugin."],
            ))

    for key, expected in required_manifest.items():
        if manifest and manifest.get(key) != expected:
            findings.append(finding(
                f"{plugin_id}_manifest_{key}_mismatch",
                severity,
                "mismatch",
                f"{display_name} manifest field {key!r} is {manifest.get(key)!r}, expected {expected!r}.",
                ["Align plugin manifest with adapter coherence rules or update the reviewed rules."],
            ))

    unsupported_present = [key for key in unsupported_manifest_fields if key in manifest]
    for field_name, field_policy in manifest_field_policies(plugin_rules, unsupported_present).items():
        disposition = str(field_policy.get("disposition") or "policy_forbidden").strip()
        reason = str(field_policy.get("reason") or "Field is forbidden by this adapter's reviewed compatibility policy.").strip()
        findings.append(finding(
            f"{plugin_id}_manifest_{stable_finding_id(field_name)}_policy_forbidden",
            severity,
            "policy_forbidden_manifest_field",
            f"{display_name} manifest declares policy-forbidden field {field_name!r}: {reason}",
            ["Remove the field or raise the reviewed adapter compatibility baseline before reintroducing it."],
            field=field_name,
            disposition=disposition,
            compatibility_note=field_policy.get("compatibility_note"),
        ))

    for forbidden_path in forbidden_runtime_paths:
        path = source_path / forbidden_path
        if path.exists():
            findings.append(finding(
                f"{plugin_id}_forbidden_runtime_path_{forbidden_path.replace('/', '_')}",
                severity,
                "runtime_path_present",
                f"{display_name} declares forbidden v1 runtime surface: {rel(path, kit)}.",
                ["Remove the runtime surface or route a new explicit design through systemic review first."],
            ))

    skill_summaries: list[dict[str, Any]] = []
    for skill_name in required_skills:
        skill_path = source_path / "skills" / skill_name / "SKILL.md"
        item = {"name": skill_name, "path": rel(skill_path, kit), "present": skill_path.is_file()}
        if not skill_path.is_file():
            findings.append(finding(
                f"{plugin_id}_skill_{skill_name}_missing",
                severity,
                "missing",
                f"Required {display_name} skill is missing: {rel(skill_path, kit)}.",
                ["Restore the plugin skill or update adapter coherence rules after review."],
            ))
        else:
            meta = parse_skill_frontmatter(skill_path)
            item["metadata_name"] = meta.get("name")
            item["description_present"] = bool(str(meta.get("description") or "").strip())
            if meta.get("name") != skill_name:
                findings.append(finding(
                    f"{plugin_id}_skill_{skill_name}_name_mismatch",
                    severity,
                    "mismatch",
                    f"Skill frontmatter name is {meta.get('name')!r}, expected {skill_name!r}.",
                    ["Align the skill directory and frontmatter name."],
                ))
            if not item["description_present"]:
                findings.append(finding(
                    f"{plugin_id}_skill_{skill_name}_description_missing",
                    severity,
                    "missing_metadata",
                    f"Skill is missing a non-empty description: {rel(skill_path, kit)}.",
                    ["Add a concise skill description."],
                ))
        skill_summaries.append(item)

    reference_summaries: list[dict[str, Any]] = []
    for reference_name in required_references:
        reference_path = source_path / "references" / reference_name
        present = reference_path.is_file()
        reference_summaries.append({"name": reference_name, "path": rel(reference_path, kit), "present": present})
        if not present:
            findings.append(finding(
                f"{plugin_id}_reference_{reference_name}_missing",
                severity,
                "missing",
                f"Required {display_name} reference is missing: {rel(reference_path, kit)}.",
                ["Restore the plugin reference or update adapter coherence rules after review."],
            ))

    return {
        "id": plugin_id,
        "name": display_name,
        "source_path": rel(source_path, kit),
        "source_present": source_path.is_dir(),
        "manifest_path": rel(manifest_path, kit),
        "manifest_present": manifest_path.is_file(),
        "manifest_name": manifest.get("name"),
        "manifest_version": manifest.get("version"),
        "policy_forbidden_manifest_fields": unsupported_manifest_fields,
        "manifest_field_policy": manifest_field_policies(plugin_rules, unsupported_manifest_fields),
        "skills": skill_summaries,
        "references": reference_summaries,
    }, findings


def inspect_adapter_surfaces(kit: Path, rules: dict[str, Any], severity: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    for surface in as_list(rules.get("adapter_surfaces")):
        if not isinstance(surface, dict):
            continue
        paths = string_list(surface.get("paths"))
        path_summaries = []
        missing = []
        for path_text in paths:
            path = kit / path_text
            present = path.exists()
            path_summaries.append({"path": path_text, "present": present, "kind": "dir" if path.is_dir() else "file" if path.is_file() else "missing"})
            if not present:
                missing.append(path_text)
        if missing:
            findings.append(finding(
                f"{surface.get('id', 'adapter_surface')}_missing_paths",
                severity,
                "missing",
                f"Adapter surface {surface.get('id')} is missing expected paths: {', '.join(missing)}.",
                ["Restore the missing adapter files or update adapter coherence rules after review."],
            ))
        summaries.append({
            "id": surface.get("id"),
            "kind": surface.get("kind"),
            "source": surface.get("source"),
            "paths": path_summaries,
            "present": not missing,
        })
    return summaries, findings


def inspect_project_local_adapters(root: Path, rules: dict[str, Any]) -> list[dict[str, Any]]:
    adapters = []
    for path_text in string_list(rules.get("project_local_adapter_paths")):
        path = root / path_text
        adapters.append({
            "path": path_text,
            "present": path.exists(),
            "file_count": sum(1 for item in path.rglob("*") if item.is_file()) if path.is_dir() else 0,
        })
    return adapters


def inspect_propagation_links(
    *,
    base: Path,
    links: list[dict[str, Any]],
    state: dict[str, Any],
    severity: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    records = review_records(state)
    reviews_by_id = {str(item.get("link_id") or ""): item for item in records if item.get("link_id")}
    allowed_dispositions = {"propagated", "no_impact", "accepted_risk", "deferred"}

    for link in links:
        link_id = str(link.get("id") or "").strip()
        if not link_id:
            findings.append(finding(
                "adapter_propagation_link_id_missing",
                severity,
                "invalid_propagation_link",
                "A propagation link is missing an id.",
                ["Add a stable id to every propagation link."],
            ))
            continue

        review = reviews_by_id.get(link_id)
        source_paths = string_list(link.get("source_paths"))
        target_paths = string_list(link.get("target_paths"))
        link_findings = 0
        stale = False
        missing = False
        invalid = False
        status = "reviewed"
        disposition = None

        if review is None:
            findings.append(finding(
                f"adapter_propagation_{stable_finding_id(link_id)}_unreviewed",
                severity,
                "unreviewed_propagation",
                f"Propagation link {link_id!r} has no reviewed propagation state.",
                ["Review the mapped source/target artifacts and record propagated, no_impact, accepted_risk, or deferred disposition."],
                link_id=link_id,
            ))
            summaries.append({
                "id": link_id,
                "description": link.get("description"),
                "status": "unreviewed",
                "disposition": None,
                "source_paths": source_paths,
                "target_paths": target_paths,
            })
            continue

        disposition = str(review.get("disposition") or "").strip()
        if disposition not in allowed_dispositions:
            invalid = True
            link_findings += 1
            findings.append(finding(
                f"adapter_propagation_{stable_finding_id(link_id)}_invalid_disposition",
                severity,
                "invalid_propagation_review",
                f"Propagation link {link_id!r} has invalid disposition {disposition!r}.",
                ["Use one of: propagated, no_impact, accepted_risk, deferred."],
                link_id=link_id,
            ))

        missing_review_fields = [
            field for field in ["reviewed_at", "reviewer", "rationale"]
            if not str(review.get(field) or "").strip()
        ]
        if missing_review_fields:
            invalid = True
            link_findings += 1
            findings.append(finding(
                f"adapter_propagation_{stable_finding_id(link_id)}_metadata_missing",
                severity,
                "invalid_propagation_review",
                f"Propagation link {link_id!r} review is missing metadata: {', '.join(missing_review_fields)}.",
                ["Record reviewed_at, reviewer, and rationale for every propagation disposition."],
                link_id=link_id,
            ))

        if disposition == "no_impact" and len(str(review.get("rationale") or "").strip()) < 20:
            invalid = True
            link_findings += 1
            findings.append(finding(
                f"adapter_propagation_{stable_finding_id(link_id)}_no_impact_rationale_weak",
                severity,
                "invalid_no_impact",
                f"Propagation link {link_id!r} has a no-impact decision without sufficient rationale.",
                ["Explain why mapped plugin/adapter targets do not need an update."],
                link_id=link_id,
            ))

        if disposition == "accepted_risk" and not str(review.get("residual_risk_id") or "").strip():
            invalid = True
            link_findings += 1
            findings.append(finding(
                f"adapter_propagation_{stable_finding_id(link_id)}_risk_id_missing",
                severity,
                "invalid_accepted_risk",
                f"Propagation link {link_id!r} accepts risk without a residual_risk_id.",
                ["Record a residual risk id for accepted adapter propagation risk."],
                link_id=link_id,
            ))

        if disposition == "deferred":
            link_findings += 1
            findings.append(finding(
                f"adapter_propagation_{stable_finding_id(link_id)}_deferred",
                severity,
                "deferred_propagation",
                f"Propagation link {link_id!r} is deferred.",
                ["Complete propagation review before claiming adapter guidance is current."],
                link_id=link_id,
            ))

        source_hashes = as_mapping(review.get("source_hashes"))
        target_hashes = as_mapping(review.get("target_hashes"))

        for path_text in source_paths:
            path, actual_hash = digest_for_relative_path(base, path_text)
            expected_hash = source_hashes.get(path_text)
            if actual_hash is None:
                missing = True
                link_findings += 1
                findings.append(finding(
                    f"adapter_propagation_{stable_finding_id(link_id)}_source_missing_{stable_finding_id(path_text)}",
                    severity,
                    "missing_source",
                    f"Propagation link {link_id!r} source is missing: {rel(path, base)}.",
                    ["Restore the source artifact or update propagation rules after review."],
                    link_id=link_id,
                    path=path_text,
                ))
            elif not expected_hash:
                invalid = True
                link_findings += 1
                findings.append(finding(
                    f"adapter_propagation_{stable_finding_id(link_id)}_source_hash_missing_{stable_finding_id(path_text)}",
                    severity,
                    "incomplete_propagation_review",
                    f"Propagation link {link_id!r} review is missing a source hash for {path_text}.",
                    ["Record source hashes for every mapped propagation source."],
                    link_id=link_id,
                    path=path_text,
                ))
            elif expected_hash != actual_hash:
                stale = True
                link_findings += 1
                findings.append(finding(
                    f"adapter_propagation_{stable_finding_id(link_id)}_source_stale_{stable_finding_id(path_text)}",
                    severity,
                    "stale_source_review",
                    f"Propagation link {link_id!r} source changed since review: {path_text}.",
                    ["Review plugin/adapter impact and update target artifacts, record no-impact rationale, or accept residual risk."],
                    link_id=link_id,
                    path=path_text,
                ))

        for path_text in target_paths:
            path, actual_hash = digest_for_relative_path(base, path_text)
            expected_hash = target_hashes.get(path_text)
            if actual_hash is None:
                missing = True
                link_findings += 1
                findings.append(finding(
                    f"adapter_propagation_{stable_finding_id(link_id)}_target_missing_{stable_finding_id(path_text)}",
                    severity,
                    "missing_target",
                    f"Propagation link {link_id!r} target is missing: {rel(path, base)}.",
                    ["Restore the plugin/adapter target or update propagation rules after review."],
                    link_id=link_id,
                    path=path_text,
                ))
            elif not expected_hash:
                invalid = True
                link_findings += 1
                findings.append(finding(
                    f"adapter_propagation_{stable_finding_id(link_id)}_target_hash_missing_{stable_finding_id(path_text)}",
                    severity,
                    "incomplete_propagation_review",
                    f"Propagation link {link_id!r} review is missing a target hash for {path_text}.",
                    ["Record target hashes for every mapped plugin/adapter target."],
                    link_id=link_id,
                    path=path_text,
                ))
            elif expected_hash != actual_hash:
                stale = True
                link_findings += 1
                findings.append(finding(
                    f"adapter_propagation_{stable_finding_id(link_id)}_target_stale_{stable_finding_id(path_text)}",
                    severity,
                    "stale_target_review",
                    f"Propagation link {link_id!r} target changed since review: {path_text}.",
                    ["Review whether the target remains coherent with source artifacts and refresh propagation state."],
                    link_id=link_id,
                    path=path_text,
                ))

        if missing:
            status = "missing"
        elif stale:
            status = "stale"
        elif invalid:
            status = "invalid"
        elif disposition == "deferred":
            status = "deferred"

        summaries.append({
            "id": link_id,
            "description": link.get("description"),
            "equivalence": link.get("equivalence"),
            "status": status,
            "disposition": disposition,
            "source_paths": source_paths,
            "target_paths": target_paths,
            "reviewed_at": review.get("reviewed_at"),
            "reviewer": review.get("reviewer"),
            "residual_risk_id": review.get("residual_risk_id"),
            "finding_count": link_findings,
        })

    review_summaries = [
        {
            "link_id": item.get("link_id"),
            "disposition": item.get("disposition"),
            "reviewed_at": item.get("reviewed_at"),
            "reviewer": item.get("reviewer"),
            "rationale_present": bool(str(item.get("rationale") or "").strip()),
            "residual_risk_id": item.get("residual_risk_id"),
        }
        for item in records
    ]
    return summaries, review_summaries, findings


def scan_for_claims(kit: Path, rules: dict[str, Any], severity: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    scan_roots = [
        kit / "plugins" / "naos-governance",
        kit / "plugins" / "naos-governance-claude-code",
        kit / "templates" / "integrations",
        kit / "docs" / "CODEX_PLUGIN_AND_MCP.md",
        kit / "docs" / "TOOL_NEUTRAL_USAGE.md",
    ]
    forbidden = [phrase.lower() for phrase in string_list(rules.get("forbidden_claim_phrases"))]
    required_non_claims = [phrase.lower() for phrase in string_list(rules.get("required_non_claims"))]
    texts: list[tuple[Path, str]] = []
    for root in scan_roots:
        if root.is_file():
            texts.append((root, root.read_text(encoding="utf-8", errors="replace")))
        elif root.is_dir():
            for path in root.rglob("*"):
                if path.is_file() and path.suffix.lower() in {".md", ".json", ".yaml", ".yml"}:
                    texts.append((path, path.read_text(encoding="utf-8", errors="replace")))
    combined = "\n".join(text for _path, text in texts).lower()
    for phrase in forbidden:
        for path, text in texts:
            if phrase in text.lower():
                findings.append(finding(
                    f"adapter_forbidden_claim_{phrase.replace(' ', '_')}",
                    severity,
                    "forbidden_claim",
                    f"Forbidden adapter claim phrase appears in {rel(path, kit)}: {phrase!r}.",
                    ["Remove or reword the claim to preserve NAOS non-authority boundaries."],
                ))
                break
    for phrase in required_non_claims:
        if phrase not in combined:
            findings.append(finding(
                f"adapter_non_claim_{phrase.replace(' ', '_')}_missing",
                "advisory",
                "missing_non_claim",
                f"Required adapter non-claim phrase is not visible in scanned adapter surfaces: {phrase!r}.",
                ["Add the non-claim where adapter users will see it, or update rules after review."],
            ))
    if (kit / "naos" / "plugins").exists():
        findings.append(finding(
            "naos_plugins_state_confusion",
            severity,
            "source_boundary_confusion",
            "A kit-level naos/plugins path exists; plugin source should remain under plugins/naos-governance, not project-state naos/.",
            ["Move canonical plugin source under plugins/naos-governance and keep project-local copies under naos/integrations/."],
        ))
    return findings


def build_report(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, int], dict[str, Any]]:
    root = Path(args.project_root).resolve()
    policy = load_policy(Path(args.policy) if args.policy else None)
    profile = normalize_profile(args.profile, policy)
    naos_root = args.naos_root or default_naos_root(policy)
    rules_path, rules_source = resolve_rules_path(root, naos_root, policy, args.rules)
    rules = load_yaml_mapping(rules_path)
    propagation_state_path, propagation_state_source = resolve_propagation_state_path(root, naos_root, policy, rules)
    propagation_state = load_propagation_state(propagation_state_path)
    posture = profile_posture(rules, profile)
    severity = severity_for_rules(root, naos_root, profile, policy, posture)
    kit = kit_root()

    findings: list[dict[str, Any]] = []
    canonical_plugins: list[dict[str, Any]] = []
    for plugin_rules in plugin_rules_list(rules):
        plugin_summary, plugin_findings = inspect_plugin(kit, plugin_rules, severity)
        canonical_plugins.append(plugin_summary)
        findings.extend(plugin_findings)
    canonical_plugin = next((item for item in canonical_plugins if item.get("id") == "codex_plugin"), canonical_plugins[0] if canonical_plugins else {})
    adapter_surfaces, surface_findings = inspect_adapter_surfaces(kit, rules, severity)
    findings.extend(surface_findings)
    project_local_adapters = inspect_project_local_adapters(root, rules)
    propagation_links, propagation_reviews, propagation_findings = inspect_propagation_links(
        base=kit,
        links=propagation_links_list(rules),
        state=propagation_state,
        severity=severity,
    )
    findings.extend(propagation_findings)
    findings.extend(scan_for_claims(kit, rules, severity))

    summary = finding_counts(findings)
    summary.update({
        "plugins_present": sum(1 for item in canonical_plugins if item.get("source_present") and item.get("manifest_present")),
        "plugins_expected": len(canonical_plugins),
        "plugin_skills_present": sum(1 for plugin in canonical_plugins for item in plugin.get("skills", []) if item.get("present")),
        "plugin_skills_expected": sum(len(plugin.get("skills", [])) for plugin in canonical_plugins),
        "plugin_references_present": sum(1 for plugin in canonical_plugins for item in plugin.get("references", []) if item.get("present")),
        "plugin_references_expected": sum(len(plugin.get("references", [])) for plugin in canonical_plugins),
        "adapter_surfaces_present": sum(1 for item in adapter_surfaces if item.get("present")),
        "adapter_surfaces_expected": len(adapter_surfaces),
        "project_local_adapters_present": sum(1 for item in project_local_adapters if item.get("present")),
        "propagation_links_expected": len(propagation_links),
        "propagation_links_reviewed": sum(1 for item in propagation_links if item.get("status") == "reviewed"),
        "propagation_links_stale": sum(1 for item in propagation_links if item.get("status") == "stale"),
        "propagation_links_unreviewed": sum(1 for item in propagation_links if item.get("status") == "unreviewed"),
        "propagation_links_invalid": sum(1 for item in propagation_links if item.get("status") == "invalid"),
        "propagation_links_deferred": sum(1 for item in propagation_links if item.get("status") == "deferred"),
        "no_impact_decisions": sum(1 for item in propagation_links if item.get("disposition") == "no_impact"),
        "accepted_risks": sum(1 for item in propagation_links if item.get("disposition") == "accepted_risk"),
    })
    report = {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": status_from_counts(summary),
        "naos_root": naos_root,
        "project_root": str(root),
        "rules_path": str(rules_path),
        "rules_source": rules_source,
        "rules_hash": safe_digest(rules_path),
        "propagation_state_path": str(propagation_state_path),
        "propagation_state_source": propagation_state_source,
        "propagation_state_hash": safe_digest(propagation_state_path),
        "profile_posture": posture,
        "canonical_plugin": canonical_plugin,
        "canonical_plugins": canonical_plugins,
        "adapter_surfaces": adapter_surfaces,
        "project_local_adapters": project_local_adapters,
        "propagation_links": propagation_links,
        "propagation_reviews": propagation_reviews,
        "findings": findings,
        "known_gaps": as_list(rules.get("known_gaps")),
        "residual_risks": as_list(rules.get("residual_risks")),
        "limitations": string_list(rules.get("limitations")) or LIMITATIONS,
        "not_claimed": string_list(rules.get("not_claimed")) or NOT_CLAIMED,
        "human_review_required": bool(findings) or profile in {"standard", "assured"},
        "summary": summary,
    }
    return report, summary, policy


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Review NAOS plugin and adapter coherence.")
    parser.add_argument("project_root", nargs="?", default=".", help="Project root to inspect.")
    parser.add_argument("--profile", default=None, help="NAOS profile.")
    parser.add_argument("--naos-root", default=None, help="NAOS project-state root.")
    parser.add_argument("--policy", help="Explicit policy YAML path.")
    parser.add_argument("--rules", help="Explicit adapter coherence rules path.")
    parser.add_argument("--output", help="Explicit output JSON path.")
    parser.add_argument("--json", action="store_true", help="Print report JSON to stdout.")
    parser.add_argument("--strict", action="store_true", help="Use strict profile exit policy.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report, summary, policy = build_report(args)
    except Exception as exc:
        print(f"adapter-coherence error: {exc}", file=sys.stderr)
        return 2
    root = Path(args.project_root).resolve()
    naos_root = report["naos_root"]
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "adapter_coherence_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"adapter-coherence: {report['status']} ({summary['total_findings']} findings)")
        if output:
            print(f"report: {output}")
    return exit_code_for_summary(report["profile"], summary, policy, strict=args.strict)


if __name__ == "__main__":
    sys.exit(main())
