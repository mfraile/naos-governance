#!/usr/bin/env python3
"""Generate a bounded, file-first task context pack for one NAOS task."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
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
    is_kit_repository,
    kit_root,
    load_policy,
    normalize_profile,
    report_default_path,
    report_output_path,
    severity_for_profile,
    write_report,
)
import naos_pre_implementation_alignment_review as pia  # noqa: E402
from naos_task_lifecycle import (  # noqa: E402
    extract_acceptance_criteria,
    extract_task_ids,
    normalize_task_id,
    resolve_task_record,
    find_task_compact,
)


REPORT_SCHEMA = "naos.task_context_pack.v1"
SPEC_REF_PATTERN = re.compile(r"(specs/[A-Za-z0-9_./-]+\.md(?:#[A-Za-z0-9_.:-]+)?)")
DEFAULT_CARD_SECTIONS = [
    "Quick Reference",
    "Schemas to Respect",
    "Existing Code to Use",
    "Acceptance Criteria",
    "Implementation Plan",
    "Out of Scope",
    "Known Risks / Gotchas",
    "Post-Implementation Checklist",
]
REPORT_KEYS = {
    "function_index_report": "function_index_health_report",
    "module_header_traceability_report": "module_header_traceability_report",
    "spec_pack_contract_report": "spec_pack_contract_report",
    "spec_pack_materialization_report": "spec_pack_materialization_report",
    "spec_assembly_worksheet_report": "spec_assembly_worksheet_report",
    "spec_cascade_report": "spec_cascade_report",
    "plan_coherence_report": "plan_coherence_report",
    "test_evidence_report": "test_evidence_report",
    "systemic_impact_report": "systemic_impact_report",
    "control_plane_review_report": "control_plane_review_report",
    "ai_surface_context_budget_report": "ai_surface_context_budget_report",
    "setup_recommendations_report": "setup_recommendations_report",
    "memory_context_readiness_report": "memory_context_readiness_report",
    "memory_provider_access_report": "memory_provider_access_report",
    "memory_use_policy_report": "memory_use_policy_report",
    "evidence_attestation_report": "evidence_attestation_report",
    "gate_status_report": "gate_status_report",
    "gate_evaluation_report": "gate_evaluation_report",
    "dashboard_summary_report": "dashboard_summary_report",
    "local_context_index_report": "local_context_index_report",
    "local_context_query_report": "local_context_query_report",
    "semantic_candidate_layer_report": "semantic_candidate_layer_report",
    "graph_context_readiness_report": "graph_context_readiness_report",
    "graph_context_query_report": "graph_context_query_report",
    "session_lifecycle_report": "session_lifecycle_report",
}


def utc_now_text() -> str:
    return controlled_utc_now_text()


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping: {path}")
    return data


def load_json_mapping(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def string_list(value: Any) -> list[str]:
    return [str(item) for item in as_list(value) if str(item).strip()]


def bounded_text(text: Any, limit: int) -> str:
    value = str(text or "").strip()
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 18)].rstrip() + " [truncated]"


def portable_artifact_ref(path: Path, root: Path) -> str:
    resolved = path.resolve(strict=False)
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        pass
    try:
        return f"kit://{resolved.relative_to(kit_root().resolve()).as_posix()}"
    except ValueError:
        return f"external://{path.name}"


def safe_digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def default_rules_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "task_context_pack_rules.yaml"


def resolve_rules_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None = None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("task_context_pack_rules") or "task_context_pack_rules.yaml")
    project_rules = root / naos_root / filename
    if project_rules.exists():
        return project_rules, "project"
    return default_rules_template(), "template"


def markdown_output_path(root: Path, naos_root: str, policy: dict[str, Any], task_id: str) -> Path | None:
    if not task_id or is_kit_repository(root, naos_root):
        return None
    base = root / naos_root
    if not base.is_dir():
        return None
    directory = str(policy.get("paths", {}).get("task_context_pack_markdown_dir") or "context_packs")
    safe_task = re.sub(r"[^A-Za-z0-9_.-]+", "_", task_id.upper())
    return base / directory / f"{safe_task}.md"


def artifact_record(
    root: Path,
    path: Path,
    role: str,
    freshness_days: int,
    now: datetime,
) -> dict[str, Any]:
    exists = path.exists()
    record: dict[str, Any] = {
        "role": role,
        "path": portable_artifact_ref(path, root),
        "status": "present" if exists else "missing",
    }
    if not exists:
        record["freshness"] = "missing"
        return record
    if path.is_file():
        stat = path.stat()
        try:
            external_kit_resource = not path.resolve().is_relative_to(root.resolve())
        except (OSError, RuntimeError):
            external_kit_resource = True
        if external_kit_resource:
            record.update(
                {
                    "size_bytes": stat.st_size,
                    "digest": safe_digest(path),
                    "age_days": None,
                    "freshness": "unknown",
                    "freshness_basis": "external_content_digest_not_filesystem_mtime",
                }
            )
        else:
            mtime = datetime.fromtimestamp(stat.st_mtime, UTC)
            age_days = max(0, (now - mtime).days)
            record.update(
                {
                    "size_bytes": stat.st_size,
                    "modified_time": mtime.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                    "digest": safe_digest(path),
                    "age_days": age_days,
                    "freshness": "stale" if freshness_days >= 0 and age_days > freshness_days else "fresh",
                    "freshness_basis": "project_file_mtime",
                }
            )
    else:
        record["freshness"] = "unknown"
    return record


def add_artifact(
    artifacts: list[dict[str, Any]],
    seen: set[tuple[str, str]],
    root: Path,
    path: Path,
    role: str,
    freshness_days: int,
    now: datetime,
) -> dict[str, Any]:
    key = (role, str(path))
    if key in seen:
        return {}
    seen.add(key)
    record = artifact_record(root, path, role, freshness_days, now)
    artifacts.append(record)
    return record


def extract_section(text: str, heading: str, limit: int) -> str:
    pattern = re.compile(
        rf"^##+\s+{re.escape(heading)}\s*$([\s\S]*?)(?=^##+\s+|\Z)",
        re.MULTILINE | re.IGNORECASE,
    )
    match = pattern.search(text)
    return bounded_text(match.group(1).strip(), limit) if match else ""


def extract_table_fields(section_text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in section_text.splitlines():
        if not line.strip().startswith("|"):
            continue
        parts = [part.strip().strip("*") for part in line.strip().strip("|").split("|")]
        if len(parts) < 2:
            continue
        key, value = parts[0], parts[1]
        if key.lower() in {"field", "---", ""} or set(key) <= {"-"}:
            continue
        fields[key] = value
    return fields


def extract_bullets(section_text: str, limit: int) -> list[str]:
    items = []
    for line in section_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("- [") or stripped.startswith("- "):
            items.append(bounded_text(stripped, limit))
    return items


def parse_existing_code(section_text: str, limit: int) -> list[dict[str, str]]:
    rows = []
    for line in section_text.splitlines():
        if not line.strip().startswith("|"):
            continue
        parts = [part.strip().strip("`") for part in line.strip().strip("|").split("|")]
        if len(parts) < 3 or parts[0].lower() in {"purpose", "---"} or set(parts[0]) <= {"-"}:
            continue
        rows.append(
            {
                "purpose": bounded_text(parts[0], limit),
                "file": bounded_text(parts[1], limit),
                "symbol": bounded_text(parts[2], limit),
            }
        )
    return rows


def find_task_card(root: Path, naos_root: str, task_id: str) -> Path | None:
    resolution = resolve_task_record(root, naos_root, task_id, "auto")
    selected = resolution.get("selected_card_path")
    return Path(str(selected)) if selected else None


def compact_path_for(root: Path, naos_root: str, task_id: str) -> Path | None:
    return find_task_compact(root, naos_root, task_id)


def parse_task_card(path: Path | None, max_chars: int, max_items: int) -> dict[str, Any]:
    if path is None or not path.exists():
        return {"status": "missing", "path": None, "fields": {}, "sections": {}}
    text = path.read_text(encoding="utf-8", errors="replace")
    quick = extract_section(text, "Quick Reference", max_chars)
    fields = extract_table_fields(quick)
    sections: dict[str, str] = {}
    for heading in DEFAULT_CARD_SECTIONS:
        sections[heading] = extract_section(text, heading, max_chars)
    lane_section = extract_section(text, "Parallelization Opportunity (Advisory)", max_chars)
    lane_fields = extract_table_fields(lane_section)
    acceptance_extraction = extract_acceptance_criteria(text)
    acceptance = acceptance_extraction["criteria"][:max_items]
    plan = extract_bullets(sections.get("Implementation Plan", ""), max_chars)[:max_items]
    post_checks = extract_bullets(sections.get("Post-Implementation Checklist", ""), max_chars)[:max_items]
    existing_code = parse_existing_code(sections.get("Existing Code to Use", ""), max_chars)[:max_items]
    missing_sections = [heading for heading in DEFAULT_CARD_SECTIONS if not sections.get(heading)]
    if acceptance and "Acceptance Criteria" in missing_sections:
        missing_sections.remove("Acceptance Criteria")
    task_ids = sorted(extract_task_ids(text))
    return {
        "status": "present",
        "path": str(path),
        "fields": fields,
        "parallelization_opportunity": {
            "status": "present" if lane_fields else "missing",
            "fields": lane_fields,
            "limitations": [
                "Active-card lane posture is advisory planning context only.",
                "Suggested lanes do not activate handoff unless lanes are explicitly declared.",
            ],
        },
        "task_ids_found": task_ids,
        "acceptance_criteria": acceptance,
        "acceptance_criteria_extraction_status": acceptance_extraction["status"],
        "acceptance_criteria_extraction_source": acceptance_extraction["source"],
        "acceptance_criteria_extraction_limitations": acceptance_extraction["limitations"],
        "implementation_plan": plan,
        "post_implementation_checks": post_checks,
        "existing_code": existing_code,
        "guardrails": bounded_text(sections.get("Out of Scope", ""), max_chars),
        "risks": bounded_text(sections.get("Known Risks / Gotchas", ""), max_chars),
        "schemas": bounded_text(sections.get("Schemas to Respect", ""), max_chars),
        "missing_sections": missing_sections,
        "bounded_sections": {key: value for key, value in sections.items() if value},
    }


def lane_fields_from_registry(registry: dict[str, Any]) -> dict[str, Any]:
    entry = registry.get("bounded_entry") if isinstance(registry.get("bounded_entry"), dict) else registry.get("entry")
    if not isinstance(entry, dict):
        return {"status": "missing", "fields": {}, "related_task_refs": []}
    fields = {
        key: entry.get(key)
        for key in [
            "parallel_lane_opportunity",
            "parallel_lane_decision",
            "parallel_lane_reasons",
            "parallel_lane_candidate_lanes",
            "parallelizable",
        ]
        if key in entry
    }
    related = []
    for key in ["dependencies", "related_tasks", "blocked_by"]:
        related.extend(string_list(entry.get(key)))
    return {
        "status": "present" if fields or related else "missing",
        "fields": fields,
        "related_task_refs": list(dict.fromkeys(related)),
    }


def lane_fields_from_alignment(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path, source = pia.alignment_path(root, naos_root, policy, None)
    if not path.exists():
        return {
            "status": "missing",
            "path": str(path),
            "source": source,
            "posture": pia.parallel_lane_posture(None),
        }
    data, parse_error = pia.extract_frontmatter(path)
    posture = pia.parallel_lane_posture(data)
    return {
        "status": "parse_error" if parse_error else "present",
        "path": str(path),
        "source": source,
        "parse_error": parse_error,
        "posture": posture,
    }


def build_parallel_lane_context(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    task_card: dict[str, Any],
    registry: dict[str, Any],
) -> dict[str, Any]:
    active_card = task_card.get("parallelization_opportunity") if isinstance(task_card.get("parallelization_opportunity"), dict) else {}
    task_registry = lane_fields_from_registry(registry)
    alignment = lane_fields_from_alignment(root, naos_root, policy)
    return {
        "status": "present"
        if any(source.get("status") == "present" for source in [active_card, task_registry, alignment])
        else "missing",
        "active_task_card": active_card or {"status": "missing", "fields": {}},
        "task_registry": task_registry,
        "pre_implementation_alignment": alignment,
        "related_task_refs": task_registry.get("related_task_refs") or [],
        "decision_authority": "human_or_project_policy_only",
        "does_not_declare_lanes": True,
        "does_not_activate_handoff": True,
        "limitations": [
            "Task context pack summarizes lane-opportunity evidence as bounded context only.",
            "It does not infer active lanes, require handoff from suggestions, or approve parallel execution.",
        ],
    }


def load_task_registry(root: Path, naos_root: str, task_id: str, max_chars: int) -> tuple[dict[str, Any], Path]:
    path = root / naos_root / "TASK_REGISTRY.yaml"
    if not path.exists():
        return {"status": "missing", "path": str(path), "entry": None}, path
    try:
        data = load_yaml_mapping(path)
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc), "entry": None}, path
    tasks = data.get("tasks") if isinstance(data.get("tasks"), list) else []
    entry = next((item for item in tasks if isinstance(item, dict) and str(item.get("id", "")).upper() == task_id.upper()), None)
    return {
        "status": "present" if entry else "task_not_found",
        "path": str(path),
        "entry": entry,
        "summary": {
            "task_count": len(tasks),
            "task_status": entry.get("status") if isinstance(entry, dict) else None,
            "task_title": entry.get("title") if isinstance(entry, dict) else None,
            "requirement": entry.get("requirement") if isinstance(entry, dict) else None,
            "phase": entry.get("phase") if isinstance(entry, dict) else None,
            "priority": entry.get("priority") if isinstance(entry, dict) else None,
            "owner": entry.get("owner") if isinstance(entry, dict) else None,
        },
        "bounded_entry": json.loads(json.dumps(entry, default=str)) if isinstance(entry, dict) else None,
    }, path


def collect_spec_refs(task_card: dict[str, Any], registry: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    fields = task_card.get("fields") if isinstance(task_card.get("fields"), dict) else {}
    for value in fields.values():
        refs.extend(SPEC_REF_PATTERN.findall(str(value)))
    bounded_sections = task_card.get("bounded_sections")
    section_values = bounded_sections.values() if isinstance(bounded_sections, dict) else []
    for value in section_values:
        refs.extend(SPEC_REF_PATTERN.findall(str(value)))
    entry = registry.get("entry") if isinstance(registry.get("entry"), dict) else registry.get("bounded_entry")
    requirement = entry.get("requirement") if isinstance(entry, dict) else fields.get("Requirement")
    if requirement:
        refs.append(f"specs/03-requirements.md#{str(requirement).strip().lower()}")
    return list(dict.fromkeys(refs))


def summarize_specs(root: Path, refs: list[str], max_chars: int, max_items: int) -> list[dict[str, Any]]:
    summaries = []
    for ref in refs[:max_items]:
        path_part, _, anchor = ref.partition("#")
        path = root / path_part
        item: dict[str, Any] = {"ref": ref, "path": path_part, "anchor": anchor or None}
        if path.exists():
            item["status"] = "present"
            text = path.read_text(encoding="utf-8", errors="replace")
            item["excerpt"] = bounded_text(text, min(max_chars, 700))
        else:
            item["status"] = "missing"
        summaries.append(item)
    return summaries


def summarize_capabilities(root: Path, task_id: str, requirement: str | None, max_chars: int, max_items: int) -> list[dict[str, Any]]:
    dirs = [root / "capabilities", root / "naos" / "capabilities", kit_root() / "capabilities"]
    seen: set[Path] = set()
    matches: list[dict[str, Any]] = []
    needles = [task_id.upper()]
    if requirement:
        needles.append(str(requirement).upper())
    for directory in dirs:
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.yaml")):
            if path in seen:
                continue
            seen.add(path)
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                data = yaml.safe_load(text) or {}
            except Exception:
                continue
            haystack = text.upper()
            if any(needle and needle in haystack for needle in needles) or path.name == "task_context_pack.yaml":
                matches.append(
                    {
                        "path": str(path),
                        "id": data.get("id") if isinstance(data, dict) else path.stem,
                        "name": data.get("name") if isinstance(data, dict) else path.stem,
                        "status": data.get("status") if isinstance(data, dict) else "unknown",
                        "summary": bounded_text(data.get("description", "") if isinstance(data, dict) else "", max_chars),
                    }
                )
            if len(matches) >= max_items:
                return matches
    return matches[:max_items]


def summarize_report(path: Path, name: str, summary_keys: list[str] | None = None) -> dict[str, Any]:
    if not path.exists():
        return {"status": "not_configured", "path": str(path), "summary": {}, "findings_count": 0}
    try:
        data = load_json_mapping(path)
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc), "summary": {}, "findings_count": 0}
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    if summary_keys:
        summary = {key: summary.get(key) for key in summary_keys if key in summary}
    return {
        "status": data.get("status") or "present",
        "path": str(path),
        "summary": summary,
        "findings_count": len(data.get("findings") or []),
        "human_review_required": bool(data.get("human_review_required")),
        "not_claimed": data.get("not_claimed") or [],
        "limitations": data.get("limitations") or [],
    }


def summarize_memory_report(path: Path) -> dict[str, Any]:
    data = summarize_report(path, "memory_context_readiness")
    if not path.exists() or data.get("status") == "parse_error":
        data["rule"] = "No memory readiness report is available; use repository evidence and compact/task-card fallback."
        data["memory_role"] = "advisory only"
        return data
    try:
        raw = load_json_mapping(path)
    except Exception:
        return data
    project_identity = raw.get("project_identity") if isinstance(raw.get("project_identity"), dict) else {}
    data.update(
        {
            "provider_posture": raw.get("provider_posture") or {},
            "fallback_readiness": raw.get("fallback_readiness") or {},
            "context_pack_readiness": raw.get("context_pack_readiness") or {},
            "mcp_tool_access": raw.get("mcp_tool_access") or {},
            "project_identity": {
                "status": project_identity.get("status"),
                "project_identity_verified": bool(project_identity.get("project_identity_verified")),
                "global_fixed_project_detected": bool(project_identity.get("global_fixed_project_detected")),
            },
            "memory_role": "advisory readiness/reference state only; repository evidence remains authoritative",
            "findings": (raw.get("findings") or [])[:8],
        }
    )
    return data


def summarize_memory_provider_access_report(path: Path) -> dict[str, Any]:
    data = summarize_report(path, "memory_provider_access")
    if not path.exists() or data.get("status") == "parse_error":
        data["rule"] = "No memory provider access report is available; do not claim memory access and use repo evidence/context packs as fallback."
        return data
    try:
        raw = load_json_mapping(path)
    except Exception:
        return data
    project_identity = raw.get("project_identity") if isinstance(raw.get("project_identity"), dict) else {}
    data.update(
        {
            "provider_configured": bool(raw.get("provider_configured")),
            "provider_access_verified": bool(raw.get("provider_access_verified")),
            "mcp_access_verified": bool(raw.get("mcp_access_verified")),
            "provider_access_method": raw.get("provider_access_method"),
            "project_identity": {
                "status": project_identity.get("status"),
                "project_identity_verified": bool(project_identity.get("project_identity_verified")),
                "global_fixed_project_detected": bool(project_identity.get("global_fixed_project_detected")),
            },
            "ci_memory_access": raw.get("ci_memory_access") or {},
            "rule": "Memory access posture is advisory metadata only; task packs must not treat configured memory as usable unless access is configured, authorized, and verified.",
            "findings": (raw.get("findings") or [])[:8],
        }
    )
    return data


def summarize_memory_use_policy_report(path: Path) -> dict[str, Any]:
    data = summarize_report(path, "memory_use_policy")
    if data.get("status") in {"not_configured", "parse_error"}:
        data["rule"] = "No memory-use policy report is available; do not treat memory as instruction-grade or approved context."
        return data
    try:
        raw = load_json_mapping(path)
    except Exception:
        return data
    summary = raw.get("summary") or {}
    data.update(
        {
            "memory_review_items": summary.get("memory_review_items", 0),
            "instruction_grade_items": raw.get("instruction_grade_items") or [],
            "supporting_context_items": raw.get("supporting_context_items") or [],
            "unsafe_instruction_grade_claims": raw.get("unsafe_instruction_grade_claims") or [],
            "memory_access_prerequisites": raw.get("memory_access_prerequisites") or {},
            "policy_item_access_posture": raw.get("policy_item_access_posture") or [],
            "recall_trace_readiness": raw.get("recall_trace_readiness") or {},
            "audit_event_readiness": raw.get("audit_event_readiness") or {},
            "rule": "Memory-use posture is metadata only; task packs must treat memory as advisory unless explicitly approved, scoped, reviewed, fresh, bounded, and separately access-verified.",
            "findings": (raw.get("findings") or [])[:8],
        }
    )
    return data


def load_source_to_test_map(root: Path, naos_root: str, policy: dict[str, Any]) -> tuple[dict[str, Any], Path]:
    path = root / naos_root / str(policy.get("paths", {}).get("source_to_test_map") or "test_evidence/source_to_test_map.json")
    if not path.exists():
        return {"status": "not_configured", "path": str(path), "summary": {}}, path
    try:
        data = load_json_mapping(path)
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc), "summary": {}}, path
    return {"status": data.get("status") or "present", "path": str(path), "summary": data.get("summary") or {}}, path


def load_evidence_lists(root: Path, naos_root: str, reports: list[dict[str, Any]], max_items: int) -> tuple[list[Any], list[Any], list[Any]]:
    known_gaps: list[Any] = []
    residual_risks: list[Any] = []
    waivers: list[Any] = []
    for report in reports:
        if not isinstance(report, dict):
            continue
        known_gaps.extend(as_list(report.get("known_gaps")))
        residual_risks.extend(as_list(report.get("residual_risks")))
        waivers.extend(as_list(report.get("waivers")))
    for filename, target in (
        ("known_gaps.yaml", known_gaps),
        ("residual_risks.yaml", residual_risks),
        ("exceptions.yaml", waivers),
    ):
        path = root / naos_root / "evidence" / filename
        if path.exists():
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                if isinstance(data, dict):
                    for key in ("known_gaps", "residual_risks", "waivers", "exceptions"):
                        target.extend(as_list(data.get(key)))
            except Exception:
                continue
    return known_gaps[:max_items], residual_risks[:max_items], waivers[:max_items]


def build_findings(
    *,
    task_requested: bool,
    task_id: str,
    task_card: dict[str, Any],
    task_resolution: dict[str, Any],
    registry: dict[str, Any],
    source_artifacts: list[dict[str, Any]],
    rules: dict[str, Any],
    profile: str,
    policy: dict[str, Any],
    known_gaps: list[Any],
    residual_risks: list[Any],
    waivers: list[Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    missing_severity = str((rules.get("missing_source_severity_by_profile") or {}).get(profile) or severity_for_profile(profile, policy))
    advisory = "advisory"
    if not task_requested:
        return [
            {
                "id": "task_context_pack.task_not_selected",
                "severity": advisory,
                "status": "not_configured",
                "message": "No task id was supplied; run with --task T-XXX to generate a task-specific context pack.",
            }
        ]
    if task_resolution.get("status") == "task_not_found":
        return [
            {
                "id": "task_context_pack.task_not_found",
                "severity": "required" if profile in {"standard", "assured"} else "warning",
                "status": "task_not_found",
                "message": f"The exact task id {task_id} was not found in active records, completed history, or TASK_REGISTRY.yaml.",
            }
        ]
    if task_resolution.get("status") == "recovery_mode_mismatch":
        findings.append(
            {
                "id": "task_context_pack.recovery_mode_mismatch",
                "severity": "required" if profile in {"standard", "assured"} else "warning",
                "status": "task_not_found",
                "message": f"The exact task id {task_id} exists but is unavailable in recovery mode {task_resolution.get('recovery_mode')}.",
            }
        )
    if task_resolution.get("status") == "unsupported_legacy_status":
        findings.append(
            {
                "id": "task_context_pack.unsupported_legacy_status",
                "severity": "required",
                "status": "unsupported_legacy_status",
                "message": (
                    f"Legacy status {task_resolution.get('legacy_status')!r} is unsupported; "
                    "reconcile it explicitly before using this task context for completion."
                ),
            }
        )
    if not task_id:
        findings.append(
            {
                "id": "task_context_pack.missing_task",
                "severity": missing_severity,
                "status": "missing_task",
                "message": "Task id is missing.",
            }
        )
    if task_card.get("status") == "missing":
        findings.append(
            {
                "id": "task_context_pack.missing_task_card",
                "severity": missing_severity,
                "status": "missing_task_card",
                "message": f"No active task card was found for {task_id}.",
            }
        )
    else:
        for section in task_card.get("missing_sections") or []:
            findings.append(
                {
                    "id": f"task_context_pack.missing_card_section.{section.lower().replace(' ', '_').replace('/', '_')}",
                    "severity": advisory,
                    "status": "missing_section",
                    "message": f"Active task card is missing section: {section}.",
                }
            )
        if not task_card.get("acceptance_criteria"):
            findings.append(
                {
                    "id": "task_context_pack.missing_acceptance_criteria",
                    "severity": missing_severity if profile in {"standard", "assured"} else advisory,
                    "status": "missing_required_source",
                    "message": "No acceptance criteria were parsed from the active task card.",
                }
            )
    if registry.get("status") == "missing":
        severity = advisory if profile == "quickstart" else missing_severity
        findings.append(
            {
                "id": "task_context_pack.missing_registry",
                "severity": severity,
                "status": "missing_registry",
                "message": "TASK_REGISTRY.yaml is missing.",
            }
        )
    elif registry.get("status") == "task_not_found":
        findings.append(
            {
                "id": "task_context_pack.task_not_found_in_registry",
                "severity": advisory if profile == "quickstart" else missing_severity,
                "status": "missing_task",
                "message": f"{task_id} was not found in TASK_REGISTRY.yaml.",
            }
        )
    required_roles = set((rules.get("required_sources") or {}).get(profile) or [])
    role_map = {
        "active_task_card": "task_record",
        "task_registry": "task_registry",
        "specs": "spec",
        "deterministic_reports": "deterministic_report",
    }
    for configured, role in role_map.items():
        if configured not in required_roles:
            continue
        matching = [
            artifact
            for artifact in source_artifacts
            if artifact.get("role") == role
            or (role == "task_record" and artifact.get("role") in {"active_task_card", "completed_task_card"})
        ]
        if not matching or not any(artifact.get("status") == "present" for artifact in matching):
            findings.append(
                {
                    "id": f"task_context_pack.missing_required_source.{configured}",
                    "severity": missing_severity,
                    "status": "missing_required_source",
                    "message": f"Required context source is missing for profile {profile}: {configured}.",
                }
            )
    for artifact in source_artifacts:
        if artifact.get("freshness") == "stale" and artifact.get("role") in {"active_task_card", "task_registry", "spec", "deterministic_report"}:
            findings.append(
                {
                    "id": f"task_context_pack.stale_source.{artifact.get('role')}",
                    "severity": advisory if artifact.get("role") == "deterministic_report" else missing_severity,
                    "status": "stale_source",
                    "message": f"Context source appears stale: {artifact.get('path')}",
                }
            )
    if known_gaps or residual_risks or waivers:
        findings.append(
            {
                "id": "task_context_pack.review_items_present",
                "severity": advisory,
                "status": "review_required",
                "message": "Known gaps, residual risks, or waivers are present in related evidence and should remain visible during task work.",
            }
        )
    return findings


def status_from_findings(task_requested: bool, task_card: dict[str, Any], registry: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    if not task_requested:
        return "not_configured"
    statuses = {str(item.get("status")) for item in findings}
    severities = {str(item.get("severity")) for item in findings}
    if "blocking" in severities:
        return "blocked"
    if "task_not_found" in statuses:
        return "task_not_found"
    if "unsupported_legacy_status" in statuses:
        return "unsupported_legacy_status"
    if "missing_task" in statuses:
        return "missing_task"
    if task_card.get("status") == "missing":
        return "missing_task_card"
    if registry.get("status") == "missing":
        return "missing_registry"
    if "missing_required_source" in statuses:
        return "missing_required_source"
    if "stale_source" in statuses:
        return "stale_source"
    if "required" in severities:
        return "review_required"
    if findings:
        return "advisory"
    return "ready"


def build_markdown(report: dict[str, Any]) -> str:
    task_id = report.get("task_id") or "unspecified"
    task_card = report.get("task_card") or {}
    registry = report.get("task_registry") or {}
    task_summary = registry.get("summary") or {}
    lines = [
        f"# Task Context Pack - {task_id}",
        "",
        "_Derived, bounded, non-authoritative context pack. JSON report and source artifacts remain the review trail._",
        "",
        "## Authority and Limitations",
        "- Current user instructions, active task constraints, repository governance, git state, and deterministic NAOS reports outrank this pack.",
        "- Memory is advisory recall only; repository evidence is authoritative.",
        "- This pack does not provide approval, evidence authority, complete coherence proof, automatic context injection, or hallucination prevention.",
        "",
        "## Task Objective",
        f"- Status: `{report.get('status')}`",
        f"- Title: {task_summary.get('task_title') or (task_card.get('fields') or {}).get('Task ID') or 'not available'}",
        f"- Requirement: {task_summary.get('requirement') or (task_card.get('fields') or {}).get('Requirement') or 'not available'}",
        "",
        "## Relevant Specs and Capabilities",
    ]
    specs = report.get("relevant_specs") or []
    if specs:
        for item in specs[:6]:
            lines.append(f"- `{item.get('ref')}` - {item.get('status')}")
    else:
        lines.append("- No spec references were found in the bounded task context.")
    for item in (report.get("relevant_capabilities") or [])[:6]:
        lines.append(f"- Capability `{item.get('id')}` - {item.get('name')} ({item.get('status')})")
    lines.extend(["", "## Existing Code and Function Index"])
    for item in (task_card.get("existing_code") or [])[:6]:
        lines.append(f"- {item.get('purpose')}: `{item.get('file')}` / `{item.get('symbol')}`")
    function_index = report.get("function_index_context") or {}
    lines.append(f"- Function-index posture: `{function_index.get('status')}`")
    local_index = report.get("local_context_index_context") or {}
    lines.append(f"- Local context index posture: `{local_index.get('status')}` (candidate references only)")
    lane = report.get("parallel_lane_context") or {}
    alignment_lane = ((lane.get("pre_implementation_alignment") or {}).get("posture") or {})
    lines.extend(["", "## Parallel Lane Context"])
    lines.append(f"- Lane-context posture: `{lane.get('status')}`")
    lines.append(f"- Alignment opportunity: `{alignment_lane.get('opportunity')}`")
    lines.append(f"- Alignment decision: `{alignment_lane.get('decision')}`")
    lines.append("- Lane context is advisory; suggestions do not activate handoff.")
    lines.extend(["", "## Test and Evidence Expectations"])
    test_context = report.get("test_evidence_context") or {}
    lines.append(f"- Test-evidence posture: `{test_context.get('status')}`")
    lines.append(f"- Module-header posture: `{(report.get('module_header_context') or {}).get('status')}`")
    lines.append(f"- Spec-pack posture: `{(report.get('spec_pack_context') or {}).get('status')}`")
    lines.append(f"- Spec-cascade posture: `{(report.get('spec_cascade_context') or {}).get('status')}`")
    lines.append(f"- Implementation-readiness posture: `{(report.get('implementation_readiness_context') or {}).get('status')}`")
    lines.extend(["", "## Systemic and Control-Plane Notes"])
    lines.append(f"- Systemic impact: `{(report.get('systemic_impact_context') or {}).get('status')}`")
    lines.append(f"- Control-plane review: `{(report.get('control_plane_review_context') or {}).get('status')}`")
    lines.extend(["", "## Memory Readiness Advisory Context"])
    memory = report.get("memory_context") or {}
    lines.append(f"- Memory readiness: `{memory.get('status')}`")
    lines.append("- Use repo evidence/context fallback when memory access is unavailable or not verified.")
    lines.extend(["", "## Known Gaps, Residual Risks, and Waivers"])
    lines.append(f"- Known gaps: {len(report.get('known_gaps') or [])}")
    lines.append(f"- Residual risks: {len(report.get('residual_risks') or [])}")
    lines.append(f"- Waivers: {len(report.get('waivers') or [])}")
    lines.extend(["", "## Commands to Run"])
    for command in report.get("commands_to_run") or []:
        lines.append(f"- `{command}`")
    lines.extend(["", "## Human Review Boundary"])
    boundary = report.get("human_review_boundary") or {}
    lines.append(f"- Human review required: `{boundary.get('required')}`")
    for item in boundary.get("reasons") or []:
        lines.append(f"- {item}")
    lines.extend(["", "## Source Artifacts"])
    for artifact in (report.get("source_artifacts") or [])[:12]:
        lines.append(f"- `{artifact.get('path')}` - {artifact.get('status')} / {artifact.get('freshness')}")
    lines.extend(["", "## Limitations and Non-Claims"])
    for item in report.get("limitations") or []:
        lines.append(f"- {item}")
    for item in report.get("not_claimed") or []:
        lines.append(f"- Not claimed: {item}")
    return "\n".join(lines).rstrip() + "\n"


def build_report(
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    task_arg: str | None,
    rules_path: Path,
    rules_source: str,
    recovery_mode: str = "auto",
) -> dict[str, Any]:
    max_chars = int(rules.get("max_chars_per_section") or 1800)
    max_items = int(rules.get("max_items_per_section") or 8)
    task_requested = bool(task_arg)
    task_id = normalize_task_id(task_arg) if task_arg else ""
    if not rules.get("enabled", True):
        return {
            "schema": REPORT_SCHEMA,
            "generated_at": utc_now_text(),
            "profile": profile,
            "status": "disabled",
            "naos_root": naos_root,
            "project_root": str(root),
            "task_id": task_id,
            "task_card": {"status": "disabled"},
            "task_registry": {"status": "disabled"},
            "compact": {"status": "disabled"},
            "source_of_truth_hierarchy": rules.get("authoritative_source_hierarchy") or [],
            "authoritative_context": {},
            "relevant_specs": [],
            "relevant_capabilities": [],
            "policy_profile": {"profile": profile},
            "existing_code_context": {},
            "function_index_context": {},
            "module_header_context": {},
            "spec_pack_context": {},
            "spec_cascade_context": {},
            "implementation_readiness_context": {},
            "test_evidence_context": {},
            "systemic_impact_context": {},
            "control_plane_review_context": {},
            "setup_recommendations_context": {},
            "memory_context": {},
            "memory_provider_access_context": {},
            "memory_use_policy_context": {},
            "evidence_attestation_context": {},
            "local_context_index_context": {},
            "local_context_query_context": {},
            "semantic_candidate_layer_context": {},
            "graph_context_readiness_context": {},
            "graph_context_query_context": {},
            "gates_context": {},
            "known_gaps": [],
            "residual_risks": [],
            "waivers": [],
            "commands_to_run": [],
            "human_review_boundary": {"required": False, "reasons": []},
            "source_artifacts": [],
            "source_artifacts_used": [],
            "source_artifacts_missing": [],
            "source_artifact_freshness": {},
            "findings": [],
            "limitations": rules.get("limitations") or [],
            "not_claimed": rules.get("not_claimed") or [],
            "summary": {"status": "disabled"},
        }

    now = controlled_now_utc()
    freshness_days = int((rules.get("source_freshness_policy") or {}).get("default_freshness_window_days", 30))
    artifacts: list[dict[str, Any]] = []
    seen_artifacts: set[tuple[str, str]] = set()
    add_artifact(artifacts, seen_artifacts, root, rules_path, "rules", freshness_days, now)

    task_resolution = (
        resolve_task_record(root, naos_root, task_id, recovery_mode)
        if task_id
        else {
            "status": "task_not_selected",
            "task_id": "",
            "recovery_mode": recovery_mode,
            "record_kind": None,
            "selected_card_path": None,
            "lifecycle_state": "unknown",
            "delivery_state": "not_delivered",
            "verification_state": "unverified",
            "human_review_required": False,
        }
    )
    selected_card = task_resolution.get("selected_card_path")
    card_path = Path(str(selected_card)) if selected_card else None
    if task_id:
        fallback_dir = "completed" if recovery_mode == "completed" else "active"
        record_role = "completed_task_card" if task_resolution.get("record_kind") == "completed" else "active_task_card"
        add_artifact(
            artifacts,
            seen_artifacts,
            root,
            card_path or (root / naos_root / fallback_dir / f"{task_id}.md"),
            record_role,
            freshness_days,
            now,
        )
        add_artifact(
            artifacts,
            seen_artifacts,
            root,
            root / naos_root / "completed_history.yaml",
            "completed_task_history",
            freshness_days,
            now,
        )
    task_card = parse_task_card(card_path, max_chars, max_items)

    compact_path = compact_path_for(root, naos_root, task_id) if task_id else None
    if task_id:
        add_artifact(artifacts, seen_artifacts, root, compact_path or (root / naos_root / "active" / f"{task_id}_compact.md"), "compact_recovery_brief", freshness_days, now)
    compact = {
        "status": "present" if compact_path and compact_path.exists() else "not_configured",
        "path": str(compact_path) if compact_path else None,
        "summary": bounded_text(compact_path.read_text(encoding="utf-8", errors="replace"), max_chars) if compact_path and compact_path.exists() else "",
    }

    task_registry, registry_path = load_task_registry(root, naos_root, task_id, max_chars)
    add_artifact(artifacts, seen_artifacts, root, registry_path, "task_registry", freshness_days, now)
    parallel_lane_context = build_parallel_lane_context(root, naos_root, policy, task_card, task_registry)

    requirement = None
    if isinstance(task_registry.get("summary"), dict):
        requirement = task_registry["summary"].get("requirement")
    if not requirement and isinstance(task_card.get("fields"), dict):
        requirement = task_card["fields"].get("Requirement")

    spec_refs = collect_spec_refs(task_card, task_registry)
    relevant_specs = summarize_specs(root, spec_refs, max_chars, max_items)
    for item in relevant_specs:
        add_artifact(artifacts, seen_artifacts, root, root / str(item.get("path")), "spec", freshness_days, now)

    relevant_capabilities = summarize_capabilities(root, task_id, requirement, max_chars, max_items)
    for item in relevant_capabilities:
        add_artifact(artifacts, seen_artifacts, root, Path(str(item.get("path"))), "capability_card", freshness_days, now)

    reports: dict[str, dict[str, Any]] = {}
    for policy_key, role in REPORT_KEYS.items():
        path = report_default_path(root, naos_root, policy, policy_key)
        if policy_key == "memory_context_readiness_report":
            reports[policy_key] = summarize_memory_report(path)
        elif policy_key == "memory_provider_access_report":
            reports[policy_key] = summarize_memory_provider_access_report(path)
        elif policy_key == "memory_use_policy_report":
            reports[policy_key] = summarize_memory_use_policy_report(path)
        else:
            reports[policy_key] = summarize_report(path, role)
        add_artifact(artifacts, seen_artifacts, root, path, "deterministic_report", freshness_days, now)

    source_to_test_map, source_to_test_path = load_source_to_test_map(root, naos_root, policy)
    add_artifact(artifacts, seen_artifacts, root, source_to_test_path, "source_to_test_map", freshness_days, now)

    function_index_path = root / naos_root / "inventory" / "FUNCTION_INDEX.yaml"
    add_artifact(artifacts, seen_artifacts, root, function_index_path, "function_index", freshness_days, now)
    function_index_context = reports["function_index_report"] | {
        "function_index_path": str(function_index_path),
        "function_index_present": function_index_path.exists(),
        "rule": "Function index and duplicate-risk posture are deterministic anchors; no semantic retrieval is performed.",
    }
    if function_index_path.exists():
        try:
            index_data = yaml.safe_load(function_index_path.read_text(encoding="utf-8")) or {}
            function_index_context["packages"] = list(index_data.keys())[:max_items] if isinstance(index_data, dict) else []
        except Exception:
            function_index_context["packages"] = []

    raw_reports: list[dict[str, Any]] = []
    for key in (
        "control_plane_review_report",
        "evidence_attestation_report",
        "memory_context_readiness_report",
        "memory_provider_access_report",
        "memory_use_policy_report",
        "spec_cascade_report",
    ):
        path = report_default_path(root, naos_root, policy, key)
        if path.exists():
            try:
                raw_reports.append(load_json_mapping(path))
            except Exception:
                pass
    known_gaps, residual_risks, waivers = load_evidence_lists(root, naos_root, raw_reports, max_items)

    commands = [
        command.replace("<TASK-ID>", task_id or "T-XXX").replace("<profile>", profile)
        for command in string_list(rules.get("commands_to_run"))
    ]
    if task_id and f"naos task-context --task {task_id} --profile {profile}" not in commands:
        commands.insert(0, f"naos task-context --task {task_id} --profile {profile}")

    findings = build_findings(
        task_requested=task_requested,
        task_id=task_id,
        task_card=task_card,
        task_resolution=task_resolution,
        registry=task_registry,
        source_artifacts=artifacts,
        rules=rules,
        profile=profile,
        policy=policy,
        known_gaps=known_gaps,
        residual_risks=residual_risks,
        waivers=waivers,
    )
    counts = finding_counts(findings)
    status = status_from_findings(task_requested, task_card, task_registry, findings)
    human_required = (
        bool(task_resolution.get("human_review_required"))
        or any(item.get("severity") in {"required", "blocking"} for item in findings)
        or bool(known_gaps or residual_risks or waivers)
    )
    human_review_reasons = list(
        dict.fromkeys(
            string_list(task_resolution.get("review_reasons"))
            + string_list(
                [
                    item.get("message")
                    for item in findings
                    if item.get("severity") in {"required", "blocking"}
                    or item.get("status") == "review_required"
                ]
            )
        )
    )
    source_artifacts_used = [str(item.get("path")) for item in artifacts if item.get("status") == "present"]
    source_artifacts_missing = [str(item.get("path")) for item in artifacts if item.get("status") == "missing"]
    freshness = {
        "fresh": sum(1 for item in artifacts if item.get("freshness") == "fresh"),
        "stale": sum(1 for item in artifacts if item.get("freshness") == "stale"),
        "missing": sum(1 for item in artifacts if item.get("freshness") == "missing"),
        "unknown": sum(1 for item in artifacts if item.get("freshness") == "unknown"),
    }
    report = {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "task_id": task_id,
        "rules": {"path": str(rules_path), "source": rules_source},
        "task_card": task_card,
        "task_resolution": task_resolution,
        "task_record_kind": task_resolution.get("record_kind"),
        "lifecycle_state": task_resolution.get("lifecycle_state"),
        "delivery_state": task_resolution.get("delivery_state"),
        "verification_state": task_resolution.get("verification_state"),
        "task_registry": task_registry,
        "parallel_lane_context": parallel_lane_context,
        "compact": compact,
        "source_of_truth_hierarchy": rules.get("authoritative_source_hierarchy") or [],
        "authoritative_context": {
            "rule": "Current user/task constraints, repository governance, git state, and deterministic reports outrank memory/context references.",
            "task_constraints": task_card.get("guardrails") or "",
            "acceptance_criteria": task_card.get("acceptance_criteria") or [],
        },
        "relevant_specs": relevant_specs,
        "relevant_capabilities": relevant_capabilities,
        "policy_profile": {
            "profile": profile,
            "severity": severity_for_profile(profile, policy),
            "supported_profiles": policy.get("profiles", {}).get("supported") or [],
        },
        "existing_code_context": {
            "from_task_card": task_card.get("existing_code") or [],
            "rule": "Check current repository sources before adding duplicate functions or modules.",
        },
        "function_index_context": function_index_context,
        "module_header_context": reports["module_header_traceability_report"],
        "spec_pack_context": reports["spec_pack_contract_report"] | {
            "rule": "Spec-pack contract is structural template conformance evidence; it does not prove specification quality or completeness.",
        },
        "spec_pack_materialization_context": reports["spec_pack_materialization_report"] | {
            "rule": "Spec-pack materialization copies or previews missing template files only; it does not fill, approve, or prove specs.",
        },
        "spec_assembly_worksheet_context": reports["spec_assembly_worksheet_report"] | {
            "rule": "Spec assembly worksheets map evidence/candidates to specs for review only; they do not promote candidates or prove traceability.",
        },
        "spec_cascade_context": reports["spec_cascade_report"] | {
            "rule": "Spec-cascade coherence is structural requirement/task/source traceability evidence; it does not prove complete traceability or code correctness.",
        },
        "implementation_readiness_context": reports["plan_coherence_report"] | {
            "rule": "Plan-coherence implementation readiness is live structural review evidence; it does not authorize implementation, task closure, merge, release, or publication.",
        },
        "test_evidence_context": {
            "status": reports["test_evidence_report"].get("status") or source_to_test_map.get("status"),
            "source_to_test_map": source_to_test_map,
            "test_evidence_report": reports["test_evidence_report"],
        },
        "systemic_impact_context": reports["systemic_impact_report"],
        "control_plane_review_context": reports["control_plane_review_report"],
        "setup_recommendations_context": reports["setup_recommendations_report"],
        "memory_context": reports["memory_context_readiness_report"],
        "memory_provider_access_context": reports["memory_provider_access_report"],
        "memory_use_policy_context": reports["memory_use_policy_report"],
        "evidence_attestation_context": reports["evidence_attestation_report"],
        "local_context_index_context": reports["local_context_index_report"] | {
            "rule": "Local context index candidates are generated, cache-like references only; source artifacts remain authoritative.",
        },
        "local_context_query_context": reports["local_context_query_report"] | {
            "rule": "Local context query candidates are bounded references only; task packs must still cite source artifacts directly.",
        },
        "semantic_candidate_layer_context": reports["semantic_candidate_layer_report"] | {
            "rule": "Semantic candidate readiness is optional posture only; task packs do not perform semantic retrieval or treat future semantic candidates as source artifacts.",
        },
        "graph_context_readiness_context": reports["graph_context_readiness_report"] | {
            "rule": "Graph context readiness is optional posture only; task packs do not perform graph traversal or treat graph links as source artifacts.",
        },
        "graph_context_query_context": reports["graph_context_query_report"] | {
            "rule": "Graph context query candidates are optional bounded relationship references only; task packs must still cite and check source artifacts directly.",
        },
        "session_lifecycle_context": reports["session_lifecycle_report"] | {
            "rule": "Session lifecycle reports are optional bounded start/checkpoint/end review aids; task packs do not treat them as task completion, approval, evidence authority, automatic context injection, or memory write-back.",
        },
        "gates_context": {
            "gate_status": reports["gate_status_report"],
            "gate_evaluation": reports["gate_evaluation_report"],
        },
        "dashboard_context": reports["dashboard_summary_report"],
        "known_gaps": known_gaps,
        "residual_risks": residual_risks,
        "waivers": waivers,
        "commands_to_run": commands[:max_items],
        "human_review_boundary": {
            "required": human_required,
            "reasons": human_review_reasons[:max_items],
            "review_posture_source": task_resolution.get("review_posture_source"),
            "rule": "Humans approve scope, governance disposition, waivers, residual risks, and durable memory decisions.",
        },
        "source_artifacts": artifacts,
        "source_artifacts_used": source_artifacts_used,
        "source_artifacts_missing": source_artifacts_missing,
        "source_artifact_freshness": freshness,
        "findings": findings,
        "limitations": rules.get("limitations") or [],
        "not_claimed": rules.get("not_claimed") or [],
        "summary": {
            "task_id": task_id,
            "status": status,
            "lifecycle_state": task_resolution.get("lifecycle_state"),
            "delivery_state": task_resolution.get("delivery_state"),
            "verification_state": task_resolution.get("verification_state"),
            "source_artifacts": len(artifacts),
            "source_artifacts_used": len(source_artifacts_used),
            "source_artifacts_missing": len(source_artifacts_missing),
            "stale_sources": freshness["stale"],
            "findings": len(findings),
            "human_review_required": human_required,
            **counts,
        },
    }
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate a bounded task context pack.")
    parser.add_argument("--task", default=os.environ.get("TASK") or os.environ.get("NAOS_TASK"), help="Task id, for example T-001.")
    parser.add_argument(
        "--recovery-mode",
        choices=["auto", "active", "completed"],
        default="auto",
        help="Select active-only, completed-only, or automatic lifecycle recovery.",
    )
    parser.add_argument("--profile", help="Profile name: quickstart, lite, standard, assured.")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"), help="Generated project NAOS root. Default from policy or naos.")
    parser.add_argument("--policy", help="Optional policy file.")
    parser.add_argument("--rules", help="Optional task_context_pack_rules.yaml path.")
    parser.add_argument("--output", help="Optional JSON report output path.")
    parser.add_argument("--write-markdown", "--markdown", action="store_true", help="Write derived Markdown pack under NAOS_ROOT/context_packs/.")
    parser.add_argument("--no-markdown", action="store_true", help="Suppress rules-driven Markdown output.")
    parser.add_argument("--strict", action="store_true", help="Use strict profile exit-code behavior.")
    parser.add_argument("--json", action="store_true", help="Print JSON report. Default is JSON for script consistency.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    rules_path, rules_source = resolve_rules_path(root, naos_root, policy, args.rules)
    rules = load_yaml_mapping(rules_path)

    try:
        report = build_report(
            root,
            naos_root,
            profile,
            policy,
            rules,
            args.task,
            rules_path,
            rules_source,
            args.recovery_mode,
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    output = (
        Path(args.output)
        if args.output
        else report_output_path(root, naos_root, policy, "task_context_pack_report")
        if args.task
        else None
    )
    write_report(output, report)

    write_markdown = bool(args.write_markdown or (rules.get("include_markdown_output") and not args.no_markdown))
    if write_markdown and report.get("task_id"):
        markdown_path = markdown_output_path(root, naos_root, policy, str(report.get("task_id")))
        if markdown_path is not None:
            markdown_path.parent.mkdir(parents=True, exist_ok=True)
            markdown_path.write_text(build_markdown(report), encoding="utf-8")
            report["markdown_output"] = {"path": str(markdown_path), "status": "written"}
            write_report(output, report)

    print(json.dumps(report, indent=2, sort_keys=True))
    exit_code = exit_code_for_summary(profile, report.get("summary", {}), policy, strict=args.strict)
    if report.get("status") in {
        "task_not_found",
        "recovery_mode_mismatch",
        "unsupported_legacy_status",
    }:
        return exit_code or 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
