#!/usr/bin/env python3
"""Validate and transition the versioned NAOS task lifecycle contract.

The exact task registry id is authoritative. This module intentionally rejects
substring extraction such as turning ``LKB-T-001`` into ``T-001``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from copy import deepcopy
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
    kit_root,
    load_policy,
    normalize_profile,
    report_output_path,
    write_report,
)


REPORT_SCHEMA = "naos.task_lifecycle.v1"
CONTRACT_SCHEMA = "naos.task_lifecycle_contract.v1"
HISTORY_SCHEMA = "naos.completed_task_history.v1"
TASK_ID_TEXT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9]+-)*T-\d{3,}(?![A-Za-z0-9-])",
    re.IGNORECASE,
)
TASK_ID_FULL_PATTERN = re.compile(r"^(?:[A-Z0-9]+-)*T-\d{3,}$")
SPEC_REF_PATTERN = re.compile(r"specs/[A-Za-z0-9_./-]+\.md(?:#[A-Za-z0-9_.:-]+)?")
PATH_REF_PATTERN = re.compile(r"`([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.#:-]+)+)`")

LIFECYCLE_STATES = {
    "unknown",
    "planned",
    "active",
    "implementation_complete",
    "completed",
    "deferred",
    "cancelled",
    "absorbed",
    "superseded",
}
DELIVERY_STATES = {"not_started", "in_progress", "delivered", "not_delivered", "excluded"}
VERIFICATION_STATES = {"unverified", "partially_verified", "verified", "inconclusive", "failed", "not_applicable"}
REVIEW_POSTURE_SOURCE = "canonical_task_lifecycle"
COMPLETION_REVIEW_REASONS = {
    "unverified": "completion_unverified",
    "partially_verified": "completion_partially_verified",
    "inconclusive": "completion_inconclusive",
    "failed": "completion_failed",
    "not_applicable": "completion_not_applicable",
}

# The sole compatibility map for historical registry status values. Consumers
# should call normalize_task_states()/is_task_delivered() rather than defining
# local done-status sets.
LEGACY_STATUS_COMPATIBILITY: dict[str, dict[str, str]] = {
    "planned": {
        "lifecycle_state": "planned",
        "delivery_state": "not_started",
        "verification_state": "unverified",
    },
    "todo": {
        "lifecycle_state": "planned",
        "delivery_state": "not_started",
        "verification_state": "unverified",
    },
    "in_progress": {
        "lifecycle_state": "active",
        "delivery_state": "in_progress",
        "verification_state": "unverified",
    },
    "active": {
        "lifecycle_state": "active",
        "delivery_state": "in_progress",
        "verification_state": "unverified",
    },
    "implemented": {
        "lifecycle_state": "implementation_complete",
        "delivery_state": "in_progress",
        "verification_state": "unverified",
    },
    "verified": {
        "lifecycle_state": "completed",
        "delivery_state": "delivered",
        "verification_state": "verified",
    },
    "done": {
        "lifecycle_state": "completed",
        "delivery_state": "delivered",
        "verification_state": "verified",
    },
    "complete": {
        "lifecycle_state": "completed",
        "delivery_state": "delivered",
        "verification_state": "verified",
    },
    "completed": {
        "lifecycle_state": "completed",
        "delivery_state": "delivered",
        "verification_state": "verified",
    },
    "deferred": {
        "lifecycle_state": "deferred",
        "delivery_state": "not_delivered",
        "verification_state": "not_applicable",
    },
    "cancelled": {
        "lifecycle_state": "cancelled",
        "delivery_state": "not_delivered",
        "verification_state": "not_applicable",
    },
    "canceled": {
        "lifecycle_state": "cancelled",
        "delivery_state": "not_delivered",
        "verification_state": "not_applicable",
    },
    "absorbed": {
        "lifecycle_state": "absorbed",
        "delivery_state": "not_delivered",
        "verification_state": "not_applicable",
    },
    "superseded": {
        "lifecycle_state": "superseded",
        "delivery_state": "not_delivered",
        "verification_state": "not_applicable",
    },
    "failed": {
        "lifecycle_state": "active",
        "delivery_state": "in_progress",
        "verification_state": "failed",
    },
}


def utc_now_text() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def string_list(value: Any) -> list[str]:
    return [str(item).strip() for item in as_list(value) if str(item).strip()]


def dedupe(values: list[Any]) -> list[str]:
    return list(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))


def safe_digest_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def safe_digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    return safe_digest_bytes(path.read_bytes())


def resolve_naos_root(root: Path, naos_root: str) -> Path:
    """Resolve the configured NAOS root without assuming it is under cwd."""

    candidate = Path(naos_root)
    return (candidate if candidate.is_absolute() else root / candidate).resolve(strict=False)


def _path_within(path: Path, allowed_root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(allowed_root.resolve(strict=False))
    except ValueError:
        return False
    return True


def portable_path(path: Path, root: Path, naos_root: str) -> dict[str, str] | None:
    """Return a portable rooted path, never a machine-specific absolute path."""

    resolved = path.resolve(strict=False)
    project_root = root.resolve(strict=False)
    sidecar_root = resolve_naos_root(root, naos_root)
    # Prefer the more specific governance root when it overlaps the project
    # root. This keeps durable references stable when the same sidecar is
    # invoked from either its host repository or the sidecar parent directory.
    for base, allowed_root in (("naos_root", sidecar_root), ("project_root", project_root)):
        try:
            relative = resolved.relative_to(allowed_root)
        except ValueError:
            continue
        return {"base": base, "path": relative.as_posix()}
    return None


def resolve_portable_path(reference: Any, root: Path, naos_root: str) -> Path | None:
    """Resolve current rooted references and legacy project-relative strings."""

    if isinstance(reference, dict):
        base = str(reference.get("base") or "")
        relative = Path(str(reference.get("path") or ""))
        if relative.is_absolute() or ".." in relative.parts:
            return None
        allowed_root = root.resolve(strict=False) if base == "project_root" else resolve_naos_root(root, naos_root) if base == "naos_root" else None
        if allowed_root is None:
            return None
        resolved = (allowed_root / relative).resolve(strict=False)
        return resolved if _path_within(resolved, allowed_root) else None
    legacy = Path(str(reference or ""))
    if not str(legacy) or legacy.is_absolute():
        return None
    resolved = (root.resolve(strict=False) / legacy).resolve(strict=False)
    return resolved if _path_within(resolved, root.resolve(strict=False)) else None


def normalize_task_id(value: Any) -> str:
    """Return one exact canonical task id or raise ValueError.

    Plain ids (``T-001``) and namespaced ids (``LKB-T-001`` or
    ``TEAM-API-T-001``) are supported. Partial matches and surrounding prose
    are rejected.
    """

    task_id = str(value or "").strip().upper()
    if not TASK_ID_FULL_PATTERN.fullmatch(task_id):
        raise ValueError(
            f"Invalid task id {value!r}; expected T-NNN or a namespaced id such as LKB-T-NNN."
        )
    return task_id


def extract_task_ids(text: Any) -> list[str]:
    """Extract complete task ids without truncating namespace prefixes."""

    return dedupe(match.group(0).upper() for match in TASK_ID_TEXT_PATTERN.finditer(str(text or "")))


def normalize_task_states(entry_or_status: dict[str, Any] | str | None) -> dict[str, Any]:
    """Resolve explicit v1 state fields or the central legacy compatibility map."""

    entry = entry_or_status if isinstance(entry_or_status, dict) else {"status": entry_or_status}
    legacy_status_exposed = entry.get("status") not in (None, "")
    legacy_status = str(entry.get("status") or "planned").strip().lower()
    legacy_status_supported = legacy_status in LEGACY_STATUS_COMPATIBILITY
    fallback = deepcopy(
        LEGACY_STATUS_COMPATIBILITY.get(legacy_status)
        or {
            "lifecycle_state": "unknown",
            "delivery_state": "not_delivered",
            "verification_state": "unverified",
        }
    )
    states = {
        "lifecycle_state": str(entry.get("lifecycle_state") or fallback["lifecycle_state"]).strip().lower(),
        "delivery_state": str(entry.get("delivery_state") or fallback["delivery_state"]).strip().lower(),
        "verification_state": str(entry.get("verification_state") or fallback["verification_state"]).strip().lower(),
        "legacy_status": legacy_status,
        "legacy_status_exposed": legacy_status_exposed,
        "legacy_status_supported": legacy_status_supported,
        "compatibility_status": "recognized" if legacy_status_supported else "unsupported",
        "compatibility_applied": not all(
            entry.get(key) for key in ("lifecycle_state", "delivery_state", "verification_state")
        ),
    }
    if not legacy_status_supported:
        states.update(
            {
                "lifecycle_state": "unknown",
                "delivery_state": "not_delivered",
                "verification_state": "unverified",
                "compatibility_applied": True,
            }
        )
        return states
    if states["lifecycle_state"] not in LIFECYCLE_STATES:
        states["lifecycle_state"] = "unknown"
        states["compatibility_applied"] = True
    if states["delivery_state"] not in DELIVERY_STATES:
        states["delivery_state"] = "not_started"
        states["compatibility_applied"] = True
    if states["verification_state"] not in VERIFICATION_STATES:
        states["verification_state"] = "unverified"
        states["compatibility_applied"] = True
    return states


def task_review_posture(
    states: dict[str, Any],
    *,
    completion_record: dict[str, Any] | None = None,
    resolution_status: str | None = None,
) -> dict[str, Any]:
    """Return the canonical deterministic review posture for one task.

    Ordinary planned or active tasks are not review-routed merely because they
    have not been delivered. Completed tasks are review-free only when their
    delivery and verification states agree on verified delivery and any
    recorded verified-delivery prerequisites are satisfied.
    """

    reasons: list[str] = []
    if resolution_status in {"task_not_found", "recovery_mode_mismatch"}:
        reasons.append(str(resolution_status))
    if resolution_status == "unsupported_legacy_status" or states.get("compatibility_status") == "unsupported":
        reasons.append("unsupported_legacy_status")

    lifecycle_state = str(states.get("lifecycle_state") or "unknown")
    delivery_state = str(states.get("delivery_state") or "not_delivered")
    verification_state = str(states.get("verification_state") or "unverified")
    legacy_status = str(states.get("legacy_status") or "")
    legacy_declares_completion = bool(states.get("legacy_status_exposed")) and (
        LEGACY_STATUS_COMPATIBILITY.get(legacy_status, {}).get("lifecycle_state") == "completed"
    )
    completion_declared = lifecycle_state == "completed" or legacy_declares_completion
    if completion_declared:
        if delivery_state != "delivered":
            reasons.append("completed_not_delivered")
        if verification_state != "verified":
            reasons.append(COMPLETION_REVIEW_REASONS.get(verification_state, "completion_unverified"))

        prerequisites_exposed = None
        for candidate in (completion_record, states):
            if isinstance(candidate, dict) and "verification_prerequisites_met" in candidate:
                prerequisites_exposed = candidate.get("verification_prerequisites_met")
                break
        if prerequisites_exposed is False:
            reasons.append("verification_prerequisites_unmet")
        if (
            lifecycle_state != "completed"
            or delivery_state not in {"delivered", "not_delivered"}
            or (delivery_state == "delivered") != (verification_state == "verified")
            or (
                bool(states.get("legacy_status_exposed"))
                and LEGACY_STATUS_COMPATIBILITY.get(legacy_status, {}).get("lifecycle_state") != "completed"
            )
        ):
            reasons.append("completion_state_inconsistent")

    review_reasons = dedupe(reasons)
    return {
        "human_review_required": bool(review_reasons),
        "review_reasons": review_reasons,
        "review_posture_source": REVIEW_POSTURE_SOURCE,
    }


def is_task_delivered(entry_or_status: dict[str, Any] | str | None) -> bool:
    """A task is delivered only when completed, delivered, and verified."""

    states = normalize_task_states(entry_or_status)
    return (
        states["lifecycle_state"] == "completed"
        and states["delivery_state"] == "delivered"
        and states["verification_state"] == "verified"
    )


def task_terminal_state(entry_or_status: dict[str, Any] | str | None) -> bool:
    return normalize_task_states(entry_or_status)["lifecycle_state"] in {
        "completed",
        "deferred",
        "cancelled",
        "absorbed",
        "superseded",
    }


def default_contract_path() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "task_lifecycle_contract.yaml"


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping: {path}")
    return data


def resolve_contract_path(root: Path, naos_root: str, explicit: str | None = None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    project = resolve_naos_root(root, naos_root) / "task_lifecycle_contract.yaml"
    if project.is_file():
        return project, "project"
    return default_contract_path(), "template"


def task_registry_path(root: Path, naos_root: str) -> Path:
    return resolve_naos_root(root, naos_root) / "TASK_REGISTRY.yaml"


def completed_history_path(root: Path, naos_root: str) -> Path:
    return resolve_naos_root(root, naos_root) / "completed_history.yaml"


def load_registry(root: Path, naos_root: str) -> tuple[dict[str, Any], Path]:
    path = task_registry_path(root, naos_root)
    if not path.is_file():
        return {"schema": "naos.task_registry.v2", "tasks": []}, path
    return load_yaml_mapping(path), path


def load_completed_history(root: Path, naos_root: str) -> tuple[dict[str, Any], Path]:
    path = completed_history_path(root, naos_root)
    if not path.is_file():
        return {"schema": HISTORY_SCHEMA, "contract_version": 1, "records": []}, path
    data = load_yaml_mapping(path)
    if not isinstance(data.get("records"), list):
        data["records"] = []
    return data, path


def registry_task(registry: dict[str, Any], task_id: str) -> dict[str, Any] | None:
    exact = normalize_task_id(task_id)
    for item in as_list(registry.get("tasks")):
        if not isinstance(item, dict) or not item.get("id"):
            continue
        try:
            candidate = normalize_task_id(item.get("id"))
        except ValueError:
            continue
        if candidate == exact:
            return item
    return None


def completed_history_record(history: dict[str, Any], task_id: str) -> dict[str, Any] | None:
    exact = normalize_task_id(task_id)
    for item in as_list(history.get("records")):
        if not isinstance(item, dict) or not item.get("task_id"):
            continue
        try:
            candidate = normalize_task_id(item.get("task_id"))
        except ValueError:
            continue
        if candidate == exact:
            return item
    return None


def _matching_markdown(directory: Path, task_id: str) -> list[Path]:
    if not directory.is_dir():
        return []
    exact = normalize_task_id(task_id)
    matches: list[Path] = []
    for path in sorted(directory.glob("*.md")):
        if path.name.startswith("_") or "compact" in path.stem.lower():
            continue
        ids = extract_task_ids(path.name)
        if exact in ids:
            matches.append(path)
            continue
        try:
            ids = extract_task_ids(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        if exact in ids:
            matches.append(path)
    return matches


def find_active_task_card(root: Path, naos_root: str, task_id: str) -> Path | None:
    matches = _matching_markdown(resolve_naos_root(root, naos_root) / "active", task_id)
    return matches[0] if matches else None


def find_completed_task_card(
    root: Path,
    naos_root: str,
    task_id: str,
    history_record: dict[str, Any] | None = None,
) -> Path | None:
    if history_record and history_record.get("completed_card_path"):
        declared = resolve_portable_path(history_record["completed_card_path"], root, naos_root)
        if declared is not None and declared.is_file():
            return declared
    matches = _matching_markdown(resolve_naos_root(root, naos_root) / "completed", task_id)
    return matches[0] if matches else None


def resolve_task_record(
    root: Path,
    naos_root: str,
    task_id: str,
    recovery_mode: str = "auto",
) -> dict[str, Any]:
    exact = normalize_task_id(task_id)
    if recovery_mode not in {"auto", "active", "completed"}:
        raise ValueError("recovery_mode must be auto, active, or completed")
    registry, registry_path = load_registry(root, naos_root)
    history, history_path = load_completed_history(root, naos_root)
    entry = registry_task(registry, exact)
    history_entry = completed_history_record(history, exact)
    active_card = find_active_task_card(root, naos_root, exact)
    completed_card = find_completed_task_card(root, naos_root, exact, history_entry)
    states = normalize_task_states(entry or history_entry) if entry or history_entry else {
        "lifecycle_state": "unknown",
        "delivery_state": "not_delivered",
        "verification_state": "unverified",
        "legacy_status": None,
        "compatibility_applied": False,
    }

    selected_kind = None
    selected_path = None
    if recovery_mode in {"auto", "active"} and active_card is not None:
        selected_kind = "active"
        selected_path = active_card
    if selected_path is None and recovery_mode in {"auto", "completed"} and completed_card is not None:
        selected_kind = "completed"
        selected_path = completed_card
    if selected_path is None and recovery_mode in {"auto", "completed"} and history_entry is not None:
        # Durable history remains recoverable even if an archived Markdown card
        # was intentionally pruned or is temporarily unavailable.
        selected_kind = "completed"

    known = bool(entry or history_entry or active_card or completed_card)
    if entry is not None and states.get("compatibility_status") == "unsupported":
        status = "unsupported_legacy_status"
    elif not known:
        status = "task_not_found"
    elif selected_path is None and selected_kind == "completed" and history_entry is not None:
        status = "completed_task"
    elif selected_path is None and recovery_mode == "auto" and entry is not None:
        status = "registry_task"
        selected_kind = "registry"
    elif selected_path is None:
        status = "recovery_mode_mismatch"
    else:
        status = f"{selected_kind}_task"
    review_posture = task_review_posture(
        states,
        completion_record=history_entry,
        resolution_status=status,
    )
    return {
        "status": status,
        "task_id": exact,
        "recovery_mode": recovery_mode,
        "record_kind": selected_kind,
        "selected_card_path": str(selected_path) if selected_path else None,
        "active_card_path": str(active_card) if active_card else None,
        "completed_card_path": str(completed_card) if completed_card else None,
        "registry_path": str(registry_path),
        "history_path": str(history_path),
        "registry_entry": deepcopy(entry),
        "completed_history_record": deepcopy(history_entry),
        **states,
        **review_posture,
    }


def extract_section(text: str, heading: str) -> str:
    pattern = re.compile(
        rf"^##+\s+{re.escape(heading)}\s*$([\s\S]*?)(?=^##+\s+|\Z)",
        re.MULTILINE | re.IGNORECASE,
    )
    match = pattern.search(text)
    return match.group(1).strip() if match else ""


def extract_bullets(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip().startswith(("- ", "- ["))]


def extract_acceptance_criteria(card_text: str, registry_entry: dict[str, Any] | None = None) -> dict[str, Any]:
    """Extract bounded acceptance criteria without inferring arbitrary lists."""

    canonical = extract_bullets(extract_section(card_text, "Acceptance Criteria"))
    if canonical:
        return {
            "criteria": canonical,
            "status": "extracted",
            "source": "canonical_heading",
            "limitations": [],
        }

    labelled = re.search(
        r"^\s*Acceptance criteria:\s*$([\s\S]*?)(?=^\s*(?:#{1,6}\s+|[A-Za-z][A-Za-z0-9 /_-]{2,}:\s*)|\Z)",
        card_text,
        re.MULTILINE | re.IGNORECASE,
    )
    labelled_criteria = extract_bullets(labelled.group(1)) if labelled else []
    if labelled_criteria:
        return {
            "criteria": labelled_criteria,
            "status": "extracted",
            "source": "labelled_unheaded_block",
            "limitations": ["Compatibility extraction used an explicitly labelled unheaded block."],
        }

    structured = None
    structured_source = None
    if isinstance(registry_entry, dict):
        structured = registry_entry.get("acceptance_criteria")
        if structured not in (None, ""):
            structured_source = "structured_task_registry"
    if structured is None and card_text.startswith("---"):
        try:
            _, frontmatter, _ = card_text.split("---", 2)
            card_metadata = yaml.safe_load(frontmatter) or {}
        except Exception:
            card_metadata = {}
        if isinstance(card_metadata, dict) and card_metadata.get("acceptance_criteria") not in (None, ""):
            structured = card_metadata.get("acceptance_criteria")
            structured_source = "structured_card_frontmatter"
    structured_criteria = string_list(structured)
    if structured_criteria:
        return {
            "criteria": structured_criteria,
            "status": "extracted",
            "source": structured_source,
            "limitations": [],
        }

    return {
        "criteria": [],
        "status": "unstructured_or_missing",
        "source": None,
        "limitations": [
            "No canonical heading, explicitly labelled block, or structured acceptance-criteria field was found.",
            "Arbitrary checklist items were not inferred as acceptance criteria.",
        ],
    }


def _reference_sets(card_text: str) -> dict[str, list[str]]:
    paths = dedupe(PATH_REF_PATTERN.findall(card_text))
    spec_refs = dedupe(SPEC_REF_PATTERN.findall(card_text))
    return {
        "spec_refs": spec_refs,
        "implementation_refs": [path for path in paths if path.startswith(("src/", "app/", "lib/", "scripts/"))],
        "test_refs": [path for path in paths if path.startswith(("tests/", "test/")) or "/test" in path],
        "evidence_refs": [path for path in paths if "evidence" in path.lower() or "report" in path.lower()],
        "decision_refs": [path for path in paths if "decision" in path.lower() or "adr-" in path.lower()],
    }


def _reference_parts(reference: str) -> tuple[str, str | None]:
    file_part, separator, fragment = str(reference or "").strip().partition("#")
    return file_part, fragment if separator else None


def _portable_reference_text(path_ref: dict[str, str] | None, fragment: str | None) -> str | None:
    if not path_ref:
        return None
    prefix = "" if path_ref["base"] == "project_root" else f"{path_ref['base']}:"
    suffix = f"#{fragment}" if fragment else ""
    return f"{prefix}{path_ref['path']}{suffix}"


def _receipt_path_identity(receipt: dict[str, Any]) -> str | None:
    resolved = receipt.get("resolved_path")
    if not isinstance(resolved, dict) or not resolved.get("base") or not resolved.get("path"):
        return None
    return f"{resolved['base']}:{resolved['path']}"


def inspect_completion_reference(
    reference: str,
    *,
    root: Path,
    naos_root: str,
) -> tuple[dict[str, Any], Path | None]:
    """Validate one file reference against project/sidecar roots."""

    original = str(reference or "").strip()
    file_part, fragment = _reference_parts(original)
    raw_path = Path(file_part) if file_part else Path()
    traversal = ".." in raw_path.parts
    project_root = root.resolve(strict=False)
    sidecar_root = resolve_naos_root(root, naos_root)
    candidates: list[Path] = []
    if file_part:
        if raw_path.is_absolute():
            candidates.append(raw_path)
        else:
            candidates.extend([project_root / raw_path, sidecar_root / raw_path])
            if raw_path.parts and raw_path.parts[0] in {"naos", sidecar_root.name} and len(raw_path.parts) > 1:
                candidates.append(sidecar_root.joinpath(*raw_path.parts[1:]))

    selected: Path | None = None
    selected_base: str | None = None
    selected_allowed = False
    selected_exists = False
    for candidate in candidates:
        resolved = candidate.resolve(strict=False)
        base = (
            "naos_root"
            if _path_within(resolved, sidecar_root)
            else "project_root"
            if _path_within(resolved, project_root)
            else None
        )
        allowed = base is not None and not traversal
        exists = resolved.is_file()
        if selected is None or (allowed and exists and not (selected_allowed and selected_exists)):
            selected = resolved
            selected_base = base
            selected_allowed = allowed
            selected_exists = exists
        if allowed and exists:
            break

    portable = portable_path(selected, root, naos_root) if selected is not None and selected_allowed else None
    failures: list[str] = []
    if not original:
        failures.append("empty_reference")
    if traversal:
        failures.append("path_traversal_forbidden")
    if not selected_allowed:
        failures.append("outside_allowed_roots")
    if not selected_exists:
        failures.append("regular_file_not_found")
    receipt = {
        "original_reference": original,
        "portable_reference": _portable_reference_text(portable, fragment),
        "resolved_path": portable,
        "fragment": fragment,
        "exists": selected_exists,
        "regular_file": selected_exists,
        "allowed_root": selected_allowed,
        "path_base": selected_base,
        "path_traversal": traversal,
        "failures": failures,
    }
    return receipt, selected if selected_allowed else None


def _placeholder_value(value: Any) -> bool:
    text = str(value or "").strip()
    lowered = text.lower()
    return (
        not text
        or (text.startswith("[") and text.endswith("]"))
        or lowered in {"tbd", "todo", "unknown", "n/a", "none", "placeholder"}
        or "named human" in lowered
        or "placeholder" in lowered
    )


def _load_reference_mapping(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8")) if path.suffix.lower() == ".json" else yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _portable_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    """Remove absolute originals before persisting a receipt in history."""

    durable = deepcopy(receipt)
    original = str(durable.get("original_reference") or "")
    file_part, _ = _reference_parts(original)
    if file_part and Path(file_part).is_absolute():
        durable["original_reference"] = durable.get("portable_reference") or "absolute_reference_redacted"
    return durable


def portable_history_references(references: list[str], root: Path, naos_root: str) -> list[str]:
    """Normalize durable references without retaining private absolute paths."""

    portable: list[str] = []
    for reference in dedupe(references):
        receipt, _ = inspect_completion_reference(reference, root=root, naos_root=naos_root)
        portable_reference = receipt.get("portable_reference")
        file_part, _ = _reference_parts(reference)
        if portable_reference:
            portable.append(str(portable_reference))
        elif file_part and not Path(file_part).is_absolute() and ".." not in Path(file_part).parts:
            portable.append(reference)
        else:
            portable.append(f"unresolved_reference:{safe_digest_bytes(reference.encode('utf-8'))}")
    return dedupe(portable)


def validate_completion_verification(
    *,
    root: Path,
    naos_root: str,
    task_id: str,
    requested_state: str,
    test_refs: list[str],
    evidence_refs: list[str],
    decision_refs: list[str],
) -> dict[str, Any]:
    """Establish deterministic structural prerequisites before any mutation."""

    test_pairs = [inspect_completion_reference(ref, root=root, naos_root=naos_root) for ref in dedupe(test_refs)]
    evidence_pairs = [inspect_completion_reference(ref, root=root, naos_root=naos_root) for ref in dedupe(evidence_refs)]
    decision_pairs = [inspect_completion_reference(ref, root=root, naos_root=naos_root) for ref in dedupe(decision_refs)]
    failures: list[str] = []
    if not test_pairs:
        failures.append("missing_test_references")
    if not evidence_pairs:
        failures.append("missing_evidence_references")
    if not decision_pairs:
        failures.append("missing_decision_references")
    for kind, pairs in (("test", test_pairs), ("evidence", evidence_pairs), ("decision", decision_pairs)):
        for index, (receipt, _) in enumerate(pairs):
            failures.extend(f"{kind}_reference_{index}:{failure}" for failure in receipt["failures"])

    schema_path = kit_root() / "schemas" / "naos" / "human_decision_record.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    supplied_evidence = {
        str(_receipt_path_identity(receipt))
        for receipt, _ in evidence_pairs
        if _receipt_path_identity(receipt) and not receipt.get("failures")
    }
    decision_receipts: list[dict[str, Any]] = []
    qualifying_decisions = 0
    for index, (reference_receipt, path) in enumerate(decision_pairs):
        record = _load_reference_mapping(path)
        schema_errors = (
            sorted(error.message for error in validator.iter_errors(record))
            if isinstance(record, dict)
            else ["Decision reference is not a readable mapping."]
        )
        schema_valid = not schema_errors
        record_evidence: set[str] = set()
        if isinstance(record, dict):
            for evidence_ref in string_list(record.get("evidence_refs")):
                evidence_receipt, _ = inspect_completion_reference(evidence_ref, root=root, naos_root=naos_root)
                if _receipt_path_identity(evidence_receipt) and not evidence_receipt.get("failures"):
                    record_evidence.add(str(_receipt_path_identity(evidence_receipt)))
        exact_task_subject = bool(record) and task_id in [str(item).strip() for item in as_list(record.get("subject_refs"))]
        decision_type = str((record or {}).get("decision_type") or "")
        outcome = str((record or {}).get("outcome") or "")
        decided_by_valid = not _placeholder_value((record or {}).get("decided_by"))
        required_authority_fields = all(
            str((record or {}).get(field) or "").strip()
            for field in ("decided_at", "rationale", "authority_scope")
        )
        evidence_linked = bool(supplied_evidence.intersection(record_evidence))
        structurally_attributable = bool(
            schema_valid and exact_task_subject and decided_by_valid and required_authority_fields
        )
        qualifies = bool(
            structurally_attributable
            and decision_type == "task_delivery"
            and outcome == "approved"
            and evidence_linked
        )
        qualifying_decisions += int(qualifies)
        authority_failures: list[str] = []
        if not schema_valid:
            authority_failures.append("schema_invalid")
        if decision_type != "task_delivery":
            authority_failures.append("decision_type_not_task_delivery")
        if outcome != "approved":
            authority_failures.append("outcome_not_approved")
        if not exact_task_subject:
            authority_failures.append("exact_task_subject_missing")
        if not decided_by_valid:
            authority_failures.append("decided_by_missing_or_placeholder")
        if not required_authority_fields:
            authority_failures.append("decision_authority_fields_missing")
        if not evidence_linked:
            authority_failures.append("completion_evidence_not_linked")
        failures.extend(f"decision_reference_{index}:{failure}" for failure in authority_failures)
        decision_receipts.append(
            {
                **reference_receipt,
                "schema_valid": schema_valid,
                "schema_errors": schema_errors,
                "decision_type": decision_type or None,
                "outcome": outcome or None,
                "exact_task_subject": exact_task_subject,
                "decided_by_non_placeholder": decided_by_valid,
                "authority_fields_present": required_authority_fields,
                "evidence_linked": evidence_linked,
                "structurally_attributable": structurally_attributable,
                "qualifies_for_verified_delivery": qualifies,
                "authority_failures": authority_failures,
            }
        )
    if qualifying_decisions == 0:
        failures.append("no_qualifying_task_delivery_decision")

    prerequisites_met = requested_state == "verified" and not failures
    return {
        "requested_state": requested_state,
        "effective_state": "verified" if prerequisites_met else "unverified",
        "prerequisites_met": prerequisites_met,
        "test_references": [receipt for receipt, _ in test_pairs],
        "evidence_references": [receipt for receipt, _ in evidence_pairs],
        "decision_references": decision_receipts,
        "failures": failures,
        "limitations": [
            "Validation establishes file existence, allowed-root containment, schema conformance, and structural attribution only.",
            "It does not prove genuine human review, semantic test sufficiency, evidence admission, merge approval, or release approval.",
        ],
    }


def _write_yaml_temp(path: Path, data: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.naos-tmp")
    temp.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return temp


def _restore_file(path: Path, original: bytes | None) -> None:
    """Restore one transaction file to its exact pre-transition bytes."""

    if original is None:
        if path.exists():
            path.unlink()
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.naos-rollback")
    temp.write_bytes(original)
    os.replace(temp, path)


def complete_task(
    *,
    root: Path,
    naos_root: str,
    task_id: str,
    profile: str,
    completion_provenance: str,
    completed_by: str | None,
    verification_state: str,
    implementation_refs: list[str],
    test_refs: list[str],
    evidence_refs: list[str],
    decision_refs: list[str],
    unresolved_risks: list[str],
    dry_run: bool,
) -> dict[str, Any]:
    exact = normalize_task_id(task_id)
    if verification_state not in VERIFICATION_STATES:
        raise ValueError(f"Unsupported verification state: {verification_state}")
    resolution = resolve_task_record(root, naos_root, exact, "active")
    if resolution["status"] == "task_not_found":
        return _error_report(profile, exact, "task_not_found", "Task is not present in the registry, active cards, or completed history.")
    if resolution["status"] == "unsupported_legacy_status":
        return _error_report(
            profile,
            exact,
            "unsupported_legacy_status",
            f"Task status {resolution.get('legacy_status')!r} is not in the lifecycle compatibility contract and must be reconciled explicitly.",
            action="complete",
        )
    if resolution["record_kind"] != "active" or not resolution.get("active_card_path"):
        return _error_report(profile, exact, "active_task_not_found", "Native completion requires one exact active task card.")
    registry, registry_path = load_registry(root, naos_root)
    entry = registry_task(registry, exact)
    if entry is None:
        return _error_report(profile, exact, "task_not_found", "The exact task id is not present in TASK_REGISTRY.yaml.")
    prior_states = normalize_task_states(entry)
    if prior_states["lifecycle_state"] not in {"active", "implementation_complete"}:
        return _error_report(
            profile,
            exact,
            "invalid_transition",
            "Native completion requires lifecycle_state active or implementation_complete.",
            action="complete",
        )
    history, history_path = load_completed_history(root, naos_root)
    if completed_history_record(history, exact):
        return _error_report(profile, exact, "already_completed", "Completed history already contains the exact task id.")

    active_path = Path(str(resolution["active_card_path"]))
    completed_dir = resolve_naos_root(root, naos_root) / "completed"
    completed_path = completed_dir / active_path.name
    if completed_path.exists():
        return _error_report(profile, exact, "completed_card_collision", f"Completed card already exists: {completed_path}")

    card_bytes = active_path.read_bytes()
    registry_original = registry_path.read_bytes() if registry_path.is_file() else None
    history_original = history_path.read_bytes() if history_path.is_file() else None
    card_text = card_bytes.decode("utf-8", errors="replace")
    refs = _reference_sets(card_text)
    requirement = entry.get("requirement")
    spec_refs = refs["spec_refs"] + ([f"specs/03-requirements.md#{str(requirement).lower()}"] if requirement else [])
    completed_at = utc_now_text()
    if verification_state == "verified":
        completion_verification = validate_completion_verification(
            root=root,
            naos_root=naos_root,
            task_id=exact,
            requested_state=verification_state,
            test_refs=test_refs,
            evidence_refs=evidence_refs,
            decision_refs=decision_refs,
        )
        if not completion_verification["prerequisites_met"]:
            return _verification_failure_report(
                profile=profile,
                task_id=exact,
                prior_states=prior_states,
                completion_verification=completion_verification,
            )
    else:
        completion_verification = {
            "requested_state": verification_state,
            "effective_state": verification_state,
            "prerequisites_met": False,
            "test_references": [
                inspect_completion_reference(ref, root=root, naos_root=naos_root)[0]
                for ref in dedupe(test_refs)
            ],
            "evidence_references": [
                inspect_completion_reference(ref, root=root, naos_root=naos_root)[0]
                for ref in dedupe(evidence_refs)
            ],
            "decision_references": [
                inspect_completion_reference(ref, root=root, naos_root=naos_root)[0]
                for ref in dedupe(decision_refs)
            ],
            "failures": [],
            "limitations": [
                "Verified-delivery authority prerequisites were not evaluated because verified was not requested.",
                "The archived task remains not delivered and requires human review.",
            ],
        }
    verified_delivery = bool(completion_verification["prerequisites_met"])
    effective_verification_state = str(completion_verification["effective_state"])
    acceptance = extract_acceptance_criteria(card_text, entry)
    if verified_delivery:
        recorded_test_refs = [
            str(item["portable_reference"])
            for item in completion_verification["test_references"]
            if item.get("portable_reference")
        ]
        recorded_evidence_refs = [
            str(item["portable_reference"])
            for item in completion_verification["evidence_references"]
            if item.get("portable_reference")
        ]
        recorded_decision_refs = [
            str(item["portable_reference"])
            for item in completion_verification["decision_references"]
            if item.get("portable_reference")
        ]
    else:
        recorded_test_refs = portable_history_references(refs["test_refs"] + test_refs, root, naos_root)
        recorded_evidence_refs = portable_history_references(refs["evidence_refs"] + evidence_refs, root, naos_root)
        recorded_decision_refs = portable_history_references(refs["decision_refs"] + decision_refs, root, naos_root)
    completed_path_reference = portable_path(completed_path, root, naos_root)
    if completed_path_reference is None:
        return _error_report(
            profile,
            exact,
            "invalid_task_lifecycle",
            "Completed card path is outside the project and configured NAOS roots.",
            action="complete",
        )
    record = {
        "task_id": exact,
        "revision": 1,
        "title": entry.get("title"),
        "lifecycle_state": "completed",
        "delivery_state": "delivered" if verified_delivery else "not_delivered",
        "verification_state": effective_verification_state,
        "requested_verification_state": verification_state,
        "effective_verification_state": effective_verification_state,
        "effective_delivery_state": "delivered" if verified_delivery else "not_delivered",
        "verification_prerequisites_met": verified_delivery,
        "prior_status": entry.get("status"),
        "prior_states": prior_states,
        "acceptance_criteria": acceptance["criteria"],
        "acceptance_criteria_extraction_status": acceptance["status"],
        "acceptance_criteria_extraction_source": acceptance["source"],
        "acceptance_criteria_extraction_limitations": acceptance["limitations"],
        "requirement_spec_links": dedupe(spec_refs),
        "implementation_references": portable_history_references(
            refs["implementation_refs"] + implementation_refs,
            root,
            naos_root,
        ),
        "test_references": recorded_test_refs,
        "evidence_references": recorded_evidence_refs,
        "decision_references": recorded_decision_refs,
        "evidence_posture": "candidate_only",
        "decision_posture": (
            "structurally_attributable_task_delivery_decision"
            if verified_delivery
            else "pending_attributable_human_decision"
        ),
        "completion_verification": {
            key: [_portable_receipt(item) for item in value]
            if key in {"test_references", "evidence_references", "decision_references"}
            else deepcopy(value)
            for key, value in completion_verification.items()
        },
        "unresolved_risks": dedupe(unresolved_risks + extract_bullets(extract_section(card_text, "Known Risks / Gotchas"))),
        "completion_provenance": {
            "source": "native_task_complete",
            "description": completion_provenance,
            "completed_by": completed_by,
            "profile": profile,
            "completed_at": completed_at,
        },
        "active_record_digest": {"algorithm": "sha256", "value": safe_digest_bytes(card_bytes)},
        "completed_card_path": completed_path_reference,
        "superseded_by": None,
        "cancelled_reason": None,
        "deferred_reason": None,
        "absorbed_into": None,
    }
    updated_entry = deepcopy(entry)
    updated_entry.update(
        {
            "status": "completed",
            "lifecycle_state": "completed",
            "delivery_state": record["delivery_state"],
            "verification_state": effective_verification_state,
            "completed_at": completed_at,
            "completed_history_record": f"{_portable_reference_text(portable_path(history_path, root, naos_root), exact)}",
        }
    )
    tasks = as_list(registry.get("tasks"))
    for index, item in enumerate(tasks):
        if item is entry:
            tasks[index] = updated_entry
            break
    registry["schema"] = "naos.task_registry.v2"
    registry["lifecycle_contract_version"] = 1
    registry["tasks"] = tasks
    history["schema"] = HISTORY_SCHEMA
    history["contract_version"] = 1
    history["records"] = [*as_list(history.get("records")), record]

    report = {
        "schema": REPORT_SCHEMA,
        "generated_at": completed_at,
        "profile": profile,
        "status": "completion_preview" if dry_run else "completed",
        "action": "complete",
        "task_id": exact,
        "lifecycle_state": "completed",
        "delivery_state": record["delivery_state"],
        "verification_state": effective_verification_state,
        "requested_verification_state": verification_state,
        "effective_verification_state": effective_verification_state,
        "effective_delivery_state": record["delivery_state"],
        "verification_prerequisites_met": verified_delivery,
        "completion_verification": completion_verification,
        "completed_history_record": record,
        "mutated": not dry_run,
        **task_review_posture(record, completion_record=record),
        "limitations": [
            "Native completion records repository state; it does not approve merge or release.",
            "A completed but unverified task is not counted as delivered.",
        ],
        "not_claimed": [
            "genuine human review",
            "semantic test sufficiency",
            "merge approval",
            "release approval",
            "evidence admission",
            "semantic correctness",
        ],
        "summary": {
            "status": "completion_preview" if dry_run else "completed",
            "task_id": exact,
            "human_review_required": not verified_delivery,
            "total_findings": 1 if not verified_delivery else 0,
            "advisory": 1 if not verified_delivery else 0,
            "warning": 0,
            "required": 0,
            "blocking": 0,
        },
    }
    if dry_run:
        return report

    completed_dir.mkdir(parents=True, exist_ok=True)
    completed_temp = completed_path.with_name(f".{completed_path.name}.naos-tmp")
    completed_temp.write_bytes(card_bytes)
    registry_temp = _write_yaml_temp(registry_path, registry)
    history_temp = _write_yaml_temp(history_path, history)
    try:
        os.replace(completed_temp, completed_path)
        os.replace(registry_temp, registry_path)
        os.replace(history_temp, history_path)
        active_path.unlink()
    except Exception:
        for temp in (completed_temp, registry_temp, history_temp):
            if temp.exists():
                temp.unlink()
        _restore_file(registry_path, registry_original)
        _restore_file(history_path, history_original)
        _restore_file(active_path, card_bytes)
        if completed_path.exists():
            completed_path.unlink()
        raise
    return report


def _error_report(
    profile: str,
    task_id: str | None,
    status: str,
    message: str,
    *,
    action: str = "inspect",
) -> dict[str, Any]:
    report = {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": status,
        "action": action,
        "task_id": task_id,
        "mutated": False,
        "human_review_required": True,
        "review_reasons": [status],
        "review_posture_source": REVIEW_POSTURE_SOURCE,
        "findings": [{"id": f"task_lifecycle.{status}", "status": status, "severity": "required", "message": message}],
        "limitations": ["Task lifecycle reports do not approve merge, release, evidence admission, or exceptions."],
        "not_claimed": ["merge approval", "release approval", "evidence admission", "semantic correctness"],
        "summary": {
            "status": status,
            "task_id": task_id,
            "human_review_required": True,
            "total_findings": 1,
            "advisory": 0,
            "warning": 0,
            "required": 1,
            "blocking": 0,
        },
    }
    if status == "unsupported_legacy_status":
        report.update(
            {
                "lifecycle_state": "unknown",
                "delivery_state": "not_delivered",
                "verification_state": "unverified",
            }
        )
    return report


def _verification_failure_report(
    *,
    profile: str,
    task_id: str,
    prior_states: dict[str, Any],
    completion_verification: dict[str, Any],
) -> dict[str, Any]:
    failures = list(completion_verification.get("failures") or [])
    return {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": "verification_prerequisites_failed",
        "action": "complete",
        "task_id": task_id,
        "lifecycle_state": prior_states.get("lifecycle_state"),
        "delivery_state": "not_delivered",
        "verification_state": "unverified",
        "requested_verification_state": "verified",
        "effective_verification_state": "unverified",
        "effective_delivery_state": "not_delivered",
        "verification_prerequisites_met": False,
        "completion_verification": completion_verification,
        "mutated": False,
        "human_review_required": True,
        "review_reasons": ["verification_prerequisites_unmet"],
        "review_posture_source": REVIEW_POSTURE_SOURCE,
        "findings": [
            {
                "id": f"task_lifecycle.verification_prerequisites.{index + 1}",
                "status": "verification_prerequisites_failed",
                "severity": "required",
                "message": failure,
            }
            for index, failure in enumerate(failures)
        ],
        "limitations": list(completion_verification.get("limitations") or []),
        "not_claimed": [
            "genuine human review",
            "semantic test sufficiency",
            "merge approval",
            "release approval",
            "evidence admission",
            "semantic correctness",
        ],
        "summary": {
            "status": "verification_prerequisites_failed",
            "task_id": task_id,
            "human_review_required": True,
            "total_findings": len(failures),
            "advisory": 0,
            "warning": 0,
            "required": len(failures),
            "blocking": 0,
        },
    }


def inspect_task(root: Path, naos_root: str, profile: str, task_id: str, recovery_mode: str) -> dict[str, Any]:
    resolution = resolve_task_record(root, naos_root, task_id, recovery_mode)
    status = resolution["status"]
    review_posture = task_review_posture(
        resolution,
        completion_record=resolution.get("completed_history_record"),
        resolution_status=status,
    )
    findings = []
    if status in {"task_not_found", "recovery_mode_mismatch", "unsupported_legacy_status"}:
        message = (
            f"Legacy status {resolution.get('legacy_status')!r} is unsupported and must be reconciled before completion."
            if status == "unsupported_legacy_status"
            else "The exact task record could not be resolved for the selected recovery mode."
        )
        findings.append(
            {
                "id": f"task_lifecycle.{status}",
                "status": status,
                "severity": "required",
                "message": message,
            }
        )
    return {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": status,
        "action": "inspect",
        "task_id": resolution["task_id"],
        "task_resolution": resolution,
        "lifecycle_state": resolution.get("lifecycle_state"),
        "delivery_state": resolution.get("delivery_state"),
        "verification_state": resolution.get("verification_state"),
        "mutated": False,
        **review_posture,
        "findings": findings,
        "limitations": ["Task lifecycle inspection is bounded repository context, not approval or evidence authority."],
        "not_claimed": ["merge approval", "release approval", "task ownership", "semantic correctness"],
        "summary": {
            "status": status,
            "task_id": resolution["task_id"],
            "human_review_required": review_posture["human_review_required"],
            "total_findings": len(findings),
            "advisory": 0,
            "warning": 0,
            "required": len(findings),
            "blocking": 0,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect or complete one exact NAOS task lifecycle record.")
    parser.add_argument("--action", choices=["inspect", "complete"], default=None)
    parser.add_argument("--task", required=True, help="Exact task registry id, e.g. T-001 or LKB-T-001.")
    parser.add_argument("--recovery-mode", choices=["auto", "active", "completed"], default="auto")
    parser.add_argument("--profile", help="Profile name: quickstart, lite, standard, assured.")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--contract")
    parser.add_argument("--output")
    parser.add_argument("--completion-provenance", default="Explicit native task-complete invocation.")
    parser.add_argument("--completed-by")
    parser.add_argument("--verification-state", choices=sorted(VERIFICATION_STATES), default="unverified")
    parser.add_argument("--implementation-ref", action="append", default=[])
    parser.add_argument("--test-ref", action="append", default=[])
    parser.add_argument("--evidence-ref", action="append", default=[])
    parser.add_argument("--decision-ref", action="append", default=[])
    parser.add_argument("--unresolved-risk", action="append", default=[])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    command_name = sys.argv[0].split()[-1].replace("_", "-")
    action = args.action or ("complete" if command_name.endswith("task-complete") else "inspect")
    try:
        exact = normalize_task_id(args.task)
        contract_path, contract_source = resolve_contract_path(root, naos_root, args.contract)
        contract = load_yaml_mapping(contract_path)
        if contract.get("schema") != CONTRACT_SCHEMA:
            raise ValueError(f"Unsupported task lifecycle contract: {contract.get('schema')!r}")
        if action == "complete":
            report = complete_task(
                root=root,
                naos_root=naos_root,
                task_id=exact,
                profile=profile,
                completion_provenance=args.completion_provenance,
                completed_by=args.completed_by,
                verification_state=args.verification_state,
                implementation_refs=args.implementation_ref,
                test_refs=args.test_ref,
                evidence_refs=args.evidence_ref,
                decision_refs=args.decision_ref,
                unresolved_risks=args.unresolved_risk,
                dry_run=args.dry_run,
            )
        else:
            report = inspect_task(root, naos_root, profile, exact, args.recovery_mode)
        report["contract"] = {"path": str(contract_path), "source": contract_source, "schema": contract.get("schema")}
    except Exception as exc:
        report = _error_report(profile, str(args.task or "").strip().upper() or None, "invalid_task_lifecycle", str(exc))

    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "task_lifecycle_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"NAOS task lifecycle ({profile}): {report['status']}")
        print(f"task: {report.get('task_id')}")
        print(f"report: {output}")
    if report.get("status") in {
        "task_not_found",
        "recovery_mode_mismatch",
        "unsupported_legacy_status",
        "active_task_not_found",
        "already_completed",
        "completed_card_collision",
        "invalid_transition",
        "invalid_task_lifecycle",
        "verification_prerequisites_failed",
    }:
        return 2
    if report.get("human_review_required"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
