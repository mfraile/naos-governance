#!/usr/bin/env python3
"""
naos add — Progressive Enhancement CLI for NAOS Governance Kit
Rationale:
    Allows users to add instructions, agents, specs, and skills AFTER the
    initial `naos init`. Makes NAOS a living toolkit rather than a one-shot
    scaffolder. Uses the same template pipeline as naos_init.py.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import textwrap
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from string import Template
from typing import Any, Callable, Iterator, Literal

import yaml
from jsonschema import Draft202012Validator

try:
    from .scripts.validators.validate_governed_debug_escalation import (
        load_agent_frontmatter,
        tool_scope_findings,
    )
    from .upgrade_contract.canonical import (
        CanonicalizationUnavailable,
        canonical_sha256,
    )
    from .upgrade_contract.planner import (
        build_content_aware_plan,
        build_create_only_plan,
        regular_file_observation,
        require_supported_source_metadata,
        revalidate_create_only_plan,
    )
    from .upgrade_contract.provenance import (
        MANAGED_CONTENT_BASES_RELATIVE,
        MANAGED_CONTENT_LOCK_RELATIVE,
        MANAGED_CONTENT_MANIFEST_RELATIVE,
        MANAGED_CONTENT_RECEIPTS_RELATIVE,
        MANAGED_CONTENT_TRANSACTIONS_RELATIVE,
        ProvenanceError,
        commit_managed_content_enrollment,
        managed_content_creator_identity,
        inspect_managed_content_manifest,
        inspect_managed_content_scope,
    )
    from .upgrade_contract.security import (
        managed_creation_identity,
        metadata_preservation_matches,
        source_metadata_contract,
    )
    from .upgrade_contract.source_origins import SourceOrigins
    from .upgrade_contract.transaction import (
        TransactionPrimitiveError,
        apply_create_only_plan,
        current_managed_content_paths,
        recorded_managed_content_paths,
        recover_create_only_transactions,
    )
except ImportError:  # Direct checkout execution: python naos_add.py ...
    _KIT_IMPORT_ROOT = Path(__file__).resolve().parent
    if str(_KIT_IMPORT_ROOT) not in sys.path:
        sys.path.insert(0, str(_KIT_IMPORT_ROOT))
    from scripts.validators.validate_governed_debug_escalation import (
        load_agent_frontmatter,
        tool_scope_findings,
    )
    from upgrade_contract.canonical import (  # type: ignore[no-redef]
        CanonicalizationUnavailable,
        canonical_sha256,
    )
    from upgrade_contract.planner import (  # type: ignore[no-redef]
        build_content_aware_plan,
        build_create_only_plan,
        regular_file_observation,
        require_supported_source_metadata,
        revalidate_create_only_plan,
    )
    from upgrade_contract.provenance import (  # type: ignore[no-redef]
        MANAGED_CONTENT_BASES_RELATIVE,
        MANAGED_CONTENT_LOCK_RELATIVE,
        MANAGED_CONTENT_MANIFEST_RELATIVE,
        MANAGED_CONTENT_RECEIPTS_RELATIVE,
        MANAGED_CONTENT_TRANSACTIONS_RELATIVE,
        ProvenanceError,
        commit_managed_content_enrollment,
        managed_content_creator_identity,
        inspect_managed_content_manifest,
        inspect_managed_content_scope,
    )
    from upgrade_contract.security import (  # type: ignore[no-redef]
        managed_creation_identity,
        metadata_preservation_matches,
        source_metadata_contract,
    )
    from upgrade_contract.source_origins import SourceOrigins  # type: ignore[no-redef]
    from upgrade_contract.transaction import (  # type: ignore[no-redef]
        TransactionPrimitiveError,
        apply_create_only_plan,
        current_managed_content_paths,
        recorded_managed_content_paths,
        recover_create_only_transactions,
    )

# ─── PATHS ────────────────────────────────────────────────────────────────────

KIT_DIR = Path(__file__).parent
TEMPLATES_DIR = KIT_DIR / "templates"

# Mapping: subcommand name → (template subdir, destination in project, file glob)
_CATALOG: dict[str, dict[str, Any]] = {
    "instruction": {
        "src_dir": TEMPLATES_DIR / "instructions",
        "dest_dir": ".github/instructions",
        "suffix": ".instructions.md",
        # instructions list: key is user-facing name
    },
    "agent": {
        "src_dir": TEMPLATES_DIR / "agents",
        "dest_dir": ".github/agents",
        "suffix": ".agent.md",
    },
    "spec": {
        "src_dir": TEMPLATES_DIR / "spec-kit" / "specs",
        "dest_dir": "specs",
        "suffix": ".md",
    },
    "skill": {
        "src_dir": TEMPLATES_DIR / "skills",
        "dest_dir": ".github/skills",
        "suffix": "",  # skills are directories
    },
}

SETUP_MODULE_KIND = "setup-module"
PROFILES = {"quickstart", "lite", "standard", "assured"}
MATURITY_RANK = {f"L{level}": level for level in range(6)}
SETUP_CATALOG_TEMPLATE = (
    TEMPLATES_DIR / "structural-seeds" / "naos" / "setup_module_catalog.yaml"
)
SETUP_CATALOG_SCHEMA = KIT_DIR / "schemas" / "naos" / "setup_module_catalog.schema.json"
UPGRADE_SOURCE_POLICY_PATH = KIT_DIR / "configs" / "upgrade_source_policy.yaml"




@dataclass(frozen=True)
class _SetupCatalogSnapshot:
    data: dict[str, Any]
    path: Path
    source: str
    sha256: str
    schema_sha256: str


# ─── HELPERS ──────────────────────────────────────────────────────────────────


def _load_naos_init_context(project_path: Path) -> dict[str, str]:
    """
    Import _make_template_context from naos_init.py using the same pipeline
    as `naos init`.
    Falls back to an empty-signals context if naos_init is unavailable.
    """
    try:
        import importlib.util

        spec_obj = importlib.util.spec_from_file_location(
            "naos_init", KIT_DIR / "naos_init.py"
        )
        if spec_obj and spec_obj.loader:
            mod = importlib.util.module_from_spec(spec_obj)
            spec_obj.loader.exec_module(mod)  # type: ignore[union-attr]
            empty_signals = mod._empty_signals()
            return mod._make_template_context(
                project_path=project_path,
                signals=empty_signals,
                tier="standard",
                archetype=None,
            )
    except Exception:
        pass
    # Fallback: bare context so safe_substitute leaves [ADAPT:] markers intact
    return {}


def _apply_template(content: str, ctx: dict[str, str]) -> str:
    """Apply string.Template safe_substitute — unknown markers are preserved."""
    return Template(content).safe_substitute(ctx)


def _list_available(kind: str, project_path: Path) -> list[str]:
    """
    Return template names not yet deployed in the project.
    For 'spec', compares by spec number prefix (e.g., '03').
    """
    cat = _CATALOG[kind]
    src_dir: Path = cat["src_dir"]
    dest_dir: Path = project_path / cat["dest_dir"]
    suffix: str = cat["suffix"]

    if not src_dir.exists():
        return []

    if kind == "skill":
        available = [p.name for p in src_dir.iterdir() if p.is_dir()]
        deployed = (
            {p.name for p in dest_dir.iterdir() if p.is_dir()}
            if dest_dir.exists()
            else set()
        )
        return [n for n in sorted(available) if n not in deployed]

    if kind == "spec":
        available = [
            p.stem for p in sorted(src_dir.glob("*.md")) if p.name != "README.md"
        ]
        deployed = (
            {p.stem for p in dest_dir.glob("*.md")} if dest_dir.exists() else set()
        )
        return [n for n in available if n not in deployed]

    # instruction / agent
    # File names like "database.instructions.md" → user-facing name "database"
    available = [p.name.split(".")[0] for p in sorted(src_dir.glob(f"*{suffix}"))]
    deployed = (
        {p.name.split(".")[0] for p in dest_dir.glob(f"*{suffix}")}
        if dest_dir.exists()
        else set()
    )
    return [n for n in available if n not in deployed]


def _resolve_source(kind: str, name: str) -> Path | None:
    """
    Resolve the source path for a given kind + name.
    For specs, `name` may be a number ('03'), full stem ('03-requirements'), or
    partial match.
    """
    cat = _CATALOG[kind]
    src_dir: Path = cat["src_dir"]
    suffix: str = cat["suffix"]

    if not src_dir.exists():
        return None

    requested_name = Path(name)
    if (
        requested_name.is_absolute()
        or len(requested_name.parts) != 1
        or requested_name.name != name
        or name in {".", ".."}
    ):
        return None

    if kind == "skill":
        candidate = src_dir / name
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            return None
        return (
            candidate
            if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)
            else None
        )

    if kind == "spec":
        # Match by number prefix or full stem
        for p in src_dir.glob("*.md"):
            if p.name == "README.md":
                continue
            if (
                p.stem == name
                or p.stem.startswith(f"{name}-")
                or p.stem.startswith(f"0{name}-")
            ):
                return p
        return None

    # instruction / agent: look for file whose name starts with "{name}."
    for p in src_dir.iterdir():
        if (
            p.is_file()
            and p.name.split(".")[0] == name
            and p.name.endswith(suffix.lstrip("."))
        ):
            return p
    return None




def _normalize_setup_module_key(value: str) -> str:
    """Normalize module ids and display names for forgiving lookup."""
    return "".join(ch.lower() if ch.isalnum() else "_" for ch in value).strip("_")


def _as_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if value:
        return [str(value)]
    return []


def _profile_module_list(
    module: dict[str, Any], profile: str, key: str
) -> list[str]:
    """Return a setup-module list with an explicit selected-profile override."""

    overrides = module.get("profile_overrides")
    if isinstance(overrides, dict):
        profile_override = overrides.get(profile)
        if isinstance(profile_override, dict) and key in profile_override:
            return _as_string_list(profile_override.get(key))
    return _as_string_list(module.get(key))


_RFC3339_DATETIME = re.compile(
    r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:[Zz]|[+-](?P<offset_hour>\d{2}):(?P<offset_minute>\d{2}))"
)


def _is_valid_rfc3339_datetime(value: Any) -> bool:
    """Validate a timezone-qualified RFC 3339 date-time without optional deps."""
    if not isinstance(value, str):
        return False
    match = _RFC3339_DATETIME.fullmatch(value)
    if match is None:
        return False
    offset_hour = match.group("offset_hour")
    offset_minute = match.group("offset_minute")
    if offset_hour is not None and (
        int(offset_hour) > 23 or int(offset_minute) > 59
    ):
        return False
    normalized = value[:10] + "T" + value[11:]
    if normalized.endswith(("Z", "z")):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def _render_setup_module_text(value: str, profile: str) -> str:
    """Render selected-profile placeholders in user-facing setup-module text."""
    return value.replace("<profile>", profile)


def _stable_regular_bytes(path: Path, *, label: str) -> bytes:
    windows = _windows_cli()
    if windows is not None:
        _observed, payload = windows.source_observation(path, capture_bytes=True)
        assert payload is not None
        return payload
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        live = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_dev, before.st_ino) != (live.st_dev, live.st_ino)
        ):
            raise ValueError(f"{label} is not a stable unique regular file: {path}")
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(descriptor)
        before_state = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            int(getattr(before, "st_flags", 0)),
        )
        after_state = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            int(getattr(after, "st_flags", 0)),
        )
        if before_state != after_state:
            raise ValueError(f"{label} changed while read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load_setup_catalog(project_path: Path, *, canonical: bool = False) -> _SetupCatalogSnapshot:
    """Load adopter-local setup catalog, falling back to the kit seed catalog."""
    project_catalog = project_path / "naos" / "setup_module_catalog.yaml"
    catalog_path = (
        project_catalog if not canonical and project_catalog.is_file() else SETUP_CATALOG_TEMPLATE
    )
    source = "project" if catalog_path == project_catalog else "template"
    if not catalog_path.is_file():
        raise FileNotFoundError(f"Setup module catalog not found: {catalog_path}")
    raw_catalog = _stable_regular_bytes(catalog_path, label="setup module catalog")
    try:
        data = yaml.safe_load(raw_catalog.decode("utf-8")) or {}
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError(
            f"Setup module catalog is not valid UTF-8 YAML: {catalog_path}"
        ) from exc
    if not isinstance(data, dict):
        raise ValueError(f"Setup module catalog must be a mapping: {catalog_path}")
    modules = data.get("modules")
    if not isinstance(modules, list):
        raise ValueError(
            f"Setup module catalog must contain a modules list: {catalog_path}"
        )
    try:
        raw_schema = _stable_regular_bytes(
            SETUP_CATALOG_SCHEMA,
            label="setup module catalog schema",
        )
        schema = json.loads(raw_schema)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"Setup module catalog schema is unavailable or invalid: {SETUP_CATALOG_SCHEMA}"
        ) from exc
    errors = sorted(
        Draft202012Validator(schema).iter_errors(data),
        key=lambda item: [str(part) for part in item.absolute_path],
    )
    if errors:
        details = []
        for error in errors[:20]:
            pointer = "/" + "/".join(str(part) for part in error.absolute_path)
            details.append(f"{pointer or '/'}: {error.message}")
        if len(errors) > 20:
            details.append(f"... and {len(errors) - 20} more schema errors")
        raise ValueError(
            f"Setup module catalog fails its schema: {catalog_path}: "
            + "; ".join(details)
        )
    return _SetupCatalogSnapshot(
        data=data,
        path=catalog_path,
        source=source,
        sha256=hashlib.sha256(raw_catalog).hexdigest(),
        schema_sha256=hashlib.sha256(raw_schema).hexdigest(),
    )


def _setup_modules(project_path: Path) -> list[dict[str, Any]]:
    snapshot = _load_setup_catalog(project_path)
    return [
        module
        for module in snapshot.data.get("modules", [])
        if isinstance(module, dict)
    ]


def _setup_effective_profile(project_path: Path, requested: str | None) -> str:
    """Use native initialization lineage; add is not a profile transition."""
    if _has_v3_control(project_path):
        try:
            from .upgrade_contract.v3_public_profile import _capture
        except ImportError:
            from upgrade_contract.v3_public_profile import _capture
        previous = dict(_capture(project_path)[0].portable.inputs)
    elif _windows_cli() is not None:
        previous = _windows_cli().recorded_profile_inputs(project_path)
    else:
        scope = inspect_managed_content_scope(project_path)
        if scope.status == "owner_enrollment_required":
            previous = None
        else:
            inspection = inspect_managed_content_manifest(project_path)
            if not inspection.apply_eligible or inspection.snapshot is None:
                if scope.status == "valid" and inspection.refusal and "initialization profile lineage is missing" in inspection.refusal:
                    # Existing standalone add compatibility: no init profile to
                    # select. The managed request still validates its provenance
                    # and permits only its existing create-only behavior.
                    previous = None
                else:
                    raise ValueError(inspection.refusal or "Setup requires valid managed profile provenance.")
            else:
                previous = inspection.snapshot.get("previous_inputs")
    recorded = previous.get("profile") if isinstance(previous, dict) else None
    if previous is not None and (not isinstance(recorded, str) or recorded not in PROFILES):
        raise ValueError("Recorded setup profile is missing or unsupported.")
    if recorded is None:
        policy_path = _guard_project_destination(
            project_path, Path("naos/policy/default_policy.yaml"),
            expected_leaf="file", reject_multiply_linked_file=True,
        )
        if policy_path.exists():
            try:
                policy = yaml.safe_load(_stable_regular_bytes(policy_path, label="project profile policy")) or {}
            except yaml.YAMLError as exc:
                raise ValueError(f"Project profile policy cannot be parsed: {exc}") from exc
            if not isinstance(policy, dict):
                raise ValueError("Project profile policy must be a YAML mapping.")
            profiles = policy.get("profiles") if isinstance(policy, dict) else None
            recorded = profiles.get("default") if isinstance(profiles, dict) else None
            if not isinstance(recorded, str) or recorded not in PROFILES:
                raise ValueError("Project policy has no supported default profile.")
    if requested is not None and requested not in PROFILES:
        raise ValueError(f"Unknown profile: {requested!r}")
    if recorded is not None and requested is not None and recorded != requested:
        raise ValueError(f"Setup profile {requested} does not match recorded project profile {recorded}; use an explicit profile transition.")
    # Preserve the pre-initialization planning default only without a profile
    # record. Malformed provenance never falls through to this default.
    return recorded or requested or "lite"


def _required_setup_modules(catalog, module, profile):
    """Bind floors to kit IDs and protected activation assets, including aliases."""
    selected_id = _normalize_setup_module_key(str(module.get("id") or ""))
    def sources(item):
        return {(_safe_relative_path(action.get("source"), field="source").as_posix().casefold(), action.get("copy_mode") == "tree")
                for action in item.get("install_actions", []) if isinstance(action, dict)}
    selected_sources = sources({**module, "install_actions": [action for action in module.get("install_actions", [])
        if isinstance(action, dict) and _action_allowed_for_profile(action, profile)]})
    def overlaps(protected):
        return any(left == right or (left_tree and right.startswith(left + "/"))
                   or (right_tree and left.startswith(right + "/"))
                   for left, left_tree in selected_sources for right, right_tree in sources(protected))
    return [item for item in catalog.get("modules", []) if (
        _normalize_setup_module_key(str(item.get("id") or "")) == selected_id
        or (isinstance(item.get("activation_gate"), dict) and overlaps(item))
    )]


def _setup_required_gate_failures(module, canonical_modules, project_path, profile):
    failures = []
    # Evaluate separately rather than merging: a local gate may add restrictions
    # but cannot delete a required check, redirect its inputs, or lower a floor.
    for candidate in [*canonical_modules, module]:
        if candidate is not None:
            failures.extend(_setup_activation_gate_failures(candidate, project_path, profile, force=False))
    return list(dict.fromkeys(failures))


def _resolve_setup_module(catalog: dict[str, Any], name: str) -> dict[str, Any] | None:
    normalized = _normalize_setup_module_key(name)
    for module in catalog.get("modules", []):
        if not isinstance(module, dict):
            continue
        module_id = str(module.get("id") or "")
        module_name = str(module.get("name") or "")
        if normalized in {
            _normalize_setup_module_key(module_id),
            _normalize_setup_module_key(module_name),
        }:
            return module
    return None


def _setup_source_authority_inventory(
    actions: list[dict[str, Any]],
    *,
    profile: str,
    project_path: Path,
) -> list[dict[str, Any]]:
    """Freeze every selected setup source, including complete tree membership."""

    inventory: list[dict[str, Any]] = []
    for action_index, action in enumerate(actions):
        if not _action_allowed_for_profile(action, profile):
            continue
        action_type = str(action.get("type") or "")
        copy_mode = str(action.get("copy_mode") or "file")
        source = _kit_source_path(action)
        destination = _project_dest_path(project_path, action)
        relative_destination = destination.relative_to(project_path)
        if action_type in {"copy_file", "repair_seed"} and copy_mode == "file":
            source_identity, source_metadata = _managed_source_contract(source)
            source_inventory = [
                {
                    "path": relative_destination.as_posix(),
                    "source": source_identity,
                    "source_metadata": source_metadata,
                }
            ]
        elif action_type == "copy_tree" and copy_mode == "tree":
            _validate_copy_tree_destination(relative_destination)
            source_inventory = _managed_request_inventory(
                _flatten_managed_tree_sources(source, relative_destination)
            )
        else:
            raise ValueError(
                f"Unsupported install action: {action_type}/{copy_mode}"
            )
        inventory.append(
            {
                "action_index": action_index,
                "action": action,
                "source": source.relative_to(KIT_DIR.resolve(strict=True)).as_posix(),
                "destination": relative_destination.as_posix(),
                "source_inventory": source_inventory,
            }
        )
    return inventory


def _print_setup_module_explanation(module: dict[str, Any], profile: str) -> None:
    """Print the choice -> rationale -> benefit -> warning -> consequence UX."""
    print(f"\n  Setup module: {module.get('name', module.get('id', 'unknown'))}")
    print(f"  Profile: {profile}")
    print(f"  Choice: {module.get('id', 'unknown')}")
    print(f"  Rationale: {module.get('why_recommended', '')}")
    print(f"  Benefit: {module.get('benefit', '')}")
    print(f"  Warning: {module.get('warning_if_enabled_too_early', '')}")
    print(f"  Consequence if deferred: {module.get('consequence_if_deferred', '')}")
    prerequisites = _profile_module_list(module, profile, "prerequisites")
    evidence_outputs = _profile_module_list(module, profile, "evidence_outputs")
    commands = _profile_module_list(module, profile, "commands")
    if prerequisites:
        print("  Prerequisites:")
        for item in prerequisites:
            print(f"    - {_render_setup_module_text(item, profile)}")
    if evidence_outputs:
        print("  Evidence outputs:")
        for item in evidence_outputs:
            print(f"    - {item}")
    if commands:
        print("  Commands:")
        for item in commands:
            print(f"    - {_render_setup_module_text(item, profile)}")
    print(f"  Human-review boundary: {module.get('human_review_boundary', '')}")
    not_claimed = _as_string_list(module.get("not_claimed"))
    if not_claimed:
        print("  Not claimed:")
        for item in not_claimed:
            print(f"    - {item}")


def _safe_relative_path(value: Any, *, field: str) -> Path:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"Install action is missing {field}.")
    # Catalogue entries travel between hosts. Check both path grammars before
    # touching the filesystem, including Windows rooted and drive-relative
    # paths, which is_absolute() alone deliberately does not reject.
    posix = PurePosixPath(text)
    windows = PureWindowsPath(text)
    if (posix.anchor or windows.anchor or ".." in posix.parts
            or ".." in windows.parts or ":" in text or "\x00" in text):
        raise ValueError(f"Install action {field} must be a safe relative path: {text}")
    return Path(text)


def _normalized_destination_component(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _windows_cli():
    try:
        from . import naos_init as init_module
    except ImportError:
        import naos_init as init_module
    return init_module._windows_cli()


def _has_v3_control(project_root: Path) -> bool:
    try:
        from .upgrade_contract.v3_recovery import has_v3_control
    except ImportError:
        from upgrade_contract.v3_recovery import has_v3_control
    return has_v3_control(project_root)


def _require_legacy_add_target(project_root: Path) -> None:
    """Keep unsupported v3 requests out of the legacy enrollment/writer path."""
    try:
        from .upgrade_contract.v3_recovery import has_v3_control
    except ImportError:
        from upgrade_contract.v3_recovery import has_v3_control
    if has_v3_control(project_root):
        raise ProvenanceError(
            "Portable v3 add/setup requires a supported v3 request plan; "
            "legacy add cannot mutate or re-enroll its control storage"
        )


def _canonical_project_root(project_path: Path) -> Path:
    """Resolve the operator-selected root before guarding descendants."""
    windows = _windows_cli()
    if windows is not None:
        return windows.canonical_target(project_path, must_exist=True)
    canonical_root = project_path.resolve(strict=False)
    try:
        root_stat = canonical_root.lstat()
    except FileNotFoundError:
        return canonical_root
    if not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError("Project root must be a directory.")
    return canonical_root


def _external_temp_root(project_root: Path) -> Path:
    try:
        from . import naos_init as init_module
    except ImportError:
        import naos_init as init_module  # type: ignore[no-redef]
    result = init_module._select_external_temp_root(project_root)
    if result is None:
        raise ValueError(
            "No external temporary source root is available; set TMPDIR outside "
            "the adopter project."
        )
    return result


def _guard_project_destination(
    project_path: Path,
    relative_path: str | Path,
    *,
    expected_leaf: Literal["file", "directory"],
    reject_multiply_linked_file: bool = False,
) -> Path:
    """Reject unsafe destination topology without following project paths."""
    rel = _safe_relative_path(relative_path, field="destination")
    if rel == Path(".") or _normalized_destination_component(rel.parts[0]) == ".git":
        raise ValueError(f"Destination targets a reserved project path: {rel}")

    project_root = _canonical_project_root(project_path)
    windows = _windows_cli()
    if windows is not None:
        windows.guard_destination(project_root, rel.as_posix(), kind=expected_leaf)
        return project_root / rel
    destination = project_root / rel

    current = project_root
    for part in rel.parts[:-1]:
        current /= part
        try:
            current_stat = current.lstat()
        except FileNotFoundError:
            continue
        current_rel = current.relative_to(project_root)
        if stat.S_ISLNK(current_stat.st_mode):
            raise ValueError(
                f"Destination ancestor is a symbolic link: {current_rel}"
            )
        if not stat.S_ISDIR(current_stat.st_mode):
            raise ValueError(
                f"Destination ancestor is not a directory: {current_rel}"
            )

    try:
        leaf_stat = destination.lstat()
    except FileNotFoundError:
        return destination
    if stat.S_ISLNK(leaf_stat.st_mode):
        raise ValueError(f"Destination leaf is a symbolic link: {rel}")
    if expected_leaf == "file" and not stat.S_ISREG(leaf_stat.st_mode):
        raise ValueError(f"Destination leaf is not a regular file: {rel}")
    if (
        expected_leaf == "file"
        and reject_multiply_linked_file
        and leaf_stat.st_nlink != 1
    ):
        raise ValueError(
            f"Destination overwrite leaf has multiple hard links: {rel}"
        )
    if expected_leaf == "directory" and not stat.S_ISDIR(leaf_stat.st_mode):
        raise ValueError(f"Destination leaf is not a directory: {rel}")
    return destination




def _normalized_destination_parts(relative_path: Path) -> tuple[str, ...]:
    return tuple(_normalized_destination_component(part) for part in relative_path.parts)


def _validate_no_overlapping_destinations(relative_paths: list[Path]) -> None:
    normalized = [(_normalized_destination_parts(path), path) for path in relative_paths]
    for index, (left_parts, left_path) in enumerate(normalized):
        for right_parts, right_path in normalized[index + 1 :]:
            common = min(len(left_parts), len(right_parts))
            if left_parts[:common] == right_parts[:common]:
                raise ValueError(
                    "Install actions have duplicate or overlapping destinations: "
                    f"{left_path} and {right_path}"
                )




def _kit_source_path(action: dict[str, Any]) -> Path:
    rel = _safe_relative_path(action.get("source"), field="source")
    if rel.parts and rel.parts[0] == "naos_tools":
        canonical_rel = Path("scripts", *rel.parts[1:])
        adapted_source = KIT_DIR / rel
        canonical_source = KIT_DIR / canonical_rel
        if (
            not adapted_source.exists()
            and not adapted_source.is_symlink()
            and canonical_source.exists()
        ):
            rel = canonical_rel
    current = KIT_DIR.resolve(strict=True)
    for component in rel.parts:
        current = current / component
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(
                f"Install action source contains a symbolic link: {rel}"
            )
    return current


def _project_dest_path(project_path: Path, action: dict[str, Any]) -> Path:
    rel = _safe_relative_path(action.get("destination"), field="destination")
    expected_leaf: Literal["file", "directory"] = (
        "directory" if str(action.get("copy_mode") or "file") == "tree" else "file"
    )
    return _guard_project_destination(
        project_path,
        rel,
        expected_leaf=expected_leaf,
    )


def _scripts_namespace_has_unmanaged_files(
    project_path: Path,
    *,
    selected_file_collisions: set[str] | None = None,
) -> bool:
    selected_file_collisions = selected_file_collisions or set()
    scripts_root = project_path / "scripts"
    if not scripts_root.exists():
        return False
    if scripts_root.is_symlink() or not scripts_root.is_dir():
        return True
    try:
        windows = _windows_cli()
        if _has_v3_control(project_path):
            try:
                from .upgrade_contract.v3_public_profile import current_managed_paths
            except ImportError:
                from upgrade_contract.v3_public_profile import current_managed_paths
            if windows is not None:
                windows.guard_destination(project_path, 'scripts', kind='directory')
            current = current_managed_paths(project_path)
        elif windows is not None:
            windows.guard_destination(project_path, 'scripts', kind='directory')
            current = windows.current_paths(project_path)
        else:
            scope = inspect_managed_content_scope(project_path)
            if (
                scope.status != "valid"
                or not scope.project_id
                or not scope.scope_integrity
                or not scope.source_policy_sha256
            ):
                return True
            runtime = _managed_runtime_arguments(project_path)
            current = current_managed_content_paths(
                project_path,
                project_id=scope.project_id,
                scope_integrity_sha3_512=scope.scope_integrity,
                source_policy_sha256=scope.source_policy_sha256,
                manifest_path=runtime["manifest_path"],
                bases_root=runtime["bases_root"],
                receipts_root=runtime["receipts_root"],
            )
        for path in scripts_root.rglob("*"):
            if path.is_symlink() or (
                path.is_file()
                and path.relative_to(project_path).as_posix() not in current
                and path.relative_to(project_path).as_posix()
                not in selected_file_collisions
            ):
                return True
    except (OSError, ValueError, ProvenanceError, TransactionPrimitiveError):
        return True
    return False


def _validate_copy_tree_destination(rel_dest: Path) -> None:
    reserved_roots = {".", ".git", ".github", "naos", "scripts"}
    if rel_dest == Path(".") or (
        len(rel_dest.parts) == 1
        and _normalized_destination_component(rel_dest.parts[0]) in reserved_roots
    ):
        raise ValueError(
            f"copy_tree destination targets a reserved project directory: {rel_dest}"
        )


def _action_allowed_for_profile(action: dict[str, Any], profile: str) -> bool:
    profiles = _as_string_list(action.get("profiles"))
    return not profiles or profile in profiles


def _load_yaml_mapping(
    path: Path, *, label: str
) -> tuple[dict[str, Any] | None, str | None]:
    """Load a required YAML mapping for a setup-module activation gate."""
    if not path.is_file():
        return None, f"{label} is missing: {path}"
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        return None, f"{label} cannot be read: {exc}"
    if not isinstance(value, dict):
        return None, f"{label} must be a YAML mapping: {path}"
    return value, None


def _load_json_mapping(
    path: Path, *, label: str
) -> tuple[dict[str, Any] | None, str | None]:
    """Load a required JSON mapping for a setup-module activation gate."""
    if not path.is_file():
        return None, f"{label} is missing: {path}"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"{label} cannot be read: {exc}"
    if not isinstance(value, dict):
        return None, f"{label} must be a JSON object: {path}"
    return value, None


def _load_agent_frontmatter_mapping(
    path: Path, *, label: str
) -> tuple[dict[str, Any] | None, str, str | None]:
    """Load a generated agent's YAML frontmatter and body for a gate."""
    if not path.is_file():
        return None, "", f"{label} is missing: {path}"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, "", f"{label} cannot be read: {exc}"
    parts = text.split("---", 2)
    if len(parts) != 3:
        return None, text, f"{label} has no YAML frontmatter: {path}"
    try:
        value = load_agent_frontmatter(parts[1]) or {}
    except yaml.YAMLError as exc:
        return None, parts[2], f"{label} frontmatter cannot be read: {exc}"
    if not isinstance(value, dict):
        return (
            None,
            parts[2],
            f"{label} frontmatter must be a YAML mapping: {path}",
        )
    return value, parts[2], None


def _normalized_agent_body(body: str) -> str:
    """Normalize line endings and trailing whitespace for integrity comparison."""
    return "\n".join(line.rstrip() for line in body.strip().splitlines())


def _module_source_for_destination(
    module: dict[str, Any], destination: Path
) -> Path | None:
    """Resolve the canonical source copied to one setup-module destination."""
    for action in module.get("install_actions", []):
        if not isinstance(action, dict):
            continue
        action_destination = _safe_relative_path(
            action.get("destination"), field="destination"
        )
        if action_destination == destination:
            return _kit_source_path(action)
    return None


def _setup_activation_gate_failures(
    module: dict[str, Any], project_path: Path, profile: str, *, force: bool = False
) -> list[str]:
    """Return fail-closed reasons for an optional setup-module activation."""
    gate = module.get("activation_gate")
    if not isinstance(gate, dict):
        return []

    allowed_profiles = _as_string_list(gate.get("allowed_profiles"))
    if allowed_profiles and profile not in allowed_profiles:
        allowed = ", ".join(allowed_profiles)
        return [
            f"{module.get('id')} is not available for profile {profile}; "
            f"allowed profiles: {allowed}"
        ]

    failures: list[str] = []
    policy_rel = _safe_relative_path(
        gate.get("profile_policy_path") or "naos/policy/default_policy.yaml",
        field="activation_gate.profile_policy_path",
    )
    state_rel = _safe_relative_path(
        gate.get("capability_state_path") or "naos/capability_state.yaml",
        field="activation_gate.capability_state_path",
    )
    config_rel = _safe_relative_path(
        gate.get("config_path"), field="activation_gate.config_path"
    )
    schema_rel = _safe_relative_path(
        gate.get("config_schema_path"), field="activation_gate.config_schema_path"
    )
    policy, policy_error = _load_yaml_mapping(
        project_path / policy_rel, label="project profile policy"
    )
    state, state_error = _load_yaml_mapping(
        project_path / state_rel, label="capability state"
    )
    config, config_error = _load_yaml_mapping(
        project_path / config_rel, label="activation configuration"
    )
    schema, schema_error = _load_json_mapping(
        project_path / schema_rel, label="activation configuration schema"
    )
    if policy_error:
        failures.append(policy_error)
    if state_error:
        failures.append(state_error)
    if config_error:
        failures.append(config_error)
    if schema_error:
        failures.append(schema_error)
    if failures:
        return failures
    assert (
        policy is not None
        and state is not None
        and config is not None
        and schema is not None
    )

    # JSON Schema format checks are annotations unless an optional checker is
    # installed. Validate date-times explicitly below so clean installs and
    # maintainer environments enforce the same activation boundary.
    validator = Draft202012Validator(schema)
    for error in sorted(
        validator.iter_errors(config), key=lambda item: list(item.path)
    ):
        location = ".".join(str(part) for part in error.path) or "<root>"
        failures.append(f"activation configuration {location}: {error.message}")

    profiles = policy.get("profiles")
    declared_profile = profiles.get("default") if isinstance(profiles, dict) else None
    if declared_profile != profile:
        failures.append(
            f"project policy profile is {declared_profile or 'missing'}, not {profile}"
        )

    capability_id = str(gate.get("capability_id") or "").strip()
    state_entries = state.get("capabilities")
    entry = None
    if isinstance(state_entries, list):
        entry = next(
            (
                item
                for item in state_entries
                if isinstance(item, dict)
                and str(item.get("capability_id") or "") == capability_id
            ),
            None,
        )
    if entry is None:
        failures.append(f"capability state has no {capability_id} entry")
    else:
        if entry.get("enabled") is not True:
            failures.append(f"{capability_id} is not explicitly enabled")
        minimum_by_profile = gate.get("minimum_maturity")
        minimum = (
            str(minimum_by_profile.get(profile) or "")
            if isinstance(minimum_by_profile, dict)
            else ""
        )
        current = str(entry.get("current_maturity") or "")
        if minimum not in MATURITY_RANK:
            failures.append(
                f"activation gate has no valid maturity threshold for {profile}"
            )
        elif MATURITY_RANK.get(current, -1) < MATURITY_RANK[minimum]:
            failures.append(
                f"{capability_id} on profile {profile} requires {minimum} or higher; "
                f"current maturity is {current or 'missing'}"
            )
        reviewer = str(entry.get("accountable_reviewer") or "").strip()
        if not reviewer or reviewer == "@unassigned":
            failures.append(
                f"{capability_id} must identify a named accountable reviewer"
            )

    if config.get("enabled") is not True:
        failures.append("activation configuration is not explicitly enabled")
    if config.get("profile") != profile:
        failures.append(
            f"activation configuration profile must be {profile}, got "
            f"{config.get('profile')!r}"
        )

    host = config.get("host")
    required_host = str(gate.get("required_host") or "")
    if not isinstance(host, dict):
        failures.append("activation configuration host must be a mapping")
    else:
        if host.get("id") != required_host:
            failures.append(f"activation host must be {required_host}")
        if (
            gate.get("require_host_acknowledgement") is True
            and host.get("capability_acknowledged") is not True
        ):
            failures.append("host capability acknowledgement is required")
        if gate.get("require_host_contract_review") is True:
            contract_reviewed_at = host.get("contract_reviewed_at")
            if not contract_reviewed_at:
                failures.append("host contract review timestamp is required")
            elif not _is_valid_rfc3339_datetime(contract_reviewed_at):
                failures.append(
                    "host.contract_reviewed_at is not valid as an RFC 3339 date-time"
                )

    transition = config.get("transition")
    expected_transition = gate.get("required_transition")
    if isinstance(expected_transition, dict) and transition != expected_transition:
        failures.append(
            "activation transition does not match the allowed parent and child"
        )

    trigger = config.get("trigger")
    expected_trigger = gate.get("required_trigger")
    if isinstance(expected_trigger, dict) and trigger != expected_trigger:
        failures.append("activation trigger does not match the bounded failure rule")

    limits = config.get("limits")
    expected_limits = gate.get("required_limits")
    if isinstance(expected_limits, dict) and limits != expected_limits:
        failures.append(
            "activation limits do not preserve one dispatch, no child write authority, and no recursion"
        )

    if isinstance(expected_transition, dict) and isinstance(expected_limits, dict):
        child_name = str(expected_transition.get("to") or "").strip()
        try:
            child_rel = _safe_relative_path(
                f".github/agents/{child_name}.agent.md",
                field="activation_gate.required_transition.to",
            )
            if child_rel.parent != Path(".github/agents"):
                raise ValueError(
                    "activation_gate.required_transition.to must be one agent name"
                )
        except ValueError as exc:
            failures.append(str(exc))
        else:
            child, child_body, child_error = _load_agent_frontmatter_mapping(
                project_path / child_rel,
                label="configured debug child",
            )
            if child_error:
                failures.append(child_error)
            else:
                assert child is not None
                failures.extend(message for _rule, message in tool_scope_findings(child, "child"))
                if child.get("name") != child_name:
                    failures.append(
                        f"configured debug child name must be {child_name}"
                    )
                if child.get("disable-model-invocation") is not True:
                    failures.append(
                        "configured debug child must be unavailable for model invocation"
                    )
                canonical_child_path = (
                    TEMPLATES_DIR / "agents" / f"{child_name}.agent.md"
                )
                (
                    _canonical_child,
                    canonical_child_body,
                    canonical_child_error,
                ) = _load_agent_frontmatter_mapping(
                    canonical_child_path,
                    label="canonical debug child",
                )
                if canonical_child_error:
                    failures.append(canonical_child_error)
                elif _normalized_agent_body(child_body) != _normalized_agent_body(
                    canonical_child_body
                ):
                    failures.append(
                        "configured debug child instructions differ from the canonical no-write/no-recursion protocol; repair the child explicitly before activation"
                    )

        parent_name = str(expected_transition.get("from") or "").strip()
        try:
            parent_rel = _safe_relative_path(
                f".github/agents/{parent_name}.agent.md",
                field="activation_gate.required_transition.from",
            )
            if parent_rel.parent != Path(".github/agents"):
                raise ValueError(
                    "activation_gate.required_transition.from must be one agent name"
                )
        except ValueError as exc:
            failures.append(str(exc))
        else:
            parent_path = project_path / parent_rel
            canonical_parent_path = _module_source_for_destination(module, parent_rel)
            if canonical_parent_path is None:
                failures.append(
                    "activation module has no canonical install source for the optional implementation parent"
                )
            else:
                (
                    _canonical_parent,
                    canonical_parent_body,
                    canonical_parent_error,
                ) = _load_agent_frontmatter_mapping(
                    canonical_parent_path,
                    label="canonical optional implementation parent",
                )
                if canonical_parent_error:
                    failures.append(canonical_parent_error)
            if parent_path.exists() and not force:
                parent, parent_body, parent_error = _load_agent_frontmatter_mapping(
                    parent_path,
                    label="existing optional implementation parent",
                )
                if parent_error:
                    failures.append(parent_error)
                else:
                    assert parent is not None
                    failures.extend("existing optional implementation parent: " + message for _rule, message in tool_scope_findings(parent, "parent"))
                    if parent.get("name") != parent_name:
                        failures.append(
                            f"existing optional implementation parent name must be {parent_name}"
                        )
                    if parent.get("agents") != [child_name]:
                        failures.append(
                            "existing optional implementation parent has the wrong child allowlist"
                        )
                    if parent.get("disable-model-invocation") is not True:
                        failures.append(
                            "existing optional implementation parent must be unavailable for model invocation"
                        )
                    if (
                        canonical_parent_path is not None
                        and not canonical_parent_error
                        and _normalized_agent_body(parent_body)
                        != _normalized_agent_body(canonical_parent_body)
                    ):
                        failures.append(
                            "existing optional implementation parent instructions differ from the canonical bounded escalation protocol; reconcile the file manually against the reviewed canonical template before retrying (blanket --force restoration is unavailable)"
                        )

    # This extra role check belongs to the governed-debug transition, not the
    # generic setup activation mechanism used by future unrelated modules.
    if capability_id == "CAP-GOVERNED-DEBUG-ESCALATION" and expected_transition == {
        "from": "naos-implement-with-debug", "to": "naos-debug"
    }:
        default, _default_body, default_error = _load_agent_frontmatter_mapping(
            project_path / ".github/agents/naos-implement.agent.md",
            label="default implementation agent",
        )
        if default_error:
            failures.append(default_error)
        else:
            assert default is not None
            failures.extend(message for _rule, message in tool_scope_findings(default, "default"))

    approval = config.get("human_approval")
    if gate.get("require_human_approval") is True:
        if not isinstance(approval, dict) or approval.get("approved") is not True:
            failures.append("named human approval is required")
        else:
            approved_by = str(approval.get("approved_by") or "").strip()
            if not approved_by or approved_by == "@unassigned":
                failures.append("human approval must identify a named approver")
            approved_at = approval.get("approved_at")
            if not approved_at:
                failures.append("human approval timestamp is required")
            elif not _is_valid_rfc3339_datetime(approved_at):
                failures.append(
                    "human_approval.approved_at is not valid as an RFC 3339 date-time"
                )

    if (
        gate.get("require_manual_fallback") is True
        and config.get("manual_fallback_required") is not True
    ):
        failures.append("manual fallback must remain required")
    return failures




def _managed_source_contract(source: Path) -> tuple[dict[str, Any], dict[str, object]]:
    """Return one stable, supported source identity for request binding."""

    windows = _windows_cli()
    if windows is not None:
        return windows.source_contract(source)
    identity, observed_metadata = regular_file_observation(source)
    metadata = source_metadata_contract(observed_metadata)
    require_supported_source_metadata(source, metadata)
    return (
        {
            "kind": identity.kind,
            "mode": identity.mode,
            "size": identity.size,
            "sha256": identity.sha256,
        },
        metadata,
    )


def _managed_source_matches_live(source: Path, destination: Path) -> bool:
    """Compare requested and live bytes/metadata after provenance qualification."""

    try:
        source_identity, source_metadata = _managed_source_contract(source)
        live_identity, live_observed_metadata = regular_file_observation(destination)
        live_contract = {
            "kind": live_identity.kind,
            "mode": live_identity.mode,
            "size": live_identity.size,
            "sha256": live_identity.sha256,
        }
    except (OSError, ValueError):
        return False
    return source_identity == live_contract and metadata_preservation_matches(
        source_metadata,
        live_observed_metadata,
        creation_identity=managed_creation_identity(),
    )


def _managed_request_inventory(
    sources: list[tuple[Path, Path]],
) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for relative, source in sorted(sources, key=lambda item: item[0].as_posix()):
        source_identity, source_metadata = _managed_source_contract(source)
        inventory.append(
            {
                "path": relative.as_posix(),
                "source": source_identity,
                "source_metadata": source_metadata,
            }
        )
    return inventory


def _managed_runtime_arguments(project_root: Path) -> dict[str, Path]:
    return {
        "transaction_root": project_root / MANAGED_CONTENT_TRANSACTIONS_RELATIVE,
        "lock_path": project_root / MANAGED_CONTENT_LOCK_RELATIVE,
        "manifest_path": project_root / MANAGED_CONTENT_MANIFEST_RELATIVE,
        "bases_root": project_root / MANAGED_CONTENT_BASES_RELATIVE,
        "receipts_root": project_root / MANAGED_CONTENT_RECEIPTS_RELATIVE,
    }


def _partition_managed_sources(
    project_root: Path,
    sources: list[tuple[Path, Path]],
    *,
    provenance_current_paths: set[str],
    provenance_recorded_paths: set[str],
) -> tuple[list[tuple[Path, Path]], list[Path], list[Path]]:
    """Partition a request into absent, provenance-satisfied, and collisions."""

    relative_paths = [relative for relative, _source in sources]
    _validate_no_overlapping_destinations(relative_paths)
    pending: list[tuple[Path, Path]] = []
    satisfied: list[Path] = []
    collisions: list[Path] = []
    for relative, source in sorted(sources, key=lambda item: item[0].as_posix()):
        destination = _guard_project_destination(
            project_root,
            relative,
            expected_leaf="file",
            reject_multiply_linked_file=True,
        )
        try:
            destination.lstat()
        except FileNotFoundError:
            if relative.as_posix() in provenance_recorded_paths:
                collisions.append(relative)
            else:
                pending.append((relative, source))
            continue
        if (
            relative.as_posix() in provenance_current_paths
            and _managed_source_matches_live(source, destination)
        ):
            satisfied.append(relative)
        else:
            collisions.append(relative)
    return pending, satisfied, collisions


def _build_managed_request_transition_plan(
    project_root: Path,
    sources: list[tuple[Path, Path]],
    *,
    operation: str,
    request_inputs: dict[str, Any],
    request_sha256: str,
) -> dict[str, Any]:
    """Classify one add/setup request against the complete managed manifest."""

    _require_legacy_add_target(project_root)
    inspection = inspect_managed_content_manifest(project_root)
    if not inspection.apply_eligible or inspection.snapshot is None:
        raise ProvenanceError(
            inspection.refusal
            or "content-aware add planning requires valid managed-content provenance"
        )
    previous_inputs = inspection.snapshot.get("previous_inputs")
    profile = (
        previous_inputs.get("profile")
        if isinstance(previous_inputs, dict)
        else None
    )
    if not isinstance(profile, str) or not profile:
        raise ProvenanceError(
            "content-aware add planning requires a provenance-bound profile"
        )
    return build_content_aware_plan(
        project_root,
        sources,
        source_policy_path=UPGRADE_SOURCE_POLICY_PATH,
        operation=operation,
        inputs={"profile": profile},
        manifest_snapshot=inspection.snapshot,
        fixed_checks=[
            {
                "check_id": "managed_request_source_authority",
                "status": "passed",
                "evidence_sha256": request_sha256,
            }
        ],
        selected_paths=[relative for relative, _source in sources],
        operation_inputs={
            "schema": "naos.add.operation_inputs.v1",
            "request_sha256": request_sha256,
            "request": request_inputs,
        },
    )


def _publish_managed_request_plan(
    project_root: Path,
    plan_out: Path,
    plan: dict[str, Any],
) -> Path:
    try:
        from . import naos_upgrade as upgrade_module
    except ImportError:
        import naos_upgrade as upgrade_module  # type: ignore[no-redef]
    return upgrade_module.publish_external_content_plan(
        project_root,
        plan_out,
        plan,
    )


def _run_managed_create_only_request(
    project_root: Path,
    sources: list[tuple[Path, Path]],
    *,
    operation: str,
    request_inputs: dict[str, Any],
    dry_run: bool,
    plan_out: Path | None = None,
    preapply_revalidator: Callable[[], None] | None = None,
    applicability=None,
) -> int:
    """Plan/apply one provenance-bound, all-or-nothing create-only request."""

    if not sources:
        print("  [REFUSED] Managed-content request has no regular-file leaves.")
        return 2
    try:
        project_root = _canonical_project_root(project_root)
        if _has_v3_control(project_root):
            try:
                from .upgrade_contract import v3_public_request
                from . import naos_upgrade as upgrade_module
            except ImportError:
                from upgrade_contract import v3_public_request
                import naos_upgrade as upgrade_module
            try:
                if applicability is not None:
                    applicability.select_route("portable_v3")
                return v3_public_request.plan_command(
                    project_root, operation=operation, request_inputs=request_inputs,
                    sources=sources, plan_out=plan_out, cli=upgrade_module,
                    add_module=sys.modules[__name__], preapply_revalidator=preapply_revalidator,
                    **({"applicability": applicability} if applicability is not None else {}))
            except (OSError, RuntimeError, ValueError) as exc:
                raise ValueError('Portable v3 request review refused: ' + str(exc)) from exc
        _require_legacy_add_target(project_root)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"  [REFUSED] Managed-content request failed: {exc}", file=sys.stderr)
        return 2
    windows = _windows_cli()
    if windows is not None:
        try:
            _validate_no_overlapping_destinations([relative for relative, _ in sources])
            return windows.run_add_request(
                project_root, sources, operation=operation,
                request_inputs=request_inputs, dry_run=dry_run, plan_out=plan_out,
                preapply_revalidator=preapply_revalidator,
                **({"applicability": applicability} if applicability is not None else {}),
            )
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"  [REFUSED] Windows managed-content request failed: {exc}", file=sys.stderr)
            return 2
    if applicability is not None:
        applicability.select_route("posix_legacy")
    try:
        inventory = _managed_request_inventory(sources)
        request_sha256 = canonical_sha256(
            {
                "schema": "naos.add.managed_request.v1",
                "operation": operation,
                "inputs": request_inputs,
                "sources": inventory,
            }
        )
        scope = inspect_managed_content_scope(project_root)
        runtime = _managed_runtime_arguments(project_root)
        transition_blocker: str | None = None
        standalone_profile_lineage_missing = False
        if scope.status == "valid":
            if (
                not scope.project_id
                or not scope.scope_integrity
                or not scope.source_policy_sha256
            ):
                raise ProvenanceError(
                    "Managed-content provenance binding is incomplete."
                )
            provenance_current = current_managed_content_paths(
                project_root,
                project_id=scope.project_id,
                scope_integrity_sha3_512=scope.scope_integrity,
                source_policy_sha256=scope.source_policy_sha256,
                manifest_path=runtime["manifest_path"],
                bases_root=runtime["bases_root"],
                receipts_root=runtime["receipts_root"],
            )
            manifest_inspection = inspect_managed_content_manifest(project_root)
            standalone_profile_lineage_missing = bool(
                manifest_inspection.refusal
                and "initialization profile lineage is missing"
                in manifest_inspection.refusal
            )
            provenance_recorded = recorded_managed_content_paths(
                project_root,
                project_id=scope.project_id,
                scope_integrity_sha3_512=scope.scope_integrity,
                source_policy_sha256=scope.source_policy_sha256,
                manifest_path=runtime["manifest_path"],
                bases_root=runtime["bases_root"],
                receipts_root=runtime["receipts_root"],
            )
        else:
            provenance_current = set()
            provenance_recorded = set()

        pending, satisfied, collisions = _partition_managed_sources(
            project_root,
            sources,
            provenance_current_paths=provenance_current,
            provenance_recorded_paths=provenance_recorded,
        )
        satisfied_set = {path.as_posix() for path in satisfied}
        satisfied_sources = [
            (relative, source)
            for relative, source in sources
            if relative.as_posix() in satisfied_set
        ]
        plan_inputs = {
            **request_inputs,
            "request_sha256": request_sha256,
            "requested_paths": [item["path"] for item in inventory],
            "provenance_satisfied_paths": [
                path.as_posix() for path in sorted(satisfied, key=str)
            ],
        }
        create_only_plan = (
            build_create_only_plan(
                project_root,
                pending,
                source_policy_path=UPGRADE_SOURCE_POLICY_PATH,
                operation=operation,
                inputs=plan_inputs,
                precondition_sources=satisfied_sources,
                expected_source_policy_sha256=(
                    scope.source_policy_sha256
                    if scope.status == "valid"
                    else None
                ),
            )
            if pending
            else None
        )
        transition_requested = bool(collisions or plan_out is not None)
        if transition_requested and standalone_profile_lineage_missing:
            transition_blocker = (
                "Create-only provenance is valid, but this project has no "
                "naos-init profile lineage. Replacement planning is unavailable; "
                "existing content was preserved."
            )
        transition_plan = (
            _build_managed_request_transition_plan(
                project_root,
                sources,
                operation=operation,
                request_inputs=request_inputs,
                request_sha256=request_sha256,
            )
            if transition_requested and transition_blocker is None
            else None
        )
    except (
        OSError,
        ValueError,
        CanonicalizationUnavailable,
        ProvenanceError,
        TransactionPrimitiveError,
    ) as exc:
        print(f"  [REFUSED] Managed-content preflight failed: {exc}", file=sys.stderr)
        return 2

    print(f"  Managed-content request SHA-256: {request_sha256}")
    if transition_plan is not None:
        print(
            "  Content-aware plan SHA-256: "
            f"{transition_plan['plan_sha256']}"
        )
        selected = set(transition_plan["selected_paths"])
        for item in transition_plan["paths"]:
            if item["path"] not in selected:
                continue
            prefix = (
                "PLAN"
                if item["mutation"]["eligible"]
                else "MANUAL_ACTION"
            )
            print(f"  [{prefix}] {item['path']}: {item['action']}")
        if plan_out is not None:
            try:
                published = _publish_managed_request_plan(
                    project_root,
                    plan_out,
                    transition_plan,
                )
            except (OSError, RuntimeError, ValueError) as exc:
                print(
                    f"  [REFUSED] External plan publication failed: {exc}",
                    file=sys.stderr,
                )
                return 2
            print(f"  [PLAN_OUT] {published}")
    elif create_only_plan is not None:
        print(
            "  Managed-content plan SHA-256: "
            f"{create_only_plan['plan_sha256']}"
        )
    for relative in satisfied:
        print(f"  [SATISFIED] {relative} (validated provenance and exact content)")

    if scope.status not in {
        "valid",
        "owner_enrollment_required",
        "enrollment_required",
    }:
        reason = scope.refusal or (
            "this project cannot establish valid managed-content provenance"
        )
        print(f"  [PLAN-BLOCKED] {reason}")
        if dry_run and applicability is not None:
            applicability.record("blocked", "scope_blocked", request_sha256=request_sha256)
        return 0 if dry_run else 2
    if transition_blocker is not None:
        print(f"  [PLAN-BLOCKED] {transition_blocker}")
        if dry_run and applicability is not None:
            applicability.record("blocked", "profile_lineage_required", request_sha256=request_sha256)
        return 0 if dry_run else 2
    if collisions:
        assert transition_plan is not None
        if plan_out is None:
            print(
                "  [PLAN-BLOCKED] Existing paths were preserved. Rerun with an "
                "external --plan-out file; only a mutation-ready plan can later "
                "be applied by `naos upgrade --apply-plan ... "
                "--expect-plan-digest ...`."
            )
            if dry_run and applicability is not None:
                applicability.record("blocked", "external_plan_required", execution_route="external_reviewed_plan_apply", request_sha256=request_sha256, plan_status=transition_plan["status"], plan_sha256=transition_plan["plan_sha256"])
            return 0 if dry_run else 2
        if transition_plan["status"] != "ready":
            print(
                "  [PLAN-BLOCKED] The persisted plan contains no eligible safe "
                "replacement; existing content was preserved."
            )
            return 2
        print(
            "  [PLAN_ONLY] Existing content was preserved. Apply only through "
            "the separate digest-bound `naos upgrade --apply-plan` invocation."
        )
        return 0
    if plan_out is not None:
        assert transition_plan is not None
        print(
            "  [PLAN_ONLY] No project content was changed. Apply only through "
            "the separate digest-bound `naos upgrade --apply-plan` invocation."
        )
        return 0 if transition_plan["status"] == "ready" else 2
    if not pending:
        if dry_run and applicability is not None:
            applicability.record("noop", "provenance_current", request_sha256=request_sha256)
        print("  [ALREADY_APPLIED] Every requested path is provenance-current.")
        return 0
    assert create_only_plan is not None
    if create_only_plan.get("status") != "ready_create_only":
        print("  [PLAN-BLOCKED] The create-only plan is not ready.")
        if dry_run and applicability is not None:
            applicability.record("blocked", "create_plan_not_ready", request_sha256=request_sha256)
        return 0 if dry_run else 2
    if dry_run:
        if applicability is not None:
            applicability.record("ready", "create_only_ready", execution_route="create_only_add", direct_add_allowed=True, request_sha256=request_sha256, plan_status=create_only_plan["status"], plan_sha256=create_only_plan["plan_sha256"])
        if scope.status != "valid":
            print(
                "  [DRY-RUN] Would establish plan-bound managed-content "
                "provenance for this absent-only request."
            )
        for relative, _source in pending:
            print(f"  [DRY-RUN] Would create: {relative}")
        return 0

    try:
        if scope.status == "valid":
            assert scope.project_id is not None
            assert scope.scope_integrity is not None
            assert scope.source_policy_sha256 is not None
            recovery = recover_create_only_transactions(
                project_root,
                project_id=scope.project_id,
                scope_integrity_sha3_512=scope.scope_integrity,
                scope_source_policy_sha256=scope.source_policy_sha256,
                **runtime,
            )
            unresolved = [
                item
                for item in recovery
                if item.status in {"recovery_required", "rollback_incomplete"}
            ]
            if unresolved:
                detail = "; ".join(
                    f"{item.transaction_id}: {item.detail or item.status}"
                    for item in unresolved
                )
                raise ProvenanceError(
                    "Managed-content recovery preserved conflicting state; " + detail
                )
            for item in recovery:
                print(
                    "  [RECOVERED] Managed-content transaction "
                    f"{item.transaction_id}: {item.status}"
                )
        if _managed_request_inventory(sources) != inventory:
            raise ProvenanceError(
                "Managed-content source inventory changed before apply."
            )
        if preapply_revalidator is not None:
            preapply_revalidator()
        closing_scope = inspect_managed_content_scope(project_root)
        if closing_scope.status != scope.status:
            raise ProvenanceError(
                "Managed-content provenance state changed before apply."
            )
        if scope.status == "valid":
            if (
                closing_scope.project_id != scope.project_id
                or closing_scope.scope_integrity != scope.scope_integrity
                or closing_scope.source_policy_sha256
                != scope.source_policy_sha256
            ):
                raise ProvenanceError(
                    "Managed-content provenance binding changed before apply."
                )
            assert scope.project_id is not None
            assert scope.scope_integrity is not None
            assert scope.source_policy_sha256 is not None
            closing_current = current_managed_content_paths(
                project_root,
                project_id=scope.project_id,
                scope_integrity_sha3_512=scope.scope_integrity,
                source_policy_sha256=scope.source_policy_sha256,
                manifest_path=runtime["manifest_path"],
                bases_root=runtime["bases_root"],
                receipts_root=runtime["receipts_root"],
            )
            closing_recorded = recorded_managed_content_paths(
                project_root,
                project_id=scope.project_id,
                scope_integrity_sha3_512=scope.scope_integrity,
                source_policy_sha256=scope.source_policy_sha256,
                manifest_path=runtime["manifest_path"],
                bases_root=runtime["bases_root"],
                receipts_root=runtime["receipts_root"],
            )
        else:
            closing_current = set()
            closing_recorded = set()
        closing_pending, closing_satisfied, closing_collisions = (
            _partition_managed_sources(
                project_root,
                sources,
                provenance_current_paths=closing_current,
                provenance_recorded_paths=closing_recorded,
            )
        )
        if (
            closing_pending != pending
            or closing_satisfied != satisfied
            or closing_collisions != collisions
        ):
            raise ProvenanceError(
                "Managed-content requested/satisfied/collision partition changed "
                "before apply."
            )
        revalidate_create_only_plan(
            project_root,
            pending,
            source_policy_path=UPGRADE_SOURCE_POLICY_PATH,
            plan=create_only_plan,
            precondition_sources=satisfied_sources,
        )
        if scope.status in {
            "owner_enrollment_required",
            "enrollment_required",
        }:
            scope = commit_managed_content_enrollment(
                project_root,
                authorization_digest=str(create_only_plan["plan_sha256"]),
                source_policy_sha256=str(create_only_plan["source_policy_sha256"]),
                creator_identity=(
                    managed_content_creator_identity(KIT_DIR)
                    if scope.status == "owner_enrollment_required" else None
                ),
            )
            enrolled_pending, enrolled_satisfied, enrolled_collisions = (
                _partition_managed_sources(
                    project_root,
                    sources,
                    provenance_current_paths=set(),
                    provenance_recorded_paths=set(),
                )
            )
            if (
                enrolled_pending != pending
                or enrolled_satisfied != satisfied
                or enrolled_collisions != collisions
            ):
                raise ProvenanceError(
                    "Managed-content destination state changed during enrollment."
                )
        if (
            scope.status != "valid"
            or not scope.project_id
            or not scope.scope_integrity
            or not scope.source_policy_sha256
        ):
            raise ProvenanceError(
                scope.refusal
                or "Managed-content enrollment did not produce a complete binding."
            )
        outcome = apply_create_only_plan(
            project_root,
            plan=create_only_plan,
            sources=pending,
            project_id=scope.project_id,
            scope_integrity_sha3_512=scope.scope_integrity,
            scope_source_policy_sha256=scope.source_policy_sha256,
            **runtime,
        )
    except (
        OSError,
        ValueError,
        CanonicalizationUnavailable,
        ProvenanceError,
        TransactionPrimitiveError,
    ) as exc:
        print(f"  [REFUSED] Managed-content apply failed: {exc}", file=sys.stderr)
        return 2
    if outcome.status not in {"committed", "already_applied"}:
        print(
            "  [ERROR] Managed-content transaction "
            f"{outcome.status}: {outcome.detail or 'inspect its durable journal'}",
            file=sys.stderr,
        )
        return 1
    for relative, _source in pending:
        print(f"  [CREATED] {relative}")
    print(
        "  [RECEIPT] Managed-content transaction "
        f"{outcome.transaction_id}: {outcome.receipt_path}"
    )
    return 0


def _materialize_text_source(source: Path, destination: Path, content: str) -> Path:
    """Create a stable derived source while preserving supported source metadata."""

    before_identity, before_metadata = _managed_source_contract(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if _windows_cli() is not None:
        # This is an operation-owned external preview. Installed Windows
        # security is declared by the runtime, never inferred from POSIX mode.
        with destination.open('x', encoding='utf-8', newline='') as derived:
            derived.write(content)
    else:
        shutil.copy2(source, destination)
        destination.write_text(content, encoding="utf-8")
        shutil.copystat(source, destination)
    after_identity, after_metadata = _managed_source_contract(source)
    if before_identity != after_identity or before_metadata != after_metadata:
        raise ValueError(f"Content source changed while materializing: {source}")
    _managed_source_contract(destination)
    return destination


def _flatten_managed_tree_sources(
    source_root: Path,
    destination_root: Path,
) -> list[tuple[Path, Path]]:
    """Flatten a tree into deterministic regular-file leaves for one transaction."""

    root_metadata = source_root.lstat()
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError(f"Managed tree source is not a safe directory: {source_root}")
    result: list[tuple[Path, Path]] = []

    def visit(current: Path) -> bool:
        contains_file = False
        entries = sorted(os.scandir(current), key=lambda item: os.fsencode(item.name))
        for entry in entries:
            if entry.name == ".DS_Store" or entry.name == "__pycache__" or entry.name.endswith((".pyc", ".pyo")):
                continue
            path = Path(entry.path)
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError(f"Managed tree source contains a symbolic link: {path}")
            if stat.S_ISREG(metadata.st_mode):
                _managed_source_contract(path)
                result.append((destination_root / path.relative_to(source_root), path))
                contains_file = True
            elif stat.S_ISDIR(metadata.st_mode):
                child_has_file = visit(path)
                if not child_has_file:
                    raise ValueError(
                        "Managed tree source contains an empty or ignored-only "
                        f"directory that create-only file provenance cannot represent: {path}"
                    )
                contains_file = True
            else:
                raise ValueError(f"Managed tree source contains a special file: {path}")
        return contains_file

    if not visit(source_root):
        raise ValueError(f"Managed tree source has no regular files: {source_root}")
    return sorted(result, key=lambda item: item[0].as_posix())


def _materialize_setup_request_sources(
    project_root: Path,
    module: dict[str, Any],
    *,
    profile: str,
    materialized_root: Path,
    source_origins: SourceOrigins | None = None,
) -> tuple[list[tuple[Path, Path]], list[dict[str, Any]]]:
    actions = [
        action
        for action in module.get("install_actions", [])
        if isinstance(action, dict)
    ]
    selected_actions = [
        action for action in actions if _action_allowed_for_profile(action, profile)
    ]
    destinations = [
        _safe_relative_path(action.get("destination"), field="destination")
        for action in selected_actions
    ]
    _validate_no_overlapping_destinations(destinations)
    selected_file_collisions = {
        destination.as_posix()
        for destination, action in zip(destinations, selected_actions)
        if str(action.get("copy_mode") or "file") == "file"
    }
    targets_scripts_namespace = any(
        destination.parts
        and _normalized_destination_component(destination.parts[0]) == "scripts"
        for destination in destinations
    )
    if targets_scripts_namespace and _scripts_namespace_has_unmanaged_files(
        project_root,
        selected_file_collisions=selected_file_collisions,
    ):
        raise ValueError(
            "Setup-module destinations target a host-owned scripts namespace; "
            "rerun brownfield init to apply the naos_tools layout adapter before "
            "adding this module."
        )

    sources: list[tuple[Path, Path]] = []
    for action_index, action in enumerate(selected_actions):
        action_type = str(action.get("type") or "")
        copy_mode = str(action.get("copy_mode") or "file")
        source = _kit_source_path(action)
        relative_destination = _safe_relative_path(
            action.get("destination"),
            field="destination",
        )
        if action_type in {"copy_file", "repair_seed"} and copy_mode == "file":
            if not source.is_file():
                raise ValueError(f"Source file is missing: {source}")
            _guard_project_destination(
                project_root,
                relative_destination,
                expected_leaf="file",
                reject_multiply_linked_file=True,
            )
            if source_origins is not None:
                source_origins.record(source, relative_destination.as_posix())
            patch = action.get("profile_patch")
            if isinstance(patch, dict) and patch.get("enabled"):
                pattern = str(patch.get("pattern") or "")
                replacement = str(
                    patch.get("replacement_template") or ""
                ).format(profile=profile)
                content = source.read_text(encoding="utf-8")
                if pattern:
                    content = content.replace(pattern, replacement)
                source = _materialize_text_source(
                    source,
                    materialized_root / f"{action_index:04d}" / source.name,
                    content,
                )
            sources.append((relative_destination, source))
        elif action_type == "copy_tree" and copy_mode == "tree":
            _validate_copy_tree_destination(relative_destination)
            tree_sources = _flatten_managed_tree_sources(source, relative_destination)
            if source_origins is not None:
                for relative_leaf, source_leaf in tree_sources:
                    source_origins.record(source_leaf, relative_leaf.as_posix())
            sources.extend(tree_sources)
        else:
            raise ValueError(
                f"Unsupported install action: {action_type}/{copy_mode}"
            )
    return sorted(sources, key=lambda item: item[0].as_posix()), selected_actions


def _materialize_skill_host_request(
    root: Path, source: Path, destination: Path, temporary: Path,
    *, source_origins: SourceOrigins | None = None,
) -> tuple[list[tuple[Path, Path]], dict[str, Any]]:
    """Bind one skill and manual host routes; never edit existing project content."""
    import importlib.util
    sources = _flatten_managed_tree_sources(source, destination)
    primary = next((p for rel, p in sources if rel == destination / "SKILL.md"), None)
    if primary is None:
        raise ValueError("Managed skill source has no SKILL.md")
    if any(rel == destination / "agents/openai.yaml" for rel, _ in sources):
        raise ValueError("Portable adapter Codex policy collides with skill support")
    renderer_path = _kit_source_path({"source": "naos_init.py"})
    renderer_identity = _managed_source_contract(renderer_path)
    spec = importlib.util.spec_from_file_location("_naos_add_host_renderer", renderer_path)
    if spec is None or spec.loader is None:
        raise ValueError("Host route renderer is unavailable")
    renderer = importlib.util.module_from_spec(spec)
    renderer_bytes = _stable_regular_bytes(renderer_path, label="host route renderer")
    if hashlib.sha256(renderer_bytes).hexdigest() != renderer_identity[0]["sha256"]:
        raise ValueError("Host route renderer source differs from its pinned contract")
    # Execute these source bytes, never a timestamp-selected cached code object.
    exec(compile(renderer_bytes, str(renderer_path), "exec"), renderer.__dict__)
    if _managed_source_contract(renderer_path) != renderer_identity:
        raise ValueError("Host route renderer changed during loading")
    profile = _setup_effective_profile(root, None)
    original = _stable_regular_bytes(primary, label="skill source")
    skill_names = {p.name for p in (TEMPLATES_DIR / "skills").iterdir() if p.is_dir()}
    # Only paths actually referenced by this selected guidance are observed.
    body = original.decode("utf-8")
    body = re.sub(r"(?<![A-Za-z0-9_./-])templates/skills/([a-z0-9-]+)/SKILL\.md",
                  r".github/skills/\1/SKILL.md", body)
    candidates = set(re.findall(
        r"scripts/[A-Za-z0-9_./-]+\.py|\.github/(?:skills/[a-z0-9-]+/SKILL\.md|agents/[a-z0-9-]+\.agent\.md|instructions/[a-z0-9-]+\.instructions\.md|prompts/[A-Za-z0-9_-]+(?:\.prompt)?\.md|autoresearch/[A-Za-z0-9_./-]+\.py)", body))
    candidates.update(f".github/skills/{name}/SKILL.md" for name in skill_names if f"`{name}`" in body)
    candidates.update(f".github/agents/{name}.agent.md" for name in re.findall(r"@naos-[a-z0-9-]+", body) for name in [name.lstrip("@")])
    for name in re.findall(r"/(naos-[A-Za-z0-9_-]+)", body):
        candidates.update((f".github/prompts/{name}.md", f".github/prompts/{name}.prompt.md"))
    # Legacy guidance presence does not establish a separately installed adapter.
    for reference in list(candidates):
        if reference.startswith(".github/skills/") and reference.endswith("/SKILL.md"):
            candidates.add(f".agents/skills/naos-portable-{Path(reference).parent.name}/SKILL.md")
        elif reference.startswith(".github/prompts/"):
            base = Path(reference).name.removesuffix(".prompt.md").removesuffix(".md").removeprefix("naos-")
            base = re.sub(r"[^a-z0-9-]+", "-", base.lower()).strip("-")
            candidates.add(f".agents/skills/naos-workflow-{base}/SKILL.md")
    planned = {rel.as_posix() for rel, _ in sources}
    planned.add(f".agents/skills/naos-portable-{destination.name}/SKILL.md")
    inventory = set(planned)
    observations = []
    for name in sorted(candidates - planned):
        relative = _safe_relative_path(name, field="host route reference")
        path = _guard_project_destination(root, relative, expected_leaf="file", reject_multiply_linked_file=True)
        if not path.exists():
            observations.append({"path": name, "present": False})
            continue
        identity, metadata = _managed_source_contract(path)
        observations.append({"path": name, "present": True, "identity": identity, "metadata": metadata})
        inventory.add(name)
    adapter_sources = {kind: _kit_source_path({"source": f"templates/host-adapters/{kind}.md"})
                       for kind in ("portable-skill", "claude-command")}
    adapter_bytes = {kind: _stable_regular_bytes(path, label="host adapter source") for kind, path in adapter_sources.items()}
    policy = _kit_source_path({"source": "templates/host-adapters/openai.yaml"})
    policy_bytes = _stable_regular_bytes(policy, label="host policy source")
    adapter_name, outputs = renderer._render_selected_host_route(
        (destination / "SKILL.md").as_posix(), original, adapter_bytes,
        inventory=inventory, skill_names=skill_names, tier=profile,
        portable_routes={path for path in inventory if path.startswith(".agents/skills/")},
    )
    portable = Path(".agents/skills") / adapter_name
    # The original tree remains exact. Copy every safe support leaf to the route.
    result = list(sources)
    if source_origins is not None:
        for relative, leaf in sources:
            source_origins.record(leaf, relative.as_posix())
    for relative, data in outputs.items():
        kind = "portable-skill" if relative.endswith("/SKILL.md") else "claude-command"
        template = adapter_sources[kind]
        materialized = _materialize_text_source(template, temporary / relative, data.decode("utf-8"))
        result.append((Path(relative), materialized))
        if source_origins is not None:
            for path, raw in [(template, adapter_bytes[kind]), (primary, original)]:
                renderer.mode_row(source_origins.declaration, source=path.relative_to(KIT_DIR.resolve()).as_posix(),
                                  source_bytes=raw, destination=relative, output_bytes=raw)
            source_origins.record_recipe("host_adapter", relative, sorted([
                ("kit/" + template.relative_to(KIT_DIR.resolve()).as_posix(), adapter_bytes[kind]),
                ("kit/" + primary.resolve().relative_to(KIT_DIR.resolve()).as_posix(), original),
                ("generated/selected_inventory.json", json.dumps(sorted(inventory), separators=(",", ":")).encode()),
                ("generated/known_skill_names.json", json.dumps(sorted(skill_names), separators=(",", ":")).encode()),
            ]), {"profile": profile, "name": adapter_name, "kind": kind})
    result.append((portable / "agents/openai.yaml", policy))
    if source_origins is not None:
        source_origins.record(policy, (portable / "agents/openai.yaml").as_posix(), source_bytes=policy_bytes)
    for relative, leaf in sources:
        if relative == destination / "SKILL.md":
            continue
        target = portable / relative.relative_to(destination)
        result.append((target, leaf))
        if source_origins is not None:
            source_origins.record(leaf, target.as_posix())
    binding = {"schema": "naos.add.skill_host_routes.v1", "profile": profile,
               "inventory": sorted(inventory), "observations": observations,
               "skill_names": sorted(skill_names), "renderer": renderer_identity,
               "add_implementation": _managed_source_contract(_kit_source_path({"source": "naos_add.py"})),
               "templates": {kind: _managed_source_contract(path) for kind, path in adapter_sources.items()},
               "policy": _managed_source_contract(policy)}
    # JSON normal form makes persisted tuples and in-memory contracts identical.
    binding = json.loads(json.dumps(binding))
    return sorted(result, key=lambda item: item[0].as_posix()), binding


@contextmanager
def regenerate_managed_request(
    project_root: Path,
    plan: dict[str, Any],
    *,
    collect_source_modes: bool = False,
    portable_request: bool = False,
) -> Iterator[dict[str, Any]]:
    """Regenerate fixed add/setup sources bound by a persisted plan."""

    windows_binding = None
    if not portable_request and _windows_cli() is not None:
        checks = plan.get('checks')
        if (not isinstance(checks, list) or len(checks) != 1
                or not isinstance(checks[0], dict)
                or checks[0].get('check_id') != 'managed_request_source_authority'):
            raise ValueError('Windows add/setup plan lacks source-authority checks')
        windows_binding = checks[0].get('operation_inputs')
        request = plan.get('request')
        if not isinstance(windows_binding, dict) or not isinstance(request, dict):
            raise ValueError('Windows add/setup operation binding is invalid')
        plan = {'operation': request.get('operation'), 'operation_inputs': windows_binding,
                'selected_paths': windows_binding.get('selected_paths')}
    root = _canonical_project_root(project_root)
    operation = str(plan.get("operation") or "")
    operation_inputs = plan.get("operation_inputs")
    if (
        not isinstance(operation_inputs, dict)
        or operation_inputs.get("schema") != "naos.add.operation_inputs.v1"
        or not isinstance(operation_inputs.get("request_sha256"), str)
        or not isinstance(operation_inputs.get("request"), dict)
    ):
        raise ValueError("Add/setup plan operation inputs are invalid.")
    request = dict(operation_inputs["request"])
    source_origins = SourceOrigins.from_kit(KIT_DIR) if collect_source_modes else None

    with tempfile.TemporaryDirectory(
        prefix="naos-add-regenerate-",
        dir=_external_temp_root(root),
    ) as temporary:
        materialized_root = Path(temporary)
        if operation.startswith("naos-add-artifact:"):
            kind = request.get("kind")
            name = request.get("name")
            if not isinstance(kind, str) or kind not in _CATALOG:
                raise ValueError("Add artifact plan kind is invalid.")
            if not isinstance(name, str) or not name:
                raise ValueError("Add artifact plan name is invalid.")
            source = _resolve_source(kind, name)
            if source is None:
                raise ValueError("Add artifact source is unavailable.")
            relative_destination = Path(str(_CATALOG[kind]["dest_dir"])) / source.name
            if operation != (
                f"naos-add-artifact:{kind}:{relative_destination.as_posix()}"
            ):
                raise ValueError("Add artifact operation binding is invalid.")
            if kind == "skill":
                route_request = request.get("host_routes")
                if route_request is None:
                    # Persisted legacy requests keep their exact tree-only scope.
                    sources = _flatten_managed_tree_sources(source, relative_destination)
                    if source_origins is not None:
                        for relative_leaf, source_leaf in sources:
                            source_origins.record(source_leaf, relative_leaf.as_posix())
                    expected_request = {"kind": kind, "name": name,
                                        "template": source.relative_to(KIT_DIR).as_posix()}
                else:
                    if not isinstance(route_request, dict) or route_request.get("schema") != "naos.add.skill_host_routes.v1":
                        raise ValueError("Unsupported progressive skill host route request")
                    sources, route_binding = _materialize_skill_host_request(
                        root, source, relative_destination, materialized_root,
                        source_origins=source_origins,
                    )
                    expected_request = {"kind": kind, "name": name,
                                        "template": source.relative_to(KIT_DIR).as_posix(),
                                        "host_routes": route_binding}
            else:
                template_bytes = _stable_regular_bytes(
                    source,
                    label=f"{kind} template source",
                )
                if source_origins is not None:
                    source_origins.record(
                        source, relative_destination.as_posix(), source_bytes=template_bytes,
                    )
                template_identity, template_metadata = _managed_source_contract(source)
                context = _load_naos_init_context(root)
                context_sha256 = canonical_sha256(context)
                populated = _apply_template(
                    template_bytes.decode("utf-8", errors="replace"),
                    context,
                )
                derived = _materialize_text_source(
                    source,
                    materialized_root / source.name,
                    populated,
                )
                sources = [(relative_destination, derived)]
                expected_request = {
                    "kind": kind,
                    "name": name,
                    "template": source.relative_to(KIT_DIR).as_posix(),
                    "template_source": template_identity,
                    "template_source_metadata": template_metadata,
                    "template_context_sha256": context_sha256,
                }
        elif operation.startswith("naos-add-setup-module:"):
            module_id = request.get("module_id")
            profile = request.get("profile")
            if not isinstance(module_id, str) or not module_id:
                raise ValueError("Setup-module plan id is invalid.")
            if not isinstance(profile, str) or profile not in PROFILES:
                raise ValueError("Setup-module plan profile is invalid.")
            if operation != f"naos-add-setup-module:{module_id}":
                raise ValueError("Setup-module operation binding is invalid.")
            _setup_effective_profile(root, profile)
            snapshot = _load_setup_catalog(root)
            canonical_snapshot = _load_setup_catalog(root, canonical=True)
            module = _resolve_setup_module(snapshot.data, module_id)
            if module is None:
                raise ValueError("Setup-module source is unavailable.")
            canonical_modules = _required_setup_modules(canonical_snapshot.data, module, profile)
            activation_failures = _setup_required_gate_failures(
                module,
                canonical_modules,
                root,
                profile,
            )
            if activation_failures:
                raise ValueError(
                    "Setup activation gate failed: " + "; ".join(activation_failures)
                )
            sources, selected_actions = _materialize_setup_request_sources(
                root,
                module,
                profile=profile,
                materialized_root=materialized_root,
                source_origins=source_origins,
            )
            actions = [
                action
                for action in module.get("install_actions", [])
                if isinstance(action, dict)
            ]
            authority = _setup_source_authority_inventory(
                actions,
                profile=profile,
                project_path=root,
            )
            expected_request = {
                "module_id": module_id,
                "profile": profile,
                "catalog_sha256": snapshot.sha256,
                "catalog_schema_sha256": snapshot.schema_sha256,
                "required_catalog_sha256": canonical_snapshot.sha256,
                "catalog_version": snapshot.data.get("version"),
                "catalog_source": snapshot.source,
                "source_authority_sha256": canonical_sha256(authority),
                "selected_actions": selected_actions,
            }
        else:
            raise ValueError("Apply plan operation is not a supported add/setup request.")

        if request != expected_request:
            raise ValueError("Add/setup source or request binding changed after planning.")
        inventory = _managed_request_inventory(sources)
        request_sha256 = canonical_sha256(
            {
                "schema": "naos.add.managed_request.v1",
                "operation": operation,
                "inputs": request,
                "sources": inventory,
            }
        )
        if request_sha256 != operation_inputs["request_sha256"]:
            raise ValueError("Add/setup source inventory changed after planning.")
        if [relative.as_posix() for relative, _source in sources] != plan.get(
            "selected_paths"
        ):
            raise ValueError("Add/setup selected path inventory changed after planning.")
        checks = [
                {
                    "check_id": "managed_request_source_authority",
                    "status": "passed",
                    "evidence_sha256": request_sha256,
                }
            ]
        if windows_binding is not None:
            checks[0]['operation_inputs'] = windows_binding
        result = {"sources": sources, "checks": checks}
        if source_origins is not None:
            result["source_mode_inventory"] = source_origins.inventory(
                [(relative.as_posix(), source) for relative, source in sources]
            )
        yield result


# ─── COMMANDS ─────────────────────────────────────────────────────────────────


def cmd_add(
    kind: str,
    name: str,
    project_path: Path,
    force: bool = False,
    dry_run: bool = False,
    plan_out: Path | None = None,
    applicability=None,
) -> int:
    """
    Deploy a single template artifact into the project.
    Apply the progressive-add validation and mutation contract.
    """
    cat = _CATALOG.get(kind)
    if cat is None:
        print(f"  [ERROR] Unknown artifact type: {kind!r}", file=sys.stderr)
        return 1
    if force:
        print(
            "  [REFUSED] Legacy blanket --force is not ownership or replacement "
            "authority. Use a reviewed, provenance-bound content transition for "
            "any existing path.",
            file=sys.stderr,
        )
        return 2

    src = _resolve_source(kind, name)
    if src is None:
        print(f"  [ERROR] Template not found: {kind}/{name!r}", file=sys.stderr)
        print(
            f"  Available: {', '.join(_list_available(kind, project_path)) or 'none'}"
        )
        return 1

    relative_dest = Path(str(cat["dest_dir"])) / src.name
    try:
        project_path = _canonical_project_root(project_path)
        if kind == "skill":
            with tempfile.TemporaryDirectory(prefix="naos-add-host-routes-", dir=_external_temp_root(project_path)) as temporary:
                sources, binding = _materialize_skill_host_request(project_path, src, relative_dest, Path(temporary))
                source_inventory = _managed_request_inventory(sources)
                def revalidate_skill_source() -> None:
                    with tempfile.TemporaryDirectory(prefix="naos-add-host-revalidate-", dir=_external_temp_root(project_path)) as fresh:
                        current_sources, current_binding = _materialize_skill_host_request(project_path, src, relative_dest, Path(fresh))
                        if current_binding != binding or _managed_request_inventory(current_sources) != source_inventory:
                            raise ValueError("Managed skill host-route inputs changed before apply.")
                return _run_managed_create_only_request(
                    project_path, sources,
                    operation=f"naos-add-artifact:{kind}:{relative_dest.as_posix()}",
                    request_inputs={"kind": kind, "name": name, "template": src.relative_to(KIT_DIR).as_posix(), "host_routes": binding},
                    dry_run=dry_run, plan_out=plan_out, preapply_revalidator=revalidate_skill_source,
                    **({"applicability": applicability} if applicability is not None else {}),
                )

        _guard_project_destination(
            project_path,
            relative_dest,
            expected_leaf="file",
            reject_multiply_linked_file=True,
        )
        template_bytes = _stable_regular_bytes(
            src,
            label=f"{kind} template source",
        )
        template_source_identity, template_source_metadata = (
            _managed_source_contract(src)
        )
        content = template_bytes.decode("utf-8", errors="replace")
        context = _load_naos_init_context(project_path)
        context_sha256 = canonical_sha256(context)
        populated = _apply_template(content, context)

        def revalidate_artifact_inputs() -> None:
            if _stable_regular_bytes(
                src,
                label=f"{kind} template source",
            ) != template_bytes:
                raise ValueError("Managed artifact template changed before apply.")
            if _managed_source_contract(src) != (
                template_source_identity,
                template_source_metadata,
            ):
                raise ValueError(
                    "Managed artifact template identity or metadata changed before apply."
                )
            if canonical_sha256(_load_naos_init_context(project_path)) != context_sha256:
                raise ValueError("Managed artifact template context changed before apply.")

        with tempfile.TemporaryDirectory(
            prefix="naos-add-sources-",
            dir=_external_temp_root(project_path),
        ) as temp_dir:
            derived = _materialize_text_source(
                src,
                Path(temp_dir) / src.name,
                populated,
            )
            result = _run_managed_create_only_request(
                project_path,
                [(relative_dest, derived)],
                operation=(
                    f"naos-add-artifact:{kind}:{relative_dest.as_posix()}"
                ),
                request_inputs={
                    "kind": kind,
                    "name": name,
                    "template": src.relative_to(KIT_DIR).as_posix(),
                    "template_source": template_source_identity,
                    "template_source_metadata": template_source_metadata,
                    "template_context_sha256": context_sha256,
                },
                dry_run=dry_run,
                plan_out=plan_out,
                preapply_revalidator=revalidate_artifact_inputs,
                **({"applicability": applicability} if applicability is not None else {}),
            )
    except CanonicalizationUnavailable as exc:
        print(
            f"  [REFUSED] Exact canonicalization prerequisite unavailable: {exc}",
            file=sys.stderr,
        )
        return 2
    except (OSError, ValueError) as exc:
        print(f"  [REFUSED] Unsafe source or destination: {exc}", file=sys.stderr)
        return 1
    if result == 0 and kind == "agent" and not dry_run:
        print(
            f"  [MANUAL_ACTION] Preserve root AGENTS.md; review .github/NAOS_AGENTS.md to add @{name} "
            "only through adopter review."
        )
    return result


def cmd_setup_module_list(project_path: Path) -> int:
    """List setup modules with installability posture."""
    try:
        modules = _setup_modules(project_path)
    except (OSError, ValueError) as exc:
        print(f"  [ERROR] {exc}", file=sys.stderr)
        return 1

    installable = [module for module in modules if bool(module.get("installable"))]
    deferred = [module for module in modules if not bool(module.get("installable"))]

    print("\n  Installable setup modules:")
    if installable:
        print(
            "    Examples below use --profile standard; change the profile deliberately."
        )
        for module in installable:
            print(
                f"    naos add setup-module {module.get('id')} --profile standard --dry-run"
            )
    else:
        print("    none")

    print("\n  Readiness-only, deferred, or command-driven modules:")
    if deferred:
        for module in deferred:
            reason = str(
                module.get("not_addable_reason") or "No install actions declared."
            )
            print(f"    {module.get('id')} — {reason}")
    else:
        print("    none")
    return 0


def cmd_setup_module_recommended(
    project_path: Path, profile: str | None, dry_run: bool
) -> int:
    """Plan recommended modules without applying bulk writes."""
    if not dry_run:
        print(
            "  [ERROR] --recommended is plan-only; rerun with --dry-run, then add selected modules one at a time.",
            file=sys.stderr,
        )
        return 1
    try:
        project_path = _canonical_project_root(project_path)
        profile = _setup_effective_profile(project_path, profile)
        modules = _setup_modules(project_path)
    except (OSError, ValueError) as exc:
        print(f"  [ERROR] {exc}", file=sys.stderr)
        return 1

    print(f"\n  [DRY-RUN] Recommended setup-module plan for profile {profile}")
    print("  Active/installable modules:")
    for module in modules:
        profile_default = module.get("profile_default")
        recommendation = (
            str(profile_default.get(profile))
            if isinstance(profile_default, dict)
            else "optional"
        )
        if recommendation == "recommended" and bool(module.get("installable")):
            print(f"    - {module.get('id')}: {module.get('name')}")
    print("  Readiness-only/deferred modules:")
    for module in modules:
        profile_default = module.get("profile_default")
        recommendation = (
            str(profile_default.get(profile))
            if isinstance(profile_default, dict)
            else "optional"
        )
        if recommendation in {"readiness_only", "experimental", "defer"} or not bool(
            module.get("installable")
        ):
            print(f"    - {module.get('id')}: {recommendation}; no bulk install")
    print(
        "  No files were written. Add selected modules one at a time after human review."
    )
    return 0


def cmd_add_setup_module(
    name: str,
    project_path: Path,
    profile: str | None = None,
    force: bool = False,
    dry_run: bool = False,
    confirm: bool = False,
    plan_out: Path | None = None,
    applicability=None,
) -> int:
    """Apply explicit install_actions from the setup module catalog."""
    if profile is not None and profile not in PROFILES:
        print(f"  [ERROR] Unknown profile: {profile!r}", file=sys.stderr)
        return 1
    if force:
        print(
            "  [REFUSED] Legacy blanket --force is not ownership or replacement "
            "authority. Setup modules preserve every unproven existing path.",
            file=sys.stderr,
        )
        return 2
    try:
        project_path = _canonical_project_root(project_path)
        profile = _setup_effective_profile(project_path, profile)
    except CanonicalizationUnavailable as exc:
        print(
            f"  [REFUSED] Exact canonicalization prerequisite unavailable: {exc}",
            file=sys.stderr,
        )
        return 2
    except (OSError, ValueError) as exc:
        print(f"  [REFUSED] {exc}", file=sys.stderr)
        return 2
    try:
        catalog_snapshot = _load_setup_catalog(project_path)
        canonical_snapshot = _load_setup_catalog(project_path, canonical=True)
        catalog = catalog_snapshot.data
        catalog_path = catalog_snapshot.path
        catalog_source = catalog_snapshot.source
        module = _resolve_setup_module(catalog, name)
    except (OSError, ValueError) as exc:
        print(f"  [ERROR] {exc}", file=sys.stderr)
        return 1

    if module is None:
        print(f"  [ERROR] Setup module not found: {name!r}", file=sys.stderr)
        print("  Available setup modules:")
        for item in catalog.get("modules", []):
            if isinstance(item, dict):
                print(f"    - {item.get('id')}: {item.get('name')}")
        return 1

    print(f"  [CATALOG] {catalog_path} ({catalog_source})")
    _print_setup_module_explanation(module, profile)
    try:
        canonical_modules = _required_setup_modules(canonical_snapshot.data, module, profile)
    except ValueError as exc:
        print(f"  [REFUSED] {exc}", file=sys.stderr)
        return 2

    if (
        (bool(module.get("requires_confirmation")) or any(bool(item.get("requires_confirmation")) for item in canonical_modules))
        and not dry_run
        and plan_out is None
        and not confirm
    ):
        print(
            "\n  [REFUSED] This setup module requires explicit --confirm after "
            "reviewing its dry-run. Confirmation never authorizes replacement "
            "of existing content."
        )
        return 2

    actions = [
        action
        for action in module.get("install_actions", [])
        if isinstance(action, dict)
    ]
    if not bool(module.get("installable")) or not actions:
        reason = str(
            module.get("not_addable_reason")
            or "No explicit install_actions are declared."
        )
        print(f"\n  [REFUSED] {reason}")
        for item in _profile_module_list(
            module, profile, "post_install_next_actions"
        ):
            print(f"    next: {_render_setup_module_text(item, profile)}")
        return 2

    try:
        activation_failures = _setup_required_gate_failures(
            module, canonical_modules, project_path, profile
        )
    except ValueError as exc:
        activation_failures = [str(exc)]
    if activation_failures:
        print("\n  Activation gate:")
        for failure in activation_failures:
            print(f"  [REFUSED] {failure}")
        return 2

    selected_actions: list[dict[str, Any]] = []
    skipped_actions: list[dict[str, Any]] = []
    try:
        catalog_sha256 = catalog_snapshot.sha256
        canonical_module_id = str(module.get("id") or name)
        setup_authority_inventory = _setup_source_authority_inventory(
            actions,
            profile=profile,
            project_path=project_path,
        )
        selected_action_destinations = [
            _safe_relative_path(action.get("destination"), field="destination")
            for action in actions
            if _action_allowed_for_profile(action, profile)
        ]
        _validate_no_overlapping_destinations(selected_action_destinations)
        selected_file_collisions = {
            _safe_relative_path(action.get("destination"), field="destination").as_posix()
            for action in actions
            if _action_allowed_for_profile(action, profile)
            and str(action.get("copy_mode") or "file") == "file"
        }
        targets_scripts_namespace = any(
            destination.parts
            and _normalized_destination_component(destination.parts[0]) == "scripts"
            for destination in selected_action_destinations
        )
        if targets_scripts_namespace and _scripts_namespace_has_unmanaged_files(
            project_path,
            selected_file_collisions=selected_file_collisions,
        ):
            raise ValueError(
                "Setup-module destinations target a host-owned scripts namespace; "
                "rerun brownfield init to apply the naos_tools layout adapter before "
                "adding this module."
            )

        def revalidate_setup_inputs() -> None:
            _setup_effective_profile(project_path, profile)
            refreshed_canonical = _load_setup_catalog(project_path, canonical=True)
            if refreshed_canonical != canonical_snapshot:
                raise ValueError("Required kit setup controls changed before apply.")
            refreshed = _load_setup_catalog(project_path)
            if (
                refreshed.path != catalog_snapshot.path
                or refreshed.source != catalog_snapshot.source
                or refreshed.sha256 != catalog_snapshot.sha256
                or refreshed.schema_sha256 != catalog_snapshot.schema_sha256
                or refreshed.data != catalog_snapshot.data
            ):
                raise ValueError("Setup catalog or schema changed before apply.")
            refreshed_module = _resolve_setup_module(
                refreshed.data,
                canonical_module_id,
            )
            if refreshed_module != module:
                raise ValueError("Selected setup module changed before apply.")
            refreshed_actions = [
                action
                for action in refreshed_module.get("install_actions", [])
                if isinstance(action, dict)
            ]
            activation_changes = _setup_required_gate_failures(
                refreshed_module,
                canonical_modules,
                project_path,
                profile,
            )
            if activation_changes:
                raise ValueError(
                    "Setup activation gate changed before apply: "
                    + "; ".join(activation_changes)
                )
            if _setup_source_authority_inventory(
                refreshed_actions,
                profile=profile,
                project_path=project_path,
            ) != setup_authority_inventory:
                raise ValueError("Setup source inventory changed before apply.")
            if targets_scripts_namespace and _scripts_namespace_has_unmanaged_files(
                project_path,
                selected_file_collisions=selected_file_collisions,
            ):
                raise ValueError(
                    "Setup-module destinations target a host-owned scripts namespace; "
                    "rerun brownfield init to apply the naos_tools layout adapter before "
                    "adding this module."
                )

        with tempfile.TemporaryDirectory(
            prefix="naos-setup-sources-",
            dir=_external_temp_root(project_path),
        ) as temp_dir:
            materialized_root = Path(temp_dir)
            sources: list[tuple[Path, Path]] = []
            for action_index, action in enumerate(actions):
                if not _action_allowed_for_profile(action, profile):
                    skipped_actions.append(action)
                    continue
                action_type = str(action.get("type") or "")
                copy_mode = str(action.get("copy_mode") or "file")
                source = _kit_source_path(action)
                destination = _project_dest_path(project_path, action)
                relative_destination = destination.relative_to(project_path)
                selected_actions.append(action)
                if action_type in {"copy_file", "repair_seed"} and copy_mode == "file":
                    if not source.is_file():
                        raise ValueError(f"Source file is missing: {source}")
                    _guard_project_destination(
                        project_path,
                        relative_destination,
                        expected_leaf="file",
                        reject_multiply_linked_file=True,
                    )
                    patch = action.get("profile_patch")
                    if isinstance(patch, dict) and patch.get("enabled"):
                        pattern = str(patch.get("pattern") or "")
                        replacement = str(
                            patch.get("replacement_template") or ""
                        ).format(profile=profile)
                        content = source.read_text(encoding="utf-8")
                        if pattern:
                            content = content.replace(pattern, replacement)
                        source = _materialize_text_source(
                            source,
                            materialized_root / f"{action_index:04d}" / source.name,
                            content,
                        )
                    sources.append((relative_destination, source))
                elif action_type == "copy_tree" and copy_mode == "tree":
                    _validate_copy_tree_destination(relative_destination)
                    sources.extend(
                        _flatten_managed_tree_sources(
                            source,
                            relative_destination,
                        )
                    )
                else:
                    raise ValueError(
                        f"Unsupported install action: {action_type}/{copy_mode}"
                    )

            print("\n  Install actions:")
            for action in skipped_actions:
                print(
                    f"  [SKIP] Action for {action.get('destination')} is not "
                    f"enabled for profile {profile}"
                )
            if not sources:
                print("  [NOTE] No actions apply to the selected profile.")
                if applicability is not None:
                    applicability.record("noop", "no_selected_actions")
                result = 0
            else:
                result = _run_managed_create_only_request(
                    project_path,
                    sources,
                    operation=f"naos-add-setup-module:{canonical_module_id}",
                    request_inputs={
                        "module_id": canonical_module_id,
                        "profile": profile,
                        "catalog_sha256": catalog_sha256,
                        "catalog_schema_sha256": catalog_snapshot.schema_sha256,
                        "required_catalog_sha256": canonical_snapshot.sha256,
                        "catalog_version": catalog.get("version"),
                        "catalog_source": catalog_source,
                        "source_authority_sha256": canonical_sha256(
                            setup_authority_inventory
                        ),
                        "selected_actions": selected_actions,
                    },
                    dry_run=dry_run,
                    plan_out=plan_out,
                    preapply_revalidator=revalidate_setup_inputs,
                    **({"applicability": applicability} if applicability is not None else {}),
                )
    except CanonicalizationUnavailable as exc:
        print(
            "\n  Install actions:\n"
            f"  [REFUSED] Exact canonicalization prerequisite unavailable: {exc}"
        )
        return 2
    except (OSError, ValueError) as exc:
        print("\n  Install actions:")
        print(f"  [REFUSED] Install action preflight failed: {exc}")
        return 1

    if result == 0:
        for action in selected_actions:
            for item in _as_string_list(action.get("post_install_next_actions")):
                print(f"    next: {_render_setup_module_text(item, profile)}")
        for item in _profile_module_list(
            module, profile, "post_install_next_actions"
        ):
            print(f"  next: {_render_setup_module_text(item, profile)}")
    return result


def cmd_list(kind: str | None, project_path: Path) -> int:
    """Show available templates not yet deployed."""
    if kind == SETUP_MODULE_KIND:
        return cmd_setup_module_list(project_path)
    kinds = [kind] if kind else list(_CATALOG.keys())
    total = 0
    for k in kinds:
        available = _list_available(k, project_path)
        total += len(available)
        if available:
            print(f"\n  {k.capitalize()}s available to add:")
            for n in available:
                print(f"    naos add {k} {n}")
        else:
            print(
                f"\n  {k.capitalize()}s: all templates already deployed (or none available)"
            )

    if total == 0:
        print(
            "\n  Nothing to add — all templates are already deployed in this project."
        )
    if kind is None:
        cmd_setup_module_list(project_path)
    return 0


# ─── MAIN ─────────────────────────────────────────────────────────────────────


def _applicability_command(args, project_path):
    """One opt-in stdout result; normal add and canonical plan wire stay unchanged."""
    from contextlib import redirect_stdout
    try:
        from .upgrade_contract.add_applicability import BranchCollector
    except ImportError:
        from upgrade_contract.add_applicability import BranchCollector
    collector = BranchCollector()
    invalid = (not args.dry_run or args.list or args.recommended
               or args.plan_out is not None or not args.kind or not args.name)
    if invalid:
        print("  [ERROR] --applicability-json requires --dry-run and one exact "
              "artifact or setup module; not --list, --recommended or --plan-out.",
              file=sys.stderr)
        print(json.dumps(collector.result(2, reason_code="invalid_report_request"),
                         sort_keys=True, separators=(",", ":")))
        return 2
    exit_code = None
    try:
        with redirect_stdout(sys.stderr):
            if args.kind == SETUP_MODULE_KIND:
                exit_code = cmd_add_setup_module(
                    name=args.name, project_path=project_path, profile=args.profile,
                    force=args.force, dry_run=args.dry_run, confirm=args.confirm,
                    plan_out=args.plan_out, applicability=collector)
            else:
                exit_code = cmd_add(
                    kind=args.kind, name=args.name, project_path=project_path,
                    force=args.force, dry_run=args.dry_run, plan_out=args.plan_out,
                    applicability=collector)
        return exit_code
    finally:
        # Uncaught errors retain their original nonzero/traceback behavior.
        # None is honest when no command return was observed; never infer ready.
        print(json.dumps(collector.result(exit_code), sort_keys=True,
                         separators=(",", ":")))


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="naos add",
        description="NAOS add — deploy a governance artifact into an existing project",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          naos add instruction postgresql    Add PostgreSQL instruction to .github/instructions/
          naos add agent naos-debug          Add naos-debug agent to .github/agents/
          naos add spec 05                   Add optional spec 05-api.md to specs/
          naos add skill cookbook-neo4j      Add neo4j cookbook skill to .github/skills/
          naos add setup-module --list       Show guided setup modules
          naos add setup-module read_only_ci_readiness --profile lite --dry-run
          naos add setup-module spec_kit_adapter --profile standard --dry-run
          naos add setup-module claude_code_hooks --profile standard --dry-run
          naos add setup-module pre_implementation_alignment --profile standard --dry-run
          naos add setup-module --recommended --profile assured --dry-run
          naos add --list                    Show all templates not yet deployed
          naos add --list instruction        Show only available instructions
          naos add instruction neo4j --dry-run   Preview without writing files
          naos add instruction neo4j --plan-out /tmp/neo4j-plan.json
                                               Persist an eligible collision plan
          naos upgrade . --apply-plan /tmp/neo4j-plan.json --expect-plan-digest SHA256
                                               Apply that exact plan separately
          naos add instruction neo4j --force     Refuse unproven legacy replacement
        """),
    )
    parser.add_argument(
        "kind",
        nargs="?",
        choices=list(_CATALOG.keys()) + [SETUP_MODULE_KIND],
        help="Artifact type: instruction | agent | spec | skill | setup-module",
    )
    parser.add_argument(
        "name",
        nargs="?",
        help="Name of the template or setup module to deploy (e.g., 'postgresql', '05', 'naos-debug', 'read_only_ci_readiness')",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available templates not yet deployed in this project",
    )
    parser.add_argument(
        "--project",
        type=Path,
        default=Path("."),
        help="Project root directory (default: current dir)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Legacy compatibility flag; unproven existing-content replacement is refused",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without writing files; recommended before setup-module installs",
    )
    parser.add_argument(
        "--plan-out",
        type=Path,
        help=(
            "Persist an immutable content-aware plan outside the project; "
            "never mutates project content"
        ),
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Confirm an explicitly selected setup module after dry-run review; never authorizes replacement",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default=None,
        help="Setup profile (default: recorded project profile; lite only before initialization). An explicit mismatch is refused.",
    )
    parser.add_argument(
        "--recommended",
        action="store_true",
        help="Plan recommended setup modules for a profile (dry-run only; apply selected modules one at a time)",
    )

    parser.add_argument(
        "--applicability-json", action="store_true",
        help="With --dry-run, emit one applicability JSON result; diagnostics go to stderr. Never authorizes mutation.",
    )
    args = parser.parse_args()
    project_path = args.project.resolve()
    if args.applicability_json:
        return _applicability_command(args, project_path)

    if args.plan_out is not None and (args.list or args.recommended):
        print(
            "  [ERROR] --plan-out requires one exact artifact or setup module.",
            file=sys.stderr,
        )
        return 2

    if args.list:
        return cmd_list(args.kind, project_path)

    if not args.kind:
        parser.print_help()
        return 1

    if args.kind == SETUP_MODULE_KIND:
        if args.recommended:
            return cmd_setup_module_recommended(
                project_path=project_path,
                profile=args.profile,
                dry_run=args.dry_run,
            )
        if not args.name:
            print(
                "  [ERROR] Specify a setup module id or use --list.",
                file=sys.stderr,
            )
            cmd_setup_module_list(project_path)
            return 1
        return cmd_add_setup_module(
            name=args.name,
            project_path=project_path,
            profile=args.profile,
            force=args.force,
            dry_run=args.dry_run,
            confirm=args.confirm,
            plan_out=args.plan_out,
        )

    if not args.name:
        print(f"  [ERROR] Specify a name. Available {args.kind}s:", file=sys.stderr)
        available = _list_available(args.kind, project_path)
        for n in available:
            print(f"    naos add {args.kind} {n}")
        return 1

    return cmd_add(
        kind=args.kind,
        name=args.name,
        project_path=project_path,
        force=args.force,
        dry_run=args.dry_run,
        plan_out=args.plan_out,
    )


if __name__ == "__main__":
    sys.exit(main())
