#!/usr/bin/env python3
"""NAOS memory onboarding and read-only Engram readiness checks."""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping

try:
    import yaml  # type: ignore[import-untyped]
except Exception:  # pragma: no cover - PyYAML is a package dependency
    yaml = None  # type: ignore[assignment]

SCRIPT_DIR = Path(__file__).resolve().parent / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_mcp_config_registry import (  # noqa: E402
    resolve_engram_project,
    scan_mcp_configs,
    summarize_mcp_configs,
)


DEFAULT_DATA_DIR = "~/.engram"
DATABASE_NAME = "engram.db"
DEFAULT_REPLICATION_PROFILE = "local"
CONFIG_PATH = Path("configs") / "naos_memory.yaml"
KNOWN_ENGRAM_BINARIES = ("engram", "engram-mcp", "mcp-engram")
PROJECT_RESOLVER_BINARY = "engram-memory"
DISPOSITIONS = ("configure-local", "use-existing", "defer", "decline")
LEGACY_MODES = {
    "centralized": "configure-local",
    "local": "configure-local",
    "deferred": "defer",
    "disabled": "decline",
}
MCP_NAMESPACE_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9_-]{0,63}(?:/(?:\*|[A-Za-z][A-Za-z0-9_-]{0,63}))?$"
)
PROJECT_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
MCP_NAMESPACE_SENSITIVE_PATTERNS = (
    re.compile(r"(?i)^(?:sk[-_]|ghp_|github_pat_|glpat-|xox[baprs]-|akia|aiza)"),
    re.compile(r"(?i)(?:api[_-]?key|bearer|connection[_-]?string|password|secret|token)"),
)


def _print_header(title: str) -> None:
    print(f"\nNAOS memory — {title}")
    print("=" * (14 + len(title)))


def _repo_root(path: Path) -> Path:
    return path.resolve()


def _config_file(root: Path) -> Path:
    return root / CONFIG_PATH


def _memory_mapping(config: dict[str, Any]) -> dict[str, Any]:
    memory = config.get("memory", config)
    return memory if isinstance(memory, dict) else {}


def _load_config(root: Path) -> tuple[dict[str, Any], str | None]:
    path = _config_file(root)
    if not path.exists() and not path.is_symlink():
        return {}, None
    if yaml is None:
        return {}, "PyYAML is unavailable"
    try:
        raw = _read_regular_file(path)
        data = yaml.safe_load(raw.decode("utf-8")) or {}
    except Exception:
        return {}, "config is not a readable regular YAML mapping"
    if not isinstance(data, dict):
        return {}, "config must contain a YAML mapping"
    return data, None


def _dump_config(data: dict[str, Any]) -> str:
    if yaml is None:
        raise ValueError("PyYAML is required to render memory configuration")
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=False)


def _detect_engram_binary() -> str | None:
    for binary in KNOWN_ENGRAM_BINARIES:
        found = shutil.which(binary)
        if found:
            return found
    return None


def _detect_project_resolver() -> str | None:
    return shutil.which(PROJECT_RESOLVER_BINARY)


def _inside_project(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _expand_user_path(value: str | Path) -> Path:
    try:
        return Path(str(value)).expanduser()
    except RuntimeError as exc:
        raise ValueError(f"cannot expand user-home reference in path: {value!s}") from exc


def _expand_data_dir(value: str | Path, root: Path) -> Path:
    path = _expand_user_path(value)
    return path if path.is_absolute() else root / path


def _effective_data_dir(
    memory: Mapping[str, Any],
    root: Path,
    environ: Mapping[str, str] | None = None,
) -> tuple[Path, str, str]:
    environment = os.environ if environ is None else environ
    environment_value = str(environment.get("ENGRAM_DATA_DIR") or "").strip()
    if environment_value:
        return _expand_data_dir(environment_value, root), "ENGRAM_DATA_DIR", environment_value
    declared_value = str(memory.get("data_dir") or "").strip()
    if declared_value:
        return _expand_data_dir(declared_value, root), "config", declared_value
    return _expand_data_dir(DEFAULT_DATA_DIR, root), "provider_default", DEFAULT_DATA_DIR


def _database_path(data_dir: Path) -> Path:
    return data_dir / DATABASE_NAME


def _display_path(path: Path) -> str:
    try:
        home = Path.home()
    except RuntimeError:
        return str(path)
    try:
        relative = path.relative_to(home)
    except ValueError:
        return str(path)
    return "~" if not relative.parts else f"~/{relative.as_posix()}"


def _validated_data_dir(value: str | Path, root: Path) -> str:
    supplied = str(value).strip()
    if not supplied or any(character in supplied for character in ("\x00", "\n", "\r")):
        raise ValueError("data directory must be a non-empty single-line path")
    expanded = _expand_user_path(supplied)
    if not expanded.is_absolute():
        raise ValueError("data directory must be absolute or start with '~/'")
    if expanded.name == DATABASE_NAME or expanded.suffix.lower() in {".db", ".sqlite"}:
        raise ValueError("--data-dir expects the directory containing engram.db, not the database file")
    if _inside_project(expanded, root):
        raise ValueError("Engram data must remain outside the project repository")
    database = _database_path(expanded)
    if database.is_file() and _inside_project(database, root):
        raise ValueError("Engram database must not resolve inside the project repository")
    default_expanded = _expand_user_path(DEFAULT_DATA_DIR)
    if expanded == default_expanded:
        return DEFAULT_DATA_DIR
    return supplied


def _validated_mcp_namespace(mcp_namespace: str | None) -> str | None:
    if mcp_namespace is None:
        return None
    if not MCP_NAMESPACE_PATTERN.fullmatch(mcp_namespace) or any(
        pattern.search(mcp_namespace) for pattern in MCP_NAMESPACE_SENSITIVE_PATTERNS
    ):
        raise ValueError("MCP namespace must be a non-sensitive tool name such as 'engram' or 'engram/*'")
    return mcp_namespace


def _validated_project_id(project: str | None) -> str | None:
    if project is None:
        return None
    if not PROJECT_ID_PATTERN.fullmatch(project):
        raise ValueError("MCP project must be an exact registered project ID or alias")
    return project


def _resolve_one_project(resolver: str, root: Path, requested: str | None) -> dict[str, Any]:
    command = [resolver, "resolve", "--cwd", str(root)]
    if requested:
        command.extend(["--project", requested])
    try:
        result = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "failed_closed"}
    if result.returncode != 0:
        return {"status": "failed_closed"}
    try:
        payload = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        return {"status": "failed_closed"}
    project = payload.get("project") if isinstance(payload, dict) else None
    source = payload.get("source") if isinstance(payload, dict) else None
    if not isinstance(project, str) or not PROJECT_ID_PATTERN.fullmatch(project):
        return {"status": "failed_closed"}
    return {"status": "resolved", "project": project, "source": str(source or "resolver")}


def _project_identity_status(
    root: Path,
    memory_config: Mapping[str, Any],
    mcp_configs: list[dict[str, Any]],
    resolver: str | None,
) -> dict[str, Any]:
    registry_identity = resolve_engram_project(memory_config, mcp_configs)
    requested = list(
        dict.fromkeys(
            project
            for project in [
                registry_identity.get("expected_project"),
                *registry_identity.get("workspace_projects", []),
            ]
            if isinstance(project, str) and project
        )
    )
    if registry_identity.get("global_project_conflict"):
        return {
            "status": "failed_closed",
            "reason": "global_fixed_project_conflict",
            "registry": registry_identity,
        }
    if resolver is None:
        if registry_identity.get("status") == "conflict" or len(requested) > 1:
            return {
                "status": "failed_closed",
                "reason": "conflicting_unverified_declarations",
                "registry": registry_identity,
            }
        if requested:
            return {
                "status": "declared_unverified",
                "project": requested[0],
                "registry": registry_identity,
            }
        return {"status": "resolver_unavailable", "registry": registry_identity}

    # Always resolve the current workspace dynamically. Fixed declarations, when
    # present, are compatibility assertions rather than a required global selector.
    resolutions = [_resolve_one_project(resolver, root, None)]
    resolutions.extend(_resolve_one_project(resolver, root, project) for project in requested)
    if any(item.get("status") != "resolved" for item in resolutions):
        return {
            "status": "failed_closed",
            "reason": "resolver_rejected_or_unavailable",
            "registry": registry_identity,
        }
    canonical = sorted({str(item["project"]) for item in resolutions})
    if len(canonical) != 1:
        return {
            "status": "failed_closed",
            "reason": "canonical_project_conflict",
            "registry": registry_identity,
        }
    return {
        "status": "resolved",
        "project": canonical[0],
        "source": resolutions[0].get("source"),
        "persisted": False,
        "registry": registry_identity,
    }


def _validate_config_destination(root: Path, path: Path) -> None:
    root = root.resolve()
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ValueError("memory config destination must stay inside the project") from exc
    current = root
    parts = relative.parts
    for index, part in enumerate(parts):
        current = current / part
        if current.is_symlink():
            raise ValueError("memory config destination must not contain symlinks")
        if index < len(parts) - 1 and current.exists() and not current.is_dir():
            raise ValueError("memory config destination parent must be a directory")
    if (path.exists() or path.is_symlink()) and not path.is_file():
        raise ValueError("memory config destination must be a regular file")
    resolved_parent = path.parent.resolve(strict=False)
    if root not in (resolved_parent, *resolved_parent.parents):
        raise ValueError("memory config destination must resolve inside the project")


def _read_regular_file(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("existing memory config must be a regular file")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            return handle.read()
    finally:
        if fd >= 0:
            os.close(fd)


def _atomic_write_config(root: Path, path: Path, text: str) -> None:
    _validate_config_destination(root, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _validate_config_destination(root, path)
    mode = 0o600
    if path.exists():
        _read_regular_file(path)
        mode = stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            os.fchmod(handle.fileno(), mode)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        _validate_config_destination(root, path)
        os.replace(temp_path, path)
    finally:
        if fd >= 0:
            os.close(fd)
        temp_path.unlink(missing_ok=True)


def explain() -> int:
    _print_header("why Engram matters")
    print(
        "NAOS recommends Engram as an optional durable episodic-memory layer.\n"
        "It can support recovery through mem_context and mem_search, and approved checkpoints\n"
        "through mem_save or mem_session_summary when access and write policy are verified.\n"
    )
    print("Provider storage:")
    print(f"  data directory: {DEFAULT_DATA_DIR} (overridden at runtime by ENGRAM_DATA_DIR)")
    print(f"  derived database: {DEFAULT_DATA_DIR}/{DATABASE_NAME}")
    print("  replication profile: local; Git memory synchronization is not configured")
    print()
    print("Privacy and authority:")
    print("  - the live database remains outside project repositories")
    print("  - NAOS checks path metadata only and never reads database payloads")
    print("  - no provider, MCP client, installer, sync, or network command is run by setup")
    print("  - memory is advisory and never overrides source, tests, policy, or human decisions")
    print("  - never store secrets, credentials, customer data, regulated data, or connection strings")
    print()
    print("If Engram already exists, run `naos memory check` and record `use-existing`; do not create a duplicate database.")
    print("If memory is deferred or disabled, NAOS uses task cards, compact files, git state, and repository governance files.")
    return 0


def check(project_root: Path) -> int:
    root = _repo_root(project_root)
    config, config_error = _load_config(root)
    memory = _memory_mapping(config)
    binary = _detect_engram_binary()
    data_dir, data_dir_source, _ = _effective_data_dir(memory, root)
    database = _database_path(data_dir)
    data_dir_exists = data_dir.is_dir()
    database_exists = database.is_file()
    data_in_project = _inside_project(data_dir, root)
    database_in_project = database_exists and _inside_project(database, root)
    legacy_store_path = memory.get("store_path")
    mcp_results = scan_mcp_configs(root, include_user=True)
    mcp_summary = summarize_mcp_configs(mcp_results)
    existing_mcp = [item for item in mcp_results if item["exists"]]
    identity = _project_identity_status(root, memory, mcp_results, _detect_project_resolver())
    registry_identity = identity.get("registry", {})

    _print_header("check")
    print(f"Project: {root}")
    print(f"Config:  {CONFIG_PATH} {'invalid' if config_error else 'found' if _config_file(root).is_file() else 'missing'}")
    if config_error:
        print("  WARN: memory config could not be parsed safely; it was not used")
    if memory:
        print(f"State:   {memory.get('state', 'unknown')} / {memory.get('scope', 'unknown')} / {memory.get('provider', 'unknown')}")
        print(f"Decision: {memory.get('disposition', 'not recorded')}")
    else:
        print("State:   unknown (run `naos memory setup --disposition defer --write` to record an explicit decision)")
    print()
    print("Engram runtime metadata:")
    print(f"  binary: {'found at ' + binary if binary else 'not found in PATH'}")
    print(f"  data directory: {_display_path(data_dir)} ({'exists' if data_dir_exists else 'missing'}; source={data_dir_source})")
    print(f"  database: {_display_path(database)} ({'exists' if database_exists else 'missing'}; payload not read)")
    replication_profile = str(memory.get("replication_profile") or DEFAULT_REPLICATION_PROFILE)
    print(f"  replication: {replication_profile} (Git sync not configured by NAOS)")
    if replication_profile.casefold() != DEFAULT_REPLICATION_PROFILE:
        print("  WARN: non-local replication is outside the maintained profile and requires explicit review; it was not changed")
    if legacy_store_path is not None:
        print("  WARN: legacy store_path is present but ignored; use data_dir and remove it only through reviewed migration")
    if data_in_project:
        print("  WARN: effective Engram data directory is inside this project repository")
    if database_in_project and not data_in_project:
        print("  WARN: derived Engram database resolves inside this project repository")
    print()
    print("Project identity:")
    if identity["status"] == "resolved":
        print(f"  canonical project: {identity['project']} (read-only resolver; not persisted)")
    elif identity["status"] == "declared_unverified":
        print(f"  declared project: {identity['project']} (resolver unavailable; unverified)")
    elif identity["status"] == "resolver_unavailable":
        print("  resolver: not installed; non-blocking, but no canonical project is inferred")
    else:
        print("  ERROR: project identity resolution failed closed; do not use memory for this workspace")
    if registry_identity.get("global_fixed_project_detected"):
        print("  WARN: a user-scoped fixed ENGRAM_PROJECT declaration was detected; it is not used as this workspace identity")
    print()
    print("MCP configuration:")
    if not existing_mcp:
        print("  no supported MCP server config files found in workspace or explicit VS Code user locations")
    for item in existing_mcp:
        print(f"  {item['path']} (scope={item.get('scope', 'unknown')})")
        if item.get("status") != "present":
            print(f"    status: {item.get('status', 'unknown')}")
        servers = item.get("servers") or []
        if servers:
            print(f"    servers: {', '.join(servers)}")
        if item.get("engram_servers"):
            print("    Engram reference: yes (declaration only)")
        projects = item.get("engram_projects") or []
        if projects:
            print(f"    fixed project declarations: {', '.join(projects)}")
        if item.get("has_secret_like_key"):
            print("    WARN: secret-like keys were detected; do not commit actual secrets")
    print()
    if config_error:
        print("Result: memory configuration is invalid. Repair or replace it through review before evaluating Engram readiness.")
        return 2
    if data_in_project or database_in_project:
        print("Result: Engram storage resolves inside the project. Move it outside the repository before use.")
        return 2
    if identity["status"] == "failed_closed":
        print("Result: project identity conflict or resolver failure. Memory use must stop until reviewed.")
        return 2
    if binary or mcp_summary.get("mcp_configured") or database_exists:
        print("Result: provider signals detected. Record `use-existing` and verify active MCP access plus mem_current_project before recall or write.")
        return 0
    print("Result: Engram is not configured. Preview `naos memory setup --disposition configure-local`; setup records state only.")
    return 0


def _merge_setup_config(
    existing: dict[str, Any],
    *,
    disposition: str,
    data_dir: str | Path | None,
    mcp_namespace: str | None,
    mcp_project: str | None,
    root: Path,
) -> dict[str, Any]:
    if disposition not in DISPOSITIONS:
        raise ValueError("unsupported memory disposition")
    if "memory" in existing:
        if not isinstance(existing.get("memory"), dict):
            raise ValueError("existing memory config must contain a memory mapping")
        result = copy.deepcopy(existing)
        memory = copy.deepcopy(existing["memory"])
    else:
        result = {}
        memory = copy.deepcopy(existing)
    obsolete_fields = [field for field in ("strict_required", "last_check") if field in memory]
    for field in obsolete_fields:
        memory.pop(field, None)
    legacy_store_path = memory.pop("store_path", None)
    if legacy_store_path is not None:
        migration = memory.get("migration")
        if migration is None:
            migration = {}
        if not isinstance(migration, dict):
            raise ValueError("existing memory migration metadata must be a mapping")
        migration = copy.deepcopy(migration)
        recorded_legacy = migration.get("legacy_store_path")
        if recorded_legacy is not None and recorded_legacy != legacy_store_path:
            raise ValueError("existing legacy store_path conflicts with recorded migration metadata")
        migration["legacy_store_path"] = legacy_store_path
        migration["status"] = "legacy_store_path_removed_from_active_config"
        memory["migration"] = migration
    selected_data_dir = data_dir if data_dir is not None else memory.get("data_dir") or DEFAULT_DATA_DIR
    persisted_data_dir = _validated_data_dir(selected_data_dir, root)
    selected_namespace = _validated_mcp_namespace(mcp_namespace) if mcp_namespace is not None else memory.get("mcp_namespace")
    selected_project = _validated_project_id(mcp_project) if mcp_project is not None else memory.get("mcp_project")
    if selected_namespace is not None:
        selected_namespace = _validated_mcp_namespace(str(selected_namespace))
    if selected_project is not None:
        selected_project = _validated_project_id(str(selected_project))
    state = {
        "configure-local": "pending_external_verification",
        "use-existing": "pending_existing_verification",
        "defer": "deferred",
        "decline": "disabled",
    }[disposition]
    scope = "user-centralized" if disposition in {"configure-local", "use-existing"} else "none"
    existing_replication = str(memory.get("replication_profile") or DEFAULT_REPLICATION_PROFILE)
    memory.update(
        {
            "enabled": False,
            "state": state,
            "disposition": disposition,
            "provider": "engram",
            "scope": scope,
            "data_dir": persisted_data_dir,
            "replication_profile": existing_replication,
            "mcp_namespace": selected_namespace,
            "mcp_project": selected_project,
        }
    )
    existing_notes = memory.get("notes")
    notes = list(existing_notes) if isinstance(existing_notes, list) else ([str(existing_notes)] if existing_notes else [])
    required_notes = [
        "NAOS memory is local-first and external to the project repository.",
        "Engram uses data_dir/ENGRAM_DATA_DIR and derives the live database as <data_dir>/engram.db.",
        "The maintained replication profile is local; NAOS does not configure Git memory synchronization.",
        "Provider installation, MCP/client configuration, synchronization, and network operations remain explicit external actions.",
        "Memory stays disabled until provider access and the canonical project are independently verified.",
        "Setup never marks memory configured; an authorized maintainer must review active-client access and mem_current_project evidence first.",
        "Never store secrets, credentials, PII, customer data, regulated data, or connection strings in memory.",
    ]
    if legacy_store_path is not None:
        required_notes.append("Legacy store_path was removed from active configuration and retained only as migration metadata; it is not provider storage.")
    if obsolete_fields:
        required_notes.append("Obsolete strict_required/last_check fields were removed; readiness strictness uses the explicit --strict-memory command option and checks remain read-only.")
    for note in required_notes:
        if note not in notes:
            notes.append(note)
    memory["notes"] = notes
    result["memory"] = memory
    return result


def setup(
    project_root: Path,
    disposition: str,
    data_dir: str | Path | None,
    mcp_namespace: str | None,
    mcp_project: str | None,
    write: bool,
    legacy_store_path: str | None = None,
) -> int:
    root = _repo_root(project_root)
    path = _config_file(root)
    _print_header("setup")
    if legacy_store_path is not None:
        print("WARN: --store-path is obsolete and is never used as Engram runtime storage.")
        print("Migration: use --data-dir for the directory containing engram.db; rerun without --store-path after reviewing existing config.")
        if write:
            print("ERROR: refusing to write while --store-path is supplied.")
            return 2
    try:
        _validate_config_destination(root, path)
        existing, config_error = _load_config(root)
        if config_error:
            raise ValueError(config_error)
        config = _merge_setup_config(
            existing,
            disposition=disposition,
            data_dir=data_dir,
            mcp_namespace=mcp_namespace,
            mcp_project=mcp_project,
            root=root,
        )
        rendered = _dump_config(config)
    except (OSError, ValueError):
        print(f"ERROR: refusing to update {CONFIG_PATH}; existing configuration or destination is not safely usable.")
        return 2
    if disposition == "configure-local":
        print("Selected: record pending local provider configuration. NAOS will not install or configure Engram.")
    elif disposition == "use-existing":
        print("Selected: use an existing setup after independent access and project verification; NAOS will not modify it.")
    elif disposition == "decline":
        print("Selected: decline optional memory and retain file-first degraded recovery.")
    else:
        print("Selected: defer optional memory and retain file-first degraded recovery.")
    if _memory_mapping(existing).get("store_path") is not None:
        print("WARN: this rendered update removes legacy store_path from active configuration and retains it under migration metadata.")
    obsolete_fields = [field for field in ("strict_required", "last_check") if field in _memory_mapping(existing)]
    if obsolete_fields:
        print(f"WARN: this rendered update removes obsolete unused fields: {', '.join(obsolete_fields)}.")
    rendered_replication = str(_memory_mapping(config).get("replication_profile") or DEFAULT_REPLICATION_PROFILE)
    if rendered_replication.casefold() != DEFAULT_REPLICATION_PROFILE:
        print("WARN: non-local replication remains unchanged and requires explicit review; NAOS did not normalize it to local.")
    print()
    print(rendered.rstrip())
    print()
    if not write:
        print(f"Dry run only. To write {CONFIG_PATH}, rerun with --write.")
        return 0
    try:
        _atomic_write_config(root, path, rendered)
    except (OSError, ValueError):
        print(f"ERROR: refusing to write {CONFIG_PATH} without a safe atomic destination.")
        return 2
    print(f"Wrote {path}")
    if _memory_mapping(existing).get("store_path") is not None:
        print("Migrated legacy store_path to metadata; it is no longer an active storage setting.")
    print("Next: run `naos memory check`; then verify actual MCP access and mem_current_project in the active client.")
    return 0


def status(project_root: Path) -> int:
    root = _repo_root(project_root)
    config, config_error = _load_config(root)
    _print_header("status")
    if config_error:
        print("Memory config is invalid or unsafe to read. State: unknown.")
        return 2
    if not config:
        print("No NAOS memory config found. State: unknown.")
        print("Recommended: run `naos memory explain` and `naos memory check`.")
        return 0
    memory = _memory_mapping(config)
    data_dir, data_dir_source, _ = _effective_data_dir(memory, root)
    print(f"State:       {memory.get('state', 'unknown')}")
    print(f"Decision:    {memory.get('disposition', 'not recorded')}")
    print(f"Provider:    {memory.get('provider', 'unknown')}")
    print(f"Scope:       {memory.get('scope', 'unknown')}")
    print(f"Data dir:    {_display_path(data_dir)} (source={data_dir_source})")
    print(f"Database:    {_display_path(_database_path(data_dir))} (derived; payload not read)")
    print(f"Replication: {memory.get('replication_profile', DEFAULT_REPLICATION_PROFILE)}")
    replication_profile = str(memory.get("replication_profile") or DEFAULT_REPLICATION_PROFILE)
    if replication_profile.casefold() != DEFAULT_REPLICATION_PROFILE:
        print("WARN: non-local replication is outside the maintained profile and requires explicit review.")
    print(f"Namespace:   {memory.get('mcp_namespace') or 'not detected'}")
    print(f"Project:     {memory.get('mcp_project') or 'not declared'}")
    if memory.get("store_path") is not None:
        print("WARN: legacy store_path is present but ignored; migrate it through a reviewed config change.")
    migration = memory.get("migration")
    if isinstance(migration, dict) and migration.get("legacy_store_path") is not None:
        print(f"Migration:   {migration.get('status', 'recorded')} (legacy store_path metadata only)")
    if memory.get("state") != "configured" or not memory.get("enabled"):
        print("Memory-aware workflows use degraded recovery unless and until provider access is independently verified.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="naos memory",
        description="Explain, check, and record NAOS Engram memory onboarding state",
    )
    parser.add_argument("command", nargs="?", choices=["explain", "check", "setup", "status"], default="explain")
    parser.add_argument("--project-root", default=".", help="Project root to inspect or update")
    decision = parser.add_mutually_exclusive_group()
    decision.add_argument("--disposition", choices=DISPOSITIONS, default=None, help="Optional-memory decision to record")
    decision.add_argument("--mode", choices=tuple(LEGACY_MODES), default=None, help="Legacy alias; use --disposition")
    parser.add_argument("--data-dir", default=None, help="Engram data directory; defaults to ~/.engram in config")
    parser.add_argument("--store-path", default=None, help="Deprecated ambiguous option; never used and rejected with --write")
    parser.add_argument("--mcp-namespace", default=None, help="Verified MCP server or server/tool name; omitted preserves an existing value")
    parser.add_argument("--mcp-project", default=None, help="Exact registered project ID or alias; omitted preserves an existing value and never infers a folder name")
    parser.add_argument("--write", action="store_true", help="Write configs/naos_memory.yaml; default is dry-run")
    args = parser.parse_args()
    disposition = args.disposition or LEGACY_MODES.get(args.mode or "", "configure-local")
    try:
        if args.command == "explain":
            return explain()
        if args.command == "check":
            return check(Path(args.project_root))
        if args.command == "setup":
            if args.mode:
                print(f"WARN: legacy --mode {args.mode} maps to --disposition {disposition}; no provider configuration is performed.")
            return setup(
                Path(args.project_root),
                disposition,
                args.data_dir,
                args.mcp_namespace,
                args.mcp_project,
                args.write,
                args.store_path,
            )
        if args.command == "status":
            return status(Path(args.project_root))
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
