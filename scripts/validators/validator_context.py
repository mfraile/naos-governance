"""Shared validator context helpers."""

from __future__ import annotations

import json
import os
import re
from typing import Any
from pathlib import Path, PurePosixPath, PureWindowsPath


def is_kit_repository(root: Path | None = None) -> bool:
    """Return True when running from the NAOS kit source, not an adopter project."""

    root = root or Path.cwd()
    naos_root = Path(os.getenv("NAOS_ROOT", "naos"))
    return (
        (root / "pyproject.toml").is_file()
        and (root / "naos_init.py").is_file()
        and (root / "templates" / "structural-seeds" / "naos" / "TASK_REGISTRY.yaml").is_file()
        and not (root / naos_root / "TASK_REGISTRY.yaml").is_file()
    )


def print_kit_skip(validator_name: str, reason: str) -> None:
    print(f"{validator_name}: SKIP")
    print(f"  - kit repo context: {reason}")


def has_canonical_kit_sources(root: Path) -> bool:
    """Canonical kit sources remain maintainer scope even with forged state markers."""
    import tomllib
    if not all((root / name).is_file() for name in (
        "pyproject.toml", "naos_init.py", "templates/structural-seeds/naos/TASK_REGISTRY.yaml",
    )):
        return False
    try:
        with (root / "pyproject.toml").open("rb") as handle:
            return tomllib.load(handle).get("project", {}).get("name") == "naos-governance"
    except (OSError, ValueError, TypeError, AttributeError):
        return False


def is_generated_adopter_repository(root: Path | None = None, naos_root: str | Path | None = None) -> bool:
    """Recognize existing generated records; malformed/foreign contracts grant no exclusion.

    Older generated records may carry only the schema identifier. Do not require
    new version/profile fields as an implicit migration of those valid records.
    """
    import json
    import yaml
    root = root or Path.cwd()
    state = Path(naos_root if naos_root is not None else os.getenv("NAOS_ROOT", "naos"))
    if has_canonical_kit_sources(root) or state.is_absolute() or ".." in state.parts:
        return False
    # Presence is not permission to follow a linked marker outside this project.
    import stat
    for relative in (state / "TASK_REGISTRY.yaml", state / "profile_generated_surface_contract.json"):
        cursor = root
        try:
            for part in relative.parts:
                cursor = cursor / part
                info = cursor.lstat()
                if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                    return False
            if not cursor.is_file():
                return False
        except OSError:
            return False
    contract = root / state / "profile_generated_surface_contract.json"
    try:
        data = load_generated_surface_contract(contract)
        registry = yaml.safe_load((root / state / "TASK_REGISTRY.yaml").read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError):
        return False
    return isinstance(registry, dict) and isinstance(registry.get("tasks"), list)


def validation_scope(root: Path, requested: str = "auto") -> str:
    """Resolve documentation scope without allowing real kit checks to be suppressed."""
    if requested not in {"auto", "kit", "project"}:
        raise ValueError("unsupported validation scope")
    if has_canonical_kit_sources(root) or is_kit_repository(root):
        if requested == "project":
            raise ValueError("project scope is unsupported for canonical kit sources; use kit scope")
        return "kit"
    if requested != "auto":
        return requested
    return "project" if is_generated_adopter_repository(root) else "kit"


# Structured records use the existing declared v1 shape and maintainer parser
# predicates; the exact schema-only object is the separately retained legacy form.
PROFILE_ORDER = ("quickstart", "lite", "standard", "assured")
MAKE_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")

def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _validated_relative_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.drive
        or windows.root
        or posix == PurePosixPath(".")
        or ".." in posix.parts
        or "\\" in value
        or posix.as_posix() != value
    ):
        raise ValueError(f"{field} must be a normalized project-relative POSIX path: {value!r}")
    return value


def validate_generated_surface_contract(data: Any, *, allow_legacy: bool = True) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("Generated-surface contract must be a JSON object")
    if data.get("schema") != "naos.profile_generated_surface_contract.v1":
        raise ValueError(f"Unsupported generated-surface contract: {data.get('schema')!r}")
    if allow_legacy and data == {"schema": "naos.profile_generated_surface_contract.v1"}:
        return data
    if set(data) != {"schema", "contract_version", "profiles"}:
        raise ValueError("Generated-surface contract has unexpected or missing top-level fields")
    if type(data.get("contract_version")) is not int or data["contract_version"] != 1:
        raise ValueError("Generated-surface contract version must be exactly 1")
    profiles = data.get("profiles")
    if not isinstance(profiles, dict) or set(profiles) != set(PROFILE_ORDER):
        raise ValueError(f"Generated-surface profiles must contain exactly {PROFILE_ORDER!r}")
    for profile in PROFILE_ORDER:
        entry = profiles[profile]
        if not isinstance(entry, dict) or set(entry) != {
            "required_surfaces", "prohibited_surfaces", "commands"
        }:
            raise ValueError(f"Generated-surface profile {profile!r} has invalid fields")
        for field in ("required_surfaces", "prohibited_surfaces"):
            values = entry[field]
            if (
                not isinstance(values, list)
                or not all(isinstance(value, str) and value for value in values)
                or len(values) != len(set(values))
            ):
                raise ValueError(f"{profile}.{field} must be a unique non-empty string list")
            for index, value in enumerate(values):
                _validated_relative_path(value, f"{profile}.{field}[{index}]")
        if not isinstance(entry["commands"], dict):
            raise ValueError(f"{profile}.commands must be a mapping")
        for command, command_contract in entry["commands"].items():
            if not isinstance(command, str) or not command or not isinstance(command_contract, dict):
                raise ValueError(f"{profile}.commands entries must be named mappings")
            if not MAKE_TARGET_RE.fullmatch(command):
                raise ValueError(
                    f"{profile}.commands key must be a safe Make target name: {command!r}"
                )
            if not set(command_contract) <= {"applicability", "target", "surface", "alternative"}:
                raise ValueError(f"{profile}.commands.{command} has unsupported fields")
            applicability = command_contract.get("applicability")
            if applicability not in {"available", "not_applicable"}:
                raise ValueError(f"{profile}.commands.{command}.applicability is invalid")
            for field in ("target", "alternative"):
                value = command_contract.get(field)
                if field in command_contract and (not isinstance(value, str) or not value):
                    raise ValueError(f"{profile}.commands.{command}.{field} must be a non-empty string")
            target = command_contract.get("target")
            if target is not None and not MAKE_TARGET_RE.fullmatch(target):
                raise ValueError(
                    f"{profile}.commands.{command}.target must be a safe Make target name"
                )
            surface = command_contract.get("surface")
            if "surface" in command_contract:
                _validated_relative_path(surface, f"{profile}.commands.{command}.surface")
            if applicability == "available" and not (
                command_contract.get("target") or command_contract.get("surface")
            ):
                raise ValueError(f"{profile}.commands.{command} needs a target or surface")
            if applicability == "not_applicable" and not command_contract.get("alternative"):
                raise ValueError(f"{profile}.commands.{command} needs an alternative")
    return data


def load_generated_surface_contract(path: Path, *, allow_legacy: bool = True) -> dict[str, Any]:
    return validate_generated_surface_contract(
        json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object),
        allow_legacy=allow_legacy,
    )
