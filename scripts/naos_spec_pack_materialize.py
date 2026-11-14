#!/usr/bin/env python3
"""Materialize profile-required NAOS spec-pack files.

This command copies missing manifest-required spec-pack files from the kit's
template pack into an adopter project's ``specs/`` directory. It is a bounded
setup helper: it does not fill specs, approve specs, promote requirements,
prove readiness, or overwrite existing files. Explicit ``--force`` refuses
selected existing targets.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import sys
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parent))
from naos_policy import (  # noqa: E402
    _open_report_parent_fd,
    default_naos_root,
    finding_counts,
    load_policy,
    normalize_profile,
    report_output_path,
    safe_policy_relative_path,
    severity_for_profile,
    status_from_counts,
    write_report,
)

SCHEMA_ID = "naos.spec_pack_materialization.v2"
MANIFEST_SCHEMA_ID = "naos.spec_pack_manifest.v1"
DEFAULT_MANIFEST_NAME = "spec_manifest.yaml"
STATE_MARKER_PREFIX = ".naos-spec-copy-state-"
_MARKER_NOT_PRECHECKED = object()
MANIFEST_SCHEMA_RELATIVE = Path("schemas/naos/spec_pack_manifest.schema.json")
SUPPORT_FILENAMES = {"README.md", "spec_manifest.yaml"}
SAFE_MANIFEST_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
WINDOWS_DEVICE_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
LIMITATIONS = [
    "Spec-pack materialization copies missing profile-required template files only.",
    "It does not fill, approve, validate, implement, test, certify, or prove specifications.",
    "Existing files are skipped; --force refuses an existing target because safe replacement is unavailable.",
    "Invalid manifests and unsafe source or destination paths block before spec files are changed.",
    "Apply implements native macOS, Linux and Windows leaf operations on CPython 3.11-3.13; other runtime families fail closed.",
    "Requested report paths receive in-project ancestor, regular single-link leaf, and basic writability preflight, but a later report-write failure can occur after spec files were copied; stdout then carries the blocked evidence.",
    "POSIX copies permission bits; Windows copies the read-only attribute and inherits destination-directory ACLs.",
    "Multi-file materialization is sequential and has no rollback; a runtime filesystem failure can leave earlier leaf copies or a clearly reported partial target for review.",
    "Each new copy has a hidden per-target status marker; an unfinished marked target blocks reruns until the operator reviews and removes the partial file and marker together. A deleted completed target can be recopied only when the marker remains writable. This marker is a recovery cue, not an attestation. Crash consistency is not proven.",
    "Qualification is bounded to the recorded native test hosts; network filesystems, hostile concurrent ancestor changes, and crash recovery are not proven.",
]
NOT_CLAIMED = [
    "approved specifications",
    "complete requirements",
    "correct architecture",
    "implemented behavior",
    "passing tests",
    "standard readiness",
    "certification or compliance proof",
]


def path_text(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


class UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that refuses duplicate mapping keys."""


def construct_unique_mapping(
    loader: UniqueKeySafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"Duplicate YAML mapping key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)


def load_yaml(
    path: Path,
    expected_identity: tuple[int, int, int, int, int, int],
) -> dict[str, Any]:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        state = os.fstat(descriptor)
        if not stat.S_ISREG(state.st_mode) or file_identity(state) != expected_identity:
            raise MaterializationRefusal(f"Manifest changed before it could be read: {path}")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            data = yaml.load(handle.read(), Loader=UniqueKeySafeLoader) or {}
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(data, dict):
        raise ValueError(f"YAML file must be a mapping: {path}")
    return data


class MaterializationRefusal(ValueError):
    """A deterministic preflight refusal that must block mutation."""


class MissingSource(MaterializationRefusal):
    """A required source file is absent."""


class RetainedSpecPartial(MaterializationRefusal):
    """A failed new copy may have left the exclusively created target in place."""

    def __init__(self, *, target: Path, identified: bool, cause: Exception) -> None:
        if identified:
            detail = f"possibly incomplete target retained for review at {target}"
        else:
            detail = (
                f"no deletion attempted; last selected name {target}; "
                "possible partial target location unresolved"
            )
        super().__init__(f"Spec copy failed ({cause}); {detail}")
        self.target = target
        self.identified = identified


def lstat_or_none(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def is_link_or_reparse(value: os.stat_result) -> bool:
    """Refuse Windows junctions and other reparse points as well as symlinks."""
    return stat.S_ISLNK(value.st_mode) or bool(
        getattr(value, "st_file_attributes", 0) & 0x400
    )


def file_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        # Windows lstat historically exposes creation time as ctime; fstat
        # can expose change time on 3.12+. Compare explicit birthtime where
        # available so both APIs refer to the same native identity field.
        (getattr(value, "st_birthtime_ns", value.st_ctime_ns)
         if os.name == "nt" else value.st_ctime_ns),
    )


def normalize_manifest_path(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise MaterializationRefusal(f"{field} must be a non-empty path without surrounding whitespace.")
    if "\x00" in value or "\\" in value or value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        raise MaterializationRefusal(f"{field} must be a portable relative POSIX path: {value!r}")
    parts = value.split("/")
    if any(
        part in {"", ".", ".."}
        or part.endswith(".")
        or not SAFE_MANIFEST_SEGMENT.fullmatch(part)
        for part in parts
    ):
        raise MaterializationRefusal(f"{field} contains an unsafe path segment: {value!r}")
    for part in parts:
        if part.split(".", 1)[0].upper() in WINDOWS_DEVICE_NAMES:
            raise MaterializationRefusal(f"{field} contains a reserved Windows device name: {value!r}")
    return value


def normalize_cli_path(value: str, *, field: str) -> Path:
    if not value or "\x00" in value:
        raise MaterializationRefusal(f"{field} must not be empty or contain NUL.")
    if os.sep != "\\" and "\\" in value:
        raise MaterializationRefusal(f"{field} uses a non-native path separator: {value!r}")
    path = Path(value).expanduser()
    if ".." in path.parts:
        raise MaterializationRefusal(f"{field} must not contain parent traversal: {value!r}")
    return path


def require_within(path: Path, root: Path, *, field: str, allow_root: bool = False) -> Path:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise MaterializationRefusal(f"{field} must stay inside project root {root}: {path}") from exc
    if not relative.parts and not allow_root:
        raise MaterializationRefusal(f"{field} must be a child of project root {root}.")
    return relative


def map_in_project_path(
    path: Path,
    *,
    project_root: Path,
    project_input_root: Path,
) -> Path | None:
    """Map a lexical project path onto the canonical project root."""
    try:
        relative = path.relative_to(project_input_root)
    except ValueError:
        try:
            path.relative_to(project_root)
        except ValueError:
            return None
        return path
    return project_root / relative


def validate_directory_chain(root: Path, directory: Path, *, field: str, allow_missing: bool) -> None:
    relative = require_within(directory, root, field=field, allow_root=True)
    root_state = lstat_or_none(root)
    if root_state is None or is_link_or_reparse(root_state) or not stat.S_ISDIR(root_state.st_mode):
        raise MaterializationRefusal(f"{field} root must be an existing non-symlink directory: {root}")
    current = root
    for part in relative.parts:
        current = current / part
        state = lstat_or_none(current)
        if state is None:
            if allow_missing:
                continue
            raise MaterializationRefusal(f"{field} directory is missing: {current}")
        if is_link_or_reparse(state):
            raise MaterializationRefusal(f"{field} directory must not be a symbolic link: {current}")
        if not stat.S_ISDIR(state.st_mode):
            raise MaterializationRefusal(f"{field} path component must be a directory: {current}")


def validate_source_root(candidate: Path) -> Path:
    state = lstat_or_none(candidate)
    if state is None:
        raise MissingSource(f"Source spec root is missing: {candidate}")
    if is_link_or_reparse(state) or not stat.S_ISDIR(state.st_mode):
        raise MaterializationRefusal(f"Source spec root must be a non-symlink directory: {candidate}")
    return candidate.resolve(strict=True)


def inspect_source_file(source_root: Path, source: Path) -> tuple[int, int, int, int, int, int]:
    validate_directory_chain(source_root, source.parent, field="Source", allow_missing=False)
    state = lstat_or_none(source)
    if state is None:
        raise MissingSource(f"Required source template is missing: {source}")
    if is_link_or_reparse(state) or not stat.S_ISREG(state.st_mode):
        raise MaterializationRefusal(f"Required source template must be a regular non-symlink file: {source}")
    return file_identity(state)


def inspect_target_file(
    project_root: Path,
    target: Path,
) -> tuple[bool, tuple[int, int, int, int, int, int] | None]:
    validate_directory_chain(project_root, target.parent, field="Target", allow_missing=True)
    state = lstat_or_none(target)
    if state is None:
        return False, None
    if is_link_or_reparse(state) or not stat.S_ISREG(state.st_mode):
        raise MaterializationRefusal(f"Target must be absent or a regular non-symlink file: {target}")
    return True, file_identity(state)


def copy_state_marker(project_root: Path, target: Path) -> Path:
    """Give each selected target one stable, hidden recovery marker name."""
    relative = require_within(target, project_root, field="Target")
    digest = hashlib.sha256("/".join(relative.parts).encode("utf-8")).hexdigest()
    return target.with_name(f"{STATE_MARKER_PREFIX}{digest}")


def inspect_copy_state_marker(
    project_root: Path, target: Path,
) -> tuple[int | None, tuple[int, int, int, int, int, int] | None]:
    """Size zero means pending; size one means the held copy was verified."""
    marker = copy_state_marker(project_root, target)
    validate_directory_chain(project_root, marker.parent, field="Copy state", allow_missing=True)
    state = lstat_or_none(marker)
    if state is None:
        return None, None
    if (is_link_or_reparse(state) or not stat.S_ISREG(state.st_mode)
            or state.st_nlink != 1 or state.st_size not in {0, 1}):
        raise MaterializationRefusal(f"Copy state marker has unsafe type, links, or size: {marker}")
    return state.st_size, file_identity(state)


def validate_report_output(
    output: Path | None,
    *,
    project_root: Path,
    project_input_root: Path,
    source_root: Path,
    target_root: Path | None,
) -> tuple[Path | None, tuple[int, int, int, int, int, int] | None]:
    if output is None:
        return None, None
    if ".." in output.parts:
        raise MaterializationRefusal(f"Report output must not contain parent traversal: {output}")
    mapped_output = map_in_project_path(
        output,
        project_root=project_root,
        project_input_root=project_input_root,
    )
    in_project_parent = mapped_output.parent if mapped_output is not None else None
    if in_project_parent is not None:
        validate_directory_chain(
            project_root,
            in_project_parent,
            field="Report output",
            allow_missing=True,
        )
    state = lstat_or_none(output)
    if state is not None:
        if is_link_or_reparse(state) or not stat.S_ISREG(state.st_mode):
            raise MaterializationRefusal(f"Report output must be absent or a regular non-symlink file: {output}")
        if state.st_nlink != 1:
            raise MaterializationRefusal(
                f"Existing report output must have exactly one hard link: {output}"
            )
        output_identity = file_identity(state)
    else:
        output_identity = None

    try:
        resolved_output = output.resolve(strict=False)
        resolved_source_root = source_root.resolve(strict=False)
        resolved_target_root = target_root.resolve(strict=False) if target_root is not None else None
    except (OSError, RuntimeError) as exc:
        raise MaterializationRefusal(f"Unable to resolve report output safely: {output}: {exc}") from exc
    if mapped_output is not None and resolved_output != mapped_output:
        raise MaterializationRefusal(
            f"In-project report output changed during resolution: {output}"
        )
    protected_roots = [(resolved_source_root, "source spec root")]
    if resolved_target_root is not None:
        protected_roots.append((resolved_target_root, "target spec root"))
    for protected_root, label in protected_roots:
        if resolved_output == protected_root or protected_root in resolved_output.parents:
            raise MaterializationRefusal(f"Report output must stay outside the {label}: {output}")
    return resolved_output, output_identity


def ensure_report_parent(parent: Path) -> tuple[Any, Any]:
    """Create the canonical parent under held, no-follow directory handles."""
    if os.name == "nt":
        from naos_windows_report import ensure_report_directory

        return ensure_report_directory(parent)
    descriptor, _name = _open_report_parent_fd(
        parent / ".naos-spec-pack-parent-probe", strict_parent_topology=True,
    )
    try:
        state = os.fstat(descriptor)
        return state.st_dev, state.st_ino
    finally:
        os.close(descriptor)


def report_parent_identity(output: Path) -> tuple[Any, Any]:
    """Observe the visible output parent without following a new link."""
    if os.name == "nt":
        from naos_windows_report import report_parent_identity as native_identity

        return native_identity(output)
    descriptor, _name = _open_report_parent_fd(
        output, strict_parent_topology=True, create_parents=False,
    )
    try:
        state = os.fstat(descriptor)
        return state.st_dev, state.st_ino
    finally:
        os.close(descriptor)


def probe_report_output(
    output: Path,
    *,
    project_root: Path,
    project_input_root: Path,
    source_root: Path,
    target_root: Path | None,
) -> tuple[Path, tuple[int, int, int, int, int, int] | None, tuple[Any, Any]]:
    canonical_output, expected_identity = validate_report_output(
        output,
        project_root=project_root,
        project_input_root=project_input_root,
        source_root=source_root,
        target_root=target_root,
    )
    if canonical_output is None:  # pragma: no cover - guarded by the caller
        raise MaterializationRefusal("A report output path is required for preflight.")
    prepared_parent_identity = ensure_report_parent(canonical_output.parent)
    canonical_output, confirmed_identity = validate_report_output(
        canonical_output,
        project_root=project_root,
        project_input_root=project_input_root,
        source_root=source_root,
        target_root=target_root,
    )
    if confirmed_identity != expected_identity:
        raise MaterializationRefusal(f"Report output changed during preflight: {canonical_output}")
    if os.name == "nt":
        from naos_windows_report import probe_strict_report_output

        observed_parent_identity = probe_strict_report_output(
            canonical_output, expect_absent=expected_identity is None,
        )
    else:
        parent_fd, name = _open_report_parent_fd(
            canonical_output, strict_parent_topology=True, create_parents=False,
        )
        descriptor = -1
        try:
            state = os.fstat(parent_fd)
            observed_parent_identity = (state.st_dev, state.st_ino)
            if observed_parent_identity != prepared_parent_identity:
                raise MaterializationRefusal(f"Report parent changed during preflight: {canonical_output.parent}")
            try:
                current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                current = None
            if (file_identity(current) if current is not None else None) != expected_identity:
                raise MaterializationRefusal(f"Report output changed during preflight: {canonical_output}")
            if not os.access(
                ".", os.W_OK | os.X_OK, dir_fd=parent_fd,
                effective_ids=True, follow_symlinks=False,
            ):
                raise MaterializationRefusal(f"Report parent is not writable: {canonical_output.parent}")
            if expected_identity is not None:
                flags = os.O_WRONLY | os.O_NOFOLLOW
                if hasattr(os, "O_CLOEXEC"):
                    flags |= os.O_CLOEXEC
                descriptor = os.open(name, flags, dir_fd=parent_fd)
                if file_identity(os.fstat(descriptor)) != expected_identity:
                    raise MaterializationRefusal(f"Report output changed during preflight: {canonical_output}")
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(parent_fd)
    if observed_parent_identity != prepared_parent_identity:
        raise MaterializationRefusal(f"Report parent changed during preflight: {canonical_output.parent}")
    current_state = lstat_or_none(canonical_output)
    current_identity = file_identity(current_state) if current_state is not None else None
    if current_identity != expected_identity or report_parent_identity(canonical_output) != prepared_parent_identity:
        raise MaterializationRefusal(f"Report output changed during preflight: {canonical_output}")
    return canonical_output, expected_identity, prepared_parent_identity


def load_manifest_schema() -> dict[str, Any]:
    schema_path = Path(__file__).resolve().parents[1] / MANIFEST_SCHEMA_RELATIVE
    schema_state = lstat_or_none(schema_path)
    if schema_state is None or is_link_or_reparse(schema_state) or not stat.S_ISREG(schema_state.st_mode):
        raise MaterializationRefusal(f"Trusted manifest schema must be a regular file: {schema_path}")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return schema


def validate_manifest_schema(manifest: dict[str, Any]) -> None:
    validator = Draft202012Validator(load_manifest_schema())
    errors = sorted(
        validator.iter_errors(manifest),
        key=lambda item: ([str(part) for part in item.absolute_path], item.message),
    )
    if errors:
        messages = []
        for error in errors:
            location = ".".join(str(part) for part in error.absolute_path) or "manifest"
            messages.append(f"{location}: {error.message}")
        raise MaterializationRefusal("Manifest schema validation failed: " + "; ".join(messages))


def validate_profile_graph(manifest: dict[str, Any]) -> None:
    profiles = manifest.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise MaterializationRefusal("Manifest profiles must be a non-empty mapping.")

    for name, block in profiles.items():
        if not isinstance(name, str) or not name:
            raise MaterializationRefusal(f"Manifest profile name must be a non-empty string: {name!r}")
        if not isinstance(block, dict):
            raise MaterializationRefusal(f"Manifest profile {name!r} must be a mapping.")
        has_required = "required_files" in block
        has_inherits = "inherits" in block
        if not has_required and not has_inherits:
            raise MaterializationRefusal(
                f"Manifest profile {name!r} must declare required_files or inherits."
            )
        required: list[str] = []
        if has_required:
            raw_required = block["required_files"]
            if not isinstance(raw_required, list):
                raise MaterializationRefusal(f"Manifest profile {name!r} required_files must be a list.")
            required = [
                normalize_manifest_path(item, field=f"profiles.{name}.required_files[{index}]")
                for index, item in enumerate(raw_required)
            ]
            if len(required) != len({item.casefold() for item in required}):
                raise MaterializationRefusal(f"Manifest profile {name!r} contains duplicate required files.")
        if has_inherits:
            parent = block["inherits"]
            if not isinstance(parent, str) or not parent or parent not in profiles:
                raise MaterializationRefusal(
                    f"Manifest profile {name!r} inherits missing profile {parent!r}."
                )
        elif not required and str(name) != "quickstart":
            raise MaterializationRefusal(f"Manifest profile {name!r} must require at least one file.")

    state: dict[str, str] = {}
    stack: list[str] = []

    def visit(name: str) -> None:
        if state.get(name) == "done":
            return
        if state.get(name) == "visiting":
            cycle_start = stack.index(name)
            cycle = " -> ".join([*stack[cycle_start:], name])
            raise MaterializationRefusal(f"Manifest profile inheritance cycle: {cycle}")
        state[name] = "visiting"
        stack.append(name)
        parent = profiles[name].get("inherits")
        if parent:
            visit(str(parent))
        stack.pop()
        state[name] = "done"

    for profile_name in profiles:
        visit(str(profile_name))


def resolve_profile_manifest(profile: str, manifest: dict[str, Any]) -> list[str]:
    profiles = manifest["profiles"]
    if profile not in profiles:
        raise MaterializationRefusal(f"Manifest does not declare selected profile {profile!r}.")
    current = profile
    seen: list[str] = []
    while True:
        if current in seen:
            cycle = " -> ".join([*seen, current])
            raise MaterializationRefusal(f"Manifest profile inheritance cycle: {cycle}")
        seen.append(current)
        block = profiles.get(current)
        if not isinstance(block, dict):
            raise MaterializationRefusal(f"Manifest profile {current!r} must be a mapping.")
        has_required = "required_files" in block
        has_inherits = "inherits" in block
        if not has_required and not has_inherits:
            raise MaterializationRefusal(
                f"Manifest profile {current!r} must declare required_files or inherits."
            )
        if has_required:
            raw_required = block["required_files"]
            if not isinstance(raw_required, list):
                raise MaterializationRefusal(f"Manifest profile {current!r} required_files must be a list.")
            required = [
                normalize_manifest_path(item, field=f"profiles.{current}.required_files[{index}]")
                for index, item in enumerate(raw_required)
            ]
            if len(required) != len({item.casefold() for item in required}):
                raise MaterializationRefusal(f"Manifest profile {current!r} contains duplicate required files.")
            if required:
                return required
            if not has_inherits:
                if profile != "quickstart":
                    raise MaterializationRefusal(f"Manifest profile {profile!r} must require at least one file.")
                return []
        parent = block["inherits"]
        if not isinstance(parent, str) or not parent or parent not in profiles:
            raise MaterializationRefusal(
                f"Manifest profile {current!r} inherits missing profile {parent!r}."
            )
        current = parent


def validate_manifest_inventory(manifest: dict[str, Any], required_files: list[str]) -> None:
    file_paths: list[str] = []
    file_ids: list[str] = []
    for index, item in enumerate(manifest["files"]):
        file_paths.append(normalize_manifest_path(item["path"], field=f"files[{index}].path"))
        file_ids.append(str(item["id"]))
    if len(file_paths) != len({item.casefold() for item in file_paths}):
        raise MaterializationRefusal("Manifest files contains duplicate path values.")
    if len(file_ids) != len(set(file_ids)):
        raise MaterializationRefusal("Manifest files contains duplicate id values.")
    declared = set(file_paths) | SUPPORT_FILENAMES
    all_required = list(required_files)
    for profile_name, block in manifest["profiles"].items():
        for index, item in enumerate(block.get("required_files") or []):
            all_required.append(
                normalize_manifest_path(item, field=f"profiles.{profile_name}.required_files[{index}]")
            )
    undeclared = sorted(set(all_required) - declared)
    if undeclared:
        raise MaterializationRefusal(
            "Profile requires paths not declared by files or the support-file allowlist: " + ", ".join(undeclared)
        )
    inventories = {"files": file_paths, "selected profile": required_files}
    for profile_name in manifest["profiles"]:
        inventories[f"profile {profile_name!r}"] = resolve_profile_manifest(str(profile_name), manifest)
    for inventory_name, inventory in inventories.items():
        normalized_paths = [tuple(part.casefold() for part in Path(item).parts) for item in inventory]
        for left_index, left in enumerate(normalized_paths):
            for right_index, right in enumerate(normalized_paths):
                if left_index == right_index or len(left) >= len(right):
                    continue
                if right[: len(left)] != left:
                    continue
                raise MaterializationRefusal(
                    f"Manifest {inventory_name} path {inventory[left_index]!r} conflicts with nested path "
                    f"{inventory[right_index]!r}."
                )


def default_source_roots(root: Path, script_root: Path) -> list[Path]:
    return [
        root / "templates" / "spec-kit" / "specs",
        root / "naos" / "spec_templates" / "spec-kit" / "specs",
        script_root.parent / "templates" / "spec-kit" / "specs",
        script_root.parent / "naos" / "spec_templates" / "spec-kit" / "specs",
    ]


def find_source_root(root: Path, explicit: str | None) -> Path:
    if explicit:
        path = Path(explicit)
        return path if path.is_absolute() else root / path
    script_root = Path(__file__).resolve().parent
    for candidate in default_source_roots(root, script_root):
        if (candidate / DEFAULT_MANIFEST_NAME).is_file():
            return candidate
    return root / "templates" / "spec-kit" / "specs"


def finding(
    *,
    profile: str,
    policy: dict[str, Any],
    status: str,
    category: str,
    message: str,
    path: str = "",
    expected: Any = None,
    actual: Any = None,
    blocking: bool = False,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": f"spec_pack_materialization.{status}.{path or category}",
        "severity": "blocking" if blocking else severity_for_profile(profile, policy, advisory=True),
        "status": status,
        "category": category,
        "message": message,
        "human_review_required": True,
        "not_claimed": NOT_CLAIMED,
        "required_next_actions": [
            "Correct the manifest, source, or destination finding and rerun materialization.",
            "Run spec-pack-contract after successful materialization.",
        ],
    }
    if path:
        item["path"] = path
    if expected is not None:
        item["expected"] = expected
    if actual is not None:
        item["actual"] = actual
    return item


def is_spec_file(filename: str) -> bool:
    name = Path(filename).name
    return name.endswith(".md") and len(name) >= 3 and name[:2].isdigit() and name[2] == "-"


def platform_supports_apply() -> bool:
    """Return whether the implemented leaf-install adapter is available."""
    return (
        sys.implementation.name == "cpython"
        and (3, 11) <= sys.version_info[:2] <= (3, 13)
        and ((os.name == "posix" and sys.platform in {"darwin", "linux"})
             or (os.name == "nt" and sys.platform == "win32"))
    )


def safe_mkdir_chain(root: Path, directory: Path) -> None:
    relative = require_within(directory, root, field="Target", allow_root=True)
    current = root
    for part in relative.parts:
        current = current / part
        state = lstat_or_none(current)
        if state is None:
            try:
                current.mkdir()
            except FileExistsError:
                pass
            state = lstat_or_none(current)
        if state is None or is_link_or_reparse(state) or not stat.S_ISDIR(state.st_mode):
            raise MaterializationRefusal(f"Target directory chain became unsafe: {current}")


def _open_spec_parent_posix(
    project_root: Path, target: Path, expected_root: tuple[int, int],
) -> tuple[int, str]:
    """Create and hold the target parent relative to the expected project root."""
    relative = require_within(target, project_root, field="Target")
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise MaterializationRefusal(f"Target contains an unsafe path segment: {target}")
    search = getattr(os, "O_PATH", None) if sys.platform == "linux" else 0x40000000
    if search is None:
        raise MaterializationRefusal("Search-only POSIX directory handles are unavailable")
    flags = search | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    current = os.open(project_root, flags)
    try:
        root_state = os.fstat(current)
        if (not stat.S_ISDIR(root_state.st_mode)
                or (root_state.st_dev, root_state.st_ino) != expected_root):
            raise MaterializationRefusal(f"Project root changed after preflight: {project_root}")
        for part in relative.parts[:-1]:
            try:
                child = os.open(part, flags, dir_fd=current)
            except FileNotFoundError:
                try:
                    os.mkdir(part, dir_fd=current)
                except FileExistsError:
                    pass
                child = os.open(part, flags, dir_fd=current)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise MaterializationRefusal(f"Target directory chain became unsafe: {target.parent}") from exc
                raise
            os.close(current)
            current = child
        return current, relative.name
    except BaseException:
        os.close(current)
        raise


def _spec_target_matches(parent_fd: int, name: str, target_fd: int) -> bool:
    """Check whether the final name still denotes the held, single-link file."""
    try:
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        held = os.fstat(target_fd)
    except OSError:
        return False
    return (stat.S_ISREG(named.st_mode) and named.st_nlink == 1
            and stat.S_ISREG(held.st_mode) and held.st_nlink == 1
            and (named.st_dev, named.st_ino) == (held.st_dev, held.st_ino))


def _spec_target_path_matches(
    project_root: Path, target: Path, expected_root: tuple[int, int],
    parent_fd: int, name: str, target_fd: int,
) -> bool:
    """Identify a retained partial only while its public path is still bound."""
    try:
        validate_directory_chain(
            project_root, target.parent, field="Target", allow_missing=False,
        )
        root = project_root.lstat()
        parent = target.parent.lstat()
        held_parent = os.fstat(parent_fd)
    except (OSError, MaterializationRefusal):
        return False
    return ((root.st_dev, root.st_ino) == expected_root
            and not is_link_or_reparse(root)
            and not is_link_or_reparse(parent)
            and (parent.st_dev, parent.st_ino) == (held_parent.st_dev, held_parent.st_ino)
            and _spec_target_matches(parent_fd, name, target_fd))


def _copy_template_file_posix(
    *, project_root: Path, source: Path, target: Path,
    source_identity: tuple[int, int, int, int, int, int],
    target_identity: tuple[int, int, int, int, int, int] | None,
    marker_identity: tuple[int, int, int, int, int, int] | None,
    project_identity: tuple[int, int] | None,
) -> None:
    root_state = project_root.lstat()
    expected_root = project_identity or (root_state.st_dev, root_state.st_ino)
    if (is_link_or_reparse(root_state) or not stat.S_ISDIR(root_state.st_mode)
            or (root_state.st_dev, root_state.st_ino) != expected_root):
        raise MaterializationRefusal(f"Project root changed after preflight: {project_root}")
    parent_fd, target_name = _open_spec_parent_posix(project_root, target, expected_root)
    marker = copy_state_marker(project_root, target)
    marker_name = marker.name
    source_fd = -1
    target_fd = -1
    marker_fd = -1
    try:
        _, current_identity = inspect_target_file(project_root, target)
        if current_identity != target_identity:
            raise MaterializationRefusal(f"Target changed after preflight: {target}")
        if current_identity is not None:
            raise MaterializationRefusal(f"Existing target cannot be replaced safely: {target}")
        source_leaf = lstat_or_none(source)
        if (source_leaf is None or is_link_or_reparse(source_leaf)
                or file_identity(source_leaf) != source_identity):
            raise MaterializationRefusal(f"Source changed after preflight: {source}")
        source_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_CLOEXEC"):
            source_flags |= os.O_CLOEXEC
        source_flags |= os.O_NOFOLLOW
        try:
            source_fd = os.open(source, source_flags)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise MaterializationRefusal(f"Source became a symbolic link after preflight: {source}") from exc
            raise
        source_state = os.fstat(source_fd)
        if (not stat.S_ISREG(source_state.st_mode)
                or file_identity(source_state) != source_identity):
            raise MaterializationRefusal(f"Source changed after preflight: {source}")

        marker_state, current_marker_identity = inspect_copy_state_marker(project_root, target)
        if current_marker_identity != marker_identity:
            raise MaterializationRefusal(f"Copy state marker changed after preflight: {marker}")
        marker_flags = os.O_WRONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
        if hasattr(os, "O_CLOEXEC"):
            marker_flags |= os.O_CLOEXEC
        if marker_state is None:
            try:
                marker_fd = os.open(
                    marker_name, marker_flags | os.O_CREAT | os.O_EXCL,
                    0o600, dir_fd=parent_fd,
                )
            except FileExistsError as exc:
                raise MaterializationRefusal(f"Copy state marker appeared before create: {marker}") from exc
        else:
            marker_fd = os.open(marker_name, marker_flags, dir_fd=parent_fd)
            held_marker = os.fstat(marker_fd)
            if (file_identity(held_marker) != marker_identity
                    or not stat.S_ISREG(held_marker.st_mode)
                    or held_marker.st_nlink != 1
                    or held_marker.st_size not in {0, 1}):
                raise MaterializationRefusal(f"Copy state marker changed before reuse: {marker}")
            if marker_state == 1:
                if not _spec_target_path_matches(
                    project_root, marker, expected_root, parent_fd, marker_name, marker_fd,
                ):
                    raise MaterializationRefusal(f"Copy state marker name changed: {marker}")
                os.ftruncate(marker_fd, 0)
        os.fsync(marker_fd)
        if (os.fstat(marker_fd).st_size != 0
                or not _spec_target_path_matches(
                    project_root, marker, expected_root, parent_fd, marker_name, marker_fd,
                )):
            raise MaterializationRefusal(f"Pending copy state marker is not bound: {marker}")

        target_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            target_flags |= os.O_CLOEXEC
        try:
            target_fd = os.open(target_name, target_flags, 0o600, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise MaterializationRefusal(f"Target appeared before exclusive copy: {target}") from exc
        with os.fdopen(source_fd, "rb") as source_handle:
            source_fd = -1
            with os.fdopen(os.dup(target_fd), "wb") as target_handle:
                shutil.copyfileobj(source_handle, target_handle)
                if file_identity(os.fstat(source_handle.fileno())) != source_identity:
                    raise MaterializationRefusal(f"Source changed while copying: {source}")
                os.fchmod(target_handle.fileno(), stat.S_IMODE(source_state.st_mode))
                target_handle.flush()
                os.fsync(target_handle.fileno())
                source_digest = hashlib.sha256()
                target_digest = hashlib.sha256()
                for descriptor, digest in (
                    (source_handle.fileno(), source_digest), (target_fd, target_digest),
                ):
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    while block := os.read(descriptor, 1024 * 1024):
                        digest.update(block)
                if source_digest.digest() != target_digest.digest():
                    raise MaterializationRefusal(f"Copied spec bytes differ from source: {target}")
                if file_identity(os.fstat(source_handle.fileno())) != source_identity:
                    raise MaterializationRefusal(f"Source changed during copy verification: {source}")
        os.utime(target_fd, ns=(source_state.st_atime_ns, source_state.st_mtime_ns))

        live_root = project_root.lstat()
        live_parent = target.parent.lstat()
        held_parent = os.fstat(parent_fd)
        if ((live_root.st_dev, live_root.st_ino) != expected_root
                or is_link_or_reparse(live_root)
                or is_link_or_reparse(live_parent)
                or (live_parent.st_dev, live_parent.st_ino)
                != (held_parent.st_dev, held_parent.st_ino)):
            raise MaterializationRefusal(f"Target parent changed while copying: {target.parent}")
        if not _spec_target_matches(parent_fd, target_name, target_fd):
            raise MaterializationRefusal(f"Target changed while copying: {target}")
        if not _spec_target_path_matches(
            project_root, marker, expected_root, parent_fd, marker_name, marker_fd,
        ):
            raise MaterializationRefusal(f"Copy state marker changed while copying: {marker}")
        if os.write(marker_fd, b"C") != 1:
            raise MaterializationRefusal(f"Unable to complete copy state marker: {marker}")
        os.fsync(marker_fd)
        if os.fstat(marker_fd).st_size != 1:
            raise MaterializationRefusal(f"Completed copy state marker has wrong size: {marker}")
    except Exception as exc:
        if target_fd >= 0:
            raise RetainedSpecPartial(
                target=target,
                identified=_spec_target_path_matches(
                    project_root, target, expected_root, parent_fd, target_name, target_fd,
                ),
                cause=exc,
            ) from exc
        if marker_fd >= 0:
            raise MaterializationRefusal(
                f"Copy failed before final target creation; pending state marker remains at {marker}: {exc}"
            ) from exc
        raise
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if target_fd >= 0:
            os.close(target_fd)
        if marker_fd >= 0:
            os.close(marker_fd)
        os.close(parent_fd)


def _copy_template_file_windows(
    *,
    project_root: Path,
    source: Path,
    target: Path,
    source_identity: tuple[int, int, int, int, int, int],
    target_identity: tuple[int, int, int, int, int, int] | None,
    marker_identity: tuple[int, int, int, int, int, int] | None,
    project_identity: tuple[int, int] | None,
) -> None:
    """Stream and publish a spec leaf beneath held, no-reparse Windows parents."""
    from naos_windows_report import _parent, wh

    require_within(target, project_root, field="Target")
    root_state = project_root.lstat()
    expected_root = project_identity or (root_state.st_dev, root_state.st_ino)
    if (is_link_or_reparse(root_state) or not stat.S_ISDIR(root_state.st_mode)
            or (root_state.st_dev, root_state.st_ino) != expected_root):
        raise MaterializationRefusal(f"Project root changed after preflight: {project_root}")
    absolute = os.path.abspath(os.fspath(target))
    wh.validate_root_path(absolute)
    handles = wh.WindowsSpecCopyHandles()
    with ExitStack() as stack:
        parent, name = _parent(handles, stack, absolute)
        held_parent = parent.info().identity
        path_parent_state = target.parent.lstat()
        if is_link_or_reparse(path_parent_state) or not stat.S_ISDIR(path_parent_state.st_mode):
            raise MaterializationRefusal(f"Target parent became unsafe: {target.parent}")
        path_parent_identity = (path_parent_state.st_dev, path_parent_state.st_ino)
        root_state = project_root.lstat()
        if ((root_state.st_dev, root_state.st_ino) != expected_root
                or is_link_or_reparse(root_state)):
            raise MaterializationRefusal(f"Project root changed after preflight: {project_root}")
        _, current_identity = inspect_target_file(project_root, target)
        if current_identity != target_identity:
            raise MaterializationRefusal(f"Target changed after preflight: {target}")

        if current_identity is not None:
            raise MaterializationRefusal(f"Existing target cannot be replaced safely: {target}")

        source_leaf = lstat_or_none(source)
        if (source_leaf is None or is_link_or_reparse(source_leaf)
                or file_identity(source_leaf) != source_identity):
            raise MaterializationRefusal(f"Source changed after preflight: {source}")
        source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        try:
            source_state = os.fstat(source_fd)
            if (not stat.S_ISREG(source_state.st_mode)
                    or file_identity(source_state) != source_identity):
                raise MaterializationRefusal(f"Source changed after preflight: {source}")

            marker = copy_state_marker(project_root, target)
            marker_state, current_marker_identity = inspect_copy_state_marker(project_root, target)
            if current_marker_identity != marker_identity:
                raise MaterializationRefusal(f"Copy state marker changed after preflight: {marker}")
            try:
                if marker_state is None:
                    state_handle = stack.enter_context(
                        handles.create_report_child(parent, marker.name, kind="file")
                    )
                else:
                    state_handle = stack.enter_context(
                        handles.open_child(parent, marker.name, kind="file", for_write=True)
                    )
                    if file_identity(marker.lstat()) != marker_identity:
                        raise MaterializationRefusal(f"Copy state marker changed before reuse: {marker}")
                    state_info = state_handle.info()
                    if state_info.directory or state_info.links != 1 or state_info.size != marker_state:
                        raise MaterializationRefusal(f"Copy state marker has unsafe native metadata: {marker}")
                    if marker_state == 1:
                        handles.reset_spec_copy_marker(state_handle)
                state_handle.flush()
                if state_handle.info().size != 0:
                    raise MaterializationRefusal(f"Pending copy state marker has wrong size: {marker}")
                state_identity = state_handle.info().identity
                marker_path_state = marker.lstat()
                if (is_link_or_reparse(marker_path_state)
                        or not stat.S_ISREG(marker_path_state.st_mode)
                        or marker_path_state.st_nlink != 1):
                    raise MaterializationRefusal(f"Pending copy state marker changed type: {marker}")
                marker_path_identity = (marker_path_state.st_dev, marker_path_state.st_ino)
            except Exception as exc:
                raise MaterializationRefusal(
                    f"Unable to prepare copy state marker; it may remain at {marker}: {exc}"
                ) from exc

            def state_marker_still_named() -> bool:
                try:
                    live_root = project_root.lstat()
                    live_parent = target.parent.lstat()
                    live_marker = marker.lstat()
                    if ((live_root.st_dev, live_root.st_ino) != expected_root
                            or is_link_or_reparse(live_root)
                            or (live_parent.st_dev, live_parent.st_ino) != path_parent_identity
                            or is_link_or_reparse(live_parent)
                            or (live_marker.st_dev, live_marker.st_ino) != marker_path_identity
                            or is_link_or_reparse(live_marker)):
                        return False
                    with handles.open_child(parent, marker.name, kind="file") as named:
                        return named.info().identity == state_identity
                except (OSError, wh.WindowsHandleError, wh.UnsafeWindowsPath):
                    return False

            if not state_marker_still_named():
                raise MaterializationRefusal(f"Pending copy state marker is not bound: {marker}")

            try:
                created = stack.enter_context(handles.create_report_child(parent, name, kind="file"))
            except Exception as exc:
                if isinstance(exc, wh.WindowsHandleError) and exc.ntstatus == 0xC0000035:
                    raise MaterializationRefusal(f"Target appeared before exclusive copy: {target}") from exc
                # Native creation can succeed and then fail its own metadata
                # validation before returning a handle. Its exact child may
                # remain; without that handle we cannot claim its identity.
                raise RetainedSpecPartial(target=target, identified=False, cause=exc) from exc
            created_identity = None
            created_path_identity: tuple[int, int] | None = None

            def created_target_still_named() -> bool:
                try:
                    if (created_identity is None
                            or created_path_identity != file_identity(target.lstat())[:2]):
                        return False
                    with handles.open_child(parent, name, kind="file") as named:
                        return named.info().identity == created_identity
                except (OSError, wh.WindowsHandleError, wh.UnsafeWindowsPath):
                    return False

            try:
                created_identity = created.info().identity
                created_path_identity = file_identity(target.lstat())[:2]
                source_digest = hashlib.sha256()

                class SourceReader:
                    def __init__(self, handle):
                        self.handle = handle

                    def read(self, size):
                        block = self.handle.read(size)
                        source_digest.update(block)
                        return block

                class TargetWriter:
                    def write(self, block):
                        created.write_all(block)
                        return len(block)

                with os.fdopen(source_fd, "rb") as source_handle:
                    source_fd = -1
                    shutil.copyfileobj(SourceReader(source_handle), TargetWriter())
                    if file_identity(os.fstat(source_handle.fileno())) != source_identity:
                        raise MaterializationRefusal(f"Source changed while copying: {source}")
                created.flush()
                if created.info().size != source_state.st_size:
                    raise MaterializationRefusal(f"Copied spec size differs from source: {target}")
                created.seek(0)
                target_digest = hashlib.sha256()
                remaining = source_state.st_size
                while remaining:
                    block = created.read(min(remaining, 1024 * 1024))
                    if not block:
                        raise MaterializationRefusal(f"Copied spec ended early: {target}")
                    target_digest.update(block)
                    remaining -= len(block)
                if target_digest.digest() != source_digest.digest():
                    raise MaterializationRefusal(f"Copied spec bytes differ from source: {target}")

                handles.set_spec_copy_metadata(
                    created,
                    access_ns=source_state.st_atime_ns,
                    write_ns=source_state.st_mtime_ns,
                    readonly=not bool(source_state.st_mode & stat.S_IWRITE),
                )
                created.flush()
                if parent.info().identity != held_parent:
                    raise MaterializationRefusal(f"Target parent changed while copying: {target.parent}")
                live_root = project_root.lstat()
                if ((live_root.st_dev, live_root.st_ino) != expected_root
                        or is_link_or_reparse(live_root)):
                    raise MaterializationRefusal(f"Project root changed while copying: {project_root}")
                if not created_target_still_named():
                    raise MaterializationRefusal(f"Target changed while copying: {target}")
                if not state_marker_still_named():
                    raise MaterializationRefusal(f"Copy state marker changed while copying: {marker}")
                state_handle.seek(0)
                state_handle.write_all(b"C")
                state_handle.flush()
                if state_handle.info().size != 1 or not state_marker_still_named():
                    raise MaterializationRefusal(f"Completed copy state marker is not bound: {marker}")
            except BaseException as primary:
                if isinstance(primary, Exception):
                    raise RetainedSpecPartial(
                        target=target, identified=created_target_still_named(), cause=primary,
                    ) from primary
                raise
        finally:
            if source_fd >= 0:
                os.close(source_fd)


def copy_template_file(
    *,
    project_root: Path,
    source: Path,
    target: Path,
    source_identity: tuple[int, int, int, int, int, int],
    target_identity: tuple[int, int, int, int, int, int] | None,
    marker_identity: tuple[int, int, int, int, int, int] | None | object = _MARKER_NOT_PRECHECKED,
    project_identity: tuple[int, int] | None = None,
) -> None:
    """Exclusively create an absent target and stream through its held handle."""
    if marker_identity is _MARKER_NOT_PRECHECKED:
        _, marker_identity = inspect_copy_state_marker(project_root, target)
    if os.name == "nt":
        return _copy_template_file_windows(
            project_root=project_root, source=source, target=target,
            source_identity=source_identity, target_identity=target_identity,
            marker_identity=marker_identity,
            project_identity=project_identity,
        )
    return _copy_template_file_posix(
        project_root=project_root, source=source, target=target,
        source_identity=source_identity, target_identity=target_identity,
        marker_identity=marker_identity,
        project_identity=project_identity,
    )


def build_report(
    args: argparse.Namespace,
) -> tuple[dict[str, Any], dict[str, Any],
           tuple[tuple[int, int, int, int, int, int] | None, tuple[Any, Any] | None]]:
    project_input_root = Path(args.project_root).expanduser().absolute()
    root = project_input_root.resolve(strict=True)
    root_state = root.lstat()
    if not stat.S_ISDIR(root_state.st_mode):
        raise MaterializationRefusal(f"Project root must be an existing directory: {root}")
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)

    source_candidate = find_source_root(root, args.source_specs_root)
    if not source_candidate.is_absolute():
        source_candidate = root / source_candidate
    source_candidate = source_candidate.absolute()
    source_root = source_candidate
    manifest_path = source_root / DEFAULT_MANIFEST_NAME

    target_value = str(args.target_specs_root or "specs")
    target_input = Path(target_value)
    target_root = target_input if target_input.is_absolute() else root / target_input

    findings: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    operations: list[dict[str, Any]] = []
    manifest: dict[str, Any] = {}
    manifest_identity: tuple[int, int, int, int, int, int] | None = None
    required_files: list[str] = []
    source_root_safe = False
    target_root_safe = False
    target_syntax_safe = False
    manifest_valid = False
    report_output: Path | None = None
    report_output_identity: tuple[int, int, int, int, int, int] | None = None
    report_output_parent_identity: tuple[Any, Any] | None = None
    report_write_allowed = False

    def add_finding(
        *,
        status: str,
        category: str,
        message: str,
        path: Path | None = None,
        expected: Any = None,
        actual: Any = None,
    ) -> None:
        findings.append(
            finding(
                profile=profile,
                policy=policy,
                status=status,
                category=category,
                message=message,
                path=path_text(path, root) if path is not None else "",
                expected=expected,
                actual=actual,
                blocking=True,
            )
        )

    try:
        mapped_source_candidate = map_in_project_path(
            source_candidate,
            project_root=root,
            project_input_root=project_input_root,
        )
        if mapped_source_candidate is not None:
            validate_directory_chain(
                root,
                mapped_source_candidate,
                field="Source",
                allow_missing=True,
            )
        source_root = validate_source_root(source_candidate)
        manifest_path = source_root / DEFAULT_MANIFEST_NAME
        source_root_safe = True
    except MissingSource as exc:
        add_finding(
            status="missing_source",
            category="source_root",
            message=str(exc),
            path=source_candidate,
        )
    except (MaterializationRefusal, OSError) as exc:
        add_finding(
            status="unsafe_path",
            category="source_root",
            message=str(exc),
            path=source_candidate,
        )

    try:
        target_input = normalize_cli_path(target_value, field="target_specs_root")
        target_root = target_input if target_input.is_absolute() else root / target_input
        target_syntax_safe = True
        require_within(target_root, root, field="Target spec root")
        validate_directory_chain(root, target_root, field="Target", allow_missing=True)
        target_root_safe = True
    except (ValueError, OSError, RuntimeError) as exc:
        add_finding(
            status="unsafe_path",
            category="destination_root",
            message=str(exc),
            path=target_root if "\x00" not in target_value else None,
            actual=target_value,
        )

    if source_root_safe and target_root_safe:
        resolved_target_root = target_root.resolve(strict=False)
        if (
            resolved_target_root == source_root
            or source_root in resolved_target_root.parents
            or resolved_target_root in source_root.parents
        ):
            target_root_safe = False
            add_finding(
                status="unsafe_path",
                category="source_target_root_overlap",
                message="Source and target spec roots must not overlap.",
                path=target_root,
            )

    if not platform_supports_apply() and not args.dry_run:
        add_finding(
            status="unsupported_platform",
            category="unsupported_platform",
            message="Spec-pack mutation requires native macOS, Linux or Windows with CPython 3.11-3.13.",
            actual={"os_name": os.name, "sys_platform": sys.platform},
        )

    try:
        if args.output:
            output_candidate = Path(args.output).expanduser()
            if not output_candidate.is_absolute():
                output_candidate = Path.cwd() / output_candidate
            report_output = output_candidate.absolute()
        else:
            default_report_root = Path(naos_root)
            if not default_report_root.is_absolute():
                default_report_root = root / default_report_root
            validate_directory_chain(
                root,
                default_report_root,
                field="Default report",
                allow_missing=True,
            )
            configured_output = report_output_path(
                root,
                naos_root,
                policy,
                "spec_pack_materialization_report",
            )
            if configured_output is not None:
                reports_dir = safe_policy_relative_path(
                    policy.get("paths", {}).get("reports_dir") or "reports",
                    field="reports_dir",
                )
                report_filename = safe_policy_relative_path(
                    policy.get("paths", {}).get("spec_pack_materialization_report")
                    or "spec_pack_materialization_report",
                    field="spec_pack_materialization_report",
                )
                report_output = default_report_root / reports_dir / report_filename
                validate_directory_chain(
                    root,
                    report_output.parent,
                    field="Default report output",
                    allow_missing=True,
                )
        if report_output is not None:
            report_output, report_output_identity, report_output_parent_identity = probe_report_output(
                report_output,
                project_root=root,
                project_input_root=project_input_root,
                source_root=source_root,
                target_root=target_root if target_syntax_safe else None,
            )
            report_write_allowed = True
    except (MaterializationRefusal, ValueError, OSError, RuntimeError) as exc:
        add_finding(
            status="unsafe_path",
            category="report_output",
            message=str(exc),
            path=report_output,
            actual=str(args.output) if args.output else None,
        )

    if source_root_safe:
        try:
            manifest_identity = inspect_source_file(source_root, manifest_path)
            manifest = load_yaml(manifest_path, manifest_identity)
            if report_write_allowed and report_output_identity == manifest_identity:
                report_write_allowed = False
                raise MaterializationRefusal(
                    f"Report output aliases the source manifest and cannot be written safely: {report_output}"
                )
        except MissingSource as exc:
            add_finding(
                status="manifest_load_error",
                category="manifest_contract",
                message=str(exc),
                path=manifest_path,
            )
        except MaterializationRefusal as exc:
            add_finding(
                status="unsafe_path",
                category="manifest_source",
                message=str(exc),
                path=manifest_path,
            )
        except Exception as exc:
            add_finding(
                status="manifest_load_error",
                category="manifest_contract",
                message=f"Unable to load source spec manifest: {exc}",
                path=manifest_path,
            )
        else:
            try:
                validate_manifest_schema(manifest)
                validate_profile_graph(manifest)
                required_files = resolve_profile_manifest(profile, manifest)
                validate_manifest_inventory(manifest, required_files)
                if target_root_safe:
                    selected_targets = {target_root / rel_path for rel_path in required_files}
                    selected_markers = {
                        copy_state_marker(root, target) for target in selected_targets
                    }
                    if selected_targets & selected_markers:
                        raise MaterializationRefusal(
                            "A selected spec path conflicts with a copy state marker path"
                        )
                manifest_valid = True
            except Exception as exc:
                add_finding(
                    status="invalid_manifest",
                    category="manifest_contract",
                    message=str(exc),
                    path=manifest_path,
                    expected=MANIFEST_SCHEMA_ID,
                    actual=manifest.get("schema"),
                )

    if manifest_valid:
        for rel_path in required_files:
            source = source_root / rel_path
            target = target_root / rel_path
            source_identity: tuple[int, int, int, int, int, int] | None = None
            target_identity: tuple[int, int, int, int, int, int] | None = None
            marker_identity: tuple[int, int, int, int, int, int] | None = None
            marker_state: int | None = None
            source_safe = True
            target_safe = target_root_safe
            existed_before = lstat_or_none(target) is not None if target_root_safe else False
            action = "pending"

            try:
                source_identity = inspect_source_file(source_root, source)
                if rel_path == DEFAULT_MANIFEST_NAME and source_identity != manifest_identity:
                    raise MaterializationRefusal(f"Manifest changed after validation: {source}")
            except MissingSource as exc:
                source_safe = False
                action = "missing_source"
                add_finding(
                    status="missing_source",
                    category="source_template",
                    message=str(exc),
                    path=source,
                    expected=rel_path,
                )
            except (MaterializationRefusal, OSError) as exc:
                source_safe = False
                action = "unsafe_path"
                add_finding(
                    status="unsafe_path",
                    category="source_template",
                    message=str(exc),
                    path=source,
                )

            if target_root_safe:
                try:
                    existed_before, target_identity = inspect_target_file(root, target)
                    marker_state, marker_identity = inspect_copy_state_marker(root, target)
                except (MaterializationRefusal, OSError) as exc:
                    target_safe = False
                    action = "unsafe_path"
                    add_finding(
                        status="unsafe_path",
                        category="destination_path",
                        message=str(exc),
                        path=target,
                    )
            else:
                action = "not_applied"

            if target_safe and existed_before and marker_state == 0:
                target_safe = False
                action = "unsafe_path"
                marker = copy_state_marker(root, target)
                add_finding(
                    status="unsafe_path",
                    category="incomplete_prior_copy",
                    message=(f"A previous spec copy did not finish: {target}. Review the file; "
                             f"remove the partial file and its state marker together before retrying."),
                    path=target,
                    actual={"state_marker": path_text(marker, root)},
                )

            if (target_root_safe and report_write_allowed and report_output is not None
                    and report_output == copy_state_marker(root, target)):
                report_write_allowed = False
                target_safe = False
                action = "unsafe_path"
                add_finding(
                    status="unsafe_path",
                    category="report_output_alias",
                    message=f"Report output aliases a spec copy state marker: {report_output}",
                    path=report_output,
                )

            if report_write_allowed and source_identity is not None and report_output_identity == source_identity:
                report_write_allowed = False
                source_safe = False
                action = "unsafe_path"
                add_finding(
                    status="unsafe_path",
                    category="report_output_alias",
                    message=f"Report output aliases a required source file: {report_output}",
                    path=report_output,
                )
            if (
                report_write_allowed
                and target_identity is not None
                and report_output_identity == target_identity
            ):
                report_write_allowed = False
                target_safe = False
                action = "unsafe_path"
                add_finding(
                    status="unsafe_path",
                    category="report_output_alias",
                    message=f"Report output aliases a target file: {report_output}",
                    path=report_output,
                )

            if source_safe and target_safe and existed_before:
                try:
                    if source.samefile(target):
                        source_safe = False
                        target_safe = False
                        action = "unsafe_path"
                        add_finding(
                            status="unsafe_path",
                            category="source_target_alias",
                            message=f"Source and target resolve to the same file: {target}",
                            path=target,
                        )
                except OSError as exc:
                    source_safe = False
                    target_safe = False
                    action = "unsafe_path"
                    add_finding(
                        status="unsafe_path",
                        category="source_target_alias",
                        message=f"Unable to compare source and target identity: {exc}",
                        path=target,
                    )

            if source_safe and target_safe:
                if existed_before:
                    if args.force:
                        action = "unsafe_path"
                        add_finding(
                            status="unsafe_path",
                            category="existing_target_force_refused",
                            message=f"Existing target cannot be replaced safely: {target}",
                            path=target,
                        )
                    else:
                        action = "skipped_existing"
                else:
                    action = "pending_copy"
                    operations.append(
                        {
                            "file_index": len(files),
                            "source": source,
                            "target": target,
                            "source_identity": source_identity,
                            "target_identity": target_identity,
                            "marker_identity": marker_identity,
                        }
                    )

            files.append(
                {
                    "path": path_text(target, root),
                    "source": path_text(source, root),
                    "filename": rel_path,
                    "kind": "spec" if is_spec_file(rel_path) else "support",
                    "required_by_profile": True,
                    "existed_before": existed_before,
                    "action": action,
                    "dry_run": bool(args.dry_run),
                    "force": bool(args.force),
                }
            )

    apply_refused = any(item.get("severity") == "blocking" for item in findings)
    if apply_refused:
        for item in files:
            if item["action"] in {"pending", "pending_copy", "pending_overwrite"}:
                item["action"] = "not_applied"
    elif args.dry_run:
        for item in files:
            if item["action"] == "pending_copy":
                item["action"] = "would_copy"
            elif item["action"] == "pending_overwrite":
                item["action"] = "would_overwrite"
    else:
        for operation_index, operation in enumerate(operations):
            file_item = files[operation["file_index"]]
            try:
                copy_template_file(
                    project_root=root,
                    source=operation["source"],
                    target=operation["target"],
                    source_identity=operation["source_identity"],
                    target_identity=operation["target_identity"],
                    marker_identity=operation["marker_identity"],
                    project_identity=(root_state.st_dev, root_state.st_ino),
                )
            except RetainedSpecPartial as exc:
                file_item["action"] = "copy_failed"
                add_finding(
                    status="copy_failed",
                    category="filesystem_write",
                    message=f"Unable to copy {file_item['filename']}: {exc}",
                    path=exc.target,
                    actual={
                        "partial_target_path_selected": path_text(exc.target, root),
                        "state_marker_path_selected": path_text(
                            copy_state_marker(root, exc.target), root,
                        ),
                        "partial_target_identity_at_failure": (
                            "owned_target" if exc.identified else "unresolved"
                        ),
                        **({"partial_target_path_observed": path_text(exc.target, root)}
                           if exc.identified else {}),
                    },
                )
                for pending in operations[operation_index + 1 :]:
                    files[pending["file_index"]]["action"] = "not_applied"
                apply_refused = True
                break
            except Exception as exc:
                file_item["action"] = "copy_failed"
                add_finding(
                    status="copy_failed",
                    category="filesystem_write",
                    message=f"Unable to copy {file_item['filename']}: {exc}",
                    path=operation["target"],
                    actual={"state_marker_path_selected": path_text(
                        copy_state_marker(root, operation["target"]), root,
                    )},
                )
                for pending in operations[operation_index + 1 :]:
                    files[pending["file_index"]]["action"] = "not_applied"
                apply_refused = True
                break
            else:
                file_item["action"] = "copied"

    counts = finding_counts(findings)
    summary: dict[str, Any] = {
        **counts,
        "required_files": len(required_files),
        "spec_files_required": sum(1 for item in required_files if is_spec_file(item)),
        "support_files_required": sum(1 for item in required_files if not is_spec_file(item)),
        "copied": sum(1 for item in files if item["action"] == "copied"),
        "overwritten": sum(1 for item in files if item["action"] == "overwritten"),
        "skipped_existing": sum(1 for item in files if item["action"] == "skipped_existing"),
        "would_copy": sum(1 for item in files if item["action"] == "would_copy"),
        "would_overwrite": sum(1 for item in files if item["action"] == "would_overwrite"),
        "missing_source": sum(1 for item in findings if item["status"] == "missing_source"),
        "invalid_manifest": sum(
            1 for item in findings if item["status"] in {"invalid_manifest", "manifest_load_error"}
        ),
        "unsafe_paths": sum(1 for item in findings if item["status"] == "unsafe_path"),
        "copy_failed": sum(1 for item in findings if item["status"] == "copy_failed"),
        "copy_cleanup_failed": sum(
            1 for item in findings if item["status"] == "copy_cleanup_failed"
        ),
        "report_write_failed": 0,
        "not_applied": sum(1 for item in files if item["action"] == "not_applied"),
        "apply_refused": apply_refused,
    }
    report = {
        "schema": SCHEMA_ID,
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "profile": profile,
        "status": status_from_counts(summary),
        "project_root": str(root),
        "naos_root": naos_root,
        "source_specs_root": path_text(source_root, root),
        "target_specs_root": path_text(target_root, root),
        "manifest": path_text(manifest_path, root),
        "dry_run": bool(args.dry_run),
        "force": bool(args.force),
        "apply_allowed": not apply_refused,
        "report_output": str(report_output) if report_output is not None else None,
        "report_write_allowed": report_write_allowed,
        "summary": summary,
        "files": files,
        "findings": findings,
        "next_actions": [
            f"Run /naos-design for profile-required specs under {path_text(target_root, root)}.",
            f"Run naos spec-pack-contract --profile {profile}.",
            f"Before planning or coding, run naos spec-pack-contract --profile {profile} --mode filled.",
            f"After specs/tasks/source references exist, run naos spec-cascade --profile {profile}.",
        ],
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": True,
    }
    return report, summary, (report_output_identity, report_output_parent_identity)


def mark_report_write_failure(report: dict[str, Any], exc: Exception) -> None:
    item = {
        "id": "spec_pack_materialization.report_write_failed.report_output",
        "severity": "blocking",
        "status": "report_write_failed",
        "category": "report_output",
        "message": f"Unable to commit materialization report: {exc}",
        "path": str(report.get("report_output") or ""),
        "human_review_required": True,
        "not_claimed": NOT_CLAIMED,
        "required_next_actions": [
            "Preserve stdout evidence, inspect any copied files, correct the report sink, and rerun.",
        ],
    }
    report["findings"].append(item)
    summary = report["summary"]
    summary["blocking"] = int(summary.get("blocking", 0)) + 1
    summary["total_findings"] = int(summary.get("total_findings", 0)) + 1
    summary["report_write_failed"] = int(summary.get("report_write_failed", 0)) + 1
    report["report_write_allowed"] = False
    report["status"] = "blocked"


def format_text_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "NAOS Spec-Pack Materialization",
        "=" * 40,
        f"Profile: {report['profile']}",
        f"Status: {report['status']}",
        f"Dry run: {report['dry_run']}",
        f"Source: {report['source_specs_root']}",
        f"Target: {report['target_specs_root']}",
        "",
        "Summary:",
        f"  Required files: {summary['required_files']}",
        f"  Spec files required: {summary['spec_files_required']}",
        f"  Support files required: {summary['support_files_required']}",
        f"  Copied: {summary['copied']}",
        f"  Overwritten: {summary['overwritten']}",
        f"  Skipped existing: {summary['skipped_existing']}",
        f"  Would copy: {summary['would_copy']}",
        f"  Would overwrite: {summary['would_overwrite']}",
        f"  Missing source: {summary['missing_source']}",
        f"  Invalid manifest: {summary['invalid_manifest']}",
        f"  Unsafe paths: {summary['unsafe_paths']}",
        f"  Copy failures: {summary['copy_failed']}",
        f"  Copy cleanup failures: {summary['copy_cleanup_failed']}",
        f"  Report write failures: {summary['report_write_failed']}",
        f"  Not applied: {summary['not_applied']}",
        f"  Apply allowed: {report['apply_allowed']}",
        f"  Apply refused: {summary['apply_refused']}",
    ]
    if report["findings"]:
        lines.extend(["", "Findings:"])
        for item in report["findings"]:
            lines.append(f"  - [{item['severity']}] {item['status']}: {item['message']}")
    lines.extend(["", "Next actions:"])
    lines.extend(f"  - {item}" for item in report["next_actions"])
    lines.extend(["", "Non-claims:"])
    lines.extend(f"  - {item}" for item in report["not_claimed"])
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Materialize profile-required NAOS spec-pack files.")
    parser.add_argument("project_root", nargs="?", default=".", help="Project root to materialize into.")
    parser.add_argument("--profile", help="Governance profile (quickstart/lite/standard/assured).")
    parser.add_argument("--source-specs-root", help="Source spec template root.")
    parser.add_argument("--target-specs-root", default=os.environ.get("SPECS_ROOT") or "specs", help="Target specs root.")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"), help="NAOS governance root.")
    parser.add_argument("--policy", help="Optional policy YAML path.")
    parser.add_argument("--output", help="Optional output report path.")
    parser.add_argument("--dry-run", action="store_true", help="Preview copies without writing spec files.")
    parser.add_argument("--force", action="store_true", help="Refuse existing spec files; replacement is unsafe.")
    parser.add_argument("--json", action="store_true", help="Print JSON report to stdout.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report, summary, output_preflight = build_report(args)
    except Exception as exc:
        print(f"spec-pack-materialize: {exc}", file=sys.stderr)
        return 1
    output = Path(report["report_output"]) if report.get("report_output") else None
    if report["report_write_allowed"] and output is not None:
        try:
            expected_output_identity, expected_parent_identity = output_preflight
            if expected_parent_identity is None:
                raise MaterializationRefusal("Report parent preflight identity is missing")
            current_output_state = lstat_or_none(output)
            if current_output_state is not None and (
                is_link_or_reparse(current_output_state)
                or not stat.S_ISREG(current_output_state.st_mode)
            ):
                raise MaterializationRefusal(f"Report output became unsafe: {output}")
            current_output_identity = (
                file_identity(current_output_state) if current_output_state is not None else None
            )
            if current_output_identity != expected_output_identity:
                raise MaterializationRefusal(f"Report output changed after preflight: {output}")
            write_report(
                output, report, strict_parent_topology=True,
                expected_parent_identity=expected_parent_identity,
                expect_absent=expected_output_identity is None,
            )
            if report_parent_identity(output) != expected_parent_identity:
                raise MaterializationRefusal(f"Report parent changed during publication: {output.parent}")
        except Exception as exc:
            mark_report_write_failure(report, exc)
            print(f"spec-pack-materialize: unable to commit report: {exc}", file=sys.stderr)
            if args.json:
                print(json.dumps(report, indent=2, sort_keys=False))
            else:
                print(format_text_report(report))
                print("report: NOT_WRITTEN")
            return 1
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=False))
    else:
        print(format_text_report(report))
        print(f"report: {output if report['report_write_allowed'] else 'NOT_WRITTEN'}")
    return 1 if summary.get("apply_refused", False) else 0


if __name__ == "__main__":
    raise SystemExit(main())
