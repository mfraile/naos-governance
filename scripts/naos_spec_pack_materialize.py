#!/usr/bin/env python3
"""Materialize profile-required NAOS spec-pack files.

This command copies missing manifest-required spec-pack files from the kit's
template pack into an adopter project's ``specs/`` directory. It is a bounded
setup helper: it does not fill specs, approve specs, promote requirements,
prove readiness, or overwrite existing files unless ``--force`` is explicit.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parent))
from naos_policy import (  # noqa: E402
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
    "Existing files are skipped unless --force is explicit.",
    "Invalid manifests and unsafe source or destination paths block before spec files are changed.",
    "Apply is enabled only for the executed macOS/POSIX adapter tuple; every other platform tuple fails closed.",
    "Requested report paths receive in-project ancestor, regular single-link leaf, and basic writability preflight, but a later report-write failure can occur after spec files were copied; stdout then carries the blocked evidence.",
    "Multi-file materialization is sequential and has no rollback; a runtime filesystem or post-install cleanup failure can leave the current and earlier same-directory leaf copies in place.",
    "Executed filesystem evidence is macOS-local only; Linux, network filesystems, hostile concurrent ancestor changes, and crash recovery are not proven.",
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


class PublishedCopyCleanupFailure(MaterializationRefusal):
    """A new target was installed but its source temporary could not be removed."""

    def __init__(self, *, target: Path, residue: Path, cause: OSError) -> None:
        super().__init__(
            f"Installed {target}, but temporary cleanup failed; inspect and remove residue "
            f"{residue}: {cause}"
        )
        self.target = target
        self.residue = residue


def lstat_or_none(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def file_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
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
    if root_state is None or stat.S_ISLNK(root_state.st_mode) or not stat.S_ISDIR(root_state.st_mode):
        raise MaterializationRefusal(f"{field} root must be an existing non-symlink directory: {root}")
    current = root
    for part in relative.parts:
        current = current / part
        state = lstat_or_none(current)
        if state is None:
            if allow_missing:
                continue
            raise MaterializationRefusal(f"{field} directory is missing: {current}")
        if stat.S_ISLNK(state.st_mode):
            raise MaterializationRefusal(f"{field} directory must not be a symbolic link: {current}")
        if not stat.S_ISDIR(state.st_mode):
            raise MaterializationRefusal(f"{field} path component must be a directory: {current}")


def validate_source_root(candidate: Path) -> Path:
    state = lstat_or_none(candidate)
    if state is None:
        raise MissingSource(f"Source spec root is missing: {candidate}")
    if stat.S_ISLNK(state.st_mode) or not stat.S_ISDIR(state.st_mode):
        raise MaterializationRefusal(f"Source spec root must be a non-symlink directory: {candidate}")
    return candidate.resolve(strict=True)


def inspect_source_file(source_root: Path, source: Path) -> tuple[int, int, int, int, int, int]:
    validate_directory_chain(source_root, source.parent, field="Source", allow_missing=False)
    state = lstat_or_none(source)
    if state is None:
        raise MissingSource(f"Required source template is missing: {source}")
    if stat.S_ISLNK(state.st_mode) or not stat.S_ISREG(state.st_mode):
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
    if stat.S_ISLNK(state.st_mode) or not stat.S_ISREG(state.st_mode):
        raise MaterializationRefusal(f"Target must be absent or a regular non-symlink file: {target}")
    return True, file_identity(state)


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
        if stat.S_ISLNK(state.st_mode) or not stat.S_ISREG(state.st_mode):
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
    protected_roots = [(resolved_source_root, "source spec root")]
    if resolved_target_root is not None:
        protected_roots.append((resolved_target_root, "target spec root"))
    for protected_root, label in protected_roots:
        if resolved_output == protected_root or protected_root in resolved_output.parents:
            raise MaterializationRefusal(f"Report output must stay outside the {label}: {output}")
    return resolved_output, output_identity


def ensure_report_parent(parent: Path) -> None:
    """Create a canonical report directory chain without following new symlinks."""
    missing: list[Path] = []
    current = parent
    while lstat_or_none(current) is None:
        missing.append(current)
        if current == current.parent:
            break
        current = current.parent
    state = lstat_or_none(current)
    if state is None or stat.S_ISLNK(state.st_mode) or not stat.S_ISDIR(state.st_mode):
        raise MaterializationRefusal(f"Report output ancestor must be a non-symlink directory: {current}")
    for directory in reversed(missing):
        try:
            directory.mkdir()
        except FileExistsError:
            pass
        state = lstat_or_none(directory)
        if state is None or stat.S_ISLNK(state.st_mode) or not stat.S_ISDIR(state.st_mode):
            raise MaterializationRefusal(
                f"Report output directory chain became unsafe: {directory}"
            )
    parent_state = lstat_or_none(parent)
    if parent_state is None or stat.S_ISLNK(parent_state.st_mode) or not stat.S_ISDIR(parent_state.st_mode):
        raise MaterializationRefusal(f"Report output parent must be a non-symlink directory: {parent}")


def probe_report_output(
    output: Path,
    *,
    project_root: Path,
    project_input_root: Path,
    source_root: Path,
    target_root: Path | None,
) -> tuple[Path, tuple[int, int, int, int, int, int] | None]:
    canonical_output, expected_identity = validate_report_output(
        output,
        project_root=project_root,
        project_input_root=project_input_root,
        source_root=source_root,
        target_root=target_root,
    )
    if canonical_output is None:  # pragma: no cover - guarded by the caller
        raise MaterializationRefusal("A report output path is required for preflight.")
    ensure_report_parent(canonical_output.parent)
    canonical_output, confirmed_identity = validate_report_output(
        canonical_output,
        project_root=project_root,
        project_input_root=project_input_root,
        source_root=source_root,
        target_root=target_root,
    )
    if confirmed_identity != expected_identity:
        raise MaterializationRefusal(f"Report output changed during preflight: {canonical_output}")
    descriptor = -1
    temporary: Path | None = None
    try:
        if expected_identity is None:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".naos-spec-pack-report-probe-",
                dir=canonical_output.parent,
            )
            temporary = Path(temporary_name)
        else:
            flags = os.O_WRONLY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(canonical_output, flags)
        current_state = lstat_or_none(canonical_output)
        current_identity = file_identity(current_state) if current_state is not None else None
        if current_identity != expected_identity:
            raise MaterializationRefusal(f"Report output changed during preflight: {canonical_output}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink()
    return canonical_output, expected_identity


def load_manifest_schema() -> dict[str, Any]:
    schema_path = Path(__file__).resolve().parents[1] / MANIFEST_SCHEMA_RELATIVE
    schema_state = lstat_or_none(schema_path)
    if schema_state is None or stat.S_ISLNK(schema_state.st_mode) or not stat.S_ISREG(schema_state.st_mode):
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
    return os.name == "posix" and sys.platform == "darwin"


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
        if state is None or stat.S_ISLNK(state.st_mode) or not stat.S_ISDIR(state.st_mode):
            raise MaterializationRefusal(f"Target directory chain became unsafe: {current}")


def copy_template_file(
    *,
    project_root: Path,
    source: Path,
    target: Path,
    source_identity: tuple[int, int, int, int, int, int],
    target_identity: tuple[int, int, int, int, int, int] | None,
) -> None:
    """Copy one file through a same-directory temporary and atomic leaf install."""
    safe_mkdir_chain(project_root, target.parent)
    _, current_target_identity = inspect_target_file(project_root, target)
    if current_target_identity != target_identity:
        raise MaterializationRefusal(f"Target changed after preflight: {target}")

    source_flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        source_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
    try:
        source_fd = os.open(source, source_flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise MaterializationRefusal(f"Source became a symbolic link after preflight: {source}") from exc
        raise
    source_state = os.fstat(source_fd)
    if not stat.S_ISREG(source_state.st_mode) or file_identity(source_state) != source_identity:
        os.close(source_fd)
        raise MaterializationRefusal(f"Source changed after preflight: {source}")

    temp_fd = -1
    temp_path: Path | None = None
    try:
        temp_fd, temp_name = tempfile.mkstemp(prefix=".naos-spec-pack-", dir=target.parent)
        temp_path = Path(temp_name)
        validate_directory_chain(project_root, target.parent, field="Target", allow_missing=False)
        with os.fdopen(source_fd, "rb") as source_handle, os.fdopen(temp_fd, "wb") as target_handle:
            source_fd = -1
            temp_fd = -1
            shutil.copyfileobj(source_handle, target_handle)
            os.fchmod(target_handle.fileno(), stat.S_IMODE(source_state.st_mode))
            target_handle.flush()
            os.fsync(target_handle.fileno())
        os.utime(
            temp_path,
            ns=(source_state.st_atime_ns, source_state.st_mtime_ns),
            follow_symlinks=False,
        )

        _, current_target_identity = inspect_target_file(project_root, target)
        if current_target_identity != target_identity:
            raise MaterializationRefusal(f"Target changed while copying: {target}")
        if target_identity is None:
            try:
                os.link(temp_path, target, follow_symlinks=False)
            except FileExistsError as exc:
                raise MaterializationRefusal(f"Target appeared while copying: {target}") from exc
            try:
                temp_path.unlink()
            except OSError as exc:
                residue = temp_path
                temp_path = None
                raise PublishedCopyCleanupFailure(
                    target=target,
                    residue=residue,
                    cause=exc,
                ) from exc
        else:
            os.replace(temp_path, target)
        temp_path = None
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if temp_fd >= 0:
            os.close(temp_fd)
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError as exc:
                raise MaterializationRefusal(
                    f"Temporary copy cleanup failed; inspect and remove residue {temp_path}: {exc}"
                ) from exc


def build_report(
    args: argparse.Namespace,
) -> tuple[dict[str, Any], dict[str, Any], tuple[int, int, int, int, int, int] | None]:
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
            status="unsafe_path",
            category="unsupported_platform",
            message="Spec-pack mutation is available only for the executed macOS/POSIX adapter tuple.",
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
            report_output, report_output_identity = probe_report_output(
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
                if existed_before and not args.force:
                    action = "skipped_existing"
                else:
                    action = "pending_overwrite" if existed_before else "pending_copy"
                    operations.append(
                        {
                            "file_index": len(files),
                            "source": source,
                            "target": target,
                            "source_identity": source_identity,
                            "target_identity": target_identity,
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
                )
            except PublishedCopyCleanupFailure as exc:
                file_item["action"] = "copied"
                add_finding(
                    status="copy_cleanup_failed",
                    category="temporary_cleanup_after_publish",
                    message=str(exc),
                    path=exc.residue,
                    actual=path_text(exc.target, root),
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
                )
                for pending in operations[operation_index + 1 :]:
                    files[pending["file_index"]]["action"] = "not_applied"
                apply_refused = True
                break
            else:
                file_item["action"] = "overwritten" if operation["target_identity"] is not None else "copied"

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
    return report, summary, report_output_identity


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
    parser.add_argument("--force", action="store_true", help="Overwrite existing spec files.")
    parser.add_argument("--json", action="store_true", help="Print JSON report to stdout.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report, summary, expected_output_identity = build_report(args)
    except Exception as exc:
        print(f"spec-pack-materialize: {exc}", file=sys.stderr)
        return 1
    output = Path(report["report_output"]) if report.get("report_output") else None
    if report["report_write_allowed"] and output is not None:
        try:
            current_output_state = lstat_or_none(output)
            if current_output_state is not None and (
                stat.S_ISLNK(current_output_state.st_mode)
                or not stat.S_ISREG(current_output_state.st_mode)
            ):
                raise MaterializationRefusal(f"Report output became unsafe: {output}")
            current_output_identity = (
                file_identity(current_output_state) if current_output_state is not None else None
            )
            if current_output_identity != expected_output_identity:
                raise MaterializationRefusal(f"Report output changed after preflight: {output}")
            write_report(output, report)
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
