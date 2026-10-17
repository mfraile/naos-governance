#!/usr/bin/env python3
"""Shared helpers for NAOS Markdown frontmatter validators."""

from __future__ import annotations

import argparse
import json
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable

import yaml  # type: ignore[import-untyped]


@dataclass(frozen=True)
class FrontmatterDocument:
    path: Path
    data: dict[str, Any]
    body: str
    error: str | None = None


@dataclass(frozen=True)
class ValidationResult:
    path: Path
    check: str
    passed: bool
    message: str


def parse_frontmatter(path: Path, *, allow_missing: bool = False) -> FrontmatterDocument:
    """Parse the top YAML frontmatter block from a Markdown file."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        return FrontmatterDocument(path=path, data={}, body="", error=f"cannot read file: {exc}")

    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return FrontmatterDocument(path=path, data={}, body=text, error=None if allow_missing else "missing top YAML frontmatter block")

    end_index: int | None = None
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            end_index = index
            break
    if end_index is None:
        return FrontmatterDocument(path=path, data={}, body=text, error="unterminated YAML frontmatter block")

    raw_frontmatter = "\n".join(lines[1:end_index])
    body = "\n".join(lines[end_index + 1 :])
    try:
        parsed = yaml.safe_load(raw_frontmatter) if raw_frontmatter.strip() else {}
    except yaml.YAMLError as exc:
        return FrontmatterDocument(path=path, data={}, body=body, error=f"invalid YAML frontmatter: {exc}")
    if not isinstance(parsed, dict):
        return FrontmatterDocument(path=path, data={}, body=body, error="frontmatter must be a YAML mapping")
    return FrontmatterDocument(path=path, data=parsed, body=body)


def is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())



def model_selector_is_valid(metadata: dict) -> bool:
    """Validate declaration shape, not model availability or policy approval.

    Omission preserves the host's selected/inherited model. VS Code supports a
    scalar or prioritized list; GitHub's own agent format documents a scalar.
    Host-only metadata scope remains separate from this NAOS authoring check.
    """
    if "model" not in metadata:
        return True
    value = metadata["model"]
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list) and metadata.get("target") != "github-copilot":
        values = value
    else:
        return False
    return bool(values) and all(
        is_non_empty_string(item) and "[ADAPT" not in item.upper()
        for item in values
    )


# Agent Skills specification, verified 2026-10-16. These checks apply only to
# NAOS-authored skills; scoped host declarations retain their separate contract.
SKILL_FRONTMATTER_FIELDS = frozenset({
    "name", "description", "license", "compatibility", "metadata", "allowed-tools",
})


def skill_authoring_metadata(data: dict[str, Any]) -> tuple[list[dict[str, Any]], str | None]:
    """Decode namespaced declarations without coercion or implied host authority.

    Agent Skills metadata values are strings. naos-parameters holds a JSON list;
    omission means no declared inputs. naos-extends is a manual base reference.
    """
    if set(data) - SKILL_FRONTMATTER_FIELDS:
        raise ValueError("skill frontmatter contains unsupported top-level fields")
    metadata = data.get("metadata", {})
    if not isinstance(metadata, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in metadata.items()):
        raise ValueError("skill metadata must map string keys to string values")
    for key in ("license", "allowed-tools"):
        if key in data and not isinstance(data[key], str):
            raise ValueError(f"skill {key} must be a string")
    if "compatibility" in data and (not is_non_empty_string(data["compatibility"])
            or len(data["compatibility"]) > 500):
        raise ValueError("skill compatibility must be a non-empty string of at most 500 characters")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key in naos-parameters JSON")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise ValueError("non-finite value in naos-parameters JSON")

    try:
        parameters = json.loads(metadata.get("naos-parameters", "[]"),
                                object_pairs_hook=unique_object, parse_constant=reject_constant)
        # Numeric overflow (e.g. 1e999) must not become a nonportable infinity.
        json.dumps(parameters, allow_nan=False)
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError("naos-parameters must contain a finite JSON list") from exc
    if not isinstance(parameters, list):
        raise ValueError("naos-parameters must contain a JSON list")
    names: set[str] = set()
    for entry in parameters:
        if (not isinstance(entry, dict) or not is_non_empty_string(entry.get("name"))
                or not is_non_empty_string(entry.get("description"))):
            raise ValueError("each skill parameter requires non-empty name and description")
        name = entry["name"].strip()
        if name in names:
            raise ValueError("Portable adapter requires unique authoring input names")
        names.add(name)
        if "required" in entry and not isinstance(entry["required"], bool):
            raise ValueError("skill parameter required must be a boolean")
    base = metadata.get("naos-extends")
    if base is not None and not is_non_empty_string(base):
        raise ValueError("naos-extends must be a non-empty manual base reference")
    return parameters, base


def is_non_empty_string_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(is_non_empty_string(item) for item in value)


def display_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def candidate_files(root: Path, kit_pattern: str, generated_pattern: str) -> list[Path]:
    """Return kit-template files when present, otherwise generated-project files."""
    kit_files = sorted(root.glob(kit_pattern))
    if kit_files:
        return [path for path in kit_files if path.is_file()]
    return sorted(path for path in root.glob(generated_pattern) if path.is_file())


def collect_markdown_targets(inputs: Iterable[str], default_files: list[Path]) -> list[Path]:
    """Resolve CLI roots/files into Markdown files; use defaults when no inputs are given."""
    raw_inputs = list(inputs)
    if not raw_inputs:
        return default_files

    targets: list[Path] = []
    for raw in raw_inputs:
        path = Path(raw).resolve()
        if path.is_file():
            targets.append(path)
        elif path.is_dir():
            targets.extend(sorted(child for child in path.rglob("*.md") if child.is_file()))
    return targets


def print_results(title: str, root: Path, results: list[ValidationResult]) -> int:
    warnings = [result for result in results if result.message.startswith("WARNING: ")]
    for result in warnings:
        print(f"  - WARNING {display_path(result.path, root)}: {result.check}: {result.message[9:]}")
    failures = [result for result in results if not result.passed]
    if failures:
        print(f"{title}: FAIL")
        for result in failures:
            rel = display_path(result.path, root)
            print(f"  - {rel}: {result.check}: {result.message}")
        return 1

    print(f"{title}: PASS — {len(results)} checks")
    return 0


def build_root_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "paths",
        nargs="*",
        help="Optional files or directories to validate. Defaults to known NAOS template/generated locations.",
    )
    parser.add_argument(
        "--root",
        default=".",
        metavar="PATH",
        help="Repository or generated project root used for default discovery and relative output.",
    )
    return parser


METADATA_SCOPE_PATH = Path("naos/ai_metadata_scope.yaml")


class MetadataScopeError(ValueError):
    """Invalid adopter declaration; no ownership or vendor authority implied."""


class _ScopeLoader(yaml.SafeLoader):
    pass


def _scope_mapping(loader: Any, node: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise MetadataScopeError("metadata scope has non-string or duplicate mapping keys")
        result[key] = loader.construct_object(value_node)
    return result


_ScopeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _scope_mapping)


def host_skill_format(relative: str) -> str | None:
    parts = relative.split("/")
    if (len(parts) == 4 and parts[1] == "skills" and parts[2] not in {"", ".", ".."}
            and parts[3] == "SKILL.md" and not any(c in relative for c in "\\:*?[]")
            and not any(ord(c) < 32 or 127 <= ord(c) < 160 for c in relative)
            and not any(part.endswith((" ", ".")) for part in parts)):
        if parts[0] == ".agents":
            return "portable_skill"
        if parts[0] == ".claude":
            return "claude_skill"
    return None


def host_surface_kind(relative: str) -> str | None:
    if host_skill_format(relative) is not None:
        return "skill"
    if relative.startswith(".github/agents/") and relative.endswith(".agent.md"):
        return "agent"
    if relative.startswith(".github/skills/") and relative.endswith("/SKILL.md"):
        return "skill"
    if relative.startswith(".github/instructions/") and relative.endswith(".instructions.md"):
        return "instruction"
    return None


def _host_entry_stat(path: Path, relative: str):
    """Inspect lexical directory entries before any target-following query."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise MetadataScopeError(f"cannot inspect host metadata path {relative}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise MetadataScopeError(f"host metadata refuses symlink/reparse paths: {relative}")
    return info


def _exact_host_component(path: Path, relative: str):
    info = _host_entry_stat(path, relative)
    if info is not None:
        try:
            exact = any(entry.name == path.name for entry in path.parent.iterdir())
        except OSError as exc:
            raise MetadataScopeError(f"cannot inspect exact host path spelling: {relative}") from exc
        if not exact:
            raise MetadataScopeError(f"host metadata refuses case aliases: {relative}")
    return info


def _literal_bounded_file(root: Path, relative: str) -> Path:
    # Same literal grammar as naos_ai_surfaces.literal_path, without coupling
    # the small standalone validators to another runtime module.
    parts = relative.split("/")
    if (not relative or relative != relative.strip()
            or any(ord(character) < 32 or 127 <= ord(character) < 160 for character in relative)
            or PurePosixPath(relative).is_absolute() or PureWindowsPath(relative).anchor
            or any(character in relative for character in "\\:*?[]")
            or any(part in {"", ".", ".."} or part.endswith((" ", ".")) for part in parts)):
        raise MetadataScopeError(f"metadata scope requires an exact portable relative path: {relative!r}")
    path = root / relative
    current = root
    exact_host = host_skill_format(relative) is not None
    info = None
    for index, part in enumerate(parts):
        current = current / part
        # Fixed schema components are case-exact; adopter directory identity
        # follows the Unicode/NFKC floor instead of raw filesystem normalization.
        fixed_component = exact_host and index in {0, 1, len(parts) - 1}
        info = (_exact_host_component(current, relative) if fixed_component
                else _host_entry_stat(current, relative))
    if info is None or not stat.S_ISREG(info.st_mode):
        raise MetadataScopeError(f"metadata scope file is missing or not regular: {relative}")
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise MetadataScopeError(f"metadata scope path escapes root: {relative}") from exc
    return path


def load_metadata_scope(root: Path) -> dict[Path, str]:
    """Read exact host declarations; absence preserves strict NAOS defaults.

    This selects metadata checks only. It never proves ownership, custody,
    provenance, vendor compatibility, tool permission, or runtime behavior.
    Kit templates cannot be exempted through this declaration.
    """
    config = root / METADATA_SCOPE_PATH
    cursor = root
    for part in METADATA_SCOPE_PATH.parts:
        cursor /= part
        if _host_entry_stat(cursor, METADATA_SCOPE_PATH.as_posix()) is None:
            return {}
    _literal_bounded_file(root, METADATA_SCOPE_PATH.as_posix())
    try:
        data = yaml.load(config.read_text(encoding="utf-8"), Loader=_ScopeLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise MetadataScopeError(f"invalid metadata scope: {exc}") from exc
    if (not isinstance(data, dict) or set(data) != {"schema_version", "host_paths"}
            or type(data["schema_version"]) is not int or data["schema_version"] != 1
            or not isinstance(data["host_paths"], list)):
        raise MetadataScopeError("metadata scope requires schema_version: 1 and host_paths: [exact paths]")
    result: dict[Path, str] = {}
    seen_portable: set[str] = set()
    for relative in data["host_paths"]:
        if not isinstance(relative, str):
            raise MetadataScopeError("metadata scope host paths must be strings")
        path = _literal_bounded_file(root, relative)
        kind = host_surface_kind(relative)
        if kind is None:
            raise MetadataScopeError(f"metadata scope path is not a supported generated host surface: {relative}")
        path = path.resolve()
        if path in result or relative.casefold() in seen_portable:
            raise MetadataScopeError(f"duplicate metadata scope host path: {relative}")
        seen_portable.add(relative.casefold())
        result[path] = kind
    return result


def automatic_host_skill_files(root: Path) -> list[Path]:
    """Discover only immediate host skill directories, refusing linked topology."""
    files: list[Path] = []
    seen: set[str] = set()
    for prefix in (".agents/skills", ".claude/skills"):
        base = root / prefix
        cursor = root
        info = None
        for part in prefix.split("/"):
            cursor /= part
            info = _exact_host_component(cursor, prefix)
            if info is None:
                break
            if not stat.S_ISDIR(info.st_mode):
                raise MetadataScopeError(f"host skill root must be a directory: {prefix}")
        if info is None:
            continue
        for child in sorted(base.iterdir(), key=lambda item: item.name):
            child_info = _host_entry_stat(child, child.relative_to(root).as_posix())
            if child_info is None:
                raise MetadataScopeError("host skill directory changed during discovery")
            if not stat.S_ISDIR(child_info.st_mode):
                continue
            path = child / "SKILL.md"
            info = _exact_host_component(path, path.relative_to(root).as_posix())
            if info is None:
                continue
            relative = path.relative_to(root).as_posix()
            _literal_bounded_file(root, relative)
            portable_key = unicodedata.normalize("NFKC", relative).casefold()
            if portable_key in seen:
                raise MetadataScopeError(f"host skill paths alias under portable case comparison: {relative}")
            seen.add(portable_key)
            files.append(path)
    return files


def metadata_host_paths(root: Path) -> dict[Path, str]:
    """Union explicit declarations with fixed host formats; no capability authority."""
    scope = load_metadata_scope(root)
    for path in automatic_host_skill_files(root):
        scope[path.resolve()] = "skill"
    return scope


def portable_skill_identity_errors(path: Path, document: FrontmatterDocument) -> list[str]:
    """A local portable identity floor, not full host/spec conformance."""
    errors = []
    name = document.data.get("name")
    if not is_non_empty_string(name):
        errors.append("name must be a nonempty string")
    else:
        normalized = unicodedata.normalize("NFKC", name.strip())
        if (len(normalized) > 64 or normalized != normalized.lower()
                or normalized.startswith("-") or normalized.endswith("-") or "--" in normalized
                or not all(character.isalnum() or character == "-" for character in normalized)
                or unicodedata.normalize("NFKC", path.parent.name) != normalized):
            errors.append("name must match its NFKC-normalized directory and use at most 64 lowercase Unicode letters/digits with single internal hyphens")
    description = document.data.get("description")
    if not is_non_empty_string(description) or len(description) > 1024:
        errors.append("description must be a nonempty string of at most 1024 characters")
    return errors


def host_declaration(path: Path, root: Path, kind: str) -> dict[str, Any]:
    try:
        relative = path.absolute().relative_to(root.absolute()).as_posix()
    except ValueError:
        try:
            relative = path.absolute().relative_to(root.resolve()).as_posix()
        except ValueError as exc:
            raise MetadataScopeError("host declaration must remain inside the project root") from exc
    _literal_bounded_file(root, relative)
    skill_format = host_skill_format(relative)
    document = parse_frontmatter(path, allow_missing=skill_format != "portable_skill")
    if document.error:
        raise MetadataScopeError(f"{display_path(path, root)}: {document.error}")
    if skill_format == "portable_skill":
        errors = portable_skill_identity_errors(path, document)
        if errors:
            raise MetadataScopeError(f"{relative}: " + "; ".join(errors))
    declared: dict[str, Any] = {}
    omitted: list[str] = []
    # Preserve portable optional declarations, without validating a host profile.
    # Unrelated metadata (including NAOS-only parameters) has no NAOS requirements.
    for key in ("name", "description", "model", "tools", "applyTo", "license", "compatibility", "metadata",
                "allowed-tools", "disable-model-invocation", "user-invocable", "argument-hint", "context", "agent"):
        if key not in document.data:
            continue
        try:
            declared[key] = json.loads(json.dumps(document.data[key], allow_nan=False))
        except (TypeError, ValueError, RecursionError):
            omitted.append(key)
    result = {"source_file": path.resolve().relative_to(root.resolve()).as_posix(),
              "type": kind, "status": "declared_host", "metadata_scope": skill_format or "adopter_declared",
              "declarations": declared}
    if omitted:
        result["nonportable_fields_omitted"] = omitted
    return result


def scoped_frontmatter_results(paths: list[Path], root: Path | None, kind: str,
                               strict_validator: Any) -> list[ValidationResult]:
    scope = metadata_host_paths(root) if root is not None else {}
    results: list[ValidationResult] = []
    for path in paths:
        if scope.get(path.resolve()) == kind:
            try:
                host_declaration(path, root, kind)
                results.append(ValidationResult(path, "host-declaration", True,
                    "Host metadata scope only; no NAOS capability, ownership, vendor or runtime validity asserted"))
            except MetadataScopeError as exc:
                results.append(ValidationResult(path, "host-declaration", False, str(exc)))
        else:
            results.extend(strict_validator(path))
    return results
