"""Strict reviewed generator recipes and exact pre-output instance artifacts.

Instances describe inputs and decisions, not trusted execution or ownership.
The historical portable codec only validates their six-field content rows.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .canonical import CanonicalizationError, canonical_bytes, canonical_sha256, loads_strict_json
from .portable_provenance import PortableProvenanceError, _path, _unique_paths
from .source_modes import SourceModeError


SCHEMA = "naos.upgrade.generated_source_recipes.v1"
INSTANCE_SCHEMA = "naos.upgrade.generated_recipe_instance.v1"
MAX_STATIC_BYTES = 64 * 1024
MAX_IMPLEMENTATION_BYTES = 1024 * 1024
MAX_INSTANCE_BYTES = 1024 * 1024
MAX_INPUTS = 4096
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_TOTAL_INPUT_BYTES = 64 * 1024 * 1024
MAX_DECISIONS = 32
MAX_JSON_TOKENS = 50_000
MAX_JSON_DEPTH = 32
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
DECISION_KEY = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
IMPLEMENTATIONS = {
    "catalogue": ("naos_init.py", "scripts/naos_emit_capabilities.py",
                  "scripts/validators/frontmatter_utils.py"),
    "host_adapter": ("naos_init.py", "scripts/validators/frontmatter_utils.py"),
    "lf_policy": ("naos_init.py",),
    "overlay_report": ("naos_init.py",),
    "ruff_boundary": ("naos_init.py",),
    "traceability_tool_content": (
        "naos_init.py", "scripts/validators/validate_traceability_headers.py",
    ),
}
DESTINATIONS = {
    "catalogue": "configs/naos_ai_surface_catalogue.yaml",
    "lf_policy": ".gitattributes",
    "overlay_report": "naos/overlay_compatibility.json",
}
RUFF_ROOTS = frozenset({"scripts", "naos_tools", "autoresearch",
                        ".github/autoresearch", ".github", "naos", "schemas"})


def bounded_canonical_input(value: Any) -> bytes:
    """Bound nested decision/observation work before canonical allocation."""
    stack = [(value, 0)]
    tokens = text_bytes = 0
    while stack:
        current, depth = stack.pop()
        tokens += 1
        if tokens > MAX_JSON_TOKENS or depth > MAX_JSON_DEPTH:
            raise SourceModeError("Generated recipe JSON input exceeds structure bound")
        if type(current) is dict:
            if len(current) > MAX_JSON_TOKENS - tokens - len(stack):
                raise SourceModeError("Generated recipe JSON input exceeds structure bound")
            for key, item in current.items():
                if type(key) is not str:
                    raise SourceModeError("Generated recipe JSON input has nontext key")
                if len(key) > MAX_INPUT_BYTES - text_bytes:
                    raise SourceModeError("Generated recipe JSON input exceeds byte bound")
                try:
                    text_bytes += len(key.encode("utf-8"))
                except UnicodeEncodeError as exc:
                    raise SourceModeError("Generated recipe JSON input has invalid Unicode") from exc
                stack.append((item, depth + 1))
        elif type(current) in {list, tuple}:
            if len(current) > MAX_JSON_TOKENS - tokens - len(stack):
                raise SourceModeError("Generated recipe JSON input exceeds structure bound")
            stack.extend((item, depth + 1) for item in current)
        elif type(current) is str:
            if len(current) > MAX_INPUT_BYTES - text_bytes:
                raise SourceModeError("Generated recipe JSON input exceeds byte bound")
            try:
                text_bytes += len(current.encode("utf-8"))
            except UnicodeEncodeError as exc:
                raise SourceModeError("Generated recipe JSON input has invalid Unicode") from exc
        elif current is not None and type(current) not in {bool, int, float}:
            raise SourceModeError("Generated recipe JSON input has unsupported value")
        elif type(current) is int and current.bit_length() > 128:
            raise SourceModeError("Generated recipe JSON integer exceeds bound")
        if text_bytes > MAX_INPUT_BYTES:
            raise SourceModeError("Generated recipe JSON input exceeds byte bound")
    try:
        data = canonical_bytes(value)
    except (CanonicalizationError, TypeError, ValueError) as exc:
        raise SourceModeError("Invalid generated recipe JSON input") from exc
    if len(data) > MAX_INPUT_BYTES:
        raise SourceModeError("Generated recipe JSON input exceeds byte bound")
    return data


class OverlayInputObserver:
    """Bounded optional witness of the host inputs actually visited by overlay detection."""

    def __init__(self, host_root: Path, preview_root: Path):
        self.host_root = host_root
        self.preview_root = preview_root
        self.inputs: list[tuple[str, bytes]] = []
        self._names: set[str] = set()
        self._total = 0
        self._visits = 0

    def _add(self, name: str, data: bytes) -> None:
        if name in self._names or len(self.inputs) >= MAX_INPUTS:
            raise SourceModeError("Overlay observation is duplicate or exceeds input bound")
        if len(data) > MAX_INPUT_BYTES or self._total + len(data) > MAX_TOTAL_INPUT_BYTES:
            raise SourceModeError("Overlay observation exceeds byte bound")
        self._names.add(name)
        self._total += len(data)
        self.inputs.append((name, data))

    def decision(self, name: str, value: Any) -> None:
        self._add("decision/" + name, bounded_canonical_input(value))

    def directory_state(self, directory: Path) -> str:
        try:
            relative = directory.relative_to(self.host_root).as_posix()
        except ValueError as exc:
            raise SourceModeError("Overlay directory escapes host root") from exc
        current = self.host_root
        for component in relative.split("/"):
            current = current / component
            try:
                metadata = current.lstat()
            except FileNotFoundError:
                return "missing"
            except OSError as exc:
                raise SourceModeError(f"Cannot inspect overlay directory: {relative}") from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise SourceModeError(f"Linked overlay directory: {relative}")
            if not stat.S_ISDIR(metadata.st_mode):
                return "nondirectory"
        return "directory"

    def visit(self, name: str) -> None:
        self._visits += 1
        if self._visits > MAX_INPUTS:
            raise SourceModeError("Overlay namespace enumeration exceeds bound")
        _path(name)

    def matching_paths(self, name: str, directory: Path, *, suffix: str,
                       recursive: bool = False) -> list[Path]:
        """Charge every native entry visited, including nonmatches and directories."""
        try:
            relative_root = directory.relative_to(self.host_root).as_posix()
        except ValueError as exc:
            raise SourceModeError("Overlay enumeration escapes host root") from exc
        pending = [directory]
        found: list[Path] = []
        visited: list[dict[str, str | bool]] = []
        while pending:
            current = pending.pop()
            try:
                with os.scandir(current) as iterator:
                    entries = []
                    for entry in iterator:
                        path = Path(entry.path)
                        relative = path.relative_to(self.host_root).as_posix()
                        self.visit(relative)
                        entries.append(entry)
            except OSError as exc:
                raise SourceModeError(f"Cannot enumerate overlay namespace: {relative_root}") from exc
            for entry in sorted(entries, key=lambda item: item.name, reverse=True):
                path = Path(entry.path)
                relative = path.relative_to(self.host_root).as_posix()
                try:
                    kind = entry.stat(follow_symlinks=False).st_mode
                except OSError as exc:
                    raise SourceModeError(f"Cannot inspect overlay namespace entry: {relative}") from exc
                if stat.S_ISLNK(kind):
                    raise SourceModeError(f"Linked overlay namespace entry: {relative}")
                is_dir = stat.S_ISDIR(kind)
                is_match = stat.S_ISREG(kind) and path.name.endswith(suffix)
                visited.append({"path": relative, "directory": is_dir, "matching": is_match})
                if is_match:
                    found.append(path)
                if recursive and is_dir:
                    pending.append(path)
        found.sort()
        self.decision(name, {"state": "complete", "visited": visited})
        return found

    def unmanaged_witness(self, directory: Path, excluded: set[str]) -> bool:
        """Stop at the first unmanaged leaf, or record a completed bounded walk."""
        relative_root = directory.relative_to(self.host_root).as_posix()
        pending = [directory]
        visited: list[dict[str, str | bool]] = []
        while pending:
            current = pending.pop()
            try:
                with os.scandir(current) as iterator:
                    entries = []
                    for entry in iterator:
                        relative = Path(entry.path).relative_to(self.host_root).as_posix()
                        self.visit(relative)
                        entries.append(entry)
            except OSError as exc:
                raise SourceModeError(f"Cannot enumerate overlay namespace: {relative_root}") from exc
            for entry in sorted(entries, key=lambda item: item.name, reverse=True):
                path = Path(entry.path)
                relative = path.relative_to(self.host_root).as_posix()
                try:
                    mode = entry.stat(follow_symlinks=False).st_mode
                except OSError as exc:
                    raise SourceModeError(f"Cannot inspect overlay namespace entry: {relative}") from exc
                if stat.S_ISLNK(mode):
                    raise SourceModeError(f"Linked overlay namespace entry: {relative}")
                is_dir = stat.S_ISDIR(mode)
                is_file = stat.S_ISREG(mode)
                is_excluded = relative in excluded
                visited.append({"path": relative, "directory": is_dir,
                                "file": is_file, "excluded": is_excluded})
                if is_file and not is_excluded:
                    self.decision("namespace/" + relative_root,
                                  {"state": "witness", "visited": visited})
                    return True
                if is_dir:
                    pending.append(path)
        self.decision("namespace/" + relative_root,
                      {"state": "complete", "visited": visited})
        return False

    def file(self, path: Path, *, root: str = "host", purpose: str = "read",
             limit: int = 2_000_000, excluded: bool = False) -> bytes | None:
        base = self.host_root if root == "host" else self.preview_root
        try:
            relative = path.relative_to(base).as_posix()
        except ValueError as exc:
            raise SourceModeError("Overlay input escapes its root") from exc
        _path(relative)
        name = f"{root}/{purpose}/{relative}"
        if excluded:
            self.decision(name, {"state": "excluded"})
            return None
        cursor = base
        for part in relative.split("/")[:-1]:
            cursor = cursor / part
            if cursor.is_symlink():
                raise SourceModeError(f"Linked overlay input ancestor: {name}")
        try:
            before = path.lstat()
        except FileNotFoundError:
            self.decision(name, {"state": "missing"})
            return None
        except OSError as exc:
            raise SourceModeError(f"Cannot inspect overlay input: {name}") from exc
        if stat.S_ISLNK(before.st_mode):
            raise SourceModeError(f"Linked overlay input: {name}")
        if stat.S_ISREG(before.st_mode) and before.st_nlink != 1:
            raise SourceModeError(f"Multiply linked overlay input: {name}")
        if not stat.S_ISREG(before.st_mode):
            self.decision(name, {"state": "nonregular", "type": stat.S_IFMT(before.st_mode)})
            return None
        if before.st_size > limit or before.st_size > MAX_INPUT_BYTES:
            self.decision(name, {"state": "oversized", "size": before.st_size})
            return None
        if before.st_size > MAX_TOTAL_INPUT_BYTES - self._total:
            raise SourceModeError("Overlay observation exceeds byte bound")
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                opened = os.fstat(fd)
                if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                        or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1):
                    raise SourceModeError(f"Overlay input changed while opening: {name}")
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    data = stream.read(limit + 1)
                after = os.fstat(fd)
            finally:
                os.close(fd)
            final = path.lstat()
        except OSError as exc:
            raise SourceModeError(f"Cannot read overlay input: {name}") from exc
        if (len(data) > limit or len(data) > MAX_INPUT_BYTES
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                != (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns)):
            raise SourceModeError(f"Overlay input changed or exceeded bound: {name}")
        self._add(name, data)
        return data


@dataclass(frozen=True)
class RecipeInstance:
    role: str
    destination: str
    artifact_bytes: bytes
    sha256: str
    executable: bool = False


class RecipeLibrary:
    def __init__(self, recipes: Mapping[str, tuple[Mapping[str, Any], str]], raw_sha256: str):
        self._recipes = MappingProxyType(dict(recipes))
        self.sha256 = raw_sha256

    def create_instance(self, role: str, destination: str,
                        inputs: list[tuple[str, bytes]],
                        decisions: dict[str, str | int | bool]) -> RecipeInstance:
        if type(role) is not str or role not in self._recipes:
            raise SourceModeError("Unknown generated recipe role")
        try:
            _path(destination)
        except PortableProvenanceError as exc:
            raise SourceModeError("Invalid generated recipe destination") from exc
        if role in DESTINATIONS:
            allowed = destination == DESTINATIONS[role]
        elif role == "traceability_tool_content":
            allowed = destination in {
                "scripts/validators/validate_traceability_headers.py",
                "naos_tools/validators/validate_traceability_headers.py",
            }
        elif role == "host_adapter":
            parts = destination.split("/")
            allowed = (
                len(parts) == 4 and parts[:2] == [".agents", "skills"]
                and parts[3] == "SKILL.md"
                and re.fullmatch(r"naos-(portable|workflow)-[a-z0-9-]+", parts[2]) is not None
                and len(parts[2]) <= 64
            ) or (
                len(parts) == 3 and parts[:2] == [".claude", "commands"]
                and parts[2].endswith(".md")
                and re.fullmatch(r"naos-(portable|workflow)-[a-z0-9-]+", parts[2][:-3]) is not None
                and len(parts[2][:-3]) <= 64
            )
        else:
            allowed = (destination.endswith("/.ruff.toml")
                       and destination.removesuffix("/.ruff.toml") in RUFF_ROOTS)
        if not allowed:
            raise SourceModeError("Generated recipe destination is outside its role")
        if type(inputs) is not list or len(inputs) > MAX_INPUTS:
            raise SourceModeError("Generated recipe input count exceeds bound")
        names: list[str] = []
        identities: list[dict[str, str]] = []
        total = 0
        for item in inputs:
            if type(item) not in {tuple, list} or len(item) != 2:
                raise SourceModeError("Malformed generated recipe input")
            name, data = item
            try:
                _path(name)
            except PortableProvenanceError as exc:
                raise SourceModeError("Invalid generated recipe input name") from exc
            if type(data) is not bytes or len(data) > MAX_INPUT_BYTES:
                raise SourceModeError("Invalid or oversized generated recipe input")
            total += len(data)
            if total > MAX_TOTAL_INPUT_BYTES:
                raise SourceModeError("Generated recipe input bytes exceed total bound")
            names.append(name)
            identities.append({"name": name, "sha256": hashlib.sha256(data).hexdigest(),
                               "size_decimal": str(len(data))})
        if names != sorted(names):
            raise SourceModeError("Generated recipe inputs must be sorted")
        try:
            _unique_paths(names)
        except PortableProvenanceError as exc:
            raise SourceModeError("Generated recipe inputs collide") from exc
        if type(decisions) is not dict or len(decisions) > MAX_DECISIONS:
            raise SourceModeError("Generated recipe decision count exceeds bound")
        for key, value in decisions.items():
            try:
                valid_value = (type(value) is bool
                               or (type(value) is int and abs(value) <= 1_000_000_000)
                               or (type(value) is str and len(value) <= 1024
                                   and len(value.encode("utf-8")) <= 1024))
            except UnicodeEncodeError as exc:
                raise SourceModeError("Invalid generated recipe scalar Unicode") from exc
            if type(key) is not str or DECISION_KEY.fullmatch(key) is None or not valid_value:
                raise SourceModeError("Invalid generated recipe scalar decision")
        body = {"schema": INSTANCE_SCHEMA, "role": role,
                "static_recipe_sha256": self._recipes[role][1],
                "destination": destination, "inputs": identities,
                "decisions": decisions}
        try:
            artifact = canonical_bytes(body)
        except (CanonicalizationError, TypeError, ValueError) as exc:
            raise SourceModeError("Cannot encode generated recipe instance") from exc
        if len(artifact) > MAX_INSTANCE_BYTES:
            raise SourceModeError("Generated recipe instance exceeds byte bound")
        return RecipeInstance(role, destination, artifact,
                              hashlib.sha256(artifact).hexdigest())


def _decimal(value: Any) -> bool:
    return (type(value) is str and 1 <= len(value) <= 20 and value.isascii()
            and value.isdecimal() and str(int(value)) == value)


def encode_static_recipes(recipes: list[dict[str, Any]]) -> bytes:
    """Encode an explicitly reviewed complete set; no mode inference."""
    body = {"schema": SCHEMA, "recipes": recipes}
    _validate_static_body(body)
    raw = canonical_bytes(body)
    if len(raw) > MAX_STATIC_BYTES:
        raise SourceModeError("Generated recipe declaration exceeds byte bound")
    return raw


def _validate_static_body(body: Any) -> None:
    if (type(body) is not dict or set(body) != {"schema", "recipes"}
            or body["schema"] != SCHEMA or type(body["recipes"]) is not list
            or len(body["recipes"]) != len(IMPLEMENTATIONS)):
        raise SourceModeError("Invalid generated recipe declaration shape")
    roles = []
    for item in body["recipes"]:
        if (type(item) is not dict
                or set(item) != {"role", "executable", "implementation"}
                or type(item["role"]) is not str
                or item["role"] not in IMPLEMENTATIONS
                or item["executable"] is not False
                or type(item["implementation"]) is not list
                or len(item["implementation"]) != len(IMPLEMENTATIONS[item["role"]])):
            raise SourceModeError("Invalid generated recipe fields or mode")
        roles.append(item["role"])
        paths = []
        for dep in item["implementation"]:
            if (type(dep) is not dict
                    or set(dep) != {"path", "sha256", "size_decimal"}
                    or type(dep["path"]) is not str
                    or type(dep["sha256"]) is not str
                    or HEX64.fullmatch(dep["sha256"]) is None
                    or not _decimal(dep["size_decimal"])
                    or int(dep["size_decimal"]) > MAX_IMPLEMENTATION_BYTES):
                raise SourceModeError("Invalid generated recipe implementation")
            paths.append(dep["path"])
        if tuple(paths) != IMPLEMENTATIONS[item["role"]]:
            raise SourceModeError("Generated recipe implementation membership changed")
    if roles != sorted(IMPLEMENTATIONS):
        raise SourceModeError("Generated recipe roles are missing or unsorted")


def load_static_recipes(raw: bytes, kit_root: Path) -> RecipeLibrary:
    if type(raw) is not bytes or len(raw) > MAX_STATIC_BYTES:
        raise SourceModeError("Missing or oversized generated recipe declaration")
    try:
        body = loads_strict_json(raw)
        _validate_static_body(body)
        if canonical_bytes(body) != raw:
            raise SourceModeError("Generated recipe declaration is not canonical")
    except (CanonicalizationError, RecursionError, OverflowError) as exc:
        raise SourceModeError("Malformed generated recipe declaration") from exc
    recipes = {}
    for item in body["recipes"]:
        for dep in item["implementation"]:
            path = kit_root / dep["path"]
            if (path.is_symlink() or not path.is_file()
                    or path.stat().st_size > MAX_IMPLEMENTATION_BYTES):
                raise SourceModeError(f"Missing or oversized recipe implementation: {dep['path']}")
            with path.open("rb") as stream:
                data = stream.read(MAX_IMPLEMENTATION_BYTES + 1)
            if (len(data) != int(dep["size_decimal"])
                    or hashlib.sha256(data).hexdigest() != dep["sha256"]):
                raise SourceModeError(f"Stale recipe implementation: {dep['path']}")
        recipes[item["role"]] = (MappingProxyType(dict(item)), canonical_sha256(item))
    return RecipeLibrary(recipes, hashlib.sha256(raw).hexdigest())


def load_kit_recipes(kit_root: Path) -> RecipeLibrary:
    path = kit_root / "configs/generated_source_recipes.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_STATIC_BYTES:
        raise SourceModeError("Missing, linked or oversized generated recipe declaration")
    with path.open("rb") as stream:
        raw = stream.read(MAX_STATIC_BYTES + 1)
    return load_static_recipes(raw, kit_root)
