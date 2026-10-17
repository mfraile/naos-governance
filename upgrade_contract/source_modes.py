"""Reviewed source-mode declarations and pure destination-bound row production.

This is source integrity, not ownership or author authentication. It performs no
filesystem reads and does not infer executable intent from native metadata.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from .canonical import CanonicalizationError, canonical_bytes, loads_strict_json
from .portable_provenance import PortableProvenanceError, _path, _unique_paths, encode_mode_inventory


SCHEMA = "naos.upgrade.reviewed_source_modes.v1"
MAX_DECLARATION_BYTES = 1024 * 1024
MAX_ITEMS = 4096
MAX_LEAF_BYTES = 64 * 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}\Z")

# Only generator-facing source roots are eligible. Exact membership is supplied
# by the reviewed declaration, then checked against public-export selection by
# private maintainer tooling; the runtime never imports that private manifest.
SOURCE_ROOTS = frozenset({
    "templates", "profiles", "archetypes", "scripts", "schemas", "configs",
    "capabilities", "policies", "autoresearch", "task_battery", "baselines", "docs",
})
GENERATOR_NATIVE_SOURCES = frozenset({
    "upgrade_contract/windows_handles.py",
    "upgrade_contract/security.py",
    "upgrade_contract/linux_primitives.py",
})
SELF_PATH = "configs/source_modes.json"


class SourceModeError(ValueError):
    """A reviewed declaration or source/output binding is invalid."""


@dataclass(frozen=True)
class SourceModeDeclaration:
    sha256: str
    _items: Mapping[str, Mapping[str, Any]]

    @property
    def items(self) -> dict[str, dict[str, Any]]:
        return {path: dict(item) for path, item in self._items.items()}


def _path_checked(value: Any) -> str:
    try:
        return _path(value)
    except PortableProvenanceError as exc:
        raise SourceModeError(str(exc)) from exc


def _decimal(value: Any) -> bool:
    return (type(value) is str and 1 <= len(value) <= 20 and value.isascii()
            and value.isdecimal() and str(int(value)) == value)


def _validate_body(body: Any) -> dict[str, Any]:
    if type(body) is not dict or set(body) != {"schema", "items"} or body["schema"] != SCHEMA:
        raise SourceModeError("Invalid reviewed source-mode declaration fields or schema")
    items = body["items"]
    if type(items) is not list or not items or len(items) > MAX_ITEMS:
        raise SourceModeError("Invalid reviewed source-mode item count")
    paths: list[str] = []
    for item in items:
        if type(item) is not dict or set(item) != {"source", "sha256", "size_decimal", "executable"}:
            raise SourceModeError("Invalid reviewed source-mode item fields")
        path = _path_checked(item["source"])
        if ((path.split("/", 1)[0] not in SOURCE_ROOTS and path not in GENERATOR_NATIVE_SOURCES) or path == SELF_PATH
                or "/" not in path or type(item["sha256"]) is not str
                or HEX64.fullmatch(item["sha256"]) is None
                or not _decimal(item["size_decimal"])
                or int(item["size_decimal"]) > MAX_LEAF_BYTES
                or type(item["executable"]) is not bool):
            raise SourceModeError(f"Invalid or unselected reviewed source: {path}")
        paths.append(path)
    if paths != sorted(paths):
        raise SourceModeError("Reviewed source-mode declaration is unsorted")
    try:
        _unique_paths(paths)
    except PortableProvenanceError as exc:
        raise SourceModeError("Reviewed source-mode paths collide") from exc
    return body


def encode_source_mode_declaration(items: list[dict[str, Any]]) -> bytes:
    """Canonicalize an explicitly supplied complete declaration."""
    body = _validate_body({"schema": SCHEMA, "items": items})
    try:
        raw = canonical_bytes(body)
    except (CanonicalizationError, ValueError, TypeError) as exc:
        raise SourceModeError("Cannot canonicalize reviewed source modes") from exc
    if len(raw) > MAX_DECLARATION_BYTES:
        raise SourceModeError("Reviewed source-mode declaration exceeds byte bound")
    return raw


def load_source_mode_declaration(raw: bytes) -> SourceModeDeclaration:
    """Accept only exact canonical, complete, bounded declaration bytes."""
    if type(raw) is not bytes or len(raw) > MAX_DECLARATION_BYTES:
        raise SourceModeError("Missing or oversized reviewed source-mode declaration")
    try:
        body = _validate_body(loads_strict_json(raw))
        if canonical_bytes(body) != raw:
            raise SourceModeError("Reviewed source-mode declaration is not canonical")
    except (CanonicalizationError, RecursionError, OverflowError) as exc:
        raise SourceModeError("Malformed reviewed source-mode declaration") from exc
    items = {item["source"]: MappingProxyType(dict(item)) for item in body["items"]}
    return SourceModeDeclaration(hashlib.sha256(raw).hexdigest(), MappingProxyType(items))


def mode_row(
    declaration: SourceModeDeclaration,
    *,
    source: str,
    source_bytes: bytes,
    destination: str,
    output_bytes: bytes,
) -> dict[str, Any]:
    """Bind one selected source to exact final bytes and destination intent."""
    if type(declaration) is not SourceModeDeclaration:
        raise SourceModeError("Missing validated source-mode declaration")
    source = _path_checked(source)
    destination = _path_checked(destination)
    if source not in declaration._items:
        raise SourceModeError(f"Unmapped reviewed source: {source}")
    if (type(source_bytes) is not bytes or type(output_bytes) is not bytes
            or len(source_bytes) > MAX_LEAF_BYTES or len(output_bytes) > MAX_LEAF_BYTES):
        raise SourceModeError("Missing or oversized source/output bytes")
    item = declaration._items[source]
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    if source_sha256 != item["sha256"] or str(len(source_bytes)) != item["size_decimal"]:
        raise SourceModeError(f"Stale reviewed source bytes: {source}")
    return {
        "destination": destination,
        "source_sha256": source_sha256,
        "source_size_decimal": str(len(source_bytes)),
        "output_sha256": hashlib.sha256(output_bytes).hexdigest(),
        "output_size_decimal": str(len(output_bytes)),
        "executable": item["executable"],
    }


def encode_mode_rows(rows: list[dict[str, Any]]) -> tuple[str, bytes]:
    """Use the portable codec's destination/alias checks and record format."""
    try:
        return encode_mode_inventory(rows)
    except PortableProvenanceError as exc:
        raise SourceModeError(str(exc)) from exc
