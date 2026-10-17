"""Shared read-only working-tree capture contract for native adapters.

This is filesystem evidence only: it contains no binding, journal inventory,
transaction-state assertion, ownership, plan, or permission to mutate. Consumers
must separately validate portable history and local recovery state, then retain
and revalidate native preconditions through their operation window.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from . import local_binding as binding
from .canonical import canonical_bytes
from .portable_provenance import MAX_BASE_BYTES, MAX_CUMULATIVE_READ_BYTES, _load_json


SCHEMA = "naos.upgrade.working_tree_capture.v1"
MAX_LEAF_BYTES = MAX_BASE_BYTES
MAX_READ_BYTES = MAX_CUMULATIVE_READ_BYTES
MAX_DIRECTORY_ENTRIES = 100_000
MAX_DIRECTORY_NAME_BYTES = 16 * 1024 * 1024
MAX_ANCESTOR_NAME_BYTES = 16 * 1024 * 1024


class WorkingTreeCaptureError(binding.LocalBindingError):
    """Unsafe, inconsistent, unsupported, or unbounded native capture."""


def managed_paths(paths: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Validate a finite canonical selection before any native filesystem call."""
    if type(paths) not in {tuple, list} or len(paths) > binding.MAX_LEAVES:
        raise WorkingTreeCaptureError("Invalid managed path inventory")
    try:
        binding._bounded_input(list(paths))
        selected = [binding._portable_path(path) for path in paths]
        binding._sorted_unique(selected, "capture paths")
        binding._unique_paths(selected)
        counts = [len(path.split("/")) for path in selected]
        if (any(count > binding.MAX_PATH_COMPONENTS for count in counts)
                or sum(counts) > binding.MAX_TOTAL_PATH_COMPONENTS):
            raise WorkingTreeCaptureError("Managed path complexity exceeds capture budget")
    except (ValueError, TypeError) as exc:
        raise WorkingTreeCaptureError("Unsafe managed path inventory") from exc
    return tuple(selected)


def ancestor_paths(paths: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Bound prefix allocation incrementally, before a native adapter opens roots."""
    selected = managed_paths(paths)
    ancestors: set[str] = set()
    name_bytes = 0
    for path in selected:
        prefix = ""
        for part in path.split("/")[:-1]:
            prefix = part if not prefix else prefix + "/" + part
            if prefix in ancestors:
                continue
            size = len(prefix.encode("utf-8"))
            if (len(ancestors) >= binding.MAX_ANCESTORS
                    or size > MAX_ANCESTOR_NAME_BYTES - name_bytes):
                raise WorkingTreeCaptureError("Managed ancestor capture budget exceeded")
            ancestors.add(prefix)
            name_bytes += size
    return tuple(sorted(ancestors))


@dataclass(frozen=True)
class WorkingTreeCapture:
    """Canonical, immutable result of a completed read and revalidation pass."""

    raw: bytes
    sha256: str

    @property
    def body(self) -> dict[str, Any]:
        return _load_json(self.raw, "working-tree capture")


def build_capture(native: dict[str, Any], leaves: list[dict[str, Any]]) -> WorkingTreeCapture:
    """Validate the shape; native adapters must establish read consistency first."""
    body = {"schema": SCHEMA, "native": native, "leaves": leaves}
    try:
        binding._bounded_input(body)
        binding._validate_native(native)
        binding._validate_leaves(leaves, native)
        raw = canonical_bytes(body)
        if len(raw) > binding.MAX_RECORD_BYTES:
            raise WorkingTreeCaptureError("Working-tree capture exceeds byte budget")
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise WorkingTreeCaptureError("Invalid working-tree capture") from exc
    return WorkingTreeCapture(raw, hashlib.sha256(raw).hexdigest())
