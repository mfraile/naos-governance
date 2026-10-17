"""Held, read-only portable-history and selected working-tree observation.

This joins two existing native readers while both root chains remain pinned.
The result grants no journal, quiescence, binding, ownership, or mutation authority.
Final checks are ordered observations, not a simultaneous filesystem snapshot;
a change after one reader's last observation can still escape without a lock.
"""

from __future__ import annotations

import os
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .portable_provenance import (
    PortableProvenanceError,
    ValidatedPortableSnapshot,
    load_portable_snapshot,
)
from .working_tree_capture import (
    WorkingTreeCapture,
    WorkingTreeCaptureError,
    ancestor_paths,
    build_capture,
    managed_paths,
)


class JointCaptureError(ValueError):
    """A bounded combined native observation could not be established."""


@dataclass(frozen=True)
class PortableWorkingTreeCapture:
    """Immutable validated portable facts paired with native leaf witnesses."""

    portable: ValidatedPortableSnapshot
    working_tree: WorkingTreeCapture


@dataclass(frozen=True)
class _HeldCapture:
    """Preliminary internal evidence until successful exit; never write authority."""

    result: PortableWorkingTreeCapture
    portable_reader: Any
    working_reader: Any


def _selected(snapshot: ValidatedPortableSnapshot, extras: tuple[str, ...]) -> tuple[str, ...]:
    # Replay retains tombstones, so every ever-introduced path remains selected.
    paths = tuple(sorted(set(snapshot.entries) | set(extras)))
    return managed_paths(paths)


def _same_posix_root(portable: Any, working: Any) -> None:
    from .portable_provenance_posix import _same_root_ancestor, _root_ancestor_witness

    if portable._slash_witness is None or not working.chain:
        raise JointCaptureError("Held POSIX filesystem-root witness is absent")
    if not _same_root_ancestor(portable._slash_witness, working.chain[0][4]):
        raise JointCaptureError("Portable and working POSIX filesystem roots differ")
    if len(portable._root_chain) != len(working.chain) - 1:
        raise JointCaptureError("Portable and working POSIX root chains differ")
    for (_, part, _, expected), (_, _, current_part, fd, observed) in zip(
        portable._root_chain, working.chain[1:]
    ):
        # Join the same identity/protection policy used by each reader. An
        # unrelated sibling may change an ancestor's directory link count.
        if (part != current_part or not _same_root_ancestor(expected, observed)
                or not _same_root_ancestor(expected, _root_ancestor_witness(
                    fd, label=f"joint root ancestor {part}"))):
            raise JointCaptureError(f"Portable and working POSIX root identity differs: {part}")
    portable._check_root()
    working._check_root()


def _same_windows_root(portable: Any, working: Any) -> None:
    from .portable_provenance_windows import _info, _security_identity

    if portable.project_parts != working.project:
        raise JointCaptureError("Portable and working Windows root paths differ")
    keys = [()]
    keys.extend(working.project[:index] for index in range(1, len(working.project) + 1))
    for key in keys:
        if key not in portable.directory_baselines or key not in working.baselines:
            raise JointCaptureError("Portable and working Windows root chain is incomplete")
        held = working.directories[key]
        portable_form = (_info(held, directory=True), _security_identity(held))
        if (portable.directory_baselines[key] != portable_form
                or working._observe(held, directory=True) != working.baselines[key]):
            raise JointCaptureError("Portable and working Windows root identity/protection differs")


@contextmanager
def _held_posix(project_root: Path, extras: tuple[str, ...]) -> Iterator[_HeldCapture]:
    from . import portable_provenance_posix as portable_native
    from . import working_tree_capture_posix as working_native

    with portable_native._ContainedReader(project_root) as portable:
        with working_native._Reader(project_root) as working:
            _same_posix_root(portable, working)
            snapshot = load_portable_snapshot(portable)
            selected = _selected(snapshot, extras)
            ancestors = ancestor_paths(selected)
            native, leaves = working_native._initial_capture(working, selected, ancestors)
            pair = PortableWorkingTreeCapture(snapshot, build_capture(native, leaves))
            yield _HeldCapture(pair, portable, working)
            # First catch portable changes during working reads, then catch
            # working/control changes during the portable consistency pass.
            portable.revalidate()
            working._final_revalidate(native, leaves)
            _same_posix_root(portable, working)


@contextmanager
def _held_windows(
    project_root: str, extras: tuple[str, ...], handles: Any,
) -> Iterator[_HeldCapture]:
    from . import portable_provenance_windows as portable_native
    from . import working_tree_capture_windows as working_native
    from .windows_handles import WindowsHandles

    active = WindowsHandles() if handles is None else handles
    with ExitStack() as stack:
        portable = portable_native._HeldReader(active, project_root, stack)
        working = working_native._Capture(active, project_root, stack)
        _same_windows_root(portable, working)
        snapshot = load_portable_snapshot(portable)
        selected = _selected(snapshot, extras)
        ancestors = ancestor_paths(selected)
        native, leaves = working_native._initial_capture(
            working, project_root, selected, ancestors
        )
        pair = PortableWorkingTreeCapture(snapshot, build_capture(native, leaves))
        yield _HeldCapture(pair, portable, working)
        portable.revalidate()
        working.revalidate()
        _same_windows_root(portable, working)


def capture_portable_working_tree(
    project_root: Path | str, extra_paths: tuple[str, ...] = (), *, handles: Any = None,
) -> PortableWorkingTreeCapture:
    """Return a detached pair after both held readers revalidate and close.

    Explicit ``handles`` selects the injectable Windows path on any host.
    Without injection, native Windows uses WindowsHandles; macOS/Linux use
    POSIX no-follow descriptors. Existing per-reader byte, path, enumeration,
    and descriptor bounds are additive; no extra hash pass is introduced.
    The pair is not an atomic snapshot or proof of continuing quiescence.
    """
    try:
        extras = managed_paths(extra_paths)  # Validate before opening native roots.
        if handles is not None or os.name == "nt":
            with _held_windows(str(project_root), extras, handles) as held:
                return held.result
        with _held_posix(Path(project_root), extras) as held:
            return held.result
    except JointCaptureError:
        raise
    except (PortableProvenanceError, WorkingTreeCaptureError, OSError,
            RuntimeError, ValueError, TypeError, AttributeError) as exc:
        raise JointCaptureError(f"Joint portable/working capture refused: {exc}") from exc
