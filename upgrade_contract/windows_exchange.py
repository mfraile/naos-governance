"""Recoverable Windows leaf exchange; deliberately not an atomic exchange.

The Windows adapter supplies held-handle observations and exact-object,
no-overwrite moves. A transaction coordinator must durably persist the intent
before invoking this protocol, retain the backup slot, and hold its transaction
lock throughout. This module never substitutes for the POSIX exchange primitive
or interprets an existing v2 journal as permitting the additional intermediate
states. The Windows coordinator must use a distinct journal version.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol


class ExchangeConflict(RuntimeError):
    """Observed objects do not match an authorized recoverable topology."""


@dataclass(frozen=True)
class LeafIdentity:
    volume: int
    file_id: bytes
    size: int
    content_sha256: str
    metadata_sha256: str

    def validate(self) -> None:
        if (
            type(self.volume) is not int or self.volume < 0
            or not isinstance(self.file_id, bytes) or len(self.file_id) != 16
            or type(self.size) is not int or self.size < 0
        ):
            raise ValueError("Invalid Windows leaf identity")
        for digest in (self.content_sha256, self.metadata_sha256):
            if not isinstance(digest, str) or len(digest) != 64 or any(
                char not in "0123456789abcdef" for char in digest
            ):
                raise ValueError("Invalid Windows leaf digest")


@dataclass(frozen=True)
class ExchangeBinding:
    """Digest-bound operation with three distinct, held-parent leaf slots.

    Slot names are opaque keys supplied by the coordinator, not filesystem
    paths. The backend maps them to the exact held parent/name pairs bound in
    the persisted intent. The backup is private and must initially be absent.
    """

    target: str
    staged: str
    backup: str
    before: LeafIdentity
    after: LeafIdentity

    def validate(self) -> None:
        slots = (self.target, self.staged, self.backup)
        if any(not isinstance(slot, str) or not slot for slot in slots):
            raise ValueError("Exchange slots must be nonempty keys")
        if len(set(slots)) != 3:
            raise ValueError("Exchange slots must be distinct")
        if not isinstance(self.before, LeafIdentity) or not isinstance(self.after, LeafIdentity):
            raise ValueError("Exchange requires two valid leaf identities")
        self.before.validate()
        self.after.validate()
        if self.before.volume != self.after.volume:
            raise ValueError("Cross-volume exchange is forbidden")
        if self.before.file_id == self.after.file_id:
            raise ValueError("Exchange requires distinct held files")


class ExchangeBackend(Protocol):
    def preflight_durability(self) -> None:
        """Prove this run can persist namespace moves, or raise before intent."""
        ...

    def observe(self, slot: str) -> LeafIdentity | None:
        """Return exact content+metadata identity; only genuine absence is None."""
        ...

    def move_exact(self, source: str, destination: str, expected: LeafIdentity) -> None:
        """Move the pinned expected object without overwriting any destination.

        Refuse unexpected identity, hardlinks, reparse points or metadata, and
        prevent concurrent writes/deletion while checking and moving the held
        object. Propagate ambiguity or native failures; never unlink a collision.
        """
        ...

    def flush(self) -> None:
        """Persist the changed namespace before reporting durable progress."""
        ...


def topology(backend: ExchangeBackend, binding: ExchangeBinding) -> str:
    binding.validate()
    observed = tuple(backend.observe(slot) for slot in (
        binding.target, binding.staged, binding.backup
    ))
    expected = {
        "prepared": (binding.before, binding.after, None),
        "detached": (None, binding.after, binding.before),
        "installed": (binding.after, None, binding.before),
        "exchanged": (binding.after, binding.before, None),
    }
    for state, identity in expected.items():
        if observed == identity:
            return state
    raise ExchangeConflict("Exchange topology is ambiguous; all objects preserved")


def exchange(
    backend: ExchangeBackend,
    binding: ExchangeBinding,
    *,
    persist_intent: Callable[[ExchangeBinding, str], None],
) -> None:
    """Run/reconcile a forward exchange after an exact durable intent.

    persist_intent must validate and atomically/durably record the coordinator's
    plan digest, slots and both identities, or raise before any move. It must
    refuse a conflicting, completed or rolling-back transaction. Native errors
    leave the intent and intermediate files available to rollback; this layer
    never guesses that a failed API call had no effect.
    """
    binding.validate()
    backend.preflight_durability()
    topology(backend, binding)
    persist_intent(binding, "forward")
    moves = {
        "prepared": (binding.target, binding.backup, binding.before, "detached"),
        "detached": (binding.staged, binding.target, binding.after, "installed"),
        "installed": (binding.backup, binding.staged, binding.before, "exchanged"),
    }
    for _ in range(3):
        state = topology(backend, binding)
        if state == "exchanged":
            break
        source, destination, identity, next_state = moves[state]
        backend.move_exact(source, destination, identity)
        backend.flush()
        if topology(backend, binding) != next_state:
            raise ExchangeConflict("Exchange publication changed; recovery required")
    if topology(backend, binding) != "exchanged":
        raise ExchangeConflict("Exchange did not reach its expected final topology")
    # A resumed already-final state may follow a crash between move and flush.
    backend.flush()
    if topology(backend, binding) != "exchanged":
        raise ExchangeConflict("Exchange final topology changed during flush")


def rollback(
    backend: ExchangeBackend,
    binding: ExchangeBinding,
    *,
    persist_intent: Callable[[ExchangeBinding, str], None],
) -> None:
    """Restore the before topology without deleting or overwriting any object.

    Recovery may resume at any of the four recognizable states, including after
    a prior recovery crash. Committed transactions are excluded by the caller's
    validated journal, not inferred from a plausible filesystem arrangement.
    """
    binding.validate()
    backend.preflight_durability()
    topology(backend, binding)
    persist_intent(binding, "rollback")
    moves = {
        "exchanged": (binding.staged, binding.backup, binding.before, "installed"),
        "installed": (binding.target, binding.staged, binding.after, "detached"),
        "detached": (binding.backup, binding.target, binding.before, "prepared"),
    }
    for _ in range(3):
        state = topology(backend, binding)
        if state == "prepared":
            break
        source, destination, identity, next_state = moves[state]
        backend.move_exact(source, destination, identity)
        backend.flush()
        if topology(backend, binding) != next_state:
            raise ExchangeConflict("Rollback publication changed; recovery required")
    if topology(backend, binding) != "prepared":
        raise ExchangeConflict("Rollback did not restore its expected topology")
    backend.flush()
    if topology(backend, binding) != "prepared":
        raise ExchangeConflict("Rollback final topology changed during flush")
