"""Pure local registration/checkpoint records, not journal or quiescence proofs.

These codecs validate bytes and references only. They neither inspect a filesystem
nor validate intent/plan/progress semantics, terminal execution, native safety,
portable replay, archives, or legacy fences. A later lifecycle layer must supply
all those proofs before constructing a quiescent local observation.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Literal

from . import local_binding as binding
from .canonical import CanonicalizationError, canonical_bytes
from .portable_provenance import PortableProvenanceError, _load_json

STORE_SCHEMA = "naos.upgrade.local_store.v1"
TERMINAL_SCHEMA = "naos.upgrade.local_journal_terminal.v1"
MAX_GENERATION = (1 << 53) - 1  # Exact RFC 8785 integer range, never bool/float.
MAX_RECORD_BYTES = binding.MAX_RECORD_BYTES
MAX_ARCHIVES = binding.MAX_JOURNALS
_ARCHIVE_ID = re.compile(r"A[0-9a-f]{64}\Z")
_STORE_KEYS = {
    "schema",
    "generation",
    "project_id",
    "owner_sha256",
    "binding_id",
    "binding_sha256",
    "journals",
    "active_journal_id",
    "archives",
}
_TERMINAL_KEYS = {
    "schema",
    "intent_sha256",
    "outcome",
    "progress_sha256",
    "binding_after_sha256",
    "portable_head_sha256",
}
UNVERIFIED_PROOFS = (
    "native_storage_and_complete_enumeration",
    "intent_plan_and_progress_semantics",
    "terminal_execution_and_cleanup",
    "portable_history_and_commitpoint",
    "binding_transition",
    "archive_contents",
    "legacy_fence",
    "quiescence",
)


class LocalStoreError(binding.LocalBindingError):
    """Malformed registration bytes or inconsistent supplied references."""


def _fail(message: str) -> None:
    raise LocalStoreError(message)


def _digest(value: Any, label: str) -> str:
    return binding._hex(value, binding.HEX64, label)


def _validate_store(body: Any) -> None:
    if type(body) is dict and body.get("schema") == "naos.upgrade.local_store.v2":
        from .foreign_store_version import validate_store
        return validate_store(body)
    binding._fields(body, _STORE_KEYS, "local store")
    generation = body["generation"]
    if type(generation) is not int or not 0 <= generation <= MAX_GENERATION:
        _fail("Invalid local store generation")
    # Existing local-binding budgets accept string/boolean/null scalar records.
    # Validate the one integer first, then budget its bounded decimal rendering.
    budget_view = dict(body)
    budget_view["generation"] = str(generation)
    binding._bounded_input(budget_view)
    if body["schema"] != STORE_SCHEMA:
        _fail("Unsupported local store schema")
    if type(body["project_id"]) is not str or not 1 <= len(body["project_id"]) <= 128:
        _fail("Invalid local store project ID")
    _digest(body["owner_sha256"], "store owner digest")
    bound = body["binding_id"] is not None
    if bound != (body["binding_sha256"] is not None):
        _fail("Local store binding ID/digest must both be present or null")
    if bound:
        binding._hex(body["binding_id"], binding.BINDING_ID, "store binding ID")
        _digest(body["binding_sha256"], "store binding digest")
    journals = binding._validate_journals(body["journals"])
    active = body["active_journal_id"]
    if active is not None:
        binding._hex(active, binding.JOURNAL_ID, "active journal ID")
        if active != journals["head_id"]:
            _fail("Only the registered journal head may be active")
    if not bound and not journals["entries"]:
        _fail("Unbound registration requires retained enrollment journal evidence")
    archives = body["archives"]
    if type(archives) is not list or len(archives) > MAX_ARCHIVES:
        _fail("Invalid local archive inventory")
    previous = ""
    for item in archives:
        binding._fields(item, {"id", "inventory_sha256"}, "archive reference")
        identifier = binding._hex(item["id"], _ARCHIVE_ID, "archive ID")
        digest = _digest(item["inventory_sha256"], "archive inventory digest")
        if identifier != "A" + digest or identifier <= previous:
            _fail("Unsorted, duplicate or mismatched archive reference")
        previous = identifier


def _validate_terminal(body: Any) -> None:
    if type(body) is dict and body.get('schema') == 'naos.upgrade.foreign_store_receiving_terminal.v1':
        from .foreign_store_records import validate_terminal
        binding._bounded_input(body)
        validate_terminal(body)
        return
    binding._fields(body, _TERMINAL_KEYS, "local terminal")
    binding._bounded_input(body)
    if body["schema"] != TERMINAL_SCHEMA:
        _fail("Unsupported local terminal schema")
    _digest(body["intent_sha256"], "terminal intent digest")
    _digest(body["progress_sha256"], "terminal progress digest")
    if type(body["outcome"]) is not str or body["outcome"] not in {
        "committed",
        "rolled_back",
    }:
        _fail("Invalid local terminal outcome")
    unbound = body["binding_after_sha256"] is None
    if unbound:
        if body["outcome"] != "rolled_back":
            _fail("Only an unbound rollback may have no result binding")
        # Initial enrollment rollback may have no portable history. A first
        # rebind rollback preserves an already existing portable head instead.
        # The full operation validator must establish which case applies.
        if body["portable_head_sha256"] is not None:
            _digest(body["portable_head_sha256"], "unbound rollback portable head")
    else:
        _digest(body["binding_after_sha256"], "terminal result binding digest")
        _digest(body["portable_head_sha256"], "terminal portable head digest")


def _encode(body: Any, *, terminal: bool) -> bytes:
    try:
        (_validate_terminal if terminal else _validate_store)(body)
        raw = canonical_bytes(body)
        if len(raw) > MAX_RECORD_BYTES:
            _fail("Local store record exceeds byte budget")
        return raw
    except LocalStoreError:
        raise
    except (
        binding.LocalBindingError,
        CanonicalizationError,
        PortableProvenanceError,
        ValueError,
        TypeError,
        OverflowError,
        RecursionError,
    ) as exc:
        raise LocalStoreError("Malformed local store record") from exc


def encode_local_store(body: Any) -> bytes:
    return _encode(body, terminal=False)


def encode_local_terminal(body: Any) -> bytes:
    return _encode(body, terminal=True)


@dataclass(frozen=True)
class ValidatedLocalStore:
    sha256: str
    raw: bytes

    @property
    def body(self) -> dict[str, Any]:
        return _load_json(self.raw, "local store")


@dataclass(frozen=True)
class ValidatedLocalTerminal:
    sha256: str
    raw: bytes

    @property
    def body(self) -> dict[str, Any]:
        return _load_json(self.raw, "local terminal")


def _load(
    raw: bytes, *, terminal: bool
) -> ValidatedLocalStore | ValidatedLocalTerminal:
    if type(raw) is not bytes or len(raw) > MAX_RECORD_BYTES:
        _fail("Missing or oversized local store record")
    try:
        body = _load_json(raw, "local terminal" if terminal else "local store")
        if _encode(body, terminal=terminal) != raw:
            _fail("Noncanonical local store record")
    except LocalStoreError:
        raise
    except (
        binding.LocalBindingError,
        CanonicalizationError,
        PortableProvenanceError,
        ValueError,
        TypeError,
        OverflowError,
        RecursionError,
    ) as exc:
        raise LocalStoreError("Malformed local store record") from exc
    cls = ValidatedLocalTerminal if terminal else ValidatedLocalStore
    return cls(hashlib.sha256(raw).hexdigest(), raw)


def load_local_store(raw: bytes) -> ValidatedLocalStore:
    result = _load(raw, terminal=False)
    assert type(result) is ValidatedLocalStore
    return result


def load_local_terminal(raw: bytes) -> ValidatedLocalTerminal:
    result = _load(raw, terminal=True)
    assert type(result) is ValidatedLocalTerminal
    return result


def _checked_store(record: ValidatedLocalStore) -> dict[str, Any]:
    if (
        type(record) is not ValidatedLocalStore
        or load_local_store(record.raw) != record
    ):
        _fail("Unvalidated or forged local store record")
    return record.body


def _checked_terminal(record: ValidatedLocalTerminal) -> dict[str, Any]:
    if (
        type(record) is not ValidatedLocalTerminal
        or load_local_terminal(record.raw) != record
    ):
        _fail("Unvalidated or forged local terminal record")
    return record.body


def _checked_binding(record: binding.ValidatedLocalBinding) -> dict[str, Any]:
    try:
        if (
            type(record) is not binding.ValidatedLocalBinding
            or binding.load_local_binding(record.raw) != record
        ):
            _fail("Unvalidated or forged local binding")
        return record.body
    except binding.LocalBindingError as exc:
        raise LocalStoreError("Invalid checkpoint binding") from exc


@dataclass(frozen=True)
class RegistrationConsistency:
    """Reference consistency only: never an inspection or a quiescence claim."""

    status: Literal[
        "checkpoint_consistent", "pending_registration", "unbound_checkpoint"
    ]
    journal_ids: tuple[str, ...]
    active_journal_id: str | None
    binding_sha256: str | None
    unverified_proofs: tuple[str, ...] = UNVERIFIED_PROOFS


def reconcile_registration(
    store: ValidatedLocalStore,
    checkpoint_binding: binding.ValidatedLocalBinding | None,
    journal_directory_ids: tuple[str, ...],
) -> RegistrationConsistency:
    """Compare declared inventory with a bounded, exact complete ID observation.

    `checkpoint_binding` is the binding whose hash state.json names: while active
    it is the saved predecessor, not necessarily the current live binding file.
    Native readers must separately establish actual namespace completeness and
    reconcile a possibly changed live binding. No intent bytes are validated here.
    """
    state = _checked_store(store)
    entries = state["journals"]["entries"]
    expected = tuple(item["id"] for item in entries)
    if (
        type(journal_directory_ids) is not tuple
        or len(journal_directory_ids) > binding.MAX_JOURNALS
        or any(type(name) is not str for name in journal_directory_ids)
        or journal_directory_ids != expected
    ):
        _fail("Missing, extra, aliased or unordered journal directory inventory")
    active = state["active_journal_id"]
    if state["binding_sha256"] is None:
        if checkpoint_binding is not None:
            _fail("Unbound store unexpectedly has a checkpoint binding")
        status = "pending_registration" if active is not None else "unbound_checkpoint"
    else:
        prior = _checked_binding(checkpoint_binding)
        if (
            checkpoint_binding.sha256 != state["binding_sha256"]
            or prior["binding_id"] != state["binding_id"]
            or prior["project_id"] != state["project_id"]
            or prior["owner_sha256"] != state["owner_sha256"]
        ):
            _fail("Store and checkpoint binding linkage differs")
        expected_prior = entries[:-1] if active is not None else entries
        if prior["observation"]["journals"]["entries"] != expected_prior:
            _fail("Registered intent inventory differs from checkpoint prefix")
        status = (
            "pending_registration" if active is not None else "checkpoint_consistent"
        )
    return RegistrationConsistency(status, expected, active, state["binding_sha256"])


@dataclass(frozen=True)
class TerminalReferenceConsistency:
    """Hash/record linkage only; terminal execution still requires native proofs."""

    journal_id: str
    outcome: Literal["committed", "rolled_back"]
    binding_after_sha256: str | None
    unverified_proofs: tuple[str, ...] = UNVERIFIED_PROOFS


def reconcile_terminal_reference(
    store: ValidatedLocalStore,
    journal_id: str,
    terminal: ValidatedLocalTerminal,
    *,
    progress_sha256: str,
    binding_after: binding.ValidatedLocalBinding | None,
) -> TerminalReferenceConsistency:
    """Link a marker to registered intent, supplied progress hash and result.

    The progress hash is a reference, not proof that progress is a legal state.
    In particular null result references do not prove an unbound rollback happened.
    Historical binding-after records may differ from the current checkpoint.
    """
    state = _checked_store(store)
    marker = _checked_terminal(terminal)
    try:
        binding._hex(journal_id, binding.JOURNAL_ID, "terminal journal ID")
        _digest(progress_sha256, "observed progress digest")
    except binding.LocalBindingError as exc:
        raise LocalStoreError("Invalid terminal reference input") from exc
    entries = state["journals"]["entries"]
    index = next(
        (i for i, item in enumerate(entries) if item["id"] == journal_id), None
    )
    if index is None or entries[index]["sha256"] != marker["intent_sha256"]:
        _fail("Terminal intent differs from registered journal")
    if progress_sha256 != marker["progress_sha256"]:
        _fail("Terminal progress digest differs")
    if marker["binding_after_sha256"] is None:
        if binding_after is not None:
            _fail("Unbound rollback marker unexpectedly has result binding")
        if (
            state["active_journal_id"] == journal_id
            and state["binding_sha256"] is not None
        ):
            _fail("Bound predecessor cannot have an unbound rollback result")
    else:
        result = _checked_binding(binding_after)
        if (
            binding_after.sha256 != marker["binding_after_sha256"]
            or result["portable_head_sha256"] != marker["portable_head_sha256"]
            or result["project_id"] != state["project_id"]
            or result["owner_sha256"] != state["owner_sha256"]
            or result["observation"]["journals"]["entries"] != entries[: index + 1]
        ):
            _fail("Terminal result binding linkage differs")
    # While a successor is active, state still names the saved checkpoint
    # produced by its immediate predecessor. Older terminals may name older
    # bindings, but that checkpoint anchor must match exactly.
    checkpoint_index = len(entries) - (2 if state["active_journal_id"] else 1)
    if index == checkpoint_index:
        if state["binding_sha256"] != marker["binding_after_sha256"]:
            _fail("Checkpoint terminal does not match store checkpoint")
        if binding_after is not None and state["binding_id"] != result["binding_id"]:
            _fail("Checkpoint terminal binding ID differs from store checkpoint")
    return TerminalReferenceConsistency(
        journal_id, marker["outcome"], marker["binding_after_sha256"]
    )
