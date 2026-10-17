"""Windows three-slot transaction for application-process-failure recovery.

This journal does not claim system-crash or power-loss namespace durability.
It is separate from the POSIX v1/v2 journals and never interprets their bytes.
"""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass, replace
import hashlib
import re
from types import MappingProxyType
from typing import Any, Mapping

from .canonical import canonical_bytes, loads_strict_json
from .windows_backend import WindowsExchangeBackend
from .windows_exchange import ExchangeBinding, ExchangeConflict, LeafIdentity, topology
from .windows_handles import UnsafeWindowsPath, WindowsHandleError, validate_component


SCHEMA = "naos.upgrade.windows_transaction.v1"
FAILURE_MODEL = "application_crash_v1"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_ABSENT = 0xC0000034
_MAX_JOURNAL = 64 * 1024
_STATES = ("prepared", "detached", "installed", "exchanged")
_FORWARD = {
    "prepared": ("target", "backup", "before", "detached"),
    "detached": ("staged", "target", "after", "installed"),
    "installed": ("backup", "staged", "before", "exchanged"),
}
_REVERSE = {
    "exchanged": ("staged", "backup", "before", "installed"),
    "installed": ("target", "staged", "after", "detached"),
    "detached": ("backup", "target", "before", "prepared"),
}


class WindowsJournalConflict(RuntimeError):
    """Unrecognized journal, lock, plan, or file topology; retain all objects."""


class WindowsRecoveryRequired(WindowsJournalConflict):
    """A journal write/flush may be incomplete; retain bytes for recovery."""


def _identity_record(value: LeafIdentity) -> dict[str, str]:
    value.validate()
    return {
        "volume_serial_hex": f"{value.volume:016x}",
        "file_id_hex": value.file_id.hex(),
        "size_bytes": str(value.size),
        "content_sha256": value.content_sha256,
        "metadata_sha256": value.metadata_sha256,
    }


def _handle_id(handle: Any) -> dict[str, str]:
    info = handle.info()
    if len(info.file_id) != 16:
        raise WindowsJournalConflict("Runtime handle lacks a 128-bit file ID")
    return {"volume_serial_hex": f"{info.volume:016x}", "file_id_hex": info.file_id.hex()}


def _envelope(body: dict[str, Any]) -> bytes:
    digest = hashlib.sha256(canonical_bytes(body)).hexdigest()
    return canonical_bytes({"body": body, "sha256": digest})


def _decode(data: bytes) -> dict[str, Any]:
    try:
        value = loads_strict_json(data)
        if (not isinstance(value, dict) or set(value) != {"body", "sha256"}
                or not isinstance(value["body"], dict)
                or not isinstance(value["sha256"], str)
                or not _HEX64.fullmatch(value["sha256"])
                or canonical_bytes(value) != data
                or hashlib.sha256(canonical_bytes(value["body"])).hexdigest() != value["sha256"]):
            raise ValueError("journal envelope differs")
        return value["body"]
    except Exception as exc:
        raise WindowsRecoveryRequired("Windows journal bytes are incomplete or invalid; retain for recovery") from exc


@dataclass(frozen=True)
class WindowsTransactionSpec:
    transaction_id: str
    plan: Mapping[str, Any]
    slot_paths: Mapping[str, str]
    binding: ExchangeBinding

    def validate(self) -> None:
        validate_component(self.transaction_id)
        self.binding.validate()
        if (self.binding.target, self.binding.staged, self.binding.backup) != ("target", "staged", "backup"):
            raise ValueError("Windows coordinator requires target/staged/backup slot keys")
        if set(self.slot_paths) != {"target", "staged", "backup"}:
            raise ValueError("Windows transaction requires exactly three slot paths")
        if not isinstance(self.plan, Mapping):
            raise ValueError("Windows transaction requires a plan object")
        canonical_bytes(dict(self.plan))


@dataclass(frozen=True)
class WindowsCreationBinding:
    target: str
    staged: str
    after: LeafIdentity

    def validate(self) -> None:
        if (self.target, self.staged) != ("target", "staged"):
            raise ValueError("Windows creation requires target/staged slot keys")
        if not isinstance(self.after, LeafIdentity):
            raise ValueError("Windows creation requires an exact staged identity")
        self.after.validate()


@dataclass(frozen=True)
class WindowsCreationSpec:
    transaction_id: str
    plan: Mapping[str, Any]
    slot_paths: Mapping[str, str]
    binding: WindowsCreationBinding

    def validate(self) -> None:
        validate_component(self.transaction_id)
        self.binding.validate()
        if set(self.slot_paths) != {"target", "staged"}:
            raise ValueError("Windows creation requires exactly two slot paths")
        if not isinstance(self.plan, Mapping):
            raise ValueError("Windows creation requires a plan object")
        canonical_bytes(dict(self.plan))


class WindowsTransaction:
    """One held-lock transaction. Construct and call within a single process."""

    _schema = SCHEMA
    _states = _STATES
    _forward = _FORWARD
    _reverse = _REVERSE
    _spec_type = WindowsTransactionSpec

    def __init__(self, handles: Any, runtime_parent: Any, directory_template: Any,
                 file_template: Any, spec: WindowsTransactionSpec | WindowsCreationSpec):
        if type(spec) is not self._spec_type:
            raise ValueError("Windows transaction spec has the wrong operation type")
        spec.validate()
        # Freeze the inputs used by both the journal and held-path backend.
        # frozen=True on the dataclass alone does not detach nested mappings.
        plan_bytes = canonical_bytes(dict(spec.plan))
        spec = replace(spec, plan=loads_strict_json(plan_bytes),
                       slot_paths=MappingProxyType(dict(spec.slot_paths)))
        self.handles, self.spec = handles, spec
        self._file_template = file_template
        self._file_template_id = _handle_id(file_template)
        self._file_template_security = file_template.security()
        if not self._file_template_security.protected:
            raise WindowsJournalConflict("Windows journal template DACL is not protected")
        self._stack = ExitStack()
        self._closed = False
        self.plan_sha256 = hashlib.sha256(plan_bytes).hexdigest()
        self._runtime_id = _handle_id(runtime_parent)
        if not runtime_parent.info().directory:
            raise UnsafeWindowsPath("Windows runtime parent is not a directory")
        try:
            # A preexisting same-name transaction cannot be made trustworthy
            # by creating a fresh global lock beside it.
            try:
                with handles.open_child(runtime_parent, spec.transaction_id,
                                        kind="directory", pin_for_read=True):
                    existing_directory = True
            except WindowsHandleError as exc:
                if exc.operation != "NtCreateFile" or exc.ntstatus != _ABSENT:
                    raise
                existing_directory = False
            self.scope_lock = self._stack.enter_context(self._open_or_create_file_at(
                runtime_parent, "managed-scope.lock", file_template, for_lock=True,
                allow_create=not existing_directory))
            self.scope_lock.lock_exclusive()
            self._scope_lock_id = _handle_id(self.scope_lock)
            opened_directory, created_directory = self._open_or_create_directory(
                runtime_parent, spec.transaction_id, directory_template)
            self.directory = self._stack.enter_context(opened_directory)
            self._created_directory = created_directory
            self._directory_id = _handle_id(self.directory)
            if not created_directory:
                # No lock or new journal may be added to a preexisting unknown
                # transaction directory. The scope lock stabilizes this read.
                if self._read("intent.json") is None:
                    raise WindowsJournalConflict("Preexisting transaction directory lacks a valid intent")
            self.lock = self._stack.enter_context(self._open_or_create_file_at(
                self.directory, "lock", file_template, for_lock=True,
                allow_create=created_directory))
            self.lock.lock_exclusive()
            self._lock_id = _handle_id(self.lock)
            if not created_directory:
                self._check_intent()
            self.backend = self._stack.enter_context(WindowsExchangeBackend(handles, spec.slot_paths))
            if self._read("intent.json") is None and self._state() != "prepared":
                raise WindowsJournalConflict("Initial Windows transaction topology differs")
        except BaseException:
            self.close()
            raise

    def _open_or_create_directory(self, parent: Any, name: str, template: Any) -> tuple[Any, bool]:
        if not template.security().protected:
            raise WindowsJournalConflict("Windows directory template DACL is not protected")
        try:
            opened = self.handles.open_child(parent, name, kind="directory", for_publish=True)
            created = False
        except WindowsHandleError as exc:
            if exc.operation != "NtCreateFile" or exc.ntstatus != _ABSENT:
                raise
            opened = self.handles.create_directory_from_template(parent, name, template)
            created = True
        expected, actual = template.security(), opened.security()
        if (expected.owner_sid, expected.group_sid, expected.dacl, expected.protected) != (
                actual.owner_sid, actual.group_sid, actual.dacl, actual.protected):
            opened.close()
            raise WindowsJournalConflict("Transaction directory security differs from template")
        return opened, created

    def _open_or_create_file_at(self, parent: Any, name: str, template: Any, *,
                                for_lock: bool = False, allow_create: bool = False) -> Any:
        try:
            opened = self.handles.open_child(parent, name, kind="file", for_lock=for_lock,
                                             pin_for_read=not for_lock)
        except WindowsHandleError as exc:
            if exc.operation != "NtCreateFile" or exc.ntstatus != _ABSENT:
                raise
            if not allow_create:
                raise WindowsJournalConflict("Existing transaction is missing its lock file") from exc
            opened = self.handles.create_file_from_template(parent, name, template)
        expected, actual = template.security(), opened.security()
        if (expected.owner_sid, expected.group_sid, expected.dacl, expected.protected) != (
                actual.owner_sid, actual.group_sid, actual.dacl, actual.protected):
            opened.close()
            raise WindowsJournalConflict("Transaction file security differs from template")
        return opened

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._stack.close()

    def __enter__(self) -> WindowsTransaction:
        if self._closed:
            raise ValueError("Closed Windows transaction")
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _journal_limit(self, name: str) -> int:
        """Maximum encoded bytes for one journal record (including envelope)."""
        return _MAX_JOURNAL

    def _read(self, name: str) -> dict[str, Any] | None:
        if self._closed:
            raise ValueError("Closed Windows transaction")
        try:
            opened = self.handles.open_child(self.directory, name, kind="file", pin_for_read=True)
        except WindowsHandleError as exc:
            if exc.operation == "NtCreateFile" and exc.ntstatus == _ABSENT:
                return None
            raise
        with opened:
            info = opened.info()
            security = opened.security()
            limit = self._journal_limit(name)
            if info.size > limit:
                raise WindowsJournalConflict("Windows journal exceeds size limit")
            opened.seek(0)
            chunks = []
            remaining = info.size + 1
            while remaining:
                block = opened.read(min(remaining, _MAX_JOURNAL))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            data = b"".join(chunks)
            if (len(data) != info.size or opened.info() != info
                    or opened.security() != security):
                raise WindowsJournalConflict("Windows journal size changed during read")
        return _decode(data)

    def _write_once(self, name: str, body: dict[str, Any]) -> None:
        if (_handle_id(self._file_template) != self._file_template_id
                or self._file_template.security() != self._file_template_security):
            raise WindowsJournalConflict("Windows journal template changed")
        payload = _envelope(body)
        if len(payload) > self._journal_limit(name):
            raise WindowsJournalConflict("Windows journal checkpoint exceeds size limit")
        existing = self._read(name)
        if existing is not None:
            if existing != body:
                raise WindowsJournalConflict("Windows journal checkpoint collision")
            try:
                with self.handles.open_child(self.directory, name, kind="file", for_write=True) as held:
                    held.flush()
                if self._read(name) != body:
                    raise WindowsJournalConflict("Windows journal changed during reflush")
            except Exception as exc:
                raise WindowsRecoveryRequired(
                    f"Windows journal checkpoint {name} could not be reflushed") from exc
            return
        with self.handles.create_file_from_template(self.directory, name, self._file_template) as created:
            try:
                created.write_all(payload)
                created.flush()  # Actual FlushFileBuffers on a GENERIC_WRITE file handle.
                created.seek(0)
                received = bytearray()
                while len(received) < len(payload) + 1:
                    block = created.read(min(64 * 1024, len(payload) + 1 - len(received)))
                    if not block:
                        break
                    received.extend(block)
                if received != payload:
                    raise WindowsJournalConflict("Windows journal write did not read back exactly")
            except Exception as exc:
                raise WindowsRecoveryRequired(
                    f"Windows journal checkpoint {name} may be incomplete; bytes retained") from exc

    def _intent(self) -> dict[str, Any]:
        if hashlib.sha256(canonical_bytes(dict(self.spec.plan))).hexdigest() != self.plan_sha256:
            raise WindowsJournalConflict("Windows transaction plan snapshot changed")
        return {
            "schema": self._schema, "failure_model": FAILURE_MODEL,
            "transaction_id": self.spec.transaction_id,
            "plan_sha256": self.plan_sha256,
            "slot_paths": dict(self.spec.slot_paths),
            "binding": self._binding_record(),
            "runtime_parent_id": self._runtime_id,
            "scope_lock_id": self._scope_lock_id,
            "transaction_directory_id": self._directory_id,
            "lock_id": self._lock_id,
        }

    def _binding_record(self) -> dict[str, Any]:
        return {"before": _identity_record(self.spec.binding.before),
                "after": _identity_record(self.spec.binding.after)}

    def _check_intent(self) -> dict[str, Any]:
        value = self._read("intent.json")
        if value is None or value != self._intent():
            raise WindowsJournalConflict("Windows transaction intent or plan binding differs")
        return value

    def _marker_body(self, direction: str, state: str) -> dict[str, Any]:
        return {"schema": self._schema, "failure_model": FAILURE_MODEL,
                "intent_sha256": hashlib.sha256(_envelope(self._intent())).hexdigest(),
                "direction": direction, "topology": state}

    def _read_marker(self, name: str, *, direction: str, state: str) -> bool:
        value = self._read(name)
        if value is None:
            return False
        if value != self._marker_body(direction, state):
            raise WindowsJournalConflict("Windows checkpoint differs from intent")
        return True

    def _marker(self, name: str, *, direction: str, state: str) -> None:
        self._check_intent()
        self._write_once(name, self._marker_body(direction, state))

    def _audit_checkpoints(self) -> tuple[int, list[int]]:
        self._check_intent()
        peak = 0
        gap = False
        for index, state in enumerate(self._states[1:], start=1):
            present = self._read_marker(f"forward-{state}.json", direction="forward", state=state)
            if present and gap:
                raise WindowsJournalConflict("Windows checkpoint sequence has a gap")
            if present:
                peak = index
            gap = gap or not present
        rollback = [index for index in reversed(range(len(self._states) - 1)) if self._read_marker(
            f"rollback-{self._states[index]}.json", direction="rollback", state=self._states[index])]
        authorized = self._read_marker("rollback.json", direction="rollback", state="authorized")
        allowed = list(range(peak - 1, -1, -1)) if peak else [0]
        if rollback and (not authorized or rollback != allowed[:len(rollback)]):
            raise WindowsJournalConflict("Windows rollback checkpoint sequence differs from its start")
        return peak, rollback

    def _reconcile_arrival(self, direction: str) -> None:
        """Checkpoint at most one move that completed before its marker.

        Every move is followed by a flushed checkpoint before another move is
        permitted. Exact live topology can therefore be one step ahead of the
        journal, never several steps ahead or behind it.
        """
        peak, rollback = self._audit_checkpoints()
        current = self._states.index(self._state())
        if direction == "forward":
            if current not in {peak, peak + 1}:
                raise WindowsJournalConflict("Windows forward topology differs from checkpoint progress")
            if current:
                self._marker(f"forward-{self._states[current]}.json",
                             direction="forward", state=self._states[current])
            return
        last = rollback[-1] if rollback else peak
        if current not in {last, last - 1}:
            raise WindowsJournalConflict("Windows rollback topology differs from checkpoint progress")
        if current < last or rollback or peak == 0:
            self._marker(f"rollback-{self._states[current]}.json",
                         direction="rollback", state=self._states[current])

    def _state(self) -> str:
        try:
            return topology(self.backend, self.spec.binding)
        except ExchangeConflict as exc:
            raise WindowsJournalConflict("Windows transaction topology is ambiguous; objects retained") from exc

    def _run(self, transitions: dict[str, tuple[str, str, str, str]], *,
             direction: str, final: str) -> None:
        self._reconcile_arrival(direction)
        for _ in range(len(self._states) - 1):
            current = self._state()
            if current == final:
                return
            source, destination, which, next_state = transitions[current]
            self.backend.move_exact(source, destination, getattr(self.spec.binding, which))
            if self._state() != next_state:
                raise ExchangeConflict("Windows move left an unexpected topology")
            self._marker(f"{direction}-{next_state}.json", direction=direction, state=next_state)
        if self._state() != final:
            raise ExchangeConflict("Windows exchange did not reach final topology")

    def apply(self) -> str:
        """Return committed; leave a recoverable intent on any interruption."""
        if (self._read_marker("rolled-back.json", direction="rollback", state="prepared")
                or self._read_marker("rollback.json", direction="rollback", state="authorized")):
            raise WindowsJournalConflict("Windows transaction has entered rollback")
        terminal = self._states[-1]
        committed = self._read_marker("committed.json", direction="forward", state=terminal)
        if committed:
            self._check_intent()
            self._audit_checkpoints()
            if not self._read_marker(f"forward-{terminal}.json", direction="forward", state=terminal):
                raise WindowsJournalConflict("Committed Windows exchange lacks final checkpoint")
            if self._state() != terminal:
                raise WindowsJournalConflict("Committed topology changed")
            self._marker("committed.json", direction="forward", state=terminal)
            return "committed"
        existing = self._read("intent.json")
        if existing is None:
            if self._state() != "prepared":
                raise WindowsJournalConflict("Cannot start without exact prepared topology")
            self._write_once("intent.json", self._intent())
        else:
            self._check_intent()
            self._write_once("intent.json", self._intent())
        self._audit_checkpoints()
        self._run(self._forward, direction="forward", final=terminal)
        self._marker("committed.json", direction="forward", state=terminal)
        return "committed"

    def recover(self) -> str:
        """Repeated recovery rolls an uncommitted intent back; retains conflicts."""
        self._check_intent()
        self._write_once("intent.json", self._intent())
        self._audit_checkpoints()
        terminal = self._states[-1]
        committed = self._read_marker("committed.json", direction="forward", state=terminal)
        rolled_back = self._read_marker("rolled-back.json", direction="rollback", state="prepared")
        rollback_authorized = self._read_marker("rollback.json", direction="rollback", state="authorized")
        if committed and rolled_back:
            raise WindowsJournalConflict("Windows transaction has conflicting terminal markers")
        if committed and rollback_authorized:
            raise WindowsJournalConflict("Committed Windows transaction also authorizes rollback")
        if committed and not self._read_marker(f"forward-{terminal}.json", direction="forward", state=terminal):
            raise WindowsJournalConflict("Committed Windows exchange lacks final checkpoint")
        if rolled_back and (not rollback_authorized or not self._read_marker(
                "rollback-prepared.json", direction="rollback", state="prepared")):
            raise WindowsJournalConflict("Rolled-back Windows exchange lacks recovery checkpoints")
        if committed:
            if self._state() != terminal:
                raise WindowsJournalConflict("Committed Windows topology changed")
            self._marker("committed.json", direction="forward", state=terminal)
            return "committed"
        if rolled_back:
            if self._state() != "prepared":
                raise WindowsJournalConflict("Rolled-back Windows topology changed")
            self._marker("rolled-back.json", direction="rollback", state="prepared")
            return "rolled_back"
        if not rollback_authorized:
            # Record an interrupted forward arrival before fixing the rollback
            # start. Later rollback must not reinterpret forward progress.
            self._reconcile_arrival("forward")
        self._marker("rollback.json", direction="rollback", state="authorized")
        self._run(self._reverse, direction="rollback", final="prepared")
        self._marker("rolled-back.json", direction="rollback", state="prepared")
        return "rolled_back"


class WindowsCreationTransaction(WindowsTransaction):
    """Publish one exact staged file into a verified-absent destination.

    A separate schema prevents a replacement journal from granting creation
    authority. The caller must establish plan/provenance authority before this
    primitive; observing absence alone does not establish historical ownership.
    Rollback returns the exact created object to its private staged slot. It
    never deletes a foreign collision or infers that a name is operation-owned.
    """

    _schema = "naos.upgrade.windows_creation_transaction.v1"
    _states = ("prepared", "published")
    _forward = {"prepared": ("staged", "target", "after", "published")}
    _reverse = {"published": ("target", "staged", "after", "prepared")}
    _spec_type = WindowsCreationSpec

    def _binding_record(self) -> dict[str, Any]:
        return {"after": _identity_record(self.spec.binding.after)}

    def _state(self) -> str:
        observed = (self.backend.observe("target"), self.backend.observe("staged"))
        if observed == (None, self.spec.binding.after):
            return "prepared"
        if observed == (self.spec.binding.after, None):
            return "published"
        raise WindowsJournalConflict("Windows creation topology is ambiguous; objects retained")
