"""One recoverable Windows operation across ordered file publications.

Application-process-failure recovery only. Versions 1/2 commit at the global
marker. Explicit version 3 commits when the exact final manifest is installed;
recovery then finishes forward, including its one witnessed rename transient.
No leaf WindowsTransaction.apply() is called by this coordinator.
"""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass, replace
import hashlib
import re
from types import MappingProxyType
from typing import Any, Mapping

from .canonical import canonical_bytes, loads_strict_json
from .windows_backend import _split_leaf
from .windows_coordinator import (FAILURE_MODEL, WindowsJournalConflict, WindowsTransaction,
                                  _ABSENT, _decode, _envelope, _handle_id, _identity_record)
from .windows_exchange import LeafIdentity
from .windows_restoring_backend import WindowsRestoringBackend
from .windows_v1_restoring_backend import _WindowsV1RestoringBackend
from .windows_rename_identity import (RenameIdentity, identity_record as _rename_record,
                                     identity_from_record as _rename_from_record)
from .windows_handles import UnsafeWindowsPath, WindowsHandleError, validate_component


SCHEMA = 'naos.upgrade.windows_operation.v1'
PLAN_SCHEMA = 'naos.upgrade.windows_operation_plan.v1'
SCHEMA_V2 = 'naos.upgrade.windows_operation.v2'
PLAN_SCHEMA_V2 = 'naos.upgrade.windows_operation_plan.v2'
SCHEMA_V3 = 'naos.upgrade.windows_operation.v3'
PLAN_SCHEMA_V3 = 'naos.upgrade.windows_operation_plan.v3'
_ROLE_ORDER = {'content': 0, 'evidence': 1, 'manifest': 2}
_TX_ID = re.compile(r'WOP-[0-9a-f]{16}\Z')
_MAX_OPERATION_INTENT = 16 * 1024 * 1024
_HEX = re.compile(r'[0-9a-f]+\Z')


def _identity_from_record(value: Any) -> LeafIdentity:
    if not isinstance(value, dict) or set(value) != {
            'volume_serial_hex', 'file_id_hex', 'size_bytes',
            'content_sha256', 'metadata_sha256'}:
        raise WindowsJournalConflict('Invalid operation identity record')
    volume, file_id, size = (value['volume_serial_hex'], value['file_id_hex'],
                             value['size_bytes'])
    if (not isinstance(volume, str) or len(volume) != 16 or not _HEX.fullmatch(volume)
            or not isinstance(file_id, str) or len(file_id) != 32 or not _HEX.fullmatch(file_id)
            or not isinstance(size, str) or not size.isascii() or not size.isdecimal()
            or (len(size) > 1 and size[0] == '0') or len(size) > 20):
        raise WindowsJournalConflict('Invalid operation identity encoding')
    result = LeafIdentity(int(volume, 16), bytes.fromhex(file_id), int(size),
                          value['content_sha256'], value['metadata_sha256'])
    try:
        result.validate()
    except ValueError as exc:
        raise WindowsJournalConflict('Invalid operation identity') from exc
    return result


def _read_existing_record(handles: Any, directory: Any, name: str, limit: int) -> dict[str, Any]:
    try:
        opened = handles.open_child(directory, name, kind='file', pin_for_read=True)
    except WindowsHandleError as exc:
        if exc.operation == 'NtCreateFile' and exc.ntstatus == _ABSENT:
            raise WindowsJournalConflict(f'Existing operation lacks {name}') from exc
        raise
    with opened:
        before, security = opened.info(), opened.security()
        if before.size > limit:
            raise WindowsJournalConflict(f'Operation {name} exceeds size limit')
        opened.seek(0)
        chunks, remaining = [], before.size + 1
        while remaining:
            block = opened.read(min(64 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b''.join(chunks)
        if len(data) != before.size or opened.info() != before or opened.security() != security:
            raise WindowsJournalConflict(f'Operation {name} changed during read')
    return _decode(data)


@dataclass(frozen=True)
class Publication:
    role: str
    kind: str
    target: str
    staged: str
    after: LeafIdentity
    backup: str | None = None
    before: LeafIdentity | None = None

    def validate(self) -> None:
        if self.role not in _ROLE_ORDER or self.kind not in {'create', 'replace'}:
            raise ValueError('Unsupported Windows publication role or kind')
        if not isinstance(self.after, LeafIdentity):
            raise ValueError('Publication lacks exact staged identity')
        self.after.validate()
        if self.kind == 'create':
            if self.before is not None or self.backup is not None:
                raise ValueError('Creation must have target and staged slots only')
        else:
            if not isinstance(self.before, LeafIdentity) or not isinstance(self.backup, str):
                raise ValueError('Replacement requires before and backup')
            self.before.validate()
            if (self.before.volume != self.after.volume
                    or self.before.file_id == self.after.file_id):
                raise ValueError('Replacement identities must be distinct on one volume')
        if self.role == 'evidence' and self.kind != 'create':
            raise ValueError('Evidence records must be immutable no-replace creations')
        names = self.slots()
        if any(not isinstance(name, str) or not name for name in names):
            raise ValueError('Publication slot keys must be nonempty')
        if len(names) != len(set(names)):
            raise ValueError('Publication slot keys overlap')

    def slots(self) -> tuple[str, ...]:
        return ((self.target, self.staged) if self.kind == 'create'
                else (self.target, self.staged, self.backup))  # type: ignore[return-value]

    def state_count(self) -> int:
        return 1 if self.kind == 'create' else 2


@dataclass(frozen=True)
class WindowsOperationSpec:
    operation_id: str
    plan: Mapping[str, Any]
    slot_paths: Mapping[str, str]
    publications: tuple[Publication, ...]
    record_version: int = 1

    def validate(self) -> None:
        if type(self.record_version) is not int or self.record_version not in (1, 2, 3):
            raise ValueError('Unsupported Windows operation record version')
        if not isinstance(self.operation_id, str) or not _TX_ID.fullmatch(self.operation_id):
            raise ValueError('Windows operation ID must be WOP followed by 16 lowercase hex digits')
        validate_component(self.operation_id)
        if not isinstance(self.plan, Mapping):
            raise ValueError('Windows operation requires a canonical plan')
        canonical_bytes(dict(self.plan))
        if not isinstance(self.publications, tuple) or not self.publications:
            raise ValueError('Windows operation requires ordered publications')
        roles = []
        slot_keys = []
        native_ids: set[tuple[int, bytes]] = set()
        for publication in self.publications:
            if not isinstance(publication, Publication):
                raise ValueError('Invalid Windows publication')
            publication.validate()
            roles.append(publication.role)
            slot_keys.extend(publication.slots())
            for identity in (publication.before, publication.after):
                if identity is not None:
                    expected_type = RenameIdentity if self.record_version >= 2 else LeafIdentity
                    if type(identity) is not expected_type:
                        raise ValueError('Operation version and identity witness differ')
                    key = identity.volume, identity.file_id
                    if key in native_ids:
                        raise ValueError('One native file identity appears in multiple publications')
                    native_ids.add(key)
        if roles[-1] != 'manifest' or roles.count('manifest') != 1:
            raise ValueError('Exactly one final manifest publication is required')
        if 'evidence' not in roles:
            raise ValueError('Immutable evidence must precede manifest publication')
        if roles != sorted(roles, key=_ROLE_ORDER.__getitem__):
            raise ValueError('Content, evidence, manifest publication order differs')
        if len(slot_keys) != len(set(slot_keys)) or set(self.slot_paths) != set(slot_keys):
            raise ValueError('Operation slot keys overlap or are missing')
        physical = []
        for key in slot_keys:
            path = self.slot_paths[key]
            if not isinstance(path, str):
                raise ValueError('Operation slot path is not a Windows path')
            root, parents, leaf = _split_leaf(path)
            physical.append((root.casefold(), *(p.casefold() for p in parents), leaf.casefold()))
        if len(physical) != len(set(physical)):
            raise ValueError('Operation slots are aliases or duplicate paths')



def _spec_from_records(operation_id: str, plan_record: dict, intent: dict) -> WindowsOperationSpec:
    """Decode historical operation records without opening native objects.

    Live recovery still constructs the operation and rechecks held identities.
    This pure record seam supplies no current-host custody or mutation authority.
    """
    if not isinstance(operation_id, str) or not _TX_ID.fullmatch(operation_id):
        raise WindowsJournalConflict("Invalid operation ID for journal recovery")
    if (not isinstance(plan_record, dict) or set(plan_record) != {
            'schema', 'operation_id', 'plan', 'plan_sha256'}
            or plan_record['schema'] not in (PLAN_SCHEMA, PLAN_SCHEMA_V2, PLAN_SCHEMA_V3)
            or plan_record['operation_id'] != operation_id
            or not isinstance(plan_record['plan'], dict)):
        raise WindowsJournalConflict('Operation plan record has unsupported schema')
    record_version = {PLAN_SCHEMA: 1, PLAN_SCHEMA_V2: 2, PLAN_SCHEMA_V3: 3}[plan_record['schema']]
    operation_schema = {1: SCHEMA, 2: SCHEMA_V2, 3: SCHEMA_V3}[record_version]
    decode_identity = _rename_from_record if record_version >= 2 else _identity_from_record
    plan_bytes = canonical_bytes(plan_record['plan'])
    plan_sha256 = hashlib.sha256(plan_bytes).hexdigest()
    if plan_record['plan_sha256'] != plan_sha256:
        raise WindowsJournalConflict('Operation plan record digest differs')
    required = {'schema', 'failure_model', 'operation_id', 'plan_sha256',
                'slot_paths', 'publications', 'runtime_parent_id',
                'scope_lock_id', 'transaction_directory_id', 'lock_id'}
    if (not isinstance(intent, dict) or set(intent) != required
            or intent['schema'] != operation_schema or intent['failure_model'] != FAILURE_MODEL
            or intent['operation_id'] != operation_id
            or intent['plan_sha256'] != plan_sha256
            or not isinstance(intent['slot_paths'], dict)
            or not isinstance(intent['publications'], list)):
        raise WindowsJournalConflict('Operation intent has unsupported schema or plan')
    publications = []
    for row in intent['publications']:
        if not isinstance(row, dict) or row.get('kind') not in ('create', 'replace'):
            raise WindowsJournalConflict('Invalid operation publication record')
        required_row = ({'role', 'kind', 'target', 'staged', 'after'}
                        if row['kind'] == 'create' else
                        {'role', 'kind', 'target', 'staged', 'backup', 'before', 'after'})
        if set(row) != required_row:
            raise WindowsJournalConflict('Operation publication fields differ')
        try:
            publications.append(Publication(
                row['role'], row['kind'], row['target'], row['staged'],
                decode_identity(row['after']), row.get('backup'),
                decode_identity(row['before']) if row['kind'] == 'replace' else None))
        except (TypeError, ValueError, KeyError) as exc:
            raise WindowsJournalConflict('Invalid operation publication values') from exc
    spec = WindowsOperationSpec(operation_id, plan_record['plan'],
                                intent['slot_paths'], tuple(publications), record_version)
    try:
        spec.validate()
    except (TypeError, ValueError, KeyError) as exc:
        raise WindowsJournalConflict('Recovered operation spec differs') from exc
    return spec


@dataclass(frozen=True)
class _Step:
    publication_index: int
    local_rank: int
    source: str
    destination: str
    identity: LeafIdentity


def _steps(publications: tuple[Publication, ...]) -> tuple[_Step, ...]:
    result: list[_Step] = []
    for index, item in enumerate(publications):
        if item.kind == 'create':
            result.append(_Step(index, 0, item.staged, item.target, item.after))
        else:
            assert item.before is not None and item.backup is not None
            result.extend((_Step(index, 0, item.target, item.backup, item.before),
                           _Step(index, 1, item.staged, item.target, item.after)))
    return tuple(result)


class WindowsOperation(WindowsTransaction):
    """One scope lock, one intent, ordered exact moves and global rollback."""

    _schema = SCHEMA

    def __init__(self, handles: Any, runtime_parent: Any, directory_template: Any,
                 file_template: Any, spec: WindowsOperationSpec,
                 *, held_scope_lock: Any | None = None):
        if type(spec) is not WindowsOperationSpec:
            raise ValueError('Windows operation requires its own spec')
        spec.validate()
        plan_bytes = canonical_bytes(dict(spec.plan))
        frozen = replace(spec, plan=loads_strict_json(plan_bytes),
                         slot_paths=MappingProxyType(dict(spec.slot_paths)))
        self.handles, self.spec = handles, frozen
        self._schema = {1: SCHEMA, 2: SCHEMA_V2, 3: SCHEMA_V3}[spec.record_version]
        self._plan_schema = {1: PLAN_SCHEMA, 2: PLAN_SCHEMA_V2, 3: PLAN_SCHEMA_V3}[spec.record_version]
        self._steps = _steps(frozen.publications)
        self.total_steps = len(self._steps)
        self._plan_bytes = plan_bytes
        self.plan_sha256 = hashlib.sha256(plan_bytes).hexdigest()
        self._file_template = file_template
        self._file_template_id = _handle_id(file_template)
        self._file_template_security = file_template.security()
        if not self._file_template_security.protected:
            raise WindowsJournalConflict('Windows journal template DACL is not protected')
        self._stack, self._closed = ExitStack(), False
        self._runtime_id = _handle_id(runtime_parent)
        if not runtime_parent.info().directory:
            raise UnsafeWindowsPath('Windows runtime parent is not a directory')
        try:
            try:
                with handles.open_child(runtime_parent, spec.operation_id,
                                        kind='directory', pin_for_read=True):
                    existing_directory = True
            except WindowsHandleError as exc:
                if exc.operation != 'NtCreateFile' or exc.ntstatus != _ABSENT:
                    raise
                existing_directory = False
            if held_scope_lock is None:
                self.scope_lock = self._stack.enter_context(self._open_or_create_file_at(
                    runtime_parent, 'managed-scope.lock', file_template, for_lock=True,
                    allow_create=not existing_directory))
                self.scope_lock.lock_exclusive()
            else:
                # The caller retains ownership. Only an already-exclusive held
                # lock with the expected protected descriptor may be borrowed.
                if (getattr(held_scope_lock, '_lock', None) is None
                        and not getattr(held_scope_lock, 'owns_lock', False)):
                    raise WindowsJournalConflict('Borrowed scope lock is not held exclusively')
                security = held_scope_lock.security()
                expected = self._file_template_security
                if (security.owner_sid, security.group_sid, security.dacl, security.protected) != (
                        expected.owner_sid, expected.group_sid, expected.dacl, expected.protected):
                    raise WindowsJournalConflict('Borrowed scope lock security differs')
                if getattr(held_scope_lock, 'value', 1) is None:
                    raise WindowsJournalConflict('Borrowed scope lock is closed')
                self.scope_lock = held_scope_lock
            self._scope_lock_id = _handle_id(self.scope_lock)
            directory, created_directory = self._open_or_create_directory(
                runtime_parent, spec.operation_id, directory_template)
            self.directory = self._stack.enter_context(directory)
            self._created_directory = created_directory
            self._directory_id = _handle_id(self.directory)
            if not created_directory and self._read('intent.json') is None:
                raise WindowsJournalConflict('Preexisting operation directory lacks intent')
            self.lock = self._stack.enter_context(self._open_or_create_file_at(
                self.directory, 'lock', file_template, for_lock=True,
                allow_create=created_directory))
            self.lock.lock_exclusive()
            self._lock_id = _handle_id(self.lock)
            self._intent_bytes = _envelope(self._build_intent())
            self._intent_sha256 = hashlib.sha256(self._intent_bytes).hexdigest()
            if not created_directory:
                self._check_plan_record()
                self._check_intent()
            backend_type = WindowsRestoringBackend if spec.record_version >= 2 else _WindowsV1RestoringBackend
            self.backend = self._stack.enter_context(backend_type(handles, self.spec.slot_paths))
            if self._read('intent.json') is None and self._progress() != 0:
                raise WindowsJournalConflict('New operation has non-prepared topology')
        except BaseException:
            self.close()
            raise

    @classmethod
    def from_journal(cls, handles: Any, runtime_parent: Any,
                     directory_template: Any, file_template: Any,
                     operation_id: str, *, held_scope_lock: Any | None = None) -> WindowsOperation:
        """Recover a spec solely from existing canonical records, then rebind.

        This discovery phase creates nothing. The regular constructor obtains
        both kernel locks and rechecks all records and held object identities.
        """
        if not isinstance(operation_id, str) or not _TX_ID.fullmatch(operation_id):
            raise WindowsJournalConflict('Invalid operation ID for journal recovery')
        with handles.open_child(runtime_parent, operation_id, kind='directory',
                                pin_for_read=True) as directory:
            plan_record = _read_existing_record(handles, directory, 'plan.json',
                                                _MAX_OPERATION_INTENT)
            intent = _read_existing_record(handles, directory, 'intent.json',
                                           _MAX_OPERATION_INTENT)
        spec = _spec_from_records(operation_id, plan_record, intent)
        return cls(handles, runtime_parent, directory_template, file_template, spec,
                   held_scope_lock=held_scope_lock)

    def _binding_record(self) -> list[dict[str, Any]]:
        rows = []
        encode_identity = _rename_record if self.spec.record_version >= 2 else _identity_record
        for item in self.spec.publications:
            row = {'role': item.role, 'kind': item.kind,
                   'target': item.target, 'staged': item.staged,
                   'after': encode_identity(item.after)}
            if item.kind == 'replace':
                assert item.before is not None and item.backup is not None
                row.update({'backup': item.backup, 'before': encode_identity(item.before)})
            rows.append(row)
        return rows

    def _journal_limit(self, name: str) -> int:
        return (_MAX_OPERATION_INTENT if name in {'plan.json', 'intent.json'}
                else super()._journal_limit(name))

    def _plan_record(self) -> dict[str, Any]:
        return {'schema': self._plan_schema, 'operation_id': self.spec.operation_id,
                'plan': loads_strict_json(self._plan_bytes),
                'plan_sha256': self.plan_sha256}

    def _check_plan_record(self) -> None:
        if self._read('plan.json') != self._plan_record():
            raise WindowsJournalConflict('Operation plan journal differs')

    def _validate_plan_snapshot(self) -> None:
        if canonical_bytes(dict(self.spec.plan)) != self._plan_bytes:
            raise WindowsJournalConflict('Windows operation plan snapshot changed')

    def _build_intent(self) -> dict[str, Any]:
        return {'schema': self._schema, 'failure_model': FAILURE_MODEL,
                'operation_id': self.spec.operation_id, 'plan_sha256': self.plan_sha256,
                'slot_paths': dict(self.spec.slot_paths), 'publications': self._binding_record(),
                'runtime_parent_id': self._runtime_id, 'scope_lock_id': self._scope_lock_id,
                'transaction_directory_id': self._directory_id, 'lock_id': self._lock_id}

    def _intent(self) -> dict[str, Any]:
        # The bound bytes are immutable. Return a fresh value to prevent callers
        # from changing the intent used by subsequent checkpoints.
        return loads_strict_json(self._intent_bytes)['body']

    def _marker_body(self, direction: str, state: str) -> dict[str, Any]:
        return {'schema': self._schema, 'failure_model': FAILURE_MODEL,
                'intent_sha256': self._intent_sha256,
                'direction': direction, 'topology': state}

    def _audit_v1_namespace(self):
        """Complete v1 names, bodies and contiguous direction before any write."""
        if self.spec.record_version != 1:
            return None
        limit = 2 * self.total_steps + 6
        names = self.handles.list_children(self.directory, max_entries=limit,
                                          max_name_bytes=limit * 64)
        if (type(names) is not tuple or len(names) > limit
                or any(type(name) is not str for name in names)
                or len(set(names)) != len(names)):
            raise WindowsJournalConflict('Invalid v1 operation journal inventory')
        allowed = {'lock', 'plan.json', 'intent.json', 'committed.json'}
        allowed.update(self._forward_name(i) for i in range(1, self.total_steps + 1))
        start = self._read_rollback_start()
        if start is not None:
            allowed.update(('rollback.json', 'rolled-back.json'))
            allowed.update(self._rollback_name(i) for i in range(start))
        if 'lock' not in names or not set(names) <= allowed:
            raise WindowsJournalConflict('Unknown or orphan v1 operation journal entry')
        if 'plan.json' in names:
            self._check_plan_record()
        if 'intent.json' not in names:
            if (not self._created_directory or not set(names) <= {'lock', 'plan.json'}):
                raise WindowsJournalConflict('V1 operation authority is incomplete')
            return 0, None, 0, False, False
        if 'plan.json' not in names:
            raise WindowsJournalConflict('V1 intent lacks its canonical plan')
        self._check_intent()
        peak = self._audit_forward()
        completed = self._audit_rollback(start) if start is not None else 0
        committed = self._read_marker('committed.json', direction='forward', state='committed')
        rolled = self._read_marker('rolled-back.json', direction='rollback', state='prepared')
        if (start is not None and start != peak
                or committed and (start is not None or rolled or peak != self.total_steps)
                or rolled and (start is None or completed != start)):
            raise WindowsJournalConflict('V1 operation terminal or rollback order differs')
        final = self.handles.list_children(self.directory, max_entries=limit,
                                          max_name_bytes=limit * 64)
        if set(final) != set(names) or len(final) != len(names):
            raise WindowsJournalConflict('V1 journal namespace changed during audit')
        return peak, start, completed, committed, rolled

    def _preflight_v1(self):
        """Read-only qualification before plan/intent writer-open or repair."""
        if self.spec.record_version != 1:
            return
        peak, start, completed, committed, rolled = self._audit_v1_namespace()
        if self._read('intent.json') is None:
            if self._progress() != 0:
                raise WindowsJournalConflict('New v1 operation is not exactly prepared')
            return
        count = start - completed if start is not None else peak
        observed = {key: self.backend.observe(key) for key in self.spec.slot_paths}
        if observed == self._v1_expected(count):
            return
        index = count - 1 if start is not None else count
        if not committed and not rolled and 0 <= index < self.total_steps:
            step = self._steps[index]
            destination = step.source if start is not None else step.destination
            after = count - 1 if start is not None else count + 1
            wanted = self._v1_expected(after)
            if (observed[destination] is not None and all(observed[k] == value
                    for k, value in wanted.items() if k != destination)
                    and self.backend.pending_matches(destination, step.identity)):
                return  # One finite unmarked pending move; this observes only.
        raise WindowsJournalConflict('Operation leaf topology is ambiguous; retain objects')

    def _v1_expected(self, count):
        expected = {key: None for key in self.spec.slot_paths}
        for item in self.spec.publications:
            expected[item.staged] = item.after
            expected[item.target] = item.before
        for step in self._steps[:count]:
            expected[step.source] = None
            expected[step.destination] = step.identity
        return expected

    def _assert_v1_topology(self, count, *, pending=None, observed=None):
        for key, expected in self._v1_expected(count).items():
            actual = observed if key == pending else self.backend.observe(key)
            if key == pending:
                # The held destination's finite witness was checked by backend.
                continue
            if actual != expected:
                raise WindowsJournalConflict('V1 full operation topology differs; retain objects')

    def _repair_v1_pending(self, index, *, reverse):
        peak, start, completed, committed, rolled = self._audit_v1_namespace()
        authorized = start - completed - 1 if reverse and start is not None else peak
        if (committed or rolled or index != authorized
                or reverse and start is None or not reverse and start is not None):
            raise WindowsJournalConflict('V1 repair is not the single authorized pending step')
        step = self._steps[index]
        source, destination = ((step.destination, step.source) if reverse
                               else (step.source, step.destination))
        before = index + 1 if reverse else index
        after = index if reverse else index + 1
        observed = {key: self.backend.observe(key) for key in self.spec.slot_paths}
        if observed == self._v1_expected(before):
            return  # No rename has occurred; nothing may be repaired.
        wanted = self._v1_expected(after)
        if observed == wanted:
            return  # Exact completed rename needs no metadata mutation rights.
        if (observed[destination] is None or any(observed[k] != value
                for k, value in wanted.items() if k != destination)):
            raise WindowsJournalConflict('V1 pending operation topology differs; retain objects')
        if not self.backend.pending_matches(destination, step.identity):
            raise WindowsJournalConflict('V1 pending metadata lacks finite repair authority')
        def held_audit(actual):
            current = self._audit_v1_namespace()
            if current != (peak, start, completed, committed, rolled):
                raise WindowsJournalConflict('V1 pending journal authority changed')
            self._assert_v1_topology(after, pending=destination, observed=actual)
        self.backend.restore_pending(source, destination, step.identity, audit=held_audit)
        self._assert_v1_topology(after)

    def _audit_v3_namespace(self) -> None:
        """Refuse unknown or unauthorised marker names before any v3 repair.

        This does not reinterpret older journal formats. Their consumers retain
        the original contract; the manifest-commit variant has its own complete
        operation-directory inventory and rollback-authorisation boundary.
        """
        if self.spec.record_version != 3:
            return
        limit = 2 * self.total_steps + 5
        names = self.handles.list_children(self.directory, max_entries=limit,
                                          max_name_bytes=limit * 64)
        if (type(names) is not tuple or len(names) > limit
                or any(type(name) is not str for name in names)
                or len(set(names)) != len(names)):
            raise WindowsJournalConflict('Invalid manifest-commit journal inventory')
        allowed = {'lock', 'plan.json', 'intent.json', 'committed.json'}
        allowed.update(self._forward_name(step) for step in range(1, self.total_steps + 1))
        start = self._read_rollback_start()
        if start is not None:
            if start == self.total_steps or 'committed.json' in names:
                raise WindowsJournalConflict('Manifest-commit journal has conflicting rollback authority')
            allowed.update(('rollback.json', 'rolled-back.json'))
            allowed.update(self._rollback_name(step) for step in range(start))
        if 'lock' not in names or not set(names) <= allowed:
            raise WindowsJournalConflict('Unknown or unauthorised manifest-commit journal entry')

    def _marker(self, name: str, *, direction: str, state: str) -> None:
        # apply()/recover() validate the bound plan and persisted intent on
        # entry. Re-serializing the whole operation for each move is quadratic.
        self._audit_v1_namespace()
        self._audit_v3_namespace()
        self._write_once(name, self._marker_body(direction, state))

    def _item_rank(self, index: int) -> int:
        item = self.spec.publications[index]
        target = self.backend.observe(item.target)
        staged = self.backend.observe(item.staged)
        if item.kind == 'create':
            if (target, staged) == (None, item.after):
                return 0
            if (target, staged) == (item.after, None):
                return 1
        else:
            assert item.before is not None and item.backup is not None
            backup = self.backend.observe(item.backup)
            observed = target, staged, backup
            states = ((item.before, item.after, None),
                      (None, item.after, item.before),
                      (item.after, None, item.before))
            for rank, expected in enumerate(states):
                if observed == expected:
                    return rank
        raise WindowsJournalConflict('Operation leaf topology is ambiguous; retain objects')

    def _progress(self) -> int:
        """Scan each leaf once; at most one item may be partially published."""
        progress, partial = 0, False
        for index, item in enumerate(self.spec.publications):
            rank = self._item_rank(index)
            if partial and rank != 0:
                raise WindowsJournalConflict('Operation publication order is ambiguous')
            if not partial:
                progress += rank
                if rank != item.state_count():
                    partial = True
        return progress

    def _forward_name(self, step: int) -> str:
        return f'forward-{step:06d}.json'

    def _rollback_name(self, remaining: int) -> str:
        return f'rollback-{remaining:06d}.json'

    def _audit_forward(self) -> int:
        peak, gap = 0, False
        for step in range(1, self.total_steps + 1):
            present = self._read_marker(self._forward_name(step), direction='forward',
                                        state=f'step:{step}')
            if present and gap:
                raise WindowsJournalConflict('Operation forward markers have a gap')
            if present:
                peak = step
            gap = gap or not present
        return peak

    def _rollback_body(self, start: int) -> dict[str, Any]:
        return {'schema': self._schema, 'failure_model': FAILURE_MODEL,
                'intent_sha256': self._intent_sha256,
                'start_step_decimal': str(start)}

    def _read_rollback_start(self) -> int | None:
        value = self._read('rollback.json')
        if value is None:
            return None
        if (not isinstance(value, dict) or set(value) != set(self._rollback_body(0))
                or value.get('schema') != self._schema or value.get('failure_model') != FAILURE_MODEL
                or value.get('intent_sha256') != self._intent_sha256
                or not isinstance(value.get('start_step_decimal'), str)
                or len(value['start_step_decimal']) > len(str(self.total_steps))
                or not value['start_step_decimal'].isdecimal()
                or str(int(value['start_step_decimal'])) != value['start_step_decimal']):
            raise WindowsJournalConflict('Operation rollback authorization differs from intent')
        start = int(value['start_step_decimal'])
        if not 0 <= start <= self.total_steps:
            raise WindowsJournalConflict('Operation rollback start is outside plan')
        return start

    def _audit_rollback(self, start: int) -> int:
        completed, gap = 0, False
        for remaining in range(start - 1, -1, -1):
            present = self._read_marker(self._rollback_name(remaining),
                                        direction='rollback', state=f'step:{remaining}')
            if present and gap:
                raise WindowsJournalConflict('Operation rollback markers have a gap')
            if present:
                completed += 1
            gap = gap or not present
        return completed

    def _reconcile_forward(self, peak: int) -> int:
        if peak < self.total_steps:
            self._repair_pending_move(peak, reverse=False)
        actual = self._progress()
        if actual not in (peak, peak + 1):
            raise WindowsJournalConflict('Operation topology differs from forward checkpoint')
        if actual == peak + 1:
            self._marker(self._forward_name(actual), direction='forward',
                         state=f'step:{actual}')
        return actual

    def _reconcile_rollback(self, start: int) -> int:
        completed = self._audit_rollback(start)
        expected = start - completed
        if expected > 0:
            self._repair_pending_move(expected - 1, reverse=True)
        actual = self._progress()
        if actual not in (expected, expected - 1):
            raise WindowsJournalConflict('Operation topology differs from rollback checkpoint')
        if actual == expected - 1:
            self._marker(self._rollback_name(actual), direction='rollback',
                         state=f'step:{actual}')
        return actual

    def _repair_pending_move(self, step_index: int, *, reverse: bool) -> None:
        """Restore only the single next unmarked move after a full topology audit.

        This is called only after persisted intent, marker ordering and absence
        of a terminal state were verified. It never repairs recorded steps.
        """
        if self.spec.record_version == 1:
            self._repair_v1_pending(step_index, reverse=reverse)
            return
        step = self._steps[step_index]
        source, destination = ((step.destination, step.source) if reverse
                               else (step.source, step.destination))
        expected = {key: None for key in self.spec.slot_paths}
        for item in self.spec.publications:
            expected[item.staged] = item.after
            expected[item.target] = item.before
        final_count = step_index if reverse else step_index + 1
        for done in self._steps[:final_count]:
            expected[done.source] = None
            expected[done.destination] = done.identity
        # All other objects must already be exact, including later publications.
        # A mismatch is left for the strict rank reader to reject without writes.
        observed = {key: self.backend.observe(key) for key in expected}
        if observed[destination] is None or observed[destination] == step.identity:
            return
        if any(observed[key] != value for key, value in expected.items()
               if key != destination):
            return
        if not self.backend.pending_matches(destination, step.identity):
            return
        self.backend.restore_pending(source, destination, step.identity)

    def _run_forward(self, position: int) -> None:
        while position < self.total_steps:
            step = self._steps[position]
            if self._item_rank(step.publication_index) != step.local_rank:
                raise WindowsJournalConflict('Next publication topology changed')
            if self.spec.record_version == 1:
                peak, start, _completed, committed, rolled = self._audit_v1_namespace()
                if peak != position or start is not None or committed or rolled:
                    raise WindowsJournalConflict('V1 next forward step lacks journal authority')
                self._assert_v1_topology(position)
            self.backend.move_exact(step.source, step.destination, step.identity)
            if self.spec.record_version == 1:
                self._repair_v1_pending(position, reverse=False)
            if self._item_rank(step.publication_index) != step.local_rank + 1:
                raise WindowsJournalConflict('Publication move outcome differs')
            position += 1
            self._marker(self._forward_name(position), direction='forward',
                         state=f'step:{position}')

    def _run_backward(self, position: int) -> None:
        while position > 0:
            step = self._steps[position - 1]
            if self._item_rank(step.publication_index) != step.local_rank + 1:
                raise WindowsJournalConflict('Next rollback topology changed')
            if self.spec.record_version == 1:
                _peak, start, completed, committed, rolled = self._audit_v1_namespace()
                if start is None or start - completed != position or committed or rolled:
                    raise WindowsJournalConflict('V1 next reverse step lacks journal authority')
                self._assert_v1_topology(position)
            self.backend.move_exact(step.destination, step.source, step.identity)
            if self.spec.record_version == 1:
                self._repair_v1_pending(position - 1, reverse=True)
            if self._item_rank(step.publication_index) != step.local_rank:
                raise WindowsJournalConflict('Rollback move outcome differs')
            position -= 1
            self._marker(self._rollback_name(position), direction='rollback',
                         state=f'step:{position}')

    def apply(self) -> str:
        self._validate_plan_snapshot()
        self._preflight_v1()
        self._audit_v3_namespace()
        existing_plan = self._read('plan.json')
        if existing_plan is None:
            if self._read('intent.json') is not None:
                raise WindowsJournalConflict('Operation intent exists without canonical plan')
            self._write_once('plan.json', self._plan_record())
        else:
            self._check_plan_record()
        if self._read_rollback_start() is not None or self._read_marker(
                'rolled-back.json', direction='rollback', state='prepared'):
            raise WindowsJournalConflict('Operation has entered rollback')
        committed = self._read_marker('committed.json', direction='forward', state='committed')
        if committed:
            self._check_plan_record()
            self._check_intent()
            if self._audit_forward() != self.total_steps or self._progress() != self.total_steps:
                raise WindowsJournalConflict('Committed operation topology or checkpoints differ')
            self._marker('committed.json', direction='forward', state='committed')
            return 'committed'
        existing = self._read('intent.json')
        if existing is None:
            if self._progress() != 0:
                raise WindowsJournalConflict('Cannot start operation without prepared topology')
            self._write_once('intent.json', self._intent())
        else:
            self._check_intent()
            self._write_once('intent.json', self._intent())
        peak = self._audit_forward()
        position = self._reconcile_forward(peak)
        self._run_forward(position)
        if self._progress() != self.total_steps:
            raise WindowsJournalConflict('Final operation topology differs')
        self._validate_plan_snapshot()
        self._check_plan_record()
        self._check_intent()
        self._marker('committed.json', direction='forward', state='committed')
        return 'committed'

    def initialize_rollback(self) -> str:
        """Cancel a newly created, exactly prepared operation without publishing.

        Only this invocation's exclusive directory creation supplies ownership.
        Preexisting incomplete journals are never adopted by this entry point.
        """
        self._validate_plan_snapshot()
        if not self._created_directory or self._progress() != 0:
            raise WindowsJournalConflict('Rollback initialization requires a new prepared operation')
        if set(self.handles.list_children(self.directory)) != {'lock'}:
            raise WindowsJournalConflict('Rollback initialization requires an empty journal')
        self._write_once('plan.json', self._plan_record())
        self._write_once('intent.json', self._intent())
        self._write_once('rollback.json', self._rollback_body(0))
        return self.recover()

    def recover(self) -> str:
        """Recover according to the exact versioned commit boundary.

        Version 3 never reverses an installed new manifest. Earlier versions
        retain their original marker-based commit and rollback behavior.
        """
        self._validate_plan_snapshot()
        self._preflight_v1()
        self._audit_v3_namespace()
        self._check_plan_record()
        self._check_intent()
        self._write_once('intent.json', self._intent())
        peak = self._audit_forward()
        start = self._read_rollback_start()
        committed = self._read_marker('committed.json', direction='forward', state='committed')
        rolled_back = self._read_marker('rolled-back.json', direction='rollback', state='prepared')
        if self.spec.record_version == 3 and start == self.total_steps:
            raise WindowsJournalConflict('Manifest-commit operation cannot authorize post-head rollback')
        if committed and (rolled_back or start is not None):
            raise WindowsJournalConflict('Operation has conflicting terminal states')
        if committed:
            if peak != self.total_steps or self._progress() != self.total_steps:
                raise WindowsJournalConflict('Committed operation differs from final topology')
            self._marker('committed.json', direction='forward', state='committed')
            return 'committed'
        if rolled_back:
            if start is None or peak != start or self._audit_rollback(start) != start or self._progress() != 0:
                raise WindowsJournalConflict('Rolled-back operation lacks exact checkpoints')
            self._marker('rolled-back.json', direction='rollback', state='prepared')
            return 'rolled_back'
        if start is None:
            start = self._reconcile_forward(peak)
            if self.spec.record_version == 3 and start == self.total_steps:
                # Reconciliation proves exact complete topology, including
                # only the pending final rename's bounded metadata repair.
                # A stale/missing marker cannot undo the installed manifest.
                self._validate_plan_snapshot()
                self._check_plan_record()
                self._check_intent()
                self._marker('committed.json', direction='forward', state='committed')
                return 'committed'
            self._write_once('rollback.json', self._rollback_body(start))
        elif start != peak:
            raise WindowsJournalConflict('Forward markers changed after rollback authorization')
        position = self._reconcile_rollback(start)
        self._run_backward(position)
        if self._progress() != 0:
            raise WindowsJournalConflict('Operation did not restore prepared topology')
        self._validate_plan_snapshot()
        self._check_plan_record()
        self._check_intent()
        self._marker('rolled-back.json', direction='rollback', state='prepared')
        return 'rolled_back'
