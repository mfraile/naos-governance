"""Held native inspection of one explicitly approved absent-store rebind journal.

This is not an enrollment/mutation API. It checks the complete supported store
inventory, native privacy/identity, and operation semantics under a nonblocking
lock. Returned facts are detached observations, never continuing authority.
Foreign stores, archives and partial unowned preparation remain unsupported.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
from typing import Any

from . import joint_capture as joint
from . import local_binding as lb
from . import local_store as store
from . import rebind_records as records

ROOT = '.naos/local/managed-content-v3'
JOURNAL = ROOT + '/journals/' + records.JOURNAL_ID
PROGRESS = JOURNAL + '/progress'
LOCK = ROOT + '/scope.lock'
BINDING = ROOT + '/binding.json'
CANDIDATE = JOURNAL + '/binding.pending.json'
MAX_TOTAL_BYTES = 4 * records.MAX_BYTES
MAX_PROGRESS_RECORDS = 10


class RebindStoreInspectionError(ValueError):
    """Unsafe native storage, incomplete journal or inconsistent recovery state."""


def _fail(message):
    raise RebindStoreInspectionError(message)


@dataclass(frozen=True)
class RebindStoreInspection:
    phase: str
    recovery_action: str
    plan_sha256: str
    intent_sha256: str
    history_sha256: str
    portable_head_sha256: str
    binding_sha256: str | None
    changed_working_paths: tuple[str, ...]
    mutation_authorized: bool = False


class _NativeStore:
    """Fixed-path local-store reader layered on an already-held working reader."""
    def __init__(self, held, windows):
        self.held, self.reader, self.windows = held, held.working_reader, windows
        self.inventories = {}
        self.observations = {}
        self.raw = {}
        self.total_bytes = 0
        self.lock_witness = None
        self.lock_handle = None
        self.private_security = self.reader.handles.private_security() if windows else None

    def _private(self, witness):
        if witness['presence'] != 'present':
            _fail('Required private local storage is absent')
        if self.windows:
            security = witness['security']
            if not security['dacl_protected']:
                _fail('Unprotected Windows local store')
            for name in ('owner_sid', 'group_sid', 'dacl'):
                if security[name + '_sha256'] != hashlib.sha256(getattr(self.private_security, name)).hexdigest():
                    _fail('Windows local storage is not owned by the current private policy')
        elif (witness['mode_octal'] != ('0700' if witness['kind'] == 'directory' else '0600')
              or witness['uid_decimal'] != str(os.geteuid()) or witness['acl_entries']):
            _fail('POSIX local storage must be private and owned by the current user')
        return witness

    def directory(self, relative):
        witness = (self.reader.directory_witness(relative) if self.windows else self.reader.directory(relative))
        return self._private(witness)

    def children(self, relative, *, final=False):
        self.directory(relative)
        if self.windows:
            key = self.reader.directory(relative)
            names = frozenset(self.reader._names(key).values())
        else:
            with ExitStack() as stack:
                fd = self.reader._walk(relative, stack)
                names = self.reader._scan(fd, relative, final=final)
        # This variant has at most ten progress records; refuse before reading.
        if len(names) > 16:
            _fail('Local journal inventory exceeds the supported variant')
        if final and names != self.inventories[relative]:
            _fail('Local journal inventory changed during inspection')
        self.inventories.setdefault(relative, names)
        return names

    def _posix_file(self, relative, *, locking=False):
        """Caller keeps the returned stack open through use of the descriptor."""
        from .portable_provenance_posix import _same_namespace, _witness
        stack = ExitStack()
        try:
            parent_path, _, name = relative.rpartition('/')
            parent = self.reader._walk(parent_path, stack)
            if parent is None or not self.reader._exists(parent, parent_path, name):
                _fail('Required local journal file is absent')
            fd = os.open(name, (os.O_RDWR if locking else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            stack.callback(os.close, fd)
            observed = _witness(fd, leaf=True, label=relative)
            _same_namespace(parent, name, observed, leaf=True, label=relative)
            self._private(lb.project_posix_witness(observed.metadata))
            return stack, parent, name, fd, observed
        except BaseException:
            stack.close()
            raise

    @contextmanager
    def locked(self):
        # Verify every local control directory; .naos itself remains adopter-owned.
        for path in lb.CONTROL_DIRECTORIES[1:]:
            self.directory(path)
        if self.windows:
            parent = self.reader.directory(ROOT)
            with self.reader.handles.open_child(self.reader.directories[parent], 'scope.lock', kind='file', for_lock=True) as handle:
                self.lock_witness = self._private(lb.project_windows_witness(handle.info(), handle.security()))
                if handle.info().size:
                    _fail('Local scope lock must be an empty file')
                handle.lock_exclusive(nonblocking=True)
                self.lock_handle = handle
                try:
                    yield
                    self.check_lock()
                finally:
                    self.lock_handle = None
                    handle.unlock()
        else:
            import fcntl
            from .portable_provenance_posix import _same_namespace, _witness
            stack, parent, name, fd, before = self._posix_file(LOCK, locking=True)
            with stack:
                if os.fstat(fd).st_size:
                    _fail('Local scope lock must be an empty file')
                self.lock_witness = lb.project_posix_witness(before.metadata)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.lock_handle = fd
                try:
                    yield
                    if _witness(fd, leaf=True, label=LOCK) != before:
                        _fail('Local lock identity or metadata changed')
                    _same_namespace(parent, name, before, leaf=True, label=LOCK)
                finally:
                    self.lock_handle = None
                    fcntl.flock(fd, fcntl.LOCK_UN)

    def check_lock(self):
        if self.lock_handle is None:
            _fail('An acquired native lock is required')
        if not self.windows:
            from .portable_provenance_posix import _same_namespace, _witness
            current = _witness(self.lock_handle, leaf=True, label=LOCK)
            if (lb.project_posix_witness(current.metadata) != self.lock_witness
                    or os.fstat(self.lock_handle).st_size):
                _fail('Held local lock identity or bytes changed')
            with ExitStack() as stack:
                parent = self.reader._walk(ROOT, stack)
                _same_namespace(parent, 'scope.lock', current, leaf=True, label=LOCK)
        if self.windows:
            current = self._private(lb.project_windows_witness(self.lock_handle.info(), self.lock_handle.security()))
            if current != self.lock_witness or self.lock_handle.info().size:
                _fail('Held local lock identity or bytes changed')
            # Default read open shares the write access required by LockFileEx.
            parent = self.reader.directory(ROOT)
            with self.reader.handles.open_child(self.reader.directories[parent], 'scope.lock', kind='file') as reopened:
                if lb.project_windows_witness(reopened.info(), reopened.security()) != current:
                    _fail('Local scope lock namespace changed')

    def read(self, relative):
        if relative in self.raw:
            return self.raw[relative]
        if self.windows:
            parent_path, _, name = relative.rpartition('/')
            parent = self.reader.directory(parent_path)
            with self.reader.handles.open_child(self.reader.directories[parent], name, kind='file', pin_for_read=True) as handle:
                info, witness = self.reader._observe(handle, directory=False)
                self._private(witness)
                self._budget(info.size)
                if handle.seek(0) != 0:
                    _fail('Local record seek failed')
                parts, remaining = [], info.size
                while remaining:
                    block = handle.read(min(remaining, 1024 * 1024))
                    if type(block) is not bytes or not 0 < len(block) <= remaining:
                        _fail('Local record read was short or invalid')
                    parts.append(block)
                    remaining -= len(block)
                if handle.read(1) or self.reader._observe(handle, directory=False) != (info, witness):
                    _fail('Local record changed while read')
                data = b''.join(parts)
                digest = hashlib.sha256(data).hexdigest()
                self.reader.files[relative] = parent, info, witness, digest
        else:
            from .portable_provenance_posix import _same_namespace, _witness
            stack, parent, name, fd, before = self._posix_file(relative)
            with stack:
                size = os.fstat(fd).st_size
                self._budget(size)
                parts, remaining = [], size
                while remaining:
                    block = os.read(fd, min(remaining, 1024 * 1024))
                    if not block:
                        _fail('Local record read was short')
                    parts.append(block)
                    remaining -= len(block)
                if os.read(fd, 1) or _witness(fd, leaf=True, label=relative) != before:
                    _fail('Local record changed while read')
                _same_namespace(parent, name, before, leaf=True, label=relative)
                data = b''.join(parts)
                witness = lb.project_posix_witness(before.metadata)
        self.total_bytes += len(data)
        self.raw[relative] = data
        self.observations[relative] = {'path': relative, 'metadata': witness,
                                      'content': {'sha256': hashlib.sha256(data).hexdigest(), 'size_decimal': str(len(data))}}
        return data

    def _budget(self, size):
        if not 0 <= size <= records.MAX_BYTES or size > MAX_TOTAL_BYTES - self.total_bytes:
            _fail('Local record or cumulative byte budget exceeded')

    def revalidate(self):
        for path in self.inventories:
            self.children(path, final=True)
        self.held.portable_reader.revalidate()
        if self.windows:
            self.reader.revalidate()
            self.check_lock()
        else:
            initial = self.held.result.working_tree.body
            self.reader._final_revalidate(initial['native'], initial['leaves'] + list(self.observations.values()))


def _registered_state(plan, intent):
    p = plan.body
    return store.load_local_store(store.encode_local_store({
        'schema': store.STORE_SCHEMA, 'generation': 1, 'project_id': p['project_id'],
        'owner_sha256': p['owner_sha256'], 'binding_id': None, 'binding_sha256': None,
        'journals': {'head_id': records.JOURNAL_ID, 'entries': [{'id': records.JOURNAL_ID, 'sha256': intent.sha256}]},
        'active_journal_id': records.JOURNAL_ID, 'archives': [],
    }))


def _inspect(native, expected_plan_sha256):
    top = native.children(ROOT)
    if not {'scope.lock', 'journals'} <= top or top - {'scope.lock', 'journals', 'state.json', 'state.pending.json', 'binding.json'}:
        _fail('Unexpected or incomplete local-store root inventory')
    if native.children(ROOT + '/journals') != {records.JOURNAL_ID}:
        _fail('Unsupported or extra journal directory')
    names = native.children(JOURNAL)
    if not {'plan.json', 'intent.json', 'progress'} <= names or names - {'plan.json', 'intent.json', 'progress', 'binding.pending.json', 'terminal.json'}:
        _fail('Unexpected or incomplete rebind journal inventory')
    revisions = native.children(PROGRESS)
    if not 1 <= len(revisions) <= MAX_PROGRESS_RECORDS or revisions != {f'{i:08d}.json' for i in range(len(revisions))}:
        _fail('Missing, aliased or extra progress revision')
    portable = native.held.result.portable
    plan = records.load_rebind_plan(native.read(JOURNAL + '/plan.json'), portable)
    if plan.sha256 != expected_plan_sha256:
        _fail('Local rebind plan differs from the explicitly expected digest')
    intent = records.load_rebind_intent(native.read(JOURNAL + '/intent.json'), plan, portable,
                                       approved_plan_sha256=expected_plan_sha256)
    if native.lock_witness != intent.body['storage_witnesses']['lock'] or native.directory(JOURNAL) != intent.body['storage_witnesses']['journal']:
        _fail('Local lock or journal identity differs from the approved operation')
    progress = tuple(records.load_rebind_progress(native.read(PROGRESS + f'/{i:08d}.json'), intent, plan, portable)
                     for i in range(len(revisions)))
    history = records.validate_progress_history(progress, intent, plan, portable)
    phase = progress[-1].body['phase']
    current = native.held.result.working_tree.body
    prepared = intent.body['prepared_capture']
    if current['native'] != prepared['native']:
        _fail('Local checkout topology or protection differs from prepared rebind')
    changed = tuple(a['path'] for a, b in zip(current['leaves'], prepared['leaves'], strict=True) if a != b)
    legacy = (native.reader.directory_witness('.naos/upgrade-v1') if native.windows else native.reader.directory('.naos/upgrade-v1'))
    if legacy['presence'] != 'absent':
        _fail('Legacy control state appeared during rebind')
    candidate = records.candidate_binding(intent, plan, portable)
    present, staged = 'binding.json' in top, 'binding.pending.json' in names
    if present and staged:
        _fail('Both staged and published bindings exist')
    if present or staged:
        path = BINDING if present else CANDIDATE
        if native.read(path) != candidate.raw or native.observations[path]['metadata'] != progress[-1].body['publication_witness']:
            _fail('Candidate binding bytes or native publication identity differ')
    if phase in {'prepared', 'registered'} and (present or staged):
        _fail('Unwitnessed candidate preparation requires separate recovery')
    if phase in {'committed', 'finalize_pending', 'finalized'} and not present:
        _fail('Published binding is missing after commit')
    if phase in {'prepared', 'registered', 'candidate_ready', 'rollback_pending', 'rolled_back'} and present:
        _fail('Unexpected published binding before the recorded commit boundary')
    if phase in {'candidate_ready', 'publish_pending'} and not (present or staged):
        _fail('Witnessed candidate binding is missing')
    if phase == 'rolled_back' and staged:
        _fail('Rollback cleanup is incomplete')
    state = store.load_local_store(native.read(ROOT + '/state.json')) if 'state.json' in top else None
    terminal = store.load_local_terminal(native.read(JOURNAL + '/terminal.json')) if 'terminal.json' in names else None
    terminal_phase = phase in {'finalized', 'rolled_back'}
    # Absence is legal only before registration ever occurred. A missing
    # registered checkpoint cannot be inferred to be an earlier empty state.
    absent_predecessor = state is None and all(
        item.body['phase'] in {'prepared', 'rollback_pending', 'rolled_back'}
        for item in progress
    )
    if 'state.pending.json' in top and not terminal_phase:
        _fail('Premature staged terminal checkpoint')
    if terminal is not None and not terminal_phase:
        _fail('Premature terminal record')
    if terminal_phase:
        expected_state, expected_terminal, binding_after = records.checkpoint_records(history, intent, plan, portable)
        if 'state.pending.json' in top:
            if (native.read(ROOT + '/state.pending.json') != expected_state.raw
                    or (state != _registered_state(plan, intent)
                        and not (phase == 'rolled_back' and absent_predecessor))):
                _fail('Staged checkpoint differs from exact final state or predecessor')
        if terminal is not None and terminal != expected_terminal:
            _fail('Terminal record differs from complete operation history')
        if state == expected_state and terminal is not None:
            records.validate_checkpoint_records(state, terminal, binding_after, history, intent, plan, portable)
            action = 'complete' if present else 'rolled_back'
        else:
            if (state not in (_registered_state(plan, intent), expected_state)
                    and not (phase == 'rolled_back' and absent_predecessor)):
                _fail('Incomplete terminal checkpoint has unknown registration state')
            action = 'forward_completion_required' if present else 'rollback_required'
    else:
        if not absent_predecessor and state != _registered_state(plan, intent):
            _fail('Pending registration state differs from approved operation')
        if state is not None:
            store.reconcile_registration(state, None, (records.JOURNAL_ID,))
        action = 'forward_completion_required' if present else 'rollback_required'
    if changed and action not in {'complete', 'rolled_back'}:
        _fail('Managed working capture changed during pending rebind')
    return RebindStoreInspection(phase, action, plan.sha256, intent.sha256, history.sha256,
                                portable.manifest_sha256, candidate.sha256 if present else None, changed)


def inspect_absent_store_rebind(project_root: Path | str, *, expected_plan_sha256: str,
                               handles: Any = None) -> RebindStoreInspection:
    """Inspect an existing supported journal without creating or modifying files.

    The explicit expected plan digest must come from the selected approved plan;
    a self-declared on-disk digest is not authorization. Recovery classifications
    select no action automatically and cannot be reused as a mutation capability.
    """
    try:
        lb._hex(expected_plan_sha256, lb.HEX64, 'expected approved rebind plan')
        windows = handles is not None or os.name == 'nt'
        context = (joint._held_windows(str(project_root), (), handles) if windows
                   else joint._held_posix(Path(project_root), ()))
        with context as held:
            native = _NativeStore(held, windows)
            with native.locked():
                result = _inspect(native, expected_plan_sha256)
                native.revalidate()
        return result
    except RebindStoreInspectionError:
        raise
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, KeyError) as exc:
        raise RebindStoreInspectionError(f'Native rebind-store inspection refused: {exc}') from exc
