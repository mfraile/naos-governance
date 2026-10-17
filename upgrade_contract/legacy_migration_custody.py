"""Hold one legacy lock across a closed read lane and a later mutation window.

The context itself performs no migration writes. A matching plan and lock are
preconditions only; subsequent journal transitions must grant their own narrow
authority and recheck every relevant native object before mutation.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
from types import SimpleNamespace

from . import legacy_archive_capture as archive_capture
from . import legacy_authority as authority
from . import legacy_migration_plan_records as records
from . import legacy_migration_planning as planning
from . import local_binding as binding
from . import portable_provenance as pp
from .rebind_store_inspection import _NativeStore, RebindStoreInspectionError


class LegacyMigrationCustodyError(ValueError):
    """The approved legacy lock or separate inspection window was lost."""


class _PosixCustodyReader:
    """Pin only the fixed legacy-lock ancestors, never a mutable inventory."""

    def __init__(self, root, source_format, stack):
        from .working_tree_capture_posix import _Reader
        from .portable_provenance_posix import _witness
        self.reader = stack.enter_context(_Reader(Path(root)))
        self.root_fd = self.reader.root_fd
        self.root_path = self.reader.root_path
        self.platform = self.reader.platform
        self.chain = self.reader.chain
        self.fds = {'': self.root_fd}
        self.witnesses = {}
        scope, suffix = archive_capture._LAYOUT[source_format]
        parent = (scope + '/' + suffix).rpartition('/')[0]
        prefix = ''
        for part in parent.split('/'):
            prefix = part if not prefix else prefix + '/' + part
            with ExitStack() as temporary:
                fd = self.reader._walk(prefix, temporary)
                if fd is None:
                    raise LegacyMigrationCustodyError('Legacy lock ancestor is absent')
                pin = os.dup(fd)
            stack.callback(os.close, pin)
            self.fds[prefix] = pin
            self.witnesses[prefix] = binding.project_posix_witness(
                _witness(pin, leaf=False, label=prefix).metadata)
        self.check()

    def check(self):
        from .portable_provenance_posix import _witness, _same_namespace
        self.reader._check_root_custody()
        for path, expected in self.witnesses.items():
            now = _witness(self.fds[path], leaf=False, label=path)
            if binding.project_posix_witness(now.metadata) != expected:
                raise LegacyMigrationCustodyError('Pinned legacy directory changed')
            parent, _, name = path.rpartition('/')
            _same_namespace(self.fds[parent], name, now, leaf=False, label=path)

    def _check_root(self):
        self.check()

    def _walk(self, relative, _stack):
        self.check()
        if relative not in self.fds:
            raise LegacyMigrationCustodyError('Custody reader cannot inspect working inventory')
        return self.fds[relative]

    def directory(self, relative):
        self.check()
        if relative not in self.witnesses:
            raise LegacyMigrationCustodyError('Unpinned legacy custody directory')
        return self.witnesses[relative]

    def _exists(self, fd, relative, name):
        # Only used once to open the existing lock before the read snapshot.
        return self.reader._exists(fd, relative, name)


class _Custody(_NativeStore):
    """Pin only root ancestry, private legacy scope ancestry, and existing lock."""

    locked = archive_capture._Capture.locked

    def __init__(self, reader, windows, source_format, approved_plan):
        super().__init__(SimpleNamespace(working_reader=reader), windows)
        self.scope, suffix = archive_capture._LAYOUT[source_format]
        self.lock_path = self.scope + '/' + suffix
        self.directory_witnesses = {}
        self.active = True
        self.snapshot_active = False
        self._approved_plan = approved_plan
        self._lock_parent = None
        self._lock_name = None

    def _posix_file(self, relative, *, locking=False):
        result = super()._posix_file(relative, locking=locking)
        if locking:
            _stack, self._lock_parent, self._lock_name, _fd, _before = result
        return result

    def check_lock(self):
        if not self.active or self.lock_handle is None:
            raise LegacyMigrationCustodyError('Held legacy scope lock is unavailable')
        if self.windows:
            # Windows reader uses pinned handles/namespace checks; its later
            # directory revalidation does not freeze sibling names in .naos.
            archive_capture._Capture.check_lock(self)
            return
        from .portable_provenance_posix import _witness, _same_namespace
        # This reader checks pinned ancestor identities and namespaces without
        # revisiting the stale child-name cache in its underlying root reader.
        self.reader.check()
        current = _witness(self.lock_handle, leaf=True, label=self.lock_path)
        if (self._lock_parent is None or self._lock_name is None
                or binding.project_posix_witness(current.metadata) != self.lock_witness
                or os.fstat(self.lock_handle).st_size):
            raise LegacyMigrationCustodyError('Held legacy lock identity or bytes changed')
        _same_namespace(self._lock_parent, self._lock_name, current,
                        leaf=True, label=self.lock_path)

    def directory(self, relative):
        witness = super().directory(relative)
        previous = self.directory_witnesses.setdefault(relative, witness)
        if previous != witness or len(self.directory_witnesses) > archive_capture.MAX_DIRECTORIES:
            raise LegacyMigrationCustodyError('Private legacy directory changed')
        return witness

    def root_chain(self):
        if self.windows:
            paths = binding._native_chain(self.reader.root, 'Windows')
            return [{'path': path, 'witness': self.reader.baselines[self.reader.project[:index]][1]}
                    for index, path in enumerate(paths)]
        return [{'path': path, 'witness': binding.project_posix_witness(witness.metadata)}
                for path, _parent, _name, _fd, witness in self.reader.chain]

    def check_root(self):
        if self.windows:
            # Compare stable native identity/protection, not mutable directory
            # timestamps. Creating .naos/local is allowed after the read lane.
            for key, held in self.reader.directories.items():
                expected = self.reader.baselines[key][1]
                if binding.project_windows_witness(held.info(), held.security()) != expected:
                    raise LegacyMigrationCustodyError('Pinned Windows custody directory changed')
                opened = (self.reader.handles.open_root(self.reader.drive) if not key else
                          self.reader.handles.open_child(
                              self.reader.directories[key[:-1]], key[-1],
                              kind='directory', pin_for_read=True))
                with opened:
                    if binding.project_windows_witness(opened.info(), opened.security()) != expected:
                        raise LegacyMigrationCustodyError('Windows custody namespace changed')
        else:
            self.reader._check_root()
        native = self._approved_plan.body['initial_capture']['native']
        if (self.reader.root if self.windows else self.reader.root_path) != native['root_path']:
            raise LegacyMigrationCustodyError('Custody project root spelling changed')
        if self.root_chain() != native['root_chain']:
            raise LegacyMigrationCustodyError('Custody root ancestry differs from approved plan')

    def check_mutation_window(self):
        """Guard a later writer's entrance; this does not authorize the write."""
        if self.snapshot_active or not self.active or self._approved_plan is None:
            raise LegacyMigrationCustodyError('Immutable inspection reader is active or custody closed')
        self.check_root()
        self.check_lock()
        if self.lock_witness != self._approved_plan.body['legacy_lock']['witness']:
            raise LegacyMigrationCustodyError('Held legacy lock differs from approved plan')


def _original_args(candidate, approved):
    """Recover exactly the controls used for the approved candidate, not defaults."""
    lineage = candidate.lineage.body
    body = approved.body
    files = candidate.projection_files
    owner, _ = pp._decode_record(files[pp.OWNER_PATH], pp.OWNER_SCHEMA,
        {'schema', 'project_id', 'minimum_reader', 'authority_kind', 'authority_sha256'})
    _, record = records._authority_directory_paths(files)
    anchors = {f"expected_{item['role']}_sha256": item['sha256']
               for item in lineage['anchors']}
    policy_sha = record['source_policy_sha256']
    mode_sha = record['mode_inventory_sha256']
    return dict(source_format=lineage['source_format'],
                original_project_id=lineage['original_project_id'],
                new_project_id=lineage['new_project_id'],
                binding_id=body['binding_id'],
                approved_lineage_sha256=candidate.lineage.sha256,
                expected_source_policy_sha256=policy_sha,
                source_policy_raw=(candidate.raw_policy if candidate.lineage._raw_archive
                                   else files[authority.blob_path(policy_sha)]),
                replay_projection=bool(candidate.lineage._raw_archive),
                expected_modes_sha256=mode_sha,
                mode_inventory_raw=(candidate.raw_modes if candidate.lineage._raw_archive
                                    else files[pp.inventory_path(mode_sha)]), **anchors)


@contextmanager
def _snapshot(custody):
    """Borrow the held lock for one immutable capture; close before mutation."""
    if type(custody) is not _Custody or custody.snapshot_active:
        raise LegacyMigrationCustodyError('A source snapshot is already active')
    custody.check_root()
    custody.check_lock()
    custody.snapshot_active = True
    held = None
    try:
        with ExitStack() as read_stack:
            if custody.windows:
                from .working_tree_capture_windows import _Capture as Reader
                reader = Reader(custody.reader.handles, custody.reader.root, read_stack)
            else:
                from .working_tree_capture_posix import _Reader as Reader
                reader = read_stack.enter_context(Reader(Path(custody.reader.root_path)))
            held = archive_capture._Capture(reader, custody.windows,
                                            custody._approved_plan.body['source_format'])
            held.lock_handle = custody.lock_handle
            held.lock_witness = custody.lock_witness
            held.check_lock()
            for path in ('.naos/upgrade-v1', held.scope, held.lock_path.rpartition('/')[0]):
                held.directory(path)
            held.capture()
            try:
                yield held
            finally:
                try:
                    held.revalidate()
                finally:
                    held.active = False
    finally:
        if held is not None:
            held.active = False
        custody.snapshot_active = False
        custody.check_root()
        custody.check_lock()


@contextmanager
def _lock_legacy_for_plan(project_root, candidate: planning.MigrationCandidate,
                          expected_plan_sha256, handles=None):
    """Hold verified ancestry/lock only; caller must inspect operation state.

    This private primitive grants no source-state or journal mutation authority.
    Both initial preparation and recovery must finish their own immutable read
    lane before entering a mutation window.
    """
    custody = None
    try:
        if (type(candidate) is not planning.MigrationCandidate
                or type(expected_plan_sha256) is not str
                or binding.HEX64.fullmatch(expected_plan_sha256) is None
                or type(candidate.projection_files) is not dict):
            raise LegacyMigrationCustodyError('Typed candidate and explicit plan digest required')
        approved = records.load_migration_plan(candidate.plan.raw,
                                               candidate.projection_files,
                                               candidate.lineage)
        if (approved.sha256 != expected_plan_sha256
                or candidate.plan.sha256 != approved.sha256
                or candidate.plan.raw != approved.raw):
            raise LegacyMigrationCustodyError('Candidate differs from approved immutable plan')
        args = _original_args(candidate, approved)
        with ExitStack() as outer:
            windows = handles is not None or os.name == 'nt'
            if windows:
                from .working_tree_capture_windows import _Capture as Reader
                from .windows_handles import WindowsHandles
                reader = Reader(handles if handles is not None else WindowsHandles(),
                                str(project_root), outer)
            else:
                reader = _PosixCustodyReader(project_root, args['source_format'], outer)
            custody = _Custody(reader, windows, args['source_format'], approved)
            with custody.locked():
                custody.check_root()
                if custody.lock_witness != approved.body['legacy_lock']['witness']:
                    raise LegacyMigrationCustodyError('Approved legacy lock identity changed')
                yield custody
                custody.check_root()
                custody.check_lock()
    except LegacyMigrationCustodyError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError,
            RebindStoreInspectionError) as exc:
        raise LegacyMigrationCustodyError(f'Approved legacy custody refused: {exc}') from exc
    finally:
        if custody is not None:
            custody.active = False


@contextmanager
def _approved_legacy_custody(project_root, candidate: planning.MigrationCandidate,
                             expected_plan_sha256, handles=None):
    """Reconstruct the initial approved plan before exposing a mutation window."""
    with _lock_legacy_for_plan(project_root, candidate, expected_plan_sha256, handles) as custody:
        args = _original_args(candidate, custody._approved_plan)
        with _snapshot(custody) as snapshot:
            recreated = planning._candidate_from_held(snapshot, **args)
            if (recreated.plan.raw != candidate.plan.raw
                    or recreated.projection_files != candidate.projection_files):
                raise LegacyMigrationCustodyError('Fresh native candidate differs from approved plan')
        custody.check_mutation_window()
        yield custody
