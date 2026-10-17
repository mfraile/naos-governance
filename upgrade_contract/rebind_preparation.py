"""Native preparation of one explicitly approved absent-store rebind journal.

An interrupted or partial preparation remains on disk and refuses a retry. No
ownership or cleanup is inferred until the complete intent and history inspect.
POSIX concurrency is bounded to cooperating writers, as for publication.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import os
from pathlib import Path

from . import joint_capture as joint
from . import local_binding as lb
from . import rebind_records as records
from . import rebind_store_inspection as inspection
from .rebind_publication import _custody, _inspect_locked
from .rebind_checkpoint import _write_new


class RebindPreparationError(ValueError):
    """The approved native preparation could not be completed."""


def _preflight(root, plan, digest, handles):
    if type(plan) is not records.ValidatedRebindPlan or plan.sha256 != digest:
        raise RebindPreparationError('Typed plan and explicit expected digest are required')
    windows = handles is not None or os.name == 'nt'
    context = (joint._held_windows(str(root), (), handles) if windows
               else joint._held_posix(Path(root), ()))
    with context as held:
        if records.load_rebind_plan(plan.raw, held.result.portable) != plan:
            raise RebindPreparationError('Approved plan is not valid for current portable history')
        if held.result.working_tree.body != plan.body['initial_capture']:
            raise RebindPreparationError('Approved working capture changed')
        legacy = (held.working_reader.directory_witness('.naos/upgrade-v1') if windows
                  else held.working_reader.directory('.naos/upgrade-v1'))
        if legacy != plan.body['legacy_absence']['witness']:
            raise RebindPreparationError('Legacy control state changed')
        native = plan.body['initial_capture']['native']
        for item in native['control_directories'][2:]:
            if item['witness']['presence'] != 'absent':
                raise RebindPreparationError('Existing managed local storage refuses preparation')
        return windows


def _normalize_created_posix(fd, owner, mode):
    """Normalize only a newly created held control to approved native ownership."""
    from .portable_provenance_posix import _witness
    before = os.fstat(fd)
    if before.st_uid != owner[0]:
        inspection._fail('New local control has an unexpected owner')
    if (before.st_uid, before.st_gid) != owner:
        os.fchown(fd, *owner)
    os.fchmod(fd, mode)
    os.fsync(fd)
    witness = lb.project_posix_witness(_witness(
        fd, leaf=mode == 0o600, label='new private local control').metadata)
    if (witness['uid_decimal'] != str(owner[0])
            or witness['gid_decimal'] != str(owner[1])
            or witness['mode_octal'] != format(mode, '04o') or witness['acl_entries']):
        inspection._fail('New local control does not match approved private ownership')


def _mkdir_posix(parent, name, *, creation_owner=None):
    os.mkdir(name, 0o700, dir_fd=parent)
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        if creation_owner is not None:
            _normalize_created_posix(fd, creation_owner, 0o700)
        if os.fstat(fd).st_mode & 0o7777 != 0o700:
            inspection._fail('New local directory is not private')
        os.fsync(parent)
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def _bootstrap_posix(root, plan, *, creation_owner=None):
    from .working_tree_capture_posix import _Reader
    from .portable_provenance_posix import _same_namespace, _witness
    if creation_owner is not None and (type(creation_owner) is not tuple
            or len(creation_owner) != 2
            or any(type(value) is not int or value < 0 for value in creation_owner)
            or creation_owner[0] != os.geteuid()):
        inspection._fail('Approved POSIX creation owner is invalid')
    expected = {x['path']: x['witness'] for x in plan.body['initial_capture']['native']['control_directories']}
    with _Reader(Path(root)) as reader, ExitStack() as stack:
        naos = os.open('.naos', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=reader.root_fd)
        stack.callback(os.close, naos)
        naos_observed = _witness(naos, leaf=False, label='.naos')
        _same_namespace(reader.root_fd, '.naos', naos_observed, leaf=False, label='.naos')
        if lb.project_posix_witness(naos_observed.metadata) != expected['.naos']:
            inspection._fail('Control ancestor changed before preparation')
        parent = naos
        pinned = {'.naos': (reader.root_fd, '.naos', naos)}
        for relative in ('.naos/local', inspection.ROOT, inspection.ROOT + '/journals', inspection.JOURNAL, inspection.PROGRESS):
            name = relative.rsplit('/', 1)[-1]
            if relative == '.naos/local' and expected[relative]['presence'] == 'present':
                fd = os.open('local', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                stack.callback(os.close, fd)
                observed = _witness(fd, leaf=False, label=relative)
                _same_namespace(parent, 'local', observed, leaf=False, label=relative)
                if lb.project_posix_witness(observed.metadata) != expected[relative]:
                    inspection._fail('Existing private local parent changed')
                witness = lb.project_posix_witness(observed.metadata)
                if witness['mode_octal'] != '0700' or witness['uid_decimal'] != str(os.geteuid()) or witness['acl_entries']:
                    inspection._fail('Existing local parent is not privately owned')
                if creation_owner is not None and any(
                        witness[key] != str(value) for key, value in
                        zip(('uid_decimal', 'gid_decimal'), creation_owner)):
                    inspection._fail('Existing local parent differs from approved creation owner')
                pinned[relative] = (parent, name, fd)
                parent = fd
                continue
            fd = _mkdir_posix(parent, name, creation_owner=creation_owner)
            stack.callback(os.close, fd)
            _same_namespace(parent, name, _witness(fd, leaf=False, label=relative), leaf=False, label=relative)
            pinned[relative] = (parent, name, fd)
            if relative == inspection.ROOT:
                store_fd = fd
            parent = fd
        lock = os.open('scope.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                       0o600, dir_fd=store_fd)
        stack.callback(os.close, lock)
        if creation_owner is not None:
            _normalize_created_posix(lock, creation_owner, 0o600)
            _same_namespace(store_fd, 'scope.lock',
                _witness(lock, leaf=True, label=inspection.LOCK),
                leaf=True, label=inspection.LOCK)
        if os.fstat(lock).st_mode & 0o7777 != 0o600:
            inspection._fail('New scope lock is not private')
        os.fsync(lock)
        os.fsync(store_fd)
        pinned[inspection.LOCK] = (store_fd, 'scope.lock', lock)
        yield pinned


@contextmanager
def _bootstrap_windows(root, plan, handles):
    from .working_tree_capture_windows import _Capture
    from .windows_handles import WindowsHandles
    active = WindowsHandles() if handles is None else handles
    expected = {x['path']: x['witness'] for x in plan.body['initial_capture']['native']['control_directories']}
    with ExitStack() as stack:
        reader = _Capture(active, str(root), stack)
        if reader.directory_witness('.naos') != expected['.naos']:
            inspection._fail('Control ancestor changed before preparation')
        parent = stack.enter_context(active.open_child(
            reader.directories[reader.project], '.naos', kind='directory', for_publish=True))
        pinned = {'.naos': parent}
        local = '.naos/local'
        if expected[local]['presence'] == 'present':
            if reader.directory_witness(local) != expected[local]:
                inspection._fail('Existing private local parent changed')
            parent = stack.enter_context(active.open_child(parent, 'local', kind='directory', for_publish=True))
            security = active.private_security()
            observed = parent.security()
            if any(getattr(observed, name) != getattr(security, name)
                   for name in ('owner_sid', 'group_sid', 'dacl')) or not observed.protected:
                inspection._fail('Existing Windows local parent is not privately owned')
        else:
            parent = stack.enter_context(active.create_private_directory(parent, 'local'))
        pinned[local] = parent
        native_security = parent.security()
        for name, relative in (('managed-content-v3', inspection.ROOT),
                               ('journals', inspection.ROOT + '/journals'),
                               (records.JOURNAL_ID, inspection.JOURNAL),
                               ('progress', inspection.PROGRESS)):
            parent = stack.enter_context(active.create_private_directory(parent, name))
            # Compare native observations, not the SDDL converter's encoding.
            # Refuse a mismatch at the first child, preserving partial storage.
            if parent.security() != native_security:
                inspection._fail('Prepared Windows directory security differs')
            pinned[relative] = parent
            if relative == inspection.ROOT:
                store_handle = parent
        with active.create_private_file(store_handle, 'scope.lock') as lock:
            lock.flush()
            pinned[inspection.LOCK] = lb.project_windows_witness(lock.info(), lock.security())
        yield pinned


def _verify_bootstrap(pinned, custody):
    """Compare every held created identity with a fresh namespace observation."""
    if custody.windows:
        for path, handle in pinned.items():
            expected = (handle if path == inspection.LOCK else
                        lb.project_windows_witness(handle.info(), handle.security()))
            if path == inspection.LOCK:
                current = custody.lock_witness
            else:
                current = custody.reader.directory_witness(path)
            if expected != current:
                inspection._fail(f'Prepared native identity changed: {path}')
    else:
        from .portable_provenance_posix import _same_namespace, _witness
        for path, (parent, name, fd) in pinned.items():
            observed = _witness(fd, leaf=path == inspection.LOCK, label=path)
            _same_namespace(parent, name, observed, leaf=path == inspection.LOCK, label=path)
            expected = lb.project_posix_witness(observed.metadata)
            current = (custody.lock_witness if path == inspection.LOCK
                       else custody.reader.directory(path))
            if expected != current:
                inspection._fail(f'Prepared native identity changed: {path}')


def prepare_absent_store_rebind(project_root: Path | str, *, plan: records.ValidatedRebindPlan,
                                expected_plan_sha256: str, handles=None) -> inspection.RebindStoreInspection:
    """Create one private prepared journal and return its fresh locked inspection.

    Approval is the caller's explicit digest for a typed plan. Existing or
    partial managed storage refuses. Exceptions preserve every created object.
    """
    try:
        lb._hex(expected_plan_sha256, lb.HEX64, 'expected approved rebind plan')
        windows = _preflight(project_root, plan, expected_plan_sha256, handles)
        bootstrap = (_bootstrap_windows(project_root, plan, handles) if windows
                     else _bootstrap_posix(project_root, plan))
        with bootstrap as pinned, _custody(project_root, handles) as custody:
            _verify_bootstrap(pinned, custody)
            context = (joint._held_windows(str(project_root), (), handles) if windows
                       else joint._held_posix(Path(project_root), ()))
            with context as held:
                prepared = held.result
                legacy = (held.working_reader.directory_witness('.naos/upgrade-v1') if windows
                          else held.working_reader.directory('.naos/upgrade-v1'))
                if legacy != plan.body['legacy_absence']['witness']:
                    inspection._fail('Legacy control state changed during preparation')
            journal = (custody.reader.directory_witness(inspection.JOURNAL) if windows
                       else custody.reader.directory(inspection.JOURNAL))
            intent = records.build_rebind_intent(
                plan, prepared.portable, prepared.working_tree,
                approved_plan_sha256=expected_plan_sha256,
                storage_witnesses={'lock': custody.lock_witness, 'journal': journal},
            )
            progress = records.initial_progress(intent, plan, prepared.portable)
            for relative, raw in ((inspection.JOURNAL + '/plan.json', plan.raw),
                                  (inspection.JOURNAL + '/intent.json', intent.raw),
                                  (inspection.PROGRESS + '/00000000.json', progress.raw)):
                _write_new(custody, relative, raw)
            result, _, _ = _inspect_locked(project_root, expected_plan_sha256, custody)
            if result.phase != 'prepared' or result.intent_sha256 != intent.sha256:
                inspection._fail('Prepared journal did not inspect as the approved intent')
            return result
    except RebindPreparationError:
        raise
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, KeyError) as exc:
        raise RebindPreparationError(f'Native absent-store preparation refused: {exc}') from exc
