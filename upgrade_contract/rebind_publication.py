"""Publish one already approved, witnessed binding under continuous native lock.

Only the publish_pending boundary is supported here. This does not prepare a
journal, advance progress, finalize registration, or enroll legacy projects.
An interrupted successful rename remains inspectable as forward completion.
The concurrency contract is lock-cooperating writers. POSIX namespace checks
cannot provide atomic compare-and-swap against a noncooperating same-user rename;
postchecks detect substitution but never delete or overwrite a foreign object.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

from . import joint_capture as joint
from . import local_binding as lb
from . import rebind_store_inspection as inspection


class _PosixCustodyReader:
    """Pinned directory identities; mutable size/times are checked by snapshots.

    These pins deliberately are not a working-tree snapshot. The fresh joint
    reader validates full inventories and file metadata on each side of mutation.
    """
    def __init__(self, root, stack):
        from .working_tree_capture_posix import _Reader
        from .portable_provenance_posix import _witness
        self.reader = stack.enter_context(_Reader(Path(root)))
        self.fds = {'': self.reader.root_fd}
        self.witnesses = {}
        for path in (*lb.CONTROL_DIRECTORIES, inspection.JOURNAL, inspection.PROGRESS):
            with ExitStack() as temporary:
                fd = self.reader._walk(path, temporary)
                if fd is None:
                    inspection._fail('Required prepared directory is absent')
                pin = os.dup(fd)
                stack.callback(os.close, pin)
                self.fds[path] = pin
                self.witnesses[path] = lb.project_posix_witness(_witness(pin, leaf=False, label=path).metadata)
        self.check()

    def check(self):
        from .portable_provenance_posix import _same_namespace, _witness
        self.reader._check_root_custody()
        for path, expected in self.witnesses.items():
            now = _witness(self.fds[path], leaf=False, label=path)
            if not lb._metadata_comparison(
                lb.project_posix_witness(now.metadata), expected,
                str(now.metadata['platform']),
            ):
                inspection._fail('Pinned publication directory identity or protection changed')
            parent, _, name = path.rpartition('/')
            _same_namespace(self.fds[parent], name, now, leaf=False, label=path)

    def _check_root(self):
        self.check()

    def _walk(self, relative, stack):
        self.check()
        return self.fds[relative]

    def directory(self, relative):
        self.check()
        return self.witnesses[relative]

    def _exists(self, fd, relative, name):
        # Only used to open the fixed lock, before the first inspection.
        return self.reader._exists(fd, relative, name)


@contextmanager
def _custody(root, handles):
    """Hold ancestry and the exclusive lock without freezing mutable inventories."""
    windows = handles is not None or os.name == 'nt'
    with ExitStack() as stack:
        if windows:
            from .working_tree_capture_windows import _Capture
            from .windows_handles import WindowsHandles
            reader = _Capture(handles if handles is not None else WindowsHandles(), str(root), stack)
        else:
            reader = _PosixCustodyReader(root, stack)
        native = inspection._NativeStore(SimpleNamespace(working_reader=reader), windows)
        with native.locked():
            yield native
            native.check_lock()
            if not windows:
                reader._check_root()


def _inspect_locked(root, expected, custody, *, records_out=None):
    """Finish every read-only final check before returning to the mutation lane."""
    custody.check_lock()
    context = (joint._held_windows(str(root), (), custody.reader.handles) if custody.windows
               else joint._held_posix(Path(root), ()))
    with context as held:
        native = inspection._NativeStore(held, custody.windows)
        native.lock_handle, native.lock_witness = custody.lock_handle, custody.lock_witness
        # Borrow a lock actually held by this operation, never acquire it twice.
        native.check_lock()
        result = inspection._inspect(native, expected)
        native.revalidate()
        candidate = native.raw.get(inspection.CANDIDATE)
        observation = native.observations.get(inspection.CANDIDATE)
        if records_out is not None:
            records_out.update(portable=held.result.portable, raw=dict(native.raw),
                               observations=dict(native.observations))
    custody.check_lock()
    return result, candidate, observation


def _publish_posix(custody, raw, observation):
    from .portable_provenance_posix import _same_namespace, _witness
    from .transaction import rename_no_replace_at
    # Descriptor-relative traversal is held until publication and postchecks.
    with ExitStack() as stack:
        source = custody.reader._walk(inspection.JOURNAL, stack)
        destination = custody.reader._walk(inspection.ROOT, stack)
        fd = os.open('binding.pending.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=source)
        stack.callback(os.close, fd)
        before = _witness(fd, leaf=True, label=inspection.CANDIDATE)
        if lb.project_posix_witness(before.metadata) != observation['metadata']:
            inspection._fail('Publication candidate native identity changed')
        parts, remaining = [], len(raw) + 1
        while remaining:
            block = os.read(fd, min(remaining, 1024 * 1024))
            if not block:
                break
            parts.append(block)
            remaining -= len(block)
        if b''.join(parts) != raw or _witness(fd, leaf=True, label=inspection.CANDIDATE) != before:
            inspection._fail('Publication candidate bytes or metadata changed')
        _same_namespace(source, 'binding.pending.json', before, leaf=True, label=inspection.CANDIDATE)
        custody.check_lock()
        rename_no_replace_at(source, 'binding.pending.json', destination, 'binding.json')
        after = _witness(fd, leaf=True, label=inspection.BINDING)
        if lb.project_posix_witness(after.metadata) != observation['metadata']:
            inspection._fail('Published native identity or protection changed')
        _same_namespace(destination, 'binding.json', after, leaf=True, label=inspection.BINDING)
        os.fsync(source)
        os.fsync(destination)


def _publish_windows(custody, raw, observation):
    reader, handles = custody.reader, custody.reader.handles
    source = reader.directories[reader.directory(inspection.JOURNAL)]
    # Mutation access is separate from the read pins retained by custody.
    parent_key = reader.directory('.naos/local')
    with handles.open_child(reader.directories[parent_key], 'managed-content-v3',
                            kind='directory', for_publish=True) as destination:
        with handles.open_child(source, 'binding.pending.json', kind='file', for_rename=True) as candidate:
            before = candidate.info()
            if lb.project_windows_witness(before, candidate.security()) != observation['metadata']:
                inspection._fail('Publication candidate native identity changed')
            candidate.seek(0)
            parts, remaining = [], len(raw) + 1
            while remaining:
                block = candidate.read(min(remaining, 1024 * 1024))
                if not block:
                    break
                parts.append(block)
                remaining -= len(block)
            if b''.join(parts) != raw or candidate.info() != before:
                inspection._fail('Publication candidate bytes or metadata changed')
            custody.check_lock()
            handles.rename_no_replace(candidate, destination, 'binding.json')
            if lb.project_windows_witness(candidate.info(), candidate.security()) != observation['metadata']:
                inspection._fail('Published native identity or protection changed')


def publish_prepared_rebind(project_root: Path | str, *, expected_plan_sha256: str,
                            handles=None) -> inspection.RebindStoreInspection:
    """Execute only an explicitly approved publish_pending no-replace rename.

    A retry after successful publication is read-only and returns the same pending
    forward-completion state. Errors preserve all files; no compensating deletion
    or overwrite is attempted. The result is an observation, not reusable authority.
    """
    try:
        lb._hex(expected_plan_sha256, lb.HEX64, 'expected approved rebind plan')
        with _custody(project_root, handles) as custody:
            before, raw, observation = _inspect_locked(project_root, expected_plan_sha256, custody)
            if before.phase != 'publish_pending':
                inspection._fail('Publication requires the exact publish_pending phase')
            if before.binding_sha256 is not None:
                return before
            if raw is None or observation is None or hashlib.sha256(raw).hexdigest() != observation['content']['sha256']:
                inspection._fail('Complete witnessed publication candidate is required')
            if custody.windows:
                _publish_windows(custody, raw, observation)
            else:
                _publish_posix(custody, raw, observation)
            after, _, _ = _inspect_locked(project_root, expected_plan_sha256, custody)
            if (after.phase != 'publish_pending' or after.recovery_action != 'forward_completion_required'
                    or after.binding_sha256 != hashlib.sha256(raw).hexdigest()):
                inspection._fail('Publication did not reach the exact forward-completion boundary')
            return after
    except inspection.RebindStoreInspectionError:
        raise
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, KeyError) as exc:
        raise inspection.RebindStoreInspectionError(f'Native rebind publication refused: {exc}') from exc
