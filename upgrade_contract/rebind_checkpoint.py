"""Complete an already published absent-store rebind's forward checkpoint.

Every complete persistence boundary is restartable under the same native lock.
A torn/partial newly created record is retained and refused, never adopted or
repaired by guessing. This internal operation does not prepare or migrate stores.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
from types import SimpleNamespace

from . import local_binding as lb
from . import rebind_publication as publication
from . import rebind_records as records
from . import rebind_store_inspection as inspection

STATE = inspection.ROOT + '/state.json'
STAGE = inspection.ROOT + '/state.pending.json'
TERMINAL = inspection.JOURNAL + '/terminal.json'


@contextmanager
def _parent(custody, relative):
    path, _, name = relative.rpartition('/')
    if custody.windows:
        parent_path, _, directory = path.rpartition('/')
        reader = custody.reader
        ancestor = reader.directories[reader.directory(parent_path)]
        with reader.handles.open_child(ancestor, directory, kind='directory', for_publish=True) as handle:
            yield handle, name
    else:
        with ExitStack() as stack:
            yield custody.reader._walk(path, stack), name


def _write_new(custody, relative, data, *, max_bytes=records.MAX_BYTES):
    # The default journal-record ceiling is unchanged. Migration archive/blob
    # staging may explicitly select the existing portable 64 MiB leaf ceiling.
    if (type(max_bytes) is not int or not 0 < max_bytes <= 64 * 1024 * 1024
            or type(data) is not bytes or len(data) > max_bytes):
        inspection._fail('Invalid checkpoint record size')
    custody.check_lock()
    with _parent(custody, relative) as (parent, name):
        if custody.windows:
            with custody.reader.handles.create_private_file(parent, name) as handle:
                handle.write_all(data)
                handle.flush()
                before = handle.info()
                handle.seek(0)
                _check_bytes(handle.read, data)
                if handle.info() != before:
                    inspection._fail('New private record changed while read')
                witness = lb.project_windows_witness(before, handle.security())
            with custody.reader.handles.open_child(parent, name, kind='file', pin_for_read=True) as reopened:
                reopened_before = reopened.info()
                # Closing the write handle may settle Windows timestamps.
                # Across close, bind native identity/protection and exact bytes;
                # within each read interval, require unchanged full metadata.
                if lb.project_windows_witness(reopened_before, reopened.security()) != witness:
                    inspection._fail('New private record namespace changed')
                reopened.seek(0)
                _check_bytes(reopened.read, data)
                if reopened.info() != reopened_before:
                    inspection._fail('New private record changed after creation')
        else:
            from .portable_provenance_posix import _same_namespace, _witness
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
            try:
                os.fchmod(fd, 0o600)
                remaining = memoryview(data)
                while remaining:
                    count = os.write(fd, remaining)
                    if count <= 0:
                        inspection._fail('Short checkpoint write')
                    remaining = remaining[count:]
                os.fsync(fd)
                before = _witness(fd, leaf=True, label=relative)
                os.lseek(fd, 0, os.SEEK_SET)
                _check_bytes(lambda count: os.read(fd, count), data)
                if _witness(fd, leaf=True, label=relative) != before:
                    inspection._fail('New private record changed while read')
                _same_namespace(parent, name, before, leaf=True, label=relative)
                witness = lb.project_posix_witness(before.metadata)
            finally:
                os.close(fd)
            os.fsync(parent)
    inspection._NativeStore(SimpleNamespace(working_reader=custody.reader), custody.windows)._private(witness)
    custody.check_lock()
    return witness


def _check_bytes(read, expected):
    parts, remaining = [], len(expected) + 1
    while remaining:
        block = read(min(remaining, 1024 * 1024))
        if not block:
            break
        parts.append(block)
        remaining -= len(block)
    if b''.join(parts) != expected:
        inspection._fail('Checkpoint predecessor or stage bytes changed')


def _replace_state(custody, snapshot):
    """Replace only two freshly validated exact records under continuous lock."""
    raw, observed = snapshot['raw'], snapshot['observations']
    custody.check_lock()
    with _parent(custody, STATE) as (parent, name):
        if custody.windows:
            handles = custody.reader.handles
            with handles.open_child(parent, 'state.pending.json', kind='file', for_rename=True) as stage:
                stage_info = stage.info()
                if lb.project_windows_witness(stage_info, stage.security()) != observed[STAGE]['metadata']:
                    inspection._fail('Checkpoint stage native identity changed')
                stage.seek(0)
                _check_bytes(stage.read, raw[STAGE])
                with handles.open_child(parent, name, kind='file', pin_for_read=True) as old:
                    before = old.info()
                    if lb.project_windows_witness(before, old.security()) != observed[STATE]['metadata']:
                        inspection._fail('Checkpoint predecessor native identity changed')
                    old.seek(0)
                    _check_bytes(old.read, raw[STATE])
                    if old.info() != before:
                        inspection._fail('Checkpoint predecessor changed while read')
                if stage.info() != stage_info:
                    inspection._fail('Checkpoint stage changed while read')
                custody.check_lock()
                # Old-state read pin must close for replacement. The surrounding
                # operation lock covers cooperating writers; this is not CAS.
                handles.replace_private_checkpoint(stage, parent)
                if lb.project_windows_witness(stage.info(), stage.security()) != observed[STAGE]['metadata']:
                    inspection._fail('Published checkpoint native identity changed')
        else:
            from .portable_provenance_posix import _same_namespace, _witness
            with ExitStack() as stack:
                fds = {}
                for path, leaf in ((STATE, name), (STAGE, 'state.pending.json')):
                    fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                    stack.callback(os.close, fd)
                    before = _witness(fd, leaf=True, label=path)
                    if lb.project_posix_witness(before.metadata) != observed[path]['metadata']:
                        inspection._fail('Checkpoint native identity or protection changed')
                    _check_bytes(lambda count: os.read(fd, count), raw[path])
                    if _witness(fd, leaf=True, label=path) != before:
                        inspection._fail('Checkpoint changed while read')
                    _same_namespace(parent, leaf, before, leaf=True, label=path)
                    fds[path] = fd
                custody.check_lock()
                os.replace('state.pending.json', name, src_dir_fd=parent, dst_dir_fd=parent)
                after = _witness(fds[STAGE], leaf=True, label=STATE)
                if lb.project_posix_witness(after.metadata) != observed[STAGE]['metadata']:
                    inspection._fail('Published checkpoint native identity changed')
                _same_namespace(parent, name, after, leaf=True, label=STATE)
                os.fsync(parent)
    custody.check_lock()


def _operation(snapshot, expected):
    raw, portable = snapshot['raw'], snapshot['portable']
    plan = records.load_rebind_plan(raw[inspection.JOURNAL + '/plan.json'], portable)
    intent = records.load_rebind_intent(raw[inspection.JOURNAL + '/intent.json'], plan, portable,
                                        approved_plan_sha256=expected)
    progress = tuple(records.load_rebind_progress(raw[path], intent, plan, portable)
                     for path in sorted(raw) if path.startswith(inspection.PROGRESS + '/'))
    return plan, intent, portable, records.validate_progress_history(progress, intent, plan, portable)


def complete_published_rebind(project_root: Path | str, *, expected_plan_sha256: str,
                              handles=None) -> inspection.RebindStoreInspection:
    """Finish a fully witnessed published binding; never publish or roll back it.

    Each retry inspects the entire current journal. A completed store with later
    adopter edits is returned unchanged. Unknown or partial records refuse.
    """
    try:
        lb._hex(expected_plan_sha256, lb.HEX64, 'expected approved rebind plan')
        with publication._custody(project_root, handles) as custody:
            # Three progress transitions, stage, replacement, marker, final check.
            for _ in range(7):
                snapshot = {}
                result, _, _ = publication._inspect_locked(project_root, expected_plan_sha256,
                                                           custody, records_out=snapshot)
                if result.recovery_action == 'complete':
                    return result
                if result.recovery_action != 'forward_completion_required':
                    inspection._fail('Forward completion requires a published native binding')
                plan, intent, portable, history = _operation(snapshot, expected_plan_sha256)
                candidate = records.candidate_binding(intent, plan, portable)
                next_phase = {'publish_pending': 'committed', 'committed': 'finalize_pending',
                              'finalize_pending': 'finalized'}.get(result.phase)
                if next_phase is not None:
                    progress = records.advance_progress(
                        history.records[-1], next_phase, intent, plan, portable,
                        live_binding=candidate, current_portable_head_sha256=portable.manifest_sha256,
                        publication_witness=history.records[-1].body['publication_witness'])
                    _write_new(custody, inspection.PROGRESS + f'/{len(history.records):08d}.json', progress.raw)
                    continue
                if result.phase != 'finalized':
                    inspection._fail('Unsupported forward checkpoint phase')
                state, terminal, _ = records.checkpoint_records(history, intent, plan, portable)
                if snapshot['raw'][STATE] != state.raw:
                    if STAGE not in snapshot['raw']:
                        _write_new(custody, STAGE, state.raw)
                    else:
                        _replace_state(custody, snapshot)
                elif TERMINAL not in snapshot['raw']:
                    _write_new(custody, TERMINAL, terminal.raw)
                else:
                    inspection._fail('Checkpoint did not converge to complete')
            inspection._fail('Forward checkpoint exceeded its fixed step bound')
    except inspection.RebindStoreInspectionError:
        raise
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, KeyError) as exc:
        raise inspection.RebindStoreInspectionError(f'Native forward checkpoint refused: {exc}') from exc
