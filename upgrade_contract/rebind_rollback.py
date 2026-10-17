"""Native rollback before binding publication, preserving portable history.

Only a recorded, fully validated rollback may remove its exact staged binding.
Published bindings always require forward completion. Partial records refuse.
"""
from __future__ import annotations

from contextlib import ExitStack
import os
from pathlib import Path

from . import local_binding as lb
from . import rebind_checkpoint as checkpoint
from . import rebind_publication as publication
from . import rebind_records as records
from . import rebind_store_inspection as inspection


def _remove_candidate(custody, snapshot):
    raw, observed = snapshot['raw'], snapshot['observations']
    path = inspection.CANDIDATE
    custody.check_lock()
    with checkpoint._parent(custody, path) as (parent, name):
        if custody.windows:
            handles = custody.reader.handles
            with handles.open_child(parent, name, kind='file', for_delete=True) as child:
                before = child.info()
                if lb.project_windows_witness(before, child.security()) != observed[path]['metadata']:
                    inspection._fail('Rollback candidate native identity changed; preserve it')
                child.seek(0)
                checkpoint._check_bytes(child.read, raw[path])
                if child.info() != before:
                    inspection._fail('Rollback candidate changed while read; preserve it')
                custody.check_lock()
                handles.delete_exact(parent, name, child)
        else:
            from .portable_provenance_posix import _same_namespace, _witness
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                before = _witness(fd, leaf=True, label=path)
                if lb.project_posix_witness(before.metadata) != observed[path]['metadata']:
                    inspection._fail('Rollback candidate native identity changed; preserve it')
                checkpoint._check_bytes(lambda count: os.read(fd, count), raw[path])
                if _witness(fd, leaf=True, label=path) != before:
                    inspection._fail('Rollback candidate changed while read; preserve it')
                _same_namespace(parent, name, before, leaf=True, label=path)
                custody.check_lock()
                # Descriptor-relative unlink under the cooperating-writer lock.
                # This is not source-identity CAS against a same-user adversary.
                os.unlink(name, dir_fd=parent)
                if os.fstat(fd).st_nlink != 0:
                    inspection._fail('Rollback did not remove the witnessed candidate')
                os.fsync(parent)
            finally:
                os.close(fd)
    custody.check_lock()


def _publish_absent_state(custody, snapshot):
    raw, observed = snapshot['raw'], snapshot['observations']
    if checkpoint.STATE in raw:
        inspection._fail('Absent-state publication cannot replace an existing checkpoint')
    custody.check_lock()
    with checkpoint._parent(custody, checkpoint.STATE) as (parent, name):
        if custody.windows:
            handles = custody.reader.handles
            with handles.open_child(parent, 'state.pending.json', kind='file', for_rename=True) as stage:
                before = stage.info()
                if lb.project_windows_witness(before, stage.security()) != observed[checkpoint.STAGE]['metadata']:
                    inspection._fail('Rollback checkpoint stage identity changed')
                stage.seek(0)
                checkpoint._check_bytes(stage.read, raw[checkpoint.STAGE])
                if stage.info() != before:
                    inspection._fail('Rollback checkpoint stage changed while read')
                custody.check_lock()
                handles.rename_no_replace(stage, parent, name)
                if lb.project_windows_witness(stage.info(), stage.security()) != observed[checkpoint.STAGE]['metadata']:
                    inspection._fail('Rollback checkpoint publication identity changed')
        else:
            from .portable_provenance_posix import _same_namespace, _witness
            from .transaction import rename_no_replace_at
            with ExitStack() as stack:
                fd = os.open('state.pending.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                stack.callback(os.close, fd)
                before = _witness(fd, leaf=True, label=checkpoint.STAGE)
                if lb.project_posix_witness(before.metadata) != observed[checkpoint.STAGE]['metadata']:
                    inspection._fail('Rollback checkpoint stage identity changed')
                checkpoint._check_bytes(lambda count: os.read(fd, count), raw[checkpoint.STAGE])
                if _witness(fd, leaf=True, label=checkpoint.STAGE) != before:
                    inspection._fail('Rollback checkpoint stage changed while read')
                _same_namespace(parent, 'state.pending.json', before, leaf=True, label=checkpoint.STAGE)
                custody.check_lock()
                rename_no_replace_at(parent, 'state.pending.json', parent, name)
                after = _witness(fd, leaf=True, label=checkpoint.STATE)
                if lb.project_posix_witness(after.metadata) != observed[checkpoint.STAGE]['metadata']:
                    inspection._fail('Rollback checkpoint publication identity changed')
                _same_namespace(parent, name, after, leaf=True, label=checkpoint.STATE)
                os.fsync(parent)
    custody.check_lock()


def rollback_prepublication_rebind(project_root: Path | str, *, expected_plan_sha256: str,
                                    handles=None) -> inspection.RebindStoreInspection:
    """Roll back an approved unpublished operation; retain its complete history.

    Completed persistence boundaries are retryable. Unknown, partial or foreign
    records refuse without guessed cleanup. A completed rollback retry is read-only.
    """
    try:
        lb._hex(expected_plan_sha256, lb.HEX64, 'expected approved rebind plan')
        with publication._custody(project_root, handles) as custody:
            for _ in range(7):
                snapshot = {}
                result, _, _ = publication._inspect_locked(project_root, expected_plan_sha256,
                                                           custody, records_out=snapshot)
                if result.recovery_action == 'rolled_back':
                    return result
                if result.recovery_action != 'rollback_required' or result.binding_sha256 is not None:
                    inspection._fail('Published binding cannot be rolled back')
                plan, intent, portable, history = checkpoint._operation(snapshot, expected_plan_sha256)
                if result.phase in {'prepared', 'registered', 'candidate_ready', 'publish_pending'}:
                    next_phase = 'rollback_pending'
                elif result.phase == 'rollback_pending':
                    if inspection.CANDIDATE in snapshot['raw']:
                        _remove_candidate(custody, snapshot)
                        continue
                    next_phase = 'rolled_back'
                elif result.phase == 'rolled_back':
                    state, terminal, _ = records.checkpoint_records(history, intent, plan, portable)
                    if snapshot['raw'].get(checkpoint.STATE) != state.raw:
                        if checkpoint.STAGE not in snapshot['raw']:
                            checkpoint._write_new(custody, checkpoint.STAGE, state.raw)
                        elif checkpoint.STATE in snapshot['raw']:
                            checkpoint._replace_state(custody, snapshot)
                        else:
                            _publish_absent_state(custody, snapshot)
                    elif checkpoint.TERMINAL not in snapshot['raw']:
                        checkpoint._write_new(custody, checkpoint.TERMINAL, terminal.raw)
                    else:
                        inspection._fail('Rollback checkpoint did not converge')
                    continue
                else:
                    inspection._fail('Unsupported rollback phase')
                progress = records.advance_progress(
                    history.records[-1], next_phase, intent, plan, portable,
                    live_binding=None, current_portable_head_sha256=portable.manifest_sha256,
                    publication_witness=history.records[-1].body['publication_witness'])
                checkpoint._write_new(custody, inspection.PROGRESS + f'/{len(history.records):08d}.json', progress.raw)
            inspection._fail('Rollback exceeded its fixed step bound')
    except inspection.RebindStoreInspectionError:
        raise
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, KeyError) as exc:
        raise inspection.RebindStoreInspectionError(f'Native rebind rollback refused: {exc}') from exc
