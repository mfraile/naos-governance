"""Register and stage an approved absent-store rebind under one native lock.

Only complete prepared, registered, candidate_ready and publish_pending records
are accepted. A candidate left before its native witness is journaled is retained
and refused; recovery must not infer ownership from matching bytes.
"""
from __future__ import annotations

from pathlib import Path

from . import local_binding as lb
from . import rebind_checkpoint as checkpoint
from . import rebind_publication as publication
from . import rebind_records as records
from . import rebind_store_inspection as inspection


def stage_prepared_rebind(project_root: Path | str, *, expected_plan_sha256: str,
                          handles=None) -> inspection.RebindStoreInspection:
    """Advance one exact prepared journal to publish_pending without publication.

    Every completed record is inspected afresh. The candidate file and the
    candidate_ready record form a deliberately indivisible *logical* step: a
    process exit between them leaves an unwitnessed file and later calls refuse.
    """
    try:
        lb._hex(expected_plan_sha256, lb.HEX64, 'expected approved rebind plan')
        with publication._custody(project_root, handles) as custody:
            for _ in range(5):
                snapshot = {}
                result, _, _ = publication._inspect_locked(
                    project_root, expected_plan_sha256, custody, records_out=snapshot)
                if result.phase == 'publish_pending':
                    return result
                if result.phase not in {'prepared', 'registered', 'candidate_ready'}:
                    inspection._fail('Staging requires a prepared forward rebind')
                plan, intent, portable, history = checkpoint._operation(snapshot, expected_plan_sha256)
                predecessor = history.records[-1]
                if result.phase == 'prepared':
                    if checkpoint.STATE not in snapshot['raw']:
                        state = inspection._registered_state(plan, intent)
                        checkpoint._write_new(custody, checkpoint.STATE, state.raw)
                        continue
                    next_phase, witness = 'registered', None
                elif result.phase == 'registered':
                    candidate = records.candidate_binding(intent, plan, portable)
                    witness = checkpoint._write_new(custody, inspection.CANDIDATE, candidate.raw)
                    next_phase = 'candidate_ready'
                else:
                    next_phase, witness = 'publish_pending', predecessor.body['publication_witness']
                progress = records.advance_progress(
                    predecessor, next_phase, intent, plan, portable,
                    live_binding=None, current_portable_head_sha256=portable.manifest_sha256,
                    publication_witness=witness)
                checkpoint._write_new(
                    custody, inspection.PROGRESS + f'/{len(history.records):08d}.json', progress.raw)
            inspection._fail('Staging exceeded its supported persistence boundaries')
    except inspection.RebindStoreInspectionError:
        raise
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, KeyError) as exc:
        raise inspection.RebindStoreInspectionError(f'Native rebind staging refused: {exc}') from exc
