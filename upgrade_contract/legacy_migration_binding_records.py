"""Pure prospective binding and final checkpoint for one approved migration.

These records bind approved bytes and a complete progress chain. They do not
observe a namespace, prove quiescence, authorize publication, or grant cleanup
rights. Native callers must hold and revalidate both source and local custody.
"""
from __future__ import annotations

from . import legacy_migration_journal as journal
from . import legacy_migration_planning as planning
from . import legacy_migration_progress as progress
from . import local_binding as binding
from . import local_store as store


class MigrationBindingRecordError(ValueError):
    """Candidate, progress, or prospective checkpoint is not exact."""


def _context(intent, candidate):
    if type(candidate) is not planning.MigrationCandidate or candidate.mutation_authorized is not False:
        raise MigrationBindingRecordError('Exact read-only migration candidate required')
    members = candidate._files
    if type(members) is not tuple or not 1 <= len(members) <= 20_000:
        raise MigrationBindingRecordError('Bounded candidate members required')
    if any(type(row) is not tuple or len(row) != 2 or type(row[0]) is not str
           or type(row[1]) is not bytes for row in members):
        raise MigrationBindingRecordError('Invalid candidate member type')
    files = dict(members)
    if len(files) != len(members) or tuple(sorted(files.items())) != members:
        raise MigrationBindingRecordError('Candidate members differ or alias')
    if type(intent) is not journal.MigrationIntent:
        raise MigrationBindingRecordError('Typed migration intent required')
    try:
        checked = journal.load_migration_intent(
            intent.raw, candidate.plan, files, candidate.lineage,
            approved_plan_sha256=candidate.plan.sha256,
        )
    except (ValueError, TypeError, AttributeError, KeyError, OverflowError, RecursionError) as exc:
        raise MigrationBindingRecordError(f'Approved migration intent refused: {exc}') from exc
    if checked != intent:
        raise MigrationBindingRecordError('Forged migration intent digest or bytes')
    return candidate.plan.body, intent.body


def candidate_binding(intent, candidate):
    """Derive the exact post-migration local binding; never claim it is live."""
    plan, prepared = _context(intent, candidate)
    capture = prepared['prepared_capture']
    observation = {
        'schema': binding.OBSERVATION_SCHEMA,
        'native': capture['native'],
        'leaves': capture['leaves'],
        'journals': {'head_id': journal.JOURNAL_ID,
                     'entries': [{'id': journal.JOURNAL_ID, 'sha256': intent.sha256}]},
        'transaction_state': 'quiescent',
        'binding_id': plan['binding_id'],
        'diagnostic_python_minor': None,
    }
    try:
        return binding.load_local_binding(binding.encode_local_binding({
            'schema': binding.BINDING_SCHEMA,
            'project_id': plan['new_project_id'],
            'owner_sha256': plan['candidate_owner_record_sha256'],
            'portable_head_sha256': plan['candidate_head_record_sha256'],
            'binding_id': plan['binding_id'],
            'observation': observation,
        }))
    except (ValueError, TypeError, AttributeError, KeyError, OverflowError, RecursionError) as exc:
        raise MigrationBindingRecordError(f'Prospective local binding refused: {exc}') from exc


def checkpoint_records(history, intent, candidate):
    """Derive finalized generation-one state, terminal, and exact binding.

    A typed tuple must revalidate as the complete, contiguous migration chain.
    Binding-pending bytes must name the exact derived binding, not merely an
    arbitrary well-formed SHA. No rollback or nonterminal phase is admitted.
    """
    result = candidate_binding(intent, candidate)
    if (type(history) is not tuple or len(history) != len(progress.PHASES)
            or any(type(item) is not progress.MigrationProgress for item in history)):
        raise MigrationBindingRecordError('Complete typed migration progress history required')
    try:
        checked = progress.load_progress_history(
            [item.raw for item in history], intent, candidate.plan,
            candidate.projection_files, candidate.lineage,
        )
    except (ValueError, TypeError, AttributeError, KeyError, OverflowError, RecursionError) as exc:
        raise MigrationBindingRecordError(f'Migration progress history refused: {exc}') from exc
    if checked != history or history[-1].body['phase'] != 'finalized':
        raise MigrationBindingRecordError('Exact finalized migration history required')
    staged = history[-2].body['commitment']
    if (staged['sha256'] != result.sha256
            or staged['size_decimal'] != str(len(result.raw))):
        raise MigrationBindingRecordError('Binding-pending commitment differs from derived binding bytes')
    plan = candidate.plan.body
    try:
        state = store.load_local_store(store.encode_local_store({
            'schema': store.STORE_SCHEMA,
            'generation': 1,
            'project_id': plan['new_project_id'],
            'owner_sha256': plan['candidate_owner_record_sha256'],
            'binding_id': plan['binding_id'],
            'binding_sha256': result.sha256,
            'journals': {'head_id': journal.JOURNAL_ID,
                         'entries': [{'id': journal.JOURNAL_ID, 'sha256': intent.sha256}]},
            'active_journal_id': None,
            'archives': [],
        }))
        terminal = store.load_local_terminal(store.encode_local_terminal({
            'schema': store.TERMINAL_SCHEMA,
            'intent_sha256': intent.sha256,
            'outcome': 'committed',
            'progress_sha256': history[-1].sha256,
            'binding_after_sha256': result.sha256,
            'portable_head_sha256': plan['candidate_head_record_sha256'],
        }))
    except (ValueError, TypeError, AttributeError, KeyError, OverflowError, RecursionError) as exc:
        raise MigrationBindingRecordError(f'Prospective migration checkpoint refused: {exc}') from exc
    return state, terminal, result


def rollback_terminal(history, intent, candidate):
    """Derive only a prospective pre-head rollback marker, never a store state.

    The native caller must prove that the portable head was never published,
    the staged tree was removed only by witnessed identity, and the original
    legacy pointer/fence transition was safely reversed. Pure history cannot
    establish those facts, especially at head_pending.
    """
    _context(intent, candidate)
    if (type(history) is not tuple or not 3 <= len(history) <= len(progress._ROLLBACK_SOURCES) + 2
            or any(type(item) is not progress.MigrationProgress for item in history)):
        raise MigrationBindingRecordError('Complete typed rollback progress history required')
    try:
        checked = progress.load_progress_history(
            [item.raw for item in history], intent, candidate.plan,
            candidate.projection_files, candidate.lineage,
        )
    except (ValueError, TypeError, AttributeError, KeyError, OverflowError, RecursionError) as exc:
        raise MigrationBindingRecordError(f'Migration rollback history refused: {exc}') from exc
    if (checked != history or history[-2].body['phase'] != 'rollback_pending'
            or history[-1].body['phase'] != 'rolled_back'):
        raise MigrationBindingRecordError('Exact rolled-back migration history required')
    try:
        return store.load_local_terminal(store.encode_local_terminal({
            'schema': store.TERMINAL_SCHEMA,
            'intent_sha256': intent.sha256,
            'outcome': 'rolled_back',
            'progress_sha256': history[-1].sha256,
            'binding_after_sha256': None,
            'portable_head_sha256': None,
        }))
    except (ValueError, TypeError, AttributeError, KeyError, OverflowError, RecursionError) as exc:
        raise MigrationBindingRecordError(f'Prospective rollback terminal refused: {exc}') from exc
