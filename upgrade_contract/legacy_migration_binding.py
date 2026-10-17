"""Publish a migration's exact local binding and finish its forward checkpoint.

Portable publication is irreversible through this API. Interrupted file moves
resume using their recorded native identity; unrecorded objects are preserved.
"""
from __future__ import annotations

import ntpath

from . import legacy_migration_binding_records as records
from . import legacy_migration_inspection as inspection
from . import legacy_migration_progress as progress
from . import legacy_migration_retention as retention
from . import local_binding as lb
from . import rebind_checkpoint as checkpoint
from . import rebind_publication as publication


class MigrationBindingError(ValueError):
    """The exact prospective binding or checkpoint cannot be completed."""


def _stage_binding(legacy, local, candidate, intent):
    legacy.check_mutation_window()
    local.check_lock()
    binding = records.candidate_binding(intent, candidate)
    witness = checkpoint._write_new(local, progress.BINDING_STAGE, binding.raw)
    identity = None
    if legacy.windows:
        from .windows_restoring_backend import WindowsRestoringBackend
        from .windows_rename_identity import identity_record
        path = ntpath.join(legacy.reader.root, *progress.BINDING_STAGE.split('/'))
        with WindowsRestoringBackend(legacy.reader.handles, {'stage': path}) as backend:
            identity = identity_record(backend.observe('stage'))
    planned = candidate.plan.body
    commitment = {'staged_path': progress.BINDING_STAGE, 'staged_witness': witness,
        'target_path': progress.BINDING_TARGET,
        'target_absent': lb.absent_witness(planned['initial_capture']['native']['platform'], 'file'),
        'sha256': binding.sha256, 'size_decimal': str(len(binding.raw)),
        'project_id': planned['new_project_id'],
        'owner_record_sha256': planned['candidate_owner_record_sha256'],
        'head_record_sha256': planned['candidate_head_record_sha256'],
        'rename_identity': identity}
    legacy.check_mutation_window()
    local.check_lock()
    return commitment


def _move_binding(legacy, local, candidate, intent, commitment, *, restore_only=False):
    legacy.check_mutation_window()
    local.check_lock()
    if legacy.windows:
        from .windows_restoring_backend import WindowsRestoringBackend
        from .windows_rename_identity import identity_from_record
        paths = {key: ntpath.join(legacy.reader.root, *path.split('/'))
                 for key, path in (('source', progress.BINDING_STAGE),
                                   ('destination', progress.BINDING_TARGET))}
        expected = identity_from_record(commitment['rename_identity'])
        with WindowsRestoringBackend(legacy.reader.handles, paths) as backend:
            if restore_only:
                backend.restore_pending('source', 'destination', expected)
            else:
                backend.move_exact('source', 'destination', expected)
    else:
        if restore_only:
            raise MigrationBindingError('POSIX binding cannot restore Windows metadata')
        publication._publish_posix(local, records.candidate_binding(intent, candidate).raw,
                                    {'metadata': commitment['staged_witness']})
    legacy.check_mutation_window()
    local.check_lock()


def complete_migration_binding(project_root, *, candidate, expected_plan_sha256, handles=None):
    """Finish only a published portable migration; retain its full native journal."""
    with inspection._held_prepared_migration(project_root, candidate=candidate,
            expected_plan_sha256=expected_plan_sha256, handles=handles) as (legacy, local, observed):
        if observed.phase == 'head_published':
            commitment = _stage_binding(legacy, local, candidate, observed.intent)
            inspection._inspect_prepared(legacy, local, candidate, binding_staged=commitment)
            retention._append(legacy, local, candidate, observed, 'binding_pending', commitment)
            observed = inspection._inspect_prepared(legacy, local, candidate)
        if observed.phase == 'binding_pending':
            commitment = observed.progress_history[8].body['commitment']
            if observed.binding_state in {'staged', 'install_restore_pending'}:
                _move_binding(legacy, local, candidate, observed.intent, commitment,
                              restore_only=observed.binding_state == 'install_restore_pending')
                observed = inspection._inspect_prepared(legacy, local, candidate)
            if observed.binding_state != 'published':
                raise MigrationBindingError('Binding is not exactly published')
            retention._append(legacy, local, candidate, observed, 'finalized')
            observed = inspection._inspect_prepared(legacy, local, candidate)
        if observed.phase != 'finalized' or observed.binding_state != 'published':
            raise MigrationBindingError('Binding completion requires a published portable head')
        state, terminal, _binding = records.checkpoint_records(
            observed.progress_history, observed.intent, candidate)
        # Each absent record is written exclusively, then independently inspected.
        # Existing partial/foreign bytes refuse; no replacement is attempted.
        for path, record in ((checkpoint.STATE, state), (checkpoint.TERMINAL, terminal)):
            if path not in observed.checkpoint_paths:
                legacy.check_mutation_window()
                checkpoint._write_new(local, path, record.raw)
                observed = inspection._inspect_prepared(legacy, local, candidate)
        if not observed.checkpoint_complete:
            raise MigrationBindingError('Migration checkpoint is incomplete')
        return observed

