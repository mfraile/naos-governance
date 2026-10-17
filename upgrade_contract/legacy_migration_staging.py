"""Private native staging of exactly the approved portable candidate bytes.

A stage is never active authority. Partial or unwitnessed stages are preserved;
only a later validated progress record may authorize subsequent transitions.
"""
from __future__ import annotations

from contextlib import ExitStack
import os

from . import local_binding as lb
from . import portable_provenance as pp
from . import rebind_checkpoint as checkpoint
from . import rebind_preparation as bootstrap
from . import rebind_store_inspection as store

STAGE = store.JOURNAL + '/portable.pending'


class MigrationStagingError(ValueError):
    """The exact private stage could not be created safely."""


class _TreeWriter:
    def __init__(self, legacy, local, stack):
        self.legacy, self.local, self.stack = legacy, local, stack
        self.windows = local.windows
        self.reader = self
        self.handles = local.reader.handles if self.windows else None
        self.directories = {}
        self.witnesses = {}
        self.parents = {}

    def check_lock(self):
        self.legacy.check_mutation_window()
        self.local.check_lock()
        for path, expected in self.witnesses.items():
            parent, name = self.parents[path]
            if self.windows:
                handle = self.directories[path]
                if lb.project_windows_witness(handle.info(), handle.security()) != expected:
                    raise MigrationStagingError('Pinned stage directory changed')
                with self.handles.open_child(parent, name, kind='directory', pin_for_read=True) as opened:
                    if lb.project_windows_witness(opened.info(), opened.security()) != expected:
                        raise MigrationStagingError('Stage directory namespace changed')
            else:
                from .portable_provenance_posix import _same_namespace, _witness
                observed = _witness(self.directories[path], leaf=False, label=path)
                if lb.project_posix_witness(observed.metadata) != expected:
                    raise MigrationStagingError('Pinned stage directory changed')
                _same_namespace(parent, name, observed, leaf=False, label=path)

    def _walk(self, relative, _stack):
        self.check_lock()
        return self.directories[relative]

    def directory(self, relative):
        self.check_lock()
        if relative not in self.directories:
            raise MigrationStagingError('Unpinned stage directory')
        return relative

    def create(self, path, parent, name):
        self.check_lock()
        if self.windows:
            handle = self.stack.enter_context(self.handles.create_private_directory(parent, name))
            witness = lb.project_windows_witness(handle.info(), handle.security())
        else:
            from .portable_provenance_posix import _witness
            handle = bootstrap._mkdir_posix(parent, name)
            self.stack.callback(os.close, handle)
            witness = lb.project_posix_witness(_witness(handle, leaf=False, label=path).metadata)
        self.local._private(witness)
        self.directories[path], self.witnesses[path] = handle, witness
        self.parents[path] = parent, name
        self.check_lock()


def _stage_candidate(legacy, local, candidate):
    """Create stage under continuous inspected custody; return actual witnesses.

    This private operation must be called only after complete prepared-journal
    inspection. The caller must persist its returned commitment before any move.
    """
    files = candidate.projection_files
    # Pure candidate validation has already run under prepared inspection.
    directories = sorted({path.removeprefix(pp.ROOT + '/').rpartition('/')[0]
                          for path in files} - {''})
    if any('/' in path for path in directories) or len(directories) > 8:
        raise MigrationStagingError('Unsupported portable stage directory layout')
    with ExitStack() as stack:
        writer = _TreeWriter(legacy, local, stack)
        with checkpoint._parent(local, STAGE) as (parent, name):
            writer.directories[store.JOURNAL] = parent
            writer.create(STAGE, parent, name)
            for path in directories:
                writer.create(STAGE + '/' + path, writer.directories[STAGE], path)
            created = []
            for path, raw in sorted(files.items()):
                relative = STAGE + '/' + path.removeprefix(pp.ROOT + '/')
                witness = checkpoint._write_new(writer, relative, raw,
                                                max_bytes=pp.control_path_limit(path))
                created.append({'path': path, 'witness': witness})
            writer.check_lock()
            return {'stage_root': writer.witnesses[STAGE],
                    'directories': [{'path': p, 'witness': writer.witnesses[STAGE + '/' + p]}
                                    for p in directories], 'files': created}


def stage_prepared_migration(project_root, *, candidate, expected_plan_sha256, handles=None):
    """Advance a complete prepared journal to witnessed candidate_ready.

    A crash before the witness record is persisted leaves an unowned stage,
    which is preserved and refused. No original pointer or active head changes.
    """
    from . import legacy_migration_inspection as inspection
    from . import legacy_migration_progress as progress
    with inspection._held_prepared_migration(project_root, candidate=candidate,
            expected_plan_sha256=expected_plan_sha256, handles=handles) as (legacy, local, observed):
        if observed.phase == 'candidate_ready':
            return observed
        if observed.phase != 'prepared':
            raise MigrationStagingError('Candidate staging requires prepared journal')
        commitment = _stage_candidate(legacy, local, candidate)
        # Prove the entire new tree and unchanged source/working state before
        # recording ownership; closed read snapshots never span our writes.
        inspection._inspect_prepared(legacy, local, candidate, staged=commitment)
        record = progress.advance_progress(observed.progress_history[-1], 'candidate_ready',
            commitment, observed.intent, candidate.plan, candidate.projection_files, candidate.lineage)
        legacy.check_mutation_window()
        checkpoint._write_new(local, store.PROGRESS + '/00000001.json', record.raw)
        return inspection._inspect_prepared(legacy, local, candidate)
