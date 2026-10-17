"""Prepare a private migration journal under legacy-then-v3 native locks.

Only plan/intent/initial-progress persistence is implemented here. Partial
preparations are retained and refused; no legacy pointer or working leaf moves.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from . import legacy_migration_custody as custody
from . import legacy_migration_journal as journal
from . import legacy_migration_plan_records as plans
from . import rebind_checkpoint as checkpoint
from . import rebind_preparation as bootstrap
from . import rebind_publication as publication
from . import rebind_store_inspection as inspection
from .working_tree_capture import ancestor_paths, build_capture, managed_paths


class MigrationPreparationError(ValueError):
    """Preparation failed; all partial objects are preserved for inspection."""


@dataclass(frozen=True)
class PreparedMigration:
    plan_sha256: str
    intent: journal.MigrationIntent
    phase: str = 'prepared'


def _working_capture(root, windows, handles, paths):
    selected = managed_paths(paths)
    ancestors = ancestor_paths(selected)
    if windows:
        from .working_tree_capture_windows import _Capture, _initial_capture
        with ExitStack() as stack:
            reader = _Capture(handles, str(root), stack)
            native, leaves = _initial_capture(reader, str(root), selected, ancestors)
            reader.revalidate()
            return build_capture(native, leaves)
    from .working_tree_capture_posix import _Reader, _initial_capture
    with _Reader(Path(root)) as reader:
        native, leaves = _initial_capture(reader, selected, ancestors)
        reader._final_revalidate(native, leaves)
        return build_capture(native, leaves)


def _verify_records(root, local, prepared, intent, records, written):
    """Use a fresh immutable reader after writes; never reuse mutation baselines."""
    paths = managed_paths([row['path'] for row in prepared.body['leaves']])
    with ExitStack() as stack:
        if local.windows:
            from .working_tree_capture_windows import _Capture, _initial_capture
            reader = _Capture(local.reader.handles, str(root), stack)
            native, leaves = _initial_capture(reader, str(root), paths, ancestor_paths(paths))
        else:
            from .working_tree_capture_posix import _Reader, _initial_capture
            reader = stack.enter_context(_Reader(Path(root)))
            native, leaves = _initial_capture(reader, paths, ancestor_paths(paths))
        observed = inspection._NativeStore(SimpleNamespace(working_reader=reader), local.windows)
        observed.lock_handle, observed.lock_witness = local.lock_handle, local.lock_witness
        observed.check_lock()
        for name, path in (('journal', inspection.JOURNAL), ('progress', inspection.PROGRESS)):
            if observed.directory(path) != intent.body['storage_witnesses'][name]:
                raise MigrationPreparationError('Persisted journal directory identity differs')
        for relative, raw in records:
            if (observed.read(relative) != raw
                    or observed.observations[relative]['metadata'] != written[relative]):
                raise MigrationPreparationError('Persisted migration record identity or bytes differ')
        if local.windows:
            reader.revalidate()
        else:
            reader._final_revalidate(native, leaves + list(observed.observations.values()))
        observed.check_lock()
        if build_capture(native, leaves).raw != prepared.raw:
            raise MigrationPreparationError('Working capture changed during journal persistence')


def prepare_legacy_migration(project_root, *, candidate, expected_plan_sha256, handles=None):
    """Persist a new private journal only after exact native plan revalidation.

    This entry point does not resume or adopt an existing/partial local store.
    The caller's approval digest binds the complete reviewed candidate plan.
    """
    try:
        with custody._approved_legacy_custody(project_root, candidate=candidate,
                expected_plan_sha256=expected_plan_sha256, handles=handles) as legacy:
            legacy.check_mutation_window()
            windows = legacy.windows
            active_handles = legacy.reader.handles if windows else None
            creating = (bootstrap._bootstrap_windows(project_root, candidate.plan, active_handles)
                        if windows else bootstrap._bootstrap_posix(project_root, candidate.plan,
                            creation_owner=tuple(int(legacy.lock_witness[key])
                                for key in ('uid_decimal', 'gid_decimal'))))
            with creating as pinned, publication._custody(project_root, active_handles) as local:
                # Existing native primitives only; their absent-store authority
                # validator is deliberately not invoked for this distinct variant.
                legacy.check_mutation_window()
                bootstrap._verify_bootstrap(pinned, local)
                paths = [item['path'] for item in candidate.plan.body['initial_capture']['leaves']]
                prepared = _working_capture(project_root, windows, active_handles, paths)
                directory = (local.reader.directory_witness if windows else local.reader.directory)
                intent = journal.build_migration_intent(candidate.plan, candidate.projection_files,
                    candidate.lineage, prepared, approved_plan_sha256=expected_plan_sha256,
                    storage_witnesses={'lock': local.lock_witness,
                        'journal': directory(inspection.JOURNAL), 'progress': directory(inspection.PROGRESS)},
                    legacy_lock={'path': legacy.lock_path, 'witness': legacy.lock_witness})
                records = ((inspection.JOURNAL + '/plan.json', candidate.plan.raw),
                           (inspection.JOURNAL + '/intent.json', intent.raw),
                           (inspection.PROGRESS + '/00000000.json', journal.initial_progress(intent)),
                           *tuple(sorted(plans.raw_evidence_files(candidate.lineage).items())))
                written = {}
                for relative, raw in records:
                    legacy.check_mutation_window()
                    written[relative] = checkpoint._write_new(local, relative, raw)
                _verify_records(project_root, local, prepared, intent, records, written)
                legacy.check_mutation_window()
                with custody._snapshot(legacy) as source:
                    planned = candidate.plan.body
                    files = [source.observations[p] for p in sorted(source.observations)]
                    directories = [{'path': p, 'witness': w}
                                   for p, w in sorted(source.directory_witnesses.items())]
                    if files != planned['legacy_files'] or directories != planned['legacy_directories']:
                        raise MigrationPreparationError('Legacy source changed during journal persistence')
                    for item in planned['portable_destinations'] + [planned['competing_legacy']]:
                        observed_directory = (source.reader.directory_witness(item['path']) if windows
                                              else source.reader.directory(item['path']))
                        if observed_directory != item['witness']:
                            raise MigrationPreparationError('Migration destination changed during preparation')
                return PreparedMigration(candidate.plan.sha256, intent)
    except MigrationPreparationError:
        raise
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, AttributeError, OverflowError) as exc:
        raise MigrationPreparationError(f'Native migration preparation refused: {exc}') from exc
