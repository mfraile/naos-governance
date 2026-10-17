"""Native read-only legacy migration planning, with one held source lock.

History and current working/native identity are separate evidence. No control
file is replaced, no local store is created and no working content is rewritten.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import legacy_archive_capture as capture
from . import legacy_authority as authority
from . import legacy_migration_records as migration
from . import legacy_migration_plan_records as records
from . import local_binding as binding
from . import portable_provenance as pp
from .working_tree_capture import ancestor_paths, build_capture, managed_paths


class LegacyMigrationPlanningError(ValueError):
    """A native migration candidate could not be observed safely."""


@dataclass(frozen=True)
class MigrationCandidate:
    plan: records.ValidatedMigrationPlan
    lineage: migration.LegacyLineage
    _files: tuple[tuple[str, bytes], ...]
    mutation_authorized: bool = False

    @property
    def raw_archive(self):
        if self.lineage._raw_archive:
            return dict(self.lineage._raw_archive)
        return {row['path']: self.projection_files[authority.blob_path(row['sha256'])]
                for row in self.lineage.body['archive']}

    @property
    def raw_lineage(self):
        return self.lineage.raw

    @property
    def raw_policy(self):
        return self.lineage._raw_policy

    @property
    def raw_modes(self):
        return self.lineage._raw_modes

    @property
    def projection_files(self):
        return dict(self._files)


def _directory(reader, windows, path):
    return reader.directory_witness(path) if windows else reader.directory(path)


def _candidate_from_held(held, *, source_format, original_project_id,
                         new_project_id, binding_id, approved_lineage_sha256,
                         expected_owner_sha256, expected_scope_sha256,
                         expected_head_sha256, source_policy_raw,
                         expected_source_policy_sha256, mode_inventory_raw,
                         expected_modes_sha256, replay_projection=True):
    """Internal observation only; caller must successfully close its read window."""
    if type(replay_projection) is not bool:
        raise LegacyMigrationPlanningError('Projection format selector must be Boolean')
    if held.source_format != source_format:
        raise LegacyMigrationPlanningError('Held source format differs')
    expected = dict(expected_owner_sha256=expected_owner_sha256,
                    expected_scope_sha256=expected_scope_sha256,
                    expected_head_sha256=expected_head_sha256)
    archive = held.archive_bytes
    lineage = migration.build_lineage(archive, source_format=source_format,
        original_project_id=original_project_id, new_project_id=new_project_id, **expected)
    if replay_projection:
        lineage = migration.LegacyLineage(lineage.raw, lineage.sha256,
            tuple(sorted(archive.items())), source_policy_raw, mode_inventory_raw)
    builder = authority.build_replay_projection if replay_projection else authority.build_legacy_projection
    files = builder(archive, lineage,
        directory_paths=held.directory_paths, source_policy_raw=source_policy_raw,
        mode_inventory_raw=mode_inventory_raw, expected_modes_sha256=expected_modes_sha256,
        approved_lineage_sha256=approved_lineage_sha256,
        expected_source_policy_sha256=expected_source_policy_sha256, **expected)
    class Reader:
        def read(self, path):
            return files.get(path)
    snapshot = pp.load_portable_snapshot(Reader())
    selected = managed_paths(sorted(snapshot.entries))
    ancestors = ancestor_paths(selected)
    reader = held.reader
    if held.windows:
        from .working_tree_capture_windows import _initial_capture
        native, leaves = _initial_capture(reader, reader.root, selected, ancestors)
    else:
        from .working_tree_capture_posix import _initial_capture
        native, leaves = _initial_capture(reader, selected, ancestors)
    working = build_capture(native, leaves)
    local_parent = native['control_directories'][1]['witness']
    if local_parent['presence'] == 'present':
        held._private(local_parent)
    destinations = [{'path': path, 'witness': _directory(reader, held.windows, path)}
                    for path in ('.naos/managed-content', pp.ROOT)]
    other = ('.naos/upgrade-v1/windows-content' if source_format == migration.POSIX_MANAGED_V1
             else '.naos/upgrade-v1/managed-content')
    competing = {'path': other, 'witness': _directory(reader, held.windows, other)}
    plan = records.build_migration_plan(projection_files=files, lineage=lineage,
        source_format=source_format, binding_id=binding_id, initial_capture=working,
        legacy_files=[held.observations[path] for path in sorted(held.observations)],
        legacy_directories=[{'path': path, 'witness': witness}
                            for path, witness in sorted(held.directory_witnesses.items())],
        legacy_lock={'path': held.lock_path, 'witness': held.lock_witness},
        portable_destinations=destinations, competing_legacy=competing)
    held.revalidate()
    if held.windows:
        reader.revalidate()
    else:
        # Legacy revalidation covers source observations, not managed leaves.
        reader._final_revalidate(native, leaves)
    if destinations != [{'path': item['path'],
                          'witness': _directory(reader, held.windows, item['path'])}
                         for item in destinations]:
        raise LegacyMigrationPlanningError('Portable destination changed during planning')
    if competing['witness'] != _directory(reader, held.windows, other):
        raise LegacyMigrationPlanningError('Competing legacy storage changed during planning')
    return MigrationCandidate(plan, lineage, tuple(sorted(files.items())))


def plan_legacy_migration(project_root, *, source_format, original_project_id,
                          new_project_id, binding_id, approved_lineage_sha256,
                          expected_owner_sha256, expected_scope_sha256,
                          expected_head_sha256, source_policy_raw,
                          expected_source_policy_sha256, mode_inventory_raw,
                          expected_modes_sha256, handles=None, replay_projection=True) -> MigrationCandidate:
    """Bind explicitly selected historical bytes and this checkout's witnesses.

    Independent expected digests must be supplied by the caller. The plan hash
    is a later approval boundary; a returned candidate grants no write authority.
    New callers default to full path-free replay. Explicit False preserves the
    historical v1 format for version-bound callers and approved-plan rebuilding.
    A complete final source AND working-tree revalidation precedes return.
    """
    try:
        # Bound caller controls before constructing a native reader.
        for digest in (approved_lineage_sha256, expected_owner_sha256, expected_scope_sha256,
                       expected_head_sha256, expected_source_policy_sha256, expected_modes_sha256):
            migration._digest(digest, 'expected migration input')
        migration._original_id(original_project_id)
        migration._uuid4(new_project_id)
        binding._hex(binding_id, binding.BINDING_ID, 'binding ID')
        if (type(source_policy_raw) is not bytes or len(source_policy_raw) > pp.MAX_RECORD_BYTES
                or type(mode_inventory_raw) is not bytes or len(mode_inventory_raw) > pp.MAX_RECORD_BYTES):
            raise LegacyMigrationPlanningError('Missing or oversized policy/mode inventory')
        with capture.held_legacy_archive(project_root, source_format=source_format, handles=handles) as held:
            candidate = _candidate_from_held(held, source_format=source_format,
                original_project_id=original_project_id, new_project_id=new_project_id,
                binding_id=binding_id, approved_lineage_sha256=approved_lineage_sha256,
                expected_owner_sha256=expected_owner_sha256,
                expected_scope_sha256=expected_scope_sha256, expected_head_sha256=expected_head_sha256,
                source_policy_raw=source_policy_raw, expected_source_policy_sha256=expected_source_policy_sha256,
                mode_inventory_raw=mode_inventory_raw, expected_modes_sha256=expected_modes_sha256,
                replay_projection=replay_projection)
        # Context exit revalidates the original source and lock once again.
        return candidate
    except LegacyMigrationPlanningError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError) as exc:
        raise LegacyMigrationPlanningError(f'Native legacy migration planning refused: {exc}') from exc
