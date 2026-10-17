"""Replay exact archived Windows v1 history without native checkout authority.

The archived root identity is historical data. This adapter never compares it
with a current root, creates Windows handles, or authorizes migration writes.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from .canonical import canonical_bytes, loads_strict_json
from . import legacy_migration_records as migration
from . import windows_provenance as provenance


class LegacyWindowsReplayError(ValueError):
    """Archived lineage or complete committed Windows history was refused."""


class _ArchiveReader:
    """Bounded by load_lineage; cache each actually supplied member once."""
    def __init__(self, archive: dict[str, bytes]):
        self.archive = archive
        self.cache: dict[str, bytes | None] = {}
        self.read_paths: set[str] = set()

    def read(self, relative: str) -> bytes | None:
        if type(relative) is not str or not relative.startswith(provenance.ROOT + '\\'):
            raise LegacyWindowsReplayError('Windows replay requested an unsupported source path')
        path = relative.replace('\\', '/')
        if path not in self.cache:
            value = self.archive.get(path)
            self.cache[path] = value
            if value is not None:
                self.read_paths.add(path)
        return self.cache[path]


@dataclass(frozen=True)
class LegacyWindowsReplay:
    snapshot: provenance.ValidatedWindowsProvenance
    lineage_sha256: str
    source_policy_sha256: str
    _historical_root_identity_bytes: bytes
    actually_read_source_paths: tuple[str, ...]
    unvalidated_archive_paths: tuple[str, ...]
    native_custody_proven: bool = False
    quiescence_proven: bool = False
    mutation_authorized: bool = False

    @property
    def historical_root_identity(self) -> dict[str, str]:
        return loads_strict_json(self._historical_root_identity_bytes)


def replay_windows_archive(archive_bytes, lineage: migration.LegacyLineage, *,
                           approved_lineage_sha256: str,
                           expected_owner_sha256: str, expected_scope_sha256: str,
                           expected_head_sha256: str, source_policy_raw: bytes,
                           expected_source_policy_sha256: str) -> LegacyWindowsReplay:
    """Use existing Windows v1 replay against a structurally approved archive.

    Successful replay proves only internal historical consistency of supplied
    bytes. Native custody, complete filesystem inventory and quiescence remain
    separate prerequisites for any migration plan or mutation.
    """
    try:
        if (type(archive_bytes) is not dict
                or not 3 <= len(archive_bytes) <= migration.MAX_ARCHIVE_FILES):
            raise LegacyWindowsReplayError('Archived source bytes must be a fixed dictionary')
        archive = dict(archive_bytes)
        if type(lineage) is not migration.LegacyLineage:
            raise LegacyWindowsReplayError('Validated legacy lineage is required')
        verified = migration.load_lineage(
            lineage.raw, archive, approved_lineage_sha256=approved_lineage_sha256,
            expected_owner_sha256=expected_owner_sha256,
            expected_scope_sha256=expected_scope_sha256,
            expected_head_sha256=expected_head_sha256)
        if lineage.sha256 != verified.sha256 or verified.body['source_format'] != migration.WINDOWS_CONTENT_V1:
            raise LegacyWindowsReplayError('Lineage is not the approved Windows source format')
        migration._digest(expected_source_policy_sha256, 'expected source policy')
        if (type(source_policy_raw) is not bytes
                or len(source_policy_raw) > provenance.MAX_CONTROL_BYTES
                or hashlib.sha256(source_policy_raw).hexdigest() != expected_source_policy_sha256):
            raise LegacyWindowsReplayError('Source policy bytes differ from independent expectation')
        reader = _ArchiveReader(archive)
        root, _ = provenance._decode(reader.read(provenance.ROOT_PATH),
                                     provenance.ROOT_SCHEMA, provenance._ROOT_KEYS)
        historical_root = provenance._root_identity(root['root_identity'])
        snapshot = provenance.load_windows_provenance(
            reader, root_identity=historical_root, source_policy_raw=source_policy_raw)
        if snapshot.project_id != verified.body['original_project_id']:
            raise LegacyWindowsReplayError('Original project ID differs from validated Windows history')
        if not snapshot.manifest['receipts'] or snapshot.previous_inputs is None:
            raise LegacyWindowsReplayError('Provisional empty Windows enrollment is not migratable')
        return LegacyWindowsReplay(
            snapshot=snapshot, lineage_sha256=verified.sha256,
            source_policy_sha256=expected_source_policy_sha256,
            _historical_root_identity_bytes=canonical_bytes(historical_root),
            actually_read_source_paths=tuple(sorted(reader.read_paths)),
            unvalidated_archive_paths=tuple(sorted(set(archive) - reader.read_paths)))
    except LegacyWindowsReplayError:
        raise
    except (migration.LegacyMigrationRecordError, provenance.WindowsProvenanceError,
            TypeError, KeyError, ValueError, OverflowError) as exc:
        raise LegacyWindowsReplayError(f'Legacy Windows archive replay refused: {exc}') from exc
