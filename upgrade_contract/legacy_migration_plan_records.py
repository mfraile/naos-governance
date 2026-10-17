"""Pure immutable legacy-migration plan record; no custody or write authority."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from . import legacy_archive_capture as capture
from . import legacy_authority as authority
from . import legacy_migration_records as migration
from . import local_binding as binding
from . import portable_provenance as pp
from . import working_tree_capture as working
from .canonical import canonical_bytes, loads_strict_json

SCHEMA = 'naos.upgrade.legacy_migration_plan.v1'
REPLAY_SCHEMA = 'naos.upgrade.legacy_migration_plan.v2'
SCHEMAS = frozenset((SCHEMA, REPLAY_SCHEMA))
RAW_NAMES = ('raw-lineage.json', 'raw-policy.json', 'raw-modes.json')
RAW_ROOT = '.naos/local/managed-content-v3/journals/J00000001'

def raw_evidence_files(lineage):
    if not lineage._raw_archive:
        return {}
    if (type(lineage._raw_archive) is not tuple or type(lineage._raw_policy) is not bytes
            or type(lineage._raw_modes) is not bytes or any(type(row) is not tuple or len(row) != 2
            or type(row[0]) is not str or type(row[1]) is not bytes for row in lineage._raw_archive)
            or list(lineage._raw_archive) != sorted(lineage._raw_archive)
            or len(dict(lineage._raw_archive)) != len(lineage._raw_archive)):
        raise LegacyMigrationPlanError('Invalid immutable raw migration evidence')
    return {RAW_ROOT + '/' + name: raw for name, raw in zip(RAW_NAMES,
        (lineage.raw, lineage._raw_policy, lineage._raw_modes))}

def raw_inventory(lineage):
    return [{'path': path, 'sha256': hashlib.sha256(raw).hexdigest(),
             'size_decimal': str(len(raw))} for path, raw in sorted(raw_evidence_files(lineage).items())]

def verify_raw_evidence(native, candidate):
    files = raw_evidence_files(candidate.lineage)
    if candidate.plan.body.get('raw_evidence_inventory', []) != raw_inventory(candidate.lineage):
        raise LegacyMigrationPlanError('Raw evidence inventory differs from plan')
    for path, raw in files.items():
        if native.read(path) != raw:
            raise LegacyMigrationPlanError('Stored raw evidence differs from approved migration')
_DESTINATIONS = ('.naos/managed-content', '.naos/managed-content/v3')
_COMPETING = {
    migration.POSIX_MANAGED_V1: '.naos/upgrade-v1/windows-content',
    migration.WINDOWS_CONTENT_V1: '.naos/upgrade-v1/managed-content',
}
_MAX_CANDIDATE_FILES = 20_000
_MAX_CANDIDATE_BYTES = 512 * 1024 * 1024
_MAX_RECORD = 16 * 1024 * 1024


class LegacyMigrationPlanError(ValueError):
    """Candidate or native evidence is malformed, incomplete, or conflicting."""


@dataclass(frozen=True)
class ValidatedMigrationPlan:
    raw: bytes
    sha256: str

    @property
    def body(self) -> dict:
        return loads_strict_json(self.raw)


def _candidate(projection_files):
    if (type(projection_files) is not dict or not projection_files
            or len(projection_files) > _MAX_CANDIDATE_FILES):
        raise LegacyMigrationPlanError('Bounded exact candidate dictionary required')
    total = 0
    for path, raw in projection_files.items():
        if (type(path) is not str or type(raw) is not bytes
                or len(raw) > migration.MAX_ARCHIVE_FILE_BYTES):
            raise LegacyMigrationPlanError('Invalid candidate member')
        total += len(raw)
        if total > _MAX_CANDIDATE_BYTES:
            raise LegacyMigrationPlanError('Candidate byte budget exceeded')
        pp.control_path_limit(path)
    files = dict(projection_files)
    class Reader:
        read_paths = set()
        def read(self, path):
            Reader.read_paths.add(path)
            return files.get(path)
    snapshot = pp.load_portable_snapshot(Reader())
    if set(files) != Reader.read_paths:
        raise LegacyMigrationPlanError('Candidate contains unvalidated or unrelated leaves')
    inventory = [{'path': path, 'sha256': hashlib.sha256(files[path]).hexdigest(),
                  'size_decimal': str(len(files[path]))} for path in sorted(files)]
    return files, snapshot, inventory


def _lineage(lineage, files, source_format, snapshot):
    if (type(lineage) is not migration.LegacyLineage or type(lineage.raw) is not bytes
            or len(lineage.raw) > migration.MAX_RECORD_BYTES
            or hashlib.sha256(lineage.raw).hexdigest() != lineage.sha256):
        raise LegacyMigrationPlanError('Exact typed lineage required')
    body = migration._lineage_structure(migration._record(lineage.raw, migration.LINEAGE_SCHEMA))
    replay = _authority_directory_paths(files)[1]['schema'] in authority.REPLAY_SCHEMAS
    if (source_format != body['source_format'] or snapshot.project_id != body['new_project_id']
            or (not replay and files.get(authority.lineage_path(lineage.sha256)) != lineage.raw)):
        raise LegacyMigrationPlanError('Candidate/lineage source format or project differs')
    archive = {}
    for member in body['archive']:
        path, digest = member['path'], member['sha256']
        raw = (dict(lineage._raw_archive).get(path) if replay
               else files.get(authority.blob_path(digest)))
        if (type(raw) is not bytes or len(raw) != int(member['size_decimal'])
                or hashlib.sha256(raw).hexdigest() != digest):
            raise LegacyMigrationPlanError('Candidate lacks exact archived source member')
        archive[path] = raw
    expectations = {f"expected_{item['role']}_sha256": item['sha256']
                    for item in body['anchors']}
    migration.load_lineage(lineage.raw, archive,
                           approved_lineage_sha256=lineage.sha256, **expectations)
    if replay:
        raw_evidence_files(lineage)
        if set(archive) != set(dict(lineage._raw_archive)):
            raise LegacyMigrationPlanError('Raw archive has missing or extra members')
        auth = _authority_directory_paths(files)[1]
        rebuilt = authority.build_replay_projection(archive, lineage,
            directory_paths=auth['directory_paths'], source_policy_raw=lineage._raw_policy,
            mode_inventory_raw=lineage._raw_modes, expected_modes_sha256=auth['mode_inventory_sha256'],
            approved_lineage_sha256=lineage.sha256,
            expected_source_policy_sha256=auth['source_policy_sha256'], **expectations)
        if rebuilt != files:
            raise LegacyMigrationPlanError('Candidate differs from deterministic raw projection')
    elif lineage._raw_archive or lineage._raw_policy is not None or lineage._raw_modes is not None:
        raise LegacyMigrationPlanError('Historical v1 lineage cannot carry v2 raw evidence')
    return body, archive


def _authority_directory_paths(files):
    owner, _ = pp._decode_record(files[pp.OWNER_PATH], pp.OWNER_SCHEMA,
        {'schema', 'project_id', 'minimum_reader', 'authority_kind', 'authority_sha256'})
    if owner['authority_kind'] not in ('legacy_projection', 'legacy_replay_projection'):
        raise LegacyMigrationPlanError('Candidate owner is not a legacy projection')
    raw = files[authority.authority_path(owner['authority_sha256'])]
    record, digest = (authority.decode_replay_authority(raw)
        if owner['authority_kind'] == 'legacy_replay_projection'
        else pp._decode_record(raw, authority.SCHEMA, authority._KEYS))
    if digest != owner['authority_sha256']:
        raise LegacyMigrationPlanError('Legacy authority digest differs')
    return tuple(record['directory_paths']), record


def _native(files, source_format, lineage_body, lineage_sha256, archive, capture_body,
            legacy_files, legacy_directories, legacy_lock,
            portable_destinations, competing_legacy, snapshot):
    platform = capture_body['native']['platform']
    # Source record format and current capture platform are independent: a
    # cloned legacy checkout may be migrated on a different supported host.
    control = capture_body['native']['control_directories']
    if control[0]['witness']['presence'] != 'present':
        raise LegacyMigrationPlanError('Legacy source requires an existing .naos parent')
    parent = control[1]['witness']
    if parent['presence'] == 'present':
        private = (parent['security']['dacl_protected'] if platform == 'Windows'
                   else parent['mode_octal'] == '0700' and not parent['acl_entries'])
        if not private:
            raise LegacyMigrationPlanError('Existing local parent is not private')
    if any(row['witness']['presence'] != 'absent' for row in control[2:]):
        raise LegacyMigrationPlanError('Existing local v3 control directory conflicts')
    if (type(portable_destinations) is not list or len(portable_destinations) != 2
            or [item.get('path') for item in portable_destinations] != list(_DESTINATIONS)):
        raise LegacyMigrationPlanError('Portable destination inventory differs')
    for row in portable_destinations:
        binding._fields(row, {'path', 'witness'}, 'portable destination')
        binding._validate_witness(row['witness'], platform, 'directory')
    if portable_destinations[1]['witness']['presence'] != 'absent':
        raise LegacyMigrationPlanError('Portable v3 destination already exists')
    binding._fields(competing_legacy, {'path', 'witness'}, 'competing legacy scope')
    if competing_legacy['path'] != _COMPETING[source_format]:
        raise LegacyMigrationPlanError('Competing legacy scope path differs')
    binding._validate_witness(competing_legacy['witness'], platform, 'directory')
    if competing_legacy['witness']['presence'] != 'absent':
        raise LegacyMigrationPlanError('Competing managed source is present')
    lock_path = '/'.join(capture._LAYOUT[source_format])
    binding._fields(legacy_lock, {'path', 'witness'}, 'legacy lock')
    if legacy_lock['path'] != lock_path or archive.get(lock_path) != b'':
        raise LegacyMigrationPlanError('Held legacy lock path or archived bytes differ')
    binding._validate_witness(legacy_lock['witness'], platform, 'file')
    if legacy_lock['witness']['presence'] != 'present':
        raise LegacyMigrationPlanError('Legacy lock witness is absent')
    inventory = {item['path']: item for item in lineage_body['archive']}
    expected_files = sorted(set(inventory) - {lock_path})
    if (type(legacy_files) is not list or len(legacy_files) != len(expected_files)
            or [row.get('path') for row in legacy_files] != expected_files):
        raise LegacyMigrationPlanError('Legacy source file observations differ from lineage')
    for row in legacy_files:
        binding._fields(row, {'path', 'metadata', 'content'}, 'legacy source file')
        binding._validate_witness(row['metadata'], platform, 'file')
        if row['metadata']['presence'] != 'present':
            raise LegacyMigrationPlanError('Legacy source file witness is absent')
        binding._fields(row['content'], {'sha256', 'size_decimal'}, 'legacy source content')
        member = inventory[row['path']]
        if row['content'] != {key: member[key] for key in ('sha256', 'size_decimal')}:
            raise LegacyMigrationPlanError('Legacy source file bytes differ from lineage')
    authority_dirs, authority_record = _authority_directory_paths(files)
    if authority_record['lineage_sha256'] != lineage_sha256:
        raise LegacyMigrationPlanError('Portable authority and approved lineage differ')
    expected_dirs = sorted({'.naos/upgrade-v1', *authority_dirs})
    if (type(legacy_directories) is not list or len(legacy_directories) != len(expected_dirs)
            or [row.get('path') for row in legacy_directories] != expected_dirs):
        raise LegacyMigrationPlanError('Legacy directory witnesses differ from complete capture')
    for row in legacy_directories:
        binding._fields(row, {'path', 'witness'}, 'legacy directory')
        binding._validate_witness(row['witness'], platform, 'directory')
        if row['witness']['presence'] != 'present':
            raise LegacyMigrationPlanError('Legacy captured directory is absent')
    # The planned original-pointer and portable-tree renames must stay on one
    # native volume. Native execution must still recheck these observations.
    volume = 'volume_serial_hex' if platform == 'Windows' else 'device_decimal'
    target_volume = control[0]['witness'][volume]
    pointer = migration._FENCE_POINTER[source_format]
    pointer_witness = next(row['metadata'] for row in legacy_files if row['path'] == pointer)
    move_witnesses = [pointer_witness, parent, portable_destinations[0]['witness']]
    if any(w['presence'] == 'present' and w[volume] != target_volume for w in move_witnesses):
        raise LegacyMigrationPlanError('Migration control renames would cross native volumes')
    expected_leaves = snapshot.entries
    leaves = capture_body['leaves']
    if set(expected_leaves) != {row['path'] for row in leaves}:
        raise LegacyMigrationPlanError('Managed capture leaves differ from portable entries')
    # Working leaves may have been edited or deleted by the adopter. Their
    # fresh native observations are bound as captured, without reclassifying
    # ownership from matching bytes or demanding historical base equality.


def build_migration_plan(*, projection_files, lineage, source_format, binding_id,
                         initial_capture, legacy_files, legacy_directories,
                         legacy_lock, portable_destinations, competing_legacy):
    """Bind an approved candidate and captured preconditions; authorize no writes."""
    try:
        if (type(source_format) is not str or source_format not in migration._ANCHORS
                or type(binding_id) is not str or binding.BINDING_ID.fullmatch(binding_id) is None
                or type(initial_capture) is not working.WorkingTreeCapture
                or type(initial_capture.raw) is not bytes or len(initial_capture.raw) > _MAX_RECORD):
            raise LegacyMigrationPlanError('Plan source, binding ID or capture type differs')
        files, snapshot, candidate_inventory = _candidate(projection_files)
        lineage_body, archive = _lineage(lineage, files, source_format, snapshot)
        capture_body = initial_capture.body
        rebuilt = working.build_capture(capture_body['native'], capture_body['leaves'])
        if rebuilt.raw != initial_capture.raw or rebuilt.sha256 != initial_capture.sha256:
            raise LegacyMigrationPlanError('Initial capture is not an exact validated record')
        _native(files, source_format, lineage_body, lineage.sha256, archive, capture_body,
                legacy_files, legacy_directories, legacy_lock,
                portable_destinations, competing_legacy, snapshot)
        pointer = migration._FENCE_POINTER[source_format]
        fence = migration.build_fence(lineage, approved_lineage_sha256=lineage.sha256,
                                     original_pointer_bytes=archive[pointer])
        body = {'schema': REPLAY_SCHEMA if lineage._raw_archive else SCHEMA, 'source_format': source_format,
                'lineage_sha256': lineage.sha256, 'new_project_id': lineage_body['new_project_id'],
                'binding_id': binding_id, 'initial_capture': capture_body,
                'legacy_files': legacy_files, 'legacy_directories': legacy_directories,
                'legacy_lock': legacy_lock, 'competing_legacy': competing_legacy,
                'portable_destinations': portable_destinations,
                'candidate_inventory': candidate_inventory,
                'candidate_owner_record_sha256': snapshot.owner_sha256,
                'candidate_head_record_sha256': snapshot.manifest_sha256,
                'source_anchor_sha256': {item['role']: item['sha256'] for item in lineage_body['anchors']},
                'source_policy_sha256': _authority_directory_paths(files)[1]['source_policy_sha256'],
                'mode_inventory_sha256': _authority_directory_paths(files)[1]['mode_inventory_sha256'],
                'fence': {'path': fence.pointer_path, 'sha256': fence.sha256,
                          'size_decimal': str(len(fence.raw))}}
        if lineage._raw_archive:
            body['raw_evidence_inventory'] = raw_inventory(lineage)
        binding._bounded_input(body)
        raw = canonical_bytes(body)
        if len(raw) > _MAX_RECORD:
            raise LegacyMigrationPlanError('Migration plan byte budget exceeded')
        return ValidatedMigrationPlan(raw, hashlib.sha256(raw).hexdigest())
    except LegacyMigrationPlanError:
        raise
    except (migration.LegacyMigrationRecordError, pp.PortableProvenanceError,
            binding.LocalBindingError, working.WorkingTreeCaptureError,
            KeyError, TypeError, ValueError, AttributeError, OverflowError,
            RecursionError) as exc:
        raise LegacyMigrationPlanError(f'Legacy migration plan refused: {exc}') from exc


def load_migration_plan(raw, projection_files, lineage):
    """Rebuild all pure invariants from a canonical immutable plan record."""
    try:
        if type(raw) is not bytes or len(raw) > _MAX_RECORD:
            raise LegacyMigrationPlanError('Missing or oversized migration plan')
        body = pp._load_json(raw, 'legacy migration plan')
        binding._bounded_input(body)
        if type(body) is not dict or set(body) != {
                'schema', 'source_format', 'lineage_sha256', 'new_project_id',
                'binding_id', 'initial_capture', 'legacy_files', 'legacy_directories',
                'legacy_lock', 'competing_legacy', 'portable_destinations',
                'candidate_inventory', 'candidate_owner_record_sha256',
                'candidate_head_record_sha256',
                'source_anchor_sha256', 'source_policy_sha256', 'mode_inventory_sha256', 'fence'} | (
                {'raw_evidence_inventory'} if body.get('schema') == REPLAY_SCHEMA else set()):
            raise LegacyMigrationPlanError('Migration plan shape differs')
        if body['schema'] not in SCHEMAS or canonical_bytes(body) != raw:
            raise LegacyMigrationPlanError('Migration plan bytes are noncanonical')
        capture_body = body['initial_capture']
        initial_capture = working.build_capture(capture_body['native'], capture_body['leaves'])
        expected = build_migration_plan(
            projection_files=projection_files, lineage=lineage,
            source_format=body['source_format'], binding_id=body['binding_id'],
            initial_capture=initial_capture, legacy_files=body['legacy_files'],
            legacy_directories=body['legacy_directories'], legacy_lock=body['legacy_lock'],
            portable_destinations=body['portable_destinations'],
            competing_legacy=body['competing_legacy'])
        if raw != expected.raw:
            raise LegacyMigrationPlanError('Migration plan differs from candidate or source evidence')
        return expected
    except LegacyMigrationPlanError:
        raise
    except (pp.PortableProvenanceError, binding.LocalBindingError,
            working.WorkingTreeCaptureError, KeyError, TypeError, ValueError,
            AttributeError, OverflowError, RecursionError) as exc:
        raise LegacyMigrationPlanError(f'Migration plan load refused: {exc}') from exc


def reconstruct_replay_candidate(read, raw):
    """Pure candidate copy from separate exact local originals; no authority."""
    from . import legacy_migration_planning as planning
    body = pp._load_json(raw, 'private replay migration plan')
    if body.get('schema') != REPLAY_SCHEMA:
        raise LegacyMigrationPlanError('Expected explicit v2 migration plan')
    evidence = {name: read(RAW_ROOT + '/' + name) for name in RAW_NAMES}
    lraw = evidence['raw-lineage.json']
    lb = migration._lineage_structure(migration._record(lraw, migration.LINEAGE_SCHEMA))
    pointer = migration._FENCE_POINTER[lb['source_format']]
    archive = {row['path']: read(RAW_ROOT + '/legacy-original.json' if row['path'] == pointer
                                  else row['path']) for row in lb['archive']}
    lineage = migration.LegacyLineage(lraw, hashlib.sha256(lraw).hexdigest(),
        tuple(sorted(archive.items())), evidence['raw-policy.json'], evidence['raw-modes.json'])
    owner, _ = pp._decode_record(read(pp.OWNER_PATH), pp.OWNER_SCHEMA,
        {'schema','project_id','minimum_reader','authority_kind','authority_sha256'})
    if owner['authority_kind'] != 'legacy_replay_projection':
        raise LegacyMigrationPlanError('V2 plan requires replay authority')
    auth, _ = authority.decode_replay_authority(read(authority.authority_path(owner['authority_sha256'])))
    expected = {f"expected_{row['role']}_sha256": row['sha256'] for row in lb['anchors']}
    files = authority.build_replay_projection(archive, lineage,
        directory_paths=auth['directory_paths'], source_policy_raw=lineage._raw_policy,
        mode_inventory_raw=lineage._raw_modes, expected_modes_sha256=auth['mode_inventory_sha256'],
        approved_lineage_sha256=lineage.sha256,
        expected_source_policy_sha256=auth['source_policy_sha256'], **expected)
    plan = load_migration_plan(raw, files, lineage)
    for row in plan.body['candidate_inventory']:
        # The mutable active head may already be a later receipt. Its original
        # native object is checked by J1 _published_file under both held locks.
        if row['path'] != pp.MANIFEST_PATH and read(row['path']) != files[row['path']]:
            raise LegacyMigrationPlanError('Published replay candidate differs from raw projection')
    return planning.MigrationCandidate(plan, lineage, tuple(sorted(files.items())))
