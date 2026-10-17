"""Pure chained migration progress records; native observations remain mandatory.

The first record is the existing prepared wire format. A later record commits
the exact evidence passed to it, but neither bytes nor a witness record prove
that the current namespace is owned or safe to change. The native inspector
must verify each before/after state under the held legacy lock.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re

from . import legacy_migration_journal as journal
from . import legacy_migration_plan_records as plans
from . import legacy_migration_records as lineage_records
from . import local_binding as lb
from . import portable_provenance as pp
from .canonical import canonical_bytes

PORTABLE_STAGE = '.naos/local/managed-content-v3/journals/J00000001/portable.pending'
RETAINED = '.naos/local/managed-content-v3/journals/J00000001/legacy-original.json'
FENCE_STAGE = '.naos/local/managed-content-v3/journals/J00000001/fence.pending.json'
BINDING_STAGE = '.naos/local/managed-content-v3/journals/J00000001/binding.pending.json'
BINDING_TARGET = '.naos/local/managed-content-v3/binding.json'
PHASES = ('prepared', 'candidate_ready', 'retain_pending', 'original_retained',
          'fence_pending', 'fenced', 'head_pending', 'head_published',
          'binding_pending', 'finalized')
_ROLLBACK_SOURCES = frozenset(PHASES[:7])
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_MAX_FILES = 20_000
_MAX_DIRS = 10_000


class MigrationProgressError(ValueError):
    """A progress record or its planned commitment is malformed or foreign."""


@dataclass(frozen=True)
class MigrationProgress:
    raw: bytes
    sha256: str

    @property
    def body(self):
        return pp._load_json(self.raw, 'legacy migration progress')


def _sha(value, name):
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise MigrationProgressError(f'Invalid {name} digest')


def _fields(value, names, label):
    if type(value) is not dict or set(value) != set(names):
        raise MigrationProgressError(f'{label} fields differ')


def _witness(value, platform, kind, presence):
    lb._validate_witness(value, platform, kind)
    if value['presence'] != presence:
        raise MigrationProgressError(f'Expected {presence} {kind} witness')


def _exact_path(path, expected):
    if type(path) is not str or path != expected:
        raise MigrationProgressError('Migration transition path differs')


def _candidate(value, plan, platform):
    _fields(value, ('stage_root', 'directories', 'files'), 'candidate commitment')
    _witness(value['stage_root'], platform, 'directory', 'present')
    inventory = plan['candidate_inventory']
    if (type(inventory) is not list or len(inventory) > _MAX_FILES
            or type(value['files']) is not list or len(value['files']) != len(inventory)):
        raise MigrationProgressError('Candidate file inventory differs')
    expected_dirs = set()
    expected_files = []
    for item in inventory:
        path = item['path']
        if type(path) is not str or not path.startswith(pp.ROOT + '/'):
            raise MigrationProgressError('Candidate file path is outside portable root')
        rel = path[len(pp.ROOT) + 1:]
        expected_files.append((path, item))
        components = rel.split('/')[:-1]
        for n in range(1, len(components) + 1):
            expected_dirs.add('/'.join(components[:n]))
    if (type(value['directories']) is not list or len(value['directories']) > _MAX_DIRS
            or [r.get('path') for r in value['directories']] != sorted(expected_dirs)):
        raise MigrationProgressError('Staged directory inventory differs')
    for row in value['directories']:
        _fields(row, ('path', 'witness'), 'candidate directory')
        _witness(row['witness'], platform, 'directory', 'present')
    if [r.get('path') for r in value['files']] != [p for p, _ in expected_files]:
        raise MigrationProgressError('Staged file paths differ from planned projection')
    for row, _ in zip(value['files'], expected_files):
        _fields(row, ('path', 'witness'), 'candidate file')
        _witness(row['witness'], platform, 'file', 'present')
    # File bytes remain bound by the validated plan candidate_inventory. This
    # record binds actual created native objects; inspector checks their bytes.


def _retention(value, plan, platform, lineage):
    _fields(value, ('source_path', 'source_witness', 'retained_path',
                    'retained_absent', 'sha256', 'size_decimal', 'rename_identity'), 'retention commitment')
    pointer = lineage_records._FENCE_POINTER[plan['source_format']]
    _exact_path(value['source_path'], pointer)
    _exact_path(value['retained_path'], RETAINED)
    original = next((r for r in plan['legacy_files'] if r['path'] == pointer), None)
    if original is None or value['source_witness'] != original['metadata']:
        raise MigrationProgressError('Original pointer native witness differs from plan')
    _witness(value['source_witness'], platform, 'file', 'present')
    _witness(value['retained_absent'], platform, 'file', 'absent')
    if (value['sha256'] != original['content']['sha256']
            or value['size_decimal'] != original['content']['size_decimal']):
        raise MigrationProgressError('Original pointer bytes differ from plan')
    _rename_witness(value['rename_identity'], value['source_witness'],
                    value['sha256'], value['size_decimal'], platform)


def _rename_witness(value, native, digest, size, platform):
    if platform == 'Windows':
        from .windows_rename_identity import identity_from_record
        identity = identity_from_record(value)
        encoded = value
        metadata = encoded['rename_metadata_v2']
        if (encoded['volume_serial_hex'] != native['volume_serial_hex']
                or encoded['file_id_hex'] != native['file_id_hex']
                or metadata['attributes_hex'] != native['attributes_hex']
                or identity.content_sha256 != digest
                or str(identity.size) != size
                or any(metadata[k] != native['security'][k] for k in
                       ('owner_sid_sha256', 'group_sid_sha256', 'dacl_sha256',
                        'descriptor_sha256', 'dacl_protected'))):
            raise MigrationProgressError('Windows rename witness differs from committed file')
    elif value is not None:
        raise MigrationProgressError('POSIX transition cannot carry Windows repair authority')


def _fence(value, plan, platform):
    _fields(value, ('staged_path', 'staged_witness', 'pointer_path',
                    'pointer_absent', 'sha256', 'size_decimal', 'rename_identity'), 'fence commitment')
    _exact_path(value['staged_path'], FENCE_STAGE)
    _exact_path(value['pointer_path'], plan['fence']['path'])
    _witness(value['staged_witness'], platform, 'file', 'present')
    _witness(value['pointer_absent'], platform, 'file', 'absent')
    if (value['sha256'] != plan['fence']['sha256']
            or value['size_decimal'] != plan['fence']['size_decimal']):
        raise MigrationProgressError('Staged fence bytes differ from plan')
    _rename_witness(value['rename_identity'], value['staged_witness'],
                    value['sha256'], value['size_decimal'], platform)


def _head(value, plan, platform):
    _fields(value, ('stage_path', 'target_path', 'target_absent',
                    'parent_path', 'parent_witness'), 'head commitment')
    _exact_path(value['stage_path'], PORTABLE_STAGE)
    _exact_path(value['target_path'], pp.ROOT)
    _exact_path(value['parent_path'], pp.ROOT.rsplit('/', 1)[0])
    _witness(value['target_absent'], platform, 'directory', 'absent')
    _witness(value['parent_witness'], platform, 'directory', 'present')


def _binding(value, plan, platform):
    _fields(value, ('staged_path', 'staged_witness', 'target_path',
                    'target_absent', 'sha256', 'size_decimal',
                    'project_id', 'owner_record_sha256', 'head_record_sha256', 'rename_identity'),
            'binding commitment')
    _exact_path(value['staged_path'], BINDING_STAGE)
    _exact_path(value['target_path'], BINDING_TARGET)
    _witness(value['staged_witness'], platform, 'file', 'present')
    _witness(value['target_absent'], platform, 'file', 'absent')
    _sha(value['sha256'], 'binding bytes')
    if (type(value['size_decimal']) is not str or not value['size_decimal'].isdigit()
            or value['size_decimal'] == '0' or value['size_decimal'].startswith('0')):
        raise MigrationProgressError('Invalid binding byte length')
    if (value['project_id'] != plan['new_project_id']
            or value['owner_record_sha256'] != plan['candidate_owner_record_sha256']
            or value['head_record_sha256'] != plan['candidate_head_record_sha256']):
        raise MigrationProgressError('Binding identity or head differs from plan')
    # The binding raw record itself must be independently validated by the
    # native caller. A digest supplied here is only a chained commitment.
    _rename_witness(value['rename_identity'], value['staged_witness'],
                    value['sha256'], value['size_decimal'], platform)


def _context(intent, plan, projection_files, lineage):
    if type(intent) is not journal.MigrationIntent or type(plan) is not plans.ValidatedMigrationPlan:
        raise MigrationProgressError('Typed migration intent and plan required')
    checked = journal.load_migration_intent(intent.raw, plan, projection_files, lineage,
                                            approved_plan_sha256=plan.sha256)
    if checked != intent:
        raise MigrationProgressError('Migration intent is not exact')
    return plan.body, intent.body['prepared_capture']['native']['platform']


def _checked_context(intent, plan, projection_files, lineage):
    try:
        return _context(intent, plan, projection_files, lineage)
    except MigrationProgressError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError) as exc:
        raise MigrationProgressError(f'Migration progress refused: {exc}') from exc


def load_progress(raw, intent, plan, projection_files, lineage, *, previous=None):
    """Validate one canonical record and its immediate predecessor."""
    planned, platform = _checked_context(intent, plan, projection_files, lineage)
    return _progress_record(raw, intent, lineage, planned, platform, previous=previous)


def _progress_record(raw, intent, lineage, planned, platform, *, previous=None):
    """Record checks shared by standalone validation and the owned batch."""
    try:
        if type(raw) is not bytes or len(raw) > lb.MAX_RECORD_BYTES:
            raise MigrationProgressError('Missing or oversized migration progress')
        body = pp._load_json(raw, 'legacy migration progress')
        if type(body) is not dict or type(body.get('sequence')) is not int:
            raise MigrationProgressError('Progress sequence must be an integer')
        number = body['sequence']
        if not 0 <= number <= 10:
            raise MigrationProgressError('Progress sequence out of bounds')
        # Local bounded parser deliberately rejects all integers. Temporarily
        # normalize only the already-checked sequence; all other integers fail.
        bounded = dict(body)
        bounded['sequence'] = str(number)
        lb._bounded_input(bounded)
        if canonical_bytes(body) != raw:
            raise MigrationProgressError('Noncanonical migration progress')
        common = {'schema', 'journal_id', 'intent_sha256', 'sequence',
                  'previous_sha256', 'phase'}
        if body.get('schema') != journal.PROGRESS_SCHEMA or body.get('journal_id') != journal.JOURNAL_ID:
            raise MigrationProgressError('Foreign migration progress schema or journal')
        if body.get('intent_sha256') != intent.sha256:
            raise MigrationProgressError('Migration progress intent differs')
        phase = body.get('phase')
        if previous is None:
            _fields(body, common, 'prepared progress')
            if number != 0 or phase != 'prepared' or body['previous_sha256'] is not None:
                raise MigrationProgressError('Initial progress must be prepared')
            if raw != journal.initial_progress(intent):
                raise MigrationProgressError('Prepared progress bytes differ')
        else:
            if type(previous) is not MigrationProgress or not 1 <= number <= 10:
                raise MigrationProgressError('Exact preceding progress required')
            before = previous.body
            if (type(before) is not dict or type(before.get('sequence')) is not int
                    or not 0 <= before['sequence'] < 10
                    or before.get('schema') != journal.PROGRESS_SCHEMA
                    or before.get('journal_id') != journal.JOURNAL_ID
                    or before.get('intent_sha256') != intent.sha256
                    or canonical_bytes(before) != previous.raw):
                raise MigrationProgressError('Preceding progress record differs')
            if (number != before['sequence'] + 1
                    or body['previous_sha256'] != previous.sha256
                    or hashlib.sha256(previous.raw).hexdigest() != previous.sha256):
                raise MigrationProgressError('Migration progress chain differs')
            prior_phase = before['phase']
            normal = prior_phase in PHASES and PHASES.index(prior_phase) < len(PHASES)-1
            if normal and phase == PHASES[PHASES.index(prior_phase) + 1]:
                pass
            elif prior_phase in _ROLLBACK_SOURCES and phase == 'rollback_pending':
                pass
            elif prior_phase == 'rollback_pending' and phase == 'rolled_back':
                pass
            else:
                raise MigrationProgressError('Unsupported migration phase transition')
            commit_phase = phase in {'candidate_ready', 'retain_pending', 'fence_pending',
                                     'head_pending', 'binding_pending', 'rollback_pending'}
            _fields(body, common | ({'commitment'} if commit_phase else set()),
                    'migration progress')
            if commit_phase:
                value = body['commitment']
                if phase == 'candidate_ready':
                    _candidate(value, planned, platform)
                elif phase == 'retain_pending':
                    _retention(value, planned, platform, lineage)
                elif phase == 'fence_pending':
                    _fence(value, planned, platform)
                elif phase == 'head_pending':
                    _head(value, planned, platform)
                elif phase == 'binding_pending':
                    _binding(value, planned, platform)
                else:
                    _fields(value, ('source_phase',), 'rollback commitment')
                    if value['source_phase'] != prior_phase:
                        raise MigrationProgressError('Rollback source phase differs')
        return MigrationProgress(raw, hashlib.sha256(raw).hexdigest())
    except MigrationProgressError:
        raise
    except (journal.MigrationJournalError, plans.LegacyMigrationPlanError,
            lineage_records.LegacyMigrationRecordError, lb.LocalBindingError,
            pp.PortableProvenanceError, ValueError, TypeError, KeyError,
            AttributeError, OverflowError, RecursionError) as exc:
        raise MigrationProgressError(f'Migration progress refused: {exc}') from exc


def advance_progress(previous, phase, commitment, intent, plan, projection_files, lineage):
    """Encode the next pure record. Native callers must validate the transition."""
    if type(previous) is not MigrationProgress:
        raise MigrationProgressError('Exact preceding progress required')
    body = {'schema': journal.PROGRESS_SCHEMA, 'journal_id': journal.JOURNAL_ID,
            'intent_sha256': intent.sha256, 'sequence': previous.body['sequence'] + 1,
            'previous_sha256': previous.sha256, 'phase': phase}
    if commitment is not None:
        body['commitment'] = commitment
    bounded = dict(body)
    bounded['sequence'] = str(body['sequence'])
    lb._bounded_input(bounded)
    raw = canonical_bytes(body)
    return load_progress(raw, intent, plan, projection_files, lineage, previous=previous)


def load_progress_history(raw_records, intent, plan, projection_files, lineage):
    """Require contiguous chained progress; inspect the terminal native state separately."""
    if type(raw_records) not in (list, tuple) or not 1 <= len(raw_records) <= 11:
        raise MigrationProgressError('Bounded nonempty progress history required')
    # The batch owns this context, never a caller-provided validated body.
    # Capture raw records before validation so list mutation cannot bind a
    # checked context or earlier result to later, different inputs.
    before = _history_inputs(raw_records, intent, plan, projection_files, lineage)
    planned, platform = _checked_context(intent, plan, projection_files, lineage)
    result = []
    for raw in raw_records:
        result.append(_progress_record(raw, intent, lineage, planned, platform,
                                       previous=result[-1] if result else None))
    if _history_inputs(raw_records, intent, plan, projection_files, lineage) != before:
        raise MigrationProgressError('Migration history inputs changed during validation')
    return tuple(result)


def _history_inputs(raw_records, intent, plan, projection_files, lineage):
    if (type(raw_records) not in (list, tuple)
            or any(type(raw) is not bytes for raw in raw_records)
            or type(intent) is not journal.MigrationIntent
            or type(plan) is not plans.ValidatedMigrationPlan
            or type(lineage) is not lineage_records.LegacyLineage
            or any(type(record.raw) is not bytes or type(record.sha256) is not str
                   for record in (intent, plan, lineage))
            or type(projection_files) is not dict
            or any(type(path) is not str or type(raw) is not bytes
                   for path, raw in projection_files.items())):
        raise MigrationProgressError('Exact migration history input types required')
    return (type(raw_records), tuple(raw_records),
            tuple((type(record), record.raw, record.sha256)
                  for record in (intent, plan, lineage)),
            tuple(sorted(projection_files.items())))
