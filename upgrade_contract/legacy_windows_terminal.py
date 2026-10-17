"""Pure terminal proof for captured Windows legacy-operation records.

Archived identities are historical syntax/bindings, never live observations.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ntpath
from types import SimpleNamespace

from . import legacy_migration_records as migration
from . import legacy_windows_replay as replay
from . import windows_operation as operation
from . import windows_provenance as provenance
from . import windows_runtime as runtime
from . import windows_runtime_directories as directories
from .canonical import canonical_bytes, canonical_sha256
from .windows_coordinator import WindowsJournalConflict, _decode, _envelope
from .windows_observation import _parts, _relative_parts

_SCOPE = '.naos/upgrade-v1/windows-content'
_TX = _SCOPE + '/transactions/'
_STAGE = _SCOPE + '/staging/'
_MAX_DIRECTORIES = 1024
_MAX_OPS = 256
_MAX_JOURNAL_BYTES = 64 * 1024 * 1024
_MAX_RECORD = 16 * 1024 * 1024
_PLAN_KEYS = {'schema', 'project_root', 'project_root_identity',
              'source_policy_observation', 'source_policy_sha256',
              'source_policy_snapshot_sha256', 'expected_manifest_sha256',
              'expected_owner_sha256', 'enrollment', 'private_file_policy',
              'request', 'checks', 'rows', 'operation_id', 'transaction_id',
              'project_id', 'status', 'digest_sha256'}


class LegacyWindowsTerminalError(ValueError):
    """A terminal Windows archive has unsupported or conflicting evidence."""


@dataclass(frozen=True)
class TerminalOperation:
    operation_id: str
    transaction_id: str
    terminal: str
    record_version: int


@dataclass(frozen=True)
class LegacyWindowsTerminal:
    replay: replay.LegacyWindowsReplay
    operations: tuple[TerminalOperation, ...]
    checked_paths: tuple[str, ...]
    native_custody_proven: bool = False
    quiescence_proven: bool = False
    mutation_authorized: bool = False


def _inventory(paths, archive):
    if (type(paths) not in (tuple, list) or not 1 <= len(paths) <= _MAX_DIRECTORIES
            or any(type(path) is not str for path in paths)):
        raise LegacyWindowsTerminalError('Bounded directory-only inventory is required')
    paths = tuple(paths)
    if paths != tuple(sorted(set(paths))) or _SCOPE not in paths:
        raise LegacyWindowsTerminalError('Directory inventory is not canonical or lacks scope root')
    dirs = set(paths)
    if dirs & set(archive):
        raise LegacyWindowsTerminalError('Archive leaf overlaps captured directory')
    for path in paths:
        if path != _SCOPE:
            migration._path(path, migration.WINDOWS_CONTENT_V1)
    for leaf in archive:
        parent = leaf.rpartition('/')[0]
        while parent.startswith(_SCOPE):
            if parent not in dirs:
                raise LegacyWindowsTerminalError('Archive leaf lacks captured parent directory')
            if parent == _SCOPE:
                break
            parent = parent.rpartition('/')[0]
    return dirs


class _PureMarkers:
    _forward_name = operation.WindowsOperation._forward_name
    _rollback_name = operation.WindowsOperation._rollback_name
    _marker_body = operation.WindowsOperation._marker_body
    _rollback_body = operation.WindowsOperation._rollback_body
    _read_marker = operation.WindowsOperation._read_marker
    _audit_forward = operation.WindowsOperation._audit_forward
    _read_rollback_start = operation.WindowsOperation._read_rollback_start
    _audit_rollback = operation.WindowsOperation._audit_rollback

    def __init__(self, values, spec, intent):
        self.values = values
        self._schema = operation.SCHEMA_V2 if spec.record_version == 2 else operation.SCHEMA
        self._intent_sha256 = hashlib.sha256(_envelope(intent)).hexdigest()
        self.total_steps = sum(item.state_count() for item in spec.publications)

    def _read(self, name):
        return self.values.get(name)


class _PureDirectories(directories.DirectoryJournal):
    def __init__(self, values, operation_id, intent_sha256, plan, root_identity):
        self.values = values
        self.handles = SimpleNamespace(list_children=lambda unused: tuple(values))
        self.directory = object()
        self.operation_id = operation_id
        self.intent_sha256 = intent_sha256
        self.expected_paths = directories.absent_content_parents(plan)
        self.root_identity = root_identity
        self.parent_anchors = directories.existing_parent_anchors(plan)

    def _read(self, name):
        return self.values.get(name)


def _source_leaf(path, root):
    if (type(path) is not str or type(root) is not str
            or not path.casefold().startswith(root.rstrip('\\').casefold() + '\\')):
        raise LegacyWindowsTerminalError('Operation slot leaves historical project root')
    relative = path[len(root.rstrip('\\')) + 1:].replace('\\', '/')
    migration._path(relative, migration.WINDOWS_CONTENT_V1)
    return relative


def _relative_slot(path, root):
    _parts(path)
    prefix = root.rstrip('\\') + '\\'
    if not path.startswith(prefix):
        raise LegacyWindowsTerminalError('Publication slot leaves exact historical project root')
    relative = path[len(prefix):]
    _relative_parts(relative)
    return relative.replace('\\', '/')


def _validate_publication_slots(spec, plan, terminal, archive, proven, source_policy_raw, work):
    """Bind every slot, including consumed stages, to the writer's recorded roles."""
    changed = [row for row in plan['rows'] if row['action'] in runtime._MUTATIONS]
    by_path = {provenance._path(row['path']).replace('\\', '/'): row for row in changed}
    if len(by_path) != len(changed):
        raise LegacyWindowsTerminalError('Duplicate changed plan paths')
    stage = _STAGE + spec.operation_id + '/'
    content, evidence, prospective = set(), {}, dict(archive)
    for index, item in enumerate(spec.publications):
        target = _relative_slot(spec.slot_paths[item.target], plan['project_root'])
        staged = _relative_slot(spec.slot_paths[item.staged], plan['project_root'])
        expected_name = (f'manifest-{index:06d}.json' if item.role == 'manifest'
                         else f'{item.role}-{index:06d}.bin')
        if staged != stage + expected_name:
            raise LegacyWindowsTerminalError('Publication stage differs from operation role')
        if item.backup is not None and _relative_slot(spec.slot_paths[item.backup], plan['project_root']) != stage + f'backup-{index}':
            raise LegacyWindowsTerminalError('Publication backup differs from operation role')
        if item.role == 'content':
            row = by_path.get(target)
            if (row is None or target in content
                    or item.kind != ('replace' if row['action'] == 'UPDATE_FROM_UPSTREAM' else 'create')
                    or item.after.content_sha256 != row['source']['sha256']
                    or str(item.after.size) != row['source']['size_decimal']):
                raise LegacyWindowsTerminalError('Content target or identity differs from changed plan row')
            content.add(target)
        else:
            if item.role == 'manifest':
                if (target != provenance.MANIFEST_PATH.replace('\\', '/')
                        or item.kind != ('create' if plan['enrollment'] else 'replace')):
                    raise LegacyWindowsTerminalError('Manifest publication target or kind differs')
            else:
                migration._path(target, migration.WINDOWS_CONTENT_V1)
                evidence[target] = item
            if terminal == 'rolled_back':
                raw = archive.get(staged)
                _check_bytes(raw, item.after, staged)
                prospective[target] = raw
    if content != set(by_path):
        raise LegacyWindowsTerminalError('Content publications do not cover changed plan paths')
    if terminal == 'rolled_back':
        # Validate staged control records as a hypothetical committed projection,
        # never as actual committed history or ownership. Bound repeated replay.
        work[0] += sum(len(raw) for raw in prospective.values())
        if work[0] > migration.MAX_ARCHIVE_BYTES:
            raise LegacyWindowsTerminalError('Prospective historical replay exceeds work budget')
        reader = replay._ArchiveReader(prospective)
        validated = provenance.load_windows_provenance(reader,
            root_identity=proven.historical_root_identity, source_policy_raw=source_policy_raw)
        expected_evidence = reader.read_paths
    else:
        validated = proven.snapshot
        expected_evidence = set(proven.actually_read_source_paths)
    receipt_path = provenance.receipt_path(plan['transaction_id']).replace('\\', '/')
    if receipt_path not in evidence:
        raise LegacyWindowsTerminalError('Operation lacks its receipt publication')
    receipt, _ = provenance._decode(prospective[receipt_path], provenance.RECEIPT_SCHEMA, provenance._RECEIPT_KEYS)
    if (receipt['plan_sha256'] != plan['digest_sha256'] or receipt['request'] != plan['request']
            or receipt['source_policy_snapshot_sha256'] != plan['source_policy_snapshot_sha256']
            or {change['path'].replace('\\', '/') for change in receipt['changes']} != content
            or plan['transaction_id'] not in {ref['transaction_id'] for ref in validated.manifest['receipts']}):
        raise LegacyWindowsTerminalError('Publication receipt differs from historical plan')
    required_evidence = {receipt_path}
    allowed_evidence = {receipt_path}
    for change in receipt['changes']:
        base_path = provenance.base_path(change['base_sha256']).replace('\\', '/')
        base, _ = provenance._decode(prospective[base_path], provenance.BASE_SCHEMA, provenance._BASE_KEYS)
        required_evidence.add(base_path)
        allowed_evidence.update((base_path, provenance.blob_path(base['content']['sha256']).replace('\\', '/')))
    if plan['enrollment']:
        enrolled = {provenance.ROOT_PATH.replace('\\', '/'), provenance.OWNER_PATH.replace('\\', '/')}
        required_evidence |= enrolled
        allowed_evidence |= enrolled
    if not required_evidence <= set(evidence) <= allowed_evidence:
        raise LegacyWindowsTerminalError('Evidence publication roles differ from receipt changes')
    for target, item in evidence.items():
        if target not in expected_evidence:
            raise LegacyWindowsTerminalError('Evidence publication lacks validated historical record')
        _check_bytes(prospective.get(target), item.after, target)


def _check_bytes(raw, identity, label):
    if (type(raw) is not bytes or len(raw) != identity.size
            or hashlib.sha256(raw).hexdigest() != identity.content_sha256):
        raise LegacyWindowsTerminalError('Historical staged/backup bytes differ: ' + label)


def validate_windows_terminal_archive(archive_bytes, lineage, *, directory_paths,
                                      **replay_args) -> LegacyWindowsTerminal:
    """Prove historical terminal record grammar and coverage without native I/O."""
    try:
        if type(archive_bytes) is not dict:
            raise LegacyWindowsTerminalError('Exact archive dictionary required')
        archive = dict(archive_bytes)  # One copy shared by lineage replay and all auditors.
        proven = replay.replay_windows_archive(archive, lineage, **replay_args)
        dirs = _inventory(directory_paths, archive)
        _active_policy, historical_policies = provenance.policy_catalog(replay_args['source_policy_raw'])
        txdirs = {path[len(_TX):] for path in dirs if path.startswith(_TX)}
        stagedirs = {path[len(_STAGE):] for path in dirs if path.startswith(_STAGE)}
        if (not 1 <= len(txdirs) <= _MAX_OPS or any(operation._TX_ID.fullmatch(name) is None
                or '/' in name for name in txdirs) or stagedirs != txdirs):
            raise LegacyWindowsTerminalError('Unknown or missing operation/staging directory')
        expected_dirs = {_SCOPE, _SCOPE + '/base-blobs', _SCOPE + '/bases',
                         _SCOPE + '/receipts', _SCOPE + '/staging',
                         _SCOPE + '/template.directory', _SCOPE + '/transactions'}
        expected_dirs |= {_TX + name for name in txdirs} | {_STAGE + name for name in txdirs}
        if dirs != expected_dirs:
            raise LegacyWindowsTerminalError('Unknown or missing selected-scope directory')
        if archive.get(_TX + 'managed-scope.lock') != b'' or archive.get(_SCOPE + '/template.file') != b'':
            raise LegacyWindowsTerminalError('Private lock or template bytes differ')
        checked = {_TX + 'managed-scope.lock', _SCOPE + '/template.file'}
        receipts = {}
        for ref in proven.snapshot.manifest['receipts']:
            txid = ref['transaction_id']
            path = provenance.receipt_path(txid).replace('\\', '/')
            receipt, _digest = provenance._decode(archive[path], provenance.RECEIPT_SCHEMA,
                                                  provenance._RECEIPT_KEYS)
            receipts[txid] = receipt
        terminals = []
        committed = set()
        journal_total = 0
        projection_work = [0]
        for opid in sorted(txdirs):
            prefix = _TX + opid + '/'
            leaves = {path[len(prefix):]: path for path in archive if path.startswith(prefix)}
            if any('/' in name for name in leaves):
                raise LegacyWindowsTerminalError('Nested operation journal residue')
            if (not {'plan.json', 'intent.json', 'lock', 'directories.json'} <= set(leaves)
                    or archive[leaves['lock']] != b''):
                raise LegacyWindowsTerminalError('Operation lacks required journal or empty lock')
            checked.add(leaves['lock'])
            values = {}
            for name, path in leaves.items():
                if name == 'lock':
                    continue
                raw = archive[path]
                journal_total += len(raw)
                if type(raw) is not bytes or len(raw) > _MAX_RECORD or journal_total > _MAX_JOURNAL_BYTES:
                    raise LegacyWindowsTerminalError('Cumulative journal byte budget exceeded')
                values[name] = _decode(raw)
                checked.add(path)
            spec = operation._spec_from_records(opid, values['plan.json'], values['intent.json'])
            if spec.record_version not in (1, 2):
                raise LegacyWindowsTerminalError('Manifest-commit journals are not legacy Windows history')
            plan = dict(spec.plan)
            if (set(plan) != _PLAN_KEYS or plan.get('schema') != runtime.SCHEMA
                    or type(plan.get('enrollment')) is not bool
                    or type(plan.get('source_policy_observation')) is not dict
                    or plan['source_policy_observation'].get('presence') != 'present'
                    or plan['source_policy_observation'].get('sha256') != plan.get('source_policy_sha256')
                    or plan.get('digest_sha256') != canonical_sha256(
                        {key: value for key, value in plan.items() if key != 'digest_sha256'})
                    or plan.get('status') != 'ready' or plan.get('operation_id') != opid
                    or plan.get('project_id') != proven.snapshot.project_id
                    or plan.get('project_root_identity') != proven.historical_root_identity
                    or not provenance._hex(plan.get('source_policy_sha256'))
                    or plan.get('source_policy_snapshot_sha256') not in historical_policies
                    or type(plan.get('project_root')) is not str
                    or ntpath.normpath(plan['project_root']) != plan['project_root']
                    or not ntpath.isabs(plan['project_root'])):
                raise LegacyWindowsTerminalError('Historical operation plan binding differs')
            _parts(plan['project_root'])  # Pure lexical validation, never opens the old root.
            txid = plan.get('transaction_id')
            if type(txid) is not str or txid != 'WMC-' + opid[4:]:
                raise LegacyWindowsTerminalError('Historical operation receipt ID invalid')
            for key in ('runtime_parent_id', 'scope_lock_id', 'transaction_directory_id', 'lock_id'):
                witness = values['intent.json'].get(key)
                if (not directories._valid_identity(witness)
                        or witness['volume_serial_hex'] != proven.historical_root_identity['volume_serial_hex']):
                    raise LegacyWindowsTerminalError('Historical intent native identity syntax differs')
            ids = [canonical_bytes(values['intent.json'][key]) for key in
                   ('runtime_parent_id', 'scope_lock_id', 'transaction_directory_id', 'lock_id')]
            if len(set(ids)) != len(ids):
                raise LegacyWindowsTerminalError('Historical intent identities alias')
            marks = _PureMarkers(values, spec, values['intent.json'])
            peak = marks._audit_forward()
            committed_marker = marks._read_marker('committed.json', direction='forward', state='committed')
            rolled_marker = marks._read_marker('rolled-back.json', direction='rollback', state='prepared')
            start = marks._read_rollback_start()
            if committed_marker and not rolled_marker and start is None and peak == marks.total_steps:
                terminal = 'committed'
                receipt = receipts.get(txid)
                if (receipt is None or receipt.get('plan_sha256') != plan.get('digest_sha256')
                        or receipt.get('request') != plan.get('request')
                        or receipt.get('source_policy_snapshot_sha256') != plan.get('source_policy_snapshot_sha256')):
                    raise LegacyWindowsTerminalError('Committed operation lacks matching replayed receipt')
                if txid in committed:
                    raise LegacyWindowsTerminalError('Duplicate committed operation receipt')
                committed.add(txid)
            elif rolled_marker and not committed_marker and start == peak and start is not None:
                if marks._audit_rollback(start) != start or txid in receipts:
                    raise LegacyWindowsTerminalError('Rolled-back operation has incomplete rollback or receipt conflict')
                terminal = 'rolled_back'
            else:
                raise LegacyWindowsTerminalError('Unfinished or conflicting operation markers')
            _validate_publication_slots(spec, plan, terminal, archive, proven,
                replay_args['source_policy_raw'], projection_work)
            intent_sha = hashlib.sha256(_envelope(values['intent.json'])).hexdigest()
            state = _PureDirectories(values, opid, intent_sha, plan, proven.historical_root_identity).validate(terminal)
            if terminal == 'rolled_back' and not state[-1]:
                raise LegacyWindowsTerminalError('Rolled-back directory cleanup is incomplete')
            known_names = {'plan.json', 'intent.json', 'lock', 'directories.json'}
            known_names |= {f'forward-{i:06d}.json' for i in range(1, peak + 1)}
            known_names.add('committed.json' if terminal == 'committed' else 'rolled-back.json')
            if terminal == 'rolled_back':
                known_names.add('rollback.json')
                known_names |= {f'rollback-{i:06d}.json' for i in range(start)}
                count = len(state[0]['directories'])
                known_names.add('directories-rolled-back.json')
                known_names |= {f'directory-delete-{i:06d}.{phase}.json'
                                for i in range(count) for phase in ('intent', 'done')
                                if f'directory-delete-{i:06d}.{phase}.json' in values}
            if set(leaves) != known_names:
                raise LegacyWindowsTerminalError('Unknown or pending operation journal leaf')
            stage_prefix = _STAGE + opid + '/'
            staged = {path for path in archive if path.startswith(stage_prefix)}
            expected_staged = set()
            for publication in spec.publications:
                if terminal == 'committed' and publication.kind == 'replace':
                    key, identity = publication.backup, publication.before
                elif terminal == 'rolled_back':
                    key, identity = publication.staged, publication.after
                else:
                    continue
                assert key is not None and identity is not None
                relative = _source_leaf(spec.slot_paths[key], plan['project_root'])
                if not relative.startswith(stage_prefix):
                    raise LegacyWindowsTerminalError('Private staged slot escapes operation directory')
                _check_bytes(archive.get(relative), identity, relative)
                expected_staged.add(relative)
            if staged != expected_staged:
                raise LegacyWindowsTerminalError('Private staged/backup inventory differs from terminal intent')
            checked |= staged
            terminals.append(TerminalOperation(opid, txid, terminal, spec.record_version))
        if committed != set(receipts):
            raise LegacyWindowsTerminalError('Receipt and committed operation coverage differ')
        if set(archive) != checked | set(proven.actually_read_source_paths):
            raise LegacyWindowsTerminalError('Unknown or pending source control leaf')
        return LegacyWindowsTerminal(proven, tuple(terminals), tuple(sorted(checked)))
    except LegacyWindowsTerminalError:
        raise
    except (replay.LegacyWindowsReplayError, migration.LegacyMigrationRecordError,
            WindowsJournalConflict, provenance.WindowsProvenanceError, ValueError,
            TypeError, KeyError, AttributeError, OverflowError, RecursionError) as exc:
        raise LegacyWindowsTerminalError(f'Legacy Windows terminal validation refused: {exc}') from exc
