"""Pure replay of archived POSIX managed-content v1/v2 history.

Historical root text is validated lexically, never resolved on this host.
Successful replay proves internal source history only, not native custody,
quiescence, complete filesystem inventory, or mutation authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath

from .canonical import canonical_bytes, loads_strict_json
from . import legacy_migration_records as migration
from . import planner, provenance, transaction, windows_provenance

_BASES = '.naos/upgrade-v1/managed-content/state/bases/'
_RECEIPTS = '.naos/upgrade-v1/managed-content/state/receipts/'
_MAX_JSON = 16 * 1024 * 1024
MAX_TRANSACTIONS = 256
MAX_REPLAY_WORK_BYTES = 256 * 1024 * 1024
MAX_POLICY_WORK_BYTES = 64 * 1024 * 1024


class LegacyPosixReplayError(ValueError):
    """Archived POSIX source history is incomplete, foreign or unsupported."""


class _ArchiveReader:
    def __init__(self, archive: dict[str, bytes]):
        self.archive = archive
        self.cache: dict[str, bytes | None] = {}
        self.read_paths: set[str] = set()
        self.base_hashes: dict[str, str] = {}

    def read(self, path: str) -> bytes | None:
        if path not in self.cache:
            raw = self.archive.get(path)
            self.cache[path] = raw
            if raw is not None:
                self.read_paths.add(path)
        return self.cache[path]

    def json(self, path: str) -> dict:
        raw = self.read(path)
        if type(raw) is not bytes or len(raw) > _MAX_JSON:
            raise LegacyPosixReplayError('Missing or oversized legacy JSON record: ' + path)
        value = loads_strict_json(raw)
        if type(value) is not dict:
            raise LegacyPosixReplayError('Legacy JSON record is not an object: ' + path)
        return value

    def base_matches(self, digest: str, *, size: int | None = None) -> bool:
        if type(digest) is not str or transaction.SHA256_RE.fullmatch(digest) is None:
            return False
        path = _BASES + digest
        raw = self.read(path)
        if raw is None or len(raw) > migration.MAX_ARCHIVE_FILE_BYTES:
            return False
        if path not in self.base_hashes:
            self.base_hashes[path] = hashlib.sha256(raw).hexdigest()
        return self.base_hashes[path] == digest and (size is None or len(raw) == size)


@dataclass(frozen=True)
class LegacyPosixReplay:
    _snapshot_bytes: bytes
    lineage_sha256: str
    source_policy_sha256: str
    historical_root: str
    actually_read_source_paths: tuple[str, ...]
    unvalidated_archive_paths: tuple[str, ...]
    native_custody_proven: bool = False
    quiescence_proven: bool = False
    mutation_authorized: bool = False

    @property
    def snapshot(self) -> dict:
        return loads_strict_json(self._snapshot_bytes)


def _root_text(plan: dict) -> str:
    schema = plan.get('schema')
    if schema in {'naos.upgrade.create_only_plan.v1', 'naos.upgrade.create_only_plan.v2'}:
        value = plan.get('project_root_binding')
    elif schema in planner.CONTENT_AWARE_PLAN_SCHEMAS:
        value = (plan.get('project') or {}).get('root_binding')
    else:
        raise LegacyPosixReplayError('Unsupported historical plan schema')
    if (type(value) is not str or len(value) > 4096 or value.startswith('//')
            or '\\' in value or any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in value)
            or not PurePosixPath(value).is_absolute() or str(PurePosixPath(value)) != value
            or '..' in PurePosixPath(value).parts or value == '/'):
        raise LegacyPosixReplayError('Historical POSIX root binding is noncanonical')
    return value


def _plan_policy_digest(plan: dict) -> str:
    if plan.get('schema') in {'naos.upgrade.create_only_plan.v1', 'naos.upgrade.create_only_plan.v2'}:
        value = plan.get('source_policy_sha256')
    else:
        value = ((plan.get('source_policy') or {}).get('provenance') or {}).get('binding_sha256')
    migration._digest(value, 'historical plan policy')
    return value


def _check_replay_budget(manifest: dict, manifest_raw: bytes, archive: dict[str, bytes]) -> None:
    """Bound repeated canonicalization and receipt projection before replay.

    Charge every pass for the full manifest four times plus all referenced
    receipt bytes. This intentionally overcounts prefixes and cached reads;
    the budget is a deterministic admission rule, not a wall-time estimate.
    """
    refs = manifest.get('transactions')
    if type(refs) is not list or not 1 <= len(refs) <= MAX_TRANSACTIONS:
        raise LegacyPosixReplayError('Historical transaction count exceeds replay budget')
    receipt_bytes = 0
    for ref in refs:
        if (type(ref) is not dict or type(ref.get('transaction_id')) is not str
                or transaction.TRANSACTION_ID_RE.fullmatch(ref['transaction_id']) is None):
            raise LegacyPosixReplayError('Invalid historical transaction reference')
        raw = archive.get(_RECEIPTS + ref['transaction_id'] + '.json')
        if type(raw) is not bytes or len(raw) > _MAX_JSON:
            raise LegacyPosixReplayError('Missing or oversized historical receipt')
        receipt_bytes += len(raw)
    charged = len(refs) * (4 * len(manifest_raw) + receipt_bytes)
    if charged > MAX_REPLAY_WORK_BYTES:
        raise LegacyPosixReplayError('Historical cumulative replay work exceeds budget')


def _replay_sequence(manifest: dict, receipts: dict[str, tuple[dict, str, str]], policy_for,
                     reader: _ArchiveReader, *, prefix_observer=None) -> None:
    """Reject omissions/stale final pointers left outside per-entry validators."""
    current: dict[str, dict] = {}
    reconstructed = None
    history = []
    is_v2 = False
    for transaction_ref in manifest['transactions']:
        txid = transaction_ref['transaction_id']
        plan = transaction_ref['plan']
        receipt, receipt_sha, version = receipts[txid]
        active_digest = ((plan.get('source_policy') or {}).get('active') or {}).get('binding_sha256') if version == 'v2' else _plan_policy_digest(plan)
        policy = policy_for(active_digest).policy
        if version == 'v1':
            for row in receipt['paths']:
                action = row['action']
                if not action.startswith('CREATE_'):
                    if action != 'NOOP_UNCHANGED':
                        raise LegacyPosixReplayError('Unsupported historical create-only action')
                    continue
                path = row['path']
                previous = current.get(path)
                if previous is not None and any(previous[key] != row[source] for key, source in (
                        ('ownership', 'ownership'), ('creation_policy', 'creation_policy'),
                        ('base', 'source'), ('source_metadata', 'source_metadata'))):
                    raise LegacyPosixReplayError('Historical create-only reintroduction changed authority')
                if not reader.base_matches(row['source']['sha256'], size=row['source']['size']):
                    raise LegacyPosixReplayError('Historical source bytes or size differ')
                rule = planner.classify_new_path(Path(path), policy)
                if (row['ownership'] != rule['ownership']
                        or row['creation_policy'] != rule['creation_policy']
                        or row['source_policy_rule'] != rule['policy_id']):
                    raise LegacyPosixReplayError('Historical creation exceeds source policy')
                current[path] = {'ownership': row['ownership'], 'creation_policy': row['creation_policy'],
                                 'base': row['source'], 'source_metadata': row['source_metadata'],
                                 'introduced_by_transaction': txid, 'last_mutated_by_transaction': txid,
                                 'receipt_sha256': receipt_sha,
                                 'created_metadata': receipt['created_metadata'][path],
                                 '_introduced_policy_digest': _plan_policy_digest(plan)}
        else:
            if reconstructed is None:
                raise LegacyPosixReplayError('Content-aware history lacks its prior manifest')
            prior_snapshot = transaction._managed_content_snapshot_from_records(
                reconstructed, manifest_version='v2' if is_v2 else 'v1',
                project_id=manifest['project_id'],
                scope_integrity_sha3_512=manifest['scope_integrity_sha3_512'],
                source_policy_sha256=manifest['source_policy_sha256'],
                load_receipt=lambda ref: receipts[ref['transaction_id']],
                base_matches=lambda entry: reader.base_matches(entry['base']['sha256'],
                                                               size=entry['base']['size']),
                historical_base_matches=reader.base_matches)
            if plan['manifest']['snapshot_sha256'] != prior_snapshot['snapshot_sha256']:
                raise LegacyPosixReplayError('Historical plan does not bind its preceding manifest')
            is_v2 = True
            plan_rows = {row['path']: row for row in plan['paths']}
            for action in receipt['actions']:
                path = action['path']
                row = plan_rows[path]
                ownership = row['ownership']
                row_policy = row['source_policy']
                if action['kind'] == 'create':
                    if path in current:
                        raise LegacyPosixReplayError('Historical create overlaps existing path')
                    rule = planner.classify_new_path(Path(path), policy)
                    active = policy_for(active_digest)
                    if (ownership['after'] != rule['ownership']
                            or ownership['creation_policy'] != rule['creation_policy']
                            or row_policy != {'binding_sha256': active.sha256,
                                              'snapshot_id': active.snapshot_id,
                                              'snapshot_sha256': active.snapshot_sha256,
                                              'rule': rule['policy_id']}):
                        raise LegacyPosixReplayError('Historical creation exceeds source policy')
                    introduced = txid
                    introduced_policy = active_digest
                elif action['kind'] == 'replace':
                    previous = current.get(path)
                    before = action['before']
                    before_base = {key: before[key] for key in ('kind', 'mode', 'size', 'sha256')}
                    if (previous is None or previous['ownership'] != 'kit_owned_derived'
                            or previous['base'] != before_base
                            or ownership['after'] != previous['ownership']
                            or ownership['creation_policy'] != previous['creation_policy']):
                        raise LegacyPosixReplayError('Historical replacement lost prior authority')
                    provenance_policy = policy_for(_plan_policy_digest(plan))
                    if row_policy != {'binding_sha256': provenance_policy.sha256,
                                      'snapshot_id': provenance_policy.snapshot_id,
                                      'snapshot_sha256': provenance_policy.snapshot_sha256,
                                      'rule': 'manifest:' + previous['introduced_by_transaction']}:
                        raise LegacyPosixReplayError('Historical replacement lost introducing policy')
                    introduced = previous['introduced_by_transaction']
                    introduced_policy = previous['_introduced_policy_digest']
                else:
                    raise LegacyPosixReplayError('Unsupported historical mutation kind')
                after = action['after']
                for identity in (action['before'], after):
                    if identity['presence'] == 'present' and not reader.base_matches(
                            identity['sha256'], size=identity['size']):
                        raise LegacyPosixReplayError('Historical mutation base bytes or size differ')
                current[path] = {'ownership': ownership['after'],
                                 'creation_policy': ownership['creation_policy'],
                                 'base': {key: after[key] for key in ('kind', 'mode', 'size', 'sha256')},
                                 'source_metadata': action['after_metadata'],
                                 'introduced_by_transaction': introduced,
                                 'last_mutated_by_transaction': txid,
                                 'receipt_sha256': receipt_sha,
                                 'created_metadata': action['installed_metadata'],
                                 '_introduced_policy_digest': introduced_policy}
        history.append(transaction_ref)
        entries_for_head = []
        for path, row in sorted(current.items()):
            entry = {'path': path, **{k: v for k, v in row.items() if not k.startswith('_')},
                     'base_blob': {'path': row['base']['sha256'], 'sha256': row['base']['sha256']}}
            if not is_v2:
                entry.pop('last_mutated_by_transaction')
            entries_for_head.append(entry)
        reconstructed = transaction._with_sha256_integrity({
            'schema': 'naos.upgrade.managed_content_manifest.v2' if is_v2 else 'naos.upgrade.managed_content_manifest.v1',
            **({'minimum_recovery_naos_version': transaction.CONTENT_AWARE_MINIMUM_RECOVERY_VERSION} if is_v2 else {}),
            'project_id': manifest['project_id'],
            'scope_integrity_sha3_512': manifest['scope_integrity_sha3_512'],
            'source_policy_sha256': manifest['source_policy_sha256'],
            'previous_integrity_sha256': reconstructed['integrity']['value'] if reconstructed else None,
            'last_transaction_id': txid, 'last_plan_sha256': plan['plan_sha256'],
            'entries': entries_for_head, 'transactions': list(history)})
        if prefix_observer is not None:
            prefix_observer(canonical_bytes(reconstructed))
    if reconstructed != manifest:
        raise LegacyPosixReplayError('Final manifest differs from chronological committed replay')
    entries = {entry['path']: entry for entry in manifest['entries']}
    if set(entries) != set(current):
        raise LegacyPosixReplayError('Final manifest omits or invents a committed path')
    for path, expected in current.items():
        actual = entries[path]
        for field, value in expected.items():
            if field.startswith('_'):
                continue
            if field == 'last_mutated_by_transaction' and manifest['schema'].endswith('.v1'):
                continue
            if actual.get(field) != value:
                raise LegacyPosixReplayError('Final manifest has stale path lineage: ' + path)


def replay_posix_archive(archive_bytes, lineage: migration.LegacyLineage, *,
                         approved_lineage_sha256: str,
                         expected_owner_sha256: str, expected_scope_sha256: str,
                         expected_head_sha256: str, source_policy_raw: bytes,
                         expected_source_policy_sha256: str, _prefix_observer=None) -> LegacyPosixReplay:
    try:
        if (type(archive_bytes) is not dict or len(archive_bytes) > migration.MAX_ARCHIVE_FILES
                or type(lineage) is not migration.LegacyLineage):
            raise LegacyPosixReplayError('Exact archived bytes and typed lineage are required')
        archive = dict(archive_bytes)
        verified = migration.load_lineage(
            lineage.raw, archive, approved_lineage_sha256=approved_lineage_sha256,
            expected_owner_sha256=expected_owner_sha256,
            expected_scope_sha256=expected_scope_sha256,
            expected_head_sha256=expected_head_sha256)
        if lineage.sha256 != verified.sha256 or verified.body['source_format'] != migration.POSIX_MANAGED_V1:
            raise LegacyPosixReplayError('Approved lineage is not POSIX managed v1')
        migration._digest(expected_source_policy_sha256, 'expected source policy')
        if (type(source_policy_raw) is not bytes or len(source_policy_raw) > _MAX_JSON
                or hashlib.sha256(source_policy_raw).hexdigest() != expected_source_policy_sha256):
            raise LegacyPosixReplayError('Source policy raw bytes differ from independent expectation')
        policy_value = windows_provenance.strict_policy_load(source_policy_raw)
        reader = _ArchiveReader(archive)
        anchors = migration._ANCHORS[migration.POSIX_MANAGED_V1]
        project_id, owner_integrity = provenance._validate_owner(reader.json(anchors['owner']))
        scope = reader.json(anchors['scope'])
        scope_integrity = provenance._validate_managed_content_scope(
            scope, project_id=project_id, owner_integrity=owner_integrity)
        if project_id != verified.body['original_project_id']:
            raise LegacyPosixReplayError('Original project ID differs from validated source')
        policy_digest = scope['enrollment']['source_policy_sha256']
        policies = {}
        policy_work = 0
        def policy_for(digest):
            nonlocal policy_work
            if digest not in policies:
                policy_work += len(source_policy_raw)
                if policy_work > MAX_POLICY_WORK_BYTES:
                    raise LegacyPosixReplayError('Historical policy replay work exceeds budget')
                policies[digest] = planner._source_policy_snapshot_from_value(
                    policy_value, source_policy_raw, expected_sha256=digest)
            return policies[digest]
        policy_for(policy_digest)
        manifest = reader.json(anchors['head'])
        _check_replay_budget(manifest, archive[anchors['head']], archive)
        if not isinstance(manifest.get('transactions'), list) or not manifest['transactions']:
            raise LegacyPosixReplayError('Committed initialization history is required')
        historical_root = _root_text(manifest['transactions'][0]['plan'])
        def validate_plan(plan):
            if _root_text(plan) != historical_root:
                raise LegacyPosixReplayError('Mixed historical POSIX root bindings')
            expected_status = ('ready_create_only' if plan['schema'] in {
                'naos.upgrade.create_only_plan.v1', 'naos.upgrade.create_only_plan.v2'} else 'ready')
            if plan.get('status') != expected_status:
                raise LegacyPosixReplayError('Committed history contains a non-ready plan')
            digest = _plan_policy_digest(plan)
            if digest != policy_digest:
                raise LegacyPosixReplayError('Historical plan policy differs from enrolled scope')
            policy_for(digest)
            if plan['schema'] in {'naos.upgrade.create_only_plan.v1', 'naos.upgrade.create_only_plan.v2'}:
                planner._validate_create_only_plan_record(plan, root_binding=historical_root)
            else:
                planner._validate_content_aware_plan_record(plan, root_binding=historical_root)
                for role in ('active', 'provenance'):
                    binding = plan['source_policy'][role]
                    selected = policy_for(binding['binding_sha256'])
                    if (binding['snapshot_id'] != selected.snapshot_id
                            or binding['snapshot_sha256'] != selected.snapshot_sha256):
                        raise LegacyPosixReplayError('Historical source policy snapshot binding differs')
        manifest_schema = manifest.get('schema')
        args = dict(validate_plan=validate_plan, project_id=project_id,
                    scope_integrity_sha3_512=scope_integrity, source_policy_sha256=policy_digest)
        if manifest_schema == 'naos.upgrade.managed_content_manifest.v1':
            transaction._validate_manifest_record(manifest, **args)
            version = 'v1'
        elif manifest_schema == 'naos.upgrade.managed_content_manifest.v2':
            transaction._validate_manifest_v2_record(manifest, **args)
            version = 'v2'
        else:
            raise LegacyPosixReplayError('Unsupported historical manifest schema')
        receipts = {}
        def load_receipt(reference):
            txid = reference['transaction_id']
            if txid not in receipts:
                receipt = reader.json(_RECEIPTS + txid + '.json')
                receipts[txid] = transaction._validate_receipt_any(
                    receipt, project_id=project_id,
                    scope_integrity_sha3_512=scope_integrity,
                    source_policy_sha256=policy_digest, transaction_id=txid,
                    plan=reference['plan'])
            return receipts[txid]
        def base_matches(entry):
            base = entry['base']
            return (entry['base_blob'] == {'path': base['sha256'], 'sha256': base['sha256']}
                    and reader.base_matches(base['sha256'], size=base['size']))
        snapshot = transaction._managed_content_snapshot_from_records(
            manifest, manifest_version=version, project_id=project_id,
            scope_integrity_sha3_512=scope_integrity, source_policy_sha256=policy_digest,
            load_receipt=load_receipt, base_matches=base_matches,
            historical_base_matches=reader.base_matches)
        _replay_sequence(manifest, receipts, policy_for, reader, prefix_observer=_prefix_observer)
        return LegacyPosixReplay(
            canonical_bytes(snapshot), verified.sha256, expected_source_policy_sha256,
            historical_root, tuple(sorted(reader.read_paths)),
            tuple(sorted(set(archive) - reader.read_paths)))
    except LegacyPosixReplayError:
        raise
    except (migration.LegacyMigrationRecordError, provenance.ProvenanceError,
            planner.ContentPlanningError, transaction.TransactionPrimitiveError,
            windows_provenance.WindowsProvenanceError, TypeError, KeyError, ValueError,
            OverflowError, AttributeError, RecursionError) as exc:
        raise LegacyPosixReplayError(f'Legacy POSIX archive replay refused: {exc}') from exc
