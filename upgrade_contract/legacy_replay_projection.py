"""Staged path-free full-replay codec. This module grants no writer authority.

Explicitly adapted POSIX and Windows histories are admitted. Unknown source
schemas and unprojectable inputs refuse. Derived materialized hashes belong to this codec's namespace;
no original raw archive, digest field or v1 authority is modified.
"""
from __future__ import annotations

import base64
import copy
import hashlib
from pathlib import PurePosixPath

from . import legacy_authority as authority
from . import legacy_migration_records as migration
from . import legacy_posix_replay as replay
from . import planner, transaction
from .canonical import canonical_bytes, canonical_sha256, loads_strict_json

SCHEMA = 'naos.upgrade.derived_posix_replay.v1'
LOCATION_SCHEMA = 'naos.upgrade.replay_location.v1'
_SYNTHETIC_ROOT = '/__naos_replay__/r0'
_PLAN_SCHEMAS = {'naos.upgrade.create_only_plan.v1', 'naos.upgrade.create_only_plan.v2',
                 *planner.CONTENT_AWARE_PLAN_SCHEMAS}
_SCHEMAS = _PLAN_SCHEMAS | {
    'naos.upgrade.control_root_owner.v1', 'naos.upgrade.managed_content_scope.v1',
    'naos.upgrade.managed_content_manifest.v1', 'naos.upgrade.managed_content_manifest.v2',
    'naos.upgrade.managed_content_receipt.v1', 'naos.upgrade.managed_content_receipt.v2',
    'naos.upgrade.create_only_transaction.v1', 'naos.upgrade.content_transaction.v2',
    transaction._COMPACT_JOURNAL_SCHEMA, 'naos.metadata.creation_identity.v1',
    'naos.metadata.darwin_create_only.v1', 'naos.metadata.darwin_source.v1',
    'naos.metadata.linux_create_only.v1', 'naos.metadata.linux_source.v1',
}
_REFERENCE_PATHS = {
    'naos.upgrade.control_root_owner.v1': {('enrollment_authorization', 'plan_sha256')},
    'naos.upgrade.managed_content_scope.v1': {('owner_integrity_sha3_512',), ('enrollment', 'plan_sha256')},
    **{name: {('scope_integrity_sha3_512',), ('previous_integrity_sha256',), ('last_plan_sha256',),
             ('transactions', '*', 'receipt_sha256'), ('entries', '*', 'receipt_sha256')}
       for name in ('naos.upgrade.managed_content_manifest.v1', 'naos.upgrade.managed_content_manifest.v2')},
    **{name: {('plan_sha256',), ('scope_integrity_sha3_512',)}
       for name in ('naos.upgrade.managed_content_receipt.v1', 'naos.upgrade.managed_content_receipt.v2')},
    **{name: {('manifest', 'snapshot_sha256'), ('project', 'scope_integrity_sha3_512')}
       for name in planner.CONTENT_AWARE_PLAN_SCHEMAS},
}
_LOCATION_PATHS = {
    **{name: {('project_root_binding',)} for name in ('naos.upgrade.create_only_plan.v1', 'naos.upgrade.create_only_plan.v2')},
    **{name: {('project', 'root_binding')} for name in planner.CONTENT_AWARE_PLAN_SCHEMAS},
}



class ReplayProjectionError(ValueError):
    """The selected raw or derived history is unsupported or inconsistent."""


def _rehash(value):
    value = copy.deepcopy(value)
    if 'integrity' in value:
        control = {k: v for k, v in value.items() if k != 'integrity'}
        algorithm = value['integrity']['algorithm']
        if algorithm not in ('sha256', 'sha3-512'):
            raise ReplayProjectionError('Unknown integrity algorithm')
        value['integrity']['value'] = hashlib.new(algorithm.replace('-', '_'), canonical_bytes(control)).hexdigest()
    return value


def _walk(value, digests, *, schema=None, path=()):
    if isinstance(value, list):
        return [_walk(item, digests, schema=schema, path=path+('*',)) for item in value]
    if not isinstance(value, dict):
        return value
    if 'schema' in value:
        schema = value['schema']; path = ()
    if 'schema' in value and schema not in _SCHEMAS:
        raise ReplayProjectionError('Unsupported source schema: ' + str(schema))
    result = {}
    for key, item in value.items():
        if path+(key,) in _LOCATION_PATHS.get(schema, set()):
            result[key] = _SYNTHETIC_ROOT
        elif path+(key,) in _REFERENCE_PATHS.get(schema, set()) and isinstance(item, str):
            result[key] = digests.get(item, item)
        else:
            result[key] = _walk(item, digests, schema=schema, path=path+(key,))
    if result.get('schema') in _PLAN_SCHEMAS:
        result['plan_sha256'] = canonical_sha256({k: v for k, v in result.items() if k != 'plan_sha256'})
    if 'integrity' in result:
        result = _rehash(result)
    return result


def _typed(value, *, decode=False, schema=None, path=()):
    if isinstance(value, list):
        return [_typed(item, decode=decode, schema=schema, path=path+('*',)) for item in value]
    if not isinstance(value, dict):
        return value
    if 'schema' in value:
        schema = value['schema']; path = ()
    if 'schema' in value and schema not in _SCHEMAS:
        raise ReplayProjectionError('Unsupported derived schema: ' + str(schema))
    result = {}
    for key, item in value.items():
        localized = path+(key,) in _LOCATION_PATHS.get(schema, set())
        if localized:
            token = {'schema': LOCATION_SCHEMA, 'root_id': 'r0', 'components': []}
            if decode:
                if item != token:
                    raise ReplayProjectionError('Mixed or noncanonical root token')
                result[key] = _SYNTHETIC_ROOT
            else:
                if item != _SYNTHETIC_ROOT:
                    raise ReplayProjectionError('Unlocalized root')
                result[key] = token
        else:
            result[key] = _typed(item, decode=decode, schema=schema, path=path+(key,))
    return result


def _snapshot(manifest, receipts, archive):
    reader = replay._ArchiveReader(archive)
    return transaction._managed_content_snapshot_from_records(
        manifest, manifest_version='v2' if manifest['schema'].endswith('.v2') else 'v1',
        project_id=manifest['project_id'], scope_integrity_sha3_512=manifest['scope_integrity_sha3_512'],
        source_policy_sha256=manifest['source_policy_sha256'],
        load_receipt=lambda ref: receipts[ref['transaction_id']],
        base_matches=lambda row: reader.base_matches(row['base']['sha256'], size=row['base']['size']),
        historical_base_matches=reader.base_matches)


def _expect(archive, fmt):
    return {f'expected_{role}_sha256': hashlib.sha256(archive[path]).hexdigest()
            for role, path in migration._ANCHORS[fmt].items()}


def _derive(archive, lineage, kwargs):
    return authority._derive(archive, lineage, kwargs['directory_paths'], kwargs['source_policy_raw'],
        kwargs['mode_inventory_raw'], kwargs['expected_modes_sha256'], **{k: v for k, v in kwargs.items()
        if k not in ('directory_paths', 'source_policy_raw', 'mode_inventory_raw', 'expected_modes_sha256')})


def build(archive_bytes, lineage, **kwargs):
    """Validate raw full replay, project chronology, then validate derived replay.

    Explicit codec entry only. Production migration remains on the v1 writer.
    """
    if lineage.body['source_format'] == migration.WINDOWS_CONTENT_V1:
        from . import legacy_windows_projection
        return legacy_windows_projection.build(archive_bytes, lineage, kwargs)
    if lineage.body['source_format'] != migration.POSIX_MANAGED_V1:
        raise ReplayProjectionError('Unsupported source format')
    archive = dict(archive_bytes)
    raw_seed = _derive(archive, lineage, kwargs)
    prefixes = []
    replay.replay_posix_archive(archive, lineage, _prefix_observer=lambda raw: prefixes.append(loads_strict_json(raw)),
        **{k: v for k, v in kwargs.items() if k not in ('directory_paths', 'mode_inventory_raw', 'expected_modes_sha256')})
    anchor = migration._ANCHORS[migration.POSIX_MANAGED_V1]
    original_manifest = loads_strict_json(archive[anchor['head']])
    original_root = replay._root_text(original_manifest['transactions'][0]['plan'])
    # Admission checks actual bytes, including payloads and free text. Rewriting
    # only declared locations must leave no occurrence of the source root.
    digests = {}
    first_plan = original_manifest['transactions'][0]['plan']
    digests[first_plan['plan_sha256']] = _walk(first_plan, {})['plan_sha256']
    projected = dict(archive)
    owner = _walk(loads_strict_json(archive[anchor['owner']]), digests)
    digests[loads_strict_json(archive[anchor['owner']])['integrity']['value']] = owner['integrity']['value']
    projected[anchor['owner']] = canonical_bytes(owner)
    scope = _walk(loads_strict_json(archive[anchor['scope']]), digests)
    digests[loads_strict_json(archive[anchor['scope']])['integrity']['value']] = scope['integrity']['value']
    projected[anchor['scope']] = canonical_bytes(scope)
    receipts = {}
    for index, prefix in enumerate(prefixes):
        reference = prefix['transactions'][-1]
        old_plan = reference['plan']
        plan = _walk(old_plan, digests)
        digests[old_plan['plan_sha256']] = plan['plan_sha256']
        receipt_path = replay._RECEIPTS + reference['transaction_id'] + '.json'
        old_receipt = loads_strict_json(archive[receipt_path])
        receipt = _walk(old_receipt, digests)
        digests[old_receipt['integrity']['value']] = receipt['integrity']['value']
        digests[reference['receipt_sha256']] = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
        projected[receipt_path] = canonical_bytes(receipt)
        receipts[reference['transaction_id']] = (receipt, hashlib.sha256(canonical_bytes(receipt)).hexdigest(),
            'v2' if receipt['schema'].endswith('.v2') else 'v1')
        transformed = _walk(prefix, digests)
        digests[prefix['integrity']['value']] = transformed['integrity']['value']
        old_snapshot = _snapshot(prefix, {
            ref['transaction_id']: (loads_strict_json(archive[replay._RECEIPTS + ref['transaction_id'] + '.json']),
                ref['receipt_sha256'], 'v2' if loads_strict_json(archive[replay._RECEIPTS + ref['transaction_id'] + '.json'])['schema'].endswith('.v2') else 'v1')
            for ref in prefix['transactions']}, archive)
        new_snapshot = _snapshot(transformed, receipts, projected)
        digests[old_snapshot['snapshot_sha256']] = new_snapshot['snapshot_sha256']
        if index == len(prefixes) - 1:
            projected[anchor['head']] = canonical_bytes(transformed)
    # Plan copies and every full/compact terminal journal receive the same
    # schema-directed transform after chronological dependencies are resolved.
    for path, raw in sorted(archive.items(), key=lambda row: (not row[0].endswith('/plan.json'), row[0])):
        if '/transactions/' not in path or not path.endswith('.json'):
            continue
        value = loads_strict_json(raw)
        transformed = _walk(value, digests)
        if path.endswith('/plan.json'):
            projected[path] = canonical_bytes(transformed) + b'\n'
        elif value.get('schema') == transaction._COMPACT_JOURNAL_SCHEMA:
            sidecar = path.removesuffix('journal.json') + 'plan.json'
            transformed['plan_ref'] = transaction._compact_plan_reference(projected[sidecar])
            projected[path] = canonical_bytes(_rehash(transformed))
        else:
            projected[path] = canonical_bytes(transformed)
    parts = PurePosixPath(original_root).parts
    home = str(PurePosixPath(*parts[:3])) if len(parts) > 3 and parts[1] in ('Users', 'home') else original_root
    canaries = [home.encode(), canonical_bytes(home)[1:-1]]
    if any(canary in raw for raw in (*projected.values(), kwargs['source_policy_raw'], kwargs['mode_inventory_raw']) for canary in canaries):
        raise ReplayProjectionError('Unsupported source-root-bearing payload or free text')
    expected = _expect(projected, migration.POSIX_MANAGED_V1)
    derived_lineage = migration.build_lineage(projected, source_format=migration.POSIX_MANAGED_V1,
        original_project_id=lineage.body['original_project_id'], new_project_id=lineage.body['new_project_id'], **expected)
    derived_kwargs = dict(kwargs, **expected, approved_lineage_sha256=derived_lineage.sha256)
    seed = _derive(projected, derived_lineage, derived_kwargs)
    origin_fields = {'source_format', 'original_introduced_by_transaction',
        'original_latest_transaction', 'original_policy_binding_sha256',
        'resolved_policy_snapshot_id', 'canonical_policy_sha256'}
    raw_origins = {path: {key: row[key] for key in origin_fields} for path, row in raw_seed['origin_map'].items()}
    derived_origins = {path: {key: row[key] for key in origin_fields} for path, row in seed['origin_map'].items()}
    if raw_origins != derived_origins or any(raw_seed[key] != seed[key] for key in ('entries', 'inputs', 'policies', 'bases', 'inventory_sha256')):
        raise ReplayProjectionError('Raw/derived portable semantics differ')
    members = []
    for path, raw in sorted(projected.items()):
        if path.endswith('.json'):
            value = _typed(loads_strict_json(raw))
            payload = {'kind': 'record', 'value': value, 'trailing_newline': raw.endswith(b'\n')}
        else:
            payload = {'kind': 'bytes', 'base64': base64.b64encode(raw).decode('ascii')}
        members.append({'path': path, 'derived_materialized_sha256': hashlib.sha256(raw).hexdigest(),
                        'derived_materialized_size_decimal': str(len(raw)), 'payload': payload})
    body = {'schema': SCHEMA, 'source_format': migration.POSIX_MANAGED_V1,
        'raw_lineage_commitment_sha256': lineage.sha256, 'derived_lineage': derived_lineage.body,
        'directory_paths': list(kwargs['directory_paths']), 'members': members}
    raw = canonical_bytes(body)
    if any(canary in raw for canary in canaries):
        raise ReplayProjectionError('Unsupported source-home-bearing serialized replay metadata')
    # Verify the serialized path-free representation through the receiving path.
    replay_derived(raw, source_policy_raw=kwargs['source_policy_raw'],
                   mode_inventory_raw=kwargs['mode_inventory_raw'], expected_modes_sha256=kwargs['expected_modes_sha256'])
    return raw


def replay_derived(raw, *, source_policy_raw, mode_inventory_raw, expected_modes_sha256):
    """Replay complete derived evidence without any original archive or path map."""
    if type(raw) is not bytes or len(raw) > migration.MAX_ARCHIVE_BYTES * 2:
        raise ReplayProjectionError('Missing or oversized derived replay')
    body = loads_strict_json(raw)
    if type(body) is dict and body.get('schema') == 'naos.upgrade.derived_windows_replay.v1':
        from . import legacy_windows_projection
        return legacy_windows_projection.replay_derived(raw, source_policy_raw=source_policy_raw, mode_inventory_raw=mode_inventory_raw, expected_modes_sha256=expected_modes_sha256)
    if type(body) is not dict or set(body) != {'schema', 'source_format', 'raw_lineage_commitment_sha256',
            'derived_lineage', 'directory_paths', 'members'} or body['schema'] != SCHEMA or body['source_format'] != migration.POSIX_MANAGED_V1 or canonical_bytes(body) != raw:
        raise ReplayProjectionError('Derived replay record differs')
    migration._digest(body['raw_lineage_commitment_sha256'], 'raw commitment')
    members = body['members']
    if not isinstance(members, list) or not 1 <= len(members) <= migration.MAX_ARCHIVE_FILES:
        raise ReplayProjectionError('Derived inventory budget differs')
    archive = {}
    total_materialized = 0
    for item in members:
        if type(item) is not dict or set(item) != {'path', 'derived_materialized_sha256', 'derived_materialized_size_decimal', 'payload'}:
            raise ReplayProjectionError('Derived member shape differs')
        path, payload = item['path'], item['payload']
        if type(payload) is not dict:
            raise ReplayProjectionError('Derived payload is not a record')
        migration._path(path, migration.POSIX_MANAGED_V1)
        if path in archive:
            raise ReplayProjectionError('Duplicate derived member')
        if payload.get('kind') == 'record' and set(payload) == {'kind', 'value', 'trailing_newline'} and type(payload['trailing_newline']) is bool:
            value = _typed(payload['value'], decode=True)
            materialized = canonical_bytes(value) + (b'\n' if payload['trailing_newline'] else b'')
        elif payload.get('kind') == 'bytes' and set(payload) == {'kind', 'base64'}:
            if type(payload['base64']) is not str or len(payload['base64']) > 4 * ((migration.MAX_ARCHIVE_FILE_BYTES + 2) // 3):
                raise ReplayProjectionError('Derived member byte budget exceeded')
            materialized = base64.b64decode(payload['base64'], validate=True)
        else:
            raise ReplayProjectionError('Unsupported derived payload')
        total_materialized += len(materialized)
        if len(materialized) > migration.MAX_ARCHIVE_FILE_BYTES or total_materialized > migration.MAX_ARCHIVE_BYTES:
            raise ReplayProjectionError('Derived archive byte budget exceeded')
        if (hashlib.sha256(materialized).hexdigest() != item['derived_materialized_sha256']
                or str(len(materialized)) != item['derived_materialized_size_decimal']):
            raise ReplayProjectionError('Derived materialized commitment differs')
        archive[path] = materialized
    if [item['path'] for item in members] != sorted(archive):
        raise ReplayProjectionError('Noncanonical derived inventory')
    lineage_raw = canonical_bytes(body['derived_lineage'])
    lineage = migration.LegacyLineage(lineage_raw, hashlib.sha256(lineage_raw).hexdigest())
    return _derive(archive, lineage, dict(directory_paths=body['directory_paths'], source_policy_raw=source_policy_raw,
        mode_inventory_raw=mode_inventory_raw, expected_modes_sha256=expected_modes_sha256,
        approved_lineage_sha256=lineage.sha256,
        expected_source_policy_sha256=hashlib.sha256(source_policy_raw).hexdigest(), **_expect(archive, migration.POSIX_MANAGED_V1)))
