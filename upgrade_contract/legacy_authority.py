"""Pure, evidence-bound legacy genesis for portable provenance.

A self-consistent archive is not proof of native custody, quiescence or approval.
The builder returns bytes only; publication requires a separate native protocol.
"""
from __future__ import annotations

import hashlib

from . import legacy_migration_records as migration
from . import portable_provenance as pp
from .canonical import canonical_sha256

SCHEMA = 'naos.upgrade.portable_legacy_authority.v1'
REPLAY_SCHEMA = 'naos.upgrade.portable_legacy_authority.v2'
FACTORED_REPLAY_SCHEMA = 'naos.upgrade.portable_legacy_authority.v4'
REPLAY_SCHEMAS = frozenset((REPLAY_SCHEMA, FACTORED_REPLAY_SCHEMA))
REPLAY_KEYS = {'schema', 'lineage_sha256', 'source_policy_sha256', 'mode_inventory_sha256',
               'directory_paths', 'derived_origin_map', 'projection_sha256', 'transcript_sha256',
               'transcript_size_decimal', 'project_id'}
FACTORED_REPLAY_KEYS = REPLAY_KEYS | {'transcript_chunks', 'transcript_encoding'}
_KEYS = {'schema', 'lineage_sha256', 'source_policy_sha256', 'mode_inventory_sha256',
         'directory_paths', 'origin_map', 'projection_sha256'}


def authority_path(digest):
    return pp._record_path('legacy-authorities', digest)


def lineage_path(digest):
    return pp._record_path('legacy-lineages', digest)


def blob_path(digest):
    migration._digest(digest, 'legacy blob')
    return f'{pp.ROOT}/legacy-blobs/{digest}.bin'


def _derive(archive, lineage, dirs, policy, modes, expected_modes, **expectations):
    from .legacy_seed import _derive_seed
    from .legacy_posix_terminal import validate_posix_terminal_archive
    from .legacy_windows_terminal import validate_windows_terminal_archive
    body = migration._lineage_structure(migration._record(lineage.raw, migration.LINEAGE_SCHEMA))
    validator = (validate_posix_terminal_archive if body['source_format'] == migration.POSIX_MANAGED_V1
                 else validate_windows_terminal_archive)
    terminal = validator(archive, lineage, directory_paths=dirs, source_policy_raw=policy,
                         **expectations)
    seed = _derive_seed(terminal, lineage, archive, policy, modes, expected_modes)
    if not seed['entries']:
        pp._fail('Empty legacy authority cannot create portable genesis')
    # This policy identifies the genesis receipt, not a reclassification policy.
    seed['genesis_policy_sha256'] = seed['entries'][0]['introduced_policy_sha256']
    return seed


def load_authority(read, owner):
    """Recompute the seed from preserved evidence through the budgeted reader."""
    authority, digest = pp._decode_record(
        read(authority_path(owner['authority_sha256']), maximum=pp.MAX_RECORD_BYTES), SCHEMA, _KEYS)
    if digest != owner['authority_sha256']:
        pp._fail('Legacy authority digest differs')
    for key in ('lineage_sha256', 'source_policy_sha256', 'mode_inventory_sha256'):
        migration._digest(authority[key], key)
    raw = read(lineage_path(authority['lineage_sha256']), maximum=migration.MAX_RECORD_BYTES)
    if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != authority['lineage_sha256']:
        pp._fail('Legacy lineage bytes differ')
    body = migration._lineage_structure(migration._record(raw, migration.LINEAGE_SCHEMA))
    if body['new_project_id'] != owner['project_id']:
        pp._fail('Legacy lineage project differs from portable owner')
    archive = {}
    for item in body['archive']:
        archive[item['path']] = read(blob_path(item['sha256']), maximum=migration.MAX_ARCHIVE_FILE_BYTES,
                                    declared_size=int(item['size_decimal']))
    policy = read(blob_path(authority['source_policy_sha256']), maximum=pp.MAX_RECORD_BYTES)
    modes = read(pp.inventory_path(authority['mode_inventory_sha256']), maximum=pp.MAX_RECORD_BYTES)
    expectations = {f"expected_{a['role']}_sha256": a['sha256'] for a in body['anchors']}
    seed = _derive(archive, migration.LegacyLineage(raw, authority['lineage_sha256']),
                   authority['directory_paths'], policy, modes, authority['mode_inventory_sha256'],
                   approved_lineage_sha256=authority['lineage_sha256'],
                   expected_source_policy_sha256=authority['source_policy_sha256'], **expectations)
    if (authority['origin_map'] != seed['origin_map']
            or authority['projection_sha256'] != canonical_sha256(
                {'entries': seed['entries'], 'inputs': seed['inputs']})):
        pp._fail('Legacy origin or projection differs from replay')
    for policy_digest, expected in seed['policies'].items():
        if read(pp.policy_path(policy_digest), maximum=pp.MAX_RECORD_BYTES) != expected:
            pp._fail('Legacy introducing policy differs from portable policy record')
    return seed


def build_legacy_projection(archive_bytes, lineage, *, directory_paths, source_policy_raw,
                            mode_inventory_raw, expected_modes_sha256, **expectations):
    """Build a candidate from explicitly bound inputs; never read working files.

    Expectations are the approved lineage digest and independent legacy anchor
    and raw policy digests required by the terminal validators. Returned files
    carry historical consistency only, not permission to publish them.
    """
    if type(archive_bytes) is not dict or type(lineage) is not migration.LegacyLineage:
        pp._fail('Fixed archive and explicit lineage are required')
    archive = dict(archive_bytes)
    if type(directory_paths) not in (tuple, list) or not 1 <= len(directory_paths) <= 1024:
        pp._fail('Complete bounded directory inventory is required')
    dirs = tuple(directory_paths)
    seed = _derive(archive, lineage, dirs, source_policy_raw, mode_inventory_raw,
                   expected_modes_sha256, **expectations)
    projection = canonical_sha256({'entries': seed['entries'], 'inputs': seed['inputs']})
    authority = {'schema': SCHEMA, 'lineage_sha256': lineage.sha256,
                 'source_policy_sha256': hashlib.sha256(source_policy_raw).hexdigest(),
                 'mode_inventory_sha256': seed['inventory_sha256'], 'directory_paths': list(dirs),
                 'origin_map': seed['origin_map'], 'projection_sha256': projection}
    authority_sha = canonical_sha256(authority)
    project = lineage.body['new_project_id']
    owner = {'schema': pp.OWNER_SCHEMA, 'project_id': project, 'minimum_reader': 3,
             'authority_kind': 'legacy_projection', 'authority_sha256': authority_sha}
    extra = {lineage_path(lineage.sha256): lineage.raw,
             blob_path(authority['source_policy_sha256']): source_policy_raw}
    extra.update({blob_path(hashlib.sha256(raw).hexdigest()): raw for raw in archive.values()})
    return _projection_files(seed, project, owner, authority, authority_sha, mode_inventory_raw, extra)


def _projection_files(seed, project, owner, authority, authority_sha, mode_inventory_raw, extra):
    projection = authority['projection_sha256']
    owner_sha = canonical_sha256(owner)
    receipt = {'schema': pp.RECEIPT_SCHEMA, 'id': 'R00000001', 'project_id': project,
               'owner_sha256': owner_sha, 'previous_receipt_sha256': None,
               'previous_projection_sha256': None, 'result_projection_sha256': projection,
               'operation': 'naos-migrate', 'inputs': seed['inputs'],
               'selected_paths': [e['path'] for e in seed['entries']],
               'changes': [{'path': e['path'], 'before': None, 'after': e} for e in seed['entries']],
               'policy_sha256': seed['genesis_policy_sha256'],
               'mode_inventory_sha256': seed['inventory_sha256']}
    receipt_sha = canonical_sha256(receipt)
    manifest = {'schema': pp.MANIFEST_SCHEMA, 'project_id': project, 'owner_sha256': owner_sha,
                'previous_head_sha256': None, 'receipts': [{'id': 'R00000001', 'sha256': receipt_sha}],
                'entries': seed['entries'], 'inputs': seed['inputs'],
                'projection_sha256': projection, 'head_receipt_sha256': receipt_sha}
    files = {pp.OWNER_PATH: pp.encode_record(owner), pp.MANIFEST_PATH: pp.encode_record(manifest),
             pp.receipt_path(receipt_sha): pp.encode_record(receipt),
             authority_path(authority_sha): pp.encode_record(authority), **extra,
             pp.inventory_path(seed['inventory_sha256']): mode_inventory_raw,
             **{pp.policy_path(k): v for k, v in seed['policies'].items()}, **seed['bases']}
    class Reader:
        def read(self, path):
            return files.get(path)
    pp.load_portable_snapshot(Reader())
    return files


def build_replay_projection(archive_bytes, lineage, *, directory_paths, source_policy_raw,
                            mode_inventory_raw, expected_modes_sha256, **expectations):
    from . import legacy_replay_projection as replay
    raw_seed = _derive(archive_bytes, lineage, tuple(directory_paths), source_policy_raw,
                       mode_inventory_raw, expected_modes_sha256, **expectations)
    transcript = replay.build(archive_bytes, lineage, directory_paths=directory_paths,
        source_policy_raw=source_policy_raw, mode_inventory_raw=mode_inventory_raw,
        expected_modes_sha256=expected_modes_sha256, **expectations)
    seed = replay.replay_derived(transcript, source_policy_raw=source_policy_raw,
        mode_inventory_raw=mode_inventory_raw, expected_modes_sha256=expected_modes_sha256)
    for key in ('entries', 'inputs', 'policies', 'bases', 'inventory_sha256'):
        if seed[key] != raw_seed[key]:
            pp._fail('Derived replay differs from validated raw semantics: ' + key)
    seed['genesis_policy_sha256'] = seed['entries'][0]['introduced_policy_sha256']
    project = lineage.body['new_project_id']
    extra = {}
    chunks = None
    if len(transcript) > pp.MAX_RECORD_BYTES:
        from . import legacy_replay_storage as storage
        transcript, chunks, blobs, encoding = storage.pack(transcript)
        extra.update({blob_path(digest): raw for digest, raw in blobs.items()})
    tsha = hashlib.sha256(transcript).hexdigest()
    auth = {'schema': REPLAY_SCHEMA, 'lineage_sha256': lineage.sha256,
        'source_policy_sha256': hashlib.sha256(source_policy_raw).hexdigest(),
        'mode_inventory_sha256': seed['inventory_sha256'], 'directory_paths': list(directory_paths),
        'derived_origin_map': _derived_origins(seed['origin_map']),
        'projection_sha256': canonical_sha256({'entries': seed['entries'], 'inputs': seed['inputs']}),
        'transcript_sha256': tsha, 'transcript_size_decimal': str(len(transcript)), 'project_id': project}
    if chunks is None:
        extra[lineage_path(tsha)] = transcript
    else:
        auth.update(schema=FACTORED_REPLAY_SCHEMA, transcript_chunks=chunks, transcript_encoding=encoding)
    extra[blob_path(auth['source_policy_sha256'])] = source_policy_raw
    asha = canonical_sha256(auth)
    owner = {'schema': pp.OWNER_SCHEMA, 'project_id': project, 'minimum_reader': 3,
             'authority_kind': 'legacy_replay_projection', 'authority_sha256': asha}
    return _projection_files(seed, project, owner, auth, asha, mode_inventory_raw, extra)


def decode_replay_authority(raw):
    """Strict version dispatch shared with pure migration-plan consumers."""
    if type(raw) is not bytes or len(raw) > pp.MAX_RECORD_BYTES:
        pp._fail('Missing or oversized derived authority')
    envelope = pp._load_json(raw, 'derived authority')
    body = envelope.get('body') if type(envelope) is dict else None
    schema = body.get('schema') if type(body) is dict else None
    if type(schema) is not str or schema not in REPLAY_SCHEMAS:
        pp._fail('Unsupported derived authority schema')
    return pp._decode_record(raw, schema, FACTORED_REPLAY_KEYS if schema == FACTORED_REPLAY_SCHEMA else REPLAY_KEYS)


def load_replay_authority(read, owner):
    from . import legacy_replay_projection as replay
    auth, sha = decode_replay_authority(read(authority_path(owner['authority_sha256']),
        maximum=pp.MAX_RECORD_BYTES))
    if sha != owner['authority_sha256'] or auth['project_id'] != owner['project_id']:
        pp._fail('Derived legacy authority identity differs')
    for key in ('lineage_sha256','source_policy_sha256','mode_inventory_sha256','transcript_sha256'):
        migration._digest(auth[key], key)
    if auth['schema'] == FACTORED_REPLAY_SCHEMA:
        from . import legacy_replay_storage as storage
        raw = storage.load(read, auth, blob_path)
    else:
        raw = _load_small_transcript(read, auth)
    body = pp._load_json(raw, 'derived transcript')
    if (body['raw_lineage_commitment_sha256'] != auth['lineage_sha256']
            or body['derived_lineage']['new_project_id'] != owner['project_id']
            or body['directory_paths'] != auth['directory_paths']):
        pp._fail('Derived transcript authority binding differs')
    policy = read(blob_path(auth['source_policy_sha256']), maximum=pp.MAX_RECORD_BYTES)
    if type(policy) is not bytes or hashlib.sha256(policy).hexdigest() != auth['source_policy_sha256']:
        pp._fail('Derived source policy bytes differ')
    modes = read(pp.inventory_path(auth['mode_inventory_sha256']), maximum=pp.MAX_RECORD_BYTES)
    seed = replay.replay_derived(raw, source_policy_raw=policy, mode_inventory_raw=modes,
                               expected_modes_sha256=auth['mode_inventory_sha256'])
    if (auth['derived_origin_map'] != _derived_origins(seed['origin_map']) or auth['projection_sha256'] != canonical_sha256(
            {'entries': seed['entries'], 'inputs': seed['inputs']})):
        pp._fail('Derived origin or projection differs from full replay')
    for digest, expected in seed['policies'].items():
        if read(pp.policy_path(digest), maximum=pp.MAX_RECORD_BYTES) != expected:
            pp._fail('Derived introducing policy differs')
    return seed


def _load_small_transcript(read, auth):
    size = auth['transcript_size_decimal']
    if (type(size) is not str or not 1 <= len(size) <= len(str(pp.MAX_RECORD_BYTES))
            or not size.isascii() or not size.isdigit() or str(int(size)) != size
            or not 1 <= int(size) <= pp.MAX_RECORD_BYTES):
        pp._fail('Invalid transcript size')
    raw = read(lineage_path(auth['transcript_sha256']), maximum=pp.MAX_RECORD_BYTES,
               declared_size=int(size))
    if type(raw) is not bytes or len(raw) != int(size) or hashlib.sha256(raw).hexdigest() != auth['transcript_sha256']:
        pp._fail('Derived transcript bytes differ')
    return raw


def _derived_origins(origins):
    """Name derivative receipt hashes only in the new public authority schema."""
    result = {}
    for path, original in origins.items():
        row = dict(original)
        row['derived_introduction_receipt_sha256'] = row.pop('original_introduction_receipt_sha256')
        row['derived_latest_receipt_sha256'] = row.pop('original_latest_receipt_sha256')
        result[path] = row
    return result
