"""Pure legacy-to-portable genesis seed projection; no filesystem authority.

The caller must separately establish native custody and freshly validate the
terminal archive. This helper only maps structurally validated history and an
independently approved mode inventory to canonical portable genesis inputs.
"""
from __future__ import annotations

import hashlib

from . import legacy_migration_records as migration
from . import legacy_posix_terminal, legacy_windows_terminal
from . import legacy_posix_replay
from . import planner, portable_provenance as pp, windows_provenance
from .canonical import loads_strict_json

GENESIS_RECEIPT = 'R00000001'
_POSIX_BASES = '.naos/upgrade-v1/managed-content/state/bases/'


class LegacySeedError(ValueError):
    """A terminal source cannot be represented as the requested portable seed."""


def _raw_base(archive, source_path, digest, size, cache):
    key = (source_path, digest, size)
    if key in cache:
        return cache[key]
    raw = archive.get(source_path)
    if (type(raw) is not bytes or type(size) is not int or type(size) is bool
            or len(raw) != size or hashlib.sha256(raw).hexdigest() != digest):
        raise LegacySeedError('Exact archived current base bytes differ')
    cache[key] = raw
    return raw


def _posix_rows(terminal, archive, policy_value, policy_raw):
    snapshot = terminal.replay.snapshot
    manifest_path = migration._ANCHORS[migration.POSIX_MANAGED_V1]['head']
    manifest = loads_strict_json(archive[manifest_path])
    transaction = {ref['transaction_id']: ref for ref in manifest['transactions']}
    originals = []
    base_cache = {}
    policies = {}
    selected_by_binding = {}
    policy_work = 0
    encoded_by_binding = {}
    for row in snapshot['entries']:
        path = row['path']
        intro = row['introduced_by_transaction']
        latest = row.get('last_mutated_by_transaction', intro)
        plan = transaction[intro]['plan']
        if plan['schema'] in {'naos.upgrade.create_only_plan.v1', 'naos.upgrade.create_only_plan.v2'}:
            binding = plan['source_policy_sha256']
        else:
            binding = plan['source_policy']['active']['binding_sha256']
        if binding not in selected_by_binding:
            policy_work += len(policy_raw)
            if policy_work > legacy_posix_replay.MAX_POLICY_WORK_BYTES:
                raise LegacySeedError('Historical source-policy resolution exceeds byte budget')
            selected_by_binding[binding] = planner._source_policy_snapshot_from_value(
                policy_value, policy_raw, expected_sha256=binding)
        selected = selected_by_binding[binding]
        if binding not in encoded_by_binding:
            encoded_by_binding[binding] = pp.encode_policy(selected.snapshot_id, selected.policy)
        canonical, policy_bytes = encoded_by_binding[binding]
        policies[canonical] = policy_bytes
        base = row['base']
        if base['kind'] != 'file' or type(base['mode']) is not int:
            raise LegacySeedError('POSIX current base is not a regular file with exact mode')
        raw = _raw_base(archive, _POSIX_BASES + base['sha256'], base['sha256'], base['size'], base_cache)
        originals.append((path, raw, bool(base['mode'] & 0o111), row['ownership'],
                          row['creation_policy'], canonical, {
                              'source_format': migration.POSIX_MANAGED_V1,
                              'original_introduced_by_transaction': intro,
                              'original_introduction_receipt_sha256': transaction[intro]['receipt_sha256'],
                              'original_latest_transaction': latest,
                              'original_latest_receipt_sha256': transaction[latest]['receipt_sha256'],
                              'original_policy_binding_sha256': binding,
                              'resolved_policy_snapshot_id': selected.snapshot_id,
                              'canonical_policy_sha256': canonical,
                          }))
    return originals, policies, snapshot['previous_inputs']


def _windows_rows(terminal, archive, policy_raw):
    snapshot = terminal.replay.snapshot
    policy_value = windows_provenance.strict_policy_load(policy_raw)
    _active, catalog = windows_provenance.policy_catalog(policy_raw)
    if type(policy_value) is not dict or type(policy_value.get('snapshots')) is not list:
        raise LegacySeedError('Windows source policy catalog is incomplete')
    policies = {}
    policy_ids = {}
    for record in policy_value['snapshots']:
        canonical, policy_bytes = pp.encode_policy(record['id'], record['policy'])
        if canonical not in catalog:
            raise LegacySeedError('Windows policy catalog and canonical policy differ')
        policies[canonical] = policy_bytes
        policy_ids[canonical] = record['id']
    origin = {}
    for ref in snapshot.manifest['receipts']:
        txid = ref['transaction_id']
        receipt_path = windows_provenance.receipt_path(txid).replace('\\', '/')
        receipt, receipt_sha = windows_provenance._decode(
            archive[receipt_path], windows_provenance.RECEIPT_SCHEMA,
            windows_provenance._RECEIPT_KEYS)
        for change in receipt['changes']:
            path = change['path']
            prior = origin.get(path)
            origin[path] = (prior[0] if prior else txid,
                            prior[1] if prior else receipt_sha,
                            txid, receipt_sha,
                            prior[4] if prior else change['introduced_policy_sha256'])
    originals = []
    base_cache = {}
    for path, row in snapshot.entries.items():
        portable_path = path.replace('\\', '/')
        digest = row['base_sha256']
        base_path = windows_provenance.base_path(digest).replace('\\', '/')
        base, _ = windows_provenance._decode(
            archive[base_path], windows_provenance.BASE_SCHEMA, windows_provenance._BASE_KEYS)
        content = base['content']
        blob_path = windows_provenance.blob_path(content['sha256']).replace('\\', '/')
        raw = _raw_base(archive, blob_path, content['sha256'], int(content['size_decimal']), base_cache)
        intro, intro_receipt_sha, latest, receipt_sha, binding = origin[path]
        if binding != row['introduced_policy_sha256'] or binding not in policies:
            raise LegacySeedError('Windows introduction policy lineage differs')
        originals.append((portable_path, raw, None, row['ownership'],
                          row['creation_policy'], binding, {
                              'source_format': migration.WINDOWS_CONTENT_V1,
                              'original_introduced_by_transaction': intro,
                              'original_introduction_receipt_sha256': intro_receipt_sha,
                              'original_latest_transaction': latest,
                              'original_latest_receipt_sha256': receipt_sha,
                              'original_policy_binding_sha256': binding,
                              'resolved_policy_snapshot_id': policy_ids[binding],
                              'canonical_policy_sha256': binding,
                          }))
    return originals, policies, snapshot.previous_inputs


def _derive_seed(terminal, lineage, archive, source_policy_raw,
                 mode_inventory_raw, expected_modes_sha256):
    """Return canonical portable genesis entries, policies, bases and lineage."""
    try:
        if (type(archive) is not dict or type(source_policy_raw) is not bytes
                or type(lineage) is not migration.LegacyLineage
                or type(mode_inventory_raw) is not bytes):
            raise LegacySeedError('Exact approved source and mode bytes are required')
        migration._digest(expected_modes_sha256, 'mode inventory')
        if (type(terminal) not in (legacy_posix_terminal.LegacyPosixTerminal,
                                   legacy_windows_terminal.LegacyWindowsTerminal)
                or terminal.replay.lineage_sha256 != lineage.sha256
                or hashlib.sha256(source_policy_raw).hexdigest() != terminal.replay.source_policy_sha256
                or terminal.native_custody_proven or terminal.mutation_authorized):
            raise LegacySeedError('Freshly validated structural terminal binding is required')
        body, observed_modes_sha256 = pp._decode_record(
            mode_inventory_raw, pp.MODE_INVENTORY_SCHEMA, {'schema', 'items'})
        if observed_modes_sha256 != expected_modes_sha256:
            raise LegacySeedError('Mode inventory differs from independent digest')
        modes = pp._mode_inventory(body)
        policy_value = windows_provenance.strict_policy_load(source_policy_raw)
        if type(terminal) is legacy_posix_terminal.LegacyPosixTerminal:
            originals, policies, inputs = _posix_rows(
                terminal, archive, policy_value, source_policy_raw)
        else:
            originals, policies, inputs = _windows_rows(terminal, archive, source_policy_raw)
        pp._inputs_shape(inputs)
        paths = [row[0] for row in originals]
        pp._unique_paths(paths)
        if set(paths) != set(modes):
            raise LegacySeedError('Mode inventory does not exactly cover legacy seed paths')
        entries, bases, origin_map = [], {}, {}
        projected_bytes = 0
        for path, raw, posix_executable, ownership, creation_policy, policy_sha, origin in sorted(originals):
            projected_bytes += len(raw)
            if projected_bytes > pp.MAX_CUMULATIVE_READ_BYTES:
                raise LegacySeedError('Cumulative seed byte work exceeds budget')
            item = modes[path]
            digest = hashlib.sha256(raw).hexdigest()
            size = str(len(raw))
            if (item['source_sha256'] != digest or item['output_sha256'] != digest
                    or item['source_size_decimal'] != size
                    or item['output_size_decimal'] != size
                    or posix_executable is not None and item['executable'] != posix_executable):
                raise LegacySeedError('Mode intent does not bind byte-identical current legacy base')
            entry = {'path': path,
                     'content': {'kind': 'file', 'sha256': digest,
                                 'size_decimal': size, 'executable': item['executable']},
                     'ownership': ownership, 'creation_policy': creation_policy,
                     'introduced_policy_sha256': policy_sha,
                     'introduced_by': GENESIS_RECEIPT,
                     'latest_base_receipt': GENESIS_RECEIPT}
            pp._entry(entry, path)
            entries.append(entry)
            bases[pp.base_path(digest)] = raw
            origin_map[path] = origin
        if [item['path'] for item in entries] != sorted(paths):
            raise LegacySeedError('Legacy seed path ordering differs')
        return {'entries': entries, 'inputs': inputs, 'origin_map': origin_map,
                'policies': policies, 'bases': bases,
                'inventory_sha256': observed_modes_sha256}
    except LegacySeedError:
        raise
    except (migration.LegacyMigrationRecordError, pp.PortableProvenanceError,
            planner.ContentPlanningError, windows_provenance.WindowsProvenanceError,
            KeyError, TypeError, ValueError, AttributeError, OverflowError) as exc:
        raise LegacySeedError(f'Legacy seed derivation refused: {exc}') from exc
