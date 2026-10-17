"""Strict Windows-native managed-content provenance, separate from POSIX v1/v2.

Local hashes establish internal consistency, not cryptographic authorship.
The writer must hold the managed-scope lock and publish records with its
recoverable transaction protocol; this module only builds and validates bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Any, Mapping, Protocol

import yaml

try:
    from ..naos_profile_rules import PROFILE_ORDER
except ImportError:  # Direct checkout import of upgrade_contract.
    from naos_profile_rules import PROFILE_ORDER

from .canonical import canonical_bytes, canonical_sha256, loads_strict_json
from .planner import _validate_source_policy, classify_new_path
from .windows_observation import _relative_parts
from .windows_observation import _parts
from pathlib import Path

ROOT = '.naos\\upgrade-v1\\windows-content'
ROOT_PATH = ROOT + '\\root.json'
OWNER_PATH = ROOT + '\\owner.json'
MANIFEST_PATH = ROOT + '\\manifest.json'
ROOT_SCHEMA = 'naos.upgrade.windows_root_enrollment.v1'
OWNER_SCHEMA = 'naos.upgrade.windows_owner_enrollment.v1'
MANIFEST_SCHEMA = 'naos.upgrade.windows_content_manifest.v1'
BASE_SCHEMA = 'naos.upgrade.windows_content_base.v1'
RECEIPT_SCHEMA = 'naos.upgrade.windows_content_receipt.v1'
HEX64 = re.compile(r'^[0-9a-f]{64}$')
HEX16 = re.compile(r'^[0-9a-f]{16}$')
HEX32 = re.compile(r'^[0-9a-f]{32}$')
MAX_CONTROL_BYTES = 16 * 1024 * 1024
MAX_BASE_ARCHIVE_BYTES = 64 * 1024 * 1024


class WindowsProvenanceError(ValueError):
    """Missing, inconsistent, foreign or unsupported Windows provenance."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _unique_mapping(loader: _UniqueKeyLoader, node: Any) -> dict[Any, Any]:
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise WindowsProvenanceError('Unhashable YAML policy key') from exc
        if duplicate:
            raise WindowsProvenanceError('Duplicate YAML policy key')
        result[key] = loader.construct_object(value_node, deep=True)
    return result


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def strict_policy_load(raw: bytes) -> Any:
    try:
        return yaml.load(raw.decode('utf-8'), Loader=_UniqueKeyLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise WindowsProvenanceError('Invalid source-policy bytes') from exc


class Reader(Protocol):
    def read(self, relative: str) -> bytes | None: ...


class WindowsProvenanceReader:
    """Use WindowsReadObserver's exact held file read for control records."""

    def __init__(self, observer: Any, project_root: str):
        self.observer, self.project_root = observer, project_root
        self._root_bytes = canonical_bytes(_root_identity(observer.root_identity(project_root)))
        self._root_depth = len(_parts(project_root)[1])

    @property
    def root_identity(self) -> dict[str, str]:
        return loads_strict_json(self._root_bytes)

    def read(self, relative: str) -> bytes | None:
        observed, data = self.observer.observe(self.project_root, relative, capture_bytes=True)
        if observed is None:
            raise WindowsProvenanceError('Control observation missing')
        ancestors = observed.get('ancestors')
        if (not isinstance(ancestors, list) or len(ancestors) <= self._root_depth
                or not isinstance(ancestors[self._root_depth], dict)
                or {key: ancestors[self._root_depth].get(key)
                    for key in ('volume_serial_hex', 'file_id_hex')} != self.root_identity):
            raise WindowsProvenanceError('Control record was read under a different project root')
        if observed['presence'] == 'absent':
            return None
        if data is None:
            raise WindowsProvenanceError('Control bytes missing')
        return data


def _hex(value: Any, length: int = 64) -> bool:
    return isinstance(value, str) and len(value) == length and all(c in '0123456789abcdef' for c in value)


def _root_identity(value: Any) -> dict[str, str]:
    if (not isinstance(value, dict) or set(value) != {'volume_serial_hex', 'file_id_hex'}
            or not _hex(value['volume_serial_hex'], 16) or not _hex(value['file_id_hex'], 32)):
        raise WindowsProvenanceError('Invalid native project-root identity')
    return value


def _path(value: Any) -> str:
    if not isinstance(value, str):
        raise WindowsProvenanceError('Invalid managed path')
    try:
        parts = _relative_parts(value)
    except ValueError as exc:
        raise WindowsProvenanceError('Unsafe managed path') from exc
    if not parts or '\\'.join(parts) != value:
        raise WindowsProvenanceError('Noncanonical managed path')
    return value


def _content(value: Any) -> dict[str, str]:
    if (not isinstance(value, dict) or set(value) != {'kind', 'size_decimal', 'sha256', 'metadata_sha256'}
            or value['kind'] != 'file' or not isinstance(value['size_decimal'], str)
            or not value['size_decimal'].isdecimal()
            or str(int(value['size_decimal'])) != value['size_decimal']
            or not _hex(value['sha256']) or not _hex(value['metadata_sha256'])):
        raise WindowsProvenanceError('Invalid native base content identity')
    return value


def encode_record(body: Mapping[str, Any]) -> bytes:
    """Pure fixture/publisher codec; no write is performed."""
    object_body = dict(body)
    return canonical_bytes({'body': object_body, 'sha256': canonical_sha256(object_body)})


def _decode(data: bytes | None, schema: str, keys: set[str]) -> tuple[dict[str, Any], str]:
    if data is None:
        raise WindowsProvenanceError(f'Missing {schema} control record')
    if not isinstance(data, bytes) or len(data) > MAX_CONTROL_BYTES:
        raise WindowsProvenanceError(f'Oversized or invalid {schema} record')
    try:
        envelope = loads_strict_json(data)
        if (not isinstance(envelope, dict) or set(envelope) != {'body', 'sha256'}
                or not isinstance(envelope['body'], dict) or set(envelope['body']) != keys
                or envelope['body']['schema'] != schema or not _hex(envelope['sha256'])
                or canonical_bytes(envelope) != data
                or canonical_sha256(envelope['body']) != envelope['sha256']):
            raise WindowsProvenanceError(f'Invalid {schema} record')
        return envelope['body'], envelope['sha256']
    except (TypeError, KeyError, ValueError) as exc:
        raise WindowsProvenanceError(f'Invalid {schema} bytes') from exc


def base_path(base_sha256: str) -> str:
    if not _hex(base_sha256):
        raise WindowsProvenanceError('Invalid base digest')
    return ROOT + '\\bases\\' + base_sha256 + '.json'


def blob_path(content_sha256: str) -> str:
    if not _hex(content_sha256):
        raise WindowsProvenanceError('Invalid archived base digest')
    return ROOT + '\\base-blobs\\' + content_sha256 + '.bin'


def receipt_path(transaction_id: str) -> str:
    if not isinstance(transaction_id, str) or not re.fullmatch(r'WMC-[0-9a-f]{16}', transaction_id):
        raise WindowsProvenanceError('Invalid Windows transaction ID')
    return ROOT + '\\receipts\\' + transaction_id + '.json'


def policy_catalog(raw: bytes) -> tuple[str, dict[str, dict[str, Any]]]:
    bundle = strict_policy_load(raw)
    if (not isinstance(bundle, dict) or set(bundle) != {'schema', 'active_snapshot', 'snapshots'}
            or bundle['schema'] != 'naos.upgrade.source_policy_bundle.v1'
            or not isinstance(bundle['active_snapshot'], str)
            or not isinstance(bundle['snapshots'], list)):
        raise WindowsProvenanceError('Invalid source-policy bundle')
    catalog: dict[str, dict[str, Any]] = {}
    ids: set[str] = set()
    active = None
    aliases: set[str] = set()
    for item in bundle['snapshots']:
        if not isinstance(item, dict) or set(item) != {'id', 'sha256_aliases', 'policy'}:
            raise WindowsProvenanceError('Invalid source-policy snapshot')
        sid = item['id']
        if not isinstance(sid, str) or not sid or sid in ids:
            raise WindowsProvenanceError('Duplicate source-policy snapshot ID')
        ids.add(sid)
        alias_list = item['sha256_aliases']
        if (not isinstance(alias_list, list) or any(not _hex(x) for x in alias_list)
                or len(alias_list) != len(set(alias_list))):
            raise WindowsProvenanceError('Invalid source-policy aliases')
        policy = _validate_source_policy(item['policy'], snapshot_id=sid)
        digest = canonical_sha256({'snapshot_id': sid, 'policy': policy})
        if digest in catalog or digest in aliases or set(alias_list) & (set(catalog) | aliases):
            raise WindowsProvenanceError('Ambiguous source-policy binding')
        aliases.update(alias_list)
        catalog[digest] = policy
        if sid == bundle['active_snapshot']:
            active = digest
    if active is None:
        raise WindowsProvenanceError('Active source policy missing')
    return active, catalog


@dataclass(frozen=True)
class ValidatedWindowsProvenance:
    """Keep validated nested state as immutable bytes; accessors return copies.

    This prevents a consumer's in-process edits from silently changing the
    history used by a later publisher. It does not authenticate local authors.
    """
    project_id: str
    _root_bytes: bytes
    owner_sha256: str
    active_policy_sha256: str
    manifest_sha256: str
    _entries_bytes: bytes
    _manifest_bytes: bytes

    @property
    def root_identity(self) -> dict[str, str]:
        return loads_strict_json(self._root_bytes)

    @property
    def entries(self) -> dict[str, dict[str, Any]]:
        return loads_strict_json(self._entries_bytes)

    @property
    def manifest(self) -> dict[str, Any]:
        return loads_strict_json(self._manifest_bytes)

    @property
    def previous_inputs(self) -> dict[str, Any] | None:
        request = self.manifest['last_request']
        return request['inputs'] if request is not None else None


_ROOT_KEYS = {'schema', 'project_id', 'root_identity', 'enrollment_plan_sha256'}
_OWNER_KEYS = {'schema', 'project_id', 'root_identity', 'root_enrollment_sha256',
               'source_policy_snapshot_sha256', 'owner_kind'}
_MANIFEST_KEYS = {'schema', 'project_id', 'root_identity', 'owner_sha256',
                  'source_policy_snapshot_sha256', 'receipts', 'entries', 'last_request'}
_BASE_KEYS = {'schema', 'path', 'content', 'archive_sha256', 'archive_size_decimal',
              'ownership', 'creation_policy',
              'introduced_policy_sha256', 'transaction_id'}
_RECEIPT_KEYS = {'schema', 'transaction_id', 'project_id', 'root_identity', 'owner_sha256',
                 'source_policy_snapshot_sha256', 'previous_receipt_sha256',
                 'plan_sha256', 'changes', 'request'}
_ENTRY_KEYS = {'path', 'base_sha256', 'receipt_sha256', 'ownership',
               'creation_policy', 'introduced_policy_sha256'}
_CHANGE_KEYS = _ENTRY_KEYS - {'receipt_sha256'}


def _request(value: Any, previous: dict[str, Any] | None) -> dict[str, Any]:
    """Preserve onboarding choices across native managed operations."""
    if (not isinstance(value, dict) or set(value) != {'operation', 'inputs'}
            or not isinstance(value['operation'], str) or not isinstance(value['inputs'], dict)):
        raise WindowsProvenanceError('Invalid managed request binding')
    operation, inputs = value['operation'], value['inputs']
    if (inputs.get('mode') not in {'greenfield', 'brownfield'}
            or inputs.get('profile') not in PROFILE_ORDER
            or any(not isinstance(inputs.get(key), str) or not inputs[key]
                   for key in ('archetype', 'backend', 'memory_choice'))
            or (inputs['mode'] == 'brownfield'
                and not isinstance(inputs.get('repository_intelligence'), dict))):
        raise WindowsProvenanceError('Incomplete preserved initialization inputs')
    if previous is None:
        if operation != 'naos-init':
            raise WindowsProvenanceError('First managed receipt must bind initialization')
    elif operation == 'naos-upgrade-profile-transition':
        if {k: v for k, v in inputs.items() if k != 'profile'} != {
                k: v for k, v in previous['inputs'].items() if k != 'profile'}:
            raise WindowsProvenanceError('Profile transition changed preserved initialization choices')
    elif (operation == 'naos-init' or operation.startswith('naos-add-artifact:')
          or operation.startswith('naos-add-setup-module:')):
        if inputs != previous['inputs']:
            raise WindowsProvenanceError('Managed request changed preserved initialization choices')
    else:
        raise WindowsProvenanceError('Unsupported managed request operation')
    return loads_strict_json(canonical_bytes(value))


def load_windows_provenance(reader: Reader, *, root_identity: Mapping[str, str],
                            source_policy_raw: bytes) -> ValidatedWindowsProvenance:
    try:
        return _load_windows_provenance(reader, root_identity=root_identity,
                                        source_policy_raw=source_policy_raw)
    except WindowsProvenanceError:
        raise
    except (TypeError, KeyError, ValueError, OverflowError) as exc:
        raise WindowsProvenanceError('Invalid Windows provenance value') from exc


def _load_windows_provenance(reader: Reader, *, root_identity: Mapping[str, str],
                             source_policy_raw: bytes) -> ValidatedWindowsProvenance:
    """Validate enrollment, complete receipt chain, all bases and ownership."""
    expected_root = _root_identity(dict(root_identity))
    if isinstance(reader, WindowsProvenanceReader) and reader.root_identity != expected_root:
        raise WindowsProvenanceError('Control reader root differs from requested root')
    active_policy, policies = policy_catalog(source_policy_raw)
    root, root_sha = _decode(reader.read(ROOT_PATH), ROOT_SCHEMA, _ROOT_KEYS)
    if (not isinstance(root['project_id'], str) or not root['project_id']
            or root['root_identity'] != expected_root or not _hex(root['enrollment_plan_sha256'])):
        raise WindowsProvenanceError('Foreign or invalid root enrollment')
    owner, owner_sha = _decode(reader.read(OWNER_PATH), OWNER_SCHEMA, _OWNER_KEYS)
    if (owner['project_id'] != root['project_id'] or owner['root_identity'] != expected_root
            or owner['root_enrollment_sha256'] != root_sha
            or not _hex(owner['source_policy_snapshot_sha256'])
            or owner['source_policy_snapshot_sha256'] not in policies
            or owner['owner_kind'] != 'naos_windows_managed_content'):
        raise WindowsProvenanceError('Foreign or invalid owner enrollment')
    manifest, manifest_sha = _decode(reader.read(MANIFEST_PATH), MANIFEST_SCHEMA, _MANIFEST_KEYS)
    if (manifest['project_id'] != root['project_id'] or manifest['root_identity'] != expected_root
            or manifest['owner_sha256'] != owner_sha
            or not _hex(manifest['source_policy_snapshot_sha256'])
            or manifest['source_policy_snapshot_sha256'] not in policies
            or not isinstance(manifest['receipts'], list)
            or not isinstance(manifest['entries'], list)):
        raise WindowsProvenanceError('Foreign or invalid Windows manifest')
    reconstructed: dict[str, dict[str, Any]] = {}
    spelling_by_fold: dict[str, str] = {}
    previous_receipt = None
    previous_request = None
    seen_ids: set[str] = set()
    for ref in manifest['receipts']:
        if (not isinstance(ref, dict) or set(ref) != {'transaction_id', 'sha256'}
                or not isinstance(ref['transaction_id'], str)
                or not re.fullmatch(r'WMC-[0-9a-f]{16}', ref['transaction_id'])
                or not _hex(ref['sha256']) or ref['transaction_id'] in seen_ids):
            raise WindowsProvenanceError('Invalid receipt index')
        transaction_id = ref['transaction_id']
        seen_ids.add(transaction_id)
        receipt, receipt_sha = _decode(reader.read(receipt_path(transaction_id)),
                                       RECEIPT_SCHEMA, _RECEIPT_KEYS)
        if (receipt_sha != ref['sha256'] or receipt['transaction_id'] != transaction_id
                or receipt['project_id'] != root['project_id']
                or receipt['root_identity'] != expected_root
                or receipt['owner_sha256'] != owner_sha
                or not _hex(receipt['source_policy_snapshot_sha256'])
                or receipt['source_policy_snapshot_sha256'] not in policies
                or receipt['previous_receipt_sha256'] != previous_receipt
                or not _hex(receipt['plan_sha256'])
                or not isinstance(receipt['changes'], list) or not receipt['changes']):
            raise WindowsProvenanceError('Invalid committed receipt chain')
        previous_receipt = receipt_sha
        previous_request = _request(receipt['request'], previous_request)
        changed: set[str] = set()
        for change in receipt['changes']:
            if not isinstance(change, dict) or set(change) != _CHANGE_KEYS:
                raise WindowsProvenanceError('Invalid receipt change')
            path = _path(change['path'])
            folded = path.casefold()
            if folded in spelling_by_fold and spelling_by_fold[folded] != path:
                raise WindowsProvenanceError('Aliased Windows managed paths')
            spelling_by_fold[folded] = path
            if path in changed or not _hex(change['base_sha256']):
                raise WindowsProvenanceError('Duplicate or unbound receipt change')
            changed.add(path)
            base, base_sha = _decode(reader.read(base_path(change['base_sha256'])), BASE_SCHEMA, _BASE_KEYS)
            if (base_sha != change['base_sha256'] or base['path'] != path
                    or base['transaction_id'] != transaction_id
                    or base['ownership'] != change['ownership']
                    or base['creation_policy'] != change['creation_policy']
                    or base['introduced_policy_sha256'] != change['introduced_policy_sha256']):
                raise WindowsProvenanceError('Base/receipt binding differs')
            _content(base['content'])
            if (base['archive_sha256'] != base['content']['sha256']
                    or base['archive_size_decimal'] != base['content']['size_decimal']):
                raise WindowsProvenanceError('Base descriptor/archive binding differs')
            archive = reader.read(blob_path(base['archive_sha256']))
            if (not isinstance(archive, bytes) or len(archive) > MAX_BASE_ARCHIVE_BYTES
                    or str(len(archive)) != base['archive_size_decimal']
                    or hashlib.sha256(archive).hexdigest() != base['archive_sha256']):
                raise WindowsProvenanceError('Historical base archive missing or altered')
            prior = reconstructed.get(path)
            if prior is None:
                policy_digest = base['introduced_policy_sha256']
                if (not _hex(policy_digest) or policy_digest not in policies
                        or policy_digest != receipt['source_policy_snapshot_sha256']):
                    raise WindowsProvenanceError('Historical source policy unavailable')
                rule = classify_new_path(Path(*_relative_parts(path)), policies[policy_digest])
                if (base['ownership'] != rule['ownership'] or
                        base['creation_policy'] != rule['creation_policy']):
                    raise WindowsProvenanceError('Ownership escalation from source policy')
            elif (prior['ownership'] != 'kit_owned_derived' or
                  base['ownership'] != prior['ownership'] or
                  base['creation_policy'] != prior['creation_policy'] or
                  base['introduced_policy_sha256'] != prior['introduced_policy_sha256']):
                raise WindowsProvenanceError('Unauthorized historical update or ownership change')
            reconstructed[path] = {**change, 'receipt_sha256': receipt_sha,
                                   'content': base['content']}
    entries = manifest['entries']
    if manifest['last_request'] != previous_request:
        raise WindowsProvenanceError('Manifest initialization inputs differ from receipt history')
    if (any(not isinstance(e, dict) or set(e) != _ENTRY_KEYS for e in entries)
            or entries != [ {k: v for k, v in reconstructed[path].items() if k != 'content'}
                            for path in sorted(reconstructed)]):
        raise WindowsProvenanceError('Manifest entries differ from committed receipts')
    return ValidatedWindowsProvenance(root['project_id'], canonical_bytes(expected_root), owner_sha,
                                      active_policy, manifest_sha, canonical_bytes(reconstructed),
                                      canonical_bytes(manifest))


def make_empty_enrollment(*, project_id: str, root_identity: Mapping[str, str],
                          enrollment_plan_sha256: str, source_policy_snapshot_sha256: str) -> dict[str, bytes]:
    """Pure initial publisher fixture: all three records must be published together."""
    identity = _root_identity(dict(root_identity))
    if not isinstance(project_id, str) or not project_id or not _hex(enrollment_plan_sha256) or not _hex(source_policy_snapshot_sha256):
        raise WindowsProvenanceError('Invalid enrollment input')
    root = {'schema': ROOT_SCHEMA, 'project_id': project_id, 'root_identity': identity,
            'enrollment_plan_sha256': enrollment_plan_sha256}
    root_bytes = encode_record(root)
    owner = {'schema': OWNER_SCHEMA, 'project_id': project_id, 'root_identity': identity,
             'root_enrollment_sha256': canonical_sha256(root),
             'source_policy_snapshot_sha256': source_policy_snapshot_sha256,
             'owner_kind': 'naos_windows_managed_content'}
    owner_bytes = encode_record(owner)
    manifest = {'schema': MANIFEST_SCHEMA, 'project_id': project_id, 'root_identity': identity,
                'owner_sha256': canonical_sha256(owner),
                'source_policy_snapshot_sha256': source_policy_snapshot_sha256,
                'receipts': [], 'entries': [], 'last_request': None}
    return {ROOT_PATH: root_bytes, OWNER_PATH: owner_bytes,
            MANIFEST_PATH: encode_record(manifest)}


def make_commit_records(snapshot: ValidatedWindowsProvenance, *,
                        transaction_id: str, plan_sha256: str,
                        changes: Mapping[str, Mapping[str, Any]],
                        source_policy_raw: bytes, request: Mapping[str, Any]) -> dict[str, bytes]:
    """Build exact base/receipt/manifest bytes for a committed transaction.

    Caller must bind these bytes to a journaled publisher and a scope lock.
    Existing paths retain ownership and can only publish kit-owned updates.
    """
    receipt_path(transaction_id)
    if not _hex(plan_sha256) or not changes:
        raise WindowsProvenanceError('Invalid committed plan or empty changes')
    if any(not isinstance(path, str) for path in changes) or len(changes) != len({path.casefold() for path in changes}):
        raise WindowsProvenanceError('Aliased Windows changes')
    active, policies = policy_catalog(source_policy_raw)
    if active != snapshot.active_policy_sha256:
        raise WindowsProvenanceError('Source policy changed after validation')
    manifest_before, entries_before = snapshot.manifest, snapshot.entries
    bound_request = _request(dict(request), manifest_before['last_request'])
    if any(ref['transaction_id'] == transaction_id for ref in manifest_before['receipts']):
        raise WindowsProvenanceError('Transaction ID already committed')
    files: dict[str, bytes] = {}
    receipt_changes: list[dict[str, str]] = []
    latest_entries = {path: {k: v for k, v in entry.items() if k != 'content'}
                      for path, entry in entries_before.items()}
    for path in sorted(changes):
        _path(path)
        if any(path.casefold() == existing.casefold() and path != existing
               for existing in entries_before):
            raise WindowsProvenanceError('Aliased Windows managed path')
        change_input = changes[path]
        if not isinstance(change_input, Mapping) or set(change_input) != {'content', 'archive_bytes'}:
            raise WindowsProvenanceError('Publisher requires content and exact archived bytes')
        content = _content(dict(change_input['content']))
        archive = change_input['archive_bytes']
        if (not isinstance(archive, bytes) or len(archive) > MAX_BASE_ARCHIVE_BYTES
                or str(len(archive)) != content['size_decimal']
                or hashlib.sha256(archive).hexdigest() != content['sha256']):
            raise WindowsProvenanceError('Archived base bytes differ from content identity')
        files[blob_path(content['sha256'])] = archive
        prior = entries_before.get(path)
        if prior is None:
            rule = classify_new_path(Path(*_relative_parts(path)), policies[active])
            ownership, creation_policy, introduced = (rule['ownership'],
                    rule['creation_policy'], active)
        else:
            if prior['ownership'] != 'kit_owned_derived':
                raise WindowsProvenanceError('Adopter-owned base cannot be replaced')
            ownership, creation_policy, introduced = (prior['ownership'],
                    prior['creation_policy'], prior['introduced_policy_sha256'])
        base = {'schema': BASE_SCHEMA, 'path': path, 'content': content,
                'archive_sha256': content['sha256'],
                'archive_size_decimal': content['size_decimal'],
                'ownership': ownership, 'creation_policy': creation_policy,
                'introduced_policy_sha256': introduced,
                'transaction_id': transaction_id}
        digest = canonical_sha256(base)
        files[base_path(digest)] = encode_record(base)
        receipt_changes.append({'path': path, 'base_sha256': digest,
                                'ownership': ownership, 'creation_policy': creation_policy,
                                'introduced_policy_sha256': introduced})
    previous_receipt = (manifest_before['receipts'][-1]['sha256']
                        if manifest_before['receipts'] else None)
    receipt = {'schema': RECEIPT_SCHEMA, 'transaction_id': transaction_id,
               'project_id': snapshot.project_id, 'root_identity': snapshot.root_identity,
               'owner_sha256': snapshot.owner_sha256,
               'source_policy_snapshot_sha256': active,
               'previous_receipt_sha256': previous_receipt,
               'plan_sha256': plan_sha256, 'changes': receipt_changes, 'request': bound_request}
    receipt_sha = canonical_sha256(receipt)
    files[receipt_path(transaction_id)] = encode_record(receipt)
    for change in receipt_changes:
        latest_entries[change['path']] = {**change, 'receipt_sha256': receipt_sha}
    manifest = {'schema': MANIFEST_SCHEMA, 'project_id': snapshot.project_id,
                'root_identity': snapshot.root_identity,
                'owner_sha256': snapshot.owner_sha256,
                'source_policy_snapshot_sha256': active,
                'receipts': [*manifest_before['receipts'],
                             {'transaction_id': transaction_id, 'sha256': receipt_sha}],
                'entries': [latest_entries[path] for path in sorted(latest_entries)],
                'last_request': bound_request}
    files[MANIFEST_PATH] = encode_record(manifest)
    return files
