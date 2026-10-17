"""Pure structural records for an explicitly reviewed legacy-to-v3 migration.

No record here validates legacy source semantics, native quiescence, checkout
ownership, or permission to mutate. A native inspector must prove complete
inventory and replay before any lineage or fence can be published.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
import uuid
from typing import Mapping

from .canonical import canonical_bytes, loads_strict_json
from . import local_binding as lb
from . import portable_provenance as pp

LINEAGE_SCHEMA = 'naos.upgrade.legacy_migration_lineage.v1'
FENCE_SCHEMA = 'naos.upgrade.legacy_migration_fence.v1'
POSIX_MANAGED_V1 = 'posix_managed_v1'
WINDOWS_CONTENT_V1 = 'windows_content_v1'
MAX_ARCHIVE_FILES = 10_000
MAX_ARCHIVE_FILE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_RECORD_BYTES = 16 * 1024 * 1024
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')
_ANCHORS = {
    POSIX_MANAGED_V1: {
        'owner': '.naos/upgrade-v1/OWNER.json',
        'scope': '.naos/upgrade-v1/managed-content/scope.json',
        'head': '.naos/upgrade-v1/managed-content/state/manifest.json',
    },
    WINDOWS_CONTENT_V1: {
        'owner': '.naos/upgrade-v1/windows-content/owner.json',
        'scope': '.naos/upgrade-v1/windows-content/root.json',
        'head': '.naos/upgrade-v1/windows-content/manifest.json',
    },
}
_FENCE_POINTER = {
    POSIX_MANAGED_V1: _ANCHORS[POSIX_MANAGED_V1]['scope'],
    WINDOWS_CONTENT_V1: _ANCHORS[WINDOWS_CONTENT_V1]['owner'],
}


class LegacyMigrationRecordError(ValueError):
    """Malformed structural record or mismatch with explicit source bytes."""


def _fail(message: str) -> None:
    raise LegacyMigrationRecordError(message)


def _digest(value: object, label: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        _fail(f'Invalid {label} digest')
    return value


def _uuid4(value: object) -> str:
    if type(value) is not str:
        _fail('New portable project ID must be a canonical UUID4')
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise LegacyMigrationRecordError('New portable project ID must be a canonical UUID4') from exc
    if parsed.version != 4 or str(parsed) != value:
        _fail('New portable project ID must be a canonical UUID4')
    return value


def _original_id(value: object) -> str:
    # The source inspector must bind these unchanged characters to its schema.
    if type(value) is not str or any(ord(char) < 32 or ord(char) == 127 for char in value):
        _fail('Invalid original project ID text')
    try:
        size = len(value.encode('utf-8'))
    except UnicodeEncodeError as exc:
        raise LegacyMigrationRecordError('Invalid original project ID text') from exc
    if not 1 <= size <= 128:
        _fail('Invalid original project ID text')
    return value


def _path(value: object, source_format: str) -> str:
    if type(value) is not str:
        _fail('Archive path must be text')
    try:
        size = len(value.encode('utf-8'))
    except UnicodeEncodeError as exc:
        raise LegacyMigrationRecordError('Archive path must be valid UTF-8') from exc
    if not 1 <= size <= 2048:
        _fail('Archive path must be text')
    components = value.split('/')
    if (len(components) > 128 or any(not component or component in {'.', '..'}
                                      or component.endswith((' ', '.'))
                                      or len(component.encode('utf-16-le')) > 510
                                      or pp.WINDOWS_RESERVED.match(component)
                                      or any(char in '<>"|?*\\:' or ord(char) < 32
                                             or 0xD800 <= ord(char) <= 0xDFFF
                                             for char in component)
                                      for component in components)):
        _fail('Unsafe archive path')
    allowed = (value == _ANCHORS[POSIX_MANAGED_V1]['owner']
               or value.startswith('.naos/upgrade-v1/managed-content/')) if source_format == POSIX_MANAGED_V1 else (
               value.startswith('.naos/upgrade-v1/windows-content/'))
    if not allowed:
        _fail('Archive path is outside the selected legacy managed scope')
    return value


def _archive_inventory(archive_bytes: Mapping[str, bytes], source_format: str) -> list[dict[str, str]]:
    if type(archive_bytes) is not dict or not 3 <= len(archive_bytes) <= MAX_ARCHIVE_FILES:
        _fail('Archive inventory has unsupported count')
    if any(type(path) is not str for path in archive_bytes):
        _fail('Archive path must be text')
    inventory = []
    aliases: set[str] = set()
    total = 0
    for path in sorted(archive_bytes):
        _path(path, source_format)
        alias = path.casefold()
        if alias in aliases:
            _fail('Case-aliased archive path')
        aliases.add(alias)
        raw = archive_bytes[path]
        if type(raw) is not bytes or len(raw) > MAX_ARCHIVE_FILE_BYTES:
            _fail('Archive member bytes are absent or oversized')
        total += len(raw)
        if total > MAX_ARCHIVE_BYTES:
            _fail('Cumulative archive bytes exceed budget')
        inventory.append({'path': path, 'sha256': hashlib.sha256(raw).hexdigest(),
                          'size_decimal': str(len(raw))})
    if not set(_ANCHORS[source_format].values()) <= set(archive_bytes):
        _fail('Required source anchor bytes are absent')
    return inventory


def _lineage_structure(body: object) -> dict:
    """Check every self-contained invariant, including forged typed inputs."""
    if (type(body) is not dict or set(body) != {
            'schema', 'source_format', 'original_project_id', 'new_project_id',
            'anchors', 'archive'} or body['schema'] != LINEAGE_SCHEMA):
        _fail('Unexpected lineage shape or schema')
    source_format = body['source_format']
    if type(source_format) is not str or source_format not in _ANCHORS:
        _fail('Unsupported legacy source format')
    _original_id(body['original_project_id'])
    _uuid4(body['new_project_id'])
    items = body['archive']
    if type(items) is not list or not 3 <= len(items) <= MAX_ARCHIVE_FILES:
        _fail('Archive inventory has unsupported count')
    by_path = {}
    aliases = []
    total = 0
    previous = ''
    for item in items:
        if type(item) is not dict or set(item) != {'path', 'sha256', 'size_decimal'}:
            _fail('Malformed archive member')
        path = _path(item['path'], source_format)
        if path <= previous:
            _fail('Archive paths are duplicate or out of order')
        previous = path
        _digest(item['sha256'], 'archive member')
        size = item['size_decimal']
        if (type(size) is not str or not 1 <= len(size) <= 20 or not size.isascii()
                or not size.isdecimal() or str(int(size)) != size):
            _fail('Invalid archive member size')
        amount = int(size)
        if amount > MAX_ARCHIVE_FILE_BYTES:
            _fail('Archive member exceeds byte budget')
        total += amount
        if total > MAX_ARCHIVE_BYTES:
            _fail('Cumulative archive bytes exceed budget')
        aliases.append(path.casefold())
        by_path[path] = item
    alias_set = set(aliases)
    if len(alias_set) != len(aliases):
        _fail('Archive paths alias')
    # Lexical neighbors are insufficient: tree-sibling sorts between a file
    # named tree and tree/child. Check every component prefix explicitly.
    for alias in aliases:
        parts = alias.split('/')
        if any('/'.join(parts[:end]) in alias_set for end in range(1, len(parts))):
            _fail('Archive contains a file-prefix collision')
    anchors = body['anchors']
    if type(anchors) is not list or len(anchors) != 3:
        _fail('Missing fixed source anchors')
    for anchor, role in zip(anchors, ('owner', 'scope', 'head')):
        path = _ANCHORS[source_format][role]
        if (type(anchor) is not dict or set(anchor) != {'role', 'path', 'sha256'}
                or anchor['role'] != role or anchor['path'] != path
                or path not in by_path or anchor['sha256'] != by_path[path]['sha256']):
            _fail('Source anchor differs from fixed path or archive digest')
    return body


def _record(raw: bytes, schema: str) -> dict:
    if type(raw) is not bytes or len(raw) > MAX_RECORD_BYTES:
        _fail('Missing or oversized migration record')
    try:
        body = pp._load_json(raw, 'legacy migration record')
        lb._bounded_input(body)
        if canonical_bytes(body) != raw:
            _fail('Migration record is not canonical')
    except (ValueError, TypeError, RecursionError, OverflowError) as exc:
        raise LegacyMigrationRecordError('Invalid migration record JSON') from exc
    if type(body) is not dict or body.get('schema') != schema:
        _fail('Unsupported migration record schema')
    return body


@dataclass(frozen=True)
class LegacyLineage:
    raw: bytes
    sha256: str
    # Immutable private adjunct; never encoded in the raw lineage wire record.
    _raw_archive: tuple[tuple[str, bytes], ...] = ()
    _raw_policy: bytes | None = None
    _raw_modes: bytes | None = None

    @property
    def body(self) -> dict:
        return loads_strict_json(self.raw)


@dataclass(frozen=True)
class LegacyFence:
    raw: bytes
    sha256: str
    pointer_path: str


def build_lineage(archive_bytes: Mapping[str, bytes], *, source_format: str,
                  original_project_id: str, new_project_id: str,
                  expected_owner_sha256: str, expected_scope_sha256: str,
                  expected_head_sha256: str) -> LegacyLineage:
    """Build an inventory from supplied original bytes, without source replay."""
    if type(source_format) is not str or source_format not in _ANCHORS:
        _fail('Unsupported legacy source format')
    _original_id(original_project_id)
    _uuid4(new_project_id)
    expected = {'owner': _digest(expected_owner_sha256, 'expected owner'),
                'scope': _digest(expected_scope_sha256, 'expected scope'),
                'head': _digest(expected_head_sha256, 'expected head')}
    inventory = _archive_inventory(archive_bytes, source_format)
    for role, path in _ANCHORS[source_format].items():
        if hashlib.sha256(archive_bytes[path]).hexdigest() != expected[role]:
            _fail(f'Original {role} bytes differ from independently expected digest')
    body = {'schema': LINEAGE_SCHEMA, 'source_format': source_format,
            'original_project_id': original_project_id,
            'new_project_id': new_project_id, 'anchors': [
                {'role': role, 'path': _ANCHORS[source_format][role], 'sha256': expected[role]}
                for role in ('owner', 'scope', 'head')],
            'archive': inventory}
    lb._bounded_input(body)
    _lineage_structure(body)
    raw = canonical_bytes(body)
    if len(raw) > MAX_RECORD_BYTES:
        _fail('Lineage record exceeds byte budget')
    return LegacyLineage(raw, hashlib.sha256(raw).hexdigest())


def load_lineage(raw: bytes, archive_bytes: Mapping[str, bytes], *,
                 approved_lineage_sha256: str, expected_owner_sha256: str,
                 expected_scope_sha256: str, expected_head_sha256: str) -> LegacyLineage:
    """Require an externally approved digest and exact archived source bytes."""
    _digest(approved_lineage_sha256, 'approved lineage')
    body = _record(raw, LINEAGE_SCHEMA)
    _lineage_structure(body)
    rebuilt = build_lineage(
        archive_bytes, source_format=body['source_format'],
        original_project_id=body['original_project_id'], new_project_id=body['new_project_id'],
        expected_owner_sha256=expected_owner_sha256,
        expected_scope_sha256=expected_scope_sha256,
        expected_head_sha256=expected_head_sha256)
    if raw != rebuilt.raw or rebuilt.sha256 != approved_lineage_sha256:
        _fail('Lineage differs from exact archive or approved digest')
    return rebuilt


def build_fence(lineage: LegacyLineage, *, approved_lineage_sha256: str,
                original_pointer_bytes: bytes) -> LegacyFence:
    """Build unsupported-schema successor bytes for the legacy pointer path."""
    if (type(lineage) is not LegacyLineage or type(lineage.raw) is not bytes
            or len(lineage.raw) > MAX_RECORD_BYTES
            or _digest(lineage.sha256, 'lineage') != hashlib.sha256(lineage.raw).hexdigest()):
        _fail('Validated lineage is required')
    _digest(approved_lineage_sha256, 'approved lineage')
    if lineage.sha256 != approved_lineage_sha256:
        _fail('Lineage lacks the explicitly approved digest')
    body = _lineage_structure(_record(lineage.raw, LINEAGE_SCHEMA))
    source_format = body['source_format']
    if source_format not in _FENCE_POINTER:
        _fail('Unsupported fence source format')
    pointer = _FENCE_POINTER[source_format]
    archived = next((item for item in body['archive'] if item['path'] == pointer), None)
    if (type(original_pointer_bytes) is not bytes or archived is None
            or len(original_pointer_bytes) > MAX_ARCHIVE_FILE_BYTES
            or archived['size_decimal'] != str(len(original_pointer_bytes))
            or archived['sha256'] != hashlib.sha256(original_pointer_bytes).hexdigest()):
        _fail('Original pointer bytes differ from lineage archive')
    successor = {'schema': FENCE_SCHEMA, 'source_format': source_format,
                 'lineage_sha256': lineage.sha256, 'original_pointer_path': pointer,
                 'original_pointer_sha256': archived['sha256'],
                 'new_project_id': body['new_project_id']}
    raw = canonical_bytes(successor)
    if len(raw) > MAX_RECORD_BYTES:
        _fail('Fence record exceeds byte budget')
    return LegacyFence(raw, hashlib.sha256(raw).hexdigest(), pointer)


def load_fence(raw: bytes, lineage: LegacyLineage, *, approved_lineage_sha256: str,
               original_pointer_bytes: bytes) -> LegacyFence:
    expected = build_fence(lineage, approved_lineage_sha256=approved_lineage_sha256,
                           original_pointer_bytes=original_pointer_bytes)
    body = _record(raw, FENCE_SCHEMA)
    if set(body) != {'schema', 'source_format', 'lineage_sha256', 'original_pointer_path',
                     'original_pointer_sha256', 'new_project_id'} or raw != expected.raw:
        _fail('Fence differs from exact approved lineage and original pointer')
    return expected
