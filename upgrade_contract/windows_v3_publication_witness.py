"""Native file witnesses for a V3 publisher's durable pre-move commitment.

The caller must persist these bytes and bind their hash/native record witness
to its operation before any rename. This module neither writes that commitment
nor grants mutation authority. Directory publication has a separate contract.
"""
from __future__ import annotations

import hashlib

from . import local_binding as lb
from .canonical import canonical_bytes, loads_strict_json
from .windows_rename_identity import identity_from_record, identity_record
from .windows_restoring_backend import _capture
from .windows_v3_security_witness import decode_security_witness, encode_security_witness

SCHEMA = 'naos.upgrade.v3_publication_windows_files.v1'


def _fail(message):
    raise ValueError(message)


def _expected(observations):
    if type(observations) is not list or not observations:
        _fail('Nonempty exact publication observations required')
    result = {}
    for item in observations:
        if type(item) is not dict or set(item) != {'path', 'metadata', 'content'}:
            _fail('Invalid publication file observation')
        path = item['path']
        # Publisher paths include private control leaves. Validate their normal
        # relative form here; the caller supplies the exact operation inventory.
        if (type(path) is not str or not path or '\\' in path or ':' in path
                or any(part in ('', '.', '..') for part in path.split('/'))
                or path in result):
            _fail('Invalid or duplicate publication witness path')
        lb._validate_witness(item['metadata'], 'Windows', 'file')
        if item['metadata']['presence'] != 'present':
            _fail('Only present source and stage files have rename witnesses')
        content = item['content']
        lb._fields(content, {'sha256', 'size_decimal'}, 'publication witness content')
        lb._hex(content['sha256'], lb.HEX64, 'publication witness content hash')
        lb._u64(content['size_decimal'], 'publication witness size')
        result[path] = item
    if len(result) > lb.MAX_LEAVES:
        _fail('Publication witness count exceeds bound')
    return result


def _project(identity, security):
    values = {}
    for name in ('owner_sid', 'group_sid', 'dacl', 'descriptor'):
        value = getattr(security, name)
        values[name + '_sha256'] = hashlib.sha256(value).hexdigest()
        values[name + '_size_decimal'] = str(len(value))
    values['dacl_protected'] = security.protected
    return {
        'schema': lb.WINDOWS_WITNESS_SCHEMA, 'kind': 'file', 'presence': 'present',
        'volume_serial_hex': f'{identity.volume:016x}',
        'file_id_hex': identity.file_id.hex(),
        'attributes_hex': f'{identity.rename_metadata.attributes:08x}',
        'security': values,
    }


def load_file_witnesses(raw, expected_observations):
    """Validate complete source coverage and return exact backend inputs.

    Native file ID alone is not authority: every descriptor/identity must match
    the selected native observation and exact bytes for its approved path.
    """
    expected = _expected(expected_observations)
    if type(raw) is not bytes or not 0 < len(raw) <= lb.MAX_RECORD_BYTES:
        _fail('Invalid publication witness record size')
    body = loads_strict_json(raw)
    if (type(body) is not dict or set(body) != {'schema', 'files'}
            or body['schema'] != SCHEMA or type(body['files']) is not list
            or len(body['files']) != len(expected) or canonical_bytes(body) != raw):
        _fail('Malformed or noncanonical publication witness record')
    identities, witnesses = {}, {}
    for row, path in zip(body['files'], sorted(expected)):
        if (type(row) is not dict or set(row) != {'path', 'identity', 'security'}
                or row['path'] != path):
            _fail('Publication witness coverage/order differs')
        identity = identity_from_record(row['identity'])
        witness = canonical_bytes(row['security'])
        original, _transient = decode_security_witness(witness, identity)
        selected = expected[path]
        if (_project(identity, original) != selected['metadata']
                or {'sha256': identity.content_sha256, 'size_decimal': str(identity.size)}
                != selected['content']):
            _fail('Publication rename witness differs from approved native evidence')
        key = identity.file_id.hex()
        if key in witnesses:
            _fail('Aliased publication file identities')
        identities[path], witnesses[key] = identity, witness
    return identities, witnesses


def capture_file_witnesses(custody, expected_observations):
    """Capture stable native security before moves; caller persists the result."""
    if not custody.windows:
        _fail('Windows native custody required')
    expected = _expected(expected_observations)
    rows = []
    for path in sorted(expected):
        custody.check_lock()
        parent, _, name = path.rpartition('/')
        reader = custody.reader
        key = reader.directory(parent) if parent else reader.project
        with reader.handles.open_child(reader.directories[key], name,
                                       kind='file', pin_for_read=True) as held:
            identity, info, security = _capture(held)
            if (lb.project_windows_witness(info, security) != expected[path]['metadata']
                    or {'sha256': identity.content_sha256, 'size_decimal': str(identity.size)}
                    != expected[path]['content']):
                _fail('Publication source changed before security commitment')
            rows.append({'path': path, 'identity': identity_record(identity),
                         'security': loads_strict_json(encode_security_witness(identity, security))})
        custody.check_lock()
    raw = canonical_bytes({'schema': SCHEMA, 'files': rows})
    load_file_witnesses(raw, expected_observations)
    return raw
