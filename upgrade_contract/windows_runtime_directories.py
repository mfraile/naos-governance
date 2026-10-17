"""Creation witnesses and restartable, exact-handle publication-parent cleanup.

Callers retain the managed scope lock, but release file-backend parent pins
before cleanup. This journal grants no authority over legacy operation plans.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import ntpath
import re

from .canonical import canonical_bytes, loads_strict_json
from .windows_coordinator import WindowsJournalConflict, WindowsTransaction, _envelope
from .windows_handles import WindowsHandleError, SUPPORTED_DIRECTORY_ATTRIBUTES
from .windows_observation import _relative_parts
from .windows_operation import _read_existing_record, SCHEMA as OP_SCHEMA, SCHEMA_V2 as OP_SCHEMA_V2
from .windows_planning import _comparison_metadata_digest


SCHEMA = 'naos.upgrade.windows_runtime_directories.v1'
CHECKPOINT_SCHEMA = 'naos.upgrade.windows_runtime_directory_cleanup.v1'
_MISSING = 0xC0000034
_MUTATIONS = {'CREATE_NEW_UPSTREAM', 'CREATE_NEW_ADOPTER_OWNED',
              'CREATE_CONFIGURATION_CHOICE', 'CREATE_MANAGED_CACHE',
              'CREATE_IMMUTABLE_REPORT', 'UPDATE_FROM_UPSTREAM'}


def identity(info):
    return {'volume_serial_hex': f'{info.volume:016x}', 'file_id_hex': info.file_id.hex()}


def _hex(value, length):
    return isinstance(value, str) and bool(re.fullmatch('[0-9a-f]{' + str(length) + '}', value))


def _valid_identity(value):
    return (isinstance(value, dict) and set(value) == {'volume_serial_hex', 'file_id_hex'}
            and _hex(value['volume_serial_hex'], 16) and _hex(value['file_id_hex'], 32))


def absent_content_parents(plan):
    """Derive cleanup scope from saved missing suffixes, never live absence."""
    paths = set()
    for row in plan['rows']:
        if row['action'] not in _MUTATIONS or row['before']['presence'] != 'absent':
            continue
        parts = _relative_parts(row['path'])
        if parts[0].casefold() == '.naos':
            raise WindowsJournalConflict('Content publication cannot own runtime directories')
        suffix = row['before'].get('missing_suffix')
        if (not isinstance(suffix, list) or not suffix or len(suffix) > len(parts)
                or list(parts[-len(suffix):]) != suffix):
            raise WindowsJournalConflict('Invalid saved content-parent absence')
        for length in range(len(parts) - len(suffix) + 1, len(parts)):
            paths.add('\\'.join(parts[:length]))
    if len({p.casefold() for p in paths}) != len(paths):
        raise WindowsJournalConflict('Aliased absent publication parents')
    return tuple(sorted(paths, key=lambda p: (p.count('\\'), p.casefold())))


def existing_parent_anchors(plan):
    """Bind the first missing component to its saved, existing native parent."""
    expected = set(absent_content_parents(plan))
    anchors = {}
    for row in plan['rows']:
        if row['action'] not in _MUTATIONS or row['before']['presence'] != 'absent':
            continue
        parts = _relative_parts(row['path'])
        suffix = row['before']['missing_suffix']
        if len(suffix) < 2:
            continue
        path = '\\'.join(parts[:len(parts) - len(suffix) + 1])
        ancestors = row['before'].get('ancestors')
        if not isinstance(ancestors, list) or not ancestors or not isinstance(ancestors[-1], dict):
            raise WindowsJournalConflict('Missing saved publication-parent anchor')
        parent = {k: ancestors[-1].get(k) for k in ('volume_serial_hex', 'file_id_hex')}
        if not _valid_identity(parent) or path in anchors and anchors[path] != parent:
            raise WindowsJournalConflict('Invalid or conflicting publication-parent anchor')
        anchors[path] = parent
    if set(anchors) != {p for p in expected if ntpath.dirname(p) not in expected}:
        raise WindowsJournalConflict('Incomplete publication-parent anchors')
    return anchors


def witness(path, parent, child):
    before, security = child.info(), child.security()
    parent_id = identity(parent.info())
    if not before.directory or not security.protected:
        raise WindowsJournalConflict('Creation witness needs a protected directory')
    result = {'path': path, 'identity': identity(before), 'parent_identity': parent_id,
              'attributes_hex': f'{before.attributes:08x}',
              'comparison_metadata_sha256': _comparison_metadata_digest(before, security)}
    if (child.info() != before or child.security() != security
            or identity(parent.info()) != parent_id):
        raise WindowsJournalConflict('Directory changed during creation witness')
    return result


class DirectoryJournal:
    """Bounded journal I/O reused without constructing a file transaction backend."""

    _journal_limit = WindowsTransaction._journal_limit
    _write_once = WindowsTransaction._write_once

    def __init__(self, handles, directory, file_template, operation_id, intent_sha256,
                 expected_paths, root_identity, parent_anchors):
        if (not isinstance(operation_id, str) or not re.fullmatch(r'WOP-[0-9a-f]{16}', operation_id)
                or not _hex(intent_sha256, 64)):
            raise WindowsJournalConflict('Invalid directory journal operation binding')
        self.handles, self.directory = handles, directory
        self._closed = False
        self._file_template = file_template
        self._file_template_id = identity(file_template.info())
        self._file_template_security = file_template.security()
        if not self._file_template_security.protected:
            raise WindowsJournalConflict('Directory journal template is not protected')
        self.operation_id, self.intent_sha256 = operation_id, intent_sha256
        self.expected_paths = tuple(expected_paths)
        if not _valid_identity(root_identity):
            raise WindowsJournalConflict('Invalid directory journal root binding')
        self.root_identity = dict(root_identity)
        self.parent_anchors = loads_strict_json(canonical_bytes(parent_anchors))

    def _read(self, name):
        # Hold the same file pinned while checking security and canonical bytes.
        try:
            opened = self.handles.open_child(self.directory, name, kind='file', pin_for_read=True)
        except WindowsHandleError as exc:
            if exc.operation == 'NtCreateFile' and exc.ntstatus == _MISSING:
                return None
            raise
        with opened:
            if opened.security() != self._file_template_security:
                raise WindowsJournalConflict('Directory journal security differs from template')
            return WindowsTransaction._read(self, name)

    def _body(self, directories):
        return {'schema': SCHEMA, 'failure_model': 'application_crash_v1',
                'operation_id': self.operation_id, 'intent_sha256': self.intent_sha256,
                'directories': directories}

    def _validate_body(self, body):
        if (not isinstance(body, dict) or set(body) != set(self._body([]))
                or {k: v for k, v in body.items() if k != 'directories'}
                != {k: v for k, v in self._body([]).items() if k != 'directories'}
                or not isinstance(body['directories'], list)):
            raise WindowsJournalConflict('Missing or invalid required directory witnesses')
        rows = body['directories']
        seen_ids, seen_paths = set(), {}
        for row in rows:
            if (not isinstance(row, dict) or set(row) != {'path', 'identity', 'parent_identity',
                    'attributes_hex', 'comparison_metadata_sha256'}
                    or not _valid_identity(row['identity'])
                    or not _valid_identity(row['parent_identity'])
                    or not _hex(row['attributes_hex'], 8)
                    or not _hex(row['comparison_metadata_sha256'], 64)):
                raise WindowsJournalConflict('Invalid directory ownership witness')
            parts = _relative_parts(row['path'])
            if (parts[0].casefold() == '.naos' or not int(row['attributes_hex'], 16) & 0x10
                    or int(row['attributes_hex'], 16) & ~SUPPORTED_DIRECTORY_ATTRIBUTES):
                raise WindowsJournalConflict('Invalid directory witness path or attributes')
            key = canonical_bytes(row['identity'])
            parent_path = ntpath.dirname(row['path']).casefold()
            if (key in seen_ids or row['path'].casefold() in seen_paths
                    or row['identity'] == row['parent_identity']
                    or row['identity']['volume_serial_hex'] != self.root_identity['volume_serial_hex']
                    or row['parent_identity']['volume_serial_hex'] != self.root_identity['volume_serial_hex']
                    or row['path'] in self.parent_anchors
                    and row['parent_identity'] != self.parent_anchors[row['path']]
                    or not parent_path and row['parent_identity'] != self.root_identity
                    or parent_path in seen_paths and seen_paths[parent_path] != row['parent_identity']):
                raise WindowsJournalConflict('Directory witness identities conflict')
            seen_ids.add(key)
            seen_paths[row['path'].casefold()] = row['identity']
        if tuple(r['path'] for r in rows) != self.expected_paths:
            raise WindowsJournalConflict('Directory witnesses do not exactly cover planned absence')

    def persist(self, directories):
        body = loads_strict_json(canonical_bytes(self._body(directories)))
        self._validate_body(body)
        self._write_once('directories.json', body)

    def _checkpoint(self, digest, index, phase):
        return {'schema': CHECKPOINT_SCHEMA, 'failure_model': 'application_crash_v1',
                'operation_id': self.operation_id, 'intent_sha256': self.intent_sha256,
                'directories_sha256': digest, 'index': index, 'phase': phase}

    @staticmethod
    def _matches(actual, expected):
        return isinstance(actual, dict) and type(actual.get('index')) is int and actual == expected

    @staticmethod
    def _name(index, phase):
        return f'directory-delete-{index:06d}.{phase}.json'

    def validate(self, terminal):
        body = self._read('directories.json')
        self._validate_body(body)
        digest = hashlib.sha256(_envelope(body)).hexdigest()
        count = len(body['directories'])
        allowed = {self._name(i, phase) for i in range(count) for phase in ('intent', 'done')}
        names = set(self.handles.list_children(self.directory))
        if any(n.casefold().startswith('directory-delete-') and n not in allowed for n in names):
            raise WindowsJournalConflict('Unknown directory cleanup checkpoint')
        done, pending, gap = 0, False, False
        for index in range(count):
            intent = self._read(self._name(index, 'intent'))
            completed = self._read(self._name(index, 'done'))
            if intent is None and completed is None:
                gap = True
                continue
            if (gap or pending or terminal != 'rolled_back'
                    or not self._matches(intent, self._checkpoint(digest, index, 'intent'))
                    or completed is not None and not self._matches(completed, self._checkpoint(digest, index, 'done'))):
                raise WindowsJournalConflict('Noncontiguous or conflicting directory cleanup checkpoints')
            if completed is None:
                pending = True
            else:
                done += 1
        final = self._read('directories-rolled-back.json')
        if final is not None and (terminal != 'rolled_back' or done != count or pending
                or not self._matches(final, self._checkpoint(digest, count, 'complete'))):
            raise WindowsJournalConflict('Directory cleanup terminal conflicts')
        return body, digest, done, pending, final is not None

    @staticmethod
    def _verify(row, parent, child):
        current = witness(row['path'], parent, child)
        if current != row:
            raise WindowsJournalConflict('Publication directory identity or security changed; retain objects')

    def verify_created(self, root, walk):
        body, *_ = self.validate(None)
        for row in body['directories']:
            with ExitStack() as stack:
                parent = self._parent(stack, root, walk, row)
                child = stack.enter_context(self.handles.open_child(parent, ntpath.basename(row['path']),
                                             kind='directory', pin_for_read=True))
                self._verify(row, parent, child)

    def _parent(self, stack, root, walk, row):
        root_handle = walk(stack, root, publish=False)
        if identity(root_handle.info()) != self.root_identity:
            raise WindowsJournalConflict('Directory cleanup root identity changed')
        return walk(stack, root + '\\' + ntpath.dirname(row['path']), publish=False)

    def _require_leaf_rollback(self):
        intent = _read_existing_record(self.handles, self.directory, 'intent.json', 16 * 1024 * 1024)
        if (intent.get('schema') not in (OP_SCHEMA, OP_SCHEMA_V2)
                or hashlib.sha256(_envelope(intent)).hexdigest() != self.intent_sha256
                or intent.get('operation_id') != self.operation_id
                or self._read('rolled-back.json') != {
                    'schema': intent['schema'], 'failure_model': 'application_crash_v1',
                    'intent_sha256': self.intent_sha256, 'direction': 'rollback', 'topology': 'prepared'}
                or self._read('committed.json') is not None):
            raise WindowsJournalConflict('Directory cleanup requires bound file rollback')

    def cleanup(self, root, walk):
        self._require_leaf_rollback()
        body, digest, done, pending, complete = self.validate('rolled_back')
        if complete:
            return
        rows = list(reversed(body['directories']))
        for index in range(done, len(rows)):
            row = rows[index]
            with ExitStack() as stack:
                parent = self._parent(stack, root, walk, row)
                if identity(parent.info()) != row['parent_identity']:
                    raise WindowsJournalConflict('Cleanup parent identity changed; retain objects')
                name = ntpath.basename(row['path'])
                try:
                    child = self.handles.open_child(parent, name, kind='directory', for_delete=True)
                except WindowsHandleError as exc:
                    if not (exc.operation == 'NtCreateFile' and exc.ntstatus == _MISSING and pending):
                        raise
                else:
                    with child:
                        self._verify(row, parent, child)
                        if self.handles.list_children(child):
                            raise WindowsJournalConflict('Publication directory contains foreign objects; retain objects')
                        self._write_once(self._name(index, 'intent'), self._checkpoint(digest, index, 'intent'))
                        self._verify(row, parent, child)
                        self.handles.delete_exact(parent, name, child)
                    # FileDispositionInfo completes on close, not on return.
                    try:
                        remaining = self.handles.open_child(parent, name, kind='directory', pin_for_read=True)
                    except WindowsHandleError as exc:
                        if not (exc.operation == 'NtCreateFile' and exc.ntstatus == _MISSING):
                            raise
                    else:
                        remaining.close()
                        raise WindowsJournalConflict('Directory deletion has not completed')
                if identity(parent.info()) != row['parent_identity']:
                    raise WindowsJournalConflict('Cleanup parent changed before completion')
                self._write_once(self._name(index, 'done'), self._checkpoint(digest, index, 'done'))
                pending = False
        self._write_once('directories-rolled-back.json', self._checkpoint(digest, len(rows), 'complete'))
