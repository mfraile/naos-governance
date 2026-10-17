"""Fresh receiving inventory under current legacy-first/local-second custody.

This module never substitutes a historical native witness into a live reader.
Byte maps passed to detached history are separate from native observations.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import os
from pathlib import Path

from . import joint_capture as joint, local_binding as lb, portable_provenance as pp
from . import rebind_store_inspection as ris
from . import foreign_store_history as history, foreign_store_records as records
from .legacy_archive_capture import _Capture as ArchiveCapture
from .foreign_store_legacy import held_current_legacy
from .v3_operation_custody import _held_operation_store


class _Inventory(ris._NativeStore):
    def __init__(self, held, windows):
        super().__init__(held, windows)
        self.directory_witnesses = {}
        self.record_bytes = 0
        self.replay_bytes = 0
        self.current_path = None
        self.payload_witnesses = {}
        self.deferred_payloads = {}

    def directory(self, path):
        if path in self.payload_witnesses:
            from .v3_j2_publication import _native_directory
            witness = _native_directory(self,path)
            if witness != self.payload_witnesses[path]:
                raise ValueError('Receiving payload directory changed')
        else:
            witness = super().directory(path)
        prior = self.directory_witnesses.setdefault(path, witness)
        if prior != witness:
            raise ValueError('Receiving directory changed during inventory')
        return witness

    def _private(self, witness):
        # Only a program-derived fixed payload file may retain supported working
        # metadata. Its real current reader witness is pinned before byte read.
        expected = self.payload_witnesses.get(self.current_path)
        if expected is not None and witness['kind']=='file':
            if witness != expected:
                raise ValueError('Receiving payload file changed')
            return witness
        return super()._private(witness)

    def children(self, path, *, final=False):
        from .v3_j2_publication import _publication_children
        # Use the existing qualified bounded enumerator; detached semantics
        # below still requires exact fixed role names and inventories.
        self.directory(path)
        return _publication_children(self, path, final=final)

    def _budget(self, size):
        path = self.current_path
        blob = ('/replay/blobs/' in path and path.endswith('.bin')) or path in self.payload_witnesses
        limit = pp.MAX_BASE_BYTES if blob else lb.MAX_RECORD_BYTES
        total = self.replay_bytes if blob else self.record_bytes
        bound = pp.MAX_CUMULATIVE_READ_BYTES if blob else ris.MAX_TOTAL_BYTES
        if not 0 <= size <= limit or size > bound - total:
            raise ValueError('Receiving evidence exceeds existing role byte budget')
        if blob:
            self.replay_bytes += size
        else:
            self.record_bytes += size

    def read(self, path):
        self.current_path = path
        try:
            return super().read(path)
        finally:
            self.current_path = None

    def _kind(self, parent_path, name):
        if not self.windows:
            return ArchiveCapture._kind(self, parent_path, name)
        from .windows_handles import UnsafeWindowsPath
        parent = self.reader.directory(parent_path)
        # Directory pins share the child-add access held by an owned directory
        # creator. A file-first probe would conflict before checking its kind.
        try:
            with self.reader.handles.open_child(self.reader.directories[parent], name,
                                               kind='directory', pin_for_read=True):
                return 'directory'
        except UnsafeWindowsPath:
            # Both opens enforce the unchanged native metadata guard. A rejected
            # directory probe never proves that the fallback file is safe.
            with self.reader.handles.open_child(self.reader.directories[parent], name,
                                               kind='file', pin_for_read=True):
                return 'file'

    def scan(self, *, retained_journal_ids=None, allowed_journal_ids=None):
        # Imported-prefix validation must not claim custody of a later ordinary
        # transaction's destination-mode stages. Its existing verifier owns them.
        # Enumerate the complete frontier before restricting recursive descent.
        journals = ris.ROOT + '/journals'
        if retained_journal_ids is not None:
            visible = self.children(journals)
            allowed = tuple(allowed_journal_ids)
            retained = tuple(retained_journal_ids)
            if (not retained or retained != allowed[:len(retained)]
                    or visible not in (set(allowed), set(allowed[:-1]))
                    or not set(retained).issubset(visible)):
                raise ValueError('Imported-prefix journal cursor differs from current qualified frontier')
        pending = [ris.ROOT]
        while pending:
            path = pending.pop()
            if path.count('/') > lb.MAX_PATH_COMPONENTS:
                raise ValueError('Receiving evidence path depth exceeds existing bound')
            for name in sorted(self.children(path)):
                child = path + '/' + name
                records.control_path(child)
                if (retained_journal_ids is not None and path == journals
                        and name not in retained_journal_ids):
                    continue
                # These exact publication parents nominate deferred candidates,
                # never authority. Shared completed program/terminal validation
                # must select every candidate before current payload reads.
                parts = path.split('/')
                if (len(parts)==7 and parts[:4]==ris.ROOT.split('/')+['journals']
                        and parts[5]=='publication' and parts[6] in ('stages','retained','directory-stages')):
                    if len(name)!=8 or not name.isascii() or not name.isdigit():
                        raise ValueError('Unknown receiving publication payload slot')
                    # Payloads retain working ACLs: a directory-first probe may
                    # require execute rights on a readable ordinary file. Keep
                    # their original qualified file-first classifier.
                    kind=ArchiveCapture._kind(self,path,name)
                    if kind not in ('file','directory'):
                        raise ValueError('Wrong receiving payload kind')
                    self.deferred_payloads[child]=kind
                    # Deferred membership stays outside observed native caches.
                    # Only the detached provisional selector sees empty byte placeholders.
                    continue
                if child == ris.LOCK:
                    self.check_lock()
                    self.raw[child] = b''
                    self.observations[child] = {'path': child, 'metadata': self.lock_witness,
                        'content': {'sha256': records.sha(b''), 'size_decimal': '0'}}
                elif self._kind(path, name) == 'directory':
                    pending.append(child)
                    if len(pending) + len(self.inventories) > lb.MAX_ANCESTORS:
                        raise ValueError('Receiving evidence directory count exceeds existing bound')
                else:
                    self.read(child)
        if self.deferred_payloads:
            provisional=dict(self.raw)
            provisional.update({path:b'' for path,kind in self.deferred_payloads.items() if kind=='file'})
            directories=set(self.directory_witnesses)|{path for path,kind in self.deferred_payloads.items() if kind=='directory'}
            roles=history.select_payload_roles(provisional,frozenset(directories))
            if set(roles)!=set(self.deferred_payloads):
                raise ValueError('Missing or extra receiving payload role')
            from .v3_j2_publication import _native_directory
            for path,(kind,content) in roles.items():
                if self.deferred_payloads[path]!=kind:
                    raise ValueError('Receiving payload slot kind differs')
                if kind=='file':
                    observed=self.reader.leaf(path)
                    if observed['content']!=content:
                        raise ValueError('Receiving payload approved content differs')
                    self.payload_witnesses[path]=observed['metadata']
                    self.read(path)
                    if self.observations[path]!=observed:
                        raise ValueError('Receiving payload changed during byte read')
                else:
                    witness=_native_directory(self,path)
                    if witness['presence']!='present':
                        raise ValueError('Receiving payload directory absent')
                    self.payload_witnesses[path]=witness
                    if self.children(path):
                        raise ValueError('Receiving payload directory is not empty')
        return self


def _lane(root, windows, handles):
    return joint._held_windows(str(root), (), handles) if windows else joint._held_posix(Path(root), ())


def _selector(root, handles):
    windows = handles is not None or os.name == 'nt'
    with _lane(root, windows, handles) as held:
        native = _Inventory(held, windows)
        names = native.children(ris.ROOT + '/journals')
        ids = tuple(f'J{i:08d}' for i in range(1, len(names) + 1))
        if not ids or names != set(ids):
            raise ValueError('Receiving selector has noncontiguous journal names')
        first = pp._load_json(native.read(ris.JOURNAL + '/plan.json'), 'receiving source dispatch')
        source_format = first.get('source_format') if first.get('schema') in ('naos.upgrade.legacy_migration_plan.v1', 'naos.upgrade.legacy_migration_plan.v2') else None
        return ids, source_format


@contextmanager
def custody(root, *, journal_ids=None, source_format=None, handles=None):
    """Current observations select custody; full semantic qualification follows."""
    if journal_ids is None:
        journal_ids, source_format = _selector(root, handles)
    windows = handles is not None or os.name == 'nt'
    with ExitStack() as stack:
        legacy = None
        if source_format is not None:
            legacy = stack.enter_context(held_current_legacy(root, windows=windows,
                source_format=source_format, handles=handles))
        local = stack.enter_context(_held_operation_store(root, journal_ids=journal_ids, handles=handles))
        local.receiving_legacy = legacy
        local.receiving_source_format = source_format
        yield local
        if legacy is not None:
            legacy.revalidate()


@dataclass(frozen=True)
class ObservedStore:
    pair: object
    files: dict
    directories: frozenset
    inventory: dict
    portable_files: dict
    prefix: object | None


def observe(root, local, *, detached=True, binding_source=ris.BINDING, state_source=ris.ROOT + '/state.json'):
    legacy = local.receiving_legacy
    local.check_lock()
    if legacy is not None:
        legacy.revalidate()
    handles = local.reader.handles if local.windows else None
    with _lane(root, local.windows, handles) as held:
        native = _Inventory(held, local.windows)
        native.lock_handle, native.lock_witness = local.lock_handle, local.lock_witness
        native.scan()
        files = dict(native.raw)
        directories = set(native.directory_witnesses)
        observations = dict(native.observations)
        dirs = {path: {'path': path, 'witness': witness, 'children': sorted(native.inventories[path])}
                for path, witness in native.directory_witnesses.items() if path in native.inventories}
        absence = []
        if legacy is None:
            witness = held.working_reader.directory_witness('.naos/upgrade-v1') if local.windows else held.working_reader.directory('.naos/upgrade-v1')
            if witness['presence'] != 'absent':
                raise ValueError('Existing legacy state requires qualified migration-origin custody')
            absence.append({'path': '.naos/upgrade-v1', 'witness': witness})
        else:
            # Opening and closing full proofs bracket this SAME immutable
            # legacy baseline. Preserve held pins here without opening two
            # redundant complete captures before reading its top inventory.
            legacy.check_lock()
            top = legacy.inventories['.naos/upgrade-v1']
            expected_top = {'OWNER.json', 'managed-content'} if legacy.scope.endswith('managed-content') else {'windows-content'}
            if set(top) != expected_top:
                raise ValueError('Unknown or competing legacy control inventory')
            files.update(dict(legacy.raw))
            directories.update(legacy.directory_witnesses)
            observations.update(legacy.observations)
            observations[legacy.lock_path] = {'path': legacy.lock_path, 'metadata': legacy.lock_witness,
                'content': {'sha256': records.sha(b''), 'size_decimal': '0'}}
            for path, witness in legacy.directory_witnesses.items():
                dirs[path] = {'path': path, 'witness': witness,
                    'children': sorted(legacy.inventories[path]) if path in legacy.inventories else []}
            other = '.naos/upgrade-v1/windows-content' if legacy.scope.endswith('managed-content') else '.naos/upgrade-v1/managed-content'
            witness = held.working_reader.directory_witness(other) if local.windows else held.working_reader.directory(other)
            if witness['presence'] != 'absent':
                raise ValueError('Competing legacy source scope is present')
            absence.append({'path': other, 'witness': witness})
        portable_files = {}
        class Tee:
            def read(self, path):
                raw = held.portable_reader.read(path)
                if raw is not None:
                    portable_files[path] = raw
                return raw
        if pp.load_portable_snapshot(Tee()) != held.result.portable:
            raise ValueError('Portable bytes changed during receiving capture')
        inventory = {'schema': records.INVENTORY_SCHEMA, 'files': [observations[path] for path in sorted(observations)],
            'directories': [dirs[path] for path in sorted(dirs)], 'legacy_absence': absence}
        records.validate_inventory(inventory, held.result.working_tree.body['native']['platform'])
        prefix = history.load_completed_semantics(files, frozenset(directories), portable_files,
            binding_source=binding_source, state_source=state_source) if detached else None
        for path in tuple(native.inventories):
            native.children(path, final=True)
        native.check_lock()
        native.revalidate()
        result = ObservedStore(held.result, files, frozenset(directories), inventory, portable_files, prefix)
    if legacy is not None:
        legacy.revalidate()
    local.check_lock()
    return result
