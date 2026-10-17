"""Windows-native managed content session; application-process recovery only.

All mutations use held one-component native handles. The semantic plan binds
source bytes, intended security, exact current observations and provenance;
source preview locations and their transient file IDs are deliberately absent.
"""
from __future__ import annotations

from contextlib import ExitStack
from contextvars import ContextVar
import hashlib
import ntpath
from pathlib import Path
import secrets
import sys
import threading
from types import SimpleNamespace
from typing import Any, Mapping

from .canonical import canonical_bytes, canonical_sha256, loads_strict_json
from .planner import (_path_action_contract, apply_ownership_guard, kit_owned_drift,
                      classify_content_state, classify_new_path)
from .windows_backend import _split_leaf
from .windows_restoring_backend import WindowsRestoringBackend
from .windows_rename_identity import identity_from_record as _rename_from_record
from .windows_coordinator import WindowsJournalConflict, _envelope
from .windows_handles import WindowsHandleError, WindowsHandles
from .windows_observation import _parts, _relative_parts
from .windows_operation import (Publication, WindowsOperation, WindowsOperationSpec,
                                PLAN_SCHEMA as OP_PLAN_SCHEMA, SCHEMA as OP_SCHEMA,
                                PLAN_SCHEMA_V2 as OP_PLAN_SCHEMA_V2, SCHEMA_V2 as OP_SCHEMA_V2,
                                _identity_from_record, _read_existing_record)
from .windows_planning import (WindowsContentIdentity, WindowsReadObserver, _content,
                               _comparison_metadata_digest)
from .windows_runtime_directories import (DirectoryJournal, absent_content_parents,
                                          existing_parent_anchors, witness)
from . import windows_provenance as prov

LEGACY_SCHEMA = 'naos.upgrade.windows_runtime_plan.v1'
SCHEMA = 'naos.upgrade.windows_runtime_plan.v2'
_MISSING = 0xC0000034
_ATTR_ARCHIVE = 0x20
_ATTR_NORMAL = 0x80
_MUTATIONS = {'CREATE_NEW_UPSTREAM', 'CREATE_NEW_ADOPTER_OWNED',
              'CREATE_CONFIGURATION_CHOICE', 'CREATE_MANAGED_CACHE',
              'CREATE_IMMUTABLE_REPORT', 'UPDATE_FROM_UPSTREAM'}


class WindowsRuntimeError(WindowsJournalConflict):
    """Unsafe or unsupported managed Windows runtime state; retain objects."""


_ENROLLMENT_OBSERVATION = ContextVar('naos_windows_enrollment_observation', default=None)


def _active_enrollment_observation():
    observation = _ENROLLMENT_OBSERVATION.get()
    if observation is not None:
        return observation
    # Direct checkout CLI and installed-style script imports can load this
    # same source under both supported names. Share only a live context from
    # the exact same physical module; never a different installed kit.
    other_name = ('upgrade_contract.windows_runtime'
                  if __name__ == 'naos_governance.upgrade_contract.windows_runtime'
                  else 'naos_governance.upgrade_contract.windows_runtime')
    other = sys.modules.get(other_name)
    if (other is not None and getattr(other, '__file__', None)
            and Path(other.__file__).resolve() == Path(__file__).resolve()):
        context = getattr(other, '_ENROLLMENT_OBSERVATION', None)
        if isinstance(context, ContextVar):
            return context.get()
    return None


class _EnrollmentObservation:
    """Revocable observation of the empty baseline during a held first apply.

    This never validates persisted provenance or authorizes exclusion of files.
    A copied execution context cannot extend its lifetime or cross threads.
    """
    def __init__(self, runtime, plan, sources, operation, parent):
        self.runtime, self.plan, self.sources = runtime, plan, sources
        self.operation, self.parent = operation, parent
        self.thread = threading.get_ident()
        self.active = True

    def validate(self, reader):
        operation, plan = self.operation, self.plan
        if (not self.active or self.thread != threading.get_ident()
                or ntpath.normcase(reader.project_root) != ntpath.normcase(self.runtime.project_root)
                or ntpath.normcase(reader.source_policy_path) != ntpath.normcase(self.runtime.source_policy_path)
                or plan['enrollment'] is not True or operation._closed
                or operation.spec.operation_id != plan['operation_id']
                or not operation._created_directory
                or canonical_sha256({k: v for k, v in plan.items() if k != 'digest_sha256'}) != plan['digest_sha256']
                or reader.observer.root_identity(reader.project_root) != plan['project_root_identity']):
            raise WindowsRuntimeError('In-flight enrollment observation is not live or bound to this root')
        for handle, expected in ((self.parent, operation._runtime_id),
                                 (operation.directory, operation._directory_id),
                                 (operation.scope_lock, operation._scope_lock_id),
                                 (operation.lock, operation._lock_id)):
            if (getattr(handle, 'closed', False) or getattr(handle, 'value', 1) is None
                    or _id(handle.info()) != expected):
                raise WindowsRuntimeError('In-flight enrollment handle changed or closed')
        for handle in (operation.scope_lock, operation.lock):
            if getattr(handle, '_lock', None) is None and not getattr(handle, 'owns_lock', False):
                raise WindowsRuntimeError('In-flight enrollment observation requires held locks')
        operation._validate_plan_snapshot()
        self.runtime._verify_state(plan, self.sources, prepared=True)
        if operation._progress() != 0:
            raise WindowsRuntimeError('In-flight enrollment has already published content')


def _absolute(path: str) -> tuple[str, str]:
    drive, parents, leaf = _split_leaf(path)
    return drive, '\\'.join((*parents, leaf))


def _join(root: str, relative: str) -> str:
    return root.rstrip('\\') + '\\' + relative


def _id(info: Any) -> dict[str, str]:
    return {'volume_serial_hex': f'{info.volume:016x}', 'file_id_hex': info.file_id.hex()}


def _private_record(security: Any) -> dict[str, Any]:
    if not security.protected:
        raise WindowsRuntimeError('Private creation security is not DACL-protected')
    return {'policy': 'protected_current_user_only.v1', 'attributes_hex': '00000020',
            'owner_sid_sha256': hashlib.sha256(security.owner_sid).hexdigest(),
            'group_sid_sha256': hashlib.sha256(security.group_sid).hexdigest(),
            'dacl_sha256': hashlib.sha256(security.dacl).hexdigest(),
            'comparison_metadata_sha256': _comparison_metadata_digest(
                SimpleNamespace(attributes=_ATTR_ARCHIVE), security)}


class _MapReader:
    def __init__(self, files: Mapping[str, bytes]): self.files = files
    def read(self, relative: str) -> bytes | None: return self.files.get(relative)


class WindowsRuntime:
    def __init__(self, handles: Any, project_root: str, source_policy_path: str):
        _parts(project_root)
        _absolute(source_policy_path)
        self.handles = handles
        self.project_root = project_root.rstrip('\\')
        self.source_policy_path = source_policy_path
        self.observer = WindowsReadObserver(handles)

    @classmethod
    def native(cls, project_root: str, source_policy_path: str) -> 'WindowsRuntime':
        return cls(WindowsHandles(), project_root, source_policy_path)

    def _walk(self, stack: ExitStack, absolute_dir: str, *, publish: bool,
              create: bool = False, created_directories: dict | None = None,
              expected_directories: tuple[str, ...] = ()) -> Any:
        drive, parts = _parts(absolute_dir)
        parent = stack.enter_context(self.handles.open_root(
            drive, for_publish=publish and not parts))
        held = [parent]
        for index, component in enumerate(parts):
            relative = ntpath.relpath(drive + '\\'.join(parts[:index + 1]), self.project_root)
            final = index == len(parts) - 1
            try:
                child = self.handles.open_child(parent, component, kind='directory',
                          for_publish=publish and final,
                          pin_for_read=not (publish and final))
                if (created_directories is not None and relative in expected_directories
                        and relative not in created_directories):
                    child.close()
                    raise WindowsRuntimeError('Previously absent publication parent appeared')
            except WindowsHandleError as exc:
                if not (create and exc.operation == 'NtCreateFile' and exc.ntstatus == _MISSING):
                    raise
                # The held read pin denies replacement of this exact parent.
                # Reopen only this parent with child-add rights and compare
                # identities before creating the missing component.
                identity = parent.info().identity
                writer = (self.handles.open_root(drive, for_publish=True)
                          if index == 0 else self.handles.open_child(
                              held[-2], parts[index - 1], kind='directory',
                              for_publish=True))
                writer = stack.enter_context(writer)
                if writer.info().identity != identity or parent.info().identity != identity:
                    raise WindowsRuntimeError('Directory identity changed before creation')
                if created_directories is not None and relative not in expected_directories:
                    raise WindowsRuntimeError('Unplanned publication parent creation')
                child = self.handles.create_private_directory(writer, component)
                if created_directories is not None:
                    try:
                        created_directories[relative] = witness(relative, parent, child)
                    except BaseException:
                        child.close()
                        raise
                if parent.info().identity != identity:
                    child.close()
                    raise WindowsRuntimeError('Directory identity changed during creation')
            parent = stack.enter_context(child)
            held.append(parent)
        return parent

    def _control_exists(self) -> bool:
        with ExitStack() as stack:
            try:
                self._walk(stack, _join(self.project_root, prov.ROOT), publish=False)
                return True
            except WindowsHandleError as exc:
                if exc.operation == 'NtCreateFile' and exc.ntstatus == _MISSING:
                    return False
                raise

    def _policy(self) -> tuple[dict[str, Any], bytes, str]:
        drive, relative = _absolute(self.source_policy_path)
        observed, raw = self.observer.observe(drive, relative, capture_bytes=True)
        if observed is None or observed['presence'] != 'present' or raw is None:
            raise WindowsRuntimeError('Source policy is absent')
        active, _catalog = prov.policy_catalog(raw)
        return observed, raw, active

    def inspect(self) -> prov.ValidatedWindowsProvenance | None:
        before_root = self.observer.root_identity(self.project_root)
        if not self._control_exists():
            if self.observer.root_identity(self.project_root) != before_root:
                raise WindowsRuntimeError('Project root changed during control absence check')
            return None
        reader = prov.WindowsProvenanceReader(self.observer, self.project_root)
        policy, raw, _active = self._policy()
        del policy
        if reader.root_identity != before_root:
            raise WindowsRuntimeError('Project root changed during control read')
        return prov.load_windows_provenance(reader,
            root_identity=before_root, source_policy_raw=raw)

    def _source_rows(self, sources: list[tuple[str, str]]) -> list[dict[str, Any]]:
        if not isinstance(sources, list) or not sources:
            raise WindowsRuntimeError('Managed sources must be a nonempty list')
        rows = []
        for pair in sources:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise WindowsRuntimeError('Managed source binding is invalid')
            relative, absolute = pair
            prov._path(relative)
            drive, source_relative = _absolute(absolute)
            observation, data = self.observer.observe(drive, source_relative, capture_bytes=True)
            if observation is None or observation['presence'] != 'present' or data is None:
                raise WindowsRuntimeError('Managed source is absent')
            rows.append({'path': relative, 'sha256': observation['sha256'],
                         'size_decimal': observation['size_decimal']})
        paths = [r['path'] for r in rows]
        if len(paths) != len(set(paths)) or len(paths) != len({p.casefold() for p in paths}):
            raise WindowsRuntimeError('Duplicate or aliased managed source paths')
        return sorted(rows, key=lambda row: row['path'])

    def _build_plan(self, sources: list[tuple[str, str]], *, request: dict, checks: list,
                    allow_enrollment: bool, ids: dict[str, str] | None = None) -> dict[str, Any]:
        root_id = self.observer.root_identity(self.project_root)
        policy_obs, policy_raw, policy_sha = self._policy()
        snapshot = self.inspect()
        if snapshot is None and (not allow_enrollment or request.get('operation') != 'naos-init'):
            raise WindowsRuntimeError('Unenrolled Windows content requires explicit naos-init enrollment')
        if snapshot is not None and allow_enrollment:
            raise WindowsRuntimeError('Existing enrollment cannot be recreated')
        prov._request(request, snapshot.manifest['last_request'] if snapshot else None)
        if not isinstance(checks, list):
            raise WindowsRuntimeError('Fixed checks must be a list')
        canonical_bytes(checks)
        private = _private_record(self.handles.private_security())
        _active, policies = prov.policy_catalog(policy_raw)
        source_rows = self._source_rows(sources)
        if snapshot is not None:
            historical = {path.casefold(): path for path in snapshot.entries}
            if any(row['path'].casefold() in historical
                   and row['path'] != historical[row['path'].casefold()]
                   for row in source_rows):
                raise WindowsRuntimeError('Selected path aliases historical managed spelling')
        rows, refused = [], False
        for source in source_rows:
            path = source['path']
            before, _ = self.observer.observe(self.project_root, path)
            if before is None:
                raise WindowsRuntimeError('Current observation is missing')
            entry = snapshot.entries.get(path) if snapshot else None
            base = (WindowsContentIdentity('present', **entry['content']) if entry else
                    WindowsContentIdentity('absent'))
            current = _content(before if before['presence'] == 'present' else None)
            intended_meta = (current.metadata_sha256 if current.presence == 'present'
                             else private['comparison_metadata_sha256'])
            candidate = WindowsContentIdentity('present', 'file', source['size_decimal'],
                                               source['sha256'], intended_meta)
            proposal = classify_content_state(base, current, candidate)
            rule = classify_new_path(Path(*_relative_parts(path)), policies[policy_sha])
            ownership = entry['ownership'] if entry else rule['ownership']
            creation = entry['creation_policy'] if entry else rule['creation_policy']
            action = apply_ownership_guard(proposal, ownership,
                                           creation_policy=creation)['action']
            if snapshot is None and before['presence'] != 'absent':
                action = 'REFUSE_UNENROLLED_COLLISION'
            # Preserve rows are bound and revalidated but never published.
            # Only the explicit Windows mutation set may grant publication.
            disposition, _ = _path_action_contract(action)
            if action not in _MUTATIONS and disposition not in {'preserve', 'unchanged'}:
                refused = True
            if kit_owned_drift(ownership, action):
                refused = True
            if action == 'UPDATE_FROM_UPSTREAM' and (
                    before['attributes'] not in {_ATTR_ARCHIVE, _ATTR_NORMAL} or
                    not before['security']['dacl_protected']):
                action, refused = 'REFUSE_UNSUPPORTED_EXISTING_METADATA', True
            rows.append({'path': path, 'source': source, 'before': before,
                         'base': base.record(), 'intended': candidate.record(),
                         'action': action, 'ownership': ownership,
                         'creation_policy': creation})
        if ids is None:
            suffix = secrets.token_hex(8)
            ids = {'operation_id': 'WOP-' + suffix,
                   'transaction_id': 'WMC-' + suffix,
                   'project_id': snapshot.project_id if snapshot else 'WIN-' + secrets.token_hex(8)}
        body = {'schema': SCHEMA, 'project_root': self.project_root,
                'project_root_identity': root_id,
                'source_policy_observation': policy_obs,
                'source_policy_sha256': hashlib.sha256(policy_raw).hexdigest(),
                'source_policy_snapshot_sha256': policy_sha,
                'expected_manifest_sha256': snapshot.manifest_sha256 if snapshot else None,
                'expected_owner_sha256': snapshot.owner_sha256 if snapshot else None,
                'enrollment': snapshot is None, 'private_file_policy': private,
                'request': request, 'checks': checks, 'rows': rows, **ids,
                'status': 'refused' if refused else 'ready'}
        # Detach request/check inputs from caller-owned nested containers.
        stable = loads_strict_json(canonical_bytes(body))
        return {**stable, 'digest_sha256': canonical_sha256(stable)}

    def plan(self, sources: list[tuple[str, str]], *, request: dict, checks: list,
             allow_enrollment: bool = False) -> dict[str, Any]:
        return self._build_plan(sources, request=request, checks=checks,
                                allow_enrollment=allow_enrollment)

    def _verify_state(self, plan: dict[str, Any], sources: list[tuple[str, str]],
                      *, prepared: bool = False) -> None:
        if self.observer.root_identity(self.project_root) != plan['project_root_identity']:
            raise WindowsRuntimeError('Project root identity changed')
        policy_obs, raw, active = self._policy()
        if (policy_obs != plan['source_policy_observation']
                or hashlib.sha256(raw).hexdigest() != plan['source_policy_sha256']
                or active != plan['source_policy_snapshot_sha256']):
            raise WindowsRuntimeError('Source policy changed')
        if _private_record(self.handles.private_security()) != plan['private_file_policy']:
            raise WindowsRuntimeError('Private file security policy changed')
        if self._source_rows(sources) != [r['source'] for r in plan['rows']]:
            raise WindowsRuntimeError('Regenerated source bytes changed')
        if plan['enrollment']:
            for path in (prov.ROOT_PATH, prov.OWNER_PATH, prov.MANIFEST_PATH):
                observation, _ = self.observer.observe(self.project_root, path)
                if observation is None or observation['presence'] != 'absent':
                    raise WindowsRuntimeError('Enrollment control collision')
        else:
            snapshot = self.inspect()
            if (snapshot is None or snapshot.manifest_sha256 != plan['expected_manifest_sha256']
                    or snapshot.owner_sha256 != plan['expected_owner_sha256']):
                raise WindowsRuntimeError('Validated history changed')
        for row in plan['rows']:
            current, _ = self.observer.observe(self.project_root, row['path'])
            before = row['before']
            if current is None or current['presence'] != before['presence']:
                raise WindowsRuntimeError('Managed target presence changed')
            if before['presence'] == 'present':
                if current != before:
                    raise WindowsRuntimeError('Managed target identity or metadata changed')
            else:
                # Private preparation may fill only the suffix that was absent.
                ancestors = current['ancestors']
                old = before['ancestors']
                if ancestors[:len(old)] != old or (not prepared and current != before):
                    raise WindowsRuntimeError('Managed target ancestor changed')

    def _prepare(self, plan: dict[str, Any]) -> tuple[Any, Any, Any, Any]:
        stack = ExitStack()
        try:
            if plan['enrollment']:
                ancestor = self._walk(stack, _join(self.project_root,
                    '.naos\\upgrade-v1'), publish=True, create=True)
                control = stack.enter_context(self.handles.create_private_directory(
                    ancestor, 'windows-content'))
            else:
                control = self._walk(stack, _join(self.project_root, prov.ROOT),
                                     publish=True)
            for child in ('bases', 'base-blobs', 'receipts', 'transactions', 'staging'):
                try:
                    opened = self.handles.open_child(control, child, kind='directory',
                                                     for_publish=True)
                except WindowsHandleError as exc:
                    if (not plan['enrollment'] or exc.operation != 'NtCreateFile'
                            or exc.ntstatus != _MISSING):
                        raise
                    opened = self.handles.create_private_directory(control, child)
                stack.enter_context(opened)
            for child, kind in (('template.file', 'file'), ('template.directory', 'directory')):
                try:
                    opened = self.handles.open_child(control, child, kind=kind,
                                                     for_publish=kind == 'directory',
                                                     pin_for_read=kind == 'file')
                except WindowsHandleError as exc:
                    if (not plan['enrollment'] or exc.operation != 'NtCreateFile'
                            or exc.ntstatus != _MISSING):
                        raise
                    opened = (self.handles.create_private_file(control, child) if kind == 'file'
                              else self.handles.create_private_directory(control, child))
                # Exclusive-create file handles carry write access and deny
                # sharing with a subsequent read pin. Close before reopening.
                opened.close()
            tx = self._walk(stack, _join(self.project_root, prov.ROOT + '\\transactions'),
                            publish=True)
            staging = self._walk(stack, _join(self.project_root, prov.ROOT + '\\staging'),
                                 publish=True)
            file_template = self.handles.open_child(control, 'template.file', kind='file',
                                                    pin_for_read=True)
            dir_template = self.handles.open_child(control, 'template.directory',
                                                   kind='directory', for_publish=True)
            stack.enter_context(file_template)
            stack.enter_context(dir_template)
            return stack, tx, staging, (dir_template, file_template)
        except BaseException:
            stack.close()
            raise

    def _stage_bytes(self, parent: Any, name: str, data: bytes,
                     preserve_from: str | None = None,
                     preserve_attributes: int | None = None) -> None:
        with self.handles.create_private_file(parent, name) as created:
            created.write_all(data)
            if preserve_from is not None:
                with ExitStack() as stack:
                    drive, parts, leaf = _split_leaf(preserve_from)
                    source_parent = self._walk(stack, drive + '\\'.join(parts), publish=False)
                    source = stack.enter_context(self.handles.open_child(
                        source_parent, leaf, kind='file', pin_for_read=True))
                    self.handles.copy_protected_security(source, created)
                    self.handles.copy_supported_file_attributes(
                        source, created, expected_attributes=preserve_attributes)
            created.flush()

    def _prior_operations_quiescent(self, snapshot: prov.ValidatedWindowsProvenance | None,
                                    *, exclude: str | None = None) -> None:
        if snapshot is None:
            return
        with ExitStack() as stack:
            transactions = self._walk(stack, _join(self.project_root,
                prov.ROOT + '\\transactions'), publish=False)
            receipt_ids = {r['transaction_id'] for r in snapshot.manifest['receipts']}
            for name in self.handles.list_children(transactions):
                if name == 'managed-scope.lock' or name == exclude:
                    continue
                if not name.startswith('WOP-'):
                    raise WindowsRuntimeError('Unknown runtime object requires recovery')
                directory = stack.enter_context(self.handles.open_child(
                    transactions, name, kind='directory', pin_for_read=True))
                intent = _read_existing_record(self.handles, directory, 'intent.json',
                                               16 * 1024 * 1024)
                plan_record = _read_existing_record(self.handles, directory, 'plan.json',
                                                    16 * 1024 * 1024)
                op_plan = plan_record.get('plan')
                operation_schema = (OP_SCHEMA_V2 if plan_record.get('schema') == OP_PLAN_SCHEMA_V2
                                    else OP_SCHEMA)
                if (plan_record.get('schema') not in (OP_PLAN_SCHEMA, OP_PLAN_SCHEMA_V2)
                        or intent.get('schema') != operation_schema
                        or not isinstance(op_plan, dict) or op_plan.get('operation_id') != name
                        or not isinstance(op_plan.get('transaction_id'), str)
                        or plan_record.get('plan_sha256') != hashlib.sha256(
                            canonical_bytes(op_plan)).hexdigest()
                        or intent.get('plan_sha256') != plan_record['plan_sha256']):
                    raise WindowsRuntimeError('Prior operation plan binding differs')
                receipt_id = op_plan['transaction_id']
                terminal_count = 0
                for marker_name, direction, topology in (
                        ('committed.json', 'forward', 'committed'),
                        ('rolled-back.json', 'rollback', 'prepared')):
                    try:
                        marker = _read_existing_record(self.handles, directory, marker_name,
                                                       64 * 1024)
                    except WindowsJournalConflict as exc:
                        if str(exc) == f'Existing operation lacks {marker_name}':
                            continue
                        raise
                    if (marker.get('schema') != operation_schema
                            or marker.get('failure_model') != 'application_crash_v1'
                            or marker.get('intent_sha256') != hashlib.sha256(
                                _envelope(intent)).hexdigest()
                            or marker.get('direction') != direction
                            or marker.get('topology') != topology):
                        raise WindowsRuntimeError('Prior operation terminal marker differs')
                    if marker_name == 'committed.json' and receipt_id not in receipt_ids:
                        raise WindowsRuntimeError('Prior committed operation lacks validated receipt')
                    if marker_name == 'committed.json':
                        reader = prov.WindowsProvenanceReader(self.observer, self.project_root)
                        receipt, _receipt_sha = prov._decode(
                            reader.read(prov.receipt_path(receipt_id)),
                            prov.RECEIPT_SCHEMA, prov._RECEIPT_KEYS)
                        if receipt['plan_sha256'] != op_plan.get('digest_sha256'):
                            raise WindowsRuntimeError('Prior receipt plan digest differs')
                    if op_plan.get('schema') == SCHEMA:
                        state = self._directory_journal(stack, directory, op_plan, intent).validate(
                            'committed' if marker_name == 'committed.json' else 'rolled_back')
                        if marker_name == 'rolled-back.json' and not state[-1]:
                            raise WindowsRuntimeError('Prior directory cleanup requires explicit recovery')
                    elif op_plan.get('schema') != LEGACY_SCHEMA:
                        raise WindowsRuntimeError('Unknown prior runtime plan schema')
                    terminal_count += 1
                if terminal_count != 1:
                    raise WindowsRuntimeError('Prior operation requires explicit recovery')

    def apply(self, plan: dict, sources: list[tuple[str, str]], *, expected_digest: str,
              preapply_revalidator=None) -> dict[str, Any]:
        expected_keys = {'schema', 'project_root', 'project_root_identity',
            'source_policy_observation', 'source_policy_sha256',
            'source_policy_snapshot_sha256', 'expected_manifest_sha256',
            'expected_owner_sha256', 'enrollment', 'private_file_policy',
            'request', 'checks', 'rows', 'operation_id', 'transaction_id',
            'project_id', 'status', 'digest_sha256'}
        if (not isinstance(plan, dict) or plan.get('schema') not in (LEGACY_SCHEMA, SCHEMA)
                or set(plan) != expected_keys
                or plan.get('project_root') != self.project_root
                or plan.get('digest_sha256') != expected_digest
                or canonical_sha256({k: v for k, v in plan.items() if k != 'digest_sha256'}) != expected_digest
                or plan.get('status') != 'ready'):
            raise WindowsRuntimeError('Windows runtime plan is not approved or canonical')
        plan = loads_strict_json(canonical_bytes(plan))
        sources = list(sources)
        prior = self.inspect()
        if prior is not None and plan['transaction_id'] in {
                ref['transaction_id'] for ref in prior.manifest['receipts']}:
            with ExitStack() as replay_stack:
                transactions = self._walk(replay_stack, _join(self.project_root,
                    prov.ROOT + '\\transactions'), publish=False)
                directory = replay_stack.enter_context(self.handles.open_child(
                    transactions, plan['operation_id'], kind='directory', pin_for_read=True))
                saved = _read_existing_record(self.handles, directory, 'plan.json',
                                              16 * 1024 * 1024)
                intent = _read_existing_record(self.handles, directory, 'intent.json',
                                               16 * 1024 * 1024)
                marker = _read_existing_record(self.handles, directory, 'committed.json',
                                               64 * 1024)
                reader = prov.WindowsProvenanceReader(self.observer, self.project_root)
                receipt, _ = prov._decode(reader.read(prov.receipt_path(
                    plan['transaction_id'])), prov.RECEIPT_SCHEMA, prov._RECEIPT_KEYS)
                operation_schema = (OP_SCHEMA_V2 if saved.get('schema') == OP_PLAN_SCHEMA_V2
                                    else OP_SCHEMA)
                if (saved.get('schema') not in (OP_PLAN_SCHEMA, OP_PLAN_SCHEMA_V2)
                        or intent.get('schema') != operation_schema
                        or saved.get('plan') != plan
                        or saved.get('plan_sha256') != hashlib.sha256(canonical_bytes(plan)).hexdigest()
                        or intent.get('plan_sha256') != saved['plan_sha256']
                        or marker.get('schema') != operation_schema
                        or marker.get('direction') != 'forward'
                        or marker.get('topology') != 'committed'
                        or marker.get('intent_sha256') != hashlib.sha256(_envelope(intent)).hexdigest()
                        or receipt['plan_sha256'] != expected_digest):
                    raise WindowsRuntimeError('Committed replay differs from validated history')
                if plan['schema'] == SCHEMA:
                    self._directory_journal(replay_stack, directory, plan, intent).validate('committed')
            return {'status': 'committed', 'transaction_id': plan['transaction_id'],
                    'receipt_path': prov.receipt_path(plan['transaction_id']),
                    'detail': 'Previously committed operation; no new mutation',
                    'created_paths': [r['path'] for r in plan['rows']
                                      if r['action'].startswith('CREATE_')]}
        if plan['schema'] == LEGACY_SCHEMA:
            raise WindowsRuntimeError('Uncommitted legacy Windows plan: regenerate the plan before apply')
        ids = {key: plan[key] for key in ('operation_id', 'transaction_id', 'project_id')}
        rebuilt = self._build_plan(sources, request=plan['request'], checks=plan['checks'],
                                   allow_enrollment=plan['enrollment'], ids=ids)
        if rebuilt != plan:
            raise WindowsRuntimeError('Windows runtime plan inputs changed')
        self._verify_state(plan, sources)
        changed = [r for r in plan['rows'] if r['action'] in _MUTATIONS]
        if not changed:
            return {'status': 'no_changes', 'transaction_id': None,
                    'receipt_path': None, 'detail': 'No managed publication', 'created_paths': []}
        policy_obs, policy_raw, _ = self._policy()
        del policy_obs
        snapshot = self.inspect()
        self._prior_operations_quiescent(snapshot)
        if snapshot is None:
            enrollment = prov.make_empty_enrollment(
                project_id=plan['project_id'], root_identity=plan['project_root_identity'],
                enrollment_plan_sha256=expected_digest,
                source_policy_snapshot_sha256=plan['source_policy_snapshot_sha256'])
            snapshot = prov.load_windows_provenance(_MapReader(enrollment),
                root_identity=plan['project_root_identity'], source_policy_raw=policy_raw)
        stack, runtime_parent, staging_parent, templates = self._prepare(plan)
        with stack:
            # A preexisting staging directory is unknown residue, never adopted.
            stage = stack.enter_context(self.handles.create_private_directory(
                staging_parent, plan['operation_id']))
            stage_root = _join(self.project_root, prov.ROOT + '\\staging\\' + plan['operation_id'])
            files: list[tuple[str, bytes, str, str]] = []
            changes: dict[str, dict[str, Any]] = {}
            source_by_path = dict(sources)
            for index, row in enumerate(changed):
                path = row['path']
                drive, relative = _absolute(source_by_path[path])
                observed, data = self.observer.observe(drive, relative, capture_bytes=True)
                if observed is None or data is None or hashlib.sha256(data).hexdigest() != row['source']['sha256']:
                    raise WindowsRuntimeError('Source changed during staging')
                stage_name = f'content-{index:06d}.bin'
                target = _join(self.project_root, path)
                updating = row['action'] == 'UPDATE_FROM_UPSTREAM'
                intended_attributes = row['before']['attributes'] if updating else _ATTR_ARCHIVE
                self._stage_bytes(stage, stage_name, data,
                                  target if updating else None,
                                  intended_attributes if updating else None)
                stage_relative = prov.ROOT + '\\staging\\' + plan['operation_id'] + '\\' + stage_name
                staged_obs, staged_data = self.observer.observe(self.project_root, stage_relative,
                                                                  capture_bytes=True)
                if (staged_obs is None or staged_obs['presence'] != 'present' or staged_data != data
                        or staged_obs['attributes'] != intended_attributes
                        or staged_obs['comparison_metadata_sha256'] != row['intended']['metadata_sha256']):
                    raise WindowsRuntimeError('Staged content metadata differs from approved policy')
                changes[path] = {'content': {'kind': 'file', 'size_decimal': row['source']['size_decimal'],
                    'sha256': row['source']['sha256'],
                    'metadata_sha256': staged_obs['comparison_metadata_sha256']},
                    'archive_bytes': data}
                files.append((path, data, 'content', stage_name))
            records = prov.make_commit_records(snapshot, transaction_id=plan['transaction_id'],
                plan_sha256=expected_digest, changes=changes, source_policy_raw=policy_raw,
                request=plan['request'])
            if plan['enrollment']:
                records.update({k: v for k, v in enrollment.items()
                                if k != prov.MANIFEST_PATH})
            reader = prov.WindowsProvenanceReader(self.observer, self.project_root) if not plan['enrollment'] else None
            for path in sorted(records):
                if path == prov.MANIFEST_PATH:
                    continue
                existing = reader.read(path) if reader is not None else None
                if existing is not None:
                    if existing != records[path]:
                        raise WindowsRuntimeError('Existing immutable evidence differs')
                    continue
                stage_name = f'evidence-{len(files):06d}.bin'
                self._stage_bytes(stage, stage_name, records[path])
                files.append((path, records[path], 'evidence', stage_name))
            manifest_name = f'manifest-{len(files):06d}.json'
            self._stage_bytes(stage, manifest_name, records[prov.MANIFEST_PATH])
            files.append((prov.MANIFEST_PATH, records[prov.MANIFEST_PATH], 'manifest', manifest_name))
            expected_directories = absent_content_parents(plan)
            created_directories = {}
            for path, _data, role, _name in files:
                drive, parents, _leaf = _split_leaf(_join(self.project_root, path))
                with ExitStack() as parents_stack:
                    self._walk(parents_stack, drive + '\\'.join(parents),
                               publish=True, create=True,
                               created_directories=created_directories if role == 'content' else None,
                               expected_directories=expected_directories)
            if set(created_directories) != set(expected_directories):
                raise WindowsRuntimeError('Publication-parent creation witnesses are incomplete')
            slots: dict[str, str] = {}
            publications = []
            for index, (path, _data, role, stage_name) in enumerate(files):
                target_key, staged_key, backup_key = (f'target-{index}', f'staged-{index}',
                                                      f'backup-{index}')
                slots[target_key] = _join(self.project_root, path)
                slots[staged_key] = stage_root + '\\' + stage_name
                if role == 'manifest' and not plan['enrollment'] or role == 'content' and next(
                        (r for r in changed if r['path'] == path), None)['action'] == 'UPDATE_FROM_UPSTREAM':
                    slots[backup_key] = stage_root + '\\' + backup_key
            with WindowsRestoringBackend(self.handles, slots) as backend:
                for index, (path, _data, role, _name) in enumerate(files):
                    target_key, staged_key, backup_key = (f'target-{index}', f'staged-{index}',
                                                          f'backup-{index}')
                    before, after = backend.observe(target_key), backend.observe(staged_key)
                    kind = 'replace' if backup_key in slots else 'create'
                    if kind == 'create' and before is not None:
                        raise WindowsRuntimeError('Creation target collided before operation')
                    if kind == 'replace' and before is None:
                        raise WindowsRuntimeError('Replacement target disappeared')
                    publications.append(Publication(role, kind, target_key, staged_key,
                                                    after, backup_key if kind == 'replace' else None,
                                                    before))
            spec = WindowsOperationSpec(plan['operation_id'], plan, slots, tuple(publications),
                                        record_version=2)
            with WindowsOperation(self.handles, runtime_parent, *templates, spec) as operation:
                directory_journal = DirectoryJournal(self.handles, operation.directory,
                    templates[1], plan['operation_id'], operation._intent_sha256, expected_directories,
                    plan['project_root_identity'], existing_parent_anchors(plan))
                directory_journal.persist([created_directories[p] for p in expected_directories])
                # The operation holds managed-scope.lock before the first move.
                self._prior_operations_quiescent(snapshot if not plan['enrollment'] else None,
                                                  exclude=plan['operation_id'])
                self._verify_state(plan, sources, prepared=True)
                if preapply_revalidator is not None:
                    observation = (_EnrollmentObservation(self, plan, sources, operation, runtime_parent)
                                   if plan['enrollment'] else None)
                    token = _ENROLLMENT_OBSERVATION.set(observation)
                    try:
                        if preapply_revalidator() is False:
                            raise WindowsRuntimeError('Pre-apply governance revalidation refused')
                    finally:
                        if observation is not None:
                            observation.active = False
                        _ENROLLMENT_OBSERVATION.reset(token)
                self._verify_state(plan, sources, prepared=True)
                directory_journal.verify_created(self.project_root, self._walk)
                status = operation.apply()
            return {'status': status, 'transaction_id': plan['transaction_id'],
                    'receipt_path': prov.receipt_path(plan['transaction_id']),
                    'detail': 'Managed Windows publication committed',
                    'created_paths': [r['path'] for r in changed if r['action'].startswith('CREATE_')]}

    def is_exact_init_repeat(self, sources: list[tuple[str, str]], *, request: dict,
                             checks: list) -> bool:
        """Recognize a recorded init invocation without granting mutation authority."""
        snapshot = self.inspect()
        if snapshot is None or request != {'operation': 'naos-init', 'inputs': snapshot.previous_inputs}:
            return False
        self._prior_operations_quiescent(snapshot)
        source_rows = self._source_rows(sources)
        receipt_refs = {ref['transaction_id']: ref['sha256'] for ref in snapshot.manifest['receipts']}
        reader = prov.WindowsProvenanceReader(self.observer, self.project_root)
        with ExitStack() as stack:
            runtime = self._walk(stack, _join(self.project_root, prov.ROOT + '\\transactions'), publish=False)
            for name in self.handles.list_children(runtime):
                if name == 'managed-scope.lock':
                    continue
                directory = stack.enter_context(self.handles.open_child(
                    runtime, name, kind='directory', pin_for_read=True))
                saved = _read_existing_record(self.handles, directory, 'plan.json', 16 * 1024 * 1024)
                plan = saved.get('plan')
                if (not isinstance(plan, dict) or plan.get('request') != request
                        or plan.get('checks') != checks
                        or plan.get('transaction_id') not in receipt_refs):
                    continue
                receipt, receipt_sha = prov._decode(reader.read(prov.receipt_path(plan['transaction_id'])),
                                                   prov.RECEIPT_SCHEMA, prov._RECEIPT_KEYS)
                if (saved.get('plan_sha256') != hashlib.sha256(canonical_bytes(plan)).hexdigest()
                        or plan.get('operation_id') != name
                        or canonical_sha256({k: v for k, v in plan.items() if k != 'digest_sha256'}) != plan.get('digest_sha256')
                        or receipt_sha != receipt_refs[plan['transaction_id']]
                        or receipt['plan_sha256'] != plan.get('digest_sha256')
                        or plan.get('project_root_identity') != snapshot.root_identity
                        or source_rows != [row['source'] for row in plan['rows']]):
                    continue
                selected = {row['path'] for row in source_rows}
                if not selected <= self.current_paths():
                    return False
                for row in source_rows:
                    current = snapshot.entries[row['path']]['content']
                    if (current['sha256'] != row['sha256'] or current['size_decimal'] != row['size_decimal']):
                        return False
                closing = self.inspect()
                if closing is None or closing.manifest_sha256 != snapshot.manifest_sha256:
                    return False
                self._prior_operations_quiescent(closing)
                return True
        return False

    def current_paths(self) -> set[str]:
        observation = _active_enrollment_observation()
        if observation is not None:
            observation.validate(self)
            return set()
        snapshot = self.inspect()
        if snapshot is None:
            return set()
        found = set()
        for path, entry in snapshot.entries.items():
            observed, _ = self.observer.observe(self.project_root, path)
            if observed is not None and observed['presence'] == 'present':
                if _content(observed).comparison_key() == WindowsContentIdentity(
                        'present', **entry['content']).comparison_key():
                    found.add(path)
        return found

    def recover(self) -> list[dict[str, Any]]:
        if not self._control_exists():
            return []
        with ExitStack() as stack:
            runtime = self._walk(stack, _join(self.project_root, prov.ROOT + '\\transactions'),
                                 publish=True)
            scope_lock = stack.enter_context(self.handles.open_child(
                runtime, 'managed-scope.lock', kind='file', for_lock=True))
            scope_lock.lock_exclusive()
            names = tuple(name for name in self.handles.list_children(runtime)
                          if name != 'managed-scope.lock')
            if any(not name.startswith('WOP-') for name in names):
                raise WindowsRuntimeError('Unknown operation entry in runtime')
            # Discover and validate *every* saved journal before touching any
            # live target. Directory order has no relation to receipt order.
            journals = {name: self._recovery_journal(runtime, scope_lock, name)
                        for name in names}
            unfinished = [name for name, journal in journals.items()
                          if journal['terminal'] is None or journal['cleanup_pending']]
            if len(unfinished) > 1:
                raise WindowsRuntimeError('Multiple unfinished operations require manual recovery')
            results: dict[str, dict[str, Any]] = {}
            if unfinished:
                name = unfinished[0]
                journal = journals[name]
                if journal['terminal'] is None:
                    self._recovery_predecessor(journal)
                    with WindowsOperation.from_journal(self.handles, runtime,
                                                       *self._templates(stack), name,
                                                       held_scope_lock=scope_lock) as operation:
                        if tuple(n for n in self.handles.list_children(runtime)
                                 if n != 'managed-scope.lock') != names:
                            raise WindowsRuntimeError('Operation directory changed during recovery')
                        self._recovery_predecessor(journal)
                        status = operation.recover()
                else:
                    status = 'rolled_back'
                # Release backend target-parent pins before directory deletion.
                if status == 'rolled_back' and journal['plan']['schema'] == SCHEMA:
                    with ExitStack() as cleanup_stack:
                        directory = cleanup_stack.enter_context(self.handles.open_child(
                            runtime, name, kind='directory', for_publish=True))
                        self._directory_journal(cleanup_stack, directory, journal['plan'],
                                                journal['intent']).cleanup(self.project_root, self._walk)
                results[name] = {'operation_id': name, 'status': status}
            try:
                snapshot = self.inspect()
            except prov.WindowsProvenanceError:
                snapshot = None
            if snapshot is None and (len(journals) != 1 or
                                     not next(iter(journals.values()))['plan']['enrollment']):
                raise WindowsRuntimeError('Partial control lacks one enrolled operation journal')
            receipt_ids = ([r['transaction_id'] for r in snapshot.manifest['receipts']]
                           if snapshot is not None else [])
            for name, journal in journals.items():
                if name in results:
                    continue
                terminal = journal['terminal']
                if terminal == 'rolled_back':
                    # The exact terminal marker is bound to the saved intent.
                    # An old prepared topology may be obsolete after a later
                    # validated commit, so do not reopen its old target IDs.
                    results[name] = {'operation_id': name,
                                     'status': 'rolled_back_recorded'}
                    continue
                if terminal != 'committed' or snapshot is None:
                    raise WindowsRuntimeError('Operation remains unfinished or history is invalid')
                receipt_id = journal['plan']['transaction_id']
                if receipt_id not in receipt_ids:
                    raise WindowsRuntimeError('Committed operation lacks validated receipt')
                reader = prov.WindowsProvenanceReader(self.observer, self.project_root)
                receipt, _sha = prov._decode(reader.read(prov.receipt_path(receipt_id)),
                                            prov.RECEIPT_SCHEMA, prov._RECEIPT_KEYS)
                if receipt['plan_sha256'] != journal['plan']['digest_sha256']:
                    raise WindowsRuntimeError('Committed receipt plan differs')
                if receipt_id in receipt_ids[:-1]:
                    results[name] = {'operation_id': name,
                                     'status': 'superseded_committed'}
                else:
                    with WindowsOperation.from_journal(self.handles, runtime,
                                                       *self._templates(stack), name,
                                                       held_scope_lock=scope_lock) as operation:
                        results[name] = {'operation_id': name,
                                         'status': operation.recover()}
            return [results[name] for name in names]

    def _recovery_journal(self, runtime: Any, scope_lock: Any,
                          name: str) -> dict[str, Any]:
        with self.handles.open_child(runtime, name, kind='directory',
                                     pin_for_read=True) as directory:
            plan_record = _read_existing_record(self.handles, directory,
                                                'plan.json', 16 * 1024 * 1024)
            intent = _read_existing_record(self.handles, directory,
                                           'intent.json', 16 * 1024 * 1024)
            plan = plan_record.get('plan')
            record_version = 2 if plan_record.get('schema') == OP_PLAN_SCHEMA_V2 else 1
            operation_schema = OP_SCHEMA_V2 if record_version == 2 else OP_SCHEMA
            decode_identity = _rename_from_record if record_version == 2 else _identity_from_record
            intent_keys = {'schema', 'failure_model', 'operation_id', 'plan_sha256',
                'slot_paths', 'publications', 'runtime_parent_id', 'scope_lock_id',
                'transaction_directory_id', 'lock_id'}
            if (not isinstance(plan, dict)
                    or set(plan_record) != {'schema', 'operation_id', 'plan', 'plan_sha256'}
                    or set(intent) != intent_keys
                    or plan_record.get('schema') not in (OP_PLAN_SCHEMA, OP_PLAN_SCHEMA_V2)
                    or plan_record.get('operation_id') != name
                    or plan.get('schema') not in (LEGACY_SCHEMA, SCHEMA) or plan.get('operation_id') != name
                    or plan.get('project_root_identity') != self.observer.root_identity(self.project_root)
                    or canonical_sha256({k: v for k, v in plan.items()
                                         if k != 'digest_sha256'}) != plan.get('digest_sha256')
                    or plan_record.get('plan_sha256') != hashlib.sha256(canonical_bytes(plan)).hexdigest()
                    or intent.get('schema') != operation_schema
                    or intent.get('failure_model') != 'application_crash_v1'
                    or intent.get('operation_id') != name
                    or intent.get('plan_sha256') != plan_record['plan_sha256']
                    or intent.get('runtime_parent_id') != _id(runtime.info())
                    or intent.get('scope_lock_id') != _id(scope_lock.info())
                    or intent.get('transaction_directory_id') != _id(directory.info())
                    or not isinstance(intent.get('slot_paths'), dict)
                    or not isinstance(intent.get('publications'), list)):
                raise WindowsRuntimeError('Operation journal plan or root binding differs')
            with self.handles.open_child(directory, 'lock', kind='file',
                                         pin_for_read=True) as transaction_lock:
                if intent.get('lock_id') != _id(transaction_lock.info()):
                    raise WindowsRuntimeError('Operation lock identity differs')
            try:
                publications = []
                for row in intent['publications']:
                    if not isinstance(row, dict) or row.get('kind') not in {'create', 'replace'}:
                        raise ValueError('Invalid publication kind')
                    fields = ({'role', 'kind', 'target', 'staged', 'after'}
                              if row['kind'] == 'create' else
                              {'role', 'kind', 'target', 'staged', 'after', 'backup', 'before'})
                    if set(row) != fields:
                        raise ValueError('Invalid publication fields')
                    publications.append(Publication(row['role'], row['kind'], row['target'],
                        row['staged'], decode_identity(row['after']),
                        row.get('backup'), decode_identity(row['before'])
                        if row['kind'] == 'replace' else None))
                WindowsOperationSpec(name, plan, intent['slot_paths'],
                                     tuple(publications), record_version).validate()
            except (KeyError, TypeError, ValueError) as exc:
                raise WindowsRuntimeError('Operation journal publication differs') from exc
            marker_hash = hashlib.sha256(_envelope(intent)).hexdigest()
            terminal = None
            for filename, direction, topology, status in (
                    ('committed.json', 'forward', 'committed', 'committed'),
                    ('rolled-back.json', 'rollback', 'prepared', 'rolled_back')):
                try:
                    marker = _read_existing_record(self.handles, directory,
                                                   filename, 64 * 1024)
                except WindowsJournalConflict as exc:
                    cause = exc.__cause__
                    if (isinstance(cause, WindowsHandleError)
                            and cause.operation == 'NtCreateFile'
                            and cause.ntstatus == _MISSING):
                        continue
                    raise
                if (set(marker) != {'schema', 'failure_model', 'intent_sha256',
                                    'direction', 'topology'}
                        or marker['schema'] != operation_schema
                        or marker['failure_model'] != 'application_crash_v1'
                        or marker['intent_sha256'] != marker_hash
                        or marker['direction'] != direction
                        or marker['topology'] != topology or terminal is not None):
                    raise WindowsRuntimeError('Operation terminal marker conflicts')
                terminal = status
            cleanup_pending = False
            if plan['schema'] == SCHEMA:
                with ExitStack() as directory_stack:
                    state = self._directory_journal(directory_stack, directory, plan, intent).validate(terminal)
                    cleanup_pending = terminal == 'rolled_back' and not state[-1]
            return {'plan': plan, 'intent': intent, 'cleanup_pending': cleanup_pending,
                    'terminal': terminal, 'publications': publications}

    def _directory_journal(self, stack, directory, plan, intent):
        return DirectoryJournal(self.handles, directory, self._templates(stack)[1],
                                plan['operation_id'], hashlib.sha256(_envelope(intent)).hexdigest(),
                                absent_content_parents(plan), plan['project_root_identity'],
                                existing_parent_anchors(plan))

    def _recovery_predecessor(self, journal: dict[str, Any]) -> None:
        plan = journal['plan']
        if plan['enrollment']:
            if plan['expected_manifest_sha256'] is not None:
                raise WindowsRuntimeError('Enrollment journal claims prior manifest')
            return
        _policy_observation, policy_raw, active = self._policy()
        if (hashlib.sha256(policy_raw).hexdigest() != plan['source_policy_sha256']
                or active != plan['source_policy_snapshot_sha256']):
            raise WindowsRuntimeError('Recovery source-policy binding changed')
        snapshot = None
        try:
            snapshot = self.inspect()
        except prov.WindowsProvenanceError:
            pass
        if snapshot is not None and snapshot.manifest_sha256 == plan['expected_manifest_sha256']:
            return
        manifests = [row for row in journal['publications'] if row.role == 'manifest']
        if len(manifests) != 1 or manifests[0].kind != 'replace':
            raise WindowsRuntimeError('Update journal lacks prior manifest backup')
        backup = journal['intent']['slot_paths'][manifests[0].backup]
        drive, relative = _absolute(backup)
        observed, prior_bytes = self.observer.observe(drive, relative, capture_bytes=True)
        if observed is None or observed['presence'] != 'present' or prior_bytes is None:
            raise WindowsRuntimeError('Prior manifest backup is absent')
        reader = prov.WindowsProvenanceReader(self.observer, self.project_root)

        class PriorReader:
            def read(self, relative_path: str) -> bytes | None:
                return prior_bytes if relative_path == prov.MANIFEST_PATH else reader.read(relative_path)

        previous = prov.load_windows_provenance(PriorReader(),
            root_identity=plan['project_root_identity'], source_policy_raw=policy_raw)
        if (previous.manifest_sha256 != plan['expected_manifest_sha256']
                or previous.owner_sha256 != plan['expected_owner_sha256']):
            raise WindowsRuntimeError('Prior manifest backup is not the approved history')

    def _templates(self, stack: ExitStack) -> tuple[Any, Any]:
        control = self._walk(stack, _join(self.project_root, prov.ROOT), publish=True)
        return (stack.enter_context(self.handles.open_child(control, 'template.directory',
                     kind='directory', for_publish=True)),
                stack.enter_context(self.handles.open_child(control, 'template.file',
                     kind='file', pin_for_read=True)))


def create_project_root(handles: Any, path: str) -> dict[str, str]:
    drive, parents, leaf = _split_leaf(path)
    with ExitStack() as stack:
        parent = stack.enter_context(handles.open_root(drive, for_publish=not parents))
        for index, component in enumerate(parents):
            final = index == len(parents) - 1
            parent = stack.enter_context(handles.open_child(parent, component,
                kind='directory', for_publish=final, pin_for_read=not final))
        with handles.create_private_directory(parent, leaf) as created:
            return _id(created.info())
