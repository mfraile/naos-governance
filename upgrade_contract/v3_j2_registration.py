"""J1 rebind -> J2 private preparation and lossless local-state registration.

Bounded native composition only. This leaves the old portable head and binding in
place, makes J2 active, and grants no working/portable publication authority.
"""
from __future__ import annotations

from . import v3_operation_context as operation_context

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import ntpath
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from . import joint_capture as joint
from . import local_binding as lb, local_store as ls, portable_provenance as pp
from . import rebind_checkpoint as checkpoint
from . import rebind_store_inspection as ris
from . import v3_j1_rebind_predecessor as j1
from . import v3_operation_records as operation
from . import v3_durable_replay as replay
from .canonical import canonical_bytes
from .transaction import rename_no_replace_at
from .windows_restoring_backend import WindowsRestoringBackend
from .windows_rename_identity import identity_record, identity_from_record

ROOT = ris.ROOT
JOURNALS = ROOT + '/journals'
J2 = JOURNALS + '/J00000002'
PROGRESS = J2 + '/progress'
STATE = ROOT + '/state.json'
BINDING = ROOT + '/binding.json'
STAGE = J2 + '/state.registered.pending.json'
BACKUP = J2 + '/state.before.json'
COMMITMENT = J2 + '/registration.json'
PLAN = J2 + '/plan.json'
INTENT = J2 + '/intent.json'
PRIOR_BINDING = J2 + '/predecessor.binding.json'
PRIOR_STATE = J2 + '/predecessor.state.json'
SCHEMA = 'naos.upgrade.v3_j2_registration.v1'
REPLAY_SCHEMA = 'naos.upgrade.v3_j2_registration.v2'
FILES_PREPARED = {'progress', 'plan.json', 'intent.json',
                  'predecessor.binding.json', 'predecessor.state.json',
                  'state.registered.pending.json', 'registration.json'}


class J2RegistrationError(ValueError):
    pass


def _fail(message):
    raise J2RegistrationError(message)


@dataclass(frozen=True)
class J2Registration:
    phase: str
    plan_sha256: str
    intent_sha256: str
    registered_state_sha256: str
    predecessor_state_sha256: str
    predecessor_binding_sha256: str
    journal_id: str = 'J00000002'
    mutation_authorized: bool = False


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _native(custody, windows):
    reader = custody.reader if windows else custody.reader.reader
    native = ris._NativeStore(SimpleNamespace(working_reader=reader), windows)
    native.operation_custody = custody
    native.operation_context = operation_context.from_custody(custody)
    native.lock_handle = custody.lock_handle
    native.lock_witness = custody.lock_witness
    return native


@contextmanager
def _fresh_native(root, custody, windows):
    # A new read lane after own writes; the earlier joint reader has closed.
    with ExitStack() as stack:
        if windows:
            from .working_tree_capture_windows import _Capture
            reader = _Capture(custody.reader.handles, str(root), stack)
        else:
            from .security import _native_metadata_binding_scope
            stack.enter_context(_native_metadata_binding_scope())
            from .working_tree_capture_posix import _Reader
            reader = stack.enter_context(_Reader(Path(root)))
        native = ris._NativeStore(SimpleNamespace(working_reader=reader), windows)
        native.operation_custody = custody
        native.operation_context = operation_context.from_custody(custody)
        native.lock_handle = custody.lock_handle
        native.lock_witness = custody.lock_witness
        yield native
        from .v3_j1_migration_predecessor import validate_legacy
        validate_legacy(custody)
        if windows:
            reader.revalidate()
        custody.check_lock()


def _names(native, relative, expected):
    actual = native.children(relative)
    if actual != expected:
        _fail(f'Unknown, missing or partial native inventory: {relative}')


def _pin_directory(custody, relative, *, create, pins):
    """Pin only the fixed next-journal directories beneath held private parents."""
    parent_path, _, name = relative.rpartition('/')
    reader = custody.reader
    if custody.windows:
        key = reader.directory(parent_path)
        parent = reader.directories[key]
        child_key = key + (name,)
        if child_key in reader.directories:
            _fail('Next journal directory was unexpectedly pre-pinned')
        if create:
            handle = reader.handles.create_private_directory(parent, name)
        else:
            handle = reader.handles.open_child(parent, name, kind='directory', pin_for_read=True)
        reader._pin(child_key, handle)
        if key in reader.names:
            reader.names[key][name.casefold()] = name
        witness = reader.directory_witness(relative)
    else:
        from .portable_provenance_posix import _same_namespace, _witness
        parent = reader.fds[parent_path]
        if create:
            os.mkdir(name, 0o700, dir_fd=parent)
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        pins.callback(os.close, fd)
        if create:
            os.fchmod(fd, 0o700)
            os.fsync(fd)
            os.fsync(parent)
        observed = _witness(fd, leaf=False, label=relative)
        _same_namespace(parent, name, observed, leaf=False, label=relative)
        witness = lb.project_posix_witness(observed.metadata)
        reader.fds[relative] = fd
        reader.witnesses[relative] = witness
    ris._NativeStore(SimpleNamespace(working_reader=reader if custody.windows else reader.reader),
                     custody.windows)._private(witness)
    custody.check_lock()
    return witness


def _source_capture(root, custody, evidence, windows, *, state_source):
    """Read J1 immutable history while allowing only the exact J2 bridge shape."""
    extras = tuple(sorted(evidence['requested']))
    context = (joint._held_windows(str(root), extras, custody.reader.handles) if windows
               else joint._held_posix(Path(root), extras))
    return context


def _historical(native, portable, *, state_source):
    _ctx = operation_context.from_custody(native)
    if _ctx != operation_context.DEFAULT or getattr(native.operation_custody, "migration_candidate", None) is not None:
        from .v3_operation_history import _inspect_native
        proof = _inspect_native(native, portable, _ctx, binding_source=_ctx.registration.BINDING, state_source=state_source)
        return {_ctx.registration.STATE: proof.state.raw, _ctx.registration.BINDING: proof.binding.raw}, None, None, proof.state, proof.binding
    _names(native, j1.JOURNAL, {'plan.json', 'intent.json', 'progress', 'terminal.json'})
    revisions = native.children(j1.PROGRESS)
    if not 1 <= len(revisions) <= j1.MAX_PROGRESS or revisions != {
            f'{i:08d}.json' for i in range(len(revisions))}:
        _fail('Historical J1 progress inventory differs')
    progress_paths = tuple(j1.PROGRESS + '/' + x for x in sorted(revisions))
    raw = {path: native.read(path) for path in (j1.PLAN, j1.INTENT,
            *progress_paths, j1.TERMINAL, _ctx.registration.BINDING)}
    raw[_ctx.registration.STATE] = native.read(state_source)
    plan, intent, history, state, binding = j1._semantic_j1(raw, portable)
    if native.observations[_ctx.registration.BINDING]['metadata'] != history.records[-1].body['publication_witness']:
        _fail('J1 binding native witness differs from terminal publication')
    if (native.lock_witness != intent.body['storage_witnesses']['lock'] or
            native.directory(j1.JOURNAL) != intent.body['storage_witnesses']['journal']):
        _fail('J1 lock or journal witness differs')
    return raw, intent, history, state, binding


def _check_plan(root, custody, held, native, plan, evidence, windows, *, state_source, allow_pending_state=False):
    _ctx = operation_context.for_plan(plan)
    raw, old_intent, history, state, binding = _historical(native, held.result.portable,
                                                           state_source=state_source)
    if (raw[_ctx.registration.STATE] != evidence['predecessor_store'].raw or
            raw[_ctx.registration.BINDING] != evidence['predecessor_binding'].raw or
            held.result.working_tree != evidence['capture']):
        _fail('Predecessor bytes or complete current capture changed')
    witnesses = evidence['predecessor_record_witnesses']
    if ((not allow_pending_state and native.observations[state_source]['metadata'] != witnesses['state']) or
            native.observations[_ctx.registration.BINDING]['metadata'] != witnesses['binding']):
        _fail('Predecessor state/binding native identity changed')
    legacy = (held.working_reader.directory_witness('.naos/upgrade-v1') if windows
              else held.working_reader.directory('.naos/upgrade-v1'))
    if (legacy['presence'] != 'absent' and getattr(custody, 'migration_candidate', None) is None
            and getattr(custody, 'receiving_legacy', None) is None):
        _fail('Legacy control appeared')
    for path, expected in evidence['portable_files'].items():
        if held.portable_reader.read(path) != expected:
            _fail('Portable native bytes differ from approved plan')
    if (binding.sha256 != plan.body['prior_binding_sha256'] or
            state.sha256 != plan.body['prior_store_sha256']):
        _fail('Historical checkpoint differs from approved J2 plan')
    return raw, state, binding


def _windows_backend(root, custody):
    _ctx = operation_context.from_custody(custody)
    base = str(root)
    slots = {'state': ntpath.join(base, _ctx.registration.STATE.replace('/', '\\')),
             'stage': ntpath.join(base, _ctx.registration.STAGE.replace('/', '\\')),
             'backup': ntpath.join(base, _ctx.registration.BACKUP.replace('/', '\\'))}
    return WindowsRestoringBackend(custody.reader.handles, slots)


def _commitment(plan, intent, state, registered, stage_witness, progress_witness,
                old_rename, stage_rename, replay_binding=None):
    _ctx = operation_context.for_plan(plan)
    if _ctx != operation_context.DEFAULT and replay_binding is None:
        _fail('Repeated registration requires complete durable replay')
    body = {'schema': SCHEMA if replay_binding is None else _ctx.registration.REPLAY_SCHEMA, 'plan_sha256': plan.sha256,
            'intent_sha256': intent.sha256, 'journal_id': _ctx.journal_id,
            'predecessor_state_sha256': state.sha256,
            'registered_state_sha256': registered.sha256,
            'predecessor_state_witness': plan.body['predecessor_record_witnesses']['state'],
            'stage_witness': stage_witness, 'progress_witness': progress_witness,
            'old_rename_identity': old_rename, 'stage_rename_identity': stage_rename}
    if replay_binding is not None:
        body['replay_binding'] = replay_binding
    lb._bounded_input(body)
    raw = canonical_bytes(body)
    if len(raw) > lb.MAX_RECORD_BYTES:
        _fail('Registration commitment exceeds byte budget')
    return raw


def _prepared_names(native):
    _ctx = operation_context.from_custody(native)
    body = pp._load_json(native.read(_ctx.registration.COMMITMENT), 'registration variant')
    if body.get('schema') == _ctx.registration.REPLAY_SCHEMA and 'replay_binding' in body:
        return FILES_PREPARED | {'replay'}
    if body.get('schema') == SCHEMA and 'replay_binding' not in body:
        return FILES_PREPARED
    _fail('Unknown registration variant')


def _validate_replay(native, commitment, plan, evidence):
    _ctx = operation_context.for_plan(plan)
    if _ctx != operation_context.DEFAULT and commitment.get('schema') != _ctx.registration.REPLAY_SCHEMA:
        _fail('Repeated operations require their explicit durable registration variant')
    if commitment.get('schema') == _ctx.registration.REPLAY_SCHEMA:
        if 'replay_binding' not in commitment:
            _fail('Missing replay binding')
        replay.validate(native, commitment['replay_binding'], plan, evidence)
    elif commitment.get('schema') != SCHEMA or 'replay_binding' in commitment:
        _fail('Unknown registration replay variant')


def _read_exact(native, path, expected):
    if native.read(path) != expected:
        _fail(f'Exact native record bytes differ: {path}')
    return native.observations[path]['metadata']


def _verify_records(root, custody, *, state_path, state_raw, state_witness,
                    binding_raw, binding_witness):
    _ctx = operation_context.from_custody(custody)
    with _fresh_native(root, custody, custody.windows) as native:
        if (_read_exact(native, state_path, state_raw) != state_witness or
                _read_exact(native, _ctx.registration.BINDING, binding_raw) != binding_witness):
            _fail('Approved predecessor/native record identity changed')


def _private_baseline(native, *, phase, old_state_raw, registered_raw=None,
                      stage_witness=None, prior=None, publication_child=False):
    """Capture fixed private records; never treat a later scan as new authority."""
    _ctx = operation_context.from_custody(native)
    if (_ctx != operation_context.DEFAULT or getattr(native.operation_custody, 'migration_candidate', None) is not None) and prior is None:
        proof = native.completed_prefix
        j1_files = {path: value for path, value in proof.records.items() if path != _ctx.registration.STATE}
        j1_dirs = proof.directories
        old_path = _ctx.registration.STATE if phase in ('needs_preparation', 'prepared') else _ctx.registration.BACKUP
        old_observation = deepcopy(native.observations[old_path])
        historical_replays, historical_leaves = proof.replay_bindings, proof.retained_leaves
        historical_directories = proof.retained_directories
    else:
        progress = native.children(j1.PROGRESS)
        j1_paths = (j1.PLAN, j1.INTENT, *(j1.PROGRESS + '/' + name for name in sorted(progress)),
                    j1.TERMINAL, _ctx.registration.BINDING)
        if prior is None:
            j1_files = {path: (native.read(path), deepcopy(native.observations[path]))
                        for path in j1_paths}
            j1_dirs = {path: (deepcopy(native.directory(path)), frozenset(native.children(path)))
                       for path in (j1.JOURNAL, j1.PROGRESS)}
            old_path = _ctx.registration.STATE if phase in ('needs_preparation', 'prepared') else _ctx.registration.BACKUP
            old_observation = deepcopy(native.observations[old_path])
        else:
            j1_files, j1_dirs, old_observation = (prior['j1_files'], prior['j1_dirs'],
                                                    prior['old_observation'])
        historical_replays = () if prior is None else prior.get('historical_replays', ())
        historical_leaves = {} if prior is None else prior.get('historical_leaves', {})
        historical_directories = {} if prior is None else prior.get('historical_directories', {})
    result = {'j1_files': j1_files, 'j1_dirs': j1_dirs,
              'old_raw': old_state_raw, 'old_observation': old_observation,
              'j2_files': {}, 'j2_dirs': {}, 'registered_raw': registered_raw,
              'stage_observation': None, 'publication_child': publication_child, 'replay_binding': None}
    result['historical_replays'] = historical_replays
    result['historical_leaves'] = historical_leaves
    result['historical_directories'] = historical_directories
    if phase != 'needs_preparation':
        commitment = pp._load_json(native.read(_ctx.registration.COMMITMENT), 'registration variant')
        result['replay_binding'] = commitment.get('replay_binding')
        if result['replay_binding'] is not None:
            replay.snapshot(native, expected=result['replay_binding'])
        for path in (_ctx.registration.PLAN, _ctx.registration.PRIOR_BINDING, _ctx.registration.PRIOR_STATE, _ctx.registration.INTENT, _ctx.registration.COMMITMENT):
            result['j2_files'][path] = (native.read(path), deepcopy(native.observations[path]))
        result['j2_dirs'] = {path: deepcopy(native.directory(path))
                             for path in (_ctx.registration.J2, _ctx.registration.PROGRESS)}
        stage_path = _ctx.registration.STATE if phase == 'registered' else _ctx.registration.STAGE
        observed = deepcopy(native.observations[stage_path]) if stage_path in native.observations else None
        if observed is None:
            native.read(stage_path)
            observed = deepcopy(native.observations[stage_path])
        result['stage_observation'] = observed
    return result


def _check_j1_private(native, baseline):
    for context, binding in baseline.get('historical_replays', ()):
        replay.snapshot(native, expected=binding, context=context)
    for path, expected in baseline.get('historical_leaves', {}).items():
        if native.reader.leaf(path) != expected:
            _fail('Immutable historical retained object changed or was substituted')
    from .v3_operation_history import recheck_payload_directories
    recheck_payload_directories(native,baseline.get('historical_directories',{}))
    for directory, (witness, names) in baseline['j1_dirs'].items():
        if native.directory(directory) != witness:
            _fail('Immutable J1 directory identity changed')
        from .v3_operation_history import historical_children
        actual = historical_children(native, directory,
            context=operation_context.from_custody(native))
        if actual != names:
            _fail(f'Unknown, missing or partial native inventory: {directory}')
    for path, (raw, observation) in baseline['j1_files'].items():
        if native.read(path) != raw or native.observations[path] != observation:
            _fail('Immutable J1 record changed or was substituted')


def _mapped_observation(observation, path):
    mapped = deepcopy(observation)
    mapped['path'] = path
    return mapped


def _check_private(native, baseline, *, phase):
    _ctx = operation_context.from_custody(native)
    if phase not in ('needs_preparation', 'prepared', 'old_retained', 'registered'):
        _fail('Unknown J2 private-history phase')
    root_expected = {'scope.lock', 'journals', 'binding.json'}
    if phase in ('needs_preparation', 'prepared', 'registered'):
        root_expected.add('state.json')
    _names(native, _ctx.registration.ROOT, root_expected)
    _names(native, _ctx.registration.JOURNALS, set(_ctx.prior_journal_ids) if phase == 'needs_preparation'
           else set(_ctx.journal_ids))
    _check_j1_private(native, baseline)
    old_path = _ctx.registration.STATE if phase in ('needs_preparation', 'prepared') else _ctx.registration.BACKUP
    if (native.read(old_path) != baseline['old_raw'] or
            native.observations[old_path] != _mapped_observation(baseline['old_observation'], old_path)):
        _fail('Original predecessor object changed or was substituted')
    if phase == 'needs_preparation':
        return
    for directory, witness in baseline['j2_dirs'].items():
        if native.directory(directory) != witness:
            _fail('J2 directory identity changed')
    prepared_names = FILES_PREPARED | ({'replay'} if baseline['replay_binding'] is not None else set())
    if baseline['replay_binding'] is not None:
        replay.snapshot(native, expected=baseline['replay_binding'])
    names = (prepared_names if phase == 'prepared' else
             prepared_names | {'state.before.json'} if phase == 'old_retained' else
             (prepared_names - {'state.registered.pending.json'}) | {'state.before.json'})
    _names(native, _ctx.registration.J2, names | ({'publication'} if baseline['publication_child'] else set()))
    _names(native, _ctx.registration.PROGRESS, set())
    for path, (raw, observation) in baseline['j2_files'].items():
        if native.read(path) != raw or native.observations[path] != observation:
            _fail('Immutable J2 preparation record changed or was substituted')
    stage_path = _ctx.registration.STATE if phase == 'registered' else _ctx.registration.STAGE
    if (native.read(stage_path) != baseline['registered_raw'] or
            native.observations[stage_path] != _mapped_observation(baseline['stage_observation'], stage_path)):
        _fail('Registered state object differs from witnessed stage')


def _revalidate_private(root, custody, baseline, *, phase):
    _ctx = operation_context.from_custody(custody)
    from .v3_j1_migration_predecessor import validate_legacy
    validate_legacy(custody)
    with _fresh_native(root, custody, custody.windows) as native:
        _check_private(native, baseline, phase=phase)
        # A second non-cached reader is necessary for the immutable records:
        # _NativeStore.read caches its first observation.
        second = ris._NativeStore(SimpleNamespace(working_reader=native.reader),
                                  custody.windows)
        for path, (raw, observation) in (baseline['j1_files'] | baseline['j2_files']).items():
            if second.read(path) != raw or second.observations[path] != observation:
                _fail('Private history changed during final revalidation')
        for directory in (j1.JOURNAL, j1.PROGRESS):
            native.children(directory, final=True)
        if phase != 'needs_preparation':
            for directory in (_ctx.registration.J2, _ctx.registration.PROGRESS):
                native.children(directory, final=True)
        native.children(_ctx.registration.ROOT, final=True)
        native.children(_ctx.registration.JOURNALS, final=True)


def _rename_identity_matches_observation(record, observation):
    """Bind separately observed Windows rename identity to one byte read."""
    identity = identity_from_record(record)
    witness = observation['metadata']
    content = observation['content']
    security = witness['security']
    rename = record['rename_metadata_v2']
    return (witness['volume_serial_hex'] == record['volume_serial_hex'] and
            witness['file_id_hex'] == record['file_id_hex'] and
            witness['attributes_hex'] == rename['attributes_hex'] and
            content['sha256'] == record['content_sha256'] and
            content['size_decimal'] == record['size_bytes'] and
            all(security[key] == rename[key] for key in (
                'owner_sid_sha256', 'group_sid_sha256', 'dacl_sha256',
                'descriptor_sha256', 'dacl_protected')) and
            identity.content_sha256 == content['sha256'])


def _verify_windows_stage(root, custody, commitment, raw):
    _ctx = operation_context.from_custody(custody)
    with _fresh_native(root, custody, True) as native:
        observed = _read_exact(native, _ctx.registration.STAGE, raw)
        if observed != commitment['stage_witness'] or not _rename_identity_matches_observation(
                commitment['stage_rename_identity'], native.observations[_ctx.registration.STAGE]):
            _fail('Windows staged state witness and rename identity diverged')
    with _windows_backend(root, custody) as backend:
        if backend.observe('stage') != identity_from_record(commitment['stage_rename_identity']):
            _fail('Windows staged state changed before predecessor move')


def _prepare(root, plan, evidence, custody, prepared_capture,
             prior_state, prior_binding, pins):
    _ctx = operation_context.for_plan(plan)
    journal_witness = _pin_directory(custody, _ctx.registration.J2, create=True, pins=pins)
    progress_witness = _pin_directory(custody, _ctx.registration.PROGRESS, create=True, pins=pins)
    intent = operation.build_operation_intent(plan, prior_binding, prior_state,
        prepared_capture,
        {'lock': custody.lock_witness, 'journal': journal_witness},
        evidence['predecessor_record_witnesses'],
        approved_plan_sha256=plan.sha256, plan_evidence=evidence)
    registered = operation.registration_store(intent, plan, prior_binding, prior_state,
                                              plan_evidence=evidence)
    for path, data in ((_ctx.registration.PLAN, plan.raw), (_ctx.registration.PRIOR_BINDING, prior_binding.raw),
                       (_ctx.registration.PRIOR_STATE, prior_state.raw), (_ctx.registration.INTENT, intent.raw),
                       (_ctx.registration.STAGE, registered.raw)):
        checkpoint._write_new(custody, path, data)
    with _fresh_native(root, custody, custody.windows) as stage_native:
        stage_witness = _read_exact(stage_native, _ctx.registration.STAGE, registered.raw)
        stage_observation = deepcopy(stage_native.observations[_ctx.registration.STAGE])
    old_rename = stage_rename = None
    if custody.windows:
        with _windows_backend(root, custody) as backend:
            old = backend.observe('state')
            staged = backend.observe('stage')
            if old is None or staged is None:
                _fail('Registration source or stage absent')
            old_rename = identity_record(old)
            stage_rename = identity_record(staged)
            expected_old = {'metadata': evidence['predecessor_record_witnesses']['state'],
                            'content': {'sha256': prior_state.sha256,
                                        'size_decimal': str(len(prior_state.raw))}}
            if (not _rename_identity_matches_observation(old_rename, expected_old) or
                    not _rename_identity_matches_observation(stage_rename, stage_observation)):
                _fail('Windows rename identity differs from approved native object')
    replay_binding = replay.prepare(root, custody, plan, evidence, pins)
    commitment = _commitment(plan, intent, prior_state, registered, stage_witness,
                             progress_witness, old_rename, stage_rename, replay_binding)
    checkpoint._write_new(custody, _ctx.registration.COMMITMENT, commitment)
    custody.check_lock()
    return intent, registered


def _windows_pending_old_allowed(*, stage_present):
    if type(stage_present) is not bool:
        _fail('Malformed Windows stage topology')
    if not stage_present:
        _fail('Registered topology cannot have a pending old-state move')


def _inspect_bridge(root, plan, evidence, custody, native, held, pins, *, publication_child=False):
    _ctx = operation_context.for_plan(plan)
    root_names = native.children(_ctx.registration.ROOT)
    if root_names not in ({'scope.lock', 'journals', 'state.json', 'binding.json'},
                          {'scope.lock', 'journals', 'binding.json'}):
        _fail('Unknown local root topology')
    _names(native, _ctx.registration.JOURNALS, set(_ctx.journal_ids))
    journal_witness = _pin_directory(custody, _ctx.registration.J2, create=False, pins=pins)
    progress_witness = _pin_directory(custody, _ctx.registration.PROGRESS, create=False, pins=pins)
    if native.children(_ctx.registration.PROGRESS):
        _fail('Unexpected J2 progress before registration')
    names = native.children(_ctx.registration.J2)
    prepared_names = _prepared_names(native)
    recognized = (prepared_names, prepared_names | {'state.before.json'},
                  (prepared_names - {'state.registered.pending.json'}) | {'state.before.json'})
    if names not in tuple(base | ({'publication'} if publication_child else set()) for base in recognized):
        _fail('Partial, extra or torn J2 private inventory')
    stage_present = 'state.registered.pending.json' in names
    backup_present = 'state.before.json' in names
    live_present = 'state.json' in root_names
    if (not backup_present and not live_present) or (backup_present and live_present and stage_present):
        _fail('Unknown predecessor/registered state topology')
    source = _ctx.registration.BACKUP if backup_present else _ctx.registration.STATE
    raw, prior_state, prior_binding = _check_plan(root, custody, held, native,
        plan, evidence, custody.windows, state_source=source,
        allow_pending_state=custody.windows and backup_present)
    _read_exact(native, _ctx.registration.PLAN, plan.raw)
    _read_exact(native, _ctx.registration.PRIOR_BINDING, prior_binding.raw)
    _read_exact(native, _ctx.registration.PRIOR_STATE, prior_state.raw)
    intent = operation.load_operation_intent(native.read(_ctx.registration.INTENT), plan, prior_binding,
        prior_state, held.result.working_tree,
        {'lock': custody.lock_witness, 'journal': journal_witness},
        evidence['predecessor_record_witnesses'],
        approved_plan_sha256=plan.sha256, plan_evidence=evidence)
    registered = operation.registration_store(intent, plan, prior_binding, prior_state,
                                              plan_evidence=evidence)
    commit_raw = native.read(_ctx.registration.COMMITMENT)
    commit = pp._load_json(commit_raw, 'J2 registration commitment')
    if type(commit) is not dict or set(commit) != {'schema', 'plan_sha256', 'intent_sha256',
            'journal_id', 'predecessor_state_sha256', 'registered_state_sha256',
            'predecessor_state_witness', 'stage_witness', 'progress_witness',
            'old_rename_identity', 'stage_rename_identity'} | ({'replay_binding'} if commit.get('schema') == _ctx.registration.REPLAY_SCHEMA else set()):
        _fail('Malformed J2 registration commitment')
    _validate_replay(native, commit, plan, evidence)
    if (commit['schema'] not in (SCHEMA, _ctx.registration.REPLAY_SCHEMA) or commit['plan_sha256'] != plan.sha256 or
            commit['intent_sha256'] != intent.sha256 or commit['journal_id'] != _ctx.journal_id or
            commit['predecessor_state_sha256'] != prior_state.sha256 or
            commit['registered_state_sha256'] != registered.sha256 or
            commit['predecessor_state_witness'] != evidence['predecessor_record_witnesses']['state'] or
            commit['progress_witness'] != progress_witness or
            canonical_bytes(commit) != commit_raw):
        _fail('J2 registration commitment differs from approved predecessor')
    lb._validate_witness(commit['stage_witness'], held.result.working_tree.body['native']['platform'], 'file')
    repairs = []
    if custody.windows:
        expected_old = {'metadata': evidence['predecessor_record_witnesses']['state'],
                        'content': {'sha256': prior_state.sha256,
                                    'size_decimal': str(len(prior_state.raw))}}
        expected_stage = {'metadata': commit['stage_witness'],
                          'content': {'sha256': registered.sha256,
                                      'size_decimal': str(len(registered.raw))}}
        if (not _rename_identity_matches_observation(commit['old_rename_identity'], expected_old) or
                not _rename_identity_matches_observation(commit['stage_rename_identity'], expected_stage)):
            _fail('Windows committed rename identity differs from witnessed object')
        old_id = identity_from_record(commit['old_rename_identity'])
        stage_id = identity_from_record(commit['stage_rename_identity'])
        with _windows_backend(root, custody) as backend:
            if backup_present:
                if stage_present and backend.observe('state') is not None:
                    _fail('Retained Windows predecessor has a live alias')
                if not stage_present and backend.observe('state') is None:
                    _fail('Registered Windows state is absent')
                if backend.observe('backup') != old_id:
                    _windows_pending_old_allowed(stage_present=stage_present)
                    if not backend.pending_matches('backup', old_id):
                        _fail('Moved Windows predecessor is not an exact witnessed pending move')
                    repairs.append(('state', 'backup', commit['old_rename_identity']))
            elif backend.observe('state') != old_id:
                _fail('Windows predecessor identity differs')
            if stage_present:
                if _read_exact(native, _ctx.registration.STAGE, registered.raw) != commit['stage_witness']:
                    _fail('Windows stage native witness differs')
                if backend.observe('stage') != stage_id:
                    _fail('Windows registration stage identity differs')
            elif not backup_present or backend.observe('stage') is not None:
                _fail('Missing Windows registration stage')
            elif backend.observe('state') != stage_id:
                if not backend.pending_matches('state', stage_id):
                    _fail('Published Windows state differs from witnessed pending move')
                repairs.append(('stage', 'state', commit['stage_rename_identity']))
    else:
        if stage_present and _read_exact(native, _ctx.registration.STAGE, registered.raw) != commit['stage_witness']:
            _fail('POSIX registration stage identity differs')
        if backup_present and native.observations[_ctx.registration.BACKUP]['metadata'] != evidence['predecessor_record_witnesses']['state']:
            _fail('Retained POSIX predecessor identity differs')
    if not backup_present:
        phase = 'prepared'
    elif stage_present and not live_present:
        phase = 'old_retained'
    elif not stage_present and live_present:
        _read_exact(native, _ctx.registration.STATE, registered.raw)
        ls.reconcile_registration(registered, prior_binding, _ctx.journal_ids)
        phase = 'registered'
    else:
        _fail('Invalid J2 state bridge topology')
    return phase, intent, registered, prior_state, commit, tuple(repairs)


def _move_posix(custody, source, destination, source_raw, source_witness):
    from .portable_provenance_posix import _same_namespace, _witness
    src_parent_path, _, src_name = source.rpartition('/')
    dst_parent_path, _, dst_name = destination.rpartition('/')
    parent_src = custody.reader.fds[src_parent_path]
    parent_dst = custody.reader.fds[dst_parent_path]
    fd = os.open(src_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                 dir_fd=parent_src)
    try:
        before = _witness(fd, leaf=True, label=source)
        if lb.project_posix_witness(before.metadata) != source_witness:
            _fail('Move source native identity differs')
        checkpoint._check_bytes(lambda n: os.read(fd, n), source_raw)
        _same_namespace(parent_src, src_name, before, leaf=True, label=source)
        custody.check_lock()
        rename_no_replace_at(parent_src, src_name, parent_dst, dst_name)
        after = _witness(fd, leaf=True, label=destination)
        if lb.project_posix_witness(after.metadata) != source_witness:
            _fail('Retained/published object identity changed')
        _same_namespace(parent_dst, dst_name, after, leaf=True, label=destination)
        os.fsync(parent_src)
        os.fsync(parent_dst)
    finally:
        os.close(fd)
    custody.check_lock()


def _move_windows(root, custody, source, destination, expected_record):
    with _windows_backend(root, custody) as backend:
        expected = identity_from_record(expected_record)
        backend.move_exact(source, destination, expected)
    custody.check_lock()


def register_j2_rebind_successor(project_root: Path | str, *,
                                  plan: operation.ValidatedOperationPlan,
                                  expected_plan_sha256: str,
                                  plan_evidence: dict[str, Any], handles=None) -> J2Registration:
    """Prepare or finish exactly one J2 registration; preserve/refuse unknown objects."""
    _ctx = operation_context.for_plan(plan)
    try:
        lb._hex(expected_plan_sha256, lb.HEX64, 'approved J2 plan digest')
        if type(plan) is not operation.ValidatedOperationPlan or plan.sha256 != expected_plan_sha256:
            _fail('Exact approved J2 plan digest required')
        operation._verified_plan(plan, plan_evidence)
        if plan.body['next_journal_id'] != _ctx.journal_id:
            _fail('This bridge supports J1-to-J2 only')
        for path in plan_evidence['portable_files']:
            pp.control_path_limit(path)
        root = Path(project_root)
        windows = handles is not None or os.name == 'nt'
        with ExitStack() as pins:
            with operation_context.held_store(root,
                    journal_ids=_ctx.prior_journal_ids, handles=handles, context=_ctx) as custody:
                with _source_capture(root, custody, plan_evidence, windows,
                                     state_source=_ctx.registration.STATE) as held:
                    native = _native(custody, windows)
                    journals = native.children(_ctx.registration.JOURNALS)
                    if journals == set(_ctx.prior_journal_ids):
                        _names(native, _ctx.registration.ROOT, {'scope.lock', 'journals', 'state.json', 'binding.json'})
                        prior_raw, prior_state, prior_binding = _check_plan(
                            root, custody, held, native, plan, plan_evidence,
                            windows, state_source=_ctx.registration.STATE)
                        prepared_capture = held.result.working_tree
                        phase = 'needs_preparation'
                        intent = registered = commit = None
                        repairs = ()
                        private_baseline = _private_baseline(native,
                            phase=phase, old_state_raw=prior_state.raw)
                    elif journals == set(_ctx.journal_ids):
                        phase, intent, registered, prior_state, commit, repairs = _inspect_bridge(
                            root, plan, plan_evidence, custody, native, held, pins)
                        private_baseline = _private_baseline(native, phase=phase,
                            old_state_raw=prior_state.raw, registered_raw=registered.raw)
                    else:
                        _fail('Foreign or incomplete journal directory inventory')
                # Joint read lane has closed; independently re-open every private
                # record and fixed inventory before any native mutation.
                _revalidate_private(root, custody, private_baseline, phase=phase)
                for source, destination, expected in repairs:
                    if not windows:
                        _fail('Unexpected POSIX repair')
                    with _windows_backend(root, custody) as backend:
                        backend.restore_pending(source, destination, identity_from_record(expected))
                    custody.check_lock()
                if repairs:
                    with _fresh_native(root, custody, windows) as repaired:
                        for source, destination, _expected in repairs:
                            if source == 'state' and destination == 'backup':
                                _read_exact(repaired, _ctx.registration.BACKUP, prior_state.raw)
                                if repaired.observations[_ctx.registration.BACKUP]['metadata'] != plan_evidence['predecessor_record_witnesses']['state']:
                                    _fail('Restored predecessor native witness differs')
                                private_baseline['old_observation']['metadata'] = deepcopy(
                                    repaired.observations[_ctx.registration.BACKUP]['metadata'])
                            elif source == 'stage' and destination == 'state':
                                _read_exact(repaired, _ctx.registration.STATE, registered.raw)
                                if repaired.observations[_ctx.registration.STATE]['metadata'] != commit['stage_witness']:
                                    _fail('Restored registered native witness differs')
                                private_baseline['stage_observation']['metadata'] = deepcopy(
                                    repaired.observations[_ctx.registration.STATE]['metadata'])
                            else:
                                _fail('Unknown Windows repair')
                if phase == 'needs_preparation':
                    replay.build_bundle(plan, plan_evidence)  # new-variant bounds before any writes
                    _verify_records(root, custody, state_path=_ctx.registration.STATE,
                        state_raw=prior_state.raw,
                        state_witness=plan_evidence['predecessor_record_witnesses']['state'],
                        binding_raw=plan_evidence['predecessor_binding'].raw,
                        binding_witness=plan_evidence['predecessor_record_witnesses']['binding'])
                    intent, registered = _prepare(root, plan, plan_evidence, custody,
                        prepared_capture, prior_state, prior_binding, pins)
                    phase = 'prepared'
                    with _fresh_native(root, custody, windows) as observed:
                        commit = pp._load_json(observed.read(_ctx.registration.COMMITMENT), 'J2 registration commitment')
                        # Compare J1 against the pre-write authority before
                        # adopting witnessed J2 objects created by this call.
                        _check_j1_private(observed, private_baseline)
                        private_baseline = _private_baseline(observed, phase=phase,
                            old_state_raw=prior_state.raw, registered_raw=registered.raw,
                            prior=private_baseline)
                    _revalidate_private(root, custody, private_baseline, phase=phase)
                if phase == 'registered':
                    _revalidate_private(root, custody, private_baseline, phase=phase)
                    _verify_records(root, custody, state_path=_ctx.registration.BACKUP,
                        state_raw=prior_state.raw,
                        state_witness=plan_evidence['predecessor_record_witnesses']['state'],
                        binding_raw=plan_evidence['predecessor_binding'].raw,
                        binding_witness=plan_evidence['predecessor_record_witnesses']['binding'])
                    with _fresh_native(root, custody, windows) as final_native:
                        if _read_exact(final_native, _ctx.registration.STATE, registered.raw) != commit['stage_witness']:
                            _fail('Registered native state differs from approved stage')
                    return J2Registration(phase, plan.sha256, intent.sha256,
                        registered.sha256, prior_state.sha256,
                        plan_evidence['predecessor_binding'].sha256, journal_id=_ctx.journal_id)
                if phase == 'prepared':
                    _revalidate_private(root, custody, private_baseline, phase=phase)
                    if windows:
                        _verify_windows_stage(root, custody, commit, registered.raw)
                    _verify_records(root, custody, state_path=_ctx.registration.STATE,
                        state_raw=prior_state.raw,
                        state_witness=plan_evidence['predecessor_record_witnesses']['state'],
                        binding_raw=plan_evidence['predecessor_binding'].raw,
                        binding_witness=plan_evidence['predecessor_record_witnesses']['binding'])
                    if windows:
                        _move_windows(root, custody, 'state', 'backup', commit['old_rename_identity'])
                    else:
                        _move_posix(custody, _ctx.registration.STATE, _ctx.registration.BACKUP, prior_state.raw,
                                    plan_evidence['predecessor_record_witnesses']['state'])
                    phase = 'old_retained'
                    _revalidate_private(root, custody, private_baseline, phase=phase)
                if phase == 'old_retained':
                    _revalidate_private(root, custody, private_baseline, phase=phase)
                    _verify_records(root, custody, state_path=_ctx.registration.BACKUP,
                        state_raw=prior_state.raw,
                        state_witness=plan_evidence['predecessor_record_witnesses']['state'],
                        binding_raw=plan_evidence['predecessor_binding'].raw,
                        binding_witness=plan_evidence['predecessor_record_witnesses']['binding'])
                    if windows:
                        _move_windows(root, custody, 'stage', 'state', commit['stage_rename_identity'])
                    else:
                        _move_posix(custody, _ctx.registration.STAGE, _ctx.registration.STATE, registered.raw,
                                    commit['stage_witness'])
                _revalidate_private(root, custody, private_baseline, phase='registered')
                _verify_records(root, custody, state_path=_ctx.registration.BACKUP,
                    state_raw=prior_state.raw,
                    state_witness=plan_evidence['predecessor_record_witnesses']['state'],
                    binding_raw=plan_evidence['predecessor_binding'].raw,
                    binding_witness=plan_evidence['predecessor_record_witnesses']['binding'])
                with _fresh_native(root, custody, windows) as final_native:
                    if _read_exact(final_native, _ctx.registration.STATE, registered.raw) != commit['stage_witness']:
                        _fail('Registered native state differs from approved stage')
                custody.check_lock()
                return J2Registration('registered', plan.sha256, intent.sha256,
                    registered.sha256, prior_state.sha256,
                    plan_evidence['predecessor_binding'].sha256, journal_id=_ctx.journal_id)
    except J2RegistrationError:
        raise
    except (OSError, RuntimeError, ValueError, TypeError, KeyError,
            AttributeError, OverflowError, RecursionError) as exc:
        raise J2RegistrationError(f'J2 registration refused: {exc}') from exc
