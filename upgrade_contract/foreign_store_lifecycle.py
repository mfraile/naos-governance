"""In-place explicit receiving using existing custody, stages and exact moves.

Complete preparation may resume with the same external raw approval. Partial
preparation refuses; after active registration, completion is forward-only.
"""
from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
from dataclasses import dataclass
from weakref import ref
import ntpath

from . import foreign_store_records as r, foreign_store_native as native
from . import foreign_store_history as history
from . import local_binding as lb, local_store as ls
from . import v3_j2_registration as registration
from .rebind_checkpoint import _write_new


def _backend(root, local, paths):
    from .windows_restoring_backend import WindowsRestoringBackend
    return WindowsRestoringBackend(local.reader.handles,
        {name: ntpath.join(str(root), *path.split('/')) for name, path in paths.items()})


def _identity(root, local, path):
    if not local.windows:
        return None
    with _backend(root, local, {'file': path}) as backend:
        identity = backend.observe('file')
        if identity is None:
            raise ValueError('Required receiving rename producer is absent')
        from .windows_rename_identity import identity_record
        return identity_record(identity)


def _moves(p):
    return ((1, p.STATE, p.OLD_STATE), (3, p.REGISTERED, p.STATE),
            (5, p.BINDING, p.OLD_BINDING), (7, p.BINDING_STAGE, p.BINDING),
            (9, p.STATE, p.ACTIVE_STATE), (11, p.STATE_STAGE, p.STATE),
            (13, p.TERMINAL_STAGE, p.TERMINAL))


@dataclass(frozen=True)
class _CompletedSemanticsProof:
    """Exact detached bytes only, confined to one acquired custody instance."""
    owner: object
    key: tuple
    result: history.RecordedPrefix


def _old_view(observed, p, plan, *, local=None):
    """Only a detached historical byte map maps retained bytes to old paths."""
    files = {}
    old_paths = {row['path'] for row in plan.body['import_inventory']['files']}
    for path in old_paths:
        source = p.OLD_BINDING if path == p.BINDING and p.OLD_BINDING in observed.files else (
            p.OLD_STATE if path == p.STATE and p.OLD_STATE in observed.files else path)
        if source not in observed.files:
            raise ValueError('Retained incoming evidence is missing')
        files[path] = observed.files[source]
    dirs = frozenset(row['path'] for row in plan.body['import_inventory']['directories'])
    if local is None:
        return history.load_completed_semantics(files, dirs, observed.portable_files)
    # Every invocation still has fresh native observations, followed by complete
    # _check_old and closing observation equality. Only deterministic detached
    # replay of identical bytes/membership is reused inside this acquired custody.
    local.check_lock()
    if (type(plan.raw) is not bytes or type(files) is not dict
            or any(type(path) is not str or type(raw) is not bytes for path, raw in files.items())
            or type(observed.portable_files) is not dict
            or any(type(path) is not str or type(raw) is not bytes
                   for path, raw in observed.portable_files.items())
            or any(type(path) is not str for path in dirs)):
        raise ValueError('Exact immutable receiving semantic inputs required')
    key = (plan.raw, tuple(sorted(files.items())), dirs,
           tuple(sorted(observed.portable_files.items())))
    proof = getattr(local, '_receiving_completed_semantics', None)
    if type(proof) is _CompletedSemanticsProof and proof.owner() is local:
        if proof.key != key:
            raise ValueError('Receiving detached semantic inputs changed during custody')
        return deepcopy(proof.result)
    result = history.load_completed_semantics(files, dirs, observed.portable_files)
    if type(result) is not history.RecordedPrefix:
        raise ValueError('Typed complete receiving semantic prefix required')
    # The proof has no reader, live native witness, or continuing authority.
    # Copy both on insertion and on return so caller mutation cannot poison it.
    local._receiving_completed_semantics = _CompletedSemanticsProof(ref(local), key, deepcopy(result))
    return deepcopy(result)


def _check_old(observed, p, plan):
    selected = plan.body['import_inventory']
    actual_files = {row['path']: row for row in observed.inventory['files']}
    for row in selected['files']:
        path = row['path']
        source = p.OLD_BINDING if path == p.BINDING and p.OLD_BINDING in observed.files else (
            p.OLD_STATE if path == p.STATE and p.OLD_STATE in observed.files else path)
        actual = actual_files.get(source)
        if actual is None or {**actual, 'path': path} != row:
            raise ValueError('Incoming exact bytes/native identity changed: ' + path)
    actual_dirs = {row['path']: row for row in observed.inventory['directories']}
    for row in selected['directories']:
        actual = actual_dirs.get(row['path'])
        if actual is None or actual['witness'] != row['witness']:
            raise ValueError('Incoming directory identity/protection changed')
        expected = set(row['children'])
        if row['path'] == p.JOURNALS:
            expected.add(plan.body['next_journal_id'])
        if row['path'] == p.ROOT:
            if p.STATE not in observed.files:
                expected.discard('state.json')
            if p.BINDING not in observed.files:
                expected.discard('binding.json')
        if set(actual['children']) != expected:
            raise ValueError('Incoming complete directory inventory changed')
    if observed.inventory['legacy_absence'] != selected['legacy_absence']:
        raise ValueError('Competing legacy state changed')
    if observed.pair.working_tree.body != plan.body['initial_capture']:
        raise ValueError('Receiving current working edits/deletions or namespace changed')
    if (observed.pair.portable.owner_sha256 != plan.body['owner_sha256']
            or observed.pair.portable.manifest_sha256 != plan.body['portable_head_sha256']):
        raise ValueError('Receiving portable provenance changed')


def _exact(observed, path, expected_raw, witness):
    row = next((item for item in observed.inventory['files'] if item['path'] == path), None)
    return (observed.files.get(path) == expected_raw and row is not None
            and row['metadata'] == witness)


def _derived(plan, intent, prefix):
    active, binding, state = r.checkpoints(plan, intent, prefix.binding, prefix.state)
    progress = r.progress_records(plan, intent, binding, state)
    terminal = r.terminal(plan, intent, binding, state, progress[-1])
    p = r.paths(plan.body['next_journal_id'])
    return p, active, binding, state, progress, terminal


def _inspect(root, local, plan, digest):
    if plan.sha256 != digest:
        raise ValueError('Exact external receiving approval differs')
    p = r.paths(plan.body['next_journal_id'])
    observed = native.observe(root, local, detached=False)
    if observed.files.get(p.PLAN) != plan.raw:
        raise ValueError('Persisted receiving plan differs from external approval')
    prefix = _old_view(observed, p, plan, local=local)
    _check_old(observed, p, plan)
    # Rebuild the exact plan using the separately validated retained semantics,
    # original receiving observations and original current-C record.
    from .working_tree_capture import build_capture
    r.validate_plan(plan.raw, observed.pair.portable,
        build_capture(plan.body['initial_capture']['native'], plan.body['initial_capture']['leaves']),
        prefix, plan.body['import_inventory'], expected_digest=digest)
    intent = r.load(observed.files.get(p.INTENT), r.INTENT_SCHEMA)
    expected = r.build_intent(plan, journal_witness=intent.body['storage_witnesses']['journal'],
        lock_witness=intent.body['storage_witnesses']['lock'])
    if intent != expected or intent.body['storage_witnesses']['lock'] != local.lock_witness:
        raise ValueError('Receiving intent/custody differs')
    p, active, binding, state, chain, terminal = _derived(plan, intent, prefix)
    commit = r.load(observed.files.get(p.COMMITMENT), r.COMMIT_SCHEMA)
    body = commit.body
    lb._fields(body, {'schema', 'plan_sha256', 'intent_sha256', 'directories', 'files'}, 'receiving preparation')
    rows = body['files']
    raws = {p.PLAN: plan.raw, p.INTENT: intent.raw, p.OLD_STATE: prefix.state.raw,
            p.OLD_BINDING: prefix.binding.raw, p.REGISTERED: active.raw,
            p.BINDING_STAGE: binding.raw, p.STATE_STAGE: state.raw, p.TERMINAL_STAGE: terminal.raw}
    if (body['plan_sha256'] != digest or body['intent_sha256'] != intent.sha256
            or type(rows) is not dict or set(rows) != set(raws)
            or set(body['directories']) != {p.JOURNAL, p.PROGRESS, p.CHECKPOINT}):
        raise ValueError('Incomplete receiving preparation commitment')
    directories = {row['path']: row for row in observed.inventory['directories']}
    for path, witness in body['directories'].items():
        if directories.get(path, {}).get('witness') != witness:
            raise ValueError('Receiving preparation directory substituted')
    if body['directories'][p.JOURNAL] != intent.body['storage_witnesses']['journal']:
        raise ValueError('Receiving preparation journal differs from intent')
    progress_names = directories[p.PROGRESS]['children']
    if not 1 <= len(progress_names) <= len(chain) or progress_names != [f'{i:08d}.json' for i in range(len(progress_names))]:
        raise ValueError('Receiving progress is partial, extra or aliased')
    for index in range(len(progress_names)):
        if observed.files.get(p.PROGRESS + f'/{index:08d}.json') != chain[index].raw:
            raise ValueError('Receiving persisted progress differs from deterministic chain')
    revision = len(progress_names) - 1
    # Map every producer to its sole location at this exact durable frontier.
    locations = {key: key for key in raws}
    locations[p.OLD_STATE] = p.STATE
    locations[p.OLD_BINDING] = p.BINDING
    producer_moves = ((1, p.OLD_STATE, p.STATE, p.OLD_STATE),
        (3, p.REGISTERED, p.REGISTERED, p.STATE), (5, p.OLD_BINDING, p.BINDING, p.OLD_BINDING),
        (7, p.BINDING_STAGE, p.BINDING_STAGE, p.BINDING), (9, p.REGISTERED, p.STATE, p.ACTIVE_STATE),
        (11, p.STATE_STAGE, p.STATE_STAGE, p.STATE), (13, p.TERMINAL_STAGE, p.TERMINAL_STAGE, p.TERMINAL))
    pending = None
    for phase, producer, source, destination in producer_moves:
        if revision > phase:
            locations[producer] = destination
        elif revision == phase:
            source_present, dest_present = source in observed.files, destination in observed.files
            if source_present == dest_present:
                raise ValueError('Ambiguous receiving pending move location')
            locations[producer] = source if source_present else destination
            pending = (producer, source, destination, source_present)
        else:
            break
    expected_files = {p.COMMITMENT, *(p.PROGRESS + '/' + name for name in progress_names), *locations.values()}
    selected_paths = {row['path'] for row in plan.body['import_inventory']['files']}
    selected_paths.discard(p.STATE)
    selected_paths.discard(p.BINDING)
    if set(observed.files) != expected_files | selected_paths:
        raise ValueError('Missing, extra or unrecorded receiving object')
    expected_dirs = {row['path'] for row in plan.body['import_inventory']['directories']} | {p.JOURNAL, p.PROGRESS, p.CHECKPOINT}
    if set(observed.directories) != expected_dirs:
        raise ValueError('Missing, extra or unrecorded receiving directory')
    for directory in (p.JOURNAL, p.PROGRESS, p.CHECKPOINT):
        children = {path[len(directory) + 1:].split('/')[0] for path in expected_files | expected_dirs
                    if path.startswith(directory + '/')}
        if set(directories[directory]['children']) != children:
            raise ValueError('Receiving fixed directory inventory differs')
    for producer, path in locations.items():
        row = rows[producer]
        lb._fields(row, {'sha256', 'witness', 'rename_identity'}, 'receiving producer commitment')
        if row['sha256'] != r.sha(raws[producer]):
            raise ValueError('Receiving producer bytes differ from deterministic candidate')
        if not _exact(observed, path, raws[producer], row['witness']):
            if not (local.windows and pending is not None and pending[0] == producer and not pending[3]):
                raise ValueError('Receiving producer bytes/native witness changed')
        if local.windows:
            from .windows_rename_identity import identity_from_record
            expected_identity = identity_from_record(row['rename_identity'])
            with _backend(root, local, {'file': path}) as backend:
                if backend.observe('file') != expected_identity:
                    if not (pending is not None and pending[0] == producer and not pending[3]
                            and backend.pending_matches('file', expected_identity)):
                        raise ValueError('Receiving full Windows producer identity changed')
        elif row['rename_identity'] is not None:
            raise ValueError('POSIX receiving commitment has foreign rename identity')
    # Close the semantic derivation interval against the SAME captured facts.
    # A new scan is never authority: every byte, current witness, child inventory,
    # competing absence, portable snapshot and current C must equal the original.
    closing = native.observe(root, local, detached=False)
    if closing != observed:
        raise ValueError('Receiving captured evidence changed during semantic proof')
    local.check_lock()
    return observed, prefix, intent, body, chain, revision, pending, (binding, state, terminal)


def _move(root, local, producer, source, destination, raw, row, source_present):
    if local.windows:
        from .windows_rename_identity import identity_from_record
        identity = identity_from_record(row['rename_identity'])
        with _backend(root, local, {'source': source, 'destination': destination}) as backend:
            if source_present:
                backend.move_exact('source', 'destination', identity)
            else:
                backend.restore_pending('source', 'destination', identity)
    elif source_present:
        registration._move_posix(local, source, destination, raw, row['witness'])
    local.check_lock()


def finish(root, local, plan, digest):
    while True:
        observed, prefix, intent, commit, chain, revision, pending, result = _inspect(root, local, plan, digest)
        p, active, binding, state, _, terminal = _derived(plan, intent, prefix)
        if revision == len(chain) - 1:
            return {'status': 'complete', 'journal_id': p.JOURNAL.rsplit('/', 1)[-1],
                    'plan_sha256': digest, 'binding_sha256': binding.sha256,
                    'claim_ceiling': r.CLAIM}
        if pending is None:
            _write_new(local, p.PROGRESS + f'/{revision + 1:08d}.json', chain[revision + 1].raw)
            continue
        producer, source, destination, source_present = pending
        raws = {p.OLD_STATE: prefix.state.raw, p.OLD_BINDING: prefix.binding.raw, p.REGISTERED: active.raw,
                p.BINDING_STAGE: binding.raw, p.STATE_STAGE: state.raw, p.TERMINAL_STAGE: terminal.raw}
        _move(root, local, producer, source, destination, raws[producer], commit['files'][producer], source_present)
        # Fresh full inspection after the move and before recording completion.
        _inspect(root, local, plan, digest)
        _write_new(local, p.PROGRESS + f'/{revision + 1:08d}.json', chain[revision + 1].raw)


def completed_approval(root, plan, digest, *, handles=None):
    """Read-only exact approved completion, including after later checkpoints.

    Current strict version/gate bytes select a candidate only. Existing full
    native predecessor inspection proves all retained evidence and completion;
    neither a self hash nor historical native IDs grant authority.
    """
    if plan.sha256!=digest:
        raise ValueError('Exact external receiving approval differs')
    from . import foreign_store_version as version
    from . import v3_operation_history as ordinary
    windows=handles is not None or __import__('os').name=='nt'
    with native._lane(root,windows,handles) as held:
        reader=native._Inventory(held,windows)
        jid=plan.body['next_journal_id']
        p=r.paths(jid)
        if jid in reader.children(p.JOURNALS):
            members=reader.children(p.JOURNAL)
            if (p.COMMITMENT.rsplit('/',1)[-1] in members and 'progress' in members
                    and f'{len(r.PHASES)-1:08d}.json' not in reader.children(p.PROGRESS)):
                # A prepared receiving journal without final progress is only
                # a recovery route candidate, even if its terminal is visible.
                # Exact approval, every persisted record and native identity
                # remain mandatory in the existing _inspect/recover path.
                return None
        binding=lb.load_local_binding(reader.read(r.paths(plan.body['next_journal_id']).BINDING))
        state=ls.load_local_store(reader.read(r.paths(plan.body['next_journal_id']).STATE))
        gate=version.inherited_gate(binding,state)
        jid=plan.body['next_journal_id']
        if gate is None or jid not in {row['journal_id'] for row in gate['boundaries']}:
            return None
    completed=ordinary.capture_completed_predecessor(root,handles=handles)
    p=r.paths(jid)
    saved=completed.prefix.records.get(p.PLAN)
    if saved is None or saved[0]!=plan.raw:
        raise ValueError('Completed receiving raw plan differs from external approval')
    matching=[row for row in completed.prefix.terminals if row[0]==jid]
    if len(matching)!=1 or matching[0][1].body['outcome']!='received':
        raise ValueError('Approved receiving completion is absent')
    return {'status':'complete','journal_id':jid,'plan_sha256':digest,
            'binding_sha256':matching[0][3].sha256,'claim_ceiling':r.CLAIM}


def apply(root, raw, *, expected_digest, handles=None):
    plan = r.load(raw, r.PLAN_SCHEMA)
    if plan.sha256 != expected_digest:
        raise ValueError('Exact external approved receiving digest differs')
    with ExitStack() as pins, native.custody(root, handles=handles) as local:
        observed = native.observe(root, local)
        r.validate_plan(raw, observed.pair.portable, observed.pair.working_tree,
            observed.prefix, observed.inventory, expected_digest=expected_digest)
        p = r.paths(plan.body['next_journal_id'])
        # All preflight refusals above are read-only. Any later exception
        # preserves the created journal; only complete preparation recovers.
        jw = registration._pin_directory(local, p.JOURNAL, create=True, pins=pins)
        pw = registration._pin_directory(local, p.PROGRESS, create=True, pins=pins)
        cw = registration._pin_directory(local, p.CHECKPOINT, create=True, pins=pins)
        intent = r.build_intent(plan, journal_witness=jw, lock_witness=local.lock_witness)
        p, active, binding, state, chain, terminal = _derived(plan, intent, observed.prefix)
        staged = {p.PLAN: plan.raw, p.INTENT: intent.raw, p.REGISTERED: active.raw,
                  p.BINDING_STAGE: binding.raw, p.STATE_STAGE: state.raw, p.TERMINAL_STAGE: terminal.raw}
        for path, data in staged.items():
            _write_new(local, path, data)
        prepared = native.observe(root, local, detached=False)
        rows = {}
        original = {row['path']: row for row in observed.inventory['files']}
        fresh = {row['path']: row for row in prepared.inventory['files']}
        for producer, path, data in [(p.OLD_STATE, p.STATE, observed.prefix.state.raw),
            (p.OLD_BINDING, p.BINDING, observed.prefix.binding.raw),
            *((path, path, data) for path, data in staged.items())]:
            observed_row = original[path] if path in (p.STATE, p.BINDING) else fresh[path]
            rows[producer] = {'sha256': r.sha(data), 'witness': observed_row['metadata'],
                              'rename_identity': _identity(root, local, path)}
        commit = r.record({'schema': r.COMMIT_SCHEMA, 'plan_sha256': plan.sha256,
            'intent_sha256': intent.sha256, 'directories': {p.JOURNAL: jw, p.PROGRESS: pw, p.CHECKPOINT: cw},
            'files': rows})
        _write_new(local, p.COMMITMENT, commit.raw)
        _write_new(local, p.PROGRESS + '/00000000.json', chain[0].raw)
        return finish(root, local, plan, expected_digest)


def recover(root, raw, *, expected_digest, handles=None):
    plan = r.load(raw, r.PLAN_SCHEMA)
    if plan.sha256 != expected_digest:
        raise ValueError('Exact external approved receiving recovery digest differs')
    ids = tuple(row['id'] for row in plan.body['prior_journals']['entries']) + (plan.body['next_journal_id'],)
    with ExitStack() as pins, native.custody(root, journal_ids=ids, source_format=plan.body['legacy_source_format'], handles=handles) as local:
        p = r.paths(plan.body['next_journal_id'])
        registration._pin_directory(local, p.CHECKPOINT, create=False, pins=pins)
        return finish(root, local, plan, expected_digest)
