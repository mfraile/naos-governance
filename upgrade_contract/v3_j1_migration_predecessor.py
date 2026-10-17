"""Historical migration proof under borrowed legacy-then-local custody.

The dispatch observation grants no authority. Exact persisted projection and
native terminal objects are revalidated under both locks; current C is separate.
"""
from __future__ import annotations
from dataclasses import dataclass
from weakref import ref
from . import portable_provenance as pp, legacy_authority as authority
from . import legacy_migration_records as lineage_records
from . import legacy_migration_plan_records as plans
from . import legacy_migration_planning as planning
from . import legacy_migration_journal as journal
from . import legacy_migration_progress as progress
from . import legacy_migration_binding_records as records
from . import legacy_migration_inspection as inspection
from . import rebind_store_inspection as store
from . import v3_operation_projection as projection


def reconstruct(native):
    """Read-only variant selector and full historical candidate reconstruction."""
    raw = native.read(store.JOURNAL + '/plan.json')
    schema = pp._load_json(raw, 'J1 dispatch plan').get('schema')
    if schema == plans.REPLAY_SCHEMA:
        from .legacy_archive_capture import _Capture
        source = _Capture(native.reader, native.windows, pp._load_json(raw, 'J1 plan')['source_format'])
        def read(path):
            return source.read(path) if path.startswith('.naos/upgrade-v1/') else native.read(path)
        return plans.reconstruct_replay_candidate(read, raw)
    if schema != plans.SCHEMA:
        return None
    owner, _ = pp._decode_record(native.read(pp.OWNER_PATH), pp.OWNER_SCHEMA,
        {'schema', 'project_id', 'minimum_reader', 'authority_kind', 'authority_sha256'})
    if owner['authority_kind'] != 'legacy_projection':
        raise ValueError('Migration plan lacks legacy projection authority')
    auth, _ = pp._decode_record(native.read(authority.authority_path(owner['authority_sha256'])),
                               authority.SCHEMA, authority._KEYS)
    lineage_raw = native.read(authority.lineage_path(auth['lineage_sha256']))
    lineage = lineage_records.LegacyLineage(lineage_raw, auth['lineage_sha256'])
    archive = {item['path']: native.read(authority.blob_path(item['sha256']))
               for item in lineage.body['archive']}
    expectations = {f"expected_{item['role']}_sha256": item['sha256']
                    for item in lineage.body['anchors']}
    files = authority.build_legacy_projection(archive, lineage,
        directory_paths=auth['directory_paths'],
        source_policy_raw=native.read(authority.blob_path(auth['source_policy_sha256'])),
        mode_inventory_raw=native.read(pp.inventory_path(auth['mode_inventory_sha256'])),
        expected_modes_sha256=auth['mode_inventory_sha256'],
        approved_lineage_sha256=lineage.sha256,
        expected_source_policy_sha256=auth['source_policy_sha256'], **expectations)
    plan = plans.load_migration_plan(raw, files, lineage)
    return planning.MigrationCandidate(plan, lineage, tuple(sorted(files.items())))


def _published_file(native, path, raw, witness, journals):
    """Find the original object, whose bytes AND original witness must match.

    A later publication path is only a lookup hint; it cannot authorize a
    substitute. The migration's original staged witness remains authority.
    """
    choices = [path]
    actual_journals = native.children(store.ROOT + '/journals')
    from . import v3_operation_context as contexts
    for jid in journals[1:]:
        if jid not in actual_journals:
            continue
        ctx = contexts.for_journal(jid)
        if 'publication' not in native.children(ctx.registration.J2):
            continue
        body = pp._load_json(native.read(ctx.staging.PROGRAM), 'historical migration lookup')
        choices.extend(slot['retained'] for slot in body['publications']
                       if slot['destination'] == path and slot['before'] is not None)
    matched = []
    for selected in choices:
        observed = native.reader.leaf(selected)
        if observed['metadata'] == witness and observed['content'] == {
                'sha256': __import__('hashlib').sha256(raw).hexdigest(), 'size_decimal': str(len(raw))}:
            # Qualified working-leaf reader enforces the portable 64 MiB leaf
            # and 256 MiB aggregate bounds. Private-record reads remain 16 MiB.
            # Retain the exact native observation for repeated native proof.
            if selected != pp.MANIFEST_PATH:
                native.migration_content_leaves[selected] = observed
            matched.append(selected)
    if len(matched) != 1:
        raise ValueError('Original published migration object is missing or aliased: ' + path)


@dataclass(frozen=True)
class _SemanticProof:
    """Pure finalized records, confined to one live held custody object."""
    owner: object
    key: tuple
    intent: object
    history: tuple
    checkpoint: tuple


def _semantic_records(native, local):
    """Fresh bytes and locks every time; reuse only identical pure derivation.

    The key contains immutable scalar/tuple/byte values, never parsed bodies or
    native observations. A changed predecessor within custody refuses; a new
    custody validates afresh. Native terminal/source proofs remain with callers.
    """
    from . import v3_operation_context as contexts
    local.check_lock()
    local.legacy_custody.check_lock()
    candidate = local.migration_candidate
    if (type(candidate) is not planning.MigrationCandidate
            or candidate.mutation_authorized is not False
            or type(candidate.plan) is not plans.ValidatedMigrationPlan
            or type(candidate.lineage) is not lineage_records.LegacyLineage):
        raise ValueError('Exact immutable migration candidate required')
    members = candidate._files
    if (type(members) is not tuple or any(type(row) is not tuple or len(row) != 2
            or type(row[0]) is not str or type(row[1]) is not bytes for row in members)):
        raise ValueError('Invalid immutable migration semantic inputs')
    context = contexts.from_custody(local)
    if (type(candidate.plan.raw) is not bytes or type(candidate.plan.sha256) is not str
            or type(candidate.lineage.raw) is not bytes or type(candidate.lineage.sha256) is not str
            or type(context.prior_journal_ids) is not tuple
            or any(type(jid) is not str for jid in context.prior_journal_ids)):
        raise ValueError('Invalid immutable migration semantic key')
    candidate_key = (candidate.plan.raw, candidate.plan.sha256,
        candidate.lineage.raw, candidate.lineage.sha256,
        tuple((path, raw) for path, raw in members),
        tuple(jid for jid in context.prior_journal_ids))
    plan_raw = native.read(store.JOURNAL + '/plan.json')
    intent_raw = native.read(store.JOURNAL + '/intent.json')
    progress_raw = tuple(native.read(store.PROGRESS + f'/{i:08d}.json')
                         for i in range(10))
    if any(type(raw) is not bytes for raw in (plan_raw, intent_raw, *progress_raw)):
        raise ValueError('Invalid immutable migration record bytes')
    if plan_raw != candidate.plan.raw:
        raise ValueError('Historical migration plan changed')
    key = (candidate_key, plan_raw, intent_raw, progress_raw)
    proof = getattr(local, '_migration_semantic_proof', None)
    if type(proof) is _SemanticProof and proof.owner() is local:
        if proof.key != key:
            raise ValueError('Immutable migration semantic prefix changed during custody')
        return proof.intent, proof.history, proof.checkpoint
    intent = journal.load_migration_intent(intent_raw, candidate.plan,
        candidate.projection_files, candidate.lineage,
        approved_plan_sha256=candidate.plan.sha256)
    history = progress.load_progress_history(progress_raw, intent, candidate.plan,
        candidate.projection_files, candidate.lineage)
    checkpoint = records.checkpoint_records(history, intent, candidate)
    local._migration_semantic_proof = _SemanticProof(ref(local), key,
                                                  intent, history, checkpoint)
    return intent, history, checkpoint


def inspect(native, first_portable, context, *, binding_source, state_source,
            pending_binding_identity=None):
    native.migration_content_leaves = {}
    candidate = native.operation_custody.migration_candidate
    legacy = native.operation_custody.legacy_custody
    legacy.check_lock()
    if native.children(store.JOURNAL) != {'plan.json', 'intent.json', 'progress',
                                        'legacy-original.json', 'terminal.json'} | (
                set(plans.RAW_NAMES) if candidate.lineage._raw_archive else set()):
        raise ValueError('Historical migration J1 inventory differs')
    if native.children(store.PROGRESS) != {f'{i:08d}.json' for i in range(10)}:
        raise ValueError('Historical migration progress is incomplete')
    if native.read(store.JOURNAL + '/plan.json') != candidate.plan.raw:
        raise ValueError('Migration selector changed after custody acquisition')
    if pp.load_portable_snapshot(projection._Reader(candidate.projection_files)) != first_portable:
        raise ValueError('Historical migration projection differs from first predecessor')
    plans.verify_raw_evidence(native, candidate)
    intent, history, checkpoint = _semantic_records(native, native.operation_custody)
    witnesses = intent.body['storage_witnesses']
    if (native.lock_witness != witnesses['lock']
            or native.directory(store.JOURNAL) != witnesses['journal']
            or native.directory(store.PROGRESS) != witnesses['progress']):
        raise ValueError('Historical migration journal/lock identity differs')
    state, terminal, binding = checkpoint
    if (native.read(binding_source) != binding.raw or native.read(state_source) != state.raw
            or native.read(store.JOURNAL + '/terminal.json') != terminal.raw):
        raise ValueError('Historical migration terminal/checkpoint differs')
    commitment = history[8].body['commitment']
    if native.windows:
        from .windows_rename_identity import identity_from_record
        from .windows_restoring_backend import WindowsRestoringBackend
        import ntpath
        expected = identity_from_record(commitment['rename_identity'])
        path = ntpath.join(legacy.reader.root, *binding_source.split('/'))
        with WindowsRestoringBackend(legacy.reader.handles, {'binding': path}) as backend:
            if backend.observe('binding') != expected:
                if (pending_binding_identity != expected
                        or not backend.pending_matches('binding', expected)):
                    raise ValueError('Historical migration Windows binding identity differs')
    elif native.observations[binding_source]['metadata'] != commitment['staged_witness']:
        raise ValueError('Historical migration binding native witness differs')
    validate_legacy(native.operation_custody)
    tree = history[1].body['commitment']
    if native.directory(pp.ROOT) != tree['stage_root']:
        raise ValueError('Historical published migration root differs')
    for row in tree['directories']:
        if native.directory(pp.ROOT + '/' + row['path']) != row['witness']:
            raise ValueError('Historical migration portable directory differs')
    for row in tree['files']:
        _published_file(native, row['path'], candidate.projection_files[row['path']],
                        row['witness'], context.journal_ids)
    legacy.check_lock()
    return intent, history, state, terminal, binding


def validate_legacy(local):
    """Revalidate immutable original/fence/source before and after own writes."""
    receiving = getattr(local, 'receiving_legacy', None)
    if receiving is not None:
        receiving.revalidate()
    candidate = getattr(local, 'migration_candidate', None)
    if candidate is None:
        return
    legacy = local.legacy_custody
    legacy.check_mutation_window()
    from .legacy_migration_source_state import _actual_source_snapshot
    with _actual_source_snapshot(legacy, local) as source:
        from types import SimpleNamespace
        observed = inspection._MigrationStore(SimpleNamespace(working_reader=source.reader), local.windows)
        observed.lock_handle, observed.lock_witness = local.lock_handle, local.lock_witness
        source.track_store(observed)
        if observed.read(store.JOURNAL + '/plan.json') != candidate.plan.raw:
            raise ValueError('Historical migration plan changed')
        plans.verify_raw_evidence(observed, candidate)
        intent, history, _checkpoint = _semantic_records(observed, local)
        names = observed.children(store.JOURNAL)
        if inspection._source_state(source, observed, candidate, 'finalized', history, names)[0] != 'retained':
            raise ValueError('Historical migration original is not retained')
        if inspection._fence_state(source, observed, candidate, 'finalized', history, names, None) != 'installed':
            raise ValueError('Historical migration fence is not installed')
        pointer = candidate.plan.body['fence']['path']
        files = [source.observations[p] for p in sorted(source.observations) if p != pointer]
        dirs = [{'path': p, 'witness': w} for p, w in sorted(source.directory_witnesses.items())]
        if (files != [r for r in candidate.plan.body['legacy_files'] if r['path'] != pointer]
                or dirs != candidate.plan.body['legacy_directories']):
            raise ValueError('Historical migration legacy archive changed')
        other = candidate.plan.body['competing_legacy']
        if inspection._directory(source.reader, local.windows, other['path']) != other['witness']:
            raise ValueError('Competing legacy source appeared')


def mirror_owned_root(local, before, after):
    """Advance a second pinned reader only after the exact local move proof."""
    receiving = getattr(local, 'receiving_legacy', None)
    if receiving is not None:
        receiving.mirror_owned_root(before, after)
    candidate = getattr(local, 'migration_candidate', None)
    if candidate is None:
        return
    from .portable_provenance_posix import _witness, _same_namespace
    reader = local.legacy_custody.reader.reader
    label, parent, name, fd, original = reader.chain[-1]
    if original.stat_fields != before.stat_fields or original.metadata != before.metadata:
        raise ValueError('Borrowed legacy root did not share exact pre-move witness')
    observed = _witness(fd, leaf=False, label=label)
    if observed.stat_fields != after.stat_fields or observed.metadata != after.metadata:
        raise ValueError('Borrowed legacy root differs from exact proved own move')
    _same_namespace(parent, name, observed, leaf=False, label=label)
    reader.chain[-1] = (label, parent, name, fd, observed)
