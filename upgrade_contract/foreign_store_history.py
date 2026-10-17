"""Detached complete historical semantics; original native fields are recorded.

This module performs no native I/O and supplies no native-reader facade. It
validates exact byte inventories and mutual historical commitments. A separate
receiving inspector must observe and bind every actual object before mutation.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from types import SimpleNamespace

from .canonical import canonical_bytes
from . import local_binding as lb, local_store as ls, portable_provenance as pp
from . import v3_operation_context as contexts
from . import v3_j1_rebind_predecessor as j1
from . import v3_operation_projection as projection
from . import v3_operation_history as native_history
from .working_tree_capture import build_capture


@dataclass(frozen=True)
class RecordedPrefix:
    binding: lb.ValidatedLocalBinding
    state: ls.ValidatedLocalStore
    terminals: tuple
    journal_ids: tuple
    retained_files: tuple
    migration_candidate: object | None = None
    original_execution_observed: bool = False
    mutation_authorized: bool = False


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _json(raw, label):
    value = pp._load_json(raw, label)
    if canonical_bytes(value) != raw:
        raise ValueError('Noncanonical recorded history: ' + label)
    return value


def _names(files, directories, path):
    if path not in directories:
        raise ValueError('Missing historical directory: ' + path)
    prefix = path + '/'
    return {name[len(prefix):].split('/')[0] for name in set(files) | set(directories)
            if name.startswith(prefix)}


def _require_names(files, directories, path, expected):
    if _names(files, directories, path) != expected:
        raise ValueError('Missing/extra recorded history objects: ' + path)


def _file(files, path):
    raw = files.get(path)
    if type(raw) is not bytes:
        raise ValueError('Missing historical file: ' + path)
    return raw


def _witness(value, platform, kind):
    lb._validate_witness(value, platform, kind)
    if value['presence'] != 'present':
        raise ValueError('Recorded producer witness is absent')


def _observation(value, platform, path, *, raw=None):
    lb._fields(value, {'path', 'metadata', 'content'}, 'recorded producer observation')
    if value['path'] != path:
        raise ValueError('Recorded producer observation path differs')
    lb._validate_witness(value['metadata'], platform, 'file')
    content = value['content']
    if value['metadata']['presence'] == 'absent':
        if content is not None or raw is not None:
            raise ValueError('Absent recorded producer object has bytes')
    else:
        lb._fields(content, {'sha256', 'size_decimal'}, 'recorded content')
        lb._hex(content['sha256'], lb.HEX64, 'recorded content digest')
        lb._u64(content['size_decimal'], 'recorded size')
        if raw is not None and content != {'sha256': _sha(raw), 'size_decimal': str(len(raw))}:
            raise ValueError('Retained bytes differ from recorded producer content')
    return value


def _result_sources(ids, number, binding_source, state_source):
    if number == len(ids):
        return binding_source, state_source
    # A receiving boundary has dedicated retention slots. Ordinary successors
    # continue to use their existing fixed checkpoint/registration paths.
    successor = contexts.for_journal(ids[number])
    return successor.checkpoint.OLD_BINDING, successor.registration.BACKUP


def _replay(files, directories, ctx, registration, platform):
    from . import v3_durable_replay as replay
    r = ctx.replay
    _require_names(files, directories, r.ROOT, {'index.json', 'blobs', 'commitment.json'})
    names = _names(files, directories, r.BLOBS)
    if len(names) > replay.MAX_BLOBS:
        raise ValueError('Recorded replay blob count exceeds bound')
    blobs = {}
    for name in sorted(names):
        if not name.endswith('.bin'):
            raise ValueError('Unsupported recorded replay blob name')
        lb._hex(name[:-4], lb.HEX64, 'recorded replay blob')
        raw = _file(files, r.BLOBS + '/' + name)
        if len(raw) > pp.MAX_BASE_BYTES or _sha(raw) != name[:-4]:
            raise ValueError('Recorded replay blob differs from selected bytes')
        blobs[name[:-4]] = raw
    index = _file(files, r.INDEX)
    commit_raw = _file(files, r.COMMITMENT)
    commit = _json(commit_raw, 'replay commitment')
    lb._fields(commit, {'schema', 'plan_sha256', 'directories', 'files'}, 'replay commitment')
    if (commit['schema'] != replay.COMMIT_SCHEMA or commit['plan_sha256'] != registration['plan_sha256']
            or set(commit['directories']) != {r.ROOT, r.BLOBS}
            or set(commit['files']) != {r.INDEX} | {r.BLOBS + '/' + name for name in names}):
        raise ValueError('Recorded replay inventory/plan differs')
    for witness in commit['directories'].values():
        _witness(witness, platform, 'directory')
    for path, observed in commit['files'].items():
        _observation(observed, platform, path, raw=_file(files, path))
    _observation(registration['replay_binding'], platform, r.COMMITMENT, raw=commit_raw)
    replay._storage_budget(index, blobs)
    return index, blobs


def _publication(files, directories, ctx, plan, program, intent, registered, outcome, *, payload_roles=None):
    from . import v3_publication_stage as stage, v3_j2_publication as pub
    platform = plan.body['initial_capture']['native']['platform']
    windows = platform == 'Windows'
    p, d = ctx.staging, ctx.publication
    expected = {'program.json', 'targets.json', 'stages', 'retained', 'commitment.json',
                'directory-stages', 'directory-commitment.json'}
    if windows:
        expected.add('windows-commitment.json')
    _require_names(files, directories, p.PUBLICATION, expected)
    if _file(files, p.PROGRAM) != program.raw:
        raise ValueError('Recorded publication program differs from durable replay')
    targets_raw = _file(files, p.TARGETS)
    targets = _json(targets_raw, 'publication targets')
    sealed = _json(_file(files, p.COMMITMENT), 'publication stage commitment')
    lb._fields(targets, {'leaves', 'directories'}, 'recorded targets')
    lb._fields(sealed, {'schema', 'program_sha256', 'intent_sha256', 'registered_state_sha256',
        'target_observations_sha256', 'storage_witnesses', 'record_witnesses', 'stages'}, 'recorded sealed stages')
    if (sealed['schema'] != stage.SCHEMA or sealed['program_sha256'] != program.sha256
            or sealed['intent_sha256'] != intent.sha256 or sealed['registered_state_sha256'] != registered.sha256
            or sealed['target_observations_sha256'] != _sha(targets_raw)
            or set(sealed['storage_witnesses']) != {p.PUBLICATION, p.STAGES, p.RETAINED}
            or set(sealed['record_witnesses']) != {p.PROGRAM, p.TARGETS}
            or type(sealed['stages']) is not list
            or len(sealed['stages']) != len(program.body['publications'])):
        raise ValueError('Recorded publication reciprocal commitment differs')
    for witness in sealed['storage_witnesses'].values():
        _witness(witness, platform, 'directory')
    for path, observed in sealed['record_witnesses'].items():
        _observation(observed, platform, path, raw=_file(files, path))
    if type(targets['leaves']) is not list or type(targets['directories']) is not list:
        raise ValueError('Malformed recorded target inventory')
    before = {}
    for observed in targets['leaves']:
        _observation(observed, platform, observed.get('path'))
        if observed['path'] in before:
            raise ValueError('Aliased recorded publication target')
        before[observed['path']] = observed
    directory_paths=set()
    required_paths={row['path'] for row in program.body['required_directories']}
    for row in targets['directories']:
        lb._fields(row, {'path', 'witness'}, 'recorded target directory')
        if row['path'] not in required_paths or row['path'] in directory_paths:
            raise ValueError('Recorded target directory differs from approved program')
        directory_paths.add(row['path'])
        lb._validate_witness(row['witness'], platform, 'directory')
    slots = program.body['publications']
    if set(before) != {slot['destination'] for slot in slots} | {row['path'] for row in program.body['reused_portable_evidence']}:
        raise ValueError('Recorded target coverage differs from approved program')
    retained, staged, kept = set(), set(), []
    for index, (slot, after) in enumerate(zip(slots, sealed['stages']), 1):
        old = before[slot['destination']]
        _observation(after, platform, slot['stage'])
        if (after['content'] != {key: slot['after'][key] for key in ('sha256', 'size_decimal')}
                or old['content'] != (None if slot['before'] is None else
                    {key: slot['before'][key] for key in ('sha256', 'size_decimal')})):
            raise ValueError('Recorded stage/source differs from approved publication slot')
        if outcome == 'committed' and slot['before'] is not None:
            path = slot['retained']
            retained.add(f'{index:08d}')
            _observation({**old, 'path': path}, platform, path,
                raw=_file(files, path) if payload_roles is None else None)
            if payload_roles is not None:
                payload_roles[path] = ('file',old['content'])
            kept.append(path)
        elif outcome == 'rolled_back':
            path = slot['stage']
            staged.add(f'{index:08d}')
            _observation(after, platform, path,
                raw=_file(files, path) if payload_roles is None else None)
            if payload_roles is not None:
                payload_roles[path] = ('file',after['content'])
            kept.append(path)
    _require_names(files, directories, p.STAGES, staged)
    _require_names(files, directories, p.RETAINED, retained)
    dirs_raw = _file(files, d.DIRECTORY_COMMITMENT)
    dirs = _json(dirs_raw, 'directory stages')
    fields = {'schema', 'program_sha256', 'intent_sha256', 'stage_root_witness', 'directories'}
    if windows:
        fields |= {'windows_commitment_sha256', 'windows_commitment_witness'}
    lb._fields(dirs, fields, 'recorded directory stages')
    missing = pub._missing_directories(program, targets)
    if (dirs['schema'] != d.DIRECTORY_SCHEMA or dirs['program_sha256'] != program.sha256
            or dirs['intent_sha256'] != intent.sha256 or type(dirs['directories']) is not list
            or [row.get('path') for row in dirs['directories']] != missing):
        raise ValueError('Recorded directory stages differ from approved absent parents')
    _witness(dirs['stage_root_witness'], platform, 'directory')
    for index, row in enumerate(dirs['directories'], 1):
        lb._fields(row, {'path', 'stage', 'witness'}, 'recorded directory stage')
        if row['stage'] != d.DIRECTORY_STAGES + f'/{index:08d}':
            raise ValueError('Recorded directory stage slot differs')
        _witness(row['witness'], platform, 'directory')
        if outcome == 'rolled_back':
            _require_names(files, directories, row['stage'], set())
            if payload_roles is not None:
                payload_roles[row['stage']] = ('directory',None)
    _require_names(files, directories, d.DIRECTORY_STAGES,
                   {f'{i:08d}' for i in range(1, len(dirs['directories']) + 1)} if outcome == 'rolled_back' else set())
    if windows:
        from .windows_v3_publication_witness import load_file_witnesses
        raw = _file(files, d.WINDOWS_COMMITMENT)
        if _sha(raw) != dirs['windows_commitment_sha256']:
            raise ValueError('Recorded Windows publication identity bytes differ')
        _observation(dirs['windows_commitment_witness'], platform, d.WINDOWS_COMMITMENT, raw=raw)
        # Pure typed historical identities/security, never a native repair input.
        load_file_witnesses(raw, pub._windows_expected(sealed, targets, program))
    return kept, dirs


def _migration_j1(files, directories, portable_files, binding_source, state_source):
    from . import legacy_authority as authority, legacy_migration_records as lineage_records
    from . import legacy_migration_plan_records as plans, legacy_migration_planning as planning
    from . import legacy_migration_journal as journal, legacy_migration_progress as progress
    from . import legacy_migration_binding_records as records
    owner, _ = pp._decode_record(portable_files[pp.OWNER_PATH], pp.OWNER_SCHEMA,
        {'schema', 'project_id', 'minimum_reader', 'authority_kind', 'authority_sha256'})
    if owner['authority_kind'] == 'legacy_replay_projection':
        candidate = plans.reconstruct_replay_candidate(
            lambda path: portable_files[path] if path.startswith(pp.ROOT + '/') else _file(files, path),
            _file(files, j1.PLAN))
        lineage, plan = candidate.lineage, candidate.plan
        archive, projection_files = candidate.raw_archive, candidate.projection_files
    else:
        lineage, archive, projection_files, plan, candidate = _historical_v1_migration(
            files, portable_files, owner)
    _require_names(files, directories, j1.JOURNAL, {'plan.json', 'intent.json', 'progress', 'legacy-original.json', 'terminal.json'} | (
        set(plans.RAW_NAMES) if candidate.lineage._raw_archive else set()))
    _require_names(files, directories, j1.PROGRESS, {f'{i:08d}.json' for i in range(10)})
    intent = journal.load_migration_intent(_file(files, j1.INTENT), plan, projection_files, lineage, approved_plan_sha256=plan.sha256)
    history = progress.load_progress_history([_file(files, j1.PROGRESS + f'/{i:08d}.json') for i in range(10)], intent, plan, projection_files, lineage)
    state, terminal, binding = records.checkpoint_records(history, intent, candidate)
    if (_file(files, state_source) != state.raw or _file(files, binding_source) != binding.raw
            or _file(files, j1.TERMINAL) != terminal.raw):
        raise ValueError('Recorded migration terminal/result differs')
    pointer = plan.body['fence']['path']
    original = archive[pointer]
    expected_fence = lineage_records.build_fence(lineage, approved_lineage_sha256=lineage.sha256, original_pointer_bytes=original)
    if _file(files, progress.RETAINED) != original:
        raise ValueError('Recorded retained migration original bytes differ')
    for path, raw in archive.items():
        if _file(files, path) != (expected_fence.raw if path == pointer else raw):
            raise ValueError('Receiving migration source/archive bytes differ')
    return binding, state, terminal, history[-1].sha256, candidate


def _historical_v1_migration(files, portable_files, owner):
    from . import legacy_authority as authority, legacy_migration_records as lineage_records
    from . import legacy_migration_plan_records as plans, legacy_migration_planning as planning
    if owner['authority_kind'] != 'legacy_projection':
        raise ValueError('Recorded migration lacks exact projection authority')
    auth, _ = pp._decode_record(portable_files[authority.authority_path(owner['authority_sha256'])], authority.SCHEMA, authority._KEYS)
    lineage = lineage_records.LegacyLineage(portable_files[authority.lineage_path(auth['lineage_sha256'])], auth['lineage_sha256'])
    archive = {row['path']: portable_files[authority.blob_path(row['sha256'])] for row in lineage.body['archive']}
    expected = {f"expected_{row['role']}_sha256": row['sha256'] for row in lineage.body['anchors']}
    projection_files = authority.build_legacy_projection(archive, lineage,
        directory_paths=auth['directory_paths'], source_policy_raw=portable_files[authority.blob_path(auth['source_policy_sha256'])],
        mode_inventory_raw=portable_files[pp.inventory_path(auth['mode_inventory_sha256'])],
        expected_modes_sha256=auth['mode_inventory_sha256'], approved_lineage_sha256=lineage.sha256,
        expected_source_policy_sha256=auth['source_policy_sha256'], **expected)
    plan = plans.load_migration_plan(_file(files, j1.PLAN), projection_files, lineage)
    candidate = planning.MigrationCandidate(plan, lineage, tuple(sorted(projection_files.items())))
    return lineage, archive, projection_files, plan, candidate


def _received(files, directories, context, raw, old_binding, old_state, portable,
              binding_source, state_source):
    from . import foreign_store_records as r
    plan = r.load(raw, r.PLAN_SCHEMA)
    body = plan.body
    p = r.paths(context.journal_id)
    if (body['next_journal_id'] != context.journal_id or body['prior_journals'] != old_state.body['journals']
            or body['old_binding_sha256'] != old_binding.sha256 or body['old_state_sha256'] != old_state.sha256):
        raise ValueError('Recorded receiving predecessor differs')
    first = _json(_file(files, j1.PLAN), 'migration-origin dispatch')
    source_format = first.get('source_format') if first.get('schema') in ('naos.upgrade.legacy_migration_plan.v1', 'naos.upgrade.legacy_migration_plan.v2') else None
    if body['legacy_source_format'] != source_format:
        raise ValueError('Recorded receiving migration-origin dispatch differs')
    migration = None if source_format is None else SimpleNamespace(plan=SimpleNamespace(body={'source_format': source_format}))
    prefix = SimpleNamespace(binding=old_binding, state=old_state,
        journal_ids=context.prior_journal_ids, migration_candidate=migration)
    capture = build_capture(body['initial_capture']['native'], body['initial_capture']['leaves'])
    r.validate_plan(raw, portable, capture, prefix, body['import_inventory'], expected_digest=plan.sha256)
    imported_files = {}
    for row in body['import_inventory']['files']:
        path = row['path']
        source = p.OLD_BINDING if path == p.BINDING else p.OLD_STATE if path == p.STATE else path
        data = _file(files, source)
        if row['content'] != {'sha256': _sha(data), 'size_decimal': str(len(data))}:
            raise ValueError('Recorded receiving retained incoming bytes differ')
        imported_files[path] = data
    if imported_files.get(p.BINDING) != old_binding.raw or imported_files.get(p.STATE) != old_state.raw:
        raise ValueError('Recorded receiving old checkpoint retention differs')
    imported_dirs = {row['path'] for row in body['import_inventory']['directories']}
    for row in body['import_inventory']['directories']:
        _require_names(imported_files, imported_dirs, row['path'], set(row['children']))
    intent = r.load(_file(files, p.INTENT), r.INTENT_SCHEMA)
    if intent != r.build_intent(plan, journal_witness=intent.body['storage_witnesses']['journal'],
                               lock_witness=intent.body['storage_witnesses']['lock']):
        raise ValueError('Recorded receiving intent differs')
    active, binding, state = r.checkpoints(plan, intent, old_binding, old_state)
    chain = r.progress_records(plan, intent, binding, state)
    expected_terminal = r.terminal(plan, intent, binding, state, chain[-1])
    if (_file(files, binding_source) != binding.raw or _file(files, state_source) != state.raw
            or _file(files, p.ACTIVE_STATE) != active.raw or _file(files, p.TERMINAL) != expected_terminal.raw):
        raise ValueError('Recorded receiving completion differs from deterministic checkpoint')
    _require_names(files, directories, p.JOURNAL,
        {'plan.json','intent.json','receiving.json','progress','state.before.json','checkpoint','terminal.json'})
    _require_names(files, directories, p.CHECKPOINT, {'binding.before.json','state.registered.before.json'})
    _require_names(files, directories, p.PROGRESS, {f'{i:08d}.json' for i in range(len(chain))})
    for index, row in enumerate(chain):
        if _file(files,p.PROGRESS+f'/{index:08d}.json') != row.raw:
            raise ValueError('Recorded receiving completion progress differs')
    commit = r.load(_file(files,p.COMMITMENT),r.COMMIT_SCHEMA).body
    lb._fields(commit, {'schema','plan_sha256','intent_sha256','directories','files'}, 'recorded receiving preparation')
    expected_raws = {p.PLAN: plan.raw,p.INTENT:intent.raw,p.OLD_BINDING:old_binding.raw,
        p.OLD_STATE:old_state.raw,p.REGISTERED:active.raw,p.BINDING_STAGE:binding.raw,
        p.STATE_STAGE:state.raw,p.TERMINAL_STAGE:expected_terminal.raw}
    platform = capture.body['native']['platform']
    if (commit['plan_sha256'] != plan.sha256 or commit['intent_sha256'] != intent.sha256
            or set(commit['files']) != set(expected_raws)
            or set(commit['directories']) != {p.JOURNAL,p.PROGRESS,p.CHECKPOINT}):
        raise ValueError('Recorded receiving preparation coverage differs')
    for witness in commit['directories'].values():
        _witness(witness,platform,'directory')
    if commit['directories'][p.JOURNAL] != intent.body['storage_witnesses']['journal']:
        raise ValueError('Recorded receiving journal producer differs')
    for path, data in expected_raws.items():
        row = commit['files'][path]
        lb._fields(row, {'sha256','witness','rename_identity'}, 'recorded receiving producer')
        _witness(row['witness'],platform,'file')
        if row['sha256'] != _sha(data):
            raise ValueError('Recorded receiving candidate digest differs')
        if platform == 'Windows':
            from .windows_rename_identity import identity_from_record
            identity_from_record(row['rename_identity'])
            from .v3_j2_registration import _rename_identity_matches_observation
            if not _rename_identity_matches_observation(row['rename_identity'],
                {'path':path,'metadata':row['witness'],'content':{'sha256':_sha(data),'size_decimal':str(len(data))}}):
                raise ValueError('Recorded receiving rename identity differs from producer witness')
        elif row['rename_identity'] is not None:
            raise ValueError('Recorded POSIX receiving has foreign rename identity')
    return binding,state,ls.load_local_terminal(expected_terminal.raw),chain[-1].sha256


def select_payload_roles(files, directories):
    """Provisional read-only roles from the SAME completed publication verifier.

    This cannot authorize mutation or claim original native execution. The
    caller must subsequently prove full history with actual payload bytes and
    fresh native witnesses; exact inventory rejects unselected candidates.
    """
    from . import v3_operation_records as op, v3_j2_checkpoint as checkpoint
    from . import v3_durable_replay as replay
    roles={}
    journals=sorted(_names(files,directories,j1.ROOT+'/journals'))
    for jid in journals[1:]:
        ctx=contexts.for_journal(jid)
        p,c=ctx.registration,ctx.checkpoint
        raw=_file(files,p.PLAN)
        body=_json(raw,'payload role dispatch')
        if body.get('schema')=='naos.upgrade.foreign_store_receiving_plan.v1':
            continue
        platform=body['initial_capture']['native']['platform']
        commit=_json(_file(files,p.COMMITMENT),'payload replay commitment')
        index,blobs=_replay(files,directories,ctx,commit,platform)
        plan,evidence,program=replay.decode_bundle(index,blobs,raw,
            _file(files,p.PRIOR_BINDING),_file(files,p.PRIOR_STATE))
        if contexts.for_plan(plan)!=ctx:
            raise ValueError('Payload role journal/program differs')
        old_binding,old_state=evidence['predecessor_binding'],evidence['predecessor_store']
        intent_body=_json(_file(files,p.INTENT),'payload role intent')
        intent=op.load_operation_intent(_file(files,p.INTENT),plan,old_binding,old_state,evidence['capture'],
            intent_body['storage_witnesses'],evidence['predecessor_record_witnesses'],
            approved_plan_sha256=plan.sha256,plan_evidence=evidence)
        registered=op.registration_store(intent,plan,old_binding,old_state,plan_evidence=evidence)
        progress_raw=_file(files,c.PROGRESS)
        progress=_json(progress_raw,'payload role final progress')
        outcome=progress.get('outcome')
        if outcome not in {'committed','rolled_back'}:
            raise ValueError('Payload role history is not completed')
        kept,dirs=_publication(files,directories,ctx,plan,program,intent,registered,outcome,payload_roles=roles)
        after_files=dict(evidence['portable_files'])
        if outcome=='committed':
            after_files.update({path:raw for path,raw in program._payloads if path.startswith(pp.ROOT+'/')})
        portable=pp.load_portable_snapshot(projection._Reader(after_files))
        capture=build_capture(progress['capture']['native'],progress['capture']['leaves'])
        result=SimpleNamespace(phases=('installed' if outcome=='committed' else 'ready',)*len(program.body['publications']),
            directory_phases=('published' if outcome=='committed' else 'staged',)*len(dirs['directories']))
        if checkpoint._progress(plan,intent,program,result,outcome,portable,capture)!=progress_raw:
            raise ValueError('Payload role deterministic progress differs')
        _,_,terminal=checkpoint.checkpoint_records(plan,intent,registered,portable,capture,progress_raw)
        if _file(files,c.TERMINAL)!=terminal.raw:
            raise ValueError('Payload role completed terminal differs')
    return roles


def load_completed_semantics(files, directories, portable_files, *, binding_source=j1.BINDING, state_source=j1.STATE):
    """Return recorded outcomes only after complete deterministic replay.

    `files` contains actual byte copies; `directories` complete receiving paths.
    Neither argument contains a replacement native witness for an old record.
    Current security/native identity and lock/quiescence proof are separate.
    """
    if (type(files) is not dict or type(directories) not in (set, frozenset)
            or any(type(path) is not str or type(raw) is not bytes for path, raw in files.items())):
        raise ValueError('Exact detached byte/directory inventories required')
    state = ls.load_local_store(_file(files, state_source))
    binding = lb.load_local_binding(_file(files, binding_source))
    if state.body['active_journal_id'] is not None or state.body['archives']:
        raise ValueError('Pending or unsupported archived history refuses import')
    ids = tuple(row['id'] for row in state.body['journals']['entries'])
    if not ids or ids != tuple(f'J{i:08d}' for i in range(1, len(ids) + 1)):
        raise ValueError('Recorded journal prefix is not complete/contiguous')
    _require_names(files, directories, j1.ROOT + '/journals', set(ids))
    operations = []
    total = 0
    for jid in ids[1:]:
        ctx = contexts.for_journal(jid)
        p = ctx.registration
        plan_raw = _file(files, p.PLAN)
        plan_body = _json(plan_raw, 'operation dispatch')
        if plan_body.get('schema') == 'naos.upgrade.foreign_store_receiving_plan.v1':
            operations.append((ctx, plan_raw, None, None, None, None))
            continue
        platform = plan_body['initial_capture']['native']['platform']
        from . import v3_j2_registration as reg, v3_durable_replay as replay
        _require_names(files, directories, p.J2, (reg.FILES_PREPARED - {'state.registered.pending.json'}) |
            {'state.before.json', 'publication', 'replay', 'checkpoint', 'terminal.json'})
        _require_names(files, directories, p.PROGRESS, set())
        commit_raw = _file(files, p.COMMITMENT)
        commit = _json(commit_raw, 'registration commitment')
        if commit.get('schema') != p.REPLAY_SCHEMA or 'replay_binding' not in commit:
            raise ValueError('Recorded operation has no complete supported replay')
        index, blobs = _replay(files, directories, ctx, commit, platform)
        total = native_history._consume_replay_budget(total, len(index) + sum(map(len, blobs.values())))
        plan, evidence, program = replay.decode_bundle(index, blobs, plan_raw,
            _file(files, p.PRIOR_BINDING), _file(files, p.PRIOR_STATE))
        operations.append((ctx, plan, evidence, program, commit_raw, commit))
    first_files = next((item[2]['portable_files'] for item in operations if item[2] is not None), portable_files)
    current_portable = pp.load_portable_snapshot(projection._Reader(first_files))
    bsource, ssource = _result_sources(ids, 1, binding_source, state_source)
    migration = None
    if _json(_file(files, j1.PLAN), 'J1 dispatch').get('schema') in ('naos.upgrade.legacy_migration_plan.v1', 'naos.upgrade.legacy_migration_plan.v2'):
        old_binding, old_state, terminal, progress_sha, migration = _migration_j1(files, directories, first_files, bsource, ssource)
    else:
        _require_names(files, directories, j1.JOURNAL, {'plan.json', 'intent.json', 'progress', 'terminal.json'})
        names = _names(files, directories, j1.PROGRESS)
        if not 1 <= len(names) <= j1.MAX_PROGRESS or names != {f'{i:08d}.json' for i in range(len(names))}:
            raise ValueError('Recorded J1 progress prefix is incomplete')
        raw = {path: _file(files, path) for path in (j1.PLAN, j1.INTENT, j1.TERMINAL, *(j1.PROGRESS + '/' + name for name in sorted(names)))}
        raw[j1.BINDING], raw[j1.STATE] = _file(files, bsource), _file(files, ssource)
        _plan, intent, history, old_state, old_binding = j1._semantic_j1(raw, current_portable)
        terminal = ls.load_local_terminal(raw[j1.TERMINAL])
        progress_sha = history.records[-1].sha256
    terminals = [('J00000001', terminal, progress_sha, old_binding)]
    retained = []
    for number, (ctx, plan, evidence, program, commit_raw, commit) in enumerate(operations, 2):
        if evidence is None:
            old_binding, old_state, terminal, progress_sha = _received(
                files, directories, ctx, plan, old_binding, old_state, current_portable,
                *_result_sources(ids, number, binding_source, state_source))
            terminals.append((ctx.journal_id, terminal, progress_sha, old_binding))
            continue
        from . import v3_operation_records as op, v3_j2_checkpoint as checkpoint, v3_j2_registration as reg
        p, c = ctx.registration, ctx.checkpoint
        if (evidence['predecessor_binding'] != old_binding or evidence['predecessor_store'] != old_state
                or pp.load_portable_snapshot(projection._Reader(evidence['portable_files'])) != current_portable):
            raise ValueError('Recorded operation predecessor/portable linkage differs')
        body = _json(_file(files, p.INTENT), 'operation intent')
        intent = op.load_operation_intent(_file(files, p.INTENT), plan, old_binding, old_state, evidence['capture'],
            body['storage_witnesses'], evidence['predecessor_record_witnesses'], approved_plan_sha256=plan.sha256, plan_evidence=evidence)
        registered = op.registration_store(intent, plan, old_binding, old_state, plan_evidence=evidence)
        if commit_raw != reg._commitment(plan, intent, old_state, registered, commit['stage_witness'], commit['progress_witness'],
                commit['old_rename_identity'], commit['stage_rename_identity'], commit['replay_binding']):
            raise ValueError('Recorded registration differs from deterministic intent/state')
        platform = plan.body['initial_capture']['native']['platform']
        for kind, witness in [('file', commit['stage_witness']), ('directory', commit['progress_witness'])]:
            _witness(witness, platform, kind)
        if (_file(files, p.BACKUP) != old_state.raw or _file(files, c.OLD_BINDING) != old_binding.raw
                or _file(files, c.OLD_STATE) != registered.raw):
            raise ValueError('Recorded retained checkpoint bytes differ')
        progress_raw = _file(files, c.PROGRESS)
        progress = _json(progress_raw, 'final progress')
        outcome = progress.get('outcome')
        if outcome not in {'committed', 'rolled_back'}:
            raise ValueError('Recorded operation is not terminal')
        after_files = dict(evidence['portable_files'])
        if outcome == 'committed':
            after_files.update({path: raw for path, raw in program._payloads if path.startswith(pp.ROOT + '/')})
        current_portable = pp.load_portable_snapshot(projection._Reader(after_files))
        capture = build_capture(progress['capture']['native'], progress['capture']['leaves'])
        kept, dirs = _publication(files, directories, ctx, plan, program, intent, registered, outcome)
        retained.extend(kept)
        result = SimpleNamespace(phases=('installed' if outcome == 'committed' else 'ready',) * len(program.body['publications']),
            directory_phases=('published' if outcome == 'committed' else 'staged',) * len(dirs['directories']))
        if checkpoint._progress(plan, intent, program, result, outcome, current_portable, capture) != progress_raw:
            raise ValueError('Recorded final progress differs from deterministic replay')
        old_binding, old_state, terminal = checkpoint.checkpoint_records(plan, intent, registered, current_portable, capture, progress_raw)
        cp = _json(_file(files, c.COMMITMENT), 'checkpoint commitment')
        fields = {'schema', 'plan_sha256', 'program_sha256', 'intent_sha256', 'outcome', 'directory_witness',
                  'old_binding_witness', 'old_state_witness', 'records'} | ({'windows_files'} if platform == 'Windows' else set())
        lb._fields(cp, fields, 'recorded checkpoint commitment')
        if (cp['schema'] != c.SCHEMA or cp['plan_sha256'] != plan.sha256 or cp['program_sha256'] != program.sha256
                or cp['intent_sha256'] != intent.sha256 or cp['outcome'] != outcome
                or cp['old_binding_witness'] != evidence['predecessor_record_witnesses']['binding']
                or cp['old_state_witness'] != commit['stage_witness']
                or set(cp['records']) != {c.PROGRESS, c.BINDING_STAGE, c.STATE_STAGE, c.TERMINAL_STAGE}):
            raise ValueError('Recorded checkpoint reciprocal references differ')
        _witness(cp['directory_witness'], platform, 'directory')
        bsource, ssource = _result_sources(ids, number, binding_source, state_source)
        for original, source, raw in [(c.PROGRESS,c.PROGRESS,progress_raw),(c.BINDING_STAGE,bsource,old_binding.raw),
                                     (c.STATE_STAGE,ssource,old_state.raw),(c.TERMINAL_STAGE,c.TERMINAL,terminal.raw)]:
            row = cp['records'][original]
            lb._fields(row, {'sha256','witness'}, 'recorded checkpoint row')
            _witness(row['witness'],platform,'file')
            if row['sha256'] != _sha(raw) or _file(files,source) != raw:
                raise ValueError('Recorded checkpoint file bytes differ')
        _require_names(files,directories,c.CHECKPOINT,{'progress.json','commitment.json','binding.before.json','state.registered.before.json'})
        if platform == 'Windows':
            checkpoint._windows_identities(cp,evidence,(old_binding,old_state,terminal))
        terminals.append((ctx.journal_id,terminal,_sha(progress_raw),old_binding))
    if old_binding != binding or old_state != state or current_portable != pp.load_portable_snapshot(projection._Reader(portable_files)):
        raise ValueError('Final recorded checkpoint/portable history differs')
    ls.reconcile_registration(state,binding,ids)
    for jid,terminal,progress_sha,historical_binding in terminals:
        ls.reconcile_terminal_reference(state,jid,terminal,progress_sha256=progress_sha,binding_after=historical_binding)
    return RecordedPrefix(binding,state,tuple(terminals),ids,tuple(retained),migration)


def _check_legacy_import_inventory(legacy, inventory):
    """Reject preexisting extras before projecting the approved legacy rows."""
    root = '.naos/upgrade-v1'
    def selected(path):
        return path == root or path.startswith(root + '/')
    files = {row['path'] for row in inventory['files'] if selected(row['path'])}
    directories = {row['path']: row for row in inventory['directories'] if selected(row['path'])}
    if set(legacy.raw) != files or set(legacy.directory_witnesses) != set(directories):
        raise ValueError('Imported receiving complete legacy inventory differs')
    if set(legacy.inventories) != set(directories):
        raise ValueError('Imported receiving legacy directory coverage differs')
    for path, row in directories.items():
        if set(legacy.inventories[path]) != set(row['children']):
            raise ValueError('Imported receiving legacy child inventory differs')


@dataclass(frozen=True)
class _ImportedSemanticsProof:
    """Detached exact-byte derivation, scoped to one acquired custody owner."""
    owner: object
    key: tuple
    result: RecordedPrefix


def _held_imported_semantics(custody, files, directories, portable_files, *,
                            context, boundary_id, binding_source, state_source):
    from copy import deepcopy
    from weakref import ref
    custody.check_lock()
    if (type(files) is not dict or type(portable_files) is not dict
            or any(type(path) is not str or type(raw) is not bytes
                   for mapping in (files, portable_files) for path, raw in mapping.items())
            or type(directories) is not frozenset
            or any(type(path) is not str for path in directories)):
        raise ValueError('Exact detached imported semantic inputs required')
    key = (context.prior_journal_ids, context.journal_ids, boundary_id,
           binding_source, state_source, tuple(sorted(files.items())),
           directories, tuple(sorted(portable_files.items())))
    proof = getattr(custody, '_imported_completed_semantics', None)
    if (type(proof) is _ImportedSemanticsProof and proof.owner() is custody
            and proof.key == key):
        return deepcopy(proof.result)
    # Checkpoint phases may legitimately change source locations/projection.
    # A different key always derives afresh; it is not itself a tamper verdict.
    result = load_completed_semantics(files, directories, portable_files)
    if type(result) is not RecordedPrefix:
        raise ValueError('Typed complete imported semantic prefix required')
    custody._imported_completed_semantics = _ImportedSemanticsProof(
        ref(custody), key, deepcopy(result))
    return deepcopy(result)


def native_imported_seed(native, portable, context, boundary_id, *, binding_source, state_source,
                         portable_files=None, pending_binding_identity=None):
    """Observe the latest receiving boundary, preserving old IDs as history.

    The independent scanner is a real same-reader native observation, not a
    historical facade. Historical path reconstruction exists only in a separate
    byte dictionary passed to the pure decoder above.
    """
    from copy import deepcopy
    from . import foreign_store_native as current, foreign_store_records as r
    from . import foreign_store_version as version
    from . import v3_operation_history as ordinary
    number = int(boundary_id[1:])
    ids = tuple(f'J{i:08d}' for i in range(1, number + 1))
    if boundary_id not in context.prior_journal_ids:
        raise ValueError('Receiving gate lies outside current predecessor prefix')
    p = r.paths(boundary_id)
    actual = current._Inventory(native.held, native.windows)
    actual.lock_handle,actual.lock_witness = native.lock_handle,native.lock_witness
    actual.scan(retained_journal_ids=ids, allowed_journal_ids=context.journal_ids)
    prefixes = tuple(j1.ROOT+'/journals/'+jid+'/' for jid in ids)
    root_dirs = {j1.ROOT,j1.ROOT+'/journals'}
    def selected(path):
        return path in root_dirs or any(path == prefix[:-1] or path.startswith(prefix) for prefix in prefixes)
    files = {path:raw for path,raw in actual.raw.items() if selected(path)}
    files[j1.BINDING],files[j1.STATE] = actual.read(binding_source),actual.read(state_source)
    files[j1.ROOT+'/scope.lock'] = b''
    dirs = {path for path in actual.directory_witnesses if selected(path)}
    custody = native.operation_custody
    legacy = getattr(custody,'receiving_legacy',None)
    if legacy is not None:
        legacy.revalidate()
        files.update(dict(legacy.raw))
        dirs.update(legacy.directory_witnesses)
    if portable_files is None:
        portable_files = _current_portable_bytes(native,portable)
    facts = _held_imported_semantics(custody, files, frozenset(dirs), portable_files,
        context=context, boundary_id=boundary_id,
        binding_source=binding_source, state_source=state_source)
    gate = version.inherited_gate(facts.binding,facts.state)
    if gate is None or gate['boundaries'][-1]['journal_id'] != boundary_id:
        raise ValueError('Receiving checkpoint gate differs from selected boundary')
    plan = r.load(actual.read(p.PLAN),r.PLAN_SCHEMA)
    intent = r.load(actual.read(p.INTENT),r.INTENT_SCHEMA)
    commit = r.load(actual.read(p.COMMITMENT),r.COMMIT_SCHEMA).body
    selected_inventory = plan.body['import_inventory']
    if legacy is not None:
        _check_legacy_import_inventory(legacy, selected_inventory)
    for row in selected_inventory['files']:
        source = p.OLD_BINDING if row['path']==p.BINDING else p.OLD_STATE if row['path']==p.STATE else row['path']
        observed = actual.observations.get(source)
        if observed is None and legacy is not None:
            observed = legacy.observations.get(source)
            if source==legacy.lock_path:
                observed={'path':source,'metadata':legacy.lock_witness,
                    'content':{'sha256':_sha(b''),'size_decimal':'0'}}
        if observed is None or {**observed,'path':row['path']} != row:
            raise ValueError('Imported receiving evidence current identity differs')
    for row in selected_inventory['directories']:
        path=row['path']
        observed=(legacy.directory_witnesses.get(path) if legacy is not None else None) or actual.directory_witnesses.get(path)
        if observed != row['witness']:
            raise ValueError('Imported receiving directory current identity differs')
    if intent.body['storage_witnesses']['lock'] != native.lock_witness:
        raise ValueError('Receiving boundary lock differs from current held lock')
    for path,witness in commit['directories'].items():
        if actual.directory_witnesses.get(path)!=witness:
            raise ValueError('Receiving producer directory current identity differs')
    locations={p.PLAN:p.PLAN,p.INTENT:p.INTENT,p.OLD_BINDING:p.OLD_BINDING,
        p.OLD_STATE:p.OLD_STATE,p.REGISTERED:p.ACTIVE_STATE,p.BINDING_STAGE:binding_source,
        p.STATE_STAGE:state_source,p.TERMINAL_STAGE:p.TERMINAL}
    for producer,source in locations.items():
        row=commit['files'][producer]
        actual.read(source)
        metadata_matches = actual.observations[source]['metadata']==row['witness']
        if pending_binding_identity is not None and producer==p.BINDING_STAGE:
            from .v3_j2_publication import _checkpoint_metadata_matches
            metadata_matches = _checkpoint_metadata_matches(actual.observations[source]['metadata'],
                row['witness'],source,(source,))
        if not metadata_matches or _sha(actual.raw[source])!=row['sha256']:
            raise ValueError('Receiving producer current bytes/native identity differ')
        if native.windows:
            from .foreign_store_lifecycle import _backend
            from .windows_rename_identity import identity_from_record
            with _backend(native.reader.root,custody,{'file':source}) as backend:
                expected=identity_from_record(row['rename_identity'])
                if pending_binding_identity is not None and producer==p.BINDING_STAGE:
                    if expected!=pending_binding_identity or (backend.observe('file')!=expected
                            and not backend.pending_matches('file',expected)):
                        raise ValueError('Receiving pending producer differs from current rename authority')
                elif backend.observe('file')!=expected:
                    raise ValueError('Receiving full Windows producer identity differs')
    native.raw.update(actual.raw)
    native.observations.update(actual.observations)
    native.inventories.update(actual.inventories)
    records={}
    leaves={}
    for path,raw in actual.raw.items():
        if not (selected(path) or path in (binding_source,state_source)):
            continue
        observed=deepcopy(actual.observations[path])
        if '/replay/blobs/' in path or path in actual.payload_witnesses:
            leaves[path]=observed
        else:
            records[path]=(raw,observed)
    directory_proof={path:(deepcopy(actual.directory_witnesses[path]),frozenset(actual.inventories[path]))
        for path in actual.inventories if selected(path) and path not in root_dirs and path not in actual.payload_witnesses}
    payload_directories={path:(deepcopy(witness),frozenset(actual.inventories[path]))
        for path,witness in actual.payload_witnesses.items() if witness['kind']=='directory'}
    # Complete fresh native revalidation remains mandatory after all semantic
    # derivation. No cached or historical metadata substitutes for this pass.
    for path in tuple(actual.inventories):
        actual.children(path,final=True)
    if native.windows:
        native.reader.revalidate()
    else:
        native.reader._final_revalidate({'control_directories':[{'path':path,'witness':witness}
            for path,witness in actual.directory_witnesses.items()],'managed_ancestors':[]},
            list(actual.observations.values()))
    custody.check_lock()
    return ordinary.CompletedPrefix(facts.binding,facts.state,facts.terminals,records,directory_proof,(),leaves,payload_directories)


def _current_portable_bytes(native,portable):
    """Fresh live portable read; replay callers supply their exact prior bytes."""
    from . import foreign_store_native as current
    root=native.reader.root if native.windows else native.reader.root_path
    handles=native.reader.handles if native.windows else None
    files={}
    with current._lane(root,native.windows,handles) as held:
        class Tee:
            def read(self,path):
                raw=held.portable_reader.read(path)
                if raw is not None:
                    files[path]=raw
                return raw
        if pp.load_portable_snapshot(Tee())!=portable:
            raise ValueError('Receiving seed selected portable bytes differ')
    return files
