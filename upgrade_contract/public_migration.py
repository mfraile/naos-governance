"""Explicit reviewed legacy migration through existing qualified lifecycles.

The raw native plan digest grants approval. External inputs carry independently
selected expectations and original evidence; transport self hashes grant no
additional authority. Historical reconstruction never changes current witnesses.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

from .plan_stdout import emit_canonical_plan
from .canonical import canonical_bytes, loads_strict_json
from . import legacy_migration_records as lineage_records
from . import legacy_migration_plan_records as plan_records
from . import legacy_migration_planning as planning
from . import legacy_authority as authority
from . import legacy_migration_source_state as source_state
from . import legacy_migration_inspection as inspection
from . import legacy_migration_preparation as preparation
from . import legacy_migration_staging as staging
from . import legacy_migration_retention as retention
from . import legacy_migration_fence as fence
from . import legacy_migration_head as head
from . import legacy_migration_binding as binding
from . import legacy_migration_rollback as rollback
from . import legacy_migration_progress as progress
from . import portable_provenance as pp
from . import rebind_publication as publication
from . import rebind_store_inspection as store
from . import public_rebind

# Defaults govern new callers; persisted inputs and plans dispatch by wire schema.
HISTORICAL_PLAN_SCHEMA = plan_records.SCHEMA
PLAN_SCHEMA = plan_records.REPLAY_SCHEMA
PLAN_SCHEMAS = (HISTORICAL_PLAN_SCHEMA, PLAN_SCHEMA)
HISTORICAL_INPUT_SCHEMA = 'naos.upgrade.legacy_migration_inputs.v1'
REPLAY_INPUT_SCHEMA = 'naos.upgrade.legacy_migration_inputs.v2'
INPUT_SCHEMA = REPLAY_INPUT_SCHEMA
INPUT_SCHEMAS = (HISTORICAL_INPUT_SCHEMA, INPUT_SCHEMA)
MAX_INPUT_BYTES = 64 * 1024
_CONTROLS = frozenset({'source_format', 'original_project_id', 'new_project_id',
    'binding_id', 'approved_lineage_sha256', 'expected_owner_sha256',
    'expected_scope_sha256', 'expected_head_sha256', 'expected_source_policy_sha256',
    'expected_modes_sha256'})


def _raw_external(root, path, *, cli, limit):
    windows = cli.naos_init._windows_cli()
    if windows is not None:
        return windows.read_external_bytes(root, path, limit=limit)
    return cli._read_external_bytes(
        cli._external_plan_path(root, path, must_exist=True), limit=limit)


def _inputs(root, path, *, cli):
    raw = _raw_external(root, path, cli=cli, limit=MAX_INPUT_BYTES)
    value = loads_strict_json(raw)
    if (type(value) is not dict or set(value) != _CONTROLS |
            {'schema', 'source_policy_file', 'mode_inventory_file'}
            or value['schema'] not in INPUT_SCHEMAS or canonical_bytes(value) != raw):
        raise ValueError('Migration inputs must contain exact canonical typed controls')
    if any(type(value[key]) is not str for key in value):
        raise ValueError('Migration inputs require string values')
    if value['source_format'] not in lineage_records._FENCE_POINTER:
        raise ValueError('Unsupported explicit migration source format')
    for key in _CONTROLS:
        if key.endswith('_sha256'):
            lineage_records._digest(value[key], key)
    lineage_records._original_id(value['original_project_id'])
    lineage_records._uuid4(value['new_project_id'])
    from . import local_binding
    local_binding._hex(value['binding_id'], local_binding.BINDING_ID, 'binding ID')
    controls = {key: value[key] for key in _CONTROLS}
    controls['replay_projection'] = value['schema'] == REPLAY_INPUT_SCHEMA
    parent = Path(path).expanduser().absolute().parent
    for path_key, raw_key in (('source_policy_file', 'source_policy_raw'),
                              ('mode_inventory_file', 'mode_inventory_raw')):
        if not value[path_key]:
            raise ValueError('Migration evidence file path is empty')
        supplied = Path(value[path_key]).expanduser()
        controls[raw_key] = _raw_external(root, supplied if supplied.is_absolute() else parent / supplied,
                                         cli=cli, limit=pp.MAX_RECORD_BYTES)
    return controls


def plan_command(root, *, inputs_path, plan_out, cli):
    candidate = planning.plan_legacy_migration(root, **_inputs(root, inputs_path, cli=cli))
    plan = candidate.plan
    if plan_out is not None:
        windows = cli.naos_init._windows_cli()
        if windows is not None:
            windows.publish_external_plan(root, plan_out, plan.body)
        else:
            cli._publish_external_plan(cli._external_plan_path(root, plan_out, must_exist=False), plan.raw)
    emit_canonical_plan(plan.raw)
    print('PLAN_ONLY: explicit legacy migration; raw plan SHA-256 ' + plan.sha256, file=sys.stderr)
    return 0


def _reconstruct(root, raw, controls, *, handles=None):
    """Read actual bytes under legacy-first/local-second custody; rebuild a copy.

    This bootstrap reads only fixed typed paths. The complete pure native plan
    validation follows, then a separate full prepared inspector reacquires both
    locks. No reconstructed historical pointer becomes a current observation.
    """
    body = loads_strict_json(raw)
    source_format = controls['source_format']
    if (type(body) is not dict or body.get('schema') not in plan_records.SCHEMAS
            or body.get('source_format') != source_format or len(raw) > plan_records._MAX_RECORD
            or canonical_bytes(body) != raw):
        raise ValueError('Approved migration plan schema/source/size differs')
    pointer = lineage_records._FENCE_POINTER[source_format]
    rows = body.get('legacy_files')
    if type(rows) is not list:
        raise ValueError('Approved original pointer observation is missing')
    originals = [row for row in rows if type(row) is dict and row.get('path') == pointer]
    if len(originals) != 1:
        raise ValueError('Approved original pointer observation is ambiguous')
    original_content = originals[0].get('content')
    windows = handles is not None or os.name == 'nt'
    actual = None
    try:
        with ExitStack() as stack:
            if windows:
                from .working_tree_capture_windows import _Capture as Reader
                from .windows_handles import WindowsHandles
                active_handles = handles if handles is not None else WindowsHandles()
                reader = Reader(active_handles, str(root), stack)
            else:
                from .working_tree_capture_posix import _Reader as Reader
                active_handles = None
                reader = stack.enter_context(Reader(Path(root)))
            actual = source_state._ActualSource(reader, windows, source_format)
            with actual.locked():
                actual.scan_actual()
                with publication._custody(root, active_handles) as local:
                    native = inspection._MigrationStore(SimpleNamespace(working_reader=reader), windows)
                    native.lock_handle, native.lock_witness = local.lock_handle, local.lock_witness
                    actual.track_store(native)
                    try:
                        if native.read(store.JOURNAL + '/plan.json') != raw:
                            raise ValueError('Persisted migration plan differs from external approval')
                        names = native.children(store.JOURNAL)
                        active = actual.archive_bytes.get(pointer)
                        retained = native.read(progress.RETAINED) if 'legacy-original.json' in names else None
                        def matches(payload, content):
                            return payload is not None and content == {
                                'sha256': hashlib.sha256(payload).hexdigest(), 'size_decimal': str(len(payload))}
                        if matches(active, original_content):
                            if retained is not None:
                                raise ValueError('Original migration pointer exists in two locations')
                            original = active
                        else:
                            planned_fence = body.get('fence')
                            if active is not None and (type(planned_fence) is not dict or
                                    planned_fence.get('path') != pointer or not matches(active,
                                    {key: planned_fence.get(key) for key in ('sha256', 'size_decimal')})):
                                raise ValueError('Current legacy pointer is neither original nor approved fence')
                            if not matches(retained, original_content):
                                raise ValueError('Retained original pointer bytes differ from approved history')
                            original = retained
                        # Historical copy only. Actual observations, reader baselines,
                        # native identities and absent pointer facts remain untouched.
                        archive = actual.archive_bytes
                        archive[pointer] = original
                        expected = {key: controls[key] for key in
                            ('expected_owner_sha256', 'expected_scope_sha256', 'expected_head_sha256')}
                        lineage = lineage_records.build_lineage(archive, source_format=source_format,
                            original_project_id=controls['original_project_id'],
                            new_project_id=controls['new_project_id'], **expected)
                        replay = body['schema'] == plan_records.REPLAY_SCHEMA
                        if replay:
                            lineage = lineage_records.LegacyLineage(lineage.raw, lineage.sha256,
                                tuple(sorted(archive.items())), controls['source_policy_raw'], controls['mode_inventory_raw'])
                        builder = authority.build_replay_projection if replay else authority.build_legacy_projection
                        files = builder(archive, lineage,
                            directory_paths=actual.directory_paths,
                            source_policy_raw=controls['source_policy_raw'],
                            mode_inventory_raw=controls['mode_inventory_raw'],
                            approved_lineage_sha256=controls['approved_lineage_sha256'],
                            expected_source_policy_sha256=controls['expected_source_policy_sha256'],
                            expected_modes_sha256=controls['expected_modes_sha256'], **expected)
                        plan = plan_records.load_migration_plan(raw, files, lineage)
                        if plan.body['binding_id'] != controls['binding_id']:
                            raise ValueError('Explicit migration binding differs from approved plan')
                        result = planning.MigrationCandidate(plan, lineage, tuple(sorted(files.items())))
                        plan_records.verify_raw_evidence(native, result)
                    finally:
                        actual.revalidate()
                        local.check_lock()
            return result
    finally:
        if actual is not None:
            actual.active = False


def _emit(observed):
    print(json.dumps({'status': 'rolled_back' if observed.phase == 'rolled_back' else 'committed',
        'phase': observed.phase, 'plan_sha256': observed.plan_sha256,
        'transaction_id': 'J00000001', 'checkpoint_complete': observed.checkpoint_complete},
        sort_keys=True, separators=(',', ':')))
    return 0


def approved_command(root, *, inputs_path, plan_path, expected_digest, recover, cli):
    body, raw = public_rebind.read_external_plan(root, plan_path, cli=cli)
    if body.get('schema') not in plan_records.SCHEMAS:
        raise ValueError('--migration-inputs accepts only the exact legacy migration plan schema')
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise ValueError('Exact raw approved migration plan digest differs')
    controls = _inputs(root, inputs_path, cli=cli)
    if controls['replay_projection'] != (body['schema'] == plan_records.REPLAY_SCHEMA):
        raise ValueError('Explicit input format differs from approved migration plan')
    if recover:
        candidate = _reconstruct(root, raw, controls)
        observed = inspection.inspect_prepared_migration(root, candidate=candidate,
                                                         expected_plan_sha256=expected_digest)
        if observed.checkpoint_complete:
            return _emit(observed)
        if observed.head_state != 'published' and observed.phase not in progress._ROLLBACK_SOURCES | {'rollback_pending', 'rolled_back'}:
            raise ValueError('Unsupported saved migration recovery state')
    else:
        candidate = planning.plan_legacy_migration(root, **controls)
        if candidate.plan.raw != raw:
            raise ValueError('Reviewed migration plan differs from current source, inputs or working capture')
    # All input/pure/initial native inspection refusals precede mutation reporting.
    try:
        if not recover:
            preparation.prepare_legacy_migration(root, candidate=candidate, expected_plan_sha256=expected_digest)
            staging.stage_prepared_migration(root, candidate=candidate, expected_plan_sha256=expected_digest)
            retention.retain_original_pointer(root, candidate=candidate, expected_plan_sha256=expected_digest)
            fence.install_legacy_fence(root, candidate=candidate, expected_plan_sha256=expected_digest)
            head.publish_migration_head(root, candidate=candidate, expected_plan_sha256=expected_digest)
            observed = binding.complete_migration_binding(root, candidate=candidate, expected_plan_sha256=expected_digest)
        elif observed.head_state == 'published':
            if observed.phase not in {'binding_pending', 'finalized'}:
                head.publish_migration_head(root, candidate=candidate, expected_plan_sha256=expected_digest)
            observed = binding.complete_migration_binding(root, candidate=candidate, expected_plan_sha256=expected_digest)
        else:
            observed = rollback.rollback_prepared_migration(root, candidate=candidate, expected_plan_sha256=expected_digest)
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({'status': 'recovery_required', 'plan_sha256': expected_digest,
            'detail': 'Migration mutation was attempted; preserve state and retry with the same external '
                      '--recover --apply-plan FILE --migration-inputs FILE --expect-plan-digest '
                      + expected_digest + ': ' + str(exc)}, sort_keys=True, separators=(',', ':')))
        return 3
    return _emit(observed)
