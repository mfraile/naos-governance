"""Native Windows consumer dispatch and held-handle external plan I/O."""

from __future__ import annotations

from .plan_stdout import emit_canonical_plan

from contextlib import ExitStack, contextmanager
import json
import ntpath
import os
from pathlib import Path
import sys
import tempfile

from .private_preview import PrivatePreviewAddress
from .canonical import canonical_bytes, canonical_sha256, loads_strict_json
from .windows_backend import _split_leaf
from .windows_handles import WindowsHandleError, WindowsHandles
from .windows_planning import OBSERVATION_SCHEMA, WindowsReadObserver, build_windows_plan
from .windows_observation import _parts, _relative_parts

MAX_PLAN_BYTES = 16 * 1024 * 1024
DIAGNOSTIC_PLAN_SCHEMA = "naos.upgrade.windows_diagnostic_plan.v1"


def _modules():
    try:
        from .. import naos_init, naos_upgrade
    except ImportError:  # Direct checkout execution.
        import naos_init
        import naos_upgrade
    return naos_init, naos_upgrade


def _runtime(project_root):
    from .windows_runtime import WindowsRuntime
    init, _ = _modules()
    return WindowsRuntime.native(str(project_root), str(init.UPGRADE_SOURCE_POLICY_PATH))


def source_pairs(sources, *, private_preview_address=None):
    if private_preview_address is not None and type(private_preview_address) is not PrivatePreviewAddress:
        raise ValueError("Private preview source handoff requires its owning address")
    return [(
        relative.as_posix().replace('/', '\\'),
        private_preview_address.ordinary_source(relative, source)
        if private_preview_address is not None else str(source),
    ) for relative, source in sources]


def activation_destination_identity(project_root, relative, *, handles=None):
    """Observe every ordinary destination component through held native handles.

    Starting at the drive also represents a missing greenfield project as a
    validated absent suffix. Public namespaces remain ordinary drive paths.
    """
    drive, project_parts = _parts(str(project_root))
    relative_parts = _relative_parts(relative.as_posix().replace('/', '\\'))
    observer = WindowsReadObserver(WindowsHandles() if handles is None else handles)
    requested = '\\'.join(project_parts + relative_parts)
    observed, _ = observer.observe(drive, requested)
    if (not isinstance(observed, dict) or observed.get('schema') != OBSERVATION_SCHEMA
            or observed.get('path') != requested
            or observed.get('presence') not in ('present', 'absent')):
        raise ValueError('Windows destination observer returned no valid bound presence record')
    def valid_identity(value):
        return isinstance(value, dict) and all(
            isinstance(value.get(key), str) and len(value[key]) == size
            and all(char in '0123456789abcdef' for char in value[key])
            for key, size in [('volume_serial_hex', 16), ('file_id_hex', 32)])

    parts = project_parts + relative_parts
    ancestor_parts = parts[:-1]
    if observed['presence'] == 'absent':
        missing = observed.get('missing_suffix')
        if (not isinstance(missing, list) or not missing
                or len(missing) > len(parts) or tuple(missing) != parts[-len(missing):]):
            raise ValueError('Windows destination absence lacks its held suffix')
        ancestor_parts = parts[:-len(missing)]
    ancestors = observed.get('ancestors')
    names = ('',) + ancestor_parts
    if (not isinstance(ancestors, list) or len(ancestors) != len(names)
            or any(not valid_identity(row) or row.get('name') != name
                   for row, name in zip(ancestors, names))):
        raise ValueError('Windows destination observation lacks its held ancestor identities')
    if observed['presence'] == 'absent':
        return None
    identity = observed.get('identity')
    if not valid_identity(identity) or set(identity) != {'volume_serial_hex', 'file_id_hex'}:
        raise ValueError('Windows destination observer returned an invalid native identity')
    return dict(identity)


def _absolute(path):
    value = str(Path(path).expanduser())
    return value if ntpath.isabs(value) else os.path.abspath(value)


def canonical_target(path, *, must_exist, allow_existing_resume=False, handles=None):
    """Validate native ancestors without resolving a reparse point first."""
    target = _absolute(path)
    drive, parents, _leaf = _split_leaf(target)
    observer = WindowsReadObserver(WindowsHandles() if handles is None else handles)
    observer.root_identity(ntpath.join(drive, *parents))
    try:
        observer.root_identity(target)
    except WindowsHandleError as exc:
        if exc.operation != 'NtCreateFile' or exc.ntstatus != 0xC0000034:
            raise
        if must_exist:
            raise ValueError('Windows project target must already exist') from exc
        return Path(target)
    if not must_exist and not allow_existing_resume:
        raise ValueError('Greenfield Windows target must be absent; use brownfield for an existing directory')
    return Path(target)


@contextmanager
def _external_parent(project_root, path, handles, *, publish):
    """Pin every ancestor and reject a plan inside the project by identity."""
    drive, parents, leaf = _split_leaf(_absolute(path))
    project_identity = WindowsReadObserver(handles).root_identity(str(project_root))
    with ExitStack() as stack:
        parent = stack.enter_context(handles.open_root(drive, for_publish=publish and not parents))
        chain = [parent]
        for index, component in enumerate(parents):
            last = index == len(parents) - 1
            parent = stack.enter_context(handles.open_child(parent, component, kind='directory',
                for_publish=publish and last, pin_for_read=not (publish and last)))
            chain.append(parent)
        for ancestor in chain:
            info = ancestor.info()
            identity = {'volume_serial_hex': f'{info.volume:016x}', 'file_id_hex': info.file_id.hex()}
            if identity == project_identity:
                raise ValueError('Windows plan files must remain outside the adopter project')
        yield parent, leaf


def _read_bytes(held, limit):
    before, security = held.info(), held.security()
    if before.directory or before.links != 1 or not 0 <= before.size <= limit:
        raise ValueError('Windows plan must be one bounded regular file')
    held.seek(0)
    output = bytearray()
    while len(output) <= before.size:
        block = held.read(min(64 * 1024, before.size + 1 - len(output)))
        if not block:
            break
        output.extend(block)
    if (len(output) != before.size or held.info() != before or held.security() != security):
        raise ValueError('Windows plan changed during its held read')
    return bytes(output)


def publish_external_plan(project_root, path, plan, *, handles=None):
    payload = canonical_bytes(plan)
    if len(payload) > MAX_PLAN_BYTES:
        raise ValueError('Windows plan exceeds its 16 MiB limit')
    handles = WindowsHandles() if handles is None else handles
    with _external_parent(project_root, path, handles, publish=True) as (parent, leaf):
        # No ordinary replace or post-failure cleanup: partial output remains
        # visible and a later invocation must choose a different absent name.
        with handles.create_private_file(parent, leaf) as created:
            created.write_all(payload)
            created.flush()
            if _read_bytes(created, MAX_PLAN_BYTES) != payload:
                raise ValueError('Windows external plan did not read back exactly')
    return Path(_absolute(path))


def read_external_bytes(project_root, path, *, handles=None, limit=None):
    limit = MAX_PLAN_BYTES if limit is None else limit
    if not 0 < limit <= MAX_PLAN_BYTES:
        raise ValueError("Unsupported Windows external file read limit")
    handles = WindowsHandles() if handles is None else handles
    with _external_parent(project_root, path, handles, publish=False) as (parent, leaf):
        with handles.open_child(parent, leaf, kind='file', pin_for_read=True) as held:
            payload = _read_bytes(held, limit)
    return payload


def read_external_plan(project_root, path, *, handles=None):
    payload = read_external_bytes(project_root, path, handles=handles)
    plan = loads_strict_json(payload)
    if not isinstance(plan, dict) or canonical_bytes(plan) != payload:
        raise ValueError('Windows apply plan must contain exact canonical JSON bytes')
    return plan


def current_paths(project_root):
    return {path.replace('\\', '/') for path in _runtime(project_root).current_paths()}


def inspect(project_root):
    return _runtime(project_root).inspect()


def source_observation(path, *, capture_bytes=False, handles=None):
    """Read a source without following native reparse ancestors or leaves."""
    drive, parents, leaf = _split_leaf(_absolute(path))
    observer = WindowsReadObserver(WindowsHandles() if handles is None else handles)
    observed, payload = observer.observe(ntpath.join(drive, *parents), leaf,
                                         capture_bytes=capture_bytes)
    if observed is None or observed['presence'] != 'present':
        raise ValueError('Windows source must be an existing regular file')
    return observed, payload


def source_contract(path):
    observed, _ = source_observation(path)
    return ({'kind': 'file', 'size_decimal': observed['size_decimal'],
             'sha256': observed['sha256']},
            {'schema': 'naos.windows.source_metadata.v1',
             'attributes': observed['attributes'], 'security': observed['security']})


def guard_destination(project_root, relative, *, kind, handles=None):
    """Read-only destination check; the runtime revalidates before publication."""
    handles = WindowsHandles() if handles is None else handles
    drive, root_parts = _parts(str(project_root))
    selected = _relative_parts(str(relative).replace('/', '\\'))
    if not selected:
        raise ValueError('Windows destination requires a relative leaf')
    with ExitStack() as stack:
        parent = stack.enter_context(handles.open_root(drive))
        components = root_parts + selected
        for index, component in enumerate(components):
            try:
                parent = stack.enter_context(handles.open_child(parent, component,
                    kind=kind if index == len(components) - 1 else 'directory', pin_for_read=True))
            except WindowsHandleError as exc:
                if (index >= len(root_parts) and exc.operation == 'NtCreateFile'
                        and exc.ntstatus == 0xC0000034):
                    return
                raise


def run_add_request(project_root, sources, *, operation, request_inputs, dry_run,
                    plan_out=None, preapply_revalidator=None, applicability=None):
    """Add absent leaves directly; existing updates need separate plan/apply."""
    try:
        from .. import naos_add as add_module
    except ImportError:
        import naos_add as add_module
    if applicability is not None:
        applicability.select_route("windows_legacy")
    runtime = _runtime(project_root)
    snapshot = runtime.inspect()
    if snapshot is None or snapshot.previous_inputs is None:
        if dry_run and plan_out is None:
            # A completed source review is not initialization or plan authority.
            # Preserve source validation failures before reporting this blocker.
            add_module._managed_request_inventory(sources)
            if applicability is not None:
                applicability.record("blocked", "managed_initialization_required",
                                     execution_route="none", direct_add_allowed=False)
            print('  [PLAN-BLOCKED] Managed initialization is required before add/setup; '
                  'dry-run inspection completed, no plan was created and no content was changed.')
            return 0
        raise ValueError('Windows add/setup requires managed initialization first')
    inventory = add_module._managed_request_inventory(sources)
    request_sha256 = canonical_sha256({
        'schema': 'naos.add.managed_request.v1', 'operation': operation,
        'inputs': request_inputs, 'sources': inventory,
    })
    binding = {'schema': 'naos.add.operation_inputs.v1',
               'request_sha256': request_sha256, 'request': request_inputs,
               # Regeneration uses the same portable sorted source inventory.
               'selected_paths': [row['path'] for row in inventory]}
    checks = [{'check_id': 'managed_request_source_authority', 'status': 'passed',
               'evidence_sha256': request_sha256, 'operation_inputs': binding}]
    plan = runtime.plan(source_pairs(sources),
        request={'operation': operation, 'inputs': snapshot.previous_inputs}, checks=checks)
    if dry_run:
        for row in plan['rows']:
            display_path = row['path'].replace('\\', '/')
            print(f"    {row['action']}: {display_path}")
    print(f"  Managed-content plan SHA-256: {plan['digest_sha256']}")
    if plan_out is not None:
        publish_external_plan(project_root, plan_out, plan)
        print(f'  [PLAN_ONLY] Saved {plan_out}; apply through naos upgrade with its exact digest.')
        return 0 if plan['status'] == 'ready' else 2
    if plan['status'] != 'ready':
        if dry_run and applicability is not None:
            applicability.record("blocked", "plan_not_ready", request_sha256=request_sha256, plan_status=plan["status"], plan_sha256=plan["digest_sha256"])
        print('  [PLAN-BLOCKED] Existing content was preserved.')
        return 0 if dry_run else 2
    creates_only = all(item['action'] == 'NOOP_UNCHANGED' or
                       (item['before']['presence'] == 'absent' and item['action'].startswith('CREATE_'))
                       for item in plan['rows'])
    if not creates_only:
        if dry_run and applicability is not None:
            applicability.record("blocked", "external_plan_required", execution_route="external_reviewed_plan_apply", request_sha256=request_sha256, plan_status=plan["status"], plan_sha256=plan["digest_sha256"])
        print('  [PLAN_ONLY] Existing updates require an external --plan-out and separate upgrade apply.')
        return 0 if dry_run else 2
    if dry_run:
        if applicability is not None:
            noop = all(item["action"] == "NOOP_UNCHANGED" for item in plan["rows"])
            applicability.record("noop" if noop else "ready", "provenance_current" if noop else "create_only_ready", execution_route="none" if noop else "create_only_add", direct_add_allowed=not noop, request_sha256=request_sha256, plan_status=plan["status"], plan_sha256=plan["digest_sha256"])
        print('  [DRY-RUN] No project content was changed.')
        return 0
    outcome = runtime.apply(plan, source_pairs(sources), expected_digest=plan['digest_sha256'],
                            preapply_revalidator=preapply_revalidator)
    print(json.dumps(outcome, sort_keys=True, separators=(',', ':')))
    return 0 if outcome['status'] in {'committed', 'already_applied', 'no_changes'} else 2


def recorded_profile_inputs(project_root):
    """Read profile lineage through the native held-handle provenance path."""
    snapshot = _runtime(project_root).inspect()
    return snapshot.previous_inputs if snapshot is not None else None


def _diagnostic_upgrade_plan(project_root, *, requested_profile, runtime, init, upgrade):
    """Observe unowned content natively; candidate defaults never grant ownership."""
    root_identity = runtime.observer.root_identity(str(project_root))
    with tempfile.TemporaryDirectory(prefix='naos-windows-diagnostic-',
            dir=upgrade._external_temp_root(project_root)) as temporary:
        preview_root = Path(temporary) / 'preview'
        # Existing-destination preview reads adopter files using ordinary paths.
        # This default-only rendering writes solely to the external preview.
        preview = init._generate_scaffold_preview(
            project_path=project_root, preview_dir=preview_root,
            signals=init._empty_signals(), tier=requested_profile,
            archetype='custom', backend='static_only', memory_choice=None,
            current_managed_paths=set(), existing_destination=False,
            apply_brownfield_layout_adapter=False, ephemeral_preview=True,
            emit_progress=False)
        drive, parents, leaf = _split_leaf(_absolute(init.UPGRADE_SOURCE_POLICY_PATH))
        native = build_windows_plan(runtime.observer,
            project_root=str(project_root), candidate_root=str(preview_root),
            policy_root=ntpath.join(drive, *parents), policy_relative=leaf,
            paths=tuple(relative.as_posix().replace('/', '\\')
                        for relative, _source in preview['sources']),
            provenance_reader=None)
        paths = []
        for row in native['paths']:
            paths.append({
                'path': row['path'].replace('\\', '/'),
                'base': row['base'], 'before': row['before'],
                'after': {key: value for key, value in row['after'].items()
                          if key != 'metadata_sha256'},
                'before_observation': row['before_observation'],
                'action': 'REFUSE_PROVENANCE', 'ownership': None,
                'mutation': {'kind': 'none', 'eligible': False},
            })
    if runtime.observer.root_identity(str(project_root)) != root_identity:
        raise ValueError('Windows diagnostic project root changed during observation')
    body = {
        'schema': DIAGNOSTIC_PLAN_SCHEMA, 'operation': upgrade.UPGRADE_OPERATION,
        'status': 'diagnostic_only', 'project_root': str(project_root),
        'project_root_identity': root_identity,
        'profile': {'requested': requested_profile, 'preserved_inputs': None},
        'candidate_defaults': {'profile': requested_profile, 'archetype': 'custom',
            'backend': 'static_only', 'memory_choice': None,
            'adopter_signals_used': False, 'preserved_inputs': False,
            'detached_preview_metadata_authoritative': False},
        'manifest': {'status': 'diagnostic_only', 'ownership_reclassified': False,
            'refusal': 'No committed Windows managed initialization inputs; ownership inference is forbidden.'},
        'source_policy': {key: native[key] for key in (
            'policy_observation', 'policy_raw_sha256', 'policy_snapshot_id',
            'policy_snapshot_sha256')},
        'paths': paths, 'ownership_inference': 'forbidden',
        'planning_mutated_target': False, 'apply_allowed': False,
    }
    return {**body, 'digest_sha256': canonical_sha256(body)}


def plan_upgrade(project_root, *, requested_profile, plan_out=None, summary_only=False):
    init, upgrade = _modules()
    runtime = _runtime(project_root)
    snapshot = runtime.inspect()
    if snapshot is None or snapshot.previous_inputs is None:
        plan = _diagnostic_upgrade_plan(project_root, requested_profile=requested_profile,
                                       runtime=runtime, init=init, upgrade=upgrade)
        if plan_out is not None:
            try:
                publish_external_plan(project_root, plan_out, plan)
            except WindowsHandleError as exc:
                if (exc.operation == 'NtCreateFile(exclusive create)'
                        and (exc.ntstatus == 0xC0000035 or exc.winerror == 183)):
                    raise ValueError('external plan already exists and was preserved') from exc
                raise
        if summary_only:
            upgrade._emit_managed_init_summary(requested_profile=requested_profile,
                status='diagnostic_only', plan_saved=plan_out is not None)
        else:
            emit_canonical_plan(canonical_bytes(plan))
        return 3
    with tempfile.TemporaryDirectory(prefix='naos-windows-plan-', dir=upgrade._external_temp_root(project_root)) as temporary:
        preview = init.regenerate_managed_init_preview(project_root, Path(temporary) / 'preview',
            manifest_snapshot=snapshot, requested_profile=requested_profile)
        plan = runtime.plan(source_pairs(preview['sources']),
            request={'operation': upgrade.UPGRADE_OPERATION, 'inputs': preview['effective_inputs']},
            checks=preview['checks'])
        upgrade._emit_lf_preview_diagnostics(project_root, preview, plan)
    if plan_out is not None:
        publish_external_plan(project_root, plan_out, plan)
    if summary_only:
        upgrade._emit_managed_init_summary(requested_profile=requested_profile,
            status='plan_only' if plan['status'] == 'ready' else 'diagnostic_only',
            plan_saved=plan_out is not None)
    else:
        emit_canonical_plan(canonical_bytes(plan))
    return 0 if plan['status'] == 'ready' else 3


def apply_upgrade(project_root, *, plan_path, expected_digest):
    init, upgrade = _modules()
    plan = read_external_plan(project_root, plan_path)
    if plan.get('schema') == DIAGNOSTIC_PLAN_SCHEMA:
        raise ValueError('Windows diagnostic-only plans cannot authorize apply')
    if plan.get('digest_sha256') != expected_digest or plan.get('status') != 'ready':
        raise ValueError('Windows apply requires the exact ready plan digest')
    request = plan.get('request')
    if not isinstance(request, dict) or not isinstance(request.get('operation'), str):
        raise ValueError('Windows apply requires a supported managed upgrade request')
    operation = request['operation']
    is_profile = operation == upgrade.UPGRADE_OPERATION
    is_add = operation.startswith(('naos-add-artifact:', 'naos-add-setup-module:'))
    if not is_profile and not is_add:
        raise ValueError('Windows apply request operation is unsupported')
    inputs = request.get('inputs')
    if not isinstance(inputs, dict) or inputs.get('profile') not in init.PROFILES:
        raise ValueError('Windows profile apply requires supported preserved inputs')
    if is_profile:
        upgrade._require_upgrade_checks(plan)
    else:
        upgrade._require_add_checks(plan)
    runtime = _runtime(project_root)
    snapshot = runtime.inspect()
    if snapshot is None:
        raise ValueError('Windows apply requires valid managed provenance')
    if is_add:
        try:
            from .. import naos_add as add_module
        except ImportError:
            import naos_add as add_module
        if snapshot.previous_inputs != inputs:
            raise ValueError('Windows add/setup cannot change preserved initialization choices')
        with add_module.regenerate_managed_request(project_root, plan) as regenerated:
            if regenerated['checks'] != plan['checks']:
                raise ValueError('Windows add/setup source authority changed after approval')
            outcome = runtime.apply(plan, source_pairs(regenerated['sources']), expected_digest=expected_digest)
        print(json.dumps(outcome, sort_keys=True, separators=(',', ':')))
        return 0 if outcome['status'] in {'committed', 'already_applied', 'no_changes'} else 3
    with tempfile.TemporaryDirectory(prefix='naos-windows-apply-',
            dir=upgrade._external_temp_root(project_root), ignore_cleanup_errors=True) as temporary:
        preview = init.regenerate_managed_init_preview(project_root, Path(temporary) / 'preview',
            manifest_snapshot=snapshot, requested_profile=request['inputs']['profile'])
        if preview['effective_inputs'] != request['inputs'] or preview['checks'] != plan['checks']:
            raise ValueError('Windows regenerated inputs or fixed governance checks changed after approval')
        outcome = runtime.apply(plan, source_pairs(preview['sources']), expected_digest=expected_digest)
    if outcome['status'] in {'committed', 'already_applied', 'no_changes'}:
        policy = preview.get('lf_policy')
        if isinstance(policy, dict):
            effective_paths = list(policy.get('text_paths') or [])
            if policy.get('status') == 'generated':
                effective_paths.append('.gitattributes')
            effective = init.inspect_effective_lf_attributes(project_root, effective_paths)
            for line in init.lf_policy_diagnostic_lines(policy, effective):
                print(line, file=sys.stderr)
    print(json.dumps(outcome, sort_keys=True, separators=(',', ':')))
    return 0 if outcome['status'] in {'committed', 'already_applied', 'no_changes'} else 3


def recover(project_root):
    outcomes = _runtime(project_root).recover()
    print(json.dumps(outcomes, sort_keys=True, separators=(',', ':')))
    return 0 if all(item['status'] in {'committed', 'rolled_back', 'rolled_back_recorded', 'already_applied', 'superseded_committed'} for item in outcomes) else 3


def activate(project_root, sources, *, request_inputs, dry_run, greenfield,
             checks, preapply_revalidator=None, private_preview_address=None):
    required = {'generated_profile_contract'}
    if not greenfield:
        required.add('overlay_compatibility')
    if (not isinstance(checks, list) or len(checks) != len(required)
            or any(not isinstance(check, dict) or check.get('status') != 'passed'
                   or not isinstance(check.get('evidence_sha256'), str)
                   or len(check['evidence_sha256']) != 64
                   or any(c not in '0123456789abcdef' for c in check['evidence_sha256'])
                   for check in checks)
            or {check.get('check_id') for check in checks} != required):
        raise ValueError('Windows initialization requires passed fixed governance checks')
    native_sources = source_pairs(sources, private_preview_address=private_preview_address)
    handles = WindowsHandles()
    # Native absence is distinct from permission errors and unsafe path types.
    canonical_target(project_root, must_exist=False, allow_existing_resume=True, handles=handles)
    try:
        WindowsReadObserver(handles).root_identity(str(project_root))
        exists = True
    except WindowsHandleError as exc:
        if exc.operation != 'NtCreateFile' or exc.ntstatus != 0xC0000034:
            raise
        exists = False
    created_root = False
    if not exists:
        if not greenfield:
            raise ValueError('Windows managed project root must already exist')
        if dry_run:
            print('  PLAN_ONLY: absent greenfield target; activation will bind its native identity.')
            return [relative.as_posix() for relative, _ in sources]
        from .windows_runtime import create_project_root
        create_project_root(handles, str(project_root))
        created_root = True
    runtime = _runtime(project_root)
    snapshot = runtime.inspect()
    if greenfield and not created_root and snapshot is None:
        raise ValueError('Existing greenfield target has no owned Windows enrollment; preserve it and use brownfield')
    if snapshot is not None and snapshot.previous_inputs is not None:
        if runtime.is_exact_init_repeat(native_sources,
                request={'operation': 'naos-init', 'inputs': request_inputs}, checks=checks):
            print('  [ALREADY_APPLIED] Exact managed Windows initialization remains current.')
            return [relative.as_posix() for relative, _ in sources]
        raise ValueError('Managed Windows init transitions are plan-only; use upgrade plan/apply')
    plan = runtime.plan(native_sources, request={'operation': 'naos-init', 'inputs': request_inputs},
                        checks=checks, allow_enrollment=True)
    print(f"  Managed-content plan SHA-256: {plan['digest_sha256']}")
    if plan['status'] != 'ready':
        blocked_rows = [row for row in plan['rows']
                        if row['action'] not in {'CREATE_NEW_UPSTREAM', 'CREATE_NEW_ADOPTER_OWNED',
                                                 'CREATE_CONFIGURATION_CHOICE', 'CREATE_MANAGED_CACHE',
                                                 'CREATE_IMMUTABLE_REPORT', 'UPDATE_FROM_UPSTREAM'}
                        and not row['action'].startswith('NOOP_')]
        if not greenfield and snapshot is None:
            init, _ = _modules()
            init._emit_unmanaged_collision_review(
                plan_sha256=plan['digest_sha256'], blocked_rows=blocked_rows)
        refusals = [f"{row['path']}: {row['action']}" for row in blocked_rows]
        raise ValueError('Windows activation plan is blocked; project content was preserved: '
                         + '; '.join(refusals))
    if dry_run:
        return [relative.as_posix() for relative, _ in sources]
    outcome = runtime.apply(plan, native_sources, expected_digest=plan['digest_sha256'],
                            preapply_revalidator=preapply_revalidator)
    if outcome['status'] not in {'committed', 'already_applied', 'no_changes'}:
        raise RuntimeError(f"Windows activation {outcome['status']}: {outcome.get('detail')}")
    for relative in outcome['created_paths']:
        print(f"  [CREATED] {relative}")
    print(f"  [RECEIPT] {outcome['transaction_id']}: {outcome.get('receipt_path')}")
    return [relative.as_posix() for relative, _ in sources]
