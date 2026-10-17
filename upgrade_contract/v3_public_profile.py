"""Reviewed profile plan/apply over a validated completed same-root history.

No enrollment, historical reset or inferred legacy scope authority.
"""
from __future__ import annotations

from .plan_stdout import emit_canonical_plan

from contextlib import ExitStack
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace

from . import local_binding as lb
from . import portable_provenance as pp
from . import v3_operation_records as records, v3_operation_program as programs
from . import v3_operation_projection as projection
from . import v3_durable_replay as replay
from .canonical import canonical_bytes
from .planner import load_source_policy_snapshot


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _read_current(reader, leaf, windows):
    if leaf['content'] is None:
        return None
    size = int(leaf['content']['size_decimal'])
    if size > pp.MAX_BASE_BYTES:
        raise ValueError('Current working byte ceiling exceeded')
    path = leaf['path']
    parent_path, _, name = path.rpartition('/')
    with ExitStack() as stack:
        if windows:
            parent = reader.directory(parent_path) if parent_path else reader.project
            handle = stack.enter_context(reader.handles.open_child(reader.directories[parent], name, kind='file', pin_for_read=True))
            before, witness = reader._observe(handle, directory=False)
            handle.seek(0)
            read = handle.read
        else:
            from .portable_provenance_posix import _witness, _same_namespace
            parent = reader._walk(parent_path, stack)
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            stack.callback(os.close, fd)
            before = _witness(fd, leaf=True, label=path)
            witness = lb.project_posix_witness(before.metadata)
            _same_namespace(parent, name, before, leaf=True, label=path)
            def read(count):
                return os.read(fd, count)
        if witness != leaf['metadata']:
            raise ValueError('Current working identity changed')
        parts, remaining = [], size
        while remaining:
            chunk = read(min(remaining, 1024 * 1024))
            if type(chunk) is not bytes or not 0 < len(chunk) <= remaining:
                raise ValueError('Current working read was short')
            parts.append(chunk)
            remaining -= len(chunk)
        if read(1):
            raise ValueError('Current working file grew')
        if windows:
            if reader._observe(handle, directory=False) != (before, witness):
                raise ValueError('Current working object changed during read')
        else:
            if _witness(fd, leaf=True, label=path) != before:
                raise ValueError('Current working object changed during read')
            _same_namespace(parent, name, before, leaf=True, label=path)
    raw = b''.join(parts)
    if leaf['content'] != {'sha256': _sha(raw), 'size_decimal': str(len(raw))}:
        raise ValueError('Current working bytes changed')
    return raw


def _capture(root, extras=()):
    from . import v3_operation_history as history
    captured = history.capture_completed_predecessor(root, extras)
    return (captured.pair, captured.portable_files, captured.current_bytes,
            captured.binding, captured.state, captured.record_witnesses,
            captured.context.prior_journal_ids)


def current_managed_paths(root, *, expected_portable=None):
    """Replay-owned leaves whose actual C still matches exact B and native state.

    Portable ownership alone does not mark an edited/deleted/replaced leaf current.
    """
    pair, files, current, binding, _state, _witnesses, _journals = _capture(root)
    if expected_portable is not None and pair.portable != expected_portable:
        raise ValueError('Portable history changed during current-path inspection')
    return _current_paths_from_capture(pair, files, current, binding)


def _current_paths_from_capture(pair, files, current, binding):
    observations = records._working_inputs(pair.working_tree.body, current,
                                          binding.body['observation'])
    windows = pair.working_tree.body['native']['platform'] == 'Windows'
    result = set()
    for path, entry in pair.portable.entries.items():
        content = entry['content']
        observed = observations[path]
        if content is None or observed['bytes'] is None or observed['native_status'] != 'clear':
            continue
        raw = observed['bytes']
        if (len(raw) == int(content['size_decimal']) and _sha(raw) == content['sha256']
                and raw == files[pp.base_path(content['sha256'])]
                and (windows or observed['executable'] == content['executable'])):
            result.add(path)
    return result


class _ProfilePreviewCapture:
    """Own the initial native capture and one render-to-fresh-capture boundary.

    Construction observes the project itself; no caller-supplied path set,
    capture dictionary or validation result is accepted as trusted authority.
    """

    def __init__(self, root):
        self._initial = deepcopy(_capture(root))
        self._used = False
        self._closed = False

    @property
    def portable(self):
        return self._initial[0].portable

    def _require_scope(self, root, portable):
        if self._closed:
            raise ValueError('Profile preview capture has already closed')
        native = self._initial[0].working_tree.body['native']
        if native['platform'] == 'Windows':
            import ntpath
            root_path = ntpath.abspath(os.fspath(root))
        else:
            root_path = os.path.abspath(os.fspath(root))
        if root_path != native['root_path'] or portable != self.portable:
            raise ValueError('Profile preview root or portable capture differs')

    def current_paths(self, root, portable):
        self._require_scope(root, portable)
        if self._used:
            raise ValueError('Profile preview capture was already consumed')
        self._used = True
        return _current_paths_from_capture(*self._initial[:4])

    def capture_after_preview(self, root, extras):
        self._require_scope(root, self.portable)
        if not self._used:
            raise ValueError('Renderer did not consume its owned profile capture')
        self._closed = True
        fresh = _capture(root, extras)
        old_pair, old_files, old_current, *old_local = self._initial
        pair, files, current, *local = fresh
        if pair.portable != old_pair.portable or files != old_files or local != old_local:
            raise ValueError('Profile ownership or portable inputs changed during regeneration')
        old_body, body = old_pair.working_tree.body, pair.working_tree.body
        old_native, native = old_body['native'], body['native']
        if ({key: value for key, value in old_native.items() if key != 'managed_ancestors'}
                != {key: value for key, value in native.items() if key != 'managed_ancestors'}):
            raise ValueError('Profile native root or control inputs changed during regeneration')
        ancestors = {row['path']: row['witness'] for row in native['managed_ancestors']}
        if any(ancestors.get(row['path']) != row['witness']
               for row in old_native['managed_ancestors']):
            raise ValueError('Profile managed ancestor changed during regeneration')
        leaves = {row['path']: row for row in body['leaves']}
        if (any(leaves.get(row['path']) != row for row in old_body['leaves'])
                or any(path not in current or current[path] != raw
                       for path, raw in old_current.items())):
            raise ValueError('Profile current managed bytes or native identity changed during regeneration')
        # Added requested paths may extend the fresh capture, but they cannot
        # change any exclusion used to render the initial managed selection.
        if (_current_paths_from_capture(*fresh[:4])
                != _current_paths_from_capture(*self._initial[:4])):
            raise ValueError('Profile current managed selection changed during regeneration')
        return fresh


def _completed_approval(root, body, raw):
    """Report exact historical completion; never authorize another mutation."""
    from . import v3_operation_history as history, v3_operation_context as contexts
    context = contexts.for_journal(body.get('next_journal_id'))
    captured = history.capture_completed_predecessor(root)
    if context.journal_id not in captured.context.prior_journal_ids:
        return None
    historical = captured.prefix.records.get(context.registration.PLAN)
    if historical is None or historical[0] != raw:
        raise ValueError('Historical approved plan bytes differ')
    terminal = next((item[1] for item in captured.prefix.terminals
                     if item[0] == context.journal_id), None)
    if terminal is None or terminal.body['outcome'] != 'committed':
        raise ValueError('Historical approved operation did not commit')
    from . import foreign_store_version as received
    gate = captured.binding.body.get(received.GATE_KEY)
    if gate is not None and context.journal_id <= gate['boundaries'][-1]['journal_id']:
        return {'status':'recorded_imported_committed','transaction_id':context.journal_id,
                'plan_sha256':_sha(raw),'receipt_id':body['next_receipt_id'],
                'completed_portable_head_sha256':body['prospective_head_sha256'],
                'detail':'Imported records describe commitment; original native execution was not observed'}
    return {'status': 'already_completed', 'transaction_id': context.journal_id,
            'plan_sha256': _sha(raw), 'receipt_id': body['next_receipt_id'],
            'completed_portable_head_sha256': body['prospective_head_sha256'],
            'detail': 'Exact approved operation previously committed; current files are not asserted unchanged'}


def build_profile_plan(root, requested_profile, preview_root, *, init_module, selected_version=True, lf_diagnostics=None):
    root = Path(root)
    owned_capture = _ProfilePreviewCapture(root)
    initial_portable = owned_capture.portable
    preview = init_module.regenerate_managed_init_preview(root, preview_root,
        manifest_snapshot=initial_portable, requested_profile=requested_profile,
        collect_source_modes=True, _profile_capture=owned_capture)
    inventory = preview['source_mode_inventory']
    inventory_sha, _inventory_raw = inventory.require_complete()
    rows = {row['destination']: dict(row) for row in inventory.rows}
    from .hook_activation import retain_generated_intent
    retain_generated_intent(initial_portable, rows)
    inventory_sha, _inventory_raw = pp.encode_mode_inventory([rows[path] for path in sorted(rows)])
    artifacts = {item.destination: item.artifact_bytes for item in inventory.source_artifacts}
    destinations = {path.as_posix(): output for path, output in preview['sources']}
    if len(destinations) != len(preview['sources']) or set(destinations) != set(rows) or set(rows) != set(artifacts):
        raise ValueError('Generated source/output authority coverage differs')
    requested = {}
    from .source_origins import SourceOrigins
    for path, output_path in destinations.items():
        if output_path != preview_root / path:
            raise ValueError('Generated output escaped exact external preview')
        output = SourceOrigins._bounded_bytes(output_path)
        source, row = artifacts[path], rows[path]
        if (row['source_sha256'] != _sha(source) or row['source_size_decimal'] != str(len(source)) or
                row['output_sha256'] != _sha(output) or row['output_size_decimal'] != str(len(output))):
            raise ValueError('Captured source/output changed after regeneration')
        requested[path] = {'source': source, 'output': output, 'executable': row['executable']}
    # Public callers report the current LF boundary before classification can
    # refuse byte or metadata drift. This callback supplies no plan authority.
    if lf_diagnostics is not None:
        lf_diagnostics(preview.get('lf_policy'))
    missing = set(initial_portable.entries) - set(requested)
    if missing and not selected_version:
        raise ValueError('Historical managed selection is not fully regenerated; removal authority is unsupported')
    pair, files, current, binding, state, witnesses, journals = owned_capture.capture_after_preview(
        root, tuple(sorted(requested)))
    policy = load_source_policy_snapshot(init_module.UPGRADE_SOURCE_POLICY_PATH)
    evidence = {'portable_files': files, 'current_bytes': current, 'requested': requested,
                'capture': pair.working_tree, 'predecessor_binding': binding, 'predecessor_store': state,
                'journal_ids': journals, 'predecessor_record_witnesses': witnesses,
                'operation': 'naos-upgrade-profile-transition', 'inputs': preview['effective_inputs'],
                'source_policy_id': policy.snapshot_id, 'source_policy': policy.policy,
                'public_review': {'requested_profile': requested_profile, 'checks': preview['checks'],
                                  'source_mode_inventory_sha256': inventory_sha}}
    if evidence['inputs'] != dict(pair.portable.inputs, profile=requested_profile):
        raise ValueError('Profile-independent preserved inputs changed')
    if selected_version:
        evidence['selection'] = {'schema': projection.SELECTION_SCHEMA,
            'selected_paths': sorted(requested), 'carry_forward_paths': sorted(missing)}
        plan = records.build_profile_review(**evidence)
    else:
        plan = records.build_operation_plan(**evidence)
    if type(plan) is records.ValidatedProfileNoop:
        return plan, evidence
    replay.build_bundle(plan, evidence)  # All new replay bounds before approval/publication.
    return plan, evidence


def plan_command(root, *, requested_profile, plan_out, cli, summary_only=False):
    with tempfile.TemporaryDirectory(prefix='naos-v3-reviewed-plan-', dir=cli._external_temp_root(root)) as temporary:
        plan, _evidence = build_profile_plan(root, requested_profile, Path(temporary) / 'preview', init_module=cli.naos_init,
            lf_diagnostics=lambda policy: cli._emit_lf_current_diagnostics(root, policy))
    if plan_out is not None:
        windows = cli.naos_init._windows_cli()
        if windows is not None:
            windows.publish_external_plan(root, plan_out, plan.body)
        else:
            cli._publish_external_plan(cli._external_plan_path(root, plan_out, must_exist=False), plan.raw)
    if summary_only:
        cli._emit_managed_init_summary(requested_profile=requested_profile,
            status='no_changes' if plan.body.get('status') == 'no_changes' else 'plan_only',
            plan_saved=plan_out is not None)
    else:
        emit_canonical_plan(plan.raw)
    return 0


def apply_command(root, *, plan_path, expected_digest, cli):
    from . import v3_j2_registration as registration, v3_publication_stage as staging
    from . import v3_j2_publication as publication, v3_j2_checkpoint as checkpoint
    windows = cli.naos_init._windows_cli()
    if windows is not None:
        body = windows.read_external_plan(root, plan_path)
        raw = canonical_bytes(body)
    else:
        body, raw = cli._read_external_plan(cli._external_plan_path(root, plan_path, must_exist=True))
    if _sha(raw) != expected_digest:
        raise ValueError('Exact raw approved v3 plan digest differs')
    if body.get('schema') not in (records.PUBLIC_PLAN_SCHEMA, records.SELECTED_PLAN_SCHEMA) or 'public_review' not in body:
        raise ValueError('Public apply requires an explicit reviewed operation plan')
    activation_review = body.get('operation') == 'naos-hook-activate'
    request_review = 'request' in body['public_review']
    if activation_review:
        records._public_review(body['public_review'], body['operation'], {})
        if body['schema'] != records.SELECTED_PLAN_SCHEMA:
            raise ValueError('Hook activation requires exact selected review')
    elif request_review:
        cli._require_add_checks(body['public_review'])
        # Validate the exact envelope before historical read-only recognition;
        # completed retries never consult the current renderer/catalogue.
        from . import v3_public_request
        request = records.decode_public_request(body['public_review']['request'])
        options = request.get('operation_inputs', {}).get('request', {})
        review_profile = options.get('profile')
        if options.get('kind') == 'skill' and 'host_routes' in options:
            route_binding = options['host_routes']
            review_profile = route_binding.get('profile') if type(route_binding) is dict else None
        # This is the claimed envelope profile, as for setup options above.
        # Current renderer/profile authority is reconstructed below before writes.
        records._public_review(body['public_review'], body.get('operation'), {'profile': review_profile})
        if body['schema'] != records.SELECTED_PLAN_SCHEMA or request['selected_paths'] != body['selection']['selected_paths']:
            raise ValueError('Public add/setup selected coverage differs')
    else:
        cli._require_upgrade_checks(body['public_review'])
        records._public_review(body['public_review'], body.get('operation'), {'profile': body['public_review']['requested_profile']})
    completed = _completed_approval(root, body, raw)
    if completed is not None:
        print(__import__('json').dumps(completed, sort_keys=True, separators=(',', ':')))
        return 0
    current_lf_policy = None
    def report_current_lf(policy):
        nonlocal current_lf_policy
        current_lf_policy = policy
        cli._emit_lf_current_diagnostics(root, policy)
    with tempfile.TemporaryDirectory(prefix='naos-v3-reviewed-apply-', dir=cli._external_temp_root(root)) as temporary:
        if activation_review:
            from .hook_activation import build_activation_plan
            review = body['public_review']['hook_activation']
            plan, evidence = build_activation_plan(root,
                approved_mode_octal=review['operator_selected_mode_octal'],
                expected_owner_sha256=body['owner_sha256'],
                expected_head_sha256=body['prior_portable_head_sha256'], init_module=cli.naos_init)
        elif request_review:
            try:
                from .. import naos_add as add_module
            except ImportError:
                import naos_add as add_module
            plan, evidence = v3_public_request.build_request_plan(
                root, body['operation'], request['operation_inputs'], request['selected_paths'],
                add_module=add_module)
        else:
            plan, evidence = build_profile_plan(root, body['public_review']['requested_profile'], Path(temporary) / 'preview', init_module=cli.naos_init, selected_version=body['schema'] == records.SELECTED_PLAN_SCHEMA,
                lf_diagnostics=report_current_lf)
    if type(plan) is records.ValidatedProfileNoop:
        raise ValueError('Read-only no-op review does not authorize apply')
    if plan.raw != raw:
        raise ValueError('Reviewed plan/checks/source bytes or native current capture changed')
    program = programs.build_publication_program(plan, evidence)
    arguments = dict(plan=plan, expected_plan_sha256=plan.sha256, plan_evidence=evidence,
                     program=program, expected_program_sha256=program.sha256)
    try:
        registration.register_j2_rebind_successor(root, plan=plan, expected_plan_sha256=plan.sha256, plan_evidence=evidence)
        staging.stage_j2_publication(root, **arguments)
        publication.prepare_j2_directories(root, **arguments)
        publication.publish_j2_destinations(root, **arguments)
        result = checkpoint.complete_j2_checkpoint(root, outcome='committed', **arguments)
        if not result.complete:
            raise ValueError('Public v3 terminal checkpoint did not complete')
    except (OSError, RuntimeError, ValueError) as exc:
        # Once registration is attempted, failure may have durable native effects.
        # The existing recovery path revalidates exact persisted state and policy.
        return cli._emit_apply_outcome(SimpleNamespace(
            status='recovery_required', transaction_id=program.body['journal_id'],
            receipt_path=None, detail='Mutation was attempted; run --recover to assess exact state: ' + str(exc)),
            expected_digest)
    if current_lf_policy is not None:
        cli._emit_lf_current_diagnostics(root, current_lf_policy)
    print(__import__('json').dumps({'status': 'committed', 'transaction_id': program.body['journal_id'],
          'plan_sha256': expected_digest, 'receipt_path': pp.receipt_path(program.body['receipt_sha256']) if 'receipt_sha256' in program.body else None}, sort_keys=True, separators=(',', ':')))
    return 0
