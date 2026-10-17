"""Exact public add/setup review over completed bound portable history.

Reuse the public publication/replay lifecycle; this adapter never enrolls a root.
"""
from __future__ import annotations

from .plan_stdout import emit_canonical_plan

import hashlib
from pathlib import Path

from . import v3_public_profile as profile
from . import v3_operation_records as records, v3_operation_projection as projection
from . import v3_durable_replay as replay
from .canonical import canonical_sha256, canonical_bytes
from .planner import load_source_policy_snapshot
from .source_origins import SourceOrigins


def build_request_plan(root, operation, operation_inputs, selected_paths, *, add_module):
    root = Path(root)
    initial, *_ = profile._capture(root)
    request = {'operation': operation, 'operation_inputs': operation_inputs,
               'selected_paths': selected_paths}
    # This is the existing renderer: canonical catalogue, activation gates,
    # template context, source identity, and explicit module/profile options.
    with add_module.regenerate_managed_request(root, request, collect_source_modes=True,
                                               portable_request=True) as preview:
        inventory = preview['source_mode_inventory']
        inventory_sha, _ = inventory.require_complete()
        rows = {row['destination']: dict(row) for row in inventory.rows}
        from .hook_activation import retain_generated_intent
        retain_generated_intent(initial.portable, rows)
        inventory_sha, _ = profile.pp.encode_mode_inventory([rows[path] for path in sorted(rows)])
        artifacts = {item.destination: item.artifact_bytes for item in inventory.source_artifacts}
        sources = {path.as_posix(): output for path, output in preview['sources']}
        if len(sources) != len(preview['sources']) or set(sources) != set(rows) or set(rows) != set(artifacts):
            raise ValueError('Generated add source/output authority coverage differs')
        requested = {}
        for path, output_path in sources.items():
            output = SourceOrigins._bounded_bytes(output_path)
            source, row = artifacts[path], rows[path]
            if (row['source_sha256'] != hashlib.sha256(source).hexdigest() or
                    row['source_size_decimal'] != str(len(source)) or
                    row['output_sha256'] != hashlib.sha256(output).hexdigest() or
                    row['output_size_decimal'] != str(len(output))):
                raise ValueError('Captured add source/output changed after regeneration')
            requested[path] = {'source': source, 'output': output, 'executable': row['executable']}
        checks = preview['checks']
    pair, files, current, binding, state, witnesses, journals = profile._capture(root, tuple(sorted(requested)))
    if pair.portable != initial.portable:
        raise ValueError('Portable inputs changed during add regeneration')
    policy = load_source_policy_snapshot(add_module.UPGRADE_SOURCE_POLICY_PATH)
    evidence = {'portable_files': files, 'current_bytes': current, 'requested': requested,
                'capture': pair.working_tree, 'predecessor_binding': binding,
                'predecessor_store': state, 'journal_ids': journals,
                'predecessor_record_witnesses': witnesses, 'operation': operation,
                'inputs': dict(pair.portable.inputs), 'source_policy_id': policy.snapshot_id,
                'source_policy': policy.policy,
                'public_review': {'request': {'schema': 'naos.add.review_request.v1',
                                            'canonical_json': canonical_bytes(request).decode('utf-8')}, 'checks': checks,
                                  'source_mode_inventory_sha256': inventory_sha},
                'selection': {'schema': projection.SELECTION_SCHEMA,
                              'selected_paths': sorted(requested),
                              'carry_forward_paths': sorted(set(pair.portable.entries) - set(requested))}}
    plan = records.build_profile_review(**evidence)
    if type(plan) is not records.ValidatedProfileNoop:
        replay.build_bundle(plan, evidence)
    return plan, evidence


def plan_command(root, *, operation, request_inputs, sources, plan_out, cli,
                 add_module, preapply_revalidator=None, applicability=None):
    # Classify/capture before touching request sources: torn, foreign and absent
    # local storage cannot be turned into legacy or fresh enrollment.
    if applicability is not None:
        applicability.select_route("portable_v3")
    profile._capture(root)
    add_module._validate_no_overlapping_destinations([path for path, _ in sources])
    if preapply_revalidator is not None:
        preapply_revalidator()
    request_sha = canonical_sha256({'schema': 'naos.add.managed_request.v1',
        'operation': operation, 'inputs': request_inputs,
        'sources': add_module._managed_request_inventory(sources)})
    operation_inputs = {'schema': 'naos.add.operation_inputs.v1',
                        'request_sha256': request_sha, 'request': request_inputs}
    plan, _ = build_request_plan(root, operation, operation_inputs,
                                sorted(path.as_posix() for path, _ in sources), add_module=add_module)
    if preapply_revalidator is not None:
        preapply_revalidator()
    if plan_out is not None:
        windows = add_module._windows_cli()
        if windows is not None:
            windows.publish_external_plan(root, plan_out, plan.body)
        else:
            cli._publish_external_plan(cli._external_plan_path(root, plan_out, must_exist=False), plan.raw)
    if applicability is not None:
        noop = type(plan) is records.ValidatedProfileNoop
        applicability.record("noop" if noop else "ready", "validated_no_changes" if noop else "validated_review_only", execution_route="none" if noop else "external_reviewed_plan_apply", direct_add_allowed=False, request_sha256=request_sha, plan_status=plan.body.get("status"), plan_sha256=plan.sha256)
    emit_canonical_plan(plan.raw)
    return 0
