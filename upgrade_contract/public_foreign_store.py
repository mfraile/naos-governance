"""Public exact-approval adapter for an in-place completed-store receive."""
from __future__ import annotations

import json
import sys
from .plan_stdout import emit_canonical_plan
from . import foreign_store_native as native, foreign_store_records as records
from . import foreign_store_lifecycle as lifecycle

PLAN_SCHEMA = records.PLAN_SCHEMA


def inspect_command(root):
    with native.custody(root) as local:
        observed = native.observe(root, local)
        import_digest = records.record(observed.inventory).sha256
        old_native = observed.prefix.binding.body['observation']['native']
        now = observed.pair.working_tree.body['native']
        same = old_native == now
        moved = (old_native['platform']==now['platform']
                 and old_native['root_path']!=now['root_path']
                 and old_native['root_chain'][-1]['witness']==now['root_chain'][-1]['witness']
                 and old_native['control_directories']==now['control_directories'])
        # Classification is review context only. Identity survival does not
        # independently attest original execution or grant mutation authority.
        status=('currently_bound_completed' if same else 'completed_move_surviving_root_control_identities'
                if moved else 'completed_import_foreign_or_unobservable_native_identities')
        print(json.dumps({'status':status,
            'owner_sha256':observed.pair.portable.owner_sha256,
            'portable_head_sha256':observed.pair.portable.manifest_sha256,
            'import_inventory_sha256':import_digest,'journal_ids':list(observed.prefix.journal_ids),
            'claim_ceiling':records.CLAIM,'mutation_authorized':False},sort_keys=True,separators=(',',':')))
    return 0


def plan_command(root, *, expected_owner_sha256, expected_head_sha256,
                 expected_inventory_sha256, binding_id, plan_out, cli):
    with native.custody(root) as local:
        observed=native.observe(root,local)
        plan=records.build_plan(observed.pair.portable,observed.pair.working_tree,
            observed.prefix,observed.inventory,expected_owner_sha256=expected_owner_sha256,
            expected_head_sha256=expected_head_sha256,expected_inventory_sha256=expected_inventory_sha256,
            binding_id=binding_id)
    if plan_out is not None:
        windows=cli.naos_init._windows_cli()
        if windows is not None:
            windows.publish_external_plan(root,plan_out,plan.body)
        else:
            cli._publish_external_plan(cli._external_plan_path(root,plan_out,must_exist=False),plan.raw)
    emit_canonical_plan(plan.raw)
    print('PLAN_ONLY: explicit in-place completed-store receive; raw plan SHA-256 '+plan.sha256,file=sys.stderr)
    return 0


def approved_command(root, *, raw, expected_digest, recover=False):
    # Schema and caller-selected raw digest are checked before any native path.
    plan=records.load(raw,PLAN_SCHEMA)
    if plan.sha256!=expected_digest:
        raise ValueError('Exact external receiving approval differs')
    completed=lifecycle.completed_approval(root,plan,expected_digest)
    if completed is not None:
        print(json.dumps(completed,sort_keys=True,separators=(',',':')))
        return 0
    if recover:
        # Inspect failures remain NOT_APPLIED; exceptions from a subsequent
        # mutation must disclose preserved state and the same explicit approval.
        ids=tuple(row['id'] for row in plan.body['prior_journals']['entries'])+(plan.body['next_journal_id'],)
        with native.custody(root,journal_ids=ids,source_format=plan.body['legacy_source_format']) as local:
            lifecycle._inspect(root,local,plan,expected_digest)
    else:
        with native.custody(root) as local:
            observed=native.observe(root,local)
            records.validate_plan(raw,observed.pair.portable,observed.pair.working_tree,
                observed.prefix,observed.inventory,expected_digest=expected_digest)
    try:
        result=(lifecycle.recover(root,raw,expected_digest=expected_digest) if recover
                else lifecycle.apply(root,raw,expected_digest=expected_digest))
    except (OSError,RuntimeError,ValueError) as exc:
        print(json.dumps({'status':'recovery_required','plan_sha256':expected_digest,
            'detail':'Receiving mutation was attempted; preserve state and retry the exact external plan '
                     'with --recover --apply-plan FILE --expect-plan-digest '+expected_digest+': '+str(exc)},
            sort_keys=True,separators=(',',':')))
        return 3
    print(json.dumps(result,sort_keys=True,separators=(',',':')))
    return 0
