"""Explicit owned-hook activation review through the existing v3 coordinator.

Portable intent is replay-derived; native authority is separately held and bound
to an exact external plan. This adapter never sets mode or configures/runs Git.
"""
import copy
import hashlib

from .plan_stdout import emit_canonical_plan
from . import local_binding as lb, portable_provenance as pp
from .canonical import canonical_bytes

SCHEMA = 'naos.upgrade.hook_activation_review.v1'
PATH = '.githooks/pre-commit'

def _sha(raw):
    return hashlib.sha256(raw).hexdigest()

def build_review(*, platform, project_id, owner_sha256, head_sha256,
                 binding_sha256, state_sha256, capture_sha256, entry, base,
                 current, prior_witness, current_witness, approved_mode_octal,
                 proposed_source, source_mode_inventory_raw, source_mode_inventory_sha256):
    """Bind an explicit POSIX hook activation request to detached exact inputs.

    Root integration MUST obtain all these inputs from the same held, complete
    native/portable replay; this pure function cannot establish their origin.
    """
    if platform not in {'Darwin', 'Linux'}:
        raise ValueError('POSIX activation reconciliation only')
    if not pp._new_project_id(project_id):
        raise ValueError('Canonical portable project UUID required')
    for digest in (owner_sha256, head_sha256, binding_sha256, state_sha256,
                   capture_sha256, source_mode_inventory_sha256):
        lb._hex(digest, lb.HEX64, 'review dependency digest')
    if type(entry) is not dict or entry.get('path') != PATH:
        raise ValueError('Exact owned hook path required')
    if entry.get('ownership') != 'kit_owned_derived' or entry.get('creation_policy') != 'create':
        raise ValueError('Historical owned hook authority required')
    content = entry.get('content')
    if (type(content) is not dict or set(content) != {'kind', 'sha256', 'size_decimal', 'executable'}
            or content['kind'] != 'file' or content['executable'] is not False):
        raise ValueError('Only recorded nonexecutable hook activation is eligible')
    if type(base) is not bytes or type(current) is not bytes or current != base:
        raise ValueError('Adopter bytes or absent hook must remain preserved')
    if content['sha256'] != _sha(base) or content['size_decimal'] != str(len(base)):
        raise ValueError('Archived baseline binding differs')
    if type(proposed_source) is not bytes or proposed_source != base:
        raise ValueError('Activation review must retain exact archived hook bytes')
    body, inventory_digest = pp._decode_record(source_mode_inventory_raw,
        pp.MODE_INVENTORY_SCHEMA, {'schema', 'items'})
    modes = pp._mode_inventory(body)
    expected_row = {'destination': PATH, 'source_sha256': _sha(base),
        'source_size_decimal': str(len(base)), 'output_sha256': _sha(base),
        'output_size_decimal': str(len(base)), 'executable': True}
    if inventory_digest != source_mode_inventory_sha256 or modes != {PATH: expected_row}:
        raise ValueError('Exact one-hook executable-true source inventory differs')
    for witness in (prior_witness, current_witness):
        lb._validate_witness(witness, platform, 'file')
        if witness['presence'] != 'present':
            raise ValueError('Exact present native hook witnesses required')
    before = int(prior_witness['mode_octal'], 8)
    after = int(current_witness['mode_octal'], 8)
    if before & ~0o777 or after & ~0o777 or not after & 0o111:
        raise ValueError('Only non-special execute-bit activation is eligible')
    old, now = copy.deepcopy(prior_witness), copy.deepcopy(current_witness)
    old.pop('mode_octal')
    now.pop('mode_octal')
    if old != now or (before & ~0o111) != (after & ~0o111):
        raise ValueError('Non-execute mode, identity, owner or supported metadata conflict')
    if approved_mode_octal != current_witness['mode_octal']:
        raise ValueError('Operator-selected exact activation mode differs')
    body = {'schema': SCHEMA, 'path': PATH, 'platform': platform,
            'project_id': project_id, 'owner_sha256': owner_sha256,
            'portable_head_sha256': head_sha256, 'binding_sha256': binding_sha256,
            'state_sha256': state_sha256, 'capture_sha256': capture_sha256,
            'historical_entry': copy.deepcopy(entry),
            'prior_native_witness': copy.deepcopy(prior_witness),
            'current_native_witness': copy.deepcopy(current_witness),
            'operator_selected_mode_octal': approved_mode_octal,
            'source_sha256': _sha(proposed_source),
            'source_size_decimal': str(len(proposed_source)),
            'source_mode_inventory_sha256': source_mode_inventory_sha256,
            'requested_executable': True,
            'effect': 'explicit_activation_intent_reconciliation',
            'mutation_authorized': False}
    return canonical_bytes(body)

def verify_review(raw, expected_sha256, **inputs):
    if type(raw) is not bytes or _sha(raw) != expected_sha256:
        raise ValueError('Exact raw review digest differs')
    if raw != build_review(**inputs):
        raise ValueError('Current replay/capture/source differs from approved review')
    return True

OPERATION = 'naos-hook-activate'
REVIEW_KEYS = frozenset({'schema', 'path', 'platform', 'project_id', 'owner_sha256',
    'portable_head_sha256', 'binding_sha256', 'state_sha256', 'capture_sha256',
    'historical_entry', 'prior_native_witness', 'current_native_witness',
    'operator_selected_mode_octal', 'source_sha256', 'source_size_decimal',
    'source_mode_inventory_sha256', 'requested_executable', 'effect', 'mutation_authorized'})

def validate_public_review(value):
    if type(value) is not dict or set(value) != {'hook_activation'}:
        raise ValueError('Exact hook activation public review required')
    body = value['hook_activation']
    if type(body) is not dict or set(body) != REVIEW_KEYS:
        raise ValueError('Hook activation review fields differ')
    if (body['schema'] != SCHEMA or body['path'] != PATH
            or body['platform'] not in {'Darwin', 'Linux'}
            or body['requested_executable'] is not True
            or body['mutation_authorized'] is not False
            or body['effect'] != 'explicit_activation_intent_reconciliation'):
        raise ValueError('Hook activation review scope differs')
    if not pp._new_project_id(body['project_id']):
        raise ValueError('Hook activation project ID differs')
    for key in ('owner_sha256', 'portable_head_sha256', 'binding_sha256', 'state_sha256',
                'capture_sha256', 'source_sha256', 'source_mode_inventory_sha256'):
        lb._hex(body[key], lb.HEX64, 'hook activation digest')
    for key in ('prior_native_witness', 'current_native_witness'):
        lb._validate_witness(body[key], body['platform'], 'file')
    pp._entry(body['historical_entry'], PATH)

def validate_activation_receipt(receipt, inventory):
    if receipt['selected_paths'] != [PATH] or len(receipt['changes']) != 1:
        raise ValueError('Activation receipt must change only the owned hook')
    change = receipt['changes'][0]
    if type(change) is not dict or set(change) != {'path', 'before', 'after'} or change['path'] != PATH:
        raise ValueError('Activation receipt change differs')
    before, after = change['before'], change['after']
    pp._entry(before, PATH)
    pp._entry(after, PATH)
    if (before['ownership'] != 'kit_owned_derived' or before['creation_policy'] != 'create'
            or before['content'] is None or after['content'] is None
            or before['content']['executable'] is not False
            or after['content'] != dict(before['content'], executable=True)):
        raise ValueError('Activation receipt must retain exact owned hook bytes')
    content = after['content']
    expected = {'destination': PATH, 'source_sha256': content['sha256'],
        'output_sha256': content['sha256'], 'source_size_decimal': content['size_decimal'],
        'output_size_decimal': content['size_decimal'], 'executable': True}
    if inventory != {PATH: expected}:
        raise ValueError('Activation receipt must bind exact same-byte mode intent')

def retain_generated_intent(snapshot, rows):
    """Change one reviewed output mode only from completely replayed activation."""
    if type(snapshot) is not pp.ValidatedPortableSnapshot:
        raise ValueError('Validated portable activation history required')
    if PATH in snapshot.activated_hooks and PATH in rows:
        entry = snapshot.entries.get(PATH)
        if (entry is None or entry['ownership'] != 'kit_owned_derived'
                or entry['content'] is None or entry['content']['executable'] is not True):
            raise ValueError('Activated hook history is inconsistent')
        rows[PATH]['executable'] = True

def review_for_evidence(*, portable_files, current_bytes, requested, capture,
                        predecessor_binding, predecessor_store, approved_mode_octal):
    from .v3_operation_projection import _Reader
    snapshot = pp.load_portable_snapshot(_Reader(portable_files))
    entry = snapshot.entries.get(PATH)
    if entry is None or entry['content'] is None or set(requested) != {PATH}:
        raise ValueError('Exact historical owned hook selection required')
    base = portable_files[pp.base_path(entry['content']['sha256'])]
    if requested[PATH] != {'source': base, 'output': base, 'executable': True}:
        raise ValueError('Activation request must retain exact owned hook bytes')
    observed = capture.body
    prior = predecessor_binding.body['observation']
    before = {leaf['path']:leaf for leaf in prior['leaves']}[PATH]['metadata']
    now = {leaf['path']:leaf for leaf in observed['leaves']}[PATH]['metadata']
    digest, raw = pp.encode_mode_inventory([{'destination': PATH,
        'source_sha256': _sha(base), 'source_size_decimal': str(len(base)),
        'output_sha256': _sha(base), 'output_size_decimal': str(len(base)), 'executable': True}])
    review = build_review(platform=observed['native']['platform'], project_id=snapshot.project_id,
        owner_sha256=snapshot.owner_sha256, head_sha256=snapshot.manifest_sha256,
        binding_sha256=predecessor_binding.sha256, state_sha256=predecessor_store.sha256,
        capture_sha256=_sha(canonical_bytes(observed)), entry=entry, base=base,
        current=current_bytes[PATH], prior_witness=before, current_witness=now,
        approved_mode_octal=approved_mode_octal, proposed_source=base,
        source_mode_inventory_raw=raw, source_mode_inventory_sha256=digest)
    return {'hook_activation': pp._load_json(review, 'hook activation review')}

def checked_review(value, **evidence):
    validate_public_review(value)
    rebuilt = review_for_evidence(**evidence,
        approved_mode_octal=value['hook_activation']['operator_selected_mode_octal'])
    if canonical_bytes(rebuilt) != canonical_bytes(value):
        raise ValueError('Hook activation review differs from exact current replay/capture')
    return copy.deepcopy(value['hook_activation'])

def projection_eligible(review, path, prior, base, current, current_exec,
                        requested, requested_exec, native_status, host):
    validate_public_review({'hook_activation': review})
    if (path != PATH or host != 'posix' or prior != review['historical_entry']
            or base is None or current != base or requested != base
            or current_exec is not True or requested_exec is not True
            or native_status not in {'clear', 'metadata_drift'}
            or _sha(base) != review['source_sha256'] or str(len(base)) != review['source_size_decimal']):
        raise ValueError('Activation projection differs from scoped reviewed facts')
    return True

def build_activation_plan(root, *, approved_mode_octal, expected_owner_sha256,
                          expected_head_sha256, init_module):
    from . import v3_public_profile as profile, v3_operation_records as records
    from . import v3_operation_projection as projection, v3_durable_replay as replay
    from .planner import load_source_policy_snapshot
    pair, files, current, binding, state, witnesses, journals = profile._capture(root)
    if (pair.portable.owner_sha256 != expected_owner_sha256
            or pair.portable.manifest_sha256 != expected_head_sha256):
        raise ValueError('Independent hook activation owner/head expectation differs')
    entry = pair.portable.entries.get(PATH)
    if entry is None or entry['content'] is None:
        raise ValueError('Hook activation requires existing owned history')
    base = files[pp.base_path(entry['content']['sha256'])]
    requested = {PATH: {'source':base, 'output':base, 'executable':True}}
    policy = load_source_policy_snapshot(init_module.UPGRADE_SOURCE_POLICY_PATH)
    evidence = dict(portable_files=files, current_bytes=current, requested=requested,
        capture=pair.working_tree, predecessor_binding=binding, predecessor_store=state,
        journal_ids=journals, predecessor_record_witnesses=witnesses, operation=OPERATION,
        inputs=pair.portable.inputs, source_policy_id=policy.snapshot_id, source_policy=policy.policy,
        selection={'schema':projection.SELECTION_SCHEMA, 'selected_paths':[PATH],
                   'carry_forward_paths':sorted(set(pair.portable.entries)-{PATH})})
    evidence['public_review'] = review_for_evidence(**{key:evidence[key] for key in
        ('portable_files','current_bytes','requested','capture','predecessor_binding','predecessor_store')},
        approved_mode_octal=approved_mode_octal)
    plan = records.build_operation_plan(**evidence)
    replay.build_bundle(plan, evidence)
    return plan, evidence

def plan_command(root, *, plan_out, cli, **selection):
    plan, _ = build_activation_plan(root, init_module=cli.naos_init, **selection)
    if plan_out is not None:
        cli._publish_external_plan(cli._external_plan_path(root, plan_out, must_exist=False), plan.raw)
    emit_canonical_plan(plan.raw)
    return 0
