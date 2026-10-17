"""Exact local-only receiving records; historical execution is not attested.

This pure codec supplies no native proof or approval. The native lifecycle must
reobserve the entire selected inventory and receive an independent raw digest.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
from types import SimpleNamespace

from .canonical import canonical_bytes
from . import local_binding as lb, local_store as ls, portable_provenance as pp
from . import foreign_store_version as version
from .working_tree_capture import build_capture

PLAN_SCHEMA = 'naos.upgrade.foreign_store_receiving_plan.v1'
INTENT_SCHEMA = 'naos.upgrade.foreign_store_receiving_intent.v1'
COMMIT_SCHEMA = 'naos.upgrade.foreign_store_receiving_preparation.v1'
PROGRESS_SCHEMA = 'naos.upgrade.foreign_store_receiving_progress.v1'
TERMINAL_SCHEMA = 'naos.upgrade.foreign_store_receiving_terminal.v1'
INVENTORY_SCHEMA = 'naos.upgrade.foreign_store_receiving_inventory.v1'
CLAIM = 'recorded_imported_terminal_history;original_native_execution_unobserved'
PHASES = ('prepared', 'state_retain_pending', 'state_retained', 'register_pending',
          'registered', 'binding_retain_pending', 'binding_retained',
          'binding_publish_pending', 'binding_published', 'active_retain_pending',
          'active_retained', 'final_state_pending', 'final_state_published',
          'terminal_pending', 'finalized')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class Record:
    raw: bytes
    sha256: str

    @property
    def body(self):
        return pp._load_json(self.raw, 'receiving record')


def record(body):
    lb._bounded_input(body)
    raw = canonical_bytes(body)
    if len(raw) > lb.MAX_RECORD_BYTES:
        raise ValueError('Receiving record exceeds existing private record limit')
    return Record(raw, sha(raw))


def load(raw, schema):
    if type(raw) is not bytes or len(raw) > lb.MAX_RECORD_BYTES:
        raise ValueError('Missing or oversized receiving record')
    body=pp._load_json(raw,'receiving record')
    if type(body) is not dict:
        raise ValueError('Receiving record is not a typed object')
    value = record(body)
    if value.raw != raw or value.body.get('schema') != schema:
        raise ValueError('Wrong or noncanonical receiving record schema')
    if schema==PLAN_SCHEMA:
        lb._fields(body,{'schema','minimum_reader','variant','claim_ceiling','project_id','owner_sha256',
            'portable_head_sha256','binding_id','next_journal_id','prior_journals','old_binding_sha256',
            'old_state_sha256','import_inventory_sha256','import_inventory','initial_capture',
            'legacy_source_format','retention_paths'},'receiving plan')
        if (body['minimum_reader']!=version.MINIMUM_READER or body['variant']!='in_place_completed_store_receiving'
                or body['claim_ceiling']!=CLAIM or not pp._new_project_id(body['project_id'])):
            raise ValueError('Unsupported receiving plan policy')
        for key in ('owner_sha256','portable_head_sha256','old_binding_sha256','old_state_sha256','import_inventory_sha256'):
            lb._hex(body[key],lb.HEX64,'receiving plan digest')
        lb._hex(body['binding_id'],lb.BINDING_ID,'receiving fresh binding ID')
        lb._validate_journals(body['prior_journals'])
        if body['next_journal_id']!=f"J{len(body['prior_journals']['entries'])+1:08d}":
            raise ValueError('Receiving journal is not next in exact prefix')
        p=paths(body['next_journal_id'])
        if body['retention_paths']!={'binding':p.OLD_BINDING,'state':p.OLD_STATE}:
            raise ValueError('Receiving retained locations differ from fixed operation paths')
        from .legacy_migration_records import POSIX_MANAGED_V1,WINDOWS_CONTENT_V1
        if body['legacy_source_format'] not in (None,POSIX_MANAGED_V1,WINDOWS_CONTENT_V1):
            raise ValueError('Unsupported receiving migration origin')
        capture=build_capture(body['initial_capture']['native'],body['initial_capture']['leaves'])
        validate_inventory(body['import_inventory'],capture.body['native']['platform'])
        if record(body['import_inventory']).sha256!=body['import_inventory_sha256']:
            raise ValueError('Receiving inventory differs from exact selected digest')
    elif schema==INTENT_SCHEMA:
        lb._fields(body,{'schema','plan_sha256','journal_id','import_inventory_sha256','claim_ceiling','storage_witnesses'},'receiving intent')
        lb._fields(body['storage_witnesses'],{'journal','lock'},'receiving intent storage')
    elif schema==COMMIT_SCHEMA:
        lb._fields(body,{'schema','plan_sha256','intent_sha256','directories','files'},'receiving preparation')
        if type(body['directories']) is not dict or type(body['files']) is not dict:
            raise ValueError('Receiving preparation inventories are malformed')
    return value


def paths(journal_id):
    from . import v3_operation_context as contexts
    c = contexts.for_journal(journal_id)
    p = c.registration
    j = p.J2
    return SimpleNamespace(ROOT=p.ROOT, JOURNALS=p.JOURNALS, JOURNAL=j,
        PLAN=p.PLAN, INTENT=p.INTENT, COMMITMENT=j + '/receiving.json',
        PROGRESS=p.PROGRESS, STATE=p.STATE, BINDING=p.BINDING,
        OLD_STATE=p.BACKUP, OLD_BINDING=c.checkpoint.OLD_BINDING,
        ACTIVE_STATE=c.checkpoint.OLD_STATE, CHECKPOINT=c.checkpoint.CHECKPOINT,
        REGISTERED=p.STAGE, BINDING_STAGE=c.checkpoint.BINDING_STAGE,
        STATE_STAGE=c.checkpoint.STATE_STAGE, TERMINAL_STAGE=c.checkpoint.TERMINAL_STAGE,
        TERMINAL=c.checkpoint.TERMINAL)


def control_path(value):
    from .security import safe_relative_path
    if type(value) is not str or not value.startswith('.naos/'):
        raise ValueError('Receiving control path is outside its fixed namespace')
    safe_relative_path(value[len('.naos/'):])
    if not (value == '.naos/upgrade-v1' or value.startswith('.naos/upgrade-v1/')
            or value == '.naos/local/managed-content-v3'
            or value.startswith('.naos/local/managed-content-v3/')):
        raise ValueError('Receiving control path is outside selected store/source roles')
    return value


def validate_inventory(body, platform):
    lb._fields(body, {'schema', 'files', 'directories', 'legacy_absence'}, 'receiving inventory')
    if body['schema'] != INVENTORY_SCHEMA or type(body['files']) is not list or type(body['directories']) is not list:
        raise ValueError('Unsupported receiving inventory')
    names = []
    for row in body['files']:
        lb._fields(row, {'path', 'metadata', 'content'}, 'receiving file observation')
        control_path(row['path'])
        lb._validate_witness(row['metadata'], platform, 'file')
        if row['metadata']['presence'] != 'present':
            raise ValueError('Receiving inventory file is absent')
        lb._fields(row['content'], {'sha256', 'size_decimal'}, 'receiving file content')
        lb._hex(row['content']['sha256'], lb.HEX64, 'receiving file digest')
        lb._u64(row['content']['size_decimal'], 'receiving file size')
        names.append(row['path'])
    lb._sorted_unique(names, 'receiving file paths')
    directories = []
    for row in body['directories']:
        lb._fields(row, {'path', 'witness', 'children'}, 'receiving directory inventory')
        control_path(row['path'])
        lb._validate_witness(row['witness'], platform, 'directory')
        if row['witness']['presence'] != 'present' or type(row['children']) is not list:
            raise ValueError('Receiving directory inventory is absent/malformed')
        lb._sorted_unique(row['children'], 'receiving directory children')
        for name in row['children']:
            lb._portable_path(name)
            if '/' in name:
                raise ValueError('Receiving child is not one path component')
        directories.append(row['path'])
    lb._sorted_unique(directories, 'receiving directory paths')
    if set(names) & set(directories):
        raise ValueError('Receiving inventory aliases a file and directory')
    # Absence is observed independently of the selected migration source scope.
    if type(body['legacy_absence']) is not list:
        raise ValueError('Receiving competing-source absence inventory is malformed')
    for row in body['legacy_absence']:
        lb._fields(row, {'path', 'witness'}, 'competing legacy absence')
        control_path(row['path'])
        lb._validate_witness(row['witness'], platform, 'directory')
        if row['witness']['presence'] != 'absent':
            raise ValueError('Competing legacy state is present')
    return body


def build_plan(portable, capture, prefix, inventory, *, expected_owner_sha256,
               expected_head_sha256, expected_inventory_sha256, binding_id):
    for digest in (expected_owner_sha256, expected_head_sha256, expected_inventory_sha256):
        lb._hex(digest, lb.HEX64, 'independent receiving expectation')
    lb._hex(binding_id, lb.BINDING_ID, 'fresh receiving binding ID')
    current = build_capture(capture.body['native'], capture.body['leaves'])
    validate_inventory(inventory, current.body['native']['platform'])
    imported = record(inventory)
    if (portable.owner_sha256 != expected_owner_sha256 or portable.manifest_sha256 != expected_head_sha256
            or imported.sha256 != expected_inventory_sha256):
        raise ValueError('Independent receiving expectation differs from actual evidence')
    old_b, old_s = prefix.binding, prefix.state
    if (old_s.body['active_journal_id'] is not None or old_s.body['archives']
            or old_b.body['binding_id'] == binding_id
            or old_b.body['portable_head_sha256'] != portable.manifest_sha256
            or old_b.body['owner_sha256'] != portable.owner_sha256):
        raise ValueError('Receiving requires a complete bound prefix and a fresh binding ID')
    ids = prefix.journal_ids
    if len(ids) >= lb.MAX_JOURNALS:
        raise ValueError('Receiving would exceed existing journal bound')
    next_id = f'J{len(ids) + 1:08d}'
    return record({'schema': PLAN_SCHEMA, 'minimum_reader': version.MINIMUM_READER,
        'variant': 'in_place_completed_store_receiving', 'claim_ceiling': CLAIM,
        'project_id': portable.project_id, 'owner_sha256': portable.owner_sha256,
        'portable_head_sha256': portable.manifest_sha256, 'binding_id': binding_id,
        'next_journal_id': next_id, 'prior_journals': old_s.body['journals'],
        'old_binding_sha256': old_b.sha256, 'old_state_sha256': old_s.sha256,
        'import_inventory_sha256': imported.sha256, 'import_inventory': inventory,
        'initial_capture': current.body,
        'legacy_source_format': (None if prefix.migration_candidate is None else
                                  prefix.migration_candidate.plan.body['source_format']),
        'retention_paths': {'binding': paths(next_id).OLD_BINDING, 'state': paths(next_id).OLD_STATE}})


def validate_plan(raw, portable, capture, prefix, inventory, *, expected_digest):
    selected = load(raw, PLAN_SCHEMA)
    if selected.sha256 != expected_digest:
        raise ValueError('Exact independent approved receiving plan digest differs')
    body = selected.body
    expected = build_plan(portable, capture, prefix, inventory,
        expected_owner_sha256=body['owner_sha256'], expected_head_sha256=body['portable_head_sha256'],
        expected_inventory_sha256=body['import_inventory_sha256'], binding_id=body['binding_id'])
    if selected != expected:
        raise ValueError('Receiving plan differs from complete current evidence')
    return selected


def build_intent(plan, *, journal_witness, lock_witness):
    p = plan.body
    platform = p['initial_capture']['native']['platform']
    for witness, kind in ((journal_witness, 'directory'), (lock_witness, 'file')):
        lb._validate_witness(witness, platform, kind)
        if witness['presence'] != 'present':
            raise ValueError('Receiving preparation native object is absent')
    return record({'schema': INTENT_SCHEMA, 'plan_sha256': plan.sha256,
        'journal_id': p['next_journal_id'], 'import_inventory_sha256': p['import_inventory_sha256'],
        'claim_ceiling': CLAIM, 'storage_witnesses': {'journal': journal_witness, 'lock': lock_witness}})


def checkpoints(plan, intent, old_binding, old_state):
    p = plan.body
    if (old_binding.sha256 != p['old_binding_sha256'] or old_state.sha256 != p['old_state_sha256']
            or intent.body['plan_sha256'] != plan.sha256):
        raise ValueError('Receiving checkpoint predecessor/intent differs')
    journals = deepcopy(p['prior_journals'])
    journals['head_id'] = p['next_journal_id']
    journals['entries'].append({'id': p['next_journal_id'], 'sha256': intent.sha256})
    gate = version.extend_gate(old_binding, old_state, journal_id=p['next_journal_id'],
                               intent_sha256=intent.sha256, inventory_sha256=p['import_inventory_sha256'])
    observation = {'schema': lb.OBSERVATION_SCHEMA, 'native': p['initial_capture']['native'],
        'leaves': p['initial_capture']['leaves'], 'journals': journals,
        'transaction_state': 'quiescent', 'binding_id': p['binding_id'], 'diagnostic_python_minor': None}
    binding = lb.load_local_binding(lb.encode_local_binding({'schema': version.BINDING_SCHEMA,
        'project_id': p['project_id'], 'owner_sha256': p['owner_sha256'],
        'portable_head_sha256': p['portable_head_sha256'], 'binding_id': p['binding_id'],
        'observation': observation, version.GATE_KEY: gate}))
    active = ls.load_local_store(ls.encode_local_store({**old_state.body,
        'schema': version.STORE_SCHEMA, 'generation': old_state.body['generation'] + 1,
        'journals': journals, 'active_journal_id': p['next_journal_id'], version.GATE_KEY: gate}))
    state = ls.load_local_store(ls.encode_local_store({**active.body,
        'binding_id': p['binding_id'], 'binding_sha256': binding.sha256, 'active_journal_id': None}))
    return active, binding, state


def progress_records(plan, intent, binding, state):
    chain = []
    for index, phase in enumerate(PHASES):
        chain.append(record({'schema': PROGRESS_SCHEMA, 'journal_id': plan.body['next_journal_id'],
            'plan_sha256': plan.sha256, 'intent_sha256': intent.sha256,
            'revision_decimal': str(index), 'previous_sha256': None if not chain else chain[-1].sha256,
            'phase': phase, 'binding_after_sha256': binding.sha256, 'state_after_sha256': state.sha256}))
    return tuple(chain)


def terminal(plan, intent, binding, state, progress):
    return record({'schema': TERMINAL_SCHEMA, 'intent_sha256': intent.sha256, 'outcome': 'received',
        'progress_sha256': progress.sha256, 'binding_after_sha256': binding.sha256,
        'portable_head_sha256': plan.body['portable_head_sha256'], 'state_after_sha256': state.sha256,
        'plan_sha256': plan.sha256, 'import_inventory_sha256': plan.body['import_inventory_sha256'],
        'claim_ceiling': CLAIM})


def validate_terminal(body):
    keys = {'schema', 'intent_sha256', 'outcome', 'progress_sha256', 'binding_after_sha256',
            'portable_head_sha256', 'state_after_sha256', 'plan_sha256', 'import_inventory_sha256', 'claim_ceiling'}
    lb._fields(body, keys, 'receiving terminal')
    if body['schema'] != TERMINAL_SCHEMA or body['outcome'] != 'received' or body['claim_ceiling'] != CLAIM:
        raise ValueError('Unsupported receiving terminal claim')
    for key in keys - {'schema', 'outcome', 'claim_ceiling'}:
        lb._hex(body[key], lb.HEX64, 'receiving terminal digest')
