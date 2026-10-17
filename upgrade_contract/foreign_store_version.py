"""Strict persistent reader gate for explicitly received recorded history.

Older exact v1 codecs reject these schemas. A gate names ordered receiving
boundaries; it does not attest original-host execution or authorize mutation.
"""
from __future__ import annotations

from copy import deepcopy

BINDING_SCHEMA = 'naos.upgrade.local_binding.v2'
STORE_SCHEMA = 'naos.upgrade.local_store.v2'
GATE_SCHEMA = 'naos.upgrade.receiving_history_gate.v1'
MINIMUM_READER = 'foreign_completed_store_receiving_v1'
GATE_KEY = 'receiving_history'


def validate_gate(value, journals):
    from . import local_binding as lb
    lb._fields(value, {'schema', 'minimum_reader', 'boundaries'}, 'receiving history gate')
    if value['schema'] != GATE_SCHEMA or value['minimum_reader'] != MINIMUM_READER:
        raise ValueError('Unsupported receiving history reader gate')
    rows = value['boundaries']
    if type(rows) is not list or not 1 <= len(rows) <= lb.MAX_JOURNALS:
        raise ValueError('Receiving history gate has invalid boundary count')
    entries = {row['id']: row['sha256'] for row in journals['entries']}
    previous = ''
    for row in rows:
        lb._fields(row, {'journal_id', 'intent_sha256', 'import_inventory_sha256'}, 'receiving boundary reference')
        jid = lb._hex(row['journal_id'], lb.JOURNAL_ID, 'receiving journal ID')
        if jid == 'J00000001' or jid <= previous or entries.get(jid) != row['intent_sha256']:
            raise ValueError('Receiving boundary is outside exact ordered journal prefix')
        lb._hex(row['intent_sha256'], lb.HEX64, 'receiving intent digest')
        lb._hex(row['import_inventory_sha256'], lb.HEX64, 'imported complete evidence digest')
        previous = jid
    return value


def validate_binding(body):
    from . import local_binding as lb
    keys = {'schema', 'project_id', 'owner_sha256', 'portable_head_sha256', 'binding_id', 'observation', GATE_KEY}
    lb._fields(body, keys, 'received local binding')
    if body['schema'] != BINDING_SCHEMA:
        raise ValueError('Wrong received binding schema')
    core = {key: deepcopy(value) for key, value in body.items() if key != GATE_KEY}
    core['schema'] = lb.BINDING_SCHEMA
    # Pure core validation, without changing any stored record or witness.
    lb._validate_binding(core)
    validate_gate(body[GATE_KEY], body['observation']['journals'])
    return body


def validate_store(body):
    from . import local_store as ls
    from . import local_binding as lb
    lb._fields(body, ls._STORE_KEYS | {GATE_KEY}, 'received local store')
    if body['schema'] != STORE_SCHEMA:
        raise ValueError('Wrong received state schema')
    core = {key: deepcopy(value) for key, value in body.items() if key != GATE_KEY}
    core['schema'] = ls.STORE_SCHEMA
    ls._validate_store(core)
    validate_gate(body[GATE_KEY], body['journals'])


def inherited_gate(binding, state):
    """Validate and retain the same typed gate; never downgrade one side."""
    b, s = binding.body, state.body
    gated = b.get('schema') == BINDING_SCHEMA or s.get('schema') == STORE_SCHEMA
    if not gated:
        if GATE_KEY in b or GATE_KEY in s:
            raise ValueError('Unknown receiving gate on legacy record')
        return None
    if b.get('schema') != BINDING_SCHEMA or s.get('schema') != STORE_SCHEMA:
        raise ValueError('Received checkpoint requires matching versioned binding/state')
    validate_binding(b)
    validate_store(s)
    if b[GATE_KEY] != s[GATE_KEY]:
        raise ValueError('Receiving gate differs between binding and state')
    return deepcopy(b[GATE_KEY])


def extend_gate(binding, state, *, journal_id, intent_sha256, inventory_sha256):
    gate = inherited_gate(binding, state)
    if gate is None:
        gate = {'schema': GATE_SCHEMA, 'minimum_reader': MINIMUM_READER, 'boundaries': []}
    gate['boundaries'].append({'journal_id': journal_id, 'intent_sha256': intent_sha256,
                              'import_inventory_sha256': inventory_sha256})
    return gate
