"""Full public body identifiers; no authentication or scanner exemptions."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import naos_audit_log as audit
from naos_systemic_family_review import _audit_output_shape


def independent_id(event, domain='naos.audit_log_event.public_id.v1'):
    body = {k: v for k, v in event.items() if k != 'event_id'}
    raw = json.dumps({'domain': domain, 'event': body}, sort_keys=True,
                     separators=(',', ':')).encode('utf-8')
    return 'audit-sha256-' + hashlib.sha256(raw).hexdigest()


class AuditPublicIdTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / 'naos').mkdir()

    def event(self, **kwargs):
        args = dict(root=self.root, naos_root='naos', policy={}, profile='standard',
                    event_type='session_started', session_id='fixture-session',
                    generated_at='2026-10-09T12:00:00Z',
                    generated_by={'operator_id': 'fixture-operator', 'operator_source': 'fixture'},
                    source_report={'schema': 'naos.session_identity.v1', 'status': 'session_created',
                                   'summary': {}, 'findings': [], 'human_review_required': True})
        args.update(kwargs)
        return audit.build_audit_event(**args)

    def test_full_hash_independently_derived_from_exact_sanitized_body(self):
        with mock.patch.object(audit.uuid, 'uuid4', return_value=mock.Mock(int=123)):
            event = self.event()
        self.assertEqual(event['event_nonce'], '123')
        self.assertEqual(event['event_id'], independent_id(event))
        self.assertRegex(event['event_id'], '^audit-sha256-[0-9a-f]{64}$')
        self.assertEqual(audit.recompute_public_audit_event_id(event), event['event_id'])
        self.assertEqual(audit.validate_audit_event(event), [])

    def test_build_calls_preserve_distinct_occurrences_and_fixed_nonce_is_deterministic(self):
        first, second = self.event(), self.event()
        self.assertNotEqual(first['event_nonce'], second['event_nonce'])
        self.assertNotEqual(first['event_id'], second['event_id'])
        with mock.patch.object(audit.uuid, 'uuid4', return_value=mock.Mock(int=123)):
            self.assertEqual(self.event(), self.event())

    def test_no_clock_filesystem_or_randomness_needed_for_public_check(self):
        event = self.event()
        before = copy.deepcopy(event)
        with mock.patch.object(audit.uuid, 'uuid4', side_effect=AssertionError('randomness')), \
                mock.patch.object(audit, 'utc_now_text', side_effect=AssertionError('clock')), \
                mock.patch.object(Path, 'read_text', side_effect=AssertionError('filesystem')):
            self.assertEqual(audit.recompute_public_audit_event_id(event), event['event_id'])
        self.assertEqual(event, before)

    def test_every_body_field_is_bound_and_legacy_or_fabricated_ids_do_not_recognize(self):
        event = self.event()
        for key in event:
            if key == 'event_id':
                continue
            altered = copy.deepcopy(event)
            value = altered[key]
            altered[key] = ({**value, 'tampered': True} if type(value) is dict else
                            value + ['tampered'] if type(value) is list else
                            value + '-tampered' if type(value) is str else 'tampered')
            with self.subTest(key=key):
                self.assertIsNone(audit.recompute_public_audit_event_id(altered))
        for label in ['audit-20261009T120000Z-abcdef123456', 'audit-sha256-' + 'a' * 64,
                      'AUDIT-SHA256-' + 'a' * 64, 'ghp_' + 'aB2cD3eF4gH5iJ6k']:
            altered = {**event, 'event_id': label}
            self.assertIsNone(audit.recompute_public_audit_event_id(altered))

    def test_wrong_domain_unknown_extra_missing_and_wrong_primitive_types_refuse(self):
        event = self.event()
        variants = [
            {**event, 'event_id': independent_id(event, domain='other-public-domain')},
            {**event, 'event_id_scheme': 'other-public-domain'},
            {**event, 'event_type': 'unknown'}, {**event, 'event_type': 'fabricated_event'},
            {**event, 'authored_extra': 'unrecognized'}, {k: v for k,v in event.items() if k != 'session_id'},
            {**event, 'event_payload_hash': 'b' * 64}, {**event, 'profile': 'unsupported'},
            {**event, 'session_id': 12}, {**event, 'human_review_required': 1},
            {**event, 'event_payload_summary': {'not-json': object()}},
            {**event, 'event_payload_summary': {'not-finite': float('nan')}},
            {**event, 'event_payload_summary': {1: 'not-string-key'}},
        ]
        for altered in variants:
            if altered.get('event_type') in {'unknown','fabricated_event'} or 'authored_extra' in altered:
                altered['event_id'] = independent_id(altered)
            self.assertIsNone(audit.recompute_public_audit_event_id(altered))

    def test_nonce_is_canonical_ascii_decimal_text_and_bounded(self):
        event = self.event()
        for value in [0, '', '00', '0123', '-1', '+1', '1.0', '1e10', '١٢٣', '１２３',
                      str(2 ** 128), '9' * 400, 'abc123']:
            altered = {**event, 'event_nonce': value}
            altered['event_id'] = independent_id(altered)
            with self.subTest(value=value):
                self.assertIsNone(audit.recompute_public_audit_event_id(altered))
        for value in ['0', str(2 ** 128 - 1)]:
            altered = {**event, 'event_nonce': value}
            altered['event_id'] = independent_id(altered)
            self.assertEqual(audit.recompute_public_audit_event_id(altered), altered['event_id'])

    def test_new_invalid_id_blocks_reader_but_old_valid_id_is_unchanged(self):
        event = self.event()
        invalid = {**event, 'event_id': 'audit-sha256-' + '0' * 64}
        self.assertTrue(any(f['id'] == 'audit_log_event.invalid_public_event_id'
                            for f in audit.validate_audit_event(invalid)))
        legacy = {k: v for k,v in event.items() if k not in {'event_nonce','event_id_scheme'}}
        legacy['event_id'] = 'audit-20261009T120000Z-abcdef123456'
        path = self.root / 'legacy.jsonl'
        raw = json.dumps(legacy) + '\n'
        path.write_text(raw)
        loaded, findings = audit.load_event_file(path)
        self.assertEqual(loaded, [legacy])
        self.assertEqual(findings, [])
        self.assertEqual(path.read_text(), raw)
        self.assertIsNone(audit.recompute_public_audit_event_id(legacy))
        # The legacy contract accepts opaque IDs, even a custom full-hash-like
        # label. Removing the new fields restores only legacy reading; it can
        # never supply a recognized public ID to the entropy consumer.
        legacy['event_id'] = event['event_id']
        self.assertEqual(audit.validate_audit_event(legacy), [])
        self.assertIsNone(audit.recompute_public_audit_event_id(legacy))

    def test_unknown_events_keep_existing_reader_behavior_without_public_recognition(self):
        event = self.event(event_type='unsupported_event')
        self.assertEqual(event['event_type'], 'unknown')
        self.assertEqual(audit.validate_audit_event(event), [])
        self.assertIsNone(audit.recompute_public_audit_event_id(event))

    def test_payload_sanitization_happens_before_both_hashes(self):
        secret = 'ghp_' + 'aB2cD3eF4gH5iJ6k'
        event = self.event(session_id=secret, generated_by={'operator_id': secret},
                           source_report={'schema': 'naos.session_identity.v1', 'summary': {'note': secret}})
        self.assertNotIn(secret, json.dumps(event))
        self.assertEqual(event['event_payload_hash'], audit.hash_json(event['event_payload_summary']))
        self.assertEqual(event['event_id'], independent_id(event))
        self.assertEqual(audit.recompute_public_audit_event_id(event), event['event_id'])

    def test_public_nonce_does_not_change_existing_entropy_candidate_predicate(self):
        event = self.event()
        self.assertTrue(event['event_nonce'].isascii())
        self.assertTrue(event['event_nonce'].isdecimal())
        self.assertNotRegex(event['event_nonce'], '[A-Za-z]')

    def test_collision_retry_reissues_nonce_binds_new_id_and_preserves_old_bytes(self):
        event = self.event()
        args = dict(root=self.root, naos_root='naos', policy={}, profile='standard',
                    event_type='session_started', session_id='fixture-session')
        with mock.patch.object(audit, 'build_audit_event', side_effect=lambda **kwargs: copy.deepcopy(event)):
            first = audit.write_audit_event(**args)
            original = Path(first['event_file']).read_bytes()
            second = audit.write_audit_event(**args)
        self.assertEqual(first['status'], 'written')
        self.assertEqual(second['status'], 'written')
        self.assertNotEqual(first['event']['event_nonce'], second['event']['event_nonce'])
        self.assertNotEqual(first['event_file'], second['event_file'])
        self.assertEqual(Path(first['event_file']).read_bytes(), original)
        self.assertEqual(second['event']['event_id'], independent_id(second['event']))
        self.assertEqual(audit.recompute_public_audit_event_id(second['event']), second['event']['event_id'])

    def test_bounded_nested_payloads_refuse_without_io_or_recursion(self):
        event = self.event()
        for summary in [{'oversized': [0] * 50001}, {'cycle': None}]:
            if 'cycle' in summary:
                summary['cycle'] = summary
            altered = {**event, 'event_payload_summary': summary}
            self.assertIsNone(audit.recompute_public_audit_event_id(altered))
        nested = {}
        for _ in range(65):
            nested = {'nested': nested}
        self.assertIsNone(audit.recompute_public_audit_event_id({**event, 'generated_by': nested}))

    def test_key_order_and_wire_whitespace_do_not_change_canonical_derivation(self):
        event = self.event()
        reordered = dict(reversed(list(event.items())))
        decoded = json.loads(json.dumps(reordered, indent=4))
        self.assertEqual(audit.recompute_public_audit_event_id(decoded), event['event_id'])

    def test_schema_extension_legacy_and_new_are_valid(self):
        import jsonschema
        schema = json.loads((ROOT/'schemas/naos/audit_log_event.schema.json').read_text())
        event = self.event()
        self.assertEqual(set(schema['properties']), audit.PUBLIC_EVENT_FIELDS)
        jsonschema.validate(event, schema)
        legacy = {k:v for k,v in event.items() if k not in {'event_nonce','event_id_scheme'}}
        legacy['event_id'] = 'audit-20261009T120000Z-abcdef123456'
        jsonschema.validate(legacy, schema)
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate({k:v for k,v in event.items() if k != 'event_nonce'}, schema)

    def test_systemic_shape_retains_legacy_and_new_but_rejects_modified_or_extra_fields(self):
        event = self.event(source_report={'schema':'naos.session_identity.v1', 'status':'session_created',
                           'summary':{'created':1,'reused':0,'missing_session_id':0}})
        # This unit isolates the new top-level contract; finite nested source
        # contracts are also exercised by existing source contract tests.
        with mock.patch('naos_systemic_family_review._audit_nested_output_shape', return_value=True):
            self.assertTrue(_audit_output_shape(event, 'session_identity_report'))
            legacy = {k:v for k,v in event.items() if k not in {'event_nonce','event_id_scheme'}}
            legacy['event_id'] = 'audit-20261009T120000Z-abcdef123456'
            self.assertTrue(_audit_output_shape(legacy, 'session_identity_report'))
            self.assertFalse(_audit_output_shape({**event, 'authored_extra':'note'}, 'session_identity_report'))
            self.assertFalse(_audit_output_shape({**event, 'event_nonce':'0123'}, 'session_identity_report'))
            self.assertFalse(_audit_output_shape({**event, 'operator_id':'modified'}, 'session_identity_report'))


if __name__ == '__main__':
    unittest.main()
