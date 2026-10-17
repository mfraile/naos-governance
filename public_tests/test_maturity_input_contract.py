"""Capability maturity rejects malformed present inputs without readiness claims."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml
from jsonschema import Draft202012Validator


ROOT = Path(os.environ.get('NAOS_TEST_KIT') or Path(__file__).resolve().parents[1])
SCRIPT = ROOT / 'scripts/naos_capability_maturity.py'
CAP_ID = 'CAP-CLAIMS-VALIDATION'
ENTRY = {'capability_id': CAP_ID, 'enabled': True, 'current_maturity': 'L0', 'target_maturity': 'L0'}
CONTRACT = {'id': CAP_ID, 'default_maturity': 'L0', 'profiles': {'quickstart': {'target_maturity': 'L0', 'enforcement': 'advisory'}}}


class InputTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='naos maturity é ')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.caps = self.root / 'capabilities'
        self.caps.mkdir()
        self.contract = self.caps / 'claims.yaml'
        self.contract.write_text(yaml.safe_dump(CONTRACT), encoding='utf-8')
        self.state = self.root / 'naos/capability_state.yaml'
        self.state.parent.mkdir()
        self.write_state({'capabilities': [ENTRY]})
        self.output = self.root / 'naos/reports/capability_maturity.json'
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(('NAOS_', 'GIT_'))}
        self.env.update(PYTHONDONTWRITEBYTECODE='1', GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_CONFIG_NOSYSTEM='1')

    def write_state(self, value):
        self.state.write_text(yaml.safe_dump(value), encoding='utf-8')

    def run_maturity(self):
        result = subprocess.run(
            [sys.executable, '-B', str(ROOT / 'cli.py'), 'capability-maturity', '--profile', 'quickstart',
             '--capabilities-dir', str(self.caps), '--state', str(self.state),
             '--output', str(self.output), '--json'],
            cwd=self.root, env=self.env, capture_output=True, text=True, timeout=30,
        )
        report = json.loads(result.stdout)
        self.assertEqual(report, json.loads(self.output.read_text(encoding='utf-8')))
        self.assertNotIn('Traceback', result.stderr)
        schema = json.loads((ROOT / 'schemas/naos/capability_maturity_report.schema.json').read_text(encoding='utf-8'))
        Draft202012Validator(schema).validate(report)
        return result, report

    def assert_invalid(self):
        result, report = self.run_maturity()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(report['status'], 'invalid_input')
        self.assertTrue(report['human_review_required'])
        self.assertNotIn('summary', report)
        return report

    def test_present_state_shapes_and_types_fail_closed(self):
        variants = [None, [], {}, {'capabilities': None}, {'capabilities': {}},
                    {'capabilities': [None]}, {'capabilities': [{}]},
                    {'capabilities': [ENTRY, ENTRY]},
                    {'capabilities': [{**ENTRY, 'enabled': 'false'}]},
                    {'capabilities': [{**ENTRY, 'enabled': 1}]},
                    {'capabilities': [{**ENTRY, 'evidence_refs': 'report.json'}]},
                    {'capabilities': [{**ENTRY, 'freshness_window_days': True}]},
                    {'capabilities': [{**ENTRY, 'waivers': [None]}]}]
        for value in variants:
            with self.subTest(value=value):
                self.write_state(value)
                self.assert_invalid()

    def test_present_contract_errors_and_duplicate_keys_fail_closed(self):
        for body in ('profiles: [\n', '{}\n', '[]\n',
                     'id: CAP-CLAIMS-VALIDATION\nid: CAP-OTHER\n',
                     'profiles: [bad]\n'):
            with self.subTest(body=body):
                self.contract.write_text(body, encoding='utf-8')
                self.assert_invalid()
        self.contract.write_text(yaml.safe_dump(CONTRACT), encoding='utf-8')
        (self.caps / 'duplicate.yaml').write_text(yaml.safe_dump(CONTRACT), encoding='utf-8')
        self.assert_invalid()

    def test_duplicate_merge_source_and_wrong_type_directory_fail_closed(self):
        self.state.write_text(
            'capabilities:\n- capability_id: CAP-CLAIMS-VALIDATION\n'
            '  <<: {enabled: true, enabled: false}\n', encoding='utf-8',
        )
        self.assert_invalid()
        self.write_state({'capabilities': [ENTRY]})
        self.contract.unlink()
        self.caps.rmdir()
        self.caps.write_text('not a directory', encoding='utf-8')
        self.assert_invalid()

    def test_controls_and_prior_output_replacement(self):
        controls = [({'capabilities': []}, 'not_configured'),
                    ({'capabilities': [{'capability_id': CAP_ID, 'enabled': True}]}, 'unknown'),
                    ({'capabilities': [{**ENTRY, 'enabled': False}]}, 'disabled')]
        for value, expected in controls:
            with self.subTest(expected=expected):
                self.write_state(value)
                result, report = self.run_maturity()
                self.assertEqual(result.returncode, 0)
                self.assertEqual(report['capabilities'][0]['evaluated_status'], expected)
        self.state.unlink()
        result, report = self.run_maturity()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(report['capabilities'][0]['evaluated_status'], 'not_configured')
        self.write_state({'capabilities': {}})
        self.assert_invalid()
        self.assertEqual(json.loads(self.output.read_text())['status'], 'invalid_input')

    def test_unreadable_selected_input_raises_sanitized_error(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        spec = importlib.util.spec_from_file_location('maturity_input_under_test', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        original = Path.read_text

        def guarded(path, *args, **kwargs):
            if path == self.state:
                raise PermissionError('SYNTHETIC_PRIVATE_VALUE')
            return original(path, *args, **kwargs)

        with patch.object(Path, 'read_text', guarded):
            with self.assertRaisesRegex(ValueError, 'cannot read unambiguous YAML mapping') as caught:
                module.load_yaml(self.state)
        self.assertNotIn('SYNTHETIC_PRIVATE_VALUE', str(caught.exception))

    def test_error_remains_visible_to_report_consumers(self):
        self.write_state({'capabilities': {}})
        self.assert_invalid()
        for command in ('evidence-pack', 'dashboard', 'gate-status'):
            if command == 'gate-status':
                # Gate input validation is independent; make its state valid so
                # this checks consumption of the earlier maturity error report.
                self.write_state({'capabilities': [ENTRY]})
            result = subprocess.run(
                [sys.executable, '-B', str(ROOT / 'cli.py'), command,
                 '--profile', 'quickstart', '--json'],
                cwd=self.root, env=self.env, capture_output=True, text=True, timeout=30,
            )
            if command != 'gate-status':
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads(result.stdout)
            if command == 'evidence-pack':
                self.assertEqual(report['artifacts']['capability_maturity_report']['report_status'], 'invalid_input')
                self.assertEqual(report['artifacts']['capability_maturity_report']['freshness']['status'], 'fresh')
                self.assertEqual(report['artifacts']['capability_maturity_report']['source_schema'],
                                 'naos.capability_maturity_input_error.v1')
            elif command == 'gate-status':
                self.assertIn('capability_maturity', report, list(report))
                self.assertEqual(report['capability_maturity']['status'], 'invalid_input')
                self.assertEqual(report['capability_maturity']['summary'], {})
            else:
                self.assertEqual(report['capability_maturity_readiness']['status'], 'invalid_input')
                self.assertEqual(report['capability_maturity_readiness']['capabilities'], [])

    def test_invalid_child_cannot_aggregate_to_assured_pass(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        import naos_self_check as self_check
        from naos_policy import exit_code_for_summary, load_policy

        self.write_state({'capabilities': {}})
        policy = load_policy()
        previous_cwd = Path.cwd()
        try:
            os.chdir(self.root)
            with patch.dict(os.environ, self.env, clear=True):
                check = self_check.run_json_script(
                    'naos_capability_maturity.py',
                    ['--capabilities-dir', str(self.caps), '--state', str(self.state),
                     '--output', str(self.output)],
                    'assured', policy, 'naos', None,
                )
        finally:
            os.chdir(previous_cwd)
        self.assertEqual(check['returncode'], 2)
        self.assertEqual(check['status'], 'invalid_input')
        aggregate = self_check.aggregate_checks([check])
        self.assertEqual(aggregate['status'], 'blocked')
        self.assertEqual(aggregate['summary']['blocking'], 1)
        self.assertEqual(exit_code_for_summary('assured', aggregate['summary'], policy), 1)


if __name__ == '__main__':
    unittest.main()
