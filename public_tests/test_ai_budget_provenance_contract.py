"""Measured budget provenance never weakens producer enforcement or unknown review."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator
import yaml

ROOT = Path(os.environ.get('NAOS_TEST_KIT', Path(__file__).resolve().parents[1])).resolve()
COMMAND = ([sys.executable, '-B', '-m', 'naos_governance.cli']
           if os.environ.get('NAOS_TEST_INSTALLED') == '1'
           else [sys.executable, '-B', str(ROOT / 'cli.py')])


class AiBudgetProvenanceContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='naos budget provenance ü ')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.project = self.root / 'preview'
        self.run_cli('init', str(self.root / 'adopter'), '--new', '--tier', 'assured',
                     '--archetype', 'custom', '--backend', 'static_only', '--memory', 'disabled',
                     '--preview-dir', str(self.project), cwd=self.root, expected=0)
        # Exercise an actual generated project with a remapped governance root.
        (self.project / 'naos').rename(self.project / 'governance ü')
        self.naos_root = 'governance ü'
        self.policy = self.root / 'enforcing-policy.yaml'
        policy = yaml.safe_load((ROOT / 'policies/default_policy.yaml').read_text())
        policy['enforcement_transition'] = 'enforce'
        self.policy.write_text(yaml.safe_dump(policy), encoding='utf-8')
        self.rules = self.root / 'selected custom rules.yaml'
        self.surface = self.project / 'measured.txt'
        self.surface.write_text('a' * 41, encoding='utf-8')  # 11 estimated tokens at 4 chars/token.
        self.output = self.root / 'budget.json'

    def run_cli(self, *args, cwd=None, expected=0):
        env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1'}
        env.pop('NAOS_ROOT', None)
        result = subprocess.run([*COMMAND, *args], cwd=cwd or self.project,
                                env=env, text=True, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, expected, (args, result.stdout[-1500:], result.stderr[-1500:]))
        self.assertNotIn('Traceback', result.stderr)
        return result

    def write_rules(self, *, block=False, combined=False):
        # Deliberately tiny test-only selection, not a whole-project readiness claim.
        self.rules.write_text(yaml.safe_dump({
            'token_estimation': {'chars_per_token': 4},
            'families': [{'id': 'measured', 'patterns': ['measured.txt'],
                          'warn_tokens': 100 if combined else 10,
                          'block_tokens': 100 if combined or not block else 10}],
            'combined_scenarios': ([{'id': 'scenario-not-a-file', 'files': ['measured.txt'],
                                    'profiles': ['assured'], 'warn_tokens': 10,
                                    'block_tokens': 10 if block else 100}] if combined else []),
            'anchors': [],
        }), encoding='utf-8')

    def budget(self, *, expected=1, baseline=None):
        args = ['ai-surface-budget', '--profile', 'assured', '--naos-root', self.naos_root,
                '--policy', str(self.policy), '--rules', str(self.rules),
                '--output', str(self.output), '--json']
        args += ['--baseline', str(baseline)] if baseline else ['--no-default-baseline']
        data = json.loads(self.run_cli(*args, expected=expected).stdout)
        Draft202012Validator(json.loads((ROOT / 'schemas/naos/ai_surface_context_budget.schema.json').read_text())).validate(data)
        self.assertEqual(Path(data['rules']['path']).resolve(), self.rules)
        self.assertEqual(data['summary']['total_estimated_tokens'], 11)
        self.assertIn('Token estimation is deterministic chars-per-token approximation, not provider tokenizer output.', data['known_gaps'])
        self.assertIn('semantic correctness proof', data['not_claimed'])
        return data

    def classify(self, *, expected=0, extra=None):
        args = ['evidence-classification', '--profile', 'assured', '--naos-root', self.naos_root,
                '--policy', str(self.policy), '--report', str(self.output), '--json',
                '--output', str(self.root / 'classification.json')]
        if extra:
            args += ['--report', str(extra)]
        data = json.loads(self.run_cli(*args, expected=expected).stdout)
        Draft202012Validator(json.loads((ROOT / 'schemas/naos/evidence_classification_report.schema.json').read_text())).validate(data)
        return data

    def assert_measured_provenance(self, budget, classified):
        self.assertEqual(len(classified['classified_findings']), len(budget['findings']))
        for item, result in zip(budget['findings'], classified['classified_findings']):
            self.assertEqual(result['finding_id'], item['id'])
            self.assertEqual(result['classification'], 'confirmed')
            self.assertEqual(result['classification_source'], 'declared')
            self.assertEqual(result['severity'], item['severity'])
            self.assertEqual(result['status'], item['status'])
            self.assertTrue(result['classification_scope'])
            self.assertTrue(result['human_review_required'])
            self.assertIn('approval', item['not_claimed'])
            self.assertTrue(result['evidence_refs'])
            local_refs = {Path(ref['ref']).resolve() for ref in result['evidence_refs']
                          if ref['type'] == 'local_file'}
            self.assertIn(self.rules, local_refs)
            self.assertIn((ROOT / 'scripts/naos_ai_surface_budget.py').resolve(), local_refs)
            for ref in result['evidence_refs']:
                if ref['type'] in {'local_file', 'generated_report'}:
                    path = Path(ref['ref'])
                    self.assertTrue((path if path.is_absolute() else self.project / path).is_file(), ref)
        self.assertEqual(classified['missing_classification'], [])
        self.assertEqual(classified['summary']['unclassified_context'],
                         len(budget['known_gaps']) + len(budget['residual_risks']))

    def test_file_measurement_warning_and_block_keep_enforcement(self):
        for block in (False, True):
            with self.subTest(block=block):
                self.write_rules(block=block)
                data = self.budget(expected=1)
                self.assertEqual(len(data['findings']), 1)
                self.assertEqual(data['findings'][0]['severity'], 'blocking' if block else 'warning')
                self.assertIn('estimated at 11 tokens', data['findings'][0]['message'])
                self.assert_measured_provenance(data, self.classify())

    def test_combined_scenario_measurement_uses_identifier_without_fake_file_ref(self):
        for block in (False, True):
            with self.subTest(block=block):
                self.write_rules(block=block, combined=True)
                data = self.budget(expected=1)
                self.assertEqual(len(data['findings']), 1)
                self.assertEqual(data['findings'][0]['source'], 'scenario-not-a-file')
                self.assertEqual(data['findings'][0]['severity'], 'blocking' if block else 'warning')
                self.assert_measured_provenance(data, self.classify())

    def test_missing_selected_baseline_is_observation_not_approval_or_existing_file(self):
        self.write_rules()
        rules = yaml.safe_load(self.rules.read_text())
        rules['families'][0]['warn_tokens'] = 100
        self.rules.write_text(yaml.safe_dump(rules), encoding='utf-8')
        absent = self.root / 'absent approved baseline.json'
        data = self.budget(expected=0, baseline=absent)
        self.assertFalse(absent.exists())
        item = next(x for x in data['findings'] if x['id'] == 'AI_SURFACE_BASELINE_MISSING')
        self.assertEqual(item['severity'], 'advisory')
        self.assertEqual(Path(item['source']), absent)
        self.assertFalse(data['baseline']['present'])
        self.assertFalse(data['baseline']['auto_update_performed'])
        self.assertTrue(data['baseline']['human_approval_required_before_update'])
        self.assert_measured_provenance(data, self.classify())

    def test_missing_or_malformed_selected_rules_do_not_fabricate_file_evidence(self):
        for malformed in (False, True):
            with self.subTest(malformed=malformed):
                if malformed:
                    self.rules.write_text('[broken', encoding='utf-8')
                elif self.rules.exists():
                    self.rules.unlink()
                absent = self.root / 'missing baseline.json'
                result = self.run_cli('ai-surface-budget', '--profile', 'assured',
                                      '--naos-root', self.naos_root, '--policy', str(self.policy),
                                      '--rules', str(self.rules), '--baseline', str(absent),
                                      '--output', str(self.output), '--json', expected=1)
                data = json.loads(result.stdout)
                self.assertEqual(data['rules']['source'], 'default_fallback')
                self.assertFalse(data['rules']['present'])
                declared = [x for x in data['findings'] if x.get('evidence_classification') == 'confirmed']
                self.assertTrue(declared)
                for item in declared:
                    refs = item['evidence_refs']
                    self.assertEqual(len(refs), 1)
                    self.assertEqual(Path(refs[0]['ref']).resolve(),
                                     (ROOT / 'scripts/naos_ai_surface_budget.py').resolve())
                    self.assertTrue(Path(refs[0]['ref']).is_file())
                self.assertNotIn(str(self.rules), [r['ref'] for x in declared for r in x['evidence_refs']])

    def test_invalid_baseline_and_unrelated_findings_still_require_review(self):
        self.write_rules()
        invalid = self.root / 'invalid.json'
        invalid.write_text('{broken', encoding='utf-8')
        data = self.budget(baseline=invalid)
        item = next(x for x in data['findings'] if x['id'] == 'AI_SURFACE_BASELINE_INVALID')
        self.assertNotIn('evidence_classification', item)
        self.assertEqual(item['severity'], 'warning')
        extra = self.root / 'unrelated.json'
        extra.write_text(json.dumps({'findings': [
            {'id': 'UNKNOWN', 'message': 'A separate unresolved observation.'},
            {'id': 'INVALID', 'classification': 'confirmed', 'evidence_classification': 'invalid'},
            {'id': 'CONFLICT', 'evidence_classification': 'confirmed', 'provenance_classification': 'hypothesized'},
        ]}), encoding='utf-8')
        result = self.classify(expected=1, extra=extra)
        missing = {x['finding_id'] for x in result['missing_classification']}
        self.assertTrue({'AI_SURFACE_BASELINE_INVALID', 'UNKNOWN', 'INVALID', 'CONFLICT'} <= missing)
        self.assertEqual(result['status'], 'review_required')


if __name__ == '__main__':
    unittest.main()
