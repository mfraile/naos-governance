"""Shipped provenance declarations retain strict review of unrelated findings."""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(os.environ.get('NAOS_TEST_KIT', Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(ROOT / 'scripts'))
from naos_evidence_classification import declared_classification  # noqa: E402

GAP_RISK_IDS = {
    'GCQ-KG-001', 'GCQ-KG-002', 'GCQ-RR-001', 'GCQ-RR-002',
    'GCR-KG-001', 'GCR-KG-002', 'GCR-RR-001', 'GCR-RR-002',
    'SCL-KG-001', 'SCL-KG-002', 'SCL-RR-001', 'SCL-RR-002',
    'LCQ-KG-001', 'LCQ-RR-001', 'LCI-KG-001', 'LCI-RR-001',
    'RISK-LEARNING-001', 'SESSION-LIFECYCLE-RISK-001',
    'POLICY_OVERRIDE_PLUGIN_RUNTIME_DEFERRED', 'MULTI_TEAM_GATEKEEPER_CONFIG_DEFERRED',
    'POLICY_OVERRIDE_MISCONFIGURATION_RISK', 'TEAM_OPERATOR_MAPPING_STALENESS_RISK',
}
FIXED_FINDING_IDS = {
    'graph_context_query.no_seed', 'local_context_query.no_query',
    'task_claims.coordination_metadata_only',
    'sqlite_write_coordination.distributed_lock_not_provided',
    'local_context_index.sensitive_paths_excluded', 'pr_governance.ci_not_detected',
}
REPORTS = (
    'graph_context_query', 'graph_context_readiness', 'semantic_candidate_layer',
    'local_context_query', 'local_context_index', 'learning_loop_review',
    'session_lifecycle', 'policy_override_merge', 'task_claim_report',
    'pr_governance_summary',
)


class AssuredFixedProvenanceContractTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='naos-assured-provenance-')
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.fixture = self.root / 'fixture'
        self.run_cli('init', str(self.root / 'adopter'), '--new', '--tier', 'assured',
                     '--archetype', 'custom', '--backend', 'static_only',
                     '--memory', 'disabled', '--preview-dir', str(self.fixture), cwd=self.root,
                     expected={0})

    def run_cli(self, *args, cwd=None, expected={0, 1}):
        env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1'}
        env.pop('GITHUB_ACTIONS', None)  # This fixture is a local preview, including when tests run in CI.
        result = subprocess.run(
            [sys.executable, str(ROOT / 'cli.py'), *args], cwd=cwd or self.fixture,
            capture_output=True, text=True, check=False,
            env=env,
        )
        self.assertIn(result.returncode, expected, (args, result.stdout[-1000:], result.stderr[-1000:]))
        self.assertNotIn('Traceback', result.stderr)
        return result

    def test_explicit_provenance_takes_precedence_without_bypassing_invalid_or_conflicting_inputs(self):
        cases = [
            ({'classification': 'safe_to_defer', 'evidence_classification': 'confirmed'}, 'confirmed'),
            ({'classification': 'confirmed', 'evidence_classification': 'unknown'}, 'unknown'),
            ({'classification': 'confirmed', 'evidence_classification': 'invalid'}, 'unknown'),
            ({'evidence_classification': 'confirmed', 'provenance_classification': 'hypothesized'}, 'unknown'),
            ({'evidence_classification': 'hypothesized', 'provenance_classification': 'hypothesized'}, 'hypothesized'),
            ({'classification': 'confirmed'}, 'confirmed'),
            ({'classification': 'safe_to_defer'}, 'unknown'),
            ({}, None),
        ]
        for item, expected in cases:
            with self.subTest(item=item):
                self.assertEqual(declared_classification(item), expected)

    def test_actual_shipped_producers_classify_only_fixed_facts_and_named_risks(self):
        for name, extra in (
            ('context-index', ()), ('context-query', ()), ('semantic-candidates', ()),
            ('graph-context', ()), ('graph-query', ()), ('learning-loop-review', ()),
            ('task-claims', ('--action', 'list')), ('policy-overrides', ('--dry-run',)),
            ('pr-governance-summary', ()),
        ):
            self.run_cli(name, '--profile', 'assured', '--naos-root', 'naos', *extra)
        lifecycle = subprocess.run(
            [sys.executable, str(ROOT / 'scripts/naos_session_lifecycle.py'),
             '--mode', 'session_start', '--profile', 'assured', '--naos-root', 'naos'],
            cwd=self.fixture, capture_output=True, text=True, check=False,
        )
        self.assertIn(lifecycle.returncode, {0, 1}, lifecycle.stderr)
        self.assertNotIn('Traceback', lifecycle.stderr)
        reports = self.fixture / 'naos/reports'
        for name in REPORTS:
            self.assertTrue((reports / f'{name}.json').is_file(), name)
        args = ['evidence-classification', '--profile', 'assured', '--naos-root', 'naos']
        for name in REPORTS:
            args += ['--report', f'naos/reports/{name}.json']
        args += ['--output', str(self.root / 'classified.json')]
        self.run_cli(*args)
        data = json.loads((self.root / 'classified.json').read_text())
        actual = {item['finding_id']: item for item in data['classified_findings']}
        self.assertEqual(GAP_RISK_IDS | FIXED_FINDING_IDS, (GAP_RISK_IDS | FIXED_FINDING_IDS) & actual.keys())
        for finding_id in GAP_RISK_IDS | FIXED_FINDING_IDS:
            with self.subTest(finding_id=finding_id):
                item = actual[finding_id]
                self.assertEqual(item['classification_source'], 'declared')
                self.assertIn(item['classification'], {'confirmed', 'hypothesized'})
                self.assertTrue(item['classification_scope'])
                self.assertTrue(item['message'])
                self.assertTrue(item['evidence_refs'])
                self.assertTrue(item['human_review_required'])
                local_refs = [ref['ref'] for ref in item['evidence_refs'] if ref['type'] == 'local_file']
                self.assertTrue(local_refs)
                for ref in local_refs:
                    path = Path(ref)
                    self.assertTrue((path if path.is_absolute() else self.fixture / path).is_file(), ref)
        policy = json.loads((reports / 'policy_override_merge.json').read_text())
        self.assertEqual(policy['known_gaps'][0]['classification'], 'safe_to_defer')
        self.assertEqual(actual['POLICY_OVERRIDE_PLUGIN_RUNTIME_DEFERRED']['message'],
                         policy['known_gaps'][0]['description'])
        # Conditional missing inputs remain review-required instead of getting blanket provenance.
        self.assertTrue(data['missing_classification'])
        self.assertEqual(data['status'], 'review_required')

    def test_ci_detection_branch_is_metadata_only(self):
        env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1',
               'GITHUB_ACTIONS': 'true'}
        result = subprocess.run(
            [sys.executable, str(ROOT / 'cli.py'), 'pr-governance-summary',
             '--profile', 'assured', '--naos-root', 'naos'],
            cwd=self.fixture, capture_output=True, text=True, check=False, env=env,
        )
        self.assertIn(result.returncode, {0, 1}, result.stderr)
        data = json.loads((self.fixture / 'naos/reports/pr_governance_summary.json').read_text())
        self.assertNotIn('pr_governance.ci_not_detected', {item['id'] for item in data['findings']})
        self.assertEqual(data['ci_provider'], 'github_actions')

    def test_custom_rule_record_and_invalid_explicit_declaration_remain_blocking(self):
        rules = self.fixture / 'naos/graph_context_rules.yaml'
        data = yaml.safe_load(rules.read_text())
        data['known_gaps'][0]['summary'] = 'Customized statement with a stale declaration.'
        data['residual_risks'].append({'id': 'CUSTOM-RISK', 'summary': 'A project-specific unresolved risk.'})
        rules.write_text(yaml.safe_dump(data, sort_keys=False))
        self.run_cli('graph-context', '--profile', 'assured', '--naos-root', 'naos')
        synthetic = self.fixture / 'naos/reports/provenance_negative.json'
        synthetic.write_text(json.dumps({'findings': [
            {'id': 'MISSING', 'message': 'No declared provenance.'},
            {'id': 'INVALID', 'classification': 'confirmed', 'evidence_classification': 'invalid'},
            {'id': 'CONFLICT', 'evidence_classification': 'confirmed',
             'provenance_classification': 'hypothesized'},
        ]}))
        self.run_cli('evidence-classification', '--profile', 'assured', '--naos-root', 'naos',
                     '--report', 'naos/reports/graph_context_readiness.json',
                     '--report', 'naos/reports/provenance_negative.json',
                     '--output', str(self.root / 'classified-negative.json'), expected={1})
        data = json.loads((self.root / 'classified-negative.json').read_text())
        missing = {item['finding_id'] for item in data['missing_classification']}
        self.assertTrue({'CUSTOM-RISK', 'MISSING', 'INVALID', 'CONFLICT'} <= missing)
        inherited = next(item for item in data['classified_findings'] if item['finding_id'] == 'GCR-KG-001')
        self.assertEqual(inherited['classification_source'], 'declared')
        self.assertTrue(inherited['human_review_required'])
        self.assertEqual(inherited['message'], 'Customized statement with a stale declaration.')
        self.assertEqual(data['status'], 'review_required')


if __name__ == '__main__':
    unittest.main()
