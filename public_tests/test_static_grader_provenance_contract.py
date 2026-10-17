"""Declared tool limits are provenance, never behavioral evaluation or approval."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(os.environ.get('NAOS_TEST_KIT', Path(__file__).resolve().parents[1])).resolve()


class StaticGraderProvenanceContractTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='naos-static-provenance-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / 'naos').mkdir()
        shutil.copy2(ROOT / 'templates/structural-seeds/naos/evidence_classification_policy.yaml',
                     self.root / 'naos/evidence_classification_policy.yaml')

    def run_tool(self, name):
        result = subprocess.run(
            [sys.executable, str(ROOT / 'scripts' / name), '--profile', 'assured', '--json'],
            cwd=self.root, capture_output=True, text=True, check=False,
        )
        self.assertNotIn('Traceback', result.stderr)
        return result.returncode, json.loads(result.stdout)

    def test_actual_coverage_limits_have_declared_source_provenance_without_behavioral_pass(self):
        _, report = self.run_tool('naos_static_grader.py')
        schema = json.loads((ROOT / 'schemas/naos/static_grader_report.schema.json').read_text())
        Draft202012Validator(schema).validate(report)
        unsupported = [x for x in report['findings'] if x['status'] == 'unsupported_behavioral_dimension']
        self.assertEqual(len(unsupported), 6)
        ids = {x['id'] for x in unsupported}
        for finding in unsupported:
            self.assertEqual(finding['classification'], 'confirmed')
            self.assertEqual(finding['classification_scope'], 'tool_coverage_limitation')
            self.assertEqual(finding['severity'], 'advisory')
            self.assertTrue(finding['human_review_required'])
            self.assertEqual(Path(finding['source_path']).resolve(),
                             (ROOT / 'autoresearch/graders/static.py').resolve())
            self.assertIn('FUTURE_BEHAVIORAL_DIMENSIONS', finding['reasoning_summary'])
        for dimension in report['not_evaluated_dimensions']:
            self.assertEqual(dimension['status'], 'readiness_only')
            self.assertTrue(dimension['human_review_required'])
        self.assertIn('approval', report['not_claimed'])
        _, classified = self.run_tool('naos_evidence_classification.py')
        classified_limits = [x for x in classified['classified_findings'] if x['finding_id'] in ids]
        self.assertEqual(len(classified_limits), 6)
        self.assertTrue(all(x['classification_source'] == 'declared' for x in classified_limits))
        self.assertFalse(any(x.get('finding_id') in ids for x in classified['missing_classification']))
        # Other actual missing-input findings are not silently classified.
        others = [x for x in report['findings'] if x['id'] not in ids]
        self.assertTrue(others)
        self.assertTrue(all('classification' not in x for x in others))

    def test_unclassified_and_unknown_findings_still_block_assured(self):
        _, report = self.run_tool('naos_static_grader.py')
        unsupported = next(x for x in report['findings'] if x['status'] == 'unsupported_behavioral_dimension')
        unsupported.pop('classification', None)
        report['findings'].append({
            'id': 'SYNTHETIC_UNKNOWN', 'severity': 'advisory', 'status': 'unknown',
            'message': 'Synthetic negative: provenance is not established.',
            'classification': 'unknown',
        })
        report_path = self.root / 'naos/reports/static_grader_report.json'
        report_path.write_text(json.dumps(report))
        code, classified = self.run_tool('naos_evidence_classification.py')
        self.assertEqual(code, 1)
        missing = {x.get('finding_id'): x for x in classified['findings']}
        for finding_id in (unsupported['id'], 'SYNTHETIC_UNKNOWN'):
            self.assertEqual(missing[finding_id]['severity'], 'blocking')
            self.assertEqual(missing[finding_id]['status'], 'missing_classification')


if __name__ == '__main__':
    unittest.main()
