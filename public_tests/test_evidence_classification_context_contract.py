"""Strict finding provenance and visible text disclosures are separate contracts."""
import importlib.util
import hashlib
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
COMMAND = ([sys.executable, '-B', '-m', 'naos_governance.cli']
           if os.environ.get('NAOS_TEST_INSTALLED') == '1'
           else [sys.executable, '-B', str(ROOT / 'cli.py')])


def load_module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class EvidenceClassificationContextContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='naos classification ü ')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.reports = self.root / 'naos/reports'
        self.reports.mkdir(parents=True)
        shutil.copy2(ROOT / 'templates/structural-seeds/naos/evidence_classification_policy.yaml',
                     self.root / 'naos/evidence_classification_policy.yaml')

    def write_report(self, **values):
        path = self.reports / 'synthetic.json'
        path.write_text(json.dumps(values), encoding='utf-8')
        return path

    def classify(self, *extra):
        result = subprocess.run(
            [*COMMAND, 'evidence-classification', '--profile', 'assured', '--strict', '--json', *extra],
            cwd=self.root, text=True, capture_output=True, timeout=60,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
        )
        self.assertNotIn('Traceback', result.stderr)
        report = json.loads(result.stdout)
        schema = json.loads((ROOT / 'schemas/naos/evidence_classification_report.schema.json').read_text())
        Draft202012Validator(schema).validate(report)
        return result.returncode, report

    def test_scan_time_payload_and_hash_survive_mutable_report_replacement(self):
        first = {'id': 'CPR-TOY', 'severity': 'required', 'status': 'review_required',
                 'message': 'Review inventory ü', 'reason_codes': ['inventory_report_missing']}
        second = {'id': 'CPR-TOY', 'severity': 'required', 'status': 'review_required',
                  'message': 'Review inventory ü', 'reason_codes': ['different_reason']}
        declared = {'id': 'declared', 'classification': 'confirmed', 'message': 'Observed field',
                    'detail': 'Not duplicated in the classifier report'}
        path = self.write_report(schema='toy.route.v1', generated_at='2026-01-01T00:00:00Z',
                                 findings=[first, second, declared], known_gaps=['Context ü'])
        original_bytes = path.read_bytes()
        code, report = self.classify()
        self.assertEqual(code, 1)
        scanned = report['reports_scanned'][0]
        self.assertEqual(scanned['raw_sha256'], hashlib.sha256(original_bytes).hexdigest())
        self.assertEqual(scanned['raw_byte_count'], len(original_bytes))
        self.assertEqual(scanned['source_schema'], 'toy.route.v1')
        self.assertEqual(scanned['source_generated_at'], '2026-01-01T00:00:00Z')
        self.assertEqual([item['source_index'] for item in report['missing_classification']], [0, 1])
        snapshots = report['source_finding_snapshots']
        self.assertEqual([item['payload'] for item in snapshots[:2]], [first, second])
        self.assertFalse(snapshots[2]['payload_retained'])
        self.assertEqual(snapshots[2]['retention_reason'], 'declared_projection_only')
        self.assertNotIn('payload', snapshots[2])
        self.assertEqual(report['source_finding_snapshot_summary']['declared_projection_only'], 1)
        for ordinal, item in enumerate(report['missing_classification']):
            self.assertEqual(item['source_report_sha256'], scanned['raw_sha256'])
            self.assertEqual(item['scan_payload_index'], ordinal)
            self.assertEqual(item['source_item_sha256'], snapshots[ordinal]['source_item_sha256'])
            self.assertEqual(item['scan_generated_at'], report['generated_at'])
            self.assertEqual(item['source_observed_at'], scanned['source_observed_at'])
            self.assertNotIn('payload', item)
        context = report['unclassified_context'][0]
        self.assertEqual(context['message'], 'Context ü')
        self.assertEqual(context['source_index'], 0)
        self.assertEqual(context['source_report_sha256'], scanned['raw_sha256'])

        path.write_text(json.dumps({'schema': 'toy.route.v1', 'findings': []}), encoding='utf-8')
        self.assertNotEqual(hashlib.sha256(path.read_bytes()).hexdigest(), scanned['raw_sha256'])
        retained = json.loads((self.reports / 'evidence_classification_report.json').read_text())
        self.assertEqual(retained['source_finding_snapshots'][0]['payload'], first)
        self.assertEqual(retained['scan_semantics'],
                         'historical_scan_time; source report paths may be replaced after this scan')
        gate = load_module('lineage_gate_status', 'scripts/naos_gate_status.py')
        policy = load_module('lineage_policy', 'scripts/naos_policy.py').load_policy(None, 'naos', self.root)
        projection = gate.load_evidence_classification(self.root, 'naos', policy)
        self.assertEqual(projection['missing_classification'][0]['source_report_sha256'], scanned['raw_sha256'])
        self.assertNotIn('source_finding_snapshots', projection)

    def test_oversize_payloads_keep_hash_and_explicit_nonretention(self):
        findings = [{'id': 'oversize', 'message': 'Review', 'detail': 'x' * 17000}]
        findings.extend({'id': f'budget-{i}', 'message': 'Review', 'detail': 'y' * 15000}
                        for i in range(19))
        self.write_report(findings=findings)
        code, report = self.classify()
        self.assertEqual(code, 1)
        snapshots = report['source_finding_snapshots']
        self.assertEqual(snapshots[0]['retention_limit'], 'per_item')
        self.assertFalse(snapshots[0]['payload_retained'])
        self.assertNotIn('payload', snapshots[0])
        self.assertTrue(any(item.get('retention_limit') == 'total' for item in snapshots))
        self.assertGreater(report['source_finding_snapshot_summary']['not_retained'], 1)
        self.assertEqual(len(report['missing_classification']), len(findings))
        self.assertTrue(all('payload' not in item for item in report['missing_classification']))

    def test_read_and_parse_failures_only_bind_bytes_actually_read(self):
        bad = self.reports / 'bad.json'
        bad.write_bytes(b'\xff')
        code, report = self.classify('--report', str(bad))
        self.assertEqual(code, 1)
        scanned = report['reports_scanned'][0]
        self.assertEqual(scanned['raw_sha256'], hashlib.sha256(b'\xff').hexdigest())
        self.assertEqual(scanned['raw_byte_count'], 1)
        self.assertTrue(scanned['exists'])
        self.assertIsNotNone(scanned['parse_error'])
        missing = self.reports / 'absent.json'
        code, report = self.classify('--report', str(missing))
        self.assertEqual(code, 1)
        scanned = report['reports_scanned'][0]
        self.assertIsNone(scanned['raw_sha256'])
        self.assertIsNone(scanned['raw_byte_count'])
        self.assertIsNone(scanned['exists'])
        self.assertIsNotNone(scanned['parse_error'])

    def test_escaped_lone_surrogate_is_hashable_without_changing_strictness(self):
        escaped = chr(0xD800)
        strict = {'id': 'strict', 'message': 'Review', 'detail': escaped}
        declared = {'id': 'declared', 'message': 'Observed',
                    'classification': 'confirmed', 'detail': escaped}
        self.write_report(findings=[strict, declared], known_gaps=[escaped])
        code, report = self.classify()
        self.assertEqual(code, 1)
        snapshots = report['source_finding_snapshots']
        self.assertEqual(snapshots[0]['payload'], strict)
        self.assertFalse(snapshots[1]['payload_retained'])
        self.assertEqual(snapshots[1]['retention_reason'], 'declared_projection_only')
        for source, snapshot in zip((strict, declared), snapshots):
            canonical = json.dumps(source, sort_keys=True, ensure_ascii=True,
                                   separators=(',', ':')).encode('utf-8')
            self.assertEqual(snapshot['source_item_sha256'], hashlib.sha256(canonical).hexdigest())
        self.assertEqual(report['unclassified_context'][0]['message'], escaped)
        self.assertEqual(report['missing_classification'][0]['finding_id'], 'strict')
        self.assertEqual(len(report['missing_classification']), 1)

    def test_text_disclosures_preserve_content_order_source_and_review_boundary(self):
        path = self.write_report(findings=[], known_gaps=['Dynamic gap ü', ''],
                                 residual_risks=['Dynamic gap ü', 'Risk\nsecond line'])
        code, report = self.classify()
        self.assertEqual(code, 0)
        self.assertEqual(report['status'], 'ready')
        self.assertEqual(report['findings_scanned'], 0)
        self.assertEqual(report['missing_classification'], [])
        context = report['unclassified_context']
        self.assertEqual([(x['source_bucket'], x['source_index'], x['message']) for x in context], [
            ('known_gaps', 0, 'Dynamic gap ü'), ('known_gaps', 1, ''),
            ('residual_risks', 0, 'Dynamic gap ü'), ('residual_risks', 1, 'Risk\nsecond line')])
        self.assertEqual(report['unclassified_context_counts'], {'known_gaps': 2, 'residual_risks': 2})
        self.assertEqual(report['summary']['unclassified_context'], 4)
        self.assertEqual(report['reports_scanned'][0]['unclassified_context'], 4)
        for item in context:
            self.assertEqual(Path(item['source_report']).resolve(), path.resolve())
            self.assertEqual(item['status'], 'unclassified_context')
            self.assertNotIn('classification', item)
            self.assertTrue(item['human_review_required'])
            self.assertIn('issue resolution', item['not_claimed'])
        self.assertTrue(report['human_review_required'])

    def test_same_text_in_findings_still_blocks(self):
        message = 'Dynamic gap needing review'
        self.write_report(findings=[message], residual_risks=[message])
        code, report = self.classify()
        self.assertEqual(code, 1)
        self.assertEqual(len(report['missing_classification']), 1)
        self.assertEqual(report['missing_classification'][0]['source_bucket'], 'findings')
        self.assertEqual(report['missing_classification'][0]['source_index'], 0)
        self.assertEqual(report['source_finding_snapshots'][0]['payload'], message)
        self.assertEqual(report['findings'][0]['severity'], 'blocking')
        self.assertEqual(len(report['unclassified_context']), 1)

    def test_structured_records_in_all_buckets_keep_strict_provenance(self):
        self.write_report(**{bucket: [{'id': bucket, 'severity': 'advisory', 'message': 'Review'}]
                             for bucket in ('findings', 'known_gaps', 'residual_risks')})
        code, report = self.classify()
        self.assertEqual(code, 1)
        self.assertEqual({x['source_bucket'] for x in report['missing_classification']},
                         {'findings', 'known_gaps', 'residual_risks'})
        self.assertEqual(report['unclassified_context'], [])
        self.assertTrue(all(x['severity'] == 'blocking' for x in report['findings']))

    def test_malformed_entries_are_not_relabelled_as_context(self):
        self.write_report(findings=[None, 42, []], known_gaps=[None], residual_risks=[False])
        code, report = self.classify()
        self.assertEqual(code, 1)
        self.assertEqual(len(report['missing_classification']), 5)
        self.assertEqual(report['unclassified_context'], [])

    def test_unknown_and_invalid_declarations_still_block(self):
        self.write_report(findings=[{'id': str(i), 'classification': value}
                                    for i, value in enumerate(('unknown', 'APPROVED'))])
        code, report = self.classify()
        self.assertEqual(code, 1)
        self.assertEqual(len(report['unknown_findings']), 2)
        self.assertEqual(report['unclassified_context'], [])

    def test_present_malformed_containers_cannot_disappear(self):
        for bucket in ('findings', 'known_gaps', 'residual_risks'):
            for value in ({'classification': 'confirmed'}, 'invalid container', None, 42):
                with self.subTest(bucket=bucket, value=value):
                    self.write_report(**{bucket: value})
                    code, report = self.classify()
                    self.assertEqual(code, 1)
                    self.assertEqual(report['status'], 'review_required')
                    self.assertEqual(len(report['unknown_findings']), 1)
                    item = report['unknown_findings'][0]
                    self.assertEqual(item['status'], 'invalid_finding_container')
                    self.assertEqual(item['source_bucket'], bucket)
                    self.assertIsNone(item['source_index'])
                    self.assertEqual(report['source_finding_snapshots'][0]['payload'], value)
                    self.assertEqual(report['findings'][0]['severity'], 'blocking')
                    self.assertEqual(report['unclassified_context'], [])

    def test_absent_buckets_are_distinct_from_malformed_containers(self):
        self.write_report(schema='synthetic.no_findings.v1')
        code, report = self.classify()
        self.assertEqual(code, 0)
        self.assertEqual(report['findings_scanned'], 0)
        self.assertEqual(report['unclassified_context'], [])

    def test_corrupt_report_cannot_become_ready_context(self):
        self.write_report(known_gaps=['visible'])
        (self.reports / 'corrupt.json').write_text('{', encoding='utf-8')
        _, report = self.classify()
        self.assertEqual(report['status'], 'review_required')
        self.assertTrue(any(x['id'].startswith('evidence_classification.parse_error') for x in report['findings']))
        self.assertEqual(len(report['unclassified_context']), 1)

    def test_real_consumer_summaries_and_dashboard_retain_review_context(self):
        self.write_report(findings=[], known_gaps=['Synthetic unresolved gap'])
        _, report = self.classify()
        dashboard = load_module('naos_context_dashboard_test', 'scripts/workflows/generate_naos_dashboard.py')
        evidence = load_module('naos_context_evidence_test', 'scripts/naos_evidence_export.py')
        gate = load_module('naos_context_gate_test', 'scripts/naos_gate_status.py')
        maturity = load_module('naos_context_maturity_test', 'scripts/naos_capability_maturity.py')
        artifact = {'data': report, 'status': report['status']}
        policy = gate.load_policy(None, 'naos', self.root)
        summaries = [dashboard.summarize_evidence_classification(artifact),
                     evidence.summarize_evidence_classification(artifact),
                     gate.load_evidence_classification(self.root, 'naos', policy),
                     maturity.related_evidence_classification_evidence(self.root, 'naos', policy)]
        for summary in summaries:
            self.assertEqual(summary['unclassified_context'], report['unclassified_context'])
            self.assertEqual(summary['unclassified_context_counts'], {'known_gaps': 1})
            self.assertTrue(summary['human_review_required'])
        result = subprocess.run([*COMMAND, 'dashboard', '--profile', 'assured', '--json'],
                                cwd=self.root, text=True, capture_output=True, timeout=60)
        self.assertNotIn('Traceback', result.stderr)
        rendered = (self.root / 'naos/DASHBOARD.md').read_text(encoding='utf-8')
        self.assertIn('Unclassified text gap/risk disclosures: `1`', rendered)
        self.assertIn('ready classification does not resolve them', rendered)


if __name__ == '__main__':
    unittest.main()
