#!/usr/bin/env python3
"""Portable report and trace contract regressions; all writes use disposable projects.

Set NAOS_TEST_KIT for kit resources and NAOS_TEST_INSTALLED=1 to test a wheel.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(os.environ.get('NAOS_TEST_KIT', Path(__file__).resolve().parents[1])).resolve()
COMMAND = ([sys.executable, '-B', '-m', 'naos_governance.cli']
           if os.environ.get('NAOS_TEST_INSTALLED') == '1' else [sys.executable, '-B', str(ROOT / 'cli.py')])


def execute(project: Path, command: str, *args: str) -> tuple[subprocess.CompletedProcess[str], dict]:
    result = subprocess.run([*COMMAND, command, *args], cwd=project, text=True, capture_output=True,
                            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, timeout=180)
    try:
        report = json.loads(result.stdout)
    except ValueError:
        raise AssertionError(f'{command} did not return JSON (exit {result.returncode}): {result.stderr[-3000:]}\n{result.stdout[-1000:]}')
    return result, report


def generate(work: Path, profile: str) -> Path:
    project = work / profile
    result = subprocess.run([*COMMAND, 'init', str(work / (profile + '-target')), '--new', '--tier', profile,
                             '--archetype', 'custom', '--backend', 'static_only', '--preview-dir', str(project)],
                            cwd=work, text=True, capture_output=True, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, timeout=120)
    if result.returncode:
        raise AssertionError(result.stderr[-3000:])
    if (work / (profile + '-target')).exists():
        raise AssertionError('Preview mutated target')
    items = project / 'naos/control_plane_review_items.yaml'
    items.write_text(yaml.safe_dump({'version': '1.0', 'items': [{
        'id': 'CPR-SYNTHETIC-FIXTURE', 'source_type': 'manual_review_item',
        'source_ref': 'naos/model_provider_policy.yaml', 'summary': 'Synthetic local fixture review.',
        'target_surfaces': ['next_actions'], 'disposition': 'routed', 'owner': 'synthetic-fixture',
        'review_date': '2026-09-16', 'human_review_required': False}]}))
    return project


def run(project: Path, command: str, profile: str = 'assured', *args: str):
    return execute(project, command, '--profile', profile, '--strict', '--json', *args)


def current_reports(project: Path, profile: str):
    for command in ('model-policy', 'model-telemetry'):
        run(project, command, profile)
    if profile in {'standard', 'assured'}:
        run(project, 'ai-component-inventory', profile)


def change_sources(project: Path):
    for name in ('model_provider_policy', 'model_telemetry_evidence'):
        path = project / 'naos' / (name + '.yaml')
        declaration = yaml.safe_load(path.read_text())
        declaration['runtime_enabled'] = True
        if name == 'model_telemetry_evidence':
            declaration.update(enabled=True, telemetry_declared=True,
                               records=[{'record_id': 'SYNTHETIC', 'policy_exception': True}])
        path.write_text(yaml.safe_dump(declaration))


def event(**updates):
    value = {'event_id': 'synthetic-event', 'generated_at': '2026-09-16T00:00:00Z',
             'session_id': 'synthetic-session', 'agent_or_surface': 'synthetic-agent',
             'lifecycle_phase': 'implementation', 'action_type': 'write', 'task_id': 'T-SYNTHETIC',
             'authority_layer': 'record_only', 'human_review_required': True,
             'review_status': 'review_pending', 'files_modified': ['synthetic.txt'],
             'referenced_specs': ['specs/03-requirements.md'], 'referenced_capabilities': ['CAP-AGENT-TRACE-EVENTS'],
             'evidence_refs': ['synthetic.txt'], 'limitations': ['Declared metadata only.'],
             'not_claimed': ['Runtime capture.', 'Approval.']}
    value.update(updates)
    return value


def write_event(project: Path, value):
    path = project / 'naos/agent_trace_events.yaml'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({'events': [value]}))


class ReportTraceContracts(unittest.TestCase):
    def test_genuine_producers_source_mutation_and_recovery_all_profiles(self):
        with tempfile.TemporaryDirectory() as temp:
            for profile in ('quickstart', 'lite', 'standard', 'assured'):
                with self.subTest(profile=profile):
                    project = generate(Path(temp), profile)
                    current_reports(project, profile)
                    _, clean = run(project, 'control-plane-review', profile)
                    for name in ('model_provider_policy', 'model_telemetry_evidence'):
                        self.assertEqual(clean[name + '_reconciliation']['summary']['routes_generated'], 0)
                    change_sources(project)
                    if profile in {'standard', 'assured'}:
                        run(project, 'ai-component-inventory', profile)
                    _, stale = run(project, 'control-plane-review', profile)
                    for name in ('model_provider_policy', 'model_telemetry_evidence'):
                        self.assertGreater(stale[name + '_reconciliation']['summary']['routes_generated'], 0)
                    self.assertTrue(stale['human_review_required'])
                    current_reports(project, profile)
                    result, risky = run(project, 'control-plane-review', profile)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(risky['status'], 'blocked')
                    self.assertTrue(risky['human_review_required'])

    def test_malformed_and_incompatible_reports_cannot_suppress_routes(self):
        with tempfile.TemporaryDirectory() as temp:
            project = generate(Path(temp), 'assured')
            current_reports(project, 'assured')
            reports = project / 'naos/reports'
            genuine = {name: json.loads((reports / (name + '.json')).read_text())
                       for name in ('model_provider_policy', 'model_telemetry_evidence')}
            for case in ('empty', 'array', 'schema', 'profile', 'identity', 'timestamp_only', 'findings_type'):
                with self.subTest(case=case):
                    for name, original in genuine.items():
                        payload = dict(original)
                        if case == 'empty':
                            payload = {}
                        elif case == 'array':
                            payload = []
                        elif case == 'schema':
                            payload['schema'] = 'unrelated.v999'
                        elif case == 'profile':
                            payload['profile'] = 'lite'
                        elif case == 'identity':
                            payload['project_root'] = 'unrelated-project'
                        elif case == 'findings_type':
                            payload['findings'] = 123
                        elif case == 'timestamp_only':
                            payload['generated_at'] = '2099-01-01T00:00:00Z'
                            payload['policy_hash' if name == 'model_provider_policy' else 'declaration_hash'] = 'stale'
                        (reports / (name + '.json')).write_text(json.dumps(payload))
                    result, report = run(project, 'control-plane-review')
                    self.assertNotEqual(result.returncode, 0)
                    self.assertTrue(report['human_review_required'])
                    for name in genuine:
                        self.assertGreater(report[name + '_reconciliation']['summary']['routes_generated'], 0)

    def test_trace_schema_cli_grading_and_stale_report(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            write_event(project, event())
            run(project, 'agent-traces')
            write_event(project, event(event_id=123, source_hashes={'synthetic.txt': {'invalid': True}}))
            # Standalone grading must reject current malformed events even if its stored report is valid.
            result, grade = run(project, 'static-grader')
            self.assertNotEqual(result.returncode, 0)
            for name in ('D1_structural_conformance', 'trace_schema_conformance'):
                dimension = next(d for d in grade['dimensions'] if d['dimension_id'] == name)
                self.assertFalse(dimension['passed'])
                self.assertNotEqual(dimension['score'], 1.0)
            result, trace = run(project, 'agent-traces')
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(trace['invalid_event_count'], 1)
            self.assertGreaterEqual(len(trace['schema_validation_results'][0]['errors']), 2)
            run(project, 'static-grader')
            result, assessment = run(project, 'grader-assessment')
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(assessment['human_review_required'])
            self.assertFalse(next(d for d in assessment['dimensions'] if d['dimension_id'] == 'trace_schema_conformance')['passed'])

    def test_malformed_trace_events_return_controlled_diagnostics(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            for field, value in [('action_type', ['write']), ('files_read', [1]), ('referenced_tasks', 1),
                                 ('source_references', 1), ('action_receipt', {'approval_status': ['approved']}),
                                 ('confidence', True), ('forbidden_payload_check', {'performed': 'yes'})]:
                with self.subTest(field=field):
                    write_event(project, event(**{field: value}))
                    result, report = run(project, 'agent-traces')
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(report['invalid_event_count'], 1)
                    self.assertEqual(report['status'], 'invalid_trace_events')

    def test_review_obligation_and_action_approval_are_distinct(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            for status in ('not_reviewed', 'review_pending', 'reviewed', 'rejected'):
                with self.subTest(status=status):
                    write_event(project, event(review_status=status))
                    result, report = run(project, 'agent-traces')
                    self.assertEqual(result.returncode, 0)
                    self.assertTrue(report['human_review_required'])
                    self.assertFalse(any(f['status'] == 'autonomy_boundary_violation' for f in report['findings']))
            write_event(project, event(human_review_required=False, review_status='not_reviewed'))
            result, report = run(project, 'agent-traces')
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(any(f['status'] == 'autonomy_boundary_violation' for f in report['findings']))
            for approval_status in ('required_pending', 'denied', 'approved'):
                with self.subTest(approval_status=approval_status):
                    receipt = {'intended_action': 'Record local update.', 'action_contract': 'local_write',
                               'side_effect_class': 'local_write', 'permission_scope': 'synthetic.txt',
                               'approval_required': True, 'approval_status': approval_status,
                               'approval_ref': 'synthetic-review-ref', 'tool_decision': 'allowed'}
                    write_event(project, event(action_receipt=receipt))
                    result, report = run(project, 'agent-traces')
                    self.assertEqual(result.returncode == 0, approval_status == 'approved')
                    result, grade = run(project, 'static-grader')
                    self.assertEqual(result.returncode == 0, approval_status == 'approved')
                    self.assertTrue(grade['human_review_required'])

    def test_configured_source_paths_and_transitive_input_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            project = generate(Path(temp), 'standard')
            governance_path = project / 'naos/policy/default_policy.yaml'
            governance = yaml.safe_load(governance_path.read_text())
            paths = governance['paths']
            paths.update(model_provider_policy='custom/models.yaml', model_provider_policy_report='reports/custom-models.json',
                         model_telemetry_evidence='custom/telemetry.yaml', model_telemetry_evidence_report='reports/custom-telemetry.json')
            governance_path.write_text(yaml.safe_dump(governance))
            (project / 'naos/custom').mkdir()
            model = project / 'naos/custom/models.yaml'
            (project / 'naos/model_provider_policy.yaml').rename(model)
            telemetry = project / 'naos/custom/telemetry.yaml'
            (project / 'naos/model_telemetry_evidence.yaml').rename(telemetry)
            declaration = yaml.safe_load(telemetry.read_text())
            declaration.update(enabled=True, telemetry_declared=True,
                               telemetry_sources=[{'path': 'usage.json', 'format': 'json'}])
            telemetry.write_text(yaml.safe_dump(declaration))
            record = {'record_id': 'SYNTHETIC', 'session_id': 'fixture-session', 'task_id': 'T-SYNTHETIC',
                      'model_role': 'planning', 'policy_ref': 'naos/custom/models.yaml#roles.planning'}
            usage = project / 'usage.json'
            usage.write_text(json.dumps([record]))
            current_reports(project, 'standard')
            _, clean = run(project, 'control-plane-review', 'standard')
            for name in ('model_provider_policy', 'model_telemetry_evidence'):
                self.assertEqual(clean[name + '_reconciliation']['summary']['routes_generated'], 0)
            # Mutating a local telemetry dependency, without changing declaration bytes,
            # must invalidate the consumed report.
            usage.write_text(json.dumps([dict(record, policy_exception=True)]))
            _, stale = run(project, 'control-plane-review', 'standard')
            self.assertGreater(stale['model_telemetry_evidence_reconciliation']['summary']['routes_generated'], 0)
            current_reports(project, 'standard')
            _, refreshed = run(project, 'control-plane-review', 'standard')
            reasons = refreshed['model_telemetry_evidence_reconciliation']['routes'][0]['model_telemetry_reason_codes']
            self.assertIn('policy_exception_declared', reasons)
            usage.write_text(json.dumps([record]))
            current_reports(project, 'standard')
            # Current model source takes precedence over a stale stored role report.
            models = yaml.safe_load(model.read_text())
            models['roles'].pop('planning')
            model.write_text(yaml.safe_dump(models))
            _, telemetry_report = run(project, 'model-telemetry', 'standard')
            self.assertTrue(any(f['reason_code'] == 'undeclared_model_role' for f in telemetry_report['findings']))
            # Agent role declarations are transitive policy inputs too.
            current_reports(project, 'standard')
            agent = project / '.github/agents/fixture.agent.md'
            agent.parent.mkdir(parents=True, exist_ok=True)
            agent.write_text('---\nnaos_model_role: nonexistent-fixture-role\n---\nSynthetic fixture.\n')
            _, stale = run(project, 'control-plane-review', 'standard')
            self.assertIn('model_provider_content_mismatch',
                          stale['model_provider_policy_reconciliation']['routes'][0]['model_provider_reason_codes'])

    def test_missing_reports_distinguish_optional_disabled_and_configured_sources(self):
        with tempfile.TemporaryDirectory() as temp:
            project = generate(Path(temp), 'assured')
            current_reports(project, 'assured')
            for name in ('model_provider_policy', 'model_telemetry_evidence'):
                (project / 'naos/reports' / (name + '.json')).unlink()
            _, report = run(project, 'control-plane-review')
            self.assertGreater(report['model_provider_policy_reconciliation']['summary']['routes_generated'], 0)
            self.assertEqual(report['model_telemetry_evidence_reconciliation']['status'], 'not_applicable')
            path = project / 'naos/model_telemetry_evidence.yaml'
            declaration = yaml.safe_load(path.read_text())
            declaration.update(enabled=True, telemetry_declared=True)
            path.write_text(yaml.safe_dump(declaration))
            _, report = run(project, 'control-plane-review')
            self.assertGreater(report['model_telemetry_evidence_reconciliation']['summary']['routes_generated'], 0)

    def test_imported_pending_event_remains_reviewable(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            (project / 'trace.jsonl').write_text(json.dumps(event()) + '\n')
            result, imported = run(project, 'harness-trace-import', 'assured', '--source', 'trace.jsonl', '--write-events')
            self.assertEqual(result.returncode, 0)
            records = yaml.safe_load((project / 'naos/agent_trace_events.yaml').read_text())['events']
            self.assertTrue(records[0]['human_review_required'])
            self.assertEqual(records[0]['review_status'], 'review_pending')
            result, validated = run(project, 'agent-traces')
            self.assertEqual(result.returncode, 0)
            self.assertEqual(validated['invalid_event_count'], 0)
            self.assertTrue(validated['human_review_required'])

    def test_self_check_refreshes_model_producers_before_reconciliation(self):
        with tempfile.TemporaryDirectory() as temp:
            project = generate(Path(temp), 'assured')
            current_reports(project, 'assured')
            change_sources(project)
            for name in ('model_provider_policy', 'model_telemetry_evidence'):
                (project / 'naos/reports' / (name + '.json')).write_text('{}')
            # Overall scaffold readiness may remain blocked for unrelated reasons.
            run(project, 'self-check')
            for name in ('model_provider_policy', 'model_telemetry_evidence'):
                report = json.loads((project / 'naos/reports' / (name + '.json')).read_text())
                self.assertEqual(report['schema'], 'naos.' + name + '.v1')
            report = json.loads((project / 'naos/reports/control_plane_review.json').read_text())
            self.assertTrue(report['human_review_required'])
            self.assertEqual(report['status'], 'blocked')
            for name in ('model_provider_policy', 'model_telemetry_evidence'):
                self.assertGreater(report[name + '_reconciliation']['summary']['routes_generated'], 0)


if __name__ == '__main__':
    unittest.main()
