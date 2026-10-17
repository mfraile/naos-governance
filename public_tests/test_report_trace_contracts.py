#!/usr/bin/env python3
"""Portable report and trace contract regressions; all writes use disposable projects.

Set NAOS_TEST_KIT for kit resources and NAOS_TEST_INSTALLED=1 to test a wheel.
"""
from __future__ import annotations

import json
import hashlib
import importlib.util
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
            run(project, 'self-check', 'assured', '--refresh')
            for name in ('model_provider_policy', 'model_telemetry_evidence'):
                report = json.loads((project / 'naos/reports' / (name + '.json')).read_text())
                self.assertEqual(report['schema'], 'naos.' + name + '.v1')
            report = json.loads((project / 'naos/reports/control_plane_review.json').read_text())
            self.assertTrue(report['human_review_required'])
            self.assertEqual(report['status'], 'blocked')
            for name in ('model_provider_policy', 'model_telemetry_evidence'):
                self.assertGreater(report[name + '_reconciliation']['summary']['routes_generated'], 0)


class IncompleteScanContracts(unittest.TestCase):
    def test_human_summary_exposes_input_state_without_changing_json_or_policy(self):
        cases = [('empty', 'not_configured', 0, 0, 0), ('valid', 'complete', 1, 1, 0),
                 ('invalid', 'incomplete', 1, 0, 1), ('mixed', 'incomplete', 2, 1, 1)]
        for command in ('duplicate-function-hygiene', 'test-quality-hygiene'):
            for profile in ('standard', 'assured'):
                for case, state, selected, scanned, failed in cases:
                    with self.subTest(command=command, profile=profile, case=case), tempfile.TemporaryDirectory() as temporary:
                        project = Path(temporary) / 'project with spaces café'
                        (project / 'tests').mkdir(parents=True)
                        if case in {'valid', 'mixed'}:
                            (project / 'tests/test_valid.py').write_text('def test_valid():\n    assert 2 + 2 == 4\n', encoding='utf-8')
                        if case in {'invalid', 'mixed'}:
                            (project / 'tests/broken.py').write_text('def broken(:\n', encoding='utf-8')
                        output = project / 'report.json'
                        args = ['--profile', profile, '--output', str(output)]
                        if profile == 'assured':
                            args.append('--strict')
                        human = subprocess.run([*COMMAND, command, *args], cwd=project, text=True, capture_output=True, timeout=30)
                        self.assertEqual(human.returncode, int(profile == 'assured' and failed > 0), human.stderr)
                        self.assertIn(f'scan inputs: {state}; selected {selected}, scanned {scanned}, failed {failed}', human.stdout)
                        saved = json.loads(output.read_text(encoding='utf-8'))
                        machine, report = execute(project, command, *args, '--json')
                        self.assertEqual(machine.returncode, human.returncode, machine.stderr)
                        saved.pop('generated_at', None)
                        report.pop('generated_at', None)
                        self.assertEqual(saved, report)
        # Secret and dependency controls also expose selected-input coverage.
        with tempfile.TemporaryDirectory() as temporary:
            for command in ('secret-hygiene', 'dependency-integrity'):
                result = subprocess.run([*COMMAND, command, '--profile', 'quickstart'], cwd=temporary,
                                        text=True, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('scan inputs: not_configured; selected 0, scanned 0, failed 0', result.stdout)
            project = Path(temporary)
            legacy = project / 'legacy.json'
            legacy.write_text(json.dumps({'status': 'pass', 'summary': {},
                                          'mappings': [{'source': 'a.py', 'mapped': True}]}), encoding='utf-8')
            args = ['--profile', 'assured', '--strict', '--map-file', str(legacy)]
            human = subprocess.run([*COMMAND, 'test-evidence', *args], cwd=project,
                                   text=True, capture_output=True, timeout=30)
            self.assertEqual(human.returncode, 0, human.stderr)
            self.assertIn('coverage inputs: unknown', human.stdout)
            machine, report = execute(project, 'test-evidence', *args, '--json')
            self.assertEqual(machine.returncode, human.returncode, machine.stderr)
            self.assertEqual(report['status'], 'pass')
            self.assertEqual(report['summary']['coverage_input_status'], 'unknown')
            self.assertTrue(report['known_gaps'])

    def test_unreadable_discovered_test_is_not_clean_or_filename_evidence(self):
        from unittest.mock import patch

        sys.path.insert(0, str(ROOT / 'scripts'))
        import naos_test_evidence_map as mapper
        from naos_policy import load_policy

        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            (project / 'src').mkdir()
            (project / 'tests').mkdir()
            (project / 'src/app.py').write_text('value = 1\n')
            denied = project / 'tests/test_app.py'
            denied.write_text('import app\n')
            original = mapper.tokenize.open

            def read(path):
                if Path(path) == denied:
                    raise PermissionError('synthetic private OS detail')
                return original(path)

            with patch.object(mapper.tokenize, 'open', read):
                mapping = mapper.build_map(project, 'assured', [str(project / 'src')],
                                           [str(project / 'tests')], [], load_policy(root=ROOT))
            self.assertEqual(mapping['status'], 'mapped_with_gaps')
            self.assertEqual(mapping['summary']['mapped_sources'], 0)
            self.assertEqual(mapping['summary']['test_inputs_failed'], 1)
            self.assertEqual(mapping['mappings'][0]['tests'], [])
            self.assertEqual(mapping['mappings'][0]['candidate_tests'], [])
            self.assertNotIn('synthetic private OS detail', json.dumps(mapping))
            with (
                patch.object(mapper.tokenize, 'open', side_effect=RuntimeError('unexpected reader defect')),
                self.assertRaisesRegex(RuntimeError, 'unexpected reader defect'),
            ):
                mapper.build_map(project, 'assured', [str(project / 'src')],
                                 [str(project / 'tests')], [], load_policy(root=ROOT))
            map_file = project / 'naos/test_evidence/source_to_test_map.json'
            map_file.parent.mkdir(parents=True)
            map_file.write_text(json.dumps(mapping))
            result, health = run(project, 'test-evidence', 'assured', '--map-file', str(map_file))
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(health['summary']['test_input_status'], 'incomplete')
            self.assertIn('test_input_unreadable', {item['status'] for item in health['findings']})
            execute(project, 'dashboard', '--profile', 'assured', '--json')
            self.assertIn('| Test evidence inputs | selected 1; read 0; failed 1 | incomplete |',
                          (project / 'naos/DASHBOARD.md').read_text())

    def test_incomplete_inputs_survive_cli_dashboard_pack_and_sarif(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            (project / 'naos').mkdir()
            (project / 'src').mkdir()
            (project / 'tests').mkdir()
            (project / 'src/app.py').write_text('value = 1\n')
            # Mapping requires an AST import declaration; filenames alone are candidates.
            (project / 'tests/test_app.py').write_text('import app\n\ndef test_app():\n    assert 2 + 2 == 4\n')
            (project / 'tests/broken.py').write_text('def broken(:\n')
            (project / 'coverage.json').write_text('{broken')
            producer_reports = {}
            for command in ('duplicate-function-hygiene', 'test-quality-hygiene'):
                result, report = run(project, command)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(report['status'], 'blocked')
                self.assertEqual(report['summary']['files_failed'], 1)
                self.assertTrue(report['known_gaps'])
                producer_reports[command.replace('-', '_')] = report
            result, mapping = execute(project, 'test-evidence-map', '--profile', 'assured', '--json')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(mapping['status'], 'mapped_with_gaps')
            self.assertEqual(mapping['summary']['unmapped_sources'], 0)
            result, health = run(project, 'test-evidence')
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(health['summary']['coverage_inputs_failed'], 1)
            self.assertEqual(health['summary']['test_inputs_failed'], 1)
            self.assertEqual({item['status'] for item in health['findings']},
                             {'coverage_input_parse_error', 'test_input_parse_error'})
            producer_reports['test_evidence_health'] = health
            result, dashboard = execute(project, 'dashboard', '--profile', 'assured', '--json')
            self.assertEqual(result.returncode, 1, result.stderr)
            markdown = (project / 'naos/DASHBOARD.md').read_text()
            self.assertIn('| Coverage inputs | selected 1; parsed 0; failed 1;', markdown)
            self.assertIn('| Test scan inputs | selected 2; scanned 1; failed 1 | incomplete |', markdown)
            result, pack = execute(project, 'evidence-pack', '--profile', 'assured', '--json')
            artifact = pack['artifacts']['test_evidence_health_report']
            self.assertEqual(pack['schema'], 'naos.evidence_pack.v2')
            self.assertEqual(artifact['status'], 'present')
            self.assertNotIn('data', artifact)
            self.assertEqual(artifact['schema'], 'naos.report_source_reference.v1')
            self.assertEqual(artifact['composition_kind'], 'source_reference')
            self.assertEqual(artifact['detail_availability'], 'source_bound')
            source = project / artifact['source_reference']
            raw = source.read_bytes()
            self.assertEqual(len(raw), artifact['source_size_bytes'])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), artifact['source_sha256'])
            spec = importlib.util.spec_from_file_location(
                'public_trace_report_composition', ROOT / 'scripts/naos_report_composition.py',
            )
            composition = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(composition)
            self.assertEqual(Path(pack['project_root']), project.resolve())
            detail = composition.read_collection_entry(artifact, Path(pack['project_root']))
            self.assertEqual(detail['detail_availability'], 'available', detail)
            self.assertEqual(detail['requirement_outcome'], 'unresolved')
            self.assertEqual(detail['data'], json.loads(raw))
            self.assertEqual(detail['data']['status'], 'blocked')
            self.assertEqual(detail['data']['findings'][0]['status'], 'coverage_input_parse_error')
            sarif_path = project / 'findings.sarif'
            result, summary = execute(project, 'sarif-export', '--profile', 'assured', '--output', str(sarif_path), '--json')
            self.assertEqual(result.returncode, 0, result.stderr)
            sarif = json.loads(sarif_path.read_text())
            failures = sarif['runs'][0]['results']
            self.assertEqual(len(failures), 4)
            # Compare original producer IDs; SARIF ruleId adds a namespace and hash.
            self.assertEqual({(item['properties']['naos_source_report'], item['properties']['naos_source_finding_id'])
                              for item in failures},
                             {(source, finding['id']) for source, report in producer_reports.items()
                              for finding in report['findings']})
            self.assertTrue(all(item['level'] == 'error' and item['locations'] and item['properties']['naos_human_review_required'] for item in failures))
            (project / 'tests/deep_duplicate.py').write_text(
                'def deep(value):\n    return ' + '+'.join(['value'] * 400) + '\n', encoding='utf-8')
            result, report = run(project, 'duplicate-function-hygiene')
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(report['summary']['analysis_errors'], 1)
            analysis_ids = {item['id'] for item in report['findings'] if item['status'] == 'analysis_error'}
            execute(project, 'sarif-export', '--profile', 'assured', '--output', str(sarif_path), '--json')
            sarif = json.loads(sarif_path.read_text())
            analysis = [item for item in sarif['runs'][0]['results']
                        if item['properties']['naos_source_finding_id'] in analysis_ids]
            self.assertEqual(len(analysis), 1)
            self.assertEqual(analysis[0]['properties']['naos_source_report'], 'duplicate_function_hygiene')
            self.assertEqual(analysis[0]['level'], 'error')
            self.assertTrue(analysis[0]['locations'])


if __name__ == '__main__':
    unittest.main()
