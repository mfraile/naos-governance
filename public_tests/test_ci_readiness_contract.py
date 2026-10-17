"""Failure retention for the installed runner, with real gate/consumer probes."""
import contextlib
import importlib.util
import io
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(os.environ.get('NAOS_TEST_KIT', Path(__file__).resolve().parents[1])).resolve()
spec = importlib.util.spec_from_file_location('naos_ci_readiness_contract', ROOT / 'scripts/naos_ci_readiness.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class CiReadinessContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='naos readiness ü ')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / 'naos'
        self.state.mkdir()
        self.policy_path = self.root / 'policy.yaml'
        self.policy_path.write_text('paths: {}\n')
        self.receipt_path = self.state / 'reports/ci_readiness.json'
        self.seen = []

    def require_native_symlink(self):
        probe = self.root / 'symlink-privilege-probe'
        try:
            probe.symlink_to(self.policy_path)
        except OSError as exc:
            if os.name == 'nt' and getattr(exc, 'winerror', None) == 1314:
                self.skipTest('This native symlink subcase requires Windows symlink privilege.')
            raise
        else:
            probe.unlink()

    def execute(self, fake, profile='lite', ac_validator='scripts/validators/validate_test_ac_references.py'):
        with patch.object(runner.subprocess, 'run', side_effect=fake), contextlib.redirect_stdout(io.StringIO()):
            code = runner.run_chain(self.root, profile, 'naos', ac_validator,
                                    policy_path=str(self.policy_path))
        receipt = json.loads(self.receipt_path.read_text())
        schema = json.loads((ROOT / 'schemas/naos/ci_readiness.schema.json').read_text())
        Draft202012Validator(schema).validate(receipt)
        return code, receipt

    def success(self, argv, **kwargs):
        command = argv[2]
        self.seen.append(command)
        if command in ('gate-status', 'gate-evaluate'):
            path = Path(argv[argv.index('--output') + 1])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({'schema': 'naos.gate_status.v1', 'run': 'new'}))
        key = {'dashboard': 'dashboard_summary_report',
               'secure-coding-reporting': 'secure_coding_reporting_report',
               'evidence-pack': 'evidence_pack_report'}.get(command)
        if key:
            policy = runner.load_policy(str(self.policy_path), 'naos', self.root)
            path = runner.output_paths(self.root, 'naos', policy)[key]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({'secure_coding_reporting': {}}))
        return subprocess.CompletedProcess(argv, 0)

    def test_each_command_runs_and_zero_exits_require_both_new_gate_files(self):
        code, receipt = self.execute(self.success)
        self.assertEqual(code, 0)
        self.assertEqual(receipt['status'], 'pass')
        self.assertTrue(all(receipt['gate_outputs_present'].values()))
        self.assertEqual(self.seen[-5:], ['evidence-pack', 'dashboard', 'secure-coding-reporting',
                                         'sarif-export', 'pr-governance-summary'])
        self.assertNotIn('naos', [record['argv'][0] for record in receipt['commands']])

    def test_early_and_consumer_failures_remain_failed_after_later_success(self):
        for failing in ('claims', 'gate-evaluate', 'dashboard'):
            self.seen.clear()
            def fake(argv, **kwargs):
                result = self.success(argv, **kwargs)
                if argv[2] == failing:
                    result.returncode = 2 if failing == 'gate-evaluate' else 1
                return result
            with self.subTest(failing=failing):
                code, receipt = self.execute(fake)
                self.assertEqual(code, 1)
                self.assertEqual(self.seen[-1], 'pr-governance-summary')
                record = next(item for item in receipt['commands'] if item['argv'][2] == failing)
                self.assertEqual(record['returncode'], 2 if failing == 'gate-evaluate' else 1)
                self.assertEqual(record['outcome'], 'nonzero_exit')

    def test_launch_failure_and_timeout_are_distinct_and_do_not_keep_old_gate_success(self):
        for error, expected in ((FileNotFoundError('synthetic missing tool'), 'launch_error'),
                                (subprocess.TimeoutExpired('synthetic', 1), 'timeout')):
            self.seen.clear()
            for name in ('gate_status.json', 'gate_evaluation.json'):
                path = self.state / 'reports' / name
                path.parent.mkdir(exist_ok=True)
                path.write_text(json.dumps({'schema': 'naos.gate_status.v1', 'run': 'old'}))
            def fake(argv, **kwargs):
                if argv[2] == 'gate-status':
                    raise error
                if argv[2] == 'evidence-pack':
                    self.assertFalse((self.state / 'reports/gate_status.json').exists())
                return self.success(argv, **kwargs)
            with self.subTest(error=expected):
                code, receipt = self.execute(fake)
                self.assertEqual(code, 1)
                self.assertEqual(self.seen[-1], 'pr-governance-summary')
                record = next(item for item in receipt['commands'] if item['argv'][2] == 'gate-status')
                self.assertIsNone(record['returncode'])
                self.assertEqual(record['outcome'], expected)
                self.assertFalse(receipt['gate_outputs_present']['gate-status'])

    def test_custom_policy_gate_paths_match_persisted_outputs(self):
        self.policy_path.write_text(yaml.safe_dump({'paths': {
            'reports_dir': 'custom-reports', 'gate_status_report': 'status-custom.json',
            'gate_evaluation_report': 'evaluation-custom.json',
        }}))
        self.receipt_path = self.state / 'custom-reports/ci_readiness.json'
        code, receipt = self.execute(self.success)
        self.assertEqual(code, 0)
        self.assertTrue((self.state / 'custom-reports/status-custom.json').exists())
        self.assertTrue((self.state / 'custom-reports/evaluation-custom.json').exists())
        for record in receipt['commands']:
            self.assertIn(str(self.policy_path), record['argv'])

    def test_sink_collision_config_alias_and_symlink_preserve_sentinels(self):
        policy = runner.load_policy(str(self.policy_path), 'naos', self.root)
        for changes in ({'gate_evaluation_report': 'gate_status.json'},
                        {'reports_dir': '.', 'gate_status_report': 'capability_state.yaml'},
                        {'reports_dir': 'reports', 'capability_state': 'reports/gate_status.json'}):
            candidate = {**policy, 'paths': {**policy['paths'], **changes}}
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner.gate_sinks(self.root, 'naos', candidate, str(self.policy_path))
        reports = self.state / 'reports'
        reports.mkdir()
        sentinel = self.root / 'outside.json'
        sentinel.write_text('unchanged')
        with self.subTest(native_symlink=True):
            self.require_native_symlink()
            (reports / 'gate_status.json').symlink_to(sentinel)
            with self.assertRaises(ValueError):
                runner.gate_sinks(self.root, 'naos', policy, str(self.policy_path))
        self.assertEqual(sentinel.read_text(), 'unchanged')
        self.assertEqual(self.policy_path.read_text(), 'paths: {}\n')

    def test_cross_report_aliases_refuse_before_removing_previous_gate_outputs(self):
        reports = self.state / 'reports'
        reports.mkdir()
        sentinel = reports / 'gate_status.json'
        previous = json.dumps({'schema': 'naos.gate_status.v1', 'run': 'old'})
        for changes in ({'dashboard_summary_report': 'gate_status.json'},
                        {'claims_report': 'ci_readiness.json'}):
            sentinel.write_text(previous)
            self.policy_path.write_text(yaml.safe_dump({'paths': changes}))
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, 'aliases another report'):
                self.execute(self.success)
            self.assertEqual(sentinel.read_text(), previous)
            self.assertEqual(self.seen, [])

    def test_zero_exits_without_required_consumer_outputs_cannot_pass(self):
        def fake(argv, **kwargs):
            if argv[2] in ('gate-status', 'gate-evaluate'):
                path = Path(argv[argv.index('--output') + 1])
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps({'schema': 'naos.gate_status.v1'}))
            return subprocess.CompletedProcess(argv, 0)
        code, receipt = self.execute(fake)
        self.assertEqual(code, 1)
        self.assertFalse(any(receipt['output_checks'].values()))

    def test_remapped_validator_is_executed_for_standard(self):
        validator = self.root / '.naos-tools/validators/validate_test_ac_references.py'
        validator.parent.mkdir(parents=True)
        validator.write_text('# Explicit synthetic adopter validator fixture.\n', encoding='utf-8')
        def fake(argv, **kwargs):
            if len(argv) == 2:
                self.assertEqual(Path(argv[1]), (self.root / '.naos-tools/validators/validate_test_ac_references.py').resolve())
                self.seen.append('ac-validator')
                return subprocess.CompletedProcess(argv, 0)
            return self.success(argv, **kwargs)
        code, receipt = self.execute(fake, 'standard', '.naos-tools/validators/validate_test_ac_references.py')
        self.assertEqual(code, 0)
        self.assertEqual(self.seen[0], 'ac-validator')
        self.assertEqual(receipt['ac_validator']['authority'], 'adopter_override')
        self.assertEqual(receipt['ac_validator']['sha256'], hashlib.sha256(validator.read_bytes()).hexdigest())

    def seed_prior_gates(self):
        reports = self.state / 'reports'
        reports.mkdir(exist_ok=True)
        for name in ('gate_status.json', 'gate_evaluation.json'):
            (reports / name).write_text(json.dumps({'schema': 'naos.gate_status.v1', 'run': 'prior'}))

    def test_real_l3_maturity_can_consume_prepared_gates_before_their_producers(self):
        # Dedicated synthetic manual-evidence capability: this proves ordering,
        # not claims-report acceptance. Gate and maturity reports are real outputs.
        actual = subprocess.run
        cli = [os.sys.executable, str(ROOT / 'cli.py')]
        caps = self.root / 'capabilities'
        caps.mkdir()
        evidence_ref = 'naos/ordering-evidence.txt'
        (self.root / evidence_ref).write_text('Synthetic ordering evidence only.\n', encoding='utf-8')
        contract = {
            'id': 'CAP-SYNTHETIC-GATE-ORDERING', 'name': 'Synthetic Gate Ordering',
            'default_maturity': 'L0', 'gatekeepers': ['G99'],
            'profiles': {'assured': {'target_maturity': 'L3', 'enforcement': 'blocking'}},
            'known_limitations': ['Fixture only; no actual claims acceptance is established.'],
        }
        (caps / 'synthetic_gate_ordering.yaml').write_text(yaml.safe_dump(contract))
        (self.state / 'gatekeepers.yaml').write_text(yaml.safe_dump({
            'version': '1.0', 'profile_order': ['quickstart', 'lite', 'standard', 'assured'],
            'gates': [{
                'id': 'G99', 'name': 'Synthetic Ordering Gate',
                'purpose': 'Exercise prior-gate consumption and producer invalidation only.',
                'profile_behavior': {}, 'required_inputs': [evidence_ref],
                'required_evidence': [evidence_ref], 'validators': [], 'outputs': [],
                'severity_by_profile': {'quickstart': 'advisory', 'lite': 'warning',
                                        'standard': 'required', 'assured': 'blocking'},
                'maturity_dependency': {'capability': contract['id'], 'minimum_maturity': 'L1'},
                'known_limitations': ['Synthetic fixture only.'],
            }],
        }))
        (self.state / 'capability_state.yaml').write_text(yaml.safe_dump({'capabilities': [{
            'capability_id': contract['id'], 'enabled': True,
            'current_maturity': 'L3', 'target_maturity': 'L3',
            'owner_1lod': 'synthetic-delivery', 'owner_2lod': 'synthetic-review',
            'accountable_reviewer': 'synthetic-test-reviewer',
            'evidence_refs': [evidence_ref],
            'freshness_window_days': 30, 'waivers': [],
        }]}))
        for command in ('gate-status', 'gate-evaluate'):
            args = cli + [command, '--profile', 'assured', '--policy', str(self.policy_path)]
            filename = 'gate_status.json' if command == 'gate-status' else 'gate_evaluation.json'
            args += ['--output', str(self.state / 'reports' / filename)]
            result = actual(args, cwd=self.root, capture_output=True, text=True)
            self.assertNotIn('Traceback', result.stderr)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        def maturity(argv):
            result = actual(argv, cwd=self.root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            data = json.loads((self.state / 'reports/capability_maturity.json').read_text())
            self.assertEqual(data['capabilities'][0]['evaluated_status'], 'ready')
            self.assertEqual(data['capabilities'][0]['missing_evidence'], [])
            self.assertEqual(data['capabilities'][0]['capability_id'], contract['id'])
            self.assertEqual(data['capabilities'][0]['evidence_basis'], 'manual')
            self.assertEqual(data['capabilities'][0]['unresolved_evidence'], [])
            return result
        maturity(cli + ['capability-maturity', '--profile', 'assured', '--policy', str(self.policy_path)])
        def fake(argv, **kwargs):
            command = argv[2] if len(argv) > 2 else 'ac-validator'
            if command == 'capability-maturity':
                self.seen.append(command)
                return maturity(argv)
            if command in ('gate-status', 'gate-evaluate'):
                self.assertFalse(Path(argv[argv.index('--output') + 1]).exists())
            if command == 'ac-validator':
                return subprocess.CompletedProcess(argv, 0)
            return self.success(argv, **kwargs)
        code, receipt = self.execute(fake, profile='assured', ac_validator=None)
        self.assertEqual(code, 0)
        # The additional design/UI/failure-observation/AI-budget producers are
        # part of the current chain, before downstream evidence consumers.
        self.assertEqual(len(receipt['commands']), 50)
        commands = [item['argv'][2] if len(item['argv']) > 2 else 'ac-validator'
                    for item in receipt['commands']]
        for command in ('design-traceability', 'ui-experience-quality',
                        'failure-mode-observations', 'ai-surface-budget'):
            self.assertIn(command, commands)
            self.assertLess(commands.index(command), commands.index('evidence-pack'))
        self.assertLess(commands.index('opencode-config-hygiene'), commands.index('control-plane-review'))

    def test_failed_gate_producer_cannot_retain_prior_success(self):
        self.seed_prior_gates()
        def fake(argv, **kwargs):
            if argv[2] == 'claims':
                self.assertTrue((self.state / 'reports/gate_status.json').is_file())
            if argv[2] == 'gate-status':
                self.assertFalse((self.state / 'reports/gate_status.json').exists())
                raise FileNotFoundError('synthetic missing gate executable')
            return self.success(argv, **kwargs)
        code, receipt = self.execute(fake)
        self.assertEqual(code, 1)
        self.assertFalse(receipt['gate_outputs_present']['gate-status'])
        self.assertEqual(self.seen[-1], 'pr-governance-summary')

    def test_midchain_gate_link_and_policy_alias_replacement_refuses_cleanup(self):
        for replacement in ('symlink', 'hardlink', 'policy-alias'):
            with self.subTest(replacement=replacement):
                self.setUp()
                if replacement == 'symlink':
                    self.require_native_symlink()
                self.seed_prior_gates()
                gate = self.state / 'reports/gate_status.json'
                sentinel = self.root / 'sentinel.json'
                original = json.dumps({'schema': 'naos.gate_status.v1', 'run': 'sentinel'})
                sentinel.write_text(original)
                def fake(argv, **kwargs):
                    if argv[2] == 'claims':
                        if replacement == 'policy-alias':
                            self.policy_path.write_text(yaml.safe_dump({'paths': {'claims_report': 'gate_status.json'}}))
                        else:
                            gate.unlink()
                            if replacement == 'symlink':
                                gate.symlink_to(sentinel)
                            else:
                                os.link(sentinel, gate)
                    try:
                        return self.success(argv, **kwargs)
                    except ValueError:
                        # Real subprocess path-validation refusal is a nonzero exit.
                        return subprocess.CompletedProcess(argv, 2)
                code, receipt = self.execute(fake)
                self.assertEqual(code, 1)
                failed = next(x for x in receipt['commands'] if x['argv'][2] == 'gate-status')
                self.assertEqual(failed['outcome'], 'cleanup_error')
                self.assertIsNone(failed['returncode'])
                self.assertNotIn('gate-status', self.seen)
                self.assertFalse(receipt['gate_outputs_present']['gate-status'])
                self.assertEqual(sentinel.read_text(), original)
                self.assertEqual(self.seen[-1], 'pr-governance-summary')

    def test_real_invalid_gate_inputs_reach_actual_consumers(self):
        (self.state / 'gatekeepers.yaml').write_text('gates: [\n')
        actual = subprocess.run
        real_commands = {'gate-status', 'gate-evaluate', 'evidence-pack', 'dashboard',
                         'sarif-export', 'pr-governance-summary', 'secure-coding-reporting'}
        def selected(argv, **kwargs):
            if argv[2] in real_commands:
                result = actual(argv, text=True, capture_output=True, **kwargs)
                self.assertNotIn('Traceback', result.stderr, result.stderr)
                return result
            return subprocess.CompletedProcess(argv, 0)
        code, receipt = self.execute(selected)
        self.assertEqual(code, 1)
        for name in ('gate-status', 'gate-evaluate'):
            path = Path(receipt['gate_outputs'][name])
            self.assertEqual(json.loads(path.read_text())['status'], 'invalid_input')
            record = next(item for item in receipt['commands'] if item['argv'][2] == name)
            self.assertEqual(record['returncode'], 2)
        for filename in ('dashboard_summary.json', 'pr_governance_summary.json'):
            self.assertIn('invalid_input', (self.state / 'reports' / filename).read_text())
        sarif = json.loads((self.state / 'reports/naos_findings.sarif').read_text())
        adverse = [item for run in sarif['runs'] for item in run['results']
                   if item['properties']['naos_source_finding_id'] == 'gate_input_invalid']
        self.assertTrue(adverse)
        self.assertTrue(all(item['level'] == 'error' for item in adverse))
        self.assertTrue(all(item['properties']['naos_source_report'] == 'gate_evaluation'
                            for item in adverse))
        self.assertIn('invalid_input', (self.state / 'evidence/evidence_pack.json').read_text())


if __name__ == '__main__':
    unittest.main()
