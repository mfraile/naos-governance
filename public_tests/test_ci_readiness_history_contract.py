"""Real dashboard input preservation across UTC midnight; finite CI routing.

The CI harness substitutes unrelated producers/gates and proof verdicts. It
checks the history's real byte-bound inventory, not full workflow acceptance.
"""
import contextlib
from datetime import datetime, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(os.environ.get('NAOS_TEST_KIT', Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(ROOT / 'scripts'))
import naos_ci_readiness as ci
import naos_self_check_dependency_resolution as resolution

spec = importlib.util.spec_from_file_location(
    'history_readiness_dashboard', ROOT / 'scripts/workflows/generate_naos_dashboard.py')
dashboard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dashboard)


class DashboardHistoryContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='naos history ü ')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / 'naos/reports').mkdir(parents=True)
        (self.root / 'specs').mkdir()
        (self.root / 'specs/03-requirements.md').write_text(
            '## FR-001: First requirement\n**Status**: Implemented\n'
            '## FR-002: Second requirement\n**Status**: Planned\n', encoding='utf-8')
        self.history = self.root / 'naos/TASK_PROGRESS_HISTORY.csv'
        self.day = 10
        owner = self

        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                current = cls(2026, 10, owner.day, 12, tzinfo=timezone.utc)
                return current.astimezone(tz) if tz else current.replace(tzinfo=None)

        self.clock = Clock

    def render(self, *options, profile='lite'):
        with contextlib.chdir(self.root), patch.object(dashboard, 'datetime', self.clock), \
                patch.object(sys, 'argv', ['dashboard', '--profile', profile,
                                         '--naos-root', 'naos', *options]), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            return dashboard.main()

    def history_binding(self, policy):
        return resolution._input_inventory(self.root, 'naos', policy)[
            'project:naos/TASK_PROGRESS_HISTORY.csv']

    def test_final_render_preserves_history_across_midnight_and_default_still_records(self):
        self.render()
        original = self.history.read_bytes()
        self.assertIn(b'2026-10-10', original)
        policy = ci.load_policy(None, 'naos', self.root)
        binding = self.history_binding(policy)
        self.day = 11
        code = self.render('--no-progress-history')
        summary = (self.root / 'naos/reports/dashboard_summary.json').read_bytes()
        self.assertEqual(self.history.read_bytes(), original)
        self.assertEqual(self.history_binding(policy), binding)
        self.assertTrue((self.root / 'naos/DASHBOARD.md').is_file())
        self.assertEqual(self.render(), code)
        self.assertEqual((self.root / 'naos/reports/dashboard_summary.json').read_bytes(), summary)
        self.assertIn(b'2026-10-11', self.history.read_bytes())
        self.assertNotEqual(self.history_binding(policy), binding)

    def test_preserve_mode_never_creates_missing_history(self):
        self.render('--no-progress-history')
        self.assertFalse(self.history.exists())
        self.assertTrue((self.root / 'naos/reports/dashboard_summary.json').is_file())

    def pipeline(self, profile, *, legacy_final_append=False, tamper=False, finalized=True):
        policy = ci.load_policy(None, 'naos', self.root)
        outputs = ci.output_paths(self.root, 'naos', policy)
        for key in ('dashboard_summary_report', 'secure_coding_reporting_report', 'evidence_pack_report'):
            outputs[key].parent.mkdir(parents=True, exist_ok=True)
            outputs[key].write_text('{"secure_coding_reporting":{}}', encoding='utf-8')
        sealed = {}
        calls = []

        def execute(argv, **kwargs):
            calls.append(argv)
            if len(argv) < 3:  # Unrelated AC-validator producer in this harness.
                return subprocess.CompletedProcess(argv, 0)
            command = argv[2]
            if command == 'dashboard':
                options = argv[3:]
                if legacy_final_append:
                    options = [x for x in options if x != '--no-progress-history']
                with contextlib.chdir(self.root), patch.object(dashboard, 'datetime', self.clock), \
                        contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()):
                    dashboard.configure_naos_root('naos')
                    dashboard.render_dashboard(
                        record_progress_history='--no-progress-history' not in options)
                return subprocess.CompletedProcess(argv, 0)
            if command in ('gate-status', 'gate-evaluate'):
                path = Path(argv[argv.index('--output') + 1])
                path.write_text(json.dumps({'schema': 'naos.gate_status.v1',
                                            'invocation': len(calls)}), encoding='utf-8')
            if '--finalize-dependencies' in argv:
                sealed['history'] = self.history_binding(policy)
                self.day = 11
                if tamper:
                    self.history.write_bytes(self.history.read_bytes().replace(b'50.00', b'49.00'))
            return subprocess.CompletedProcess(argv, 0)

        def verify(*args, **kwargs):
            digest = self.history_binding(policy)
            return {'status': 'resolved' if digest == sealed.get('history') else 'unresolved'}

        with patch.object(ci, 'PRODUCERS', ()), patch.object(ci, 'CONSUMERS', (('dashboard',),)), \
                patch.object(ci.subprocess, 'run', side_effect=execute), \
                patch.object(ci, 'project_gate_readiness', return_value={
                    'required_readiness': 'ready', 'readiness': 'ready'}), \
                patch.object(ci, '_assured_maturity_cycle'), \
                patch.object(ci, '_reporting_source_binding', return_value='fixture-source-binding'), \
                patch.object(resolution, 'verify_published_resolution', side_effect=verify), \
                contextlib.redirect_stdout(io.StringIO()):
            code = ci.run_chain(self.root, profile, 'naos', finalize_dependencies=finalized)
        return code, json.loads((self.root / 'naos/reports/ci_readiness.json').read_text()), calls

    def test_finite_ci_keeps_real_history_binding_on_each_finalized_profile(self):
        for profile in ('lite', 'standard', 'assured'):
            with self.subTest(profile=profile):
                self.day = 10
                self.history.unlink(missing_ok=True)
                code, receipt, calls = self.pipeline(profile)
                self.assertEqual(code, 0)
                self.assertTrue(receipt['output_checks']['complete_dependency_resolution'])
                renders = [x for x in calls if len(x) > 2 and x[2] == 'dashboard']
                self.assertEqual(len(renders), 2)
                self.assertNotIn('--no-progress-history', renders[0])
                self.assertIn('--no-progress-history', renders[1])

    def test_legacy_post_proof_append_and_authored_history_edits_still_fail(self):
        for options in ({'legacy_final_append': True}, {'tamper': True}):
            with self.subTest(options=options):
                self.day = 10
                self.history.unlink(missing_ok=True)
                code, receipt, _ = self.pipeline('standard', **options)
                self.assertEqual(code, 1)
                self.assertFalse(receipt['output_checks']['complete_dependency_resolution'])

    def test_ordinary_collection_keeps_default_dashboard_recording(self):
        _, _, calls = self.pipeline('lite', finalized=False)
        renders = [x for x in calls if len(x) > 2 and x[2] == 'dashboard']
        self.assertEqual(len(renders), 1)
        self.assertNotIn('--no-progress-history', renders[0])
        self.assertTrue(self.history.exists())


if __name__ == '__main__':
    unittest.main()
