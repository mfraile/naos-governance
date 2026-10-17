"""Synthetic opt-in context integrity acceptance; no host/model or memory calls."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(os.environ.get('NAOS_TEST_KIT_ROOT') or Path(__file__).resolve().parents[1]).resolve()
sys.path.insert(0, str(ROOT / 'scripts'))
import naos_task_context_integrity as integrity  # noqa: E402
import naos_ac_completion_evidence as completion  # noqa: E402
from naos_policy import load_policy, write_report, exit_code_for_summary, finding_counts, severity_for_profile  # noqa: E402
from naos_session_identity import ensure_session_context  # noqa: E402

ORIGIN = 'https://example.test/synthetic/project.git'
SESSION = 'synthetic-session-001'


class ContextIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        for path in ['naos/active', 'naos/reports', 'specs', 'src', 'tests']:
            (self.root / path).mkdir(parents=True, exist_ok=True)
        self.write('specs/requirements.md', b'# Requirements\n\nAC-001-1: selected constraint\n')
        self.write('naos/active/T-123.md', b'# T-123\n\n## Acceptance Criteria\n- [ ] bounded context\n')
        self.write('naos/TASK_REGISTRY.yaml', b'tasks:\n  - id: T-123\n    status: active\n')
        self.write('tests/test_subject.py', b'def test_subject():\n    assert True\n')
        self.write('src/worker.py', b'def worker():\n    return 1\n')
        self.rules = self.root / 'naos/task_context_pack_rules.yaml'
        self.rules.write_bytes((ROOT / 'templates/structural-seeds/naos/task_context_pack_rules.yaml').read_bytes())
        self.git('init', '-q')
        self.git('config', 'user.name', 'Synthetic Operator')
        self.git('config', 'user.email', 'operator@example.test')
        self.git('remote', 'add', 'origin', ORIGIN)
        self.git('add', 'specs', 'tests')
        self.git('commit', '-q', '-m', 'synthetic base')
        base = self.git('rev-parse', 'HEAD')
        self.git('add', 'src')
        self.git('commit', '-q', '-m', 'synthetic subject')
        self.repo_binding = {'base_commit': base, 'subject_commit': self.git('rev-parse', 'HEAD'),
                             'subject_tree': self.git('rev-parse', 'HEAD^{tree}')}
        self.policy = load_policy(str(ROOT / 'policies/default_policy.yaml'), 'naos', self.root)
        with patch.dict(os.environ, {'NAOS_OPERATOR_ID': 'synthetic-operator'}):
            ensure_session_context(self.root, 'naos', self.policy, 'standard', SESSION, task_id='T-123')
        self.pack = {'schema': 'naos.task_context_pack.v1', 'task_id': 'T-123', 'profile': 'standard', 'naos_root': 'naos'}
        self.freeze()

    def git(self, *args):
        return subprocess.run(['git', '-c', 'core.hooksPath=', '-C', str(self.root), *args],
                              capture_output=True, text=True, check=True).stdout.strip()

    def write(self, path, content):
        (self.root / path).write_bytes(content)

    def freeze(self, **kwargs):
        options = {'inputs': ['specs/requirements.md', 'src/worker.py'],
                   'expected_outputs': ['src/worker.py']}
        options.update(kwargs)
        self.pack['context_integrity'] = integrity.freeze_selection(
            self.root, 'naos', self.policy, report=self.pack, project_id=ORIGIN,
            session_id=SESSION, rules_path=self.rules, **options)
        self.save_pack()

    def save_pack(self):
        write_report(self.root / 'naos/frozen.json', self.pack, strict_parent_topology=True)
        self.digest = hashlib.sha256((self.root / 'naos/frozen.json').read_bytes()).hexdigest()
        self.selection = {'path': 'naos/frozen.json', 'pack_sha256': self.digest,
                          'manifest_sha256': self.pack['context_integrity']['manifest_sha256'],
                          'project_id': ORIGIN, 'task_id': 'T-123', 'session_id': SESSION}

    def check(self, **kwargs):
        options = {'path': 'naos/frozen.json', 'pack_sha256': self.digest, 'project_id': ORIGIN,
                   'task_id': 'T-123', 'session_id': SESSION, 'profile': 'standard'}
        options.update(kwargs)
        return integrity.check_context(self.root, 'naos', self.policy, **options)

    def test_relevant_drift_ignores_mtime_and_unrelated_changes(self):
        self.assertEqual(self.check()['status'], 'matched')
        self.write('unrelated.txt', b'unrelated')
        self.assertEqual(self.check()['status'], 'matched')
        path = self.root / 'specs/requirements.md'
        before = path.stat()
        path.write_bytes(b'# Different requirement\n')
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(before.st_mtime_ns, path.stat().st_mtime_ns)
        self.assertEqual(self.check()['status'], 'changed')

    def test_identity_and_pack_digests_cannot_be_missing_or_misbound(self):
        for key, value, expected in [
            ('project_id', 'https://example.test/other.git', 'scope_mismatch'),
            ('task_id', 'T-999', 'scope_mismatch'), ('session_id', 'wrong-session-001', 'scope_mismatch'),
            ('pack_sha256', '0' * 64, 'scope_mismatch'), ('pack_sha256', None, 'unknown'),
            ('session_id', None, 'unknown'), ('manifest_sha256', '0' * 64, 'scope_mismatch')]:
            with self.subTest(field=key):
                self.assertEqual(self.check(**{key: value})['status'], expected)
        self.git('remote', 'set-url', 'origin', 'https://example.test/wrong/project.git')
        self.assertEqual(self.check()['status'], 'scope_mismatch')

    def test_missing_or_ambiguous_session_and_project_are_unknown(self):
        (self.root / 'naos/sessions_index.json').unlink()
        self.assertEqual(self.check()['status'], 'unknown')
        self.git('config', '--add', 'remote.origin.url', 'https://example.test/other.git')
        self.assertEqual(integrity.project_identity(self.root, ORIGIN), 'unknown')

    def test_expected_output_changes_only_at_end_and_completion(self):
        self.write('src/worker.py', b'def worker():\n    return 2\n')
        self.assertEqual(self.check()['status'], 'changed')
        result = self.check(phase='completion')
        self.assertEqual(result['status'], 'matched')
        self.assertIn({'path': 'src/worker.py', 'status': 'expected_changed'}, result['inputs'])
        self.assertEqual(self.check(phase='end')['status'], 'matched')
        self.assertEqual(self.check(phase='anything')['status'], 'unknown')

    def test_raw_newlines_and_portable_paths(self):
        self.write('specs/requirements.md', b'line\r\n')
        self.freeze()
        self.assertEqual(self.check()['status'], 'matched')
        self.write('specs/requirements.md', b'line\n')
        self.assertEqual(self.check()['status'], 'changed')
        for path in ['../escape', '/absolute', 'src\\worker.py', 'src/a:stream', 'src/CON.txt', 'src/x.', './src/worker.py']:
            with self.subTest(path=path):
                self.assertEqual(integrity.read_bytes(self.root, path)[0], 'unsafe')

    def test_missing_oversized_unreadable_and_partial_states(self):
        (self.root / 'specs/requirements.md').unlink()
        self.assertEqual(self.check()['status'], 'missing')
        self.write('specs/requirements.md', b'x' * (integrity.MAX_FILE_BYTES + 1))
        self.assertEqual(self.check()['status'], 'oversized')
        with patch.object(integrity.os, 'open', side_effect=PermissionError):
            self.assertEqual(integrity.read_bytes(self.root, 'src/worker.py')[0], 'unreadable')
        self.write('specs/requirements.md', b'selected constraint\n')
        with patch.object(integrity, 'MAX_TOTAL_BYTES', 1):
            self.freeze()
        self.assertEqual(self.check()['status'], 'partial')

    def test_symlink_and_reparse_topology_are_unsafe(self):
        path = self.root / 'specs/requirements.md'
        path.unlink()
        try:
            path.symlink_to(self.root / 'src/worker.py')
        except OSError as exc:
            self.skipTest('native symlink privilege unavailable: ' + str(exc))
        self.assertEqual(self.check()['status'], 'unsafe')

    def test_legacy_malformed_and_duplicate_json_are_unknown(self):
        self.pack.pop('context_integrity')
        write_report(self.root / 'naos/frozen.json', self.pack)
        digest = hashlib.sha256((self.root / 'naos/frozen.json').read_bytes()).hexdigest()
        self.assertEqual(self.check(pack_sha256=digest)['status'], 'unknown')
        raw = b'{"schema":"x","schema":"y"}'
        self.write('naos/frozen.json', raw)
        self.assertEqual(self.check(pack_sha256=hashlib.sha256(raw).hexdigest())['status'], 'unknown')
        self.assertEqual(integrity.completion_context(self.root, 'naos', self.policy, 'standard', None, None)['required'], False)

    def test_assistant_labels_never_promote_observation(self):
        for label in ['host_delivery', 'model_use', 'behavioral_effectiveness']:
            self.pack[label] = 'verified'
            self.pack['context_integrity']['evidence_dimensions'][label] = 'verified'
        self.save_pack()
        result = self.check()
        self.assertEqual(result['status'], 'matched')
        self.assertEqual(result['evidence_dimensions']['host_delivery'], 'not_observed')
        self.assertEqual(result['evidence_dimensions']['model_use'], 'unknown')
        self.assertEqual(result['evidence_dimensions']['behavioral_effectiveness'], 'not_evaluated')

    def test_completion_join_and_superseded_replay(self):
        binding = {key: value for key, value in self.selection.items() if key != 'path'}
        self.assertEqual(integrity.completion_context(self.root, 'naos', self.policy, 'standard', self.selection, binding)['status'], 'matched')
        self.assertEqual(integrity.completion_context(self.root, 'naos', self.policy, 'standard', self.selection, None)['status'], 'unknown')
        old = dict(binding)
        self.freeze(supersedes=self.digest)
        result = integrity.completion_context(self.root, 'naos', self.policy, 'standard', self.selection, old)
        self.assertEqual(result['status'], 'superseded')
        binding['pack_sha256'] = '0' * 64
        self.assertEqual(integrity.completion_context(self.root, 'naos', self.policy, 'standard', self.selection, binding)['status'], 'scope_mismatch')

    def test_completion_consumer_preserves_git_evidence_and_downgrades_bad_join(self):
        self.write('naos/reports/unit.json', b'{"status":"pass"}\n')
        binding = {key: value for key, value in self.selection.items() if key != 'path'}
        manifest = {'schema': completion.MANIFEST_SCHEMA, 'selected_context': self.selection, 'completions': [{
            'record_id': 'ACE-001', 'ac_id': 'AC-001-1', 'status': 'claimed_complete',
            'repository_binding': self.repo_binding, 'context_binding': binding,
            'evidence': [{'type': 'test_report', 'path': 'naos/reports/unit.json',
                          'command': 'python tests/test_subject.py', 'outcome': 'pass'}]}]}
        path = self.root / 'naos/ac_completion_evidence.yaml'
        def assess():
            path.write_text(yaml.safe_dump(manifest), encoding='utf-8')
            return completion.build_report(root=self.root, naos_root='naos', policy=self.policy,
                                           profile='standard', manifest_path=path, specs_root=self.root / 'specs')
        good = assess()
        self.assertEqual(good['summary']['satisfied_completions'], 1, good['findings'])
        manifest['completions'][0]['context_binding']['task_id'] = 'T-999'
        bad = assess()
        self.assertEqual(bad['summary']['satisfied_completions'], 0)
        self.assertEqual(bad['completions'][0]['repository_binding']['status'], 'ready')
        self.assertIn('context_scope_mismatch', {finding['status'] for finding in bad['findings']})
        # Presence is significant: invalid explicit null is not legacy absence.
        manifest['selected_context'] = None
        manifest['completions'][0].pop('context_binding')
        bad = assess()
        self.assertEqual(bad['summary']['satisfied_completions'], 0)
        self.assertTrue(bad['completions'][0]['context_binding']['required'])
        manifest.pop('selected_context')
        legacy = assess()
        self.assertEqual(legacy['summary']['satisfied_completions'], 1)
        self.assertFalse(legacy['completions'][0]['context_binding']['required'])

    def test_malformed_frozen_selection_and_join_never_crash_or_match(self):
        binding = {key: value for key, value in self.selection.items() if key != 'path'}
        for invalid in [None, [], 'malformed']:
            with self.subTest(selection=invalid):
                self.pack['context_integrity']['selection'] = invalid
                self.save_pack()
                result = integrity.completion_context(
                    self.root, 'naos', self.policy, 'standard', self.selection, binding)
                self.assertEqual(result['status'], 'unknown')
                self.assertTrue(result['required'])

    def test_exact_selection_domain_rejects_missing_fields_floats_and_false_binding(self):
        original = json.loads(json.dumps(self.pack['context_integrity']['selection']))
        for case in ['missing_predecessor', 'float_extra', 'false_association']:
            value = dict(original)
            if case == 'missing_predecessor':
                value.pop('supersedes_pack_sha256')
            elif case == 'float_extra':
                value['unknown_float'] = 1.5
            else:
                value['association_at_freeze'] = 'expected_changed'
            self.pack['context_integrity']['selection'] = value
            self.pack['context_integrity']['manifest_sha256'] = integrity.canonical_digest(value)
            self.save_pack()
            with self.subTest(case=case):
                self.assertEqual(self.check()['status'], 'unknown')

    def test_cli_and_session_inspection_use_same_comparison(self):
        args = ['--check-context', 'naos/frozen.json', '--pack-sha256', self.digest,
                '--project-id', ORIGIN, '--session-id', SESSION, '--task', 'T-123', '--profile', 'standard', '--json']
        for script, extra in [('naos_task_context_pack.py', []),
                              ('naos_session_lifecycle.py', ['--mode', 'session_checkpoint', '--inspect-session'])]:
            result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts' / script), *args, *extra],
                                    cwd=self.root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            value = json.loads(result.stdout)
            checked = value if script == 'naos_task_context_pack.py' else value['context_revalidation']
            self.assertEqual(checked['status'], 'matched')
            self.assertEqual(checked['manifest_sha256'], self.selection['manifest_sha256'])
        self.write('specs/requirements.md', b'changed\n')
        for profile in ['quickstart', 'lite', 'standard']:
            # Profile mismatch is explicit, while legacy advisory exit policy stays intact.
            request = list(args)
            request[request.index('standard')] = profile
            result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/naos_task_context_pack.py'), *request, '--strict'],
                                    cwd=self.root, capture_output=True, text=True)
            expected_exit = exit_code_for_summary(profile, finding_counts([{'severity': severity_for_profile(profile, self.policy)}]), self.policy, strict=True)
            self.assertEqual(result.returncode, expected_exit, result.stderr)

    def test_freeze_cli_new_output_and_no_self_hash_cycle(self):
        args = ['--freeze-context', '--project-id', ORIGIN, '--session-id', SESSION,
                '--task', 'T-123', '--profile', 'standard', '--context-input', 'specs/requirements.md',
                '--output', 'naos/another-frozen.json', '--json']
        def run():
            return subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/naos_task_context_pack.py'), *args],
                                  cwd=self.root, capture_output=True, text=True)
        result = run()
        self.assertEqual(result.returncode, 0, result.stderr)
        pack = json.loads(result.stdout)
        self.assertEqual(pack['context_integrity']['status'], 'matched')
        self.assertNotIn('pack_sha256', pack['context_integrity'])
        self.assertEqual(run().returncode, 2)
        self.assertNotIn('markdown_output', pack)

    def test_report_and_selected_binding_schemas(self):
        import jsonschema
        pack_schema = json.loads((ROOT / 'schemas/naos/task_context_pack.schema.json').read_text())
        jsonschema.validate(self.pack['context_integrity'], pack_schema['properties']['context_integrity'])
        check_schema = json.loads((ROOT / 'schemas/naos/task_context_revalidation.schema.json').read_text())
        jsonschema.validate(self.check(), check_schema)
        manifest_schema = json.loads((ROOT / 'schemas/naos/ac_completion_evidence_manifest.schema.json').read_text())
        jsonschema.validate(self.selection, manifest_schema['properties']['selected_context'])
        malformed = dict(self.selection)
        malformed.pop('manifest_sha256')
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(malformed, manifest_schema['properties']['selected_context'])
        completion_schema = manifest_schema['$defs']['completion']
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate({'ac_id': 'AC-001-1', 'status': 'claimed_complete',
                                 'evidence': [], 'context_binding': 'malformed'},
                                completion_schema)
        malformed_schema = {'properties': {'context_integrity': {'properties': {
            'selection': {'type': 'invalid_type'}}}}}
        with patch.object(integrity, 'read_bytes', return_value=('present', json.dumps(malformed_schema).encode())):
            self.assertEqual(integrity.selection_validation(self.pack['context_integrity']['selection']),
                             'schema_unavailable')

    @unittest.skipUnless(os.name == 'nt', 'junctions are a Windows native case')
    def test_windows_junction_input_is_unsafe(self):
        target = self.root / 'junction'
        result = subprocess.run(['cmd', '/c', 'mklink', '/J', str(target), str(self.root / 'specs')],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.addCleanup(target.rmdir)
        self.assertEqual(integrity.read_bytes(self.root, 'junction/requirements.md')[0], 'unsafe')


if __name__ == '__main__':
    unittest.main()
