"""Exact ordinal task operands and adjacent credential/session refusal."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys
import shutil
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

KIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KIT / 'scripts'))
import naos_hygiene_common as common
import naos_secret_public_literals as public
import naos_policy as policy
import naos_local_context_index as index
import naos_external_evidence_ingest as external

TOKEN = 'aB3dE5fG7hI9jK0mN2pQ4rS6tU8vW'
TIME = '2026-10-09T23:34:20Z'


class ReferenceOperands(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='naos-public-reference-123-')
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value), encoding='utf-8')
        return path

    def sources(self, *, session='TEST-FIXTURE-CONNECTED-001', task='T-001', naos='naos'):
        registry = self.write(naos + '/TASK_REGISTRY.yaml', {'schema': 'naos.task_registry.v2', 'tasks': [{'id': task, 'title': 'Public task'}]})
        record = {'session_id': session, 'created_at': TIME, 'updated_at': TIME, 'status': 'active', 'profile': 'assured',
                  'report_root': naos + '/sessions/' + session + '/reports', 'latest_reports': {},
                  'operator_id': None, 'limitations': [], 'not_claimed': []}
        sessions = self.write(naos + '/sessions_index.json', {'schema': 'naos.session_index.v1', 'generated_at': TIME,
            'sessions': [record], 'active_session_ids': [session], 'closed_session_ids': [], 'latest_session_id': session,
            'limitations': [], 'not_claimed': [], 'human_review_required': True})
        return [registry, sessions]

    def values(self, files, **kw):
        return public.selected_public_reference_literals(files, root=self.root, naos_root=kw.get('naos_root', 'naos'))

    def scan(self, values, **rules):
        self.write('input.json', values)
        return common.check_secret_hygiene(root=self.root, profile='assured', naos_root='naos', rules=rules, rules_path=None, severity='blocking')

    def git_comparison_report(self):
        doc = {'changed_files': [{'path': 'README.md', 'risk_categories': [], 'status': 'M'}],
         'classification_status': 'complete',
         'contributor': {'actor': None,
                         'event_name': None,
                         'fork': False,
                         'not_claimed': ['authentication',
                                         'authorization',
                                         'team membership proof',
                                         'identity proof'],
                         'reason': 'no PR author metadata detected',
                         'source': 'local_env',
                         'trust': 'local_preview'},
         'cost_posture': {'cost_incurred_by_default': False,
                          'cost_usd': 0.0,
                          'external_api_required': False,
                          'human_approval_required_before_cost': True,
                          'model_dependency_required': False,
                          'provider_dependency_required': False},
         'deterministic': True,
         'findings': [],
         'generated_at': '2026-10-10T06:18:41Z',
         'git': {'base_ref': 'd33fe62c84f5c79379230ca54d8e616f17d29a18',
                 'branch': 'test-fixture',
                 'commit_sha': '5f34264aebc93081793c9206ea4a34426c7dbbde',
                 'diff_line_metadata': {'diff_args': ['d33fe62c84f5c79379230ca54d8e616f17d29a18...5f34264aebc93081793c9206ea4a34426c7dbbde'],
                                        'diff_source': 'explicit_base_head',
                                        'git_status': 'available',
                                        'lines_scanned': 2,
                                        'resolved_commits': {'base_ref': 'd33fe62c84f5c79379230ca54d8e616f17d29a18',
                                                             'head_ref': '5f34264aebc93081793c9206ea4a34426c7dbbde'}},
                 'diff_metadata': {'diff_args': ['d33fe62c84f5c79379230ca54d8e616f17d29a18...5f34264aebc93081793c9206ea4a34426c7dbbde'],
                                   'diff_source': 'explicit_base_head',
                                   'git_status': 'available',
                                   'resolved_commits': {'base_ref': 'd33fe62c84f5c79379230ca54d8e616f17d29a18',
                                                        'head_ref': '5f34264aebc93081793c9206ea4a34426c7dbbde'}},
                 'head_ref': '5f34264aebc93081793c9206ea4a34426c7dbbde'},
         'human_review_required': False,
         'known_gaps': ['sandbox_execution_not_implemented',
                        'clean_room_attestation_not_implemented',
                        'contributor_identity_not_authenticated_by_naos'],
         'limitations': ['Classification is deterministic and local; it reviews path and diff metadata '
                         'only.',
                         'The classifier does not execute changed code, install dependencies, run '
                         'sandboxes, call providers, or call the network.',
                         'Pattern findings are review signals and can be false positives or false '
                         'negatives.',
                         'Contributor trust metadata from CI or environment variables is governance '
                         'metadata, not authentication or authorization.',
                         'Human review remains required for protected path, dependency, workflow, prompt, '
                         'secret-like, and governance-surface decisions.'],
         'naos_root': 'naos',
         'not_claimed': ['PR approval',
                         'security proof',
                         'malware analysis',
                         'sandbox execution',
                         'prompt-injection prevention',
                         'legal or regulatory compliance',
                         'proof of compliance',
                         'certification',
                         'release authorization',
                         'deployment authorization',
                         'DSSE signing',
                         'signature verification',
                         'key custody',
                         'proof of execution',
                         'human review replacement'],
         'profile': 'assured',
         'project_root': '/private/tmp/naos-connected-public-audit-source-pilot-20261010-r13/fence/run/project',
         'residual_risks': ['Path and pattern checks can miss malicious behavior hidden in apparently '
                            'low-risk files.',
                            'Diff metadata can be incomplete outside CI or when base/head refs are '
                            'unavailable.',
                            'Repository owners must decide how to treat findings in branch protection and '
                            'review policy.'],
         'rules_path': '/private/tmp/naos-connected-public-audit-source-pilot-20261010-r13/fence/run/project/naos/pr_risk_rules.yaml',
         'schema': 'naos.pr_risk_classification.v1',
         'status': 'pass',
         'summary': {'advisory': 0,
                     'blocking': 0,
                     'category_counts': {},
                     'changed_files': 1,
                     'effective_profile': 'assured',
                     'required': 0,
                     'risk_files': 0,
                     'risk_implied_profile': None,
                     'risk_tier': 'low',
                     'total_findings': 0,
                     'warnings': 0}}
        doc['project_root'] = str(self.root)
        doc['rules_path'] = str(self.root/'naos/pr_risk_rules.yaml')
        return doc

    def git_comparison_spans(self, doc, relative='naos/reports/pr_risk_classification.json', selected=True, selected_policy=None):
        path=self.write(relative,doc)
        text=path.read_text(encoding='utf-8').replace('\r\n','\n').replace('\r','\n')
        return text,public.public_git_comparison_spans(text,relative,root=self.root,naos_root='naos',selected=[path] if selected else [],policy=selected_policy)

    def test_git_comparison_exact_two_coordinates_and_escaped_crlf(self):
        for escaped in (False,True):
            doc=self.git_comparison_report()
            expected=doc['git']['base_ref']+'...'+doc['git']['head_ref']
            raw=json.dumps(doc,indent=2)
            if escaped: raw=raw.replace('...',r'\u002e\u002e\u002e').replace('\n','\r\n')
            text,spans=self.git_comparison_spans(raw)
            self.assertEqual(len(spans),2)
            self.assertEqual([json.loads(text[a:b]) for a,b in sorted(spans)],[expected,expected])
            self.assertTrue(all(text[a]=='"' and text[b-1]=='"' for a,b in spans))
        report=common.check_secret_hygiene(root=self.root,profile='assured',naos_root='naos',
            rules={'scan_roots':['naos/reports/pr_risk_classification.json'],'include_root_files':False},
            rules_path=None,severity='blocking')
        self.assertEqual(report['summary']['entropy_matches'],0)
        self.assertGreaterEqual(report['summary']['public_literal_matches'],2)

    def test_git_comparison_refuses_bad_bindings_tuple_pointer_and_unselected_path(self):
        original=self.git_comparison_report();cases=[]
        for key,value in [('project_root','/foreign'),('naos_root','other'),('schema','foreign')]:
            doc=copy.deepcopy(original);doc[key]=value;cases.append(doc)
        doc=copy.deepcopy(original);doc.pop('summary');cases.append(doc)
        for bucket in ('diff_metadata','diff_line_metadata'):
            for key,value in [('diff_args',['forged']),('diff_args',[]),('diff_args',[original['git'][bucket]['diff_args'][0],'extra']),
                              ('resolved_commits',{'base_ref':'0'*40,'head_ref':original['git']['head_ref']}),
                              ('git_status','unavailable'),('diff_source','explicit_base_to_head'),('diff_args',{'0':original['git'][bucket]['diff_args'][0]}),
                              ('unknown',TOKEN),('lines_scanned',True)]:
                doc=copy.deepcopy(original);doc['git'][bucket][key]=value;cases.append(doc)
            doc=copy.deepcopy(original);doc['git'][bucket]['other_args']=doc['git'][bucket].pop('diff_args');cases.append(doc)
        for value in ('A'*40,'0'*64,'-unsafe','bad..ref'):
            doc=copy.deepcopy(original);doc['git']['base_ref']=value;cases.append(doc)
        for doc in cases:self.assertFalse(self.git_comparison_spans(doc)[1])
        self.assertFalse(self.git_comparison_spans(original,selected=False)[1])
        for relative in ('custom/pr_risk_classification.json','naos/reports/pr_risk_classification-custom.json',
                         'naos/sessions/session/reports/pr_risk_classification.json'):
            self.assertFalse(self.git_comparison_spans(original,relative=relative)[1])

    def comparison_carrier(self, doc, relative='naos/review-inputs/prepared-pr.json'):
        path = self.write(relative, doc)
        chosen = {'paths': {'systemic_impact_family_review_record': 'review-inputs/pr-review.json'}}
        record = {'schema': 'naos.systemic_impact_family_review.v1',
                  'scope': {'project_root': str(self.root), 'naos_root': 'naos', 'profile': doc['profile']},
                  'binding': {'rules_sha256': None, 'policy_sha256': None, 'effective_policy_sha256': None},
                  'reviews': [{'source_family_id': 'pr_risk_classification',
                               'target_kind': 'review_surface', 'target_id': 'policy',
                               'obligation_sha256': None, 'rationale': '', 'output_evidence': [],
                               'evidence_refs': [relative],
                               'evidence_sha256': {relative: hashlib.sha256(path.read_bytes()).hexdigest()},
                               'disposition': 'unresolved'}]}
        self.write('naos/review-inputs/pr-review.json', record)
        return path, chosen, record

    def test_git_comparison_policy_and_current_preparation_role_carriers(self):
        doc = self.git_comparison_report()
        chosen = {'paths': {'reports_dir': 'results', 'pr_risk_classification_report': 'reviewed-pr.json'}}
        self.assertEqual(len(self.git_comparison_spans(doc, 'naos/results/reviewed-pr.json', selected_policy=chosen)[1]), 2)
        self.assertFalse(self.git_comparison_spans(doc, selected_policy=chosen)[1])
        path, chosen, record = self.comparison_carrier(doc)
        latest = copy.deepcopy(doc); latest['generated_at'] = '2026-10-10T01:00:00Z'
        self.write('naos/reports/pr_risk_classification.json', latest)
        text = path.read_text()
        self.assertEqual(len(public.public_git_comparison_spans(text, path.relative_to(self.root).as_posix(),
            root=self.root, naos_root='naos', selected=[path], policy=chosen)), 2)
        report = common.check_secret_hygiene(root=self.root, profile='assured', naos_root='naos',
            rules={'scan_roots':[path.relative_to(self.root).as_posix()], 'include_root_files':False},
            rules_path=None, severity='blocking', policy=chosen)
        self.assertEqual(report['summary']['entropy_matches'], 0)

    def test_git_comparison_preparation_role_refuses_unbound_and_malformed_records(self):
        doc = self.git_comparison_report()
        path, chosen, original = self.comparison_carrier(doc)
        relative = path.relative_to(self.root).as_posix(); text = path.read_text()
        cases = []
        for key, value in [('project_root','/foreign'), ('naos_root','other'), ('profile','standard')]:
            record=copy.deepcopy(original); record['scope'][key]=value; cases.append(record)
        for field, value in [('source_family_id','foreign'), ('evidence_refs',[]),
                             ('evidence_sha256',{}), ('evidence_sha256',{relative:'0'*64})]:
            record=copy.deepcopy(original); record['reviews'][0][field]=value; cases.append(record)
        record=copy.deepcopy(original); record['schema']='foreign'; cases.append(record)
        record=copy.deepcopy(original); record.pop('binding'); cases.append(record)
        record=copy.deepcopy(original); record['unknown_root']='value'; cases.append(record)
        record=copy.deepcopy(original); record['reviews'][0]['target_kind']='foreign'; cases.append(record)
        record=copy.deepcopy(original); record['reviews'][0].pop('output_evidence'); cases.append(record)
        cases.extend([{}, {'schema':original['schema'], 'scope':original['scope'], 'reviews':[None]},
                      '{"reviews":[],"reviews":[]}', '{"n":NaN}', '['*65+'0'+']'*65])
        for record in cases:
            self.write('naos/review-inputs/pr-review.json', record)
            with self.subTest(record=record):
                self.assertFalse(public.public_git_comparison_spans(text,relative,root=self.root,
                    naos_root='naos',selected=[path],policy=chosen))
        self.write('naos/review-inputs/pr-review.json', original)
        for selected, selected_policy in [([],chosen),([path],None),
                ([path],{'paths':{'systemic_impact_family_review_record':'../escape.json'}})]:
            self.assertFalse(public.public_git_comparison_spans(text,relative,root=self.root,
                naos_root='naos',selected=selected,policy=selected_policy))
        self.assertFalse(public.public_git_comparison_spans(text+' ',relative,root=self.root,
            naos_root='naos',selected=[path],policy=chosen))
        path.write_text(text+' ')
        self.assertFalse(public.public_git_comparison_spans(path.read_text(),relative,root=self.root,
            naos_root='naos',selected=[path],policy=chosen))

    def test_git_comparison_preparation_exact_slots_leave_body_provider_and_assignment_scanned(self):
        doc=self.git_comparison_report(); comparison=doc['git']['diff_metadata']['diff_args'][0]
        doc['git'].update(unknown_comparison=comparison, password=TOKEN,
                          provider='ghp_' + 'aB3dE5fG7hI9jK0mN2pQ4rS6tU8vW0xY2zA4bC6dE8')
        path, chosen, record=self.comparison_carrier(doc)
        self.assertEqual(len(public.public_git_comparison_spans(path.read_text(),path.relative_to(self.root).as_posix(),
            root=self.root,naos_root='naos',selected=[path],policy=chosen)),2)
        report=common.check_secret_hygiene(root=self.root,profile='assured',naos_root='naos',
            rules={'scan_roots':[path.relative_to(self.root).as_posix()], 'include_root_files':False},
            rules_path=None,severity='blocking',policy=chosen)
        statuses={f['status'] for f in report['findings']}
        self.assertIn('high_entropy_literal',statuses)
        self.assertTrue(any(f.get('pattern_id')=='assigned_secret' for f in report['findings']))
        self.assertTrue(any(f.get('pattern_id')=='github_style_token' for f in report['findings']))
        neighbor=self.write('naos/review-inputs/unreferenced-pr.json',self.git_comparison_report())
        self.assertFalse(public.public_git_comparison_spans(neighbor.read_text(),neighbor.relative_to(self.root).as_posix(),
            root=self.root,naos_root='naos',selected=[neighbor],policy=chosen))

    def test_git_comparison_named_refs_finite_modes_and_full_commit_formats(self):
        for length in (40,64):
            for mode in ('explicit_base_head','explicit_base_to_head','working_tree_vs_head'):
                doc=self.git_comparison_report();git=doc['git']
                git['base_ref']='origin/main' if mode!='working_tree_vs_head' else None
                git['head_ref']='feature/topic' if mode=='explicit_base_head' else None
                resolved={'head_ref':'b'*length}
                if git['base_ref']:resolved['base_ref']='a'*length
                expected=resolved['base_ref']+'...'+resolved['head_ref'] if git['base_ref'] else resolved['head_ref']
                for key in ('diff_metadata','diff_line_metadata'):
                    git[key]={'diff_source':mode,'diff_args':[expected],'git_status':'available','resolved_commits':resolved.copy()}
                git['diff_line_metadata']['lines_scanned']=0
                if mode=='working_tree_vs_head':
                    git['diff_metadata']['untracked_git_status']='available'
                    git['diff_line_metadata']['untracked']={'untracked_files_scanned':0,'untracked_lines_scanned':0}
                with self.subTest(length=length,mode=mode),patch('naos_pr_risk_classification.run_git',side_effect=AssertionError('Git must not run for admission')):
                    text,spans=self.git_comparison_spans(doc)
                    self.assertEqual(len(spans),2)
                    self.assertEqual([json.loads(text[a:b]) for a,b in sorted(spans)],[expected,expected])
        mixed=self.git_comparison_report();mixed['git'].update(base_ref='origin/main',head_ref='feature/topic')
        for key in ('diff_metadata','diff_line_metadata'):
            mixed['git'][key]['resolved_commits']={'base_ref':'a'*40,'head_ref':'b'*64}
            mixed['git'][key]['diff_args']=['a'*40+'...'+'b'*64]
        self.assertFalse(self.git_comparison_spans(mixed)[1])
        original=self.git_comparison_report()
        for suffix in ('..','....','-'):
            doc=copy.deepcopy(original)
            for key in ('diff_metadata','diff_line_metadata'):
                doc['git'][key]['diff_args']=[doc['git']['base_ref']+suffix+doc['git']['head_ref']]
            self.assertFalse(self.git_comparison_spans(doc)[1])
        doc=copy.deepcopy(original);doc['git']['base_ref']=None
        self.assertFalse(self.git_comparison_spans(doc)[1])
        doc=copy.deepcopy(original)
        for key in ('diff_metadata','diff_line_metadata'):
            doc['git'][key]['resolved_commits']['base_ref']='0'*40
            doc['git'][key]['diff_args']=['0'*40+'...'+doc['git']['head_ref']]
        self.assertFalse(self.git_comparison_spans(doc)[1])

    def test_git_comparison_neighbor_body_provider_assignment_still_scanned(self):
        doc=self.git_comparison_report();expected=doc['git']['diff_metadata']['diff_args'][0]
        doc['git'].update(unknown_comparison=expected,neighbor=TOKEN,password=expected,
                   provider='sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456')
        text,spans=self.git_comparison_spans(doc)
        self.assertEqual(len(spans),2)
        self.assertGreater(text.count(expected),len(spans))
        report=common.check_secret_hygiene(root=self.root,profile='assured',naos_root='naos',
            rules={'scan_roots':['naos/reports/pr_risk_classification.json'],'include_root_files':False},
            rules_path=None,severity='blocking')
        self.assertGreaterEqual(report['summary']['entropy_matches'],2)
        self.assertTrue(any(f.get('pattern_id')=='assigned_secret' for f in report['findings']))
        self.assertTrue(any(f.get('pattern_id')=='openai_style_key' for f in report['findings']))

    def test_git_comparison_invalid_catalog_keeps_both_entropy_findings_without_proof_call(self):
        doc=self.git_comparison_report();relative='naos/reports/pr_risk_classification.json'
        path=self.write(relative,doc);text=path.read_text(encoding='utf-8')
        expected=doc['git']['diff_metadata']['diff_args'][0]
        quoted=json.dumps(expected)
        positions=[];start=0
        while True:
            start=text.find(quoted,start)
            if start<0:break
            positions.append((text.count('\n',0,start)+1,start-text.rfind('\n',0,start)))
            start+=len(quoted)
        self.assertEqual(len(positions),2)
        with patch.object(public,'read_catalog',side_effect=public.PublicVocabularyError('digest_mismatch')), \
                patch.object(common,'public_git_comparison_spans',side_effect=AssertionError('invalid catalog must not call comparison proof')) as proof:
            report=common.check_secret_hygiene(root=self.root,profile='assured',naos_root='naos',
                rules={'scan_roots':[relative],'include_root_files':False},rules_path=None,severity='blocking')
        proof.assert_not_called()
        self.assertEqual(report['scans']['public_literals']['status'],'invalid')
        self.assertTrue(any(f['status']=='public_vocabulary_invalid' and f['severity']=='blocking'
                            for f in report['findings']))
        entropy={(f['line'],f['column']) for f in report['findings']
                 if f['status']=='high_entropy_literal' and f['path']==relative}
        self.assertTrue(set(positions)<=entropy)

    def test_git_comparison_malformed_stale_oversized_and_reparse_inputs_refuse(self):
        doc=self.git_comparison_report();raw=json.dumps(doc)
        for text in (raw[:-1],raw.replace('"git":','"git":0,"git":',1),raw[:-1]+',"n":NaN}',
                     raw[:-1]+',"deep":'+'['*65+'0'+']'*65+'}',raw[:-1]+',"large":"'+'x'*(1024*1024)+'"}'):
            self.assertFalse(self.git_comparison_spans(text)[1])
        relative='naos/reports/pr_risk_classification.json';path=self.write(relative,doc)
        self.assertFalse(public.public_git_comparison_spans(raw+' ',relative,root=self.root,naos_root='naos',selected=[path]))
        observed=Path.lstat
        for unsafe in (path,path.parent,self.root):
            def metadata(candidate,*args,**kwargs):
                result=observed(candidate,*args,**kwargs)
                if candidate==unsafe:return SimpleNamespace(st_mode=result.st_mode,st_size=result.st_size,st_file_attributes=0x400)
                return result
            with patch.object(Path,'lstat',metadata):
                self.assertFalse(public.public_git_comparison_spans(raw,relative,root=self.root,naos_root='naos',selected=[path]))

    def test_exact_catalog_selectors_are_public_but_adopter_selector_fields_are_not(self):
        catalog = public.read_catalog()
        selector = next(g['selector'] for g in catalog['groups'] if len(g['selector']) > 40 and '1' in g['selector'])
        report = self.scan({'selector': selector, 'unknown_selector': TOKEN, 'mixed': selector + TOKEN})
        self.assertEqual(report['summary']['entropy_matches'], 2)
        self.assertEqual(report['summary']['public_literal_matches'], 1)

    def test_shipped_catalog_self_scan_has_no_entropy_omissions(self):
        self.write('catalog.json', (KIT / 'scripts' / public.CATALOG_FILENAME).read_text(encoding='utf-8'))
        report = common.check_secret_hygiene(root=self.root, profile='assured', naos_root='naos', rules={}, rules_path=None, severity='blocking')
        self.assertEqual(report['summary']['entropy_matches'], 0)


    def test_selected_public_ordinal_task_native_relative_spelling_only(self):
        from pathlib import PureWindowsPath
        files=self.sources();original_path=public.Path
        def native_relative(value,*args,**kwargs):
            # Pure lexical Windows branch; real schema/registry bytes stay read.
            if isinstance(value,str) and value.startswith('naos/active/T-'):
                return PureWindowsPath(value)
            return original_path(value,*args,**kwargs)
        with patch.object(public,'Path',side_effect=native_relative):
            values=self.values(files)
            for path in ['naos/active/T-001.md','naos/active/T-001_compact.md']:
                self.assertIn(path,values)
                self.assertIn(str(PureWindowsPath(path)),values)
                self.assertIn(json.dumps(str(PureWindowsPath(path)))[1:-1],values)
            self.assertFalse(self.values([]))
            for path in [r'naos\active\T-999_compact.md',r'naos\active\custom_compact.md',
                         r'naos\sessions\TEST-FIXTURE-CONNECTED-001\reports\session_lifecycle.json',
                         r'naos\active\sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456.md']:
                self.assertNotIn(path,values)

    def test_posix_public_ordinal_task_forms_remain_unchanged(self):
        files=self.sources();values=self.values(files)
        for relative in ['naos/active/T-001.md','naos/active/T-001_compact.md']:
            self.assertIn(relative,values);self.assertIn(str(self.root/relative),values)
        if sys.platform!='win32':
            self.assertNotIn(r'naos\active\T-001_compact.md',values)

    def test_default_ordinal_task_paths_are_exact_and_need_no_output_existence(self):
        files = self.sources()
        values = self.values(files)
        for relative in ['naos/active/T-001.md', 'naos/active/T-001_compact.md']:
            self.assertFalse((self.root / relative).exists())
            self.assertIn(relative, values)
            self.assertIn(str(self.root / relative), values)
        report = self.scan({'task': 'naos/active/T-001.md', 'compact': str(self.root / 'naos/active/T-001_compact.md')})
        self.assertFalse(any(f.get('path') == 'input.json' and f['status'] == 'high_entropy_literal' for f in report['findings']))

    def test_unselected_custom_unknown_mixed_and_authored_paths_remain_blocking(self):
        files = self.sources()
        self.assertFalse(self.values([]))
        known = 'naos/sessions/TEST-FIXTURE-CONNECTED-001/reports/session_lifecycle.json'
        report = self.scan({'unknown': known + TOKEN, 'custom': known.replace('reports/', 'private/'),
            'basename': known.replace('session_lifecycle.json', TOKEN + '.json'),
            'outside': '/outside/' + known, 'authored': 'naos/human_decisions/' + TOKEN + '.yaml'})
        self.assertEqual(sum(f.get('path') == 'input.json' and f['status'] == 'high_entropy_literal' for f in report['findings']), 5)
        self.assertNotIn(known.replace('reports/', 'private/'), self.values(files))

    def test_opaque_ids_are_not_admitted_and_raw_source_neighbors_are_scanned(self):
        token = TOKEN
        self.sources(session=token, task=token.upper() + '-T-001')
        report = self.scan({'path': 'naos/sessions/' + token + '/reports/session_lifecycle.json'})
        self.assertGreaterEqual(report['summary']['entropy_matches'], 3)
        self.assertFalse(self.values([self.root / 'naos/TASK_REGISTRY.yaml', self.root / 'naos/sessions_index.json']))
        # Alphabetic opaque labels can acquire digits from the observed root.
        alpha = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        files = self.sources(session=alpha)
        self.assertNotIn('naos/sessions/' + alpha, self.values(files))

    def test_namespaced_tasks_are_not_automatically_public_and_short_ordinal_control_is(self):
        files = self.sources(task='TEAM-API-T-001')
        self.assertNotIn('naos/active/TEAM-API-T-001.md', self.values(files))
        for identifier in ['T-0001', 'T-123456789012345678901234']:
            self.assertFalse(self.values(self.sources(task=identifier)))
            result = self.scan({'path': str(self.root / ('naos/active/' + identifier + '.md'))})
            self.assertTrue(any(f.get('path') == 'input.json' and f['status'] == 'high_entropy_literal' for f in result['findings']))
        report = self.scan({'path': 'naos/active/TEAM-API-T-001.md'})
        self.assertTrue(any(f.get('path') == 'input.json' and f['status'] == 'high_entropy_literal' for f in report['findings']))
        self.sources(task='T-001')
        report = self.scan({'path': 'naos/active/T-001.md'})
        self.assertFalse(any(f.get('path') == 'input.json' and f['status'] == 'high_entropy_literal' for f in report['findings']))

    def test_short_padded_long_and_uuid_session_counterexamples_preserve_prior_findings(self):
        identifiers = ['aB3dE5fG7hI9jK0mN2p', 'AAAAAAAAAAAAAAAAaB3dE5fG7hI9jK0m',
                       'AAAAAAAAAAAAAAAAaB3dE5fG7hI9jK0mN2pQ4rS6t',
                       'c237fa68-e947-43b8-a352-409ef77a0641', 'PUBLIC-001']
        for identifier in identifiers:
            with self.subTest(identifier=identifier):
                files = self.sources(session=identifier)
                operand = 'naos/sessions/' + identifier + '/reports/session_lifecycle.json'
                self.assertNotIn(operand, self.values(files))
                report = self.scan({'path': operand})
                with patch.object(common, 'selected_public_reference_literals', return_value=set()):
                    baseline = self.scan({'path': operand})
                self.assertEqual(report['findings'], baseline['findings'])
                self.assertTrue(any(f.get('path') == 'input.json' and f['status'] == 'high_entropy_literal' for f in report['findings']))

    def test_canonical_session_paths_keep_the_only_entropy_signal_for_short_or_padded_ids(self):
        from jsonschema import Draft202012Validator
        schema = json.loads((KIT / 'schemas/naos/session_index.schema.json').read_text(encoding='utf-8'))
        for identifier in ('ab3de5fg7hi9jk0mn2p', 'a' * 12 + 'ab3de5fg7hi9jk0mn2pq4rs6t'):
            self.assertTrue(len(identifier) < 20 or common.shannon_entropy(identifier) < 4.0)
            for separator in ('/', '\\'):
                with self.subTest(identifier=identifier, separator=separator):
                    files = self.sources(session=identifier)
                    index = json.loads(files[1].read_text(encoding='utf-8'))
                    operand = separator.join(('naos', 'sessions', identifier, 'reports'))
                    index['sessions'][0]['report_root'] = operand
                    Draft202012Validator(schema).validate(index)
                    self.write('naos/sessions_index.json', index)
                    report = self.scan({'value': 'safe'})
                    self.assertTrue(any(f.get('path') == 'naos/sessions_index.json'
                                        and f['status'] == 'high_entropy_literal'
                                        for f in report['findings']))

    def test_provider_and_assignment_checks_remain_unconditional(self):
        self.sources()
        report = self.scan({'password': 'naos/active/T-001.md', 'provider': 'sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'})
        self.assertTrue(any(f.get('pattern_id') == 'assigned_secret' for f in report['findings']))
        self.assertTrue(any(f.get('pattern_id') == 'openai_style_key' for f in report['findings']))

    def test_malformed_duplicate_aliased_unreadable_and_modified_schema_fail_closed(self):
        cases = ['tasks: [{id: T-001, title: One}]\ntasks: [{id: T-002, title: Two}]',
                 'tasks: &a [{id: T-001, title: One}]\nextra: *a',
                 'tasks: [{id: T-001, title: One}]\nextra: .nan',
                 'tasks: [{id: T-001, title: One}]\n123: value',
                 '{"tasks":[{"id":"T-001"}]}', 'tasks: [']
        for text in cases:
            with self.subTest(text=text):
                path = self.write('naos/TASK_REGISTRY.yaml', text)
                self.assertFalse(self.values([path]))
        files = self.sources()
        with patch.object(public, '_REFERENCE_SCHEMAS', {'task_registry': '0' * 64, 'session_index': '0' * 64}):
            self.assertFalse(self.values(files))
        with patch.object(public, '_bounded_regular_bytes', side_effect=PermissionError('read denied')):
            self.assertFalse(self.values(files))
        session = files[1]
        session.write_text(session.read_text(encoding='utf-8').replace('"sessions":', '"sessions": [], "sessions":'), encoding='utf-8')
        self.assertFalse(self.values([session]))

    def test_custom_stored_report_root_and_duplicate_ids_are_not_evidence(self):
        files = self.sources()
        doc = json.loads(files[1].read_text(encoding='utf-8'))
        doc['sessions'][0]['report_root'] += '/custom'
        files[1].write_text(json.dumps(doc), encoding='utf-8')
        self.assertFalse(self.values([files[1]]))
        doc['sessions'][0]['report_root'] = 'naos/sessions/TEST-FIXTURE-CONNECTED-001/reports'
        doc['sessions'].append(copy.deepcopy(doc['sessions'][0]))
        files[1].write_text(json.dumps(doc), encoding='utf-8')
        self.assertFalse(self.values([files[1]]))

    def test_naos_remap_uses_only_whole_declared_operands(self):
        files = self.sources(naos='controls/naos')
        values = self.values(files, naos_root='controls/naos')
        self.assertIn('controls/naos/active/T-001.md', values)
        self.assertNotIn('naos/active/T-001.md', values)

    def test_actual_source_and_operand_links_fail_closed(self):
        files = self.sources()
        saved = files[0].read_text(encoding='utf-8')
        files[0].unlink()
        target = self.write('target.yaml', saved)
        try:
            files[0].symlink_to(target)
        except OSError as error:
            if getattr(error, 'winerror', None) == 1314:
                self.skipTest('Native account cannot create symlink')
            raise
        self.assertFalse(self.values([files[0]]))
        files[0].unlink()
        files[0].write_text(saved, encoding='utf-8')
        active = self.root / 'naos/active'
        active.symlink_to(self.root, target_is_directory=True)
        self.assertNotIn('naos/active/T-001.md', self.values([files[0]]))
    def test_reparse_points_and_bounds_are_mandatory_without_symlink_privilege(self):
        files = self.sources()
        self.assertTrue(public._unsafe_link(SimpleNamespace(st_mode=0o040755, st_file_attributes=0x400)))
        original_lstat = Path.lstat
        def shaped_lstat(path):
            if path == files[0]:
                return SimpleNamespace(st_mode=0o100644, st_file_attributes=0x400, st_size=100)
            return original_lstat(path)
        with patch.object(Path, 'lstat', shaped_lstat):
            self.assertFalse(self.values([files[0]]))
        self.assertFalse(self.values([files[0]] * 50_001))
        files[0].write_text(' ' * (1024 * 1024 + 1), encoding='utf-8')
        self.assertFalse(self.values([files[0]]))

    def test_invalid_catalog_disables_dynamic_paths_and_unknown_neighbors_are_scanned(self):
        files = self.sources()
        task = json.loads(files[0].read_text(encoding='utf-8'))
        task['unknown_metadata'] = TOKEN
        files[0].write_text(json.dumps(task), encoding='utf-8')
        self.write('naos/active/T-002.md', 'An existing undeclared card is not evidence.')
        report = self.scan({'task': 'naos/active/T-001.md', 'other': 'naos/active/T-002.md'})
        self.assertTrue(any(f.get('path') == 'naos/TASK_REGISTRY.yaml' and f['status'] == 'high_entropy_literal' for f in report['findings']))
        self.assertTrue(any(f.get('path') == 'input.json' and f['status'] == 'high_entropy_literal' for f in report['findings']))
        with patch.object(public, 'read_catalog', side_effect=public.PublicVocabularyError('digest_mismatch')):
            report = self.scan({'task': 'naos/active/T-001.md'})
        self.assertTrue(any(f['status'] == 'public_vocabulary_invalid' for f in report['findings']))
        self.assertTrue(any(f.get('path') == 'input.json' and f['status'] == 'high_entropy_literal' for f in report['findings']))

    def test_actual_installer_schema_branch_and_script_copy_support_task_recognition(self):
        # Execute the actual schema copy branch and actual script copy function,
        # isolated from activation, native operations and unrelated scaffolding.
        tree = ast.parse((KIT / 'naos_init.py').read_text(encoding='utf-8'))
        scaffold = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'scaffold_files')
        assignments = {n.targets[0].id: n for n in ast.walk(scaffold) if isinstance(n, ast.Assign)
                       and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                       and n.targets[0].id in {'schema_src', 'adopter_schema_names'}}
        schema_copy = next(n for n in ast.walk(scaffold) if isinstance(n, ast.If)
                           and ast.unparse(n.test) == 'schema_src.is_dir()')
        preview = self.root / 'copied'
        preview.mkdir()
        namespace = {'KIT_DIR': KIT, 'preview_dir': preview, 'tier': 'assured',
                     'copy_source': shutil.copy2, 'generated': []}
        block = [assignments['schema_src'], assignments['adopter_schema_names'], schema_copy]
        exec(compile(ast.Module(body=block, type_ignores=[]), 'actual_installer_schema_branch', 'exec'), namespace)
        self.assertIn('schemas/naos/task_registry.schema.json', namespace['generated'])
        self.assertEqual((preview / 'schemas/naos/task_registry.schema.json').read_bytes(),
                         (KIT / 'schemas/naos/task_registry.schema.json').read_bytes())
        copier = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_copy_generated_script')
        scope = {'Path': Path, 'shutil': shutil, 'SourceOrigins': object}
        exec(compile(ast.Module(body=[copier], type_ignores=[]), 'actual_installer_script_copy', 'exec'), scope)
        scripts = preview / 'scripts'
        scripts.mkdir()
        for name in ['naos_secret_public_literals.py', public.CATALOG_FILENAME]:
            scope['_copy_generated_script'](KIT / 'scripts' / name, scripts / name)
        registry = preview / 'naos/TASK_REGISTRY.yaml'
        registry.parent.mkdir()
        registry.write_text('{"tasks":[{"id":"T-001","title":"Public task"}]}', encoding='utf-8')
        code = """import sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import naos_secret_public_literals as p
root=Path(sys.argv[2]); registry=root/'naos/TASK_REGISTRY.yaml'
values=p.selected_public_reference_literals([registry],root=root,naos_root='naos')
assert 'naos/active/T-001.md' in values
assert str(root/'naos/active/T-001_compact.md') in values
assert 'naos/active/T-0001.md' not in values
"""
        result = subprocess.run([sys.executable, '-B', '-c', code, str(scripts), str(preview)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_sqlite_failed_build_keeps_prior_target_and_failure_evidence(self):
        target = self.root / 'naos/context_index/local_context_index.sqlite'
        target.parent.mkdir(parents=True)
        target.write_bytes(b'prior target preserved')
        with patch.object(index, 'populate_sqlite_database', side_effect=RuntimeError('deliberate build failure')):
            result = index.create_sqlite_artifact(target, {}, [], [], [], root=self.root, naos_root='naos',
                policy=copy.deepcopy(policy.SAFE_FALLBACK_POLICY), profile='assured', generated_at=TIME,
                session_id='TEST-FIXTURE-CONNECTED-001', generated_by={})
        coordination = result[3]
        self.assertEqual(target.read_bytes(), b'prior target preserved')
        self.assertFalse(coordination['atomic_replace_used'])
        self.assertEqual(coordination['status'], 'validation_failed')
        failed = next(f for f in coordination['findings'] if f['id'] == 'sqlite_write_coordination.db_build_failed')
        self.assertEqual(failed['severity'], 'blocking')
        self.assertEqual(failed['path'], str(target))
        self.assertEqual(failed['artifact_role'], 'temporary_database')
        self.assertIn('deliberate build failure', failed['message'])
        self.assertIsNone(coordination['temp_db_path'])
        self.assertFalse(list(target.parent.glob('*.tmp.*')))

    def test_sqlite_success_retains_actions_target_and_coverage_without_temp_name(self):
        target = self.root / 'naos/context_index/local_context_index.sqlite'
        result = index.create_sqlite_artifact(target, {"generated_at": TIME, "profile": "assured", "status": "ready"}, [], [], [], root=self.root, naos_root='naos',
            policy=copy.deepcopy(policy.SAFE_FALLBACK_POLICY), profile='assured', generated_at=TIME,
            session_id='TEST-FIXTURE-CONNECTED-001', generated_by={})
        coordination = result[3]
        self.assertTrue(target.is_file())
        self.assertTrue(coordination['atomic_replace_used'])
        self.assertTrue(coordination['tables_verified'])
        self.assertTrue(coordination['target_db_hash'])
        self.assertIsNone(coordination['temp_db_path'])
        replace = next(a for a in coordination['cleanup_actions'] if a['action'] == 'atomic_replace')
        self.assertEqual(replace['target'], str(target))
        self.assertEqual(replace['source_role'], 'temporary_database')
        self.assertIsNone(replace['source'])
        self.assertEqual(replace['status'], 'completed')
        self.assertNotIn('.sqlite.tmp.', json.dumps(coordination))


    def derived_sources(self, *, naos='naos'):
        source = self.write('src/fixture123.py', 'def example():\n    return 1\n')
        rules = {'artifact_families': [{'id': 'python_sources', 'include_patterns': ['src/*.py']}],
                 'chunking': {'max_artifacts': 10}}
        artifacts, _, _, _ = index.build_artifact_records(self.root, rules, TIME)
        self.assertEqual(len(artifacts), 1)
        schema = json.loads((KIT / 'schemas/naos/local_context_index.schema.json').read_text(encoding='utf-8'))
        defaults = {'array': [], 'object': {}, 'string': '', 'boolean': True}
        document = {key: copy.deepcopy(defaults[schema['properties'][key].get('type', 'string')[0]
                    if isinstance(schema['properties'][key].get('type'), list) else schema['properties'][key].get('type', 'string')])
                    for key in schema['required']}
        document.update(schema=index.REPORT_SCHEMA, generated_at=TIME, profile='assured', status='ready',
                        project_root=str(self.root), naos_root=naos, indexed_artifacts=artifacts)
        local = self.write(naos + '/reports/local_context_index.json', document)
        self.write('review.sarif', {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'review'}},
                    'results': [{'ruleId': 'fixture', 'level': 'warning', 'message': {'text': 'omitted'}}]}]})
        imported = external.build_report(self.root, 'assured', naos, copy.deepcopy(policy.SAFE_FALLBACK_POLICY),
                                         'review.sarif', 'sarif')
        self.assertEqual(len(imported['result_records']), 1)
        ingest = self.write(naos + '/reports/external_evidence_ingest.json', imported)
        return [local, ingest], document, imported

    def derived_values(self, files, naos='naos'):
        return public.selected_public_derived_report_ids(files, root=self.root, naos_root=naos)

    def test_producer_outputs_share_exact_pure_id_computations(self):
        files, local, imported = self.derived_sources()
        artifact = local['indexed_artifacts'][0]
        expected = 'A-' + hashlib.sha256(('python_sources' + chr(0) + 'src/fixture123.py').encode()).hexdigest()[:16]
        self.assertEqual(artifact['artifact_id'], expected)
        self.assertEqual(index.recompute_public_artifact_id(artifact), expected)
        record = imported['result_records'][0]
        vector = {'source_sha256': record['source_sha256'], 'run_index': 0, 'result_index': 0}
        digest = hashlib.sha256(json.dumps(vector, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        self.assertEqual(record['external_result_id'], 'sarif-' + digest)
        self.assertEqual(external.recompute_public_external_result_id(record), 'sarif-' + digest)
        self.assertEqual(external.recompute_public_external_route_id(record), 'CPR-EXTERNAL-SARIF-' + digest.upper())
        values = self.derived_values(files)
        self.assertEqual(values, {expected, 'artifact:' + expected, 'sarif-' + digest, 'CPR-EXTERNAL-SARIF-' + digest.upper()})
        import naos_graph_context_query as graph
        import naos_control_plane_review as control
        edges = graph.build_edges([artifact], [{'source_path': artifact['path'], 'link_type': 'task_ref',
                                  'reference_id': 'T-001'}], {}, {})
        self.assertEqual(edges[0]['source_node'], 'artifact:' + expected)
        _, _, reconciliation = control.build_external_sarif_reconciliation(
            root=self.root, profile='assured', naos_root='naos', policy=copy.deepcopy(policy.SAFE_FALLBACK_POLICY),
            rules={}, allowed_source_types={control.EXTERNAL_SARIF_SOURCE_TYPE},
            allowed_target_surfaces=set(control.EXTERNAL_SARIF_TARGETS), allowed_dispositions={'needs_review'}, required_fields=[])
        self.assertEqual(reconciliation['routes'][0]['id'], 'CPR-EXTERNAL-SARIF-' + digest.upper())

    def test_exact_cross_file_ids_leave_neighbors_provider_and_assignment_scanned(self):
        files, local, imported = self.derived_sources()
        graph = 'artifact:' + local['indexed_artifacts'][0]['artifact_id']
        route = external.recompute_public_external_route_id(imported['result_records'][0])
        payload = {'graph': graph, 'route': route, 'mixed': graph + TOKEN,
                   'forged': 'CPR-EXTERNAL-SARIF-' + '0123456789ABCDEF' * 4,
                   'password': route, 'provider': 'sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'}
        report = self.scan(payload)
        rows = [f for f in report['findings'] if f.get('path') == 'input.json']
        self.assertEqual(sum(f['status'] == 'high_entropy_literal' for f in rows), 3)
        self.assertTrue(any(f.get('pattern_id') == 'assigned_secret' for f in rows))
        self.assertTrue(any(f.get('pattern_id') == 'openai_style_key' for f in rows))
        with patch.object(public, 'read_catalog', side_effect=public.PublicVocabularyError('digest_mismatch')):
            invalid = self.scan({'graph': graph, 'route': route})
        self.assertEqual(sum(f.get('path') == 'input.json' and f['status'] == 'high_entropy_literal' for f in invalid['findings']), 2)

    def test_only_selected_default_reports_and_exact_context_establish_ids(self):
        files, local, imported = self.derived_sources()
        self.assertFalse(self.derived_values([]))
        custom = self.write('custom/report.json', local)
        self.assertFalse(self.derived_values([custom]))
        for field, value in [('schema', 'naos.local_context_index.v2'), ('project_root', '/outside'),
                             ('naos_root', 'other'), ('indexed_artifacts', {})]:
            changed = copy.deepcopy(local); changed[field] = value
            files[0].write_text(json.dumps(changed), encoding='utf-8')
            self.assertFalse(self.derived_values([files[0]]), field)
        files[0].write_text(json.dumps(local), encoding='utf-8')
        with patch.object(common, 'selected_public_derived_report_ids', return_value=set()):
            baseline = self.scan({'graph': 'artifact:' + local['indexed_artifacts'][0]['artifact_id']})
        self.assertTrue(any(f.get('path') == 'input.json' and f['status'] == 'high_entropy_literal' for f in baseline['findings']))

    def test_defining_fields_forged_ids_duplicates_and_report_digest_mismatch_refused(self):
        files, local, imported = self.derived_sources()
        artifact = local['indexed_artifacts'][0]
        for field, value in [('family_id', True), ('family_id', ''), ('path', '../escape.json'),
                             ('path', 'C:/outside/file.json'), ('path', '/outside/file.json'),
                             ('path', 'src/./file.json'), ('artifact_id', 'A-' + 'f' * 16)]:
            changed = copy.deepcopy(local); changed['indexed_artifacts'][0][field] = value
            files[0].write_text(json.dumps(changed), encoding='utf-8'); self.assertFalse(self.derived_values([files[0]]), field)
        changed = copy.deepcopy(local); del changed['indexed_artifacts'][0]['family_id']
        files[0].write_text(json.dumps(changed), encoding='utf-8'); self.assertFalse(self.derived_values([files[0]]))
        changed = copy.deepcopy(local); changed['indexed_artifacts'].append(copy.deepcopy(artifact))
        files[0].write_text(json.dumps(changed), encoding='utf-8'); self.assertFalse(self.derived_values([files[0]]))
        for field, value in [('run_index', True), ('run_index', -1), ('result_index', 0.0),
                             ('source_sha256', 'f' * 63), ('source_sha256', 'A' * 64),
                             ('external_result_id', 'sarif-' + 'f' * 64)]:
            changed = copy.deepcopy(imported); changed['result_records'][0][field] = value
            files[1].write_text(json.dumps(changed), encoding='utf-8'); self.assertFalse(self.derived_values([files[1]]), field)
        changed = copy.deepcopy(imported); changed['result_records'].append(copy.deepcopy(changed['result_records'][0]))
        files[1].write_text(json.dumps(changed), encoding='utf-8'); self.assertFalse(self.derived_values([files[1]]))
        changed = copy.deepcopy(imported); changed['summary']['source_sha256'] = 'f' * 64
        files[1].write_text(json.dumps(changed), encoding='utf-8'); self.assertFalse(self.derived_values([files[1]]))

    def test_raw_defining_and_neighbor_values_never_become_public(self):
        files, local, imported = self.derived_sources()
        artifact = local['indexed_artifacts'][0]
        artifact['family_id'] = TOKEN
        artifact['path'] = 'src/' + TOKEN + '.json'
        artifact['artifact_id'] = index.artifact_id_for(artifact['family_id'], artifact['path'])
        local['password'] = 'sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'
        files[0].write_text(json.dumps(local), encoding='utf-8')
        self.assertIn('artifact:' + artifact['artifact_id'], self.derived_values([files[0]]))
        self.assertNotIn(TOKEN, self.derived_values([files[0]]))
        self.assertNotIn(artifact['path'], self.derived_values([files[0]]))
        report = self.scan({'id': 'artifact:' + artifact['artifact_id']})
        rows = [f for f in report['findings'] if f.get('path') == 'naos/reports/local_context_index.json']
        self.assertGreaterEqual(sum(f['status'] == 'high_entropy_literal' for f in rows), 3)
        self.assertTrue(any(f.get('pattern_id') == 'assigned_secret' for f in rows))
        self.assertTrue(any(f.get('pattern_id') == 'openai_style_key' for f in rows))

    def test_strict_report_json_schema_bytes_and_resource_bounds_fail_closed(self):
        files, local, imported = self.derived_sources()
        original = json.dumps(local)
        bad = [original.replace('"schema":', '"schema": "duplicate", "schema":'),
               original[:-1] + ', "bad": NaN}',
               original[:-1] + ', "deep": ' + '[' * 65 + '0' + ']' * 65 + '}',
               original[:-1] + ', "wide": [' + ','.join(['0'] * 50001) + ']}']
        for raw in bad:
            files[0].write_text(raw, encoding='utf-8'); self.assertFalse(self.derived_values([files[0]]))
        files[0].write_text(' ' * (1024 * 1024 + 1), encoding='utf-8'); self.assertFalse(self.derived_values([files[0]]))
        files[0].write_text(original, encoding='utf-8')
        self.assertFalse(self.derived_values([files[0]] * 50001))
        with patch.dict(public._REFERENCE_SCHEMAS, {'local_context_index': 'f' * 64}):
            self.assertFalse(self.derived_values([files[0]]))

    def test_derived_report_leaf_ancestor_links_and_reparse_refused(self):
        files, local, imported = self.derived_sources()
        saved = files[0].read_text(encoding='utf-8'); files[0].unlink()
        target = self.write('target.json', saved)
        try:
            files[0].symlink_to(target)
        except OSError as error:
            if getattr(error, 'winerror', None) != 1314:
                raise
        else:
            self.assertFalse(self.derived_values([files[0]]))
            files[0].unlink()
        files[0].write_text(saved, encoding='utf-8')
        original_lstat = Path.lstat
        for selected in [files[0], files[0].parent]:
            def shaped(path, *args, **kwargs):
                return SimpleNamespace(st_mode=0o100644, st_file_attributes=0x400, st_size=100) if path == selected else original_lstat(path, *args, **kwargs)
            with patch.object(Path, 'lstat', shaped): self.assertFalse(self.derived_values([files[0]]))

    def test_symlink_privilege_restriction_retains_both_mandatory_reparse_checks(self):
        observed = []
        derived_values = self.derived_values
        def observe_reparse(files, *args, **kwargs):
            observed.append(tuple(bool(getattr(path.lstat(), 'st_file_attributes', 0) & 0x400)
                                  for path in (files[0], files[0].parent)))
            return derived_values(files, *args, **kwargs)
        denied = OSError('simulated symlink privilege restriction')
        denied.winerror = 1314
        with patch.object(Path, 'symlink_to', side_effect=denied), \
                patch.object(self, 'skipTest', side_effect=AssertionError('mandatory reparse checks skipped')) as skip, \
                patch.object(self, 'derived_values', side_effect=observe_reparse):
            self.test_derived_report_leaf_ancestor_links_and_reparse_refused()
        skip.assert_not_called()
        self.assertEqual(observed, [(True, False), (False, True)])
        for winerror in (5, None):
            with self.subTest(winerror=winerror):
                failure = OSError('simulated unrelated symlink failure')
                if winerror is not None:
                    failure.winerror = winerror
                with patch.object(Path, 'symlink_to', side_effect=failure), \
                        patch.object(self, 'skipTest', side_effect=AssertionError('unrelated failure skipped')) as skip:
                    with self.assertRaises(OSError) as raised:
                        self.test_derived_report_leaf_ancestor_links_and_reparse_refused()
                self.assertIs(raised.exception, failure)
                skip.assert_not_called()


    def test_copied_installer_runtime_and_remapped_roots_keep_exact_rederivation(self):
        files, local, imported = self.derived_sources(naos='controls/naos')
        values = self.derived_values(files, 'controls/naos')
        self.assertEqual(len(values), 4)
        self.assertFalse(self.derived_values(files))
        tree = ast.parse((KIT / 'naos_init.py').read_text(encoding='utf-8'))
        scaffold = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'scaffold_files')
        assignments = {n.targets[0].id: n for n in ast.walk(scaffold) if isinstance(n, ast.Assign)
                       and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                       and n.targets[0].id in {'schema_src', 'adopter_schema_names'}}
        schema_copy = next(n for n in ast.walk(scaffold) if isinstance(n, ast.If) and ast.unparse(n.test) == 'schema_src.is_dir()')
        preview = self.root / 'copied'; preview.mkdir()
        namespace = {'KIT_DIR': KIT, 'preview_dir': preview, 'tier': 'assured', 'copy_source': shutil.copy2, 'generated': []}
        exec(compile(ast.Module(body=[assignments['schema_src'], assignments['adopter_schema_names'], schema_copy], type_ignores=[]), 'actual_schema_copy', 'exec'), namespace)
        for name in ['local_context_index', 'external_evidence_ingest']:
            self.assertEqual((preview / ('schemas/naos/' + name + '.schema.json')).read_bytes(), (KIT / ('schemas/naos/' + name + '.schema.json')).read_bytes())
        copier = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_copy_generated_script')
        block = next(n for n in ast.walk(scaffold) if isinstance(n, ast.If)
                     and ast.unparse(n.test) == "scripts_src.is_dir() and tier != 'quickstart'")
        loop = next(n for n in block.body if isinstance(n, ast.For) and ast.unparse(n.iter) == 'scripts_src.iterdir()')
        scope = {'Path': Path, 'shutil': shutil, 'SourceOrigins': object,
                 'scripts_src': KIT / 'scripts', 'preview_dir': preview, 'tier': 'assured',
                 'source_origins': None, 'copied_tool_outputs': set(), 'generated': []}
        exec(compile(ast.Module(body=[copier] + block.body[:block.body.index(loop) + 1], type_ignores=[]),
                     'actual_assured_installer_selection', 'exec'), scope)
        scripts = preview / 'scripts'
        target = preview / 'controls/naos/reports'; target.mkdir(parents=True)
        expected = set(values)
        for original in files:
            doc = json.loads(original.read_text(encoding='utf-8')); doc['project_root'] = str(preview)
            (target / original.name).write_text(json.dumps(doc), encoding='utf-8')
        code = "import sys,json; from pathlib import Path; sys.path.insert(0,sys.argv[1]); import naos_secret_public_literals as p; root=Path(sys.argv[2]); files=list((root/'controls/naos/reports').glob('*.json')); assert p.selected_public_derived_report_ids(files,root=root,naos_root='controls/naos') == set(json.loads(sys.argv[3])); assert p.load_public_literals(root=root,naos_root='controls/naos')[1]['runtime_layout']=='copied_project'"
        result = subprocess.run([sys.executable, '-B', '-c', code, str(scripts), str(preview), json.dumps(sorted(expected))], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)



    def test_actual_lite_installer_preserves_local_ids_and_external_review_without_ingest(self):
        files, local, imported = self.derived_sources()
        tree = ast.parse((KIT / 'naos_init.py').read_text(encoding='utf-8'))
        copier = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_copy_generated_script')
        scaffold = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'scaffold_files')
        block = next(n for n in ast.walk(scaffold) if isinstance(n, ast.If)
                     and ast.unparse(n.test) == "scripts_src.is_dir() and tier != 'quickstart'")
        loop = next(n for n in block.body if isinstance(n, ast.For) and ast.unparse(n.iter) == 'scripts_src.iterdir()')
        preview = self.root / 'copied-lite'; preview.mkdir()
        namespace = {'Path': Path, 'shutil': shutil, 'SourceOrigins': object,
                     'scripts_src': KIT / 'scripts', 'preview_dir': preview, 'tier': 'lite',
                     'source_origins': None, 'copied_tool_outputs': set(), 'generated': []}
        exec(compile(ast.Module(body=[copier] + block.body[:block.body.index(loop) + 1], type_ignores=[]),
                     'actual_lite_installer_selection', 'exec'), namespace)
        scripts = preview / 'scripts'
        self.assertTrue((scripts / 'naos_local_context_index.py').is_file())
        self.assertTrue((scripts / 'naos_external_evidence_ingest.py').is_file())
        assignments = {n.targets[0].id: n for n in ast.walk(scaffold) if isinstance(n, ast.Assign)
                       and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                       and n.targets[0].id in {'schema_src', 'adopter_schema_names'}}
        schema_copy = next(n for n in ast.walk(scaffold) if isinstance(n, ast.If) and ast.unparse(n.test) == 'schema_src.is_dir()')
        schema_namespace = {'KIT_DIR': KIT, 'preview_dir': preview, 'tier': 'lite',
                            'copy_source': shutil.copy2, 'generated': []}
        exec(compile(ast.Module(body=[assignments['schema_src'], assignments['adopter_schema_names'], schema_copy],
                               type_ignores=[]), 'actual_lite_schema_copy', 'exec'), schema_namespace)
        target = preview / 'naos/reports'; target.mkdir(parents=True)
        for original in files:
            document = json.loads(original.read_text(encoding='utf-8'))
            document.update(project_root=str(preview), profile='lite')
            (target / original.name).write_text(json.dumps(document), encoding='utf-8')
        expected = self.derived_values(files)
        local_id = local['indexed_artifacts'][0]['artifact_id']
        code = """import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import naos_secret_public_literals as public
import naos_control_plane_review as control
from naos_policy import SAFE_FALLBACK_POLICY
root=Path(sys.argv[2]); reports=root/'naos/reports'
local=reports/'local_context_index.json'; external=reports/'external_evidence_ingest.json'
public.read_catalog()
assert public.selected_public_derived_report_ids([local],root=root,naos_root='naos')=={sys.argv[3],'artifact:'+sys.argv[3]}
assert public.selected_public_derived_report_ids([local,external],root=root,naos_root='naos')==set(json.loads(sys.argv[4]))
document=json.loads(external.read_text(encoding='utf-8'))
assert control.validate_external_sarif_report(document)==([],[])
_,_,review=control.build_external_sarif_reconciliation(root=root,profile='lite',naos_root='naos',
    policy=SAFE_FALLBACK_POLICY,rules={},allowed_source_types={control.EXTERNAL_SARIF_SOURCE_TYPE},
    allowed_target_surfaces=set(control.EXTERNAL_SARIF_TARGETS),allowed_dispositions={'needs_review'},required_fields=[])
assert len(review['routes'])==1 and review['status']=='review_required'
assert document['result_records'][0]['origin']=='external_unverified'
assert 'naos_external_evidence_ingest' not in sys.modules
"""
        result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(scripts), str(preview),
                                 local_id, json.dumps(sorted(expected))], capture_output=True, text=True, timeout=25)
        self.assertEqual(result.returncode, 0, result.stderr)

    def chunk_report(self, counts=(2, 1)):
        files, document, imported = self.derived_sources()
        candidates = []
        per_path = {}
        for number, count in enumerate(counts):
            path = self.write(f'src/chunk{number}.py', 'def ordinary():\n    return 1\n')
            candidates.append({'path': str(path), 'family': {'id': 'python_sources'}})
            per_path[path.name] = [{'text': f'ordinary section {i}'} for i in range(count)]
        with patch.object(index, 'collect_candidates', return_value=(candidates, [])), \
                patch.object(index, 'chunks_for_artifact_bytes', side_effect=lambda path, *args: per_path[path.name]):
            artifacts, chunks, _, _ = index.build_artifact_records(self.root, {}, TIME)
        producer = ast.parse((KIT / 'scripts/naos_local_context_index.py').read_text(encoding='utf-8'))
        report = next(n for n in ast.walk(producer) if isinstance(n, ast.Dict)
                      and any(isinstance(k, ast.Constant) and k.value == 'artifact_chunks' for k in n.keys))
        prefix = next(v for k, v in zip(report.keys, report.values)
                      if isinstance(k, ast.Constant) and k.value == 'artifact_chunks')
        emitted = eval(compile(ast.Expression(prefix), 'actual-public-chunk-prefix', 'eval'), {'chunks': chunks})
        document.update(indexed_artifacts=artifacts, artifact_chunks=emitted,
                        chunk_counts={'artifacts': len(artifacts), 'chunks': len(chunks)})
        files[0].write_text(json.dumps(document), encoding='utf-8')
        return files, document, chunks

    def test_public_chunks_share_unchanged_producer_formula_and_exact_verified_parent_order(self):
        files, document, chunks = self.chunk_report()
        for ordinal, chunk in enumerate(chunks[:2], start=1):
            self.assertEqual(chunk['chunk_id'], f"{chunk['artifact_id']}-C{ordinal:03d}")
            self.assertEqual(index.chunk_id_for(chunk['artifact_id'], ordinal), chunk['chunk_id'])
        values = self.derived_values(files)
        self.assertTrue({chunk['chunk_id'] for chunk in chunks} <= values)
        for invalid in [True, 0, -1, '1']:
            with self.assertRaises(ValueError): index.chunk_id_for('A-ordinary', invalid)

    def test_public_chunks_truncated_at200_keep_order_and_full_parent_counts(self):
        files, document, chunks = self.chunk_report((150, 75))
        self.assertEqual(len(chunks), 225)
        self.assertEqual(len(document['artifact_chunks']), 200)
        self.assertEqual([a['chunk_count'] for a in document['indexed_artifacts']], [150, 75])
        values = self.derived_values(files)
        self.assertTrue({c['chunk_id'] for c in chunks[:200]} <= values)
        self.assertNotIn(chunks[200]['chunk_id'], values)
        self.assertEqual(chunks[199]['chunk_id'], chunks[199]['artifact_id'] + '-C050')
        document['indexed_artifacts'][0]['chunk_count'] += 1
        document['chunk_counts']['chunks'] += 1
        files[0].write_text(json.dumps(document), encoding='utf-8')
        self.assertFalse({c['chunk_id'] for c in chunks[:200]} & self.derived_values(files))

    def test_public_chunks_missing_mixed_duplicate_forged_path_count_or_id_fail_closed(self):
        files, document, chunks = self.chunk_report()
        mutations = []
        for key, value in [('chunk_id', chunks[0]['chunk_id']+'0'), ('artifact_id', document['indexed_artifacts'][1]['artifact_id']),
                           ('path', 'src/other.py'), ('source_reference', 'src/other.py')]:
            bad = copy.deepcopy(document); bad['artifact_chunks'][0][key] = value; mutations.append(bad)
        for records in [chunks[:-1], [chunks[1], chunks[0], chunks[2]], [chunks[0], chunks[0], chunks[2]], [None]+chunks[1:]]:
            bad=copy.deepcopy(document);bad['artifact_chunks']=records;mutations.append(bad)
        for count in [True, -1, 16385, 3]:
            bad=copy.deepcopy(document);bad['indexed_artifacts'][0]['chunk_count']=count;mutations.append(bad)
        bad=copy.deepcopy(document);bad['chunk_counts']['chunks']+=1;mutations.append(bad)
        bad=copy.deepcopy(document);del bad['indexed_artifacts'][0]['chunk_count'];mutations.append(bad)
        bad=copy.deepcopy(document);bad['chunk_counts']['artifacts']=True;mutations.append(bad)
        bad=copy.deepcopy(document);bad['indexed_artifacts'][0]['artifact_id']='A-forged';mutations.append(bad)
        for bad in mutations:
            with self.subTest(bad=bad['artifact_chunks'][0]):
                files[0].write_text(json.dumps(bad), encoding='utf-8'); values=self.derived_values(files)
                self.assertFalse({c['chunk_id'] for c in chunks} & values)
        document.pop('artifact_chunks');files[0].write_text(json.dumps(document), encoding='utf-8')
        values=self.derived_values(files)
        self.assertFalse({c['chunk_id'] for c in chunks} & values)
        self.assertIn(document['indexed_artifacts'][0]['artifact_id'], values)

    def test_public_chunks_unselected_custom_context_schema_or_bounded_inputs_do_not_qualify(self):
        files, document, chunks = self.chunk_report()
        label=chunks[0]['chunk_id'];self.assertNotIn(label,self.derived_values([]))
        custom=self.write('naos/reports/custom_chunks.json',document);self.assertNotIn(label,self.derived_values([custom]))
        document['project_root']=str(self.root/'elsewhere');files[0].write_text(json.dumps(document), encoding='utf-8');self.assertNotIn(label,self.derived_values(files))
        document['project_root']=str(self.root);document['schema']='wrong';files[0].write_text(json.dumps(document), encoding='utf-8');self.assertNotIn(label,self.derived_values(files))
        document['schema']=index.REPORT_SCHEMA;files[0].write_text(json.dumps(document), encoding='utf-8')
        with patch.dict(public._REFERENCE_SCHEMAS, {'local_context_index':'f'*64}):self.assertNotIn(label,self.derived_values(files))
        files[0].write_text(' '*(1024*1024+1), encoding='utf-8');self.assertNotIn(label,self.derived_values(files))

    def test_public_chunks_only_exact_labels_leave_excerpts_neighbors_provider_assignment_scanned(self):
        files, document, chunks = self.chunk_report()
        label=chunks[0]['chunk_id'];document['artifact_chunks'][0]['bounded_excerpt']=TOKEN
        files[0].write_text(json.dumps(document), encoding='utf-8');self.write('chunk-neighbors.json', {'known':label,'mixed':label+TOKEN,'unknown':TOKEN,'password':label,'provider':'sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'})
        report=common.check_secret_hygiene(root=self.root,profile='assured',naos_root='naos',rules={},rules_path=None,severity='blocking')
        self.assertTrue(any(f.get('path')=='chunk-neighbors.json' and f['status']=='high_entropy_literal' for f in report['findings']))
        self.assertTrue(any(f.get('path')=='chunk-neighbors.json' and f.get('pattern_id')=='assigned_secret' for f in report['findings']))
        self.assertTrue(any(f.get('pattern_id')=='openai_style_key' for f in report['findings']))
        self.assertTrue(any(f.get('path')==files[0].relative_to(self.root).as_posix() and f['status']=='high_entropy_literal' for f in report['findings']))
        with patch.object(public, 'recompute_public_external_result_id', wraps=public.recompute_public_external_result_id):
            import builtins
            original=builtins.__import__
            def without_local(name, *args, **kwargs):
                if name=='naos_local_context_index':raise ImportError('optional local supplier unavailable')
                return original(name,*args,**kwargs)
            with patch.object(builtins,'__import__',side_effect=without_local):
                values=self.derived_values(files)
        self.assertNotIn(label,values)
        external_document=json.loads(files[1].read_text(encoding='utf-8'));identifier=external_document['result_records'][0]['external_result_id']
        self.assertIn(identifier,values)
        self.assertIn(public.recompute_public_external_route_id(external_document['result_records'][0]),values)


    def test_shared_scanner_comparison_cache_mutation_after_admission_refuses(self):
        import os
        import naos_secret_managed_operands as managed
        record_relative = 'naos/review-inputs/pr-review.json'
        original_comparison = common.public_git_comparison_spans
        for member_role in ('review_record', 'carrier'):
            with self.subTest(cached_member=member_role):
                path, chosen, _ = self.comparison_carrier(self.git_comparison_report())
                relative = path.relative_to(self.root).as_posix()
                mutated_relative = record_relative if member_role == 'review_record' else relative
                admitted = []
                observed = {}

                def mutate_after_real_admission(text, current_relative, **kwargs):
                    spans = original_comparison(text, current_relative, **kwargs)
                    if spans:
                        self.assertEqual(current_relative, relative)
                        self.assertEqual(len(spans), 2)
                        context = kwargs['context']
                        self.assertIsInstance(context, managed._ScannerProofBudget)
                        # The scanner supplies its shared proof object to the
                        # actual comparison helper; neither input belongs to a
                        # managed-family path prefix or needs selected coverage.
                        self.assertIn(record_relative, context.cache)
                        self.assertIn(relative, context.cache)
                        self.assertEqual(set(context.cache), {record_relative, relative})
                        observed['context'] = context
                        observed['charged'] = context.bytes_read
                        admitted.append(current_relative)
                        member = self.root / mutated_relative
                        before = member.lstat()
                        raw = member.read_bytes()
                        member.write_bytes(raw + b'\nchanged-after-comparison-admission')
                        os.utime(member, ns=(before.st_atime_ns,
                                            before.st_mtime_ns + 2_000_000_000))
                        self.assertNotEqual(managed._snapshot(member.lstat()),
                                            managed._snapshot(before),
                                            'fixture must establish an observed mutation')
                        self.assertNotEqual(member.read_bytes(), raw)
                    return spans

                with patch.object(common, 'public_git_comparison_spans',
                                  side_effect=mutate_after_real_admission), \
                        patch.object(common, 'build_base_report',
                                     wraps=common.build_base_report) as build:
                    with self.assertRaisesRegex(managed.OperandRefusal,
                                                '^scan_proof_invalidated$'):
                        common.check_secret_hygiene(
                            root=self.root, profile='assured', naos_root='naos',
                            rules={'scan_roots': [relative], 'include_root_files': False},
                            rules_path=None, severity='blocking', policy=chosen)
                self.assertEqual(admitted, [relative])
                build.assert_not_called()
                self.assertEqual(observed['context'].bytes_read, observed['charged'])


if __name__ == '__main__':
    unittest.main()
