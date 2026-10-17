"""Exact local source references preserve adverse evidence with finite composition."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from jsonschema import Draft202012Validator
KIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KIT / 'scripts'))
sys.path.insert(0, str(KIT / 'scripts/workflows'))
import naos_hygiene_common as common
import naos_report_composition as composition
import naos_evidence_export as exporter
import naos_capability_maturity as maturity
import generate_naos_dashboard as dashboard
from naos_policy import SAFE_FALLBACK_POLICY, report_default_path

class CompositionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve();(self.root / 'naos/reports').mkdir(parents=True)
    def write(self, name, value):
        path = self.root / name;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(value,indent=2));return path
    def entry(self, path):
        return dashboard.read_json_artifact(path, 'source')
    def create_symlink(self, path, target, *, target_is_directory=False):
        try:
            path.symlink_to(target, target_is_directory=target_is_directory)
        except OSError as error:
            if sys.platform == 'win32' and getattr(error, 'winerror', None) == 1314:
                self.skipTest('Windows token lacks symlink privilege; portable path checks still run')
            raise
    def test_adverse_unknown_unverified_and_legacy_exact_payload_access(self):
        data = {'schema':'naos.source.v1','status':'unknown','human_approval_required':True,
                'findings':[{'id':'distinct-adverse','severity':'blocking'}],
                'external_references':[{'url':'https://example.invalid/unverified','verified':False}]}
        path = self.write('naos/reports/source.json',data);entry = self.entry(path)
        ref = composition.source_reference(entry,self.root)
        self.assertNotIn('data',ref);self.assertEqual(ref['report_status'],'unknown')
        self.assertEqual(ref['source_sha256'],hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(ref['source_size_bytes'],len(path.read_bytes()))
        self.assertEqual(composition.read_collection_entry(ref,self.root)['data'],data)
        self.assertEqual(composition.read_collection_entry(entry,self.root)['data'],data)
        path.write_text('{"status":"pass"}');self.assertEqual(composition.read_collection_entry(ref,self.root)['reason'],'changed_source')
        path.unlink();self.assertEqual(composition.read_collection_entry(ref,self.root)['reason'],'missing_source')
    def test_malformed_domain_retention_schema_and_adverse_review(self):
        path = self.write('naos/reports/cross_harness_review_readiness_report.json',{'status':'blocked','readiness_score':'not-an-integer','findings':[{'id':'negative-evidence'}]})
        args=exporter.build_parser().parse_args(['--profile','quickstart','--cross-harness-review-readiness-report',str(path)])
        internal=exporter.build_evidence_pack(root=self.root,profile='quickstart',naos_root='naos',policy=SAFE_FALLBACK_POLICY,args=args)
        output=composition.compose_publication(internal,self.root)
        self.assertEqual(output['readiness']['status'],'unresolved')
        self.assertEqual(output['cross_harness_review_readiness']['projection_status'],'invalid_input')
        ref=output['artifacts']['cross_harness_review_readiness_report']
        self.assertEqual(composition.read_collection_entry(ref,self.root)['data'],json.loads(path.read_bytes()))
        Draft202012Validator(json.loads((KIT/'schemas/naos/evidence_pack.schema.json').read_text())).validate(output)
    def test_missing_unsafe_malformed_oversized_and_unknown_version_refusal(self):
        path=self.write('naos/reports/source.json',{'status':'blocked'});ref=composition.source_reference(self.entry(path),self.root)
        for value in ('../outside.json','/outside.json','naos\\reports\\source.json','naos//reports/source.json'):
            altered={**ref,'source_reference':value};self.assertEqual(composition.read_collection_entry(altered,self.root)['reason'],'unsafe_source_reference')
        self.assertEqual(composition.read_collection_entry(ref,self.root,max_bytes=1)['reason'],'oversized_source')
        self.assertEqual(composition.read_collection_entry({**ref,'schema':'naos.report_source_reference.v9'},self.root)['reason'],'unknown_collection_version')
        path.write_text('{broken');bad=composition.source_reference({**self.entry(path),'collection_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'collection_size_bytes':len(path.read_bytes())},self.root)
        bad['detail_availability']='source_bound';self.assertIsNone(composition.read_collection_entry(bad,self.root)['data'])

    def test_native_only_linked_leaf_source_refuses(self):
        path=self.write('naos/reports/source.json',{'status':'blocked'});ref=composition.source_reference(self.entry(path),self.root)
        path.unlink();self.create_symlink(path,KIT/'schemas/naos/evidence_pack.schema.json')
        self.assertEqual(composition.read_collection_entry(ref,self.root)['reason'],'unsafe_source_reference')
    def test_large_classifier_and_three_composition_cycles(self):
        values=[{'id':'finding-'+str(i),'message':'x'*1024,'severity':'blocking'} for i in range(9000)]
        data={'schema':'naos.evidence_classification_report.v1','status':'review_required','policy_valid':True,
              'findings_scanned':9000,'classification_counts':{'unknown':9000},'human_review_required':True,
              'missing_classification':values,'unknown_findings':values,'findings':values,'unclassified_context':values}
        path=self.write('naos/reports/evidence_classification.json',data);self.assertGreater(path.stat().st_size,8*1024*1024);self.assertLess(path.stat().st_size,64*1024*1024)
        entry=self.entry(path);sizes=[]
        for cycle in range(3):
            pack={'schema':'naos.evidence_pack.v1','artifacts':{'evidence_classification_report':entry},'evidence_classification':exporter.summarize_evidence_classification(entry),'findings':[{'id':'native-finding'}]}
            composed=composition.compose_publication(pack,self.root)
            dash={'schema':'naos.dashboard_summary.v1','inputs':{'evidence_classification':entry,'evidence_pack':self.entry(self.write('naos/evidence/evidence_pack.json',composed))},'evidence_classification':dashboard.summarize_evidence_classification(entry),'findings':[{'id':'native-finding'}]}
            composed_dash=composition.compose_publication(dash,self.root)
            self.assertNotIn('data',composed_dash['inputs']['evidence_pack']);sizes.append((len(composition.checked_publication_bytes(composed)),len(composition.checked_publication_bytes(composed_dash))))
            for result in (composed,composed_dash):
                summary=result['evidence_classification'];self.assertTrue(summary['human_review_required']);self.assertEqual(summary['status'],'review_required')
                for bucket in composition.CLASSIFICATION_BUCKETS:
                    ref=summary['collection_references'][bucket];self.assertEqual(ref['item_count'],9000)
                    raw=json.dumps(values,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode()
                    self.assertEqual(ref['canonical_sha256'],hashlib.sha256(raw).hexdigest())
                    self.assertNotIn(bucket,summary);self.assertEqual(composition.read_collection_bucket(ref,self.root)['data'],values)
        corrupt=copy.deepcopy(ref);corrupt['item_count']+=1;self.assertEqual(composition.read_collection_bucket(corrupt,self.root)['reason'],'changed_collection_identity')
        self.assertEqual(sizes,[sizes[0]]*3);self.assertLess(max(max(pair) for pair in sizes),8*1024*1024)
    def test_pack_alone_and_same_relative_path_review_relocation(self):
        path=self.write('naos/reports/source.json',{'findings':[{'id':'historical'}]});ref=composition.source_reference(self.entry(path),self.root)
        with tempfile.TemporaryDirectory() as temp:
            review=Path(temp).resolve();self.assertEqual(composition.read_collection_entry(ref,review)['reason'],'missing_source')
            target=review/'naos/reports/source.json';target.parent.mkdir(parents=True);shutil.copyfile(path,target)
            self.assertEqual(composition.read_collection_entry(ref,review)['data'],json.loads(path.read_bytes()))
    def test_publication_bound_refuses_before_writer(self):
        self.assertEqual(composition.PUBLICATION_MAX_BYTES,8*1024*1024)
        with self.assertRaises(composition.CompositionError):composition.checked_publication_bytes({'findings':['x'*(8*1024*1024)]})
    def signal_fixture(self):
        fields={'capability_id':'CAP-X','enabled':True,'current_maturity':'L1','target_maturity':'L4','evaluated_status':'ready','ready_for_promotion':True,'human_approval_required':True,'promotion_recorded':False,'missing_evidence':[],'stale_evidence':[],'waivers':[],'required_next_actions':[]}
        l2={'stage':'L2',**{k:None for k in composition.L2_FIELDS},'reference':'review.md','content_sha256':'a'*64,'candidates':[{'reference':'review.md','content_sha256':'a'*64,'availability':'available','requirement_outcome':'satisfied'}]}
        l2.update(availability='available',validation='valid',requirement_outcome='satisfied',generation_age={'status':'unknown','basis':'fixture','timestamp':None},requirement_contract={'type':'manual','optional':False,'require_current_source':False,'freshness_window_days':0},claim_ceiling='manual_review')
        row={**fields,'evidence_results':[l2]};state={'path':str(self.root/'naos/capability_state.yaml'),'exists':True,'source':'project'}
        current={'schema':'naos.capability_maturity.v1','profile':'standard','naos_root':'naos','project_root':str(self.root),'state':state,'capabilities':[row]}
        schema=json.loads((KIT/'schemas/naos/capability_maturity_report.schema.json').read_text())
        current.update(generated_at='2026-10-10T12:00:00Z',status='ready',findings=[],limitations=[],related_evidence={},policy={'version':None,'source':'fixture','path':None},semantics={k:'fixture' for k in ('state','report','promotion','flow')},summary={k:0 for k in schema['properties']['summary']['required']})
        Draft202012Validator(schema).validate(current)
        self.write('naos/reports/capability_maturity.json',current)
        return row,l2,current
    def signal(self, doc, row, l2):
        path=self.write('naos/reports/dashboard_summary.json',doc)
        return maturity._current_signal_projection(self.root,'naos',SAFE_FALLBACK_POLICY,'standard','CAP-X',row,path.relative_to(self.root).as_posix(),[l2],self.root/'naos/capability_state.yaml',hashlib.sha256(path.read_bytes()).hexdigest())
    def test_maturity_legacy_witness_parity_and_every_proof_field(self):
        row,l2,current=self.signal_fixture();entry=self.entry(self.root/'naos/reports/capability_maturity.json')
        old={'schema':'naos.dashboard_summary.v1','inputs':{'capability_maturity':entry},'capability_maturity_readiness':{'capabilities':[row]}}
        new=composition.compose_publication(old,self.root)
        self.assertEqual(self.signal(old,row,l2),(True,'current_selected_projection'));self.assertEqual(self.signal(new,row,l2),self.signal(old,row,l2))
        for key in composition.PROOF_FIELDS:
            changed=copy.deepcopy(new);w=changed['inputs']['capability_maturity']['collection_witness'];value=w['capabilities'][0][key]
            w['capabilities'][0][key]=not value if isinstance(value,bool) else value+'-changed' if isinstance(value,str) else value+[{}] if key=='waivers' else value+['changed']
            with self.subTest(field=key):self.assertFalse(self.signal(changed,row,l2)[0])
        for key in composition.L2_FIELDS:
            changed=copy.deepcopy(new);changed['inputs']['capability_maturity']['collection_witness']['capabilities'][0]['evidence_results'][0][key]='changed'
            with self.subTest(l2=key):self.assertFalse(self.signal(changed,row,l2)[0])
        for key in composition.CANDIDATE_FIELDS:
            changed=copy.deepcopy(new);changed['inputs']['capability_maturity']['collection_witness']['capabilities'][0]['evidence_results'][0]['candidates'][0][key]='changed';self.assertFalse(self.signal(changed,row,l2)[0])
        for key in ('profile','naos_root','project_root','source_schema','state'):
            changed=copy.deepcopy(new);changed['inputs']['capability_maturity']['collection_witness'][key]='changed';self.assertFalse(self.signal(changed,row,l2)[0])
        current['generated_at']='later';self.write('naos/reports/capability_maturity.json',current);self.assertTrue(self.signal(new,row,l2)[0])
        partial=copy.deepcopy(old);partial['inputs']['capability_maturity']['data'].pop('semantics');self.assertFalse(self.signal(partial,row,l2)[0])
        spoof=copy.deepcopy(new);spoof['inputs']['capability_maturity']['collection_witness']['schema']='naos.capability_maturity.v1';self.assertFalse(self.signal(spoof,row,l2)[0])

    def test_secret_injections_and_exact_scanned_bytes(self):
        token='aB3dE5fG7hI9jK0mN2pQ4rS6tU8vW+/='
        original=self.write('naos/reports/original.json',{'api_key':token,'findings':[{'id':'adverse','diagnostic':token}]})
        ref=composition.source_reference(self.entry(original),self.root)
        ref['error']=token;metadata=self.write('naos/reports/reference.json',ref)
        legacy=self.write('naos/reports/legacy.json',{'data':{'credential':token}})
        before={p.relative_to(self.root).as_posix():p.read_bytes() for p in (original,metadata,legacy)}
        report=common.check_secret_hygiene(root=self.root,profile='standard',naos_root='naos',rules={'scan_roots':list(before),'include_root_files':False},rules_path=None,severity='blocking',policy=SAFE_FALLBACK_POLICY)
        self.assertGreaterEqual(report['summary']['regex_matches'],2)
        self.assertEqual({f['path'] for f in report['findings']},set(before))
        for row in report['scans']['input_files']:
            self.assertEqual(row['sha256'],hashlib.sha256(before[row['path']]).hexdigest());self.assertEqual(row['size_bytes'],len(before[row['path']]))
        original.write_bytes(before['naos/reports/original.json']+b' ')
        self.assertNotEqual(report['scans']['input_files'][0]['sha256'],hashlib.sha256(original.read_bytes()).hexdigest())
    def test_copied_reference_runtime_and_exact_schema(self):
        path=self.write('naos/reports/source.json',{'findings':[{'id':'adverse'}]});ref=composition.source_reference(self.entry(path),self.root)
        self.write('ref.json',ref)
        with tempfile.TemporaryDirectory() as temp:
            runtime=Path(temp);(runtime/'scripts').mkdir();(runtime/'schemas/naos').mkdir(parents=True)
            shutil.copy2(KIT/'scripts/naos_report_composition.py',runtime/'scripts/naos_report_composition.py')
            shutil.copy2(KIT/'schemas/naos/report_source_reference.schema.json',runtime/'schemas/naos/report_source_reference.schema.json')
            code="import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);from naos_report_composition import read_collection_entry;root=Path(sys.argv[2]);ref=json.loads((root/'ref.json').read_text());assert read_collection_entry(ref,root)['data']['findings'][0]['id']=='adverse'"
            result=subprocess.run([sys.executable,'-I','-B','-c',code,str(runtime/'scripts'),str(self.root)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
    def test_real_publication_and_failure_preserves_both_outputs(self):
        pack=self.root/'naos/evidence/evidence_pack.json';pack.parent.mkdir();pack.write_text('old pack')
        with patch.object(exporter,'build_evidence_pack',return_value={'schema':'naos.evidence_pack.v1','artifacts':{},'findings':['x'*(8*1024*1024)]}),patch.object(exporter.Path,'cwd',return_value=self.root):
            self.assertEqual(exporter.main(['--output',str(pack)]),2)
        self.assertEqual(pack.read_text(),'old pack')
        markdown=self.root/'naos/DASHBOARD.md';markdown.write_text('old markdown');summary=self.root/'naos/reports/dashboard_summary.json';summary.write_text('old summary')
        fake={'schema':'naos.dashboard_summary.v1','inputs':{},'findings':['x'*(8*1024*1024)]}
        with patch.object(dashboard,'build_dashboard_summary',return_value=fake),patch.object(dashboard,'dashboard_finding_occurrences',return_value=([],[])),patch.object(dashboard,'render_dashboard',return_value='new markdown'),patch.object(dashboard.Path,'cwd',return_value=self.root):
            with patch.object(sys,'argv',['dashboard','--output',str(markdown),'--json-output',str(summary)]):
                self.assertEqual(dashboard.main(),2)
        self.assertEqual(markdown.read_text(),'old markdown');self.assertEqual(summary.read_text(),'old summary')

    def test_contained_symlink_and_windows_reparse_attributes_refused_before_resolution(self):
        import stat
        from types import SimpleNamespace
        path=self.write('naos/reports/source.json',{'status':'blocked'})
        ref=composition.source_reference(self.entry(path),self.root)
        real_lstat=Path.lstat
        for selected in (self.root, self.root/'naos/reports', path):
            def flagged_lstat(target, *args, **kwargs):
                info=real_lstat(target,*args,**kwargs)
                if target == selected:
                    return SimpleNamespace(st_mode=info.st_mode,st_file_attributes=0x400)
                return info
            with self.subTest(component=selected.relative_to(self.root).as_posix()),patch.object(Path,'lstat',flagged_lstat):
                self.assertEqual(composition.read_collection_entry(ref,self.root)['reason'],'unsafe_source_reference')
        self.assertEqual(composition.read_collection_entry(ref,self.root)['data'],{'status':'blocked'})
        missing=composition.source_reference({'label':'absent','path':str(self.root/'naos/missing/no.json'),'status':'missing','exists':False,'data':None},self.root)
        self.assertEqual(missing['source_reference'],'naos/missing/no.json')
        self.assertEqual(missing['detail_reason'],'source_missing')

    def test_native_only_contained_symlink_and_symlink_root_refused(self):
        path=self.write('naos/reports/source.json',{'status':'blocked'});ref=composition.source_reference(self.entry(path),self.root)
        alias=self.root/'naos/contained';self.create_symlink(alias,self.root/'naos/reports',target_is_directory=True)
        contained={**ref,'source_reference':'naos/contained/source.json'}
        self.assertEqual(composition.read_collection_entry(contained,self.root)['reason'],'unsafe_source_reference')
        alias_root=self.root/'alias-root';self.create_symlink(alias_root,self.root,target_is_directory=True)
        self.assertEqual(composition.read_collection_entry(ref,alias_root)['reason'],'unsafe_source_reference')

    def test_nonregular_unreadable_and_root_ancestor_refusal_without_opening(self):
        path=self.write('naos/reports/source.json',{'status':'blocked'})
        ref=composition.source_reference(self.entry(path),self.root)
        real_open=Path.open
        def checked_open(selected,*args,**kwargs):
            if selected == path:raise AssertionError('refused source must never be opened')
            return real_open(selected,*args,**kwargs)
        path.unlink();path.mkdir()
        self.assertEqual(composition.read_collection_entry(ref,self.root)['reason'],'not_regular_source')
        path.rmdir();path.write_text('{}')
        with patch.object(composition.os,'access',return_value=False),patch.object(Path,'open',checked_open):
            self.assertEqual(composition.read_collection_entry(ref,self.root)['reason'],'unreadable_source')
        original_lstat=Path.lstat
        def denied_lstat(selected,*args,**kwargs):
            if selected == path:raise OSError('untrusted mount with credential-like diagnostic')
            return original_lstat(selected,*args,**kwargs)
        with patch.object(Path,'lstat',denied_lstat),patch.object(Path,'open',checked_open):
            self.assertEqual(composition.read_collection_entry(ref,self.root)['reason'],'unreadable_source')
        alias=self.root/'ancestor-alias'
        original_lstat=Path.lstat
        def reparse_ancestor(selected,*args,**kwargs):
            info=original_lstat(selected,*args,**kwargs)
            if selected==alias:
                from types import SimpleNamespace
                return SimpleNamespace(**{name:getattr(info,name) for name in dir(info) if name.startswith('st_')} | {'st_file_attributes':0x400})
            return info
        alias.mkdir();(alias/'reports').mkdir()
        with patch.object(Path,'lstat',reparse_ancestor):
            self.assertEqual(composition.read_collection_entry({**ref,'source_reference':'source.json'},alias/'reports')['reason'],'unsafe_source_reference')

    def test_native_only_fifo_source_refusal(self):
        path=self.write('naos/reports/source.json',{'status':'blocked'});ref=composition.source_reference(self.entry(path),self.root)
        real_open=Path.open
        def checked_open(selected,*args,**kwargs):
            if selected == path:raise AssertionError('refused source must never be opened')
            return real_open(selected,*args,**kwargs)
        if not hasattr(os,'mkfifo'):
            self.skipTest('FIFO source requires POSIX mkfifo')
        path.unlink();os.mkfifo(path)
        with patch.object(Path,'open',checked_open):
            result=composition.read_collection_entry(ref,self.root)
        self.assertEqual(result['reason'],'not_regular_source')
        self.assertEqual(result['requirement_outcome'],'unresolved')

    def test_native_only_symlink_ancestor_refusal(self):
        path=self.write('naos/reports/source.json',{'status':'blocked'});ref=composition.source_reference(self.entry(path),self.root)
        alias=self.root/'ancestor-alias';self.create_symlink(alias,self.root/'naos',target_is_directory=True)
        self.assertEqual(composition.read_collection_entry({**ref,'source_reference':'source.json'},alias/'reports')['reason'],'unsafe_source_reference')

if __name__=='__main__':unittest.main()
