"""Report ordinals avoid generated-ID feedback without scanner exemptions."""
import copy
import json
from types import SimpleNamespace
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

KIT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(KIT/'scripts'))
import naos_hygiene_common as common
import naos_evidence_classification as classification
import naos_sarif_export as sarif
import naos_secret_public_literals as public
from jsonschema import Draft202012Validator

TOKENS=['aB3dE5fG7hI9jK0mN2pQ4rS6tU8vW','zY8xW6vU4tS2rQ0pN9mK7jI5hG3fE','qA2wS3eD4rF5tG6yH7uJ8iK9oL0pZ']
PROVIDER='sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'
TIME='2026-10-10T00:48:21Z'


def node_count(value):
    pending=[value];count=0
    while pending:
        value=pending.pop();count+=1
        if type(value)is dict:pending.extend(value.values())
        elif type(value)is list:pending.extend(value)
    return count


class ReportScopedFindingIds(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix='naos-ordinal-123-');self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name).resolve()
        self.registry={s.id:s for s in sarif.DETERMINISTIC_SOURCES}

    def write(self,name,value):
        path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True)
        raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
        self.assertLess(len(raw),8*1024*1024)
        path.write_bytes(raw);return path

    def scan(self):
        r=common.check_secret_hygiene(root=self.root,profile='assured',naos_root='naos',rules={},rules_path=None,severity='blocking')
        Draft202012Validator(json.loads((KIT/'schemas/naos/secret_hygiene.schema.json').read_text())).validate(r)
        return r

    def record(self, identifier='old', **extra):
        return {'id':identifier,'severity':'blocking','status':'high_entropy_literal','message':'Review finding.',
            'path':'input.json','line':1,'column':1,'human_review_required':True,'not_claimed':[],**extra}

    def test_large_repeated_scan_classification_sarif_preserves_original_cardinality(self):
        self.write('input.json',[TOKENS[i%3] for i in range(2200)])
        expected=[f'SH-{i}' for i in range(1,2201)];cycles=[];self.cycle_evidence=[]
        for cycle in range(3):
            report=self.scan();cycles.append(report['summary']['entropy_matches'])
            self.assertEqual(report['summary']['regex_matches'],0)
            self.assertEqual(report['summary']['coverage_status'],'complete')
            self.assertEqual([f['id'] for f in report['findings']],expected)
            self.assertTrue(all(f['path']=='input.json' for f in report['findings']))
            self.assertGreater(node_count(report),50000)
            self.cycle_evidence.append({'cycle':cycle+1,'findings':len(report['findings']),'original_body_findings':sum(f['path']=='input.json' for f in report['findings']),'nodes':node_count(report),'coverage':report['summary']['coverage_status'],'regex':report['summary']['regex_matches']})
            self.assertFalse(public.public_secret_finding_ids(json.dumps(report)))
            for token in TOKENS:self.assertNotIn(token,json.dumps(report))
            secret_path=self.write('naos/reports/secret_hygiene.json',report)
            _,classified,errors,_,snapshots=classification.classify_findings([secret_path],TIME)
            self.assertFalse(errors);self.assertEqual(len(classified),2200)
            self.assertEqual([r['finding_id'] for r in classified],expected)
            diagnostics=[classification.finding('evidence_classification.missing.'+r['finding_id'],'blocking',
                'missing_classification','Finding lacks declared provenance classification.',
                finding_id=r['finding_id'],source_report=r['source_report'],source_item_sha256=r['source_item_sha256'],
                source_report_sha256=r['source_report_sha256'],source_index=r['source_index'],source_bucket=r['source_bucket']) for r in classified]
            classification.assign_diagnostic_ids(diagnostics)
            self.assertEqual([r['id'] for r in diagnostics],[f'EC-{i}' for i in range(1,2201)])
            self.write('naos/reports/evidence_classification_report.json',{'findings':diagnostics,'classified_findings':classified,'source_finding_snapshots':snapshots})
            # Both full-cardinality SARIF outputs remain below the diagnostic
            # per-file bound, without changing exporter/scanner resource limits.
            for name,rows,filename in [('secret_hygiene',report['findings'],'sarif_export.json'),
                    ('evidence_classification',diagnostics,'sarif-summary.json')]:
                output,_=sarif.build_sarif(root=self.root,profile='assured',sources_and_findings=[(self.registry[name],rows)])
                self.assertEqual(len(output['runs'][0]['results']),2200)
                self.write('naos/reports/'+filename,output)
        self.assertEqual(cycles,[2200,2200,2200])

    def test_duplicate_physical_records_get_unique_labels_without_field_loss(self):
        original=self.record();records=[copy.deepcopy(original),copy.deepcopy(original)]
        common.assign_secret_finding_ids(records)
        self.assertEqual([r['id'] for r in records],['SH-1','SH-2'])
        for record in records:
            self.assertEqual({k:v for k,v in record.items() if k not in {'id','id_scheme'}},{k:v for k,v in original.items() if k!='id'})
            self.assertEqual(record['id_scheme'],'report_ordinal_v1')
        diagnostics=[classification.finding('duplicate','blocking','missing_classification','Review.',finding_id='SH-1') for _ in range(2)]
        classification.assign_diagnostic_ids(diagnostics)
        self.assertEqual([r['id'] for r in diagnostics],['EC-1','EC-2'])
        self.assertEqual([r['finding_id'] for r in diagnostics],['SH-1','SH-1'])
        unrelated=classification.finding('evidence_classification.parse_error.input','blocking','review_required','Parse failed.')
        saved=copy.deepcopy(unrelated)
        classification.assign_diagnostic_ids([unrelated])
        self.assertEqual(unrelated,saved)

    def test_only_marked_new_routes_change_sarif_ids_and_fingerprints_are_exact(self):
        marked=self.record('SH-1',id_scheme='report_ordinal_v1')
        cases=[('secret_hygiene',marked,True),('self_check',marked,True),
            ('evidence_classification',{**marked,'id':'EC-1'},True),
            ('self_check',{**marked,'id':'EC-1'},True),
            ('gate_evaluation',marked,False),('secret_hygiene',self.record('SH-1'),False),
            ('secret_hygiene',{**marked,'id_scheme':'unknown'},False),
            ('secret_hygiene',{**marked,'rule_id':'explicit-rule'},False),
            ('secret_hygiene',{**marked,'id':TOKENS[0]},False),
            ('secret_hygiene',{**marked,'id':'SH-01'},False),
            ('secret_hygiene',{**marked,'id':'SH-١'},False),
            ('secret_hygiene',self.record('secret_hygiene.high_entropy.input.json.1.1'),False)]
        for name,item,remapped in cases:
            with self.subTest(source=name,id=item['id'],remapped=remapped):
                source=self.registry[name];prior_id,prior=sarif.build_result(source,item,'assured',self.root)
                output,rules=sarif.build_sarif(root=self.root,profile='assured',sources_and_findings=[(source,[item])])
                result=output['runs'][0]['results'][0]
                self.assertEqual(result['ruleId'],'NAOS-D1' if remapped else prior_id)
                self.assertIn(result['ruleId'],rules)
                self.assertEqual(result['partialFingerprints'],prior['partialFingerprints'])
                self.assertEqual(result['properties'],prior['properties'])
                self.assertEqual({k:v for k,v in result.items() if k!='ruleId'},{k:v for k,v in prior.items() if k!='ruleId'})

    def test_cross_source_namespace_separation_shared_rule_reuse_and_routing(self):
        one=self.record('SH-1',id_scheme='report_ordinal_v1')
        different={**one,'line':2}
        pairs=[(self.registry['secret_hygiene'],[one,different]),(self.registry['self_check'],[one]),
               (self.registry['evidence_classification'],[{**one,'id':'EC-1'}]),
               (self.registry['gate_evaluation'],[one])]
        output,rules=sarif.build_sarif(root=self.root,profile='assured',sources_and_findings=pairs)
        labels=[r['ruleId'] for r in output['runs'][0]['results']]
        self.assertEqual(labels[:4],['NAOS-D1','NAOS-D1','NAOS-D2','NAOS-D3'])
        self.assertNotIn(labels[-1],labels[:4]);self.assertEqual(len(rules),4)
        routed,_=sarif.route_self_check_findings([(self.registry['self_check'],[{**one,'_naos_self_check_id':'naos_secret_hygiene'}])],self.root,False)
        self.assertEqual(routed[0][0].id,'secret_hygiene');self.assertEqual(routed[0][1][0]['id'],'SH-1')

    def test_unknown_body_provider_assignment_and_forged_marker_are_not_exempt(self):
        self.write('naos/reports/secret_hygiene.json',{'findings':[self.record(TOKENS[0],id_scheme='report_ordinal_v1')],
            'unknown':TOKENS[1],'path':'naos/reports/'+TOKENS[2]+'.json','password':'SH-12345678','provider':PROVIDER})
        report=self.scan()
        self.assertGreaterEqual(report['summary']['entropy_matches'],3)
        self.assertTrue(any(f.get('pattern_id')=='assigned_secret' for f in report['findings']))
        self.assertTrue(any(f.get('pattern_id')=='openai_style_key' for f in report['findings']))
        self.assertEqual(len({f['id'] for f in report['findings']}),len(report['findings']))

    def ordinal_document(self, self_check=False):
        rows=[classification.finding('evidence_classification.policy_missing','advisory','missing_policy','Missing policy.')]
        for index in range(2):
            rows.append(classification.finding('before-assignment','blocking','missing_classification',
                'Finding lacks declared provenance classification; inferred candidate requires human review.',
                finding_id='source-'+str(index),source_report=str(self.root/'naos/reports/secret_hygiene.json'),
                source_report_sha256='1'*64,source_item_sha256='2'*64,source_bucket='findings',source_index=index,
                scan_generated_at=TIME,source_observed_at=TIME,inferred_classification='unknown'))
        classification.assign_diagnostic_ids(rows)
        common_fields={'schema':'naos.evidence_classification_report.v1','generated_at':TIME,'profile':'assured',
            'project_root':str(self.root),'naos_root':'naos','status':'missing_classification'}
        if self_check:
            return {**common_fields,'schema':'naos.self_check.v1','status':'blocked',
                'summary':{'blocking':2,'required':0,'warnings':0,'advisory':1,'total_findings':3,'checks':1},
                'checks':[{'id':'naos_evidence_classification','returncode':1,'status':'missing_classification',
                    'summary':{'total_findings':3},'findings':rows}], 'limitations':[]}
        return {**common_fields,'policy_path':'naos/evidence_classification_policy.yaml','policy_present':False,
            'policy_valid':False,'reports_scanned':[],'findings_scanned':0,'classified_findings':[],
            'missing_classification':[],'classification_counts':{},'evidence_ref_counts':{},'unknown_findings':[],
            'review_required_findings':[],'findings':rows,'known_gaps':[],'residual_risks':[],'limitations':[],
            'not_claimed':[],'human_review_required':True,'summary':{'total_findings':3}}

    def ordinal_rows(self, doc):
        return doc['checks'][0]['findings'] if doc['schema']=='naos.self_check.v1' else doc['findings']

    def canonical_audit(self, **changes):
        import naos_audit_log as audit
        event=audit.build_audit_event(root=self.root,naos_root='naos',policy={},profile='standard',
            event_type='session_started',session_id='fixture-session',generated_at='2026-10-09T12:00:00Z',
            generated_by={'operator_id':'fixture-operator','operator_source':'fixture'},
            source_report={'schema':'naos.session_identity.v1','status':'session_created','summary':{},
                'findings':[],'human_review_required':True})
        event.update(changes)
        if changes:
            event['event_id']='audit-sha256-'+audit.hash_json({'domain':audit.PUBLIC_EVENT_ID_SCHEME,
                'event':{key:value for key,value in event.items() if key!='event_id'}})
        path=audit.event_file_path(self.root/'naos/audit_log',event)
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(event)+'\n')
        return path,event

    def test_canonical_witnesses_restore_both_families_after_actual_corpus_exhaustion(self):
        files=[self.write('padding-'+str(index)+'.json',{'padding':'x'*(7*1024*1024)}) for index in range(5)]
        source=self.write('naos/reports/self_check.json',self.ordinal_document(True))
        classifier=self.write('naos/reports/evidence_classification_report.json',self.ordinal_document())
        event_path,event=self.canonical_audit()
        files.extend([source,classifier,event_path])
        self.assertGreater(sum(path.stat().st_size for path in files),32*1024*1024)
        self.assertFalse(public.selected_public_secret_finding_literals(files,root=self.root))
        self.assertFalse(public.collect_public_audit_event_references(files,root=self.root,naos_root='naos'))
        values=public.selected_public_producer_witness_literals(files,root=self.root,naos_root='naos')
        expected={'naos_evidence_classification/EC-2','naos_evidence_classification/EC-3',event['event_id'],str(event_path),event_path.relative_to(self.root).as_posix()}
        self.assertTrue(expected<=values)
        self.assertEqual(values,public.selected_public_producer_witness_literals(list(reversed(files)),root=self.root,naos_root='naos'))
        self.write('later.json',{'finding_id':'naos_evidence_classification/EC-2','event_file':str(event_path)})
        self.assertEqual(self.scan()['summary']['entropy_matches'],0)
        self.write('later.json',{'finding_id':'naos_evidence_classification/EC-2','event_file':str(event_path),
            'unknown':TOKENS[0],'password':event['event_id'],'provider':PROVIDER})
        report=self.scan()
        self.assertTrue(any(finding.get('pattern_id')=='assigned_secret' for finding in report['findings']))
        self.assertTrue(any(finding.get('pattern_id')=='openai_style_key' for finding in report['findings']))
        self.assertEqual([finding['path'] for finding in report['findings'] if finding['status']=='high_entropy_literal'],['later.json','later.json'])

    def test_canonical_witnesses_reject_partial_foreign_event_filename_and_body(self):
        source=self.write('naos/reports/self_check.json',self.ordinal_document(True))
        event_path,event=self.canonical_audit()
        self.assertTrue(public.selected_public_producer_witness_literals([source,event_path],root=self.root,naos_root='naos'))
        for change in ('partial','ordinal','foreign'):
            doc=self.ordinal_document(True)
            if change=='partial':self.ordinal_rows(doc)[1].pop('source_item_sha256')
            elif change=='ordinal':self.ordinal_rows(doc)[1]['id']='EC-02'
            else:doc['project_root']='/foreign'
            self.write('naos/reports/self_check.json',doc)
            self.assertFalse(public.selected_public_producer_witness_literals([source],root=self.root,naos_root='naos'))
        raw=event_path.read_bytes()
        for mutation in ('body','foreign','nested','duplicate','filename'):
            value=json.loads(raw);path=event_path
            if mutation=='body':value['event_nonce']='00'
            elif mutation=='foreign':value['project_root']='/foreign'
            elif mutation=='nested':value={'event':value}
            elif mutation=='filename':path=event_path.parent/'authored.jsonl'
            text=json.dumps(value)
            if mutation=='duplicate':text=text[:-1]+',"event_id":"duplicate"}'
            path.write_text(text)
            self.assertFalse(public.selected_public_producer_witness_literals([path],root=self.root,naos_root='naos'))
            event_path.write_bytes(raw)
        arbitrary=self.write('consumer.json',{'source_findings':[{'id':'naos_evidence_classification/EC-2'}]})
        self.assertFalse(public.selected_public_producer_witness_literals([arbitrary],root=self.root,naos_root='naos'))
        self.assertFalse(public.selected_public_producer_witness_literals([event_path],root=self.root,naos_root='other'))
        self.assertFalse(public.selected_public_producer_witness_literals([],root=self.root,naos_root='naos'))

    def test_canonical_witness_context_must_observe_the_supplied_root(self):
        from naos_secret_managed_operands import ProofBudget
        selected=self.root/'naos/reports/self_check.json'
        self.assertFalse(selected.exists())
        foreign=self.root/'foreign-root'
        # Complete foreign bytes falsely claim the requested original root.
        source=self.write('foreign-root/naos/reports/self_check.json',self.ordinal_document(True))
        context=ProofBudget(foreign)
        with patch.object(context,'read',wraps=context.read) as reader:
            self.assertFalse(public.selected_public_producer_witness_literals([selected],root=self.root,naos_root='naos',context=context))
            reader.assert_not_called()
        for invalid in (object(),SimpleNamespace(root='not-a-path'),SimpleNamespace()):
            self.assertFalse(public.selected_public_producer_witness_literals([selected],root=self.root,naos_root='naos',context=invalid))
        self.assertTrue(source.exists())
        self.assertEqual(context.bytes_read,0)

    def test_canonical_witnesses_keep_projection_caps_links_and_current_raw_custody(self):
        source=self.write('naos/reports/self_check.json',self.ordinal_document(True));raw=source.read_bytes()
        with patch.object(public,'MAX_CONTEXT_VALUES',1):
            self.assertFalse(public.selected_public_producer_witness_literals([source],root=self.root,naos_root='naos'))
        with patch.object(public,'MAX_ENTRIES',0):
            self.assertFalse(public.selected_public_producer_witness_literals([source],root=self.root,naos_root='naos'))
        self.assertFalse(public.selected_public_producer_witness_literals([source]*50001,root=self.root,naos_root='naos'))
        huge=json.dumps({'padding':'x'*(7*1024*1024)}).encode()
        with patch('naos_secret_managed_operands.ProofBudget.read',return_value=huge):
            self.assertFalse(public.selected_public_producer_witness_literals([source]*5,root=self.root,naos_root='naos'))
        from naos_secret_managed_operands import ProofBudget, MAX_PROOF_BYTES
        context=ProofBudget(self.root)
        context.bytes_read=MAX_PROOF_BYTES-len(raw)+1
        self.assertFalse(public.selected_public_producer_witness_literals([source],root=self.root,naos_root='naos',context=context))
        self.assertEqual(context.bytes_read,MAX_PROOF_BYTES-len(raw)+1)
        context=ProofBudget(self.root)
        with patch.object(context,'read',side_effect=[raw,raw+b' ']):
            self.assertFalse(public.selected_public_producer_witness_literals([source],root=self.root,naos_root='naos',context=context))
        context=ProofBudget(self.root)
        checkpoint=context.admission_checkpoint
        def terminal_change():
            source.write_bytes(raw+b' ')
            checkpoint()
        with patch.object(context,'admission_checkpoint',side_effect=terminal_change):
            self.assertFalse(public.selected_public_producer_witness_literals([source],root=self.root,naos_root='naos',context=context))
        source.write_bytes(raw)
        event_path,event=self.canonical_audit();event_raw=event_path.read_bytes()
        context=ProofBudget(self.root);checkpoint=context.admission_checkpoint
        def terminal_event_change():
            event_path.write_bytes(event_raw+b' ')
            checkpoint()
        with patch.object(context,'admission_checkpoint',side_effect=terminal_event_change):
            self.assertFalse(public.selected_public_producer_witness_literals([event_path],root=self.root,naos_root='naos',context=context))
        event_path.write_bytes(event_raw)
        target=self.write('outside.json',self.ordinal_document(True));source.unlink()
        try:source.symlink_to(target)
        except OSError as error:
            if getattr(error,'winerror',None)==1314:self.skipTest('Windows symlink privilege unavailable')
            raise
        self.assertFalse(public.selected_public_producer_witness_literals([source],root=self.root,naos_root='naos'))

    def test_complete_classifier_and_retained_self_check_vectors_prove_exact_aliases(self):
        expected={'naos_evidence_classification/EC-2','naos_evidence_classification/EC-3'}
        for self_check in (False,True):
            doc=self.ordinal_document(self_check)
            path=self.write('naos/reports/'+('self_check' if self_check else 'evidence_classification_report')+'.json',doc)
            self.assertEqual(public.selected_public_secret_finding_literals([path],root=self.root),expected)
            self.assertNotIn('naos_evidence_classification/EC-1',expected)
            self.assertNotIn('EC-2',expected)
            self.assertFalse(public.selected_public_secret_finding_literals([],root=self.root))

    def test_ordinal_vectors_reject_forgery_partial_provenance_and_noncanonical_paths(self):
        for self_check in (False,True):
            original=self.ordinal_document(self_check)
            name='self_check' if self_check else 'evidence_classification_report'
            cases=[]
            for key,value in [('id','EC-02'),('id','EC-3'),('id','EC-١'),('id_scheme','unknown'),
                              ('status','review_required'),('source_index',True),('source_item_sha256','A'*64),
                              ('source_report_sha256',TOKENS[0]),('human_review_required',False),
                              ('message','forged'),('source_bucket',None)]:
                doc=copy.deepcopy(original);self.ordinal_rows(doc)[1][key]=value;cases.append(doc)
            doc=copy.deepcopy(original);self.ordinal_rows(doc)[2]['id']='EC-99';cases.append(doc)
            doc=copy.deepcopy(original);self.ordinal_rows(doc)[1].pop('source_item_sha256');cases.append(doc)
            doc=copy.deepcopy(original);self.ordinal_rows(doc)[1]={'id':'EC-2','status':'missing_classification',
                'id_scheme':'report_ordinal_v1','severity':'blocking','message':'forged'};cases.append(doc)
            for key,value in [('project_root','/foreign'),('naos_root','../naos'),('profile','custom'),('schema','foreign')]:
                doc=copy.deepcopy(original);doc[key]=value;cases.append(doc)
            if self_check:
                doc=copy.deepcopy(original);doc['checks'].append(copy.deepcopy(doc['checks'][0]));cases.append(doc)
                doc=copy.deepcopy(original);doc['checks'][0]['id']='custom_classifier';cases.append(doc)
                doc=copy.deepcopy(original);doc['checks'][0].pop('returncode');cases.append(doc)
            for index,doc in enumerate(cases):
                with self.subTest(self_check=self_check,case=index):
                    path=self.write('naos/reports/'+name+'.json',doc)
                    self.assertFalse(public.selected_public_secret_finding_literals([path],root=self.root))
            for relative in ('custom/'+name+'.json','naos/reports/custom-'+name+'.json',
                             'naos/sessions/session/reports/'+name+'.json'):
                path=self.write(relative,original)
                self.assertFalse(public.selected_public_secret_finding_literals([path],root=self.root))

    def test_ordinal_body_assignment_and_provider_values_still_scanned(self):
        doc=self.ordinal_document(True)
        row=self.ordinal_rows(doc)[1]
        row.update(finding_id=TOKENS[0],unknown=TOKENS[1],password='naos_evidence_classification/EC-2',provider=PROVIDER)
        path=self.write('naos/reports/self_check.json',doc)
        self.assertIn('naos_evidence_classification/EC-2',public.selected_public_secret_finding_literals([path],root=self.root))
        report=self.scan()
        self.assertGreaterEqual(report['summary']['entropy_matches'],2)
        self.assertTrue(any(f.get('pattern_id')=='assigned_secret' for f in report['findings']))
        self.assertTrue(any(f.get('pattern_id')=='openai_style_key' for f in report['findings']))

    def test_ordinal_malformed_duplicate_complex_and_windows_links_fail_closed(self):
        doc=self.ordinal_document(True);path=self.write('naos/reports/self_check.json',doc)
        raw=path.read_bytes()
        for invalid in (raw[:-1],raw.replace(b'"schema":',b'"schema":0,"schema":',1),
                        raw[:-1]+b',"nonfinite":NaN}',raw[:-1]+b',"deep":'+b'['*65+b'0'+b']'*65+b'}'):
            path.write_bytes(invalid)
            self.assertFalse(public.selected_public_secret_finding_literals([path],root=self.root))
        path.write_bytes(raw)
        observed=Path.lstat
        for unsafe in (path,path.parent,self.root):
            def metadata(candidate, *args, **kwargs):
                stat_result=observed(candidate,*args,**kwargs)
                if candidate==unsafe:
                    return SimpleNamespace(st_mode=stat_result.st_mode,st_size=stat_result.st_size,st_file_attributes=0x400)
                return stat_result
            with self.subTest(unsafe=unsafe),patch.object(Path,'lstat',metadata):
                self.assertFalse(public.selected_public_secret_finding_literals([path],root=self.root))

    def test_native_only_linked_ordinal_source_refuses(self):
        doc=self.ordinal_document(True);path=self.write('naos/reports/self_check.json',doc)
        outside=self.write('outside.json',doc);path.unlink()
        try:path.symlink_to(outside)
        except OSError as error:
            if getattr(error,'winerror',None)==1314:self.skipTest('Windows symlink privilege unavailable')
            raise
        self.assertFalse(public.selected_public_secret_finding_literals([path],root=self.root))

    def test_legacy_ids_and_classifier_source_provenance_remain_opaque(self):
        legacy=[self.record('secret_hygiene.high_entropy.input.json.1.1'),self.record()]
        legacy[1]['id']=public.secret_finding_id(legacy[1]);original=copy.deepcopy(legacy)
        path=self.write('naos/reports/secret_hygiene.json',{'findings':legacy})
        _,classified,_,_,snapshots=classification.classify_findings([path],TIME)
        self.assertEqual([r['finding_id'] for r in classified],[r['id'] for r in legacy])
        self.assertEqual([r['source_index'] for r in classified],[0,1])
        self.assertTrue(all(len(r['source_item_sha256'])==64 and len(r['source_report_sha256'])==64 for r in classified))
        self.assertEqual(json.loads(path.read_text())['findings'],original)
        self.assertEqual([s['payload']['id'] for s in snapshots],[r['id'] for r in original])

if __name__=='__main__':unittest.main()
