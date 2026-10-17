"""Pure constructor label proofs; no native ownership or mutation authority."""
import copy
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

KIT = Path(os.environ.get('NAOS_TEST_KIT', Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(KIT/'scripts'))
import naos_secret_managed_operands as managed
import naos_hygiene_common as common

SOURCE = Path(os.environ.get('NAOS_PRODUCER_SOURCE', KIT))
sys.path.insert(0, str(SOURCE))
# Adjacent public fixtures remain available without the excluded private test tree.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from upgrade_contract.canonical import canonical_sha256, canonical_bytes
from upgrade_contract.transaction import _with_sha256_integrity
from upgrade_contract.provenance import _managed_content_scope_object


class ManagedInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='managed-proof-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.relative = managed._MANAGED_ROOT
        self.raw = b'source producer fixture\r\n'
        self.digest = hashlib.sha256(self.raw).hexdigest()
        source_meta = {'schema':'naos.metadata.darwin_source.v1','platform':'Darwin','machine':'arm64','python_minor':'3.11','file_type':'regular_file','mode':420,'uid':0,'gid':0,'flags':0,'acl_entries':[],'xattrs':[]}
        created = {**source_meta, 'schema':'naos.metadata.darwin_create_only.v1','device':1,'inode':1}
        identity = {'kind':'file','mode':420,'size':len(self.raw),'sha256':self.digest}
        self.scope = _managed_content_scope_object(project_id='fixture-project',owner_integrity='1'*128, authorization_digest='2'*64, source_policy_sha256='3'*64)
        self.plan = {'schema':'naos.upgrade.create_only_plan.v1','operation':'naos-init','status':'ready_create_only','project_root_binding':str(self.root),'source_policy_sha256':'3'*64,'creation_identity':{'schema':'naos.metadata.creation_identity.v1','policy':'executing_uid_primary_gid','uid':0,'gid':0},'inputs':{},'replacement_allowed':False,'ownership_inference':'forbidden','paths':[{'path':'scripts/fixture.py','source':identity,'source_metadata':source_meta,'base':'verified_absent','current':'absent','content_state':'PROPOSE_NEW_UPSTREAM_CREATE','ownership':'kit_owned_derived','creation_policy':'create','source_policy_rule':'kit','action':'CREATE_NEW_KIT_OWNED','ancestor_identities':[]}]}
        self.plan['plan_sha256'] = canonical_sha256(self.plan)
        tid = 'MC-' + self.plan['plan_sha256'][:16] + '-01234567';self.tid = tid
        self.journal = _with_sha256_integrity({'schema':'naos.upgrade.create_only_transaction.v1','transaction_id':tid,'plan':self.plan,'state':'COMMITTED','applied_paths':['scripts/fixture.py'],'applied_identities':{'scripts/fixture.py':created},'created_directories':[],'pending_action':None,'detail':None})
        self.receipt = _with_sha256_integrity({'schema':'naos.upgrade.managed_content_receipt.v1','project_id':'fixture-project','scope_integrity_sha3_512':self.scope['integrity']['value'],'source_policy_sha256':'3'*64,'transaction_id':tid,'plan_sha256':self.plan['plan_sha256'],'status':'COMMITTED','paths':self.plan['paths'],'created_metadata':{'scripts/fixture.py':created},'replacement_performed':False})
        receipt_sha = canonical_sha256(self.receipt)
        self.manifest = _with_sha256_integrity({'schema':'naos.upgrade.managed_content_manifest.v1','project_id':'fixture-project','scope_integrity_sha3_512':self.scope['integrity']['value'],'source_policy_sha256':'3'*64,'previous_integrity_sha256':None,'last_transaction_id':tid,'last_plan_sha256':self.plan['plan_sha256'],'transactions':[{'transaction_id':tid,'plan':self.plan,'receipt_sha256':receipt_sha}],'entries':[{'path':'scripts/fixture.py','ownership':'kit_owned_derived','creation_policy':'create','base':identity,'source_metadata':source_meta,'base_blob':{'path':self.digest,'sha256':self.digest},'created_metadata':created,'introduced_by_transaction':tid,'receipt_sha256':receipt_sha}]})
        self.operands = [self.relative+'/state/bases/'+self.digest,self.relative+'/state/receipts/'+tid+'.json',self.relative+'/transactions/'+tid+'/journal.json',self.relative+'/transactions/'+tid]
        self.write(self.relative+'/scope.json',self.scope)
        self.write(self.relative+'/state/manifest.json',self.manifest)
        self.write(self.operands[1],self.receipt); self.write(self.operands[2],self.journal)
        target=self.root/self.operands[0];target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(self.raw)

    def write(self, relative, value):
        path=self.root/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(canonical_bytes(value));return path

    def report(self, values=None):
        values=self.operands if values is None else values
        return {'schema':'naos.secret_hygiene.v1','project_root':str(self.root),'naos_root':'naos','scans':{'input_files':[{'path':p,'status':'read'} for p in values],'scope_inventory':[{'path':p,'status':'unselected_suffix'} for p in values],'unassessed_suffix_files':values},'findings':[{'path':p,'message':p} for p in values],'unknown':values}

    def spans(self, doc, context=None):
        text=json.dumps(doc,ensure_ascii=False) if type(doc) is not str else doc
        spans,diag=managed.inventory_operand_spans(text,'naos/reports/secret_hygiene.json',self.root,'naos',context or managed.ProofBudget(self.root))
        return text,spans,diag

    def high_entropy_committed_fixture(self):
        # Finite deterministic producer-plan inputs, not random ID generation.
        plan=copy.deepcopy(self.plan);plan.pop('plan_sha256')
        for nonce in range(256):
            plan['inputs']={'control_label_fixture':nonce}
            digest=canonical_sha256(plan)
            suffix=''.join(sorted('0123456789abcdef',key=lambda c:(digest[:16].count(c),c))[:8])
            tid='MC-'+digest[:16]+'-'+suffix
            if common.shannon_entropy(tid)>4.0:
                break
        else:
            self.fail('bounded deterministic high-entropy fixture search exhausted')
        plan['plan_sha256']=digest
        journal=copy.deepcopy(self.journal);journal.pop('integrity');journal.update(transaction_id=tid,plan=plan)
        receipt=copy.deepcopy(self.receipt);receipt.pop('integrity');receipt.update(transaction_id=tid,plan_sha256=digest)
        receipt=_with_sha256_integrity(receipt)
        manifest=copy.deepcopy(self.manifest);manifest.pop('integrity')
        manifest.update(last_transaction_id=tid,last_plan_sha256=digest,
            transactions=[{'transaction_id':tid,'plan':plan,'receipt_sha256':canonical_sha256(receipt)}])
        manifest['entries'][0].update(introduced_by_transaction=tid,receipt_sha256=canonical_sha256(receipt))
        paths=[self.relative+'/state/manifest.json',self.relative+'/state/receipts/'+tid+'.json',
               self.relative+'/transactions/'+tid+'/journal.json']
        for path,record in zip(paths,[_with_sha256_integrity(manifest),receipt,_with_sha256_integrity(journal)]):
            self.write(path,record)
        return tid,paths

    def raw_control_spans(self, path, text=None, context=None):
        text=(self.root/path).read_text() if text is None else text
        spans,diag=managed.inventory_operand_spans(text,path,self.root,'naos',context or managed.ProofBudget(self.root))
        return text,spans,diag

    def test_committed_control_ids_exact_slots_and_same_value_body_negative(self):
        tid,paths=self.high_entropy_committed_fixture()
        journal=json.loads((self.root/paths[2]).read_text());journal.pop('integrity')
        journal['detail']={'payload':tid,'inputs':{'transaction_id':tid},'password':tid}
        self.write(paths[2],_with_sha256_integrity(journal))
        context=managed.ProofBudget(self.root)
        for path,count in zip(paths,[3,1,1]):
            text,spans,diag=self.raw_control_spans(path,context=context)
            self.assertEqual(len(spans),count,diag)
            self.assertEqual({json.loads(text[a:b]) for a,b in spans},{tid})
        self.write('data/body.json',{'payload':tid,'inputs':{'transaction_id':tid},'password':tid,
                                    'provider':'sk-'+'aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'})
        self.write('data/plain.txt',tid) # JSON quoted scalar in an ordinary file.
        result=common.check_secret_hygiene(root=self.root,profile='standard',naos_root='naos',
            rules={'scan_roots':paths+['data'],'include_root_files':False},rules_path=None,severity='blocking')
        self.assertEqual(result['summary']['inventory_operand_matches'],5)
        self.assertGreaterEqual(result['summary']['entropy_matches'],7)
        self.assertGreater(result['summary']['regex_matches'],0)
        for path in ['data/body.json','data/plain.txt']:
            self.assertFalse(self.raw_control_spans(path)[1])

    def test_control_ids_require_exact_bytes_chain_and_bound_record_path(self):
        tid,paths=self.high_entropy_committed_fixture();path=paths[0]
        raw=(self.root/path).read_text()
        for altered in [raw+' ',raw.replace(tid,tid.replace('M','\\u004d')),raw[:-1],raw.replace('"entries":','"entries":[],"entries":')]:
            self.assertFalse(self.raw_control_spans(path,altered)[1])
        self.write('data/manifest.json',json.loads(raw))
        self.assertFalse(self.raw_control_spans('data/manifest.json')[1])
        receipt=json.loads((self.root/paths[1]).read_text());receipt['transaction_id']='MC-'+'a'*16+'-'+'b'*8
        self.write(paths[1],receipt)
        self.assertFalse(self.raw_control_spans(path)[1])

    def test_control_ids_refuse_deleted_or_tampered_raw_base(self):
        for delete in [False,True]:
            with self.subTest(delete=delete):
                _,paths=self.high_entropy_committed_fixture()
                base=self.root/self.operands[0]
                if delete: base.unlink()
                else: base.write_bytes(b'tampered')
                self.assertFalse(self.raw_control_spans(paths[0])[1])
                base.write_bytes(self.raw)

    def test_control_parser_does_not_collect_payload_or_unbounded_coordinates(self):
        _,coordinates=managed._control_record(self.relative+'/state/manifest.json')
        parser=managed._OffsetJSON(json.dumps({'last_transaction_id':'label',
            'inputs':{'transaction_id':'label'},'entries':[{'introduced_by_transaction':'label','body':'label'}]}),coordinates)
        parser.parse()
        self.assertEqual(set(parser.strings),{('last_transaction_id',),('entries',0,'introduced_by_transaction')})
        with patch.object(managed,'MAX_METADATA_NODES',1):
            with self.assertRaises(managed.OperandRefusal):
                managed._OffsetJSON(parser.text,coordinates).parse()

    def test_exact_coordinates_and_raw_spelling(self):
        text,spans,diag=self.spans(self.report());self.assertEqual(len(spans),12)
        self.assertEqual(diag['status'],'proved')
        self.assertEqual([json.loads(text[a:b]) for a,b in sorted(spans)],self.operands*3)
        self.assertTrue(all(text[a]=='"' and text[b-1]=='"' for a,b in spans))
        # Identical body, findings paths and fake JSON remain outside the intervals.
        self.assertLess(len(spans),text.count(self.operands[0])*4)

    def scanner_read_row(self, operand):
        return {'path':operand, 'status':'read', 'sha256':self.digest, 'size_bytes':len(self.raw)}

    def test_scanner_read_rows_and_mixed_legacy_rows_admit_only_path_quotes(self):
        for mixed in (False, True):
            with self.subTest(mixed=mixed):
                doc=self.report()
                doc['scans']['input_files']=[self.scanner_read_row(p) if not mixed or i % 2 == 0
                                            else {'path':p,'status':'read'} for i,p in enumerate(self.operands)]
                doc['scans']['input_files'][0]['size_bytes']=0
                text,spans,diag=self.spans(doc)
                self.assertEqual(diag['status'],'proved')
                self.assertGreater(diag['proof_bytes'],0)
                self.assertEqual([json.loads(text[a:b]) for a,b in sorted(spans)],self.operands*3)
                self.assertTrue(all(text[a]=='"' and text[b-1]=='"' for a,b in spans))
                # Hash and size metadata supply no spans; findings and unknown bodies remain outside.
                self.assertEqual(len(spans),12)

    def test_scanner_read_row_invalid_metadata_refuses_before_proof(self):
        valid=self.scanner_read_row(self.operands[0])
        invalid=[None, [], 'read', {'status':'read'}, {'path':self.operands[0]}]
        for digest in (None, 123, '', 'a'*63, 'a'*65, 'A'*64, 'g'*64, 'a'*63+'\n'):
            invalid.append({**valid,'sha256':digest})
        for size in (None, True, False, -1, 1.0, '1'):
            invalid.append({**valid,'size_bytes':size})
        invalid.extend([{k:v for k,v in valid.items() if k!='sha256'},
                        {k:v for k,v in valid.items() if k!='size_bytes'},
                        {**valid,'extra':'unknown'}, {**valid,'path':123}, {**valid,'status':123},
                        {**valid,'status':'unknown'}])
        for row in invalid:
            with self.subTest(row=row):
                doc=self.report();doc['scans']['input_files'][0]=row
                _,spans,diag=self.spans(doc)
                self.assertFalse(spans);self.assertEqual(diag['status'],'refused')
                self.assertEqual(diag['proof_bytes'],0)

    def test_scanner_metadata_is_for_read_input_rows_only(self):
        for key,statuses in [('input_files',('read_error','decode_error','symlink')),
                             ('scope_inventory',('selected','unselected_suffix','unselected_file','excluded','symlink','read_error','directory'))]:
            for status in statuses:
                with self.subTest(key=key,status=status):
                    doc=self.report();doc['scans'][key][0]={'path':self.operands[0],'status':status}
                    self.assertEqual(len(self.spans(doc)[1]),12)
                    doc['scans'][key][0].update(sha256=self.digest,size_bytes=len(self.raw))
                    _,spans,diag=self.spans(doc)
                    self.assertFalse(spans);self.assertEqual(diag['status'],'refused')
                    self.assertEqual(diag['proof_bytes'],0)
        doc=self.report();doc['scans']['scope_inventory'][0]=self.scanner_read_row(self.operands[0])
        self.assertFalse(self.spans(doc)[1])

    def test_scanner_read_metadata_cannot_replace_linked_raw_base_proof(self):
        doc=self.report();doc['scans']['input_files']=[self.scanner_read_row(p) for p in self.operands]
        (self.root/self.operands[0]).write_bytes(b'changed')
        _,spans,diag=self.spans(doc)
        self.assertFalse(spans);self.assertEqual(diag['status'],'partial_refusal')
        self.assertGreater(diag['proof_bytes'],0)

    def test_provider_assignment_unchanged_and_body_detected(self):
        doc=self.report();doc['scans']['input_files']=[self.scanner_read_row(p) for p in self.operands]
        doc['password']=self.operands[0];doc['token']='sk-'+'aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'
        self.write('naos/reports/secret_hygiene.json',doc)
        r=common.check_secret_hygiene(root=self.root,profile='standard',naos_root='naos',rules={'scan_roots':['naos/reports/secret_hygiene.json'],'include_root_files':False},rules_path=None,severity='blocking')
        self.assertEqual(r['summary']['inventory_operand_matches'],12)
        self.assertGreater(r['summary']['regex_matches'],0);self.assertGreater(r['summary']['entropy_matches'],0)
        self.assertEqual(r['summary']['files_selected'],1)

    def diagnostic_report(self, paths=None):
        doc=self.report([])
        doc['findings']=[];doc.pop('unknown')
        doc['scans']['inventory_operand_proofs']=[{'path':path,'status':'proved','matches':1,'proof_bytes':123}
            for path in (self.operands[1:3] if paths is None else paths)]
        return doc

    def test_diagnostic_feedback_second_scan_and_body_detection(self):
        _,paths=self.high_entropy_committed_fixture()
        doc=self.diagnostic_report(paths[1:])
        target='naos/reports/secret_hygiene.json';self.write(target,doc)
        kwargs=dict(root=self.root,profile='standard',naos_root='naos',
            rules={'scan_roots':[target],'include_root_files':False},rules_path=None,severity='blocking')
        first=common.check_secret_hygiene(**kwargs)
        self.assertEqual(first['summary']['inventory_operand_matches'],2)
        self.assertEqual(first['summary']['total_findings'],0)
        self.write(target,first)
        second=common.check_secret_hygiene(**kwargs)
        self.assertEqual(second['summary']['total_findings'],0)
        doc['unknown']=paths[1];doc['password']=paths[1]
        doc['token']='sk-'+'aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'
        self.write(target,doc)
        body=common.check_secret_hygiene(**kwargs)
        self.assertEqual(body['summary']['inventory_operand_matches'],2)
        self.assertGreater(body['summary']['entropy_matches'],0)
        self.assertGreater(body['summary']['regex_matches'],0)

    def test_diagnostic_carriers_and_escaped_crlf_quote_positions(self):
        inner=self.diagnostic_report()
        def carrier(schema, **fields):
            return dict(schema=schema,project_root=str(self.root),naos_root='naos',**fields)
        evidence=carrier('naos.evidence_pack.v1',artifacts={'secret_hygiene_report':{'data':inner}})
        docs=[inner,evidence,
              carrier('naos.dashboard_summary.v1',inputs={'secret_hygiene':{'data':inner}}),
              carrier('naos.dashboard_summary.v1',inputs={'evidence_pack':{'data':evidence}})]
        for doc in docs:
            with self.subTest(schema=doc['schema']):
                text=json.dumps(doc,indent=2,ensure_ascii=True).replace('/',r'\/').replace('\n','\r\n')
                value,spans,diag=self.spans(text)
                self.assertEqual(diag['status'],'proved')
                self.assertEqual([json.loads(value[a:b]) for a,b in sorted(spans)],self.operands[1:3])
        misplaced=carrier('naos.evidence_pack.v1',unknown={'data':inner})
        self.assertFalse(self.spans(misplaced)[1])
        foreign=copy.deepcopy(inner);foreign['project_root']=str(self.root/'foreign')
        self.assertFalse(self.spans(foreign)[1])
        unsupported=copy.deepcopy(evidence);unsupported['schema']='naos.evidence_pack.v2'
        self.assertFalse(self.spans(unsupported)[1])

    def test_diagnostic_metadata_cannot_grant_or_disrupt_old_inventory(self):
        good=self.diagnostic_report()['scans']['inventory_operand_proofs'][0]
        invalid=[None,[],{'path':good['path'],'status':'proved'},
                 {**good,'extra':good['path']}, {**good,'path':'../escape'},
                 {**good,'status':'refused'}, {**good,'status':'partial_refusal'},
                 {**good,'status':'unknown'}]
        for key,limit in [('matches',managed.MAX_REPRESENTATIONS),('proof_bytes',managed.MAX_PROOF_BYTES)]:
            invalid.extend({**good,key:value} for value in [True,False,-1,limit+1,1.5,'1'])
        for row in invalid:
            with self.subTest(row=row):
                doc=self.diagnostic_report();doc['scans']['inventory_operand_proofs']=[row]
                _,spans,diag=self.spans(doc)
                self.assertFalse(spans);self.assertEqual(diag['proof_bytes'],0)
                old=self.report();old['scans']['inventory_operand_proofs']=[row]
                self.assertEqual(len(self.spans(old)[1]),12)
        for malformed in [None,{},'proved']:
            doc=self.report();doc['scans']['inventory_operand_proofs']=malformed
            self.assertEqual(len(self.spans(doc)[1]),12)
        doc=self.diagnostic_report([self.operands[1]+'.unknown'])
        self.assertFalse(self.spans(doc)[1])
        doc=self.diagnostic_report();doc['scans']['inventory_operand_proofs'].append({**good,'status':'refused'})
        self.assertEqual(len(self.spans(doc)[1]),2)

    def test_diagnostic_reported_proof_cannot_replace_chain_or_raw_base(self):
        doc=self.diagnostic_report()
        self.assertEqual(len(self.spans(doc)[1]),2)
        base=self.root/self.operands[0];base.write_bytes(b'changed')
        _,spans,diag=self.spans(doc)
        self.assertFalse(spans);self.assertEqual(diag['status'],'partial_refusal')
        base.write_bytes(self.raw)
        journal=copy.deepcopy(self.journal);journal.pop('integrity');journal['state']='PREPARED'
        self.write(self.operands[2],_with_sha256_integrity(journal))
        self.assertFalse(self.spans(doc)[1])

    def test_diagnostic_nodes_share_existing_parser_budget(self):
        doc=self.diagnostic_report()
        with patch.object(managed,'MAX_METADATA_NODES',5):
            _,spans,diag=self.spans(doc)
            self.assertFalse(spans);self.assertEqual(diag['status'],'refused')

    def test_invalid_json_and_unknown_rows(self):
        good=json.dumps(self.report())
        invalid=[good[:-1],good.replace('"schema":','"schema":0,"schema":',1),good.replace('"schema":','"\\u0073chema":0,"schema":',1),good[:-1]+',"n":NaN}',good[:-1]+',"n":Infinity}',good[:-1]+',"n":1e999}',good[:-1]+',"deep":'+'['*65+'0'+']'*65+'}']
        for text in invalid:self.assertFalse(self.spans(text)[1])
        doc=self.report();doc['scans']['input_files'][0]['extra']=self.operands[0];self.assertFalse(self.spans(doc)[1])
        doc=self.report();doc['schema']='forged';self.assertFalse(self.spans(doc)[1])

    def test_escaped_unicode_crlf_spans(self):
        doc=self.report();doc['unknown']='non BMP \U0001f600 quote " slash \\';text=json.dumps(doc,ensure_ascii=True,indent=2).replace('\n','\r\n')
        value,spans,_=self.spans(text);self.assertEqual(len(spans),12)
        self.assertTrue(all(json.loads(value[a:b]) in self.operands for a,b in spans))

    def test_unrelated_namespace_and_chosen_digest_no_preimage(self):
        chosen=self.relative+'/state/bases/'+'abcdef0123456789'*4
        self.assertFalse(self.spans(self.report([chosen]))[1])
        self.assertFalse(self.spans(self.report([self.operands[0]+'.json']))[1])
        doc=self.report();doc['scans']['arbitrary']=[self.operands[0]];self.assertEqual(len(self.spans(doc)[1]),12)

    def test_altered_deleted_linked_base_refuses_whole_family(self):
        base=self.root/self.operands[0]
        for raw in [b'altered', self.raw+b'x']:
            base.write_bytes(raw);self.assertFalse(self.spans(self.report())[1])
        base.unlink();self.assertFalse(self.spans(self.report())[1])

    def test_link_and_hash_tampering(self):
        for relative, original, edit in [(self.operands[1],self.receipt,{'plan_sha256':'4'*64}),(self.operands[2],self.journal,{'transaction_id':'MC-'+'4'*16+'-01234567'})]:
            changed={**original,**edit};changed.pop('integrity');self.write(relative,_with_sha256_integrity(changed));self.assertFalse(self.spans(self.report())[1]);self.write(relative,original)

    def test_native_only_symlink_ancestor_and_leaf(self):
        base=self.root/self.operands[0];base.unlink();outside=self.root/'outside';outside.write_bytes(self.raw)
        self._native_symlink(base,outside)
        self.assertFalse(self.spans(self.report())[1])

    def test_cache_once_and_substitution(self):
        budget=managed.ProofBudget(self.root);self.assertTrue(self.spans(self.report(),budget)[1]);charged=budget.bytes_read
        self.assertTrue(self.spans(self.report(),budget)[1]);self.assertEqual(charged,budget.bytes_read)
        (self.root/self.operands[0]).write_bytes(b'changed');self.assertFalse(self.spans(self.report(),budget)[1])

    def test_dependency_absent_wrong_or_shadow_refuses_but_scan_continues(self):
        with patch.object(managed.importlib_metadata,'distribution',side_effect=managed.importlib_metadata.PackageNotFoundError):self.assertFalse(self.spans(self.report())[1])
        with patch.object(managed.importlib_metadata,'distribution',return_value=type('D',(),{'version':'0.1.3'})()):self.assertFalse(self.spans(self.report())[1])
        import rfc8785
        with patch.object(rfc8785,'__file__',str(self.root/'shadow.py')):self.assertFalse(self.spans(self.report())[1])

    def test_finite_carrier_routes(self):
        inner=self.report();binding={'project_root':str(self.root),'naos_root':'naos'}
        evidence={'schema':'naos.evidence_pack.v1',**binding,'artifacts':{'secret_hygiene_report':{'data':inner}}}
        dashboard={'schema':'naos.dashboard_summary.v1',**binding,'inputs':{'secret_hygiene':{'data':inner},'evidence_pack':{'data':evidence}},'unknown':inner}
        self.assertEqual(len(self.spans(evidence)[1]),12);self.assertEqual(len(self.spans(dashboard)[1]),24)
        dashboard['inputs']['evidence_pack']['data']['project_root']='foreign';self.assertEqual(len(self.spans(dashboard)[1]),12)
        dashboard['inputs']['secret_hygiene']['data']['project_root']='foreign';self.assertFalse(self.spans(dashboard)[1])

    def test_portable_producer_positive_and_preimage_negative(self):
        import secret_portable_provenance_fixtures as module
        files=module.fixture()
        for path,raw in files.items():p=self.root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
        values=[path for path in files if '/bases/' in path or any('/'+kind+'/' in path for kind in ['receipts','policies','mode-inventories'])]
        _,spans,diag=self.spans(self.report(values));self.assertEqual(len(spans),3*len(values),diag)
        for path in files:
            if '/bases/' in path:(self.root/path).write_bytes(b'bad')
        self.assertFalse(self.spans(self.report(values))[1])

    def test_windows_producers_operation_binding_and_tamper(self):
        from upgrade_contract import windows_provenance as wp
        from upgrade_contract.windows_coordinator import _envelope
        from secret_windows_provenance_fixtures import enrolled, ROOT_ID, PATH, REQUEST, POLICY
        from secret_windows_provenance_fixtures import observation
        reader,snapshot=enrolled()
        plan={'schema':'naos.upgrade.windows_runtime_plan.v2','project_root':str(self.root),'project_root_identity':ROOT_ID,
              'source_policy_observation':{},'source_policy_sha256':hashlib.sha256(POLICY).hexdigest(),
              'source_policy_snapshot_sha256':snapshot.manifest['source_policy_snapshot_sha256'],
              'expected_manifest_sha256':snapshot.manifest_sha256,'expected_owner_sha256':snapshot.owner_sha256,
              'enrollment':False,'private_file_policy':{'inputs':{'transaction_id':'WMC-0123456789abcdef'},'password':'WOP-0123456789abcdef'},'request':REQUEST,'checks':[],'rows':[],
              'operation_id':'WOP-0123456789abcdef','transaction_id':'WMC-0123456789abcdef',
              'project_id':snapshot.project_id,'status':'ready'}
        plan['digest_sha256']=canonical_sha256(plan)
        obs=observation(PATH,b'base')
        content={'kind':'file','size_decimal':obs['size_decimal'],'sha256':obs['sha256'],'metadata_sha256':obs['comparison_metadata_sha256']}
        reader.files.update(wp.make_commit_records(snapshot,transaction_id=plan['transaction_id'],plan_sha256=plan['digest_sha256'],
                          changes={PATH:{'content':content,'archive_bytes':b'base'}},source_policy_raw=POLICY,request=REQUEST))
        for version in [1,2]:
            op=managed._WINDOWS_ROOT+'/transactions/'+plan['operation_id']
            record={'schema':f'naos.upgrade.windows_operation_plan.v{version}','operation_id':plan['operation_id'],
                    'plan':plan,'plan_sha256':canonical_sha256(plan)}
            intent={'schema':f'naos.upgrade.windows_operation.v{version}','failure_model':'application_crash_v1',
                    'operation_id':plan['operation_id'],'plan_sha256':canonical_sha256(plan),'slot_paths':{},'publications':[],
                    'runtime_parent_id':ROOT_ID,'scope_lock_id':ROOT_ID,'transaction_directory_id':ROOT_ID,'lock_id':ROOT_ID}
            marker={'schema':intent['schema'],'failure_model':'application_crash_v1','intent_sha256':hashlib.sha256(_envelope(intent)).hexdigest(),'direction':'forward','topology':'committed'}
            for relative,raw in reader.files.items():
                path=self.root/relative.replace('\\','/');path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
            for leaf,body in [('plan.json',record),('intent.json',intent),('committed.json',marker)]:
                path=self.root/op/leaf;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(_envelope(body))
            values=[r.replace('\\','/') for r in reader.files if any('/'+kind+'/' in r.replace('\\','/') for kind in ['bases','base-blobs','receipts'])]+[op,op+'/plan.json',op+'/intent.json',op+'/committed.json']
            _,spans,diag=self.spans(self.report(values));self.assertEqual(len(spans),3*len(values),diag)
            self.assertGreater(common.shannon_entropy(plan['transaction_id']),4.0)
            self.assertEqual(len(self.raw_control_spans(managed._WINDOWS_ROOT+'/manifest.json')[1]),1)
            self.assertEqual(len(self.raw_control_spans(op+'/plan.json')[1]),3)
            self.assertEqual(len(self.raw_control_spans(op+'/intent.json')[1]),1)
            observed=common.check_secret_hygiene(root=self.root,profile='standard',naos_root='naos',
                rules={'scan_roots':[op+'/plan.json'],'include_root_files':False},rules_path=None,severity='blocking')
            self.assertEqual(observed['summary']['inventory_operand_matches'],3)
            self.assertGreaterEqual(observed['summary']['entropy_matches'],2)
            self.assertGreater(observed['summary']['regex_matches'],0)
            for raw_path in values:
                if '/receipts/' in raw_path or '/bases/' in raw_path:
                    self.assertEqual(len(self.raw_control_spans(raw_path)[1]),1)
            self.write('data/windows-label.json',{'transaction_id':plan['transaction_id'],'operation_id':plan['operation_id']})
            self.assertFalse(self.raw_control_spans('data/windows-label.json')[1])
            record['plan_sha256']='a'*64;(self.root/op/'plan.json').write_bytes(_envelope(record));self.assertFalse(self.spans(self.report(values))[1])
            self.assertFalse(self.raw_control_spans(op+'/plan.json')[1])

    def test_legacy_v2_exact_record_constructors(self):
        old=self.plan['paths'][0];after={**old['source'],'sha256':hashlib.sha256(b'updated').hexdigest(),'size':7}
        plan={'schema':'naos.upgrade.content_aware_plan.v2','operation':'naos-add-artifact:test','status':'ready',
              'project':{'root_binding':str(self.root),'project_id':self.scope['project_id'],'scope_integrity_sha3_512':self.scope['integrity']['value']},
              'profile':{},'request_inputs':{},'creation_identity':self.plan['creation_identity'],
              'source_policy':{'active':{'binding_sha256':'3'*64},'provenance':{'binding_sha256':'3'*64}},
              'manifest':{},'paths':[{'path':old['path'],'base':None,'before':old['source'],
                'after':{'presence':'present',**after},'base_metadata':None,'before_metadata':None,'after_metadata':old['source_metadata'],
                'content_state':'PROPOSE_UPDATE_FROM_UPSTREAM','ownership':{'after':'kit_owned_derived'},'source_policy':{},
                'preservation':{},'action':'UPDATE_FROM_UPSTREAM','mutation':{'eligible':True,'kind':'replace'},'metadata_status':{},'ancestor_identities':[]}],
              'ownership_inference':'forbidden','planning_mutated_target':False,'apply_requires_separate_digest_bound_invocation':True,
              'selected_paths':[old['path']],'operation_inputs':{},'checks':[]}
        plan['plan_sha256']=canonical_sha256(plan);tid='MC-'+plan['plan_sha256'][:16]+'-89abcdef'
        journal=_with_sha256_integrity({'schema':'naos.upgrade.content_transaction.v2','minimum_recovery_naos_version':'1.1.0',
             'transaction_id':tid,'plan':plan,'state':'COMMITTED','applied_actions':[],'created_directories':[],'pending_action':None,'detail':None})
        item=plan['paths'][0]
        action={k:item[k] for k in ('path','before','after','before_metadata','after_metadata')}
        action.update(kind='replace',installed_metadata={},backup_metadata={},base_blob={'path':after['sha256'],'sha256':after['sha256']},publication_adapter='darwin_rename_swap')
        receipt=_with_sha256_integrity({'schema':'naos.upgrade.managed_content_receipt.v2','minimum_recovery_naos_version':'1.1.0',
             'project_id':self.scope['project_id'],'scope_integrity_sha3_512':self.scope['integrity']['value'],'source_policy_sha256':'3'*64,
             'transaction_id':tid,'plan_sha256':plan['plan_sha256'],'status':'COMMITTED','actions':[action],'replacement_performed':True})
        manifest=copy.deepcopy(self.manifest);manifest.pop('integrity');manifest.update(schema='naos.upgrade.managed_content_manifest.v2',minimum_recovery_naos_version='1.1.0',last_transaction_id=tid,last_plan_sha256=plan['plan_sha256'])
        manifest['transactions'].append({'transaction_id':tid,'plan':plan,'receipt_sha256':canonical_sha256(receipt)})
        manifest['entries'][0].update(base=after,base_blob={'path':after['sha256'],'sha256':after['sha256']},last_mutated_by_transaction=tid,receipt_sha256=canonical_sha256(receipt))
        self.write(self.relative+'/state/manifest.json',_with_sha256_integrity(manifest))
        rp=self.relative+'/state/receipts/'+tid+'.json';jp=self.relative+'/transactions/'+tid+'/journal.json';bp=self.relative+'/state/bases/'+after['sha256']
        self.write(rp,receipt);self.write(jp,journal);(self.root/bp).write_bytes(b'updated')
        _,spans,diag=self.spans(self.report([rp,jp,bp]));self.assertEqual(len(spans),9,diag)
        text,control,diag=self.raw_control_spans(self.relative+'/state/manifest.json')
        self.assertEqual(len(control),5,diag)
        self.assertEqual({json.loads(text[a:b]) for a,b in control},{self.tid,tid})
        self.assertEqual(len(self.raw_control_spans(rp)[1]),1)
        self.assertEqual(len(self.raw_control_spans(jp)[1]),1)
        (self.root/bp).write_bytes(b'changed');self.assertFalse(self.spans(self.report([rp,jp,bp]))[1])

    def directory_inventory_doc(self):
        return {'schema':'naos.secret_hygiene.v1','project_root':str(self.root),'naos_root':'naos',
                'scans':{'scope_inventory':[{'path':self.relative+'/state/bases','status':'directory'}]}}

    def test_directory_inventory_uses_native_ancestor_witness_and_sticky_checkpoint(self):
        context=managed._ScannerProofBudget(self.root)
        self.assertEqual(len(self.spans(self.directory_inventory_doc(),context)[1]),1)
        directory=self.root/self.relative/'state/bases'
        moved=directory.with_name('previous-bases');directory.rename(moved);directory.mkdir()
        # Preserve the file object and bytes while replacing only its parent.
        (moved/self.digest).rename(directory/self.digest)
        with self.assertRaisesRegex(managed.OperandRefusal,'scan_proof_invalidated'):
            context.finish_scanner_batch()
        (directory/self.digest).rename(moved/self.digest);directory.rmdir();moved.rename(directory)
        with self.assertRaisesRegex(managed.OperandRefusal,'scan_proof_invalidated'):
            context.finish_scanner_batch()

    def test_directory_inventory_link_reparse_and_security_substitution_refused(self):
        from types import SimpleNamespace
        import stat
        directory=self.root/self.relative/'state/bases';original=Path.lstat;metadata=directory.lstat()
        fields=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_uid','st_gid')
        values={name:getattr(metadata,name) for name in fields}
        values['st_file_attributes']=getattr(metadata,'st_file_attributes',0)
        for delta in [{'st_dev':values['st_dev']+1},{'st_ino':values['st_ino']+1},
                      {'st_mode':values['st_mode']^0o100},{'st_uid':values['st_uid']+1},
                      {'st_gid':values['st_gid']+1},{'st_file_attributes':0x400},
                      {'st_file_attributes':values['st_file_attributes']^0x20},
                      {'st_mode':stat.S_IFLNK|0o777},{'st_mode':stat.S_IFREG|0o600}]:
            with self.subTest(delta=delta):
                context=managed._ScannerProofBudget(self.root)
                self.assertEqual(len(self.spans(self.directory_inventory_doc(),context)[1]),1)
                def observed(p,*args,**kwargs):
                    return SimpleNamespace(**{**values,**delta}) if p==directory else original(p,*args,**kwargs)
                with patch.object(Path,'lstat',observed):
                    with self.assertRaisesRegex(managed.OperandRefusal,'scan_proof_invalidated'):
                        context.finish_scanner_batch()

    def test_directory_inventory_augmentation_retains_identity_limit(self):
        context=managed.ProofBudget(self.root)
        managed._legacy_operands(context)
        with patch.object(managed,'MAX_IDENTITIES',0):
            with self.assertRaisesRegex(managed.OperandRefusal,'inventory_directory_identities'):
                managed._proved_inventory_directories(context,{self.operands[0]},self.root)

    def test_all_declared_type_annotations_resolve(self):
        import inspect
        import typing
        for name,value in vars(managed).items():
            if inspect.isfunction(value) and value.__module__ == managed.__name__:
                with self.subTest(function=name):typing.get_type_hints(value)

    def test_refused_read_remains_charged_across_second_file(self):
        from types import SimpleNamespace
        first=self.root/'first.bin';second=self.root/'second.bin'
        first.write_bytes(b'a'*1024);second.write_bytes(b'b'*1024)
        observed=[];original_fdopen=managed.os.fdopen;original_fstat=managed.os.fstat;calls=0
        class ObservedRead:
            def __init__(self,stream):self.stream=stream
            def __enter__(self):return self
            def __exit__(self,*args):return self.stream.__exit__(*args)
            def read(self,size):
                raw=self.stream.read(size);observed.append((size,len(raw)));return raw
        def opened(*args,**kwargs):
            self.assertEqual(kwargs.get('buffering'),0)
            return ObservedRead(original_fdopen(*args,**kwargs))
        def changed_after_read(descriptor):
            nonlocal calls
            calls+=1;value=original_fstat(descriptor)
            if calls==2:
                return SimpleNamespace(st_dev=value.st_dev,st_ino=value.st_ino,st_mode=value.st_mode,
                    st_size=value.st_size,st_mtime_ns=value.st_mtime_ns+1,st_ctime_ns=value.st_ctime_ns,
                    st_file_attributes=getattr(value,'st_file_attributes',0))
            return value
        budget=managed.ProofBudget(self.root)
        with patch.object(managed,'MAX_PROOF_BYTES',1024),patch.object(managed.os,'fdopen',side_effect=opened),patch.object(managed.os,'fstat',side_effect=changed_after_read):
            with self.assertRaisesRegex(managed.OperandRefusal,'unstable_read'):budget.read(first.name)
            self.assertEqual(budget.bytes_read,1024);self.assertNotIn(first.name,budget.cache)
            with self.assertRaisesRegex(managed.OperandRefusal,'proof_bytes'):budget.read(second.name)
        self.assertEqual(observed,[(1024,1024)]);self.assertEqual(budget.bytes_read,1024)

    def test_growth_at_budget_edge_never_reads_extra_sentinel(self):
        first=self.root/'growing.bin';second=self.root/'another.bin'
        first.write_bytes(b'a'*1024);second.write_bytes(b'b')
        observed=[];original_fdopen=managed.os.fdopen
        class GrowingRead:
            def __init__(self,stream):self.stream=stream
            def __enter__(self):return self
            def __exit__(self,*args):return self.stream.__exit__(*args)
            def read(self,size):
                with first.open('ab',buffering=0) as writer:writer.write(b'x')
                raw=self.stream.read(size);observed.append((size,len(raw)));return raw
        def opened(*args,**kwargs):
            self.assertEqual(kwargs.get('buffering'),0)
            return GrowingRead(original_fdopen(*args,**kwargs))
        budget=managed.ProofBudget(self.root)
        with patch.object(managed,'MAX_PROOF_BYTES',1024),patch.object(managed.os,'fdopen',side_effect=opened):
            with self.assertRaisesRegex(managed.OperandRefusal,'unstable_read'):budget.read(first.name)
            with self.assertRaisesRegex(managed.OperandRefusal,'proof_bytes'):budget.read(second.name)
        self.assertEqual(observed,[(1024,1024)]);self.assertEqual(first.stat().st_size,1025)
        self.assertEqual(budget.bytes_read,1024);self.assertEqual(budget.cache,{})

    def test_io_failure_keeps_conservative_reservation(self):
        from unittest.mock import MagicMock
        path=self.root/'failed.bin';path.write_bytes(b'a'*1024)
        stream=MagicMock();stream.__enter__.return_value=stream;stream.read.side_effect=OSError('controlled I/O refusal')
        budget=managed.ProofBudget(self.root)
        with patch.object(managed,'MAX_PROOF_BYTES',1024),patch.object(managed.os,'fdopen',return_value=stream):
            with self.assertRaises(OSError):budget.read(path.name)
        self.assertEqual(budget.bytes_read,1024);self.assertEqual(budget.cache,{})

    def test_portable_prior_manifest_respects_final_identity_cap(self):
        import secret_portable_provenance_fixtures as module
        files=module.two_receipt_fixture()[0]
        for relative,raw in files.items():
            path=self.root/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        with patch.object(managed,'MAX_IDENTITIES',8):
            operands=managed._portable_operands(managed.ProofBudget(self.root));self.assertEqual(len(operands),8)
            self.assertTrue(any('/manifests/' in path for path in operands))
        values=sorted(operands)
        with patch.object(managed,'MAX_IDENTITIES',7):
            with self.assertRaisesRegex(managed.OperandRefusal,'identities'):managed._portable_operands(managed.ProofBudget(self.root))
            # A refusal must not leak the earlier seven accumulated paths.
            self.assertFalse(self.spans(self.report(values))[1])

    def test_real_31_32_mib_shared_cache_boundary(self):
        files=[]
        for index,size in enumerate([8,8,8,7,1]):
            p=self.root/f'budget{index}.bin';p.write_bytes(b'x'*(size*1024*1024));files.append(p.name)
        overflow=self.root/'overflow.bin';overflow.write_bytes(b'x')
        budget=managed.ProofBudget(self.root)
        for p in files[:4]:budget.read(p)
        self.assertEqual(budget.bytes_read,31*1024*1024)
        for p in files[:4]:budget.read(p)
        self.assertEqual(budget.bytes_read,31*1024*1024)
        budget.read(files[4]);self.assertEqual(budget.bytes_read,32*1024*1024)
        with self.assertRaises(managed.OperandRefusal):budget.read(overflow.name)
        (self.root/'oversized.bin').write_bytes(b'x'*(8*1024*1024+1))
        with self.assertRaises(managed.OperandRefusal):managed.ProofBudget(self.root).read('oversized.bin')

    def test_precise_50000_metadata_and_64_depth_boundaries(self):
        doc={'schema':'naos.secret_hygiene.v1','project_root':str(self.root),'naos_root':'naos',
             'scans':{'unassessed_suffix_files':['x']*49999}}
        parser=managed._OffsetJSON(json.dumps(doc));parser.parse();self.assertEqual(parser.nodes,50000)
        doc['scans']['unassessed_suffix_files'].append('x')
        with self.assertRaises(managed.OperandRefusal):managed._OffsetJSON(json.dumps(doc)).parse()
        doc=self.report();text=json.dumps(doc)[:-1]+',"deep":'+'['*63+'0'+']'*63+'}'
        self.assertEqual(len(self.spans(text)[1]),12)
        text=json.dumps(doc)[:-1]+',"deep":'+'['*64+'0'+']'*64+'}'
        self.assertFalse(self.spans(text)[1])

    def test_copied_module_without_upgrade_contract(self):
        import subprocess
        directory=self.root/'copied';directory.mkdir()
        shutil.copy2(KIT/'scripts/naos_secret_managed_operands.py',directory)
        code="import sys;sys.path.insert(0,sys.argv[1]);import naos_secret_managed_operands as m;assert not any(n=='upgrade_contract' or n.startswith('upgrade_contract.') for n in sys.modules);assert m._OffsetJSON('{\"n\":1}').parse()=={'n':1}"
        result=subprocess.run([sys.executable,'-I','-c',code,str(directory)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_whole_byte_depth_and_metadata_node_bounds(self):
        with patch.object(managed,'MAX_DOCUMENT_BYTES',100):self.assertFalse(self.spans(self.report())[1])
        with patch.object(managed,'MAX_METADATA_NODES',10):self.assertFalse(self.spans(self.report())[1])
        budget=managed.ProofBudget(self.root)
        with patch.object(managed,'MAX_PROOF_BYTES',1):self.assertFalse(self.spans(self.report(),budget)[1]);self.assertEqual(budget.bytes_read,0)


    def _read_hook(self, callback):
        original=managed.os.fdopen
        class HookedRead:
            def __init__(self,stream):self.stream=stream
            def __enter__(self):return self
            def __exit__(self,*args):return self.stream.__exit__(*args)
            def read(self,size):
                raw=self.stream.read(size);callback();return raw
        return patch.object(managed.os,'fdopen',side_effect=lambda *a,**kw:HookedRead(original(*a,**kw)))

    def test_cached_proof_survives_sibling_namespace_changes(self):
        budget=managed.ProofBudget(self.root)
        before=self.spans(self.report(),budget)[1];self.assertTrue(before)
        charged=budget.bytes_read
        # Include an outer ancestor outside the project, matching the r7 probe.
        with tempfile.TemporaryDirectory(prefix='managed-outer-sibling-',dir=self.root.parent) as outer:
            locations=[self.root/'namespace-sibling',self.root/self.relative/'namespace-sibling',Path(outer)/'child']
            for path in locations:
                with self.subTest(parent=str(path.parent)):
                    path.mkdir();self.assertEqual(self.spans(self.report(),budget)[1],before)
                    renamed=path.with_name(path.name+'-renamed');path.rename(renamed)
                    self.assertEqual(self.spans(self.report(),budget)[1],before)
                    renamed.rmdir();self.assertEqual(self.spans(self.report(),budget)[1],before)
        self.assertEqual(self.spans(self.report(),budget)[1],before)
        self.assertEqual(budget.bytes_read,charged)

    def test_fresh_read_survives_sibling_namespace_changes(self):
        path=self.root/'namespace-input';path.write_bytes(b'unchanged raw input')
        sibling=self.root/'namespace-sibling'
        def changed():
            sibling.mkdir();sibling.rename(self.root/'namespace-renamed')
            (self.root/'namespace-renamed').rmdir()
        budget=managed.ProofBudget(self.root)
        with self._read_hook(changed):self.assertEqual(budget.read(path.name),path.read_bytes())
        self.assertEqual(budget.bytes_read,len(path.read_bytes()))
        self.assertIn(path.name,budget.cache)

    def test_parent_snapshot_ignores_only_namespace_fields(self):
        from types import SimpleNamespace
        metadata=self.root.lstat()
        values={name:getattr(metadata,name) for name in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')}
        values['st_file_attributes']=0
        changed={**values,'st_size':values['st_size']+999,'st_mtime_ns':values['st_mtime_ns']+1,'st_ctime_ns':values['st_ctime_ns']+1}
        self.assertEqual(managed._ancestor_snapshot(SimpleNamespace(**values)),managed._ancestor_snapshot(SimpleNamespace(**changed)))
        self.assertNotEqual(managed._snapshot(SimpleNamespace(**values)),managed._snapshot(SimpleNamespace(**changed)))

    def test_parent_security_object_and_type_changes_refused_cached_and_fresh(self):
        from types import SimpleNamespace
        import stat
        path=self.root/'parent-input';path.write_bytes(b'fixed leaf bytes')
        original=Path.lstat;metadata=self.root.lstat()
        values={name:getattr(metadata,name) for name in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')}
        values['st_file_attributes']=getattr(metadata,'st_file_attributes',0)
        changes={'device':{'st_dev':values['st_dev']+1},'inode':{'st_ino':values['st_ino']+1},
                 'mode':{'st_mode':values['st_mode']^0o100},'uid':{'st_uid':values['st_uid']+1},
                 'gid':{'st_gid':values['st_gid']+1},'attributes':{'st_file_attributes':values['st_file_attributes']^0x20},
                 'reparse':{'st_file_attributes':0x400},'link':{'st_mode':stat.S_IFLNK|0o777},
                 'nondirectory':{'st_mode':stat.S_IFREG|0o600}}
        for phase in ('cached','fresh'):
            for kind,delta in changes.items():
                with self.subTest(phase=phase,property=kind):
                    self.assertTrue(any(values[name]!=value for name,value in delta.items()),
                                    'fixture must change an observed field')
                    budget=managed.ProofBudget(self.root);active=False
                    if phase=='cached':budget.read(path.name);active=True
                    def observed(p,*args,**kwargs):
                        if p==self.root and active:return SimpleNamespace(**{**values,**delta})
                        return original(p,*args,**kwargs)
                    def activate():
                        nonlocal active
                        active=True
                    with patch.object(Path,'lstat',observed):
                        if phase=='fresh':
                            with self._read_hook(activate),self.assertRaises(managed.OperandRefusal):budget.read(path.name)
                        else:
                            with self.assertRaises(managed.OperandRefusal):budget.read(path.name)
                    self.assertEqual(budget.bytes_read,len(path.read_bytes()))
                    if phase=='fresh':self.assertEqual(budget.cache,{})

    def test_actual_parent_replacement_same_leaf_inode_refused(self):
        directory=self.root/'object-parent';directory.mkdir();path=directory/'input';path.write_bytes(b'identical')
        replacement=self.root/'replacement-parent';replacement.mkdir()
        os.link(path,replacement/'input')
        budget=managed.ProofBudget(self.root);budget.read('object-parent/input')
        before=managed._snapshot(path.lstat())
        directory.rename(self.root/'previous-parent');replacement.rename(directory)
        self.assertEqual(managed._snapshot(path.lstat()),before)
        with self.assertRaisesRegex(managed.OperandRefusal,'cached_substitution'):budget.read('object-parent/input')


    def _native_symlink(self, path, target, *, directory=False):
        try:
            path.symlink_to(target,target_is_directory=directory)
        except NotImplementedError:
            self.skipTest('Native symlinks are unavailable; synthetic link/reparse refusal remains mandatory')
        except OSError as error:
            # Only the observed Windows privilege-not-held condition is optional;
            # other operating-system errors remain failures.
            if getattr(error,'winerror',None)==1314:
                self.skipTest('Native symlink privilege/support unavailable; synthetic refusal remains mandatory')
            raise

    def _native_mode_change(self, path, previous, requested):
        try:
            path.chmod(requested)
        except NotImplementedError:
            self.skipTest('Native chmod unavailable; synthetic mode refusal remains mandatory')
        except OSError as error:
            if error.errno in {errno.ENOSYS,errno.ENOTSUP,errno.EOPNOTSUPP}:
                self.skipTest('Native chmod unsupported; synthetic mode refusal remains mandatory')
            raise
        if path.lstat().st_mode==previous:
            self.skipTest('Requested native mode bit is not stat-observable; synthetic mode refusal remains mandatory')

    def _native_mtime_change(self, path, metadata):
        try:
            # Two seconds is observable on the separately probed Windows NTFS
            # cell; verify the field itself on every filesystem used here.
            os.utime(path,ns=(metadata.st_atime_ns,metadata.st_mtime_ns+2_000_000_000))
        except NotImplementedError:
            self.skipTest('Native mtime update unavailable; synthetic mtime refusal remains mandatory')
        except OSError as error:
            if error.errno in {errno.ENOSYS,errno.ENOTSUP,errno.EOPNOTSUPP}:
                self.skipTest('Native mtime update unsupported; synthetic mtime refusal remains mandatory')
            raise
        if path.lstat().st_mtime_ns==metadata.st_mtime_ns:
            self.skipTest('Requested native mtime change is not stat-observable; synthetic mtime refusal remains mandatory')

    def test_leaf_snapshot_substitutions_are_mandatory(self):
        from types import SimpleNamespace
        import stat
        path=self.root/'synthetic-leaf';path.write_bytes(b'fixed')
        original=Path.lstat;metadata=path.lstat()
        values={name:getattr(metadata,name) for name in ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')}
        values['st_file_attributes']=getattr(metadata,'st_file_attributes',0)
        changes={'device':{'st_dev':values['st_dev']+1},'inode':{'st_ino':values['st_ino']+1},
                 'mode':{'st_mode':values['st_mode']^0o100},'size':{'st_size':values['st_size']+1},
                 'mtime':{'st_mtime_ns':values['st_mtime_ns']+1},'ctime':{'st_ctime_ns':values['st_ctime_ns']+1},
                 'attributes':{'st_file_attributes':values['st_file_attributes']^0x20},'reparse':{'st_file_attributes':0x400},
                 'link':{'st_mode':stat.S_IFLNK|0o777},'nonregular':{'st_mode':stat.S_IFDIR|0o700}}
        for phase in ('cached','fresh'):
            for kind,delta in changes.items():
                with self.subTest(phase=phase,property=kind):
                    self.assertTrue(any(values[name]!=value for name,value in delta.items()),
                                    'fixture must change an observed field')
                    budget=managed.ProofBudget(self.root);active=False
                    if phase=='cached':budget.read(path.name);active=True
                    def observed(p,*args,**kwargs):
                        return SimpleNamespace(**{**values,**delta}) if p==path and active else original(p,*args,**kwargs)
                    def activate():
                        nonlocal active
                        active=True
                    with patch.object(Path,'lstat',observed):
                        if phase=='fresh':
                            with self._read_hook(activate),self.assertRaises(managed.OperandRefusal):budget.read(path.name)
                        else:
                            with self.assertRaises(managed.OperandRefusal):budget.read(path.name)
                    self.assertEqual(budget.bytes_read,5)
                    if phase=='fresh':self.assertEqual(budget.cache,{})


    def _windows_clock_observations(self, path, birthtime, change, active=lambda:False, delta=None):
        from types import SimpleNamespace
        from contextlib import ExitStack
        original_lstat=Path.lstat;original_fstat=os.fstat
        def values(metadata):
            return {name:getattr(metadata,name) for name in dir(metadata) if name.startswith('st_')}
        def observed(candidate,*args,**kwargs):
            metadata=original_lstat(candidate,*args,**kwargs)
            if candidate!=path:return metadata
            return SimpleNamespace(**{**values(metadata),'st_file_attributes':0x20,
                                     'st_birthtime_ns':birthtime,'st_ctime_ns':birthtime})
        def opened(descriptor):
            metadata=original_fstat(descriptor)
            current={**values(metadata),'st_file_attributes':0x20,
                     'st_birthtime_ns':birthtime,'st_ctime_ns':change}
            if active():current.update(delta or {})
            return SimpleNamespace(**current)
        stack=ExitStack()
        stack.enter_context(patch.object(Path,'lstat',observed))
        stack.enter_context(patch.object(os,'fstat',opened))
        return stack

    def test_windows_distinct_creation_and_change_clocks_preserve_cached_bytes(self):
        from types import SimpleNamespace
        path=self.root/'clock-input';path.write_bytes(b'fixed')
        birthtime=path.lstat().st_ctime_ns
        metadata=path.lstat()
        values={name:getattr(metadata,name) for name in dir(metadata) if name.startswith('st_')}
        values.update(st_dev=(1<<48)+1,st_ino=(1<<100)+1,st_file_attributes=0x20,
                      st_birthtime_ns=birthtime,st_ctime_ns=birthtime)
        before=SimpleNamespace(**values)
        opened_values={**values,'st_ctime_ns':birthtime+2_000_000_000}
        self.assertTrue(managed._descriptor_matches_path(before,SimpleNamespace(**opened_values)))
        for field,delta in [('st_dev',1<<32),('st_ino',1<<64),('st_mode',0o100),
                            ('st_size',1),('st_mtime_ns',1),('st_birthtime_ns',1),('st_file_attributes',1)]:
            with self.subTest(field=field):
                changed={**opened_values,field:opened_values[field]^delta}
                self.assertFalse(managed._descriptor_matches_path(before,SimpleNamespace(**changed)))
        missing_birth={k:v for k,v in opened_values.items() if k!='st_birthtime_ns'}
        self.assertFalse(managed._descriptor_matches_path(before,SimpleNamespace(**missing_birth)))
        noncreation=SimpleNamespace(**{**values,'st_ctime_ns':birthtime+1})
        self.assertFalse(managed._descriptor_matches_path(noncreation,SimpleNamespace(**opened_values)))
        budget=managed.ProofBudget(self.root)
        with self._windows_clock_observations(path,birthtime,birthtime+2_000_000_000):
            self.assertEqual(budget.read(path.name),b'fixed')
            with patch.object(managed.os,'fdopen',side_effect=AssertionError('cache must not read bytes')):
                self.assertEqual(budget.read(path.name),b'fixed')
        self.assertEqual(budget.bytes_read,5)

    def test_windows_descriptor_full_snapshot_changes_refused_cached_and_fresh(self):
        import stat
        path=self.root/'descriptor-input';path.write_bytes(b'fixed')
        metadata=path.lstat();birthtime=metadata.st_ctime_ns;change=birthtime+2_000_000_000
        changes={'device':{'st_dev':metadata.st_dev+1},'inode':{'st_ino':metadata.st_ino+1},
                 'mode':{'st_mode':metadata.st_mode^0o100},'size':{'st_size':metadata.st_size+1},
                 'mtime':{'st_mtime_ns':metadata.st_mtime_ns+1},'ctime':{'st_ctime_ns':change+1},
                 'birthtime':{'st_birthtime_ns':birthtime+1},'attributes':{'st_file_attributes':0x20^0x1},
                 'reparse':{'st_file_attributes':0x20|0x400},'nonregular':{'st_mode':stat.S_IFDIR|0o700}}
        for phase in ('cached','fresh'):
            for kind,delta in changes.items():
                with self.subTest(phase=phase,property=kind):
                    budget=managed.ProofBudget(self.root);active=False
                    def activate():
                        nonlocal active
                        active=True
                    with self._windows_clock_observations(path,birthtime,change,lambda:active,delta):
                        if phase=='cached':
                            budget.read(path.name);activate()
                            with self.assertRaisesRegex(managed.OperandRefusal,'cached_substitution'):budget.read(path.name)
                        else:
                            with self._read_hook(activate),self.assertRaisesRegex(managed.OperandRefusal,'unstable_read'):budget.read(path.name)
                    self.assertEqual(budget.bytes_read,5)
                    if phase=='fresh':self.assertEqual(budget.cache,{})

        for target in ('leaf','parent'):
            with self.subTest(cached_reobservation=target):
                budget=managed.ProofBudget(self.root);active=False
                with self._windows_clock_observations(path,birthtime,change):
                    budget.read(path.name)
                    original_lstat=Path.lstat;original_close=os.close
                    def closed(descriptor):
                        nonlocal active
                        original_close(descriptor);active=True
                    def replaced(candidate,*args,**kwargs):
                        from types import SimpleNamespace
                        observed=original_lstat(candidate,*args,**kwargs)
                        if active and candidate==(path if target=='leaf' else self.root):
                            values={name:getattr(observed,name) for name in dir(observed) if name.startswith('st_')}
                            values['st_ino']+=1
                            return SimpleNamespace(**values)
                        return observed
                    with patch.object(Path,'lstat',replaced),patch.object(os,'close',closed):
                        with self.assertRaisesRegex(managed.OperandRefusal,'cached_substitution'):budget.read(path.name)
                self.assertEqual(budget.bytes_read,5)

    def test_unexpected_native_operation_errors_are_not_skipped(self):
        for operation in ('symlink','chmod','utime'):
            with self.subTest(operation=operation):
                error=OSError(errno.EIO,'controlled unexpected I/O error')
                if operation=='symlink':
                    with patch.object(Path,'symlink_to',side_effect=error),self.assertRaises(OSError):
                        self._native_symlink(self.root/'link',self.root/'target')
                elif operation=='chmod':
                    with patch.object(Path,'chmod',side_effect=error),self.assertRaises(OSError):
                        self._native_mode_change(self.root,self.root.lstat().st_mode,0o700)
                else:
                    with patch.object(os,'utime',side_effect=error),self.assertRaises(OSError):
                        self._native_mtime_change(self.root,self.root.lstat())

    def test_actual_parent_symlink_refused(self):
        from types import SimpleNamespace
        directory=self.root/'link-parent';directory.mkdir();(directory/'input').write_bytes(b'identical')
        budget=managed.ProofBudget(self.root);budget.read('link-parent/input')
        original=Path.lstat
        def linked(candidate,*args,**kwargs):
            metadata=original(candidate,*args,**kwargs)
            return SimpleNamespace(**{**{name:getattr(metadata,name) for name in dir(metadata) if name.startswith('st_')},'st_mode':stat.S_IFLNK|0o777}) if candidate==directory else metadata
        import stat
        with patch.object(Path,'lstat',linked),self.assertRaisesRegex(managed.OperandRefusal,'unsafe_ancestor'):
            budget.read('link-parent/input')

    def test_native_only_actual_parent_symlink_refused(self):
        directory=self.root/'link-parent';directory.mkdir();(directory/'input').write_bytes(b'identical')
        budget=managed.ProofBudget(self.root);budget.read('link-parent/input')
        retained=self.root/'retained-parent';directory.rename(retained);self._native_symlink(directory,retained,directory=True)
        with self.assertRaisesRegex(managed.OperandRefusal,'unsafe_ancestor'):budget.read('link-parent/input')

    def test_actual_parent_mode_change_refused(self):
        from types import SimpleNamespace
        directory=self.root/'mode-parent';directory.mkdir();path=directory/'input';path.write_bytes(b'identical')
        budget=managed.ProofBudget(self.root);budget.read('mode-parent/input');mode=directory.stat().st_mode
        original=Path.lstat
        def changed(candidate,*args,**kwargs):
            metadata=original(candidate,*args,**kwargs)
            values={name:getattr(metadata,name) for name in dir(metadata) if name.startswith('st_')}
            return SimpleNamespace(**{**values,'st_mode':mode^0o020}) if candidate==directory else metadata
        with patch.object(Path,'lstat',changed),self.assertRaisesRegex(managed.OperandRefusal,'cached_substitution'):
            budget.read('mode-parent/input')

    def test_native_only_actual_parent_mode_change_refused(self):
        directory=self.root/'mode-parent';directory.mkdir();path=directory/'input';path.write_bytes(b'identical')
        budget=managed.ProofBudget(self.root);budget.read('mode-parent/input');mode=directory.stat().st_mode
        changed=False
        try:
            self._native_mode_change(directory,mode,mode^0o020)
            changed=True
            with self.assertRaisesRegex(managed.OperandRefusal,'cached_substitution'):budget.read('mode-parent/input')
        finally:
            if changed:directory.chmod(mode)

    def test_unexpected_parent_mode_cleanup_error_is_not_suppressed(self):
        from types import SimpleNamespace
        original=Path.lstat;calls=0;requested=None
        def changed_then_failed(path,mode):
            nonlocal calls,requested
            calls+=1
            if calls==1:
                requested=mode
                return
            raise OSError(errno.EIO,'controlled unexpected cleanup I/O failure')
        def observed(path,*args,**kwargs):
            metadata=original(path,*args,**kwargs)
            if path==self.root/'mode-parent' and requested is not None:
                values={name:getattr(metadata,name) for name in dir(metadata) if name.startswith('st_')}
                return SimpleNamespace(**{**values,'st_mode':requested})
            return metadata
        with patch.object(Path,'chmod',changed_then_failed),patch.object(Path,'lstat',observed),self.assertRaises(OSError) as raised:
            self.test_native_only_actual_parent_mode_change_refused()
        self.assertEqual(raised.exception.errno,errno.EIO);self.assertEqual(calls,2)

    def test_leaf_full_snapshot_and_regular_file_checks_preserved(self):
        from types import SimpleNamespace
        mutations=['bytes','inode','ctime','reparse']
        for kind in mutations:
            with self.subTest(property=kind):
                path=self.root/('leaf-'+kind);path.write_bytes(b'fixed')
                budget=managed.ProofBudget(self.root);budget.read(path.name)
                original=Path.lstat;metadata=path.lstat()
                values={name:getattr(metadata,name) for name in ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')}
                values['st_file_attributes']=getattr(metadata,'st_file_attributes',0)
                if kind=='bytes':
                    path.write_bytes(b'other')
                    # Endpoint metadata can be unchanged after an immediate rewrite.
                    # Establish an observed mutation without relying on clock ticks.
                    os.utime(path,ns=(metadata.st_atime_ns,metadata.st_mtime_ns+2_000_000_000))
                    self.assertNotEqual(path.lstat().st_mtime_ns,metadata.st_mtime_ns,
                                        'fixture must establish a stat-visible mtime change')
                elif kind=='inode':
                    replacement=self.root/'replacement-leaf';replacement.write_bytes(b'fixed');replacement.replace(path)
                if kind in ('ctime','reparse'):
                    delta={'st_ctime_ns':values['st_ctime_ns']+1} if kind=='ctime' else {'st_file_attributes':0x400}
                    def observed(p,*args,**kwargs):
                        return SimpleNamespace(**{**values,**delta}) if p==path else original(p,*args,**kwargs)
                    with patch.object(Path,'lstat',observed),self.assertRaises(managed.OperandRefusal):budget.read(path.name)
                else:
                    with self.assertRaises(managed.OperandRefusal):budget.read(path.name)
                self.assertEqual(budget.bytes_read,5)

    def _native_leaf_snapshot_refusal(self, kind):
        path=self.root/('native-leaf-'+kind);path.write_bytes(b'fixed')
        budget=managed.ProofBudget(self.root);budget.read(path.name);metadata=path.lstat()
        if kind=='mode':self._native_mode_change(path,metadata.st_mode,metadata.st_mode^0o100)
        elif kind=='mtime':self._native_mtime_change(path,metadata)
        else:
            target=self.root/'native-link-leaf-target';path.rename(target);self._native_symlink(path,target)
        with self.assertRaises(managed.OperandRefusal):budget.read(path.name)
        self.assertEqual(budget.bytes_read,5)

    def test_native_only_leaf_mode_snapshot_refusal(self):self._native_leaf_snapshot_refusal('mode')
    def test_native_only_leaf_mtime_snapshot_refusal(self):self._native_leaf_snapshot_refusal('mtime')
    def test_native_only_leaf_symlink_snapshot_refusal(self):self._native_leaf_snapshot_refusal('link')


    def _batch_scan_kwargs(self, paths):
        return dict(root=self.root, profile='standard', naos_root='naos',
                    rules={'scan_roots': paths, 'include_root_files': False},
                    rules_path=None, severity='blocking')

    def _mutate_cached_member(self, relative):
        target = self.root / relative
        before = target.lstat()
        original = target.read_bytes()
        target.write_bytes(original + b'\nchanged-after-provisional-admission')
        os.utime(target, ns=(before.st_atime_ns,
                            before.st_mtime_ns + 2_000_000_000))
        self.assertNotEqual(managed._snapshot(target.lstat()),
                            managed._snapshot(before),
                            'fixture must establish an observed mutation')
        self.assertNotEqual(target.read_bytes(), original)
        return original

    def test_scanner_batch_actual_control_and_proof_member_mutations_refuse(self):
        _, paths = self.high_entropy_committed_fixture()
        # Base content is proof-only; the other three are raw control records.
        members = [self.operands[0], *paths]
        for relative in members:
            with self.subTest(member=relative):
                budget = managed._ScannerProofBudget(self.root)
                _, spans, _ = self.raw_control_spans(paths[0], context=budget)
                self.assertEqual(len(spans), 3)
                self.assertIn(relative, budget.cache)
                charged = budget.bytes_read
                original = self._mutate_cached_member(relative)
                try:
                    with self.assertRaisesRegex(managed.OperandRefusal,
                                                '^scan_proof_invalidated$'):
                        budget.finish_scanner_batch()
                    self.assertEqual(budget.bytes_read, charged)
                finally:
                    (self.root / relative).write_bytes(original)

    def test_scanner_batch_observed_refusal_remains_sticky_after_restore(self):
        from types import SimpleNamespace
        _, paths = self.high_entropy_committed_fixture()
        budget = managed._ScannerProofBudget(self.root)
        self.assertEqual(len(self.raw_control_spans(paths[0], context=budget)[1]), 3)
        charged = budget.bytes_read
        original_lstat = Path.lstat
        active = False

        def observed(path, *args, **kwargs):
            metadata = original_lstat(path, *args, **kwargs)
            if active and path == self.root:
                values = {name: getattr(metadata, name) for name in dir(metadata)
                          if name.startswith('st_')}
                return SimpleNamespace(**{**values, 'st_ino': metadata.st_ino + 1})
            return metadata

        with patch.object(Path, 'lstat', observed):
            active = True
            # Match the real helper catch boundary, rather than propagating a
            # direct read exception. The altered ancestor observation is later
            # restored; no native clocks/ACL privileges are needed for this case.
            _, spans, diagnostic = self.raw_control_spans(paths[0], context=budget)
            self.assertFalse(spans)
            self.assertEqual(diagnostic['status'], 'refused')
            active = False
            # Prove the ordinary cache sweep can now succeed. Terminal refusal
            # below must therefore depend on sticky invalidation, not remaining
            # filesystem damage or an un-restorable native ctime.
            ordinary = managed.ProofBudget(self.root)
            ordinary.cache = budget.cache.copy()
            ordinary.verify_cached()
            with self.assertRaisesRegex(managed.OperandRefusal,
                                        '^scan_proof_invalidated$'):
                budget.finish_scanner_batch()
        self.assertEqual(budget.bytes_read, charged)

    def test_scanner_batch_defers_only_admission_sweeps_and_preserves_charging(self):
        _, paths = self.high_entropy_committed_fixture()
        budget = managed._ScannerProofBudget(self.root)
        with patch.object(budget, 'verify_cached', wraps=budget.verify_cached) as sweep:
            self.assertEqual(len(self.raw_control_spans(paths[0], context=budget)[1]), 3)
            charged = budget.bytes_read
            expected_charge = sum(len(row[0]) for row in budget.cache.values())
            self.assertEqual(charged, expected_charge)
            self.assertGreater(charged, 0)
            self.assertLessEqual(charged, managed.MAX_PROOF_BYTES)
            self.assertEqual(sweep.call_count, 1,
                             'initial constructor verification must remain eager')
            for _ in range(2):
                for relative, count in zip(paths, [3, 1, 1]):
                    self.assertEqual(len(self.raw_control_spans(
                        relative, context=budget)[1]), count)
                    self.assertEqual(budget.bytes_read, charged)
            self.assertEqual(sweep.call_count, 1,
                             'per-control admission must not resweep the cache')
            budget.finish_scanner_batch()
            self.assertEqual(sweep.call_count, 2,
                             'terminal verification must perform a real sweep')
        self.assertEqual(budget.bytes_read, charged)

    def test_direct_control_helper_remains_eager_for_unrelated_cached_member(self):
        _, paths = self.high_entropy_committed_fixture()
        budget = managed.ProofBudget(self.root)
        with patch.object(budget, 'verify_cached', wraps=budget.verify_cached) as sweep:
            self.assertEqual(len(self.raw_control_spans(paths[0], context=budget)[1]), 3)
            initial_sweeps = sweep.call_count
            charged = budget.bytes_read
            self._mutate_cached_member(self.operands[0])
            _, spans, diagnostic = self.raw_control_spans(paths[0], context=budget)
            self.assertFalse(spans)
            self.assertEqual(diagnostic['status'], 'refused')
            self.assertGreater(sweep.call_count, initial_sweeps,
                               'ordinary helper must still sweep before returning')
        self.assertEqual(budget.bytes_read, charged)

    def test_scanner_terminal_verification_precedes_finding_ids_and_report(self):
        _, paths = self.high_entropy_committed_fixture()
        events = []
        budget = managed._ScannerProofBudget(self.root)
        original_finish = budget.finish_scanner_batch
        original_ids = common.assign_secret_finding_ids
        original_build = common.build_base_report

        def finish():
            original_finish()
            events.append('terminal_verified')

        def ids(findings):
            self.assertIn('terminal_verified', events)
            events.append('finding_ids')
            return original_ids(findings)

        def build(**kwargs):
            self.assertEqual(events, ['terminal_verified', 'finding_ids'])
            events.append('report_built')
            return original_build(**kwargs)

        with patch.object(common, '_ScannerProofBudget', return_value=budget), \
                patch.object(budget, 'finish_scanner_batch', side_effect=finish) as terminal, \
                patch.object(common, 'assign_secret_finding_ids', side_effect=ids), \
                patch.object(common, 'build_base_report', side_effect=build):
            report = common.check_secret_hygiene(**self._batch_scan_kwargs(paths))
        terminal.assert_called_once_with()
        self.assertEqual(events, ['terminal_verified', 'finding_ids', 'report_built'])
        self.assertEqual(report['summary']['inventory_operand_matches'], 5)
        self.assertEqual(report['summary']['coverage_status'], 'complete')
        self.assertEqual(report['summary']['files_selected'], 3)
        self.assertEqual(report['summary']['files_scanned'], 3)

    def test_terminal_refusal_prevents_publication_and_keeps_existing_output(self):
        from naos_policy import SAFE_FALLBACK_POLICY
        _, paths = self.high_entropy_committed_fixture()
        output = self.root / 'retained-output.json'
        sentinel = b'preexisting-report-bytes\n'
        output.write_bytes(sentinel)
        original_spans = common.inventory_operand_spans
        admitted = []

        def after_admission(text, relative, root, naos_root, context):
            result = original_spans(text, relative, root, naos_root, context)
            if result[0] and not admitted:
                admitted.append(relative)
                self.assertIsInstance(context, managed._ScannerProofBudget)
                self._mutate_cached_member(self.operands[0])
            return result

        kwargs = self._batch_scan_kwargs([paths[0]])
        # Exercise the actual shared command publication boundary in-process;
        # no subprocess/native job or substituted acceptance workflow.
        with patch.object(common, 'inventory_operand_spans', side_effect=after_admission), \
                patch.object(common, 'load_policy', return_value=copy.deepcopy(SAFE_FALLBACK_POLICY)), \
                patch.object(common, 'rules_for', return_value=(kwargs['rules'], None)), \
                patch.object(common, 'assign_secret_finding_ids') as ids, \
                patch.object(common, 'build_base_report', wraps=common.build_base_report) as build, \
                patch.object(common, 'write_report', wraps=common.write_report) as publish, \
                patch('builtins.print') as emit:
            with self.assertRaisesRegex(managed.OperandRefusal,
                                        '^scan_proof_invalidated$'):
                common.run_report_command(
                    argv=[str(self.root), '--profile', 'standard', '--naos-root', 'naos',
                          '--output', str(output), '--json'],
                    description='scanner batch publication contract',
                    rules_filename='secret_hygiene_rules.yaml',
                    report_key='secret_hygiene_report', schema='naos.secret_hygiene.v1',
                    fallback_rules={}, builder=common.check_secret_hygiene,
                    summary_label='Secret Hygiene', pass_policy=True)
        self.assertEqual(admitted, [paths[0]])
        ids.assert_not_called()
        build.assert_not_called()
        publish.assert_not_called()
        emit.assert_not_called()
        self.assertEqual(output.read_bytes(), sentinel)


    def test_cached_permission_error_caught_by_inventory_helper_is_sticky(self):
        _, paths = self.high_entropy_committed_fixture()
        budget = managed._ScannerProofBudget(self.root)
        text, spans, _ = self.raw_control_spans(paths[0], context=budget)
        self.assertEqual(len(spans), 3)
        self.assertIn(paths[0], budget.cache)
        charged = budget.bytes_read
        original_lstat = Path.lstat
        refusal_detail = 'SyntheticCredential123 must not enter diagnostic output'

        def denied(path, *args, **kwargs):
            if path == self.root / paths[0]:
                raise PermissionError(refusal_detail)
            return original_lstat(path, *args, **kwargs)

        with patch.object(Path, 'lstat', denied):
            # Supply already captured text so the PermissionError originates
            # inside the proof read and crosses the real inventory catch path.
            _, refused_spans, diagnostic = self.raw_control_spans(
                paths[0], text=text, context=budget)
        self.assertFalse(refused_spans)
        self.assertEqual(diagnostic['status'], 'refused')
        self.assertEqual(diagnostic['reason'], 'PermissionError')
        self.assertNotIn(refusal_detail, json.dumps(diagnostic))

        # Access observations are restored. A fresh ordinary cache verifier can
        # succeed, proving final refusal depends on the sticky scanner state.
        ordinary = managed.ProofBudget(self.root)
        ordinary.cache = budget.cache.copy()
        ordinary.verify_cached()
        with self.assertRaisesRegex(managed.OperandRefusal,
                                    '^scan_proof_invalidated$') as refusal:
            budget.finish_scanner_batch()
        self.assertTrue(refusal.exception.__suppress_context__)
        self.assertNotIn(refusal_detail, str(refusal.exception))
        self.assertEqual(budget.bytes_read, charged)



class WindowsConstructorCoordinatesTests(unittest.TestCase):
    """Pure native producer records mapped onto an ordinary temporary file tree."""
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='win-constructor-');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve()
        self.logical=managed.PureWindowsPath('C:\\fixture-abcdef0123456789')
        self.kit='C:\\kit-abcdef0123456789'
        from upgrade_contract import windows_provenance
        from upgrade_contract.windows_coordinator import _envelope
        from secret_windows_provenance_fixtures import ROOT_ID, REQUEST, POLICY, Reader
        self.wp=windows_provenance;self.envelope=_envelope
        self.identity=ROOT_ID;self.request=REQUEST;self.policy=POLICY;self.Reader=Reader
        self.tid='WMC-0123456789abcdef';self.operation='WOP-0123456789abcdef'
        self.op=managed._WINDOWS_ROOT+'/transactions/'+self.operation
        self.project_id='WIN-b358f0c871260a44'
        self.fixture()

    def write_bytes(self, path, raw):
        q=self.root/path;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(raw)

    def fixture(self, plan_mutation=None, version=2):
        active,_=self.wp.policy_catalog(self.policy)
        paths=['scripts\\fixture-012345abcdef.py','scripts\\other-abcdef012345.py']
        self.contents={path:('pure content '+str(index)).encode() for index,path in enumerate(paths)}
        rows=[]
        for path in paths:
            digest=hashlib.sha256(self.contents[path]).hexdigest()
            rows.append({'path':path,'source':{'path':path,'sha256':digest,'size_decimal':str(len(self.contents[path]))},
                'before':{'schema':'naos.upgrade.windows_content_observation.v1','path':path,'presence':'absent',
                    'ancestors':[{'name':name,**self.identity} for name in ['',*self.logical.parts[1:]]],
                    'missing_suffix':path.split('\\')},
                'base':{'presence':'absent','kind':None,'size_decimal':None,'sha256':None,'metadata_sha256':None},
                'intended':{'presence':'present','kind':'file','size_decimal':str(len(self.contents[path])),
                            'sha256':digest,'metadata_sha256':'1'*64},
                'action':'CREATE_NEW_UPSTREAM','ownership':'kit_owned_derived','creation_policy':'create'})
        self.plan={'schema':'naos.upgrade.windows_runtime_plan.v2','project_root':str(self.logical),
            'project_root_identity':self.identity,'project_id':self.project_id,'status':'ready',
            'source_policy_observation':{'schema':'naos.upgrade.windows_content_observation.v1','presence':'present',
                'path':self.kit[3:]+'\\configs\\upgrade_source_policy.yaml','sha256':hashlib.sha256(self.policy).hexdigest()},
            'source_policy_sha256':hashlib.sha256(self.policy).hexdigest(),'source_policy_snapshot_sha256':active,
            'expected_manifest_sha256':None,'expected_owner_sha256':None,'enrollment':True,
            'private_file_policy':{},'request':self.request,'checks':[],'rows':rows,
            'operation_id':self.operation,'transaction_id':self.tid}
        if plan_mutation:plan_mutation(self.plan)
        self.plan['digest_sha256']=canonical_sha256(self.plan)
        enrollment=self.wp.make_empty_enrollment(project_id=self.project_id,root_identity=self.identity,
            enrollment_plan_sha256=self.plan['digest_sha256'],source_policy_snapshot_sha256=active)
        snapshot=self.wp.load_windows_provenance(self.Reader(enrollment),root_identity=self.identity,source_policy_raw=self.policy)
        changes={row['path']:{'content':{key:row['intended'][key] for key in ('kind','size_decimal','sha256','metadata_sha256')},
                             'archive_bytes':self.contents[row['path']]} for row in rows}
        records=self.wp.make_commit_records(snapshot,transaction_id=self.tid,plan_sha256=self.plan['digest_sha256'],
            changes=changes,source_policy_raw=self.policy,request=self.request)
        records.update({p:b for p,b in enrollment.items() if p!=self.wp.MANIFEST_PATH})
        self.files=records
        manifest_path=self.wp.MANIFEST_PATH
        output=[(row['path'],self.contents[row['path']],'content',f'content-{index:06d}.bin') for index,row in enumerate(rows)]
        for path in sorted(records):
            if path!=manifest_path:
                output.append((path,records[path],'evidence',f'evidence-{len(output):06d}.bin'))
        output.append((manifest_path,records[manifest_path],'manifest',f'manifest-{len(output):06d}.json'))
        slots={};publications=[]
        for index,(path,raw,role,stage_name) in enumerate(output):
            target,staged=f'target-{index}',f'staged-{index}'
            slots[target]=str(self.logical)+'\\'+path
            slots[staged]=str(self.logical)+'\\'+self.wp.ROOT+'\\staging\\'+self.operation+'\\'+stage_name
            after={'volume_serial_hex':self.identity['volume_serial_hex'],'file_id_hex':f'{index+1:032x}',
                   'size_bytes':str(len(raw)),'content_sha256':hashlib.sha256(raw).hexdigest(),'metadata_sha256':'2'*64,
                   'rename_metadata_v2':{'created_100ns_decimal':'1','last_write_100ns_decimal':'1','attributes_hex':'00000020',
                       'owner_sid_sha256':'3'*64,'group_sid_sha256':'4'*64,'dacl_sha256':'5'*64,'descriptor_sha256':'6'*64,
                       'dacl_protected':True}}
            publications.append({'role':role,'kind':'create','target':target,'staged':staged,'after':after})
        # Genuine pure operation constructors validate witness syntax and roles.
        from upgrade_contract.windows_operation import WindowsOperationSpec, Publication
        from upgrade_contract.windows_rename_identity import identity_from_record
        WindowsOperationSpec(self.operation,self.plan,slots,tuple(Publication(row['role'],row['kind'],row['target'],
            row['staged'],identity_from_record(row['after'])) for row in publications),record_version=2).validate()
        self.intent={'schema':f'naos.upgrade.windows_operation.v{version}','failure_model':'application_crash_v1',
            'operation_id':self.operation,'plan_sha256':canonical_sha256(self.plan),'slot_paths':slots,'publications':publications,
            'runtime_parent_id':self.identity,'scope_lock_id':self.identity,'transaction_directory_id':self.identity,'lock_id':self.identity}
        self.record={'schema':f'naos.upgrade.windows_operation_plan.v{version}','operation_id':self.operation,
                     'plan':self.plan,'plan_sha256':canonical_sha256(self.plan)}
        for path,raw in records.items():self.write_bytes(path.replace('\\','/'),raw)
        self.persist_operation()

    def persist_operation(self):
        self.write_bytes(self.op+'/plan.json',self.envelope(self.record))
        raw=self.envelope(self.intent);self.write_bytes(self.op+'/intent.json',raw)
        marker={'schema':self.intent['schema'],'failure_model':'application_crash_v1',
                'intent_sha256':hashlib.sha256(raw).hexdigest(),'direction':'forward','topology':'committed'}
        self.write_bytes(self.op+'/committed.json',self.envelope(marker))

    def context(self,batch=False):
        physical=(managed._ScannerProofBudget if batch else managed.ProofBudget)(self.root)
        # Test-only adapter: exact logical Windows label, guarded physical bytes.
        class Context:
            root=self.logical
            def __init__(self):
                self.cache=physical.cache;self.operands={};self.reason={};self.evidence={};self.constructor_coordinates={}
            @property
            def bytes_read(self):return physical.bytes_read
            def read(self,path):return physical.read(path)
            def object(self,path):return managed._strict_object(self.read(path))
            def verify_cached(self):return physical.verify_cached()
            def admission_checkpoint(self):return physical.admission_checkpoint()
            def finish_scanner_batch(self):return physical.finish_scanner_batch()
        return Context()

    def spans(self,path=None,context=None,text=None):
        path=path or self.op+'/intent.json';text=text or (self.root/path).read_text()
        with patch.object(managed,'__file__',self.kit+'\\scripts\\naos_secret_managed_operands.py'):
            spans,diagnostic=managed.inventory_operand_spans(text,path,self.root,'naos',context or self.context())
        return text,spans,diagnostic

    def path_values(self,text,spans):
        return [json.loads(text[a:b]) for a,b in sorted(spans) if '\\' in json.loads(text[a:b])]


    def _carrier_fixture(self):
        from upgrade_contract.windows_runtime_directories import (
            DirectoryJournal, absent_content_parents, existing_parent_anchors)
        intent_sha=hashlib.sha256(self.envelope(self.intent)).hexdigest()
        self.carrier_forward=[]
        for step in range(1,len(self.intent['publications'])+1):
            relative=self.op+'/forward-'+format(step,'06d')+'.json'
            marker={'schema':'naos.upgrade.windows_operation.v2','failure_model':'application_crash_v1',
                    'intent_sha256':intent_sha,'direction':'forward','topology':'step:'+str(step)}
            self.write_bytes(relative,self.envelope(marker));self.carrier_forward.append(relative)
        expected=absent_content_parents(self.plan);anchors=existing_parent_anchors(self.plan)
        ids={path:{'volume_serial_hex':self.identity['volume_serial_hex'],'file_id_hex':format(100000+i,'032x')}
             for i,path in enumerate(expected)}
        rows=[]
        for path in expected:
            parent=path.rsplit('\\',1)[0] if '\\' in path else ''
            rows.append({'path':path,'identity':ids[path],
                'parent_identity':ids[parent] if parent in ids else anchors[path],
                'attributes_hex':'00000010','comparison_metadata_sha256':'2'*64})
        validator=object.__new__(DirectoryJournal);validator.operation_id=self.operation
        validator.intent_sha256=intent_sha;validator.expected_paths=expected
        validator.root_identity=self.identity;validator.parent_anchors=anchors
        self.carrier_directories=validator._body(rows);validator._validate_body(self.carrier_directories)
        self.write_bytes(self.op+'/directories.json',self.envelope(self.carrier_directories))
        root=managed._WINDOWS_ROOT
        return set(self.carrier_forward)|{root+'/root.json',root+'/owner.json',root+'/manifest.json',
            root+'/bases',root+'/base-blobs',root+'/receipts',root+'/transactions',root+'/staging',
            root+'/template.file',root+'/template.directory',root+'/staging/'+self.operation,
            self.op,self.op+'/lock',root+'/transactions/managed-scope.lock',self.op+'/directories.json'}

    def _carrier_spans(self,paths,context=None,extra=None):
        report={'schema':'naos.secret_hygiene.v1','project_root':str(self.root),'naos_root':'naos',
            'scans':{'input_files':[{'path':p,'status':'read'} for p in paths],
                'scope_inventory':[{'path':p,'status':'selected'} for p in paths],
                'unassessed_suffix_files':list(paths),
                'inventory_operand_proofs':[{'path':p,'status':'proved','matches':1,'proof_bytes':1} for p in paths]}}
        if extra:report.update(extra)
        text=json.dumps(report,indent=2)
        return self.spans('naos/reports/secret_hygiene.json',context,text)

    def test_carrier_complete_constructor_roles_all_four_metadata_arrays(self):
        paths=sorted(self._carrier_fixture());context=self.context()
        text,spans,diag=self._carrier_spans(paths,context)
        self.assertEqual(diag['status'],'proved')
        self.assertEqual(len(spans),4*len(paths))
        self.assertEqual({json.loads(text[a:b]) for a,b in spans},set(paths))
        # Retired constructor paths need no live directory or output existence.
        self.assertFalse((self.root/managed._WINDOWS_ROOT/'staging'/self.operation).exists())

    def test_pure_saved_directory_scope_and_witnesses_agree_with_producer(self):
        import ntpath
        from upgrade_contract.windows_runtime_directories import (
            DirectoryJournal, absent_content_parents, existing_parent_anchors, _MUTATIONS)
        from upgrade_contract.windows_handles import SUPPORTED_DIRECTORY_ATTRIBUTES
        from upgrade_contract.windows_observation import _relative_parts
        self.assertEqual(SUPPORTED_DIRECTORY_ATTRIBUTES, 0x20b7)
        self.assertEqual(managed._WINDOWS_CREATE_ACTIONS|{'UPDATE_FROM_UPSTREAM'},_MUTATIONS)
        for path in (r'scripts\nested\file.py', r'CON\file.py', 'a\\\\b',
                     'a/b', 'C:\\file.py', '\\file.py', 'a\\..\\b',
                     'a\\bad.\\file.py', 'a\\name:stream', 'x'*256):
            with self.subTest(component_path=path):
                try:producer_parts=_relative_parts(path)
                except ValueError:producer_parts=None
                try:candidate_parts=managed._windows_relative_path(path)
                except ValueError:candidate_parts=None
                self.assertEqual(candidate_parts,producer_parts)
        plan=copy.deepcopy(self.plan)
        plan['rows'][0]['path']=r'scripts\nested\fixture.py'
        plan['rows'][0]['before']['missing_suffix']=plan['rows'][0]['path'].split('\\')
        expected=absent_content_parents(plan);anchors=existing_parent_anchors(plan)
        self.assertEqual(managed._windows_saved_directory_scope(plan),(expected,anchors))
        self.assertEqual(expected,(r'scripts',r'scripts\nested'))
        ids={path:{'volume_serial_hex':self.identity['volume_serial_hex'],
                   'file_id_hex':format(100000+i,'032x')} for i,path in enumerate(expected)}
        rows=[{'path':path,'identity':ids[path],
               'parent_identity':ids[ntpath.dirname(path)] if ntpath.dirname(path) in ids else anchors[path],
               'attributes_hex':'00000010','comparison_metadata_sha256':'2'*64} for path in expected]
        validator=object.__new__(DirectoryJournal);validator.operation_id=self.operation
        validator.intent_sha256='3'*64;validator.expected_paths=expected
        validator.root_identity=self.identity;validator.parent_anchors=anchors
        body=validator._body(rows)
        def agrees(candidate_plan,candidate_body):
            producer=True;candidate=True
            try:
                validator.expected_paths=absent_content_parents(candidate_plan)
                validator.parent_anchors=existing_parent_anchors(candidate_plan)
                validator._validate_body(candidate_body)
            except (ValueError,RuntimeError,KeyError,TypeError):producer=False
            try:managed._windows_saved_directory_witnesses(candidate_plan,self.operation,'3'*64,candidate_body)
            except (ValueError,RuntimeError,KeyError,TypeError):candidate=False
            self.assertEqual(candidate,producer)
            return candidate
        self.assertTrue(agrees(plan,body))
        for mutation in ('order','alias','same_identity','parent','volume','attributes','extra','link','metadata'):
            with self.subTest(mutation=mutation):
                bad=copy.deepcopy(body)
                if mutation=='order':bad['directories'].reverse()
                elif mutation=='alias':bad['directories'][1]['path']='SCRIPTS'
                elif mutation=='same_identity':bad['directories'][1]['identity']=bad['directories'][0]['identity']
                elif mutation=='parent':bad['directories'][1]['parent_identity']=self.identity
                elif mutation=='volume':bad['directories'][0]['identity']['volume_serial_hex']='f'*16
                elif mutation=='attributes':bad['directories'][0]['attributes_hex']='00000410'
                elif mutation=='extra':bad['directories'][0]['extra']='provider'
                elif mutation=='link':bad['intent_sha256']='0'*64
                else:bad['directories'][0]['comparison_metadata_sha256']='Z'*64
                self.assertFalse(agrees(plan,bad))
        for mutation in ('suffix','runtime','alias','anchor','missing_anchor'):
            with self.subTest(scope=mutation):
                bad=copy.deepcopy(plan)
                if mutation=='suffix':bad['rows'][0]['before']['missing_suffix']=['wrong.py']
                elif mutation=='runtime':bad['rows'][0]['path']=r'.naos\nested\fixture.py'
                elif mutation=='alias':bad['rows'][1]['path']=r'SCRIPTS\other.py';bad['rows'][1]['before']['missing_suffix']=['SCRIPTS','other.py']
                elif mutation=='anchor':bad['rows'][1]['before']['ancestors'][-1]['file_id_hex']='f'*32
                else:bad['rows'][0]['before']['ancestors']=[]
                self.assertFalse(agrees(bad,body))

    def project_id_spans(self, context=None):
        positions=[(managed._WINDOWS_ROOT+'/'+name+'.json',('body','project_id'))
                   for name in ('root','owner','manifest')]
        positions.extend([(managed._WINDOWS_ROOT+'/receipts/'+self.tid+'.json',('body','project_id')),
                          (self.op+'/plan.json',('body','plan','project_id'))])
        selected=[]
        for path,coordinate in positions:
            text,spans,_=self.spans(path,context)
            selected.extend((path,json.loads(text[a:b])) for a,b in spans
                            if json.loads(text[a:b])==self.project_id)
        return selected

    def test_generated_project_labels_exact_five_roles_and_entropy_seed_independence(self):
        for label in ('WIN-b358f0c871260a44','WIN-0123456789abcdef','WIN-a9876543210fedcb',
                      'WIN-0000000000000000'):
            with self.subTest(label=label):
                self.project_id=label;self.fixture();context=self.context()
                selected=self.project_id_spans(context)
                self.assertEqual(len(selected),5)
                self.assertEqual({value for _,value in selected},{label})
                if label!='WIN-0000000000000000':
                    self.assertGreaterEqual(common.shannon_entropy(label),4.0)
                expected=context.constructor_coordinates[managed._WINDOWS_ROOT]
                self.assertEqual(sum(value==label for row in expected.values() for value in row.values()),5)
                text=json.dumps({'body':{'project_id':label},'schema':'foreign'})
                self.assertFalse(self.spans('data/authored-copy.json',text=text)[1])

    def test_generated_project_labels_do_not_admit_user_labels_or_other_coordinates(self):
        for label in ('user-chosen-label-0123456789','WIN-0123456789ABCDEf','WIN-0123456789abcdef0'):
            with self.subTest(label=label):
                self.project_id=label;self.fixture()
                self.assertFalse(self.project_id_spans())
        self.project_id='WIN-b358f0c871260a44'
        self.fixture(lambda p:p['private_file_policy'].update(project_id=self.project_id,
            password=self.project_id,token='sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'))
        self.assertEqual(len(self.project_id_spans()),5)
        text,spans,_=self.spans(self.op+'/plan.json')
        parser=managed._OffsetJSON(text,exact_control_coordinates={
            ('body','plan','private_file_policy','project_id'),
            ('body','plan','private_file_policy','password')});parser.parse()
        self.assertFalse(set(spans)&{(a,b) for a,b,value in parser.strings.values()})
        with patch.object(common,'_ScannerProofBudget',side_effect=lambda root:self.context(True)), \
             patch.object(managed,'__file__',self.kit+'\\scripts\\naos_secret_managed_operands.py'):
            report=common.check_secret_hygiene(root=self.root,profile='standard',naos_root='naos',
                rules={'scan_roots':[self.op+'/plan.json'],'include_root_files':False},rules_path=None,severity='blocking')
        self.assertGreater(report['summary']['regex_matches'],0)
        self.assertGreaterEqual(report['summary']['entropy_matches'],2)

    def test_generated_project_labels_require_whole_new_constructor_and_budgets(self):
        mutations=[lambda p:p.__setitem__('enrollment',False),
                   lambda p:p.__setitem__('expected_manifest_sha256','a'*64),
                   lambda p:p.__setitem__('expected_owner_sha256','b'*64),
                   lambda p:p['source_policy_observation'].__setitem__('path','custom\\policy.yaml')]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.fixture(mutation);self.assertFalse(self.project_id_spans())
                if self.plan['expected_manifest_sha256'] or self.plan['expected_owner_sha256']:
                    text,spans,_=self.spans()
                    self.assertTrue(self.path_values(text,spans))
        self.fixture(version=1);self.assertFalse(self.project_id_spans())
        self.fixture();context=self.context();self.project_id_spans(context)
        count=sum(len(row) for row in context.constructor_coordinates[managed._WINDOWS_ROOT].values())
        with patch.object(managed,'MAX_REPRESENTATIONS',count):self.assertEqual(len(self.project_id_spans()),5)
        with patch.object(managed,'MAX_REPRESENTATIONS',count-1):self.assertFalse(self.project_id_spans())
        path=managed._WINDOWS_ROOT+'/root.json';raw=(self.root/path).read_text()
        self.assertFalse(self.spans(path,text=raw+' ')[1])
        self.assertFalse(self.spans(path,text=raw.replace('"body":','"body":0,"body":',1))[1])
        bad=json.loads(raw);bad['body']['schema']='unknown';self.write_bytes(path,self.envelope(bad['body']))
        self.assertFalse(self.project_id_spans())
        self.fixture()
        owner_path=managed._WINDOWS_ROOT+'/owner.json'
        owner=json.loads((self.root/owner_path).read_bytes())['body']
        owner['root_enrollment_sha256']='f'*64
        self.write_bytes(owner_path,self.envelope(owner))
        self.assertFalse(self.project_id_spans())
        self.fixture();self.spans(context=context)
        blob=next(name for name in context.cache if '/base-blobs/' in name)
        self.write_bytes(blob,b'forged-preimage');self.assertFalse(self.project_id_spans())

    def test_generated_directory_operation_label_exact_role_and_optional_cap(self):
        self._carrier_fixture();path=self.op+'/directories.json';context=self.context()
        text,spans,diag=self.spans(path,context)
        self.assertGreater(common.shannon_entropy(self.operation),4.0)
        self.assertEqual([json.loads(text[a:b]) for a,b in spans],[self.operation])
        self.assertEqual(diag['status'],'proved')
        self.assertEqual(len(self.project_id_spans(context)),5)
        count=sum(len(row) for row in context.constructor_coordinates[managed._WINDOWS_ROOT].values())
        with patch.object(managed,'MAX_REPRESENTATIONS',count):
            self.assertEqual(len(self.spans(path)[1]),1)
        with patch.object(managed,'MAX_REPRESENTATIONS',count-1):
            capped=self.context()
            self.assertFalse(self.spans(path,capped)[1])
            self.assertEqual(len(self.project_id_spans(capped)),5)
            text,spans,_=self.spans(context=capped);self.assertTrue(self.path_values(text,spans))
        copied=json.dumps({'body':{'operation_id':self.operation}})
        self.assertFalse(self.spans('data/authored-directories.json',text=copied)[1])
        raw=(self.root/path).read_text()
        self.assertFalse(self.spans(path,text=raw+' ')[1])

    def test_generated_directory_operation_label_refusal_retains_prior_coordinates(self):
        for mutation in ('missing','schema','intent','operation','path','identity','credential','duplicate','preimage'):
            with self.subTest(mutation=mutation):
                self.fixture();self._carrier_fixture();path=self.op+'/directories.json'
                body=copy.deepcopy(self.carrier_directories)
                if mutation=='missing':(self.root/path).unlink()
                else:
                    if mutation=='schema':body['schema']='naos.upgrade.windows_runtime_directories.v2'
                    elif mutation=='intent':body['intent_sha256']='0'*64
                    elif mutation=='operation':body['operation_id']='WOP-abcdef0123456789'
                    elif mutation=='path':body['directories'][0]['path']='unplanned'
                    elif mutation=='identity':body['directories'][0]['identity']=body['directories'][0]['parent_identity']
                    elif mutation=='credential':body['provider']='sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'
                    raw=self.envelope(body)
                    if mutation=='duplicate':raw=raw.replace(b'"body":',b'"body":0,"body":',1)
                    elif mutation=='preimage':
                        parsed=json.loads(raw);parsed['body']['directories'][0]['path']='changed-without-rehash'
                        raw=json.dumps(parsed).encode()
                    self.write_bytes(path,raw)
                context=self.context()
                self.assertEqual(len(self.project_id_spans(context)),5)
                text,spans,_=self.spans(context=context);self.assertTrue(self.path_values(text,spans))
                if mutation!='missing':self.assertFalse(self.spans(path,context)[1])
                if mutation=='credential':
                    with patch.object(common,'_ScannerProofBudget',side_effect=lambda root:self.context(True)), \
                         patch.object(managed,'__file__',self.kit+'\\scripts\\naos_secret_managed_operands.py'):
                        report=common.check_secret_hygiene(root=self.root,profile='standard',naos_root='naos',
                            rules={'scan_roots':[path],'include_root_files':False},rules_path=None,severity='blocking')
                    self.assertGreater(report['summary']['regex_matches'],0)
                    self.assertGreater(report['summary']['entropy_matches'],0)
        for prior in ('expected_manifest_sha256','expected_owner_sha256'):
            with self.subTest(non_new_predecessor=prior):
                self.fixture(lambda p:p.__setitem__(prior,'a'*64));self._carrier_fixture()
                context=self.context()
                self.assertFalse(self.spans(self.op+'/directories.json',context)[1])
                self.assertFalse(self.project_id_spans(context))
                text,spans,_=self.spans(context=context)
                self.assertTrue(self.path_values(text,spans))
        self.fixture(version=1);self._carrier_fixture()
        self.assertFalse(self.spans(self.op+'/directories.json')[1])
        self.fixture(lambda p:p.__setitem__('enrollment',False));self._carrier_fixture()
        self.assertFalse(self.spans(self.op+'/directories.json')[1])

    def test_proved_high_entropy_windows_ancestor_names_have_exact_coordinates(self):
        self.logical=managed.PureWindowsPath('C:\\p02-a9-cb5d63-win-r33-r4-one311')
        self.fixture()
        context=self.context();text,spans,diag=self.spans(self.op+'/plan.json',context)
        self.assertEqual(diag['status'],'proved')
        coordinates=managed._windows_constructor_coordinates(context)[self.op+'/plan.json']
        for index in range(len(self.plan['rows'])):
            coordinate=('body','plan','rows',index,'before','ancestors',1,'name')
            self.assertEqual(coordinates[coordinate],self.logical.name)
        self.assertEqual(sum(json.loads(text[a:b])==self.logical.name for a,b in spans),len(self.plan['rows']))

    def test_windows_ancestor_name_copied_into_foreign_body_has_no_admission(self):
        self.logical=managed.PureWindowsPath('C:\\p02-a9-cb5d63-win-r33-r4-one311')
        self.fixture()
        text=json.dumps({'schema':'other','before':{'ancestors':[{'name':self.logical.name}]}})
        self.assertFalse(self.spans('data/copied.json',text=text)[1])

    def test_rehashed_windows_ancestor_name_volume_identity_and_shape_tampering_refuse(self):
        self.logical=managed.PureWindowsPath('C:\\p02-a9-cb5d63-win-r33-r4-one311')
        for mutation in ('name','volume','identity','shape'):
            with self.subTest(mutation=mutation):
                def alter(plan):
                    ancestor=plan['rows'][0]['before']['ancestors'][-1]
                    if mutation=='name':ancestor['name']='foreign-ancestor-abcdefgh012345'
                    elif mutation=='volume':ancestor['volume_serial_hex']='f'*16
                    elif mutation=='identity':ancestor['file_id_hex']='e'*32
                    else:ancestor['credential']='sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'
                self.fixture(alter)
                context=self.context();self.spans(self.op+'/plan.json',context)
                self.assertFalse(managed._windows_constructor_coordinates(context))

    def test_windows_ancestor_coordinates_do_not_admit_neighbor_credentials(self):
        self.logical=managed.PureWindowsPath('C:\\p02-a9-cb5d63-win-r33-r4-one311')
        credential='sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'
        self.fixture(lambda plan:plan['private_file_policy'].update(
            copied_ancestor=self.logical.name,api_key=credential))
        context=self.context();text,spans,diag=self.spans(self.op+'/plan.json',context)
        self.assertEqual(diag['status'],'proved')
        self.assertEqual(sum(json.loads(text[a:b])==self.logical.name for a,b in spans),
                         len(self.plan['rows']))
        parser=managed._OffsetJSON(text,exact_control_coordinates={
            ('body','plan','private_file_policy','copied_ancestor'),
            ('body','plan','private_file_policy','api_key')})
        parser.parse()
        self.assertFalse(set(spans)&{(a,b) for a,b,value in parser.strings.values()})
        with patch.object(common,'_ScannerProofBudget',side_effect=lambda root:self.context(True)), \
             patch.object(managed,'__file__',self.kit+'\\scripts\\naos_secret_managed_operands.py'):
            report=common.check_secret_hygiene(root=self.root,profile='standard',naos_root='naos',
                rules={'scan_roots':[self.op+'/plan.json'],'include_root_files':False},
                rules_path=None,severity='blocking')
        self.assertGreater(report['summary']['regex_matches'],0)
        self.assertGreater(report['summary']['entropy_matches'],0)
        doc=json.loads(text)
        doc['body']['credential']=credential
        doc['body']['copied_ancestor']=self.logical.name
        selected_text,selected,_=self.spans(self.op+'/plan.json',context,text=json.dumps(doc))
        values=[json.loads(selected_text[a:b]) for a,b in selected]
        self.assertNotIn(credential,values)
        # Altered report text is not the linked raw plan: refuse every coordinate.
        self.assertFalse(selected)

    def test_managed_proof_module_has_no_upgrade_contract_import(self):
        import ast
        tree=ast.parse(Path(managed.__file__).read_text(encoding='utf-8'))
        imports=[node.module or '' for node in ast.walk(tree) if isinstance(node,ast.ImportFrom)]
        imports.extend(alias.name for node in ast.walk(tree) if isinstance(node,ast.Import) for alias in node.names)
        self.assertFalse(any(name=='upgrade_contract' or name.startswith('upgrade_contract.') for name in imports))

    def test_carrier_missing_wrong_ordinal_direction_intent_and_extra_marker_refuse_only_augmentation(self):
        for mutation in ('missing','ordinal','direction','intent','extra'):
            with self.subTest(mutation=mutation):
                self._carrier_fixture();path=self.carrier_forward[0];file=self.root/path
                marker=json.loads(file.read_bytes())['body']
                if mutation=='missing':file.unlink()
                else:
                    if mutation=='ordinal':marker['topology']='step:0'
                    elif mutation=='direction':marker['direction']='rollback'
                    elif mutation=='intent':marker['intent_sha256']='0'*64
                    else:marker['provider']='sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'
                    self.write_bytes(path,self.envelope(marker))
                old=self.op+'/plan.json'
                text,spans,diag=self._carrier_spans([path,old])
                self.assertEqual([json.loads(text[a:b]) for a,b in sorted(spans)],[old]*4)
                self.assertEqual(diag['status'],'proved')

    def test_carrier_directory_witness_wrong_link_path_identity_extra_fields_refuse(self):
        for mutation in ('link','path','identity','extra'):
            with self.subTest(mutation=mutation):
                paths=self._carrier_fixture();body=copy.deepcopy(self.carrier_directories)
                if mutation=='link':body['intent_sha256']='0'*64
                elif mutation=='path':body['directories'][0]['path']='unplanned'
                elif mutation=='identity':body['directories'][0]['identity']=body['directories'][0]['parent_identity']
                else:body['unknown']='secret-neighbor'
                self.write_bytes(self.op+'/directories.json',self.envelope(body))
                text,spans,_=self._carrier_spans(sorted(paths-{self.op}))
                self.assertFalse(spans)

    def test_carrier_out_of_range_unknown_copy_and_raw_body_paths_get_no_spans(self):
        known=sorted(self._carrier_fixture())[0]
        unknown=[self.op+'/forward-000000.json',self.op+'/forward-'+format(len(self.intent['publications'])+1,'06d')+'.json',
                 self.op+'/private-abcdef012345.json',managed._WINDOWS_ROOT+'/unknown-template.file']
        text,spans,_=self._carrier_spans([known,*unknown],extra={'password':known,'provider':'sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456','unknown':known})
        self.assertEqual([json.loads(text[a:b]) for a,b in sorted(spans)],[known]*4)
        # The exact scalar copied into an ordinary JSON body has no allowance.
        ordinary=json.dumps({'schema':'other','project_root':str(self.root),'naos_root':'naos','path':known})
        self.assertFalse(self.spans('data/copied.json',text=ordinary)[1])

    def test_carrier_custom_policy_and_v1_have_no_optional_membership(self):
        for version in (1,2):
            with self.subTest(version=version):
                mutation=(lambda plan:plan['source_policy_observation'].update(path='private\\custom-policy.yaml')) if version==2 else None
                self.fixture(plan_mutation=mutation,version=version);self._carrier_fixture()
                text,spans,_=self._carrier_spans([self.carrier_forward[0],self.op+'/plan.json'])
                self.assertEqual([json.loads(text[a:b]) for a,b in sorted(spans)],[self.op+'/plan.json']*4)

    def test_carrier_optional_refusal_does_not_erase_old_operands(self):
        self._carrier_fixture()
        with patch.object(managed,'_windows_constructor_coordinates',return_value={}):
            text,spans,_=self._carrier_spans([self.carrier_forward[0],self.op+'/plan.json'])
        self.assertEqual([json.loads(text[a:b]) for a,b in sorted(spans)],[self.op+'/plan.json']*4)

    def test_carrier_multi_receipt_is_not_a_supported_optional_constructor(self):
        self._carrier_fixture();context=self.context()
        original=context.object
        def objects(path):
            value=original(path)
            if path==managed._WINDOWS_ROOT+'/manifest.json':
                value=copy.deepcopy(value)
                value['body']['receipts'].append(copy.deepcopy(value['body']['receipts'][0]))
            return value
        with patch.object(managed,'_windows_constructor_coordinates',return_value={'complete':{}}),patch.object(context,'object',side_effect=objects):
            self.assertFalse(managed._windows_new_enrollment_carrier_operands(context))

    def test_carrier_runtime_lock_role_invalid_identity_refuses_optional_only(self):
        for mutation in ('shape','volume'):
            with self.subTest(mutation=mutation):
                self.fixture();self._carrier_fixture()
                if mutation=='shape':self.intent['lock_id']={'file_id_hex':'0'*32}
                else:self.intent['scope_lock_id']={**self.identity,'volume_serial_hex':'f'*16}
                self.persist_operation();self._carrier_fixture()
                text,spans,_=self._carrier_spans([self.op+'/lock',self.op+'/plan.json'])
                self.assertEqual([json.loads(text[a:b]) for a,b in sorted(spans)],[self.op+'/plan.json']*4)

    def test_carrier_optional_read_budget_refusal_preserves_old_membership(self):
        self._carrier_fixture();context=self.context();original=context.read
        def read(path):
            if '/forward-' in path:raise managed.OperandRefusal('proof_budget')
            return original(path)
        with patch.object(context,'read',side_effect=read):
            text,spans,_=self._carrier_spans([self.carrier_forward[0],self.op+'/plan.json'],context)
        self.assertEqual([json.loads(text[a:b]) for a,b in sorted(spans)],[self.op+'/plan.json']*4)

    def test_carrier_combined_old_and_optional_inventory_cap_preserves_old_on_overflow(self):
        self._carrier_fixture();context=self.context()
        context.operands[managed._WINDOWS_ROOT]=managed._windows_operands(context)
        with patch.object(managed,'__file__',self.kit+'\\scripts\\naos_secret_managed_operands.py'):
            extra=managed._windows_new_enrollment_carrier_operands(context)
        self.assertTrue(extra)
        old=context.operands[managed._WINDOWS_ROOT]
        count=managed.MAX_IDENTITIES-len(old|extra)
        for overflow in (0,1):
            with self.subTest(overflow=overflow):
                bounded=self.context()
                managed._windows_operands(bounded)  # Populate the genuine saved-evidence cache first.
                prior=old|{managed._WINDOWS_ROOT+'/fixture-old-'+str(i) for i in range(count+overflow)}
                self.assertLessEqual(len(prior),managed.MAX_IDENTITIES)
                bounded.operands[managed._WINDOWS_ROOT]=set(prior)
                with patch.object(managed,'__file__',self.kit+'\\scripts\\naos_secret_managed_operands.py'):
                    augmentation=managed._windows_new_enrollment_carrier_operands(bounded)
                self.assertEqual(bool(augmentation),not overflow)
                self.assertEqual(bounded.operands[managed._WINDOWS_ROOT],prior)
                if not overflow:self.assertEqual(len(prior|augmentation),managed.MAX_IDENTITIES)

    def test_carrier_augmentation_is_cached_once_in_existing_budget(self):
        paths=sorted(self._carrier_fixture());context=self.context()
        with patch.object(managed,'_windows_constructor_coordinates',wraps=managed._windows_constructor_coordinates) as constructor:
            first=self._carrier_spans(paths,context);charged=context.bytes_read
            second=self._carrier_spans(paths,context)
            self.assertEqual(first[1],second[1]);self.assertEqual(context.bytes_read,charged)
            self.assertEqual(constructor.call_count,1)
        self.assertLess(context.bytes_read,managed.MAX_PROOF_BYTES)

    def test_carrier_augmentation_cache_terminal_checkpoint_remains_sticky(self):
        paths=sorted(self._carrier_fixture());context=self.context(batch=True)
        self._carrier_spans(paths,context)
        path=self.root/self.carrier_forward[0];path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaises(managed.OperandRefusal):context.finish_scanner_batch()
        path.write_bytes(self.envelope({'schema':'naos.upgrade.windows_operation.v2','failure_model':'application_crash_v1',
            'intent_sha256':hashlib.sha256(self.envelope(self.intent)).hexdigest(),'direction':'forward','topology':'step:1'}))
        with self.assertRaises(managed.OperandRefusal):context.finish_scanner_batch()

    def test_coherent_all_raw_controls_and_optional_cache_once(self):
        context=self.context()
        with patch.object(managed,'_windows_enrollment_coordinates',wraps=managed._windows_enrollment_coordinates) as builder:
            text,spans,diag=self.spans(context=context)
            self.assertEqual(diag['status'],'proved')
            self.assertEqual(set(self.path_values(text,spans)),set(self.intent['slot_paths'].values()))
            for path in [managed._WINDOWS_ROOT+'/manifest.json',self.op+'/plan.json',
                         managed._WINDOWS_ROOT+'/receipts/'+self.tid+'.json']:
                value,selected,_=self.spans(path,context)
                self.assertTrue(self.path_values(value,selected))
            base=next(path.replace('\\','/') for path in self.files if '\\bases\\' in path)
            value,selected,_=self.spans(base,context);self.assertEqual(len(self.path_values(value,selected)),1)
            self.assertEqual(builder.call_count,1)

    def test_rehashed_constructor_attacks_preserve_ids(self):
        attacks=[lambda d:d['slot_paths'].__setitem__('target-0','C:\\wrong-root\\arbitrary.py'),
            lambda d:d['slot_paths'].__setitem__('staged-0',d['slot_paths']['staged-0'].replace('content-000000','content-000001')),
            lambda d:d['slot_paths'].__setitem__('staged-0',d['slot_paths']['staged-0'].replace('staging','other')),
            lambda d:d['slot_paths'].__setitem__('arbitrary-key',d['slot_paths']['target-0']),
            lambda d:d['publications'].reverse(),
            lambda d:d['publications'][0].__setitem__('target','target-1'),
            lambda d:d['publications'][0]['after'].__setitem__('content_sha256','f'*64),
            lambda d:d['publications'][0].__setitem__('backup','backup-0')]
        original=copy.deepcopy(self.intent)
        for attack in attacks:
            with self.subTest(attack=attack):
                self.intent=copy.deepcopy(original);attack(self.intent);self.persist_operation()
                text,spans,diag=self.spans();self.assertEqual(diag['status'],'proved')
                self.assertEqual([json.loads(text[a:b]) for a,b in spans],[self.operation])
        self.intent=original;self.persist_operation()

    def test_unsupported_variants_and_custom_policy_keep_identifiers(self):
        for mutation,version in [(lambda p:p.__setitem__('enrollment',False),2),
            (lambda p:p['rows'][0].__setitem__('action','UPDATE_FROM_UPSTREAM'),2),
            (lambda p:p['source_policy_observation'].__setitem__('path','custom\\policy.yaml'),2),
            (lambda p:p['rows'].reverse(),2),
            (lambda p:p['rows'][0]['before']['ancestors'][-1].__setitem__('file_id_hex','e'*32),2),
            (None,1)]:
            self.fixture(mutation,version)
            text,spans,diag=self.spans();self.assertEqual(diag['status'],'proved')
            self.assertEqual([json.loads(text[a:b]) for a,b in spans],[self.operation])

    def test_unsupported_genuine_two_receipt_history_retains_ids(self):
        snapshot=self.wp.load_windows_provenance(self.Reader(self.files),root_identity=self.identity,source_policy_raw=self.policy)
        second=copy.deepcopy(self.plan);second.pop('digest_sha256')
        second.update(transaction_id='WMC-abcdef0123456789',operation_id='WOP-abcdef0123456789',enrollment=False)
        second['digest_sha256']=canonical_sha256(second)
        changes={row['path']:{'content':{key:row['intended'][key] for key in ('kind','size_decimal','sha256','metadata_sha256')},
            'archive_bytes':self.contents[row['path']]} for row in second['rows']}
        records=self.wp.make_commit_records(snapshot,transaction_id=second['transaction_id'],plan_sha256=second['digest_sha256'],
            changes=changes,source_policy_raw=self.policy,request=self.request)
        for path,raw in records.items():self.write_bytes(path.replace('\\','/'),raw)
        record={'schema':self.record['schema'],'operation_id':second['operation_id'],'plan':second,'plan_sha256':canonical_sha256(second)}
        intent=copy.deepcopy(self.intent);intent.update(operation_id=second['operation_id'],plan_sha256=canonical_sha256(second),slot_paths={},publications=[])
        op=managed._WINDOWS_ROOT+'/transactions/'+second['operation_id']
        raw=self.envelope(intent)
        self.write_bytes(op+'/plan.json',self.envelope(record));self.write_bytes(op+'/intent.json',raw)
        self.write_bytes(op+'/committed.json',self.envelope({'schema':intent['schema'],'failure_model':'application_crash_v1',
            'intent_sha256':hashlib.sha256(raw).hexdigest(),'direction':'forward','topology':'committed'}))
        text,spans,diag=self.spans()
        self.assertEqual(diag['status'],'proved');self.assertEqual([json.loads(text[a:b]) for a,b in spans],[self.operation])

    def test_exact_parser_unicode_escape_crlf_and_batch_parity(self):
        coordinate=('body','slot_paths','staged-0')
        text=json.dumps({'body':{'slot_paths':{'staged-0':'C:\\unicode-\u00e9\\stage.bin'},'unknown':'C:\\unicode-\u00e9\\stage.bin'}},ensure_ascii=True,indent=2).replace('\n','\r\n')
        parser=managed._OffsetJSON(text,exact_control_coordinates={coordinate});parser.parse()
        self.assertEqual(set(parser.strings),{coordinate})
        a,b,value=parser.strings[coordinate];self.assertEqual(json.loads(text[a:b]),value)
        eager=self.spans()[1];batch=self.context(True);provisional=self.spans(context=batch)[1]
        self.assertEqual(eager,provisional);batch.finish_scanner_batch()

    def test_body_provider_assignment_and_offsets(self):
        # Existing plan permits declaration body data; keep its hash chain genuine.
        self.fixture(lambda p:p['private_file_policy'].update(password=str(self.logical)+'\\scripts\\fixture-012345abcdef.py',
            token='sk-'+'aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'))
        raw=(self.root/(self.op+'/plan.json')).read_text()
        text,spans,_=self.spans(self.op+'/plan.json')
        unknown=self.plan['private_file_policy']['password'];self.assertNotIn(unknown,[json.loads(text[a:b]) for a,b in spans])
        with patch.object(common,'_ScannerProofBudget',side_effect=lambda root:self.context(True)), \
             patch.object(managed,'__file__',self.kit+'\\scripts\\naos_secret_managed_operands.py'):
            report=common.check_secret_hygiene(root=self.root,profile='standard',naos_root='naos',
                rules={'scan_roots':[self.op+'/plan.json'],'include_root_files':False},rules_path=None,severity='blocking')
        self.assertGreater(report['summary']['inventory_operand_matches'],0)
        self.assertGreater(report['summary']['regex_matches'],0);self.assertGreater(report['summary']['entropy_matches'],0)
        # Guarded original bytes support raw Unicode escapes and CRLF.
        parsed=json.loads(raw);escaped=json.dumps(parsed,ensure_ascii=True,indent=2).replace('\n','\r\n')
        # Controls require exact raw identity; reserialization is refused.
        self.assertFalse(self.spans(self.op+'/plan.json',text=escaped)[1])

    def test_caps_json_and_terminal_custody(self):
        with patch.object(managed,'MAX_REPRESENTATIONS',2):
            text,spans,_=self.spans();self.assertEqual([json.loads(text[a:b]) for a,b in spans],[self.operation])
        with patch.object(managed,'MAX_METADATA_NODES',2):self.assertFalse(self.spans()[1])
        with patch.object(managed,'MAX_PROOF_BYTES',1):self.assertFalse(self.spans()[1])
        raw=(self.root/(self.op+'/intent.json')).read_text()
        self.assertFalse(self.spans(text=raw[:-1])[1])
        self.assertFalse(self.spans(text=raw.replace('"body":','"body":0,"body":',1))[1])
        context=self.context(True);self.assertTrue(self.spans(context=context)[1])
        blob=next(name for name in context.cache if '/base-blobs/' in name)
        self.write_bytes(blob,b'changed')
        with self.assertRaises(managed.OperandRefusal):context.finish_scanner_batch()
        eager=self.context();self.assertFalse(self.spans(context=eager)[1])

    def test_exact_coordinate_membership_does_not_expand_wildcard_work(self):
        with patch.object(managed,'_control_coordinate',wraps=managed._control_coordinate) as matcher:
            text,spans,_=self.spans()
        self.assertTrue(spans)
        # Every wildcard comparison receives only preexisting finite ID slots.
        self.assertTrue(all(len(call.args[1])<=3 for call in matcher.call_args_list))

    def test_windows_component_boundaries_refuse_unsafe_constructor_operands(self):
        for value in ('NUL.txt', 'nul.TXT', 'COM\u00b2', 'C:\\outside', '\\\\server\\share',
                      '\\rooted', 'docs/file', 'docs\\..\\file', 'docs\\file:stream',
                      'docs\\trailing.', 'docs\\trailing ', 'docs\\a\x00b',
                      'docs\\' + 'a' * 256, 'docs\\' + '\U0001f600' * 128):
            with self.subTest(value=value):
                with self.assertRaises(managed.OperandRefusal):
                    managed._windows_relative_path(value)
        for value in ('docs\\r\u00e9sum\u00e9.md', 'docs\\' + 'a' * 255, 'COM10.txt'):
            self.assertEqual(managed._windows_relative_path(value), tuple(value.split('\\')))


if __name__=='__main__':unittest.main()
