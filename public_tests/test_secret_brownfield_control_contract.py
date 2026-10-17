"""Linked saved control labels; fixtures make no native ownership/runtime claim."""
import copy
import hashlib
import json
import os
import shutil
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

KIT = Path(os.environ.get('NAOS_TEST_KIT', Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(KIT/'scripts'))
sys.path.insert(0, str(KIT/'public_tests'))
import naos_secret_managed_operands as managed
import naos_hygiene_common as common
import test_secret_managed_inventory_contract as inventory_tests
from upgrade_contract.provenance import _managed_content_scope_object
from upgrade_contract.transaction import _with_sha256_integrity


class BrownfieldControlTests(unittest.TestCase):
    def setUp(self):
        fixture = inventory_tests.ManagedInventoryTests()
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        self.fixture = fixture; self.root = fixture.root
        docs = json.loads((KIT/'public_tests/fixtures/ri_public_controls.json').read_text())
        self.owner = docs['.naos/upgrade-v1/OWNER.json']
        self.scope = docs[managed._RI_SCOPE]
        self.active = docs[managed._RI_ROOT+'/active.json']
        self.manifest = next(v for k,v in docs.items() if k.endswith('/manifest.json'))
        self.validation = next(v for k,v in docs.items() if k.endswith('/validation_receipt.json'))
        self.inventory = next(v for k,v in docs.items() if k.endswith('/inventory.json'))
        self.activation = next(v for k,v in docs.items() if k.endswith('/receipt.json'))
        self.journal = next(v for k,v in docs.items() if k.endswith('/journal.json'))
        self.write('.naos/upgrade-v1/OWNER.json', self.owner)
        project = self.owner['project_id']
        scope = _managed_content_scope_object(project_id=project, owner_integrity=self.owner['integrity']['value'],
            authorization_digest='2'*64, source_policy_sha256='3'*64)
        fixture.write(fixture.relative+'/scope.json',scope)
        for value,path in [(fixture.receipt,fixture.operands[1]),(fixture.manifest,fixture.relative+'/state/manifest.json')]:
            value.pop('integrity'); value.update(project_id=project,scope_integrity_sha3_512=scope['integrity']['value'])
            if value is fixture.manifest:
                value['transactions'][0]['receipt_sha256'] = managed.canonical_sha256(fixture.receipt)
                value['entries'][0]['receipt_sha256'] = managed.canonical_sha256(fixture.receipt)
            value.update(_with_sha256_integrity(value));fixture.write(path,value)
        for row in self.inventory['artifacts']:
            path=row['path'];dest=self.root/path;dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes((KIT/'public_tests/fixtures/ri_public_sources'/path).read_bytes())
        self.rebuild_ri()

    def write(self,path,value):
        dest=self.root/path;dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes(managed.canonical_bytes(value) if type(value) is dict else value)
        return dest

    def rebuild_ri(self, *, high_entropy_generation=False):
        previous_generation = getattr(self, 'generation', None)
        control=self.manifest['control'];control['project_root']=str(self.root)
        control['rules'].update(sha256=hashlib.sha256(b'bounded rules fixture').hexdigest(),path='fixture-rules.yaml')
        identity={key:control[key] for key in ('project_root','profile','purpose','component_mode','effective_source_sha256','rules','runtime','implementation','provenance_gate','components','graph_model_sha256','ongoing_use_scope')}
        identity['capability_id']='CAP-LOCAL-CONTEXT-INDEX'
        if high_entropy_generation:
            # A real producer identity field varies; no digest, proof or entropy
            # check is mocked. The temporary project root still enters the hash.
            for attempt in range(1024):
                control['ongoing_use_scope'] = ['bounded-fixture-' + str(attempt)]
                identity['ongoing_use_scope'] = control['ongoing_use_scope']
                digest = managed.canonical_sha256(identity)
                if common.shannon_entropy('RI-' + digest[:24]) > 4.0:
                    break
            else:
                self.fail('bounded genuine generation search found no high-entropy label')
        digest=managed.canonical_sha256(identity);label='RI-'+digest[:24]
        generation=managed._RI_ROOT+'/generations/'+label
        transaction=managed._RI_TRANSACTIONS+'/'+self.active['control']['transaction_id']
        if previous_generation is not None and previous_generation != generation:
            shutil.rmtree(self.root/previous_generation)
        self.generation=generation;self.transaction=transaction
        for value in (control,self.validation['control'],self.active['control'],self.activation['control'],self.journal):
            value.update(generation_id=label,generation_content_sha256=digest)
        self.validation['control'].update(runtime=copy.deepcopy(control['runtime']))
        self.inventory.update(project_root=str(self.root),generation_id=label)
        self.validation['receipt_sha256']=managed.canonical_sha256(self.validation['control'])
        control['validation_receipt_sha256']=self.validation['receipt_sha256']
        contents={'inventory.json':managed.canonical_bytes(self.inventory),
            'validation_receipt.json':managed.canonical_bytes(self.validation),
            'repository_intelligence_rules.yaml':b'bounded rules fixture',
            'local_context_index.sqlite':b'saved opaque fixture, no SQLite runtime assurance'}
        control['files']=[dict(path=k,sha256=hashlib.sha256(v).hexdigest(),size_bytes=len(v)) for k,v in sorted(contents.items())]
        self.manifest['manifest_sha256']=managed.canonical_sha256(control)
        contents['manifest.json']=managed.canonical_bytes(self.manifest)
        for key in ('manifest','validation_receipt'):
            raw=contents[key+'.json']; field=key+'_sha256'
            sha=self.manifest['manifest_sha256'] if key=='manifest' else self.validation['receipt_sha256']
            for value in (self.active['control'],self.activation['control']):
                value.update({key+'_file_sha256':hashlib.sha256(raw).hexdigest(),field:sha})
        self.activation['receipt_sha256']=managed.canonical_sha256(self.activation['control'])
        active=self.active['control'];active.update(manifest_path=generation+'/manifest.json',
            validation_receipt_path=generation+'/validation_receipt.json',activation_receipt_path=transaction+'/receipt.json',
            activation_receipt_sha256=self.activation['receipt_sha256'],activation_receipt_file_sha256=hashlib.sha256(managed.canonical_bytes(self.activation)).hexdigest())
        self.active['active_sha256']=managed.canonical_sha256(active)
        self.journal.update(active_path=managed._RI_ROOT+'/active.json',active_pending_path=managed._RI_ROOT+'/.active.json.pending',
            final_path=generation,staging_path=transaction+'/staging',context_staging_path=transaction+'/context',
            proposed_active_sha256=self.active['active_sha256'],proposed_active_file_sha256=hashlib.sha256(managed.canonical_bytes(self.active)).hexdigest(),
            staging_files=[dict(path=k,sha256=hashlib.sha256(v).hexdigest(),size_bytes=len(v)) for k,v in sorted(contents.items())])
        self.journal['journal_sha256']=managed.canonical_sha256({k:v for k,v in self.journal.items() if k!='journal_sha256'})
        for path,value in [(managed._RI_SCOPE,self.scope),(managed._RI_ROOT+'/active.json',self.active),
                (transaction+'/receipt.json',self.activation),(transaction+'/journal.json',self.journal)]: self.write(path,value)
        for name,raw in contents.items(): self.write(generation+'/'+name,raw)

    def spans(self,path,text=None,context=None):
        text=(self.root/path).read_text() if text is None else text
        spans,diag=managed.inventory_operand_spans(text,path,self.root,'naos',context or managed.ProofBudget(self.root))
        return text,spans,diag

    def directory_report(self, value=None, status='directory'):
        value = managed._RI_ROOT+'/generations' if value is None else value
        return {'schema':'naos.secret_hygiene.v1','project_root':str(self.root),'naos_root':'naos',
                'scans':{'scope_inventory':[{'path':value,'status':status}]},
                'unknown':value,'findings':[{'path':value}]}

    def bind_current_ri_plan(self, *, change=None, change_plan=None):
        # Reuse genuine saved RI/MC constructor fixtures, then seal the new
        # committed MC plan/journal/receipt/manifest with their real hash helpers.
        label = 'RIT-0453d87a2bc1b8d6b6cec21d'
        for value in (self.active['control'], self.activation['control'], self.journal):
            value['transaction_id'] = label
        self.rebuild_ri()
        generation = {field: self.active['control'][field]
                      for field in managed._RI_GENERATION_BINDING_FIELDS}
        inputs = {'lifecycle_status': 'validated_current',
                  'recommendation': 'use_validated_current_generation',
                  'binding': {'binding_type': 'validated_generation', 'generation': generation}}
        if change is not None:
            change(inputs)
        fixture = self.fixture
        plan = copy.deepcopy(fixture.manifest['transactions'][0]['plan'])
        plan.pop('plan_sha256')
        plan['inputs']['repository_intelligence'] = inputs
        if change_plan is not None:
            change_plan(plan)
        plan['plan_sha256'] = managed.canonical_sha256(plan)
        transaction = 'MC-' + plan['plan_sha256'][:16] + '-01234567'
        receipt = copy.deepcopy(fixture.receipt)
        receipt.pop('integrity')
        receipt.update(transaction_id=transaction, plan_sha256=plan['plan_sha256'])
        receipt = _with_sha256_integrity(receipt)
        receipt_sha = managed.canonical_sha256(receipt)
        journal = copy.deepcopy(fixture.journal)
        journal.pop('integrity')
        journal.update(transaction_id=transaction, plan=plan)
        journal = _with_sha256_integrity(journal)
        manifest = copy.deepcopy(fixture.manifest)
        manifest.pop('integrity')
        manifest.update(last_transaction_id=transaction, last_plan_sha256=plan['plan_sha256'],
                        transactions=[{'transaction_id': transaction, 'plan': plan,
                                       'receipt_sha256': receipt_sha}])
        for entry in manifest['entries']:
            entry.update(introduced_by_transaction=transaction, receipt_sha256=receipt_sha)
        manifest = _with_sha256_integrity(manifest)
        self.write(fixture.relative + '/state/receipts/' + transaction + '.json', receipt)
        self.mc_journal = fixture.relative + '/transactions/' + transaction + '/journal.json'
        self.write(self.mc_journal, journal)
        self.write(fixture.relative + '/state/manifest.json', manifest)
        self.mc_id = transaction
        return label

    def rit_values(self, path, *, context=None, text=None):
        text, spans, diagnostic = self.spans(path, context=context, text=text)
        return {json.loads(text[a:b]) for a,b in spans}, diagnostic


    def test_current_ri_generation_exact_six_control_coordinates(self):
        self.rebuild_ri(high_entropy_generation=True)
        label = self.active['control']['generation_id']
        self.assertGreater(common.shannon_entropy(label), 4.0)
        self.assertEqual(label, 'RI-' + managed.canonical_sha256({
            **{key: self.manifest['control'][key] for key in
               ('project_root','profile','purpose','component_mode','effective_source_sha256',
                'rules','runtime','implementation','provenance_gate','components',
                'graph_model_sha256','ongoing_use_scope')},
            'capability_id': 'CAP-LOCAL-CONTEXT-INDEX'})[:24])
        paths = [managed._RI_ROOT + '/active.json', self.generation + '/inventory.json',
                 self.generation + '/manifest.json', self.generation + '/validation_receipt.json',
                 self.transaction + '/journal.json', self.transaction + '/receipt.json']
        for path in paths:
            with self.subTest(path=path):
                values, diagnostic = self.rit_values(path)
                self.assertIn(label, values, diagnostic)
        result = common.check_secret_hygiene(root=self.root, profile='standard', naos_root='naos',
            rules={'scan_roots':paths,'include_root_files':False},rules_path=None,severity='required')
        self.assertEqual(result['summary']['entropy_matches'],0,result['findings'])
        self.assertEqual(result['summary']['regex_matches'],0,result['findings'])

    def test_current_ri_generation_exact_complete_consumer_echo(self):
        self.rebuild_ri(high_entropy_generation=True)
        transaction = self.bind_current_ri_plan()
        generation = self.active['control']['generation_id']
        paths = [self.fixture.relative + '/state/manifest.json', self.mc_journal]
        for path in paths:
            with self.subTest(path=path):
                text, spans, diagnostic = self.spans(path)
                coordinate = ('plan','inputs','repository_intelligence','binding','generation','generation_id')
                if path.endswith('/state/manifest.json'):
                    coordinate = ('transactions',0,*coordinate)
                parser = managed._OffsetJSON(text,exact_control_coordinates=[coordinate]); parser.parse()
                start, end, value = parser.strings[coordinate]
                self.assertEqual(value, generation)
                self.assertIn((start,end), spans, diagnostic)
                self.assertIn(transaction,{json.loads(text[a:b]) for a,b in spans},diagnostic)
        result = common.check_secret_hygiene(root=self.root, profile='lite', naos_root='naos',
            rules={'scan_roots':paths,'include_root_files':False},rules_path=None,severity='required')
        self.assertEqual(result['summary']['entropy_matches'],0,result['findings'])

    def test_current_ri_generation_authored_predecessor_and_credentials_stay_strict(self):
        self.rebuild_ri(high_entropy_generation=True)
        label = self.active['control']['generation_id']
        # Equal, shape-valid predecessor claims do not prove a saved predecessor.
        self.active['control']['previous_generation_id'] = label
        self.activation['control']['previous_generation_id'] = label
        self.journal['last_error'] = label
        self.rebuild_ri()
        paths = [managed._RI_ROOT + '/active.json', self.transaction + '/receipt.json',
                 self.transaction + '/journal.json']
        for path in paths:
            text, spans, diagnostic = self.spans(path)
            coordinate = ('last_error',) if path.endswith('/journal.json') else ('control','previous_generation_id')
            parser = managed._OffsetJSON(text,exact_control_coordinates=[coordinate]); parser.parse()
            start,end,value = parser.strings[coordinate]
            self.assertEqual(value,label)
            self.assertNotIn((start,end),spans,diagnostic)
        self.write('authored.json', {'generation_id':label,'password':label,
                                    'provider':'sk-'+'aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'})
        self.assertFalse(self.spans('authored.json')[1])
        paths.append('authored.json')
        result = common.check_secret_hygiene(root=self.root, profile='standard', naos_root='naos',
            rules={'scan_roots':paths,'include_root_files':False},rules_path=None,severity='required')
        self.assertGreaterEqual(result['summary']['entropy_matches'],4,result['findings'])
        self.assertGreater(result['summary']['regex_matches'],0,result['findings'])
        active = managed._RI_ROOT + '/active.json'
        raw = (self.root/active).read_text()
        self.assertFalse(self.spans(active,text=raw+' ')[1])
        for field,value in [('generation_id','RI-'+'0'*24),('generation_id','RI-malformed')]:
            changed = copy.deepcopy(self.active); changed['control'][field]=value
            changed['active_sha256']=managed.canonical_sha256(changed['control'])
            self.write(active,changed)
            self.assertFalse(self.spans(active)[1])
            self.write(active,self.active)
        with patch.object(managed,'MAX_DOCUMENT_BYTES',64):
            self.assertFalse(self.spans(active)[1])
        with patch.object(managed,'MAX_PROOF_BYTES',64):
            self.assertFalse(self.spans(active)[1])
        with patch.object(managed,'MAX_METADATA_NODES',1):
            self.assertFalse(self.spans(active)[1])

    def test_unrelated_mc_plan_does_not_request_optional_ri_proof(self):
        with patch.object(managed, '_ri_constructor_coordinates',
                          side_effect=AssertionError('unrelated plan must not read RI')):
            values, diagnostic = self.rit_values(self.fixture.relative + '/state/manifest.json')
            self.assertIn(self.fixture.tid, values, diagnostic)

    def test_nonmapping_committed_plan_inputs_preserve_mc_without_ri_reads(self):
        for shape in (None, [], ['opaque'], 'opaque'):
            with self.subTest(shape=shape):
                self.bind_current_ri_plan(change_plan=lambda plan, value=shape:
                    plan.__setitem__('inputs', value))
                # All MC integrity links are rederived by the real fixture helper.
                # This mock only rejects an unwanted optional read, never proves one.
                with patch.object(managed, '_ri_constructor_coordinates',
                                  side_effect=AssertionError('nonmapping inputs must not read RI')):
                    for path in (self.fixture.relative + '/state/manifest.json', self.mc_journal):
                        values, diagnostic = self.rit_values(path)
                        self.assertIn(self.mc_id, values, diagnostic)
                        self.assertEqual(diagnostic['status'], 'proved')

    def test_current_ri_transaction_exact_five_control_coordinates(self):
        label = self.bind_current_ri_plan()
        self.assertGreater(common.shannon_entropy(label), 4.0)
        paths = [managed._RI_ROOT + '/active.json', self.transaction + '/journal.json',
                 self.transaction + '/receipt.json', self.fixture.relative + '/state/manifest.json',
                 self.mc_journal]
        for path in paths:
            with self.subTest(path=path):
                values, diagnostic = self.rit_values(path)
                self.assertIn(label, values, diagnostic)
        result = common.check_secret_hygiene(root=self.root, profile='lite', naos_root='naos',
            rules={'scan_roots': paths, 'include_root_files': False}, rules_path=None, severity='required')
        self.assertEqual(result['summary']['entropy_matches'], 0, result['findings'])
        self.assertEqual(result['summary']['regex_matches'], 0, result['findings'])

    def test_ri_labels_unknown_sibling_and_secret_adjacency_are_not_public(self):
        label = self.bind_current_ri_plan()
        mirror = 'input.json'
        self.write(mirror, {'transaction_id': label, 'unknown': {'transaction_id': label},
                            'password': label, 'provider': 'sk-'+'aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'})
        self.assertFalse(self.spans(mirror)[1])
        result = common.check_secret_hygiene(root=self.root, profile='standard', naos_root='naos',
            rules={'scan_roots': [mirror], 'include_root_files': False}, rules_path=None, severity='required')
        self.assertGreater(result['summary']['entropy_matches'], 0)
        self.assertGreater(result['summary']['regex_matches'], 0)
        active = self.root / managed._RI_ROOT / 'active.json'
        raw = active.read_text()
        self.assertFalse(self.spans(managed._RI_ROOT + '/active.json', text=raw+' ')[1])
        changed = json.loads(raw); changed['unknown'] = {'transaction_id': label}
        self.write(managed._RI_ROOT + '/active.json', changed)
        self.assertFalse(self.spans(managed._RI_ROOT + '/active.json')[1])

    def test_ri_binding_all_fields_and_typed_state_refuse_without_erasing_mc(self):
        self.rebuild_ri(high_entropy_generation=True)
        for field in managed._RI_GENERATION_BINDING_FIELDS:
            with self.subTest(field=field):
                label = self.bind_current_ri_plan(change=lambda inputs, f=field:
                    inputs['binding']['generation'].__setitem__(f, 'different'))
                values, diagnostic = self.rit_values(self.mc_journal)
                self.assertNotIn(label, values, diagnostic)
                self.assertNotIn(self.active['control']['generation_id'], values, diagnostic)
                self.assertIn(self.mc_id, values, diagnostic)
        for change in [lambda i: i.__setitem__('lifecycle_status', 'unknown'),
                       lambda i: i['binding'].__setitem__('binding_type', 'unknown'),
                       lambda i: i['binding']['generation'].__setitem__('extra', 'credential')]:
            label = self.bind_current_ri_plan(change=change)
            values, diagnostic = self.rit_values(self.mc_journal)
            self.assertNotIn(label, values, diagnostic)
            self.assertNotIn(self.active['control']['generation_id'], values, diagnostic)
            self.assertIn(self.mc_id, values, diagnostic)

    def test_optional_ri_missing_or_bad_provenance_preserves_mc_proof(self):
        label = self.bind_current_ri_plan()
        active = self.root / managed._RI_ROOT / 'active.json'
        raw = active.read_bytes()
        active.unlink()
        values, diagnostic = self.rit_values(self.mc_journal)
        self.assertNotIn(label, values, diagnostic)
        self.assertIn(self.mc_id, values, diagnostic)
        active.write_bytes(raw)
        invalid = json.loads(raw); invalid['control']['provenance_project_id'] = 'foreign'
        self.write(managed._RI_ROOT + '/active.json', invalid)
        values, diagnostic = self.rit_values(self.mc_journal)
        self.assertNotIn(label, values, diagnostic)
        self.assertIn(self.mc_id, values, diagnostic)

    def test_ri_id_malformed_bounded_and_final_custody_refusals(self):
        label = self.bind_current_ri_plan()
        path = managed._RI_ROOT + '/active.json'
        for text in ['{"control":', '{"control":{},"control":{}}']:
            self.assertFalse(self.spans(path, text=text)[1])
        with patch.object(managed, 'MAX_DOCUMENT_BYTES', 64):
            self.assertFalse(self.spans(path)[1])
        with patch.object(managed, 'MAX_METADATA_NODES', 1):
            self.assertFalse(self.spans(path)[1])
        context = managed._ScannerProofBudget(self.root)
        values, diagnostic = self.rit_values(self.mc_journal, context=context)
        self.assertIn(label, values, diagnostic)
        active = self.root / path
        active.write_bytes(active.read_bytes() + b' ')
        with self.assertRaises(managed.OperandRefusal):
            context.finish_scanner_batch()

    def test_directory_inventory_proved_parent_exact_slot_and_repeated_scan(self):
        self.rebuild_ri(high_entropy_generation=True)
        directory = managed._RI_ROOT+'/generations'
        self.assertGreater(common.shannon_entropy(directory), 4.0)
        report='naos/reports/secret_hygiene.json'
        doc=self.directory_report();self.write(report,doc)
        text,spans,diag=self.spans(report)
        self.assertEqual(len(spans),1,diag)
        self.assertEqual([json.loads(text[a:b]) for a,b in spans],[directory])
        # Identical body/finding occurrences remain ordinary entropy input.
        result=common.check_secret_hygiene(root=self.root,profile='standard',naos_root='naos',
            rules={'scan_roots':[report],'include_root_files':False},rules_path=None,severity='required')
        self.assertEqual(result['summary']['inventory_operand_matches'],1)
        self.assertEqual(result['summary']['entropy_matches'],2)
        doc.pop('unknown');doc.pop('findings');self.write(report,doc)
        kwargs=dict(root=self.root,profile='standard',naos_root='naos',
            # An explicit configured root is echoed at unproved configuration slots;
            # test the emitted inventory row by scanning its ordinary parent.
            rules={'scan_roots':[managed._RI_ROOT.rsplit('/',1)[0],report],
                   'include_root_files':False},rules_path=None,severity='required')
        # Exercise the scanner's emitted directory row on the following scan.
        first=common.check_secret_hygiene(**kwargs)
        self.assertEqual(first['summary']['entropy_matches'],0,first['findings'])
        self.assertIn({'path':directory,'status':'directory'},first['scans']['scope_inventory'])
        self.write(report,first)
        second=common.check_secret_hygiene(**kwargs)
        self.assertEqual(second['summary']['entropy_matches'],0,second['findings'])
        self.assertEqual(second['summary']['regex_matches'],0)

    def test_directory_inventory_needs_linked_bytes_and_exact_context_status(self):
        report='naos/reports/secret_hygiene.json'
        for status in ['read','selected','excluded','unselected_suffix']:
            with self.subTest(status=status):
                doc=self.directory_report(status=status)
                if status=='read':doc['scans']={'input_files':doc['scans']['scope_inventory']}
                self.assertFalse(self.spans(report,text=json.dumps(doc))[1])
        for change in [('project_root',str(self.root/'foreign')),('naos_root','foreign'),('schema','other')]:
            doc=self.directory_report();doc[change[0]]=change[1]
            self.assertFalse(self.spans(report,text=json.dumps(doc))[1])
        target=self.root/self.generation/'inventory.json';raw=target.read_bytes()
        target.write_bytes(raw+b' ')
        self.assertFalse(self.spans(report,text=json.dumps(self.directory_report()))[1])

    def test_directory_inventory_fake_existing_and_unsafe_paths_not_public(self):
        report='naos/reports/secret_hygiene.json'
        fake=managed._RI_ROOT+'/authored-aB3dE5fG7hI9jK0mN2pQ4rS6'
        (self.root/fake).mkdir()
        for value in [fake,managed._RI_ROOT+'/missing',managed._RI_ROOT+'/generations/../generations',
                      managed._RI_ROOT+'/generations/',managed._RI_ROOT+'//generations',
                      '/'+managed._RI_ROOT+'/generations',managed._RI_ROOT+'/generations\\alias']:
            with self.subTest(value=value):
                self.assertFalse(self.spans(report,text=json.dumps(self.directory_report(value)))[1])
        doc=self.directory_report();doc['scans']['scope_inventory'][0]['extra']='payload'
        self.assertFalse(self.spans(report,text=json.dumps(doc))[1])
        # Public directory coordinates do not bypass assignment/provider checks.
        doc=self.directory_report();doc['password']=managed._RI_ROOT+'/generations'
        doc['provider']='sk-'+'aBcDeFgHiJkLmNoPqRsTuVwXyZ123456';self.write(report,doc)
        result=common.check_secret_hygiene(root=self.root,profile='standard',naos_root='naos',
            rules={'scan_roots':[report],'include_root_files':False},rules_path=None,severity='required')
        self.assertGreater(result['summary']['entropy_matches'],0)
        self.assertGreater(result['summary']['regex_matches'],0)

    def test_directory_inventory_finite_wrappers_and_unknown_body_remain_scanned(self):
        inner=self.directory_report();binding={'project_root':str(self.root),'naos_root':'naos'}
        evidence={'schema':'naos.evidence_pack.v1',**binding,'artifacts':{'secret_hygiene_report':{'data':inner}}}
        dashboard={'schema':'naos.dashboard_summary.v1',**binding,
                   'inputs':{'secret_hygiene':{'data':inner},'evidence_pack':{'data':evidence}},'unknown':inner}
        text=json.dumps(dashboard,ensure_ascii=True,indent=2).replace('\n','\r\n')
        _,spans,diag=self.spans('naos/reports/dashboard_summary.json',text=text)
        self.assertEqual(len(spans),2,diag)
        self.assertTrue(all(json.loads(text[a:b])==managed._RI_ROOT+'/generations' for a,b in spans))
        dashboard['inputs']['secret_hygiene']['data']['project_root']='foreign'
        dashboard['inputs']['evidence_pack']['data']['project_root']='foreign'
        self.assertFalse(self.spans('naos/reports/dashboard_summary.json',text=json.dumps(dashboard))[1])

    def test_linked_control_positions_and_brownfield_regression(self):
        paths=['.naos/upgrade-v1/OWNER.json',self.fixture.relative+'/scope.json',self.fixture.relative+'/state/manifest.json',
            self.fixture.operands[1],managed._RI_SCOPE,managed._RI_ROOT+'/active.json',self.generation+'/inventory.json',
            self.generation+'/manifest.json',self.generation+'/validation_receipt.json',self.transaction+'/journal.json',self.transaction+'/receipt.json']
        context=managed.ProofBudget(self.root)
        counts=[1,1,4,2,7,6,13,3,3,7,3]
        for path,count in zip(paths,counts):
            with self.subTest(path=path): self.assertEqual(len(self.spans(path,context=context)[1]),count)
        result=common.check_secret_hygiene(root=self.root,profile='standard',naos_root='naos',
            rules={'scan_roots':paths,'include_root_files':False},rules_path=None,severity='required')
        self.assertEqual(result['summary']['entropy_matches'],0,result['findings'])
        self.assertEqual(result['summary']['regex_matches'],0)

    def test_report_inventory_echo_uses_linked_operand_not_body_membership(self):
        operand=self.generation+'/inventory.json'
        doc={'schema':'naos.secret_hygiene.v1','project_root':str(self.root),'naos_root':'naos',
            'scans':{'input_files':[{'path':operand,'status':'read'}],
                     'scope_inventory':[{'path':operand,'status':'selected'}],
                     'unassessed_suffix_files':[]},'unknown':operand,'findings':[{'path':operand}]}
        self.write('naos/reports/secret_hygiene.json',doc)
        text,spans,diag=self.spans('naos/reports/secret_hygiene.json')
        self.assertEqual(len(spans),2,diag)
        self.assertEqual({json.loads(text[a:b]) for a,b in spans},{operand})
        doc['scans']['input_files'][0]['path']=self.generation+'/unrelated.json'
        self.write('naos/reports/secret_hygiene.json',doc)
        self.assertEqual(len(self.spans('naos/reports/secret_hygiene.json')[1]),1)
        (self.root/self.generation/'inventory.json').write_bytes(b'changed')
        self.assertFalse(self.spans('naos/reports/secret_hygiene.json')[1])

    def test_same_tokens_in_authored_bodies_keep_entropy_and_regex_findings(self):
        token=self.owner['project_id'];provider='sk-'+'aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'
        self.journal['last_error']=token
        self.journal['journal_sha256']=managed.canonical_sha256({k:v for k,v in self.journal.items() if k!='journal_sha256'})
        path=self.transaction+'/journal.json';self.write(path,self.journal)
        text,spans,diag=self.spans(path)
        self.assertEqual(len(spans),7,diag)
        self.write('data/authored.json',dict(payload=token,unknown=self.active['control']['manifest_path'],password=provider))
        result=common.check_secret_hygiene(root=self.root,profile='standard',naos_root='naos',
            rules={'scan_roots':[path,'data'],'include_root_files':False},rules_path=None,severity='required')
        self.assertGreaterEqual(result['summary']['entropy_matches'],3)
        self.assertGreater(result['summary']['regex_matches'],0)
        self.assertFalse(self.spans('data/authored.json')[1])

    def test_copied_mirrored_unknown_schema_and_changed_bytes_refuse(self):
        path=managed._RI_ROOT+'/active.json';raw=(self.root/path).read_text()
        self.write('data/active.json',self.active);self.assertFalse(self.spans('data/active.json')[1])
        for text in (raw+' ',raw[:-1],raw.replace('"control":','"control":{},"control":')):
            self.assertFalse(self.spans(path,text)[1])
        for field,value in [('schema','naos.repository_intelligence.active.v999'),('unknown',self.owner['project_id'])]:
            changed=copy.deepcopy(self.active);changed[field]=value;self.write(path,changed)
            self.assertFalse(self.spans(path)[1]);self.write(path,self.active)
        import tempfile,shutil
        with tempfile.TemporaryDirectory() as mirror:
            shutil.copytree(self.root,mirror,dirs_exist_ok=True)
            spans,diag=managed.inventory_operand_spans(raw,path,Path(mirror),'naos',managed.ProofBudget(mirror))
            self.assertFalse(spans,diag)

    def test_tampered_source_base_owner_and_schema_refuse(self):
        path=managed._RI_ROOT+'/active.json'
        for target in ('src/adopter_existing.py',self.generation+'/local_context_index.sqlite','.naos/upgrade-v1/OWNER.json'):
            target=self.root/target;raw=target.read_bytes();target.write_bytes(raw+b'changed')
            self.assertFalse(self.spans(path)[1]);target.write_bytes(raw)
        with patch.dict(managed._RI_SCHEMAS,repository_intelligence_active='0'*64):
            self.assertFalse(self.spans(path)[1])

    def test_final_checkpoint_and_bounds_preserve_refusal(self):
        path=managed._RI_ROOT+'/active.json';context=managed._ScannerProofBudget(self.root)
        self.assertTrue(self.spans(path,context=context)[1])
        (self.root/'src/adopter_existing.py').write_bytes(b'changed after provisional spans')
        with self.assertRaises(managed.OperandRefusal): context.finish_scanner_batch()
        with patch.object(managed,'MAX_PROOF_BYTES',64): self.assertFalse(self.spans(path)[1])
        with patch.object(managed,'MAX_METADATA_NODES',1): self.assertFalse(self.spans(path)[1])

    def test_directory_membership_refuses_without_materializing_full_listing(self):
        relative = 'bounded-directory'
        directory = self.root / relative
        directory.mkdir()
        for index in range(5):
            (directory / str(index)).write_bytes(b'')
        original_scandir = managed.os.scandir
        visited = []
        streams = []

        class CountedDirectory:
            def __init__(self, path):
                self.stream = original_scandir(path)
                self.closed = False
                streams.append(self)

            def __enter__(self):
                self.stream.__enter__()
                return self

            def __iter__(self):
                return self

            def __next__(self):
                child = next(self.stream)
                visited.append(child.name)
                return child

            def __exit__(self, *args):
                self.closed = True
                return self.stream.__exit__(*args)

        with patch.object(managed, 'MAX_IDENTITIES', 2), \
                patch.object(managed.os, 'scandir', side_effect=CountedDirectory), \
                patch.object(managed.os, 'listdir', side_effect=AssertionError('unbounded listing')):
            with self.assertRaisesRegex(managed.OperandRefusal, 'directory_entries'):
                managed.ProofBudget(self.root).entries(relative)
        self.assertEqual(len(visited), 3)
        self.assertTrue(streams and all(stream.closed for stream in streams))

    def test_mac_and_linux_saved_runtime_labels_without_native_probe(self):
        for system,machine,expected in [('Darwin','arm64','macos_arm64_cpython_3_11_to_3_13_binary_wheels'),
                ('Linux','x86_64','linux_x86_64_cpython_3_11_to_3_13_binary_wheels'),
                ('Linux','aarch64','linux_aarch64_cpython_3_11_to_3_13_binary_wheels')]:
            self.manifest['control']['runtime']['platform'].update(system=system,machine=machine,supported_tuple=expected)
            self.rebuild_ri();text,spans,diag=self.spans(self.generation+'/manifest.json')
            self.assertIn(expected,{json.loads(text[a:b]) for a,b in spans},diag)

    def test_pure_reader_and_constructor_do_not_import_native_upgrade_runtime(self):
        import subprocess
        code = "import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);import naos_secret_managed_operands as m;assert len(m._ri_constructor_coordinates(m.ProofBudget(Path(sys.argv[2]))))==7;assert not any(n=='upgrade_contract' or n.startswith('upgrade_contract.') for n in sys.modules)"
        result=subprocess.run([sys.executable,'-B','-c',code,str(KIT/'scripts'),str(self.root)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)


if __name__=='__main__': unittest.main()
