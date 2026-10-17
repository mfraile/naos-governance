"""Synthetic Windows RI bytes; logical labels and explicit empty directories.

These tests perform no native Windows calls and establish no current ownership.
All native-looking identities, security hashes and timestamps are deterministic
public test constants. The fixture generator rebuilds every linked control hash.
"""
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

KIT=Path(os.environ.get('NAOS_TEST_KIT',Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(KIT/'scripts'))
sys.path.insert(0,str(KIT))
import naos_secret_managed_operands as m
import naos_secret_ri_windows_operands as w
import naos_hygiene_common as common


class WindowsRIControls(unittest.TestCase):
    def test_fixture_native_values_are_public_synthetic_constants(self):
        fixture=json.loads((KIT/'public_tests/fixtures/ri_windows_saved_documents.json').read_text())
        self.assertEqual(fixture['provenance']['kind'],'fully_synthetic')
        self.assertNotIn('archive_sha256',fixture)
        self.assertNotIn('selected_receipt_sha256',fixture)
        seed='naos-public-synthetic-windows-ri-v1:'
        public_hash=lambda label:hashlib.sha256((seed+label).encode()).hexdigest()
        paths=set(fixture['files'])|set(fixture['derived_empty_directories'])
        paths|={str(parent) for path in tuple(paths) for parent in PurePosixPath(path).parents if str(parent)!='.'}
        documents=[]
        for row in fixture['files'].values():
            raw=zlib.decompress(base64.b64decode(row['zlib_base64']))
            if raw.startswith(b'{'):documents.append(json.loads(raw))
        slots=set()
        def walk(value):
            if isinstance(value,dict):
                yield value
                for item in value.values():yield from walk(item)
            elif isinstance(value,list):
                for item in value:yield from walk(item)
        records=[record for document in documents for record in walk(document)]
        for record in records:
            if 'target' in record and 'after' in record:slots.add(record['target'])
        allowed_ids={public_hash('root')[:32]}|{public_hash('native:'+path)[:32] for path in paths}|{
            public_hash('publication:'+slot)[:32] for slot in slots}
        expected={'volume_serial_hex':'0123456789abcdef',
            'security_sha256':public_hash('private-security-descriptor'),
            'private_security_sha256':public_hash('private-security-descriptor'),
            'created_100ns_decimal':'125911584000000000','last_write_100ns_decimal':'125911584000000000',
            'owner_sid_sha256':public_hash('owner-sid'),'group_sid_sha256':public_hash('group-sid'),
            'dacl_sha256':public_hash('dacl'),'descriptor_sha256':public_hash('descriptor')}
        observed=set()
        for record in records:
            for key,value in record.items():
                if key in expected:self.assertEqual(value,expected[key]);observed.add(key)
                if key=='file_id_hex':self.assertIn(value,allowed_ids);observed.add(key)
        self.assertEqual(observed,set(expected)|{'file_id_hex'})

    def setUp(self):
        temporary_root=Path(tempfile.gettempdir()).resolve(strict=True)
        self.temp=tempfile.TemporaryDirectory(dir=temporary_root);self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'project';self.root.mkdir()
        self.fixture=json.loads((KIT/'public_tests/fixtures/ri_windows_saved_documents.json').read_text())
        for path,row in self.fixture['files'].items():
            raw=zlib.decompress(base64.b64decode(row['zlib_base64']))
            self.assertEqual(len(raw),row['size_bytes']);self.assertEqual(hashlib.sha256(raw).hexdigest(),row['sha256'])
            target=self.root/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        for path in self.fixture['derived_empty_directories']:
            directory = self.root/path
            directory.mkdir(parents=True)
            # Finish observing the derived fixture before the saved-chain proof.
            # A fresh Windows directory can change raw attributes on enumeration;
            # the product continues to refuse changes during its proof window.
            with os.scandir(directory) as entries:
                self.assertEqual([entry.name for entry in entries], [])
        self.active=m._RI_ROOT+'/active.json';self.pointer=json.loads((self.root/self.active).read_text())
        self.op=w.RUNTIME+'/operations/'+self.pointer['operation_id']
        self.generation=m._RI_ROOT+'/generations/'+self.pointer['request']['generation_id']

    def context(self,batch=False,logical=None):
        physical=(m._ScannerProofBudget if batch else m.ProofBudget)(self.root)
        class Context:
            root=PureWindowsPath(logical or self.fixture['logical_root'])
            def __init__(self):
                self.cache=physical.cache;self.operands={};self.reason={};self.evidence={};self.constructor_coordinates={}
            @property
            def bytes_read(self):return physical.bytes_read
            @bytes_read.setter
            def bytes_read(self,value):physical.bytes_read=value
            def read(self,path):return physical.read(path)
            def object(self,path):return m._strict_object(self.read(path))
            def entries(self,path):return physical.entries(path)
            def verify_cached(self):
                if hasattr(self,'schema_context'):self.schema_context.verify_cached()
                return physical.verify_cached()
            def admission_checkpoint(self):
                if not batch:return self.verify_cached()
                return physical.admission_checkpoint()
            def finish_scanner_batch(self):
                if hasattr(self,'schema_context'):self.schema_context.verify_cached()
                return physical.finish_scanner_batch()
        return Context()

    def spans(self,path,text=None,context=None):
        text=text if text is not None else (self.root/path).read_text()
        spans,diag=m.inventory_operand_spans(text,path,self.root,'naos',context or self.context())
        return text,spans,diag

    def echo_report(self,paths):
        return {'schema':'naos.secret_hygiene.v1','project_root':str(self.root),'naos_root':'naos',
            'scans':{'input_files':[{'path':path,'status':'read'} for path in paths],
                'scope_inventory':[{'path':path,'status':'selected'} for path in paths],
                'unassessed_suffix_files':paths,
                'inventory_operand_proofs':[{'path':path,'status':'proved','matches':1,'proof_bytes':1} for path in paths]}}

    def operation_records(self):
        return sorted(path for path in self.fixture['files']
                      if path.startswith(self.op+'/') and path.endswith('.json'))

    def test_operation_echoes_all_proved_records_and_existing_carriers(self):
        paths=self.operation_records();self.assertGreaterEqual(len(paths),5)
        report=self.echo_report(paths);context=self.context()
        text,spans,diag=self.spans('naos/reports/secret_hygiene.json',text=json.dumps(report),context=context)
        self.assertEqual(len(spans),4*len(paths),diag)
        self.assertEqual({json.loads(text[a:b]) for a,b in spans},set(paths))
        self.assertTrue(any('/forward-' in path for path in paths));self.assertTrue(any('/committed.json' in path for path in paths))
        binding={'project_root':str(self.root),'naos_root':'naos'}
        evidence={'schema':'naos.evidence_pack.v1',**binding,'artifacts':{'secret_hygiene_report':{'data':report}}}
        dashboard={'schema':'naos.dashboard_summary.v1',**binding,'inputs':{
            'secret_hygiene':{'data':report},'evidence_pack':{'data':evidence}}}
        for carrier,count in ((evidence,4),(dashboard,8)):
            _,spans,diag=self.spans('naos/reports/carrier.json',text=json.dumps(carrier),context=context)
            self.assertEqual(len(spans),count*len(paths),diag)
        count=len(context.operands[m._RI_ROOT])
        with patch.object(m,'MAX_IDENTITIES',count):
            self.assertEqual(len(self.spans('naos/reports/secret_hygiene.json',text=json.dumps(report))[1]),4*len(paths))
        with patch.object(m,'MAX_IDENTITIES',count-1):
            self.assertFalse(self.spans('naos/reports/secret_hygiene.json',text=json.dumps(report))[1])

    def test_operation_echoes_survive_repeated_self_report_scan(self):
        path='naos/reports/secret_hygiene.json';target=self.root/path;target.parent.mkdir(parents=True)
        paths=self.runtime_echo_roles();self.assertEqual(len(paths),22)
        target.write_text(json.dumps(self.echo_report(paths),indent=2))
        for iteration in range(3):
            input_text=target.read_text()
            with patch.object(common,'_ScannerProofBudget',side_effect=lambda root:self.context(batch=True)):
                report=common.check_secret_hygiene(root=self.root,profile='standard',naos_root='naos',
                    rules={'scan_roots':['.'],'include_root_files':False},rules_path=None,severity='blocking')
            self.assertEqual(report['summary']['regex_matches'],0)
            # Synthetic Windows controls declare separate logical root and kit
            # paths. On this physical fixture those three body literals
            # stay findings; later output also retains their three finding-path
            # echoes. They cannot justify a body/root exception in this fix.
            baseline={self.generation+'/inventory.json',self.generation+'/manifest.json'}
            raw_findings=[finding for finding in report['findings']
                          if finding['status']=='high_entropy_literal' and finding['path']!=path]
            self.assertEqual([(finding['id'],finding['path'],finding['line']) for finding in raw_findings],
                [('SH-1',self.generation+'/inventory.json',156),
                 ('SH-2',self.generation+'/manifest.json',121),
                 ('SH-3',self.generation+'/manifest.json',146)])
            for finding in report['findings']:
                if finding['status']!='high_entropy_literal':continue
                if finding['path']==path:
                    literal=json.loads(input_text.splitlines()[finding['line']-1].strip().split(':',1)[1].rstrip(','))
                    self.assertIn(literal,baseline)
                else:self.assertIn(finding['path'],baseline)
            self.assertGreater(report['summary']['inventory_operand_matches'],0)
            self.assertTrue(set(paths)<={row['path'] for row in report['scans']['scope_inventory']})
            # Actual default-project scanner output becomes its next input.
            target.write_text(json.dumps(report,indent=2))

    def test_operation_echoes_refuse_foreign_body_unproven_and_malformed_contexts(self):
        paths=self.operation_records();report=self.echo_report(paths)
        report.update(payload=paths,password=paths[0],provider='sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456')
        text,spans,_=self.spans('naos/reports/secret_hygiene.json',text=json.dumps(report))
        self.assertEqual(len(spans),4*len(paths))
        report['project_root']='C:\\foreign-root'
        self.assertFalse(self.spans('naos/reports/secret_hygiene.json',text=json.dumps(report))[1])
        report=self.echo_report([self.op+'/forward-999999.json',self.op+'/rolled-back.json',self.op+'/authored.json'])
        self.assertFalse(self.spans('naos/reports/secret_hygiene.json',text=json.dumps(report))[1])
        report=self.echo_report(paths);report['scans']['inventory_operand_proofs'][0]['status']='refused'
        self.assertEqual(len(self.spans('naos/reports/secret_hygiene.json',text=json.dumps(report))[1]),4*len(paths)-1)
        text=json.dumps(self.echo_report(paths));text=text.replace('"scans":','"scans":0,"scans":',1)
        self.assertFalse(self.spans('naos/reports/secret_hygiene.json',text=text)[1])
        changed=self.root/self.op/'committed.json';raw=changed.read_bytes()
        changed.write_bytes(raw+b' ')
        # Envelope bytes need not be canonical, so break its actual bound body.
        record=json.loads(raw);record['body']['intent_sha256']='0'*64
        record['sha256']=m.canonical_sha256(record['body']);changed.write_bytes(m.canonical_bytes(record))
        self.assertFalse(self.spans('naos/reports/secret_hygiene.json',text=json.dumps(self.echo_report(paths)))[1])
        changed.write_bytes(raw)
        path='naos/reports/secret_hygiene.json';target=self.root/path;target.parent.mkdir(parents=True)
        report=self.echo_report(paths);report['api_key']='sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456';report['password']=paths[0]
        target.write_text(json.dumps(report))
        with patch.object(common,'_ScannerProofBudget',side_effect=lambda root:self.context(batch=True)):
            findings=common.check_secret_hygiene(root=self.root,profile='standard',naos_root='naos',
                rules={'scan_roots':[path],'include_root_files':False},rules_path=None,severity='blocking')
        self.assertGreater(findings['summary']['regex_matches'],0)
        self.assertGreater(findings['summary']['entropy_matches'],0)
        self.assertGreater(findings['summary']['inventory_operand_matches'],0)

    def runtime_echo_roles(self):
        op=self.pointer['operation_id']
        return sorted({*self.operation_records(),self.op,self.op+'/lock',
            *(w.RUNTIME+'/'+name for name in ('directory-template','file-template','operations',
                'preparations','receipts','scope.lock','staging')),
            w.RUNTIME+'/preparations/'+op+'.json',w.RUNTIME+'/receipts/'+op+'.json',w.RUNTIME+'/staging/'+op})

    def test_all_22_actual_runtime_echo_roles_require_complete_physical_proof(self):
        paths=self.runtime_echo_roles();self.assertEqual(len(paths),22)
        report=self.echo_report(paths);context=self.context()
        text,spans,diag=self.spans('naos/reports/secret_hygiene.json',text=json.dumps(report),context=context)
        self.assertEqual(len(spans),4*22,diag)
        self.assertEqual({json.loads(text[a:b]) for a,b in spans},set(paths))
        self.assertIn(self.op+'/lock',context.cache)
        self.assertEqual(context.read(self.op+'/lock'),b'')
        self.assertTrue(set(w.DIRECTORIES)|set(w.FILES)<=context.operands[m._RI_ROOT])
        report=self.echo_report([w.RUNTIME]);self.assertEqual(len(self.spans(
            'naos/reports/secret_hygiene.json',text=json.dumps(report))[1]),4)
        for path in (self.op+'/lock',w.RUNTIME+'/file-template',w.RUNTIME+'/scope.lock'):
            with self.subTest(preimage=path):
                target=self.root/path;raw=target.read_bytes();target.write_bytes(b'not-empty')
                self.assertFalse(self.spans('naos/reports/secret_hygiene.json',text=json.dumps(self.echo_report(paths)))[1])
                target.write_bytes(raw)
        for path in (w.RUNTIME+'/directory-template',w.RUNTIME+'/staging'):
            with self.subTest(membership=path):
                extra=self.root/path/'unproved-file';extra.write_bytes(b'')
                self.assertFalse(self.spans('naos/reports/secret_hygiene.json',text=json.dumps(self.echo_report(paths)))[1])
                extra.unlink()
        context=self.context(batch=True);self.assertTrue(self.spans(
            'naos/reports/secret_hygiene.json',text=json.dumps(self.echo_report(paths)),context=context)[1])
        (self.root/self.op/'lock').write_bytes(b'changed-after-proof')
        with self.assertRaises(m.OperandRefusal):context.finish_scanner_batch()
        (self.root/self.op/'lock').write_bytes(b'')
        with self.assertRaises(m.OperandRefusal):context.finish_scanner_batch()

    def test_saved_windows_directory_inventory_needs_actual_linked_parents(self):
        directory=m._RI_ROOT+'/generations'
        report={'schema':'naos.secret_hygiene.v1','project_root':str(self.root),'naos_root':'naos',
                'scans':{'scope_inventory':[{'path':directory,'status':'directory'}]},'payload':directory}
        text=json.dumps(report);context=self.context()
        _,spans,diag=self.spans('naos/reports/secret_hygiene.json',text=text,context=context)
        self.assertEqual(len(spans),1,diag)
        self.assertEqual([json.loads(text[a:b]) for a,b in spans],[directory])
        fake=directory+'/authored-secret-aB3dE5fG7hI9jK0mN2'
        report['scans']['scope_inventory'][0]['path']=fake
        self.assertFalse(self.spans('naos/reports/secret_hygiene.json',text=json.dumps(report))[1])
        report['scans']['scope_inventory'][0]['path']=directory
        target=self.root/self.generation/'local_context_index.sqlite';raw=target.read_bytes()
        target.write_bytes(raw+b' ')
        self.assertFalse(self.spans('naos/reports/secret_hygiene.json',text=json.dumps(report))[1])

    def test_exact_saved_producer_chain_57_positions_and_cache(self):
        context=self.context();coordinates=m._ri_constructor_coordinates(context)
        self.assertEqual(len(coordinates),10);self.assertEqual(sum(map(len,coordinates.values())),57)
        charged=context.bytes_read
        for path,expected in coordinates.items():
            text,spans,diag=self.spans(path,context=context)
            self.assertEqual(len(spans),len(expected),diag)
            parser=m._OffsetJSON(text,exact_control_coordinates=expected);parser.parse()
            self.assertEqual(spans,{parser.strings[key][:2] for key in expected})
        self.assertEqual(context.bytes_read,charged)
        self.assertLess(charged,m.MAX_PROOF_BYTES)

    def test_saved_native_map_keys_need_complete_constructor_and_exact_bytes(self):
        paths=[w.BOOTSTRAP,w.RUNTIME+'/preparations/'+self.pointer['operation_id']+'.json',self.op+'/plan.json']
        context=self.context();coordinates=m._ri_constructor_coordinates(context)
        key_count=0
        for path in paths:
            text,spans,diag=self.spans(path,context=context)
            expected={key:value for key,value in coordinates[path].items()
                      if isinstance(key[-1],tuple) and key[-1][0]=='object_key'}
            parser=m._OffsetJSON(text,exact_control_coordinates=coordinates[path]);parser.parse()
            self.assertTrue(expected)
            for key,value in expected.items():
                start,end,observed=parser.strings[key]
                self.assertEqual(observed,value)
                self.assertIn((start,end),spans)
            key_count+=len(expected)
            self.assertFalse(self.spans(path,text=text+' ')[1])
            authored='authored-map-keys.json';(self.root/authored).write_text(text)
            self.assertFalse(self.spans(authored,text=text)[1])
        self.assertEqual(key_count,17)
        for path in paths:
            with self.subTest(schema=path):
                target=self.root/path;raw=target.read_bytes();record=json.loads(raw)
                record['schema']='naos.authored.lookalike.v1'
                target.write_bytes(m.canonical_bytes(record))
                self.assertFalse(self.spans(path)[1])
                target.write_bytes(raw)
        authored='authored-native-map.json'
        directory=w.RUNTIME+'/directory-template'
        text=json.dumps({'schema':w.BOOTSTRAP_SCHEMA,'directories':{directory:'ordinary-body'},
                         'body':directory,'api_key':'sk-'+('A9b8C7d6E5f4'*5)})
        (self.root/authored).write_text(text)
        self.assertFalse(self.spans(authored,text=text)[1])
        report=common.check_secret_hygiene(root=self.root,profile='standard',naos_root='naos',
            rules={'scan_roots':[authored],'include_root_files':False},rules_path=None,severity='required')
        self.assertGreater(report['summary']['regex_matches'],0)
        self.assertGreater(report['summary']['entropy_matches'],0)
        target=self.root/w.BOOTSTRAP;raw=target.read_bytes();record=json.loads(raw)
        fake=w.RUNTIME+'/authored-credential-aB3dE5fG7hI9jK0mN2'
        record['directories'][fake]=record['directories'].pop(w.RUNTIME+'/operations')
        target.write_bytes(m.canonical_bytes(record))
        self.assertFalse(self.spans(w.BOOTSTRAP)[1])
        target.write_bytes(raw)
        proof_source=self.root/self.generation/'local_context_index.sqlite'
        proof_source.write_bytes(proof_source.read_bytes()+b' ')
        self.assertFalse(self.spans(w.BOOTSTRAP)[1])

    def test_credential_regex_still_runs_at_a_key_entropy_interval(self):
        # Isolate the scanner consumer boundary; this is not native proof.
        credential='sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'
        path='authored-key-credential.json';text=json.dumps({credential:'ordinary-body'})
        (self.root/path).write_text(text)
        coordinate=(('object_key',credential),)
        parser=m._OffsetJSON(text,exact_control_coordinates={coordinate});parser.parse()
        start,end,_=parser.strings[coordinate]
        with patch.object(common,'inventory_operand_spans',return_value=({(start,end)},
                {'status':'proved','matches':1,'proof_bytes':0})):
            report=common.check_secret_hygiene(root=self.root,profile='standard',naos_root='naos',
                rules={'scan_roots':[path],'include_root_files':False},rules_path=None,severity='required')
        self.assertTrue(any(row.get('pattern_id')=='openai_style_key' for row in report['findings']))
        self.assertGreater(report['summary']['regex_matches'],0)

    def test_exact_object_key_coordinates_are_distinct_and_bounded(self):
        key='constructor-path-with-high-entropy-aB3dE5fG7hI9jK0mN2'
        key_coordinate=('directories',('object_key',key))
        value_coordinate=('directories',key)
        text=json.dumps({'directories':{key:'ordinary-body'}})
        parser=m._OffsetJSON(text,exact_control_coordinates={key_coordinate,value_coordinate})
        parser.parse()
        self.assertEqual(parser.strings[key_coordinate][2],key)
        self.assertEqual(parser.strings[value_coordinate][2],'ordinary-body')
        self.assertNotEqual(parser.strings[key_coordinate][:2],parser.strings[value_coordinate][:2])
        parser=m._OffsetJSON(text);parser.parse();self.assertEqual(parser.strings,{})
        duplicate='{"directories":{"'+key+'":1,"'+key+'":2}}'
        with self.assertRaises(m.OperandRefusal):
            m._OffsetJSON(duplicate,exact_control_coordinates={key_coordinate}).parse()
        with patch.object(m,'MAX_METADATA_NODES',0),self.assertRaises(m.OperandRefusal):
            m._OffsetJSON(text,exact_control_coordinates={key_coordinate}).parse()
        with patch.object(m,'MAX_DEPTH',1),self.assertRaises(m.OperandRefusal):
            m._OffsetJSON(text,exact_control_coordinates={key_coordinate}).parse()
        with patch.object(m,'MAX_DOCUMENT_BYTES',len(text.encode('utf-8'))-1),self.assertRaises(m.OperandRefusal):
            m._OffsetJSON(text,exact_control_coordinates={key_coordinate})

    def test_original_generated_reference_literals_are_admitted_exactly(self):
        path=self.generation+'/inventory.json';text,spans,diag=self.spans(path)
        self.assertEqual(len(spans),12,diag)
        quoted={json.loads(text[start:end]) for start,end in spans}
        self.assertTrue(any(value.startswith('artifact:A-') for value in quoted))
        self.assertTrue(any(value.startswith('spec:') for value in quoted))
        authored=self.root/'authored.json';authored.write_text(json.dumps({'payload':sorted(quoted)}))
        self.assertFalse(self.spans('authored.json')[1])
        findings=common.check_secret_hygiene(root=self.root,profile='standard',naos_root='naos',
            rules={'scan_roots':['authored.json'],'include_root_files':False},rules_path=None,severity='required')
        self.assertGreater(findings['summary']['entropy_matches'],0)

    def test_unknown_authored_mirror_and_changed_input_do_not_get_spans(self):
        text=(self.root/self.active).read_text();unknown='authored/active.json'
        (self.root/'authored').mkdir();(self.root/unknown).write_text(text)
        self.assertEqual(self.spans(unknown)[1],set())
        self.assertEqual(self.spans(self.active,text=text+' ')[1],set())
        token=self.pointer['operation_id']
        authored=json.dumps({'schema':'naos.repository_intelligence.windows_active.v1','body':token,'unknown_token':'aB3dE5fG7hI9jK0mN2pQ4rS6tU8vW+/=','api_key':'sk-'+('A9b8C7d6E5f4'*5)})
        spans=self.spans(unknown,text=authored)[1];self.assertEqual(spans,set())
        (self.root/unknown).write_text(authored)
        findings=common.check_secret_hygiene(root=self.root,profile='standard',naos_root='naos',
            rules={'scan_roots':['authored'],'include_root_files':False},rules_path=None,severity='required')
        self.assertGreater(findings['summary']['entropy_matches'],0)
        self.assertGreater(findings['summary']['regex_matches'],0)
        value=json.loads(text);value['body']=token;(self.root/self.active).write_bytes(m.canonical_bytes(value))
        self.assertEqual(self.spans(self.active)[1],set())

    def test_wrong_root_missing_source_or_tampered_generation_refuse(self):
        self.assertEqual(m._ri_constructor_coordinates(self.context(logical='C:\\unrelated\\project')), {})
        for path in ('src/adopter_existing.py',self.generation+'/local_context_index.sqlite',w.ENROLLMENT):
            with self.subTest(path=path):
                target=self.root/path;raw=target.read_bytes();target.write_bytes(raw+b' ')
                self.assertEqual(self.spans(self.active)[1],set());target.write_bytes(raw)

    def test_missing_wrong_checkpoint_and_unknown_history_refuse(self):
        checkpoint=self.root/self.op/'forward-000007.json';raw=checkpoint.read_bytes()
        checkpoint.unlink();self.assertEqual(self.spans(self.active)[1],set());checkpoint.write_bytes(raw)
        value=m._strict_object(raw);value['body']['topology']='step:6'
        value['sha256']=m.canonical_sha256(value['body']);checkpoint.write_bytes(m.canonical_bytes(value))
        self.assertEqual(self.spans(self.active)[1],set());checkpoint.write_bytes(raw)
        for parent in (self.op,w.RUNTIME+'/staging',m._RI_ROOT+'/generations',w.RUNTIME+'/directory-template'):
            with self.subTest(parent=parent):
                extra=self.root/parent/'unknown';extra.write_text('extra')
                self.assertEqual(self.spans(self.active)[1],set());extra.unlink()

    def test_refresh_rollback_malformed_and_unknown_schema_refuse(self):
        target=self.root/self.active;raw=target.read_bytes()
        for key,value in [('predecessor',{'operation_id':'WOP-'+('0'*16),'pointer_sha256':'0'*64}),('schema','unknown'),('members',[]),('request',{})]:
            with self.subTest(key=key):
                pointer=json.loads(raw);pointer[key]=value;target.write_bytes(m.canonical_bytes(pointer))
                self.assertEqual(self.spans(self.active)[1],set())
        target.write_bytes(raw);extra=self.root/self.op/'rolled-back.json';extra.write_text('{}')
        self.assertEqual(self.spans(self.active)[1],set())

    def test_membership_terminal_refusal_stays_sticky_after_restore(self):
        context=self.context(batch=True);self.assertTrue(self.spans(self.active,context=context)[1])
        extra=self.root/self.op/'unknown';extra.write_text('extra')
        with self.assertRaises(m.OperandRefusal):context.finish_scanner_batch()
        extra.unlink()
        with self.assertRaises(m.OperandRefusal):context.finish_scanner_batch()

    def test_bounds_and_schema_tamper_refuse(self):
        with patch.object(m,'MAX_PROOF_BYTES',1024):self.assertEqual(self.spans(self.active)[1],set())
        with patch.object(m,'MAX_IDENTITIES',2):self.assertEqual(self.spans(self.active)[1],set())
        schema='schemas/naos/repository_intelligence_manifest.schema.json'
        fake=Path(self.temp.name)/'kit';(fake/'scripts').mkdir(parents=True);(fake/'schemas/naos').mkdir(parents=True)
        (fake/schema).write_bytes((KIT/schema).read_bytes()+b' ')
        with patch.object(m,'__file__',str(fake/'scripts/naos_secret_managed_operands.py')):
            self.assertEqual(self.spans(self.active)[1],set())

    def test_pure_fresh_process_imports_no_native_upgrade_modules(self):
        code="import runpy,sys;ns=runpy.run_path(sys.argv[1]);t=ns['WindowsRIControls']();t.setUp();assert len(ns['m']._ri_constructor_coordinates(t.context()))==10;assert not any(n=='upgrade_contract' or n.startswith('upgrade_contract.') for n in sys.modules);t.doCleanups()"
        result=subprocess.run([sys.executable,'-B','-c',code,__file__],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_lite_preview_copies_importable_linked_parser(self):
        import naos_init as init
        from upgrade_contract.source_origins import SourceOrigins
        preview=Path(self.temp.name)/'lite-preview'
        origins=SourceOrigins.from_kit(KIT,output_root=preview)
        generated=init.scaffold_files(project_path=self.root,tier='lite',archetype=None,
            backend='static_only',preview_dir=preview,memory_choice='disabled',emit_progress=False,
            source_origins=origins)
        relative='scripts/naos_secret_ri_windows_operands.py'
        self.assertIn(relative,generated)
        expected='# AUTO-GENERATED: Copied by naos init from the NAOS kit.\n'+(KIT/relative).read_text()
        self.assertEqual((preview/relative).read_text(),expected)
        code="import sys;from pathlib import Path;root=Path(sys.argv[1]);sys.path.insert(0,str(root/'scripts'));import naos_secret_managed_operands as m;import naos_secret_ri_windows_operands as w;assert Path(m.__file__).parent==root/'scripts';assert Path(w.__file__).parent==root/'scripts';assert not any(n=='upgrade_contract' or n.startswith('upgrade_contract.') for n in sys.modules)"
        result=subprocess.run([sys.executable,'-I','-B','-c',code,str(preview)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)


if __name__=='__main__':unittest.main()
