"""Selected defining claim records, finite carriers and neighboring tripwires."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import yaml
from jsonschema import Draft202012Validator
KIT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(KIT/'scripts'))
import naos_secret_public_literals as public
import naos_hygiene_common as common
import naos_task_claims as producer
TOKEN='aB3dE5fG7hI9jK0mN2pQ4rS6tU8vW+/='

class ClaimLabelTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='public-claim-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
  from naos_policy import SAFE_FALLBACK_POLICY
  time='2026-10-10T03:06:20Z';session='fixture-session';operator={'operator_id':'fixture','operator_source':'cli'}
  with patch.object(producer.uuid,'uuid4',return_value=SimpleNamespace(hex='ea7fd3f8db97'+'0'*20)),patch.object(producer,'generated_by_for',return_value={'operator_id':'fixture','session_id':session,'generated_at':time}):
   record=producer.make_claim(root=self.root,task_id='T-001',operator=operator,session_id=session,branch='fixture',now_text=time,ttl_hours=72)
   self.registry={'schema':producer.CLAIMS_SCHEMA,'updated_at':time,'claims':[record]}
   self.report=producer.build_report(root=self.root,naos_root='naos',policy=SAFE_FALLBACK_POLICY,profile='standard',action='claim',task_id='T-001',session_id=session,operator=operator,branch='fixture',claims_path=self.root/'naos/task_claims.yaml',data=self.registry,load_findings=[],operator_findings=[],task_finding=None,action_findings=[],action_status='claim_created',audit_result=None,generated_at=time)
  self.source=self.write('naos/task_claims.yaml',yaml.safe_dump(self.registry,sort_keys=False))
  self.path=self.write('naos/reports/task_claim_report.json',json.dumps(self.report,indent=2))
 def write(self,rel,text):
  p=self.root/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text, encoding='utf-8');return p
 def context(self,selected=None):return public.selected_public_claim_context(selected or [self.source,self.path],root=self.root,naos_root='naos')
 def spans(self,doc=None,path=None,context=None):
  relative=path or 'naos/reports/task_claim_report.json';text=json.dumps(doc or self.report);target=self.write(relative,text)
  return public.public_claim_label_spans(text,relative,root=self.root,naos_root='naos',context=context or self.context([self.source,target]))
 def scan(self,extra=None):
  rules={'scan_roots':['naos/task_claims.yaml','naos/reports/task_claim_report.json'],'include_root_files':False}
  return common.check_secret_hygiene(root=self.root,profile='standard',naos_root='naos',rules={**rules,**(extra or {})},rules_path=None,severity='blocking')
 def test_actual_producer_four_occurrences_and_ordinary_coverage(self):
  sid=self.report['session_id'];self.write('naos/sessions/'+sid+'/reports/task_claim_report.json',json.dumps(self.report,indent=2))
  rules={'scan_roots':['naos/task_claims.yaml','naos/reports/task_claim_report.json','naos/sessions/'+sid+'/reports/task_claim_report.json']}
  with patch.object(common,'selected_public_claim_context',return_value=None):before=self.scan(rules)
  after=self.scan(rules);self.assertEqual(before['summary']['entropy_matches']-after['summary']['entropy_matches'],4)
  claim_paths={self.path.relative_to(self.root).as_posix(),'naos/sessions/'+sid+'/reports/task_claim_report.json'}
  removed={(f['path'],f['line'],f['column']) for f in before['findings']} - {(f['path'],f['line'],f['column']) for f in after['findings']}
  self.assertEqual(len(removed),4);self.assertEqual({row[0] for row in removed},claim_paths)
  self.assertEqual(after['summary']['files_selected'],before['summary']['files_selected']);self.assertEqual(after['summary']['files_scanned'],before['summary']['files_scanned']);self.assertEqual(after['summary']['coverage_status'],'complete')
 def test_noncarriers_do_not_consume_claim_proof_or_withdraw_valid_labels(self):
  import naos_secret_managed_operands as managed
  doc={'padding':'x'*(len(self.path.read_bytes())+1567),'neighbor':self.report['claims'][0]['claim_id'],
       'credential':TOKEN,'api_key':TOKEN,'provider':'sk-proj-'+TOKEN}
  unrelated=self.write('naos/reports/a-unrelated.json',json.dumps(doc,indent=2))
  cap=len(self.source.read_bytes())+len(unrelated.read_bytes())
  with patch.object(managed,'MAX_PROOF_BYTES',cap):
   context=self.context([self.source,self.path,unrelated]);self.assertIsNotNone(context)
   initial_bytes=context['proof'].bytes_read;initial_cache=set(context['proof'].cache)
   with patch.object(context['proof'],'read',wraps=context['proof'].read) as read:
    self.assertFalse(public.public_claim_label_spans(unrelated.read_text(encoding='utf-8'),'naos/reports/a-unrelated.json',root=self.root,naos_root='naos',context=context))
    read.assert_not_called()
   self.assertEqual(context['proof'].bytes_read,initial_bytes);self.assertEqual(set(context['proof'].cache),initial_cache)
   self.assertEqual(len(public.public_claim_label_spans(self.path.read_text(encoding='utf-8'),'naos/reports/task_claim_report.json',root=self.root,naos_root='naos',context=context)),2)
   admitted_bytes=context['proof'].bytes_read
   self.assertFalse(public.public_claim_label_spans(unrelated.read_text(encoding='utf-8'),'naos/reports/a-unrelated.json',root=self.root,naos_root='naos',context=context))
   self.assertEqual(context['proof'].bytes_read,admitted_bytes)
   self.assertEqual(len(public.public_claim_label_spans(self.path.read_text(encoding='utf-8'),'naos/reports/task_claim_report.json',root=self.root,naos_root='naos',context=context)),2)
   rules={'scan_roots':['naos/task_claims.yaml','naos/reports/task_claim_report.json','naos/reports/a-unrelated.json']}
   with patch.object(common,'selected_public_claim_context',return_value=None):before=self.scan(rules)
   after=self.scan(rules)
   self.assertEqual(before['summary']['entropy_matches']-after['summary']['entropy_matches'],2)
   self.assertEqual(after['summary']['files_scanned'],3);self.assertEqual(after['summary']['coverage_status'],'complete')
   before_unrelated=[f for f in before['findings'] if f['path']=='naos/reports/a-unrelated.json']
   after_unrelated=[f for f in after['findings'] if f['path']=='naos/reports/a-unrelated.json']
   self.assertEqual(after_unrelated,before_unrelated);self.assertGreaterEqual(after['summary']['regex_matches'],2)
   self.assertGreaterEqual(after['summary']['entropy_matches'],2)
 def test_noncarrier_path_nearmisses_are_gated_before_read(self):
  for relative in ['unknown.json','naos/reports/other.json','naos/sessions/x/reports/other.json',
                   'naos/sessions/x/nested/reports/task_claim_report.json','naos/sessions/x:foreign/reports/task_claim_report.json',
                   'other/reports/task_claim_report.json','naos/reports/nested/evidence_pack.json']:
   with self.subTest(relative=relative):
    text=json.dumps(self.report)
    if ':' in relative:
     # NTFS cannot materialize this name; select the pure path operand without IO.
     context=self.context();context['selected'].add(self.root/relative)
    else:
     target=self.write(relative,text);context=self.context([self.source,self.path,target])
    with patch.object(context['proof'],'read',wraps=context['proof'].read) as read:
     self.assertFalse(public.public_claim_label_spans(text,relative,root=self.root,naos_root='naos',context=context));read.assert_not_called()

 def test_multiple_entropy_high_actual_constructor_pairs(self):
  for time,nonce in [('2026-10-10T03:06:20Z','ea7fd3f8db97'),('2026-12-31T23:59:58Z','012345abcdef'),('2026-09-28T17:45:36Z','f0e1d2c3b4a5')]:
   with self.subTest(time=time,nonce=nonce):
    with patch.object(producer.uuid,'uuid4',return_value=SimpleNamespace(hex=nonce+'0'*20)):identifier=producer.claim_id(time,'T-001')
    self.assertGreater(common.shannon_entropy(identifier),4.0)
    record=self.registry['claims'][0];record.update(claimed_at=time,claim_id=identifier)
    self.source.write_text(yaml.safe_dump(self.registry,sort_keys=False), encoding='utf-8')
    report=copy.deepcopy(self.report)
    for bucket in ['claims','active_claims']:report[bucket][0].update(claimed_at=time,claim_id=identifier)
    self.assertEqual(len(self.spans(report)),2)
 def test_selected_default_source_is_required(self):
  self.assertIsNone(self.context([self.path]));self.source.rename(self.root/'naos/custom-claims.yaml');self.assertIsNone(self.context())
 def test_source_mutations_fail_closed(self):
  for key,value in [('task_id','T-002'),('claimed_at','2026-10-10T03:06:21Z'),('claim_id','claim-T-001-2026-10-10T03:06:20Z-012345abcdeZ'),('claim_source','forged'),('task_id','../T-001'),('claimed_at','invalid')]:
   with self.subTest(field=key,value=value):
    doc=copy.deepcopy(self.registry);doc['claims'][0][key]=value;self.source.write_text(yaml.safe_dump(doc,sort_keys=False), encoding='utf-8');self.assertIsNone(self.context())
 def test_unknown_report_nonce_and_defining_fields_stay_scanned(self):
  for key,value in [('task_id','T-002'),('claimed_at','2026-10-10T03:06:21Z'),('claim_id','claim-T-001-2026-10-10T03:06:20Z-012345abcdef'),('claim_source','forged')]:
   with self.subTest(field=key):
    doc=copy.deepcopy(self.report);doc['claims'][0][key]=value;self.assertFalse(self.spans(doc))
 def test_duplicate_schema_alias_nonfinite_source_refused(self):
  original=self.source.read_text(encoding='utf-8')
  for raw in [original+'\nschema: naos.task_claims.v1\n',original.replace('schema: naos.task_claims.v1','schema: forged'),original+'\nextra: &a [1]\ncopy: *a\n',original+'\nextra: .nan\n']:
   with self.subTest(raw=raw[:30]):self.source.write_text(raw, encoding='utf-8');self.assertIsNone(self.context())
  doc=copy.deepcopy(self.registry);doc['claims'].append(copy.deepcopy(doc['claims'][0]));self.source.write_text(yaml.safe_dump(doc), encoding='utf-8');self.assertIsNone(self.context())
 def test_unbound_root_path_schema_and_duplicate_json_refused(self):
  for key,value in [('project_root','foreign'),('naos_root','other'),('claims_file','other'),('schema','forged')]:
   doc=copy.deepcopy(self.report);doc[key]=value;self.assertFalse(self.spans(doc))
  self.assertFalse(self.spans(path='naos/reports/other.json'));self.assertFalse(self.spans(path='naos/sessions/foreign/reports/task_claim_report.json'))
  text=json.dumps(self.report)[:-1]+',"schema":"naos.task_claim_report.v1"}';self.path.write_text(text, encoding='utf-8')
  self.assertFalse(public.public_claim_label_spans(text,'naos/reports/task_claim_report.json',root=self.root,naos_root='naos',context=self.context()))
 def test_reparse_source_is_not_admitted(self):
  original=Path.lstat
  def metadata(path,*a,**kw):
   value=original(path,*a,**kw)
   if path==self.source:
    fields={name:getattr(value,name) for name in dir(value) if name.startswith('st_')};return SimpleNamespace(**{**fields,'st_file_attributes':0x400})
   return value
  with patch.object(Path,'lstat',metadata):self.assertIsNone(self.context())
 def test_neighbor_and_assignment_provider_checks_remain_active(self):
  doc=copy.deepcopy(self.report);doc['neighbor']=doc['claims'][0]['claim_id'];doc['credential']=TOKEN;doc['api_key']=doc['claims'][0]['claim_id'];doc['provider']='sk-proj-'+TOKEN
  self.path.write_text(json.dumps(doc,indent=2), encoding='utf-8');result=self.scan();self.assertGreaterEqual(result['summary']['entropy_matches'],2);self.assertGreaterEqual(result['summary']['regex_matches'],2)
  self.assertEqual(len(self.spans(doc)),2)
 def minimal(self,name):
  schema=json.loads((KIT/'schemas/naos'/f'{name}.schema.json').read_text(encoding='utf-8'))
  def fill(node):
   if '$ref' in node:return fill(schema['$defs'][node['$ref'].split('/')[-1]])
   if 'const' in node:return node['const']
   if 'enum' in node:return node['enum'][0]
   kind=node.get('type','object');kind=kind[0] if isinstance(kind,list) else kind
   if kind=='object':return {key:fill(node.get('properties',{}).get(key,{})) for key in node.get('required',[])}
   return {'array':[],'string':'x','integer':0,'number':0,'boolean':False,'null':None}.get(kind,{})
  branch=schema['oneOf'][0] if 'oneOf' in schema else schema
  doc=fill(branch);doc.update(project_root=str(self.root),naos_root='naos');Draft202012Validator(schema).validate(doc);return doc
 def test_finite_evidence_dashboard_carriers_and_unknown_body(self):
  evidence=self.minimal('evidence_pack');evidence['artifacts']={'task_claim_report':{'data':self.report}}
  dashboard=self.minimal('dashboard_summary');dashboard['inputs']={'task_claims':{'data':self.report},'evidence_pack':{'data':evidence}};dashboard['inputs']['unknown_body']={'data':self.report}
  self.assertEqual(len(self.spans(evidence,'naos/evidence/evidence_pack.json')),2);self.assertEqual(len(self.spans(dashboard,'naos/reports/dashboard_summary.json')),4)
  dashboard['inputs']['evidence_pack']['data']['project_root']='foreign';self.assertEqual(len(self.spans(dashboard,'naos/reports/dashboard_summary.json')),2)
 def test_actual_schema_copy_branch_and_copied_helper_contract(self):
  tree=ast.parse((KIT/'naos_init.py').read_text(encoding='utf-8'));scaffold=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='scaffold_files')
  assignments={n.targets[0].id:n for n in ast.walk(scaffold) if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in {'schema_src','adopter_schema_names'}}
  branch=next(n for n in ast.walk(scaffold) if isinstance(n,ast.If) and ast.unparse(n.test)=='schema_src.is_dir()');preview=self.root/'copied';preview.mkdir()
  namespace={'KIT_DIR':KIT,'preview_dir':preview,'tier':'standard','copy_source':shutil.copy2,'generated':[]}
  exec(compile(ast.Module(body=[assignments['schema_src'],assignments['adopter_schema_names'],branch],type_ignores=[]),'actual_schema_copy','exec'),namespace)
  for name in ['task_claims','task_claim_report']:
   self.assertEqual((preview/'schemas/naos'/f'{name}.schema.json').read_bytes(),(KIT/'schemas/naos'/f'{name}.schema.json').read_bytes())
 def test_strict_size_depth_and_node_limits_preserved(self):
  self.path.write_text(' '*8_388_609, encoding='utf-8')
  self.assertFalse(public.public_claim_label_spans(self.path.read_text(encoding='utf-8'),'naos/reports/task_claim_report.json',root=self.root,naos_root='naos',context=self.context()))
  text=json.dumps(self.report)[:-1]+',"deep":'+'['*65+'0'+']'*65+'}';self.path.write_text(text, encoding='utf-8');self.assertFalse(public.public_claim_label_spans(text,'naos/reports/task_claim_report.json',root=self.root,naos_root='naos',context=self.context()))
  doc=copy.deepcopy(self.report);doc['unknown']=[0]*50_000;self.assertFalse(self.spans(doc))


 def test_unselected_report_stale_bytes_and_changed_registry_refused(self):
  context=self.context([self.source]);self.assertFalse(public.public_claim_label_spans(self.path.read_text(encoding='utf-8'),'naos/reports/task_claim_report.json',root=self.root,naos_root='naos',context=context))
  context=self.context();original=self.path.read_text(encoding='utf-8');self.path.write_text(original+' ', encoding='utf-8')
  self.assertFalse(public.public_claim_label_spans(original,'naos/reports/task_claim_report.json',root=self.root,naos_root='naos',context=context))
  self.path.write_text(original, encoding='utf-8');context=self.context();self.source.write_text(self.source.read_text(encoding='utf-8')+'\n', encoding='utf-8')
  self.assertFalse(public.public_claim_label_spans(original,'naos/reports/task_claim_report.json',root=self.root,naos_root='naos',context=context))
 def test_replaced_schema_cannot_expand_admission(self):
  path=KIT/'schemas/naos/task_claims.schema.json';raw=path.read_bytes()
  try:
   path.write_bytes(b'{}');self.assertIsNone(self.context())
  finally:path.write_bytes(raw)
 def test_copied_runtime_without_upgrade_contract_uses_exact_schemas(self):
  import subprocess
  preview=self.root/'runtime';preview.mkdir();shutil.copytree(KIT/'scripts',preview/'scripts');shutil.copytree(KIT/'schemas',preview/'schemas')
  tree=ast.parse((KIT/'naos_init.py').read_text(encoding='utf-8'));copier=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_copy_generated_script')
  scope={'Path':Path,'shutil':shutil,'SourceOrigins':object};exec(compile(ast.Module(body=[copier],type_ignores=[]),'actual_script_copy','exec'),scope)
  scope['_copy_generated_script'](KIT/'scripts/naos_secret_public_literals.py',preview/'scripts/naos_secret_public_literals.py')
  code="import sys,pathlib;sys.path.insert(0,sys.argv[1]);import naos_secret_public_literals as p;r=pathlib.Path(sys.argv[2]);f=r/'naos/reports/task_claim_report.json';c=p.selected_public_claim_context([r/'naos/task_claims.yaml',f],root=r,naos_root='naos');assert c;assert len(p.public_claim_label_spans(f.read_text(encoding='utf-8'),'naos/reports/task_claim_report.json',root=r,naos_root='naos',context=c))==2;assert not any(n=='upgrade_contract' or n.startswith('upgrade_contract.') for n in sys.modules)"
  result=subprocess.run([sys.executable,'-I','-B','-c',code,str(preview/'scripts'),str(self.root)],capture_output=True,text=True);self.assertEqual(result.returncode,0,result.stderr)

 def test_validated_policy_remapped_exact_carriers_and_fake_default(self):
  from naos_policy import SAFE_FALLBACK_POLICY, deep_merge
  evidence=self.minimal('evidence_pack');evidence['artifacts']={'task_claim_report':{'data':self.report}}
  fake=self.write('naos/reports/evidence_pack.json',json.dumps(evidence));context=self.context([self.source,fake])
  self.assertFalse(public.public_claim_label_spans(fake.read_text(encoding='utf-8'),'naos/reports/evidence_pack.json',root=self.root,naos_root='naos',context=context))
  policy=deep_merge(SAFE_FALLBACK_POLICY,{'paths':{'reports_dir':'stored','evidence_dir':'review','task_claim_report':'claims.json','dashboard_summary_report':'view.json','evidence_pack_report':'pack.json','sessions_root':'runs'}})
  report=copy.deepcopy(self.report);report.update(naos_root='gov',claims_file=str(self.root/'gov/task_claims.yaml'))
  source=self.write('gov/task_claims.yaml',yaml.safe_dump(self.registry,sort_keys=False))
  path=self.write('gov/stored/claims.json',json.dumps(report))
  context=public.selected_public_claim_context([source,path],root=self.root,naos_root='gov',policy=policy)
  self.assertIsNotNone(context);self.assertEqual(context['carriers']['evidence_pack'],'gov/review/pack.json')
  self.assertEqual(len(public.public_claim_label_spans(path.read_text(encoding='utf-8'),'gov/stored/claims.json',root=self.root,naos_root='gov',context=context)),2)
  wrong=self.write('gov/stored/task_claim_report.json',json.dumps(report));context=public.selected_public_claim_context([source,wrong],root=self.root,naos_root='gov',policy=policy)
  self.assertFalse(public.public_claim_label_spans(wrong.read_text(encoding='utf-8'),'gov/stored/task_claim_report.json',root=self.root,naos_root='gov',context=context))
  unsafe=deep_merge(policy,{'paths':{'evidence_dir':'../outside'}})
  self.assertIsNone(public.selected_public_claim_context([source,path],root=self.root,naos_root='gov',policy=unsafe))

 def test_raw_input_identity_preserves_lf_crlf_and_cr_claim_coordinates(self):
  original=self.path.read_bytes();self.assertIn(b'\n',original)
  baseline=self.scan();base_findings=[(f['path'],f.get('line'),f.get('column'),f['status']) for f in baseline['findings']]
  for ending in (b'\r\n',b'\r'):
   raw=original.replace(b'\n',ending);self.path.write_bytes(raw)
   report=self.scan();self.assertEqual(report['summary']['entropy_matches'],baseline['summary']['entropy_matches'])
   self.assertEqual([(f['path'],f.get('line'),f.get('column'),f['status']) for f in report['findings']],base_findings)
   row=next(x for x in report['scans']['input_files'] if x['path']=='naos/reports/task_claim_report.json')
   self.assertEqual(row['sha256'],hashlib.sha256(raw).hexdigest());self.assertEqual(row['size_bytes'],len(raw))

if __name__=='__main__':unittest.main()
