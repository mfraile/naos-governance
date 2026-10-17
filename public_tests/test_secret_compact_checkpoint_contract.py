"""Pure committed compact sidecar admission; no native upgrade operations."""
import sys, os, copy, json, importlib.util, unittest
from pathlib import Path
REPO = Path(__file__).resolve().parents[1]
# The scratch review runner may reuse immutable existing fixture resources.
ROOT = Path(os.environ.get('NAOS_TEST_FIXTURE_SOURCE', str(REPO))).resolve()
OUT = REPO
sys.path.insert(0, str(REPO)); sys.path.insert(0, str(REPO/'scripts'))
sys.path.append(str(ROOT)); sys.path.append(str(ROOT/'scripts'))
import naos_secret_managed_operands as managed
from upgrade_contract import transaction as tx
spec=importlib.util.spec_from_file_location('secret_inventory_fixtures',ROOT/'public_tests/test_secret_managed_inventory_contract.py');inv=importlib.util.module_from_spec(spec);spec.loader.exec_module(inv)
sys.modules['test_secret_managed_inventory_contract']=inv
spec=importlib.util.spec_from_file_location('secret_brownfield_fixtures',ROOT/'public_tests/test_secret_brownfield_control_contract.py');brown=importlib.util.module_from_spec(spec);spec.loader.exec_module(brown)

class CompactSecretTests(unittest.TestCase):
 def setUp(self):
  self.fixture=inv.ManagedInventoryTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
  # The exact existing content-aware committed chain fixture, including its assertions.
  self.fixture.test_legacy_v2_exact_record_constructors()
  root=self.fixture.root
  manifest=managed._strict_object((root/self.fixture.relative/'state/manifest.json').read_bytes())
  self.transaction=manifest['transactions'][-1];self.plan=copy.deepcopy(self.transaction['plan'])
  self.tid=self.transaction['transaction_id'];self.journal_path=self.fixture.relative+'/transactions/'+self.tid+'/journal.json'
  self.plan_path=self.journal_path.rsplit('/',1)[0]+'/plan.json'
  # The old test ends with a deliberate base tamper; restore the known fixture bytes.
  (root/self.fixture.relative/'state/bases'/self.plan['paths'][0]['after']['sha256']).write_bytes(b'updated')
  journal=managed._strict_object((root/self.journal_path).read_bytes())
  self.install(journal)
 def install(self,journal):
  raw=managed.canonical_bytes(journal['plan'])+b'\n'
  body={key:value for key,value in journal.items() if key not in {'plan','integrity'}}
  body.update(schema=tx._COMPACT_JOURNAL_SCHEMA,plan_ref=tx._compact_plan_reference(raw))
  self.compact=tx._with_sha256_integrity(body)
  self.fixture.write(self.journal_path,self.compact)
  (self.fixture.root/self.plan_path).write_bytes(raw)
 def test_exact_committed_sidecar_is_managed_operand(self):
  proved=managed._legacy_operands(managed.ProofBudget(self.fixture.root))
  self.assertIn(self.plan_path,proved)
  _,spans,diag=self.fixture.spans(self.fixture.report([self.plan_path,self.journal_path]))
  self.assertEqual(len(spans),6,diag)
 def test_missing_foreign_changed_uncommitted_sidecar_refuse_admission(self):
  raw=(self.fixture.root/self.plan_path).read_bytes()
  for case in ['missing','edited','foreign_ref','uncommitted']:
   (self.fixture.root/self.plan_path).write_bytes(raw);self.fixture.write(self.journal_path,self.compact)
   if case=='missing':(self.fixture.root/self.plan_path).unlink()
   elif case=='edited':(self.fixture.root/self.plan_path).write_bytes(raw+b' ')
   else:
    bad=copy.deepcopy(self.compact);bad.pop('integrity')
    if case=='foreign_ref':bad['plan_ref']['name']='../plan.json'
    else:bad['state']='APPLYING'
    self.fixture.write(self.journal_path,tx._with_sha256_integrity(bad))
   with self.subTest(case=case),self.assertRaises((managed.OperandRefusal,OSError)):
    managed._legacy_operands(managed.ProofBudget(self.fixture.root))
 def test_same_sidecar_custody_change_is_sticky(self):
  context=managed.ProofBudget(self.fixture.root);managed._legacy_operands(context)
  path=self.fixture.root/self.plan_path;raw=path.read_bytes();path.write_bytes(raw+b' ')
  with self.assertRaises(managed.OperandRefusal):context.verify_cached()
 def test_secret_in_valid_sidecar_remains_a_finding(self):
  # Rebuild the full committed chain after adding an authored secret to supported request_inputs.
  manifest=managed._strict_object((self.fixture.root/self.fixture.relative/'state/manifest.json').read_bytes());manifest.pop('integrity')
  plan=copy.deepcopy(self.plan);plan.pop('plan_sha256');token='sk-'+'aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'
  plan['request_inputs']={'authored_secret':token};plan['plan_sha256']=managed.canonical_sha256(plan)
  tid='MC-'+plan['plan_sha256'][:16]+'-89abcdef'
  receipt_path=self.fixture.relative+'/state/receipts/'+self.tid+'.json';receipt=managed._strict_object((self.fixture.root/receipt_path).read_bytes());receipt.pop('integrity');receipt.update(transaction_id=tid,plan_sha256=plan['plan_sha256']);receipt=tx._with_sha256_integrity(receipt)
  old_tid=self.tid;self.tid=tid;self.journal_path=self.fixture.relative+'/transactions/'+tid+'/journal.json';self.plan_path=self.journal_path.rsplit('/',1)[0]+'/plan.json'
  self.fixture.write(self.fixture.relative+'/state/receipts/'+tid+'.json',receipt)
  manifest['transactions'][-1]={'transaction_id':tid,'plan':plan,'receipt_sha256':managed.canonical_sha256(receipt)};manifest.update(last_transaction_id=tid,last_plan_sha256=plan['plan_sha256'])
  manifest['entries'][0].update(last_mutated_by_transaction=tid,receipt_sha256=managed.canonical_sha256(receipt));self.fixture.write(self.fixture.relative+'/state/manifest.json',tx._with_sha256_integrity(manifest))
  journal={'schema':'naos.upgrade.content_transaction.v2','minimum_recovery_naos_version':'1.1.0','transaction_id':tid,'plan':plan,'state':'COMMITTED','applied_actions':[],'created_directories':[],'pending_action':None,'detail':None}
  self.install(journal)
  self.assertIn(self.plan_path,managed._legacy_operands(managed.ProofBudget(self.fixture.root)))
  result=inv.common.check_secret_hygiene(root=self.fixture.root,profile='standard',naos_root='naos',rules={'scan_roots':[self.plan_path],'include_root_files':False},rules_path=None,severity='required')
  self.assertGreater(result['summary']['regex_matches'],0,result['findings'])

class CompactCoordinateTests(unittest.TestCase):
 def setUp(self):
  self.controls=brown.BrownfieldControlTests();self.controls.setUp();self.addCleanup(self.controls.doCleanups)
  self.fixture=self.controls.fixture
  self.fixture.scope=managed._strict_object((self.fixture.root/self.fixture.relative/'scope.json').read_bytes())
 def install_chain(self,requests):
  f=self.fixture;old=f.plan['paths'][0];after={**old['source'],'size':7,'sha256':managed.hashlib.sha256(b'updated').hexdigest()}
  plan={'schema':'naos.upgrade.content_aware_plan.v2','operation':'profile_transition','status':'ready',
   'project':{'root_binding':str(f.root),'project_id':f.scope['project_id'],'scope_integrity_sha3_512':f.scope['integrity']['value']},
   'profile':{},'request_inputs':requests,'creation_identity':f.plan['creation_identity'],
   'source_policy':{'active':{'binding_sha256':'3'*64},'provenance':{'binding_sha256':'3'*64}},'manifest':{},
   'paths':[{'path':old['path'],'base':None,'before':old['source'],'after':{'presence':'present',**after},
    'base_metadata':None,'before_metadata':None,'after_metadata':old['source_metadata'],
    'content_state':'PROPOSE_UPDATE_FROM_UPSTREAM','ownership':{'after':'kit_owned_derived'},'source_policy':{},'preservation':{},
    'action':'UPDATE_FROM_UPSTREAM','mutation':{'eligible':True,'kind':'replace'},'metadata_status':{},'ancestor_identities':[]}],
   'ownership_inference':'forbidden','planning_mutated_target':False,'apply_requires_separate_digest_bound_invocation':True,
   'selected_paths':[old['path']],'operation_inputs':{},'checks':[]}
  plan['plan_sha256']=managed.canonical_sha256(plan);tid='MC-'+plan['plan_sha256'][:16]+'-89abcdef';item=plan['paths'][0]
  action={key:item[key] for key in ('path','before','after','before_metadata','after_metadata')}
  action.update(kind='replace',installed_metadata={},backup_metadata={},base_blob={'path':after['sha256'],'sha256':after['sha256']},publication_adapter='darwin_rename_swap')
  receipt=tx._with_sha256_integrity({'schema':'naos.upgrade.managed_content_receipt.v2','minimum_recovery_naos_version':'1.1.0',
   'project_id':f.scope['project_id'],'scope_integrity_sha3_512':f.scope['integrity']['value'],'source_policy_sha256':'3'*64,
   'transaction_id':tid,'plan_sha256':plan['plan_sha256'],'status':'COMMITTED','actions':[action],'replacement_performed':True})
  manifest=copy.deepcopy(f.manifest);manifest.pop('integrity');manifest.update(schema='naos.upgrade.managed_content_manifest.v2',minimum_recovery_naos_version='1.1.0',last_transaction_id=tid,last_plan_sha256=plan['plan_sha256'])
  manifest['transactions'].append({'transaction_id':tid,'plan':plan,'receipt_sha256':managed.canonical_sha256(receipt)})
  manifest['entries'][0].update(base=after,base_blob={'path':after['sha256'],'sha256':after['sha256']},last_mutated_by_transaction=tid,receipt_sha256=managed.canonical_sha256(receipt))
  f.write(f.relative+'/state/manifest.json',tx._with_sha256_integrity(manifest));f.write(f.relative+'/state/receipts/'+tid+'.json',receipt)
  (f.root/f.relative/'state/bases'/after['sha256']).write_bytes(b'updated')
  self.journal_path=f.relative+'/transactions/'+tid+'/journal.json';self.plan_path=self.journal_path.rsplit('/',1)[0]+'/plan.json'
  raw=managed.canonical_bytes(plan)+b'\n';(f.root/self.plan_path).parent.mkdir(parents=True,exist_ok=True);(f.root/self.plan_path).write_bytes(raw)
  f.write(self.journal_path,tx._with_sha256_integrity(tx._compact_checkpoint_body(tid,tx._compact_plan_reference(raw),'COMMITTED',[],[])))
 def test_project_constructor_uuid_is_admitted_only_at_actual_sidecar_coordinate(self):
  self.install_chain({})
  context=managed.ProofBudget(self.fixture.root)
  coords=managed._legacy_constructor_coordinates(context)
  self.assertEqual(coords[self.plan_path][('project','project_id')],self.controls.owner['project_id'])
  self.assertNotIn(self.journal_path,coords)
  text,spans,diag=self.fixture.raw_control_spans(self.plan_path)
  parser=managed._OffsetJSON(text,exact_control_coordinates=[('project','project_id')]);parser.parse()
  start,end,value=parser.strings[('project','project_id')]
  self.assertIn((start,end),spans,diag)
 def test_compact_ri_echo_uses_request_inputs_and_sidecar_coordinate(self):
  self.controls.rebuild_ri(high_entropy_generation=True)
  generation={field:self.controls.active['control'][field] for field in managed._RI_GENERATION_BINDING_FIELDS}
  self.install_chain({'repository_intelligence':{'lifecycle_status':'validated_current','recommendation':'use_validated_current_generation',
    'binding':{'binding_type':'validated_generation','generation':generation}}})
  coords=managed._legacy_constructor_coordinates(managed.ProofBudget(self.fixture.root))
  for field in ['transaction_id','generation_id']:
   key=('request_inputs','repository_intelligence','binding','generation',field)
   self.assertEqual(coords[self.plan_path][key],generation[field])
  self.assertNotIn(self.journal_path,coords)
  text,spans,diag=self.fixture.raw_control_spans(self.plan_path)
  key=('request_inputs','repository_intelligence','binding','generation','generation_id')
  parser=managed._OffsetJSON(text,exact_control_coordinates=[key]);parser.parse();start,end,value=parser.strings[key]
  self.assertIn((start,end),spans,diag)
 def test_compact_ri_mismatched_binding_does_not_gain_coordinate_admission(self):
  self.controls.rebuild_ri(high_entropy_generation=True)
  generation={field:self.controls.active['control'][field] for field in managed._RI_GENERATION_BINDING_FIELDS};generation['generation_id']='RI-'+'a'*24
  self.install_chain({'repository_intelligence':{'lifecycle_status':'validated_current','binding':{'binding_type':'validated_generation','generation':generation}}})
  coords=managed._legacy_constructor_coordinates(managed.ProofBudget(self.fixture.root))
  self.assertNotIn(('request_inputs','repository_intelligence','binding','generation','generation_id'),coords[self.plan_path])

if __name__=='__main__':
 suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(CompactSecretTests),unittest.defaultTestLoader.loadTestsFromTestCase(CompactCoordinateTests)])
 # Existing relevant actual pure consumer checks, no native upgrade implementation test.
 for name in ['test_legacy_v2_exact_record_constructors','test_committed_control_ids_exact_slots_and_same_value_body_negative','test_control_ids_require_exact_bytes_chain_and_bound_record_path']:
  suite.addTest(inv.ManagedInventoryTests(name))
 for name in ['test_current_ri_generation_exact_complete_consumer_echo','test_current_ri_transaction_exact_five_control_coordinates']:
  suite.addTest(brown.BrownfieldControlTests(name))
 result=unittest.TextTestRunner(verbosity=2).run(suite)
 sys.exit(not result.wasSuccessful())
