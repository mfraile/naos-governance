"""Finite dependency refresh regression with mocked subprocess collection."""
import importlib.util,json,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
candidate=load('current_ci_readiness_temporal_test',ROOT/'scripts/naos_ci_readiness.py')
def exercise(runner,profile='standard',*,proof='resolved',gap=False,final_failure=False,stale_guard=True,unchanged_gate=False):
 with tempfile.TemporaryDirectory() as directory:
  root=Path(directory);(root/'naos').mkdir();policy=runner.load_policy(None,'naos',root); outputs=runner.output_paths(root,'naos',policy)
  for key in ('dashboard_summary_report','secure_coding_reporting_report','evidence_pack_report'):
   outputs[key].parent.mkdir(parents=True,exist_ok=True);outputs[key].write_text(json.dumps({'secure_coding_reporting':{}}))
  state={'f1':False,'refreshed':False}; calls=[]
  def execute(argv,**kwargs):
   calls.append(argv);code=0
   if 'self-check' in argv and '--capture-dependency-inputs' not in argv and '--finalize-dependencies' not in argv:state['f1']=True
   if len(argv)>2 and argv[2] in {'gate-status','gate-evaluate'}:
    output=Path(argv[argv.index('--output')+1]);output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps({'schema':'naos.gate_status.v1','source_generation':'F1' if state['f1'] else 'acquisition','invocation':0 if unchanged_gate else len(calls)}))
    if state['f1']:state['refreshed']=True
    elif argv[2]=='gate-evaluate':code=1 # Original adverse acquisition must remain visible.
   if '--finalize-dependencies' in argv:
    code=int(final_failure or (stale_guard and not state['refreshed']))
   return SimpleNamespace(returncode=code)
  def projection(*args):
   return {'readiness':'unresolved','required_readiness':'unresolved' if gap else 'ready','reason_codes':['selected_gate_unresolved'],'gates':[{'id':'G7','status':'advisory_missing','severity':'advisory','readiness':'unresolved'}]}
  with patch.object(runner,'PRODUCERS',()),patch.object(runner,'CONSUMERS',()),patch.object(runner.subprocess,'run',side_effect=execute),patch.object(runner,'project_gate_readiness',side_effect=projection),patch.object(runner,'_assured_maturity_cycle'),patch.object(runner,'_reporting_source_binding',return_value='fixture-binding'),patch('naos_self_check_dependency_resolution.verify_published_resolution',return_value={'status':proof}):
   code=runner.run_chain(root,profile,'naos',finalize_dependencies=True)
  return code,json.loads((root/'naos/reports/ci_readiness.json').read_text())
class TemporalTests(unittest.TestCase):
 def test_standard_refreshes_changed_f1_dependency_before_proof(self):
  new,r=exercise(candidate);self.assertEqual(new,0)
  cmds=r['commands'];proof=next(i for i,x in enumerate(cmds) if '--finalize-dependencies' in x['argv']);f1=next(i for i,x in enumerate(cmds) if 'self-check' in x['argv'] and '--capture-dependency-inputs' not in x['argv'] and '--finalize-dependencies' not in x['argv'])
  refresh=[x for x in cmds[f1+1:proof] if any(k in x['argv'] for k in ('gate-status','gate-evaluate'))];self.assertEqual(len(refresh),2);self.assertTrue(all(x['phase']=='acquisition' for x in refresh));self.assertEqual(r['acquisition_status'],'failed');self.assertTrue(any(x['returncode']==1 for x in cmds));self.assertTrue(r['output_checks']['complete_dependency_resolution'])
 def test_zero_finalizer_exit_cannot_substitute_for_independent_proof(self):
  new,r=exercise(candidate,proof='unresolved');self.assertEqual(new,1);self.assertFalse(r['output_checks']['complete_dependency_resolution'])
 def test_real_required_gap_and_failed_finalizer_remain_failures(self):
  for kw in ({'gap':True},{'final_failure':True}):
   with self.subTest(kw=kw):self.assertEqual(exercise(candidate,**kw)[0],1)
 def test_unchanged_canonical_gate_bytes_remain_rejected(self):
  code,r=exercise(candidate,unchanged_gate=True);self.assertEqual(code,1);self.assertTrue(any(x.get('gate_publication',{}).get('status')=='unchanged_invalidated' for x in r['commands']))
 def test_existing_lite_and_assured_semantics_remain(self):
  self.assertEqual(exercise(candidate,'lite')[0],0);self.assertEqual(exercise(candidate,'assured')[0],1)
if __name__=='__main__':unittest.main()
