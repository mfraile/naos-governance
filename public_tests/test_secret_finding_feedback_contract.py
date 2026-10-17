"""Legacy content-addressed finding proof stays exact and fail-closed."""
import ast
import copy
import shutil
import subprocess
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

KIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KIT / 'scripts'))
import naos_hygiene_common as common
import naos_secret_public_literals as public
import naos_audit_log as audit
import naos_evidence_classification as classification
import naos_sarif_export as sarif
from naos_policy import SAFE_FALLBACK_POLICY
from jsonschema import Draft202012Validator

TOKEN = 'aB3dE5fG7hI9jK0mN2pQ4rS6tU8vW'
PROVIDER = 'sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'
TIME = '2026-10-10T00:08:26Z'


class SecretFindingFeedback(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='naos-finding-feedback-123-')
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()

    def write(self, name, obj):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(obj if isinstance(obj, str) else json.dumps(obj, indent=2, sort_keys=True), encoding='utf-8')
        return path

    def scan(self):
        report = common.check_secret_hygiene(root=self.root, profile='assured', naos_root='naos', rules={}, rules_path=None, severity='blocking')
        Draft202012Validator(json.loads((KIT / 'schemas/naos/secret_hygiene.schema.json').read_text(encoding='utf-8'))).validate(report)
        return report

    def finding(self):
        item = common.finding(finding_id='secret_hygiene.high_entropy.input.json.1.1', severity='blocking',
            status='high_entropy_literal', message='Review this redacted finding.', path='input.json', line=1,
            extra={'column': 1, 'entropy': 4.5, 'min_length': 20})
        item['id'] = public.secret_finding_id(item)
        return item

    def event(self):
        operand = self.root / ('naos/review-inputs/' + TOKEN + '.json')
        event = audit.build_audit_event(root=self.root, naos_root='naos', profile='assured', policy=SAFE_FALLBACK_POLICY,
            event_type='gate_evaluated', generated_at=TIME, source_report_path=operand,
            source_report={'schema':'naos.gate_evaluation.v1', 'summary':{}}, related_artifacts=[str(operand)],
            generated_by={'operator_id':None,'operator_source':'unknown'})
        path = audit.event_file_path(self.root / 'naos/audit_log', event)
        self.write(path.relative_to(self.root), json.dumps(event, sort_keys=True) + '\n')
        self.assertEqual(audit.recompute_public_audit_event_id(event), event['event_id'])
        return operand, path

    def test_exact_public_derivation_and_full_body_binding(self):
        item = self.finding()
        body = {k:v for k,v in item.items() if k != 'id'}
        raw = json.dumps(body,sort_keys=True,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode('ascii')
        self.assertEqual(item['id'], 'secret_hygiene.sha256.' + hashlib.sha256(b'naos.secret_finding.v1\0'+raw).hexdigest())
        self.assertIn(item['id'], public.public_secret_finding_ids(json.dumps(item)))
        for key, value in [('path',TOKEN),('column',2),('message',TOKEN),('severity','advisory'),('extra',TOKEN)]:
            changed = {**item,key:value}
            self.assertNotIn(item['id'], public.public_secret_finding_ids(json.dumps(changed)))
        for identifier in ['secret_hygiene.sha256.'+'a'*64, 'secret_hygiene.high_entropy.input.json.1.1', TOKEN]:
            self.assertFalse(public.public_secret_finding_ids(json.dumps({**item,'id':identifier})))

    def test_repeated_secret_classification_and_sarif_cycles_are_stable(self):
        operand, event_path = self.event()
        cycles=[]
        secret_path=self.root/'naos/reports/secret_hygiene.json'
        secret_source=next(s for s in sarif.DETERMINISTIC_SOURCES if s.id=='secret_hygiene')
        classifier_source=next(s for s in sarif.DETERMINISTIC_SOURCES if s.id=='evidence_classification')
        for cycle in range(5):
            report=self.scan()
            cycles.append(report['summary']['entropy_matches'])
            self.assertEqual(report['summary']['regex_matches'],0)
            self.assertEqual(report['summary']['coverage_status'],'complete')
            self.assertNotIn(str(operand),json.dumps(report))
            self.assertTrue(all(f['path']==event_path.relative_to(self.root).as_posix() for f in report['findings']))
            self.write(secret_path.relative_to(self.root),report)
            scanned,classified,errors,context,snapshots=classification.classify_findings([secret_path],TIME)
            self.assertFalse(errors)
            self.assertEqual([row['finding_id'] for row in classified],[row['id'] for row in report['findings']])
            diagnostics=[classification.finding('evidence_classification.missing.'+row['finding_id'],'blocking',
                'missing_classification','Finding lacks declared provenance classification.',finding_id=row['finding_id'],
                source_report=row['source_report']) for row in classified]
            classification.assign_diagnostic_ids(diagnostics)
            self.write('naos/reports/evidence_classification_report.json',{'classified_findings':classified,'findings':diagnostics,'source_finding_snapshots':snapshots})
            output,_=sarif.build_sarif(root=self.root,profile='assured',sources_and_findings=[(secret_source,report['findings']),(classifier_source,diagnostics)])
            self.write('naos/reports/sarif_export.json',output)
        self.assertGreater(cycles[0],0)
        self.assertEqual(cycles,[cycles[0]]*5)

    def test_unknown_report_bodies_paths_provider_and_assignment_stay_detected(self):
        item=self.finding()
        # Even a correctly computed forged public ID does not classify its body.
        item['unknown']=TOKEN
        item['path']='naos/reports/'+TOKEN+'.json'
        item['id']=public.secret_finding_id(item)
        self.write('naos/reports/secret_hygiene.json',{'findings':[item],'unknown':TOKEN,
            'password':item['id'],'provider':PROVIDER,'mixed':item['id']+TOKEN})
        report=self.scan()
        self.assertGreaterEqual(report['summary']['entropy_matches'],4)
        self.assertTrue(any(f.get('pattern_id')=='assigned_secret' for f in report['findings']))
        self.assertTrue(any(f.get('pattern_id')=='openai_style_key' for f in report['findings']))
        self.assertNotIn(TOKEN,json.dumps(report))

    def test_sarif_router_preserves_ids_and_only_exact_known_aliases_qualify(self):
        item=self.finding(); values=public.public_secret_finding_ids(json.dumps(item))
        registry={s.id:s for s in sarif.DETERMINISTIC_SOURCES}
        for source_id,record in [('secret_hygiene',item),('self_check',item),('evidence_classification',{'id':'evidence_classification.missing.'+item['id'],'status':'missing_classification'})]:
            alias,_=sarif.build_result(registry[source_id],record,'assured',self.root)
            self.assertIn(alias,values)
            self.assertNotIn(alias+TOKEN,values)
        alias,_=sarif.build_result(registry['secret_hygiene'],{'id':TOKEN},'assured',self.root)
        self.assertNotIn(alias,values)
        routed,_=sarif.route_self_check_findings([(registry['self_check'],[{**item,'_naos_self_check_id':'naos_secret_hygiene'}])],self.root,False)
        self.assertEqual(routed[0][0].id,'secret_hygiene')
        self.assertEqual(routed[0][1][0]['id'],item['id'])

    def test_legacy_reader_schema_and_classification_compatibility(self):
        item=self.finding();item['id']='secret_hygiene.high_entropy.input.json.1.1'
        path=self.write('naos/reports/secret_hygiene.json',{'findings':[item]})
        self.assertEqual(classification.collect_findings({'findings':[item]},path)[0]['id'],item['id'])
        self.assertEqual(classification.classify_findings([path],TIME)[1][0]['finding_id'],item['id'])
        self.assertFalse(public.public_secret_finding_ids(json.dumps(item)))

    def test_duplicate_malformed_nonfinite_depth_node_and_input_bounds_refuse(self):
        item=self.finding(); raw=json.dumps(item)
        for text in [raw[:-1]+',"id":'+json.dumps(item['id'])+'}', raw[:-1]+',"x":NaN}', raw[:-1],
                '['*65+raw+']'*65, json.dumps([item]+[None]*50000), ' '*(8*1024*1024+1)]:
            self.assertFalse(public.public_secret_finding_ids(text))
        self.assertIn(item['id'],public.public_secret_finding_ids(raw+'\n'+json.dumps({'ordinary':'value'})))

    def test_selected_proofs_links_corpus_bound_and_same_file_fallback(self):
        item=self.finding();path=self.write('naos/reports/secret_hygiene.json',{'findings':[item]})
        self.assertIn(item['id'],public.selected_public_secret_finding_literals([path],root=self.root))
        self.assertFalse(public.selected_public_secret_finding_literals([],root=self.root))
        self.assertFalse(public.selected_public_secret_finding_literals([path]*50001,root=self.root))
        link=self.root/'linked.json'
        try:link.symlink_to(path)
        except OSError as error:
            if getattr(error,'winerror',None)!=1314:raise
        else:self.assertFalse(public.selected_public_secret_finding_literals([link],root=self.root))
        huge=json.dumps({'padding':'x'*(7*1024*1024)}).encode()
        with patch.object(public,'_bounded_regular_bytes',return_value=huge):
            self.assertFalse(public.selected_public_secret_finding_literals([path]*5,root=self.root))
        # Corpus exhaustion cannot erase same-file proof or suppress neighbors.
        with patch.object(common,'selected_public_secret_finding_literals',return_value=set()):
            report=self.scan()
        self.assertEqual(report['summary']['entropy_matches'],0)

    def test_actual_copied_helper_verifies_new_body_and_exact_references(self):
        tree=ast.parse((KIT/'naos_init.py').read_text(encoding='utf-8'))
        copier=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_copy_generated_script')
        namespace={'Path':Path,'shutil':shutil,'SourceOrigins':object}
        exec(compile(ast.Module(body=[copier],type_ignores=[]),'actual_installer_copy','exec'),namespace)
        scripts=self.root/'scripts';scripts.mkdir()
        for name in ['naos_secret_public_literals.py',public.CATALOG_FILENAME]:
            namespace['_copy_generated_script'](KIT/'scripts'/name,scripts/name)
        item=self.finding();self.write('input.json',item)
        code="""import sys,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import naos_secret_public_literals as p
root=Path(sys.argv[2]); path=root/'input.json'; item=json.loads(path.read_text(encoding='utf-8'))
assert p.read_catalog()
assert p.secret_finding_id(item)==item['id']
assert item['id'] in p.public_secret_finding_ids(path.read_text(encoding='utf-8'))
assert item['id'] in p.selected_public_secret_finding_literals([path],root=root)
item['path']='changed'
assert not p.public_secret_finding_ids(json.dumps(item))
"""
        result=subprocess.run([sys.executable,'-I','-B','-c',code,str(scripts),str(self.root)],capture_output=True,text=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_catalog_invalid_disables_finding_id_admission(self):
        item=self.finding();self.write('naos/reports/secret_hygiene.json',item)
        with patch.object(common,'load_public_literals',side_effect=public.PublicVocabularyError('invalid')):
            report=self.scan()
        self.assertTrue(any(f['status']=='public_vocabulary_invalid' for f in report['findings']))
        self.assertTrue(any(f['status']=='high_entropy_literal' for f in report['findings']))

if __name__=='__main__':unittest.main()
