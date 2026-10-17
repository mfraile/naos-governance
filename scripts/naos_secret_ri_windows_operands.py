"""Pure saved Windows RI genesis label proof; no native imports or dispatch."""
from __future__ import annotations
import hashlib
import ntpath
import re
import uuid
from pathlib import PureWindowsPath
import naos_secret_managed_operands as m

ENROLLMENT = '.naos/upgrade-v1/windows-repository-intelligence.json'
BOOTSTRAP = '.naos/upgrade-v1/windows-ri-runtime.json'
RUNTIME = '.naos/upgrade-v1/windows-ri-runtime'
ENROLLMENT_SCHEMA = 'naos.repository_intelligence.windows_enrollment.v1'
ENROLLMENT_PLAN_SCHEMA = 'naos.repository_intelligence.windows_enrollment_plan.v1'
BOOTSTRAP_SCHEMA = 'naos.repository_intelligence.windows_bootstrap.v1'
ACTIVE_SCHEMA = 'naos.repository_intelligence.windows_active.v1'
ACTIVATION_RECEIPT_SCHEMA = 'naos.repository_intelligence.windows_activation_receipt.v1'
PREPARATION_SCHEMA = 'naos.repository_intelligence.windows_preparation.v1'
_SUPPORTED_TUPLE = 'windows_x86_64_cpython_3_11_to_3_13_native_handles'
_REVIEWER_ID_PATTERN = '[A-Za-z0-9][A-Za-z0-9._@:/+\\-]{1,127}'
DIRECTORIES = (RUNTIME, RUNTIME+'/operations', RUNTIME+'/preparations', RUNTIME+'/staging',
    RUNTIME+'/receipts', RUNTIME+'/directory-template', m._RI_ROOT, m._RI_ROOT+'/generations')
FILES = (RUNTIME+'/file-template', RUNTIME+'/scope.lock')
ENROLLMENT_IMPLEMENTATION = ('canonical.py','windows_handles.py','repository_intelligence_windows.py','repository_intelligence_windows_enrollment.py')
RUNTIME_IMPLEMENTATION = (*ENROLLMENT_IMPLEMENTATION,'repository_intelligence_windows_runtime.py','windows_backend.py',
    'windows_exchange.py','windows_coordinator.py','windows_operation.py','windows_rename_identity.py','windows_restoring_backend.py')


def _canonical(context, relative, keys):
    value=m._shape(context.object(relative),keys)
    if m.canonical_bytes(value)!=context.read(relative): raise m.OperandRefusal('ri_windows_canonical')
    return value


def _native(value, kind, root, security=None):
    m._shape(value,'schema volume_serial_hex file_id_hex kind security_sha256')
    m._same(value,dict(schema='naos.repository_intelligence.windows_object_identity.v1',kind=kind,
        volume_serial_hex=root['volume_serial_hex']))
    m._hex(value['file_id_hex'],32);m._hex(value['security_sha256'])
    if security is not None: m._same(value,{'security_sha256':security})
    return value


def _implementation(value, keys):
    m._shape(value,' '.join(keys))
    for digest in value.values():m._hex(digest)


def constructor_coordinates(context):
    """One fully linked committed new-enrollment activation only.

    Native identities are parsed as saved witnesses, never observed as current
    ownership. Refresh, rollback, mixed histories and unknown variants refuse.
    All admitted labels require the root-bound manifest and current preimages.
    """
    result={}
    try:
        project=str(context.root); logical=PureWindowsPath(project)
        if not logical.is_absolute() or len(logical.drive)!=2 or logical.drive[1]!=':': raise m.OperandRefusal('ri_windows_root')
        record=_canonical(context,ENROLLMENT,'schema plan plan_sha256 parents record_sha256')
        m._same(record,{'schema':ENROLLMENT_SCHEMA})
        plan=m._shape(record['plan'],'schema owner_kind capability_id scope_id project_id root_identity record_path governed_root initial_governed_root_state ownership_inference activation_authorized private_security_sha256 parents implementation python_minor source_authorization_sha256')
        m._same(plan,dict(schema=ENROLLMENT_PLAN_SCHEMA,owner_kind='naos_windows_repository_intelligence',
            capability_id='CAP-LOCAL-CONTEXT-INDEX',scope_id='repository-intelligence',record_path=ENROLLMENT,
            governed_root=m._RI_ROOT,initial_governed_root_state='absent',ownership_inference='forbidden',activation_authorized=False))
        root=m._windows_directory_identity(plan['root_identity']);security=m._hex(plan['private_security_sha256'])
        label='urn:uuid:'+str(uuid.uuid5(uuid.NAMESPACE_URL,'naos:windows:ri:'+m.canonical_sha256(root)))
        m._same(plan,{'project_id':label});m._hex(plan['source_authorization_sha256'])
        _implementation(plan['implementation'],ENROLLMENT_IMPLEMENTATION)
        if plan['python_minor'] not in ('3.11','3.12','3.13'):raise m.OperandRefusal('ri_windows_python')
        m._shape(plan['parents'],'.naos .naos/upgrade-v1');m._shape(record['parents'],'.naos .naos/upgrade-v1')
        absent=False
        for path in ('.naos','.naos/upgrade-v1'):
            before=plan['parents'][path];after=_native(record['parents'][path],'directory',root,security)
            if before is None:absent=True
            elif absent or before!=after:raise m.OperandRefusal('ri_windows_parent')
        m._same(record,dict(plan_sha256=m.canonical_sha256(plan),record_sha256=m.canonical_sha256({k:v for k,v in record.items() if k!='record_sha256'})))
        bootstrap=_canonical(context,BOOTSTRAP,'schema enrollment directories files')
        m._same(bootstrap,{'schema':BOOTSTRAP_SCHEMA})
        binding=m._shape(bootstrap['enrollment'],'record_sha256 record_identity project_id enrollment_plan_sha256')
        m._same(binding,dict(record_sha256=hashlib.sha256(context.read(ENROLLMENT)).hexdigest(),project_id=label,enrollment_plan_sha256=record['plan_sha256']))
        _native(binding['record_identity'],'file',root,security)
        m._shape(bootstrap['directories'],' '.join(('.naos','.naos/upgrade-v1','.naos/upgrade-v1/state',*DIRECTORIES)))
        m._shape(bootstrap['files'],' '.join(FILES))
        for path,identity in bootstrap['directories'].items():_native(identity,'directory',root,security)
        for path,identity in bootstrap['files'].items():
            _native(identity,'file',root,security)
            if context.read(path)!=b'':raise m.OperandRefusal('ri_windows_template')
        for path in record['parents']:
            if bootstrap['directories'][path]!=record['parents'][path]:raise m.OperandRefusal('ri_windows_parent_link')
        active_path=m._RI_ROOT+'/active.json'
        pointer=_canonical(context,active_path,'schema operation_id request members predecessor receipt_sha256')
        m._same(pointer,dict(schema=ACTIVE_SCHEMA,predecessor=None))
        op=pointer['operation_id']
        if type(op) is not str or re.fullmatch(r'WOP-[0-9a-f]{16}',op) is None:raise m.OperandRefusal('ri_windows_operation')
        request=m._shape(pointer['request'],'public_plan_sha256 bundle_sha256 generation_id authorization')
        m._hex(request['public_plan_sha256']);m._hex(request['bundle_sha256'])
        gid=request['generation_id']
        if type(gid) is not str or re.fullmatch(r'RI-[0-9a-f]{24}',gid) is None:raise m.OperandRefusal('ri_windows_generation')
        generation=m._RI_ROOT+'/generations/'+gid;stage=RUNTIME+'/staging/'+op
        members=pointer['members']
        if type(members) is not dict or not 3<=len(members)<=32 or len({p.casefold() for p in members})!=len(members):raise m.OperandRefusal('ri_windows_members')
        raw_members={}
        for name,digest in members.items():
            if len(m._windows_relative_path(name))!=1 or name.casefold() in {'active.json','activation-receipt.json','previous-active.json'}:raise m.OperandRefusal('ri_windows_member')
            m._hex(digest);raw=context.read(generation+'/'+name)
            if hashlib.sha256(raw).hexdigest()!=digest:raise m.OperandRefusal('ri_windows_preimage')
            raw_members[name]=raw
        receipt_path=RUNTIME+'/receipts/'+op+'.json'
        receipt=_canonical(context,receipt_path,'schema operation_id request members predecessor')
        if receipt!={**{k:v for k,v in pointer.items() if k not in {'schema','receipt_sha256'}},'schema':ACTIVATION_RECEIPT_SCHEMA}:raise m.OperandRefusal('ri_windows_receipt')
        m._same(pointer,{'receipt_sha256':hashlib.sha256(context.read(receipt_path)).hexdigest()})
        preparation_path=RUNTIME+'/preparations/'+op+'.json'
        preparation=_canonical(context,preparation_path,'schema operation_id request bootstrap_sha256 implementation predecessor directories members publications pointer_sha256 receipt_sha256')
        m._same(preparation,dict(schema=PREPARATION_SCHEMA,operation_id=op,request=request,
            bootstrap_sha256=m.canonical_sha256(bootstrap),predecessor=None,members=members,
            pointer_sha256=hashlib.sha256(context.read(active_path)).hexdigest(),receipt_sha256=pointer['receipt_sha256']))
        _implementation(preparation['implementation'],RUNTIME_IMPLEMENTATION)
        m._shape(preparation['directories'],' '.join((stage,generation)))
        for identity in preparation['directories'].values():_native(identity,'directory',root,security)
        names=sorted(members);slots={}
        payloads=[]
        for index,name in enumerate(names):
            slots['content-'+str(index)]=generation+'/'+name;slots['staged-'+str(index)]=stage+'/'+name
            payloads.append(('content','content-'+str(index),'staged-'+str(index),raw_members[name]))
        slots.update(receipt=receipt_path,**{'staged-receipt':stage+'/activation-receipt.json','pointer':active_path,'staged-pointer':stage+'/active.json'})
        payloads += [('evidence','receipt','staged-receipt',context.read(receipt_path)),('manifest','pointer','staged-pointer',context.read(active_path))]
        publications=m._list(preparation['publications'])
        if len(publications)!=len(payloads):raise m.OperandRefusal('ri_windows_publications')
        identities=set()
        for row,(role,target,staged,raw) in zip(publications,payloads):
            m._shape(row,'role kind target staged after');m._same(row,dict(role=role,kind='create',target=target,staged=staged))
            identity=m._windows_v2_publication_identity(row['after'],root,raw)
            if identity in identities:raise m.OperandRefusal('ri_windows_alias')
            identities.add(identity)
        operation=RUNTIME+'/operations/'+op
        saved,_=m._envelope(context,operation+'/plan.json','naos.upgrade.windows_operation_plan.v2','schema operation_id plan plan_sha256')
        m._same(saved,dict(operation_id=op,plan=preparation,plan_sha256=m.canonical_sha256(preparation)))
        intent,_=m._envelope(context,operation+'/intent.json','naos.upgrade.windows_operation.v2','schema failure_model operation_id plan_sha256 slot_paths publications runtime_parent_id scope_lock_id transaction_directory_id lock_id')
        expected_slots={key:ntpath.join(project,*value.split('/')) for key,value in slots.items()}
        m._same(intent,dict(failure_model='application_crash_v1',operation_id=op,plan_sha256=saved['plan_sha256'],slot_paths=expected_slots,publications=publications))
        for field in ('runtime_parent_id','scope_lock_id','transaction_directory_id','lock_id'):m._windows_directory_identity(intent[field])
        for field,path,kind in [('runtime_parent_id',RUNTIME+'/operations','directory'),('scope_lock_id',RUNTIME+'/scope.lock','file')]:
            source=bootstrap['directories' if kind=='directory' else 'files'][path]
            m._same(intent[field],{k:source[k] for k in ('volume_serial_hex','file_id_hex')})
        intent_sha=hashlib.sha256(context.read(operation+'/intent.json')).hexdigest()
        expected_marker=dict(schema='naos.upgrade.windows_operation.v2',failure_model='application_crash_v1',intent_sha256=intent_sha,direction='forward',topology='committed')
        marker,_=m._envelope(context,operation+'/committed.json',expected_marker['schema'],'schema failure_model intent_sha256 direction topology')
        if marker!=expected_marker:raise m.OperandRefusal('ri_windows_terminal')
        for index in range(1,len(publications)+1):
            checkpoint,_=m._envelope(context,operation+'/forward-'+f'{index:06d}'+'.json',expected_marker['schema'],'schema failure_model intent_sha256 direction topology')
            if checkpoint!={**expected_marker,'topology':'step:'+str(index)}:raise m.OperandRefusal('ri_windows_checkpoint')
        memberships = {
            RUNTIME:{'operations','preparations','staging','receipts','directory-template','file-template','scope.lock'},
            RUNTIME+'/directory-template':set(),m._RI_ROOT:{'active.json','generations'},
            RUNTIME+'/preparations':{op+'.json'}, RUNTIME+'/receipts':{op+'.json'},
            RUNTIME+'/operations':{op}, RUNTIME+'/staging':{op}, stage:set(),
            m._RI_ROOT+'/generations':{gid}, generation:set(members),
            operation:{'lock','plan.json','intent.json','committed.json'}|{'forward-'+f'{index:06d}'+'.json' for index in range(1,len(publications)+1)}}
        for relative,names in memberships.items():
            if set(context.entries(relative)) != names:raise m.OperandRefusal('ri_windows_history_membership')
        manifest=m._ri_object(context,generation+'/manifest.json','repository_intelligence_manifest');control=manifest['control']
        validation=m._ri_object(context,generation+'/validation_receipt.json','repository_intelligence_validation');vc=validation['control']
        inventory=m._ri_object(context,generation+'/inventory.json','repository_intelligence_inventory')
        gate=dict(status='valid',activation_eligible=True,backend='windows-ri-enrollment.v1',governed_root=m._RI_ROOT,
            record_path=ENROLLMENT,ownership_inference='forbidden',refusal=None,native_enrollment_plan=None,
            enrollment=dict(project_id=label,native_plan_sha256=record['plan_sha256'],record_bytes_sha256=binding['record_sha256'],record_identity=binding['record_identity']))
        m._same(control,dict(project_root=project,generation_id=gid,provenance_gate=gate,validation_receipt_sha256=validation['receipt_sha256']))
        m._same(manifest,dict(status='validated',manifest_sha256=m.canonical_sha256(control)))
        m._same(validation,dict(status='validated_generation',receipt_sha256=m.canonical_sha256(vc)))
        m._same(vc,{key:control[key] for key in ('generation_id','generation_content_sha256','effective_source_sha256','profile','purpose','component_mode','runtime','implementation','provenance_gate')})
        identity={key:control[key] for key in ('project_root','profile','purpose','component_mode','effective_source_sha256','rules','runtime','implementation','provenance_gate','components','graph_model_sha256','ongoing_use_scope')}
        identity['capability_id']='CAP-LOCAL-CONTEXT-INDEX'
        m._same(control,{'generation_content_sha256':m.canonical_sha256(identity)})
        if gid!='RI-'+control['generation_content_sha256'][:24]:raise m.OperandRefusal('ri_windows_generation_label')
        authorization=m._shape(request['authorization'],'schema profile naos_root profile_gate reviewer effective_source_sha256 rules_sha256 manifest_sha256 generation_content_sha256')
        m._same(authorization,dict(schema='naos.repository_intelligence.windows_authorization.v1',profile=control['profile'],
            effective_source_sha256=control['effective_source_sha256'],rules_sha256=control['rules']['sha256'],manifest_sha256=manifest['manifest_sha256'],generation_content_sha256=control['generation_content_sha256']))
        profile=control['profile'];named=profile in {'standard','assured'}
        profile_gate=dict(profile=profile,digest_confirmation_required=True,named_review_required=named,
            reviewer_identity_is_attribution_not_authentication=True,maturity_does_not_authorize_component_selection=True)
        if profile not in {'quickstart','lite','standard','assured'} or authorization['profile_gate']!=profile_gate:
            raise m.OperandRefusal('ri_windows_profile')
        reviewer=m._shape(authorization['reviewer'],'reviewer_id required identity_status authentication_status')
        reviewer_id=reviewer['reviewer_id']
        if (reviewer_id is not None and (type(reviewer_id) is not str or re.fullmatch(_REVIEWER_ID_PATTERN,reviewer_id) is None)) or (named and not reviewer_id):
            raise m.OperandRefusal('ri_windows_reviewer')
        m._same(reviewer,dict(required=named,identity_status='declared_attribution' if reviewer_id else 'not_required',authentication_status='not_claimed'))
        if type(authorization['naos_root']) is not str or not m._safe_component_path(authorization['naos_root']):raise m.OperandRefusal('ri_windows_naos_root')
        implementation=m._shape(control['implementation'],'contract_version engine_sha256 local_context_index_sha256 canonical_adapter_sha256 graphml_writer sqlite_serializer windows_ri_enrollment windows_ri_runtime windows_ri_public')
        m._same(implementation,dict(contract_version=1,graphml_writer='networkx.write_graphml_xml',sqlite_serializer='python_stdlib_sqlite3',
            windows_ri_enrollment=plan['implementation'],windows_ri_runtime=preparation['implementation']))
        for key in ('engine_sha256','local_context_index_sha256','canonical_adapter_sha256','windows_ri_public'):m._hex(implementation[key])
        source_authorization=dict(project_root=project,profile=profile,profile_gate=profile_gate,naos_root=authorization['naos_root'],
            purpose=control['purpose'],component_mode=control['component_mode'],rules_sha256=control['rules']['sha256'],
            effective_source_sha256=control['effective_source_sha256'],runtime=control['runtime'],components=control['components'],implementation=control['implementation'])
        m._same(plan,dict(source_authorization_sha256=m.canonical_sha256(source_authorization)))
        listed={row['path']:row for row in m._list(control['files'])}
        if len(listed)!=len(control['files']) or set(listed)!=set(members)-{'manifest.json'}:raise m.OperandRefusal('ri_windows_file_inventory')
        for name,row in listed.items():
            m._shape(row,'path sha256 size_bytes');m._same(row,dict(sha256=members[name],size_bytes=len(raw_members[name])))
        if listed[control['rules_snapshot']]['sha256']!=control['rules']['sha256']:raise m.OperandRefusal('ri_windows_rules')
        m._same(inventory,dict(project_root=project,generation_id=gid,effective_source_sha256=control['effective_source_sha256']))
        result[ENROLLMENT]={('plan',key):plan[key] for key in ('project_id','record_path','governed_root')}
        result[BOOTSTRAP]={('enrollment','project_id'):label}
        for field in ('directories','files'):
            result[BOOTSTRAP].update({(field,('object_key',path)):path for path in bootstrap[field]})
        result[active_path]={('operation_id',):op}
        result[receipt_path]={('operation_id',):op}
        result[preparation_path]={('operation_id',):op}
        result[operation+'/plan.json']={('body','operation_id'):op,('body','plan','operation_id'):op}
        for path in (stage,generation):
            result[preparation_path][('directories',('object_key',path))]=path
            result[operation+'/plan.json'][('body','plan','directories',('object_key',path))]=path
        result[operation+'/intent.json']={('body','operation_id'):op,**{('body','slot_paths',key):value for key,value in expected_slots.items()}}
        for relative in (generation+'/manifest.json',generation+'/validation_receipt.json'):
            result[relative]={('control','provenance_gate','enrollment','project_id'):label}
            platform=control['runtime']['platform'];expected=_SUPPORTED_TUPLE
            if (platform.get('system')=='Windows' and platform.get('machine') in {'amd64','x86_64'} and platform.get('implementation')=='CPython'
                    and platform.get('supported_tuple')==expected and platform.get('supported_for_apply') is True
                    and type(platform.get('python')) is str and re.fullmatch(r'3\.1[123]\.[0-9]+',platform['python']) is not None):
                result[relative][('control','runtime','platform','supported_tuple')]=expected
        result[generation+'/inventory.json']=m._ri_reference_coordinates(context,inventory)
        # Export only exact operation records already proved above. Markers
        # have no label coordinates themselves, but their inventory echoes do.
        operation_records={operation+'/plan.json',operation+'/intent.json',operation+'/committed.json'}
        operation_records.update(operation+'/forward-'+f'{index:06d}'+'.json'
                                 for index in range(1,len(publications)+1))
        # The operation lock is created from the already proved empty template.
        # Its exact name is in the closed operation membership, but membership
        # alone cannot replace a guarded physical preimage read.
        lock=operation+'/lock'
        if context.read(lock)!=b'':raise m.OperandRefusal('ri_windows_operation_lock')
        operands=(set(result)|set(DIRECTORIES)|set(FILES)|{generation,stage,operation,lock}
                  |{generation+'/'+name for name in members}|operation_records)
        if len(operands)>m.MAX_IDENTITIES:raise m.OperandRefusal('ri_windows_identities')
        context.verify_cached()
        context.operands[m._RI_ROOT]=operands
    except (OSError,UnicodeError,ValueError,TypeError,KeyError,RecursionError,RuntimeError):result={}
    context.constructor_coordinates[m._RI_ROOT]=result
    return result
