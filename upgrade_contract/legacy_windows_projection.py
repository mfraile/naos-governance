"""Schema-directed Windows historical replay derivative; no native authority."""
from __future__ import annotations
import base64
import copy
import hashlib

from . import legacy_migration_records as migration
from . import legacy_windows_terminal as terminal
from . import windows_provenance as provenance
from . import windows_operation as operation
from . import windows_runtime as runtime
from . import windows_runtime_directories as directories
from .windows_coordinator import _decode, _envelope
from .windows_observation import _parts, _relative_parts
from .canonical import canonical_bytes, canonical_sha256, loads_strict_json

SCHEMA = 'naos.upgrade.derived_windows_replay.v1'
LOCATION_SCHEMA = 'naos.upgrade.replay_location.v1'
COMPONENT_SCHEMA = 'naos.upgrade.replay_component.v1'
_SCHEMAS = {provenance.ROOT_SCHEMA, provenance.OWNER_SCHEMA, provenance.MANIFEST_SCHEMA,
    provenance.BASE_SCHEMA, provenance.RECEIPT_SCHEMA, operation.SCHEMA, operation.SCHEMA_V2,
    operation.PLAN_SCHEMA, operation.PLAN_SCHEMA_V2, runtime.SCHEMA, directories.SCHEMA,
    directories.CHECKPOINT_SCHEMA, 'naos.upgrade.windows_content_observation.v1'}
# Paths are relative to each declared schema record. An embedded declared
# schema resets the path, so reference-name coincidences are never adapters.
_REFS = {
 provenance.ROOT_SCHEMA: {('enrollment_plan_sha256',)},
 provenance.OWNER_SCHEMA: {('root_enrollment_sha256',)},
 provenance.MANIFEST_SCHEMA: {('owner_sha256',), ('receipts','*','sha256'), ('entries','*','receipt_sha256')},
 provenance.RECEIPT_SCHEMA: {('owner_sha256',), ('previous_receipt_sha256',), ('plan_sha256',)},
 runtime.SCHEMA: {('expected_owner_sha256',), ('expected_manifest_sha256',)},
 operation.PLAN_SCHEMA: {('plan_sha256',)}, operation.PLAN_SCHEMA_V2: {('plan_sha256',)},
 operation.SCHEMA: {('plan_sha256',), ('intent_sha256',)},
 operation.SCHEMA_V2: {('plan_sha256',), ('intent_sha256',)},
 directories.SCHEMA: {('intent_sha256',)},
 directories.CHECKPOINT_SCHEMA: {('intent_sha256',), ('directories_sha256',)},
}

_SHAPES = {
 provenance.ROOT_SCHEMA: [provenance._ROOT_KEYS], provenance.OWNER_SCHEMA: [provenance._OWNER_KEYS],
 provenance.MANIFEST_SCHEMA: [provenance._MANIFEST_KEYS], provenance.BASE_SCHEMA: [provenance._BASE_KEYS],
 provenance.RECEIPT_SCHEMA: [provenance._RECEIPT_KEYS], runtime.SCHEMA: [terminal._PLAN_KEYS],
 operation.PLAN_SCHEMA: [{'schema','operation_id','plan','plan_sha256'}],
 operation.PLAN_SCHEMA_V2: [{'schema','operation_id','plan','plan_sha256'}],
 **{name: [{'schema','failure_model','operation_id','plan_sha256','slot_paths','publications','runtime_parent_id','scope_lock_id','transaction_directory_id','lock_id'},
           {'schema','failure_model','intent_sha256','direction','topology'},
           {'schema','failure_model','intent_sha256','start_step_decimal'}]
    for name in (operation.SCHEMA,operation.SCHEMA_V2)},
 directories.SCHEMA: [{'schema','failure_model','operation_id','intent_sha256','directories'}],
 directories.CHECKPOINT_SCHEMA: [{'schema','failure_model','operation_id','intent_sha256','directories_sha256','index','phase'}],
 'naos.upgrade.windows_content_observation.v1': [
     {'schema','presence','path','ancestors','missing_suffix'},
     {'schema','presence','path','identity','ancestors','size_decimal','sha256','metadata_sha256',
      'comparison_metadata_sha256','attributes','file_times_100ns','security'}],
}


def _admit_schema_record(value):
    schema=value.get('schema')
    if schema not in _SHAPES or set(value) not in _SHAPES[schema]:
        raise WindowsProjectionError('Unknown source schema fields or path roles: '+str(schema))
    identity_keys={'volume_serial_hex','file_id_hex'}
    if schema=='naos.upgrade.windows_content_observation.v1':
        for row in value['ancestors']:
            if type(row) is not dict or set(row)!={'name',*identity_keys}:
                raise WindowsProjectionError('Unknown ancestor fields/path roles')
        if value['presence']=='present':
            if (type(value['identity']) is not dict or set(value['identity'])!=identity_keys
                or set(value['file_times_100ns'])!={'created','modified','changed'}
                or set(value['security'])!={'owner_sid_sha256','group_sid_sha256','dacl_sha256','dacl_protected'}):
                raise WindowsProjectionError('Unknown observation metadata fields')
    if schema==runtime.SCHEMA:
        if set(value['project_root_identity'])!=identity_keys:
            raise WindowsProjectionError('Unknown root identity fields')
        if set(value['private_file_policy'])!={'attributes_hex','comparison_metadata_sha256','dacl_sha256','group_sid_sha256','owner_sid_sha256','policy'}:
            raise WindowsProjectionError('Unknown private file policy fields')
        if set(value['request'])!={'operation','inputs'}:
            raise WindowsProjectionError('Unknown request fields')
        for row in value['rows']:
            if type(row) is not dict or set(row)!={'path','action','ownership','creation_policy','source','before','base','intended'}:
                raise WindowsProjectionError('Unknown plan row fields/path roles')
            if set(row['source'])!={'path','sha256','size_decimal'}:
                raise WindowsProjectionError('Unknown source row fields/path roles')
            for role in ('base','intended'):
                if set(row[role])!={'presence','kind','sha256','size_decimal','metadata_sha256'}:
                    raise WindowsProjectionError('Unknown content identity fields')

class WindowsProjectionError(ValueError):
    pass

class _Pending(Exception):
    pass


def _names(plans):
    values=set()
    for plan in plans:
        _, parts=_parts(plan['project_root']);values.update(parts)
        for row in plan['source_policy_observation']['ancestors']:
            if row['name']:values.add(row['name'])
        values.update(_relative_parts(plan['source_policy_observation']['path']))
    groups={}
    for value in values:groups.setdefault(value.casefold(), []).append(value)
    result={}
    for index,key in enumerate(sorted(groups)):
        variants=sorted(groups[key]);width=max(1,(len(variants)-1).bit_length())
        for number, name in enumerate(variants):
            letters=''.join('A' if number & (1<<bit) else 'a' for bit in range(width))
            result[name]=letters+f'n{index:04d}'
    return result


def _localized_plan(plan,names):
    value=copy.deepcopy(plan)
    drive,parts=_parts(value['project_root'])
    # The supported raw grammar admits ordinary drive roots only. Same depth,
    # case equivalence and shared ancestor names survive alpha-renaming.
    _validate_location_topology(plan)
    value['project_root']=drive+'\\'.join(names[name] for name in parts)
    policy=value['source_policy_observation']
    policy['path']='\\'.join(names[name] for name in _relative_parts(policy['path']))
    for row in policy['ancestors']:
        if row['name']:row['name']=names[row['name']]
    for row in value['rows']:
        ancestors=row['before']['ancestors']
        if len(ancestors) < len(parts)+1:
            raise WindowsProjectionError('Content observation lacks full root ancestor depth')
        if [item['name'] for item in ancestors[:len(parts)+1]] != ['',*parts]:
            raise WindowsProjectionError('Content observation root ancestor topology differs')
        for ancestor in ancestors[1:len(parts)+1]:ancestor['name']=names[ancestor['name']]
    return value


def _validate_location_topology(plan):
    _,parts=_parts(plan['project_root'])
    for row in plan['rows']:
        ancestors=row['before']['ancestors']
        if len(ancestors)<len(parts)+1 or [item['name'] for item in ancestors[:len(parts)+1]]!=['',*parts]:
            raise WindowsProjectionError('Derived root ancestor topology/depth differs')
        root_identity={key:ancestors[len(parts)][key] for key in ('volume_serial_hex','file_id_hex')}
        if root_identity!=plan['project_root_identity']:
            raise WindowsProjectionError('Derived root ancestor native identity differs')
    observation=plan['source_policy_observation']
    policy_parts=_relative_parts(observation['path'])
    if [item['name'] for item in observation['ancestors']]!=['',*policy_parts[:-1]]:
        raise WindowsProjectionError('Derived policy ancestor topology differs')


def _ref(value,mapping,known):
    if value is None:return None
    if value in mapping:return mapping[value]
    if value in known:raise _Pending()
    return value


def _project(value,mapping,known,content, *,schema=None,path=()):
    if isinstance(value,list):
        return [_project(item,mapping,known,content,schema=schema,path=path+('*',)) for item in value]
    if not isinstance(value,dict):return value
    if 'schema' in value:
        schema=value['schema'];path=()
        _admit_schema_record(value)
    result={}
    for key,item in value.items():
        location=path+(key,)
        if schema in (operation.PLAN_SCHEMA,operation.PLAN_SCHEMA_V2) and location==('plan_sha256',):
            result[key]=item  # Recomputed from the transformed embedded plan below.
        elif location in _REFS.get(schema,set()):
            result[key]=_ref(item,mapping,known)
        elif schema in (operation.SCHEMA,operation.SCHEMA_V2) and location in {
             ('publications','*','after'),('publications','*','before')}:
            identity=copy.deepcopy(item);digest=identity['content_sha256']
            if digest in content:
                identity['content_sha256'],size=content[digest]
                identity['size_bytes']=str(size)
            elif digest in known:raise _Pending()
            result[key]=identity
        else:result[key]=_project(item,mapping,known,content,schema=schema,path=location)
    if schema == runtime.SCHEMA and not path:
        result['digest_sha256']=canonical_sha256({k:v for k,v in result.items() if k!='digest_sha256'})
    if schema in (operation.PLAN_SCHEMA,operation.PLAN_SCHEMA_V2) and not path:
        result['plan_sha256']=canonical_sha256(result['plan'])
    return result


def _typed(value, *,decode=False,schema=None,path=()):
    if isinstance(value,list):return [_typed(v,decode=decode,schema=schema,path=path+('*',)) for v in value]
    if not isinstance(value,dict):return value
    if 'schema' in value:
        schema=value['schema'];path=()
        _admit_schema_record(value)
    result={}
    for key,item in value.items():
        here=path+(key,)
        absolute=(schema==runtime.SCHEMA and here==('project_root',)
            or schema in (operation.SCHEMA,operation.SCHEMA_V2) and path==('slot_paths',))
        component=(schema=='naos.upgrade.windows_content_observation.v1' and here==('ancestors','*','name'))
        # Observation has its own schema, so policy-path dispatch is handled by
        # the plan wrapper explicitly below rather than schema inheritance.
        if schema==runtime.SCHEMA and here==('source_policy_observation',):
            observation=copy.deepcopy(item)
            if decode:
                location=observation['path']
                if type(location) is not dict or set(location)!={'schema','root_id','components'} or location['schema']!=LOCATION_SCHEMA or location['root_id']!='policy_observation':
                    raise WindowsProjectionError('Invalid external policy location token')
                parts=location['components']
                if type(parts) is not list or any(type(p) is not str for p in parts):raise WindowsProjectionError('Invalid policy components')
                observation['path']='\\'.join(parts);_relative_parts(observation['path'])
                result[key]=_typed(observation,decode=True)
            else:
                result[key]=_typed(observation)
                result[key]['path']={'schema':LOCATION_SCHEMA,'root_id':'policy_observation','components':list(_relative_parts(observation['path']))}
        elif absolute:
            if decode:
                if type(item) is not dict or set(item)!={'schema','root_id','components'} or item['schema']!=LOCATION_SCHEMA:
                    raise WindowsProjectionError('Invalid Windows location token')
                root=item['root_id']
                if type(root) is not str or len(root)!=1 or not root.isascii() or not root.isalpha():
                    raise WindowsProjectionError('Invalid Windows drive token')
                parts=item['components']
                if type(parts) is not list or any(type(p) is not str for p in parts):raise WindowsProjectionError('Invalid components')
                result[key]=root+':\\'+'\\'.join(parts)
                _parts(result[key])
            else:
                drive,parts=_parts(item)
                result[key]={'schema':LOCATION_SCHEMA,'root_id':drive[0],'components':list(parts)}
        elif component:
            if decode:
                if type(item) is not dict or set(item)!={'schema','component_id'} or item['schema']!=COMPONENT_SCHEMA or type(item['component_id']) is not str:
                    raise WindowsProjectionError('Invalid ancestor component token')
                result[key]=item['component_id']
            else:result[key]={'schema':COMPONENT_SCHEMA,'component_id':item}
        else:result[key]=_typed(item,decode=decode,schema=schema,path=here)
    return result


def _rebuild_derivative_dependencies(archive, original_bodies, localized, plans):
    known=set();mapping={};content={}
    for path,body in original_bodies.items():
        known.update((canonical_sha256(body),hashlib.sha256(archive[path]).hexdigest()))
        if path in plans:
            known.update((canonical_sha256(plans[path]),plans[path]['digest_sha256']))
    pending=dict(localized);projected=dict(archive)
    # Dependency-order processing is explicit and bounded. Any source reference
    # into this graph must resolve; external policy/content/native digests stay.
    for unused in range(len(pending)+1):
        progressed=False
        for path,body in list(pending.items()):
            try:value=_project(body,mapping,known,content)
            except _Pending:continue
            raw=_envelope(value);old=original_bodies[path]
            mapping[canonical_sha256(old)]=canonical_sha256(value)
            mapping[hashlib.sha256(archive[path]).hexdigest()]=hashlib.sha256(raw).hexdigest()
            content[hashlib.sha256(archive[path]).hexdigest()]=(hashlib.sha256(raw).hexdigest(),len(raw))
            if path in plans:
                mapping[plans[path]['digest_sha256']]=value['plan']['digest_sha256']
                mapping[canonical_sha256(plans[path])]=canonical_sha256(value['plan'])
            projected[path]=raw;del pending[path];progressed=True
        if not pending:break
        if not progressed:raise WindowsProjectionError('Cyclic or unsupported Windows derivative references: '+','.join(sorted(pending)))
    return projected


def build(archive_bytes,lineage,kwargs):
    from . import legacy_replay_projection as common
    archive=dict(archive_bytes);raw_seed=common._derive(archive,lineage,kwargs)
    replay_args={k:v for k,v in kwargs.items() if k not in ('directory_paths','mode_inventory_raw','expected_modes_sha256')}
    raw_terminal=terminal.validate_windows_terminal_archive(archive,lineage,directory_paths=kwargs['directory_paths'],**replay_args)
    plans={path:_decode(raw)['plan'] for path,raw in archive.items() if path.endswith('/plan.json')}
    names=_names(plans.values())
    roots={plan['project_root']:_localized_plan(plan,names)['project_root'] for plan in plans.values()}
    original_bodies={};localized={};control_paths={path for path in archive if path.endswith('.json')}
    for plan_path,plan in plans.items():
        prefix=plan_path.removesuffix('plan.json');intent=_decode(archive[prefix+'intent.json'])
        for publication in intent['publications']:
            if publication['role']=='content':continue
            target=terminal._relative_slot(intent['slot_paths'][publication['target']],plan['project_root'])
            if target.endswith('.json'):
                for key in ('staged','backup'):
                    if key in publication:
                        path=terminal._relative_slot(intent['slot_paths'][publication[key]],plan['project_root'])
                        if path in archive:control_paths.add(path)
    for path in control_paths:
        body=_decode(archive[path]);original_bodies[path]=body;value=copy.deepcopy(body)
        if path in plans:value['plan']=_localized_plan(plans[path],names)
        elif path.endswith('/intent.json'):
            plan=plans[path.removesuffix('intent.json')+'plan.json'];root=plan['project_root']
            value['slot_paths']={key:roots[root]+'\\'+terminal._relative_slot(slot,root).replace('/','\\') for key,slot in value['slot_paths'].items()}
        localized[path]=value
    projected=_rebuild_derivative_dependencies(archive,original_bodies,localized,plans)
    # The private source-home canary is checked against actual decoded bytes,
    # before base64 transport. It is never written into the transcript.
    canaries=set()
    for root in roots:
        drive,parts=_parts(root);home=drive+'\\'.join(parts[:2]) if parts and parts[0].casefold()=='users' else root
        canaries.update((home.encode(),canonical_bytes(home)[1:-1]))
        canaries.add(home.removeprefix(drive).encode())
        canaries.add(canonical_bytes(home.removeprefix(drive))[1:-1])
    if any(canary in raw for raw in (*projected.values(),kwargs['source_policy_raw'],kwargs['mode_inventory_raw']) for canary in canaries):
        raise WindowsProjectionError('Unsupported source-home-bearing Windows payload/free text')
    expected=common._expect(projected,migration.WINDOWS_CONTENT_V1)
    derived=migration.build_lineage(projected,source_format=migration.WINDOWS_CONTENT_V1,
        original_project_id=lineage.body['original_project_id'],new_project_id=lineage.body['new_project_id'],**expected)
    derived_kwargs=dict(kwargs,**expected,approved_lineage_sha256=derived.sha256)
    seed=common._derive(projected,derived,derived_kwargs)
    fields={'source_format','original_introduced_by_transaction','original_latest_transaction',
        'original_policy_binding_sha256','resolved_policy_snapshot_id','canonical_policy_sha256'}
    if any(raw_seed[key]!=seed[key] for key in ('entries','inputs','policies','bases','inventory_sha256')) or {
        p:{k:r[k] for k in fields} for p,r in raw_seed['origin_map'].items()}!={p:{k:r[k] for k in fields} for p,r in seed['origin_map'].items()}:
        raise WindowsProjectionError('Windows raw/derived semantic result differs')
    derived_terminal=terminal.validate_windows_terminal_archive(projected,derived,directory_paths=kwargs['directory_paths'],
        **{k:v for k,v in derived_kwargs.items() if k not in ('directory_paths','mode_inventory_raw','expected_modes_sha256')})
    if raw_terminal.operations!=derived_terminal.operations or raw_terminal.checked_paths!=derived_terminal.checked_paths:
        raise WindowsProjectionError('Windows terminal classification or coverage differs')
    members=[]
    for path,raw in sorted(projected.items()):
        payload=({'kind':'record','value':_typed(_decode(raw))} if path in control_paths else
            {'kind':'bytes','base64':base64.b64encode(raw).decode('ascii')})
        members.append({'path':path,'derived_materialized_sha256':hashlib.sha256(raw).hexdigest(),
            'derived_materialized_size_decimal':str(len(raw)),'payload':payload})
    raw=canonical_bytes({'schema':SCHEMA,'source_format':migration.WINDOWS_CONTENT_V1,
        'raw_lineage_commitment_sha256':lineage.sha256,'derived_lineage':derived.body,
        'directory_paths':list(kwargs['directory_paths']),'members':members})
    if any(canary in raw for canary in canaries):
        raise WindowsProjectionError('Unsupported source-home-bearing serialized Windows metadata')
    replay_derived(raw,source_policy_raw=kwargs['source_policy_raw'],mode_inventory_raw=kwargs['mode_inventory_raw'],expected_modes_sha256=kwargs['expected_modes_sha256'])
    return raw


def replay_derived(raw,*,source_policy_raw,mode_inventory_raw,expected_modes_sha256):
    from . import legacy_replay_projection as common
    if type(raw) is not bytes or len(raw)>migration.MAX_ARCHIVE_BYTES*2:raise WindowsProjectionError('Derived Windows byte budget exceeded')
    body=loads_strict_json(raw)
    if type(body) is not dict or set(body)!={'schema','source_format','raw_lineage_commitment_sha256','derived_lineage','directory_paths','members'} or body['schema']!=SCHEMA or body['source_format']!=migration.WINDOWS_CONTENT_V1 or canonical_bytes(body)!=raw:
        raise WindowsProjectionError('Derived Windows shape/schema differs')
    migration._digest(body['raw_lineage_commitment_sha256'],'raw commitment')
    members=body['members'];archive={};total=0
    if type(members) is not list or not 1<=len(members)<=migration.MAX_ARCHIVE_FILES:raise WindowsProjectionError('Derived Windows inventory budget differs')
    for row in members:
        if type(row) is not dict or set(row)!={'path','derived_materialized_sha256','derived_materialized_size_decimal','payload'}:raise WindowsProjectionError('Derived member shape differs')
        path,payload=row['path'],row['payload'];migration._path(path,migration.WINDOWS_CONTENT_V1)
        if path in archive or type(payload) is not dict:raise WindowsProjectionError('Duplicate or malformed derived member')
        if payload.get('kind')=='record' and set(payload)=={'kind','value'}:materialized=_envelope(_typed(payload['value'],decode=True))
        elif payload.get('kind')=='bytes' and set(payload)=={'kind','base64'}:
            if type(payload['base64']) is not str or len(payload['base64'])>4*((migration.MAX_ARCHIVE_FILE_BYTES+2)//3):raise WindowsProjectionError('Derived leaf byte budget exceeded')
            materialized=base64.b64decode(payload['base64'],validate=True)
        else:raise WindowsProjectionError('Unsupported derived payload')
        total+=len(materialized)
        if len(materialized)>migration.MAX_ARCHIVE_FILE_BYTES or total>migration.MAX_ARCHIVE_BYTES:raise WindowsProjectionError('Derived archive byte budget exceeded')
        if row['derived_materialized_sha256']!=hashlib.sha256(materialized).hexdigest() or row['derived_materialized_size_decimal']!=str(len(materialized)):raise WindowsProjectionError('Derived materialized commitment differs')
        archive[path]=materialized
    if [row['path'] for row in members]!=sorted(archive):raise WindowsProjectionError('Derived inventory order differs')
    for path,record_raw in archive.items():
        if path.endswith('/plan.json'):
            plan=_decode(record_raw)['plan']
            _validate_location_topology(plan)
    lineage_raw=canonical_bytes(body['derived_lineage']);lineage=migration.LegacyLineage(lineage_raw,hashlib.sha256(lineage_raw).hexdigest())
    return common._derive(archive,lineage,dict(directory_paths=body['directory_paths'],source_policy_raw=source_policy_raw,mode_inventory_raw=mode_inventory_raw,expected_modes_sha256=expected_modes_sha256,
        approved_lineage_sha256=lineage.sha256,expected_source_policy_sha256=hashlib.sha256(source_policy_raw).hexdigest(),**common._expect(archive,migration.WINDOWS_CONTENT_V1)))
