"""Pure injected Windows provenance fixtures; no native Windows API calls."""
from upgrade_contract import windows_planning as wp
from upgrade_contract import windows_provenance as prov


POLICY = b'''schema: naos.upgrade.source_policy_bundle.v1
active_snapshot: v2
snapshots:
  - id: v2
    sha256_aliases: []
    policy:
      version: 2
      scope: managed-content
      semantics:
        ownership_inference: forbidden
        unmatched_new_path: create_once_adopter_owned
        existing_without_valid_base: preserve_and_refuse
        exact_path_precedence: true
        prior_manifest_ownership: preserve_verbatim
      rules:
        - id: kit
          ownership: kit_owned_derived
          creation_policy: create
          first_components: [scripts]
      fallback:
        id: fallback
        ownership: adopter_owned
        creation_policy: create_once_adopter_owned
'''


def observation(path, byte=b'x', *, ident='01'):
    if byte is None:
        return {'schema': wp.OBSERVATION_SCHEMA, 'presence': 'absent', 'path': path,
                'ancestors': [{'name': '', 'volume_serial_hex': '0000000000000001',
                               'file_id_hex': '00' * 16},
                              {'name': 'project', 'volume_serial_hex': '0000000000000001',
                               'file_id_hex': 'ab' * 16}]}
    import hashlib
    return {'schema': wp.OBSERVATION_SCHEMA, 'presence': 'present', 'path': path,
            'identity': {'volume_serial_hex': 'ffffffffffffffff', 'file_id_hex': ident * 16},
            'ancestors': [{'name': '', 'volume_serial_hex': '0000000000000001',
                           'file_id_hex': '00' * 16},
                          {'name': 'project', 'volume_serial_hex': '0000000000000001',
                           'file_id_hex': 'ab' * 16}],
            'size_decimal': str(len(byte)), 'sha256': hashlib.sha256(byte).hexdigest(),
            'metadata_sha256': 'a' * 64, 'comparison_metadata_sha256': 'e' * 64,
            'file_times_100ns': {
                'created': '134347392000000001', 'modified': '134347392000000002',
                'changed': '134347392000000003'}, 'security': {
                'owner_sid_sha256': 'b' * 64, 'group_sid_sha256': 'c' * 64,
                'dacl_sha256': 'd' * 64, 'dacl_protected': True}, 'attributes': 0}


ROOT_ID = {'volume_serial_hex': '0000000000000001', 'file_id_hex': 'ab' * 16}


PATH = 'scripts\\tool.py'


REQUEST = {'operation': 'naos-init', 'inputs': {
    'mode': 'greenfield', 'profile': 'standard', 'archetype': 'custom',
    'backend': 'static_only', 'memory_choice': 'not_selected'}}


class Reader:
    def __init__(self, files): self.files = dict(files)
    def read(self, path): return self.files.get(path)


def enrolled():
    digest, _ = prov.policy_catalog(POLICY)
    reader = Reader(prov.make_empty_enrollment(project_id='project-1', root_identity=ROOT_ID,
                     enrollment_plan_sha256='1' * 64, source_policy_snapshot_sha256=digest))
    return reader, prov.load_windows_provenance(reader, root_identity=ROOT_ID,
                                                 source_policy_raw=POLICY)
