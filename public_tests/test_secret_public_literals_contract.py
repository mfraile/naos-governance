"""Portable public-declaration admission and unknown-credential boundaries."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import uuid

from jsonschema import Draft202012Validator

KIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KIT / "scripts"))
import naos_secret_public_literals as public
import naos_hygiene_common as common

TOKEN = "aB3dE5fG7hI9jK0mN2pQ4rS6tU8vW+/="
PUBLIC_NAME = "Y29tLmFwcGxlLnByb3ZlbmFuY2U="


class PublicLiteralContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-public-declaration-ü-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding="utf-8")
        return path

    def scan(self, data, **rules):
        self.write("input.json", json.dumps(data))
        report = common.check_secret_hygiene(root=self.root, profile="assured", naos_root="naos",
                                            rules=rules, rules_path=None, severity="blocking")
        Draft202012Validator(json.loads((KIT / "schemas/naos/secret_hygiene.schema.json").read_text(encoding='utf-8'))).validate(report)
        return report

    def test_catalog_digest_schema_and_provenance_are_bound(self):
        raw = (KIT / "scripts" / public.CATALOG_FILENAME).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), public.CATALOG_SHA256)
        catalog = public.read_catalog()
        Draft202012Validator(json.loads((KIT / "schemas/naos/secret_public_literals.schema.json").read_text(encoding='utf-8'))).validate(catalog)
        for group in catalog["groups"]:
            canonical = json.dumps(group["values"], ensure_ascii=True, separators=(",", ":")).encode()
            self.assertEqual(hashlib.sha256(canonical).hexdigest(), group["component_sha256"])

    def test_exact_public_declaration_and_observed_operands_need_no_file_existence(self):
        known = self.root / "naos/reports/agent_trace_validation.json"
        self.assertFalse(known.exists())
        report = self.scan({"os_name": PUBLIC_NAME, "schema": "naos.secret_hygiene.v1",
                            "root": str(self.root), "path": str(known)})
        self.assertEqual(report["summary"]["blocking"], 0)
        self.assertGreater(report["summary"]["public_literal_matches"], 0)

    def test_unknown_json_keys_metadata_paths_and_mixed_strings_stay_blocking(self):
        rows = [{TOKEN: "key"}, {"schema": TOKEN}, {"sha256": TOKEN}, {"owner_id": TOKEN},
                {"path": str(self.root / ("metadata/" + TOKEN + ".json"))},
                {"path": "/outside/" + TOKEN + ".json"}, {"mixed": "prefix-" + TOKEN + "-suffix"}]
        self.write(".naos/upgrade-v1/managed-content/unknown.json", "\n".join(json.dumps(row) for row in rows))
        report = common.check_secret_hygiene(root=self.root, profile="assured", naos_root="naos", rules={}, rules_path=None, severity="blocking")
        self.assertEqual([f["line"] for f in report["findings"] if f["status"] == "high_entropy_literal"], list(range(1, 8)))
        self.assertNotIn(TOKEN, json.dumps(report))

    def test_modified_public_values_and_neighbor_paths_are_not_admitted(self):
        neighbor = "naos/reports/agent_trace_validation.json.extra123"
        vocabulary, metadata = public.load_public_literals(root=self.root, naos_root="naos")
        self.assertEqual(metadata["status"], "valid")
        # Exact admission must refuse both representations, including an absolute
        # temporary root whose spaces intentionally exclude it from entropy scans.
        for value in (neighbor, str(self.root / neighbor)):
            for representation in public.raw_literal_representations(value):
                self.assertNotIn(representation, vocabulary)
        # A portable relative operand isolates admission from the scanner's
        # documented whitespace exclusion for quoted high-entropy candidates.
        report = self.scan({"os": PUBLIC_NAME + "extra123", "schema": "naos.secret_hygiene.v1-extra123",
                            "path": neighbor})
        self.assertEqual(report["summary"]["entropy_matches"], 3)

    def test_assignment_and_provider_patterns_run_even_when_entropy_literal_is_public(self):
        provider = "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"
        with patch.object(common, "load_public_literals", return_value=({PUBLIC_NAME, provider}, {"status": "valid"})):
            report = self.scan({"password": PUBLIC_NAME, "provider": provider})
        self.assertTrue(any(f.get("pattern_id") == "assigned_secret" for f in report["findings"]))
        self.assertTrue(any(f.get("pattern_id") == "openai_style_key" for f in report["findings"]))

    def test_native_windows_schemas_are_declared_in_both_runtime_layouts(self):
        schemas = {
            "upgrade_contract/windows_planning.py": {
                "SCHEMA": "naos.upgrade.windows_content_plan.v1",
                "OBSERVATION_SCHEMA": "naos.upgrade.windows_content_observation.v1",
            },
            "upgrade_contract/windows_runtime_directories.py": {
                "SCHEMA": "naos.upgrade.windows_runtime_directories.v1",
                "CHECKPOINT_SCHEMA": "naos.upgrade.windows_runtime_directory_cleanup.v1",
            },
        }
        expected = set()
        for relative, declarations in schemas.items():
            tree = ast.parse((KIT / relative).read_text(encoding="utf-8"))
            actual = {target.id: node.value.value for node in tree.body
                      if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
                      for target in node.targets if isinstance(target, ast.Name)}
            for name, value in declarations.items():
                self.assertEqual(actual[name], value)
                expected.add(value)
        catalog = public.read_catalog()
        for layout in ("kit", "copied_project"):
            with self.subTest(layout=layout):
                values = public.context_values(catalog, project_root=PureWindowsPath("C:/project"),
                                               kit_root=PureWindowsPath("D:/kit"), naos_root="naos",
                                               runtime_layout=layout)
                self.assertTrue(expected <= values)
        report = self.scan({"declared_schemas": sorted(expected)})
        self.assertEqual(report["summary"]["blocking"], 0)

    def test_native_schema_membership_does_not_admit_unknowns_or_disable_secret_patterns(self):
        schema = "naos.upgrade.windows_content_observation.v1"
        report = self.scan({"known": schema, "modified": schema + "-" + TOKEN,
                            "unknown": "naos.upgrade.unreviewed_" + TOKEN,
                            "password": schema,
                            "provider": "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"})
        self.assertEqual(report["summary"]["entropy_matches"], 3)
        self.assertTrue(any(f.get("pattern_id") == "assigned_secret" for f in report["findings"]))
        self.assertTrue(any(f.get("pattern_id") == "openai_style_key" for f in report["findings"]))

    def test_shipped_managed_parser_grammars_leave_unknown_source_literals_scanned(self):
        (self.root / "scripts").mkdir()
        for name in ("naos_secret_managed_operands.py", "naos_secret_ri_windows_operands.py"):
            with self.subTest(parser=name):
                helper = self.root / "scripts" / name
                source = (KIT / "scripts" / name).read_text(encoding="utf-8")
                helper.write_text(source, encoding="utf-8")
                report = common.check_secret_hygiene(root=self.root, profile="assured", naos_root="naos",
                                                    rules={}, rules_path=None, severity="blocking")
                self.assertEqual(report["summary"]["coverage_status"], "complete")
                self.assertEqual(report["summary"]["blocking"], 0)
                helper.write_text(source + "\nunknown_value = " + repr(TOKEN)
                                  + "\npassword = " + repr(PUBLIC_NAME)
                                  + "\nprovider = 'sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'\n", encoding="utf-8")
                report = common.check_secret_hygiene(root=self.root, profile="assured", naos_root="naos",
                                                    rules={}, rules_path=None, severity="blocking")
                self.assertTrue(any(f["status"] == "high_entropy_literal" for f in report["findings"]))
                self.assertTrue(any(f.get("pattern_id") == "assigned_secret" for f in report["findings"]))
                self.assertTrue(any(f.get("pattern_id") == "openai_style_key" for f in report["findings"]))
                helper.unlink()

    def test_exact_windows_and_posix_raw_path_representations_and_remap(self):
        catalog = public.read_catalog()
        for root, kit in [(PureWindowsPath("C:/work ü/project"), PureWindowsPath("D:/trusted/kit")),
                          (PurePosixPath("/work ü/project"), PurePosixPath("/trusted/kit"))]:
            values = public.context_values(catalog, project_root=root, kit_root=kit, naos_root="controls/naos")
            operand = root / "controls/naos/reports/agent_trace_validation.json"
            self.assertIn(json.dumps(str(operand), ensure_ascii=True)[1:-1], values)
            self.assertIn(operand.as_posix(), values)
            self.assertNotIn(str(root / "unknown" / TOKEN), values)

    def test_native_relative_spellings_require_existing_declared_path_membership(self):
        catalog = public.read_catalog()
        for project, kit in [(PureWindowsPath("C:/work ü/project"), PureWindowsPath("D:/kit")),
                             (PurePosixPath("/work ü/project"), PurePosixPath("/kit"))]:
            for layout in ("kit", "copied_project"):
                with self.subTest(platform=type(project).__name__, layout=layout):
                    values = public.context_values(catalog, project_root=project, kit_root=kit,
                                                   naos_root="controls/naos", runtime_layout=layout)
                    for relative in ("controls/naos/reports/agent_trace_validation.json", "specs/07-cost-analysis.md"):
                        native = str(project.joinpath(*relative.split("/")).relative_to(project))
                        self.assertIn(json.dumps(native, ensure_ascii=True)[1:-1], values)
                    native_kit = str(kit.joinpath("upgrade_contract", "windows_planning.py").relative_to(kit))
                    self.assertEqual(json.dumps(native_kit, ensure_ascii=True)[1:-1] in values,
                                     layout == "kit" or type(kit) is PurePosixPath)
                    unknown = str(project.joinpath("specs", TOKEN + ".md").relative_to(project))
                    self.assertNotIn(json.dumps(unknown, ensure_ascii=True)[1:-1], values)
                    session = str(project.joinpath("controls", "naos", "sessions", TOKEN, "reports").relative_to(project))
                    self.assertNotIn(json.dumps(session, ensure_ascii=True)[1:-1], values)

    def test_shipped_audit_directory_and_hook_operands_leave_unknown_neighbors_scanned(self):
        report = self.scan({"audit_log_root": str(self.root / "naos/audit_log"),
                            "pre_commit_hook_path": str(self.root / ".githooks/pre-commit"),
                            "unknown_neighbor": str(self.root / "naos/audit_log" / TOKEN)})
        self.assertEqual(report["summary"]["entropy_matches"], 1)
        self.assertEqual(len([finding for finding in report["findings"]
                              if finding["status"] == "high_entropy_literal"]), 1)

    def test_default_control_operands_remap_only_under_declared_native_roots(self):
        catalog = public.read_catalog()
        for root, kit in [(PureWindowsPath("C:/work ü/project"), PureWindowsPath("D:/trusted/kit")),
                          (PurePosixPath("/work ü/project"), PurePosixPath("/trusted/kit"))]:
            values = public.context_values(catalog, project_root=root, kit_root=kit, naos_root="controls/naos")
            for operand in (root / "controls/naos/audit_log", root / ".githooks/pre-commit"):
                self.assertIn(json.dumps(str(operand), ensure_ascii=True)[1:-1], values)
                self.assertIn(operand.as_posix(), values)
            self.assertNotIn(str(root / "controls/naos/audit_log-custom"), values)
            self.assertNotIn(str(root / ".custom-hooks/pre-commit"), values)

    def test_malformed_missing_linked_and_oversized_catalogs_fail_closed(self):
        cases = [public.PublicVocabularyError("digest_mismatch"), public.PublicVocabularyError("unreadable_or_malformed"),
                 public.PublicVocabularyError("not_regular_or_oversized")]
        for error in cases:
            with self.subTest(reason=str(error)), patch.object(public, "read_catalog", side_effect=error):
                report = self.scan({"value": TOKEN})
            self.assertEqual(report["scans"]["public_literals"]["status"], "invalid")
            self.assertTrue(any(f["status"] == "public_vocabulary_invalid" and f["severity"] == "blocking" for f in report["findings"]))
            self.assertTrue(any(f["status"] == "high_entropy_literal" for f in report["findings"]))

    def test_real_catalog_loader_rejects_duplicate_keys_and_bad_shape_even_with_matching_digest(self):
        module_file = self.root / "scripts/naos_secret_public_literals.py"
        module_file.parent.mkdir()
        shutil.copyfile(public.__file__, module_file)
        spec = importlib.util.spec_from_file_location("relocated_public", module_file)
        relocated = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(relocated)
        for raw in [b'{"schema":"naos.secret_public_literals.v1","schema":"naos.secret_public_literals.v1","groups":[]}',
                    b'{"schema":"wrong","groups":[]}', b'\xff']:
            (module_file.parent / public.CATALOG_FILENAME).write_bytes(raw)
            relocated.CATALOG_SHA256 = hashlib.sha256(raw).hexdigest()
            with self.assertRaises(relocated.PublicVocabularyError):
                relocated.read_catalog()

    def test_relocated_loader_missing_tampered_oversized_and_symlink_files(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        module_file = scripts / "naos_secret_public_literals.py"
        shutil.copyfile(public.__file__, module_file)
        spec = importlib.util.spec_from_file_location("relocated_failure_public", module_file)
        relocated = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(relocated)
        data = scripts / public.CATALOG_FILENAME
        with self.assertRaises(relocated.PublicVocabularyError):
            relocated.read_catalog()
        data.write_bytes(b"{}")
        with self.assertRaises(relocated.PublicVocabularyError):
            relocated.read_catalog()
        data.write_bytes(b"x" * (public.MAX_CATALOG_BYTES + 1))
        with self.assertRaises(relocated.PublicVocabularyError):
            relocated.read_catalog()
        data.unlink()
        try:
            data.symlink_to(KIT / "scripts" / public.CATALOG_FILENAME)
        except OSError as error:
            if getattr(error, "winerror", None) == 1314:
                self.skipTest("Windows symlink privilege unavailable")
            raise
        with self.assertRaises(relocated.PublicVocabularyError):
            relocated.read_catalog()

    def owner(self, digest="a" * 64):
        value = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"naos:managed-content:{self.root.resolve()}:{digest}"))
        path = self.write(".naos/upgrade-v1/OWNER.json", json.dumps({"project_id": value, "enrollment_authorization": {"plan_sha256": digest}}))
        return value, path

    def test_enrollment_label_is_recomputed_only_from_exact_native_root_and_typed_digest(self):
        value, path = self.owner()
        self.assertEqual(public.public_enrollment_id(self.root)[0], value)
        owner = json.loads(path.read_text(encoding='utf-8'))
        owner["enrollment_authorization"]["plan_sha256"] = "b" * 64
        path.write_text(json.dumps(owner), encoding='utf-8')
        self.assertIsNone(public.public_enrollment_id(self.root)[0])
        owner["enrollment_authorization"]["plan_sha256"] = 123
        path.write_text(json.dumps(owner), encoding='utf-8')
        self.assertIsNone(public.public_enrollment_id(self.root)[0])

    def test_owner_duplicate_keys_unknown_uuid_and_moved_root_are_not_admitted(self):
        value, path = self.owner()
        path.write_text('{"project_id":"' + value + '","project_id":"different","enrollment_authorization":{"plan_sha256":"' + "a" * 64 + '"}}', encoding='utf-8')
        self.assertIsNone(public.public_enrollment_id(self.root)[0])
        value, path = self.owner()
        moved = self.root / "moved"
        shutil.copytree(self.root / ".naos", moved / ".naos")
        self.assertIsNone(public.public_enrollment_id(moved)[0])

    def test_owner_neighbors_and_provider_assignments_remain_scanned(self):
        value, path = self.owner()
        owner = json.loads(path.read_text(encoding='utf-8'))
        owner.update({"unknown": TOKEN, "password": value})
        path.write_text(json.dumps(owner), encoding='utf-8')
        report = self.scan({"value": value})
        self.assertTrue(any(f["status"] == "high_entropy_literal" for f in report["findings"]))
        self.assertTrue(any(f.get("pattern_id") == "assigned_secret" for f in report["findings"]))

    def test_windows_reparse_shaped_catalog_and_owner_inputs_are_rejected(self):
        self.owner()
        original = Path.lstat
        reparse = SimpleNamespace(st_mode=0o040755, st_file_attributes=0x400, st_size=0)
        def owner_junction(path, *args, **kwargs):
            return reparse if path == self.root / ".naos" else original(path, *args, **kwargs)
        with patch.object(Path, "lstat", owner_junction):
            self.assertIsNone(public.public_enrollment_id(self.root)[0])
        catalog_path = Path(public.__file__).absolute().parent / public.CATALOG_FILENAME
        def catalog_reparse(path, *args, **kwargs):
            return reparse if path == catalog_path else original(path, *args, **kwargs)
        with patch.object(Path, "lstat", catalog_reparse), self.assertRaises(public.PublicVocabularyError):
            public.read_catalog()

    def test_source_ast_credentials_never_become_public_by_appearing_in_code(self):
        self.write("scripts/custom.py", 'value = "' + TOKEN + '"\n')
        report = self.scan({"value": "safe"})
        self.assertTrue(any(f.get("path") == "scripts/custom.py" and f["status"] == "high_entropy_literal" for f in report["findings"]))

    def test_real_installer_copy_marker_selects_project_operands_in_isolated_runtime(self):
        tree = ast.parse((KIT / "naos_init.py").read_text(encoding='utf-8'))
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_copy_generated_script")
        namespace = {"Path": Path, "shutil": shutil, "SourceOrigins": object}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "installer_copy", "exec"), namespace)
        scripts = self.root / "scripts"
        scripts.mkdir()
        for name in ("naos_secret_public_literals.py", public.CATALOG_FILENAME):
            namespace["_copy_generated_script"](KIT / "scripts" / name, scripts / name)
        self.assertEqual((scripts / public.CATALOG_FILENAME).read_bytes(), (KIT / "scripts" / public.CATALOG_FILENAME).read_bytes())
        # A copied scanner inspecting another project must still avoid invented
        # installer-excluded member operands beneath its own module location.
        other = self.root / "other-project"
        other.mkdir()
        code = """import json,sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import naos_secret_public_literals as public
values, status = public.load_public_literals(root=Path(sys.argv[2]), naos_root='controls/naos')
assert status['runtime_layout'] == 'copied_project'
assert str(Path(sys.argv[1]).parent / 'scripts/naos_public_export.py') not in values
assert str(Path(sys.argv[2]) / 'controls/naos/reports/agent_trace_validation.json') in values
assert 'naos.upgrade.windows_content_observation.v1' in values
assert 'naos.upgrade.windows_runtime_directories.v1' in values
print(json.dumps(status))
"""
        result = subprocess.run([sys.executable, "-B", "-c", code, str(scripts), str(other)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def audit_event(self):
        import naos_audit_log as audit
        return audit.build_audit_event(root=self.root, naos_root="naos", policy={}, profile="standard",
            event_type="session_started", session_id="fixture-session", generated_at="2026-10-09T12:00:00Z",
            generated_by={"operator_id": "fixture-operator", "operator_source": "fixture"},
            source_report={"schema": "naos.session_identity.v1", "status": "session_created", "summary": {},
                           "findings": [], "human_review_required": True})

    def test_new_marked_audit_id_only_is_public_and_unknown_payload_neighbors_still_block(self):
        import naos_audit_log as audit
        event = self.audit_event()
        event["event_payload_summary"]["summary"]["opaque"] = TOKEN
        event["event_payload_hash"] = audit.hash_json(event["event_payload_summary"])
        body = {key: value for key, value in event.items() if key != "event_id"}
        event["event_id"] = "audit-sha256-" + audit.hash_json({"domain": audit.PUBLIC_EVENT_ID_SCHEME, "event": body})
        self.assertEqual(public.public_audit_ids(json.dumps({"events": [event]})), {event["event_id"]})
        report = self.scan({"events": [event]})
        self.assertEqual(report["summary"]["entropy_matches"], 1)
        report = self.scan({"events": [event], "password": event["event_id"],
                            "provider": "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"})
        self.assertTrue(any(f.get("pattern_id") == "assigned_secret" for f in report["findings"]))
        self.assertTrue(any(f.get("pattern_id") == "openai_style_key" for f in report["findings"]))

    def test_cross_file_event_operand_is_recomputed_with_exact_root_and_no_clock_fallback(self):
        import naos_audit_log as audit
        event = self.audit_event()
        event_path = audit.event_file_path(self.root / "naos/audit_log", event)
        self.write(event_path.relative_to(self.root), json.dumps(event))
        self.write("later.json", json.dumps({"event_file": str(event_path), "unknown": TOKEN}))
        report = self.scan({"value": "safe"})
        entropy = [f for f in report["findings"] if f["status"] == "high_entropy_literal"]
        self.assertEqual(len(entropy), 1)
        self.assertEqual(entropy[0]["path"], "later.json")
        for changes in ({"project_root": str(self.root / "different")}, {"naos_root": "other"},
                        {"generated_at": "2026-10-09T12:00:00"}, {"generated_at": "bad"}):
            changed = {**event, **changes}
            body = {key: value for key, value in changed.items() if key != "event_id"}
            changed["event_id"] = "audit-sha256-" + audit.hash_json({"domain": audit.PUBLIC_EVENT_ID_SCHEME, "event": body})
            values = public.public_audit_ids(json.dumps(changed), root=self.root, naos_root="naos")
            self.assertIn(changed["event_id"], values)
            self.assertFalse(any(".jsonl" in value for value in values))
        remapped = {**event, "naos_root": "controls/naos"}
        body = {key: value for key, value in remapped.items() if key != "event_id"}
        remapped["event_id"] = "audit-sha256-" + audit.hash_json({"domain": audit.PUBLIC_EVENT_ID_SCHEME, "event": body})
        expected = audit.event_file_path(self.root / "controls/naos/audit_log", remapped)
        values = public.public_audit_ids(json.dumps(remapped), root=self.root, naos_root="controls/naos")
        self.assertIn(str(expected), values)
        self.assertNotIn(str(expected) + TOKEN, values)

    def test_misnamed_jsonl_event_cannot_authorize_cross_file_operand(self):
        import naos_audit_log as audit
        event = self.audit_event()
        expected = audit.event_file_path(self.root / "naos/audit_log", event)
        source = self.write("audit.jsonl", json.dumps(event))
        self.assertFalse(public.selected_public_audit_literals(
            [source], root=self.root, naos_root="naos",
        ))
        self.write("later.json", json.dumps({"event_file": str(expected)}))
        report = self.scan({"value": "safe"})
        self.assertTrue(any(
            item.get("path") == "later.json" and item["status"] == "high_entropy_literal"
            for item in report["findings"]
        ))

    def test_invalid_duplicate_malformed_audit_records_and_legacy_ids_have_no_exception(self):
        event = self.audit_event()
        invalid = {**event, "event_nonce": "00"}
        legacy = {key: value for key, value in event.items() if key not in {"event_nonce", "event_id_scheme"}}
        legacy["event_id"] = "audit-20261009T120000Z-" + TOKEN
        raw = json.dumps(event)
        duplicate = raw[:-1] + ', "event_nonce": "123"}'
        for text in (json.dumps(invalid), json.dumps(legacy), duplicate, raw[:-2], raw + "\n" + duplicate,
                     raw[:-1] + ', "event_nonce": NaN}'):
            self.assertEqual(public.public_audit_ids(text), set())
            self.write("audit.jsonl", text)
            report = self.scan({"neighbor": TOKEN})
            self.assertTrue(any(f["status"] == "high_entropy_literal" for f in report["findings"]))

    def test_jsonl_defaults_seed_and_explicit_overrides_preserve_selection_authority(self):
        import yaml
        from naos_secret_patterns import SECRET_SCAN_SUFFIXES
        seed = yaml.safe_load((KIT / "templates/structural-seeds/naos/secret_hygiene_rules.yaml").read_text(encoding='utf-8'))
        self.assertIn(".jsonl", SECRET_SCAN_SUFFIXES)
        self.assertEqual(set(seed["suffixes"]), set(SECRET_SCAN_SUFFIXES))
        self.write("record.jsonl", json.dumps({"unknown": TOKEN}))
        report = self.scan({"value": "safe"})
        self.assertTrue(any(f.get("path") == "record.jsonl" for f in report["findings"]))
        report = self.scan({"value": "safe"}, suffixes=[".json"])
        self.assertFalse(any(f.get("path") == "record.jsonl" for f in report["findings"]))

    def test_invalid_catalog_disables_dynamic_public_exceptions_as_well(self):
        event = self.audit_event()
        with patch.object(public, "read_catalog", side_effect=public.PublicVocabularyError("digest_mismatch")):
            report = self.scan({"event": event})
        self.assertTrue(any(f["status"] == "public_vocabulary_invalid" for f in report["findings"]))
        self.assertEqual(report["summary"]["public_literal_matches"], 0)

    def test_collector_refuses_linked_components_and_corpus_exhaustion(self):
        import naos_audit_log as audit
        from naos_policy import SAFE_FALLBACK_POLICY
        event = self.audit_event()
        path = audit.event_file_path(
            self.root / "naos" / SAFE_FALLBACK_POLICY["paths"]["audit_log_root"], event)
        self.write(path.relative_to(self.root).as_posix(), json.dumps(event))
        self.assertIn(event["event_id"], public.collect_public_audit_event_references([path], root=self.root, naos_root="naos"))
        original = Path.lstat
        reparse = SimpleNamespace(st_mode=0o040755, st_file_attributes=0x400, st_size=0)
        def linked_component(value, *args, **kwargs):
            return reparse if value == path.parent else original(value, *args, **kwargs)
        with patch.object(Path, "lstat", linked_component):
            self.assertEqual(public.collect_public_audit_event_references([path], root=self.root, naos_root="naos"), {})
        # Keep each mocked read a valid event, so empty output demonstrates the
        # total corpus bound rather than an earlier malformed-JSON refusal.
        event_bytes = json.dumps(event).encode("utf-8")
        padded = event_bytes + b" " * (8 * 1024 * 1024 - len(event_bytes))
        class LargeRead:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, count):
                self_count = len(padded)
                assert count > self_count
                return padded
        with patch.object(Path, "open", return_value=LargeRead()):
            self.assertIn(event["event_id"], public.collect_public_audit_event_references([path] * 4, root=self.root, naos_root="naos"))
            self.assertEqual(public.collect_public_audit_event_references([path] * 5, root=self.root, naos_root="naos"), {})

    def test_only_live_absolute_interpreter_operand_is_public_and_neighbors_stay_checked(self):
        values, _ = public.load_public_literals(root=self.root, naos_root="naos")
        self.assertIn(sys.executable, values)
        forged = "/stored-interpreter/" + TOKEN + "/python"
        self.assertNotIn(forged, values)
        self.assertNotIn(sys.executable + TOKEN, values)
        report = self.scan({"interpreter": sys.executable, "stored_interpreter": forged,
                            "password": sys.executable, "provider": "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"})
        self.assertTrue(any(f["status"] == "high_entropy_literal" for f in report["findings"]))
        self.assertTrue(any(f.get("pattern_id") == "assigned_secret" for f in report["findings"]))
        self.assertTrue(any(f.get("pattern_id") == "openai_style_key" for f in report["findings"]))
        with patch.object(public.sys, "executable", "relative/" + TOKEN):
            values, _ = public.load_public_literals(root=self.root, naos_root="naos")
        self.assertNotIn("relative/" + TOKEN, values)

    def test_own_report_is_scanned_for_unknown_literals(self):
        self.write("naos/reports/secret_hygiene.json", json.dumps({"metadata": TOKEN}))
        report = self.scan({"value": "safe"})
        self.assertTrue(any(f.get("path") == "naos/reports/secret_hygiene.json" and f["status"] == "high_entropy_literal" for f in report["findings"]))


class FinitePublicConstructorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("public_generator_contract", Path(public.__file__).with_name("generate_naos_secret_public_literals.py"))
        cls.generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.generator)
        cls.catalog = cls.generator.build(KIT)
        cls.literals = {v for g in cls.catalog["groups"] if g["kind"] == "literal" for v in g["values"]}
        cls.paths = {v for g in cls.catalog["groups"] if g["kind"] == "project_path" for v in g["values"]}

    def test_actual_policy_default_helpers_match_finite_catalog_operands(self):
        import naos_policy as policy
        defaults = __import__("yaml").safe_load((KIT / "policies/default_policy.yaml").read_text(encoding='utf-8'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "naos").mkdir()
            for key in ("task_path_report", "context_manifest_report", "exceptions_report", "completion_certificate_report", "source_to_test_map"):
                operand = policy.evidence_default_path(root, "naos", defaults, key)
                self.assertIn(operand.relative_to(root).as_posix(), self.paths)
            operand = policy.evidence_pack_output_path(root, "naos", defaults)
            self.assertIn(operand.relative_to(root).as_posix(), self.paths)
            ordinary = policy.report_default_path(root, "naos", policy.SAFE_FALLBACK_POLICY, "secret_hygiene_report")
            self.assertIn(ordinary.relative_to(root).as_posix(), self.paths)
        self.assertNotIn("naos/reports/evidence/context_manifest.json", self.paths)
        self.assertNotIn("naos/reports/evidence_pack.json", self.paths)
        for value in ("naos/secure_coding_control_register.yaml", "naos/policy_overrides.d", "naos/capabilities", ".github/profiles", "templates/profiles", "naos/reports/advanced_readiness.json", "naos/reports/behavioral_evaluation.json"):
            self.assertIn(value, self.paths)
        self.assertNotIn("naos/reports/custom_readiness.json", self.paths)

    def test_public_descriptions_and_sources_select_only_reviewed_fields(self):
        import yaml
        self.assertIn("sha256_of_the_raw_declaring_file_bytes", self.literals)
        register = yaml.safe_load((KIT / "configs/secure_coding_control_register.yaml").read_text(encoding='utf-8'))
        for standard in register["standards"].values():
            self.assertIn(standard["source"], self.literals)
        for value in ("https://example.invalid/custom-standard", "https://owasp.org/custom", TOKEN, "custom_source_sha256_description"):
            self.assertNotIn(value, self.literals)

    def test_exact_external_location_constructor_is_capped_and_not_prefix_admission(self):
        from naos_evidence_export import collect_external_references
        for collection, cap in (("artifact_chunks", 200), ("results", 50)):
            references = collect_external_references({collection: [{"bounded_excerpt": "https://example.invalid/document"}] * cap}, {})
            locations = {reference["location"] for reference in references}
            self.assertEqual(locations, {"$." + collection + "[" + str(i) + "].bounded_excerpt" for i in range(cap)})
            self.assertTrue(locations <= self.literals)
            for value in ("$." + collection + "[" + str(cap) + "].bounded_excerpt", "$." + collection + "[-1].bounded_excerpt", "$." + collection + "[0].custom_excerpt"):
                self.assertNotIn(value, self.literals)
        self.assertNotIn("https://example.invalid/document", self.literals)

    def test_actual_worksheet_finding_constructor_has_only_finite_public_branch(self):
        from naos_spec_assembly_worksheet import finding
        for file in ("05-api.md", "06-acceptance.md", "07-cost-analysis.md", "08-market-analysis.md", "09-integration-contract.md"):
            row = finding(profile="standard", policy={}, status="non_applicability_decision_needed", category="spec_applicability_review", message="test", path="specs/" + file)
            self.assertIn(row["id"], self.literals)
        for value in ("spec_assembly_worksheet.non_applicability_decision_needed.specs/custom.md", "spec_assembly_worksheet.custom_status.specs/05-api.md", "spec_assembly_worksheet.non_applicability_decision_needed.custom/05-api.md"):
            self.assertNotIn(value, self.literals)

    def test_changed_caps_and_nonfinite_policy_selector_fail_closed(self):
        for relative, old, new in (("scripts/naos_local_context_query.py", "MAX_LIMIT = 50", "MAX_LIMIT = 51"), ("scripts/naos_local_context_index.py", "chunks[:200]", "chunks[:201]"), ("scripts/naos_evidence_export.py", 'policy, "task_path_report")', 'policy, dynamic_key)')):
            with tempfile.TemporaryDirectory() as directory:
                overlay = Path(directory)
                target = overlay / relative
                target.parent.mkdir(parents=True)
                text = (KIT / relative).read_text(encoding='utf-8')
                self.assertIn(old, text)
                target.write_text(text.replace(old, new), encoding='utf-8')
                with self.assertRaises(ValueError):
                    self.generator.build(KIT, overlay)


class RemainingPublicConstructorTests(FinitePublicConstructorTests):
    def test_actual_static_grader_finite_diagnostics_and_custom_neighbors(self):
        spec = importlib.util.spec_from_file_location("static_constructor_contract", KIT / "autoresearch/graders/static.py")
        static = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(static)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            report = static.StaticGrader().grade(root=root, profile="assured", naos_root="naos", policy={}, trace_report=None, trace_events=[], input_reports=[], trace_report_path=None, trace_file_path=None)
        unsupported = [item["id"] for item in report["findings"] if item["status"] == "unsupported_behavioral_dimension"]
        self.assertEqual(set(unsupported), {"STATICGRADER_UNSUPPORTED_" + v for v in static.FUTURE_BEHAVIORAL_DIMENSIONS})
        for namespace in ("naos_static_grader", "naos_grader_assessment"):
            self.assertTrue({namespace + "/" + value for value in unsupported} <= self.literals)
        for value in ("custom_grader/STATICGRADER_UNSUPPORTED_D3_instruction_following_behavior", "naos_static_grader/STATICGRADER_UNSUPPORTED_custom_dimension", "naos_evidence_classification/EC-10", "naos_evidence_classification/EC-999999", "p2:invalid-evidence:CAP-CUSTOM", TOKEN):
            self.assertNotIn(value, self.literals)

    def test_actual_scope_directory_and_requirement_reference_helpers(self):
        from naos_policy_overrides import collect_override_files
        from naos_task_context_pack import collect_spec_refs
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            overrides = root / "naos/policy_overrides.d"
            for name in ("teams", "operators", "custom"):
                (overrides / name).mkdir(parents=True)
            _, ignored, _ = collect_override_files(overrides)
            for row in ignored:
                value = Path(row["path"]).relative_to(root).as_posix()
                self.assertEqual(value in self.paths, not value.endswith("/custom"))
        template = (KIT / "templates/spec-kit/specs/03-requirements.md").read_text(encoding='utf-8')
        import re
        ids = re.findall(r"^### ((?:FR|NFR)-[0-9]+):", template, re.M)
        for requirement in ids:
            refs = collect_spec_refs({}, {"entry": {"requirement": requirement}})
            self.assertIn("specs/03-requirements.md#" + requirement.lower(), refs)
            self.assertTrue(set(refs) <= self.literals)
        self.assertNotIn("specs/03-requirements.md#fr-987654", self.literals)
        self.assertNotIn("naos/policy_overrides.d/teams/custom", self.paths)
        self.assertIn("naos/reports/ci_readiness.json", self.paths)
        self.assertNotIn("naos/reports/custom_ci_readiness.json", self.paths)

    def test_public_identifiers_leave_provider_and_assignment_detection_active(self):
        public_id = "naos_static_grader/STATICGRADER_UNSUPPORTED_D3_instruction_following_behavior"
        values = public.context_values(self.catalog, project_root=Path("/test/project"), kit_root=KIT, naos_root="naos")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "input.json").write_text(json.dumps({"public": public_id, "password": public_id, "unknown": TOKEN, "provider": "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"}), encoding='utf-8')
            with patch.object(common, "load_public_literals", return_value=(values, {"status": "valid"})):
                report = common.check_secret_hygiene(root=root, profile="assured", naos_root="naos", rules={}, rules_path=None, severity="blocking")
        self.assertTrue(any(f.get("pattern_id") == "assigned_secret" for f in report["findings"]))
        self.assertTrue(any(f.get("pattern_id") == "openai_style_key" for f in report["findings"]))
        self.assertTrue(any(f["status"] == "high_entropy_literal" for f in report["findings"]))

    def test_changed_finite_public_constructors_fail_closed(self):
        for relative, old, new in (("scripts/naos_evidence_contracts.py", 'f"{check_id}/{item[\'id\']}"', 'f"custom/{check_id}/{item[\'id\']}"'), ("scripts/secure_coding_reporting/model.py", 'f"p2:{item.get(\'id\') or index}"', 'f"p3:{item.get(\'id\') or index}"'), ("scripts/naos_ci_readiness.py", "'ci_readiness.json', field='ci_readiness'", "'custom_ci_readiness.json', field='ci_readiness'")):
            with tempfile.TemporaryDirectory() as directory:
                overlay = Path(directory)
                target = overlay / relative
                target.parent.mkdir(parents=True)
                text = (KIT / relative).read_text(encoding='utf-8')
                self.assertIn(old, text)
                target.write_text(text.replace(old, new), encoding='utf-8')
                with self.assertRaises(ValueError):
                    self.generator.build(KIT, overlay)


if __name__ == "__main__":
    unittest.main()
