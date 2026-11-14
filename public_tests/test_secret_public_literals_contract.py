"""Portable public-declaration admission and unknown-credential boundaries."""
import ast
import hashlib
import importlib.util
import json
import os
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
import naos_secret_public_literals as public  # noqa: E402 - local scripts bootstrap above
import naos_hygiene_common as common  # noqa: E402 - local scripts bootstrap above

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
        namespace = {
            "Path": Path, "shutil": shutil, "SourceOrigins": object,
            "os": os, "KIT_DIR": KIT, "hashlib": hashlib,
            "UPGRADE_SOURCE_POLICY_PATH": KIT / "configs/upgrade_source_policy.yaml",
        }
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

    def session_audit_event(self, key="session_identity_report", session_id="a1b2c3d4-e5f6-4789-abcd-1234567890ef", policy=None):
        import copy
        import naos_audit_log as audit
        from naos_policy import SAFE_FALLBACK_POLICY, report_default_path, session_report_default_path
        policy = copy.deepcopy(SAFE_FALLBACK_POLICY) if policy is None else policy
        schemas = {"session_identity_report": "naos.session_identity.v1",
                   "session_lifecycle_report": "naos.session_lifecycle.v1",
                   "operator_attribution_report": "naos.operator_attribution.v1"}
        latest = report_default_path(self.root, "naos", policy, key)
        mirror = session_report_default_path(self.root, "naos", policy, session_id, key)
        body = {"schema": schemas[key], "session_id": session_id, "summary": {},
                "findings": [], "human_review_required": True}
        latest.parent.mkdir(parents=True, exist_ok=True)
        latest.write_text(json.dumps(body), encoding="utf-8")
        event = audit.build_audit_event(root=self.root, naos_root="naos", policy=policy, profile="standard",
            event_type="operator_attributed" if key == "operator_attribution_report" else "session_started",
            session_id=session_id, generated_at="2026-10-27T12:00:00Z",
            generated_by={"operator_id": "fixture-operator", "operator_source": "fixture"},
            source_report_path=latest, source_report=body, related_artifacts=[str(latest), str(mirror)])
        return event, mirror

    def save_session_event(self, event):
        import naos_audit_log as audit
        path = audit.event_file_path(self.root / "naos/audit_log", event)
        return self.write(path.relative_to(self.root), json.dumps(event) + "\n")

    def test_exact_session_paths_require_joint_source_and_mirror_witness(self):
        for key in ("session_identity_report", "session_lifecycle_report", "operator_attribution_report"):
            with self.subTest(key=key):
                event, mirror = self.session_audit_event(key)
                path = self.save_session_event(event)
                values = public.selected_public_audit_literals([path], root=self.root, naos_root="naos")
                for operand in (mirror, mirror.parent, mirror.parent.parent):
                    self.assertIn(str(operand), values)
                    self.assertIn(operand.relative_to(self.root).as_posix(), values)
                    self.assertNotIn(str(operand) + ".extra", values)
                self.assertNotIn(event["session_id"], values)

    def test_session_path_witness_mutants_do_not_expand_vocabulary(self):
        import copy
        import naos_audit_log as audit
        event, mirror = self.session_audit_event()
        variants = [
            {"related_artifacts": [event["source_report_path"]]},
            {"related_artifacts": [event["source_report_path"], str(mirror) + ".extra"]},
            {"related_artifacts": [str(mirror), event["source_report_path"]]},
            {"source_report_path": event["source_report_path"] + ".extra"},
            {"source_report": "naos.static_grader.v1"},
            {"session_id": "not/valid"},
            {"source_report_hash": None},
        ]
        for changes in variants:
            with self.subTest(fields=list(changes)):
                changed = copy.deepcopy(event)
                changed.update(changes)
                changed["event_payload_hash"] = audit.hash_json(changed["event_payload_summary"])
                body = {key: value for key, value in changed.items() if key != "event_id"}
                changed["event_id"] = "audit-sha256-" + audit.hash_json({"domain": audit.PUBLIC_EVENT_ID_SCHEME, "event": body})
                path = self.save_session_event(changed)
                values = public.selected_public_audit_literals([path], root=self.root, naos_root="naos")
                self.assertNotIn(str(mirror), values)
                self.assertNotIn(mirror.relative_to(self.root).as_posix(), values)

    def test_session_path_witness_requires_matching_summary(self):
        import copy
        import naos_audit_log as audit
        event, mirror = self.session_audit_event()
        for field, value in (("session_id", "other-session"), ("schema", "naos.static_grader.v1"),
                             ("source_report_path", event["source_report_path"] + ".extra")):
            with self.subTest(field=field):
                changed = copy.deepcopy(event)
                changed["event_payload_summary"][field] = value
                changed["event_payload_hash"] = audit.hash_json(changed["event_payload_summary"])
                body = {key: value for key, value in changed.items() if key != "event_id"}
                changed["event_id"] = "audit-sha256-" + audit.hash_json({"domain": audit.PUBLIC_EVENT_ID_SCHEME, "event": body})
                path = self.save_session_event(changed)
                values = public.selected_public_audit_literals([path], root=self.root, naos_root="naos")
                self.assertNotIn(str(mirror), values)

    def test_session_path_metadata_still_scans_neighbor_credentials_and_raw_ids(self):
        sid = "a9b8c7d6e5f4g3h2i1j0k9l8m7n6p5q4r3s2t1u0"
        event, mirror = self.session_audit_event(session_id=sid)
        self.save_session_event(event)
        report = self.scan({"session_path": str(mirror),
                            "report_root": mirror.parent.relative_to(self.root).as_posix(),
                            "session_root": str(mirror.parent.parent),
                            "raw_session_id": sid,
                            "neighbor": str(mirror) + ".extra",
                            "password": str(mirror),
                            "provider": "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"})
        by_status = [item for item in report["findings"] if item["status"] == "high_entropy_literal"]
        self.assertTrue(any(item["path"] == "input.json" for item in by_status))
        self.assertTrue(any(item.get("pattern_id") == "assigned_secret" for item in report["findings"]))
        self.assertTrue(any(item.get("pattern_id") == "openai_style_key" for item in report["findings"]))
        # The exact benign report paths on line one receive no entropy findings;
        # raw IDs and adjacent paths remain candidates.
        text = (self.root / "input.json").read_text(encoding="utf-8")
        quoted = {match.start() + 1: match.group(1) if match.group(1) is not None else match.group(2)
                  for match in common.QUOTED_SECRET_LITERAL.finditer(text)}
        values = [quoted[item["column"]] for item in by_status if item["path"] == "input.json"]
        self.assertIn(sid, values)
        self.assertTrue(public.raw_literal_representations(str(mirror) + ".extra") & set(values))
        self.assertFalse(public.raw_literal_representations(str(mirror)) & set(values))

    def test_session_paths_follow_explicit_policy_and_refuse_unsafe_segments(self):
        import copy
        from naos_policy import SAFE_FALLBACK_POLICY
        policy = copy.deepcopy(SAFE_FALLBACK_POLICY)
        policy["paths"].update({"sessions_root": "runtime/sessions", "reports_dir": "reports/current",
                                "session_identity_report": "identity/report.json"})
        event, mirror = self.session_audit_event(policy=policy)
        path = self.save_session_event(event)
        values = public.selected_public_audit_literals([path], root=self.root, naos_root="naos", policy=policy)
        # Nested report filenames do not change the constructor's reports root.
        expected_root = self.root / "naos/runtime/sessions" / event["session_id"] / "reports/current"
        self.assertIn(str(mirror), values)
        self.assertIn(str(expected_root), values)
        self.assertNotIn(str(mirror), public.selected_public_audit_literals([path], root=self.root, naos_root="naos"))
        for unsafe in ("../outside", "/absolute", "C:/outside", "nested/../outside", "nested\\outside"):
            with self.subTest(unsafe=unsafe):
                changed = copy.deepcopy(policy)
                changed["paths"]["sessions_root"] = unsafe
                values = public.selected_public_audit_literals([path], root=self.root, naos_root="naos", policy=changed)
                self.assertNotIn(str(mirror), values)

    def test_session_context_budget_preserves_original_audit_labels(self):
        event, mirror = self.session_audit_event()
        path = self.save_session_event(event)
        with patch.object(public, "_audit_session_path_literals", return_value=set()), \
             patch.object(public, "_audit_day_directory_literals", return_value=set()):
            original = public.selected_public_audit_literals([path], root=self.root, naos_root="naos")
        with patch.object(public, "MAX_CONTEXT_VALUES", len(original)):
            values = public.selected_public_audit_literals([path], root=self.root, naos_root="naos")
        self.assertEqual(values, original)
        self.assertNotIn(str(mirror), values)

    def test_session_witness_reuses_selected_audit_read_without_extra_source_reads(self):
        event, mirror = self.session_audit_event()
        path = self.save_session_event(event)
        original = Path.open
        opened = []

        def observed_open(operand, *args, **kwargs):
            opened.append(operand)
            return original(operand, *args, **kwargs)

        with patch.object(Path, "open", observed_open):
            values = public.selected_public_audit_literals([path], root=self.root, naos_root="naos")
        self.assertIn(str(mirror), values)
        self.assertEqual(opened, [path])
        self.assertFalse(public.selected_public_audit_literals([], root=self.root, naos_root="naos"))

    def test_session_paths_include_native_windows_relative_constructor_forms(self):
        import naos_audit_log as audit
        from naos_policy import SAFE_FALLBACK_POLICY
        event, _mirror = self.session_audit_event()
        # PureWindowsPath tests emitted spellings, not native Windows execution
        # or the content of a report at these model paths.
        root = PureWindowsPath("C:/fixture_root")
        latest = root / "naos/reports/session_identity.json"
        mirror = root / "naos/sessions" / event["session_id"] / "reports/session_identity.json"
        event.update(project_root=str(root), source_report_path=str(latest),
                     related_artifacts=[str(latest), str(mirror)])
        event["event_payload_summary"]["source_report_path"] = str(latest)
        event["event_payload_hash"] = audit.hash_json(event["event_payload_summary"])
        audit._assign_public_audit_event_id(event)
        self.assertEqual(audit.validate_audit_event(event), [])
        values = public._audit_session_path_literals(event, root=root, naos_root="naos",
                                                     policy=SAFE_FALLBACK_POLICY)
        for operand in (mirror, mirror.parent, mirror.parent.parent):
            relative = str(operand.relative_to(root))
            self.assertTrue(public.raw_literal_representations(relative) <= values)
            self.assertNotIn(relative + ".extra", values)
        self.assertNotIn(event["session_id"], values)
        operands = audit.event_file_paths(root / "naos/audit_log", event)
        days = public._audit_day_directory_literals(operands, root=root)
        native_day = str(operands[0].parent.relative_to(root))
        self.assertTrue(public.raw_literal_representations(native_day) <= days)

    def physical_references(self, files, *, policy=None, context=None):
        from naos_secret_managed_operands import ProofBudget
        return public._selected_physical_audit_event_references(files, root=self.root,
            naos_root="naos", policy=policy,
            context=context if context is not None else ProofBudget(self.root))

    def test_shared_physical_anchors_survive_broad_context_refusal(self):
        from naos_secret_managed_operands import ProofBudget
        event, mirror = self.session_audit_event()
        path = self.save_session_event(event)
        with patch.object(public, "collect_public_audit_event_references", return_value={}):
            self.assertEqual(public.selected_public_audit_literals(
                [path], root=self.root, naos_root="naos"), set())
            values = public.selected_public_audit_literals([path], root=self.root,
                naos_root="naos", context=ProofBudget(self.root))
        self.assertIn(str(mirror), values)
        self.assertNotIn(event['session_id'], values)
        self.assertNotIn(str(mirror) + '.extra', values)

    def test_shared_physical_anchor_preserves_filename_aliases_and_selection_order(self):
        import naos_audit_log as audit
        event, _ = self.session_audit_event()
        paths = audit.event_file_paths(self.root / 'naos/audit_log', event)
        self.assertEqual(len(paths), 2)
        for path in paths:
            self.write(path.relative_to(self.root), json.dumps(event))
            references = self.physical_references([path])
            self.assertEqual(references[event['event_id']]['event_file'], str(path))
        for selected in (list(paths), list(reversed(paths))):
            references = self.physical_references(selected)
            self.assertEqual(references[event['event_id']]['event_file'], min(map(str, paths)))
        self.assertEqual(self.physical_references([]), {})

    def test_shared_physical_anchor_rejects_malformed_and_wrapped_events(self):
        event, _ = self.session_audit_event()
        path = self.save_session_event(event)
        raw = json.dumps(event).encode()
        cases = [b'{}', b'\xff', json.dumps([event]).encode(),
                 json.dumps({'events': [event]}).encode(), raw + b'\n' + raw,
                 raw[:-1] + b',"event_id":"duplicate"}',
                 raw[:-1] + b',"unknown":NaN}', raw[:-2]]
        for bad in cases:
            with self.subTest(value=bad[:24]):
                path.write_bytes(bad)
                self.assertEqual(self.physical_references([path]), {})
        path.write_bytes(raw)
        neighbor = self.write('naos/audit_log/2026-10-27/not-an-event.jsonl', 'not-json')
        self.assertEqual(set(self.physical_references([path, neighbor])), {event['event_id']})

    def test_shared_physical_anchor_requires_default_route_and_exact_name(self):
        from naos_policy import SAFE_FALLBACK_POLICY
        event, _ = self.session_audit_event()
        path = self.save_session_event(event)
        for relative in ('audit.jsonl', 'naos/audit_log/2026-10-28/' + path.name,
                         'naos/audit_log/2026-10-27/nested/' + path.name):
            other = self.write(relative, json.dumps(event))
            self.assertEqual(self.physical_references([other]), {})
        policy = {**SAFE_FALLBACK_POLICY, 'paths': {
            **SAFE_FALLBACK_POLICY['paths'], 'audit_log_root': 'custom-audit'}}
        self.assertEqual(self.physical_references([path], policy=policy), {})
        changed = {**event, 'session_id': 'different-session'}
        path.write_text(json.dumps(changed), encoding='utf-8')
        self.assertEqual(self.physical_references([path]), {})

    def test_shared_physical_anchor_respects_proof_and_selected_file_limits(self):
        from naos_secret_managed_operands import ProofBudget, MAX_PROOF_BYTES
        event, _ = self.session_audit_event()
        path = self.save_session_event(event)
        context = ProofBudget(self.root)
        context.bytes_read = MAX_PROOF_BYTES
        self.assertEqual(self.physical_references([path], context=context), {})
        self.assertEqual(context.bytes_read, MAX_PROOF_BYTES)
        self.assertEqual(context.cache, {})
        self.assertEqual(self.physical_references([path] * 50_001), {})

    def test_shared_physical_anchor_is_cached_until_terminal_verification(self):
        from naos_secret_managed_operands import ProofBudget, _ScannerProofBudget, OperandRefusal
        event, _ = self.session_audit_event()
        path = self.save_session_event(event)
        raw = path.read_bytes()
        for budget_class in (ProofBudget, _ScannerProofBudget):
            with self.subTest(budget=budget_class.__name__):
                path.write_bytes(raw)
                context = budget_class(self.root)
                self.assertEqual(set(self.physical_references([path], context=context)), {event['event_id']})
                self.assertIn(path.relative_to(self.root).as_posix(), context.cache)
                self.assertEqual(context.bytes_read, len(raw))
                self.physical_references([path], context=context)
                self.assertEqual(context.bytes_read, len(raw))
                path.write_bytes(raw + b' ')
                with self.assertRaises(OperandRefusal):
                    if isinstance(context, _ScannerProofBudget):
                        context.finish_scanner_batch()
                    else:
                        context.admission_checkpoint()

    def test_shared_physical_anchor_refuses_link_and_modeled_reparse_input(self):
        event, _ = self.session_audit_event()
        path = self.save_session_event(event)
        original = Path.lstat
        class ReparseMetadata:
            st_file_attributes = 0x400
            def __init__(self, metadata): self.metadata = metadata
            def __getattr__(self, name): return getattr(self.metadata, name)
        def observed(operand, *args, **kwargs):
            metadata = original(operand, *args, **kwargs)
            return ReparseMetadata(metadata) if operand == path else metadata
        with patch.object(Path, 'lstat', observed):
            self.assertEqual(self.physical_references([path]), {})
        if os.name != 'nt':
            target = self.write('owned-target.json', path.read_text(encoding='utf-8'))
            before = target.read_bytes()
            path.unlink()
            path.symlink_to(target)
            self.assertEqual(self.physical_references([path]), {})
            self.assertEqual(target.read_bytes(), before)

    def test_shared_physical_anchor_rejects_timestamp_overflow_without_erasing_neighbors(self):
        import copy
        import naos_audit_log as audit
        event, _ = self.session_audit_event()
        path = self.save_session_event(event)
        for timestamp in ('0001-01-01T00:00:00+01:00', '9999-12-31T23:59:59-01:00'):
            changed = copy.deepcopy(event)
            changed['generated_at'] = timestamp
            audit._assign_public_audit_event_id(changed)
            self.assertEqual(audit.recompute_public_audit_event_id(changed), changed['event_id'])
            other = self.write('naos/audit_log/2026-10-27/overflow.jsonl', json.dumps(changed))
            self.assertEqual(set(self.physical_references([path, other])), {event['event_id']})
            self.assertEqual(self.physical_references([other]), {})
        report = common.check_secret_hygiene(root=self.root, profile='standard',
            naos_root='naos', rules={'scan_roots': ['naos'], 'include_root_files': False},
            rules_path=None, severity='required')
        self.assertEqual(report['summary']['files_failed'], 0)
        self.assertEqual(report['summary']['coverage_status'], 'complete')

    def test_shared_physical_anchor_models_windows_case_insensitive_default_path(self):
        import naos_audit_log as audit
        class WindowsPathModel(PureWindowsPath):
            def absolute(self): return self
        root = WindowsPathModel('C:/synthetic-root')
        event, _ = self.session_audit_event()
        latest = root / 'naos/reports/session_identity.json'
        mirror = root / 'naos/sessions' / event['session_id'] / 'reports/session_identity.json'
        event.update(project_root=str(root), source_report_path=str(latest),
                     related_artifacts=[str(latest), str(mirror)])
        event['event_payload_summary']['source_report_path'] = str(latest)
        event['event_payload_hash'] = audit.hash_json(event['event_payload_summary'])
        audit._assign_public_audit_event_id(event)
        expected = audit.event_file_path(root / 'naos/audit_log', event)
        physical = root / 'NAOS/Audit_Log' / expected.parent.name / expected.name.upper()
        raw = json.dumps(event).encode()
        class CachedModel:
            def __init__(self):
                self.root = root
                self.reads = []
                self.checked = False
            def read(self, relative):
                self.reads.append(relative)
                return raw
            def admission_checkpoint(self):
                self.checked = True
        proof = CachedModel()
        with patch.object(public, 'Path', WindowsPathModel):
            found = public._selected_physical_audit_event_references([physical],
                root=root, naos_root='naos', policy=None, context=proof)
        self.assertEqual(set(found), {event['event_id']})
        self.assertEqual(proof.reads, [physical.relative_to(root).as_posix()])
        self.assertTrue(proof.checked)
        # Native path classes, not arbitrary string case folding, own equality.
        self.assertEqual(physical, expected)
        self.assertNotEqual(PurePosixPath('/root/NAOS/Audit_Log'),
                            PurePosixPath('/root/naos/audit_log'))

    def test_day_label_budget_never_displaces_previous_session_labels(self):
        event, mirror = self.session_audit_event()
        path = self.save_session_event(event)
        with patch.object(public, "_audit_day_directory_literals", return_value=set()):
            previous = public.selected_public_audit_literals([path], root=self.root, naos_root="naos")
        with patch.object(public, "MAX_CONTEXT_VALUES", len(previous)):
            current = public.selected_public_audit_literals([path], root=self.root, naos_root="naos")
        self.assertEqual(current, previous)
        self.assertIn(str(mirror), current)
        self.assertNotIn(str(path.parent), current)

    def test_selected_audit_day_directory_is_exact_and_credential_checks_remain(self):
        import naos_audit_log as audit
        event = self.audit_event()
        path = audit.event_file_path(self.root / "naos/audit_log", event)
        self.write(path.relative_to(self.root), json.dumps(event) + "\n")
        values = public.selected_public_audit_literals([path], root=self.root, naos_root="naos")
        directory = path.parent
        for label in (str(directory), directory.as_posix(),
                      str(directory.relative_to(self.root)), directory.relative_to(self.root).as_posix()):
            self.assertTrue(public.raw_literal_representations(label) <= values)
        self.assertNotIn(str(directory) + ".extra", values)
        self.assertNotIn(str(directory.parent / "2026-10-10"), values)
        self.assertNotIn(str(directory.parent), values)
        relative = directory.relative_to(self.root).as_posix()
        unknown = "naos/audit_log/2026-10-10/" + TOKEN
        data = {"folder": relative, "password": relative, "unknown": unknown,
                "provider": "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"}
        report = self.scan(data)
        self.assertTrue(any(row.get("pattern_id") == "assigned_secret" for row in report["findings"]))
        self.assertTrue(any(row.get("pattern_id") == "openai_style_key" for row in report["findings"]))
        column = json.dumps(data).index(json.dumps(unknown)) + 1
        self.assertTrue(any(row["status"] == "high_entropy_literal" and row["column"] == column
                            for row in report["findings"] if row["path"] == "input.json"))

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

    def staged_kit_scan(self, payload):
        temporary = tempfile.TemporaryDirectory(prefix="NAOS-S2-A1b2C3d4E5f6-")
        self.addCleanup(temporary.cleanup)
        kit = Path(temporary.name).resolve()
        (kit / "scripts").mkdir()
        helper = kit / "scripts/naos_secret_public_literals.py"
        shutil.copy2(KIT / "scripts/naos_secret_public_literals.py", helper)
        shutil.copy2(KIT / "scripts/naos_secret_public_literals.json",
                     kit / "scripts/naos_secret_public_literals.json")
        shutil.copy2(KIT / "cli.py", kit / "cli.py")
        cli_path = str(kit / "cli.py")
        with patch.object(public, "__file__", str(helper)):
            return cli_path, self.scan(payload(cli_path))

    def test_readiness_cli_operand_is_declared_in_native_kit_contexts(self):
        catalog = public.read_catalog()
        for project, kit in (
            (PurePosixPath("/work/project"), PurePosixPath("/opt/NAOS-S2-A1b2C3")),
            (PureWindowsPath("C:/work/project"), PureWindowsPath("D:/NAOS-S2-A1b2C3")),
        ):
            with self.subTest(kit=str(kit)):
                values = public.context_values(
                    catalog, project_root=project, kit_root=kit,
                    naos_root="naos", runtime_layout="kit",
                )
                for value in (str(kit / "cli.py"), (kit / "cli.py").as_posix()):
                    self.assertTrue(public.raw_literal_representations(value) <= values)
                self.assertNotIn(str(kit / "cli.py.extra123"), values)
                self.assertNotIn(str(project / "cli.py"), values)

    def test_copied_context_does_not_invent_a_cli_destination(self):
        catalog = public.read_catalog()
        for project, kit in (
            (PurePosixPath("/work/project"), PurePosixPath("/work/project")),
            (PureWindowsPath("C:/work/project"), PureWindowsPath("C:/work/project")),
        ):
            with self.subTest(kit=str(kit)):
                values = public.context_values(
                    catalog, project_root=project, kit_root=kit,
                    naos_root="naos", runtime_layout="copied_project",
                )
                self.assertNotIn(str(project / "cli.py"), values)
                self.assertNotIn((project / "cli.py").as_posix(), values)

    def test_actual_scanner_accepts_the_exact_source_declared_cli_operand(self):
        cli_path, report = self.staged_kit_scan(
            lambda cli: {"schema": "naos.ci_readiness.v1",
                         "commands": [{"argv": [sys.executable, cli, "claims"]}]},
        )
        self.assertFalse(any(character.isspace() for character in cli_path))
        self.assertGreaterEqual(common.shannon_entropy(cli_path), 4.0)
        self.assertEqual(report["summary"]["total_findings"], 0, report["findings"])
        self.assertGreater(report["summary"]["public_literal_matches"], 0)

    def test_cli_operand_admission_preserves_credentials_and_neighbor_scanning(self):
        cli_path, report = self.staged_kit_scan(
            lambda cli: {"api_key": cli, "token": "ghp_" + "xY9" * 10,
                         "neighbor": cli + ".extra123", "unknown": TOKEN},
        )
        self.assertTrue(any(row.get("pattern_id") == "assigned_secret"
                            and row["column"] == 2 for row in report["findings"]))
        self.assertTrue(any(row.get("pattern_id") == "github_style_token"
                            for row in report["findings"]))
        source = json.dumps({"api_key": cli_path, "token": "ghp_" + "xY9" * 10,
                             "neighbor": cli_path + ".extra123", "unknown": TOKEN})
        expected_columns = {source.index(json.dumps(value)) + 1
                            for value in (cli_path + ".extra123", TOKEN)}
        entropy_columns = {row["column"] for row in report["findings"]
                           if row["status"] == "high_entropy_literal"}
        self.assertTrue(expected_columns <= entropy_columns)
        self.assertNotIn(TOKEN, json.dumps(report))



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


class GateParserGrammarContractTests(unittest.TestCase):
    """Reviewed parser syntax is public; changed content stays a candidate."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='naos-parser-grammar-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / 'scripts').mkdir()
        (self.root / 'src').mkdir()

    def scan(self):
        from naos_policy import load_policy
        return common.check_secret_hygiene(root=self.root, profile='standard', naos_root='naos',
            rules={'scan_roots': ['scripts', 'src'], 'include_root_files': False},
            rules_path=None, severity='required', policy=load_policy(root=self.root, naos_root='naos'))

    def test_gate_parser_has_one_finite_source_declaration(self):
        groups = [g for g in public.read_catalog()['groups']
                  if g['source'] == 'scripts/naos_secret_public_literals.py'
                  and g['selector'] == 'reviewed_parser:public_gate_reference_location_spans:re.compile']
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0]['values']), 6)
        component = json.dumps(groups[0]['values'], ensure_ascii=True, separators=(',', ':')).encode()
        self.assertEqual(hashlib.sha256(component).hexdigest(), groups[0]['component_sha256'])

    def test_shipped_parser_stays_quiet_and_all_four_detector_classes_stay_active(self):
        (self.root / 'scripts/naos_secret_public_literals.py').write_bytes(Path(public.__file__).read_bytes())
        body = f'unknown = "{TOKEN}"\npassword = "{TOKEN}"\nprovider = "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"\nprivate_key = "-----BEGIN PRIVATE KEY-----"\n'
        (self.root / 'src/control.py').write_text(body, encoding='utf-8')
        report = self.scan()
        helper_findings = [r for r in report['findings'] if r.get('path') == 'scripts/naos_secret_public_literals.py']
        self.assertEqual(helper_findings, [])
        controls = [r for r in report['findings'] if r.get('path') == 'src/control.py']
        self.assertEqual(len(controls), 7)
        self.assertEqual({r.get('pattern_id', r['status']) for r in controls},
                         {'assigned_secret', 'high_entropy_literal', 'openai_style_key', 'private_key_header'})
        self.assertEqual(report['summary']['coverage_status'], 'complete')

    def test_changed_parser_like_value_is_not_a_public_declaration(self):
        tree = ast.parse(Path(public.__file__).read_bytes())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                        and n.name == 'public_gate_reference_location_spans')
        grammar = next(n.args[0].value for n in ast.walk(function)
                       if isinstance(n, ast.Call) and ast.unparse(n.func) == 're.compile')
        changed = grammar + TOKEN
        (self.root / 'src/unknown.py').write_text('unknown = ' + json.dumps(changed) + '\n', encoding='utf-8')
        report = self.scan()
        self.assertTrue(any(r['status'] == 'high_entropy_literal' for r in report['findings']))


if __name__ == "__main__":
    unittest.main()
