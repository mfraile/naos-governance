"""Exact source-proved report-path echoes; other body and credential scans stay active."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import yaml
from jsonschema import Draft202012Validator
import test_windows_policy_ancestor_operands_contract as ancestors

managed = ancestors.managed
common = ancestors.common


class ReportMetadataEchoTests(unittest.TestCase):
    def setUp(self):
        self.seed = ancestors.WindowsPolicyAncestorTests()
        self.seed.setUp()
        self.addCleanup(self.seed.doCleanups)
        self.seed.prepare()
        self.control = self.seed.seed
        self.path = self.control.op + "/plan.json"
        raw = (self.control.root / self.path).read_bytes()
        text, spans, _diagnostic, _coordinates = self.seed.coordinates()
        start = next(a for a, b in spans if json.loads(text[a:b]) == ancestors.LABEL)
        self.report = {
            "schema": "naos.secret_hygiene.v1",
            "project_root": str(self.control.root),
            "naos_root": "naos",
            "scans": {
                "input_files": [
                    {
                        "path": self.path,
                        "status": "read",
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "size_bytes": len(raw),
                    }
                ]
            },
            "findings": [
                {
                    "id": "SH-1",
                    "id_scheme": "report_ordinal_v1",
                    "status": "high_entropy_literal",
                    "path": self.path,
                    "line": text[:start].count("\n") + 1,
                    "column": start - text.rfind("\n", 0, start),
                }
            ],
        }

    def spans(self, report=None):
        text = json.dumps(report or self.report, indent=2)
        return self.control.spans("naos/reports/secret_hygiene.json", text=text)

    def paths(self, report=None):
        text, spans, diagnostic = self.spans(report)
        self.assertEqual(diagnostic["status"], "proved")
        return [json.loads(text[a:b]) for a, b in spans].count(self.path)

    def test_generated_scope_states_the_narrow_report_echo_exception(self):
        scope = self.seed.scan()["scans"]["entropy_scope"]
        self.assertIn("other finding-body fields remain scanned", scope)
        self.assertIn("unique current hash/size-bound input", scope)
        self.assertIn("not report authenticity", scope)
        self.assertIn("schema-bound operational metadata", scope)
        self.assertIn("existing explicit operand exception", scope)

    def test_exact_proved_metadata_echo_adds_only_the_finding_path(self):
        self.assertEqual(self.paths(), 2)  # Inventory plus this exact echo.

    def test_repeated_echoes_parse_current_control_only_once(self):
        report = copy.deepcopy(self.report)
        report["findings"] = [
            dict(report["findings"][0], id="SH-" + str(i + 1)) for i in range(10)
        ]
        original = managed._OffsetJSON
        calls = []

        def factory(*args, **kwargs):
            coordinates = kwargs.get("exact_control_coordinates", ())
            if coordinates and all(
                len(key) == 6 and key[:4] == ancestors.PREFIX for key in coordinates
            ):
                calls.append(1)
            return original(*args, **kwargs)

        with patch.object(managed, "_OffsetJSON", side_effect=factory):
            self.assertEqual(self.paths(report), 11)
        self.assertEqual(len(calls), 1)

    def test_bare_or_nonmodern_finding_path_stays_scanned(self):
        for field, value in [
            ("id", "SH-2"),
            ("id_scheme", "other"),
            ("status", "secret_like_pattern"),
        ]:
            report = copy.deepcopy(self.report)
            report["findings"][0][field] = value
            self.assertEqual(self.paths(report), 1)
        report = copy.deepcopy(self.report)
        report["findings"] = [{"path": self.path}]
        self.assertEqual(self.paths(report), 1)

    def test_current_content_binding_and_unique_read_row_required(self):
        for variant in ["hash", "size", "duplicate", "legacy"]:
            report = copy.deepcopy(self.report)
            row = report["scans"]["input_files"][0]
            if variant == "hash":
                row["sha256"] = "0" * 64
            elif variant == "size":
                row["size_bytes"] += 1
            elif variant == "duplicate":
                report["scans"]["input_files"].append(dict(row))
            else:
                row.pop("sha256")
                row.pop("size_bytes")
            self.assertEqual(self.paths(report), len(report["scans"]["input_files"]))

    def test_only_exact_ancestor_scalar_start_is_accepted(self):
        for field, value in [
            ("column", 1),
            ("column", self.report["findings"][0]["column"] + 1),
            ("line", 2),
            ("line", True),
            ("line", 0),
        ]:
            report = copy.deepcopy(self.report)
            report["findings"][0][field] = value
            self.assertEqual(self.paths(report), 1)

    def test_other_report_fields_and_duplicate_body_remain_scanned(self):
        report = copy.deepcopy(self.report)
        report["message"] = ancestors.TOKEN
        report["findings"][0]["message"] = self.path
        report["findings"][0]["credential"] = ancestors.TOKEN
        text, spans, _diagnostic = self.spans(report)
        values = [json.loads(text[a:b]) for a, b in spans]
        self.assertEqual(values.count(self.path), 2)
        self.assertNotIn(ancestors.TOKEN, values)

    def test_broken_committed_control_chain_grants_no_echo(self):
        marker = self.control.root / self.control.op / "committed.json"
        marker.write_bytes(b"{}")
        text, spans, diagnostic = self.spans()
        self.assertEqual(diagnostic["status"], "partial_refusal")
        self.assertFalse(spans)

    def test_actual_scan_of_only_the_proved_old_report_has_no_entropy_echo(self):
        self.control.write_bytes(
            "naos/reports/secret_hygiene.json",
            json.dumps(self.report, indent=2).encode(),
        )
        with (
            patch.object(
                common,
                "_ScannerProofBudget",
                side_effect=lambda root: self.control.context(True),
            ),
            patch.object(
                managed,
                "__file__",
                self.control.kit + "\\scripts\\naos_secret_managed_operands.py",
            ),
        ):
            result = common.check_secret_hygiene(
                root=self.control.root,
                profile="standard",
                naos_root="naos",
                rules={
                    "scan_roots": ["naos/reports/secret_hygiene.json"],
                    "include_root_files": False,
                },
                rules_path=None,
                severity="blocking",
            )
        self.assertEqual(result["summary"]["total_findings"], 0, result["findings"])

    def test_neighbor_real_secret_is_detected_by_actual_scanner(self):
        report = copy.deepcopy(self.report)
        report["findings"][0]["credential"] = ancestors.TOKEN
        self.control.write_bytes(
            "naos/reports/secret_hygiene.json", json.dumps(report, indent=2).encode()
        )
        with (
            patch.object(
                common,
                "_ScannerProofBudget",
                side_effect=lambda root: self.control.context(True),
            ),
            patch.object(
                managed,
                "__file__",
                self.control.kit + "\\scripts\\naos_secret_managed_operands.py",
            ),
        ):
            result = common.check_secret_hygiene(
                root=self.control.root,
                profile="standard",
                naos_root="naos",
                rules={
                    "scan_roots": ["naos/reports/secret_hygiene.json"],
                    "include_root_files": False,
                },
                rules_path=None,
                severity="blocking",
            )
        self.assertGreater(result["summary"]["regex_matches"], 0)
        self.assertTrue(
            any(x["status"] == "secret_like_pattern" for x in result["findings"])
        )


class OperationalReportPathTests(unittest.TestCase):
    """Exercise the real scanner with small, schema-valid synthetic reports."""

    def setUp(self):
        import naos_secret_public_literals as public
        from naos_policy import SAFE_FALLBACK_POLICY

        self.public = public
        self.kit = Path(__file__).resolve().parents[1]
        temp = tempfile.TemporaryDirectory(prefix="metadata-F2k7M9p3R6w5Q8z4-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.policy = copy.deepcopy(SAFE_FALLBACK_POLICY)
        self.card = "naos/active/T-001_scope-k7m9p3w5q2.md"
        self.test = "tests/test_rule_k7m9p3w5q2.py"
        self.rule_ref = "naos/secret_hygiene_rules.yaml"
        self.rules = {
            "schema": "naos.secret_hygiene_rules.v1",
            "scan_roots": ["naos", "tests"],
            "include_root_files": False,
            "entropy_allowed_values": [self.card, self.test],
        }
        self.write(self.card, "# T-001: Synthetic example\n\n| Task ID | T-001 |\n")
        self.write(self.test, "def test_example():\n    assert 1 + 1 == 2\n")
        self.write(self.rule_ref, yaml.safe_dump(self.rules))
        self.row = {
            "id": "T-001", "title": "Synthetic example", "requirement": "FR-001",
            "phase": 1, "priority": "P1", "status": "implemented",
            "lifecycle_state": "implementation_complete", "delivery_state": "delivered",
            "verification_state": "partially_verified", "owner": "synthetic",
            "description": "Test data only; no human closure.", "dependencies": [],
        }
        self.registry = {
            "schema": "naos.task_registry.v2", "version": "2.0.0",
            "lifecycle_contract_version": 1, "last_updated": "2026-11-09",
            "total_tasks": 1, "requirements_summary": {
                "total_fr": 1, "total_nfr": 0, "total": 1,
                "status_breakdown": {"delivered": 0, "in_progress": 1,
                                     "planned": 0, "deferred": 0}},
            "phases": [{"id": 1, "name": "Synthetic", "objective": "Contract check"}],
            "tasks": [self.row],
        }
        self.write("naos/TASK_REGISTRY.yaml", yaml.safe_dump(self.registry))
        self.reports = {}
        for role in ("task_context_pack", "session_lifecycle", "test_evidence_health"):
            doc = self.minimum(role)
            doc.update(schema="naos." + role + ".v1", profile="standard",
                       naos_root="naos", project_root=str(self.root),
                       generated_at="2026-11-09T00:00:00Z")
            if role == "test_evidence_health":
                doc["test_inputs"] = [{"path": str(self.root / self.test), "status": "read"}]
            else:
                doc["task_id"] = "T-001"
                doc["task_resolution"] = {
                    "record_kind": "active", "registry_entry": copy.deepcopy(self.row),
                    "active_card_path": str(self.root / self.card),
                    "selected_card_path": str(self.root / self.card)}
                if role == "task_context_pack":
                    doc["task_card"] = {"path": str(self.root / self.card),
                                        "fields": {"Task ID": "T-001"}}
                else:
                    raw = (self.root / self.card).read_bytes()
                    record = {"path": str(Path(self.card)), "record_kind": "active",
                              "digest": hashlib.sha256(raw).hexdigest(),
                              "size_bytes": len(raw)}
                    doc["active_task_card"] = dict(record)
                    doc["task_record"] = dict(record)
            self.reports[role] = doc
            self.save(role)

    def minimum(self, role, fragment=None):
        schema = json.loads((self.kit / "schemas/naos" / (role + ".schema.json")).read_text())

        def value(spec):
            if "allOf" in spec:
                combined = {"type": "object", "properties": {}, "required": []}
                for part in spec["allOf"]:
                    if "$ref" in part:
                        resolved = schema
                        for component in part["$ref"].split("/")[1:]:
                            resolved = resolved[component]
                        part = resolved
                    combined["properties"].update(part.get("properties", {}))
                    combined["required"].extend(part.get("required", []))
                return value(combined)
            if "$ref" in spec:
                selected = schema
                for part in spec["$ref"].split("/")[1:]:
                    selected = selected[part]
                return value(selected)
            if "const" in spec:
                return spec["const"]
            if "enum" in spec:
                return spec["enum"][0]
            kind = spec.get("type")
            if isinstance(kind, list):
                kind = next((item for item in kind if item != "null"), "null")
            if kind == "object":
                return {key: value(spec["properties"][key]) for key in spec.get("required", [])}
            if kind == "array":
                return []
            if kind == "boolean":
                return False
            if kind in {"integer", "number"}:
                return 0
            if kind == "null":
                return None
            return "fixture"

        return value(schema if fragment is None else schema['$defs'][fragment])

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def save(self, role):
        doc = self.reports[role]
        schema = json.loads((self.kit / "schemas/naos" / (role + ".schema.json")).read_text())
        Draft202012Validator(schema).validate(doc)
        return self.write("naos/reports/" + role + ".json", json.dumps(doc, indent=2))

    def scan(self):
        return common.check_secret_hygiene(
            root=self.root, profile="standard", naos_root="naos",
            rules=self.rules, rules_path=self.root / self.rule_ref,
            severity="required", policy=self.policy)

    def coordinates(self, role, field):
        return self.coordinate_ref("naos/reports/" + role + ".json", field)

    def coordinate_ref(self, relative, field):
        from naos_secret_managed_operands import _OffsetJSON

        text = (self.root / relative).read_text()
        parser = _OffsetJSON(text, exact_control_coordinates={field})
        parser.parse()
        start, _end, _value = parser.strings[field]
        line = text[:start].count("\n") + 1
        column = start - text.rfind("\n", 0, start)
        return relative, line, column

    @staticmethod
    def finding_coordinates(report):
        return {(row["path"], row.get("line"), row.get("column"))
                for row in report["findings"]}

    def assert_metadata(self, role, field, *, admitted):
        coordinate = self.coordinates(role, field)
        found = coordinate in self.finding_coordinates(self.scan())
        self.assertEqual(found, not admitted, coordinate)

    def test_omitted_policy_keeps_metadata_and_credentials_scanned(self):
        self.reports["task_context_pack"]["api_key"] = "sk-" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"
        self.save("task_context_pack")
        for supplied in ({}, {"policy": None}):
            with self.subTest(supplied=supplied):
                report = common.check_secret_hygiene(
                    root=self.root, profile="standard", naos_root="naos",
                    rules=self.rules, rules_path=self.root / self.rule_ref,
                    severity="required", **supplied)
                self.assertIn(
                    self.coordinates("task_context_pack", ("task_card", "path")),
                    self.finding_coordinates(report))
                self.assertTrue(any(row["status"] == "secret_like_pattern"
                                    for row in report["findings"]))

    def test_invalid_policy_shape_admits_no_operational_metadata(self):
        from naos_secret_managed_operands import _ScannerProofBudget

        relative = "naos/reports/task_context_pack.json"
        target = self.root / relative
        for policy in (None, [], {"paths": None}, {"paths": []}):
            with self.subTest(policy=policy):
                self.assertEqual(self.public.public_operational_path_spans(
                    target.read_text(), relative, root=self.root, naos_root="naos",
                    profile="standard", selected=[target], policy=policy,
                    rules=self.rules, context=_ScannerProofBudget(self.root),
                    session_context=None), set())

    def test_crlf_metadata_uses_the_scanners_line_normalization(self):
        for role in self.reports:
            path = self.root / "naos/reports" / (role + ".json")
            raw = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            path.write_bytes(raw)
        for role, coordinate in [
            ("task_context_pack", ("task_card", "path")),
            ("session_lifecycle", ("task_resolution", "selected_card_path")),
            ("test_evidence_health", ("test_inputs", 0, "path")),
        ]:
            self.assert_metadata(role, coordinate, admitted=True)

    def test_actual_scanner_admits_only_explicit_current_task_metadata(self):
        self.assert_metadata("task_context_pack", ("task_card", "path"), admitted=True)

    def test_scanned_consumer_does_not_exhaust_independent_proof_budget(self):
        from naos_secret_managed_operands import _ScannerProofBudget, MAX_PROOF_BYTES

        self.reports["task_context_pack"]["limitations"].append("plain context " * 30_000)
        self.save("task_context_pack")
        budget = _ScannerProofBudget(self.root)
        budget.bytes_read = MAX_PROOF_BYTES - 65_536
        with patch.object(common, "_ScannerProofBudget", return_value=budget):
            report = self.scan()
        self.assertNotIn(self.coordinates("task_context_pack", ("task_card", "path")),
                         self.finding_coordinates(report))
        self.assertEqual(report["summary"]["coverage_status"], "complete")
        self.assertLessEqual(budget.bytes_read, MAX_PROOF_BYTES)

    def test_oversized_consumer_keeps_body_credentials_and_complete_coverage(self):
        self.reports['task_context_pack']['limitations'].append(
            'sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456')
        self.save('task_context_pack')
        with patch.object(managed, 'MAX_DOCUMENT_BYTES', 128):
            report = self.scan()
        self.assertEqual(report['summary']['coverage_status'], 'complete')
        self.assertEqual(report['summary']['files_failed'], 0)
        self.assertTrue(any(row.get('path') == 'naos/reports/task_context_pack.json'
                            and row.get('pattern_id') == 'openai_style_key'
                            for row in report['findings']))

    def test_actual_scanner_admits_current_lifecycle_metadata(self):
        self.assert_metadata("session_lifecycle",
                             ("task_resolution", "selected_card_path"), admitted=True)

    def test_actual_scanner_admits_explicit_selected_test_metadata(self):
        self.assert_metadata("test_evidence_health", ("test_inputs", 0, "path"), admitted=True)

    def test_existing_but_unallowlisted_task_is_still_scanned(self):
        self.rules["entropy_allowed_values"].remove(self.card)
        self.write(self.rule_ref, yaml.safe_dump(self.rules))
        self.assert_metadata("task_context_pack", ("task_card", "path"), admitted=False)

    def test_foreign_absolute_exception_does_not_rebind_by_suffix(self):
        self.rules["entropy_allowed_values"] = ["C:/different-owner/" + self.test, self.card]
        self.write(self.rule_ref, yaml.safe_dump(self.rules))
        self.assert_metadata("test_evidence_health", ("test_inputs", 0, "path"), admitted=False)

    def test_rule_bytes_must_match_active_scanner_values(self):
        self.write(self.rule_ref, yaml.safe_dump(dict(self.rules, entropy_allowed_values=[])))
        self.assert_metadata("task_context_pack", ("task_card", "path"), admitted=False)

    def test_changed_card_digest_refuses_lifecycle_path(self):
        self.write(self.card, (self.root / self.card).read_text() + "\n")
        self.assert_metadata("session_lifecycle",
                             ("task_resolution", "selected_card_path"), admitted=False)

    def test_ambiguous_active_cards_are_not_admitted(self):
        self.write("naos/active/T-001_other.md", (self.root / self.card).read_text())
        self.assert_metadata("task_context_pack", ("task_card", "path"), admitted=False)

    def test_compact_card_does_not_create_false_ambiguity(self):
        self.write("naos/active/T-001_compact.md", "# T-001: Compact context\n")
        self.assert_metadata("task_context_pack", ("task_card", "path"), admitted=True)

    def test_registry_subject_mismatch_refuses(self):
        self.registry["tasks"][0]["owner"] = "different"
        self.write("naos/TASK_REGISTRY.yaml", yaml.safe_dump(self.registry))
        self.assert_metadata("task_context_pack", ("task_card", "path"), admitted=False)

    def test_invalid_test_input_remains_scanned(self):
        self.write(self.test, "def invalid(")
        self.assert_metadata("test_evidence_health", ("test_inputs", 0, "path"), admitted=False)

    def test_wrong_project_scope_remains_scanned(self):
        self.reports["task_context_pack"]["project_root"] = str(self.root / "other")
        self.save("task_context_pack")
        self.assert_metadata("task_context_pack", ("task_card", "path"), admitted=False)

    def test_same_path_in_ordinary_body_is_not_admitted(self):
        self.reports["task_context_pack"]["ordinary_body"] = str(self.root / self.card)
        self.save("task_context_pack")
        self.assert_metadata("task_context_pack", ("ordinary_body",), admitted=False)

    def test_neighbor_credentials_survive_real_scan(self):
        self.reports["task_context_pack"]["api_key"] = "sk-" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"
        self.save("task_context_pack")
        self.assertTrue(any(row["status"] == "secret_like_pattern"
                            for row in self.scan()["findings"]))

    def test_assignment_of_allowed_path_still_reports_credential(self):
        self.reports["task_context_pack"]["api_key"] = str(self.root / self.card)
        self.save("task_context_pack")
        self.assertTrue(any(row.get("pattern_id") == "assigned_secret"
                            for row in self.scan()["findings"]))

    def mirror(self, *, anchor):
        session = "fixture-session"
        self.reports["session_lifecycle"]["session_id"] = session
        latest = self.save("session_lifecycle")
        relative = "naos/sessions/" + session + "/reports/session_lifecycle.json"
        self.write(relative, latest.read_text())
        if anchor:
            import naos_audit_log as audit
            import naos_session_identity as identity

            generated = {
                "operator_id": None, "session_id": session,
                "generated_at": "2026-11-09T00:00:00Z", "operator_source": "unknown",
                "operator_attribution_status": "unknown", "limitations": [], "not_claimed": [],
            }
            target = self.root / "naos/reports/session_identity.json"
            mirrored = self.root / "naos/sessions" / session / "reports/session_identity.json"
            with patch.object(identity, "resolve_operator_attribution", return_value={}), \
                    patch.object(identity, "build_generated_by", return_value=generated):
                report = identity.build_identity_report(self.root, "naos", "standard", {
                    "status": "session_created", "session_id": session,
                    "session_root": mirrored.parent.parent,
                    "session_report_root": mirrored.parent,
                    "index_path": self.root / "naos/sessions_index.json", "findings": []})
            for path in (target, mirrored):
                self.write(path.relative_to(self.root).as_posix(), json.dumps(report, indent=2))
            event = audit.build_audit_event(
                root=self.root, naos_root="naos", policy=self.policy,
                profile="standard", event_type="session_started", source_report=report,
                source_report_path=target, session_id=session, generated_by=generated,
                related_artifacts=[str(target), str(mirrored)])
            event_path = audit.event_file_path(self.root / "naos/audit_log", event)
            self.write(event_path.relative_to(self.root).as_posix(), json.dumps(event) + "\n")
        return relative

    def test_current_audit_anchor_and_exact_mirror_admit_metadata(self):
        relative = self.mirror(anchor=True)
        coordinate = self.coordinate_ref(relative, ("task_resolution", "selected_card_path"))
        self.assertNotIn(coordinate, self.finding_coordinates(self.scan()))

    def test_unanchored_mirror_remains_scanned(self):
        relative = self.mirror(anchor=False)
        coordinate = self.coordinate_ref(relative, ("task_resolution", "selected_card_path"))
        self.assertIn(coordinate, self.finding_coordinates(self.scan()))

    def test_unknown_role_does_not_borrow_metadata_exception(self):
        path = self.write("naos/reports/unknown-role.json",
                          json.dumps(self.reports["task_context_pack"], indent=2))
        coordinate = self.coordinate_ref(path.relative_to(self.root).as_posix(),
                                         ("task_card", "path"))
        self.assertIn(coordinate, self.finding_coordinates(self.scan()))

    def test_exact_metadata_only_changes_without_scan_coverage_change(self):
        with patch.object(common, "public_operational_path_spans", return_value=set(), create=True):
            before = self.scan()
        after = self.scan()
        removed = self.finding_coordinates(before) - self.finding_coordinates(after)
        self.assertGreater(len(removed), 0)
        self.assertEqual(after["summary"]["files_scanned"], before["summary"]["files_scanned"])
        self.assertEqual(after["summary"]["coverage_status"], before["summary"]["coverage_status"])
        self.assertEqual(after["summary"]["regex_matches"], before["summary"]["regex_matches"])


class VerifiedCollectionMetadataTests(unittest.TestCase):
    """Real producers, synthetic inputs; no execution or human approval claim."""

    def setUp(self):
        import naos_secret_public_literals as public
        from naos_policy import SAFE_FALLBACK_POLICY
        self.public = public
        self.kit = Path(__file__).resolve().parents[1]
        temporary = tempfile.TemporaryDirectory(prefix='metadata-Q7m9P2k4W6z8R3t5-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.policy = copy.deepcopy(SAFE_FALLBACK_POLICY)
        self.rules = {'scan_roots': ['naos', 'src', 'tests'], 'include_root_files': False}
        self.write('naos/policy/default_policy.yaml', yaml.safe_dump(self.policy))
        self.write('naos/secret_hygiene_rules.yaml', yaml.safe_dump(self.rules))
        self.write('src/service.py', 'def greet(name):\n    return "hello " + name\n')
        self.write('tests/test_service.py',
                   'from src.service import greet\n\ndef test_greet():\n    assert greet("world") == "hello world"\n')
        import naos_test_evidence_map as mapper
        self.map_ref = 'naos/test_evidence/source_to_test_map.json'
        self.mapping = mapper.build_map(self.root, 'standard', ['src'], ['tests'], [], self.policy)
        self.write(self.map_ref, json.dumps(self.mapping, indent=2))
        self.prepare_gate()
        self.refresh_pack()

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        return path

    def minimum(self, fragment=None):
        return OperationalReportPathTests.minimum(self, 'gate_status', fragment)

    def prepare_gate(self):
        from naos_configuration_posture_review import _digest
        scope = {'project_root': str(self.root), 'naos_root': 'naos', 'profile': 'standard'}
        posture = {'host_context': {'vendor_guidance': {'source_refs': [
            'https://vendor.invalid/alpha', 'https://vendor.invalid/beta']}},
            'host_contexts': {'copilot_harness': {'source_refs': ['https://vendor.invalid/copilot']},
                              'cursor': {'source_refs': ['https://vendor.invalid/cursor']}}}
        subject = {'schema': 'naos.configuration_posture_review.v1.subject',
                   'report_key': 'ai_surface_context_budget', 'scope': scope,
                   'configuration_posture': posture}
        envelope = {'schema': 'naos.configuration_posture_review_subject.v1',
                    'report_key': 'ai_surface_context_budget', 'scope': scope,
                    'subject': subject, 'binding': {'rules_sha256': '0' * 64,
                        'policy_sha256': None, 'effective_policy_sha256': _digest(self.policy),
                        'subject_sha256': _digest(subject)}, 'finding_bindings': [],
                    'limits': ['Synthetic constructor metadata; no human review.']}
        evidence = self.minimum('evidence_result')
        evidence.update(report_key='ai_surface_context_budget',
                        configuration_posture_review_subject=envelope)
        gate = self.minimum('gate')
        gate.update(id='G2', name='Synthetic gate', evidence_results=[
            self.minimum('evidence_result') for _ in range(3)] + [evidence])
        self.gate = self.minimum()
        self.gate.update(schema='naos.gate_status.v1', generated_at='2026-11-12T00:00:00Z',
                         project_root=str(self.root), naos_root='naos', profile='standard',
                         gates=[self.minimum('gate'), self.minimum('gate'), gate])
        schema = json.loads((self.kit / 'schemas/naos/gate_status.schema.json').read_text())
        Draft202012Validator(schema).validate(self.gate)
        for filename in ('gate_status.json', 'gate_evaluation.json'):
            self.write('naos/reports/' + filename, json.dumps(self.gate, indent=2))

    def refresh_pack(self):
        import naos_evidence_export as exporter
        from naos_report_composition import compose_publication
        args = exporter.build_parser().parse_args([])
        args.generated_at = '2026-11-12T00:00:00Z'
        self.pack = compose_publication(exporter.build_evidence_pack(root=self.root,
            profile='standard', naos_root='naos', policy=self.policy, args=args), self.root)
        schema = json.loads((self.kit / 'schemas/naos/evidence_pack.schema.json').read_text())
        Draft202012Validator(schema).validate(self.pack)
        self.pack_ref = 'naos/evidence/evidence_pack.json'
        self.write(self.pack_ref, json.dumps(self.pack, indent=2))

    def scan(self):
        return common.check_secret_hygiene(root=self.root, profile='standard',
            naos_root='naos', rules=self.rules, rules_path=None, severity='required',
            policy=self.policy)

    def coordinate(self, relative, field):
        from naos_secret_managed_operands import _OffsetJSON
        text = (self.root / relative).read_text()
        parser = _OffsetJSON(text, exact_control_coordinates={field})
        parser.parse()
        start, _, value = parser.strings[field]
        self.assertGreaterEqual(common.shannon_entropy(value), 4.0)
        return relative, text[:start].count('\n') + 1, start - text.rfind('\n', 0, start)

    @staticmethod
    def entropy_coordinates(report):
        return {(row['path'], row['line'], row['column']) for row in report['findings']
                if row['status'] == 'high_entropy_literal'}

    def test_fresh_gate_locations_are_exact_metadata_not_body_exemptions(self):
        field = ('artifacts', 'gate_evaluation_report', 'external_references', 0, 'location')
        value = self.pack['artifacts']['gate_evaluation_report']['external_references'][0]['location']
        self.pack['known_gaps'].append(value)
        self.write(self.pack_ref, json.dumps(self.pack, indent=2))
        report = self.scan()
        entropy = self.entropy_coordinates(report)
        self.assertNotIn(self.coordinate(self.pack_ref, field), entropy)
        index = next(index for index, row in enumerate(self.pack['external_references'])
                     if row['url'] == self.pack['artifacts']['gate_evaluation_report']['external_references'][0]['url'])
        self.assertNotIn(self.coordinate(self.pack_ref,
            ('external_references', index, 'location')), entropy)
        self.assertIn(self.coordinate(self.pack_ref, ('known_gaps', len(self.pack['known_gaps']) - 1)), entropy)

    def test_changed_summary_reference_cannot_borrow_a_proved_location(self):
        original = copy.deepcopy(self.pack)
        for change in ('url', 'location', 'extra_field'):
            self.pack = copy.deepcopy(original)
            row = self.pack['external_references'][0]
            if change == 'url':
                row['url'] = 'https://vendor.invalid/different'
            elif change == 'location':
                row['location'] += '.unknown_9A8b7C6d'
            else:
                row['unknown_9A8b7C6d'] = 'extra'
            self.write(self.pack_ref, json.dumps(self.pack, indent=2))
            self.assertIn(self.coordinate(self.pack_ref,
                ('external_references', 0, 'location')), self.entropy_coordinates(self.scan()))

    def test_summary_reference_requires_at_least_one_current_selected_gate_row(self):
        for filename in ('gate_status.json', 'gate_evaluation.json'):
            path = self.root / 'naos/reports' / filename
            path.write_bytes(path.read_bytes().replace(b'2026-11-12T00:00:00Z', b'2026-11-12T00:00:01Z'))
        self.assertIn(self.coordinate(self.pack_ref,
            ('external_references', 0, 'location')), self.entropy_coordinates(self.scan()))

    def test_source_test_map_projects_root_but_keeps_body_and_credentials(self):
        source = self.mapping['mappings'][0]['source']
        self.mapping['limitations'].append(source)
        self.mapping['API_KEY'] = 'sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'
        self.write(self.map_ref, json.dumps(self.mapping, indent=2))
        report = self.scan()
        entropy = self.entropy_coordinates(report)
        for field in (('mappings', 0, 'source'), ('mappings', 0, 'tests', 0, 'path'),
                      ('test_inputs', 0, 'path')):
            self.assertNotIn(self.coordinate(self.map_ref, field), entropy)
        self.assertIn(self.coordinate(self.map_ref, ('limitations', len(self.mapping['limitations']) - 1)), entropy)
        self.assertTrue(any(row.get('pattern_id') == 'openai_style_key' and row['path'] == self.map_ref
                            for row in report['findings']))

    def test_stale_same_size_gate_source_refuses_only_its_artifact_labels(self):
        source = self.root / 'naos/reports/gate_status.json'
        before = source.read_bytes()
        after = before.replace(b'2026-11-12T00:00:00Z', b'2026-11-12T00:00:01Z')
        self.assertEqual(len(after), len(before))
        self.assertNotEqual(after, before)
        source.write_bytes(after)
        entropy = self.entropy_coordinates(self.scan())
        self.assertIn(self.coordinate(self.pack_ref,
            ('artifacts', 'gate_status_report', 'external_references', 0, 'location')), entropy)
        self.assertNotIn(self.coordinate(self.pack_ref,
            ('artifacts', 'gate_evaluation_report', 'external_references', 0, 'location')), entropy)

    def test_changed_collected_location_or_order_is_not_a_navigation_proof(self):
        original = copy.deepcopy(self.pack)
        for change in ('location', 'order', 'url', 'hash'):
            self.pack = copy.deepcopy(original)
            artifact = self.pack['artifacts']['gate_evaluation_report']
            if change == 'location':
                artifact['external_references'][0]['location'] += '.unknown_key_9A8b7C6d'
            elif change == 'order':
                artifact['external_references'].reverse()
            elif change == 'url':
                artifact['external_references'][0]['url'] = 'https://vendor.invalid/changed'
            else:
                artifact['source_sha256'] = '0' * 64
            self.write(self.pack_ref, json.dumps(self.pack, indent=2))
            with self.subTest(change=change):
                self.assertIn(self.coordinate(self.pack_ref,
                    ('artifacts', 'gate_evaluation_report', 'external_references', 0, 'location')),
                    self.entropy_coordinates(self.scan()))

    def test_unselected_gate_source_does_not_authorize_navigation(self):
        self.rules['scan_roots'] = [self.pack_ref, 'naos/reports/gate_status.json', 'src', 'tests']
        entropy = self.entropy_coordinates(self.scan())
        self.assertIn(self.coordinate(self.pack_ref,
            ('artifacts', 'gate_evaluation_report', 'external_references', 0, 'location')), entropy)
        self.assertNotIn(self.coordinate(self.pack_ref,
            ('artifacts', 'gate_status_report', 'external_references', 0, 'location')), entropy)

    def test_high_entropy_relative_source_name_stays_a_finding(self):
        import naos_test_evidence_map as mapper
        name = 'q9W8e7R6t5Y4u3I2o1P0a9S8d7F6g5H4'
        self.write('src/' + name + '.py', 'def greet(name):\n    return name\n')
        self.write('tests/test_' + name + '.py',
                   'from src.' + name + ' import greet\n\ndef test_name():\n    assert greet("ok") == "ok"\n')
        self.mapping = mapper.build_map(self.root, 'standard', ['src'], ['tests'], [], self.policy)
        self.write(self.map_ref, json.dumps(self.mapping, indent=2))
        index = next(i for i, row in enumerate(self.mapping['mappings']) if name in row['source'])
        normal = next(i for i, row in enumerate(self.mapping['mappings']) if name not in row['source'])
        entropy = self.entropy_coordinates(self.scan())
        self.assertIn(self.coordinate(self.map_ref, ('mappings', index, 'source')), entropy)
        self.assertNotIn(self.coordinate(self.map_ref, ('mappings', normal, 'source')), entropy)

    def test_changed_test_import_and_unselected_inputs_refuse_projection(self):
        source_field = self.coordinate(self.map_ref, ('mappings', 0, 'source'))
        self.write('tests/test_service.py', 'def test_other():\n    assert True\n')
        self.assertIn(source_field, self.entropy_coordinates(self.scan()))
        self.rules['scan_roots'] = [self.map_ref]
        self.assertIn(source_field, self.entropy_coordinates(self.scan()))

    def test_malformed_map_does_not_grant_path_projection(self):
        source_field = self.coordinate(self.map_ref, ('mappings', 0, 'source'))
        raw = (self.root / self.map_ref).read_text()
        self.write(self.map_ref, raw[:-1] + ', "profile": "standard"}')
        self.assertIn(source_field, self.entropy_coordinates(self.scan()))

    def test_absolute_default_source_root_keeps_the_same_path_roles(self):
        import naos_test_evidence_map as mapper
        self.mapping = mapper.build_map(self.root, 'standard', [str(self.root / 'src')],
                                        ['tests'], [], self.policy)
        self.write(self.map_ref, json.dumps(self.mapping, indent=2))
        entropy = self.entropy_coordinates(self.scan())
        self.assertNotIn(self.coordinate(self.map_ref, ('mappings', 0, 'source')), entropy)

    def test_gate_source_above_old_reference_limit_uses_existing_eight_mib_domain(self):
        self.gate['limitations'].append(' ' * (1024 * 1024 + 64))
        for filename in ('gate_status.json', 'gate_evaluation.json'):
            self.write('naos/reports/' + filename, json.dumps(self.gate, indent=2))
        self.refresh_pack()
        entropy = self.entropy_coordinates(self.scan())
        self.assertNotIn(self.coordinate(self.pack_ref,
            ('artifacts', 'gate_evaluation_report', 'external_references', 0, 'location')), entropy)

    def test_shared_proof_budget_refuses_both_metadata_routes(self):
        from naos_secret_managed_operands import ProofBudget, MAX_PROOF_BYTES
        selected = sorted(path for path in self.root.rglob('*') if path.is_file())
        for route, relative in ((self.public.public_gate_reference_location_spans, self.pack_ref),
                                (self.public.public_source_test_path_projections, self.map_ref)):
            context = ProofBudget(self.root)
            context.bytes_read = MAX_PROOF_BYTES
            result = route((self.root / relative).read_text(), relative, root=self.root,
                naos_root='naos', profile='standard', selected=selected,
                policy=self.policy, context=context)
            self.assertFalse(result)
            self.assertEqual(context.bytes_read, MAX_PROOF_BYTES)

    def test_source_substitution_after_projection_prevents_a_scanner_report(self):
        from naos_secret_managed_operands import OperandRefusal
        original = common.public_source_test_path_projections
        changed = []
        def substitute(*args, **kwargs):
            result = original(*args, **kwargs)
            if result and not changed:
                self.write('src/service.py', 'def replaced():\n    return False\n')
                changed.append(True)
            return result
        with patch.object(common, 'public_source_test_path_projections', substitute):
            with self.assertRaises(OperandRefusal):
                self.scan()
        self.assertEqual(changed, [True])

    def test_current_collected_url_credential_remains_detected(self):
        from naos_configuration_posture_review import _digest
        envelope = self.gate['gates'][2]['evidence_results'][3]['configuration_posture_review_subject']
        url = 'https://vendor.invalid/sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'
        envelope['subject']['configuration_posture']['host_context']['vendor_guidance']['source_refs'][0] = url
        envelope['binding']['subject_sha256'] = _digest(envelope['subject'])
        for filename in ('gate_status.json', 'gate_evaluation.json'):
            self.write('naos/reports/' + filename, json.dumps(self.gate, indent=2))
        self.refresh_pack()
        rows = self.pack['artifacts']['gate_evaluation_report']['external_references']
        index = next(i for i, row in enumerate(rows) if row['url'] == url)
        report = self.scan()
        self.assertNotIn(self.coordinate(self.pack_ref,
            ('artifacts', 'gate_evaluation_report', 'external_references', index, 'location')),
            self.entropy_coordinates(report))
        self.assertTrue(any(row.get('pattern_id') == 'openai_style_key' and row['path'] == self.pack_ref
                            for row in report['findings']))

    def test_current_source_unknown_location_tail_is_not_a_public_label(self):
        from naos_configuration_posture_review import _digest
        envelope = self.gate['gates'][2]['evidence_results'][3]['configuration_posture_review_subject']
        envelope['subject']['configuration_posture']['host_context']['unknown_9A8b7C6d'] = {
            'source_refs': ['https://vendor.invalid/unknown']}
        envelope['binding']['subject_sha256'] = _digest(envelope['subject'])
        for filename in ('gate_status.json', 'gate_evaluation.json'):
            self.write('naos/reports/' + filename, json.dumps(self.gate, indent=2))
        self.refresh_pack()
        rows = self.pack['artifacts']['gate_evaluation_report']['external_references']
        index = next(i for i, row in enumerate(rows) if 'unknown_9A8b7C6d' in row['location'])
        self.assertIn(self.coordinate(self.pack_ref,
            ('artifacts', 'gate_evaluation_report', 'external_references', index, 'location')),
            self.entropy_coordinates(self.scan()))

    def test_none_and_malformed_policy_grant_neither_metadata_route(self):
        from naos_secret_managed_operands import ProofBudget
        selected = sorted(path for path in self.root.rglob('*') if path.is_file())
        for policy in (None, {'paths': None}):
            for route, relative in ((self.public.public_gate_reference_location_spans, self.pack_ref),
                                    (self.public.public_source_test_path_projections, self.map_ref)):
                self.assertFalse(route((self.root / relative).read_text(), relative,
                    root=self.root, naos_root='naos', profile='standard', selected=selected,
                    policy=policy, context=ProofBudget(self.root)))

    def test_windows_model_matches_selected_path_case_without_folding_filename(self):
        from pathlib import PureWindowsPath
        import naos_policy as policy_module
        import naos_test_evidence_map as mapper
        class WindowsPathModel(PureWindowsPath):
            def absolute(self): return self
            def resolve(self, *args, **kwargs): return self
            def is_symlink(self): return False
            def is_dir(self): return self in {root, root / 'naos', root / 'src', root / 'tests'}
            def is_file(self): return self in {root / name for name in data}
        root = WindowsPathModel('C:/synthetic-root')
        document = copy.deepcopy(self.mapping)
        document['mappings'][0]['source'] = str(root / 'src/service.py')
        document['mappings'][0]['tests'][0]['path'] = str(root / 'tests/test_service.py')
        document['test_inputs'][0]['path'] = str(root / 'tests/test_service.py')
        text = json.dumps(document, indent=2)
        data = {self.map_ref: text.encode(), 'src/service.py': (self.root / 'src/service.py').read_bytes(),
                'tests/test_service.py': (self.root / 'tests/test_service.py').read_bytes()}
        class ProofModel:
            def __init__(self): self.root = root
            def read(self, relative): return data[relative]
            def admission_checkpoint(self): pass
        def paths(*args):
            return WindowsPathModel(*args) if args and str(args[0]).startswith('C:') else Path(*args)
        selected = [root / self.map_ref, root / 'SRC/service.py', root / 'TESTS/test_service.py']
        with patch.object(self.public, 'Path', paths), patch.object(policy_module, 'Path', paths), \
                patch.object(mapper, 'Path', paths):
            projections = self.public.public_source_test_path_projections(text, self.map_ref,
                root=root, naos_root='naos', profile='standard', selected=selected,
                policy=self.policy, context=ProofModel())
        self.assertEqual(len(projections), 3)
        self.assertEqual(set(projections.values()), {'src/service.py', 'tests/test_service.py'})


class DependencyReceiptMetadataTests(unittest.TestCase):
    """Source-bound key labels do not assert receipt validity or authenticity."""

    def setUp(self):
        from naos_policy import SAFE_FALLBACK_POLICY

        temporary = tempfile.TemporaryDirectory(prefix="receipt-key-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.operand = "src/aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z.txt"
        target = self.root / self.operand
        target.parent.mkdir()
        target.write_text("ordinary source\n")
        self.policy = copy.deepcopy(SAFE_FALLBACK_POLICY)
        self.relative = "naos/reports/self_check_dependency_resolution.json"
        self.carrier = self.root / self.relative
        self.carrier.parent.mkdir(parents=True)
        self.bindings = {"project:" + self.operand: hashlib.sha256(target.read_bytes()).hexdigest()}
        self.report = {
            "schema": "naos.self_check_dependency_resolution.v1",
            "project_root": str(self.root),
            "naos_root": "naos",
            "proof": {"source_bindings": self.bindings},
        }

    def save(self):
        self.report["proof"]["source_binding_sha256"] = hashlib.sha256(
            json.dumps(self.bindings, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.carrier.write_text(json.dumps(self.report, indent=2))

    def scan(self, **kwargs):
        return common.check_secret_hygiene(
            root=self.root, profile="standard", naos_root="naos",
            rules={"scan_roots": [self.relative], "include_root_files": False},
            rules_path=None, severity="blocking", policy=kwargs.get("policy", self.policy),
        )

    def test_current_source_binding_key_does_not_create_an_entropy_finding(self):
        self.save()
        report = self.scan()
        self.assertEqual(report["summary"]["total_findings"], 0, report["findings"])

    def key_is_detected(self, report, label=None):
        text = self.carrier.read_text()
        label = label or "project:" + self.operand
        coordinate = ("proof", "source_bindings", ("object_key", label))
        parser = managed._OffsetJSON(text, exact_control_coordinates={coordinate})
        parser.parse()
        start = parser.strings[coordinate][0]
        position = (text[:start].count("\n") + 1, start - text.rfind("\n", 0, start))
        return any(row["status"] == "high_entropy_literal"
                   and (row["line"], row["column"]) == position for row in report["findings"])

    def test_body_unknown_content_and_credentials_remain_detected(self):
        self.report["body"] = "project:" + self.operand
        self.report["API_KEY"] = "project:" + self.operand
        self.report["unknown"] = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z+/="
        self.report["provider"] = ancestors.TOKEN
        self.save()
        report = self.scan()
        self.assertFalse(self.key_is_detected(report))
        self.assertEqual(report["summary"]["total_findings"], 6, report["findings"])
        self.assertEqual(sorted(row["pattern_id"] for row in report["findings"]
                                if row["status"] == "secret_like_pattern"),
                         ["assigned_secret", "openai_style_key"])

    def test_wrong_role_scope_schema_or_map_digest_grants_no_key_allowance(self):
        self.save()
        original = copy.deepcopy(self.report)
        for variant in ("role", "root", "schema", "map_digest", "missing_policy"):
            with self.subTest(variant=variant):
                self.report = copy.deepcopy(original)
                chosen = self.policy
                if variant == "role":
                    chosen = copy.deepcopy(self.policy)
                    chosen["paths"]["self_check_dependency_resolution_report"] = "other.json"
                elif variant == "root":
                    self.report["project_root"] = str(self.root / "wrong")
                elif variant == "schema":
                    self.report["schema"] = "naos.unknown.v1"
                elif variant == "missing_policy":
                    chosen = None
                self.save()
                if variant == "map_digest":
                    self.report["proof"]["source_binding_sha256"] = "0" * 64
                    self.carrier.write_text(json.dumps(self.report, indent=2))
                self.assertTrue(self.key_is_detected(self.scan(policy=chosen)))

    def test_stale_missing_and_linked_sources_remain_findings(self):
        self.save()
        target = self.root / self.operand
        target.write_text("changed source\n")
        self.assertTrue(self.key_is_detected(self.scan()))
        target.unlink()
        self.assertTrue(self.key_is_detected(self.scan()))
        other = self.root / "other.txt"
        other.write_text("ordinary source\n")
        try:
            target.symlink_to(other)
        except OSError as error:
            self.skipTest(f"Native link creation unavailable: {error}")
        self.assertTrue(self.key_is_detected(self.scan()))

    def test_namespace_traversal_and_private_source_names_grant_no_allowance(self):
        for label in ("other:" + self.operand, "project:src/../" + self.operand,
                      "project:.git/" + self.operand, "project:" + self.operand + ".env"):
            with self.subTest(label=label):
                self.bindings = {label: next(iter(self.bindings.values()))}
                self.report["proof"]["source_bindings"] = self.bindings
                self.save()
                self.assertTrue(self.key_is_detected(self.scan(), label))

    def test_exact_kit_reference_shares_budget_and_terminal_verification(self):
        kit = self.root / "kit"
        relative = "schemas/naos/aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z.json"
        source = kit / relative
        source.parent.mkdir(parents=True)
        source.write_text('{"type":"object"}\n')
        self.bindings = {"kit:" + relative: hashlib.sha256(source.read_bytes()).hexdigest()}
        self.report["proof"]["source_bindings"] = self.bindings
        self.save()
        budget = managed._ScannerProofBudget(self.root)
        with (patch.object(managed, "__file__", str(kit / "scripts/naos_secret_managed_operands.py")),
              patch.object(common, "_ScannerProofBudget", return_value=budget)):
            report = self.scan()
        self.assertEqual(report["summary"]["total_findings"], 0, report["findings"])
        self.assertIs(budget.schema_context.shared_budget, budget)
        self.assertEqual(budget.bytes_read, source.stat().st_size)
        self.assertIn(relative, budget.schema_context.cache)

    def test_unknown_or_changed_kit_reference_remains_detected(self):
        self.bindings = {"kit:" + self.operand: next(iter(self.bindings.values()))}
        self.report["proof"]["source_bindings"] = self.bindings
        self.save()
        self.assertTrue(self.key_is_detected(self.scan(), next(iter(self.bindings))))
        kit = self.root / "kit"
        relative = "schemas/naos/aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z.json"
        target = kit / relative
        target.parent.mkdir(parents=True)
        target.write_text("changed schema\n")
        self.bindings = {"kit:" + relative: "0" * 64}
        self.report["proof"]["source_bindings"] = self.bindings
        self.save()
        with patch.object(managed, "__file__", str(kit / "scripts/naos_secret_managed_operands.py")):
            self.assertTrue(self.key_is_detected(self.scan(), next(iter(self.bindings))))

    def test_unalerted_projected_binding_is_not_read(self):
        self.bindings["project:naos/sessions_index.json"] = "0" * 64
        self.save()
        original = managed.ProofBudget.read

        def guarded(owner, relative):
            self.assertNotEqual(relative, "naos/sessions_index.json")
            return original(owner, relative)

        with patch.object(managed.ProofBudget, "read", guarded):
            self.assertEqual(self.scan()["summary"]["total_findings"], 0)

    def test_proof_exhaustion_keeps_findings_and_late_substitution_refuses_report(self):
        self.save()
        budget = managed._ScannerProofBudget(self.root)
        budget.bytes_read = managed.MAX_PROOF_BYTES
        with patch.object(common, "_ScannerProofBudget", return_value=budget):
            self.assertTrue(self.key_is_detected(self.scan()))
        original = managed.ProofBudget.read
        changed = []

        def substitute(owner, relative):
            raw = original(owner, relative)
            if relative == self.operand and not changed:
                changed.append(True)
                (self.root / relative).write_bytes(raw + b"changed\n")
            return raw

        with patch.object(managed.ProofBudget, "read", substitute):
            with self.assertRaisesRegex(managed.OperandRefusal, "scan_proof_invalidated"):
                self.scan()

    def test_crlf_and_escaped_keys_use_original_quote_coordinates(self):
        self.report["body"] = "project:" + self.operand
        self.save()
        text = self.carrier.read_text().replace("project:", "project\\u003a").replace("\n", "\r\n")
        self.carrier.write_bytes(text.encode())
        report = self.scan()
        self.assertFalse(self.key_is_detected(report))
        self.assertEqual(report["summary"]["total_findings"], 1, report["findings"])

    def test_destination_selection_does_not_read_an_existing_receipt(self):
        from naos_self_check_dependency_resolution import receipt_output_path

        self.carrier.write_bytes(b"invalid JSON remains untouched")
        with patch.object(Path, "read_bytes", side_effect=AssertionError("selector read payload")):
            self.assertEqual(receipt_output_path(self.root, "naos", self.policy), self.carrier)
            self.assertEqual(common._selected_dependency_receipt(self.root, "naos", self.policy), self.relative)

    def test_protected_input_and_report_aliases_are_not_selected(self):
        for key, relative in (("sessions_index", self.relative.removeprefix("naos/")),
                              ("secret_hygiene_report", self.carrier.name)):
            with self.subTest(key=key):
                policy = copy.deepcopy(self.policy)
                policy["paths"][key] = relative
                self.assertIsNone(common._selected_dependency_receipt(self.root, "naos", policy))

    def test_malformed_optional_selector_inputs_and_bounds_grant_no_allowance(self):
        for policy in (None, {}, {"paths": []}, {**self.policy, "_meta": ["bad"]}):
            self.assertIsNone(common._selected_dependency_receipt(self.root, "naos", policy))
        self.save()
        for bound in ("MAX_IDENTITIES", "MAX_METADATA_NODES", "MAX_REPRESENTATIONS"):
            with self.subTest(bound=bound):
                with patch.object(managed, bound, 0):
                    report = self.scan()
                self.assertTrue(self.key_is_detected(report))

    def test_non_string_policy_key_does_not_abort_ordinary_scanning(self):
        self.save()
        policy = copy.deepcopy(self.policy)
        policy["paths"][1] = "unused.json"
        self.assertIsNone(common._selected_dependency_receipt(self.root, "naos", policy))
        self.assertTrue(self.key_is_detected(self.scan(policy=policy)))


class SelectedConsumerBudgetTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="consumer-proof-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.first = self.root / "first.json"
        self.second = self.root / "second.json"
        self.first.write_bytes(b'{"value":"first"}')
        self.second.write_bytes(b'{"value":"second"}')

    def test_consumer_eviction_and_later_source_read_keep_original_charge(self):
        budget = managed._ScannerProofBudget(self.root)
        self.assertEqual(budget.read_scanned_consumer("first.json"), self.first.read_bytes())
        self.assertEqual(budget.read("first.json"), self.first.read_bytes())
        self.assertEqual(budget.bytes_read, 0)
        budget.end_scanned_consumer()
        self.assertNotIn("first.json", budget.cache)
        self.assertEqual(budget.read("first.json"), self.first.read_bytes())
        self.assertEqual(budget.bytes_read, self.first.stat().st_size)
        budget.finish_scanner_batch()

    def test_only_one_consumer_buffer_survives(self):
        budget = managed._ScannerProofBudget(self.root)
        budget.read_scanned_consumer("first.json")
        budget.read_scanned_consumer("second.json")
        self.assertNotIn("first.json", budget.cache)
        self.assertIn("second.json", budget.cache)
        budget.finish_scanner_batch()
        self.assertNotIn("second.json", budget.cache)

    def test_independent_source_exhaustion_still_refuses(self):
        budget = managed._ScannerProofBudget(self.root)
        budget.bytes_read = managed.MAX_PROOF_BYTES
        self.assertEqual(budget.read_scanned_consumer("first.json"), self.first.read_bytes())
        with self.assertRaisesRegex(managed.OperandRefusal, "proof_bytes"):
            budget.read("second.json")
        self.assertEqual(budget.bytes_read, managed.MAX_PROOF_BYTES)

    def test_evicted_consumer_substitution_invalidates_final_result(self):
        budget = managed._ScannerProofBudget(self.root)
        budget.read_scanned_consumer("first.json")
        budget.end_scanned_consumer()
        self.first.write_bytes(b'{"value":"changed"}')
        with self.assertRaisesRegex(managed.OperandRefusal, "scan_proof_invalidated"):
            budget.finish_scanner_batch()
        with self.assertRaisesRegex(managed.OperandRefusal, "scan_proof_invalidated"):
            budget.read("second.json")

    def test_previously_charged_source_does_not_receive_refund(self):
        budget = managed._ScannerProofBudget(self.root)
        budget.read("first.json")
        charged = budget.bytes_read
        budget.read_scanned_consumer("first.json")
        budget.end_scanned_consumer()
        self.assertEqual(budget.bytes_read, charged)
        self.assertIn("first.json", budget.cache)

    def test_consumer_read_uses_descriptor_identity_checks(self):
        budget = managed._ScannerProofBudget(self.root)
        with patch.object(managed, '_descriptor_matches_path', return_value=False):
            with self.assertRaisesRegex(managed.OperandRefusal, 'substitution'):
                budget.read_scanned_consumer('first.json')
        self.assertNotIn('first.json', budget.cache)

    def test_consumer_parent_link_is_refused_before_leaf_inspection(self):
        import stat
        from types import SimpleNamespace

        alias = self.root / 'alias'
        alias.mkdir()
        budget = managed._ScannerProofBudget(self.root)
        original = Path.lstat

        def guarded(path, *args, **kwargs):
            self.assertNotEqual(path, alias / 'first.json')
            if path == alias:
                return SimpleNamespace(st_mode=stat.S_IFLNK)
            return original(path, *args, **kwargs)

        with patch.object(Path, 'lstat', guarded):
            with self.assertRaisesRegex(managed.OperandRefusal, 'unsafe_ancestor'):
                budget.read_scanned_consumer('alias/first.json')

    def test_observed_consumer_change_stays_invalid_after_bytes_are_restored(self):
        budget = managed._ScannerProofBudget(self.root)
        original = self.first.read_bytes()
        budget.read_scanned_consumer('first.json')
        budget.end_scanned_consumer()
        self.first.write_bytes(original + b'changed')
        with self.assertRaises(managed.OperandRefusal):
            budget.read('first.json')
        self.first.write_bytes(original)
        with self.assertRaisesRegex(managed.OperandRefusal, 'scan_proof_invalidated'):
            budget.read_scanned_consumer('second.json')

    def test_oversized_consumer_declines_optimization_without_reading(self):
        budget = managed._ScannerProofBudget(self.root)
        with patch.object(managed, "MAX_DOCUMENT_BYTES", 1):
            self.assertIsNone(budget.read_scanned_consumer("first.json"))
        self.assertEqual(budget.bytes_read, 0)
        self.assertEqual(budget.cache, {})

    def test_fresh_growth_after_preflight_declines_only_the_optimization(self):
        self.first.write_bytes(b'{}')
        original = managed.ProofBudget.read

        def grow(owner, relative):
            self.first.write_bytes(b'{"value":"grown beyond the consumer cap"}')
            return original(owner, relative)

        budget = managed._ScannerProofBudget(self.root)
        with patch.object(managed, 'MAX_DOCUMENT_BYTES', 8), \
                patch.object(managed.ProofBudget, 'read', grow):
            self.assertIsNone(budget.read_scanned_consumer('first.json'))
        self.assertFalse(budget._invalidated)
        self.assertEqual(budget.cache, {})
        self.assertIn(b'grown', self.first.read_bytes())

    def test_observed_growth_refuses_before_and_after_preflight(self):
        original = managed.ProofBudget.read
        for during_read in (False, True):
            with self.subTest(during_read=during_read):
                self.first.write_bytes(b'{}')
                budget = managed._ScannerProofBudget(self.root)
                budget.read_scanned_consumer('first.json')
                budget.end_scanned_consumer()

                def grow(owner, relative):
                    if during_read:
                        self.first.write_bytes(b'{"value":"changed observed file"}')
                    return original(owner, relative)

                if not during_read:
                    self.first.write_bytes(b'{"value":"changed observed file"}')
                with patch.object(managed, 'MAX_DOCUMENT_BYTES', 8), \
                        patch.object(managed.ProofBudget, 'read', grow):
                    with self.assertRaises(managed.OperandRefusal):
                        budget.read_scanned_consumer('first.json')
                self.assertTrue(budget._invalidated)


if __name__ == "__main__":
    unittest.main()
