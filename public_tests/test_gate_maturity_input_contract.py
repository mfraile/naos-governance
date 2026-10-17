"""Gate maturity inputs must not turn parse failures into advisory readiness."""

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import naos_gate_status as gates  # noqa: E402
from naos_policy import load_policy  # noqa: E402


class GateMaturityInputContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="naos maturity é ")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cap_dir = self.root / "naos/capabilities"
        self.cap_dir.mkdir(parents=True)
        self.cap_path = self.cap_dir / "gatekeeper.yaml"
        self.contract = yaml.safe_load((ROOT / "capabilities/gatekeeper_manifest.yaml").read_text(encoding="utf-8"))
        self.cap_path.write_text(yaml.safe_dump(self.contract), encoding="utf-8")
        self.state_path = self.root / "naos/capability_state.yaml"
        self.state = {"capabilities": [{"capability_id": self.contract["id"], "current_maturity": "L3"}]}
        self.write_state(self.state)
        manifest = yaml.safe_load((ROOT / "templates/structural-seeds/naos/gatekeepers.yaml").read_text(encoding="utf-8"))
        manifest["gates"] = [g for g in manifest["gates"] if g["id"] == "G0"]
        (self.root / "gates.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")

    def write_state(self, data):
        self.state_path.write_text(yaml.safe_dump(data), encoding="utf-8")

    def run_gate(self, command="gate-evaluate", profile="assured"):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("NAOS_", "GIT_"))}
        env.update(PYTHONDONTWRITEBYTECODE="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        output = self.root / "naos/reports" / ("gate_status.json" if command == "gate-status" else "gate_evaluation.json")
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "cli.py"), command, "--profile", profile,
             "--manifest", "gates.yaml", "--output", str(output), "--json"],
            cwd=self.root, env=env, text=True, capture_output=True, timeout=30,
        )
        report = json.loads(result.stdout)
        self.assertEqual(report, json.loads(output.read_text(encoding="utf-8")))
        return result, report

    def assert_invalid(self, command="gate-evaluate", profile="assured"):
        result, report = self.run_gate(command, profile)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(report["schema"], "naos.gate_input_error.v1")
        self.assertEqual(report["status"], "invalid_input")
        self.assertTrue(report["human_review_required"])
        self.assertNotIn("summary", report)
        self.assertNotIn("Traceback", result.stderr)
        from jsonschema import Draft202012Validator
        schema = json.loads((ROOT / "schemas/naos/gate_input_error.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(report)
        return report

    def test_mature_immature_and_absent_state_keep_distinct_behavior(self):
        result, report = self.run_gate()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["gates"][0]["status"], "blocked")
        self.state["capabilities"][0]["current_maturity"] = "L0"
        self.write_state(self.state)
        result, report = self.run_gate()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(report["gates"][0]["status"], "advisory_missing")
        self.state_path.unlink()
        result, report = self.run_gate()
        self.assertEqual(result.returncode, 0)
        self.assertTrue(report["gates"][0]["maturity_gated"])

    def test_malformed_state_is_error_in_both_commands_and_every_profile(self):
        self.state_path.write_text("capabilities: [\n", encoding="utf-8")
        for command in ("gate-status", "gate-evaluate"):
            for profile in ("quickstart", "lite", "standard", "assured"):
                with self.subTest(command=command, profile=profile):
                    self.assert_invalid(command, profile)

    def test_invalid_state_structure_values_and_duplicates_are_errors(self):
        entry = self.state["capabilities"][0]
        variants = [None, [], {}, {"capabilities": None}, {"capabilities": {}},
                    {"capabilities": [None]}, {"capabilities": [{}]},
                    {"capabilities": [entry, entry]}]
        for level in (None, "", "L9", 0, False, []):
            variants.append({"capabilities": [{**entry, "current_maturity": level}]})
        for value in variants:
            with self.subTest(value=value):
                self.write_state(value)
                self.assert_invalid()

    def test_malformed_and_invalid_contracts_cannot_be_silently_skipped(self):
        variants = ["profiles: [\n", "", "null\n", "[]\n", "{}\n"]
        for field, value in (("id", None), ("gatekeepers", None), ("gatekeepers", "G0"),
                             ("default_maturity", "L9"), ("profiles", [])):
            variants.append(yaml.safe_dump({**self.contract, field: value}))
        for field, value in (("target_maturity", None), ("enforcement", "mystery")):
            data = copy.deepcopy(self.contract)
            data["profiles"]["assured"][field] = value
            variants.append(yaml.safe_dump(data))
        for body in variants:
            with self.subTest(body=body):
                self.cap_path.write_text(body, encoding="utf-8")
                self.assert_invalid()

    def test_duplicate_yaml_keys_and_contract_ids_are_rejected_without_value_disclosure(self):
        self.state_path.write_text(
            "capabilities: [\n  {capability_id: CAP-GATEKEEPER-MANIFEST, current_maturity: L3, current_maturity: L0}\n]\n",
            encoding="utf-8",
        )
        self.assert_invalid()
        self.write_state(self.state)
        (self.cap_dir / "second.yaml").write_text(yaml.safe_dump(self.contract), encoding="utf-8")
        self.assert_invalid()
        (self.cap_dir / "second.yaml").unlink()
        self.state_path.write_text("capabilities: [SYNTHETIC_PRIVATE_VALUE", encoding="utf-8")
        report = self.assert_invalid()
        self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", json.dumps(report))

    def test_unreadable_selected_file_is_not_default_state(self):
        original = Path.read_text
        def guarded(path, *args, **kwargs):
            if path == self.state_path:
                raise PermissionError("synthetic denial")
            return original(path, *args, **kwargs)
        with patch.object(Path, "read_text", guarded):
            with self.assertRaisesRegex(ValueError, "maturity input"):
                gates.build_gate_maturity_map(self.root, "naos", load_policy(), "assured")

    def test_duplicate_keys_in_merge_sources_are_rejected_by_both_commands(self):
        sources = (
            "{<<: {current_maturity: L3, current_maturity: L0}}",
            "{<<: {<<: {current_maturity: L3, current_maturity: L0}}}",
            "{<<: [{current_maturity: L3, current_maturity: L0}, {other: value}]}",
            "{<<: &level {current_maturity: L3, current_maturity: L0}}",
        )
        for source in sources:
            # The merge source is deliberately inline: flattening must validate it
            # even when no ordinary construction visits that source separately.
            body = "capabilities:\n- capability_id: CAP-GATEKEEPER-MANIFEST\n  <<: " + source + "\n"
            self.state_path.write_text(body, encoding="utf-8")
            for command in ("gate-status", "gate-evaluate"):
                with self.subTest(source=source, command=command):
                    self.assert_invalid(command)

    def test_scalar_constructor_failures_do_not_disclose_values(self):
        for tag in ("int", "float", "timestamp"):
            self.state_path.write_text("capabilities: !!" + tag + " SYNTHETICPRIVATEVALUE\n", encoding="utf-8")
            for command in ("gate-status", "gate-evaluate"):
                with self.subTest(tag=tag, command=command):
                    report = self.assert_invalid(command)
                    self.assertNotIn("SYNTHETICPRIVATEVALUE", json.dumps(report))
                    self.assertIn(str(self.state_path), report["errors"][0])

    def test_repeated_merge_directives_in_state_and_contract_are_rejected(self):
        self.state_path.write_text(
            "capabilities:\n- capability_id: CAP-GATEKEEPER-MANIFEST\n"
            "  <<: {current_maturity: L3}\n  <<: {current_maturity: L0}\n",
            encoding="utf-8",
        )
        for command in ("gate-status", "gate-evaluate"):
            with self.subTest(input="state", command=command):
                self.assert_invalid(command)
        self.write_state(self.state)
        self.cap_path.write_text(
            "id: CAP-GATEKEEPER-MANIFEST\ngatekeepers: [G0]\nprofiles:\n  assured:\n"
            "    <<: {enforcement: blocking, target_maturity: L3}\n"
            "    <<: {enforcement: advisory, target_maturity: L3}\n",
            encoding="utf-8",
        )
        for command in ("gate-status", "gate-evaluate"):
            with self.subTest(input="contract", command=command):
                self.assert_invalid(command)

    def test_reused_merge_alias_and_merge_list_precedence_remain_valid(self):
        self.state_path.write_text(
            "base: &base {current_maturity: L3}\n"
            "overridden: &overridden {<<: *base, current_maturity: L0}\n"
            "capabilities:\n"
            "- <<: *overridden\n  capability_id: CAP-GATEKEEPER-MANIFEST\n"
            "- <<: *overridden\n  capability_id: CAP-OTHER\n",
            encoding="utf-8",
        )
        result, report = self.run_gate()
        self.assertEqual(result.returncode, 0)
        self.assertTrue(report["gates"][0]["maturity_gated"])
        self.state_path.write_text(
            "capabilities:\n- capability_id: CAP-GATEKEEPER-MANIFEST\n"
            "  <<: [{current_maturity: L3}, {current_maturity: L0}]\n",
            encoding="utf-8",
        )
        result, report = self.run_gate()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["gates"][0]["status"], "blocked")

    def test_explicit_empty_collection_and_omitted_optional_maturity_keep_defaults(self):
        for state in ({"capabilities": []}, {"capabilities": [{"capability_id": self.contract["id"]}]}):
            with self.subTest(state=state):
                self.write_state(state)
                result, report = self.run_gate()
                self.assertEqual(result.returncode, 0)
                self.assertTrue(report["gates"][0]["maturity_gated"])

    def test_present_wrong_type_and_unreadable_directory_are_errors(self):
        self.cap_path.unlink()
        self.cap_dir.rmdir()
        self.cap_dir.write_text("not a directory", encoding="utf-8")
        self.assert_invalid()
        self.cap_dir.unlink()
        self.cap_dir.mkdir()
        original = Path.iterdir
        def guarded(path):
            if path == self.cap_dir:
                raise PermissionError("synthetic denial")
            return original(path)
        with patch.object(Path, "iterdir", guarded):
            with self.assertRaisesRegex(ValueError, "cannot enumerate capability directory"):
                gates.build_gate_maturity_map(self.root, "naos", load_policy(), "assured")

    def test_contract_selection_preserves_native_glob_matching(self):
        self.cap_path.unlink()
        self.state["capabilities"][0]["current_maturity"] = "L0"
        self.write_state(self.state)
        for name in ("normal.yaml", "UPPER.YAML", "MiXeD.Yaml", ".yaml"):
            path = self.cap_dir / name
            path.write_text(yaml.safe_dump(self.contract), encoding="utf-8")
            # This is the pre-existing discovery contract on the executing host.
            # Windows admits mixed-case suffixes; POSIX preserves case matching.
            selected = path in self.cap_dir.glob("*.yaml")
            self.assertEqual(bool(gates.build_gate_maturity_map(self.root, "naos", load_policy(), "assured")), selected)
            for command in ("gate-status", "gate-evaluate"):
                with self.subTest(name=name, command=command, selected=selected):
                    result, report = self.run_gate(command)
                    # Preserve each command's existing configured exit policy.
                    self.assertEqual(result.returncode, 0 if selected or command == "gate-status" else 1)
                    self.assertEqual(report["gates"][0]["status"], "advisory_missing" if selected else "blocked")
            path.unlink()

    def test_yaml_merge_and_omitted_contract_fields_keep_legacy_semantics(self):
        self.state_path.write_text(
            "capabilities:\n  - <<: {current_maturity: L3}\n    capability_id: CAP-GATEKEEPER-MANIFEST\n    current_maturity: L0\n",
            encoding="utf-8",
        )
        result, report = self.run_gate()
        self.assertEqual(result.returncode, 0)
        self.assertTrue(report["gates"][0]["maturity_gated"])
        for enforcement in ("none", "not_applicable"):
            with self.subTest(enforcement=enforcement):
                data = copy.deepcopy(self.contract)
                data["profiles"]["assured"]["enforcement"] = enforcement
                self.cap_path.write_text(yaml.safe_dump(data), encoding="utf-8")
                result, report = self.run_gate()
                self.assertEqual(result.returncode, 0)
                self.assertNotEqual(report["gates"][0]["status"], "blocked")
        self.cap_path.write_text("gatekeepers: [G0]\n", encoding="utf-8")
        result, report = self.run_gate()
        self.assertEqual(result.returncode, 0)
        self.assertTrue(report["gates"][0]["maturity_gated"])

    def test_input_error_overwrites_prior_output_and_reaches_consumers(self):
        for command in ("gate-status", "gate-evaluate"):
            self.run_gate(command)
        self.state_path.write_text("capabilities: [\n", encoding="utf-8")
        for command in ("gate-status", "gate-evaluate"):
            self.assert_invalid(command)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("NAOS_", "GIT_"))}
        env.update(PYTHONDONTWRITEBYTECODE="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        reports = {}
        for command in ("pr-governance-summary", "sarif-export", "evidence-pack", "dashboard"):
            result = subprocess.run(
                [sys.executable, "-B", str(ROOT / "cli.py"), command, "--profile", "quickstart", "--json"],
                cwd=self.root, env=env, text=True, capture_output=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            reports[command] = json.loads(result.stdout)
        finding_ids = {item["id"] for item in reports["pr-governance-summary"]["findings"]}
        self.assertIn("pr_governance.gate_status_invalid_input", finding_ids)
        self.assertIn("pr_governance.gate_evaluation_invalid_input", finding_ids)
        sarif = json.loads(Path(reports["sarif-export"]["output_path"]).read_text(encoding="utf-8"))
        self.assertTrue(any(item["properties"].get("naos_source_report") == "gate_evaluation"
                            for item in sarif["runs"][0]["results"]))
        for key in ("gate_status_report", "gate_evaluation_report"):
            self.assertEqual(reports["evidence-pack"]["artifacts"][key]["report_status"], "invalid_input")
        self.assertEqual(reports["dashboard"]["gatekeeper_readiness"]["status"], "invalid_input")
        self.assertEqual(reports["dashboard"]["gatekeeper_readiness"]["gates"], [])


if __name__ == "__main__":
    unittest.main()
