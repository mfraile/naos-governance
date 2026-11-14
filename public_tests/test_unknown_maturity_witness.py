"""Unknown declarations remain distinct from disabled in composed reports."""

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator
import yaml


ROOT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
WITNESS_ID = "urn:naos-governance:schemas:naos:capability_maturity_collection_witness:v1"
SCHEMAS = ("capability_maturity_collection_witness", "report_source_reference", "dashboard_summary", "evidence_pack")


class UnknownMaturityWitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.project = Path(cls.temporary.name).resolve()
        (cls.project / "naos/reports").mkdir(parents=True)
        (cls.project / "src").mkdir()
        (cls.project / "src/app.py").write_text('def health():\n    return "synthetic"\n', encoding="utf-8")
        for name in ("capability_state.yaml", "gatekeepers.yaml"):
            shutil.copyfile(ROOT / "templates/structural-seeds/naos" / name, cls.project / "naos" / name)
        state = cls.project / "naos/capability_state.yaml"
        value = yaml.safe_load(state.read_text(encoding="utf-8"))
        selected = next(r for r in value["capabilities"] if r["capability_id"] == "CAP-CLAIMS-VALIDATION")
        selected["target_maturity"] = "L4"
        state.write_text(yaml.safe_dump(value), encoding="utf-8")
        cls.source_bytes = {path: path.read_bytes() for path in cls.project.rglob("*") if path.is_file()}
        cls.environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        cls.environment.pop("NAOS_ROOT", None)
        cls.maturity = cls.run_tool("naos_capability_maturity.py")
        cls.dashboard = cls.run_tool("workflows/generate_naos_dashboard.py")
        cls.pack = cls.run_tool("naos_evidence_export.py")
        cls.l4 = cls.run_tool("naos_capability_maturity.py")
        cls.witness = cls.dashboard["inputs"]["capability_maturity"]["collection_witness"]

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @classmethod
    def run_tool(cls, script):
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts" / script), "--profile", "standard", "--json"],
            cwd=cls.project, env=cls.environment, capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            raise AssertionError(result.stdout + result.stderr)
        return json.loads(result.stdout)

    def test_actual_dashboard_and_pack_accept_unknown_without_changing_source_state(self):
        unknown = [r for r in self.witness["capabilities"] if r["enabled"] is None]
        self.assertTrue(unknown)
        for row in unknown:
            self.assertEqual(row["evaluated_status"], "not_configured")
            self.assertFalse(row["ready_for_promotion"])
            self.assertFalse(row["promotion_recorded"])
        for name, report in (("dashboard_summary", self.dashboard), ("evidence_pack", self.pack)):
            with self.subTest(report=name):
                schema = json.loads((ROOT / "schemas/naos" / (name + ".schema.json")).read_text(encoding="utf-8"))
                Draft202012Validator(schema).validate(report)
        reference = json.loads((ROOT / "schemas/naos/report_source_reference.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(reference).validate(self.dashboard["inputs"]["capability_maturity"])
        for path, body in self.source_bytes.items():
            self.assertEqual(path.read_bytes(), body)

    def test_every_embedded_witness_preserves_unknown_and_refuses_false_readiness_claims(self):
        def witnesses(value):
            if isinstance(value, dict):
                if value.get("$id") == WITNESS_ID:
                    yield value
                for child in value.values():
                    yield from witnesses(child)
            elif isinstance(value, list):
                for child in value:
                    yield from witnesses(child)

        expected_counts = (1, 1, 5, 5)
        for name, count in zip(SCHEMAS, expected_counts):
            schema = json.loads((ROOT / "schemas/naos" / (name + ".schema.json")).read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            definitions = list(witnesses(schema))
            self.assertEqual(len(definitions), count)
            for index, definition in enumerate(definitions):
                with self.subTest(schema=name, definition=index):
                    validator = Draft202012Validator(definition)
                    self.assertTrue(validator.is_valid(self.witness))
                    unknown = next(row for row in self.witness["capabilities"] if row["enabled"] is None)
                    for change in ({"evaluated_status": "ready"}, {"evaluated_status": "disabled"},
                                   {"ready_for_promotion": True}, {"promotion_recorded": True}, {"enabled": "false"}):
                        bad = copy.deepcopy(self.witness)
                        bad["capabilities"] = [{**unknown, **change}]
                        self.assertFalse(validator.is_valid(bad), change)
                    for row in self.witness["capabilities"]:
                        if isinstance(row["enabled"], bool):
                            boolean = {**self.witness, "capabilities": [row]}
                            self.assertTrue(validator.is_valid(boolean))

    def test_l4_no_longer_rejects_dashboard_for_unknown_rows_and_retains_other_gaps(self):
        selected = next(row for row in self.l4["capabilities"] if row["capability_id"] == "CAP-CLAIMS-VALIDATION")
        result = next(row for row in selected["evidence_results"] if row["stage"] == "L4")
        self.assertNotIn("schema_invalid", result["reason_codes"])
        self.assertNotIn("dashboard_unresolved", result["reason_codes"])
        self.assertFalse(selected["promotion_recorded"])
        self.assertFalse(selected["ready_for_promotion"])
        self.assertEqual(selected["evaluated_status"], "blocked")
        self.assertTrue(selected["required_next_actions"])


if __name__ == "__main__":
    unittest.main()
