"""Unreadable handoff evidence remains a review obligation, never lane approval."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator
import yaml

ROOT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()


class InvalidLaneReviewRoutingTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.handoffs = self.root / "naos/reports/parallel_lane_handoff"
        self.handoffs.mkdir(parents=True)
        (self.root / "naos/control_plane_review_items.yaml").write_text(
            yaml.safe_dump({"version": "1.0", "items": []}), encoding="utf-8"
        )

    def review(self, profile="standard"):
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/naos_control_plane_review.py"),
             "--profile", profile, "--json"], cwd=self.root,
            capture_output=True, text=True, timeout=60,
        )
        self.assertIn(result.returncode, (0, 1), result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        report = json.loads(result.stdout)
        schema = json.loads((ROOT / "schemas/naos/control_plane_review.schema.json").read_text())
        Draft202012Validator(schema).validate(report)
        return report

    def test_invalid_handoff_routes_review_without_claiming_a_declared_lane(self):
        path = self.handoffs / "synthetic-lane.json"
        for text in ('{"parallel_lanes_declared":', '[]', 'null', '{}',
                     '{"parallel_lanes_declared": "false"}'):
            path.write_text(text, encoding="utf-8")
            for profile in ("quickstart", "lite", "standard", "assured"):
                with self.subTest(text=text, profile=profile):
                    report = self.review(profile)
                    section = report["parallel_lane_handoff_reconciliation"]
                    self.assertNotEqual(section["status"], "not_applicable")
                    self.assertEqual(section["summary"]["routes_generated"], 1)
                    self.assertEqual(section["summary"]["hitl_required"], 1)
                    self.assertEqual(section["summary"]["declared_lane_reports"], 0)
                    self.assertTrue(section["source_reports"][0]["error"])
                    self.assertTrue(section["routes"][0]["hitl_required"])
                    self.assertIn("handoff_report_invalid", section["routes"][0]["hitl_reason_codes"])
                    expected = {"quickstart": "advisory", "lite": "warning",
                                "standard": "required", "assured": "required"}[profile]
                    self.assertEqual(section["routes"][0]["severity"], expected)
                    self.assertIn("agent dispatch", section["not_claimed"])
                    self.assertEqual(path.read_text(encoding="utf-8"), text)

    def test_absent_and_explicitly_undeclared_inputs_keep_not_applicable(self):
        for text in (None, '{"parallel_lanes_declared": false, "status": "not_applicable"}'):
            if text is not None:
                (self.handoffs / "unscoped.json").write_text(text, encoding="utf-8")
            section = self.review()["parallel_lane_handoff_reconciliation"]
            self.assertEqual(section["status"], "not_applicable")
            self.assertEqual(section["routes"], [])

    def test_valid_and_invalid_reports_both_reach_review_without_mutating_inputs(self):
        valid = {"parallel_lanes_declared": True, "status": "required_missing",
                 "lane": {"lane_id": "declared-lane"}, "findings": [],
                 "human_review_required": True}
        path = self.handoffs / "declared-lane.json"
        path.write_text(json.dumps(valid), encoding="utf-8")
        broken = self.handoffs / "broken.json"
        broken.write_text("[", encoding="utf-8")
        before = {p.name: p.read_bytes() for p in self.handoffs.iterdir()}
        report = self.review()
        section = report["parallel_lane_handoff_reconciliation"]
        self.assertEqual(section["summary"]["declared_lane_reports"], 1)
        self.assertEqual(section["summary"]["routes_generated"], 2)
        self.assertEqual(section["summary"]["hitl_required"], 2)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.handoffs.iterdir()})


if __name__ == "__main__":
    unittest.main()
