"""Shipped review rules must accept their own source and target vocabulary."""

import json
import os
from datetime import date
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator
import yaml


ROOT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
SEED = ROOT / "templates/structural-seeds/naos/control_plane_review_rules.yaml"
MISSING_TARGETS = {"claude_code_plugin_adapter", "evidence", "function_index", "governed_learning_lifecycle",
                   "human_review", "security", "spec_cascade", "specs", "tasks"}


class ReviewRoutingVocabularyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.project = Path(temporary.name).resolve()
        (self.project / "naos").mkdir()
        shutil.copyfile(SEED, self.project / "naos/control_plane_review_rules.yaml")
        self.rules = yaml.safe_load(SEED.read_text(encoding="utf-8"))
        self.environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        self.environment.pop("NAOS_ROOT", None)

    def item(self, identity, source, targets, disposition="needs_review"):
        return {"id": identity, "source_type": source, "source_ref": "naos/reports/synthetic-review.json",
                "summary": "Synthetic declared finding for bounded routing review.", "target_surfaces": targets,
                "disposition": disposition, "owner": "synthetic-owner", "review_date": date.today().isoformat()}

    def review(self, items, *, profile="standard", strict=False):
        path = self.project / "naos/control_plane_review_items.yaml"
        path.write_text(yaml.safe_dump({"version": "1.0", "items": items}), encoding="utf-8")
        sources = {p: p.read_bytes() for p in (path, self.project / "naos/control_plane_review_rules.yaml")}
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/naos_control_plane_review.py"),
             "--profile", profile, "--json", *(["--strict"] if strict else [])],
            cwd=self.project, env=self.environment, capture_output=True, text=True, timeout=120,
        )
        self.assertNotIn("Traceback", result.stderr)
        report = json.loads(result.stdout)
        saved = self.project / "naos/reports/control_plane_review.json"
        self.assertEqual(report, json.loads(saved.read_text(encoding="utf-8")))
        schema = json.loads((ROOT / "schemas/naos/control_plane_review.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(report)
        for source, body in sources.items():
            self.assertEqual(source.read_bytes(), body)
        return result, {row["id"]: row for row in report["routing_decisions"]}, report

    def test_shipped_rule_vocabulary_is_closed_and_implicit_review_fallback_is_preserved(self):
        sources = set(self.rules["source_types"])
        targets = set(self.rules["target_surfaces"])
        self.assertLessEqual(set(self.rules["expected_routing_targets"]), sources)
        self.assertLessEqual(set(self.rules["human_review_required"]), sources)
        for source, expected in self.rules["expected_routing_targets"].items():
            with self.subTest(source=source):
                self.assertLessEqual(set(expected), targets)
        self.assertTrue(sources - set(self.rules["human_review_required"]))

    def test_adapter_findings_remain_review_required_on_every_profile(self):
        items = [self.item(source, source, self.rules["expected_routing_targets"][source])
                 for source in ("adapter_coherence_finding", "adapter_propagation_finding")]
        for profile, severity in (("quickstart", "advisory"), ("lite", "warning"),
                                  ("standard", "required"), ("assured", "blocking")):
            with self.subTest(profile=profile):
                result, rows, report = self.review(items, profile=profile)
                self.assertEqual(result.returncode, 1 if profile == "assured" else 0)
                for item in items:
                    row = rows[item["id"]]
                    self.assertEqual(row["status"], "review_required")
                    self.assertEqual(row["severity"], severity)
                    self.assertTrue(row["human_review_required"])
                    self.assertEqual(row["expected_target_surfaces"], item["target_surfaces"])
                self.assertFalse(any(f["status"] == "invalid_item" for f in report["findings"]))
        strict, _, _ = self.review(items, strict=True)
        self.assertEqual(strict.returncode, 1)

    def test_previously_omitted_targets_are_required_and_unknown_labels_still_refuse(self):
        items = []
        for target in sorted(MISSING_TARGETS):
            source = next(source for source, expected in self.rules["expected_routing_targets"].items() if target in expected)
            targets = self.rules["expected_routing_targets"][source]
            items.append(self.item(target + "-full", source, targets, "routed"))
            items.append(self.item(target + "-missing", source, [t for t in targets if t != target], "routed"))
        items.extend((self.item("bad-source", "synthetic-unknown-source", ["next_actions"]),
                      self.item("bad-target", "manual_review_item", ["synthetic-unknown-target"])))
        result, rows, report = self.review(items)
        self.assertEqual(result.returncode, 0)
        for target in MISSING_TARGETS:
            with self.subTest(target=target):
                self.assertEqual(rows[target + "-full"]["status"], "routed")
                missing = rows[target + "-missing"]
                self.assertEqual(missing["status"], "missing_routing")
                self.assertIn(target, missing["missing_expected_targets"])
                self.assertTrue(missing["human_review_required"])
        for identity in ("bad-source", "bad-target"):
            self.assertEqual(rows[identity]["status"], "unknown")
            self.assertTrue(any(f["status"] == "invalid_item" and f["id"] == identity for f in report["findings"]))


if __name__ == "__main__":
    unittest.main()
