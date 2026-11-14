"""Canonical numeric zero is an active review threshold, not an absent value."""

from datetime import UTC, datetime
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


class ZeroTelemetryThresholdTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / "naos").mkdir()
        self.record = {"record_id": "MT-synthetic", "timestamp": datetime.now(UTC).isoformat(),
                       "session_id": "synthetic-session", "task_id": "T-001", "tool": "synthetic",
                       "model_role": "planning", "provider_kind": "managed_platform", "provider": "host_tool",
                       "model": "synthetic-model", "route_class": "planning", "data_class": "repo_metadata_only",
                       "cost_usd": 4, "latency_ms": 1200,
                       "policy_ref": "naos/model_provider_policy.yaml#roles.planning"}

    def report(self, thresholds, profile="standard", **record_values):
        declaration = yaml.safe_load((ROOT / "templates/structural-seeds/naos/model_telemetry_evidence.yaml").read_text(encoding="utf-8"))
        declaration.update(enabled=True, telemetry_declared=True, thresholds=thresholds,
                           records=[{**self.record, **record_values}])
        (self.root / "naos/model_telemetry_evidence.yaml").write_text(yaml.safe_dump(declaration), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/naos_model_telemetry_evidence.py"), str(self.root),
             "--profile", profile, "--json"],
            cwd=self.root, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        schema = json.loads((ROOT / "schemas/naos/model_telemetry_evidence.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(report)
        for key in ("runtime_enabled", "provider_calls_allowed", "gateway_calls_allowed", "memory_allowed", "mcp_allowed"):
            self.assertFalse(report[key])
        return report

    def threshold_reasons(self, report):
        return [row["reason_code"] for row in report["findings"] if row["reason_code"] in
                {"cost_threshold_exceeded", "latency_threshold_exceeded"}]

    def test_zero_canonical_thresholds_flag_positive_values_in_every_profile(self):
        for profile in ("quickstart", "lite", "standard", "assured"):
            with self.subTest(profile=profile):
                report = self.report({"cost_usd_review_threshold": 0, "latency_ms_review_threshold": 0}, profile)
                self.assertCountEqual(self.threshold_reasons(report), ["cost_threshold_exceeded", "latency_threshold_exceeded"])
                self.assertFalse(any(row["severity"] == "blocking" for row in report["findings"]))

    def test_zero_canonical_values_override_permissive_legacy_aliases(self):
        report = self.report({"cost_usd_review_threshold": 0.0, "latency_ms_review_threshold": 0.0,
                              "max_cost_usd": 100, "max_latency_ms": 10000})
        self.assertCountEqual(self.threshold_reasons(report), ["cost_threshold_exceeded", "latency_threshold_exceeded"])

    def test_missing_null_alias_and_equality_controls_keep_their_existing_semantics(self):
        for primary in ({}, {"cost_usd_review_threshold": None, "latency_ms_review_threshold": None}):
            with self.subTest(primary=primary):
                report = self.report({**primary, "max_cost_usd": 1, "max_latency_ms": 1000})
                self.assertCountEqual(self.threshold_reasons(report), ["cost_threshold_exceeded", "latency_threshold_exceeded"])
        for thresholds in (
            {}, {"cost_usd_review_threshold": None, "latency_ms_review_threshold": None},
            {"cost_usd_review_threshold": 4, "latency_ms_review_threshold": 1200},
            {"cost_usd_review_threshold": 100, "latency_ms_review_threshold": 10000, "max_cost_usd": 0, "max_latency_ms": 0},
        ):
            with self.subTest(thresholds=thresholds):
                self.assertFalse(self.threshold_reasons(self.report(thresholds)))
        zero = {"cost_usd_review_threshold": 0, "latency_ms_review_threshold": 0}
        self.assertFalse(self.threshold_reasons(self.report(zero, cost_usd=0, latency_ms=0)))


if __name__ == "__main__":
    unittest.main()
