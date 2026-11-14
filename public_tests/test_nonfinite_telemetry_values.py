"""Non-finite telemetry is reviewable invalid evidence, never non-JSON output."""

from datetime import UTC, datetime
import hashlib
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


class NonfiniteTelemetryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / "naos").mkdir()
        self.record = {"record_id": "MT-synthetic", "timestamp": datetime.now(UTC).isoformat(),
                       "session_id": "synthetic-session", "task_id": "T-001", "tool": "synthetic",
                       "model_role": "planning", "provider_kind": "managed_platform", "provider": "host_tool",
                       "model": "synthetic-model", "route_class": "planning", "data_class": "repo_metadata_only",
                       "cost_usd": 0, "latency_ms": 0,
                       "policy_ref": "naos/model_provider_policy.yaml#roles.planning"}

    def report(self, *, record_values=None, thresholds=None, profile="standard", external=False, enabled=True, records=None, strict=False, expected_exit=0):
        declaration = yaml.safe_load((ROOT / "templates/structural-seeds/naos/model_telemetry_evidence.yaml").read_text(encoding="utf-8"))
        rows = records if records is not None else [{**self.record, **(record_values or {})}]
        declaration.update(enabled=enabled, telemetry_declared=enabled,
                           thresholds=thresholds if thresholds is not None else {"cost_usd_review_threshold": 1, "latency_ms_review_threshold": 1000},
                           records=rows)
        evidence = None
        if external:
            evidence = self.root / "source.jsonl"
            evidence.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            declaration.update(records=[], telemetry_sources=[{"path": str(evidence), "format": "jsonl", "source_kind": "tool_summary"}])
        path = self.root / "naos/model_telemetry_evidence.yaml"
        path.write_text(yaml.safe_dump(declaration), encoding="utf-8")
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        source_before = evidence.read_bytes() if evidence is not None else None
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/naos_model_telemetry_evidence.py"), str(self.root),
             "--profile", profile, "--json", *( ["--strict"] if strict else [])], cwd=self.root, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, expected_exit, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        def reject(value):
            raise ValueError("Non-JSON numeric constant: " + value)
        report = json.loads(result.stdout, parse_constant=reject)
        saved = json.loads((self.root / "naos/reports/model_telemetry_evidence.json").read_text(encoding="utf-8"), parse_constant=reject)
        self.assertEqual(saved, report)
        json.dumps(report, allow_nan=False)
        schema = json.loads((ROOT / "schemas/naos/model_telemetry_evidence.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(report)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)
        if evidence is not None:
            self.assertEqual(evidence.read_bytes(), source_before)
        for key in ("runtime_enabled", "provider_calls_allowed", "gateway_calls_allowed", "memory_allowed", "mcp_allowed"):
            self.assertFalse(report[key])
        return report

    def assert_invalid_numeric_review(self, report):
        self.assertTrue(any(row["id"].startswith("model_telemetry.invalid_numeric") for row in report["findings"]))
        self.assertGreater(report["reason_code_counts"]["model_telemetry_review_required"], 0)
        self.assertNotEqual(report["status"], "pass")
        self.assertTrue(report["human_review_required"])
        self.assertFalse(any(row["severity"] == "blocking" for row in report["findings"]))

    def test_nonfinite_metric_values_become_null_with_review_for_inline_and_jsonl_sources(self):
        for value in (float("nan"), float("inf"), float("-inf"), "nan", "Infinity", "-Infinity", "1e999"):
            for external in (False, True):
                with self.subTest(value=str(value), external=external):
                    report = self.report(record_values={"cost_usd": value, "latency_ms": value}, external=external)
                    self.assert_invalid_numeric_review(report)
                    self.assertIsNone(report["records"][0]["cost_usd"])
                    self.assertIsNone(report["records"][0]["latency_ms"])

    def test_nonfinite_selected_thresholds_and_aliases_cannot_disable_review(self):
        for thresholds in (
            {"cost_usd_review_threshold": float("nan"), "latency_ms_review_threshold": float("nan")},
            {"cost_usd_review_threshold": "nan", "latency_ms_review_threshold": "Infinity"},
            {"cost_usd_review_threshold": None, "max_cost_usd": float("inf"), "max_latency_ms": float("-inf")},
            {"stale_after_days": float("nan")},
        ):
            with self.subTest(thresholds=repr(thresholds)):
                self.assert_invalid_numeric_review(self.report(thresholds=thresholds))

    def test_other_projected_nonfinite_metadata_is_json_safe_and_visible(self):
        report = self.report(record_values={"input_tokens": float("inf"), "provider": float("nan")})
        self.assert_invalid_numeric_review(report)
        self.assertIsNone(report["records"][0]["input_tokens"])
        self.assertIsNone(report["records"][0]["provider"])

    def test_profiles_and_finite_neighbor_records_preserve_review_posture(self):
        for profile in ("quickstart", "lite", "standard", "assured"):
            with self.subTest(profile=profile):
                rows = [{**self.record, "record_id": "MT-invalid", "cost_usd": float("nan")},
                        {**self.record, "record_id": "MT-finite", "cost_usd": 4, "latency_ms": 1200}]
                report = self.report(profile=profile, records=rows)
                self.assert_invalid_numeric_review(report)
                self.assertEqual(len(report["records"]), 2)
                valid = next(row for row in report["records"] if row["record_id"] == "MT-finite")
                self.assertEqual((valid["cost_usd"], valid["latency_ms"]), (4, 1200))
                self.assertEqual(report["summary"]["cost_threshold_findings"], 1)
                self.assertEqual(report["summary"]["latency_threshold_findings"], 1)

    def test_finite_zero_null_and_disabled_controls_remain_unchanged(self):
        for values in ({"cost_usd": 0, "latency_ms": 0}, {"cost_usd": None, "latency_ms": None},
                       {"cost_usd": "0.5", "latency_ms": "100"}):
            with self.subTest(values=values):
                report = self.report(record_values=values)
                self.assertEqual(report["status"], "pass")
                self.assertFalse(report["findings"])
        disabled = self.report(enabled=False, thresholds={"cost_usd_review_threshold": float("nan")})
        self.assertEqual(disabled["status"], "not_configured")
        self.assertFalse(disabled["enabled"])
        self.assertFalse(disabled["records"])

    def test_strict_cli_refuses_invalid_numeric_evidence_and_accepts_clean_control(self):
        invalid = self.report(record_values={"cost_usd": float("nan")}, strict=True, expected_exit=1)
        self.assert_invalid_numeric_review(invalid)
        clean = self.report(strict=True)
        self.assertEqual(clean["status"], "pass")
        self.assertFalse(clean["findings"])
