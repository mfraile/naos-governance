"""Trace timestamps must be checked without optional jsonschema format extras."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator, FormatChecker
import yaml

ROOT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
SCRIPT = ROOT / "scripts/naos_agent_trace_validate.py"


class TraceTimestampTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.project = Path(temporary.name).resolve()
        (self.project / "naos").mkdir()
        self.event = {"event_id": "synthetic-timestamp-event", "generated_at": "2026-05-18T12:00:00Z",
                      "session_id": "synthetic-session", "agent_or_surface": "synthetic-agent",
                      "lifecycle_phase": "session_start", "action_type": "read", "human_review_required": True,
                      "limitations": ["Declared synthetic record only."], "not_claimed": ["runtime execution proof"]}
        self.environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        self.environment.pop("NAOS_ROOT", None)

    def report(self, *, generated_at="2026-05-18T12:00:00Z", reviewed_at=None, no_extra=False, strict=False, invalid=False):
        event = {**self.event, "generated_at": generated_at, "reviewed_at": reviewed_at}
        path = self.project / "naos/agent_trace_events.yaml"
        path.write_text(yaml.safe_dump({"version": 1, "events": [event]}), encoding="utf-8")
        before = path.read_bytes()
        arguments = [str(SCRIPT), "--profile", "standard", "--json", *(["--strict"] if strict else [])]
        if no_extra:
            # Remove only the child's optional checker registration. Installed
            # packages, the canonical schema and the actual CLI stay unchanged.
            bootstrap = "from jsonschema import FormatChecker; FormatChecker.checkers.pop('date-time', None); import runpy,sys; sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0], run_name='__main__')"
            command = [sys.executable, "-B", "-c", bootstrap, *arguments]
        else:
            command = [sys.executable, "-B", *arguments]
        result = subprocess.run(command, cwd=self.project, env=self.environment,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 1 if strict and invalid else 0, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report, json.loads((self.project / "naos/reports/agent_trace_validation.json").read_text(encoding="utf-8")))
        schema = json.loads((ROOT / "schemas/naos/agent_trace_validation.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(report)
        self.assertEqual(path.read_bytes(), before)
        self.assertTrue(report["human_review_required"])
        return report

    def test_invalid_generated_timestamps_refuse_with_and_without_optional_checker(self):
        invalid = ("yesterday-ish", "2026-05-18", "2026-05-18T12:00:00", "2026-05-18 12:00:00Z",
                   "2025-02-29T12:00:00Z", "2026-05-18T24:00:00Z", "2026-05-18T12:60:00Z",
                   "2026-05-18T12:00:61Z", "2026-05-18T12:00:00+24:00", "2026-05-18T12:00:00+01:60",
                   "2026-05-18T12:00:00,5Z", "2026-05-18T12:00:00Z\n", "2026-05-18T23:59:60Z")
        for value in invalid:
            for no_extra in (False, True):
                with self.subTest(value=value, no_extra=no_extra):
                    report = self.report(generated_at=value, no_extra=no_extra, invalid=True)
                    self.assertEqual(report["invalid_event_count"], 1)
                    self.assertEqual(report["valid_event_count"], 0)
                    self.assertEqual(report["status"], "invalid_trace_events")
                    self.assertTrue(any("$.generated_at" in error for error in report["schema_validation_results"][0]["errors"]))
        strict = self.report(generated_at="yesterday-ish", no_extra=True, strict=True, invalid=True)
        self.assertTrue(any(row["status"] == "invalid_event_schema" for row in strict["findings"]))

    def test_valid_calendar_offsets_fractions_case_and_leap_second_positions_are_preserved(self):
        valid = ("2026-05-18T12:00:00Z", "2026-05-18t12:00:00z", "2024-02-29T01:02:03.123456789+02:30",
                 "2026-05-18T12:00:00-04:00", "2026-05-18T12:00:00-00:00", "0000-02-29T00:00:00Z",
                 "1990-12-31T23:59:60Z", "1991-01-01T00:59:60+01:00", "1990-12-31T15:59:60-08:00")
        for value in valid:
            with self.subTest(value=value):
                report = self.report(generated_at=value, no_extra=True)
                self.assertEqual(report["valid_event_count"], 1)
                self.assertEqual(report["invalid_event_count"], 0)
                self.assertEqual(report["status"], "ready")

    def test_optional_review_timestamp_and_local_checker_registration_do_not_relax_other_types(self):
        self.assertEqual(self.report(reviewed_at=None, no_extra=True)["valid_event_count"], 1)
        invalid = self.report(reviewed_at="yesterday-ish", no_extra=True, invalid=True)
        self.assertEqual(invalid["invalid_event_count"], 1)
        self.assertTrue(any("$.reviewed_at" in error for error in invalid["schema_validation_results"][0]["errors"]))
        invalid_type = self.report(generated_at=42, no_extra=True, invalid=True)
        self.assertEqual(invalid_type["invalid_event_count"], 1)
        spec = importlib.util.spec_from_file_location("_trace_timestamp_registration", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with patch.dict(FormatChecker.checkers, {}, clear=True):
            validator = module.canonical_event_validator()
            self.assertNotIn("date-time", FormatChecker.checkers)
            self.assertTrue(list(validator.iter_errors({**self.event, "generated_at": "yesterday-ish"})))
            self.assertFalse(list(validator.iter_errors(self.event)))
