"""One import cannot append two events with the same normalized identifier."""

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


class HarnessBatchEventIdsTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.source = self.root / "input.jsonl"
        self.target = self.root / "naos/agent_trace_events.yaml"

    def source_records(self, *identities):
        records = [{"task_id": "T-001", "action": "read", "phase": "implementation", **identity}
                   for identity in identities]
        self.source.write_text("\n".join(json.dumps(row) for row in records) + "\n", encoding="utf-8")

    def import_events(self, *, write=False, profile="standard"):
        args = [sys.executable, "-B", str(ROOT / "scripts/naos_harness_trace_import.py"),
                "--source", str(self.source), "--profile", profile, "--json"]
        if write:
            args.append("--write-events")
        result = subprocess.run(args, cwd=self.root, capture_output=True, text=True, timeout=60)
        self.assertIn(result.returncode, (0, 1), result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        report = json.loads(result.stdout)
        schema = json.loads((ROOT / "schemas/naos/harness_trace_import.schema.json").read_text())
        Draft202012Validator(schema).validate(report)
        return report

    def test_duplicate_aliases_are_visible_in_report_only_mode(self):
        self.source_records({"id": "same-event"}, {"event_id": "same-event"})
        report = self.import_events()
        items = [f for f in report["findings"] if f["status"] == "duplicate_event_ids"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["duplicate_event_ids"], ["same-event"])
        self.assertNotEqual(report["status"], "ready")
        self.assertFalse(report["events_written"])
        self.assertFalse(self.target.exists())

    def test_duplicate_batch_preserves_existing_history_or_absence_for_all_profiles(self):
        self.source_records({"id": "duplicate"}, {"trace_id": "duplicate"}, {"id": "unique"})
        for profile in ("quickstart", "lite", "standard", "assured"):
            for existing in (False, True):
                with self.subTest(profile=profile, existing=existing):
                    self.target.parent.mkdir(parents=True, exist_ok=True)
                    if self.target.exists():
                        self.target.unlink()
                    original = b"# Existing history must stay byte-identical\nversion: 1\nevents: []\n"
                    if existing:
                        self.target.write_bytes(original)
                    report = self.import_events(write=True, profile=profile)
                    self.assertFalse(report["events_written"])
                    self.assertEqual(report["summary"]["written_events"], 0)
                    self.assertTrue(any(f["status"] == "duplicate_event_ids" for f in report["findings"]))
                    if existing:
                        self.assertEqual(self.target.read_bytes(), original)
                    else:
                        self.assertFalse(self.target.exists())

    def test_unique_case_sensitive_ids_append_and_existing_collision_still_refuses(self):
        self.source_records({"id": "Event"}, {"id": "event"})
        written = self.import_events(write=True)
        self.assertTrue(written["events_written"])
        self.assertEqual(written["summary"]["written_events"], 2)
        events = yaml.safe_load(self.target.read_text(encoding="utf-8"))["events"]
        self.assertEqual([row["event_id"] for row in events], ["Event", "event"])
        before = self.target.read_bytes()
        refused = self.import_events(write=True)
        self.assertFalse(refused["events_written"])
        self.assertTrue(any(f["status"] == "duplicate_event_ids" for f in refused["findings"]))
        self.assertEqual(self.target.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
