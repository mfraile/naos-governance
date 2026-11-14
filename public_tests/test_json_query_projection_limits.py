"""Known JSON projection omissions must be visible without weakening the cap."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()


class JsonQueryProjectionLimitTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / "specs").mkdir()
        (self.root / "naos/reports").mkdir(parents=True)

    def fixture(self, count, *, sqlite=False):
        for number in range(count):
            text = f"# Spec {number}\nTask T-{9000 + number}\n"
            text += "boundarytailtoken\n" if number == count - 1 else "ordinary context\n"
            (self.root / "specs" / f"{number:03d}.md").write_text(text, encoding="utf-8")
        report = self.command("naos_local_context_index.py", *([] if sqlite else ["--no-sqlite"]))
        self.assertEqual(report["summary"]["chunks"], count)
        self.assertEqual(report["summary"]["links"], count)
        self.assertEqual(len(report["artifact_chunks"]), min(count, 200))
        self.assertEqual(len(report["artifact_links"]), min(count, 200))
        self.assertEqual(report["collection_coverage"]["status"], "complete_within_configured_bounds")
        self.index_path = self.root / "naos/reports/local_context_index.json"
        return hashlib.sha256(self.index_path.read_bytes()).hexdigest()

    def command(self, script, *args):
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts" / script), "--profile", "standard", "--json", *args],
            cwd=self.root, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        report = json.loads(result.stdout)
        schema_name = {"naos_local_context_index.py": "local_context_index",
                       "naos_local_context_query.py": "local_context_query",
                       "naos_graph_context_query.py": "graph_context_query"}[script]
        schema = json.loads((ROOT / "schemas/naos" / (schema_name + ".schema.json")).read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(report)
        return report

    def projection_findings(self, report):
        return [row for row in report["findings"] if ".json_projection_partial_" in row["id"]]

    def test_json_keyword_and_link_queries_disclose_the_known_unsearched_portion(self):
        before = self.fixture(230)
        for script, flag, value in (
            ("naos_local_context_query.py", "--query", "boundarytailtoken"),
            ("naos_local_context_query.py", "--task", "T-9229"),
            ("naos_graph_context_query.py", "--task", "T-9229"),
        ):
            with self.subTest(script=script, flag=flag):
                report = self.command(script, flag, value)
                self.assertEqual(report["result_count"], 0)
                rows = self.projection_findings(report)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["severity"], "advisory")
                self.assertIn("200 of 230", rows[0]["message"])
                self.assertIn("30 unavailable", rows[0]["message"])
                self.assertIn("not query completeness", rows[0]["message"])
                self.assertEqual(hashlib.sha256(self.index_path.read_bytes()).hexdigest(), before)

    def test_exact_path_metadata_is_not_falsely_degraded_by_missing_chunks(self):
        self.fixture(230)
        report = self.command("naos_local_context_query.py", "--path", "specs/229.md")
        self.assertTrue(any(row["path"] == "specs/229.md" for row in report["results"]))
        self.assertFalse(self.projection_findings(report))

    def test_complete_json_inputs_have_no_projection_warning(self):
        self.fixture(3)
        for script, flag, value in (
            ("naos_local_context_query.py", "--query", "boundarytailtoken"),
            ("naos_local_context_query.py", "--task", "T-9002"),
            ("naos_graph_context_query.py", "--task", "T-9002"),
        ):
            with self.subTest(script=script, flag=flag):
                report = self.command(script, flag, value)
                self.assertGreater(report["result_count"], 0)
                self.assertFalse(self.projection_findings(report))

    def test_full_sqlite_does_not_inherit_the_json_preview_limit(self):
        self.fixture(230, sqlite=True)
        for script, flag, value in (
            ("naos_local_context_query.py", "--query", "boundarytailtoken"),
            ("naos_local_context_query.py", "--task", "T-9229"),
            ("naos_graph_context_query.py", "--task", "T-9229"),
        ):
            with self.subTest(script=script, flag=flag):
                report = self.command(script, flag, value)
                self.assertTrue(report["sqlite_artifact"]["available"])
                self.assertGreater(report["result_count"], 0)
                self.assertFalse(self.projection_findings(report))

    def test_combined_modes_use_distinct_findings_and_invalid_totals_do_not_crash(self):
        self.fixture(230)
        report = self.command("naos_local_context_query.py", "--query", "boundarytailtoken", "--task", "T-9229")
        rows = self.projection_findings(report)
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({row["id"] for row in rows}), 2)
        original = json.loads(self.index_path.read_text(encoding="utf-8"))
        for value in (True, "230", -1, None):
            with self.subTest(total=value):
                changed = dict(original, chunk_counts={"chunks": value}, link_counts={"links": value})
                self.index_path.write_text(json.dumps(changed), encoding="utf-8")
                report = self.command("naos_local_context_query.py", "--query", "boundarytailtoken", "--task", "T-9229")
                self.assertFalse(self.projection_findings(report))


if __name__ == "__main__":
    unittest.main()
