"""A current JSON-only index must not silently select a superseded SQLite file."""

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


class JsonOnlyIndexSelectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / "specs").mkdir()
        (self.root / "naos/reports").mkdir(parents=True)
        (self.root / "README.md").write_text("# Synthetic project\nOriginal index only.\n", encoding="utf-8")
        (self.root / "specs/original.md").write_text("# Original spec\nInitial candidate.\n", encoding="utf-8")

    def command(self, script, *args):
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts" / script), "--profile", "standard", "--json", *args],
            cwd=self.root, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        report = json.loads(result.stdout)
        schema_name = {
            "naos_local_context_index.py": "local_context_index",
            "naos_local_context_query.py": "local_context_query",
            "naos_graph_context_query.py": "graph_context_query",
        }[script]
        schema = json.loads((ROOT / "schemas/naos" / (schema_name + ".schema.json")).read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(report)
        return report

    def test_json_only_rebuild_queries_current_candidates_and_preserves_old_database(self):
        original = self.command("naos_local_context_index.py")
        database = Path(original["sqlite_artifact"]["path"])
        before = hashlib.sha256(database.read_bytes()).hexdigest()
        (self.root / "specs/zebra.md").write_text("# Zebra\nsyntheticzebraquux T-777\n", encoding="utf-8")
        current = self.command("naos_local_context_index.py", "--no-sqlite")
        self.assertFalse(current["sqlite_artifact"]["enabled"])
        self.assertIsNone(current["sqlite_artifact"]["path"])
        self.assertTrue(any(row["path"] == "specs/zebra.md" for row in current["indexed_artifacts"]))
        for script, flag, value in (
            ("naos_local_context_query.py", "--path", "specs/zebra.md"),
            ("naos_local_context_query.py", "--query", "syntheticzebraquux"),
            ("naos_graph_context_query.py", "--path", "specs/zebra.md"),
        ):
            with self.subTest(script=script, flag=flag):
                report = self.command(script, flag, value)
                self.assertFalse(report["sqlite_artifact"]["available"])
                self.assertIsNone(report["sqlite_artifact"]["path"])
                self.assertTrue(any(row["path"] == "specs/zebra.md" for row in report["source_artifacts"]))
                self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)

    def test_explicit_database_override_and_normal_sqlite_selection_are_preserved(self):
        original = self.command("naos_local_context_index.py")
        database = Path(original["sqlite_artifact"]["path"])
        before = database.read_bytes()
        for script in ("naos_local_context_query.py", "naos_graph_context_query.py"):
            with self.subTest(script=script, selection="normal"):
                report = self.command(script, "--path", "specs/original.md")
                self.assertTrue(report["sqlite_artifact"]["available"])
                self.assertTrue(any(row["path"] == "specs/original.md" for row in report["source_artifacts"]))
        self.command("naos_local_context_index.py", "--no-sqlite")
        for script in ("naos_local_context_query.py", "naos_graph_context_query.py"):
            with self.subTest(script=script, selection="explicit"):
                report = self.command(script, "--path", "specs/original.md", "--sqlite", str(database))
                self.assertTrue(report["sqlite_artifact"]["available"])
                self.assertEqual(Path(report["sqlite_artifact"]["path"]), database)
                self.assertEqual(database.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
