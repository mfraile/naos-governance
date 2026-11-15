"""A1: documentation must not dilute name matches or index generated notes."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("_a1_similarity", ROOT / "scripts/naos_function_index_query.py")
QUERY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = QUERY
SPEC.loader.exec_module(QUERY)


class FunctionSimilarityContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.index_path = self.root / "similarity.json"

    def build(self, declarations, *, purpose=""):
        index = {"billing": {"money": {"source_path": "src/billing/money.py", "public": declarations,
                                       "classes": [], "purpose": purpose}}}
        with patch.object(QUERY, "load_function_index", return_value=index), \
                patch.multiple(QUERY, SIMILARITY_INDEX_PATH=self.index_path,
                               AI_PRECOMMIT_CONFIG_PATH=self.root / "no-provider.yaml"), \
                contextlib.redirect_stdout(io.StringIO()):
            QUERY.build_similarity_index()
        return json.loads(self.index_path.read_text(encoding="utf-8"))

    def query(self, phrase):
        with patch.multiple(QUERY, SIMILARITY_INDEX_PATH=self.index_path,
                            AI_PRECOMMIT_CONFIG_PATH=self.root / "no-provider.yaml"):
            return QUERY.query_similar(phrase)

    def test_documented_and_undocumented_functions_are_found_by_name(self):
        self.build(["normalize_amount(value)  # Convert a raw amount into integer cents",
                    "to_minor_units(value)"])
        self.assertIn("billing.money.normalize_amount", self.query("normalize amount"))
        self.assertIn("billing.money.to_minor_units", self.query("to minor units"))

    def test_long_docstring_cannot_reduce_an_exact_name_match(self):
        declaration = "normalize_amount(value)  # "
        short = "Convert amounts"
        long = "Validate currency precision rounding formats receipts totals balances accounts and conversion limits"
        for summary in (short, long):
            with self.subTest(summary=summary):
                self.build([declaration + summary])
                self.assertIn("1.000  billing.money.normalize_amount", self.query("normalize amount"))

    def test_generated_duplicate_paths_and_deprecation_notes_are_not_documentation(self):
        saved = self.build([
            "normalize_amount(value: Decimal) -> int  # Convert amount into cents  # DUP: also in src/app/reports/format.py; DEPRECATED",
            "to_minor_units(value)  # DUP: also in src/legacy/billing.py",
            "round_units(value)  # DEPRECATED",
        ])
        entries = saved["entries"]
        documented = entries["billing.money.normalize_amount"]
        self.assertEqual(documented["doc_tokens"], ["amount", "cents", "convert", "into"])
        self.assertEqual(documented["tokens"], ["amount", "normalize"])
        self.assertEqual(entries["billing.money.to_minor_units"]["doc_tokens"], [])
        self.assertEqual(entries["billing.money.round_units"]["doc_tokens"], [])
        for annotation in ("dup also src app reports format py", "decimal int", "deprecated"):
            with self.subTest(annotation=annotation):
                self.assertIn("No similar functions found", self.query(annotation))

    def test_meaningful_documentation_can_match_an_unrelated_name(self):
        self.build(["convert(value)  # Normalize amount"])
        self.assertIn("billing.money.convert", self.query("normalize amount"))

    def test_authored_deprecation_and_duplicate_prose_remain_searchable(self):
        for summary in ("DEPRECATED: validate document.", "DEPRECATED modules validate document.",
                        "DUP: validate document."):
            with self.subTest(summary=summary):
                saved = self.build(["convert(value)  # " + summary])
                self.assertIn("validate", saved["entries"]["billing.money.convert"]["doc_tokens"])
                self.assertIn("billing.money.convert", self.query("validate document"))

    def test_empty_unrelated_and_tag_only_descriptions_do_not_gain_matches(self):
        self.build(["normalize_amount(value)  # Synthetic unrelated description"], purpose="[TAG ONLY] Module: billing")
        for phrase in ("the and to", "missing document", "synthetic unrelated description"):
            with self.subTest(phrase=phrase):
                self.assertIn("No similar functions found", self.query(phrase))

    def test_existing_index_shape_remains_usable_without_rebuild(self):
        self.index_path.write_text(json.dumps({"_meta": {"has_embeddings": False}, "entries": {
            "billing.money.normalize_amount": {"tokens": ["normalize", "amount"],
                "doc_tokens": ["convert", "raw", "amount", "integer", "cents", "dup", "src", "format"],
                "signature": "normalize_amount(value)", "module": "src/billing/money.py"}}}), encoding="utf-8")
        self.assertIn("billing.money.normalize_amount", self.query("normalize amount"))

    def test_source_index_to_copied_cli_finds_the_actual_documented_function(self):
        import naos_code_quality_audit as quality

        source = self.root / "src/billing"
        source.mkdir(parents=True)
        declaration = 'def normalize_amount(value):\n    """Convert a raw amount into integer cents."""\n    return int(value)\n'
        (source / "money.py").write_text(declaration + '\ndef to_minor_units(value):\n    return value\n', encoding="utf-8")
        (source / "other.py").write_text(declaration, encoding="utf-8")
        inventory = self.root / "naos/inventory/FUNCTION_INDEX.yaml"
        with patch.multiple(quality, PROJECT_ROOT=self.root, SRC_DIR=self.root / "src", SRC_ROOT_VAL="src",
                            ALLOWLIST_PATH=self.root / "absent.yaml"), \
                patch.dict(os.environ, {"SRC_ROOT": "src"}), contextlib.redirect_stdout(io.StringIO()):
            quality.generate_function_index(inventory)
        self.assertIn("DUP: also in", inventory.read_text(encoding="utf-8"))
        script = self.root / "scripts/naos_function_index_query.py"
        script.parent.mkdir()
        shutil.copyfile(ROOT / "scripts/naos_function_index_query.py", script)
        env = {k: v for k, v in os.environ.items() if not k.startswith("NAOS_") and k != "SRC_ROOT"}
        env.update(PYTHONPATH=str(ROOT / "scripts"), PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")
        for arguments in (["--rebuild-index"], ["--similar", "normalize amount"], ["--similar", "to minor units"]):
            result = subprocess.run([sys.executable, "-B", str(script), *arguments], cwd=self.root,
                                    env=env, capture_output=True, text=True, encoding="utf-8", timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            if arguments[0] == "--similar":
                expected = "normalize_amount" if arguments[1] == "normalize amount" else "to_minor_units"
                self.assertIn(expected, result.stdout)
        saved = json.loads((inventory.parent / "FUNCTION_SIMILARITY_INDEX.json").read_text(encoding="utf-8"))
        self.assertFalse(saved["_meta"]["has_embeddings"])
        self.assertFalse({"dup", "also", "src", "billing", "py"} & set(
            saved["entries"]["billing.money.normalize_amount"]["doc_tokens"]))


if __name__ == "__main__":
    unittest.main()
