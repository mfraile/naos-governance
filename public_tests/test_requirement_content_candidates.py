"""Content-backed review hints; file presence never establishes a requirement."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from jsonschema import Draft202012Validator

ROOT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(ROOT / "scripts"))
import naos_adoption_common as adoption  # noqa: E402


class RequirementContentCandidatesTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.args = argparse.Namespace(naos_root="naos", mode="brownfield")

    def file(self, name, body):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")

    def report(self):
        with mock.patch.object(adoption, "read_report", return_value={}):
            result = adoption.build_requirements_reconstruct(
                self.args, self.root, "standard", {}
            )
        schema = json.loads(
            (ROOT / "schemas/naos/candidate_requirements.schema.json").read_text()
        )
        Draft202012Validator(schema).validate(result)
        self.assertEqual(result["promotion_rule"], "human_review_required")
        self.assertFalse(result["reconstruction_coverage"]["requirements_complete"])
        for item in result["candidates"]:
            self.assertTrue(item["human_review_required"])
            self.assertFalse(item["promoted_to_authority"])
        return result

    def test_empty_modules_and_comment_only_modules_have_no_candidates(self):
        for name, text in (("app/__init__.py", ""),
                           ("app/security.py", "# authentication\n"),
                           ("tests/test_empty.py", " \n")):
            self.file(name, text)
        result = self.report()
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["candidates"][0]["source_basis"], "missing_evidence")
        self.assertEqual(result["candidates"][0]["evidence_refs"], [])

    def test_named_callable_and_readme_section_replace_generic_file_hints(self):
        self.file("app/payments.py", 'def normalize_amount(raw):\n'
                  '    """Convert a raw amount into integer cents."""\n'
                  '    return int(raw * 100)\n')
        self.file("README.md", "# Payment service\n\n```md\n## Fake section\n```\n"
                  "\n## Amount normalization\nConvert amounts to cents.\n")
        items = {c["evidence_refs"][0]: c for c in self.report()["candidates"]}
        self.assertIn("normalize_amount", items["app/payments.py"]["title"])
        self.assertIn("Convert a raw amount", items["app/payments.py"]["title"])
        self.assertIn("Amount normalization", items["README.md"]["title"])
        self.assertNotIn("Fake section", items["README.md"]["title"])

    def test_test_methods_are_selected_once_as_tests_even_with_repository_overlap(self):
        path = "tests/test_payments.py"
        self.file(path, "class PaymentsTests:\n"
                  "    def test_normalize_amount(self):\n        assert True\n")
        records = [{"source_path": path, "family_id": family,
                    "source_revalidated": True} for family in ("source", "tests")]
        setattr(self.args, adoption._ADOPTION_REPOSITORY_INTELLIGENCE_ATTR,
                {"candidates": records, "retrieval_candidates": []})
        result = self.report()
        items = [c for c in result["candidates"] if path in c["evidence_refs"]]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["source_basis"], "tests_or_ci")
        self.assertIn("PaymentsTests.test_normalize_amount", items[0]["title"])
        self.assertEqual(result["reconstruction_coverage"]["categories"]["source"]["matched"], 0)
        self.assertEqual(result["reconstruction_coverage"]["evidence_selection"]["source"]["available"], 0)

    def test_module_docstring_is_a_cue_but_imports_or_broken_code_are_not(self):
        self.file("app/documented.py", '"""Convert local amounts to cents."""\nimport decimal\n')
        self.file("app/imports.py", "import decimal\n")
        self.file("app/private.py", "def _helper():\n    return 1\n")
        self.file("app/broken.py", "def guessed_behavior(\n")
        items = self.report()["candidates"]
        self.assertEqual(len(items), 1)
        self.assertIn("Convert local amounts to cents", items[0]["title"])
        self.assertEqual(items[0]["evidence_refs"], ["app/documented.py"])

    def test_retrieved_empty_module_stays_absent_and_named_retrieval_keeps_priority(self):
        self.file("app/__init__.py", "")
        self.file("extras/api.py", "async def fetch_amount():\n    return 1\n")
        records = [{"source_path": path, "family_id": "source",
                    "source_revalidated": True, "lane": "fts"}
                   for path in ("app/__init__.py", "extras/api.py")]
        setattr(self.args, adoption._ADOPTION_REPOSITORY_INTELLIGENCE_ATTR,
                {"candidates": [], "retrieval_candidates": records})
        items = self.report()["candidates"]
        self.assertEqual(len(items), 1)
        self.assertIn("fetch_amount", items[0]["title"])
        self.assertEqual(items[0]["repository_intelligence_review_priority"]["rank"], 1)

    def test_other_declarations_and_workflow_jobs_have_observed_names(self):
        for name, body, cue in (
            ("app/pay.js", "export function convertAmount(raw) { return raw; }\n", "convertAmount"),
            ("app/pay.ts", "export async function fetchAmount() { return 1; }\n", "fetchAmount"),
            ("app/pay.go", "func ConvertAmount(raw int) int { return raw }\n", "ConvertAmount"),
            ("app/Pay.java", "public int convertAmount(int raw) { return raw; }\n", "convertAmount"),
            (".github/workflows/check.yml", "jobs:\n  check_amount:\n    runs-on: ubuntu-latest\n", "check_amount"),
        ):
            self.file(name, body)
            with self.subTest(path=name):
                items = [c for c in self.report()["candidates"]
                         if name in c["evidence_refs"] and c["candidate_type"] == "FR"]
                self.assertEqual(len(items), 1)
                self.assertIn(cue, items[0]["title"])

    def test_recognized_secret_is_redacted_before_excerpt_truncation(self):
        synthetic = "AK" + "IA" + "Z" * 16
        self.file("README.md", "# " + "X" * 147 + " " + synthetic + "\n")
        self.file("app/documented.py", '"""Credential example: ' + synthetic + '."""\n')
        result = self.report()
        serialized = json.dumps(result)
        self.assertNotIn(synthetic, serialized)
        self.assertNotIn(synthetic[:12], serialized)
        self.assertIn("[REDACTED", serialized)

    def test_cli_persists_candidates_and_keeps_gap_review_open(self):
        self.file("README.md", "# Payments\n## Normalize amounts\nConvert to cents.\n")
        self.file("app/__init__.py", "")
        self.file("app/pay.py", "def normalize_amount(raw):\n    return raw\n")
        self.file("tests/test_pay.py", "def test_normalize_amount():\n    assert True\n")
        reports = {}
        for script in ("naos_requirements_reconstruct", "naos_traceability_gap_register"):
            result = subprocess.run(
                [sys.executable, "-B", str(ROOT / "scripts" / (script + ".py")),
                 str(self.root), "--profile", "standard", "--json", "--no-prompt"],
                capture_output=True, text=True, timeout=60,
            )
            self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            reports[script] = json.loads(result.stdout)
        candidates = reports["naos_requirements_reconstruct"]
        self.assertEqual(len(candidates["candidates"]), 3)
        stored = json.loads((self.root / "naos/reports/candidate_requirements.json").read_text())
        self.assertEqual(candidates["candidates"], stored["candidates"])
        gaps = reports["naos_traceability_gap_register"]["gaps"]
        self.assertTrue(gaps)
        self.assertTrue(all(gap["closure_state"] == "open" for gap in gaps))
        self.assertTrue(all(gap["human_review_required"] for gap in gaps))


if __name__ == "__main__":
    unittest.main()
