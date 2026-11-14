"""Invalid local rules remain visible without changing profile exit policy."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(ROOT / "scripts"))
import naos_ai_surface_budget as budget  # noqa: E402


class BudgetInvalidRulesTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.rules = self.root / "rules.yaml"

    def report(self, profile="standard"):
        result = budget.build_report(
            root=self.root, profile=profile, naos_root="naos", policy={},
            rules_path=self.rules, baseline_path=None,
        )
        schema = json.loads((ROOT / "schemas/naos/ai_surface_context_budget.schema.json").read_text())
        Draft202012Validator(schema).validate(result)
        return result

    def test_malformed_and_nonmapping_rules_have_dedicated_warning(self):
        for text in ("families: [\n", "- not-a-mapping\n"):
            self.rules.write_text(text, encoding="utf-8")
            for profile in ("quickstart", "lite", "standard", "assured"):
                with self.subTest(text=text, profile=profile):
                    result = self.report(profile)
                    self.assertTrue(result["rules"]["present"])
                    self.assertEqual(result["rules"]["source"], "default_fallback")
                    self.assertTrue(result["rules"]["error"])
                    items = [f for f in result["findings"] if f["status"] == "rules_invalid"]
                    self.assertEqual(len(items), 1)
                    self.assertEqual(items[0]["severity"], "advisory" if profile == "quickstart" else "warning")
                    self.assertTrue(result["human_review_required"])

    def test_missing_and_valid_rules_keep_existing_fallback_and_thresholds(self):
        result = self.report()
        self.assertFalse(result["rules"]["present"])
        self.assertFalse(any(f["status"] == "rules_invalid" for f in result["findings"]))
        self.rules.write_text("version: 1\n", encoding="utf-8")
        result = self.report()
        self.assertEqual(result["rules"]["source"], "rules_file")
        self.assertFalse(any(f["status"] == "rules_invalid" for f in result["findings"]))
        loaded, _ = budget.load_rules(self.rules)
        self.assertEqual(loaded, budget.DEFAULT_RULES)

    def test_cli_reports_rules_warning_and_preserves_strict_exit_convention(self):
        self.rules.write_text("families: [\n", encoding="utf-8")
        for strict, expected in ((False, 0), (True, 1)):
            with self.subTest(strict=strict):
                args = [sys.executable, "-B", str(ROOT / "scripts/naos_ai_surface_budget.py"),
                        "--profile", "lite", "--rules", str(self.rules), "--json"]
                if strict:
                    args.append("--strict")
                result = subprocess.run(args, cwd=self.root, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, expected, result.stderr)
                data = json.loads(result.stdout)
                self.assertEqual(len([f for f in data["findings"] if f["status"] == "rules_invalid"]), 1)
                self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
