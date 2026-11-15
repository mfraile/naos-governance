"""Valid requirement comments and named URLs retain their declared import names."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()


class RequirementNameExtractionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / "src").mkdir()
        (self.root / "src/app.py").write_text("import requests\nimport yaml\nimport missing_synthetic_dependency\n", encoding="utf-8")

    def report(self, profile="standard"):
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/naos_dependency_integrity.py"),
             ".", "--profile", profile, "--json"],
            cwd=self.root, capture_output=True, text=True, timeout=60,
        )
        # The genuinely undeclared control stays blocking in Assured.
        self.assertEqual(result.returncode, 1 if profile == "assured" else 0, result.stderr)
        report = json.loads(result.stdout)
        schema = json.loads((ROOT / "schemas/naos/dependency_integrity.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(report)
        return report

    def assert_only_genuine_missing_import(self, report):
        findings = [row for row in report["findings"] if row["status"] == "undeclared_or_unresolved_import"]
        self.assertEqual([row["import_name"] for row in findings], ["missing_synthetic_dependency"])
        self.assertEqual(report["scans"]["declared_dependency_imports"], ["pyyaml", "requests", "yaml"])
        self.assertEqual(report["summary"]["undeclared_or_unresolved_imports"], 1)

    def test_requirement_comments_and_named_urls_match_plain_names_in_every_profile(self):
        cases = (
            "requests\npyyaml\n",
            "requests  # HTTP client\npyyaml\t# YAML\n",
            "requests @ https://example.invalid/requests.whl#sha256=synthetic\npyyaml @ file:///synthetic/pyyaml.whl\n",
            "requests[security]>=2 ; python_version >= '3.11'  # bounded name only\npyyaml>=6\n",
        )
        for profile in ("quickstart", "lite", "standard", "assured"):
            for requirement in cases:
                with self.subTest(profile=profile, requirement=requirement):
                    (self.root / "requirements.txt").write_text(requirement, encoding="utf-8")
                    self.assert_only_genuine_missing_import(self.report(profile))

    def test_pyproject_required_and_optional_named_urls_share_the_same_name_extraction(self):
        (self.root / "pyproject.toml").write_text(
            '[project]\nname = "synthetic-project"\nversion = "0"\n'
            'dependencies = ["requests @ https://example.invalid/requests.whl#sha256=synthetic"]\n'
            '[project.optional-dependencies]\nreview = ["PyYAML @ file:///synthetic/pyyaml.whl"]\n', encoding="utf-8",
        )
        self.assert_only_genuine_missing_import(self.report())

    def test_options_bare_urls_comments_and_package_alias_mapping_stay_unchanged(self):
        (self.root / "requirements.txt").write_text(
            "# Whole-line comment\n--index-url https://example.invalid/simple\n"
            "https://example.invalid/unknown.whl#egg=unknown\ngit+https://example.invalid/repo\n"
            "requests\nPyYAML\n", encoding="utf-8",
        )
        self.assert_only_genuine_missing_import(self.report())


if __name__ == "__main__":
    unittest.main()
