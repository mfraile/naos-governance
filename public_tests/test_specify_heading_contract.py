"""The specify prompt must use the shipped spec pack's heading hierarchy."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator
import yaml


ROOT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
SPECS = ROOT / "templates/spec-kit/specs"
PROMPT = ROOT / "templates/prompts/naos-specify.prompt.md"


class SpecifyHeadingContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.project = Path(temporary.name).resolve()
        shutil.copytree(SPECS, self.project / "specs")
        (self.project / "naos").mkdir()
        shutil.copyfile(ROOT / "templates/structural-seeds/naos/TASK_REGISTRY.yaml",
                        self.project / "naos/TASK_REGISTRY.yaml")
        self.requirements = self.project / "specs/03-requirements.md"
        prompt = PROMPT.read_text(encoding="utf-8")
        self.output = prompt.split("```markdown\n", 1)[1].split("\n```\n\n### Step 5:", 1)[0]
        self.headings = re.findall(r"^(#+) (.+)$", self.output, re.MULTILINE)
        self.environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        for name in ("NAOS_ROOT", "SPECS_ROOT"):
            self.environment.pop(name, None)

    def review(self, profile):
        inputs = {p: p.read_bytes() for p in (self.project / "specs").rglob("*") if p.is_file()}
        registry = self.project / "naos/TASK_REGISTRY.yaml"
        inputs[registry] = registry.read_bytes()
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/naos_spec_pack_contract.py"),
             "--profile", profile, "--json"],
            cwd=self.project, env=self.environment, capture_output=True, text=True, timeout=60,
        )
        self.assertNotIn("Traceback", result.stderr)
        report = json.loads(result.stdout)
        schema = json.loads((ROOT / "schemas/naos/spec_pack_contract.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(report)
        for path, body in inputs.items():
            self.assertEqual(path.read_bytes(), body)
        self.assertIn("approved specifications", report["not_claimed"])
        return result, report

    def test_output_headings_follow_the_canonical_requirement_hierarchy(self):
        canonical = self.requirements.read_text(encoding="utf-8")
        parent = re.search(r"^(#+) FR-001:", canonical, re.MULTILINE).group(1)
        manifest = yaml.safe_load((SPECS / "spec_manifest.yaml").read_text(encoding="utf-8"))
        rule = next(row for row in manifest["files"] if row["path"] == "03-requirements.md")
        child = next(text.split(" ", 1)[0] for text in rule["required_sections"] if "Systemic Impacts" in text)
        self.assertGreater(len(self.headings), 1)
        self.assertEqual(self.headings[0], (parent, "[FR|NFR]-XXX: [Concise Title]"))
        for hashes, title in self.headings[1:]:
            with self.subTest(title=title):
                self.assertEqual(hashes, child)

    def test_literal_prompt_heading_levels_preserve_a_valid_spec_pack(self):
        canonical = self.requirements.read_text(encoding="utf-8")
        parent = self.headings[0][0]
        child = next(hashes for hashes, title in self.headings if title.startswith("Systemic Impacts"))
        projected = re.sub(r"^#+ ((?:FR|NFR)-[0-9]{3}:)",
                           lambda match: parent + " " + match.group(1), canonical, flags=re.MULTILINE)
        projected = re.sub(r"^#+ (Systemic Impacts[^\n]*)$",
                           lambda match: child + " " + match.group(1), projected, flags=re.MULTILINE)
        self.requirements.write_text(projected, encoding="utf-8")
        for profile in ("standard", "assured"):
            with self.subTest(profile=profile):
                result, report = self.review(profile)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(report["status"], "pass")

    def test_missing_required_section_still_reports_review_or_blocks(self):
        canonical = self.requirements.read_text(encoding="utf-8")
        malformed = re.sub(r"^#+ Systemic Impacts[^\n]*\n", "", canonical, flags=re.MULTILINE)
        self.assertNotEqual(malformed, canonical)
        self.requirements.write_text(malformed, encoding="utf-8")
        for profile, expected_code, expected_status in (("standard", 0, "required_missing"),
                                                        ("assured", 1, "blocked")):
            with self.subTest(profile=profile):
                result, report = self.review(profile)
                self.assertEqual(result.returncode, expected_code, result.stderr)
                self.assertEqual(report["status"], expected_status)
                self.assertTrue(any("missing_section" in row["id"] and "Systemic Impacts" in row["id"]
                                    for row in report["findings"]))


if __name__ == "__main__":
    unittest.main()
