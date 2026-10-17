"""Public installed-surface contract for dashboard workflow applicability."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/workflows/generate_naos_dashboard.py"
SCHEMA = ROOT / "schemas/naos/dashboard_summary.schema.json"


class DashboardApplicabilityPublicContractTests(unittest.TestCase):
    def test_project_opt_in_is_visible_and_preserves_unrelated_missing_input(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            policy = project / "naos/policy/default_policy.yaml"
            policy.parent.mkdir(parents=True)
            policy.write_text(
                "dashboard:\n  applicability: selected_workflows\n  selected_workflows: []\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--profile", "assured", "--json"],
                cwd=project, text=True, capture_output=True, check=False,
            )
            self.assertTrue(result.stdout.startswith("{"), result.stderr)
            report = json.loads(result.stdout)
            Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8"))).validate(report)
            self.assertEqual(report["input_applicability"]["inputs"]["ai_code_provenance"]["decision"], "exempt_missing")
            findings = {finding["id"] for finding in report["findings"]}
            self.assertNotIn("ai_code_provenance", findings)
            self.assertIn("self_check", findings)
            self.assertIn("Dashboard Input Applicability", (project / "naos/DASHBOARD.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
