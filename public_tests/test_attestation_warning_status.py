"""Reviewer warnings stay visible in the attestation and its projections."""

import json
import os
from datetime import UTC, datetime
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator
import yaml

ROOT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT)]
import naos_evidence_attestation as attestation  # noqa: E402
import naos_evidence_export as export  # noqa: E402
from naos_policy import finding_counts  # noqa: E402
from workflows import generate_naos_dashboard as dashboard  # noqa: E402


class AttestationWarningStatusTests(unittest.TestCase):
    def test_canonical_warning_counts_and_status_precedence(self):
        counts = finding_counts([{"severity": "warning"}])
        self.assertEqual(counts["warnings"], 1)
        self.assertEqual(attestation.status_from_findings(counts), "warning")
        for severity, expected in (("required", "review_required"), ("blocking", "blocked")):
            with self.subTest(severity=severity):
                counts = finding_counts([{"severity": "warning"}, {"severity": severity}])
                self.assertEqual(attestation.status_from_findings(counts), expected)
        self.assertEqual(attestation.status_from_findings(finding_counts([])), "ready")

    def test_actual_lite_warning_is_not_ready_in_report_pack_or_dashboard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            artifact = root / "docs/ev/a.md"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("Synthetic local evidence.\n", encoding="utf-8")
            rules = {"enabled": True, "digest_algorithm": "sha256",
                     "profile_severity_behavior": {"quickstart": "advisory", "lite": "warning",
                                                   "standard": "required", "assured": "blocking"},
                     "artifact_groups": [{"id": "g1", "included_paths": ["docs/ev/a.md"],
                                          "required_artifacts": ["docs/ev/a.md"]}],
                     "reviewer_attestation_requirements": {"required_fields": ["reviewer_name", "review_date"]}}
            (root / "rules.yaml").write_text(yaml.safe_dump(rules), encoding="utf-8")
            reviews = root / "reviews.yaml"
            reviews.write_text(yaml.safe_dump({"attestations": [
                {"id": "r1", "reviewer_name": "", "review_date": "",
                 "artifact_groups": ["g1"], "review_outcome": "acknowledged"}
            ]}), encoding="utf-8")
            command = [sys.executable, "-B", str(ROOT / "scripts/naos_evidence_attestation.py"),
                       "--profile", "lite", "--rules", str(root / "rules.yaml"),
                       "--attestations", str(reviews), "--output", str(root / "out.json"), "--json"]
            before = artifact.read_bytes()
            result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["summary"]["warnings"], 1)
            self.assertEqual(report["status"], "warning")
            schema = json.loads((ROOT / "schemas/naos/evidence_attestation.schema.json").read_text())
            Draft202012Validator(schema).validate(report)
            item = {"data": report, "status": "available", "report_status": report["status"]}
            self.assertEqual(export.summarize_evidence_attestation(item)["status"], "warning")
            self.assertEqual(dashboard.summarize_evidence_attestation(item)["status"], "warning")
            self.assertEqual(artifact.read_bytes(), before)
            reviews.write_text(yaml.safe_dump({"attestations": [
                {"id": "r1", "reviewer_name": "Synthetic reviewer", "review_date": datetime.now(UTC).date().isoformat(),
                 "artifact_groups": ["g1"], "review_outcome": "acknowledged"}
            ]}), encoding="utf-8")
            clean = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=60)
            self.assertEqual(clean.returncode, 0, clean.stderr)
            clean_report = json.loads(clean.stdout)
            self.assertEqual(clean_report["summary"]["warnings"], 0)
            self.assertEqual(clean_report["status"], "ready")


if __name__ == "__main__":
    unittest.main()
