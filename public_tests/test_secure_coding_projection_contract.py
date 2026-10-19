"""Optional P3 projection preserves the published dashboard/pack contracts."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from naos_policy import load_policy  # noqa: E402
import naos_secret_public_literals as public_literals  # noqa: E402
from secure_coding_reporting import model, projection  # noqa: E402


class SecureCodingProjectionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="naos projection contract ")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        (cls.root / "naos/reports").mkdir(parents=True)
        cls.schemas = {
            name: json.loads((ROOT / "schemas/naos" / f"{name}.schema.json").read_text())
            for name in ("evidence_pack", "dashboard_summary")
        }
        cls.reports = {}
        for version in (1, 2):
            for name, command in (("evidence_pack", "evidence-pack"), ("dashboard_summary", "dashboard")):
                # The current producers construct v1 before source-reference
                # composition publishes v2. Capture that actual legacy output.
                launcher = (
                    "import runpy,sys;from pathlib import Path;"
                    "root=Path(sys.argv[1]);sys.path.insert(0,str(root/'scripts'));"
                    "import naos_report_composition as composition;"
                    + ("composition.compose_publication=lambda report,root:report;" if version == 1 else "")
                    + "sys.argv=[str(root/'cli.py'),*sys.argv[2:]];"
                    "runpy.run_path(str(root/'cli.py'),run_name='__main__')"
                )
                arguments = [
                    sys.executable, "-B", "-c", launcher, str(ROOT), command,
                    "--profile", "quickstart", "--policy", str(ROOT / "policies/default_policy.yaml"), "--json",
                ]
                if command == "dashboard":
                    arguments.append("--no-progress-history")
                result = subprocess.run(
                    arguments, cwd=cls.root, text=True, capture_output=True, timeout=60,
                    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                )
                if result.returncode:
                    raise AssertionError(result.stderr)
                report = json.loads(result.stdout)
                if report["schema"] != f"naos.{name}.v{version}":
                    raise AssertionError(report["schema"])
                Draft202012Validator(cls.schemas[name]).validate(report)
                cls.reports[(name, version)] = report
        policy = load_policy(str(ROOT / "policies/default_policy.yaml"), "naos", cls.root)
        cls.p3 = model.build_report(
            root=cls.root, naos_root="naos", profile="quickstart", policy=policy,
            reference_path=cls.root / "missing-reference.json",
            controls_path=cls.root / "missing-controls.json",
            check_mode=False, generated_at="2026-01-01T00:00:00Z",
        )
        Draft202012Validator(json.loads((ROOT / "schemas/naos/secure_coding_reporting.schema.json").read_text())).validate(cls.p3)

    def test_optional_projection_round_trips_real_legacy_and_v2_reports(self):
        with tempfile.TemporaryDirectory(prefix="naos projected reports ") as temporary:
            directory = Path(temporary)
            for version in (1, 2):
                with self.subTest(version=version):
                    dashboard = directory / "dashboard.json"
                    evidence = directory / "evidence.json"
                    markdown = directory / "DASHBOARD.md"
                    dashboard.write_text(json.dumps(self.reports[("dashboard_summary", version)]))
                    evidence.write_text(json.dumps(self.reports[("evidence_pack", version)]))
                    markdown.write_text("# Project Dashboard\n")
                    for _ in range(2):
                        result = projection.project(
                            report=self.p3, dashboard_summary=dashboard,
                            dashboard_markdown=markdown, evidence_pack=evidence,
                        )
                        self.assertTrue(all(row["state"] == "projected" for row in result.values()))
                    for name, path in (("dashboard_summary", dashboard), ("evidence_pack", evidence)):
                        projected = json.loads(path.read_text())
                        # The finite secret-label consumer also pins these schema
                        # bytes; validate through its actual fail-closed loader.
                        Draft202012Validator(self.schemas[name]).validate(projected)
                        public_literals._claim_validator(name).validate(projected)
                        self.assertEqual(projected.pop("secure_coding_reporting"), projection.payload(self.p3))
                        # Every pre-existing outcome, readiness, finding and
                        # source digest remains exactly the producer's result.
                        self.assertEqual(projected, self.reports[(name, version)])
                    self.assertEqual(markdown.read_text().count(projection.BEGIN_MARKER), 1)

    def test_projection_keeps_all_five_dimensions_and_human_review(self):
        payload = projection.payload(self.p3)
        self.assertEqual(payload["dimension_keys"], list(model.DIMENSION_KEYS))
        self.assertEqual(set(payload["dimensions"]), set(model.DIMENSION_KEYS))
        self.assertTrue(payload["human_review_required"])
        self.assertEqual(payload["standards_snapshot"]["state"], "unavailable")

    def test_projection_contract_rejects_malformed_or_overclaiming_payloads(self):
        mutations = {
            "missing_dimension": lambda value: value["dimensions"].pop("mapping_verification"),
            "extra_score_dimension": lambda value: value["dimensions"].update(score={"state": "pass", "source": "synthetic"}),
            "wrong_dimension_order": lambda value: value["dimension_keys"].reverse(),
            "waived_human_review": lambda value: value.update(human_review_required=False),
            "compliance_outcome": lambda value: value.update(status="compliant"),
            "wrong_schema": lambda value: value.update(schema="unknown"),
            "unstructured_limitations": lambda value: value.update(limitations="none"),
            "unstructured_sources": lambda value: value.update(sources=[]),
            "extra_projection_field": lambda value: value.update(compliance_certified=True),
            "incomplete_standards_snapshot": lambda value: value["standards_snapshot"].pop("human_review_required"),
        }
        for (name, version), original in self.reports.items():
            for label, mutate in mutations.items():
                with self.subTest(name=name, version=version, mutation=label):
                    value = copy.deepcopy(projection.payload(self.p3))
                    mutate(value)
                    report = copy.deepcopy(original)
                    report["secure_coding_reporting"] = value
                    errors = list(Draft202012Validator(self.schemas[name]).iter_errors(report))
                    self.assertTrue(errors, label)

    def test_projection_does_not_open_parent_schema_to_arbitrary_fields(self):
        for (name, version), original in self.reports.items():
            with self.subTest(name=name, version=version):
                report = copy.deepcopy(original)
                report["secure_coding_reporting"] = projection.payload(self.p3)
                report["compliance_certified"] = True
                self.assertTrue(list(Draft202012Validator(self.schemas[name]).iter_errors(report)))


if __name__ == "__main__":
    unittest.main()
