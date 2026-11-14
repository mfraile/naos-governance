"""Project claim identities are distinct and independent of checkout location."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator
import yaml

ROOT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()


class AdapterClaimIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.project = self.base / "clone-one"
        (self.project / "naos").mkdir(parents=True)
        self.rules = yaml.safe_load((ROOT / "templates/structural-seeds/naos/adapter_coherence_rules.yaml").read_text(encoding="utf-8"))
        self.write_rules(self.project)
        (self.project / "AGENTS.md").write_text("# Synthetic adapter\nmodel api required\nmcp access guaranteed\n", encoding="utf-8")
        self.environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        self.environment.pop("NAOS_ROOT", None)

    def write_rules(self, project):
        (project / "naos/adapter_coherence_rules.yaml").write_text(yaml.safe_dump(self.rules), encoding="utf-8")

    def classify(self, project, *, profile="standard", strict=False):
        sources = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in project.rglob("*")
                   if p.is_file() and "reports" not in p.relative_to(project).parts}
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/naos_adapter_coherence.py"), str(project),
             "--profile", profile, "--json", *(["--strict"] if strict else [])],
            cwd=project, env=self.environment, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 1 if strict or profile == "assured" else 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report, json.loads((project / "naos/reports/adapter_coherence.json").read_text(encoding="utf-8")))
        schema = json.loads((ROOT / "schemas/naos/adapter_coherence_report.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(report)
        for path, digest in sources.items():
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        claims = [f for f in report["findings"] if f["id"].startswith("project_adapter_claim_")]
        return report, claims

    def sarif_claims(self, project, claims):
        # Exercise the existing nested self-check collector with actual producer
        # findings. This fixture is not execution of the full self-check command.
        wrapper = {"schema": "naos.self_check.v1", "checks": [{"id": "naos_adapter_coherence", "findings": claims}]}
        (project / "naos/reports/self_check.json").write_text(json.dumps(wrapper), encoding="utf-8")
        output = self.base / (project.name + ".sarif")
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/naos_sarif_export.py"), "--profile", "standard",
             "--output", str(output), "--summary-output", str(self.base / (project.name + "-summary.json")), "--json"],
            cwd=project, env=self.environment, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(output.read_text(encoding="utf-8"))
        return [r for r in document["runs"][0]["results"]
                if r["properties"]["naos_source_finding_id"].startswith("project_adapter_claim_")]

    def test_distinct_claims_and_sarif_fingerprints_are_stable_across_clones(self):
        other = self.base / "clone-two"
        shutil.copytree(self.project, other)
        identities, consumers = [], []
        for project in (self.project, other):
            report, claims = self.classify(project)
            self.assertEqual(len(claims), 2)
            self.assertEqual({f["path"] for f in claims}, {"AGENTS.md"})
            self.assertTrue(report["human_review_required"])
            identities.append({f["message"]: f["id"] for f in claims})
            consumers.append(self.sarif_claims(project, claims))
        self.assertEqual(len(set(identities[0].values())), 2)
        self.assertEqual(identities[0], identities[1])
        for results in consumers:
            self.assertEqual(len(results), 2)
            self.assertEqual(len({r["ruleId"] for r in results}), 2)
        self.assertEqual({r["partialFingerprints"]["naosFindingFingerprint"] for r in consumers[0]},
                         {r["partialFingerprints"]["naosFindingFingerprint"] for r in consumers[1]})

    def test_path_and_phrase_punctuation_do_not_alias_and_rule_order_does_not_change_identity(self):
        self.rules["forbidden_claim_phrases"] = ["model api required", "model_api_required"]
        self.write_rules(self.project)
        (self.project / "AGENTS.md").write_text("# Benign synthetic guidance\n", encoding="utf-8")
        directory = self.project / ".github/instructions"
        directory.mkdir(parents=True)
        for name in ("a-b.md", "a_b.md"):
            (directory / name).write_text("model api required\nmodel_api_required\n", encoding="utf-8")
        _, claims = self.classify(self.project)
        self.assertEqual(len(claims), 4)
        self.assertEqual(len({f["id"] for f in claims}), 4)
        original = {(f["path"], f["message"]): f["id"] for f in claims}
        self.rules["forbidden_claim_phrases"].reverse()
        self.rules["forbidden_claim_phrases"].append("unmatched synthetic claim")
        self.write_rules(self.project)
        _, reordered = self.classify(self.project)
        self.assertEqual({(f["path"], f["message"]): f["id"] for f in reordered}, original)

    def test_profile_severity_strict_exit_and_benign_control_are_preserved(self):
        identities = []
        for profile, severity in (("quickstart", "advisory"), ("lite", "warning"),
                                  ("standard", "required"), ("assured", "blocking")):
            with self.subTest(profile=profile):
                report, claims = self.classify(self.project, profile=profile)
                self.assertEqual(len(claims), 2)
                self.assertEqual({f["severity"] for f in claims}, {severity})
                self.assertEqual({f["status"] for f in claims}, {"forbidden_claim"})
                self.assertTrue(report["human_review_required"])
                identities.append({f["message"]: f["id"] for f in claims})
        self.assertTrue(all(value == identities[0] for value in identities))
        _, strict = self.classify(self.project, strict=True)
        self.assertEqual({f["message"]: f["id"] for f in strict}, identities[0])
        (self.project / "AGENTS.md").write_text("# Benign synthetic guidance\n", encoding="utf-8")
        _, clean = self.classify(self.project)
        self.assertFalse(clean)
