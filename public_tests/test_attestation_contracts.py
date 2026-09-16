"""Distribution-safe public CLI regressions for evidence input/output contracts.

NAOS_TEST_KIT selects an exported kit. NAOS_TEST_INSTALLED=1 exercises the
installed package entry point. All writes remain in temporary project fixtures.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()


class AttestationContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="naos-attestation-contract-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "naos/reports").mkdir(parents=True)
        (self.root / "naos/evidence").mkdir()
        self.att_path = self.root / "naos/reports/evidence_attestation.json"

    def run_cli(self, command, *args, expected=None):
        entry = (["-m", "naos_governance.cli"] if os.environ.get("NAOS_TEST_INSTALLED") == "1"
                 else [str(KIT / "cli.py")])
        env = {k: v for k, v in os.environ.items() if not k.startswith("NAOS_")}
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        run = subprocess.run([sys.executable, "-B", *entry, command, "--profile", getattr(self, "profile", "assured"),
                              "--strict", "--json", *args], cwd=self.root, env=env,
                             text=True, capture_output=True, timeout=120)
        try:
            report = json.loads(run.stdout)
        except ValueError:
            self.fail(f"{command} did not return JSON: {run.stdout}\n{run.stderr}")
        if expected is not None:
            self.assertEqual(run.returncode, expected, (command, report, run.stderr))
        return run.returncode, report

    def write(self, path, value):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value), encoding="utf-8")

    def producer(self, rules=None):
        if rules is None:
            rules = {"enabled": True, "digest_algorithm": "sha256", "artifact_groups": [
                {"id": "fixture", "required_artifacts": ["input.txt"]}]}
        (self.root / "input.txt").write_text("independent evidence\n", encoding="utf-8")
        (self.root / "naos/evidence_attestation_rules.yaml").write_text(yaml.safe_dump(rules))
        (self.root / "naos/evidence_review_attestations.yaml").write_text(yaml.safe_dump({
            "attestations": [{"id": "synthetic-fixture-review", "review_date": "2026-09-16",
                              "review_scope": "Disposable fixture bytes only",
                              "review_outcome": "acknowledged", "artifact_groups": ["fixture"]}]}))
        return self.run_cli("evidence-attestation")[1]

    def assert_consumers(self, verification):
        for command in ("evidence-pack", "dashboard"):
            with self.subTest(consumer=command):
                _, report = self.run_cli(command)
                section = report.get("evidence_verification") or report.get("control_plane", {}).get("evidence_verification")
                self.assertIsInstance(section, dict)
                for key in ("input_validation", "digest_validation", "manifest_root_validation",
                            "scope_status", "required_coverage", "attestation_status", "artifacts_checked"):
                    self.assertEqual(section.get(key), verification.get(key), key)
                self.assertTrue(section["human_review_required"])
                self.assertFalse(section["signature_validation_performed"])

    def test_genuine_producer_and_tampering(self):
        self.producer()
        self.run_cli("evidence-sign", expected=0)
        _, report = self.run_cli("evidence-verify", expected=0)
        self.assertEqual(report.get("digest_validation"), "valid")
        self.assertEqual(report.get("manifest_root_validation"), "valid")
        self.assertTrue(report["tamper_evident"])
        self.assert_consumers(report)
        (self.root / "input.txt").write_text("changed evidence\n")
        _, changed = self.run_cli("evidence-verify", expected=1)
        self.assertEqual(changed.get("digest_validation"), "invalid")
        self.assertFalse(changed["tamper_evident"])
        self.assert_consumers(changed)

    def test_malformed_inputs_are_structured_errors_in_both_entrypoints(self):
        valid = self.producer()
        inputs = [{}, [], [1], {"unrelated": True}, {**valid, "artifact_manifest": {}},
                  {**valid, "artifact_manifest": None}, {**valid, "schema": "unrelated.v1"}]
        for value in inputs:
            for command in ("evidence-sign", "evidence-verify"):
                with self.subTest(value=value, command=command):
                    self.write("naos/reports/evidence_attestation.json", value)
                    code, report = self.run_cli(command)
                    self.assertNotEqual(code, 0)
                    self.assertEqual(report.get("input_validation"), "invalid")
                    self.assertEqual(report.get("artifacts_checked"), 0)
                    if command == "evidence-verify":
                        self.assertFalse(report["tamper_evident"])
        self.assert_consumers(report)

    def test_invalid_json_is_not_missing_or_success(self):
        self.att_path.write_text("{broken")
        _, report = self.run_cli("evidence-verify", expected=1)
        self.assertEqual(report.get("input_validation"), "invalid")

    def test_invalid_subjects_are_rejected(self):
        valid = self.producer()
        for path in ("", "../input.txt", str(self.root / "input.txt")):
            with self.subTest(path=path):
                value = copy.deepcopy(valid)
                value["artifact_manifest"][0]["path"] = path
                self.write("naos/reports/evidence_attestation.json", value)
                _, report = self.run_cli("evidence-verify", expected=1)
                self.assertEqual(report.get("input_validation"), "invalid")
        value = copy.deepcopy(valid)
        value["artifact_manifest"] *= 2
        self.write("naos/reports/evidence_attestation.json", value)
        _, report = self.run_cli("evidence-verify", expected=1)
        self.assertEqual(report.get("input_validation"), "invalid")

    def test_rootless_legacy_empty_and_disabled_are_explicit(self):
        value = self.producer()
        value.pop("manifest_root_digest")
        self.write("naos/reports/evidence_attestation.json", value)
        _, rootless = self.run_cli("evidence-verify", expected=0)
        self.assertEqual(rootless.get("digest_validation"), "valid")
        self.assertEqual(rootless.get("manifest_root_validation"), "not_recorded")
        self.assertFalse(rootless["tamper_evident"])
        self.assert_consumers(rootless)
        for rules, scope in (({"enabled": True, "artifact_groups": []}, "empty"),
                             ({"enabled": False}, "disabled")):
            with self.subTest(scope=scope):
                self.producer(rules)
                self.run_cli("evidence-sign", expected=0)
                _, report = self.run_cli("evidence-verify", expected=0)
                self.assertEqual(report.get("scope_status"), scope)
                self.assertEqual(report.get("artifacts_checked"), 0)
                self.assertEqual(report.get("digest_validation"), "not_applicable")
                self.assertNotEqual(report.get("status"), "pass")
                self.assert_consumers(report)

    def test_required_missing_coverage_is_distinct_from_empty_root(self):
        self.producer({"artifact_groups": [{"id": "fixture", "required_artifacts": ["absent.txt"]}]})
        _, report = self.run_cli("evidence-verify", expected=1)
        self.assertEqual(report.get("required_coverage"), {"status": "missing", "missing_count": 1})
        self.assertEqual(report.get("artifacts_checked"), 0)
        self.assertTrue(report["tamper_evident"])
        self.assert_consumers(report)

    def test_signature_presence_never_means_validation(self):
        self.producer()
        self.write("naos/evidence/evidence_envelope.json", {"envelope": {"signatures": [{"sig": "synthetic"}]}})
        _, report = self.run_cli("evidence-verify", expected=0)
        self.assertTrue(report["signature_entries_present"])
        self.assertFalse(report["signature_validation_performed"])
        self.write("naos/evidence/evidence_envelope.json", [])
        _, report = self.run_cli("evidence-verify", expected=1)
        self.assertFalse(report["signature_entries_present"])
        self.write("naos/evidence/evidence_envelope.json", {"unrelated": True})
        _, report = self.run_cli("evidence-verify", expected=1)
        self.assertTrue(any(item["status"] == "invalid_envelope" for item in report["findings"]))

    def test_missing_or_unrecorded_digests_remain_unavailable(self):
        value = self.producer()
        value["artifact_manifest"][0]["digest"] = None
        value.pop("manifest_root_digest")
        self.write("naos/reports/evidence_attestation.json", value)
        _, report = self.run_cli("evidence-verify", expected=1)
        self.assertEqual(report["input_validation"], "valid")
        self.assertEqual(report["digest_validation"], "unavailable")
        value = self.producer()
        (self.root / "input.txt").unlink()
        _, report = self.run_cli("evidence-verify", expected=1)
        self.assertEqual(report["digest_validation"], "unavailable")
        self.assertEqual(report["artifacts_checked"], 0)

    def test_required_generated_output_remains_missing(self):
        self.write("naos/evidence/evidence_envelope.json", {"fixture_only": True})
        att = self.producer({"artifact_groups": [{"id": "fixture",
            "required_artifacts": ["input.txt", "naos/evidence/evidence_envelope.json"]}]})
        self.assertEqual([item["path"] for item in att["artifact_manifest"]], ["input.txt"])
        self.assertEqual([item["path"] for item in att["missing_artifacts"]], ["naos/evidence/evidence_envelope.json"])

    def stock_fixture(self, overridden):
        rules = yaml.safe_load((KIT / "templates/structural-seeds/naos/evidence_attestation_rules.yaml").read_text())
        # Legacy generated rules intentionally lack the newly shipped exclusions.
        rules["excluded_paths"] = ["naos/reports/evidence_attestation.json"]
        paths = {}
        args = []
        naos_root = "naos"
        if overridden:
            naos_root = "governance"
            paths = {"default_naos_root": naos_root, "reports_dir": "observations", "evidence_dir": "artifacts",
                     "evidence_attestation_report": "attestation-current.json",
                     "evidence_verification_report": "verify-current.json",
                     "evidence_envelope_report": "envelope-current.json"}
            rules = yaml.safe_load(yaml.safe_dump(rules).replace("naos/reports/", "governance/observations/")
                                   .replace("naos/evidence/", "governance/artifacts/").replace("naos/", "governance/"))
            (self.root / "governance").mkdir()
            self.write("policy.json", {"paths": paths})
            args = ["--policy", str(self.root / "policy.json"), "--naos-root", naos_root]
        reports = paths.get("reports_dir", "reports")
        evidence = paths.get("evidence_dir", "evidence")
        (self.root / naos_root / "evidence_attestation_rules.yaml").write_text(yaml.safe_dump(rules))
        (self.root / naos_root / "evidence_review_attestations.yaml").write_text(yaml.safe_dump({
            "attestations": [{"id": "synthetic-cycle-fixture", "review_date": "2026-09-16",
                              "review_scope": "Synthetic fixture bytes only", "review_outcome": "acknowledged",
                              "artifact_groups": ["control_plane_reports", "governing_configuration"]}]}))
        inputs = [f"{naos_root}/{reports}/claims_validation.json", f"{naos_root}/{reports}/self_check.json",
                  f"{naos_root}/{evidence}/evidence_pack.json"]
        for path in inputs:
            self.write(path, {"synthetic_fixture_only": True})
        return args, inputs

    def test_two_cycles_preserve_independent_required_evidence(self):
        for overridden in (False, True):
            with self.subTest(overridden=overridden):
                args, inputs = self.stock_fixture(overridden)
                original = {p: hashlib.sha256((self.root / p).read_bytes()).hexdigest() for p in inputs}
                for _ in range(2):
                    _, att = self.run_cli("evidence-attestation", *args, expected=0)
                    manifest = {i["path"] for i in att["artifact_manifest"]}
                    self.assertTrue(set(inputs).issubset(manifest))
                    self.run_cli("evidence-sign", *args, expected=0)
                    _, verify = self.run_cli("evidence-verify", *args, expected=0)
                    self.assertTrue(verify["tamper_evident"])
                self.assertEqual(original, {p: hashlib.sha256((self.root / p).read_bytes()).hexdigest() for p in inputs})
                self.write(inputs[0], {"changed_independent_evidence": True})
                _, verify = self.run_cli("evidence-verify", *args, expected=1)
                self.assertFalse(verify["tamper_evident"])

    def test_output_overwrite_refuses_before_mutating_subject(self):
        self.producer()
        subject = self.root / "input.txt"
        before = subject.read_bytes()
        for command in ("evidence-sign", "evidence-verify"):
            _, report = self.run_cli(command, "--output", str(subject), expected=1)
            self.assertTrue(any(i.get("status") == "output_is_subject" for i in report["findings"]))
            self.assertEqual(subject.read_bytes(), before)

    def test_generated_profile_defaults_repeat(self):
        fixture_parent = self.root
        entry = (["-m", "naos_governance.cli"] if os.environ.get("NAOS_TEST_INSTALLED") == "1"
                 else [str(KIT / "cli.py")])
        for profile in ("quickstart", "lite", "standard", "assured"):
            with self.subTest(profile=profile):
                preview = fixture_parent / f"preview-{profile}"
                generated = subprocess.run([sys.executable, "-B", *entry, "init",
                    str(fixture_parent / f"absent-target-{profile}"), "--new", "--tier", profile,
                    "--archetype", "custom", "--backend", "static_only", "--preview-dir", str(preview)],
                    cwd=fixture_parent, text=True, capture_output=True, timeout=120)
                self.assertEqual(generated.returncode, 0, generated.stderr)
                self.root = preview
                self.profile = profile
                self.assertTrue((preview / "naos/evidence_attestation_rules.yaml").is_file())
                # Keep the actual generated defaults; only add labelled fixture evidence.
                for path in ("naos/reports/claims_validation.json", "naos/reports/self_check.json",
                             "naos/evidence/evidence_pack.json"):
                    self.write(path, {"synthetic_fixture_only": True})
                (preview / "naos/evidence_review_attestations.yaml").write_text(yaml.safe_dump({
                    "attestations": [{"id": "synthetic-generated-cycle", "review_date": "2026-09-16",
                                      "review_scope": "Disposable generated project only", "review_outcome": "acknowledged",
                                      "artifact_groups": ["control_plane_reports", "governing_configuration"]}]}))
                for _ in range(2):
                    self.run_cli("evidence-attestation", expected=0)
                    self.run_cli("evidence-sign", expected=0)
                    _, report = self.run_cli("evidence-verify", expected=0)
                    self.assertTrue(report["tamper_evident"])
                self.write("naos/reports/claims_validation.json", {"changed_real_subject": True})
                _, report = self.run_cli("evidence-verify")
                self.assertFalse(report["tamper_evident"])
                self.assertEqual(report["digest_validation"], "invalid")
        self.root = fixture_parent


if __name__ == "__main__":
    unittest.main()
