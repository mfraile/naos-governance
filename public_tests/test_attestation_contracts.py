"""Distribution-safe public CLI regressions for evidence input/output contracts.

NAOS_TEST_KIT selects an exported kit. NAOS_TEST_INSTALLED=1 exercises the
installed package entry point. All writes remain in temporary project fixtures.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import os
import shutil
import stat
import time
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml


KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
if str(KIT / "scripts") not in sys.path:
    sys.path.insert(0, str(KIT / "scripts"))
import naos_evidence_attestation as attestation  # noqa: E402
import naos_self_check_dependency_resolution as resolution  # noqa: E402
from naos_policy import load_policy, evidence_pack_output_path  # noqa: E402


class AttestationContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="naos-attestation-contract-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
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

    def test_signature_presence_is_not_signed_and_integrity_names_unsigned_baseline(self):
        self.producer()
        _, emitted = self.run_cli("evidence-sign", expected=0)
        self.assertNotIn("signed", emitted)
        envelope_path = self.root / "naos/evidence/evidence_envelope.json"
        envelope = json.loads(envelope_path.read_text())
        envelope["envelope"]["signatures"] = [{"keyid": "synthetic", "sig": "unverified"}]
        envelope_path.write_text(json.dumps(envelope))
        _, report = self.run_cli("evidence-verify", expected=0)
        self.assertNotIn("signed", report)
        self.assertTrue(report["signature_entries_present"])
        self.assertFalse(report["signature_validation_performed"])
        self.assertTrue(report["tamper_evident"])
        self.assertEqual(report["tamper_evidence_basis"], "unsigned_local_attestation_baseline")
        for command in ("evidence-pack", "dashboard"):
            with self.subTest(consumer=command):
                _, output = self.run_cli(command)
                section = output["evidence_verification"]
                self.assertNotIn("signed", section)
                self.assertTrue(section["signature_entries_present"])
                self.assertFalse(section["signature_validation_performed"])
                self.assertEqual(section["tamper_evidence_basis"], "unsigned_local_attestation_baseline")

    def test_author_email_is_explicit_optin_in_cli_and_projections(self):
        self.producer()
        email = "synthetic-author@example.invalid"
        empty_template = self.root / "empty-git-template"
        empty_template.mkdir()
        for command in (
            ["git", "init", "--template", str(empty_template), str(self.root)],
            ["git", "-C", str(self.root), "-c", "user.name=" + email.upper(),
             "-c", "user.email=" + email, "-c", "commit.gpgsign=false",
             "-c", "core.hooksPath=" + str(empty_template),
             "commit", "--allow-empty", "-m", "Synthetic identity privacy fixture"],
        ):
            run = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr)
        for optin in (False, True):
            args = ["--include-author-email"] if optin else []
            for command in ("evidence-sign", "evidence-verify"):
                _, report = self.run_cli(command, *args, expected=0)
                identity = report["identity_binding"]
                self.assertEqual("email" in identity["author"], optin)
                self.assertEqual(email in json.dumps(report).lower(), optin)
                self.assertFalse(identity["identity_authentication_performed"])
                self.assertFalse(report["signature_validation_performed"])
            for command in ("evidence-pack", "dashboard"):
                _, report = self.run_cli(command)
                identity = report["evidence_verification"]["identity_binding"]
                self.assertEqual("email" in identity["author"], optin)
                self.assertEqual(email in json.dumps(identity).lower(), optin)

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
                if scope == "disabled":
                    self.assertEqual(report["envelope_payload_validation"], "not_applicable")
                    self.assertFalse(report["tamper_evident"])
                    self.assertFalse(report["signature_entries_present"])
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
        _, envelope = self.run_cli("evidence-sign", expected=0)
        envelope["envelope"]["signatures"] = [{"sig": "synthetic"}]
        self.write("naos/evidence/evidence_envelope.json", envelope)
        _, report = self.run_cli("evidence-verify", expected=0)
        self.assertEqual(report["envelope_payload_validation"], "valid")
        self.assertTrue(report["signature_entries_present"])
        self.assertFalse(report["signature_validation_performed"])
        self.write("naos/evidence/evidence_envelope.json", {"envelope": {"signatures": [{"sig": "synthetic"}]}})
        _, report = self.run_cli("evidence-verify", expected=1)
        self.assertEqual(report["envelope_payload_validation"], "invalid")
        self.assertTrue(report["signature_entries_present"])
        self.assertFalse(report["signature_validation_performed"])
        self.assertFalse(report["tamper_evident"])
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

    def test_epoch_kit_generates_fresh_configuration(self):
        # Model deterministic tar extraction without changing the input kit.
        epoch_kit = self.root / "epoch-kit"

        def copy_epoch(source, destination):
            copied = shutil.copy2(source, destination)
            os.utime(copied, ns=(0, 0))
            return copied

        shutil.copytree(KIT, epoch_kit, copy_function=copy_epoch,
                        ignore=shutil.ignore_patterns(".git", "__pycache__", ".venv", "venv",
                                                     "build", "dist", "*.egg-info", ".ruff_cache"))
        paths = {
            "naos/evidence_attestation_rules.yaml": "templates/structural-seeds/naos/evidence_attestation_rules.yaml",
            "naos/secure_coding_control_register.yaml": "configs/secure_coding_control_register.yaml",
        }
        for profile in ("quickstart", "lite", "standard", "assured"):
            with self.subTest(profile=profile):
                preview = self.root / f"epoch-preview-{profile}"
                started = time.time()
                result = subprocess.run([sys.executable, "-B", str(epoch_kit / "cli.py"), "init",
                    str(self.root / f"absent-{profile}"), "--new", "--tier", profile,
                    "--archetype", "custom", "--backend", "static_only", "--preview-dir", str(preview)],
                    cwd=self.root, text=True, capture_output=True, timeout=120)
                self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr)
                finished = time.time()
                for relative, source_relative in paths.items():
                    source = epoch_kit / source_relative
                    self.assertEqual(source.stat().st_mtime_ns, 0)
                    destination = preview / relative
                    if profile == "quickstart" and "secure_coding" in relative:
                        self.assertFalse(destination.exists())
                        continue
                    self.assertEqual(destination.read_bytes(), source.read_bytes())
                    self.assertEqual(stat.S_IMODE(destination.stat().st_mode), stat.S_IMODE(source.stat().st_mode))
                    # Two seconds tolerates coarse filesystem timestamp resolution.
                    self.assertGreaterEqual(destination.stat().st_mtime, started - 2)
                    self.assertLessEqual(destination.stat().st_mtime, finished + 2)
                # Copies outside the two seed families retain their source metadata.
                self.assertEqual((preview / "naos/profile_generated_surface_contract.json").stat().st_mtime_ns, 0)

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
                # Fresh generation must never exempt genuinely old adopter inputs.
                stale_paths = ("naos/evidence_attestation_rules.yaml", "naos/reports/claims_validation.json")
                old = time.time() - 91 * 24 * 60 * 60
                old_state = {}
                for relative in stale_paths:
                    target = preview / relative
                    os.utime(target, (old, old))
                    old_state[relative] = (target.read_bytes(), target.stat().st_mtime_ns)
                code, stale = self.run_cli("evidence-attestation")
                self.assertEqual(code, 0 if profile == "quickstart" else 1)
                self.assertTrue(set(stale_paths).issubset({item["path"] for item in stale["stale_artifacts"]}))
                for relative, state in old_state.items():
                    target = preview / relative
                    self.assertEqual((target.read_bytes(), target.stat().st_mtime_ns), state)
        self.root = fixture_parent


class DependencyReceiptAttestationContracts(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="naos-receipt-domain-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        (self.root / "naos/reports").mkdir(parents=True)
        self.policy = load_policy(root=self.root, naos_root="naos")

    def collect(self, rules, policy=None, **kwargs):
        return attestation.collect_artifacts(
            root=self.root, rules=rules, policy=self.policy if policy is None else policy,
            generated_at=datetime.now(timezone.utc), **kwargs,
        )

    def test_classified_receipt_publication_does_not_change_independent_domain(self):
        # This models endpoint classification only. The file is deliberately not
        # a receipt and is never offered to a proof reader or used as evidence.
        for reports in ("reports", "observations"):
            with self.subTest(reports=reports):
                self.policy["paths"]["reports_dir"] = reports
                directory = self.root / "naos" / reports
                directory.mkdir(exist_ok=True)
                independent = directory / "independent.json"
                independent.write_text('{"synthetic_independent_input":true}')
                pack = evidence_pack_output_path(self.root, "naos", self.policy)
                pack.parent.mkdir(exist_ok=True)
                pack.write_text('{"synthetic_independent_pack":true}')
                endpoint = resolution.receipt_path(self.root, "naos", self.policy)
                rules = {"artifact_groups": [{"id": "independent", "included_paths": [
                    f"naos/{reports}/*.json", pack.relative_to(self.root).as_posix()]}]}
                with patch.object(resolution, "inspect_derived_receipt_endpoint",
                                  return_value=(endpoint, None, None), create=True):
                    before, _, _ = self.collect(rules)
                    endpoint.write_text('{"synthetic_membership_witness_only":true}')
                    after, _, _ = self.collect(rules)
                    self.assertEqual(before, after)
                    self.assertEqual({v["path"] for v in after}, {
                        independent.relative_to(self.root).as_posix(), pack.relative_to(self.root).as_posix()})
                    neighbor = directory / "unknown-neighbor.json"
                    neighbor.write_text('{"independent_neighbor":true}')
                    changed, _, _ = self.collect(rules)
                    self.assertIn(neighbor.relative_to(self.root).as_posix(), {v["path"] for v in changed})
                    pack.write_text('{"changed_independent_pack":true}')
                    changed_pack, _, _ = self.collect(rules)
                    old_digest = next(v["digest"] for v in changed if v["path"] == pack.relative_to(self.root).as_posix())
                    new_digest = next(v["digest"] for v in changed_pack if v["path"] == pack.relative_to(self.root).as_posix())
                    self.assertNotEqual(old_digest, new_digest)

    def test_explicitly_required_classified_receipt_stays_missing(self):
        endpoint = resolution.receipt_path(self.root, "naos", self.policy)
        endpoint.write_text('{"synthetic_membership_witness_only":true}')
        reference = endpoint.relative_to(self.root).as_posix()
        with patch.object(resolution, "inspect_derived_receipt_endpoint",
                          return_value=(endpoint, None, None), create=True):
            manifest, missing, _ = self.collect({"artifact_groups": [{
                "id": "explicit", "required_artifacts": [reference]}]})
        self.assertEqual(manifest, [])
        self.assertEqual([v["path"] for v in missing], [reference])

    def test_absent_endpoint_and_partial_policy_are_read_only(self):
        endpoint, digest, identity = resolution.inspect_derived_receipt_endpoint(
            self.root, "naos", self.policy)
        self.assertFalse(endpoint.exists())
        self.assertIsNone(digest)
        self.assertIsNone(identity)
        manifest, missing, _ = self.collect({"artifact_groups": []}, policy={})
        self.assertEqual((manifest, missing), ([], []))
        self.assertFalse(endpoint.exists())
        # Standalone collectors also work before a governance folder exists;
        # the optional evidence-pack output then has no destination.
        unadopted = self.root / "not-yet-adopted"
        unadopted.mkdir()
        policy = load_policy(root=unadopted, naos_root="naos")
        absent, digest, identity = resolution.inspect_derived_receipt_endpoint(
            unadopted, "naos", policy)
        self.assertFalse(absent.exists())
        self.assertIsNone(digest)
        self.assertIsNone(identity)
        self.assertFalse((unadopted / "naos").exists())

    def test_named_input_and_pack_aliases_refuse_before_exemption(self):
        import copy

        for kind in ("declared-input", "pack", "explicit-source"):
            with self.subTest(kind=kind):
                policy = copy.deepcopy(self.policy)
                extras = ()
                if kind == "pack":
                    policy["paths"].update(reports_dir="evidence", self_check_dependency_resolution_report="evidence_pack.json")
                else:
                    policy["paths"]["self_check_dependency_resolution_report"] = "authored.json"
                    source = self.root / "naos/reports/authored.json"
                    if kind == "declared-input":
                        policy["paths"]["custom_authored_input"] = "reports/authored.json"
                    else:
                        extras = (source,)
                with self.assertRaises(ValueError):
                    resolution.inspect_derived_receipt_endpoint(
                        self.root, "naos", policy, extra_protected=extras)
                self.assertFalse((self.root / "naos/reports/authored.json").exists())

        for invalid in (None, False, 1, []):
            with self.subTest(invalid_path=invalid):
                policy = copy.deepcopy(self.policy)
                policy["paths"]["self_check_dependency_resolution_report"] = invalid
                with self.assertRaises(ValueError):
                    resolution.inspect_derived_receipt_endpoint(self.root, "naos", policy)

    def test_foreign_malformed_and_hardlinked_endpoint_never_becomes_exempt(self):
        endpoint = resolution.receipt_path(self.root, "naos", self.policy)
        for content in ('{broken', '{"schema":"foreign"}',
                        json.dumps({"schema": resolution.SCHEMA, "synthetic_authored_input": True})):
            with self.subTest(content=content):
                endpoint.write_text(content)
                with self.assertRaises(ValueError):
                    self.collect({"artifact_groups": [{"id": "reports", "included_paths": ["naos/reports/*.json"]}]})
                self.assertEqual(endpoint.read_text(), content)
        endpoint.unlink()
        original = self.root / "authored.json"
        original.write_text(json.dumps({"schema": resolution.SCHEMA, "synthetic_authored_input": True}))
        os.link(original, endpoint)
        with self.assertRaises(ValueError):
            resolution.inspect_derived_receipt_endpoint(self.root, "naos", self.policy)
        self.assertEqual(endpoint.read_bytes(), original.read_bytes())
        self.assertEqual(original.stat().st_nlink, 2)


if __name__ == "__main__":
    unittest.main()
