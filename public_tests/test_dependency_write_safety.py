"""G1: dependency captures preserve source bytes and refuse redirected publication."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

KIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KIT / "scripts"))
import naos_self_check as self_check  # noqa: E402
import naos_self_check_dependency_resolution as resolution  # noqa: E402
from naos_policy import evidence_pack_output_path, finding_counts, load_policy, status_from_counts  # noqa: E402


class DependencyWriteSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-dependency-ü-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / "naos/reports").mkdir(parents=True)
        self.policy = load_policy(root=self.root)
        ids = self_check.selected_check_ids(self.root, "standard", "naos", self.policy)
        checks = [{"id": name, "status": "pass", "findings": [], "returncode": 0} for name in ids]
        checks[-1].update(status="required_missing", returncode=1, findings=[{
            "id": "fixture_required", "severity": "required", "status": "unresolved",
            "message": "Synthetic adverse capture: not complete resolution or readiness proof.",
        }])
        counts = {**finding_counts([f for c in checks for f in c["findings"]]), "checks": len(checks)}
        self.report = {"schema": "naos.self_check.v1", "generated_at": "2026-10-04T09:00:00Z",
            "profile": "standard", "project_root": str(self.root), "naos_root": "naos",
            "status": status_from_counts(counts), "summary": counts, "checks": checks,
            "limitations": ["Synthetic adverse acquisition fixture, not a resolved component."]}
        self.source = self.root / "naos/reports/self_check.json"
        self.source.write_text(json.dumps(self.report) + "\n", encoding="utf-8")
        self.pack = evidence_pack_output_path(self.root, "naos", self.policy)
        self.pack.parent.mkdir(parents=True, exist_ok=True)
        self.pack.write_text('{"schema":"naos.evidence_pack.v1","status":"advisory"}\n', encoding="utf-8")
        self.path = resolution.dependency_inputs_path(self.root, "naos", self.policy)

    def capture(self):
        return resolution.capture_dependency_inputs(self.root, naos_root="naos", policy=self.policy)

    def alias(self, source, destination, *, directory=False):
        try:
            destination.symlink_to(source, target_is_directory=directory)
        except OSError as exc:
            if os.name == "nt" and directory and getattr(exc, "winerror", None) == 1314:
                result = subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(destination), str(source)],
                    capture_output=True)
                if result.returncode == 0:
                    return
                self.skipTest(f"Directory alias unavailable: {result.stderr}")
            self.skipTest(f"Symlink unavailable: {exc}")

    def test_capture_preserves_exact_adverse_inputs_and_encoding(self):
        prior = [self.source.read_bytes(), self.pack.read_bytes()]
        self.assertEqual(self.capture(), self.path)
        data = json.loads(self.path.read_bytes())
        self.assertEqual(data["purpose"], "attestation_collection_preimages_only")
        self.assertNotIn("status", data)
        for entry, content in zip(data["artifacts"], prior):
            self.assertEqual(entry["raw_utf8"].encode("utf-8"), content)
            self.assertEqual(entry["content_sha256"], hashlib.sha256(content).hexdigest())
            self.assertEqual(entry["size_bytes"], len(content))
        self.assertEqual(self.path.read_bytes(), resolution._canonical(data))
        self.assertEqual(prior, [self.source.read_bytes(), self.pack.read_bytes()])

    def test_parent_substitution_after_final_validation_preserves_outside_capture(self):
        self.path.parent.mkdir()
        outside = self.root / "outside"
        outside.mkdir()
        victim = outside / self.path.name
        original = b'{"schema":"naos.self_check_dependency_inputs.v1","sentinel":"outside"}\n'
        victim.write_bytes(original)
        saved = self.root / "original-capture-parent"
        resolver = resolution.dependency_inputs_path
        calls = 0
        substituted = False

        def checked(*args, **kwargs):
            nonlocal calls, substituted
            result = resolver(*args, **kwargs)
            calls += 1
            if calls == 2:
                self.path.parent.rename(saved)
                self.alias(outside, self.path.parent, directory=True)
                substituted = True
                # The old producer publishes by this pathname; retain a real
                # same-named outside stage to expose the redirected replacement.
                for stage in saved.glob(".self-check-collection-*"):
                    (outside / stage.name).write_bytes(stage.read_bytes())
            return result

        try:
            with patch.object(resolution, "dependency_inputs_path", side_effect=checked):
                try:
                    self.capture()
                except (OSError, ValueError):
                    pass
            self.assertGreaterEqual(calls, 2)
            self.assertEqual(victim.read_bytes(), original)
        finally:
            if substituted:
                if os.name == "nt":
                    os.rmdir(self.path.parent)
                else:
                    self.path.parent.unlink()
            if saved.exists():
                saved.rename(self.path.parent)

    def test_capture_leaf_symlink_preserves_target(self):
        self.path.parent.mkdir()
        victim = self.root / "victim.json"
        victim.write_bytes(b"outside")
        self.alias(victim, self.path)
        with self.assertRaises((OSError, ValueError)):
            self.capture()
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(victim.read_bytes(), b"outside")

    def test_capture_hardlink_preserves_both_names(self):
        self.capture()
        original = self.path.read_bytes()
        other = self.root / "other.json"
        os.link(self.path, other)
        with self.assertRaises((OSError, ValueError)):
            self.capture()
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(other.read_bytes(), original)
        self.assertEqual(self.path.stat().st_nlink, 2)

    def test_capture_refuses_foreign_prior_schema(self):
        self.path.parent.mkdir()
        self.path.write_bytes(b'{"schema":"foreign"}\n')
        with self.assertRaisesRegex(resolution.ResolutionRefusal, "collection_destination_alias"):
            self.capture()
        self.assertEqual(self.path.read_bytes(), b'{"schema":"foreign"}\n')

    def test_real_unverified_resolution_refuses_before_receipt_publication(self):
        receipt = {"schema": resolution.SCHEMA, "status": "resolved", "profile": "standard"}
        target = resolution.receipt_path(self.root, "naos", self.policy)
        with self.assertRaisesRegex(resolution.ResolutionRefusal, "receipt_failed_publication_verification"):
            resolution.write_resolution(self.root, receipt, naos_root="naos", policy=self.policy)
        self.assertFalse(target.exists())

    def test_low_level_receipt_bytes_do_not_establish_proof_acceptance(self):
        target = resolution.receipt_path(self.root, "naos", self.policy)
        synthetic = {"schema": resolution.SCHEMA, "boundary_fixture": "not a verified proof"}
        raw = json.dumps(synthetic, indent=2, allow_nan=False).encode() + b"\n"
        resolution._publish_dependency_output(target, raw, schema=resolution.SCHEMA,
                                             alias_code="receipt_aliases_unrecognized_input")
        self.assertEqual(target.read_bytes(), raw)
        with self.assertRaisesRegex(resolution.ResolutionRefusal, "only_verified_resolved_receipt_may_publish"):
            resolution.write_resolution(self.root, synthetic, naos_root="naos", policy=self.policy)
        self.assertEqual(target.read_bytes(), raw)

    def test_capture_change_after_preimage_read_is_preserved(self):
        self.capture()
        foreign = b'{"schema":"naos.self_check_dependency_inputs.v1","foreign":"new"}'
        import naos_trace_atomic_write as writer
        publish = writer.publish_trace

        def changed(path, payload, original, **kwargs):
            path.write_bytes(foreign)
            return publish(path, payload, original, **kwargs)

        with patch.object(writer, "publish_trace", side_effect=changed):
            with self.assertRaises((OSError, ValueError)):
                self.capture()
        self.assertEqual(self.path.read_bytes(), foreign)

    def test_late_foreign_schema_is_refused_at_shared_boundary(self):
        self.capture()
        foreign = b'{"schema":"foreign"}'
        self.path.write_bytes(foreign)
        with self.assertRaisesRegex(resolution.ResolutionRefusal, "collection_destination_alias"):
            resolution._publish_dependency_output(self.path, b"unpublished", schema="naos.self_check_dependency_inputs.v1",
                                                 alias_code="collection_destination_alias")
        self.assertEqual(self.path.read_bytes(), foreign)

    def test_capture_write_failure_preserves_prior_output_and_platform_cleanup(self):
        self.capture()
        original = self.path.read_bytes()
        import naos_trace_atomic_write as writer
        before = sorted(path.name for path in self.path.parent.iterdir())
        if os.name == "nt":
            import naos_windows_report as native
            failure = patch.object(native.wh.HeldHandle, "write_all",
                                   side_effect=OSError("synthetic stage write failure"))
        else:
            failure = patch.object(writer.os, "write", side_effect=OSError("synthetic stage write failure"))
        with failure as failed_write:
            with self.assertRaisesRegex(OSError, "synthetic stage write failure"):
                self.capture()
            failed_write.assert_called()
        self.assertEqual(self.path.read_bytes(), original)
        after = {path.name for path in self.path.parent.iterdir()}
        if os.name == "posix":
            retained = after - set(before)
            self.assertEqual(len(retained), 1)
            self.assertTrue(next(iter(retained)).startswith(".naos-trace-"))
            self.assertEqual(after - retained, set(before))
        else:
            self.assertEqual(sorted(after), before)

    @unittest.skipUnless(os.name == "posix", "POSIX mode reset and parent authority")
    def test_readable_read_only_capture_replacement_preserves_creation_mode(self):
        self.capture()
        self.path.chmod(0o444)
        self.report["limitations"].append("Changed adverse source; no readiness claim.")
        self.source.write_text(json.dumps(self.report), encoding="utf-8")
        previous = os.umask(0o027)
        try:
            self.capture()
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertIn("Changed adverse source", self.path.read_text(encoding="utf-8"))

    def assert_owner_read_refusal_preserves_output(self, action, target, mask):
        before_bytes = target.read_bytes() if target.exists() else None
        before_stat = target.stat() if target.exists() else None
        before_names = sorted(path.name for path in target.parent.iterdir())
        previous = os.umask(mask)
        try:
            with self.assertRaisesRegex(ValueError, "owner-read is masked.*destination left unchanged"):
                action()
            self.assertEqual(os.umask(mask), mask, "publication changed the process umask")
        finally:
            os.umask(previous)
        if before_stat is None:
            self.assertFalse(target.exists())
        else:
            self.assertEqual(target.read_bytes(), before_bytes)
            after_stat = target.stat()
            for field in ("st_dev", "st_ino", "st_mode", "st_mtime_ns", "st_nlink"):
                self.assertEqual(getattr(after_stat, field), getattr(before_stat, field), field)
        after_names = {path.name for path in target.parent.iterdir()}
        retained = after_names - set(before_names)
        self.assertEqual(len(retained), 1)
        self.assertTrue(next(iter(retained)).startswith(".naos-trace-"))
        self.assertEqual(after_names - retained, set(before_names))

    @unittest.skipUnless(os.name == "posix", "Approved POSIX owner-read-masking refusal")
    def test_new_capture_refuses_owner_read_mask_without_changing_umask(self):
        self.path.parent.mkdir()
        for mask in (0o400, 0o600, 0o577):
            with self.subTest(mask=oct(mask)):
                self.assert_owner_read_refusal_preserves_output(self.capture, self.path, mask)

    @unittest.skipUnless(os.name == "posix", "Approved POSIX owner-read-masking refusal")
    def test_existing_capture_refusal_preserves_file_and_umask(self):
        self.capture()
        self.report["limitations"].append("Changed adverse input; not proof acceptance.")
        self.source.write_text(json.dumps(self.report), encoding="utf-8")
        for mask in (0o400, 0o600, 0o577):
            with self.subTest(mask=oct(mask)):
                self.assert_owner_read_refusal_preserves_output(self.capture, self.path, mask)

    @unittest.skipUnless(os.name == "posix", "Approved POSIX owner-read-masking refusal")
    def test_receipt_boundary_permission_refusal_is_not_proof_acceptance(self):
        target = resolution.receipt_path(self.root, "naos", self.policy)
        target.parent.mkdir(parents=True, exist_ok=True)
        # Exercise the shared receipt writer only; no verified receipt is claimed.
        raw = json.dumps({"schema": resolution.SCHEMA, "boundary_fixture": "unverified"}).encode() + b"\n"
        def publish():
            resolution._publish_dependency_output(target, raw, schema=resolution.SCHEMA,
                                                 alias_code="receipt_aliases_unrecognized_input")
        for existing in (False, True):
            if existing:
                publish()
                raw = json.dumps({"schema": resolution.SCHEMA, "boundary_fixture": "changed unverified"}).encode() + b"\n"
            for mask in (0o400, 0o600, 0o577):
                with self.subTest(existing=existing, mask=oct(mask)):
                    self.assert_owner_read_refusal_preserves_output(publish, target, mask)


if __name__ == "__main__":
    unittest.main()
