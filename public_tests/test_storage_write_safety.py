"""G6/G10 memory CLI and audit publication boundary regressions."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(KIT / "scripts"))
sys.path.insert(0, str(KIT))
import naos_audit_log as audit  # noqa: E402
from naos_policy import load_policy  # noqa: E402


class StorageWriteSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-storage-writes-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.project = self.base / "adopter"
        self.project.mkdir()
        (self.project / "naos/reports").mkdir(parents=True)
        self.outside = self.base / "outside"
        self.outside.mkdir()
        self.victim = self.outside / "sentinel.txt"
        self.original = b"SYNTHETIC OUTSIDE FILE\n"
        self.victim.write_bytes(self.original)
        self.policy = load_policy(root=self.project)
        self.kwargs = dict(root=self.project, naos_root="naos", policy=self.policy,
                           profile="standard", event_type="report_generated",
                           generated_by={"operator_id": "synthetic-team", "operator_source": "env"})
        self.env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        for name in ("NAOS_ROOT", "NAOS_POLICY", "NAOS_STRICT", "NAOS_PROFILE", "PYTHONPATH"):
            self.env.pop(name, None)

    def memory(self, *, mask=None):
        return subprocess.run(
            [sys.executable, "-B", str(KIT / "naos_memory.py"), "setup",
             "--project-root", str(self.project), "--disposition", "defer", "--write"],
            cwd=self.project, env=self.env, capture_output=True, text=True, check=False, timeout=30,
            preexec_fn=(lambda: os.umask(mask)) if mask is not None else None,
        )

    def directory_link(self, path):
        if os.name == "nt":
            result = subprocess.run(
                [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", "mklink", "/J", str(path), str(self.outside)],
                capture_output=True, text=True, check=False, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            path.symlink_to(self.outside, target_is_directory=True)

    def file_link(self, path):
        try:
            path.symlink_to(self.victim)
        except OSError:
            if os.name != "nt":
                raise
            os.link(self.victim, path)

    def event(self):
        event = audit.build_audit_event(**self.kwargs, generated_at="2026-10-19T00:00:00Z")
        self.assertFalse(audit.validate_audit_event(event))
        return event

    def event_path(self, event):
        return audit.event_file_path(self.project / "naos/audit_log", event)

    def make_audit(self, *extra):
        shutil.copytree(KIT / "scripts", self.project / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(KIT / "schemas", self.project / "schemas")
        metadata = self.project / "scripts/naos_posix_metadata"
        metadata.mkdir()
        for name in ("security.py", "linux_primitives.py"):
            shutil.copy2(KIT / "upgrade_contract" / name, metadata / name)
        shutil.copy2(KIT / "upgrade_contract/windows_handles.py", self.project / "scripts/naos_windows_handles.py")
        shutil.copy2(KIT / "templates/Makefile.naos", self.project / "Makefile.naos")
        make = shutil.which("make")
        if make is not None:
            command = [make, "-f", "Makefile.naos", "naos-audit-log", "NAOS_PROFILE=standard",
                       "PYTHON=" + sys.executable, *extra]
        else:
            command = [sys.executable, "-B", "scripts/naos_audit_log.py", "--profile", "standard"]
            if extra:
                command += ["--event-type", "report_generated"]
        return subprocess.run(command, cwd=self.project, env=self.env, capture_output=True,
                              text=True, check=False, timeout=30)

    def test_memory_cli_refuses_hardlinked_config(self):
        config = self.project / "configs/naos_memory.yaml"
        config.parent.mkdir()
        original = b"memory:\n  custom: preserve\n"
        source = self.outside / "shared.yaml"
        source.write_bytes(original)
        os.link(source, config)
        before = config.stat()
        result = self.memory()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(config.read_bytes(), original)
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual((config.stat().st_dev, config.stat().st_ino), (before.st_dev, before.st_ino))

    def test_memory_cli_refuses_linked_config_parent(self):
        self.directory_link(self.project / "configs")
        result = self.memory()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(list(self.outside.iterdir()), [self.victim])

    def test_memory_private_creation_and_existing_mode_control(self):
        result = self.memory()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = self.project / "configs/naos_memory.yaml"
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
            config.write_text("memory:\n  custom: keep\n", encoding="utf-8")
            config.chmod(0o440)
            self.addCleanup(config.chmod, 0o600)
            result = self.memory()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o440)
            self.assertIn("custom: keep", config.read_text())

    @unittest.skipUnless(os.name == "posix", "POSIX umask contract; Windows uses native private ACLs")
    def test_memory_private_creation_restores_owner_bits_masked_by_umask(self):
        config = self.project / "configs/naos_memory.yaml"
        config.parent.mkdir(mode=0o700)
        for mask in (0o200, 0o400, 0o600):
            with self.subTest(umask=oct(mask)):
                config.unlink(missing_ok=True)
                result = self.memory(mask=mask)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
                self.assertIn("state: deferred", config.read_text())

    def test_make_audit_refuses_linked_event_parent(self):
        self.directory_link(self.project / "naos/audit_log")
        result = self.make_audit("EVENT_TYPE=report_generated")
        if os.name == "nt" and result.returncode:
            self.assertIn("[WinError 448]", result.stderr)
            self.assertEqual(list(self.outside.iterdir()), [self.victim])
            self.assertEqual(self.victim.read_bytes(), self.original)
            self.assertFalse((self.project / "naos/reports/audit_log_summary.json").exists())
            return
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(list(self.outside.iterdir()), [self.victim])
        report = json.loads((self.project / "naos/reports/audit_log_summary.json").read_text())
        self.assertEqual(report["manual_event_write"]["status"], "advisory")
        self.assertEqual(report["manual_event_write"]["findings"][-1]["id"], "audit_log.event_write_failed")

    def test_make_audit_summary_refuses_leaf_link(self):
        self.file_link(self.project / "naos/reports/audit_log_summary.json")
        result = self.make_audit()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.victim.read_bytes(), self.original)

    def test_audit_refuses_linked_date_parent(self):
        event = self.event()
        destination = self.event_path(event)
        destination.parent.parent.mkdir()
        self.directory_link(destination.parent)
        with patch.object(audit, "build_audit_event", return_value=copy.deepcopy(event)):
            result = audit.write_audit_event(**self.kwargs)
        self.assertEqual(result["status"], "advisory", result)
        self.assertEqual(list(self.outside.iterdir()), [self.victim])

    def test_audit_does_not_follow_predictable_legacy_temp_alias(self):
        event = self.event()
        destination = self.event_path(event)
        destination.parent.mkdir(parents=True)
        legacy = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
        self.file_link(legacy)
        with patch.object(audit, "build_audit_event", return_value=copy.deepcopy(event)):
            result = audit.write_audit_event(**self.kwargs)
        self.assertEqual(self.victim.read_bytes(), self.original)
        self.assertEqual(result["status"], "written", result)
        self.assertEqual(json.loads(Path(result["event_file"]).read_text()), event)

    def test_audit_preserves_final_file_appearing_during_staging(self):
        event = self.event()
        destination = self.event_path(event)
        foreign = b"SYNTHETIC CONCURRENT OCCUPANT\n"
        if os.name == "nt":
            import naos_windows_report as native
            owner, name = native.wh.HeldHandle, "flush"
        else:
            owner, name = os, "fsync"
        original_flush = getattr(owner, name)
        injected = []
        def appear(*args, **kwargs):
            original_flush(*args, **kwargs)
            if not injected:
                destination.write_bytes(foreign)
                injected.append(destination.stat().st_ino)
        with (patch.object(audit, "build_audit_event", return_value=copy.deepcopy(event)),
              patch.object(owner, name, side_effect=appear, autospec=True) if os.name == "nt"
              else patch.object(owner, name, side_effect=appear)):
            result = audit.write_audit_event(**self.kwargs)
        self.assertTrue(injected)
        self.assertEqual(destination.read_bytes(), foreign)
        self.assertEqual(destination.stat().st_ino, injected[0])
        if os.name == "nt":
            self.assertEqual(result["status"], "written", result)
            written = Path(result["event_file"])
            self.assertNotEqual(written, destination)
            retried = json.loads(written.read_text())
            self.assertFalse(audit.validate_audit_event(retried))
            self.assertEqual(audit.recompute_public_audit_event_id(retried), retried["event_id"])
            self.assertEqual(self.event_path(retried), written)
            self.assertNotEqual(event["event_nonce"], retried["event_nonce"])
        else:
            self.assertEqual(result["status"], "advisory", result)

    def test_regular_events_are_valid_and_do_not_change_prior_event(self):
        first = audit.write_audit_event(**self.kwargs)
        self.assertEqual(first["status"], "written", first)
        path = Path(first["event_file"])
        before, identity = path.read_bytes(), path.stat().st_ino
        self.assertFalse(audit.validate_audit_event(json.loads(before)))
        second = audit.write_audit_event(**self.kwargs)
        self.assertEqual(second["status"], "written", second)
        self.assertNotEqual(first["event_file"], second["event_file"])
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(path.stat().st_ino, identity)

    def test_audit_native_collision_preserves_occupant_and_rebinds_retry(self):
        import naos_trace_atomic_write as atomic
        event = self.event()
        destination = self.event_path(event)
        foreign = b"SYNTHETIC OCCUPANT AT NATIVE PUBLICATION\n"
        injected = []
        if os.name == "nt":
            import naos_windows_report as native
            owner, name = native.wh.WindowsHandles, "rename_no_replace"
        else:
            owner, name = atomic, "_publish_no_replace"
        original_publish = getattr(owner, name)
        def collide(*args, **kwargs):
            if not injected:
                destination.write_bytes(foreign)
                injected.append(destination.stat().st_ino)
            return original_publish(*args, **kwargs)
        with (patch.object(audit, "build_audit_event", return_value=copy.deepcopy(event)),
              patch.object(owner, name, side_effect=collide, autospec=True) if os.name == "nt"
              else patch.object(owner, name, side_effect=collide)):
            result = audit.write_audit_event(**self.kwargs)
        self.assertTrue(injected)
        self.assertEqual(destination.read_bytes(), foreign)
        self.assertEqual(destination.stat().st_ino, injected[0])
        self.assertEqual(result["status"], "written", result)
        written = Path(result["event_file"])
        self.assertNotEqual(written, destination)
        retried = json.loads(written.read_text())
        self.assertFalse(audit.validate_audit_event(retried))
        self.assertEqual(audit.recompute_public_audit_event_id(retried), retried["event_id"])
        self.assertEqual(self.event_path(retried), written)
        self.assertNotEqual(event["event_nonce"], retried["event_nonce"])

    def test_audit_refuses_absolute_and_traversal_configured_roots(self):
        for configured in (str(self.outside), "../../outside"):
            with self.subTest(configured=configured):
                policy = copy.deepcopy(self.policy)
                policy.setdefault("paths", {})["audit_log_root"] = configured
                result = audit.write_audit_event(**{**self.kwargs, "policy": policy})
                self.assertEqual(result["status"], "advisory", result)
                self.assertEqual(list(self.outside.iterdir()), [self.victim])
        for configured in (str(self.outside), "../outside"):
            with self.subTest(naos_root=configured):
                result = audit.write_audit_event(**{**self.kwargs, "naos_root": configured})
                self.assertEqual(result["status"], "advisory", result)
                self.assertEqual(list(self.outside.iterdir()), [self.victim])

    def test_windows_create_only_collision_dispatch_is_portable(self):
        import naos_trace_atomic_write as atomic
        import naos_windows_report as native
        target = self.project / "portable-native-dispatch.json"
        cases = [native.wh.WindowsHandleError("NtSetInformationFile(FileRenameInformation)",
                                             winerror=183, ntstatus=native.COLLISION),
                 native.wh.UnsafeWindowsPath("Trace target appeared before publication")]
        for error in cases:
            with self.subTest(error=type(error).__name__):
                with (patch.object(atomic.os, "name", "nt"),
                      patch.object(native, "write_strict_report", side_effect=error) as publish):
                    with self.assertRaises(FileExistsError):
                        atomic.publish_trace(target, "event", None, create_only=True)
                self.assertTrue(publish.call_args.kwargs["expect_absent"])
                self.assertTrue(publish.call_args.kwargs["require_existing_write_access"])
        # Other native errors retain their original failure; no retry/fallback.
        with (patch.object(atomic.os, "name", "nt"),
              patch.object(native, "write_strict_report", side_effect=native.wh.UnsafeWindowsPath("unsupported ACL"))):
            with self.assertRaises(native.wh.UnsafeWindowsPath):
                atomic.publish_trace(target, "event", None, create_only=True)

    def test_audit_valid_nested_root_and_unicode_metadata(self):
        policy = copy.deepcopy(self.policy)
        policy.setdefault("paths", {})["audit_log_root"] = "nested/audit-é"
        kwargs = {**self.kwargs, "policy": policy,
                  "source_report": {"schema": "naos.synthetic.v1", "summary": {"note": "review café"}}}
        result = audit.write_audit_event(**kwargs)
        self.assertEqual(result["status"], "written", result)
        path = Path(result["event_file"])
        self.assertTrue(path.is_relative_to(self.project / "naos/nested/audit-é"))
        event = json.loads(path.read_text())
        self.assertFalse(audit.validate_audit_event(event))
        self.assertEqual(audit.recompute_public_audit_event_id(event), event["event_id"])

    @unittest.skipUnless(os.name == "posix", "POSIX staging seam; native Windows uses held handles")
    def test_memory_refuses_late_hardlink_without_changing_config(self):
        import naos_memory as memory
        config = self.project / "configs/naos_memory.yaml"
        config.parent.mkdir()
        original = b"memory:\n  custom: keep\n"
        config.write_bytes(original)
        alias = self.outside / "late-alias.yaml"
        original_fsync = os.fsync
        injected = []
        def link_after_stage(descriptor):
            original_fsync(descriptor)
            if not injected:
                os.link(config, alias)
                injected.append(config.stat().st_ino)
        with patch.object(os, "fsync", side_effect=link_after_stage):
            with self.assertRaises((OSError, ValueError, RuntimeError)):
                memory._atomic_write_config(self.project, config, "replacement")
        self.assertTrue(injected)
        self.assertEqual(config.read_bytes(), original)
        self.assertEqual(alias.read_bytes(), original)
        self.assertEqual(config.stat().st_ino, injected[0])


if __name__ == "__main__":
    unittest.main()
