"""G1: directory preparation and persistent claim locks refuse filesystem aliases."""
from __future__ import annotations
import contextlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path[:0] = [str(KIT), str(KIT / "scripts")]
import naos_task_claims as CLAIMS  # noqa: E402
import naos_session_identity as SESSION  # noqa: E402
import naos_windows_report as NATIVE  # noqa: E402


class CoordinationWriteSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-coordination-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.project = self.base / "project"
        (self.project / "naos/reports").mkdir(parents=True)
        self.outside = self.base / "outside"
        self.outside.mkdir()
        self.claims = self.project / "naos/task_claims.yaml"
        self.lock = self.claims.with_name(self.claims.name + ".lock")

    def directory_alias(self, path, destination):
        if os.name == "nt":
            result = subprocess.run([os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", "mklink", "/J",
                                     str(path), str(destination)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            path.symlink_to(destination, target_is_directory=True)

    def test_lock_parent_alias_creates_no_external_directory_or_lock(self):
        alias = self.project / "naos/alias"
        self.directory_alias(alias, self.outside)
        with self.assertRaises(CLAIMS.ClaimLockError):
            with CLAIMS.claim_transaction(alias / "new/task_claims.yaml"):
                self.fail("Unsafe lock parent reached transaction")
        self.assertEqual(list(self.outside.iterdir()), [])

    def test_hardlinked_lock_is_refused_without_changing_aliases(self):
        victim = self.outside / "preserve"
        victim.write_bytes(b"synthetic existing bytes")
        os.link(victim, self.lock)
        before = (victim.stat().st_ino, victim.read_bytes(), victim.stat().st_nlink)
        with self.assertRaises(CLAIMS.ClaimLockError):
            with CLAIMS.claim_transaction(self.claims):
                self.fail("Multiply-linked lock reached transaction")
        self.assertEqual((victim.stat().st_ino, victim.read_bytes(), victim.stat().st_nlink), before)
        self.assertEqual(self.lock.stat().st_ino, before[0])

    @unittest.skipUnless(os.name == "posix", "POSIX deterministic parent replacement; Windows ancestors are pinned")
    def test_parent_swap_at_leaf_open_creates_no_external_lock(self):
        original_open = os.open
        changed = False
        held = self.project / "held-naos"
        def exchange(path, *args, **kwargs):
            nonlocal changed
            if not changed and os.fspath(path) in {str(self.lock), self.lock.name}:
                changed = True
                self.lock.parent.rename(held)
                self.directory_alias(self.lock.parent, self.outside)
            return original_open(path, *args, **kwargs)
        # Mocking os.open changes supports_dir_fd membership; retain the real
        # capability decision while injecting only the actual leaf-open event.
        import naos_policy as policy
        with patch.object(policy, "_secure_directory_fd_writes_supported", return_value=True), \
             patch.object(CLAIMS.os, "open", side_effect=exchange):
            with self.assertRaises(CLAIMS.ClaimLockError):
                with CLAIMS.claim_transaction(self.claims):
                    self.fail("Changed logical lock parent reached transaction")
        self.assertTrue(changed)
        self.assertEqual(list(self.outside.iterdir()), [])

    @unittest.skipUnless(os.name == "posix", "POSIX late hardlink creation while held")
    def test_hardlink_added_after_lock_acquisition_is_refused(self):
        original = CLAIMS._regular_lock_stat
        calls = 0
        alias = self.outside / "late-lock"
        def linked(path):
            nonlocal calls
            calls += 1
            if calls == 3:
                os.link(self.lock, alias)
            return original(path)
        with patch.object(CLAIMS, "_regular_lock_stat", side_effect=linked):
            with self.assertRaises(CLAIMS.ClaimLockError):
                with CLAIMS.claim_transaction(self.claims):
                    self.fail("New hardlink reached transaction")
        self.assertTrue(alias.exists())
        self.assertEqual(alias.read_bytes(), b"")

    def test_regular_lock_keeps_bytes_inode_and_releases_after_body_error(self):
        self.lock.write_bytes(b"existing lock bytes are not a protocol")
        before = (self.lock.stat().st_ino, self.lock.read_bytes())
        with self.assertRaisesRegex(RuntimeError, "synthetic body"):
            with CLAIMS.claim_transaction(self.claims):
                raise RuntimeError("synthetic body")
        with CLAIMS.claim_transaction(self.claims, timeout=0.1):
            self.assertEqual(self.lock.stat().st_ino, before[0])
        self.assertEqual((self.lock.stat().st_ino, self.lock.read_bytes()), before)

    def test_missing_ordinary_lock_parents_are_created_without_payload(self):
        target = self.project / "new/nested/task_claims.yaml"
        with CLAIMS.claim_transaction(target):
            lock = target.with_name(target.name + ".lock")
            self.assertEqual(lock.stat().st_nlink, 1)
        self.assertEqual(lock.read_bytes(), b"")
        self.assertFalse(target.exists())

    def session(self, policy=None):
        return SESSION.ensure_session_context(root=self.project, naos_root="naos", policy=policy or {},
                    profile="quickstart", requested_session_id="session-synthetic")

    def test_session_id_directory_alias_creates_no_external_reports(self):
        parent = self.project / "naos/sessions"
        parent.mkdir()
        self.directory_alias(parent / "session-synthetic", self.outside)
        with self.assertRaises((OSError, ValueError)):
            self.session()
        self.assertEqual(list(self.outside.iterdir()), [])
        self.assertFalse((self.project / "naos/sessions_index.json").exists())

    def test_session_reports_subdirectory_alias_creates_no_external_child(self):
        parent = self.project / "naos/sessions/session-synthetic"
        parent.mkdir(parents=True)
        self.directory_alias(parent / "alias", self.outside)
        with self.assertRaises((OSError, ValueError)):
            self.session({"paths": {"reports_dir": "alias/new"}})
        self.assertEqual(list(self.outside.iterdir()), [])

    def test_ordinary_session_nested_reports_and_reuse_remain(self):
        with patch.dict(os.environ, {"NAOS_FIXED_TIME": "2026-10-20T00:00:00Z"}):
            first = self.session({"paths": {"reports_dir": "nested/reports"}})
            index = self.project / "naos/sessions_index.json"
            before = index.read_bytes()
            second = self.session({"paths": {"reports_dir": "nested/reports"}})
        self.assertEqual(first["status"], "session_created")
        self.assertEqual(second["status"], "session_reused")
        self.assertEqual(index.read_bytes(), before)
        self.assertTrue((self.project / "naos/sessions/session-synthetic/nested/reports").is_dir())

    def copied_cli(self):
        if shutil.which("make") is None:
            self.skipTest("Make unavailable; direct native directory/lock tests remain separate")
        for name in ("scripts", "schemas", "policies", "upgrade_contract"):
            if (KIT / name).is_dir():
                shutil.copytree(KIT / name, self.project / name, ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copyfile(KIT / "templates/Makefile.naos", self.project / "Makefile.naos")
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("NAOS_") and key != "PYTHONPATH"}
        env.update(PYTHONDONTWRITEBYTECODE="1", NAOS_FIXED_TIME="2026-10-20T00:00:00Z",
                   NAOS_OPERATOR_ID="synthetic-operator", PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        return env

    def make(self, target, env, arguments="--profile quickstart"):
        return subprocess.run([shutil.which("make"), "-f", "Makefile.naos", target,
                    "PYTHON=" + sys.executable, "NAOS_COMMON_ARGS=" + arguments,
                    "SESSION_ID=session-synthetic", "TASK=T-SYNTHETIC"], cwd=self.project, env=env,
                    capture_output=True, text=True, timeout=30)

    def assert_make_session(self, target):
        env = self.copied_cli()
        parent = self.project / "naos/sessions"
        parent.mkdir()
        self.directory_alias(parent / "session-synthetic", self.outside)
        result = self.make(target, env)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(list(self.outside.iterdir()), [])
        self.assertFalse((self.project / "naos/sessions_index.json").exists())

    def assert_make_claims(self, target):
        env = self.copied_cli()
        alias = self.project / "naos/alias"
        self.directory_alias(alias, self.outside)
        policy = self.project / "naos/test-policy.yaml"
        policy.write_text(yaml.safe_dump({"paths": {"task_claims_file": "alias/new/claims.yaml"}}), encoding="utf-8")
        result = self.make(target, env, "--profile quickstart --policy naos/test-policy.yaml")
        report_path = self.project / "naos/reports/task_claim_report.json"
        self.assertIn("blocked", result.stdout, result.stdout + result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(list(self.outside.iterdir()), [])
        self.assertFalse(report_path.exists())
        self.assertFalse((self.project / "naos/sessions_index.json").exists())

    def test_make_session_id_refuses_linked_session_directory(self):
        self.assert_make_session("naos-session-id")
    def test_make_operator_attribution_refuses_linked_session_directory(self):
        self.assert_make_session("naos-operator-attribution")
    def test_make_session_start_refuses_linked_session_directory(self):
        self.assert_make_session("naos-session-start")
    def test_make_session_checkpoint_refuses_linked_session_directory(self):
        self.assert_make_session("naos-session-checkpoint")
    def test_make_session_end_refuses_linked_session_directory(self):
        self.assert_make_session("naos-session-end")
    def test_make_claim_refuses_linked_coordination_parent(self):
        self.assert_make_claims("naos-task-claim")
    def test_make_release_refuses_linked_coordination_parent(self):
        self.assert_make_claims("naos-task-release")
    def test_make_claim_list_refuses_linked_coordination_parent(self):
        self.assert_make_claims("naos-task-claims")
        with self.subTest(guard="Make lock leaf symlink"):
            victim = self.outside / "lock-leaf-victim"
            victim.write_bytes(b"synthetic lock victim")
            try:
                self.lock.symlink_to(victim)
            except OSError as exc:
                if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                    self.skipTest("Native Windows file-symlink privilege unavailable")
                raise
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith("NAOS_") and key != "PYTHONPATH"}
            env.update(PYTHONDONTWRITEBYTECODE="1", NAOS_FIXED_TIME="2026-10-20T00:00:00Z")
            result = self.make("naos-task-claims", env, "--profile quickstart --json")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("task_claims.lock_unavailable", result.stdout)
            self.assertNotIn("Traceback", result.stderr)
            self.assertEqual(victim.read_bytes(), b"synthetic lock victim")
            self.assertTrue(self.lock.is_symlink())

    @unittest.skipUnless(os.name == "nt", "Native shared lock mode requires Windows")
    def test_windows_shared_lock_options_refuse_other_access_modes(self):
        self.lock.write_bytes(b"")
        handles = NATIVE.wh.WindowsHandles()
        with contextlib.ExitStack() as stack:
            parent, name = NATIVE._parent(handles, stack, str(self.lock))
            for options in ({"shared_lock": 1}, {"shared_lock": True},
                            {"shared_lock": True, "for_lock": True, "for_write": True},
                            {"shared_lock": True, "for_lock": True, "pin_for_read": True}):
                with self.subTest(options=options):
                    with self.assertRaises(ValueError):
                        handles.open_child(parent, name, kind="file", **options)

    @unittest.skipUnless(os.name == "nt", "Native shared lock mode requires Windows")
    def test_windows_shared_lock_open_interoperates_with_crt_and_denies_delete(self):
        import msvcrt
        self.lock.write_bytes(b"")
        handles = NATIVE.wh.WindowsHandles()
        with contextlib.ExitStack() as stack:
            parent, name = NATIVE._parent(handles, stack, str(self.lock))
            fd = os.open(self.lock, os.O_RDWR)
            try:
                with handles.open_child(parent, name, kind="file", for_lock=True, shared_lock=True) as held:
                    held.lock_exclusive(nonblocking=True)
                    os.lseek(fd, 0, os.SEEK_SET)
                    with self.assertRaises(OSError):
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    with self.assertRaises(OSError):
                        self.lock.rename(self.lock.with_name("must-not-rename"))
                    held.unlock()
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    with self.assertRaises(NATIVE.wh.WindowsHandleError) as raised:
                        held.lock_exclusive(nonblocking=True)
                    self.assertEqual(raised.exception.winerror, 33)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    held.lock_exclusive(nonblocking=True)
                    held.unlock()
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
