"""G1: SQLite publication and ephemeral lock cleanup retain file custody."""
import copy
from contextlib import chdir
import json
import os
from pathlib import Path
import sqlite3
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

KIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KIT / "scripts"))
import naos_local_context_index as index  # noqa: E402
import naos_policy as policy  # noqa: E402

TIME = "2026-05-20T00:00:00Z"


class SQLiteWriteSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-sqlite-ü-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / "naos").mkdir()
        self.target = self.root / "naos/context_index/index.sqlite"
        self.target.parent.mkdir()
        self.lock = self.target.with_name(self.target.name + ".lock")
        self.policy = copy.deepcopy(policy.SAFE_FALLBACK_POLICY)
        self.policy.get("paths", {}).pop("local_context_index_db_lock", None)
        self.report = {"generated_at": TIME, "profile": "quickstart", "status": "ready"}

    def create(self, target=None):
        return index.create_sqlite_artifact(target or self.target, self.report, [], [], [],
            root=self.root, naos_root="naos", policy=self.policy, profile="quickstart",
            generated_at=TIME, session_id="session-1", generated_by={})

    def acquire(self, lock=None):
        return index.acquire_sqlite_lock(lock or self.lock, target_db_path=self.target,
            session_id="session-1", generated_by={}, generated_at=TIME,
            timeout_seconds=0.03, retry_interval_seconds=0.005, stale_after_seconds=60)

    def assert_create_refused(self, target=None):
        try:
            result = self.create(target)
        except (OSError, ValueError):
            return
        self.assertNotEqual(result[0]["status"], "written", result[3])

    def assert_lock_refused(self, lock):
        fd = None
        try:
            fd, result = self.acquire(lock)
        except (OSError, ValueError):
            return
        finally:
            if fd is not None:
                index.release_sqlite_lock(fd, lock)
        self.assertIsNone(fd, result)
        self.assertTrue(any(f.get("status") == "blocked" for f in result["findings"]), result)

    def symlink(self, source, destination, *, directory=False):
        try:
            destination.symlink_to(source, target_is_directory=directory)
        except OSError as exc:
            if os.name == "nt" and directory and getattr(exc, "winerror", None) == 1314:
                result = subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(destination), str(source)],
                    capture_output=True)
                if result.returncode == 0:
                    return
                self.skipTest(f"directory alias unavailable: {result.stderr}")
            self.skipTest(f"symlink unavailable: {exc}")

    def release_with_close_mutation(self, fd, mutate):
        # Windows prevents unlink/rename while the CRT lock handle is open.
        # Exercise the real close-to-delete window on every platform instead.
        original_close = os.close
        triggered = False

        def close(descriptor):
            nonlocal triggered
            original_close(descriptor)
            if descriptor == int(fd) and not triggered:
                triggered = True
                mutate()

        with patch.object(index.os, "close", side_effect=close):
            result = index.release_sqlite_lock(fd, self.lock)
        self.assertTrue(triggered)
        return result

    def hardlink(self, source, destination):
        try:
            os.link(source, destination)
        except OSError as exc:
            self.skipTest(f"hardlink unavailable: {exc}")

    def test_db_parent_alias_preserves_outside_database(self):
        outside = self.root / "outside"
        outside.mkdir()
        victim = outside / self.target.name
        victim.write_bytes(b"outside database untouched")
        alias = self.root / "alias"
        self.symlink(outside, alias, directory=True)
        self.assert_create_refused(alias / victim.name)
        self.assertEqual(victim.read_bytes(), b"outside database untouched")

    def test_db_hardlink_is_refused(self):
        victim = self.root / "victim.sqlite"
        victim.write_bytes(b"outside database untouched")
        self.hardlink(victim, self.target)
        self.assert_create_refused()
        self.assertEqual(victim.read_bytes(), b"outside database untouched")
        self.assertEqual(self.target.stat().st_ino, victim.stat().st_ino)

    def test_dangling_db_symlink_is_preserved(self):
        victim = self.root / "missing.sqlite"
        self.symlink(victim, self.target)
        self.assert_create_refused()
        self.assertFalse(victim.exists())
        self.assertTrue(self.target.is_symlink())

    def test_lock_parent_alias_is_refused_before_metadata_write(self):
        outside = self.root / "outside"
        outside.mkdir()
        alias = self.root / "alias"
        self.symlink(outside, alias, directory=True)
        self.assert_lock_refused(alias / "index.lock")
        self.assertFalse((outside / "index.lock").exists())

    def test_stale_lock_hardlink_is_preserved(self):
        victim = self.root / "victim.lock"
        original = b'{"acquired_at":"2020-01-01T00:00:00Z"}'
        victim.write_bytes(original)
        self.hardlink(victim, self.lock)
        self.assert_lock_refused(self.lock)
        self.assertEqual(victim.read_bytes(), original)
        self.assertEqual(self.lock.stat().st_ino, victim.stat().st_ino)

    def test_release_preserves_replacement_lock(self):
        fd, _ = self.acquire()
        self.assertIsNotNone(fd)
        def replace():
            self.lock.unlink()
            self.lock.write_bytes(b"foreign replacement")

        result = self.release_with_close_mutation(fd, replace)
        self.assertEqual(result["status"], "failed", result)
        self.assertEqual(self.lock.read_bytes(), b"foreign replacement")

    def test_release_preserves_in_place_lock_edit(self):
        fd, _ = self.acquire()
        self.assertIsNotNone(fd)
        self.lock.write_bytes(b"foreign edit")
        result = index.release_sqlite_lock(fd, self.lock)
        self.assertEqual(result["status"], "failed", result)
        self.assertEqual(self.lock.read_bytes(), b"foreign edit")

    def test_release_parent_substitution_preserves_outside_lock(self):
        fd, _ = self.acquire()
        self.assertIsNotNone(fd)
        old = self.target.parent.with_name("old-parent")
        outside = self.root / "outside"
        outside.mkdir()
        victim = outside / self.lock.name
        victim.write_bytes(b"foreign outside lock")
        def replace():
            self.target.parent.rename(old)
            self.symlink(outside, self.target.parent, directory=True)

        result = self.release_with_close_mutation(fd, replace)
        self.assertEqual(result["status"], "failed", result)
        self.assertEqual(victim.read_bytes(), b"foreign outside lock")
        self.assertTrue((old / self.lock.name).exists())

    def test_normal_stale_lock_and_release_remain_ephemeral(self):
        self.lock.write_text('{"acquired_at":"2020-01-01T00:00:00Z"}', encoding="utf-8")
        fd, result = self.acquire()
        self.assertIsInstance(fd, int)
        self.assertTrue(result["stale_lock_detected"])
        self.assertEqual(result["stale_lock_action"], "removed")
        metadata = json.loads(self.lock.read_bytes())
        self.assertEqual(metadata["acquired_at"], TIME)
        result = index.release_sqlite_lock(fd, self.lock)
        self.assertEqual(result["status"], "removed")
        self.assertFalse(self.lock.exists())

    def assert_malformed_lock_uses_mtime(self, raw):
        self.lock.write_bytes(raw)
        os.utime(self.lock, (1577836800, 1577836800))
        fd, result = self.acquire()
        try:
            self.assertIsNotNone(fd, result)
            self.assertTrue(result["stale_lock_detected"])
        finally:
            if fd is not None:
                index.release_sqlite_lock(fd, self.lock)

    def test_utf16_lock_retains_legacy_mtime_fallback(self):
        self.assert_malformed_lock_uses_mtime(json.dumps({"acquired_at": TIME}).encode("utf-16"))

    def test_bom_lock_retains_legacy_mtime_fallback(self):
        self.assert_malformed_lock_uses_mtime(("\ufeff" + json.dumps({"acquired_at": TIME})).encode("utf-8"))

    def test_busy_lock_preserves_database_bytes_and_mtime(self):
        self.target.write_bytes(b"old database")
        self.lock.write_text(json.dumps({"acquired_at": TIME}), encoding="utf-8")
        before = self.target.stat()
        with patch.dict(os.environ, {"NAOS_SQLITE_LOCK_TIMEOUT_SECONDS": "0.01"}):
            artifact, _, _, coordination = self.create()
        self.assertEqual(artifact["status"], "not_written")
        self.assertEqual(coordination["status"], "lock_timeout")
        self.assertEqual(self.target.read_bytes(), b"old database")
        self.assertEqual(self.target.stat().st_mtime_ns, before.st_mtime_ns)

    def test_ordinary_database_tables_schema_and_lock_cleanup(self):
        artifact, _, _, coordination = self.create()
        self.assertEqual(artifact["status"], "written")
        self.assertTrue(coordination["atomic_replace_used"])
        self.assertEqual(coordination["tables_verified"], index.verify_sqlite_tables(self.target))
        self.assertFalse(self.lock.exists())
        self.assertFalse(list(self.target.parent.glob("*.tmp.*")))
        schema = json.loads((KIT / "schemas/naos/sqlite_write_coordination.schema.json").read_bytes())
        Draft202012Validator(schema).validate(coordination)

    def test_private_inspection_database_uses_exact_registered_sink(self):
        from naos_self_check_inspection import activate_inspection, create_inspection_context, inspection_output_path

        sentinel = b"canonical database remains untouched"
        self.target.write_bytes(sentinel)
        self.policy.setdefault("paths", {})["local_context_index_sqlite"] = "context_index/index.sqlite"
        with tempfile.TemporaryDirectory(prefix="naos-private-db-") as workspace:
            context = create_inspection_context(self.root, "naos", "quickstart", self.policy,
                [("naos_local_context_index.py", [])], Path(workspace).resolve() / "inspection")
            before = {str(p.relative_to(self.root)): (p.stat().st_mode, p.stat().st_mtime_ns,
                      p.read_bytes() if p.is_file() else None) for p in [self.root, *self.root.rglob("*")]}
            with chdir(self.root), activate_inspection(context, producer="naos_local_context_index.py"):
                physical = inspection_output_path(self.root, "naos", self.target)
                self.assertNotEqual(physical, self.target)
                artifact, _, _, coordination = self.create()
                self.assertEqual(artifact["status"], "written", coordination)
                self.assertEqual(index.verify_sqlite_tables(physical), coordination["tables_verified"])
                self.assertFalse(physical.with_name(physical.name + ".lock").exists())
            after = {str(p.relative_to(self.root)): (p.stat().st_mode, p.stat().st_mtime_ns,
                     p.read_bytes() if p.is_file() else None) for p in [self.root, *self.root.rglob("*")]}
            self.assertEqual(after, before)
        self.assertEqual(self.target.read_bytes(), sentinel)

    @unittest.skipIf(os.name == "nt", "POSIX parent-authorized replacement")
    def test_readable_read_only_database_replacement_still_works(self):
        self.target.write_bytes(b"old database")
        self.target.chmod(0o444)
        probe = self.root / "mode-probe"
        probe.write_bytes(b"")
        expected = stat.S_IMODE(probe.stat().st_mode)
        self.assertEqual(self.create()[0]["status"], "written")
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), expected)

    def test_caller_owned_connection_remains_open(self):
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        index.populate_sqlite_database(None, self.report, [], [], [], connection=connection)
        self.assertEqual(connection.execute("select count(*) from index_runs").fetchone()[0], 1)

    def test_database_changed_after_validation_is_not_published(self):
        self.target.write_bytes(b"old database preserved")
        original = index.verify_sqlite_tables

        def changed(database):
            tables = original(database)
            database.write_bytes(b"")
            return tables

        with patch.object(index, "verify_sqlite_tables", side_effect=changed):
            artifact, _, _, coordination = self.create()
        self.assertEqual(artifact["status"], "not_written")
        self.assertEqual(coordination["status"], "replace_failed")
        self.assertEqual(self.target.read_bytes(), b"old database preserved")

    def test_relative_output_spelling_is_preserved_in_reports(self):
        relative = Path("naos/context_index/relative.sqlite")
        with chdir(self.root):
            artifact, _, _, coordination = self.create(relative)
        self.assertEqual(artifact["path"], str(relative))
        self.assertEqual(coordination["target_db_path"], str(relative))

    def test_release_already_absent_lock_remains_explicit(self):
        fd, _ = self.acquire()
        result = self.release_with_close_mutation(fd, self.lock.unlink)
        self.assertEqual(result["status"], "already_absent")

    def test_release_does_not_close_a_reused_foreign_descriptor(self):
        fd, _ = self.acquire()
        os.close(fd)
        foreign_path = self.root / "foreign-fd"
        foreign_path.write_bytes(b"foreign descriptor")
        foreign = os.open(foreign_path, os.O_RDONLY)
        try:
            os.dup2(foreign, int(fd))
            result = index.release_sqlite_lock(fd, self.lock)
            self.assertEqual(result["status"], "failed")
            self.assertTrue(stat.S_ISREG(os.fstat(int(fd)).st_mode))
            self.assertTrue(self.lock.exists())
        finally:
            for descriptor in {foreign, int(fd)}:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def test_actual_cli_parent_alias_preserves_outside_database(self):
        outside = self.root / "outside"
        outside.mkdir()
        victim = outside / "index.sqlite"
        victim.write_bytes(b"outside database untouched")
        alias = self.root / "alias"
        self.symlink(outside, alias, directory=True)
        result = subprocess.run([sys.executable, "-B", str(KIT / "scripts/naos_local_context_index.py"),
            "--profile", "quickstart", "--sqlite-output", str(alias / victim.name),
            "--output", str(self.root / "report.json"), "--json"], cwd=self.root,
            capture_output=True, text=True, timeout=30, env={**os.environ, "NAOS_FIXED_TIME": TIME})
        self.assertEqual(victim.read_bytes(), b"outside database untouched", result.stderr)
        if result.returncode == 0:
            self.assertFalse(json.loads(result.stdout)["summary"]["sqlite_written"])

        with self.subTest(guard="Make leaf symlink"):
            make = shutil.which("make")
            if make is None:
                self.skipTest("Make unavailable; direct CLI parent control ran separately")
            for name in ("scripts", "schemas", "upgrade_contract"):
                shutil.copytree(KIT / name, self.root / name,
                                ignore=shutil.ignore_patterns("__pycache__"))
            metadata = self.root / "scripts/naos_posix_metadata"
            metadata.mkdir(exist_ok=True)
            for name in ("security.py", "linux_primitives.py"):
                shutil.copy2(KIT / "upgrade_contract" / name, metadata / name)
            shutil.copy2(KIT / "upgrade_contract/windows_handles.py",
                         self.root / "scripts/naos_windows_handles.py")
            shutil.copy2(KIT / "policies/default_policy.yaml", self.root / "policy.yaml")
            shutil.copy2(KIT / "templates/structural-seeds/naos/local_context_index_rules.yaml",
                         self.root / "rules.yaml")
            self.symlink(victim, self.target)
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith("NAOS_") and key != "PYTHONPATH"}
            env.update(PYTHONDONTWRITEBYTECODE="1", NAOS_FIXED_TIME=TIME)
            result = subprocess.run(
                [make, "-f", str(KIT / "templates/Makefile.naos"), "naos-context-index",
                 "PYTHON=" + sys.executable, "NAOS_STRICT_ARG=",
                 "NAOS_COMMON_ARGS=--profile quickstart --policy policy.yaml --rules rules.yaml "
                 "--sqlite-output naos/context_index/index.sqlite --output make-report.json --json"],
                cwd=self.root, env=env, capture_output=True, text=True, timeout=60)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Refusing linked SQLite output component:", result.stderr)
            self.assertIn(str(self.target), result.stderr)
            self.assertEqual(victim.read_bytes(), b"outside database untouched")
            self.assertTrue(self.target.is_symlink())


if __name__ == "__main__":
    unittest.main()
