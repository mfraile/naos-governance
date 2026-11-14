"""G1: immutable repository-intelligence outputs use guarded create-only publication."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import stat
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

KIT = Path(__file__).resolve().parents[1]
for directory in (KIT, KIT / "scripts"):
    sys.path.insert(0, str(directory))
import naos_repository_intelligence as engine  # noqa: E402


class RIOutputWriteSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-ri-output-ü-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "README.md").write_text("# Synthetic project\n", encoding="utf-8")
        self.path = self.root / "reports" / "status.json"
        self.path.parent.mkdir()

    def status(self, output=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = engine.main(["status", str(self.project), "--output", str(output or self.path)])
        return result, stdout.getvalue(), stderr.getvalue()

    def alias(self, source, destination, *, directory=False):
        try:
            destination.symlink_to(source, target_is_directory=directory)
        except OSError as exc:
            if os.name == "nt" and directory and getattr(exc, "winerror", None) == 1314:
                result = subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(destination), str(source)],
                                        capture_output=True)
                if result.returncode == 0:
                    return
            self.skipTest(f"Symlink unavailable: {exc}")

    def test_real_status_external_report_matches_stdout_without_project_writes(self):
        before = {str(p.relative_to(self.project)): p.read_bytes() for p in self.project.rglob("*") if p.is_file()}
        code, stdout, stderr = self.status()
        self.assertEqual(code, 2)  # not_configured is a diagnostic report, not readiness.
        self.assertEqual(stderr, "")
        report = json.loads(stdout)
        self.assertEqual(report["status"], "not_configured")
        self.assertEqual(self.path.read_bytes(),
                         (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode())
        self.assertEqual(before, {str(p.relative_to(self.project)): p.read_bytes()
                                  for p in self.project.rglob("*") if p.is_file()})

    def test_parent_substitution_after_normalization_does_not_redirect_creation(self):
        outside = self.root / "outside"
        outside.mkdir()
        sentinel = outside / "sentinel"
        sentinel.write_bytes(b"preserve")
        parked = self.root / "parked"
        resolver = engine._external_output_path
        substituted = False

        def admitted(*args, **kwargs):
            nonlocal substituted
            result = resolver(*args, **kwargs)
            self.path.parent.rename(parked)
            try:
                self.alias(outside, self.path.parent, directory=True)
            except BaseException:
                parked.rename(self.path.parent)
                raise
            substituted = True
            return result

        try:
            with patch.object(engine, "_external_output_path", side_effect=admitted):
                self.status()
            self.assertTrue(substituted)
            self.assertFalse((outside / self.path.name).exists())
            self.assertEqual(sentinel.read_bytes(), b"preserve")
        finally:
            if substituted:
                os.rmdir(self.path.parent) if os.name == "nt" else self.path.parent.unlink()
                parked.rename(self.path.parent)

    @unittest.skipUnless(os.name == "posix", "POSIX pathname chmod regression")
    def test_no_pathname_permission_mutation_after_payload(self):
        victim = self.root / "victim"
        victim.write_bytes(b"foreign")
        victim.chmod(0o640)
        chmod = os.chmod
        dangerous_calls = []

        def substituted(path, mode, *args, **kwargs):
            if Path(path) == self.path:
                dangerous_calls.append(str(path))
                self.path.unlink()
                self.path.symlink_to(victim)
            return chmod(path, mode, *args, **kwargs)

        with patch.object(engine.os, "chmod", side_effect=substituted):
            self.status()
        self.assertEqual(stat.S_IMODE(victim.stat().st_mode), 0o640)
        self.assertEqual(victim.read_bytes(), b"foreign")
        self.assertEqual(dangerous_calls, [])
        self.assertFalse(self.path.is_symlink())

    def test_failed_payload_does_not_leave_partial_final_report(self):
        if os.name == "nt":
            import naos_windows_report as native
            modules = [sys.modules[engine.ri_windows_storage.WindowsHandles.__module__], native.wh]
            owners = [(module.HeldHandle, "write_all") for module in modules]
        else:
            owners = [(os, "write")]

        def fail_after_partial(original):
            def partial(target, data):
                original(target, data[:5])
                raise OSError("synthetic partial payload failure")
            return partial

        before = sorted(p.name for p in self.path.parent.iterdir())
        with ExitStack() as stack:
            injections = [stack.enter_context(patch.object(owner, name, autospec=True,
                          side_effect=fail_after_partial(getattr(owner, name)))) for owner, name in owners]
            code, stdout, stderr = self.status()
            self.assertGreater(sum(injected.call_count for injected in injections), 0)
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("synthetic partial payload failure", stderr)
        self.assertFalse(self.path.exists())
        after = {p.name for p in self.path.parent.iterdir()}
        if os.name == "posix":
            retained = after - set(before)
            self.assertEqual(len(retained), 1)
            name = next(iter(retained))
            self.assertTrue(name.startswith(".naos-trace-"))
            self.assertIn(str(self.path.parent / name), stderr)
            self.assertEqual(after - retained, set(before))
        else:
            self.assertEqual(sorted(after), before)

    def test_existing_regular_and_hardlinked_outputs_are_preserved(self):
        self.path.write_bytes(b"existing")
        other = self.root / "other"
        os.link(self.path, other)
        before = self.path.stat()
        code, stdout, stderr = self.status()
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("refused", stderr)
        after = self.path.stat()
        self.assertEqual((after.st_ino, after.st_mtime_ns, after.st_mode, after.st_nlink),
                         (before.st_ino, before.st_mtime_ns, before.st_mode, before.st_nlink))
        self.assertEqual(self.path.read_bytes(), b"existing")
        self.assertEqual(other.read_bytes(), b"existing")

    def test_symlink_leaf_is_preserved(self):
        victim = self.root / "victim"
        victim.write_bytes(b"foreign")
        self.alias(victim, self.path)
        code, stdout, stderr = self.status()
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("symbolic link", stderr)
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(victim.read_bytes(), b"foreign")

        with self.subTest(guard="Make plan leaf symlink"):
            make = shutil.which("make")
            if make is None:
                self.skipTest("Make unavailable; direct RI status control ran separately")
            for name in ("scripts", "upgrade_contract", "schemas", "policies"):
                shutil.copytree(KIT / name, self.project / name,
                                ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copy2(KIT / "naos_profile_rules.py", self.project / "naos_profile_rules.py")
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith("NAOS_") and key != "PYTHONPATH"}
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            result = subprocess.run(
                [make, "-f", str(KIT / "templates/Makefile.naos"),
                 "naos-repository-intelligence-plan", "PYTHON=" + sys.executable,
                 "NAOS_COMMON_ARGS=--profile quickstart --policy policies/default_policy.yaml",
                 "REPOSITORY_INTELLIGENCE_ARGS=--output " + shlex.quote(str(self.path))],
                cwd=self.project, env=env, capture_output=True, text=True, timeout=60)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Repository intelligence refused: Output path is a symbolic link and was preserved.",
                          result.stderr)
            self.assertTrue(self.path.is_symlink())
            self.assertEqual(victim.read_bytes(), b"foreign")
            self.assertFalse((self.project / ".naos").exists())

    def test_nested_unicode_report_keeps_exact_serialization(self):
        path = self.root / "new" / "nested" / "é.json"
        report = {"z": "é", "a": [1, False, None]}
        engine._write_immutable_json(path, report)
        self.assertEqual(path.read_bytes(),
                         (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode())
        with self.assertRaises((OSError, ValueError)):
            engine._write_immutable_json(path, {"changed": True})
        self.assertEqual(json.loads(path.read_bytes()), report)

    @unittest.skipUnless(os.name == "posix", "POSIX explicit private mode")
    def test_private_mode_overrides_owner_read_mask_without_changing_umask(self):
        previous = os.umask(0o577)
        try:
            engine._write_immutable_json(self.path, {"fixture": "private"})
            observed = os.umask(0o577)
            self.assertEqual(observed, 0o577)
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(json.loads(self.path.read_bytes()), {"fixture": "private"})

    def test_existing_ancestor_alias_retains_normalization_or_native_refusal(self):
        real = self.root / "physical"
        real.mkdir()
        alias = self.root / "alias"
        self.alias(real, alias, directory=True)
        try:
            code, stdout, stderr = self.status(alias / "status.json")
            if os.name == "nt" and "[WinError 448]" in stderr:
                self.assertEqual((code, stdout), (2, ""))
                self.assertIn("Repository intelligence refused:", stderr)
                self.assertNotIn("Traceback", stderr)
                self.assertFalse((real / "status.json").exists())
                return
            self.assertEqual((code, stderr), (2, ""))
            self.assertEqual(json.loads((real / "status.json").read_bytes()), json.loads(stdout))
        finally:
            os.rmdir(alias) if os.name == "nt" else alias.unlink()

    def test_internal_output_is_refused_before_creation(self):
        internal = self.project / "status.json"
        code, stdout, stderr = self.status(internal)
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("outside", stderr)
        self.assertFalse(internal.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX search-only ancestor authority")
    def test_search_only_nonfinal_ancestor_retains_report_creation(self):
        ancestor = self.root / "search-only"
        parent = ancestor / "reports"
        parent.mkdir(parents=True)
        ancestor.chmod(0o111)
        try:
            code, stdout, stderr = self.status(parent / "status.json")
            self.assertEqual((code, stderr), (2, ""))
            self.assertEqual(json.loads((parent / "status.json").read_bytes()), json.loads(stdout))
        finally:
            ancestor.chmod(0o700)

    @unittest.skipUnless(os.name == "posix", "POSIX held parent sync")
    def test_parent_sync_uses_held_directory_and_failure_keeps_complete_report(self):
        sync = os.fsync
        directory_syncs = []

        def failed_directory_sync(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                directory_syncs.append(os.fstat(descriptor).st_ino)
                raise OSError("synthetic directory sync failure")
            return sync(descriptor)

        with patch.object(os, "fsync", side_effect=failed_directory_sync):
            code, stdout, stderr = self.status()
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("synthetic directory sync failure", stderr)
        self.assertEqual(directory_syncs, [self.path.parent.stat().st_ino])
        self.assertEqual(json.loads(self.path.read_bytes())["status"], "not_configured")
        self.assertEqual(sorted(p.name for p in self.path.parent.iterdir()), [self.path.name])

    @unittest.skipUnless(os.name == "posix", "POSIX held parent sync")
    def test_parent_sync_remains_opt_in_and_requires_boolean(self):
        from naos_trace_atomic_write import publish_trace
        sync = os.fsync
        directory_syncs = []

        def observed(descriptor):
            directory_syncs.append(stat.S_ISDIR(os.fstat(descriptor).st_mode))
            return sync(descriptor)

        with patch.object(os, "fsync", side_effect=observed):
            publish_trace(self.path, "plain", None, private_new_file=True, create_only=True)
        self.assertEqual(directory_syncs, [False])
        with self.assertRaisesRegex(ValueError, "booleans"):
            publish_trace(self.root / "invalid.json", "plain", None, fsync_parent=1)
        self.assertFalse((self.root / "invalid.json").exists())

    @unittest.skipUnless(os.name == "nt", "Native Windows immutable payload bound")
    def test_native_payload_bound_is_preserved_without_final_creation(self):
        self.assertEqual(engine.ri_windows_storage.MAX_FILE_BYTES, 64 * 1024 * 1024)
        with patch.object(engine.ri_windows_storage, "MAX_FILE_BYTES", 32):
            with self.assertRaisesRegex(engine.ri_windows_storage.RIStorageConflict, "exceeds the bound"):
                engine._write_immutable_json(self.path, {"payload": "x" * 40})
        self.assertFalse(self.path.exists())

    def test_default_plan_directory_retains_private_create_only_output(self):
        path = engine._external_output_path(
            self.project, None, engine.default_plan_output({"plan_id": "RI-0123456789abcdef"}))
        self.addCleanup(lambda: __import__("shutil").rmtree(path.parent))
        engine._write_immutable_json(path, {"fixture": "default allocation only"})
        self.assertEqual(path.name, "RI-0123456789abcdef.json")
        with self.assertRaises((OSError, ValueError)):
            engine._write_immutable_json(path, {})


if __name__ == "__main__":
    unittest.main()
