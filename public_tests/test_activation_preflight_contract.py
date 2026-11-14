"""G2/G9: installed policy reads and truthful pre-mutation refusals."""

import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import naos_init as init  # noqa: E402 - kit module bootstrap
from upgrade_contract import planner, security, windows_cli, windows_handles  # noqa: E402 - kit module bootstrap
from upgrade_contract.windows_handles import UnsafeWindowsPath, WindowsHandles  # noqa: E402


class PolicyFixture:
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.policy = self.root / "source-policy.yaml"
        self.raw = (ROOT / "configs/upgrade_source_policy.yaml").read_bytes()
        self.policy.write_bytes(self.raw)
        self.alias = self.root / "installed-policy.yaml"
        os.link(self.policy, self.alias)


class SourcePolicyLinkTests(PolicyFixture, unittest.TestCase):
    def test_linked_installed_policy_resolves_the_same_snapshot(self):
        expected = planner.load_source_policy_snapshot(ROOT / "configs/upgrade_source_policy.yaml")
        actual = planner.load_source_policy_snapshot(self.alias, expected_sha256=expected.sha256)
        self.assertEqual(actual, expected)
        self.assertEqual(self.policy.read_bytes(), self.raw)
        self.assertEqual(self.alias.stat().st_nlink, 2)

    def test_linked_policy_still_refuses_an_unexpected_digest(self):
        with self.assertRaisesRegex(planner.ContentPlanningError, "snapshot is unavailable"):
            planner.load_source_policy_snapshot(self.alias, expected_sha256="0" * 64)

    @unittest.skipUnless(os.name == "posix", "POSIX no-follow source reader")
    def test_policy_symlink_remains_refused(self):
        symbolic = self.root / "policy-symlink.yaml"
        symbolic.symlink_to(self.policy)
        with self.assertRaises((OSError, planner.ContentPlanningError)):
            planner.load_source_policy_snapshot(symbolic)
        self.assertEqual(self.policy.read_bytes(), self.raw)

    @unittest.skipUnless(os.name == "posix", "POSIX concurrent alias-write observation")
    def test_policy_changed_through_an_alias_during_read_is_refused(self):
        original_read = os.read
        changed = False

        def mutate(descriptor, count):
            nonlocal changed
            raw = original_read(descriptor, count)
            if raw and not changed:
                changed = True
                self.policy.write_bytes(self.raw + b"\n")
            return raw

        with patch.object(planner.os, "read", side_effect=mutate), \
                self.assertRaisesRegex(planner.ContentPlanningError, "changed while it was read"):
            planner.load_source_policy_snapshot(self.alias)


class ActivationPreflightTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX greenfield intent route")
    def test_unsupported_adapter_is_not_applied_and_creates_no_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary).resolve() / "project"
            stdout, stderr = io.StringIO(), io.StringIO()
            simulated = types.SimpleNamespace(version_info=types.SimpleNamespace(major=3, minor=14))
            args = [str(init.__file__), str(target), "--new", "--tier", "quickstart", "--memory", "disabled", "--activate"]
            with patch.object(security, "sys", simulated), patch.object(sys, "argv", args), \
                    patch.object(init, "begin_greenfield_root") as begin, \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = init.main()
            self.assertEqual(result, 3, stdout.getvalue() + stderr.getvalue())
            self.assertFalse(target.exists())
            begin.assert_not_called()
            self.assertIn("NOT_APPLIED", stderr.getvalue())
            self.assertIn("Python 3.11-3.13", stderr.getvalue())
            self.assertNotIn("ACTIVATION_FAILED", stderr.getvalue())

    def test_windows_native_admission_failure_is_preflight(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "project"
            with patch.object(init, "_windows_cli", return_value=windows_cli), \
                    patch.object(windows_cli, "source_pairs", return_value=[]), \
                    patch.object(windows_cli, "WindowsHandles", side_effect=RuntimeError("unsupported native runtime")), \
                    self.assertRaisesRegex(init.ActivationPreflightRefusal, "unsupported native runtime"):
                init._activate_managed_content(target, [], request_inputs={}, dry_run=False, greenfield=True,
                    fixed_checks=[{"check_id": "generated_profile_contract", "status": "passed", "evidence_sha256": "a" * 64}])
            self.assertFalse(target.exists())

    def test_late_windows_failure_is_not_relabelled_as_preflight(self):
        with patch.object(init, "_windows_cli", return_value=windows_cli), \
                patch.object(windows_cli, "activate", side_effect=RuntimeError("late failure")):
            with self.assertRaisesRegex(RuntimeError, "late failure"):
                init._activate_managed_content(Path("unused-project"), [], request_inputs={},
                                                dry_run=False, greenfield=True)


@unittest.skipUnless(os.name == "nt", "native Windows read-handle contract")
class WindowsPolicyReadTests(PolicyFixture, unittest.TestCase):
    @contextlib.contextmanager
    def parent_handle(self, handles):
        with contextlib.ExitStack() as stack:
            parent = stack.enter_context(handles.open_root(self.root.anchor))
            for component in self.root.parts[1:]:
                parent = stack.enter_context(handles.open_child(
                    parent, component, kind="directory", pin_for_read=True))
            yield parent

    def test_policy_role_allows_read_only_alias_and_default_read_stays_strict(self):
        handles = WindowsHandles()
        with self.parent_handle(handles) as parent:
            with self.assertRaises(UnsafeWindowsPath):
                handles.open_child(parent, self.alias.name, kind="file", pin_for_read=True)
            with handles.open_child(parent, self.alias.name, kind="file", pin_for_read=True,
                                    for_policy_read=True) as held:
                self.assertEqual(held.read(len(self.raw)), self.raw)
                with self.assertRaises(ValueError):
                    held.write_all(b"no mutation")
                with self.assertRaises(OSError):
                    self.policy.write_bytes(b"competing alias write")
        self.assertEqual(self.policy.read_bytes(), self.raw)

    def test_policy_role_cannot_request_mutation_access(self):
        handles = WindowsHandles()
        with self.parent_handle(handles) as parent:
            for mutation in ("for_write", "for_delete", "for_rename", "for_lock", "for_security_copy", "for_metadata_restore"):
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    handles.open_child(parent, self.alias.name, kind="file", pin_for_read=True,
                                       for_policy_read=True, **{mutation: True})

    def test_unsupported_windows_version_is_refused_at_cli_entry(self):
        target = self.root / "unsupported-project"
        stdout, stderr = io.StringIO(), io.StringIO()
        simulated = types.SimpleNamespace(platform="win32", implementation=sys.implementation,
                                          version_info=(3, 14))
        args = [str(init.__file__), str(target), "--new", "--tier", "quickstart", "--memory", "disabled", "--activate"]
        with patch.object(windows_handles, "sys", simulated), patch.object(sys, "argv", args), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = init.main()
        self.assertEqual(result, 2, stdout.getvalue() + stderr.getvalue())
        self.assertFalse(target.exists())
        self.assertIn("NOT_APPLIED", stderr.getvalue())
        self.assertIn("CPython 3.11, 3.12, or 3.13", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
