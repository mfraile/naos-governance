"""Family-review templates publish complete create-only files or refuse safely."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

KIT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(KIT / "scripts"), str(KIT)]
import naos_systemic_family_review as family  # noqa: E402


def aggregate():
    return {
        "binding": {"rules_sha256": "a" * 64, "effective_policy_sha256": "b" * 64},
        "obligations": [],
        "template": {
            "schema": "synthetic.fixture",
            "reviews": [{"disposition": "unresolved", "text": "é test fixture"}],
        },
    }


class Base(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="s28-template-")
        self.addCleanup(temp.cleanup)
        self.project = Path(temp.name).resolve() / "project"
        self.project.mkdir()
        self.target = self.project / "naos/reviews/template.json"
        self.target.parent.mkdir(parents=True)

    def create(self, value=None, path=None):
        return family.create_unresolved_template(
            self.project, path or self.target, aggregate() if value is None else value
        )

    def assert_empty(self):
        self.assertFalse(self.target.exists())
        self.assertEqual(list(self.target.parent.iterdir()), [])

    def assert_failed_stage(self, before=()):
        self.assertFalse(self.target.exists())
        entries = set(self.target.parent.iterdir())
        previous = set(before)
        if os.name == "nt":
            self.assertEqual(entries, previous)
            return
        added = entries - previous
        self.assertEqual(len(added), 1)
        stage = added.pop()
        self.assertTrue(stage.name.startswith(".naos-trace-"))
        self.assertTrue(stage.name.endswith(".tmp"))
        self.assertTrue(stat.S_ISREG(stage.lstat().st_mode))
        self.assertEqual(entries - {stage}, previous)

    def expected(self):
        return (
            json.dumps(aggregate()["template"], indent=2, ensure_ascii=False) + "\n"
        ).encode()


class FamilyTemplatePublicationTests(Base):
    def test_ordinary_nested_exact_utf8_lf_and_create_only(self):
        self.target.parent.rmdir()
        self.target.parent.parent.rmdir()
        self.create()
        self.assertEqual(self.target.read_bytes(), self.expected())
        with self.assertRaises((OSError, ValueError)):
            self.create()
        self.assertEqual(self.target.read_bytes(), self.expected())

    def test_existing_regular_hardlink_and_directory_preserved(self):
        keeper = self.project / "keeper"
        keeper.write_bytes(b"outside sentinel")
        for kind in ("regular", "hardlink", "directory"):
            with self.subTest(kind=kind):
                if kind == "directory":
                    self.target.mkdir()
                elif kind == "hardlink":
                    os.link(keeper, self.target)
                else:
                    self.target.write_bytes(b"existing")
                before = self.target.stat()
                with self.assertRaises((OSError, ValueError)):
                    self.create()
                self.assertEqual(self.target.stat(), before)
                self.assertEqual(keeper.read_bytes(), b"outside sentinel")
                if kind == "directory":
                    self.target.rmdir()
                else:
                    self.target.unlink()

    def test_leaf_symlink_is_refused(self):
        keeper = self.project / "keeper"
        keeper.write_bytes(b"sentinel")
        try:
            self.target.symlink_to(keeper)
        except OSError as exc:
            self.skipTest(f"File symlink unavailable: {exc}")
        with self.assertRaises((OSError, ValueError)):
            self.create()
        self.assertTrue(self.target.is_symlink())
        self.assertEqual(keeper.read_bytes(), b"sentinel")

    def test_linked_parent_is_refused_and_outside_files_preserved(self):
        outside = self.project.parent / "outside"
        outside.mkdir()
        sentinel = outside / "keeper"
        sentinel.write_bytes(b"outside keeper")
        alias = self.project / "alias"
        try:
            alias.symlink_to(outside, target_is_directory=True)
        except OSError as exc:
            if os.name != "nt" or getattr(exc, "winerror", None) != 1314:
                self.skipTest(f"Directory alias unavailable: {exc}")
            import subprocess

            result = subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(alias), str(outside)],
                capture_output=True,
                text=True,
            )
            if result.returncode:
                self.skipTest(f"Directory junction unavailable: {result.stderr}")
        with self.assertRaises((OSError, ValueError)):
            self.create(path=alias / "template.json")
        self.assertEqual(sentinel.read_bytes(), b"outside keeper")
        self.assertEqual([p.name for p in outside.iterdir()], ["keeper"])

    def test_invalid_binding_does_not_allocate_output(self):
        for field in ("rules_sha256", "effective_policy_sha256"):
            value = aggregate()
            value["binding"][field] = None
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    self.create(value)
                self.assert_empty()

    def test_serialization_and_encoding_failure_leave_no_final_name(self):
        for number, value in enumerate((object(), "\ud800")):
            self.target = self.target.with_name(f"bad-{number}.json")
            with self.subTest(value=type(value).__name__):
                data = aggregate()
                data["template"]["bad"] = value
                with self.assertRaises((TypeError, UnicodeError)):
                    self.create(data)
                self.assert_empty()
                self.create()
                self.assertEqual(self.target.read_bytes(), self.expected())
                self.target.unlink()

    def test_partial_payload_failure_leaves_no_final_name_and_retry_succeeds(self):
        opened = os.fdopen
        written = os.write

        class Partial:
            def __init__(self, stream):
                self.stream = stream

            def __getattr__(self, key):
                return getattr(self.stream, key)

            def __enter__(self):
                self.stream.__enter__()
                return self

            def __exit__(self, *args):
                return self.stream.__exit__(*args)

            def write(self, data):
                self.stream.write(data[:17])
                self.stream.flush()
                raise OSError("synthetic partial payload")

        def partial_fdopen(fd, *args, **kwargs):
            return Partial(opened(fd, *args, **kwargs))

        def partial_write(fd, data):
            written(fd, data[:17])
            raise OSError("synthetic partial payload")

        with ExitStack() as contexts:
            contexts.enter_context(
                patch.object(os, "fdopen", side_effect=partial_fdopen)
            )
            contexts.enter_context(patch.object(os, "write", side_effect=partial_write))
            if os.name == "nt":
                from naos_windows_report import wh

                native = wh.HeldHandle.write_all

                def partial_native(handle, data):
                    native(handle, data[:17])
                    raise OSError("synthetic partial payload")

                contexts.enter_context(
                    patch.object(wh.HeldHandle, "write_all", new=partial_native)
                )
            with self.assertRaisesRegex(OSError, "synthetic partial payload"):
                self.create()
        self.assert_failed_stage()
        self.create()
        self.assertEqual(self.target.read_bytes(), self.expected())

    def test_flush_failure_leaves_no_final_name_and_retry_succeeds(self):
        with ExitStack() as contexts:
            contexts.enter_context(
                patch.object(
                    os, "fsync", side_effect=OSError("synthetic flush failure")
                )
            )
            if os.name == "nt":
                from naos_windows_report import wh

                contexts.enter_context(
                    patch.object(
                        wh.HeldHandle,
                        "flush",
                        side_effect=OSError("synthetic flush failure"),
                    )
                )
            with self.assertRaisesRegex(OSError, "synthetic flush failure"):
                self.create()
        self.assert_failed_stage()
        self.create()
        self.assertEqual(self.target.read_bytes(), self.expected())

    @unittest.skipUnless(os.name == "posix", "POSIX umask-filtered ordinary creation")
    def test_ordinary_modes_and_umask_are_preserved(self):
        for mask in (0o22, 0o77, 0o277):
            with self.subTest(mask=oct(mask)):
                prior = os.umask(mask)
                try:
                    self.create()
                    self.assertEqual(os.umask(mask), mask)
                finally:
                    os.umask(prior)
                self.assertEqual(self.target.stat().st_mode & 0o777, 0o600 & ~mask)
                self.assertEqual(self.target.read_bytes(), self.expected())
                self.target.unlink()


class TemplatePermissionRefusalTests(Base):
    @unittest.skipUnless(sys.platform == "darwin", "Native macOS inherited ACL")
    def test_inherited_owner_acl_is_refused_without_removing_it(self):
        import pwd
        import subprocess

        parent = self.target.parent
        entry = (
            "user:"
            + pwd.getpwuid(os.getuid()).pw_name
            + " allow read,write,file_inherit,directory_inherit"
        )
        subprocess.run(
            ["chmod", "+a", entry, str(parent)],
            check=True,
            capture_output=True,
            text=True,
        )

        def acl_entries():
            result = subprocess.run(
                ["ls", "-led", str(parent)], check=True, capture_output=True, text=True
            )
            return result.stdout.splitlines()[1:]

        before = acl_entries()
        self.assertTrue(before)
        mode = parent.stat().st_mode
        with self.assertRaisesRegex(ValueError, "inherited POSIX ACLs"):
            self.create()
        self.assert_failed_stage()
        self.assertEqual(acl_entries(), before)
        self.assertEqual(parent.stat().st_mode, mode)

    @unittest.skipUnless(
        os.name == "posix", "Approved POSIX creation-permission refusal"
    )
    def test_owner_read_mask_refuses_without_allocating_final_name_or_changing_umask(
        self,
    ):
        for mask in (0o400, 0o600, 0o577):
            self.target = self.target.with_name(f"masked-{mask}.json")
            with self.subTest(mask=oct(mask)):
                before = set(self.target.parent.iterdir())
                prior = os.umask(mask)
                try:
                    with self.assertRaisesRegex(ValueError, "owner-read"):
                        self.create()
                    self.assertEqual(os.umask(mask), mask)
                finally:
                    os.umask(prior)
                self.assert_failed_stage(before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
