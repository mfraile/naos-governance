"""Admissibility ZIP output custody, compatibility and streaming regressions."""
from __future__ import annotations

import contextlib
from datetime import date
import importlib.util
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import tracemalloc
import unittest
from unittest.mock import patch
import zipfile

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(KIT / "scripts"))
SPEC = importlib.util.spec_from_file_location("_zip_output_safety", KIT / "scripts/workflows/make_admissibility_pack.py")
PACK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACK)
DAY = "2026-10-19"


class ZipOutputWriteSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-zip-output-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.project = self.base / "project"
        self.project.mkdir()
        self.output = self.project / "pack.zip"
        self.outside = self.base / "outside"
        self.outside.mkdir()
        self.victim = self.outside / "victim.zip"
        self.original = b"SYNTHETIC OUTSIDE ZIP SENTINEL\r\n"
        self.victim.write_bytes(self.original)
        for pattern in PACK.REQUIRED_ARTEFACTS:
            path = self.project / PACK._resolve(pattern, Path("naos"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"# synthetic " + path.name.encode() + b"\x00\xff\r\n")
            os.utime(path, (1600000000, 1600000000))
        conformance = self.project / "naos/reports/conformance_latest.json"
        conformance.parent.mkdir()
        conformance.write_bytes(b'{"status":"pass"}\n')
        os.utime(conformance, (1600000000, 1600000000))

    def build(self, output=None, root=Path("naos")):
        with contextlib.chdir(self.project):
            return PACK.build_pack(root, DAY, self.output if output is None else output)

    def file_alias(self, output, *, hard=False):
        if hard:
            os.link(self.victim, output)
        else:
            try:
                output.symlink_to(self.victim)
            except OSError as exc:
                if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                    self.skipTest("Native Windows file-symlink privilege unavailable")
                raise

    def directory_alias(self, alias, target):
        if os.name == "nt":
            result = subprocess.run([os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", "mklink", "/J",
                                     str(alias), str(target)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            alias.symlink_to(target, target_is_directory=True)

    def test_leaf_aliases_refuse_without_changing_victim(self):
        for hard in (True, False):
            with self.subTest(hard=hard):
                self.file_alias(self.output, hard=hard)
                try:
                    with self.assertRaises((ValueError, OSError)):
                        self.build()
                    self.assertEqual(self.victim.read_bytes(), self.original)
                finally:
                    self.output.unlink(missing_ok=True)
                    self.victim.write_bytes(self.original)

    def test_linked_parent_does_not_receive_archive_or_children(self):
        alias = self.project / "alias"
        self.directory_alias(alias, self.outside)
        with self.assertRaises((ValueError, OSError)):
            self.build(alias / "new/nested/pack.zip")
        self.assertEqual(list(self.outside.iterdir()), [self.victim])
        self.assertEqual(self.victim.read_bytes(), self.original)

    @unittest.skipUnless(os.name == "posix", "POSIX alias/dotdot traversal")
    def test_canceled_parent_alias_is_not_collapsed(self):
        child = self.outside / "child"
        child.mkdir()
        alias = self.project / "alias"
        alias.symlink_to(child, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            self.build(alias / ".." / "victim.zip")
        self.assertEqual(self.victim.read_bytes(), self.original)
        self.assertFalse((self.project / "victim.zip").exists())

    def test_generation_failure_preserves_previous_output(self):
        before = b"SYNTHETIC PREVIOUS OUTPUT"
        self.output.write_bytes(before)
        self.output.chmod(0o640)
        class Interrupted(zipfile.ZipFile):
            def write(self, *args, **kwargs):
                super().write(*args, **kwargs)
                raise OSError("synthetic archive-generation interruption")
        with patch.object(PACK, "ZipFile", Interrupted):
            with self.assertRaisesRegex(OSError, "synthetic archive-generation interruption"):
                self.build()
        self.assertEqual(self.output.read_bytes(), before)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o640)
        self.assertEqual(len(list(self.project.glob(".naos-trace-*.tmp"))), 1 if os.name == "posix" else 0)

    def test_finalized_crc_failure_preserves_old_output_or_absence(self):
        events = []
        class CorruptAfterClose(zipfile.ZipFile):
            def close(self):
                stream, opened = self.fp, self.fp is not None
                super().close()
                if self.mode == "w" and opened:
                    def corrupt(held):
                        held.seek(0)
                        central = held.read().find(b"PK\x01\x02")
                        if central < 0:
                            raise AssertionError("Missing finalized central directory")
                        held.seek(central + 16)
                        byte = held.read(1)
                        held.seek(central + 16)
                        held.write(bytes([byte[0] ^ 1]))
                        held.flush()
                    if getattr(stream, "closed", False):
                        with open(self.filename, "r+b") as held:
                            corrupt(held)
                    else:
                        corrupt(stream)
                    events.append("tampered")
        def archive(file, mode="r", *args, **kwargs):
            if mode == "w":
                return CorruptAfterClose(file, mode, *args, **kwargs)
            events.append("reader")
            return zipfile.ZipFile(file, mode, *args, **kwargs)
        for existing in (False, True):
            with self.subTest(existing=existing):
                self.output.unlink(missing_ok=True)
                before = b"SYNTHETIC PRIOR VALIDATION BOUNDARY"
                if existing:
                    self.output.write_bytes(before)
                events.clear()
                with patch.object(PACK, "ZipFile", archive):
                    with self.assertRaisesRegex(RuntimeError, "Zip integrity check failed at naos/DASHBOARD.md"):
                        self.build()
                self.assertEqual(events, ["tampered", "reader"])
                if existing:
                    self.assertEqual(self.output.read_bytes(), before)
                else:
                    self.assertFalse(self.output.exists())

    def test_finalized_reader_uses_same_held_object(self):
        writers = []
        def archive(file, mode="r", *args, **kwargs):
            if mode == "w":
                writers.append(file)
            else:
                self.assertIs(file, writers[0])
                self.assertFalse(isinstance(file, (str, Path)))
            return zipfile.ZipFile(file, mode, *args, **kwargs)
        with patch.object(PACK, "ZipFile", archive):
            self.build()
        self.assertEqual(len(writers), 1)

    def test_alias_inserted_after_validation_refuses_and_preserves_victim(self):
        for hard in (True, False):
            with self.subTest(hard=hard):
                self.output.unlink(missing_ok=True)
                owner = self
                class AliasAfterValidation(zipfile.ZipFile):
                    def testzip(self):
                        result = super().testzip()
                        owner.output.unlink(missing_ok=True)
                        owner.file_alias(owner.output, hard=hard)
                        return result
                def archive(file, mode="r", *args, **kwargs):
                    cls = AliasAfterValidation if mode == "r" else zipfile.ZipFile
                    return cls(file, mode, *args, **kwargs)
                with patch.object(PACK, "ZipFile", archive):
                    try:
                        with self.assertRaises((ValueError, OSError)):
                            self.build()
                        self.assertEqual(self.victim.read_bytes(), self.original)
                    finally:
                        self.output.unlink(missing_ok=True)

    def test_ordinary_archive_matches_legacy_bytes_and_mode(self):
        expected = io.BytesIO()
        with contextlib.chdir(self.project), zipfile.ZipFile(expected, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for pattern in PACK.REQUIRED_ARTEFACTS:
                path = PACK._resolve(pattern, Path("naos"))
                archive.write(path, PACK._archive_name(path, Path("naos")))
            path = PACK._resolve(PACK.OPTIONAL_CONFORMANCE, Path("naos"))
            archive.write(path, PACK._archive_name(path, Path("naos")))
        self.output.write_bytes(b"SYNTHETIC PRIOR ZIP")
        self.output.chmod(0o640)
        result = self.build()
        self.assertEqual(result, self.output)
        self.assertEqual(self.output.read_bytes(), expected.getvalue())
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o640)

    def test_cli_io_refusal_is_reported_without_output_creation(self):
        output = self.project / "uncreated/pack.zip"
        error = OSError(22, "synthetic unreadable input junction")
        error.winerror = 448
        stderr = io.StringIO()
        with patch.object(PACK, "_missing_required", side_effect=error), \
             patch.object(sys, "argv", ["make_admissibility_pack.py", "--root", "naos",
                                       "--date", DAY, "--output", str(output)]), \
             contextlib.redirect_stderr(stderr):
            result = PACK.main()
        self.assertEqual(result, 1)
        self.assertIn("admissibility-pack: ERROR:", stderr.getvalue())
        self.assertIn(str(error), stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertFalse(output.parent.exists())
        self.assertEqual(self.victim.read_bytes(), self.original)

    def test_input_root_alias_is_usable_or_clearly_refused_with_safe_output(self):
        inputs = {self.project / PACK._resolve(pattern, Path("naos")):
                  (self.project / PACK._resolve(pattern, Path("naos"))).read_bytes()
                  for pattern in PACK.REQUIRED_ARTEFACTS}
        alias = self.project / "input-alias"
        self.directory_alias(alias, self.project / "naos")
        output = self.project / "nested/pack.zip"
        try:
            result = self.build(output, root=Path("input-alias"))
        except OSError as exc:
            if os.name == "nt" and getattr(exc, "winerror", None) == 448:
                self.assertFalse(output.parent.exists())
                self.assertEqual(self.victim.read_bytes(), self.original)
                result = subprocess.run(
                    [sys.executable, "-B", str(KIT / "scripts/workflows/make_admissibility_pack.py"),
                     "--root", "input-alias", "--date", DAY, "--output", str(output)],
                    cwd=self.project, capture_output=True, text=True, encoding="utf-8", timeout=30)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("admissibility-pack: ERROR:", result.stderr)
                self.assertIn("448", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertFalse(output.parent.exists())
                self.assertEqual(self.victim.read_bytes(), self.original)
                self.assertTrue(all(path.read_bytes() == raw for path, raw in inputs.items()))
                return
            raise
        self.assertEqual(result, output)
        with zipfile.ZipFile(output) as archive:
            self.assertIsNone(archive.testzip())
            self.assertIn("input-alias/DASHBOARD.md", archive.namelist())

    def test_make_target_refuses_planted_output_alias(self):
        shutil.copytree(KIT / "scripts", self.project / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(KIT / "schemas", self.project / "schemas")
        shutil.copytree(KIT / "templates/structural-seeds", self.project / "templates/structural-seeds")
        metadata = self.project / "scripts/naos_posix_metadata"
        metadata.mkdir()
        for name in ("security.py", "linux_primitives.py"):
            shutil.copy2(KIT / "upgrade_contract" / name, metadata / name)
        shutil.copy2(KIT / "upgrade_contract/windows_handles.py", self.project / "scripts/naos_windows_handles.py")
        shutil.copy2(KIT / "templates/Makefile.naos", self.project / "Makefile.naos")
        output = self.project / ("naos/admissibility-" + date.today().isoformat() + ".zip")
        make = shutil.which("make")
        command = ([make, "-f", "Makefile.naos", "admissibility-pack", "PYTHON=" + sys.executable]
                   if make else [sys.executable, "-B", "scripts/workflows/make_admissibility_pack.py"])
        for hard in (True, False):
            with self.subTest(hardlink=hard):
                self.file_alias(output, hard=hard)
                selected = output.lstat()
                try:
                    result = subprocess.run(command, cwd=self.project, env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                                            capture_output=True, text=True, encoding="utf-8", timeout=60)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(self.victim.read_bytes(), self.original)
                    self.assertIn("admissibility-pack: ERROR:", result.stderr)
                finally:
                    observed = output.lstat()
                    self.assertEqual((observed.st_dev, observed.st_ino), (selected.st_dev, selected.st_ino))
                    output.unlink()

    def test_large_archive_and_preimage_remain_streamed(self):
        peaks = []
        chunk = os.urandom(1024 * 1024)
        for megabytes in (2, 24):
            for path in (self.project / "naos/DASHBOARD.md", self.output):
                with path.open("wb") as stream:
                    for _ in range(megabytes):
                        stream.write(chunk)
            tracemalloc.start()
            try:
                self.build()
                peaks.append(tracemalloc.get_traced_memory()[1])
            finally:
                tracemalloc.stop()
            with zipfile.ZipFile(self.output) as archive:
                self.assertIsNone(archive.testzip())
                self.assertEqual(archive.getinfo("naos/DASHBOARD.md").file_size, megabytes * len(chunk))
        self.assertLess(peaks[1], 12 * 1024 * 1024, peaks)
        self.assertLess(peaks[1] - peaks[0], 4 * 1024 * 1024, peaks)


class BinaryPublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-binary-publication-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def test_production_then_validation_precede_publication(self):
        from naos_policy import write_binary_output
        path = self.root / "nested/report.bin"
        events = []
        def produce(stream):
            events.append("produce")
            self.assertFalse(path.exists())
            stream.write(b"\x00\xff\r\n")
        def validate(stream):
            events.append("validate")
            self.assertFalse(path.exists())
            self.assertEqual(stream.read(), b"\x00\xff\r\n")
        write_binary_output(path, produce, validate)
        self.assertEqual(events, ["produce", "validate"])
        self.assertEqual(path.read_bytes(), b"\x00\xff\r\n")

    def test_validator_cannot_change_bytes_and_publish_them(self):
        from naos_policy import write_binary_output
        path = self.root / "report.bin"
        path.write_bytes(b"SYNTHETIC ORIGINAL")
        def validate(stream):
            stream.write(b"tamper")
        with self.assertRaises((ValueError, OSError)):
            write_binary_output(path, lambda stream: stream.write(b"expected"), validate)
        self.assertEqual(path.read_bytes(), b"SYNTHETIC ORIGINAL")
        self.assertEqual(len(list(self.root.glob(".naos-trace-*.tmp"))), 1 if os.name == "posix" else 0)

    def test_binary_route_never_uses_whole_file_byte_reader(self):
        from naos_policy import write_binary_output
        import naos_trace_atomic_write as atomic
        path = self.root / "report.bin"
        block = b"x" * (1024 * 1024)
        with path.open("wb") as stream:
            for _ in range(8):
                stream.write(block)
        def produce(stream):
            for _ in range(8):
                stream.write(block)
        def validate(stream):
            count = 0
            while data := stream.read(65536):
                self.assertEqual(data, b"x" * len(data))
                count += len(data)
            self.assertEqual(count, 8 * len(block))
        with patch.object(atomic, "_bytes", side_effect=AssertionError("whole-file byte materialization")):
            write_binary_output(path, produce, validate)
        self.assertEqual(path.stat().st_size, 8 * len(block))

    def test_invalid_callbacks_refuse_before_parent_creation(self):
        from naos_policy import write_binary_output
        target = self.root / "absent/parent/report.bin"
        for produce, validate in ((None, lambda stream: None), (lambda stream: None, None)):
            with self.subTest(produce=produce), self.assertRaises(TypeError):
                write_binary_output(target, produce, validate)
            self.assertFalse(target.parent.exists())

    def test_existing_native_byte_route_remains_dependency_free(self):
        code = (
            "import importlib.abc,pathlib,sys,os\n"
            "class NoYaml(importlib.abc.MetaPathFinder):\n"
            " def find_spec(self,fullname,path=None,target=None):\n"
            "  if fullname=='yaml' or fullname.startswith('yaml.'): raise ImportError('YAML deliberately unavailable')\n"
            "sys.meta_path.insert(0,NoYaml())\n"
            f"sys.path.insert(0,{str(KIT / 'scripts')!r})\n"
            "import naos_windows_report as native\n"
            f"target=pathlib.Path({str(self.root / 'native.dat')!r})\n"
            "try: native.write_strict_report(target,b'bytes',private_new_file='invalid')\n"
            "except ValueError: pass\n"
            "else: raise AssertionError('Invalid mode accepted')\n"
            "if os.name=='nt':\n"
            " native.write_strict_report(target,b'bytes')\n"
            " assert target.read_bytes()==b'bytes'\n"
            " native.write_strict_report(target,b'updated bytes')\n"
            " assert target.read_bytes()==b'updated bytes'\n"
            " assert not list(target.parent.glob('.naos-report-*.tmp'))\n"
            "else:\n"
            " try: native.write_strict_report(target,b'bytes')\n"
            " except RuntimeError: pass\n"
            " else: raise AssertionError('Native Windows guard missing')\n"
        )
        result = subprocess.run([sys.executable, "-I", "-B", "-c", code], cwd=self.root,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
