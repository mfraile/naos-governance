"""G1: semantic CSV history retains bytes and refuses redirected publication."""
from __future__ import annotations

import contextlib
import hashlib
from datetime import datetime as RealDateTime, UTC
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

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(KIT / "scripts"))
SPEC = importlib.util.spec_from_file_location("_g1_csv_quality", KIT / "scripts/naos_code_quality_audit.py")
QUALITY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = QUALITY
SPEC.loader.exec_module(QUALITY)
HEADER = "timestamp,new_function,matched_function,score,method\n"
NOW = RealDateTime(2026, 10, 20, 12, 0, tzinfo=UTC)
ROW = f"{NOW.isoformat()},new,matched,0.5000,jaccard\n"


class FixedClock(RealDateTime):
    @classmethod
    def now(cls, tz=None):
        return NOW.astimezone(tz) if tz else NOW.replace(tzinfo=None)


class SemanticHistoryWriteSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-semantic-history-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.project = self.base / "project"
        self.inventory = self.project / "naos/inventory"
        self.inventory.mkdir(parents=True)
        self.csv = self.inventory / "SEMANTIC_WARNINGS_LOG.csv"
        self.archive = self.inventory / "SEMANTIC_WARNINGS_ARCHIVE_202610.csv"
        self.victim = self.base / "outside.csv"
        self.original = b"SYNTHETIC OUTSIDE\r\n"
        self.victim.write_bytes(self.original)
        self.addCleanup(patch.stopall)
        patch.object(QUALITY, "SEMANTIC_WARNINGS_LOG", self.csv).start()
        patch("datetime.datetime", FixedClock).start()

    @staticmethod
    def native(text):
        return text.replace("\n", os.linesep).encode("utf-8")

    @staticmethod
    def history(count, separator="\n"):
        return HEADER + "".join(f"t{i},new{i},match,0.5000,jaccard{separator}" for i in range(count))

    def append(self):
        QUALITY._log_semantic_warning("new", "matched", 0.5, "jaccard")

    def rotate(self, path=None):
        with contextlib.redirect_stderr(io.StringIO()) as messages:
            result = QUALITY.rotate_semantic_warnings_log(path)
        return result, messages.getvalue()

    def link(self, path, target, *, hard=False, directory=False):
        if hard:
            os.link(target, path)
        elif os.name == "nt" and directory:
            result = subprocess.run([os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", "mklink", "/J",
                                     str(path), str(target)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            try:
                path.symlink_to(target, target_is_directory=directory)
            except OSError as exc:
                if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                    self.skipTest("Native Windows file-symlink privilege unavailable")
                raise

    def test_append_leaf_symlink_does_not_change_victim(self):
        self.link(self.csv, self.victim)
        with self.assertRaises((OSError, ValueError)):
            self.append()
        self.assertEqual(self.victim.read_bytes(), self.original)

    def test_append_hardlink_does_not_change_victim(self):
        self.link(self.csv, self.victim, hard=True)
        with self.assertRaises((OSError, ValueError)):
            self.append()
        self.assertEqual(self.victim.read_bytes(), self.original)

    def test_append_parent_alias_does_not_create_outside_children(self):
        outside = self.base / "outside-dir"
        outside.mkdir()
        alias = self.project / "alias"
        self.link(alias, outside, directory=True)
        with patch.object(QUALITY, "SEMANTIC_WARNINGS_LOG", alias / "new/log.csv"):
            with self.assertRaises((OSError, ValueError)):
                self.append()
        self.assertEqual(list(outside.iterdir()), [])

    def test_rotation_main_aliases_preserve_victim_and_create_no_archive(self):
        for hard in (True, False):
            with self.subTest(hard=hard):
                original = self.history(2001).encode()
                self.victim.write_bytes(original)
                self.link(self.csv, self.victim, hard=hard)
                try:
                    with self.assertRaises((OSError, ValueError)):
                        self.rotate()
                    self.assertEqual(self.victim.read_bytes(), original)
                    self.assertFalse(self.archive.exists())
                finally:
                    self.csv.unlink(missing_ok=True)

    def test_archive_aliases_refuse_without_shortening_main(self):
        original = self.history(2001).encode()
        self.csv.write_bytes(original)
        for hard in (True, False):
            with self.subTest(hard=hard):
                self.link(self.archive, self.victim, hard=hard)
                try:
                    with self.assertRaises((OSError, ValueError)):
                        self.rotate()
                    self.assertEqual(self.csv.read_bytes(), original)
                    self.assertEqual(self.victim.read_bytes(), self.original)
                finally:
                    self.archive.unlink(missing_ok=True)

    def test_same_main_and_archive_destination_refuses_without_data_loss(self):
        original = self.history(2001).encode()
        self.archive.write_bytes(original)
        with self.assertRaises((OSError, ValueError)):
            self.rotate(self.archive)
        self.assertEqual(self.archive.read_bytes(), original)

    def test_dangling_and_nonregular_append_destinations_are_preserved(self):
        absent = self.base / "absent-victim"
        self.link(self.csv, absent)
        try:
            with self.assertRaises((OSError, ValueError)):
                self.append()
            self.assertFalse(absent.exists())
        finally:
            self.csv.unlink()
        self.csv.mkdir()
        with self.assertRaises((OSError, ValueError)):
            self.append()
        self.assertEqual(list(self.csv.iterdir()), [])

    def test_append_absent_empty_and_existing_history_keep_exact_prefix(self):
        for original in (None, b"", b"legacy\r\nrow\r\n", b"header\nno-final-newline"):
            with self.subTest(original=original):
                self.csv.unlink(missing_ok=True)
                if original is not None:
                    self.csv.write_bytes(original)
                self.append()
                expected = self.native(HEADER + ROW) if original is None else original + self.native(ROW)
                self.assertEqual(self.csv.read_bytes(), expected)
                self.assertFalse(self.archive.exists())

    def test_changed_append_preimage_is_refused_and_foreign_bytes_preserved(self):
        self.csv.write_bytes(b"header\noriginal\n")
        foreign = b"header\nconcurrent update\n"
        original_publish = QUALITY.publish_trace

        def changed(path, *args, **kwargs):
            path.write_bytes(foreign)
            return original_publish(path, *args, **kwargs)

        with patch.object(QUALITY, "publish_trace", side_effect=changed):
            with self.assertRaises((OSError, ValueError)):
                self.append()
        self.assertEqual(self.csv.read_bytes(), foreign)
        self.assertEqual(list(self.inventory.glob(".naos-*.tmp")), [])

    def test_late_append_leaf_alias_is_preserved_and_victim_unchanged(self):
        self.csv.write_bytes(b"header\none\n")
        original_publish = QUALITY.publish_trace

        def exchanged(path, *args, **kwargs):
            path.unlink()
            self.link(path, self.victim)
            return original_publish(path, *args, **kwargs)

        with patch.object(QUALITY, "publish_trace", side_effect=exchanged):
            with self.assertRaises((OSError, ValueError)):
                self.append()
        self.assertTrue(self.csv.is_symlink())
        self.assertEqual(self.victim.read_bytes(), self.original)

    def test_rotation_noops_preserve_exact_bytes_inode_mtime_and_unused_archive(self):
        self.link(self.archive, self.victim, hard=True)
        for original in (None, b"", HEADER.encode(), self.history(2000, "\r\n").encode()):
            with self.subTest(original=original):
                self.csv.unlink(missing_ok=True)
                if original is not None:
                    self.csv.write_bytes(original)
                    before = self.csv.stat()
                self.assertEqual(self.rotate(), (False, ""))
                if original is None:
                    self.assertFalse(self.csv.exists())
                else:
                    self.assertEqual(self.csv.read_bytes(), original)
                    after = self.csv.stat()
                    self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))
                self.assertEqual(self.victim.read_bytes(), self.original)
        missing = self.base / "absent/parent/log.csv"
        self.assertEqual(self.rotate(missing), (False, ""))
        self.assertFalse(missing.parent.exists())

    def test_rotation_partition_newlines_unicode_and_archive_prefix_match_legacy(self):
        for separator in ("\r\n", "\r", "\u0085", "\u2028"):
            for prefix in (None, b"", b"ARCHIVE\r\nmissing-final-newline\xff"):
                with self.subTest(separator=repr(separator), prefix=prefix):
                    raw = self.history(2001, separator).encode("utf-8")
                    self.csv.write_bytes(raw)
                    self.archive.unlink(missing_ok=True)
                    if prefix is not None:
                        self.archive.write_bytes(prefix)
                    # Original read_text universal-newline semantics followed by
                    # text splitlines, then host write translation of new rows.
                    text = io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8", newline=None).read()
                    lines = text.splitlines(keepends=True)
                    rotated, message = self.rotate()
                    self.assertTrue(rotated)
                    self.assertEqual(self.csv.read_bytes(), self.native(lines[0] + "".join(lines[1002:])))
                    archived = self.native("".join(lines[1:1002]))
                    self.assertEqual(self.archive.read_bytes(), (self.native(lines[0]) if prefix is None else prefix) + archived)
                    self.assertIn("Archived 1001 rows", message)
                    self.assertIn("Log truncated to 1000 rows.", message)

    @unittest.skipUnless(os.name == "posix", "POSIX read-only no-op authority")
    def test_readonly_under_cap_history_needs_no_directory_write_permission(self):
        if os.geteuid() == 0:
            self.skipTest("Root bypasses ordinary permissions")
        original = b"header\r\none\r\n"
        self.csv.write_bytes(original)
        self.csv.chmod(0o400)
        self.inventory.chmod(0o500)
        try:
            self.assertEqual(self.rotate(), (False, ""))
            self.assertEqual(self.csv.read_bytes(), original)
        finally:
            self.inventory.chmod(0o700)
            self.csv.chmod(0o600)

    def test_readonly_under_cap_file_remains_a_noop(self):
        original = b"header\r\none\r\n"
        self.csv.write_bytes(original)
        self.csv.chmod(0o400)
        try:
            self.assertEqual(self.rotate(), (False, ""))
            self.assertEqual(self.csv.read_bytes(), original)
            self.assertFalse(self.archive.exists())
        finally:
            self.csv.chmod(0o600)

    @unittest.skipUnless(os.name == "posix", "POSIX search-only directory authority")
    def test_search_only_parent_preserves_readable_under_cap_noop(self):
        if os.geteuid() == 0:
            self.skipTest("Root bypasses ordinary directory permissions")
        original = b"header\nrow\n"
        self.csv.write_bytes(original)
        before = self.csv.stat()
        self.inventory.chmod(0o100)
        try:
            self.assertTrue(self.csv.exists())
            self.assertEqual(self.csv.read_bytes(), original)
            self.assertEqual(self.rotate(), (False, ""))
            self.assertEqual(self.csv.read_bytes(), original)
            after = self.csv.stat()
            self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))
        finally:
            self.inventory.chmod(0o700)

    @unittest.skipUnless(os.name == "posix", "POSIX stage failure injection")
    def test_failed_append_publication_keeps_history_and_mode(self):
        original = b"header\r\none\r\n"
        self.csv.write_bytes(original)
        self.csv.chmod(0o640)
        with patch("os.fsync", side_effect=OSError("synthetic stage refusal")):
            with self.assertRaises(OSError):
                self.append()
        self.assertEqual(self.csv.read_bytes(), original)
        self.assertEqual(stat.S_IMODE(self.csv.stat().st_mode), 0o640)
        self.assertEqual(len(list(self.inventory.glob(".naos-trace-*.tmp"))), 1)

    def test_large_archive_is_processed_in_chunks(self):
        self.csv.write_bytes(self.history(2001).encode())
        block = b"synthetic archive\r\n" * 32768
        with self.archive.open("wb") as stream:
            for _ in range(24):
                stream.write(block)
        before = self.archive.stat().st_size
        tracemalloc.start()
        try:
            rotated, _ = self.rotate()
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertTrue(rotated)
        self.assertGreater(self.archive.stat().st_size, before)
        self.assertLess(peak, 6 * 1024 * 1024, f"whole archive buffered: peak={peak}")
        with self.archive.open("rb") as stream:
            for _ in range(24):
                self.assertEqual(stream.read(len(block)), block)

    def test_copied_cli_rotation_uses_same_boundary_and_positive_partition(self):
        shutil.copytree(KIT / "scripts", self.project / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        metadata = self.project / "scripts/naos_posix_metadata"
        if not metadata.is_dir():
            metadata.mkdir()
            for name in ("security.py", "linux_primitives.py"):
                shutil.copy2(KIT / "upgrade_contract" / name, metadata / name)
        handles = self.project / "scripts/naos_windows_handles.py"
        if not handles.exists():
            shutil.copy2(KIT / "upgrade_contract/windows_handles.py", handles)
        code = (
            "import datetime,sys\n"
            f"sys.path.insert(0,{str(self.project / 'scripts')!r})\n"
            "import naos_code_quality_audit as audit\n"
            "class Clock(datetime.datetime):\n"
            " @classmethod\n"
            " def now(cls,tz=None): return cls(2026,10,20,12,0,tzinfo=datetime.timezone.utc)\n"
            "datetime.datetime=Clock\n"
            "sys.argv=['audit','--rotate-warnings-log']\naudit.main()\n"
        )
        env = {**os.environ, "NAOS_ROOT": "naos", "PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1"}
        env.pop("PYTHONPATH", None)
        original = self.history(2001).encode()
        self.csv.write_bytes(original)
        self.link(self.archive, self.victim, hard=True)
        result = subprocess.run([sys.executable, "-B", "-c", code], cwd=self.project, env=env,
                                capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.csv.read_bytes(), original)
        self.assertEqual(self.victim.read_bytes(), self.original)
        self.archive.unlink()
        result = subprocess.run([sys.executable, "-B", "-c", code], cwd=self.project, env=env,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.csv.read_text(encoding="utf-8").splitlines()), 1001)
        self.assertEqual(len(self.archive.read_text(encoding="utf-8").splitlines()), 1002)


class HistoryPublicationContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-history-publication-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def producer(self, value=b"new"):
        from naos_trace_atomic_write import BinaryProducer
        return BinaryProducer(lambda stream: stream.write(value),
                              lambda stream: self.assertEqual(stream.read(), value))

    def test_binary_create_only_publishes_once_and_refuses_occupant(self):
        from naos_trace_atomic_write import publish_trace
        target = self.root / "created/file"
        publish_trace(target, self.producer(), None, strict_parent_topology=True, create_only=True)
        with self.assertRaises((OSError, ValueError)):
            publish_trace(target, self.producer(b"foreign"), None,
                          strict_parent_topology=True, create_only=True)
        self.assertEqual(target.read_bytes(), b"new")

    def test_binary_digest_preimage_matches_and_refuses_stale_or_missing(self):
        from naos_trace_atomic_write import publish_trace
        target = self.root / "file"
        target.write_bytes(b"old")
        digest = hashlib.sha256(b"old").hexdigest()
        publish_trace(target, self.producer(), None, strict_parent_topology=True,
                      observe_current=True, expected_preimage_sha256=digest)
        with self.assertRaises((OSError, ValueError)):
            publish_trace(target, self.producer(b"lost update"), None, strict_parent_topology=True,
                          observe_current=True, expected_preimage_sha256=digest)
        self.assertEqual(target.read_bytes(), b"new")
        missing = self.root / "absent/parent/file"
        with self.assertRaises((OSError, ValueError)):
            publish_trace(missing, self.producer(), None, strict_parent_topology=True,
                          observe_current=True, expected_preimage_sha256=digest)
        self.assertFalse(missing.parent.exists())

    def test_missing_read_context_preserves_body_exception_and_creates_nothing(self):
        from naos_trace_atomic_write import read_trace_source
        target = self.root / "absent/parent/file"
        with self.assertRaisesRegex(FileNotFoundError, "synthetic body failure"):
            with read_trace_source(target) as source:
                self.assertIsNone(source)
                raise FileNotFoundError("synthetic body failure")
        self.assertFalse(target.parent.exists())

    def test_reader_refuses_changed_source_before_result_is_consumed(self):
        from naos_trace_atomic_write import read_trace_source
        target = self.root / "file"
        target.write_bytes(b"old")
        with self.assertRaises(ValueError):
            with read_trace_source(target) as source:
                self.assertEqual(source.read(), b"old")
                target.write_bytes(b"changed")

    @unittest.skipUnless(os.name == "posix", "POSIX FIFO refusal")
    def test_reader_refuses_fifo_without_waiting_for_a_writer(self):
        from naos_trace_atomic_write import read_trace_source
        target = self.root / "fifo"
        os.mkfifo(target)
        with self.assertRaises((OSError, ValueError)):
            with read_trace_source(target):
                self.fail("FIFO admitted")


if __name__ == "__main__":
    unittest.main()
