"""G1: deterministic function-index publication refuses output aliases."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(KIT / "scripts"))
SPEC = importlib.util.spec_from_file_location("_g1_index_quality", KIT / "scripts/naos_code_quality_audit.py")
QUALITY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = QUALITY
SPEC.loader.exec_module(QUALITY)

# Bytes observed before hardening, for the source fixture below (host newline
# translation is part of the original Path.write_text contract).
LEGACY_INDEX = """# FUNCTION_INDEX.yaml — Codebase cognitive map
# Auto-generated via: python scripts/naos_code_quality_audit.py --generate-index
#
# PURPOSE: Static Python public declarations in selected roots: src.
# Initializer files contribute import references but are not declaration leaves.
# Import coverage (not runtime availability): {"execution": "static_references_only", "language": "Python", "parse_failures": 0, "sample_limit": 25, "samples_truncated": false, "unresolved_count": 0, "unresolved_samples": []}
# Importer lists are capped at five plus an omitted-count marker.
# Serves as 'external hippocampus' — persistent memory across AI sessions.
# Read this BEFORE creating new functions to avoid duplication.

service:
  public:
  - 'public_action()  # Source fixture.'
  source_path: src/service.py
"""


class FunctionIndexWriteSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-index-output-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "project"
        (self.root / "src").mkdir(parents=True)
        (self.root / "src/service.py").write_text(
            'def public_action():\n    """Source fixture."""\n    return 1\n', encoding="utf-8")
        self.output = self.root / "naos/inventory/FUNCTION_INDEX.yaml"
        self.output.parent.mkdir(parents=True)
        self.victim = self.base / "outside.txt"
        self.original = b"SYNTHETIC OUTSIDE\r\n"
        self.victim.write_bytes(self.original)
        self.addCleanup(patch.stopall)
        patch.multiple(QUALITY, PROJECT_ROOT=self.root, SRC_DIR=self.root / "src", SRC_ROOT_VAL="src",
                       INDEX_OUTPUT=self.output, ALLOWLIST_PATH=self.root / "absent.yaml").start()
        patch.dict(os.environ, {"SRC_ROOT": "src"}).start()

    def generate(self, output=None):
        with contextlib.redirect_stdout(io.StringIO()) as messages:
            index = QUALITY.generate_function_index(output)
        return index, messages.getvalue()

    def symlink(self, path, target, *, directory=False):
        try:
            path.symlink_to(target, target_is_directory=directory)
        except OSError as exc:
            if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                self.skipTest("Native Windows symlink privilege unavailable")
            raise

    def directory_alias(self, path, target):
        if os.name == "nt":
            result = subprocess.run([os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", "mklink", "/J",
                                     str(path), str(target)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.symlink(path, target, directory=True)

    def assert_refused(self, output=None):
        with self.assertRaises((OSError, ValueError)):
            self.generate(output)
        self.assertEqual(self.victim.read_bytes(), self.original)

    def test_leaf_symlink_refused_before_referent_changes(self):
        self.symlink(self.output, self.victim)
        self.assert_refused()

    def test_hardlink_refused_before_referent_changes(self):
        os.link(self.victim, self.output)
        self.assert_refused()

    def test_dangling_symlink_does_not_create_referent(self):
        missing = self.base / "absent-outside"
        self.symlink(self.output, missing)
        self.assert_refused()
        self.assertFalse(missing.exists())

    def test_parent_alias_does_not_receive_new_children(self):
        outside = self.base / "outside-dir"
        outside.mkdir()
        alias = self.root / "alias"
        self.directory_alias(alias, outside)
        self.assert_refused(alias / "new/nested/index.yaml")
        self.assertEqual(list(outside.iterdir()), [])

    @unittest.skipUnless(os.name == "posix", "POSIX canceled-parent semantics")
    def test_canceled_parent_alias_does_not_bypass_topology_check(self):
        outside = self.base / "outside-dir"
        (outside / "child").mkdir(parents=True)
        alias = self.root / "alias"
        self.symlink(alias, outside / "child", directory=True)
        self.assert_refused(alias / ".." / "index.yaml")
        self.assertFalse((outside / "index.yaml").exists())
        self.assertFalse((self.root / "index.yaml").exists())

    def test_directory_leaf_is_preserved(self):
        self.output.mkdir()
        marker = self.output / "keep"
        marker.write_bytes(self.original)
        self.assert_refused()
        self.assertEqual(marker.read_bytes(), self.original)

    def test_ordinary_custom_output_bytes_messages_and_mode_remain(self):
        output = self.base / "custom/created/index.yaml"
        expected = LEGACY_INDEX.replace("\n", os.linesep).encode("utf-8")
        index, messages = self.generate(output)
        self.assertEqual(output.read_bytes(), expected)
        self.assertEqual(index, yaml.safe_load(LEGACY_INDEX))
        self.assertIn(f"Function Index generated: {output}", messages)
        self.assertIn("Modules indexed: 1", messages)
        self.assertIn("Approximate size:", messages)
        output.chmod(0o640)
        self.generate(output)
        self.assertEqual(output.read_bytes(), expected)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o640)

    @unittest.skipUnless(os.name == "posix", "POSIX publication failure injection")
    def test_failed_publication_preserves_previous_bytes_and_retains_stage(self):
        self.output.write_bytes(self.original)
        # Fail after stage creation without replacing a capability-checked
        # dir_fd function (whose identity participates in platform support).
        with patch("os.fsync", side_effect=OSError("synthetic staging refusal")):
            with self.assertRaises(OSError) as raised:
                self.generate()
        self.assertEqual(self.output.read_bytes(), self.original)
        retained = list(self.output.parent.glob(".naos-trace-*.tmp"))
        self.assertEqual(len(retained), 1)
        self.assertTrue(any(str(retained[0]) in note for note in raised.exception.__notes__))

    @unittest.skipUnless(os.name == "posix", "POSIX file permission semantics")
    def test_unreadable_existing_output_is_refused_unchanged(self):
        if os.geteuid() == 0:
            self.skipTest("Root bypasses ordinary read permission checks")
        self.output.write_bytes(self.original)
        self.output.chmod(0o200)
        try:
            with self.assertRaises((OSError, ValueError)):
                self.generate()
            self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o200)
        finally:
            self.output.chmod(0o600)
        self.assertEqual(self.output.read_bytes(), self.original)

    def test_copied_cli_default_and_make_target_use_hardened_writer(self):
        shutil.copytree(KIT / "scripts", self.root / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        metadata = self.root / "scripts/naos_posix_metadata"
        if not metadata.is_dir():
            metadata.mkdir()
            for name in ("security.py", "linux_primitives.py"):
                shutil.copy2(KIT / "upgrade_contract" / name, metadata / name)
        handles = self.root / "scripts/naos_windows_handles.py"
        if not handles.exists():
            shutil.copy2(KIT / "upgrade_contract/windows_handles.py", handles)
        env = {**os.environ, "NAOS_ROOT": "naos", "PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1"}
        env.pop("PYTHONPATH", None)
        command = [sys.executable, "-B", "scripts/naos_code_quality_audit.py", "--generate-index"]
        success = subprocess.run(command, cwd=self.root, env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(success.returncode, 0, success.stdout + success.stderr)
        self.assertEqual(self.output.read_bytes(), LEGACY_INDEX.replace("\n", os.linesep).encode("utf-8"))
        self.output.unlink()
        make = shutil.which("make")
        if make:
            shutil.copy2(KIT / "templates/Makefile.naos", self.root / "Makefile")
        for hard in (True, False):
            with self.subTest(hardlink=hard):
                if hard:
                    os.link(self.victim, self.output)
                else:
                    self.symlink(self.output, self.victim)
                selected = self.output.lstat()
                try:
                    refused = subprocess.run(command, cwd=self.root, env=env, capture_output=True, text=True, timeout=30)
                    self.assertNotEqual(refused.returncode, 0, refused.stdout + refused.stderr)
                    self.assertEqual(self.victim.read_bytes(), self.original)
                    if make:
                        result = subprocess.run([make, "function-index", f"PYTHON={sys.executable}"], cwd=self.root,
                                                env=env, capture_output=True, text=True, timeout=30)
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertEqual(self.victim.read_bytes(), self.original)
                        self.assertIn(str(self.output), result.stderr)
                finally:
                    observed = self.output.lstat()
                    self.assertEqual((observed.st_dev, observed.st_ino), (selected.st_dev, selected.st_ino))
                    self.output.unlink()


if __name__ == "__main__":
    unittest.main()
