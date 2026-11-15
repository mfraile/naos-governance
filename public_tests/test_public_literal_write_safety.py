"""G1: public-vocabulary generation must not follow output aliases."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


KIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KIT / "scripts"))
import generate_naos_secret_public_literals as generator  # noqa: E402


class PublicLiteralWriteSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-vocabulary-write-ü-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.output = self.root / "output"
        (self.output / "scripts").mkdir(parents=True)
        (self.output / "schemas/naos").mkdir(parents=True)
        self.schema = self.output / "schemas/naos/demo.schema.json"
        self.schema.write_bytes(b'{"title":"demo"}\n')
        self.helper = self.output / "scripts/naos_secret_public_literals.py"
        self.target = self.output / "scripts/naos_secret_public_literals.json"
        self.initial = '_REFERENCE_SCHEMAS = {"demo": "stale"}\nCATALOG_SHA256 = "stale"\n'
        self.helper.write_text(self.initial, encoding="utf-8")
        self.target.write_bytes(b"old catalogue\n")
        self.catalog = {"schema": generator.SCHEMA, "groups": []}

    def invoke(self, *, check=False, build=None):
        argv = ["generate", "--source-root", str(self.output), "--output-root", str(self.output)]
        if check:
            argv.append("--check")
        with patch.object(sys, "argv", argv), patch.object(generator, "build", build or (lambda *_: self.catalog)), contextlib.redirect_stdout(io.StringIO()) as output:
            generator.main()
        return json.loads(output.getvalue())

    def alias(self, path, kind):
        victim = self.root / (path.name + ".victim")
        victim.write_bytes(path.read_bytes())
        path.unlink()
        try:
            if kind == "symlink":
                path.symlink_to(victim)
            else:
                os.link(victim, path)
        except OSError as exc:
            self.skipTest(f"{kind} unavailable: {exc}")
        return victim, victim.read_bytes()

    def assert_leaf_refused(self, path, kind):
        victim, before = self.alias(path, kind)
        with self.assertRaises((OSError, ValueError)):
            self.invoke()
        self.assertEqual(victim.read_bytes(), before)

    def test_main_refuses_helper_symlink(self):
        self.assert_leaf_refused(self.helper, "symlink")

    def test_main_refuses_helper_hardlink(self):
        self.assert_leaf_refused(self.helper, "hardlink")

    def test_main_refuses_catalogue_symlink(self):
        self.assert_leaf_refused(self.target, "symlink")

    def test_main_refuses_catalogue_hardlink(self):
        self.assert_leaf_refused(self.target, "hardlink")

    def test_main_refuses_output_parent_alias(self):
        real = self.output / "scripts-real"
        self.helper.parent.rename(real)
        try:
            self.helper.parent.symlink_to(real, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"directory symlink unavailable: {exc}")
        before = (real / self.helper.name).read_bytes()
        with self.assertRaises((OSError, ValueError)):
            self.invoke()
        self.assertEqual((real / self.helper.name).read_bytes(), before)
        self.assertEqual((real / self.target.name).read_bytes(), b"old catalogue\n")

    def test_real_cli_refuses_helper_alias_before_catalogue_build(self):
        # Real main/build invocation: even a later catalogue validation failure
        # must not disguise the first unsafe pin write.
        self.helper.write_text('_REFERENCE_SCHEMAS = {"self_check": "stale"}\nCATALOG_SHA256 = "stale"\n', encoding="utf-8")
        victim, before = self.alias(self.helper, "symlink")
        result = subprocess.run([sys.executable, "-B", str(KIT / "scripts/generate_naos_secret_public_literals.py"), "--source-root", str(KIT), "--output-root", str(self.output)], capture_output=True, text=True, timeout=30)
        self.assertEqual(victim.read_bytes(), before, result.stderr)
        self.assertNotEqual(result.returncode, 0)

    def test_real_cli_normal_generation_succeeds(self):
        self.helper.write_text('_REFERENCE_SCHEMAS = {"self_check": "stale"}\nCATALOG_SHA256 = "stale"\n', encoding="utf-8")
        result = subprocess.run([sys.executable, "-B", str(KIT / "scripts/generate_naos_secret_public_literals.py"), "--source-root", str(KIT), "--output-root", str(self.output)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        raw = self.target.read_bytes()
        self.assertEqual(summary["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(summary["bytes"], len(raw))
        self.assertGreater(summary["groups"], 0)
        self.assertIn(summary["sha256"], self.helper.read_text(encoding="utf-8"))

    def test_final_helper_publication_refuses_alias_introduced_by_build(self):
        observed = {}

        def build(*_):
            victim, before = self.alias(self.helper, "symlink")
            observed.update(victim=victim, before=before)
            return self.catalog

        with self.assertRaises((OSError, ValueError)):
            self.invoke(build=build)
        self.assertEqual(observed["victim"].read_bytes(), observed["before"])

    def test_normal_generation_preserves_pin_order_and_exact_serialization(self):
        def build(source, overlay):
            self.assertEqual(source, self.output)
            self.assertIsNone(overlay)
            self.assertIn(hashlib.sha256(self.schema.read_bytes()).hexdigest(), self.helper.read_text(encoding="utf-8"))
            return self.catalog

        self.helper.chmod(0o640)
        self.target.chmod(0o600)
        helper_mode = self.helper.stat().st_mode
        target_mode = self.target.stat().st_mode
        result = self.invoke(build=build)
        raw = (json.dumps(self.catalog, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
        self.assertEqual(self.target.read_bytes(), raw)
        self.assertIn(hashlib.sha256(raw).hexdigest(), self.helper.read_text(encoding="utf-8"))
        self.assertEqual(result, {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "groups": 0, "entries": 0, "check": False})
        self.assertEqual(self.helper.stat().st_mode, helper_mode)
        self.assertEqual(self.target.stat().st_mode, target_mode)

    def test_absent_catalogue_is_created_with_the_same_payload(self):
        self.target.unlink()
        self.invoke()
        self.assertEqual(self.target.read_bytes(), b'{"schema":"naos.secret_public_literals.v1","groups":[]}\n')

    def test_constructor_consumer_requires_its_schema_declaration(self):
        text = self.initial + '\ndef selected_public_constructor_context():\n    pass\n'
        self.helper.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "missing exact constructor reference schema declaration"):
            self.invoke()
        self.assertEqual(self.helper.read_text(encoding="utf-8"), text)
        self.assertEqual(self.target.read_bytes(), b"old catalogue\n")

    def test_check_mode_does_not_publish_or_touch_inodes(self):
        self.invoke()
        before = [(p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns) for p in (self.helper, self.target)]
        result = self.invoke(check=True)
        self.assertTrue(result["check"])
        self.assertEqual(before, [(p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns) for p in (self.helper, self.target)])

    def test_build_failure_retains_existing_pin_only_progress(self):
        with self.assertRaisesRegex(ValueError, "deliberate build failure"):
            self.invoke(build=lambda *_: (_ for _ in ()).throw(ValueError("deliberate build failure")))
        self.assertIn(hashlib.sha256(self.schema.read_bytes()).hexdigest(), self.helper.read_text(encoding="utf-8"))
        self.assertIn('CATALOG_SHA256 = "stale"', self.helper.read_text(encoding="utf-8"))
        self.assertEqual(self.target.read_bytes(), b"old catalogue\n")


if __name__ == "__main__":
    unittest.main()
