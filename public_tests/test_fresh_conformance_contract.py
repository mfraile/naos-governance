"""G3: the shipped battery requires the agent index actually scaffolded."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import naos_init  # noqa: E402 - kit bootstrap

INDEX = ".github/NAOS_AGENTS.md"
LEGACY = ".github/agents/AGENTS.md"


class FreshConformanceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="naos conformance ü ")
        cls.addClassCleanup(temporary.cleanup)
        cls.base = Path(temporary.name).resolve()
        cls.project = cls.base / "project"
        cls.project.mkdir()
        host = cls.base / "empty-host"
        host.mkdir()
        naos_init.scaffold_files(host, "standard", "custom", "static_only", cls.project,
                                 signals=naos_init._empty_signals(), memory_choice="disabled",
                                 emit_progress=False)
        cls.env = {k: v for k, v in os.environ.items()
                   if not k.startswith("NAOS_") and k not in ("PYTHONPATH", "SRC_ROOT")}
        cls.env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")

    def invoke(self):
        if os.name == "posix" and shutil.which("make"):
            command = ["make", "-f", "Makefile.naos", "naos-conformance", "PYTHON=" + sys.executable]
        else:
            command = [sys.executable, "-B", ".github/autoresearch/runner.py", "--conformance",
                       "--output", "naos/reports/conformance_latest.json"]
        result = subprocess.run(command, cwd=self.project, env=self.env, text=True,
                                encoding="utf-8", capture_output=True, timeout=90)
        report = json.loads((self.project / "naos/reports/conformance_latest.json").read_text(encoding="utf-8"))
        return result, report

    def test_fresh_standard_passes_the_actual_conformance_entrypoint(self):
        self.assertTrue((self.project / INDEX).is_file())
        self.assertFalse((self.project / LEGACY).exists())
        result, report = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(report["overall_conformance"], 1.0)
        self.assertGreater(report["battery_checks"]["total"], 0)
        self.assertEqual(report["battery_checks"]["passed"], report["battery_checks"]["total"])

    def test_missing_required_index_still_fails(self):
        path = self.project / INDEX
        raw = path.read_bytes()
        try:
            path.unlink()
            result, report = self.invoke()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing: " + INDEX, result.stdout)
            self.assertLess(report["battery_checks"]["passed"], report["battery_checks"]["total"])
        finally:
            path.write_bytes(raw)

    def test_legacy_location_does_not_replace_the_required_index(self):
        path = self.project / INDEX
        legacy = self.project / LEGACY
        raw = path.read_bytes()
        try:
            path.unlink()
            legacy.write_bytes(raw)
            result, report = self.invoke()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing: " + INDEX, result.stdout)
            self.assertLess(report["battery_checks"]["passed"], report["battery_checks"]["total"])
        finally:
            legacy.unlink()
            path.write_bytes(raw)


if __name__ == "__main__":
    unittest.main()
