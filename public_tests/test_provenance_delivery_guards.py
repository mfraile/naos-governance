"""Exercise the shipped A14 byte limits; these fixtures do not sign artifacts."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

import yaml

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
MIB = 1024 * 1024


class ProvenanceDeliveryGuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="naos-provenance-guard-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.runner = self.root / "runner"
        self.runner.mkdir()
        workflow = yaml.safe_load(
            (KIT / ".github/workflows/release-provenance.yml").read_text(encoding="utf-8")
        )
        self.steps = workflow["jobs"]["provenance"]["steps"]

    def package(self, name, size):
        path = self.dist / name
        with path.open("xb") as output:
            output.truncate(size)
        return path

    def run_fragment(self, step_name):
        step = next(item for item in self.steps if item["name"] == step_name)
        snippets = list(re.finditer(
            r"(?ms)^python - <<'(?P<tag>[A-Z_]+)'\n(?P<code>.*?)^(?P=tag)\s*$",
            step["run"],
        ))
        self.assertEqual(len(snippets), 1)
        environment = dict(os.environ, RUNNER_TEMP=str(self.runner), PYTHONDONTWRITEBYTECODE="1")
        environment.pop("PYTHONPATH", None)
        return subprocess.run(
            [sys.executable, "-I", "-B", "-c", snippets[0].group("code")],
            cwd=self.root, env=environment, capture_output=True, text=True, timeout=10,
        )

    def retained_files(self, total):
        self.package("naos.whl", total - 3)
        for name in ["naos.tar.gz", "provenance.sigstore.json", "SHA256SUMS"]:
            self.package(name, 1)

    def test_built_packages_at_48_mib_produce_both_checksums(self):
        self.package("naos.whl", 48 * MIB - 1)
        self.package("naos.tar.gz", 1)
        result = self.run_fragment("Build exactly one wheel and source archive")
        self.assertEqual(result.returncode, 0, result.stderr)
        checksums = (self.runner / "naos-release-SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(checksums), 2)
        self.assertEqual({line.split("  ", 1)[1] for line in checksums}, {"naos.whl", "naos.tar.gz"})

    def test_built_packages_above_48_mib_refuse_before_checksum_publication(self):
        self.package("naos.whl", 48 * MIB)
        self.package("naos.tar.gz", 1)
        result = self.run_fragment("Build exactly one wheel and source archive")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exceed the 48 MiB", result.stderr)
        self.assertFalse((self.runner / "naos-release-SHA256SUMS").exists())
        self.assertEqual((self.dist / "naos.whl").stat().st_size, 48 * MIB)

    def test_extra_built_output_remains_refused(self):
        self.package("naos.whl", 1)
        self.package("naos.tar.gz", 1)
        self.package("unexpected.txt", 1)
        result = self.run_fragment("Build exactly one wheel and source archive")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Expected exactly two built artifacts", result.stderr)

    def test_retained_files_at_50_mib_are_accepted(self):
        self.retained_files(50 * MIB)
        result = self.run_fragment("Collect and recheck the same artifact bytes")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_retained_files_above_50_mib_are_refused(self):
        self.retained_files(50 * MIB + 1)
        result = self.run_fragment("Collect and recheck the same artifact bytes")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exceeds the 50 MiB", result.stderr)
        self.assertEqual(len(list(self.dist.iterdir())), 4)

    def test_nonregular_retained_entry_is_refused(self):
        self.package("naos.whl", 1)
        self.package("naos.tar.gz", 1)
        self.package("SHA256SUMS", 1)
        (self.dist / "provenance.sigstore.json").mkdir()
        result = self.run_fragment("Collect and recheck the same artifact bytes")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Expected two packages, checksums and the attestation bundle", result.stderr)

    def test_new_version_update_prs_are_paused_for_both_ecosystems(self):
        published = KIT / ".github/dependabot.yml"
        source = KIT / "configs/naos_public_dependabot.yml"
        config = yaml.safe_load((published if published.is_file() else source).read_text())
        self.assertEqual({item["package-ecosystem"] for item in config["updates"]}, {"pip", "github-actions"})
        self.assertTrue(all(item["open-pull-requests-limit"] == 0 for item in config["updates"]))


if __name__ == "__main__":
    unittest.main()
