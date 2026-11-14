"""A14 external-dependency integrity declarations; no network or installation."""
from __future__ import annotations

import os
from pathlib import Path
import unittest

import yaml

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
LOCKS = ("requirements-runtime.txt", "requirements-build.txt", "requirements-ci.txt",
         "requirements-repository-intelligence.txt")


class DependencyLockTests(unittest.TestCase):
    def test_external_requirements_are_exact_pins_with_local_sha256_hashes(self):
        for name in LOCKS:
            with self.subTest(lock=name):
                text = (KIT / name).read_text(encoding="utf-8")
                statements = text.replace("\\\n", " ").splitlines()
                pins = []
                for line in statements:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("-r "):
                        self.assertIn(line[3:], LOCKS)
                        continue
                    self.assertRegex(line, r"^[A-Za-z0-9_.-]+==[0-9][A-Za-z0-9.!+-]*[ ;]")
                    self.assertRegex(line, r"--hash=sha256:[0-9a-f]{64}(?:\s|$)")
                    self.assertNotIn("http", line)
                    self.assertNotIn("--trusted-host", line)
                    pins.append(line)
                self.assertTrue(pins)

    def test_candidate_ci_uses_hash_checks_and_preinstalled_build_requirements(self):
        workflow = yaml.safe_load((KIT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        for job in workflow["jobs"].values():
            commands = "\n".join(step.get("run", "") for step in job["steps"])
            installs = [line for line in commands.splitlines() if "-m pip install" in line]
            self.assertTrue(installs)
            for line in installs:
                self.assertIn("--require-hashes", line)
            self.assertNotIn("pip install -e", commands)
            for line in commands.splitlines():
                if "-m build " in line:
                    self.assertIn("--no-isolation", line)
            self.assertTrue("requirements-ci.txt" in commands or "requirements-build.txt" in commands)

    def test_dependency_update_configuration_declares_bounded_weekly_proposals(self):
        config = yaml.safe_load((KIT / ".github/dependabot.yml").read_text(encoding="utf-8"))
        self.assertEqual(config["version"], 2)
        self.assertEqual({item["package-ecosystem"] for item in config["updates"]},
                         {"pip", "github-actions"})
        for item in config["updates"]:
            self.assertEqual(item["directory"], "/")
            self.assertEqual(item["schedule"]["interval"], "weekly")
            self.assertLessEqual(item["open-pull-requests-limit"], 5)


if __name__ == "__main__":
    unittest.main()
