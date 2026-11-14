"""A14 build-backend declaration contract; no network or installed-tool changes."""
from __future__ import annotations

import os
from pathlib import Path
import re
import tomllib
import unittest

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()


class BuildBackendPinTests(unittest.TestCase):
    def test_existing_backend_requirements_are_exact_versions(self):
        build = tomllib.loads((KIT / "pyproject.toml").read_text(encoding="utf-8"))["build-system"]
        self.assertEqual(build["build-backend"], "setuptools.build_meta")
        self.assertEqual(len(build["requires"]), 2)
        self.assertEqual({re.match(r"[A-Za-z0-9_-]+", item).group() for item in build["requires"]},
                         {"setuptools", "wheel"})
        for requirement in build["requires"]:
            with self.subTest(requirement=requirement):
                self.assertRegex(requirement, r"^(?:setuptools|wheel)==[0-9][A-Za-z0-9.!+-]*$")


if __name__ == "__main__":
    unittest.main()
