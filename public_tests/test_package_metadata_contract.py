"""K6 source version and explicit package-data contracts, without a builder."""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()


class PackageMetadataContractTests(unittest.TestCase):
    def test_build_version_is_derived_from_the_root_literal(self):
        metadata = tomllib.loads((KIT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertNotIn("version", metadata["project"])
        self.assertEqual(metadata["project"]["dynamic"], ["version"])
        self.assertEqual(metadata["tool"]["setuptools"]["dynamic"]["version"],
                         {"attr": "naos_governance.__version__"})
        tree = ast.parse((KIT / "__init__.py").read_text(encoding="utf-8"))
        assignments = [n for n in tree.body if isinstance(n, ast.Assign)]
        self.assertEqual(len(assignments), 1)
        assignment, = assignments
        self.assertEqual([n.id for n in assignment.targets], ["__version__"])
        self.assertEqual(ast.literal_eval(assignment.value), "1.1.0")

    def test_source_shim_uses_its_own_root_when_cwd_has_a_planted_module(self):
        with tempfile.TemporaryDirectory(prefix="naos-version-contract-") as temporary:
            base = Path(temporary)
            source, foreign = base / "source", base / "foreign"
            (source / "naos_governance").mkdir(parents=True)
            foreign.mkdir()
            shutil.copyfile(KIT / "naos_governance/__init__.py",
                            source / "naos_governance/__init__.py")
            (source / "__init__.py").write_text('__version__ = "9.8.7"\n', encoding="utf-8")
            sentinel = foreign / "executed"
            payload = f"from pathlib import Path; Path({str(sentinel)!r}).touch()\n"
            (foreign / "__init__.py").write_text(payload, encoding="utf-8")
            driver = (
                "import json,sys;sys.path.insert(0,sys.argv[1]);"
                "import naos_governance;"
                "print(json.dumps({'version':naos_governance.__version__,"
                "'path':naos_governance.__file__}))"
            )
            result = subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(source)],
                                    cwd=foreign, capture_output=True, text=True,
                                    check=False, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            observed = json.loads(result.stdout)
            self.assertEqual(observed["version"], "9.8.7")
            self.assertEqual(Path(observed["path"]).resolve(),
                             (source / "naos_governance/__init__.py").resolve())
            self.assertFalse(sentinel.exists())

    def test_explicit_package_data_is_the_only_data_list(self):
        metadata = tomllib.loads((KIT / "pyproject.toml").read_text(encoding="utf-8"))
        setuptools = metadata["tool"]["setuptools"]
        self.assertFalse(setuptools.get("include-package-data", True))
        self.assertEqual(setuptools["packages"],
                         ["naos_governance", "naos_governance.upgrade_contract"])
        self.assertTrue(setuptools["package-data"]["naos_governance"])
        self.assertIn("**/*.pyc", setuptools["exclude-package-data"]["naos_governance"])
        directives = [line for line in (KIT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
                      if line.strip() and not line.lstrip().startswith("#")]
        self.assertEqual(directives, [])
        self.assertEqual(metadata["project"]["license"], "Apache-2.0")
        self.assertFalse(any(value.startswith("License ::")
                             for value in metadata["project"]["classifiers"]))


if __name__ == "__main__":
    unittest.main()
