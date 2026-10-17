"""Exercise the acquisition code shipped in the generated workflow, offline."""

import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / "templates/workflows/naos-control-plane-ci.yml"


def acquisition_code():
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    step = next(item for item in workflow["jobs"]["naos-readiness"]["steps"]
                if item["name"] == "Install NAOS CLI")
    lines = step["run"].splitlines()
    if lines[0] != "python - <<'PY'" or lines[-1] != "PY":
        raise AssertionError("Acquisition must remain an inspectable Python step")
    return compile("\n".join(lines[1:-1]), str(WORKFLOW), "exec")


class AcquisitionContractTests(unittest.TestCase):
    def test_invalid_selection_never_starts_pip(self):
        valid = "https://artifacts.example/approved/naos.tar.gz"
        for url, digest in [
            ("", ""), (valid, ""), (valid, "f" * 63),
            ("http://artifacts.example/naos.tar.gz", "f" * 64),
            ("https://user:token@artifacts.example/naos.tar.gz", "f" * 64),
            ("https://@artifacts.example/naos.tar.gz", "f" * 64),
            ("https://artifacts.example:bad/naos.tar.gz", "f" * 64),
            ("https://artifacts.example:99999/naos.tar.gz", "f" * 64),
            (valid + "#sha256=other", "f" * 64),
            (valid + "?download=1", "f" * 64),
            ("https://[invalid/naos.tar.gz", "f" * 64),
            (valid + "\n", "f" * 64),
            ("https://artifacts.example/main", "f" * 64),
        ]:
            with self.subTest(url=url), patch.dict(os.environ, {
                "NAOS_ARTIFACT_URL": url, "NAOS_ARTIFACT_SHA256": digest,
            }), patch("subprocess.run") as run:
                with self.assertRaisesRegex(SystemExit, "NAOS acquisition error"):
                    exec(acquisition_code(), {})
                run.assert_not_called()

    def test_valid_selection_uses_exact_hash_and_propagates_pip_failure(self):
        url = "https://artifacts.example/approved/naos.tar.gz"
        with patch.dict(os.environ, {
            "NAOS_ARTIFACT_URL": url, "NAOS_ARTIFACT_SHA256": "A" * 64,
        }), patch("subprocess.run") as run:
            exec(acquisition_code(), {})
            run.assert_called_once_with(
                [sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
                 "--no-cache-dir", url + "#sha256=" + "a" * 64], check=True,
            )
            run.side_effect = subprocess.CalledProcessError(1, "pip")
            with self.assertRaises(subprocess.CalledProcessError):
                exec(acquisition_code(), {})

    def test_wrong_hash_is_rejected_before_source_build_code(self):
        with tempfile.TemporaryDirectory(prefix="naos acquisition ü ") as temp:
            root = Path(temp)
            sentinel = root / "BUILD_EXECUTED"
            archive = root / "naos_acquisition_probe-0.0.0.tar.gz"
            setup = ("from pathlib import Path\n"
                     f"Path({str(sentinel)!r}).write_text('unexpected')\n"
                     "from setuptools import setup\n"
                     "setup(name='naos-acquisition-probe', version='0.0.0')\n").encode()
            with tarfile.open(archive, "w:gz") as output:
                member = tarfile.TarInfo("naos_acquisition_probe-0.0.0/setup.py")
                member.size = len(setup)
                output.addfile(member, io.BytesIO(setup))
            actual = hashlib.sha256(archive.read_bytes()).hexdigest()
            wrong = ("0" if actual[0] != "0" else "1") + actual[1:]
            result = subprocess.run(
                [sys.executable, "-m", "pip", "--isolated", "install",
                 "--disable-pip-version-check", "--no-cache-dir", "--no-index",
                 "--no-deps", "--no-build-isolation",
                 archive.resolve().as_uri() + "#sha256=" + wrong],
                text=True, capture_output=True, cwd=root, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("DO NOT MATCH THE HASHES", result.stderr)
            self.assertFalse(sentinel.exists(), result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
