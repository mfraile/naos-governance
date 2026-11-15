"""G1 gate outputs: actual Make/CLI alias refusal and compatible regular writes."""

from __future__ import annotations

import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(KIT / "scripts"))


class GateWriteSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="naos-gate-writes-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.project = self.base / "adopter"
        self.project.mkdir()
        shutil.copytree(KIT / "scripts", self.project / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(KIT / "schemas", self.project / "schemas")
        metadata = self.project / "scripts/naos_posix_metadata"
        metadata.mkdir()
        for name in ("security.py", "linux_primitives.py"):
            shutil.copy2(KIT / "upgrade_contract" / name, metadata / name)
        shutil.copy2(KIT / "upgrade_contract/windows_handles.py", self.project / "scripts/naos_windows_handles.py")
        (self.project / "naos/reports").mkdir(parents=True)
        shutil.copy2(KIT / "templates/Makefile.naos", self.project / "Makefile.naos")
        shutil.copy2(KIT / "templates/structural-seeds/naos/gatekeepers.yaml", self.project / "naos/gatekeepers.yaml")
        self.victim = self.base / "outside.txt"
        self.original = b"SYNTHETIC OUTSIDE FILE\n"
        self.victim.write_bytes(self.original)
        self.env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        for name in ("NAOS_ROOT", "NAOS_POLICY", "NAOS_STRICT", "NAOS_PROFILE", "PYTHONPATH"):
            self.env.pop(name, None)

    def output(self, name):
        return self.project / "naos/reports" / name

    def link(self, path, *, hard=False):
        if hard:
            os.link(self.victim, path)
            return
        try:
            path.symlink_to(self.victim)
        except OSError:
            if os.name != "nt":
                raise
            # Windows may restrict symbolic links. Execute the native hardlink
            # refusal case there; POSIX jobs exercise actual leaf symlinks.
            os.link(self.victim, path)

    def cli(self, script, output, *extra):
        return subprocess.run(
            [sys.executable, "-B", str(self.project / "scripts" / script),
             "--profile", "standard", "--output", str(output), *extra],
            cwd=self.project, env=self.env, capture_output=True, text=True, check=False, timeout=30,
        )

    def make(self, target, filename):
        executable = shutil.which("make")
        if executable is None:
            # Same portable CLI invocation as the Make recipe on hosts without
            # GNU Make; it is an executed control, not native Make evidence.
            return self.cli(target.replace("-", "_") + ".py", self.output(filename))
        return subprocess.run(
            [executable, "-f", "Makefile.naos", target, "NAOS_PROFILE=standard", "PYTHON=" + sys.executable],
            cwd=self.project, env=self.env, capture_output=True, text=True, check=False, timeout=30,
        )

    def assert_refused(self, result):
        self.assertEqual(self.victim.read_bytes(), self.original, "outside victim changed")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_make_gate_status_refuses_leaf_link(self):
        self.link(self.output("gate_status.json"))
        self.assert_refused(self.make("naos-gate-status", "gate_status.json"))

    def test_make_gate_evaluate_refuses_leaf_link(self):
        self.link(self.output("gate_evaluation.json"))
        self.assert_refused(self.make("naos-gate-evaluate", "gate_evaluation.json"))

    def test_input_error_writer_refuses_leaf_link(self):
        for script in ("naos_gate_status.py", "naos_gate_evaluate.py"):
            with self.subTest(script=script):
                output = self.output(script + ".error.json")
                self.link(output)
                self.assert_refused(self.cli(script, output, "--manifest", "missing.yaml", "--json"))

    def test_success_writer_refuses_hard_link(self):
        for script in ("naos_gate_status.py", "naos_gate_evaluate.py"):
            with self.subTest(script=script):
                output = self.output(script + ".hard.json")
                self.link(output, hard=True)
                self.assert_refused(self.cli(script, output, "--json"))

    def test_input_error_refuses_unreadable_output_without_changes(self):
        if os.name != "posix":
            self.skipTest("POSIX write-only mode; Windows permissions use native ACLs")
        for script in ("naos_gate_status.py", "naos_gate_evaluate.py"):
            with self.subTest(script=script):
                output = self.output(script + ".write-only.json")
                output.write_bytes(self.original)
                output.chmod(0o200)
                self.addCleanup(output.chmod, 0o600)
                before = output.stat()
                result = self.cli(script, output, "--manifest", "missing.yaml", "--json")
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o200)
                if os.access(output, os.R_OK):
                    # Privileged processes can legitimately read this mode.
                    self.assertEqual(result.returncode, 2, result.stderr)
                    output.chmod(0o600)
                    self.assertEqual(json.loads(output.read_text()), json.loads(result.stdout))
                    continue
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("existing output must be readable and writable", result.stderr)
                self.assertEqual((output.stat().st_dev, output.stat().st_ino), (before.st_dev, before.st_ino))
                output.chmod(0o600)
                self.assertEqual(output.read_bytes(), self.original)
                self.assertEqual(list(output.parent.glob(".naos-trace-*.tmp")), [])

    def test_linked_output_parent_is_refused(self):
        outside = self.base / "outside-reports"
        outside.mkdir()
        alias = self.project / "linked-reports"
        if os.name == "nt":
            result = subprocess.run(
                [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", "mklink", "/J", str(alias), str(outside)],
                capture_output=True, text=True, check=False, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            alias.symlink_to(outside, target_is_directory=True)
        for script in ("naos_gate_status.py", "naos_gate_evaluate.py"):
            with self.subTest(script=script):
                result = self.cli(script, alias / (script + ".json"), "--json")
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertEqual(list(outside.iterdir()), [])

    def test_regular_output_preserves_json_order_and_mode(self):
        for script in ("naos_gate_status.py", "naos_gate_evaluate.py"):
            with self.subTest(script=script):
                output = self.output(script + ".json")
                output.write_text("{}\n", encoding="utf-8")
                output.chmod(0o640)
                result = self.cli(script, output, "--json")
                self.assertEqual(result.returncode, 0, result.stderr)
                expected = result.stdout.replace("\n", os.linesep).encode("utf-8")
                self.assertEqual(output.read_bytes(), expected)
                self.assertEqual(next(iter(json.loads(result.stdout))), "schema")
                if os.name == "posix":
                    self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o640)

    def test_readonly_output_is_not_replaced(self):
        for script in ("naos_gate_status.py", "naos_gate_evaluate.py"):
            with self.subTest(script=script):
                output = self.output(script + ".readonly.json")
                output.write_bytes(self.original)
                output.chmod(0o440)
                self.addCleanup(output.chmod, 0o600)
                writable = os.access(output, os.W_OK)
                result = self.cli(script, output, "--json")
                if writable:
                    # A privileged process can legitimately write this mode.
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(output.read_bytes(), self.original)

    def test_post_audit_rewrite_revalidates_leaf(self):
        previous = Path.cwd()
        self.addCleanup(os.chdir, previous)
        os.chdir(self.project)
        for script in ("naos_gate_status.py", "naos_gate_evaluate.py"):
            with self.subTest(script=script):
                specification = importlib.util.spec_from_file_location("gate_write_fixture_" + script, KIT / "scripts" / script)
                module = importlib.util.module_from_spec(specification)
                sys.modules[specification.name] = module
                self.addCleanup(sys.modules.pop, specification.name, None)
                specification.loader.exec_module(module)
                output = self.output(script + ".post-audit.json")
                def swap(**_):
                    output.unlink()
                    self.link(output)
                    return {"status": "not_configured", "findings": []}
                with patch.object(module, "write_audit_event", side_effect=swap), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises((OSError, ValueError, RuntimeError)):
                        module.main(["--profile", "standard", "--output", str(output), "--json"])
                self.assertEqual(self.victim.read_bytes(), self.original)


if __name__ == "__main__":
    unittest.main()
