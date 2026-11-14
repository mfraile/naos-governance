"""A4: actual child imports must use the selected interpreter's installation."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import venv


KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
DISPATCH = KIT / "templates/integrations/claude-code/hooks/dispatch.py"


class ClaudeHookIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="naos-hook-isolation-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.project = self.base / "adopter project"
        self.project.mkdir()
        environment = self.project / ".venv"
        venv.EnvBuilder(with_pip=False).create(environment)
        self.python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        paths = subprocess.run(
            [str(self.python), "-I", "-B", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
            capture_output=True, text=True, check=True, timeout=30,
        )
        self.library = Path(paths.stdout.strip())
        self.package = self.library / "naos_governance"
        self.package.mkdir()
        (self.package / "__init__.py").write_text("", encoding="utf-8")
        (self.package / "__main__.py").write_text(
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['NAOS_HOOK_TEST_OUTPUT']).write_text(\n"
            " json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd(),\n"
            " 'isolated': sys.flags.isolated}), encoding='utf-8')\n",
            encoding="utf-8",
        )
        self.metadata = self.library / "naos_governance-1.1.0.dist-info"
        self.metadata.mkdir()
        (self.metadata / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: naos-governance\nVersion: 1.1.0\n", encoding="utf-8",
        )
        self.witness = self.base / "installed.json"
        self.attacker = self.base / "planted.txt"
        self.env = {**os.environ, "CLAUDE_PROJECT_DIR": str(self.project),
                    "NAOS_HOOK_TEST_OUTPUT": str(self.witness), "NAOS_PROFILE": "standard"}
        self.env.pop("PYTHONPATH", None)
        self.env.pop("PYTHONHOME", None)

    def plant(self, root, *, module=False):
        payload = f"from pathlib import Path\nPath({str(self.attacker)!r}).write_text('executed')\n"
        if module:
            (root / "naos_governance.py").write_text(payload, encoding="utf-8")
        else:
            package = root / "naos_governance"
            package.mkdir()
            (package / "__init__.py").write_text(payload, encoding="utf-8")
            (package / "__main__.py").write_text(payload, encoding="utf-8")

    def dispatch(self, *, manual=False):
        env = dict(self.env)
        if manual:
            env.pop("CLAUDE_PROJECT_DIR")
        return subprocess.run(
            [str(self.python), "-I", "-B", str(DISPATCH), "--event", "pre-tool-edit"],
            cwd=self.project, env=env, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, check=False, timeout=30,
        )

    def assert_installed_only(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.attacker.exists(), "untrusted project code executed")
        self.assertTrue(self.witness.exists(), result.stderr)
        witness = json.loads(self.witness.read_text(encoding="utf-8"))
        self.assertEqual(witness["argv"], ["task-claims", "--action", "list", "--profile", "standard"])
        self.assertEqual(Path(witness["cwd"]).resolve(), self.project.resolve())
        self.assertEqual(witness["isolated"], 1)

    def test_project_package_cannot_replace_project_venv_installation(self):
        self.plant(self.project)
        self.assert_installed_only(self.dispatch())

    def test_project_module_cannot_replace_project_venv_installation(self):
        self.plant(self.project, module=True)
        self.assert_installed_only(self.dispatch())

    def test_pythonpath_is_ignored_with_manual_cwd_fallback(self):
        injected = self.base / "injected"
        injected.mkdir()
        self.plant(injected)
        self.env["PYTHONPATH"] = str(injected)
        self.assert_installed_only(self.dispatch(manual=True))

    def test_settings_launch_isolates_dispatcher_startup(self):
        hooks = self.project / "naos/integrations/claude-code/hooks"
        hooks.mkdir(parents=True)
        shutil.copy2(DISPATCH, hooks / "dispatch.py")
        injected = self.base / "startup injection"
        injected.mkdir()
        (injected / "sitecustomize.py").write_text(
            f"from pathlib import Path\nPath({str(self.attacker)!r}).write_text('startup')\n",
            encoding="utf-8",
        )
        self.env["PYTHONPATH"] = str(injected)
        for filename in ("settings.template.json", "settings.assured.template.json"):
            with self.subTest(filename=filename):
                template = json.loads((DISPATCH.parent.parent / filename).read_text(encoding="utf-8"))
                handler = template["hooks"]["PreToolUse"][0]["hooks"][0]
                arguments = [arg.replace("${CLAUDE_PROJECT_DIR}", str(self.project)) for arg in handler["args"]]
                result = subprocess.run(
                    [str(self.python), *arguments], cwd=self.project, env=self.env,
                    stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False, timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(self.attacker.exists(), "settings allowed project startup code")
                self.assertTrue(self.witness.exists(), result.stderr)
                self.witness.unlink()

    def test_manual_wrapper_python_launches_are_isolated(self):
        for wrapper in DISPATCH.parent.glob("*.sh"):
            launches = [line.strip() for line in wrapper.read_text(encoding="utf-8").splitlines()
                        if line.strip().startswith(("python ", "python3 "))]
            self.assertEqual(len(launches), 2, wrapper.name)
            for line in launches:
                self.assertIn(' -I -B "$SCRIPT_DIR/dispatch.py"', line, wrapper.name)

    def test_unregistered_package_is_an_advisory_refusal(self):
        (self.metadata / "METADATA").unlink()
        self.metadata.rmdir()
        result = self.dispatch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.witness.exists(), "unregistered package executed")
        self.assertIn("nonzero", result.stderr)

    def test_installed_search_path_cannot_redirect_to_adopter_package(self):
        shutil.rmtree(self.package)
        self.plant(self.project)
        (self.library / "synthetic-search-path.pth").write_text(str(self.project), encoding="utf-8")
        result = self.dispatch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.attacker.exists(), "origin check imported the planted package")
        self.assertIn("nonzero", result.stderr)

    def editable(self, source):
        source.mkdir()
        shutil.move(str(self.package), str(source / "naos_governance"))
        (self.library / "synthetic-editable.pth").write_text(str(source), encoding="utf-8")
        (self.metadata / "direct_url.json").write_text(
            json.dumps({"url": source.as_uri(), "dir_info": {"editable": True}}), encoding="utf-8",
        )

    def test_external_editable_installation_remains_usable(self):
        self.editable(self.base / "selected editable source")
        self.assert_installed_only(self.dispatch())

    def test_editable_source_inside_adopter_is_refused(self):
        self.editable(self.project / "editable source")
        result = self.dispatch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.witness.exists(), "adopter editable source executed")
        self.assertIn("nonzero", result.stderr)


if __name__ == "__main__":
    unittest.main()
