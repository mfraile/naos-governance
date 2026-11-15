"""G7: bounded post-write checks without changing hook cadence or isolation."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import site
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import venv

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
DISPATCH = KIT / "templates/integrations/claude-code/hooks/dispatch.py"
SPEC = importlib.util.spec_from_file_location("_claude_budget_dispatch", DISPATCH)
ADAPTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADAPTER)


class ClaudeHookBudgetTests(unittest.TestCase):
    def test_post_write_budget_is_configurable_and_other_events_keep_their_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {"CLAUDE_PROJECT_DIR": temporary, "NAOS_TASK_ID": "T-1"}
            for event in sorted(ADAPTER.EVENTS - {"stop"}):
                with self.subTest(event=event), patch.object(
                    ADAPTER.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)
                ) as run:
                    self.assertEqual(ADAPTER.main(
                        ["--event", event, "--post-write-timeout-seconds", "180"], environ=env), 0)
                    self.assertTrue(run.called)
                    expected = 180 if event == "post-tool-write" else 15
                    for call in run.call_args_list:
                        self.assertEqual(call.kwargs["timeout"], expected)
                        self.assertEqual(call.args[0][1:3], ["-I", "-B"])
                        self.assertNotIn("--post-write-timeout-seconds", call.args[0][5:])

    def test_invalid_post_write_budget_cannot_launch_or_block(self):
        for value in ("0", "-1", "601", "abc", "1.5", "nan"):
            with self.subTest(value=value), patch.object(ADAPTER.subprocess, "run") as run:
                self.assertEqual(ADAPTER.main(
                    ["--event", "post-tool-write", "--post-write-timeout-seconds", value], environ={}), 0)
                run.assert_not_called()

    def test_templates_align_inner_and_outer_post_write_timeouts(self):
        for name in ("settings.template.json", "settings.assured.template.json"):
            data = json.loads((DISPATCH.parent.parent / name).read_text(encoding="utf-8"))
            handler = data["hooks"]["PostToolUse"][0]["hooks"][0]
            arguments = handler["args"]
            inner = int(arguments[arguments.index("--post-write-timeout-seconds") + 1])
            self.assertEqual(inner, 120)
            self.assertEqual(handler["timeout"], inner + 5)
            self.assertEqual(data["hooks"]["SessionEnd"][0]["hooks"][0]["timeout"], 20)
            self.assertEqual(data["hooks"]["SessionStart"][0]["hooks"][0]["timeout"], 35)

    def test_fresh_standard_post_write_finishes_inside_its_budget(self):
        with tempfile.TemporaryDirectory(prefix="naos-post-write-budget-") as temporary:
            base = Path(temporary).resolve()
            project = base / "standard"
            target = base / "unused-target"
            env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
            created = subprocess.run(
                [sys.executable, "-B", str(KIT / "cli.py"), "init", str(target), "--new",
                 "--tier", "standard", "--archetype", "custom", "--backend", "disabled",
                 "--memory", "disabled", "--preview-dir", str(project)],
                cwd=KIT, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                text=True, encoding="utf-8", timeout=120)
            self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
            self.assertFalse(target.exists())
            # Register current source behind a disposable project-local installed
            # entry point. This is a source-runtime fixture, not a wheel-install claim.
            environment = project / ".venv"
            venv.EnvBuilder(with_pip=False).create(environment)
            python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            selected = subprocess.run(
                [str(python), "-I", "-B", "-c", "import sysconfig;print(sysconfig.get_path('purelib'))"],
                capture_output=True, text=True, check=True, timeout=30)
            library = Path(selected.stdout.strip())
            package = library / "naos_governance"
            package.mkdir()
            (package / "__init__.py").write_text(f"__path__.append({str(KIT)!r})\n", encoding="utf-8")
            (package / "__main__.py").write_bytes((KIT / "__main__.py").read_bytes())
            metadata = library / "naos_governance-1.1.0.dist-info"
            metadata.mkdir()
            (metadata / "METADATA").write_text(
                "Metadata-Version: 2.1\nName: naos-governance\nVersion: 1.1.0\n", encoding="utf-8")
            (library / "fixture-dependencies.pth").write_text(
                "\n".join(site.getsitepackages()) + "\n", encoding="utf-8")
            env.update(CLAUDE_PROJECT_DIR=str(project), NAOS_PROFILE="standard")
            env.pop("PYTHONPATH", None)
            env.pop("PYTHONHOME", None)
            report = project / "naos/reports/self_check.json"
            self.assertFalse(report.exists())
            start = time.monotonic()
            result = subprocess.run(
                [str(python), "-I", "-B", str(DISPATCH), "--event", "post-tool-write"],
                cwd=project, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                text=True, encoding="utf-8", timeout=125)
            elapsed = time.monotonic() - start
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("self-check ran;", result.stderr)
            self.assertIn("live inspection completed", result.stderr)
            self.assertNotIn("timed out", result.stderr)
            self.assertLess(elapsed, 120)
            self.assertFalse(report.exists(), "Default self-check must remain inspection-only")
