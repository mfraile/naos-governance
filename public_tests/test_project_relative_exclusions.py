"""G8: checkout ancestor names must not change project-local checks."""
from __future__ import annotations

from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(KIT / "scripts"))


def load_module(name, relative):
    spec = importlib.util.spec_from_file_location(name, KIT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


COHERENCE = load_module("_g8_coherence", "scripts/validators/validate_project_coherence.py")
BUDGET = load_module("_g8_budget", "scripts/naos_ai_surface_budget.py")


@contextmanager
def working_directory(root):
    previous = Path.cwd()
    try:
        os.chdir(root)
        yield
    finally:
        os.chdir(previous)


class ProjectRelativeExclusionTests(unittest.TestCase):
    def test_ancestor_names_do_not_hide_syntax_but_local_exclusions_remain(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            for ancestor in ("ordinary", "build", "dist", "venv", ".venv", "node_modules"):
                with self.subTest(ancestor=ancestor):
                    root = base / ancestor / "proj"
                    root.mkdir(parents=True)
                    (root / "bad.py").write_text("def broken(:\n", encoding="utf-8")
                    for excluded in sorted(COHERENCE.EXCLUDE_DIRS):
                        location = root / excluded
                        location.mkdir()
                        (location / "hidden.py").write_text("def broken(:\n", encoding="utf-8")
                    with working_directory(root):
                        passed, issues = COHERENCE.check_python_syntax()
                    self.assertFalse(passed)
                    self.assertEqual(issues, ["bad.py: syntax error"])
                    (root / "bad.py").write_text("value = 1\n", encoding="utf-8")
                    with working_directory(root):
                        self.assertEqual(COHERENCE.check_python_syntax(), (True, []))

    def test_fresh_standard_results_are_equal_under_ordinary_and_excluded_ancestors(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            source = base / "preview"
            target = base / "unused-target"
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")
            created = subprocess.run(
                [sys.executable, "-B", str(KIT / "cli.py"), "init", str(target), "--new",
                 "--tier", "standard", "--archetype", "custom", "--backend", "disabled",
                 "--memory", "disabled", "--preview-dir", str(source)],
                cwd=KIT, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                text=True, encoding="utf-8", timeout=120)
            self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
            self.assertFalse(target.exists())
            # Same adopter error and nested excluded inputs in every copied scaffold.
            (source / "bad.py").write_text("def broken(:\n", encoding="utf-8")
            (source / "build").mkdir()
            (source / "build/hidden.py").write_text("def broken(:\n", encoding="utf-8")
            (source / "build/hidden.md").write_text("excluded\n", encoding="utf-8")
            expected = None
            for ancestor in ("ordinary", "build", "dist", "venv"):
                with self.subTest(ancestor=ancestor):
                    project = base / ancestor / "proj"
                    shutil.copytree(source, project)
                    policy = BUDGET.load_policy(None, None, project)
                    report = BUDGET.build_report(
                        root=project, profile="standard", naos_root="naos", policy=policy,
                        rules_path=BUDGET.default_rules_path(project, "naos", policy),
                        baseline_path=None)
                    report.pop("generated_at")
                    # Project identity differs; substantive report content must not.
                    normalized = json.loads(json.dumps(report).replace(
                        json.dumps(str(project))[1:-1], "<project>"))
                    inventory = BUDGET.generated_files(project)
                    self.assertIn("bad.py", inventory)
                    self.assertNotIn("build/hidden.py", inventory)
                    self.assertTrue(report["snapshot"]["total_files"])
                    self.assertIsNotNone(BUDGET.resolve_scenario_file(
                        project, "naos/TASK_REGISTRY.yaml")[0])
                    self.assertIsNone(BUDGET.resolve_scenario_file(project, "build/hidden.md")[0])
                    with working_directory(project):
                        syntax = COHERENCE.check_python_syntax()
                    self.assertEqual(syntax, (False, ["bad.py: syntax error"]))
                    observed = (normalized, inventory, syntax)
                    if expected is None:
                        expected = observed
                    else:
                        self.assertEqual(observed, expected)
