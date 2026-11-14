"""Staged hook headers use the canonical rules and the indexed source bytes."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/naos_staged_python.py"
VALIDATOR = ROOT / "scripts/naos_module_header_traceability.py"


def header(path="src/service.py", requirement="FR-001"):
    return f'''"""
Module: {path}

Purpose:
    Synthetic service.

Implements:
    - {requirement}: Synthetic requirement

Tasks:
    - T-001: Synthetic task

Specs:
    - specs/03-requirements.md#fr-001

Rationale:
    One synthetic source boundary.
"""
'''


@unittest.skipUnless(shutil.which("git"), "native Git required")
class StagedModuleHeadersTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos staged headers ü ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("GIT_", "NAOS_")) and k not in ("SRC_ROOT", "PYTHONPATH")}
        self.env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(ROOT / "scripts"),
                        PYTHONIOENCODING="utf-8",
                        NAOS_TIER="standard", NAOS_PYTHON=Path(sys.executable).as_posix(),
                        GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        self.git("init", "-q")
        self.write("specs/03-requirements.md", "## FR-001: Synthetic requirement\n")
        self.write("naos/TASK_REGISTRY.yaml", "tasks:\n  - id: T-001\n    status: Planned\n")

    def write(self, relative, source):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        return path

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, env=self.env,
                              check=True, capture_output=True).stdout

    def stage(self, relative, source):
        self.write(relative, source)
        self.git("add", "--", relative)

    def check(self):
        before = self.git("diff", "--cached", "--binary")
        result = subprocess.run([sys.executable, "-B", str(HELPER), "--headers"],
                                cwd=self.root, env=self.env, capture_output=True,
                                text=True, encoding="utf-8", timeout=30)
        self.assertEqual(self.git("diff", "--cached", "--binary"), before)
        self.assertFalse((self.root / "naos/reports/module_header_traceability.json").exists())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def test_multiline_header_agrees_with_canonical_validator(self):
        self.stage("src/service.py", header())
        canonical = subprocess.run([sys.executable, "-B", str(VALIDATOR), "--profile", "standard", "--json"],
                                   cwd=self.root, env=self.env, capture_output=True,
                                   text=True, encoding="utf-8", timeout=30)
        self.assertEqual(json.loads(canonical.stdout)["scanned_files"][0]["status"], "ready")
        (self.root / "naos/reports/module_header_traceability.json").unlink()
        output = self.check()
        self.assertNotIn("[WARN]", output)
        self.assertNotIn("missing", output)

    def test_unknown_inline_requirement_is_reported(self):
        source = header(requirement="FR-999").replace("Implements:\n    - FR-999: Synthetic requirement", "Implements: FR-999")
        self.stage("src/service.py", source)
        self.assertIn("FR-999", self.check())

    def test_canonical_exclusions_and_unstaged_sources_are_preserved(self):
        self.stage("src/__init__.py", "")
        self.stage("src/migrations/old.py", "# intentionally excluded\n")
        self.write("src/unstaged.py", "# not in this commit\n")
        self.assertNotIn("[WARN]", self.check())

    def test_staged_invalid_header_is_not_hidden_by_valid_working_copy(self):
        self.stage("src/service.py", header(requirement="FR-999"))
        self.write("src/service.py", header())
        self.assertIn("FR-999", self.check())

    def test_valid_index_is_not_replaced_by_unstaged_bad_header(self):
        self.stage("src/service.py", header())
        self.write("src/service.py", header(requirement="FR-999"))
        self.assertNotIn("FR-999", self.check())

    def test_explicit_exclusions_and_remapped_roots_apply(self):
        self.env.update(NAOS_ROOT="controls/governance", SRC_ROOT="packages")
        self.write("controls/governance/module_header_rules.yaml", "enabled: true\ninclude_patterns: ['packages/**/*.py']\nexclude_patterns: ['**/omit.py']\n")
        self.stage("packages/omit.py", "# excluded\n")
        self.stage("packages/name with ü.py", header("packages/name with ü.py", "FR-999"))
        output = self.check()
        self.assertIn("FR-999", output)
        self.assertIn("packages/name with ü.py", output)
        self.assertNotIn("packages/omit.py", output)

    def test_malformed_configuration_is_not_silently_exempted(self):
        self.stage("src/service.py", header())
        self.write("naos/module_header_rules.yaml", "enabled: true\ninclude_patterns: []\n")
        self.assertIn("include_patterns must be a non-empty list", self.check())

    def test_staged_source_selection_gap_keeps_canonical_warning(self):
        self.stage("src/service.py", header())
        self.write("naos/module_header_rules.yaml", "enabled: true\ninclude_patterns: ['src/api/**/*.py']\nexclude_patterns: []\n")
        self.assertIn("No Python source files matched configured module-header include patterns", self.check())

    def test_disabled_rules_do_not_reintroduce_the_old_matcher(self):
        self.stage("src/service.py", "# deliberately headerless\n")
        self.write("naos/module_header_rules.yaml", "enabled: false\n")
        self.assertNotIn("[WARN]", self.check())

    @unittest.skipUnless(shutil.which("bash"), "Bash required for actual hook")
    def test_actual_hook_uses_same_validator_without_changing_soft_enforcement(self):
        for name in ("naos_staged_python.py", "validators/validate_test_ac_references.py"):
            target = self.root / "scripts" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / "scripts" / name, target)
        self.stage("src/service.py", header(requirement="FR-999"))
        before = self.git("diff", "--cached", "--binary")
        result = subprocess.run(["bash", str(ROOT / "templates/rules-chain/.githooks/pre-commit")],
                                cwd=self.root, env=self.env, capture_output=True,
                                text=True, encoding="utf-8", timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("FR-999", result.stdout)
        self.assertEqual(self.git("diff", "--cached", "--binary"), before)
        self.assertFalse((self.root / "naos/reports/module_header_traceability.json").exists())


if __name__ == "__main__":
    unittest.main()
