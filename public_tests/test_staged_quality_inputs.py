"""G11: staged Git failures are unavailable; filenames are NUL-delimited data."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(KIT / "scripts"))
SPEC = importlib.util.spec_from_file_location("_g11_quality", KIT / "scripts/naos_code_quality_audit.py")
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)


class StagedQualityInputTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        for name in ("src/pkg", "src/db", "configs", "specs", "naos/inventory"):
            (self.root / name).mkdir(parents=True)
        self.config = self.root / "configs/naos_architecture_boundaries.yaml"
        self.config.write_text(yaml.safe_dump({
            "forbidden_imports": [{"from": "src/pkg/**", "to": "src/db/**"}],
            "arch_components": {"ARCH-1": {"affected_modules": ["src/pkg/*.py"]}},
        }), encoding="utf-8")
        (self.root / "src/db/models.py").write_text("MODEL = True\n", encoding="utf-8")
        (self.root / "src/pkg/clean.py").write_text("value = 1\n", encoding="utf-8")
        (self.root / "specs/03-requirements.md").write_text("## FR-001: Fixture\n", encoding="utf-8")
        (self.root / "naos/TASK_REGISTRY.yaml").write_text("tasks: []\n", encoding="utf-8")
        similarity = self.root / "naos/inventory/FUNCTION_SIMILARITY_INDEX.json"
        similarity.write_text('{"entries":{"fixture":{}}}', encoding="utf-8")
        self.env = dict(os.environ, SRC_ROOT="src", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        if os.name == "nt" and shutil.which("git", path=self.env.get("PATH", "")) is None:
            directory = Path(self.env.get("ProgramFiles", r"C:\Program Files")) / "Git/cmd"
            self.assertTrue((directory / "git.exe").is_file(), "Native staged tests require installed Git")
            self.env["PATH"] = str(directory) + os.pathsep + self.env.get("PATH", "")
        self.context = patch.multiple(
            AUDIT, PROJECT_ROOT=self.root, SRC_DIR=self.root / "src", SRC_ROOT_VAL="src",
            ALLOWLIST_PATH=self.root / "missing-allowlist.yaml", BOUNDARIES_CONFIG=self.config,
            SIMILARITY_INDEX_PATH=similarity, THRESHOLDS_CONFIG_PATH=self.root / "missing-thresholds.yaml",
            SEMANTIC_ALLOWLIST_PATH=self.root / "missing-semantic.yaml",
            REQUIREMENTS_SPEC=self.root / "specs/03-requirements.md",
            TASK_REGISTRY=self.root / "naos/TASK_REGISTRY.yaml")
        self.context.start()
        self.addCleanup(self.context.stop)
        environment = patch.dict(os.environ, self.env, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def invoke(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", ["audit", *args]), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit) as exited:
                AUDIT.main()
        return exited.exception.code, out.getvalue(), err.getvalue()

    def test_real_git_failure_is_not_a_clean_cli_result(self):
        for flag in ("--check-duplicates", "--check-boundaries", "--check-spec-alignment", "--check-arch-ownership"):
            with self.subTest(flag=flag):
                code, out, err = self.invoke(flag, "--staged-only", "--report", "json")
                self.assertEqual(code, 2, out + err)
                report = json.loads(out)
                self.assertEqual(report["status"], "not_evaluated")
                self.assertEqual(report["reason_code"], "STAGED_DIFF_UNAVAILABLE")
                self.assertNotIn("Traceback", err)
                self.assertNotIn("error_count", report)

    def test_reader_preserves_filename_data_without_text_translation(self):
        names = ["src/pkg/ leading and trailing .py", "src/pkg/line\nbreak.py",
                 "src/pkg/carriage\rreturn.py", "src/pkg/tab\tname.py", "src/pkg/café.py",
                 "src/pkg/back\\slash.py"]
        if os.name != "nt":
            names.append(os.fsdecode(b"src/pkg/nonutf8-\xff.py"))
        raw = b"\0".join(os.fsencode(name) for name in names) + b"\0"
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, raw, b"")) as run:
            self.assertEqual(AUDIT.staged_paths(), names)
        self.assertIn("-z", run.call_args.args[0])
        self.assertFalse(run.call_args.kwargs.get("text", False))
        self.assertNotIn("encoding", run.call_args.kwargs)

    def test_all_five_readers_propagate_git_unavailability(self):
        operations = (
            lambda: AUDIT.check_duplicates(staged_only=True, report_format="silent"),
            lambda: AUDIT.check_semantic_duplicates(staged_only=True),
            lambda: AUDIT.check_boundaries(staged_only=True),
            lambda: AUDIT.check_arch_ownership(staged_only=True),
            lambda: AUDIT.check_spec_alignment(staged_only=True),
        )
        for operation in operations:
            with self.subTest(operation=operations.index(operation)), patch(
                "subprocess.run", return_value=subprocess.CompletedProcess([], 9, b"", b"private-marker")
            ):
                with self.assertRaises(AUDIT.StagedDiffUnavailable) as caught:
                    operation()
                self.assertNotIn("private-marker", str(caught.exception))

    def test_missing_git_text_result_and_malformed_output_are_explicit(self):
        with patch("subprocess.run", side_effect=FileNotFoundError("private-marker")):
            code, out, err = self.invoke("--check-boundaries", "--staged-only")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("not evaluated", err)
        self.assertNotIn("private-marker", err)
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, b"src/not-terminated.py", b"")):
            with self.assertRaises(AUDIT.StagedDiffUnavailable):
                AUDIT.staged_paths()

    def test_actual_git_quoted_filename_is_checked_and_unstaged_control_is_excluded(self):
        git = shutil.which("git", path=self.env.get("PATH", ""))
        self.assertIsNotNone(git, "Native staged tests require installed Git")
        name = "src/pkg/café odd name.py" if os.name == "nt" else "src/pkg/café odd\nname.py"
        bad = self.root / name
        bad.write_text("import src.db.models\ndef duplicate_action():\n    return 1\n", encoding="utf-8")
        (self.root / "src/pkg/copy.py").write_text("def duplicate_action():\n    return 1\n", encoding="utf-8")
        for arguments in (("init", "-q"), ("add", "--", name, "src/pkg/clean.py")):
            subprocess.run([git, *arguments], cwd=self.root, env=self.env, capture_output=True, check=True)
        with contextlib.redirect_stdout(io.StringIO()):
            violations = AUDIT.check_boundaries(staged_only=True)
        self.assertEqual([item.importer_file for item in violations], [name])
        duplicates = AUDIT.check_duplicates(staged_only=True, report_format="silent")
        self.assertEqual(len(duplicates.errors), 1)
        self.assertIn(name, [item["file"] for item in duplicates.errors[0]["locations"]])
        subprocess.run([git, "rm", "--cached", "--", name], cwd=self.root, env=self.env, capture_output=True, check=True)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(AUDIT.check_boundaries(staged_only=True), [])

    def test_empty_successful_git_list_preserves_existing_duplicate_full_scan(self):
        for name in ("a.py", "b.py"):
            (self.root / "src/pkg" / name).write_text("def duplicate_action():\n    return 1\n", encoding="utf-8")
        git = shutil.which("git", path=self.env.get("PATH", ""))
        self.assertIsNotNone(git, "Native staged tests require installed Git")
        subprocess.run([git, "init", "-q"], cwd=self.root, env=self.env, capture_output=True, check=True)
        report = AUDIT.check_duplicates(staged_only=True, report_format="silent")
        self.assertEqual(len(report.errors), 1)
