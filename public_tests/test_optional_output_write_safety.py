"""G1 optional outputs: real entry points refuse aliases without changing bytes."""

from __future__ import annotations

import contextlib
import importlib
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

import yaml


KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(KIT / "scripts"))


class OptionalOutputWriteSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-optional-output-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.project = self.base / "project"
        self.project.mkdir()
        shutil.copytree(KIT / "scripts", self.project / "scripts",
                        ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(KIT / "schemas", self.project / "schemas")
        shutil.copytree(KIT / "templates/structural-seeds", self.project / "templates/structural-seeds")
        metadata = self.project / "scripts/naos_posix_metadata"
        metadata.mkdir()
        for name in ("security.py", "linux_primitives.py"):
            shutil.copy2(KIT / "upgrade_contract" / name, metadata / name)
        shutil.copy2(KIT / "upgrade_contract/windows_handles.py",
                     self.project / "scripts/naos_windows_handles.py")
        shutil.copy2(KIT / "templates/Makefile.naos", self.project / "Makefile.naos")
        (self.project / "naos/reports").mkdir(parents=True)
        (self.project / "naos/TASK_REGISTRY.yaml").write_text("tasks: []\n", encoding="utf-8")
        (self.project / "configs").mkdir()
        (self.project / "out").mkdir()
        self.victim = self.base / "outside.txt"
        self.original = b"SYNTHETIC OUTSIDE SENTINEL\r\n"
        self.victim.write_bytes(self.original)
        self.env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "NAOS_FIXED_TIME": "2026-10-19T00:00:00Z"}
        for name in ("NAOS_ROOT", "NAOS_POLICY", "NAOS_STRICT", "NAOS_PROFILE", "PYTHONPATH"):
            self.env.pop(name, None)

    def link(self, output, *, hard=False):
        output.parent.mkdir(parents=True, exist_ok=True)
        if hard:
            os.link(self.victim, output)
        else:
            try:
                output.symlink_to(self.victim)
            except OSError:
                if os.name != "nt":
                    raise
                # Native hardlink control on Windows hosts without symlink privilege.
                os.link(self.victim, output)

    def cli(self, script, *args):
        return subprocess.run([sys.executable, "-B", str(self.project / "scripts" / script), *args],
                              cwd=self.project, env=self.env, capture_output=True, text=True,
                              check=False, timeout=60)

    def make(self, target, args, script, *cli_args):
        executable = shutil.which("make")
        if executable is None:
            return self.cli(script, *cli_args)
        return subprocess.run([executable, "-f", "Makefile.naos", target,
                               "PYTHON=" + sys.executable, "NAOS_PROFILE=quickstart", *args],
                              cwd=self.project, env=self.env, capture_output=True, text=True,
                              check=False, timeout=60)

    def assert_refused(self, result):
        self.assertEqual(self.victim.read_bytes(), self.original, "outside victim changed")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def cases(self):
        return (
            ("naos-intake", "naos/install/intake.yaml", [], "naos_intake.py", ["--no-prompt"]),
            ("naos-install-decision-record", "naos/INSTALL_DECISION_RECORD.md", [],
             "naos_install_decision_record.py", ["--no-prompt"]),
            ("naos-context-query", "out/local.md",
             ["NAOS_COMMON_ARGS=--profile quickstart --query fixture --write-markdown --markdown-output out/local.md"],
             "naos_local_context_query.py", ["--query", "fixture", "--write-markdown", "--markdown-output", "out/local.md"]),
            ("naos-graph-query", "out/graph.md",
             ["QUERY_ARGS=--task T-123 --write-markdown --markdown-output out/graph.md"],
             "naos_graph_context_query.py", ["--task", "T-123", "--write-markdown", "--markdown-output", "out/graph.md"]),
            ("naos-sarif-export", "out/findings.sarif", ["NAOS_COMMON_ARGS=--profile quickstart --output out/findings.sarif"],
             "naos_sarif_export.py", ["--output", "out/findings.sarif"]),
            ("naos-spec-assembly-worksheet", "out/worksheet.md",
             ["SPEC_ASSEMBLY_WORKSHEET_ARGS=--write-markdown --markdown-output out/worksheet.md"],
             "naos_spec_assembly_worksheet.py", ["--write-markdown", "--markdown-output", "out/worksheet.md"]),
            ("gov-refresh", "configs/naos_ai_surface_catalogue.yaml", [],
             "naos_emit_capabilities.py", ["--root", "."]),
        )

    def test_make_targets_refuse_planted_leaf_symlinks(self):
        for target, relative, args, script, flags in self.cases():
            with self.subTest(target=target):
                output = self.project / relative
                self.link(output)
                try:
                    self.assert_refused(self.make(target, args, script, "--profile", "quickstart", *flags)
                                        if target != "gov-refresh" else self.make(target, args, script, *flags))
                finally:
                    output.unlink()
                    self.victim.write_bytes(self.original)

    def test_make_targets_keep_regular_outputs_and_modes(self):
        for target, relative, args, script, flags in self.cases():
            with self.subTest(target=target):
                output = self.project / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(b"old\n")
                output.chmod(0o640)
                result = (self.make(target, args, script, "--profile", "quickstart", *flags)
                          if target != "gov-refresh" else self.make(target, args, script, *flags))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                payload = output.read_bytes()
                self.assertNotEqual(payload, b"old\n")
                if os.name == "posix":
                    self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o640)
                if target == "naos-intake":
                    self.assertIsInstance(yaml.safe_load(payload), dict)
                elif target == "gov-refresh":
                    self.assertTrue(payload.startswith(b"# AUTO-GENERATED"))
                    self.assertNotIn(b"\r\n", payload)
                elif target == "naos-sarif-export":
                    parsed = json.loads(payload)
                    self.assertEqual(payload, (json.dumps(parsed, indent=2, sort_keys=True) + "\n").replace("\n", os.linesep).encode())
                else:
                    self.assertTrue(payload.startswith(b"#"))
                    self.assertTrue(payload.endswith(os.linesep.encode()))

    def test_companion_and_document_sinks_refuse_hardlinks(self):
        for target, relative, args, script, flags in self.cases():
            with self.subTest(target=target):
                output = self.project / relative
                self.link(output, hard=True)
                try:
                    result = (self.make(target, args, script, "--profile", "quickstart", *flags)
                              if target != "gov-refresh" else self.make(target, args, script, *flags))
                    self.assert_refused(result)
                finally:
                    output.unlink()
                    self.victim.write_bytes(self.original)

    def test_marker_aliases_refused_and_regular_json_unchanged(self):
        output = self.project / "data/rules_embeddings.status.json"
        for hard in (False, True):
            with self.subTest(hard=hard):
                self.link(output, hard=hard)
                try:
                    self.assert_refused(self.cli("naos_ai_precommit.py", "--rebuild-embeddings"))
                finally:
                    output.unlink()
                    self.victim.write_bytes(self.original)
        result = self.cli("naos_ai_precommit.py", "--rebuild-embeddings")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        payload = output.read_bytes()
        self.assertFalse(payload.endswith(b"\n"))
        parsed = json.loads(payload)
        self.assertEqual(parsed["status"], "not_built_by_v092_safe_mode")
        self.assertEqual(payload, json.dumps(parsed, indent=2).replace("\n", os.linesep).encode())

    def test_catalogue_equal_aliases_refused_and_regular_noop_keeps_inode_mtime(self):
        emitter = importlib.import_module("naos_emit_capabilities")
        content = "name: España\nvalue: one\n"
        self.victim.write_bytes(content.encode())
        output = self.project / "configs/equal.yaml"
        for hard in (False, True):
            with self.subTest(hard=hard):
                self.link(output, hard=hard)
                try:
                    with self.assertRaises((ValueError, OSError)):
                        emitter.write_catalogue(output, content)
                    self.assertEqual(self.victim.read_bytes(), content.encode())
                finally:
                    output.unlink()
        output.write_bytes(content.encode())
        output.chmod(0o440)
        self.addCleanup(output.chmod, 0o600)
        before = output.stat()
        self.assertFalse(emitter.write_catalogue(output, content))
        after = output.stat()
        self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))
        self.assertEqual(output.read_bytes(), content.encode())

    def test_catalogue_package_import_fresh_process_and_nested_external_output(self):
        output = self.base / "external/nested/catalogue.yaml"
        code = ("from pathlib import Path; from scripts.naos_emit_capabilities import write_catalogue; "
                "p=Path(__import__('sys').argv[1]); "
                "assert write_catalogue(p, 'name: España\\n'); "
                "assert not write_catalogue(p, 'name: España\\n')")
        result = subprocess.run([sys.executable, "-B", "-c", code, str(output)], cwd=self.project,
                                env=self.env, capture_output=True, text=True, check=False, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(output.read_bytes(), "name: España\n".encode())

    def test_dependency_free_help_and_static_config_check_remain_available(self):
        for script in ("naos_ai_precommit.py", "naos_overlay_coexistence.py"):
            with self.subTest(script=script):
                result = subprocess.run([sys.executable, "-B", "-S", str(self.project / "scripts" / script), "--help"],
                                        cwd=self.project, env=self.env, capture_output=True, text=True,
                                        check=False, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run([sys.executable, "-B", "-S", str(self.project / "scripts/naos_ai_precommit.py"), "--check-config"],
                                cwd=self.project, env=self.env, capture_output=True, text=True,
                                check=False, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.project / "data").exists())

    def test_explicit_document_outputs_refuse_linked_parent(self):
        outside = self.base / "external-reports"
        outside.mkdir()
        alias = self.project / "alias"
        if os.name == "nt":
            result = subprocess.run([os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", "mklink", "/J", str(alias), str(outside)],
                                    capture_output=True, text=True, check=False, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            alias.symlink_to(outside, target_is_directory=True)
        for script, flags in (
            ("naos_emit_capabilities.py", ["--root", ".", "--output", "alias/catalogue.yaml"]),
            ("naos_local_context_query.py", ["--query", "fixture", "--write-markdown", "--markdown-output", "alias/local.md"]),
            ("naos_graph_context_query.py", ["--task", "T-123", "--write-markdown", "--markdown-output", "alias/graph.md"]),
            ("naos_spec_assembly_worksheet.py", ["--write-markdown", "--markdown-output", "alias/worksheet.md"]),
            ("naos_sarif_export.py", ["--output", "alias/findings.sarif"]),
        ):
            with self.subTest(script=script):
                self.assertNotEqual(self.cli(script, *flags).returncode, 0)
                self.assertEqual(list(outside.iterdir()), [])

    def test_overlay_rechecks_leaf_after_report_build(self):
        overlay = importlib.import_module("naos_overlay_coexistence")
        target = self.project / "target"
        target.mkdir()
        output = self.base / "overlay.json"
        for hard in (False, True):
            with self.subTest(hard=hard):
                output.write_bytes(b"ordinary precheck\n")

                def swap(*args):
                    output.unlink()
                    self.link(output, hard=hard)
                    return {"status": "pass", "target_unchanged": True}

                with patch.object(overlay, "protected_directories", return_value=[target]), \
                        patch.object(overlay, "target_snapshot", return_value={}), \
                        patch.object(overlay, "build_report", side_effect=swap), \
                        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises((ValueError, OSError)):
                        overlay.main([str(target), "--output", str(output)])
                self.assertEqual(self.victim.read_bytes(), self.original)
                output.unlink()
                self.victim.write_bytes(self.original)

    def test_overlay_keeps_protected_target_guard_and_sorted_json(self):
        overlay = importlib.import_module("naos_overlay_coexistence")
        target = self.project / "target"
        target.mkdir()
        with patch.object(overlay, "protected_directories", return_value=[target]), \
                patch.object(overlay, "target_snapshot", return_value={}), \
                patch.object(overlay, "build_report", return_value={"status": "pass", "target_unchanged": True}), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            output = target / "forbidden.json"
            self.assertEqual(overlay.main([str(target), "--output", str(output)]), 2)
            self.assertFalse(output.exists())
            outside = self.base / "nested/overlay.json"
            self.assertEqual(overlay.main([str(target), "--output", str(outside)]), 0)
            self.assertEqual(outside.read_bytes(), (json.dumps({"status": "pass", "target_unchanged": True},
                                                             indent=2, sort_keys=True) + "\n").replace("\n", os.linesep).encode())

    def test_overlay_guard_checks_publisher_normalized_destination(self):
        overlay = importlib.import_module("naos_overlay_coexistence")
        target = self.project / "target"
        target.mkdir()
        outside = self.base / "external/child"
        outside.mkdir(parents=True)
        alias = target / "alias"
        if os.name == "nt":
            result = subprocess.run([os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", "mklink", "/J", str(alias), str(outside)],
                                    capture_output=True, text=True, check=False, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            alias.symlink_to(outside, target_is_directory=True)
        output = alias / ".." / "report.json"
        with patch.object(overlay, "protected_directories", return_value=[target]), \
                patch.object(overlay, "target_snapshot", return_value={}), \
                patch.object(overlay, "build_report", return_value={"status": "pass", "target_unchanged": True}) as build, \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(overlay.main([str(target), "--output", str(output)]), 2)
            build.assert_not_called()
        self.assertFalse((target / "report.json").exists())
        self.assertFalse((outside.parent / "report.json").exists())
        with patch.object(overlay, "protected_directories", return_value=[target]), \
                patch.object(overlay, "target_snapshot", return_value={}), \
                patch.object(overlay, "build_report", return_value={"status": "pass", "target_unchanged": True}), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(overlay.main([str(target), "--output", str(outside / ".." / "ordinary.json")]), 0)
        self.assertTrue((outside.parent / "ordinary.json").is_file())


if __name__ == "__main__":
    unittest.main()
