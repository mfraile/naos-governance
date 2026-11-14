"""G1: remaining derived text outputs retain bytes and refuse redirection."""
from __future__ import annotations

import contextlib
import importlib.util
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


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, KIT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


QUERY = load_module("_g1_derived_query", "naos_function_index_query.py")
CONTEXT = load_module("_g1_derived_context", "naos_task_context_pack.py")
RENDER = load_module("_g1_derived_render", "naos_render_secure_coding_controls.py")
OVERLAYS = load_module("_g1_derived_overlays", "naos_policy_overrides.py")


class DerivedTextWriteSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-derived-text-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.project = self.base / "project"
        self.project.mkdir()
        shutil.copytree(KIT / "scripts", self.project / "scripts",
                        ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(KIT / "schemas", self.project / "schemas")
        shutil.copytree(KIT / "templates/structural-seeds", self.project / "templates/structural-seeds")
        native = self.project / "scripts/naos_posix_metadata"
        native.mkdir(exist_ok=True)
        for filename in ("security.py", "linux_primitives.py"):
            shutil.copy2(KIT / "upgrade_contract" / filename, native / filename)
        shutil.copy2(KIT / "upgrade_contract/windows_handles.py",
                     self.project / "scripts/naos_windows_handles.py")
        shutil.copy2(KIT / "templates/Makefile.naos", self.project / "Makefile.naos")
        (self.project / "configs").mkdir()
        shutil.copy2(KIT / "policies/default_policy.yaml", self.project / "default_policy.yaml")
        (self.project / "naos/active").mkdir(parents=True)
        (self.project / "naos/inventory").mkdir()
        (self.project / "naos/policy_overrides.d").mkdir()
        (self.project / "naos/TASK_REGISTRY.yaml").write_text(
            "tasks:\n- id: T-123\n  title: Synthetic task\n  status: active\n  requirement: FR-123\n",
            encoding="utf-8")
        (self.project / "naos/active/T-123.md").write_text(
            "# T-123\n\n## Acceptance Criteria\n- [ ] Synthetic evidence.\n", encoding="utf-8")
        self.index = self.project / "naos/inventory/FUNCTION_SIMILARITY_INDEX.json"
        (self.index.parent / "FUNCTION_INDEX.yaml").write_text(
            "service:\n  purpose: Synthetic café service.\n  public:\n"
            "  - 'public_action() # Synthetic purpose.'\n", encoding="utf-8")
        self.markdown = self.project / "naos/context_packs/T-123.md"
        self.markdown.parent.mkdir()
        self.victim = self.base / "outside.txt"
        self.original = b"SYNTHETIC OUTSIDE\r\n"
        self.victim.write_bytes(self.original)
        self.env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "NAOS_FIXED_TIME": "2026-10-20T00:00:00Z"}
        for key in ("NAOS_ROOT", "NAOS_POLICY", "NAOS_PROFILE", "NAOS_STRICT", "PYTHONPATH"):
            self.env.pop(key, None)

    def link(self, path, target=None, *, hard=False, directory=False):
        target = target or self.victim
        if hard:
            os.link(target, path)
        elif os.name == "nt" and directory:
            result = subprocess.run([os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", "mklink", "/J",
                                     str(path), str(target)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            try:
                path.symlink_to(target, target_is_directory=directory)
            except OSError as exc:
                if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                    self.skipTest("Native Windows file-symlink privilege unavailable")
                raise

    def cli(self, filename, *args):
        return subprocess.run([sys.executable, "-B", str(self.project / "scripts" / filename), *args],
                              cwd=self.project, env=self.env, capture_output=True, text=True, timeout=60)

    def assert_refused(self, result):
        self.assertEqual(self.victim.read_bytes(), self.original, "outside victim changed")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_similarity_leaf_aliases_are_refused(self):
        for hard in (False, True):
            with self.subTest(hardlink=hard):
                self.link(self.index, hard=hard)
                try:
                    self.assert_refused(self.cli("naos_function_index_query.py", "--rebuild-index"))
                finally:
                    self.index.unlink()
                    self.victim.write_bytes(self.original)

    def test_similarity_dangling_leaf_does_not_create_referent(self):
        missing = self.base / "missing.txt"
        self.link(self.index, missing)
        result = self.cli("naos_function_index_query.py", "--rebuild-index")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(missing.exists())

    def test_similarity_parent_alias_creates_no_outside_children(self):
        outside = self.base / "outside-inventory"
        outside.mkdir()
        alias = self.project / "alias"
        self.link(alias, outside, directory=True)
        with patch.multiple(QUERY, FUNCTION_INDEX_PATH=self.index.parent / "FUNCTION_INDEX.yaml",
                            SIMILARITY_INDEX_PATH=alias / "new/index.json",
                            AI_PRECOMMIT_CONFIG_PATH=self.project / "absent.yaml"), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises((OSError, ValueError)):
                QUERY.build_similarity_index()
        self.assertEqual(list(outside.iterdir()), [])

    def test_similarity_compact_json_messages_and_existing_mode_remain(self):
        self.index.write_bytes(b"stale")
        self.index.chmod(0o640)
        result = self.cli("naos_function_index_query.py", "--rebuild-index")
        self.assertEqual(result.returncode, 0, result.stderr)
        raw = self.index.read_bytes()
        value = json.loads(raw)
        self.assertEqual(raw, json.dumps(value, indent=None, separators=(",", ":")).encode("utf-8"))
        self.assertFalse(raw.endswith(b"\n"))
        self.assertFalse(value["_meta"]["has_embeddings"])
        self.assertEqual(value["_meta"]["entries"], 1)
        self.assertIn("Index written:", result.stdout)
        self.assertIn("Optional similarity provider disabled", result.stdout)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.index.stat().st_mode), 0o640)

    def test_task_context_make_target_refuses_leaf_aliases(self):
        make = shutil.which("make")
        if make is None:
            self.skipTest("make unavailable; copied CLI is exercised separately")
        for hard in (False, True):
            with self.subTest(hardlink=hard):
                self.link(self.markdown, hard=hard)
                try:
                    result = subprocess.run(
                        [make, "-f", "Makefile.naos", "naos-task-context", "TASK=T-123",
                         "PYTHON=" + sys.executable, "NAOS_COMMON_ARGS=--profile quickstart --write-markdown"],
                        cwd=self.project, env=self.env, capture_output=True, text=True, timeout=60)
                    self.assert_refused(result)
                finally:
                    self.markdown.unlink()
                    self.victim.write_bytes(self.original)

    def test_task_context_parent_alias_is_refused(self):
        self.markdown.parent.rmdir()
        outside = self.base / "outside-packs"
        outside.mkdir()
        self.link(self.markdown.parent, outside, directory=True)
        result = self.cli("naos_task_context_pack.py", "--task", "T-123", "--profile", "quickstart", "--write-markdown")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(list(outside.iterdir()), [])

    def test_task_context_copied_cli_refuses_hardlinked_leaf(self):
        self.link(self.markdown, hard=True)
        result = self.cli("naos_task_context_pack.py", "--task", "T-123", "--profile", "quickstart", "--write-markdown")
        self.assert_refused(result)

    def test_task_context_no_markdown_and_missing_task_preserve_unused_alias(self):
        self.link(self.markdown)
        for args in (("--task", "T-123", "--no-markdown"), ()):
            with self.subTest(args=args):
                result = self.cli("naos_task_context_pack.py", "--profile", "quickstart", *args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.victim.read_bytes(), self.original)
                self.assertTrue(self.markdown.is_symlink())

    def test_task_context_markdown_bytes_report_and_mode_remain(self):
        self.markdown.write_bytes(b"stale")
        self.markdown.chmod(0o640)
        result = self.cli("naos_task_context_pack.py", "--task", "T-123", "--profile", "quickstart", "--write-markdown")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(self.markdown.read_bytes(), CONTEXT.build_markdown(report).replace("\n", os.linesep).encode("utf-8"))
        self.assertEqual(report["markdown_output"]["status"], "written")
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.markdown.stat().st_mode), 0o640)

    def render_fixture(self):
        for rel in ("configs/secure_coding_control_register.yaml", "configs/secure_coding_control_render_manifest.yaml"):
            shutil.copy2(KIT / rel, self.project / rel)
        manifest_path = self.project / "configs/secure_coding_control_render_manifest.yaml"
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        manifest["targets"] = manifest["targets"][:1]
        manifest["targets"][0]["path"] = "render/target.md"
        manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
        target = self.project / "render/target.md"
        target.parent.mkdir()
        return target

    def test_renderer_in_root_leaf_symlink_and_external_hardlink_are_refused(self):
        target = self.render_fixture()
        for hard in (False, True):
            with self.subTest(hardlink=hard):
                victim = self.victim if hard else self.project / "inside-victim.md"
                victim.write_bytes(self.original)
                self.link(target, victim, hard=hard)
                try:
                    result = self.cli("naos_render_secure_coding_controls.py", "--root", str(self.project))
                    self.assertEqual(victim.read_bytes(), self.original)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                finally:
                    target.unlink()

    def test_renderer_in_root_parent_alias_is_refused(self):
        target = self.render_fixture()
        target.parent.rmdir()
        inside = self.project / "inside-directory"
        inside.mkdir()
        occupant = inside / target.name
        occupant.write_bytes(self.original)
        self.link(target.parent, inside, directory=True)
        result = self.cli("naos_render_secure_coding_controls.py", "--root", str(self.project))
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(occupant.read_bytes(), self.original)

    def test_renderer_late_leaf_alias_is_refused(self):
        target = self.render_fixture()
        target.write_text("# Synthetic target\n", encoding="utf-8")
        build_plan = RENDER.build_plan

        def substitute(*args):
            plans, findings = build_plan(*args)
            target.unlink()
            self.link(target)
            return plans, findings

        with patch.object(RENDER, "build_plan", side_effect=substitute), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises((OSError, ValueError)):
                RENDER.main(["--root", str(self.project)])
        self.assertEqual(self.victim.read_bytes(), self.original)

    def test_renderer_exact_lf_bytes_and_readonly_check_noop_remain(self):
        target = self.render_fixture()
        target.write_bytes(b"# Synthetic target\r\n")
        plans, findings = RENDER.build_plan(self.project)
        self.assertEqual(findings, [])
        expected = plans[0].expected.encode("utf-8")
        result = self.cli("naos_render_secure_coding_controls.py", "--root", str(self.project))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(target.read_bytes(), expected)
        target.chmod(0o444)
        try:
            before = target.stat().st_mtime_ns
            result = self.cli("naos_render_secure_coding_controls.py", "--check", "--root", str(self.project))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(target.read_bytes(), expected)
            self.assertEqual(target.stat().st_mtime_ns, before)
        finally:
            target.chmod(0o600)

    def test_effective_policy_alias_inserted_after_guards_is_structured_refusal(self):
        output = self.project / "effective.yaml"
        output.write_bytes(b"stale")
        safe_dump = yaml.safe_dump

        def substitute(*args, **kwargs):
            text = safe_dump(*args, **kwargs)
            if kwargs.get("sort_keys") is True and not output.is_symlink():
                output.unlink()
                self.link(output)
            return text

        with contextlib.chdir(self.project), patch.object(OVERLAYS.yaml, "safe_dump", side_effect=substitute), contextlib.redirect_stdout(io.StringIO()) as messages:
            code = OVERLAYS.main(["--profile", "quickstart", "--policy", str(self.project / "default_policy.yaml"),
                                  "--json", "--write-effective-policy", "--effective-policy-output", str(output)])
        report = json.loads(messages.getvalue())
        self.assertEqual(self.victim.read_bytes(), self.original)
        self.assertNotEqual(code, 0)
        self.assertEqual(report["status"], "blocked")
        self.assertFalse(report["summary"]["effective_policy_written"])
        self.assertTrue(any(item["id"] == "POLICY_OVERRIDE_EFFECTIVE_WRITE_FAILED" for item in report["findings"]))

    def test_effective_policy_retains_parent_spelling_when_symlink_predicate_is_false(self):
        # Windows junctions are reparse points but Path.is_symlink() is false.
        # Exercise that resolver contract on POSIX too, without claiming this
        # predicate substitution establishes native Windows qualification.
        outside = self.base / "outside-policy"
        outside.mkdir()
        occupant = outside / "effective.yaml"
        occupant.write_bytes(self.original)
        alias = self.project / "policy-alias"
        self.link(alias, outside, directory=True)
        with contextlib.chdir(self.project), patch.object(Path, "is_symlink", return_value=False), contextlib.redirect_stdout(io.StringIO()) as messages:
            code = OVERLAYS.main(["--profile", "quickstart", "--policy", str(self.project / "default_policy.yaml"),
                                  "--json", "--write-effective-policy", "--effective-policy-output", str(alias / occupant.name)])
        self.assertEqual(occupant.read_bytes(), self.original)
        self.assertNotEqual(code, 0)
        report = json.loads(messages.getvalue())
        self.assertEqual(report["status"], "blocked")
        self.assertFalse(report["summary"]["effective_policy_written"])

    def test_default_effective_policy_retains_parent_spelling(self):
        inside = self.project / "naos/other-reports"
        inside.mkdir()
        policy = yaml.safe_load((self.project / "default_policy.yaml").read_text(encoding="utf-8"))
        filename = policy["paths"].get("effective_policy") or "effective_policy"
        occupant = inside / filename
        occupant.write_bytes(self.original)
        self.link(self.project / "naos/reports", inside, directory=True)
        with contextlib.chdir(self.project), patch.object(Path, "is_symlink", return_value=False), contextlib.redirect_stdout(io.StringIO()) as messages:
            code = OVERLAYS.main(["--profile", "quickstart", "--policy", str(self.project / "default_policy.yaml"),
                                  "--json", "--write-effective-policy"])
        self.assertEqual(occupant.read_bytes(), self.original)
        self.assertNotEqual(code, 0)
        report = json.loads(messages.getvalue())
        self.assertEqual(report["status"], "blocked")
        self.assertFalse(report["summary"]["effective_policy_written"])

    def test_already_blocked_policy_keeps_json_when_report_destination_refuses(self):
        output = self.project / "effective.yaml"
        self.link(output, hard=True)
        arguments = ["--profile", "quickstart", "--policy", str(self.project / "default_policy.yaml"),
                     "--json", "--write-effective-policy", "--effective-policy-output", str(output)]
        with contextlib.chdir(self.project), patch.object(OVERLAYS, "report_output_path", side_effect=OSError("synthetic untrusted report parent")), contextlib.redirect_stdout(io.StringIO()) as messages, contextlib.redirect_stderr(io.StringIO()) as errors:
            code = OVERLAYS.main(arguments)
        self.assertEqual(code, 1)
        report = json.loads(messages.getvalue())
        self.assertEqual(report["status"], "blocked")
        self.assertFalse(report["summary"]["effective_policy_written"])
        self.assertEqual(self.victim.read_bytes(), self.original)
        self.assertIn("merge report destination refused", errors.getvalue())
        # A ready operation's separate output error keeps its existing contract.
        with contextlib.chdir(self.project), patch.object(OVERLAYS, "report_output_path", side_effect=OSError("synthetic report failure")):
            with self.assertRaises(OSError):
                OVERLAYS.main(arguments[:5])


if __name__ == "__main__":
    unittest.main()
