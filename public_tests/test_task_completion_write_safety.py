"""G1 completion publication and rollback, in disposable projects."""
from __future__ import annotations

import os
import contextlib
import io
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(KIT / "scripts"))
import naos_task_lifecycle as lifecycle  # noqa: E402


class TaskCompletionWriteSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-completion-writes-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.serial = 0

    def fixture(self, *, sidecar=False):
        self.serial += 1
        root = self.base / ("project-" + str(self.serial))
        root.mkdir()
        naos = self.base / ("sidecar-" + str(self.serial)) if sidecar else root / "naos"
        for name in ("active", "completed", "reports"):
            (naos / name).mkdir(parents=True, exist_ok=True)
        registry = (
            "# Café registry stays\r\n"
            "schema: naos.task_registry.v2\r\n"
            "lifecycle_contract_version: 1\r\n"
            "tasks:\r\n"
            "  - id: T-901\r\n"
            "    title: Café completion\r\n"
            "    status: active\r\n"
            "    lifecycle_state: active\r\n"
            "    priority: P1 # retain this comment\r\n"
        ).encode()
        (naos / "TASK_REGISTRY.yaml").write_bytes(registry)
        (naos / "active/T-901_story.md").write_bytes(
            b"# T-901\r\n\r\n## Acceptance Criteria\r\n\r\n- Exact card stays.\r\n"
        )
        (naos / "completed_history.yaml").write_bytes(
            b"schema: naos.completed_task_history.v1\ncontract_version: 1\n"
            b"records:\n- task_id: T-900\n  fixture: preserve this prior record\n"
        )
        return root, naos, str(naos) if sidecar else "naos"

    def complete(self, root, naos_root, *, dry_run=False):
        return lifecycle.complete_task(
            root=root, naos_root=naos_root, task_id="T-901", profile="standard",
            completion_provenance="Synthetic bounded test only.", completed_by="synthetic",
            verification_state="unverified", implementation_refs=[], test_refs=[],
            evidence_refs=[], decision_refs=[], unresolved_risks=[], dry_run=dry_run,
        )

    def snapshot(self, naos, *, active=None, completed=None):
        names = ("TASK_REGISTRY.yaml", "completed_history.yaml",
                 "active/T-901_story.md", "completed/T-901_story.md")
        paths = {n: naos / n for n in names}
        if active is not None:
            paths["active/T-901_story.md"] = active / "T-901_story.md"
        if completed is not None:
            paths["completed/T-901_story.md"] = completed / "T-901_story.md"
        return {n: path.read_bytes() if path.is_file() else None for n, path in paths.items()}

    def alias(self, path, destination, *, hard=False, directory=False):
        if hard:
            os.link(destination, path)
        elif os.name == "nt" and directory:
            result = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(path), str(destination)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            try:
                path.symlink_to(destination, target_is_directory=directory)
            except OSError:
                if os.name == "nt" and not directory:
                    self.skipTest("File symlink creation privilege unavailable")
                raise

    def test_predictable_completion_stages_do_not_clobber_aliases(self):
        for hard in (False, True):
            for name in ("completed/.T-901_story.md.naos-tmp",
                         ".TASK_REGISTRY.yaml.naos-tmp", ".completed_history.yaml.naos-tmp"):
                with self.subTest(hard=hard, stage=name):
                    root, naos, configured = self.fixture()
                    victim = self.base / ("victim-" + str(self.serial))
                    victim.write_bytes(b"outside stage sentinel")
                    self.alias(naos / name, victim, hard=hard)
                    self.complete(root, configured)
                    self.assertEqual(victim.read_bytes(), b"outside stage sentinel")
                    self.assertTrue((naos / name).exists())

    def test_rollback_does_not_clobber_predictable_stage_aliases(self):
        for hard in (False, True):
            with self.subTest(hard=hard):
                root, naos, _ = self.fixture()
                target = naos / "state.yaml"
                target.write_bytes(b"published bytes")
                victim = root / "rollback-victim"
                victim.write_bytes(b"rollback sentinel")
                self.alias(naos / ".state.yaml.naos-rollback", victim, hard=hard)
                lifecycle._restore_file(target, b"original bytes")
                self.assertEqual(victim.read_bytes(), b"rollback sentinel")
                self.assertEqual(target.read_bytes(), b"original bytes")

    def test_mutation_refuses_linked_registry_and_history(self):
        for hard in (False, True):
            for name in ("TASK_REGISTRY.yaml", "completed_history.yaml"):
                with self.subTest(hard=hard, path=name):
                    root, naos, configured = self.fixture()
                    target = naos / name
                    victim = self.base / ("leaf-" + str(self.serial))
                    original = target.read_bytes()
                    victim.write_bytes(original)
                    target.unlink()
                    self.alias(target, victim, hard=hard)
                    before = self.snapshot(naos)
                    with self.assertRaises((OSError, ValueError)):
                        self.complete(root, configured)
                    self.assertEqual(victim.read_bytes(), original)
                    self.assertEqual(self.snapshot(naos), before)

    def test_mutation_refuses_linked_active_parent(self):
        root, naos, configured = self.fixture()
        before = self.snapshot(naos)
        outside = self.base / "outside-active"
        shutil.move(naos / "active", outside)
        self.alias(naos / "active", outside, directory=True)
        with self.assertRaises((OSError, ValueError)):
            self.complete(root, configured)
        self.assertEqual(self.snapshot(naos, active=outside), before)

    def test_mutation_refuses_linked_configured_naos_parent(self):
        root, naos, configured = self.fixture()
        before = self.snapshot(naos)
        outside = self.base / "outside-naos"
        shutil.move(naos, outside)
        self.alias(naos, outside, directory=True)
        with self.assertRaises((OSError, ValueError)):
            self.complete(root, configured)
        self.assertEqual(self.snapshot(outside), before)

    def test_mutation_refuses_linked_completed_parent_inside_project(self):
        root, naos, configured = self.fixture()
        before = self.snapshot(naos)
        other = root / "alternate-completed"
        shutil.move(naos / "completed", other)
        self.alias(naos / "completed", other, directory=True)
        with self.assertRaises((OSError, ValueError)):
            self.complete(root, configured)
        self.assertEqual(self.snapshot(naos, completed=other), before)

    def test_completed_leaf_collision_is_an_unchanged_refusal(self):
        root, naos, configured = self.fixture()
        output = naos / "completed/T-901_story.md"
        output.write_bytes(b"existing completed record")
        before = self.snapshot(naos)
        with self.assertRaisesRegex(ValueError, "inconsistent"):
            self.complete(root, configured)
        self.assertEqual(self.snapshot(naos), before)

    def test_completion_rollback_restores_each_publication_phase(self):
        for failed_phase in (1, 2, 3, 4):
            with self.subTest(failed_phase=failed_phase):
                root, naos, configured = self.fixture(sidecar=True)
                before = self.snapshot(naos)
                original_publish = lifecycle._publish_completion_file
                original_remove = lifecycle._remove_completion_file
                calls = 0

                def publish(path, content, original):
                    nonlocal calls
                    original_publish(path, content, original)
                    calls += 1
                    if calls == failed_phase:
                        raise OSError("injected post-publication failure")

                def remove(path, expected):
                    if failed_phase == 4 and path.parent.name == "active":
                        raise OSError("injected active removal failure")
                    return original_remove(path, expected)

                with (mock.patch.object(lifecycle, "_publish_completion_file", side_effect=publish),
                      mock.patch.object(lifecycle, "_remove_completion_file", side_effect=remove),
                      self.assertRaisesRegex(OSError, "injected")):
                    self.complete(root, configured)
                self.assertEqual(self.snapshot(naos), before)

    def test_rollback_preserves_a_foreign_edit_and_reports_restoration_failure(self):
        root, naos, configured = self.fixture()
        before = self.snapshot(naos)
        original_publish = lifecycle._publish_completion_file
        error = OSError("injected publication failure")

        def publish(path, content, original):
            original_publish(path, content, original)
            if path.name == "TASK_REGISTRY.yaml":
                path.write_bytes(b"foreign later edit")
                raise error

        with (mock.patch.object(lifecycle, "_publish_completion_file", side_effect=publish),
              self.assertRaises(OSError) as caught):
            self.complete(root, configured)
        self.assertIs(caught.exception, error)
        self.assertIn("Task rollback could not restore TASK_REGISTRY.yaml",
                      " ".join(getattr(error, "__notes__", [])))
        after = self.snapshot(naos)
        self.assertEqual(after["TASK_REGISTRY.yaml"], b"foreign later edit")
        for key in before.keys() - {"TASK_REGISTRY.yaml"}:
            self.assertEqual(after[key], before[key])

    def test_actual_make_target_refuses_registry_leaf_alias(self):
        make = shutil.which("make")
        if make is None:
            self.skipTest("Make unavailable; direct native completion remains tested")
        root, naos, configured = self.fixture()
        shutil.copytree(KIT / "scripts", root / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(KIT / "schemas", root / "schemas")
        shutil.copytree(KIT / "templates/structural-seeds", root / "templates/structural-seeds")
        metadata = root / "scripts/naos_posix_metadata"
        metadata.mkdir()
        for name in ("security.py", "linux_primitives.py"):
            shutil.copyfile(KIT / "upgrade_contract" / name, metadata / name)
        shutil.copyfile(KIT / "upgrade_contract/windows_handles.py", root / "scripts/naos_windows_handles.py")
        shutil.copyfile(KIT / "templates/Makefile.naos", root / "Makefile.naos")
        target = naos / "TASK_REGISTRY.yaml"
        victim = self.base / "make-victim.yaml"
        victim.write_bytes(target.read_bytes())
        target.unlink()
        self.alias(target, victim)
        before = self.snapshot(naos)
        result = subprocess.run(
            [make, "-f", "Makefile.naos", "naos-task-complete", "TASK=T-901",
             "PYTHON=" + sys.executable, "NAOS_ROOT=" + configured, "NAOS_PROFILE=standard"],
            cwd=root, capture_output=True, text=True, check=False, timeout=60,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(victim.read_bytes(), before["TASK_REGISTRY.yaml"])
        self.assertEqual(self.snapshot(naos), before)

    def test_dry_run_keeps_bytes_inodes_and_mtimes(self):
        root, naos, configured = self.fixture()
        before = self.snapshot(naos)
        paths = [naos / n for n, value in before.items() if value is not None]
        identities = [(p.stat().st_ino, p.stat().st_mtime_ns) for p in paths]
        report = self.complete(root, configured, dry_run=True)
        self.assertEqual(report["status"], "completion_preview")
        self.assertFalse(report["mutated"])
        self.assertEqual(self.snapshot(naos), before)
        self.assertEqual([(p.stat().st_ino, p.stat().st_mtime_ns) for p in paths], identities)

    def test_relative_external_sidecars_remain_supported(self):
        for missing in (False, True):
            with self.subTest(missing_erased_component=missing):
                root, naos, _ = self.fixture(sidecar=True)
                configured = os.path.relpath(naos, root)
                if missing:
                    configured = "missing/../" + configured
                card = (naos / "active/T-901_story.md").read_bytes()
                report = self.complete(root, configured)
                self.assertEqual(report["status"], "completed")
                self.assertEqual((naos / "completed/T-901_story.md").read_bytes(), card)
                self.assertFalse((root / "missing").exists())

    def test_alias_before_parent_traversal_is_not_normalized_away(self):
        root, naos, _ = self.fixture()
        outside = self.base / "outside-target"
        outside.mkdir()
        other_naos = self.base / "naos"
        shutil.copytree(naos, other_naos)
        self.alias(root / "redirect", outside, directory=True)
        before = self.snapshot(naos)
        outside_before = self.snapshot(other_naos)
        with self.assertRaises((OSError, ValueError)):
            self.complete(root, "redirect/../naos")
        self.assertEqual(self.snapshot(naos), before)
        self.assertEqual(self.snapshot(other_naos), outside_before)

    def test_cli_reports_incomplete_rollback_with_existing_schema_fields(self):
        root, naos, configured = self.fixture()
        original_publish = lifecycle._publish_completion_file

        def publish(path, content, original):
            original_publish(path, content, original)
            if path.name == "TASK_REGISTRY.yaml":
                path.write_bytes(b"foreign later edit")
                raise OSError("injected publication failure")

        capture = io.StringIO()
        previous = Path.cwd()
        try:
            os.chdir(root)
            with (mock.patch.object(lifecycle, "_publish_completion_file", side_effect=publish),
                  contextlib.redirect_stdout(capture)):
                result = lifecycle.main([
                    "--action", "complete", "--task", "T-901", "--profile", "standard",
                    "--naos-root", configured, "--output", str(naos / "reports/rollback.json"), "--json",
                ])
        finally:
            os.chdir(previous)
        report = json.loads(capture.getvalue())
        self.assertEqual(result, 2)
        self.assertEqual(report["status"], "invalid_task_lifecycle")
        self.assertTrue(report["mutated"])
        self.assertIn("rollback incomplete", report["findings"][0]["message"])
        self.assertIn("TASK_REGISTRY.yaml", report["findings"][0]["message"])
        self.assertTrue((naos / "active/T-901_story.md").is_file())
        self.assertFalse((naos / "completed/T-901_story.md").exists())

    @unittest.skipUnless(os.name == "posix", "POSIX creation umask compatibility")
    def test_owner_read_mask_refuses_clearly_and_preserves_task_state(self):
        program = """import contextlib,io,json,os,sys
from pathlib import Path
sys.path.insert(0,str(Path(sys.argv[3])/'scripts'))
import naos_task_lifecycle as lifecycle
mask=int(sys.argv[4],8);os.umask(mask);os.chdir(sys.argv[1])
capture=io.StringIO()
with contextlib.redirect_stdout(capture):
 result=lifecycle.main(['--action','complete','--task','T-901','--profile','standard','--naos-root',sys.argv[2],'--output',sys.argv[5],'--json'])
print(json.dumps({'report':json.loads(capture.getvalue()),'umask':os.umask(mask)}))
sys.exit(result)
"""
        for mask in (0o400, 0o600):
            with self.subTest(mask=oct(mask)):
                root, naos, configured = self.fixture()
                before = self.snapshot(naos)
                paths = [naos / name for name, value in before.items() if value is not None]
                identities = [(p.stat().st_ino, p.stat().st_mode, p.stat().st_mtime_ns) for p in paths]
                result = subprocess.run(
                    [sys.executable, "-B", "-c", program, str(root), configured, str(KIT), oct(mask),
                     str(self.base / ("refusal-" + str(mask) + ".json"))],
                    capture_output=True, text=True, check=False, timeout=30,
                    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("last observed location:", result.stderr)
                self.assertIn("foreign occupant", result.stderr)
                output = json.loads(result.stdout)
                self.assertEqual(output["umask"], mask)
                self.assertEqual(output["report"]["status"], "invalid_task_lifecycle")
                self.assertFalse(output["report"]["mutated"])
                self.assertIn("owner-read", output["report"]["findings"][0]["message"])
                self.assertEqual(self.snapshot(naos), before)
                self.assertEqual([(p.stat().st_ino, p.stat().st_mode, p.stat().st_mtime_ns) for p in paths],
                                 identities)
                retained = list(naos.rglob(".naos-trace-*.tmp"))
                self.assertEqual(len(retained), 1)
                self.assertIn(str(retained[0]), result.stderr)

    def test_completion_preserves_exact_card_registry_text_and_prior_history(self):
        for sidecar in (False, True):
            with self.subTest(sidecar=sidecar):
                root, naos, configured = self.fixture(sidecar=sidecar)
                before = self.snapshot(naos)
                if os.name == "posix":
                    (naos / "TASK_REGISTRY.yaml").chmod(0o444)
                report = self.complete(root, configured)
                self.assertEqual(report["status"], "completed")
                self.assertFalse(report["verification_prerequisites_met"])
                self.assertTrue(report["human_review_required"])
                self.assertFalse((naos / "active/T-901_story.md").exists())
                self.assertEqual((naos / "completed/T-901_story.md").read_bytes(),
                                 before["active/T-901_story.md"])
                current = (naos / "TASK_REGISTRY.yaml").read_bytes()
                self.assertTrue(current.startswith("# Café registry stays\r\n".encode()))
                self.assertIn(b"priority: P1 # retain this comment\r\n", current)
                history = yaml.safe_load((naos / "completed_history.yaml").read_bytes())
                self.assertEqual(history["records"][0],
                                 {"task_id": "T-900", "fixture": "preserve this prior record"})
                self.assertEqual(history["records"][-1]["task_id"], "T-901")
                if os.name == "posix":
                    mask = os.umask(0)
                    os.umask(mask)
                    self.assertEqual(stat.S_IMODE((naos / "TASK_REGISTRY.yaml").stat().st_mode),
                                     0o666 & ~mask)


if __name__ == "__main__":
    unittest.main()
