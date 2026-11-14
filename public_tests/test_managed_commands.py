"""Public CLI lifecycle tests on disposable projects, without external providers.

The tests use the selected source kit (or an exported kit), real CLI subprocesses
and native writers. They do not certify installed wheels or a full host matrix.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

import yaml

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()


def snapshot(root: Path) -> dict:
    result = {}
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        value = (stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode),
                 info.st_ino, info.st_mtime_ns)
        if path.is_symlink():
            value += (os.readlink(path),)
        elif path.is_file():
            value += (path.read_bytes(),)
        result[path.relative_to(root).as_posix()] = value
    return result


def receipts(project: Path) -> set[Path]:
    directory = ("windows-content/receipts" if os.name == "nt"
                 else "managed-content/state/receipts")
    return set((project / ".naos/upgrade-v1" / directory).glob("*.json"))


class ManagedCommandTests(unittest.TestCase):
    def cli(self, *args, expected=0):
        result = subprocess.run(
            [sys.executable, "-B", str(KIT / "cli.py"), *map(str, args)],
            cwd=KIT, input="", text=True, capture_output=True, check=False,
            timeout=300,
        )
        self.assertEqual(result.returncode, expected, (result.stdout + result.stderr)[-6000:])
        self.assertNotIn("Traceback", result.stdout + result.stderr)
        return result

    def initialize(self, base: Path) -> Path:
        project = base / "project"
        result = self.cli("init", project, "--new", "--tier", "quickstart",
                          "--archetype", "custom", "--backend", "static_only",
                          "--memory", "disabled", "--activate")
        self.assertIn("[RECEIPT]", result.stdout)
        return project

    def test_add_preview_apply_repeat_and_collision_refusal(self):
        with tempfile.TemporaryDirectory() as temp:
            project = self.initialize(Path(temp).resolve())
            destination = project / ".github/instructions/configs.instructions.md"
            self.assertFalse(destination.exists())
            before = snapshot(project)
            old_receipts = receipts(project)
            preview = self.cli("add", "instruction", "configs", "--project", project, "--dry-run")
            self.assertIn("Managed-content plan SHA-256" if os.name == "nt" else "[DRY-RUN]",
                          preview.stdout)
            self.assertEqual(snapshot(project), before)
            self.cli("add", "instruction", "configs", "--project", project)
            self.assertEqual(destination.read_bytes(),
                             (KIT / "templates/instructions/configs.instructions.md").read_bytes())
            created_receipts = receipts(project)
            self.assertTrue(old_receipts < created_receipts)
            self.assertEqual(len(created_receipts - old_receipts), 1)
            after = snapshot(project)
            self.cli("add", "instruction", "configs", "--project", project)
            self.assertEqual(snapshot(project), after)
            destination.write_bytes(b"adopter instruction: preserve this exact text\n")
            collision = snapshot(project)
            self.cli("add", "instruction", "configs", "--project", project, expected=2)
            forced = self.cli("add", "instruction", "configs", "--project", project,
                              "--force", expected=2)
            self.assertIn("Legacy blanket --force", forced.stderr)
            self.assertEqual(snapshot(project), collision)
            self.assertEqual(receipts(project), created_receipts)

    def test_upgrade_plan_apply_repeat_and_wrong_approval_refusal(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            project = self.initialize(base)
            adopter = project / "adopter-note.txt"
            adopter.write_bytes(b"keep me\n")
            before = snapshot(project)
            old_receipts = receipts(project)
            plan_path = base / "reviewed-plan.json"
            planned = self.cli("upgrade", project, "--tier", "lite", "--plan-out", plan_path)
            plan = json.loads(planned.stdout)
            self.assertEqual(plan["status"], "ready")
            self.assertEqual(plan_path.read_bytes(), planned.stdout.rstrip("\n").encode())
            self.assertEqual(snapshot(project), before)
            digest = plan["digest_sha256"] if os.name == "nt" else plan["plan_sha256"]
            self.cli("upgrade", project, "--apply-plan", plan_path,
                     "--expect-plan-digest", "0" * 64, expected=3)
            self.assertEqual(snapshot(project), before)
            applied = self.cli("upgrade", project, "--apply-plan", plan_path,
                               "--expect-plan-digest", digest)
            applied_outcome = json.loads(applied.stdout)
            self.assertEqual(applied_outcome["status"], "committed")
            after_receipts = receipts(project)
            self.assertEqual(len(after_receipts - old_receipts), 1)
            self.assertTrue(old_receipts <= after_receipts)
            self.assertEqual(adopter.read_bytes(), b"keep me\n")
            after = snapshot(project)
            repeated = self.cli("upgrade", project, "--apply-plan", plan_path,
                                "--expect-plan-digest", digest)
            repeated_outcome = json.loads(repeated.stdout)
            self.assertEqual(repeated_outcome["status"],
                             "committed" if os.name == "nt" else "already_applied")
            self.assertEqual(repeated_outcome["transaction_id"], applied_outcome["transaction_id"])
            if os.name == "nt":
                self.assertEqual(repeated_outcome["detail"],
                                 "Previously committed operation; no new mutation")
            self.assertEqual(receipts(project), after_receipts)
            self.assertEqual(snapshot(project), after)

    def test_upgrade_selected_kit_drift_is_read_only_refusal(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            project = self.initialize(base)
            rules = project / ".ai/RULES.md"
            rules.write_bytes(rules.read_bytes() + b"\n<!-- adopter conflict -->\n")
            hook = project / ".githooks/pre-commit"
            sentinel = base / "hook-executed"
            hook.write_text(f"#!/bin/sh\ntouch '{sentinel.as_posix()}'\n", encoding="utf-8")
            hook.chmod(0o755)
            before = snapshot(project)
            plan_path = base / "refused-plan.json"
            result = self.cli("upgrade", project, "--tier", "lite",
                              "--plan-out", plan_path, expected=3)
            plan = json.loads(result.stdout)
            self.assertEqual(plan["status"], "refused" if os.name == "nt" else "diagnostic_only")
            if os.name == "nt":
                rows = {Path(item["path"]).as_posix(): item for item in plan["rows"]}
                for path in (".ai/RULES.md", ".githooks/pre-commit"):
                    self.assertEqual(rows[path]["action"], "CONFLICT_PRESERVE")
                digest = plan["digest_sha256"]
            else:
                checks = {item["check_id"]: item["status"] for item in plan["checks"]}
                self.assertEqual(checks["kit_owned_drift"], "blocking")
                rows = {item["path"]: item for item in plan["paths"]}
                for path in (".ai/RULES.md", ".githooks/pre-commit"):
                    self.assertEqual(rows[path]["action"], "CONFLICT_PRESERVE")
                    self.assertFalse(rows[path]["mutation"]["eligible"])
                digest = plan["plan_sha256"]
            self.assertEqual(snapshot(project), before)
            self.assertFalse(sentinel.exists())
            self.cli("upgrade", project, "--apply-plan", plan_path,
                     "--expect-plan-digest", digest, expected=3)
            self.assertEqual(snapshot(project), before)
            self.assertFalse(sentinel.exists())

    def test_memory_preview_apply_and_obsolete_option_refusal(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp).resolve()
            config = project / "configs/naos_memory.yaml"
            config.parent.mkdir()
            config.write_text("adopter_extension:\n  owner: example-team\nmemory: {}\n", encoding="utf-8")
            before = snapshot(project)
            args = ("memory", "setup", "--project-root", project, "--disposition", "defer")
            preview = self.cli(*args)
            self.assertIn("Dry run only", preview.stdout)
            self.assertEqual(snapshot(project), before)
            applied = self.cli(*args, "--write")
            self.assertIn("Wrote", applied.stdout)
            value = yaml.safe_load(config.read_text(encoding="utf-8"))
            self.assertEqual(value["adopter_extension"], {"owner": "example-team"})
            self.assertEqual(value["memory"]["disposition"], "defer")
            self.assertFalse(value["memory"]["enabled"])
            self.assertIn("file-first", applied.stdout)
            current = snapshot(project)
            refused = self.cli(*args, "--store-path", "obsolete-store", "--write", expected=2)
            self.assertIn("refusing to write while --store-path is supplied", refused.stdout)
            self.assertEqual(snapshot(project), current)


if __name__ == "__main__":
    unittest.main()
