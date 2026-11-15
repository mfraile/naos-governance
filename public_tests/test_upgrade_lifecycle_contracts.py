"""K4 public native lifecycles on freshly generated synthetic histories.

No private test imports, captured native metadata, Git repositories, provider
requests or invocation-policy changes. Windows exercises its implemented hook
refusal; successful POSIX mode reconciliation is checked on macOS and Ubuntu.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path[:0] = [str(KIT), str(KIT / "public_tests")]

import managed_upgrade_fixtures as fixture  # noqa: E402
from upgrade_contract import hook_activation as hook  # noqa: E402
from upgrade_contract import legacy_migration_progress as migration_progress  # noqa: E402
from upgrade_contract import legacy_migration_records as migration  # noqa: E402
from upgrade_contract import portable_provenance as pp  # noqa: E402
from upgrade_contract import rebind_records  # noqa: E402

CRASH_AFTER_PREPARATION = """import importlib,os,sys
sys.path.insert(0,sys.argv[1])
import naos_upgrade
family=sys.argv[2]
adapter=importlib.import_module('upgrade_contract.public_'+family)
name='prepare_legacy_migration' if family=='migration' else 'prepare_absent_store_rebind'
original=getattr(adapter.preparation,name)
def stop(*args,**kwargs):
 original(*args,**kwargs)
 os._exit(73)
setattr(adapter.preparation,name,stop)
sys.argv=[naos_upgrade.__file__,*sys.argv[3:]]
sys.exit(naos_upgrade.main())
"""


class UpgradeLifecycleTests(unittest.TestCase):
    def setUp(self):
        owner = tempfile.TemporaryDirectory(prefix="naos-k4-")
        self.addCleanup(fixture.cleanup_owned_temp, owner)
        self.base = Path(owner.name).resolve()

    def cli(self, root, *args, expected=0, crash=None):
        argv = ([sys.executable, "-B", "-c", CRASH_AFTER_PREPARATION, str(KIT), crash,
                 str(root), *map(str, args)] if crash else
                [sys.executable, "-B", str(KIT / "cli.py"), "upgrade", str(root), *map(str, args)])
        result = subprocess.run(argv, cwd=KIT, input="", text=True, capture_output=True,
                                check=False, timeout=300)
        self.assertEqual(result.returncode, expected, (result.stdout + result.stderr)[-6000:])
        self.assertNotIn("Traceback", result.stdout + result.stderr)
        return result

    def external_plan(self, root, name, *args):
        path = self.base / f"{name}.json"
        before = fixture.tree(root)
        result = self.cli(root, *args, "--plan-out", path)
        self.assertEqual(fixture.tree(root), before)
        self.assertEqual(result.stdout.rstrip("\n").encode(), path.read_bytes())
        return path, fixture.sha(path.read_bytes())

    def migration_plan(self, seed):
        return self.external_plan(seed.root, "migration-plan", "--plan-migration",
                                  "--migration-inputs", seed.inputs_file)

    def assert_legacy_history(self, seed, *, rolled_back=False):
        pointer = migration._FENCE_POINTER[seed.source_format]
        for path, raw in seed.archive.items():
            actual = (migration_progress.RETAINED if path == pointer and not rolled_back else path)
            self.assertEqual(fixture.io_path(seed.root / actual).read_bytes(), raw, actual)
        for path, raw in seed.contents.items():
            self.assertEqual(fixture.io_path(seed.root / path).read_bytes(), raw, path)

    def rebind_plan(self, seed):
        return self.external_plan(seed.root, "rebind-plan", "--plan-rebind",
                                  "--expected-owner-sha256", seed.snapshot.owner_sha256,
                                  "--expected-head-sha256", seed.snapshot.manifest_sha256,
                                  "--binding-id", "b" * 32)

    def test_native_migration_plan_apply_refusal_and_terminal_recovery(self):
        seed = fixture.native_legacy_seed(self.base, KIT)
        note = seed.root / "adopter-note.txt"
        note.write_bytes(b"independent adopter bytes\n")
        path, digest = self.migration_plan(seed)
        self.assertEqual(json.loads(path.read_bytes())["schema"],
                         "naos.upgrade.legacy_migration_plan.v2")
        before = fixture.tree(seed.root)
        self.cli(seed.root, "--apply-plan", path, "--expect-plan-digest", "0" * 64,
                 "--migration-inputs", seed.inputs_file, expected=3)
        self.assertEqual(fixture.tree(seed.root), before)
        args = ("--apply-plan", path, "--expect-plan-digest", digest,
                "--migration-inputs", seed.inputs_file)
        applied = json.loads(self.cli(seed.root, *args).stdout)
        self.assertEqual((applied["status"], applied["phase"], applied["checkpoint_complete"]),
                         ("committed", "finalized", True))
        self.assert_legacy_history(seed)
        portable = fixture.load_portable(seed.root)
        self.assertEqual(portable.project_id, seed.new_id)
        self.assertEqual(note.read_bytes(), b"independent adopter bytes\n")
        current = fixture.tree(seed.root)
        # Ordinary apply rechecks the original source; the published fence must
        # refuse that fresh planning route. Saved-plan recovery recognizes the
        # completed migration without changing history.
        refused = self.cli(seed.root, *args, expected=3)
        self.assertIn("NOT_APPLIED", refused.stderr)
        self.assertEqual(fixture.tree(seed.root), current)
        recovered = json.loads(self.cli(seed.root, "--recover", *args).stdout)
        self.assertEqual((recovered["status"], recovered["phase"], recovered["checkpoint_complete"]),
                         ("committed", "finalized", True))
        self.assertEqual(fixture.tree(seed.root), current)
        self.assert_legacy_history(seed)

    def test_native_migration_preparation_exit_recovers_original_history(self):
        seed = fixture.native_legacy_seed(self.base, KIT)
        path, digest = self.migration_plan(seed)
        args = ("--apply-plan", path, "--expect-plan-digest", digest,
                "--migration-inputs", seed.inputs_file)
        self.cli(seed.root, *args, crash="migration", expected=73)
        recovered = json.loads(self.cli(seed.root, "--recover", *args).stdout)
        self.assertEqual(recovered["status"], "rolled_back")
        self.assert_legacy_history(seed, rolled_back=True)
        self.assertFalse(fixture.io_path(seed.root / pp.MANIFEST_PATH).exists())
        current = fixture.tree(seed.root)
        self.cli(seed.root, "--recover", *args)
        self.assertEqual(fixture.tree(seed.root), current)

    def test_native_rebind_plan_apply_refusal_and_terminal_recovery(self):
        seed = fixture.portable_seed(self.base, KIT)
        # Actual adopter edits are captured and preserved; the portable base is not restored.
        fixture.io_path(seed.root / seed.path).write_bytes(b"adopter edit\r\n")
        before = fixture.preserved_tree(seed.root)
        path, digest = self.rebind_plan(seed)
        self.assertEqual(json.loads(path.read_bytes())["schema"], rebind_records.PLAN_SCHEMA)
        current = fixture.tree(seed.root)
        self.cli(seed.root, "--apply-plan", path, "--expect-plan-digest", "0" * 64, expected=3)
        self.assertEqual(fixture.tree(seed.root), current)
        self.assertFalse((seed.root / ".naos/local").exists())
        applied = json.loads(self.cli(seed.root, "--apply-plan", path,
                                      "--expect-plan-digest", digest).stdout)
        self.assertEqual(applied["status"], "complete")
        self.assertEqual(fixture.preserved_tree(seed.root), before)
        self.assertEqual(fixture.load_portable(seed.root).manifest_sha256, seed.snapshot.manifest_sha256)
        current = fixture.tree(seed.root)
        self.cli(seed.root, "--recover", "--expect-plan-digest", digest)
        self.assertEqual(fixture.tree(seed.root), current)

    def test_native_rebind_preparation_exit_rolls_back_without_history_changes(self):
        seed = fixture.portable_seed(self.base, KIT)
        before = fixture.preserved_tree(seed.root)
        path, digest = self.rebind_plan(seed)
        self.cli(seed.root, "--apply-plan", path, "--expect-plan-digest", digest,
                 crash="rebind", expected=73)
        recovered = json.loads(self.cli(seed.root, "--recover", "--expect-plan-digest", digest).stdout)
        self.assertEqual(recovered["status"], "rolled_back")
        self.assertEqual(fixture.preserved_tree(seed.root), before)
        current = fixture.tree(seed.root)
        self.cli(seed.root, "--recover", "--expect-plan-digest", digest)
        self.assertEqual(fixture.tree(seed.root), current)

    def test_hook_plan_requires_platform_support_and_exact_reviewed_approval(self):
        seed = fixture.portable_seed(self.base, KIT, hook=True)
        path, digest = self.rebind_plan(seed)
        self.cli(seed.root, "--apply-plan", path, "--expect-plan-digest", digest)
        args = ("--plan-hook-activation", "--hook-mode-octal", "0755",
                "--expected-owner-sha256", seed.snapshot.owner_sha256,
                "--expected-head-sha256", seed.snapshot.manifest_sha256)
        if os.name == "nt":
            before = fixture.tree(seed.root)
            refused = self.cli(seed.root, *args, expected=3)
            self.assertIn("POSIX activation reconciliation only", refused.stderr)
            self.assertEqual(fixture.tree(seed.root), before)
            return
        leaf = seed.root / hook.PATH
        leaf.chmod(0o755)
        path, digest = self.external_plan(seed.root, "hook-plan", *args)
        self.assertEqual(json.loads(path.read_bytes())["operation"], hook.OPERATION)
        current = fixture.tree(seed.root)
        self.cli(seed.root, "--apply-plan", path, "--expect-plan-digest", "0" * 64, expected=3)
        self.assertEqual(fixture.tree(seed.root), current)
        outcome = json.loads(self.cli(seed.root, "--apply-plan", path,
                                      "--expect-plan-digest", digest).stdout)
        self.assertEqual(outcome["status"], "committed")
        after = fixture.load_portable(seed.root)
        self.assertEqual(after.activated_hooks, (hook.PATH,))
        self.assertEqual(after.owner_sha256, seed.snapshot.owner_sha256)
        self.assertEqual(leaf.read_bytes(), seed.data)
        self.assertEqual(leaf.stat().st_mode & 0o7777, 0o755)
        current = fixture.tree(seed.root)
        self.cli(seed.root, "--recover")
        self.assertEqual(fixture.tree(seed.root), current)


if __name__ == "__main__":
    unittest.main()
