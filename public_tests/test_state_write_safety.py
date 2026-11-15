"""G1: session and claim payload publication rejects filesystem aliases."""
from __future__ import annotations

import contextlib
import errno
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(KIT / "scripts"))
import naos_session_identity as SESSION  # noqa: E402
import naos_task_claims as CLAIMS  # noqa: E402
import naos_trace_atomic_write as ATOMIC  # noqa: E402
import naos_windows_report as NATIVE  # noqa: E402
from naos_policy import write_text_output  # noqa: E402


class StateWriteSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-state-write-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.project = self.base / "project"
        (self.project / "naos/reports").mkdir(parents=True)
        self.victim = self.base / "victim.txt"
        self.original = b"SYNTHETIC OUTSIDE\r\n"
        self.victim.write_bytes(self.original)
        self.data = {"z": "caf\u00e9", "a": [1, 2]}
        self.writers = {"session": SESSION.atomic_write_json, "claims": CLAIMS.atomic_write_yaml}

    def link(self, path, target, *, hard=False, directory=False):
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

    def copied_cli(self):
        for name in ("scripts", "schemas", "policies", "upgrade_contract"):
            source = KIT / name
            if source.is_dir():
                shutil.copytree(source, self.project / name, ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copyfile(KIT / "templates/Makefile.naos", self.project / "Makefile.naos")
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("NAOS_") and key != "PYTHONPATH"}
        env.update(PYTHONDONTWRITEBYTECODE="1", NAOS_FIXED_TIME="2026-10-20T00:00:00Z",
                   NAOS_OPERATOR_ID="synthetic-operator", PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        return env

    def run_copied_cli(self, script, env, *args):
        return subprocess.run([sys.executable, "-B", str(self.project / "scripts" / script),
                               "--profile", "quickstart", *args], cwd=self.project, env=env,
                              capture_output=True, text=True, timeout=30)

    def run_make(self, target, env, *variables):
        make = shutil.which("make")
        if make is None:
            self.skipTest("Make unavailable; copied CLI and native writer cases remain separate")
        return subprocess.run([make, "-f", "Makefile.naos", target, "PYTHON=" + sys.executable,
                               "NAOS_COMMON_ARGS=--profile quickstart", "SESSION_ID=session-synthetic",
                               "OPERATOR_ID=synthetic-operator", "BRANCH=synthetic", *variables],
                              cwd=self.project, env=env, capture_output=True, text=True, timeout=30)

    def assert_make_session_leaf_refusal(self, target):
        if shutil.which("make") is None:
            self.skipTest("Make unavailable; copied CLI and native writer cases remain separate")
        env = self.copied_cli()
        seed = self.run_copied_cli("naos_session_identity.py", env, "--session-id", "session-synthetic", "--json")
        self.assertEqual(seed.returncode, 0, seed.stdout + seed.stderr)
        index = self.project / "naos/sessions_index.json"
        self.victim.write_bytes(index.read_bytes())
        before = self.victim.read_bytes()
        index.unlink()
        self.link(index, self.victim)
        result = self.run_make(target, env, "TASK=T-SYNTHETIC")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.victim.read_bytes(), before)
        self.assertTrue(index.is_symlink())

    def assert_make_claim_leaf_refusal(self, target, task):
        if shutil.which("make") is None:
            self.skipTest("Make unavailable; copied CLI and native writer cases remain separate")
        env = self.copied_cli()
        seed = self.run_copied_cli("naos_task_claims.py", env, "--action", "claim", "--task", "T-SEED",
                                   "--session-id", "session-synthetic", "--branch", "synthetic", "--json")
        self.assertEqual(seed.returncode, 0, seed.stdout + seed.stderr)
        claims = self.project / "naos/task_claims.yaml"
        self.victim.write_bytes(claims.read_bytes())
        before = self.victim.read_bytes()
        claims.unlink()
        self.link(claims, self.victim)
        result = self.run_make(target, env, "TASK=" + task)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.victim.read_bytes(), before)
        self.assertTrue(claims.is_symlink())

    def test_make_session_id_preserves_planted_index_leaf(self):
        self.assert_make_session_leaf_refusal("naos-session-id")

    def test_make_operator_attribution_preserves_planted_index_leaf(self):
        self.assert_make_session_leaf_refusal("naos-operator-attribution")

    def test_make_session_start_preserves_planted_index_leaf(self):
        self.assert_make_session_leaf_refusal("naos-session-start")

    def test_make_session_checkpoint_preserves_planted_index_leaf(self):
        self.assert_make_session_leaf_refusal("naos-session-checkpoint")

    def test_make_session_end_preserves_planted_index_leaf(self):
        self.assert_make_session_leaf_refusal("naos-session-end")

    def test_make_task_claim_preserves_planted_claims_leaf(self):
        self.assert_make_claim_leaf_refusal("naos-task-claim", "T-NEW")

    def test_make_task_release_preserves_planted_claims_leaf(self):
        self.assert_make_claim_leaf_refusal("naos-task-release", "T-SEED")

    def test_copied_claim_list_keeps_history_and_stable_lock_inode(self):
        env = self.copied_cli()
        seed = self.run_copied_cli("naos_task_claims.py", env, "--action", "claim", "--task", "T-SEED", "--json")
        self.assertEqual(seed.returncode, 0, seed.stdout + seed.stderr)
        claims = self.project / "naos/task_claims.yaml"
        lock = self.project / "naos/task_claims.yaml.lock"
        before = claims.read_bytes()
        identity = (lock.stat().st_dev, lock.stat().st_ino)
        result = self.run_copied_cli("naos_task_claims.py", env, "--action", "list", "--json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["claim_count"], 1)
        self.assertEqual(claims.read_bytes(), before)
        self.assertEqual((lock.stat().st_dev, lock.stat().st_ino), identity)

    def test_copied_session_cli_refuses_hardlinked_index(self):
        env = self.copied_cli()
        seed = self.run_copied_cli("naos_session_identity.py", env, "--session-id", "session-synthetic", "--json")
        self.assertEqual(seed.returncode, 0, seed.stdout + seed.stderr)
        target = self.project / "naos/sessions_index.json"
        self.victim.write_bytes(target.read_bytes())
        before = self.victim.read_bytes()
        target.unlink()
        self.link(target, self.victim, hard=True)
        inode = target.stat().st_ino
        result = self.run_copied_cli("naos_session_identity.py", env, "--session-id", "session-synthetic", "--json")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.victim.read_bytes(), before)
        self.assertEqual(target.stat().st_ino, inode)
        self.assertEqual(target.stat().st_nlink, 2)

    def test_copied_claim_cli_refuses_hardlinked_history(self):
        env = self.copied_cli()
        seed = self.run_copied_cli("naos_task_claims.py", env, "--action", "claim", "--task", "T-SEED", "--json")
        self.assertEqual(seed.returncode, 0, seed.stdout + seed.stderr)
        target = self.project / "naos/task_claims.yaml"
        self.victim.write_bytes(target.read_bytes())
        before = self.victim.read_bytes()
        target.unlink()
        self.link(target, self.victim, hard=True)
        inode = target.stat().st_ino
        result = self.run_copied_cli("naos_task_claims.py", env, "--action", "claim", "--task", "T-NEW", "--json")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.victim.read_bytes(), before)
        self.assertEqual(target.stat().st_ino, inode)
        self.assertEqual(target.stat().st_nlink, 2)

    def test_both_writers_refuse_hardlinked_leaf_without_replacing_it(self):
        for name, writer in self.writers.items():
            with self.subTest(writer=name):
                target = self.project / (name + ".data")
                self.link(target, self.victim, hard=True)
                before = target.stat()
                with self.assertRaises((OSError, ValueError)):
                    writer(target, self.data)
                self.assertEqual(self.victim.read_bytes(), self.original)
                self.assertEqual(target.read_bytes(), self.original)
                self.assertEqual(target.stat().st_ino, before.st_ino)

    def test_both_writers_refuse_symlink_leaf(self):
        for name, writer in self.writers.items():
            with self.subTest(writer=name):
                target = self.project / (name + ".data")
                self.link(target, self.victim)
                with self.assertRaises((OSError, ValueError)):
                    writer(target, self.data)
                self.assertTrue(target.is_symlink())
                self.assertEqual(self.victim.read_bytes(), self.original)

    def test_dangling_leaf_is_refused_without_creating_referent(self):
        missing = self.base / "not-created"
        for name, writer in self.writers.items():
            with self.subTest(writer=name):
                target = self.project / (name + ".data")
                self.link(target, missing)
                with self.assertRaises((OSError, ValueError)):
                    writer(target, self.data)
                self.assertFalse(missing.exists())
                self.assertTrue(target.is_symlink())

    def test_parent_alias_cannot_create_outside_children(self):
        outside = self.base / "outside"
        outside.mkdir()
        alias = self.project / "alias"
        self.link(alias, outside, directory=True)
        for name, writer in self.writers.items():
            with self.subTest(writer=name):
                with self.assertRaises((OSError, ValueError)):
                    writer(alias / name / "target.data", self.data)
                self.assertEqual(list(outside.iterdir()), [])

    def test_claims_preoccupied_legacy_temporary_hardlink_cannot_change_victim(self):
        target = self.project / "claims.yaml"
        temporary = target.with_name(f".{target.name}.{os.getpid()}.01234567.tmp")
        self.link(temporary, self.victim, hard=True)
        with patch.object(CLAIMS.uuid, "uuid4", return_value=SimpleNamespace(hex="01234567" * 4)):
            CLAIMS.atomic_write_yaml(target, self.data)
        self.assertEqual(self.victim.read_bytes(), self.original)
        self.assertEqual(temporary.read_bytes(), self.original)
        self.assertEqual(target.stat().st_nlink, 1)
        self.assertEqual(yaml.safe_load(target.read_bytes()), self.data)

    def test_new_staging_collision_does_not_truncate_a_foreign_file(self):
        for name, writer in self.writers.items():
            with self.subTest(writer=name):
                prefix = ".naos-report" if os.name == "nt" else ".naos-trace"
                stage = self.project / f"{prefix}-{os.getpid()}-0123456789abcdef.tmp"
                if stage.exists():
                    stage.unlink()
                self.link(stage, self.victim, hard=True)
                target = self.project / (name + ".data")
                with patch.object(ATOMIC.secrets, "token_hex", return_value="0123456789abcdef"):
                    with self.assertRaises(FileExistsError):
                        writer(target, self.data)
                self.assertFalse(target.exists())
                self.assertEqual(self.victim.read_bytes(), self.original)
                self.assertEqual(stage.read_bytes(), self.original)

    @unittest.skipUnless(os.name == "posix", "held POSIX stage substitution; native aliases tested separately")
    def test_stage_substitution_before_publication_preserves_foreign_name(self):
        for name, writer in self.writers.items():
            with self.subTest(writer=name):
                target = self.project / (name + ".data")
                target.write_bytes(b"old payload")
                native_fsync = os.fsync
                foreign = []

                def exchange(descriptor):
                    native_fsync(descriptor)
                    stage, = self.project.glob("*.tmp")
                    stage.rename(self.project / (name + ".held"))
                    self.link(stage, self.victim, hard=True)
                    foreign.append(stage)

                with patch.object(os, "fsync", side_effect=exchange):
                    with self.assertRaises((OSError, ValueError)):
                        writer(target, self.data)
                self.assertEqual(target.read_bytes(), b"old payload")
                self.assertEqual(self.victim.read_bytes(), self.original)
                self.assertEqual(foreign[0].read_bytes(), self.original)
                foreign[0].unlink()

    def test_serialization_and_parent_creation_remain(self):
        for name, writer in self.writers.items():
            with self.subTest(writer=name):
                target = self.project / name / "nested/target.data"
                writer(target, self.data)
                expected = ((json.dumps(self.data, indent=2, sort_keys=True) + "\n") if name == "session"
                            else yaml.safe_dump(self.data, sort_keys=False).replace("\n", os.linesep))
                self.assertEqual(target.read_bytes(), expected.encode("utf-8"))
                self.assertEqual(list(target.parent.glob("*.tmp")), [])

    @unittest.skipUnless(os.name == "posix", "POSIX mode behavior; Windows has native security")
    def test_session_keeps_private_mode_reset_and_claims_preserve_existing_mode(self):
        session = self.project / "index.json"
        claims = self.project / "claims.yaml"
        for target in (session, claims):
            target.write_bytes(b"old payload")
            target.chmod(0o440)
        SESSION.atomic_write_json(session, self.data)
        CLAIMS.atomic_write_yaml(claims, self.data)
        self.assertEqual(stat.S_IMODE(session.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(claims.stat().st_mode), 0o440)

    @unittest.skipUnless(os.name == "posix", "POSIX creation umask behavior")
    def test_session_creation_keeps_umask_or_refuses_unverifiable_owner_read(self):
        for mask in (0o200, 0o400, 0o600):
            with self.subTest(mask=oct(mask)):
                target = self.project / ("mask-" + str(mask) + ".json")
                before_stages = set(self.project.glob(".naos-trace-*.tmp"))
                result, report = self._session_umask_result(target, mask)
                self.assertEqual(report["umask"], mask)
                if mask & 0o400:
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn("Refusing publication", report["error"])
                    self.assertIn("owner-read", report["error"])
                    self.assertFalse(target.exists())
                    after_stages = set(self.project.glob(".naos-trace-*.tmp"))
                    self.assertEqual(len(after_stages - before_stages), 1)
                    self.assertTrue(before_stages <= after_stages)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600 & ~mask)

    def _session_umask_result(self, target, mask):
        command = (
            "import json,os,sys\nfrom pathlib import Path\n"
            "sys.path.insert(0,sys.argv[1])\nimport naos_session_identity as s\n"
            "mask=int(sys.argv[3]);os.umask(mask)\nreport={}\n"
            "try:\n s.atomic_write_json(Path(sys.argv[2]),{'synthetic':True})\n"
            "except (OSError,ValueError) as exc:\n report['error']=str(exc)\n"
            "report['umask']=os.umask(mask)\nprint(json.dumps(report))\n"
            "sys.exit(2 if 'error' in report else 0)\n"
        )
        result = subprocess.run([sys.executable, "-B", "-c", command, str(KIT / "scripts"), str(target), str(mask)],
                                cwd=self.project, capture_output=True, text=True, timeout=20)
        report = json.loads(result.stdout)
        if "error" in report and mask & 0o400:
            self.assertIn("last observed location:", result.stderr)
            self.assertIn("foreign occupant", result.stderr)
        else:
            self.assertEqual(result.stderr, "")
        return result, report

    @unittest.skipUnless(os.name == "posix", "POSIX owner-read masking refusal")
    def test_session_owner_read_refusal_preserves_existing_file_and_umask(self):
        target = self.project / "existing-index.json"
        target.write_bytes(b"prior session index")
        target.chmod(0o600)
        before = target.stat()
        for mask in (0o400, 0o600):
            with self.subTest(mask=oct(mask)):
                before_stages = set(self.project.glob(".naos-trace-*.tmp"))
                result, report = self._session_umask_result(target, mask)
                self.assertEqual(result.returncode, 2)
                self.assertIn("Refusing publication", report["error"])
                self.assertIn("owner-read", report["error"])
                self.assertEqual(report["umask"], mask)
                self.assertEqual(target.read_bytes(), b"prior session index")
                after = target.stat()
                self.assertEqual((after.st_ino, after.st_mode, after.st_mtime_ns, after.st_nlink),
                                 (before.st_ino, before.st_mode, before.st_mtime_ns, before.st_nlink))
                after_stages = set(self.project.glob(".naos-trace-*.tmp"))
                self.assertEqual(len(after_stages - before_stages), 1)
                self.assertTrue(before_stages <= after_stages)

    @unittest.skipUnless(os.name == "posix", "POSIX parent-authorized replacement")
    def test_claims_readonly_file_stays_readonly_after_parent_authorized_update(self):
        target = self.project / "claims.yaml"
        target.write_bytes(b"old payload")
        target.chmod(0o400)
        CLAIMS.atomic_write_yaml(target, self.data)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o400)
        self.assertEqual(yaml.safe_load(target.read_bytes()), self.data)

    def test_shared_text_default_serialization_remains_separate(self):
        target = self.project / "ordinary.txt"
        target.write_bytes(b"old")
        target.chmod(0o640)
        write_text_output(target, "caf\u00e9\n")
        self.assertEqual(target.read_bytes(), ("caf\u00e9" + os.linesep).encode("utf-8"))
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)

    def test_state_options_validate_before_filesystem_changes(self):
        cases = ({"posix_creation_mode": True}, {"posix_creation_mode": 0o777},
                 {"preserve_existing_posix_mode": False}, {"preserve_existing_posix_mode": 0},
                 {"retry_windows_sharing": 1}, {"cleanup_error_note": ""})
        for options in cases:
            with self.subTest(options=options):
                target = self.project / "invalid-options/target.txt"
                with self.assertRaises(ValueError):
                    write_text_output(target, "never published", **options)
                self.assertFalse(target.parent.exists())

    def test_native_retry_understands_native_errors_and_keeps_exact_cap(self):
        for code in (5, 32, 33, 1314):
            with self.subTest(code=code):
                failure = NATIVE.wh.WindowsHandleError("NtSetInformationFile(FileRenameInformation)", winerror=code)
                action = unittest.mock.Mock(side_effect=failure)
                with patch.object(NATIVE.sys, "platform", "win32"), patch.object(NATIVE.time, "sleep") as sleep:
                    with self.assertRaises(NATIVE.wh.WindowsHandleError) as raised:
                        NATIVE._retry_windows_publication(action, True)
                self.assertIs(raised.exception, failure)
                expected = 4 if code in (5, 32, 33) else 1
                self.assertEqual(action.call_count, expected)
                self.assertEqual([call.args[0] for call in sleep.call_args_list], [0.05, 0.1, 0.2][:expected - 1])

    def test_opt_in_cleanup_preserves_primary_error_across_native_stack_close(self):
        primary = PermissionError("synthetic publication refusal")
        cleanup = OSError("synthetic parent close failure")
        with self.assertRaises(PermissionError) as raised:
            with NATIVE._CleanupStack("Session cleanup failed") as stack:
                stack.callback(unittest.mock.Mock(side_effect=cleanup))
                raise primary
        self.assertIs(raised.exception, primary)
        self.assertEqual(primary.__notes__, ["Session cleanup failed: OSError"])

    def test_cleanup_cancellation_is_not_silenced_by_an_earlier_error(self):
        for native in (False, True):
            with self.subTest(native=native):
                primary = PermissionError("synthetic prior failure")
                cancelled = unittest.mock.Mock(side_effect=KeyboardInterrupt("cancelled cleanup"))
                with self.assertRaises(KeyboardInterrupt):
                    if native:
                        with NATIVE._CleanupStack("Session cleanup failed") as stack:
                            stack.callback(cancelled)
                            raise primary
                    else:
                        ATOMIC._run_cleanup(cancelled, primary, "Session cleanup failed")
                self.assertFalse(hasattr(primary, "__notes__"))


@unittest.skipUnless(os.name == "posix", "POSIX shared-writer failure retention")
class FailedSharedPublicationRetentionTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-failed-publication-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        target = root / "report.txt"
        target.write_bytes(b"original report")
        return root, target

    def test_post_qualification_substitution_cannot_delete_foreign_file_or_link(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink):
                root, target = self.fixture()
                foreign = root / "foreign"
                if symlink:
                    foreign.symlink_to(target)
                else:
                    foreign.write_bytes(b"foreign occupant")
                foreign_identity = (foreign.lstat().st_dev, foreign.lstat().st_ino)
                real_matches = ATOMIC._stage_name_matches
                real_unlink = ATOMIC.os.unlink
                moved = []

                def substitute_after_check(parent, name, descriptor):
                    accepted = real_matches(parent, name, descriptor)
                    if accepted:
                        stage = root / name
                        stage.rename(root / "held-stage-moved")
                        foreign.rename(stage)
                        moved.append(stage)
                    return accepted

                failure = OSError("synthetic prepublication failure")
                self.assertTrue(ATOMIC._secure_directory_fd_writes_supported())
                with patch.object(ATOMIC, "_stage_name_matches", side_effect=substitute_after_check), \
                        patch.object(ATOMIC, "_secure_directory_fd_writes_supported", return_value=True), \
                        patch.object(ATOMIC.os, "unlink", wraps=real_unlink) as unlink, \
                        patch.object(ATOMIC.os, "fsync", side_effect=failure), \
                        contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(OSError) as raised:
                        ATOMIC.publish_trace(target, b"new report", b"original report")
                self.assertIs(raised.exception, failure)
                # The old cleanup invokes the substitution and deletes its victim.
                # Removing that entire sink also leaves the original canary alone.
                location = moved[0] if moved else foreign
                self.assertTrue(location.is_symlink() if symlink else location.is_file())
                self.assertEqual((location.lstat().st_dev, location.lstat().st_ino), foreign_identity)
                self.assertEqual(target.read_bytes(), b"original report")
                unlink.assert_not_called()

    def test_foreign_occupant_already_substituted_before_failure_is_preserved(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink):
                root, target = self.fixture()
                named = []
                failure = OSError("synthetic failure after substitution")

                def replace_then_fail(_descriptor):
                    stage = next(root.glob(".naos-trace-*.tmp"))
                    stage.rename(root / "held-stage-moved")
                    if symlink:
                        stage.symlink_to(target)
                    else:
                        stage.write_bytes(b"foreign occupant")
                    named.append(stage)
                    raise failure

                stderr = io.StringIO()
                with patch.object(ATOMIC.os, "fsync", side_effect=replace_then_fail), \
                        contextlib.redirect_stderr(stderr):
                    with self.assertRaises(OSError) as raised:
                        ATOMIC.publish_trace(target, "new report", b"original report")
                self.assertIs(raised.exception, failure)
                self.assertEqual(target.read_bytes(), b"original report")
                if symlink:
                    self.assertTrue(named[0].is_symlink())
                    self.assertEqual(named[0].readlink(), target)
                else:
                    self.assertEqual(named[0].read_bytes(), b"foreign occupant")
                self.assertIn(str(named[0]), stderr.getvalue())
                self.assertIn("last observed", stderr.getvalue())
                self.assertIn("foreign", stderr.getvalue())

    def test_text_bytes_and_binary_callback_failures_retain_unpublished_stages(self):
        for kind in ("text", "bytes", "produce", "validate"):
            for create_only in (False, True):
                with self.subTest(kind=kind, create_only=create_only):
                    root, target = self.fixture()
                    if create_only:
                        target.unlink()
                    failure = OSError("synthetic payload failure")

                    def produce(stream):
                        stream.write(b"partial binary")
                        if kind == "produce":
                            raise failure

                    def validate(_stream):
                        if kind == "validate":
                            raise failure

                    content = ("new report" if kind == "text" else b"new report")
                    if kind in ("produce", "validate"):
                        content = ATOMIC.BinaryProducer(produce, validate)
                    stderr = io.StringIO()
                    failure_seam = (patch.object(ATOMIC.os, "fsync", side_effect=failure)
                                    if kind in ("text", "bytes") else contextlib.nullcontext())
                    options = {"create_only": True} if create_only else {"observe_current": True}
                    with failure_seam, contextlib.redirect_stderr(stderr):
                        with self.assertRaises(OSError) as raised:
                            ATOMIC.publish_trace(target, content, None, **options)
                    self.assertIs(raised.exception, failure)
                    stages = list(root.glob(".naos-trace-*.tmp"))
                    self.assertEqual(len(stages), 1)
                    if create_only:
                        self.assertFalse(target.exists())
                    else:
                        self.assertEqual(target.read_bytes(), b"original report")
                    self.assertIn(str(stages[0]), stderr.getvalue())
                    self.assertTrue(any(str(stages[0]) in note for note in failure.__notes__))

    def test_cancellation_and_failed_diagnostic_still_close_all_held_descriptors(self):
        root, target = self.fixture()
        failure = KeyboardInterrupt("synthetic payload cancellation")
        observed_descriptors = set()
        metadata = ATOMIC._metadata_module()
        original_observe = metadata.observe_created_file_metadata_fd
        original_parent = ATOMIC._open_report_parent_fd

        def observe(descriptor):
            observed_descriptors.add(descriptor)
            return original_observe(descriptor)

        def parent(*args, **kwargs):
            descriptor, name = original_parent(*args, **kwargs)
            observed_descriptors.add(descriptor)
            return descriptor, name

        def produce(stream):
            stream.write(b"partial")
            raise failure

        class BrokenStderr:
            def write(self, _text):
                raise OSError("diagnostic sink unavailable")

        with patch.object(metadata, "observe_created_file_metadata_fd", side_effect=observe), \
                patch.object(ATOMIC, "_open_report_parent_fd", side_effect=parent), \
                contextlib.redirect_stderr(BrokenStderr()):
            with self.assertRaises(KeyboardInterrupt) as raised:
                ATOMIC.publish_trace(target, ATOMIC.BinaryProducer(produce, lambda _stream: None),
                                     None, observe_current=True)
        self.assertIs(raised.exception, failure)
        self.assertGreaterEqual(len(observed_descriptors), 3)
        for descriptor in observed_descriptors:
            with self.assertRaises(OSError) as closed:
                os.fstat(descriptor)
            self.assertEqual(closed.exception.errno, errno.EBADF)
        self.assertEqual(target.read_bytes(), b"original report")
        self.assertEqual(len(list(root.glob(".naos-trace-*.tmp"))), 1)
        self.assertTrue(any("last observed" in note for note in failure.__notes__))

    def test_pre_stage_refusal_has_no_retention_diagnostic(self):
        root, target = self.fixture()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(FileExistsError) as raised:
            ATOMIC.publish_trace(target, b"new report", None, create_only=True)
        self.assertEqual(stderr.getvalue(), "")
        self.assertFalse(hasattr(raised.exception, "__notes__"))
        self.assertEqual(list(root.glob(".naos-trace-*.tmp")), [])
        self.assertEqual(target.read_bytes(), b"original report")

    def test_published_output_survives_parent_sync_failure_without_retention_claim(self):
        root, target = self.fixture()
        failure = OSError("synthetic parent sync failure")
        real_sync = ATOMIC.os.fsync

        def sync(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise failure
            return real_sync(descriptor)

        stderr = io.StringIO()
        with patch.object(ATOMIC.os, "fsync", side_effect=sync), contextlib.redirect_stderr(stderr):
            with self.assertRaises(OSError) as raised:
                ATOMIC.publish_trace(target, b"complete output", b"original report", fsync_parent=True)
        self.assertIs(raised.exception, failure)
        self.assertEqual(target.read_bytes(), b"complete output")
        self.assertEqual(list(root.glob(".naos-trace-*.tmp")), [])
        self.assertEqual(stderr.getvalue(), "")
        self.assertFalse(hasattr(failure, "__notes__"))


if __name__ == "__main__":
    unittest.main()
