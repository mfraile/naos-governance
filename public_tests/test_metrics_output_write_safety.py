"""Metrics publication refuses aliases while preserving legacy text bytes."""

from __future__ import annotations

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


KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
EPOCH = 1792411200
STAMP = "snapshot_20261019_120000.json"
SNAPSHOT = {
    "generated_at": EPOCH, "version": "1.0.0", "tasks_total": 2, "tasks_done": 1,
    "tasks_in_progress": 0, "tasks_planned": 1, "tasks_deferred": 0,
    "tasks_unsupported_legacy_status": 0, "completion_pct": 50.0,
    "requirements_total": 2, "requirements_delivered": 1, "requirements_pct": 50.0,
}
REGISTRY = """tasks:
  - id: T-901
    requirement: FR-901
    status: verified
    lifecycle_state: completed
    delivery_state: delivered
    verification_state: verified
  - id: T-902
    requirement: FR-902
    status: planned
"""


class MetricsOutputWriteSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-metrics-output-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.project = self.base / "project"
        self.project.mkdir()
        shutil.copytree(KIT / "scripts", self.project / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(KIT / "schemas", self.project / "schemas")
        shutil.copytree(KIT / "templates/structural-seeds", self.project / "templates/structural-seeds")
        metadata = self.project / "scripts/naos_posix_metadata"
        metadata.mkdir()
        for name in ("security.py", "linux_primitives.py"):
            shutil.copy2(KIT / "upgrade_contract" / name, metadata / name)
        shutil.copy2(KIT / "upgrade_contract/windows_handles.py", self.project / "scripts/naos_windows_handles.py")
        (self.project / "naos").mkdir()
        (self.project / "naos/TASK_REGISTRY.yaml").write_text(REGISTRY, encoding="utf-8")
        self.out = self.project / "snapshots"
        self.out.mkdir()
        self.paths = {"stamped": self.out / STAMP, "latest": self.project / "latest.json",
                      "trend": self.project / "trend.md"}
        self.victim = self.base / "outside.txt"
        self.original = b"SYNTHETIC OUTSIDE\r\n"
        self.env = {**os.environ, "NAOS_ROOT": "naos", "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
        self.env.pop("PYTHONPATH", None)

    def run_metrics(self, *, out=None, latest=None, trend=None, previous=None, locale=None,
                    utf8=None, legacy_reference=False, encoding_override=None):
        arguments = ["metrics", "--out-dir", str(out or self.out),
                     "--output-json", str(latest or self.paths["latest"])]
        if trend is not False:
            arguments += ["--trend-md", str(trend or self.paths["trend"])]
        if previous is not None:
            arguments += ["--prev", str(previous)]
        script = str(self.project / "scripts/workflows/metrics_snapshot.py")
        code = "import io,json,locale,os,pathlib,runpy,sys,time\n"
        if locale:
            code += ("try: locale.setlocale(locale.LC_CTYPE, '')\n"
                     "except locale.Error: sys.exit(77)\n")
        code += f"time.time=lambda:{EPOCH}\nsys.argv={arguments!r}\nm=runpy.run_path({script!r})\n"
        if encoding_override:
            code += f"io.text_encoding=lambda encoding,stacklevel=2: encoding if encoding is not None else {encoding_override!r}\n"
        if legacy_reference:
            code += (
                "curr=m['collect_snapshot']()\n"
                "pathlib.Path('legacy.json').write_text(json.dumps(curr,indent=2))\n"
                "with pathlib.Path('legacy.json').open() as f: print('LEGACY_ENCODING='+f.encoding)\n"
                "pathlib.Path('legacy.md').write_text(m['render_trend_md'](m['compute_trend'](curr,None)))\n"
            )
        code += "m['main']()\n"
        env = dict(self.env)
        if locale:
            env.update(LC_ALL=locale, PYTHONCOERCECLOCALE="0")
        if utf8 is not None:
            env["PYTHONUTF8"] = str(utf8)
        return subprocess.run([sys.executable, "-B", "-c", code], cwd=self.project, env=env,
                              capture_output=True, text=True, check=False, timeout=60)

    def link(self, output, *, hard=False):
        if hard:
            os.link(self.victim, output)
        else:
            try:
                output.symlink_to(self.victim)
            except OSError as exc:
                if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                    self.skipTest("Native Windows symlink privilege unavailable")
                raise

    def directory_alias(self, alias, target):
        if os.name == "nt":
            result = subprocess.run([os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", "mklink", "/J",
                                     str(alias), str(target)], capture_output=True, text=True, check=False, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            alias.symlink_to(target, target_is_directory=True)

    def clear_outputs(self):
        for path in self.paths.values():
            path.unlink(missing_ok=True)

    def test_all_three_sinks_refuse_leaf_aliases(self):
        for hard in (True, False):
            for sink, path in self.paths.items():
                with self.subTest(sink=sink, hard=hard):
                    self.clear_outputs()
                    self.victim.write_bytes(self.original)
                    self.link(path, hard=hard)
                    try:
                        result = self.run_metrics()
                        self.assertEqual(self.victim.read_bytes(), self.original)
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    finally:
                        path.unlink(missing_ok=True)

    def test_all_three_sinks_refuse_linked_parent(self):
        for sink in self.paths:
            with self.subTest(sink=sink):
                outside = self.base / ("outside-" + sink)
                outside.mkdir()
                alias = self.project / ("alias-" + sink)
                self.directory_alias(alias, outside)
                actual = outside / (STAMP if sink == "stamped" else sink)
                actual.write_bytes(self.original)
                options = {"out": alias} if sink == "stamped" else {sink: alias / sink}
                result = self.run_metrics(**options)
                self.assertEqual(actual.read_bytes(), self.original)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_linked_out_directory_does_not_receive_new_children(self):
        outside = self.base / "empty-outside"
        outside.mkdir()
        alias = self.project / "out-alias"
        self.directory_alias(alias, outside)
        result = self.run_metrics(out=alias / "new/nested")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(list(outside.iterdir()), [])

    @unittest.skipUnless(os.name == "posix", "POSIX parent-alias/dotdot semantics")
    def test_canceled_parent_alias_refuses_without_redirect(self):
        for sink in self.paths:
            with self.subTest(sink=sink):
                outside = self.base / ("dotdot-" + sink)
                (outside / "child").mkdir(parents=True)
                alias = self.project / ("dotdot-alias-" + sink)
                alias.symlink_to(outside / "child", target_is_directory=True)
                if sink == "stamped":
                    operand = alias / "../snapshot-dir"
                    actual = outside / "snapshot-dir"
                    actual.mkdir()
                    (actual / STAMP).write_bytes(self.original)
                    lexical = self.project / "snapshot-dir"
                    lexical.mkdir()
                    (lexical / STAMP).write_bytes(self.original)
                    options = {"out": operand}
                    checks = (actual / STAMP, lexical / STAMP)
                else:
                    name = sink + ".txt"
                    checks = (outside / name, self.project / name)
                    for path in checks:
                        path.write_bytes(self.original)
                    options = {sink: alias / ".." / name}
                result = self.run_metrics(**options)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                for path in checks:
                    self.assertEqual(path.read_bytes(), self.original)

    def test_ordinary_bytes_modes_and_timestamp_collision_keep_previous_selection(self):
        for path in self.paths.values():
            path.write_bytes(b"{}")
            path.chmod(0o640)
        result = self.run_metrics()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = json.dumps(SNAPSHOT, indent=2).replace("\n", os.linesep).encode()
        for key in ("stamped", "latest"):
            self.assertEqual(self.paths[key].read_bytes(), expected)
        self.assertTrue(self.paths["trend"].read_text(encoding="utf-8").startswith("# Governance Metrics Snapshot Trend\n"))
        self.assertIn("compared against: " + str(self.paths["stamped"]), result.stdout)
        if os.name == "posix":
            for path in self.paths.values():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
        second = self.run_metrics()
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(self.paths["stamped"].read_bytes(), expected)
        self.assertIn("completion_pct | 50.0 | 50.0 | 0.0 | 0.0 | =", self.paths["trend"].read_text(encoding="utf-8"))

    def test_only_snapshot_out_directory_is_created_and_partial_order_is_retained(self):
        for sink in ("latest", "trend"):
            with self.subTest(sink=sink):
                out = self.project / ("created-" + sink) / "nested"
                missing = self.project / ("missing-" + sink) / "output"
                result = self.run_metrics(out=out, **{sink: missing})
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(missing.parent.exists())
                self.assertTrue((out / STAMP).is_file())
                if sink == "trend":
                    self.assertEqual(json.loads(self.paths["latest"].read_text()), SNAPSHOT)

    def test_native_requested_locale_and_utf8_mode_match_legacy_default_text_io(self):
        for utf8 in (0, 1):
            with self.subTest(utf8=utf8):
                self.clear_outputs()
                result = self.run_metrics(locale="ja_JP.SJIS", utf8=utf8, legacy_reference=True)
                if result.returncode == 77:
                    self.skipTest("Native ja_JP.SJIS locale unavailable")
                encoding = result.stdout.split("LEGACY_ENCODING=", 1)[-1].splitlines()[0]
                if result.returncode and "UnicodeEncodeError" in result.stderr:
                    self.assertEqual(utf8, 0, result.stdout + result.stderr)
                    candidate = self.run_metrics(locale="ja_JP.SJIS", utf8=utf8)
                    self.assertNotEqual(candidate.returncode, 0, candidate.stdout + candidate.stderr)
                    self.assertIn("UnicodeEncodeError", candidate.stderr)
                    self.assertEqual(self.paths["latest"].read_bytes(), (self.project / "legacy.json").read_bytes())
                    self.assertTrue(self.paths["stamped"].is_file())
                    self.assertFalse(self.paths["trend"].exists())
                    continue
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.paths["latest"].read_bytes(), (self.project / "legacy.json").read_bytes())
                self.assertEqual(self.paths["trend"].read_bytes(), (self.project / "legacy.md").read_bytes())
                payload = self.paths["trend"].read_bytes()
                self.assertIn("Δ".encode(encoding), payload)

    def test_omitted_optional_trend_preserves_an_unused_alias(self):
        self.victim.write_bytes(self.original)
        self.link(self.paths["trend"], hard=True)
        result = self.run_metrics(trend=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.victim.read_bytes(), self.original)
        self.assertNotIn("trend markdown:", result.stdout)

    def test_controlled_utf16_default_matches_legacy_io_with_bom(self):
        result = self.run_metrics(encoding_override="utf-16", legacy_reference=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for key, reference in (("latest", "legacy.json"), ("trend", "legacy.md")):
            self.assertEqual(self.paths[key].read_bytes(), (self.project / reference).read_bytes())
            self.assertTrue(self.paths[key].read_bytes().startswith((b"\xff\xfe", b"\xfe\xff")))

    def test_unrepresentable_default_encoding_keeps_error_after_json_outputs(self):
        result = self.run_metrics(encoding_override="ascii")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("UnicodeEncodeError", result.stderr)
        self.assertEqual(result.stdout, "")
        for key in ("stamped", "latest"):
            self.assertEqual(json.loads(self.paths[key].read_text(encoding="ascii")), SNAPSHOT)

    def test_explicit_previous_precedes_automatic_selection(self):
        self.paths["stamped"].write_text(json.dumps(SNAPSHOT), encoding="utf-8")
        previous = self.project / "previous.json"
        previous.write_text(json.dumps({**SNAPSHOT, "tasks_done": 0, "tasks_planned": 2,
                                        "completion_pct": 0.0, "requirements_delivered": 0,
                                        "requirements_pct": 0.0}), encoding="utf-8")
        result = self.run_metrics(previous=previous)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("compared against: " + str(previous), result.stdout)
        self.assertIn("tasks_done | 1.0 | 0.0 | 1 | - | ▲", self.paths["trend"].read_text(encoding="utf-8"))


class PublicationPayloadAndParentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-metrics-payload-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        sys.path.insert(0, str(KIT / "scripts"))

    def test_non_utf8_payload_is_published_exactly_with_existing_mode(self):
        import naos_trace_atomic_write as atomic
        target = self.root / "encoded.dat"
        target.write_bytes(b"original")
        target.chmod(0o640)
        payload = b"\xff\x00" + "Δ ▲ ▼".encode("shift_jis")
        atomic.publish_trace(target, payload, b"original", strict_parent_topology=True)
        self.assertEqual(target.read_bytes(), payload)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)

    def test_missing_parent_at_publication_is_not_recreated(self):
        import naos_policy as policy
        import naos_trace_atomic_write as atomic
        parent = self.root / "disappears"
        parent.mkdir()
        original = atomic.publish_trace

        def remove_parent(*args, **kwargs):
            parent.rmdir()
            return original(*args, **kwargs)

        with patch.object(atomic, "publish_trace", side_effect=remove_parent):
            with self.assertRaises(OSError):
                policy.write_text_output(parent / "latest.json", "{}", encoding=None, create_parents=False)
        self.assertFalse(parent.exists())

    def test_windows_dispatch_preserves_bytes_and_parent_creation_choice(self):
        import naos_trace_atomic_write as atomic
        import naos_windows_report as native
        target = self.root / "native.dat"
        payload = b"\xff\x00\x83\xa2"
        with patch.object(atomic.os, "name", "nt"), patch.object(native, "write_strict_report") as publish:
            atomic.publish_trace(target, payload, None, create_parents=False)
        self.assertEqual(publish.call_args.args, (target, payload))
        self.assertIs(publish.call_args.kwargs["create_parents"], False)
        self.assertIs(publish.call_args.kwargs["require_existing_write_access"], True)


if __name__ == "__main__":
    unittest.main()
