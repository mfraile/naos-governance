"""G1: existing projection targets keep their preimages and refuse aliases."""
from __future__ import annotations

import contextlib
import copy
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

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(KIT / "scripts"))
from secure_coding_reporting import projection as PROJECTION  # noqa: E402

SPEC = importlib.util.spec_from_file_location("_g1_projection_cli", KIT / "scripts/naos_secure_coding_reporting.py")
CLI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLI)
REPORT = {"schema": "synthetic", "status": "pass", "summary": {}, "findings": [],
          "dimensions": {}, "limitations": [], "not_claimed": []}


class ProjectionWriteSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-projection-write-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.project = self.base / "project"
        self.project.mkdir()
        self.targets = {"dashboard_summary": self.project / "dashboard.json",
                        "dashboard_markdown": self.project / "DASHBOARD.md",
                        "evidence_pack": self.project / "evidence.json"}
        self.originals = {"dashboard_summary": b'{"existing":"caf\\u00e9"}\r\n',
                          "dashboard_markdown": b"# Existing\r\n\r\n",
                          "evidence_pack": b'{"existing":"pack"}\r\n'}
        for key, path in self.targets.items():
            path.write_bytes(self.originals[key])

    def project_reports(self):
        return PROJECTION.project(report=copy.deepcopy(REPORT), **self.targets)

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

    def assert_static_refusal(self, key):
        result = self.project_reports()
        self.assertEqual(result[key]["state"], "unsafe_target", result)
        for other, path in self.targets.items():
            if other != key:
                self.assertEqual(path.read_bytes(), self.originals[other])
                self.assertEqual(result[other]["state"], "aborted", result)

    def test_every_hardlinked_target_aborts_all_prepared_outputs(self):
        for key, path in self.targets.items():
            with self.subTest(key=key):
                victim = self.base / (key + ".victim")
                victim.write_bytes(self.originals[key])
                path.unlink()
                self.link(path, victim, hard=True)
                try:
                    self.assert_static_refusal(key)
                    self.assertEqual(victim.read_bytes(), self.originals[key])
                finally:
                    path.unlink()
                    path.write_bytes(self.originals[key])

    def test_symlink_leaf_aborts_all_outputs(self):
        key = "evidence_pack"
        path = self.targets[key]
        victim = self.base / "victim.json"
        victim.write_bytes(self.originals[key])
        path.unlink()
        self.link(path, victim)
        self.assert_static_refusal(key)
        self.assertEqual(victim.read_bytes(), self.originals[key])

    def test_dangling_leaf_is_unsafe_and_does_not_create_referent(self):
        path = self.targets["evidence_pack"]
        path.unlink()
        victim = self.base / "not-created.json"
        self.link(path, victim)
        self.assert_static_refusal("evidence_pack")
        self.assertFalse(victim.exists())

    def test_parent_alias_aborts_all_outputs(self):
        outside = self.base / "outside"
        outside.mkdir()
        victim = outside / "evidence.json"
        victim.write_bytes(self.originals["evidence_pack"])
        alias = self.project / "alias"
        self.link(alias, outside, directory=True)
        self.targets["evidence_pack"] = alias / victim.name
        self.assert_static_refusal("evidence_pack")
        self.assertEqual(victim.read_bytes(), self.originals["evidence_pack"])

    def test_missing_target_and_parents_are_not_created(self):
        missing = self.project / "missing/child/evidence.json"
        self.targets["evidence_pack"] = missing
        result = self.project_reports()
        self.assertEqual(result["evidence_pack"]["state"], "not_configured")
        self.assertFalse(missing.parent.parent.exists())
        self.assertTrue(result["dashboard_summary"]["updated"])

    def test_changed_preimage_is_not_overwritten_after_preflight(self):
        target = self.targets["dashboard_summary"]
        original_write = PROJECTION.safe_write_text

        def changed(path, text, **kwargs):
            target.write_bytes(b'{"newer":"preserve"}\n')
            return original_write(path, text, **kwargs)

        with patch.object(PROJECTION, "safe_write_text", side_effect=changed):
            with self.assertRaises((OSError, ValueError)):
                self.project_reports()
        self.assertEqual(target.read_bytes(), b'{"newer":"preserve"}\n')
        self.assertEqual(self.targets["evidence_pack"].read_bytes(), self.originals["evidence_pack"])

    def test_deleted_preimage_is_not_recreated_after_preflight(self):
        target = self.targets["dashboard_summary"]
        original_write = PROJECTION.safe_write_text

        def removed(path, text, **kwargs):
            target.unlink()
            return original_write(path, text, **kwargs)

        with patch.object(PROJECTION, "safe_write_text", side_effect=removed):
            with self.assertRaises((OSError, ValueError)):
                self.project_reports()
        self.assertFalse(target.exists())

    def test_late_hardlink_is_refused_without_victim_mutation(self):
        target = self.targets["dashboard_summary"]
        victim = self.base / "late-victim.json"
        victim.write_bytes(self.originals["dashboard_summary"])
        original_write = PROJECTION.safe_write_text

        def exchanged(path, text, **kwargs):
            target.unlink()
            self.link(target, victim, hard=True)
            return original_write(path, text, **kwargs)

        with patch.object(PROJECTION, "safe_write_text", side_effect=exchanged):
            with self.assertRaises((OSError, ValueError)):
                self.project_reports()
        self.assertEqual(victim.read_bytes(), self.originals["dashboard_summary"])

    def test_direct_writer_does_not_create_a_missing_target_or_parent(self):
        missing = self.project / "absent/target.json"
        with self.assertRaises((OSError, ValueError)):
            PROJECTION.safe_write_text(missing, "unused")
        self.assertFalse(missing.parent.exists())

    def test_ordinary_serialization_modes_and_idempotency_remain(self):
        for path in self.targets.values():
            path.chmod(0o640)
        result = self.project_reports()
        first = {key: path.read_bytes() for key, path in self.targets.items()}
        self.project_reports()
        for key, path in self.targets.items():
            self.assertEqual(result[key]["state"], "projected")
            self.assertEqual(path.read_bytes(), first[key])
            if key != "dashboard_markdown":
                expected = json.loads(self.originals[key])
                expected[PROJECTION.PROJECTION_KEY] = PROJECTION.payload(REPORT)
                text = json.dumps(expected, indent=2, sort_keys=True) + "\n"
            else:
                text = "# Existing\n\n" + PROJECTION.markdown_block(REPORT) + "\n"
            self.assertEqual(path.read_bytes(), text.replace("\n", os.linesep).encode("utf-8"))
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)

    def test_parse_or_marker_error_preserves_all_targets(self):
        for key, content in (("evidence_pack", b"not json"),
                             ("dashboard_markdown", PROJECTION.BEGIN_MARKER.encode())):
            with self.subTest(key=key):
                self.targets[key].write_bytes(content)
                before = {name: path.read_bytes() for name, path in self.targets.items()}
                result = self.project_reports()
                self.assertIn(result[key]["state"], {"parse_error", "marker_error"})
                self.assertEqual(before, {name: path.read_bytes() for name, path in self.targets.items()})
                self.targets[key].write_bytes(self.originals[key])

    def cli(self, *args):
        output = io.StringIO()
        with patch.object(CLI, "build_report", return_value=copy.deepcopy(REPORT)), \
                patch.object(CLI, "schema_errors", return_value=[]), \
                contextlib.redirect_stdout(output):
            result = CLI.main(["--root", str(self.project), "--profile", "quickstart", "--check", "--json", *args])
        return result, json.loads(output.getvalue())

    def test_cli_explicit_projection_retains_leaf_alias_spelling(self):
        path = self.targets["evidence_pack"]
        alias = self.project / "alias.json"
        self.link(alias, path)
        _, report = self.cli("--project", "--evidence-pack", str(alias))
        self.assertEqual(path.read_bytes(), self.originals["evidence_pack"])
        self.assertEqual(report["projection"]["evidence_pack"]["state"], "unsafe_target")

    def test_cli_explicit_projection_retains_parent_alias_spelling(self):
        alias = self.project / "alias"
        self.link(alias, self.project, directory=True)
        _, report = self.cli("--project", "--evidence-pack", str(alias / "evidence.json"))
        self.assertEqual(self.targets["evidence_pack"].read_bytes(), self.originals["evidence_pack"])
        if "evidence_pack" in report.get("projection", {}):
            self.assertIn(report["projection"]["evidence_pack"]["state"], {"unsafe_target", "parse_error"})
        else:
            self.assert_windows_resolution_refusal(report)

    def assert_windows_resolution_refusal(self, report):
        self.assertEqual(os.name, "nt", "unexpected early refusal on this platform")
        self.assertEqual(report.get("projection"), {})
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["status"], "load_error")
        self.assertIn("WinError 448", report["findings"][0]["message"])

    def test_cli_report_output_does_not_resolve_leaf_alias(self):
        victim = self.project / "diagnostic.json"
        victim.write_bytes(b"SYNTHETIC DIAGNOSTIC\n")
        alias = self.project / "report-alias.json"
        self.link(alias, victim)
        with self.assertRaises((OSError, ValueError)):
            self.cli("--output", str(alias))
        self.assertEqual(victim.read_bytes(), b"SYNTHETIC DIAGNOSTIC\n")

    def test_cli_report_output_refuses_linked_parent(self):
        victim = self.project / "diagnostic.json"
        victim.write_bytes(b"SYNTHETIC DIAGNOSTIC\n")
        alias = self.project / "report-alias"
        self.link(alias, self.project, directory=True)
        try:
            _, report = self.cli("--output", str(alias / victim.name))
        except (OSError, ValueError):
            pass
        else:
            self.assert_windows_resolution_refusal(report)
        self.assertEqual(victim.read_bytes(), b"SYNTHETIC DIAGNOSTIC\n")

    def test_check_without_project_does_not_inspect_unused_projection_alias(self):
        alias = self.project / "unused.json"
        self.link(alias, self.targets["evidence_pack"])
        result, report = self.cli("--evidence-pack", str(alias))
        self.assertEqual(result, 0)
        self.assertNotIn("projection", report)
        self.assertEqual(self.targets["evidence_pack"].read_bytes(), self.originals["evidence_pack"])

    def test_actual_make_projection_target_preserves_linked_victim(self):
        make = shutil.which("make")
        if make is None:
            self.skipTest("make unavailable; direct CLI and projection cases run separately")
        alias = self.project / "pack-alias.json"
        victim = self.targets["evidence_pack"]
        self.link(alias, victim)
        package = self.project / "make-runtime/naos_governance"
        package.mkdir(parents=True)
        for name in ("scripts", "schemas", "policies", "configs", "templates", "upgrade_contract"):
            shutil.copytree(KIT / name, package / name, ignore=shutil.ignore_patterns("__pycache__"))
        for name in ("__init__.py", "secure_coding_reporting_cli.py"):
            shutil.copy2(KIT / name, package / name)
        arguments = (
            f'--root "{self.project}" --profile quickstart --naos-root naos --json '
            f'--policy "{KIT / "policies/default_policy.yaml"}" '
            f'--dashboard-summary "{self.targets["dashboard_summary"]}" '
            f'--dashboard-markdown "{self.targets["dashboard_markdown"]}" '
            f'--evidence-pack "{alias}"'
        )
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        env["PYTHONPATH"] = str(package.parent)
        selected = subprocess.run([sys.executable, "-B", "-c",
                                   "import naos_governance;print(naos_governance.__file__)"],
                                  cwd=self.project, env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(selected.returncode, 0, selected.stderr)
        self.assertEqual(Path(selected.stdout.strip()).resolve(), package / "__init__.py")
        result = subprocess.run([make, "-f", str(KIT / "templates/structural-seeds/Makefile.naos.secure-coding-reporting"),
                                 "naos-secure-coding-reporting-project", "PYTHON=" + sys.executable,
                                 "NAOS_P3_SCRIPT=" + str(KIT / "scripts/naos_secure_coding_reporting.py"),
                                 "NAOS_P3_ARGS=" + arguments], cwd=self.project, env=env,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(victim.read_bytes(), self.originals["evidence_pack"])
        report = json.loads(result.stdout)
        self.assertEqual(report["projection"]["evidence_pack"]["state"], "unsafe_target", result.stderr)
        for key in ("dashboard_summary", "dashboard_markdown"):
            self.assertEqual(self.targets[key].read_bytes(), self.originals[key])
            self.assertEqual(report["projection"][key]["state"], "aborted")


if __name__ == "__main__":
    unittest.main()
