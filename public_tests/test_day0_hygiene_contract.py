"""Day-zero hygiene: no scaffold noise, with real secrets still detected."""

import importlib
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


class PublicDeclarationFreshnessTests(unittest.TestCase):
    def test_shipped_declarations_are_reproducible_from_current_source(self):
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/generate_naos_secret_public_literals.py"), "--check"],
            cwd=ROOT, capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "native Git and Bash required")
class FreshStandardHygieneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="naos day0 ü ")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.base = Path(cls.temporary.name).resolve()
        cls.project = cls.base / "project"
        cls.project.mkdir()
        config = cls.base / "empty-gitconfig"
        config.write_text("")
        cls.env = {k: v for k, v in os.environ.items()
                   if not k.startswith(("GIT_", "NAOS_")) and k != "PYTHONPATH"}
        cls.env.update(PYTHONDONTWRITEBYTECODE="1", NAOS_PYTHON=Path(sys.executable).as_posix(),
                       GIT_CONFIG_GLOBAL=str(config), GIT_CONFIG_NOSYSTEM="1")
        subprocess.run(["git", "init", "-q", str(cls.project)], env=cls.env, check=True,
                       capture_output=True)
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "cli.py"), "init", str(cls.project),
             "--tier", "standard", "--archetype", "custom", "--backend", "static_only", "--activate"],
            cwd=cls.base, env=cls.env, text=True, capture_output=True, timeout=240,
        )
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    def scan(self):
        result = subprocess.run(
            [sys.executable, "-B", str(self.project / "scripts/naos_secret_hygiene.py"),
             str(self.project), "--profile", "standard", "--strict", "--json"],
            cwd=self.project, env=self.env, text=True, capture_output=True, timeout=120,
        )
        self.assertTrue(result.stdout, result.stderr)
        return result, json.loads(result.stdout)

    def test_01_fresh_standard_and_its_own_report_pass_strict_secret_scan(self):
        for _ in range(2):
            result, report = self.scan()
            self.assertEqual(result.returncode, 0, report["findings"])
            self.assertEqual(report["summary"]["total_findings"], 0, report["findings"])
            self.assertEqual(report["summary"]["coverage_status"], "complete")

    def test_02_staged_scaffold_has_no_header_or_ruff_noise(self):
        subprocess.run(["git", "add", "--all"], cwd=self.project, env=self.env,
                       check=True, capture_output=True)
        result = subprocess.run(
            ["bash", (self.project / ".githooks/pre-commit").as_posix()], cwd=self.project,
            env=self.env, text=True, capture_output=True, timeout=180,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("missing 'Implements", result.stdout)
        self.assertNotIn("Ruff check did not succeed", result.stdout)

    def test_03_real_secrets_in_adopter_managed_and_report_files_are_detected(self):
        paths = ["src/adopter.py", "scripts/naos_readiness.py", "naos/reports/synthetic.json"]
        for relative in paths:
            path = self.project / relative
            previous = path.read_bytes() if path.exists() else None
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                path.write_text('AUTH_TOKEN = "sk-' + 'aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"\n')
                result, report = self.scan()
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(any(f.get("path") == relative
                                    and f["status"] == "secret_like_pattern"
                                    for f in report["findings"]), report["findings"])
            finally:
                if previous is None:
                    path.unlink()
                else:
                    path.write_bytes(previous)


class StagedScaffoldSelectionTests(unittest.TestCase):
    def test_copied_windows_policy_role_needs_exact_generator_pin(self):
        existing = importlib.import_module("test_secret_managed_inventory_contract")
        fixture = existing.WindowsConstructorCoordinatesTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.fixture()
        managed = existing.managed
        context = fixture.context()
        managed._windows_operands(context)
        observed = fixture.plan["source_policy_observation"]["path"]
        pin = hashlib.sha256(observed.encode("utf-8")).hexdigest()
        copied_module = str(fixture.logical) + "\\scripts\\naos_secret_managed_operands.py"
        with mock.patch.object(managed, "__file__", copied_module), \
                mock.patch.object(managed, "COPIED_SOURCE_POLICY_PATH_SHA256", pin, create=True):
            coordinates = managed._windows_enrollment_coordinates(context)
            self.assertEqual(coordinates[fixture.op + "/plan.json"][
                ("body", "plan", "source_policy_observation", "path")], observed)
        for invalid in (None, "0" * 64, "not-a-pin"):
            with self.subTest(pin=invalid), mock.patch.object(managed, "__file__", copied_module), \
                    mock.patch.object(managed, "COPIED_SOURCE_POLICY_PATH_SHA256", invalid, create=True), \
                    self.assertRaisesRegex(managed.OperandRefusal, "constructor_policy_path"):
                managed._windows_enrollment_coordinates(context)

    def test_proved_windows_names_are_normalized_for_git_without_guessing(self):
        selected = importlib.import_module("naos_staged_python")
        managed = selected.managed
        context = mock.Mock()
        context.object.side_effect = [
            {"body": {"entries": [{"path": "scripts\\tool.py", "base_sha256": "a" * 64}]}},
            {"body": {"content": {"sha256": "b" * 64, "size_decimal": "3"}}},
        ]
        with mock.patch.object(managed, "_legacy_operands", side_effect=ValueError), \
                mock.patch.object(managed, "_portable_operands", side_effect=ValueError), \
                mock.patch.object(managed, "_windows_operands"):
            self.assertEqual(selected._recorded_scaffold(context), {"scripts/tool.py": ("b" * 64, 3, None)})

    def test_portable_manifest_and_unchanged_adopter_seed_follow_same_byte_boundary(self):
        selected = importlib.import_module("naos_staged_python")
        fixtures = importlib.import_module("secret_portable_provenance_fixtures")
        for relative, ownership, policy in (
            ("scripts/tool.py", "kit_owned_derived", "create"),
            ("src/seed.py", "adopter_owned", "create_once_adopter_owned"),
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                raw = b"print('synthetic scaffold')\n"
                for name, data in fixtures.fixture(
                    path=relative, data=raw, ownership=ownership, creation_policy=policy,
                ).items():
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
                subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
                self.stage(root)
                self.assertEqual(selected.selected_staged_python(root), [])
                path.write_bytes(raw + b"# adopter modification\n")
                self.stage(root)
                self.assertEqual(selected.selected_staged_python(root), [relative])

    def fixture(self):
        selected = importlib.import_module("naos_staged_python")
        existing = importlib.import_module("test_secret_managed_inventory_contract")
        fixture = existing.ManagedInventoryTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        path = fixture.root / "scripts/fixture.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(fixture.raw)
        subprocess.run(["git", "init", "-q", str(fixture.root)], check=True, capture_output=True)
        self.stage(fixture.root)
        return selected, fixture, path

    def stage(self, root):
        subprocess.run(["git", "-c", "core.autocrlf=false", "add", "--all"],
                       cwd=root, check=True, capture_output=True)

    def test_exact_recorded_scaffold_is_omitted(self):
        selected, fixture, _ = self.fixture()
        self.assertEqual(selected.selected_staged_python(fixture.root), [])

    def test_index_only_and_worktree_only_edits_remain_selected(self):
        selected, fixture, path = self.fixture()
        path.write_bytes(fixture.raw + b"# authored change\n")
        self.stage(fixture.root)
        path.write_bytes(fixture.raw)
        self.assertEqual(selected.selected_staged_python(fixture.root), ["scripts/fixture.py"])
        self.stage(fixture.root)
        path.write_bytes(fixture.raw + b"# unstaged change\n")
        self.assertEqual(selected.selected_staged_python(fixture.root), ["scripts/fixture.py"])

    def test_invalid_manifest_and_hardlinked_source_never_grant_omission(self):
        selected, fixture, path = self.fixture()
        other = fixture.root / "linked-source"
        os.link(path, other)
        self.assertEqual(selected.selected_staged_python(fixture.root), ["scripts/fixture.py"])
        other.unlink()
        manifest = fixture.root / fixture.relative / "state/manifest.json"
        data = json.loads(manifest.read_bytes())
        data["integrity"]["value"] = "0" * 64
        manifest.write_text(json.dumps(data))
        self.assertEqual(selected.selected_staged_python(fixture.root), ["scripts/fixture.py"])

    def test_missing_proof_never_excludes_authored_staged_python(self):
        selected = importlib.import_module("naos_staged_python")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
            path = root / "authored space.py"
            path.write_text("print('authored')\n")
            subprocess.run(["git", "add", "--all"], cwd=root, check=True, capture_output=True)
            self.assertEqual(selected.selected_staged_python(root), ["authored space.py"])


class BoundedTestQualitySelectionTests(unittest.TestCase):
    def common(self):
        path = ROOT / "scripts/naos_hygiene_common.py"
        spec = importlib.util.spec_from_file_location("day0_bounded_hygiene", path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_over_limit_selectors_share_discovery_and_report_bound(self):
        common = self.common()

        class Reference:
            calls = 0

            def __str__(self):
                Reference.calls += 1
                return "tests"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "tests").mkdir()
            (root / "tests/test_ok.py").write_text(
                "def test_ok():\n    assert answer() == 7\n", encoding="utf-8"
            )
            with mock.patch.object(common, "_HYGIENE_MAX_ENTRIES", 5):
                report = common.check_test_quality_hygiene(
                    root=root, profile="assured", naos_root="naos",
                    rules={"scan_roots": [Reference() for _ in range(100)]},
                    rules_path=None, severity="blocking",
                )
        self.assertLessEqual(Reference.calls, 10)
        self.assertEqual(report["scans"]["effective_scan_roots"], ["tests"] * 5)
        self.assertEqual(report["summary"]["files_selected"], 1)
        self.assertEqual(report["summary"]["coverage_status"], "incomplete")
        self.assertEqual(report["status"], "blocked")
        self.assertTrue(any(
            row["status"] == "selector_limit" and row["severity"] == "blocking"
            for row in report["findings"]
        ))

    def test_below_limit_report_keeps_explicit_roots_and_fallbacks(self):
        common = self.common()
        cases = (
            (None, ["tests"], "complete"), ([], [], "not_configured"),
            ("tests", ["tests"], "complete"), ("   ", ["tests"], "complete"),
            (["tests", "tests/sub", "tests"], ["tests", "tests/sub", "tests"], "complete"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "tests/sub").mkdir(parents=True)
            (root / "tests/test_ok.py").write_text(
                "def test_ok():\n    assert answer() == 7\n", encoding="utf-8"
            )
            for profile in ("quickstart", "lite", "standard", "assured"):
                for roots, expected, coverage in cases:
                    with self.subTest(profile=profile, roots=roots):
                        rules = {} if roots is None else {"scan_roots": roots}
                        report = common.check_test_quality_hygiene(
                            root=root, profile=profile, naos_root="naos",
                            rules=rules, rules_path=None, severity="blocking",
                        )
                        self.assertEqual(report["scans"]["effective_scan_roots"], expected)
                        self.assertEqual(report["summary"]["coverage_status"], coverage)


if __name__ == "__main__":
    unittest.main()
