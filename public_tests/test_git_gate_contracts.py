"""Portable CLI regressions for Git snapshot and gate input contracts.

Run with ``python -m unittest discover -s public_tests``. NAOS_TEST_KIT may
point to an exported or installed kit; all mutations use disposable projects.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
VALIDATOR = KIT / "scripts/validators/validate_test_ac_references.py"


def environment():
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("NAOS_", "GIT_")) and k not in {"SPECS_ROOT", "TESTS_ROOT"}}
    return {**env, "PYTHONDONTWRITEBYTECODE": "1", "NAOS_PYTHON": sys.executable,
            "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}


def run(root, *args):
    return subprocess.run([str(a) for a in args], cwd=root, env=environment(),
                          text=True, capture_output=True, timeout=180, check=False)


def git(root, *args):
    result = run(root, "git", *args)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout


def write(root, path, text):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


class StagedSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="naos-staged-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        git(self.root, "init", "-q", "-b", "main")
        git(self.root, "config", "user.name", "Synthetic regression fixture")
        git(self.root, "config", "user.email", "fixture@example.invalid")
        write(self.root, "specs/acceptance.md", "AC-700001.1\n")
        write(self.root, "tests/test_case.py", "# AC-700001.1\n")
        git(self.root, "add", ".")
        git(self.root, "commit", "-qm", "test: establish fixture")

    def check(self, expected):
        result = run(self.root, sys.executable, VALIDATOR, "--staged")
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def test_index_invalid_worktree_valid(self):
        write(self.root, "tests/test_case.py", "# AC-700002.1\n")
        git(self.root, "add", "tests")
        write(self.root, "tests/test_case.py", "# AC-700001.1\n")
        self.check(1)

    def test_index_valid_worktree_invalid(self):
        write(self.root, "tests/test_case.py", "# AC-700001.1\n# staged\n")
        git(self.root, "add", "tests")
        write(self.root, "tests/test_case.py", "# AC-700002.1\n")
        self.check(0)

    def test_unstaged_only_definition_is_not_a_definition(self):
        write(self.root, "tests/test_case.py", "# AC-700002.1\n")
        git(self.root, "add", "tests")
        write(self.root, "specs/acceptance.md", "AC-700001.1 AC-700002.1\n")
        self.check(1)

    def test_spec_only_removal_rechecks_unchanged_tests(self):
        write(self.root, "specs/acceptance.md", "AC-700002.1\n")
        git(self.root, "add", "specs")
        self.check(1)

    def test_staged_definition_survives_unstaged_spec_edit(self):
        write(self.root, "specs/acceptance.md", "AC-700001.1 AC-700002.1\n")
        write(self.root, "tests/test_case.py", "# AC-700002.1\n")
        git(self.root, "add", ".")
        write(self.root, "specs/acceptance.md", "AC-700001.1\n")
        self.check(0)

    def test_spec_rename_preserves_definitions(self):
        git(self.root, "mv", "specs/acceptance.md", "specs/renamed.md")
        self.check(0)

    def test_unreadable_utf8_blob_is_controlled_failure(self):
        (self.root / "tests/test_case.py").write_bytes(b"\xff")
        git(self.root, "add", "tests")
        self.check(2)

    def test_removing_all_definitions_does_not_unconfigure_existing_contract(self):
        git(self.root, "rm", "specs/acceptance.md")
        self.check(1)
        git(self.root, "commit", "-qm", "test: exercise committed deletion without hook")
        result = run(self.root, sys.executable, VALIDATOR)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        # An unrelated later commit must not turn the deleted contract into onboarding.
        write(self.root, "README.md", "fixture\n")
        git(self.root, "add", ".")
        git(self.root, "commit", "-qm", "test: subsequent fixture commit")
        result = run(self.root, sys.executable, VALIDATOR)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_spec_only_change_rechecks_source_adjacent_tests(self):
        write(self.root, "src/subject.spec.ts", "// AC-700001.1\n")
        git(self.root, "add", ".")
        git(self.root, "commit", "-qm", "test: colocated fixture")
        git(self.root, "rm", "tests/test_case.py")
        write(self.root, "specs/acceptance.md", "AC-700002.1\n")
        git(self.root, "add", ".")
        self.check(1)
        git(self.root, "commit", "-qm", "test: committed invalid criterion rename")
        result = run(self.root, sys.executable, VALIDATOR)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_full_checkout_unreadable_utf8_is_controlled_failure(self):
        (self.root / "tests/test_case.py").write_bytes(b"\xff")
        result = run(self.root, sys.executable, VALIDATOR)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_shallow_checkout_cannot_hide_removed_criteria(self):
        git(self.root, "rm", "specs/acceptance.md")
        git(self.root, "commit", "-qm", "test: committed deletion fixture")
        with tempfile.TemporaryDirectory() as tmp:
            clone = Path(tmp) / "clone"
            git(Path(tmp), "clone", "-q", "--depth", "1", self.root.as_uri(), clone)
            result = run(clone, sys.executable, VALIDATOR)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("full Git history", result.stderr)

    def test_merged_topic_history_cannot_hide_authored_then_removed_criteria(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git(root, "init", "-q", "-b", "main")
            git(root, "config", "user.name", "Synthetic regression fixture")
            git(root, "config", "user.email", "fixture@example.invalid")
            write(root, "specs/acceptance.md", "No authored criteria yet.\n")
            write(root, "tests/test_subject.py", "# AC-700001.1\n")
            git(root, "add", ".")
            git(root, "commit", "-qm", "test: unconfigured baseline")
            git(root, "checkout", "-qb", "topic")
            write(root, "specs/acceptance.md", "AC-700001.1\n")
            git(root, "add", ".")
            git(root, "commit", "-qm", "test: author criteria")
            write(root, "specs/acceptance.md", "No authored criteria yet.\n")
            write(root, "topic.txt", "topic\n")
            git(root, "add", ".")
            git(root, "commit", "-qm", "test: remove criteria")
            git(root, "checkout", "-q", "main")
            write(root, "main.txt", "main\n")
            git(root, "add", ".")
            git(root, "commit", "-qm", "test: main fixture work")
            git(root, "merge", "--no-ff", "topic", "-m", "test: merge fixture history")
            result = run(root, sys.executable, VALIDATOR)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_renamed_test_is_read_from_index_even_when_deleted_in_worktree(self):
        git(self.root, "mv", "tests/test_case.py", "tests/test_renamed.py")
        write(self.root, "tests/test_renamed.py", "# AC-700002.1\n")
        git(self.root, "add", "tests")
        (self.root / "tests/test_renamed.py").unlink()
        self.check(1)

    def test_deleted_test_does_not_leave_a_phantom_reference(self):
        git(self.root, "rm", "tests/test_case.py")
        write(self.root, "specs/acceptance.md", "AC-700002.1\n")
        git(self.root, "add", "specs")
        self.check(0)

    def test_unconfigured_new_repository_can_commit_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git(root, "init", "-q")
            write(root, "tests/test_case.py", "# AC-700001.1\n")
            git(root, "add", ".")
            result = run(root, sys.executable, VALIDATOR, "--staged")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_non_git_staged_input_is_controlled_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run(Path(tmp), sys.executable, VALIDATOR, "--staged")
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertNotIn("Traceback", result.stderr)


class GeneratedHookSnapshotTests(unittest.TestCase):
    def test_actual_generated_hooks_commit_the_valid_snapshot_only(self):
        for profile in ("standard", "assured"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory(prefix="naos-hooks-") as tmp:
                base = Path(tmp)
                seed = base / "preview"
                result = run(base, sys.executable, KIT / "cli.py", "init", base / "absent",
                             "--new", "--tier", profile, "--archetype", "custom",
                             "--backend", "static_only", "--memory", "disabled", "--preview-dir", seed)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((base / "absent").exists())
                write(seed, "specs/snapshot.md", "AC-700001.1\n")
                write(seed, "tests/test_snapshot.py", "# Implements: FR-700001\n# AC-700001.1\ndef test_sum():\n    assert sum([1, 2]) == 3\n")
                git(seed, "init", "-q", "-b", "main")
                git(seed, "config", "user.name", "Synthetic regression fixture")
                git(seed, "config", "user.email", "fixture@example.invalid")
                git(seed, "add", ".")
                git(seed, "commit", "-qm", "test: establish fixture before hook activation")
                for name, staged, unstaged, expected in (
                    ("invalid-valid", "700002", "700001", 1),
                    ("valid-invalid", "700001", "700002", 0),
                    ("both-valid", "700001", "700001", 0),
                    ("both-invalid", "700002", "700002", 1),
                    ("unstaged-spec", "700002", "700002", 1),
                    ("missing-validator", "700002", "700002", 1),
                ):
                    with self.subTest(case=name):
                        root = base / name
                        git(base, "clone", "-q", "--no-hardlinks", seed, root)
                        git(root, "config", "user.name", "Synthetic regression fixture")
                        git(root, "config", "user.email", "fixture@example.invalid")
                        (root / ".githooks/pre-commit").chmod(0o755)
                        git(root, "config", "core.hooksPath", ".githooks")
                        before = git(root, "rev-parse", "HEAD")
                        def body(identifier):
                            return f"# Implements: FR-700001\n# AC-{identifier}.1\n# changed\ndef test_sum():\n    assert sum([1, 2]) == 3\n"
                        write(root, "tests/test_snapshot.py", body(staged))
                        git(root, "add", "tests")
                        staged_bytes = git(root, "show", ":tests/test_snapshot.py")
                        write(root, "tests/test_snapshot.py", body(unstaged))
                        if name == "unstaged-spec":
                            write(root, "specs/snapshot.md", "AC-700001.1 AC-700002.1\n")
                        if name == "missing-validator":
                            (root / "scripts/validators/validate_test_ac_references.py").unlink()
                        commit = run(root, "git", "commit", "-m", "test: snapshot contract")
                        self.assertIn("Test-AC reference validator", commit.stdout + commit.stderr)
                        self.assertEqual(commit.returncode, expected, commit.stdout + commit.stderr)
                        if expected:
                            self.assertEqual(git(root, "rev-parse", "HEAD"), before)
                            self.assertEqual(git(root, "show", ":tests/test_snapshot.py"), staged_bytes)
                        else:
                            self.assertNotEqual(git(root, "rev-parse", "HEAD"), before)
                            self.assertEqual(git(root, "show", "HEAD:tests/test_snapshot.py"), staged_bytes)
                            clean = base / (name + "-clean")
                            git(base, "clone", "-q", "--no-hardlinks", root, clean)
                            check = run(clean, sys.executable, clean / "scripts/validators/validate_test_ac_references.py")
                            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
                workflow = yaml.safe_load((seed / ".github/workflows/naos-control-plane-ci.yml").read_text())
                self.assertEqual(workflow["env"]["NAOS_PROFILE"], profile)
                scripts = "\n".join(str(s.get("run", "")) for s in workflow["jobs"]["naos-readiness"]["steps"])
                self.assertIn("validate_test_ac_references.py", scripts)
                self.assertLess(scripts.index("naos model-policy"), scripts.index("naos control-plane-review"))
                self.assertLess(scripts.index("naos model-telemetry"), scripts.index("naos control-plane-review"))
                self.assertEqual(workflow["jobs"]["naos-readiness"]["steps"][0]["with"]["fetch-depth"], 0)


class GateInputContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="naos-gates-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manifest = yaml.safe_load((KIT / "templates/structural-seeds/naos/gatekeepers.yaml").read_text())
        self.manifest["gates"] = [next(g for g in self.manifest["gates"] if g["id"] == "G5")]

    def check(self, data, expected, *args):
        write(self.root, "gates.yaml", yaml.safe_dump(data))
        result = run(self.root, sys.executable, KIT / "cli.py", "gate-evaluate",
                     "--manifest", "gates.yaml", "--json", "--output", "result.json", *args)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report, json.loads((self.root / "result.json").read_text()))
        return report

    def test_unknown_and_mixed_gate_selectors_are_errors(self):
        for selected in [("G999",), ("G5", "G999")]:
            with self.subTest(selected=selected):
                args = [a for gate in selected for a in ("--gate", gate)]
                report = self.check(self.manifest, 2, "--profile", "quickstart", *args)
                self.assertEqual(report["status"], "invalid_input")

    def test_malformed_roots_entries_ids_and_duplicates_are_errors(self):
        variants = [{}, [], "invalid", {**self.manifest, "gates": ""},
                    {**self.manifest, "gates": [None]}, {**self.manifest, "gates": [{}]},
                    {**self.manifest, "gates": self.manifest["gates"] * 2}]
        for index, data in enumerate(variants):
            with self.subTest(index=index):
                report = self.check(data, 2)
                self.assertEqual(report["status"], "invalid_input")
                self.assertTrue(report["errors"])

    def test_valid_empty_scope_remains_explicit_even_in_strict_mode(self):
        report = self.check({**self.manifest, "gates": []}, 0, "--strict-required")
        self.assertEqual(report["evaluation_scope"]["status"], "empty")
        self.assertEqual(report["summary"]["total"], 0)

    def test_required_missing_and_disabled_states_remain_distinct(self):
        for profile, strict, expected in [("standard", False, 0), ("standard", True, 1), ("assured", False, 1)]:
            with self.subTest(profile=profile, strict=strict):
                self.check(self.manifest, expected, "--profile", profile, *(("--strict-required",) if strict else ()))
        disabled = copy.deepcopy(self.manifest)
        disabled["gates"][0]["enabled"] = False
        report = self.check(disabled, 0, "--profile", "assured", "--gate", "g5")
        self.assertEqual(report["gates"][0]["status"], "not_applicable")
        self.assertEqual(report["evaluation_scope"]["status"], "not_applicable")

    def test_explicit_missing_errors_and_implicit_fallback_evaluates_template(self):
        result = run(self.root, sys.executable, KIT / "cli.py", "gate-evaluate", "--manifest", "absent.yaml", "--json")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"], "invalid_input")
        result = run(self.root, sys.executable, KIT / "cli.py", "gate-evaluate", "--profile", "quickstart", "--json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["summary"]["total"], 9)

    def test_invalid_gate_report_remains_a_review_gap_in_pr_consumer(self):
        self.check({}, 2)
        write(self.root, "naos/reports/gate_evaluation.json", (self.root / "result.json").read_text())
        result = run(self.root, sys.executable, KIT / "cli.py", "pr-governance-summary", "--profile", "standard", "--json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertIn("pr_governance.gate_evaluation_invalid_input", {item["id"] for item in report["findings"]})
        self.assertTrue(report["human_review_required"])

    def test_invalid_gate_report_remains_a_finding_in_sarif(self):
        self.check({}, 2)
        write(self.root, "naos/reports/gate_evaluation.json", (self.root / "result.json").read_text())
        result = run(self.root, sys.executable, KIT / "cli.py", "sarif-export", "--profile", "standard", "--json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertGreaterEqual(report["deterministic_findings_count"], 1)
        self.assertTrue(report["human_review_required"])
        sarif = json.loads(Path(report["output_path"]).read_text())
        self.assertTrue(any(r["properties"]["naos_source_report"] == "gate_evaluation"
                            for r in sarif["runs"][0]["results"]))


if __name__ == "__main__":
    unittest.main()
