"""Portable read-only hook guidance and adoption refusal regressions."""

import importlib.util
import json
import jsonschema
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

KIT = Path(
    os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])
).resolve()
sys.path.insert(0, str(KIT))
sys.path.insert(0, str(KIT / "scripts"))
spec = importlib.util.spec_from_file_location(
    "init_operator_contract", KIT / "naos_init.py"
)
init = importlib.util.module_from_spec(spec)
spec.loader.exec_module(init)
import naos_adoption_common as adoption  # noqa: E402
import naos_governance_bypass_posture as bypass  # noqa: E402


class OperatorGuidanceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos operator ü ")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.global_config = self.base / "global.gitconfig"
        self.global_config.write_text("")
        self.env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("GIT_", "NAOS_")) and key != "PYTHONPATH"
        }
        self.env.update(
            GIT_CONFIG_GLOBAL=str(self.global_config),
            GIT_CONFIG_NOSYSTEM="1",
            PYTHONDONTWRITEBYTECODE="1",
        )

    def git(self, root, *args):
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout.strip()

    def repository(self, name="repo"):
        root = self.base / name
        root.mkdir()
        self.git(root, "init", "-q")
        return root

    def guide(self, root):
        with patch.dict(os.environ, self.env, clear=True):
            return "\n".join(init.hook_activation_guidance(root))

    def snapshot(self, root):
        return {
            str(path.relative_to(root)): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file()
        }

    def cli(self, *args, timeout=90):
        return subprocess.run(
            [sys.executable, "-B", str(KIT / "cli.py"), *map(str, args)],
            cwd=self.base,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def test_setup_guidance_does_not_become_enforced_finding(self):
        policy = yaml.safe_load(
            (KIT / "policies/default_policy.yaml").read_text(encoding="utf-8")
        )
        policy["enforcement_transition"] = "enforce"
        policy_path = self.base / "policy.yaml"
        policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
        catalog = yaml.safe_load(
            (KIT / "templates/structural-seeds/naos/setup_module_catalog.yaml").read_text(
                encoding="utf-8"
            )
        )
        catalog_path = self.base / "catalog.yaml"

        def run():
            result = subprocess.run(
                [sys.executable, "-B", str(KIT / "scripts/naos_setup_recommendations.py"),
                 "--profile", "assured", "--policy", str(policy_path),
                 "--catalog", str(catalog_path), "--no-write-preview", "--json"],
                cwd=self.base, env=self.env, capture_output=True, text=True, timeout=90,
            )
            self.assertTrue(result.stdout, result.stderr)
            report = json.loads(result.stdout)
            schema = json.loads(
                (KIT / "schemas/naos/setup_recommendations.schema.json").read_text(
                    encoding="utf-8"
                )
            )
            jsonschema.validate(report, schema)
            return result, report

        catalog_path.write_text(yaml.safe_dump(catalog), encoding="utf-8")
        clean_result, clean = run()
        self.assertEqual(clean_result.returncode, 0, clean_result.stderr)
        self.assertEqual(clean["status"], "pass")
        self.assertEqual(clean["findings"], [])
        self.assertEqual(clean["summary"]["warnings"], 0)
        self.assertGreater(clean["summary"]["guidance_warning_count"], 0)
        self.assertEqual(clean["summary"]["guidance_warning_count"], len(clean["warnings"]))
        self.assertTrue(clean["human_review_required"])
        self.assertTrue(clean["limitations"])

        invalid = {**catalog, "modules": [dict(item) for item in catalog["modules"]]}
        invalid["modules"][0].pop("name")
        catalog_path.write_text(yaml.safe_dump(invalid), encoding="utf-8")
        invalid_result, broken = run()
        self.assertEqual(invalid_result.returncode, 1)
        self.assertEqual(broken["status"], "blocked")
        self.assertGreater(broken["summary"]["blocking"], 0)
        self.assertEqual(broken["summary"]["blocking"], sum(
            item["severity"] == "blocking" for item in broken["findings"]
        ))
        self.assertEqual(broken["summary"]["warnings"], sum(
            item["severity"] == "warning" for item in broken["findings"]
        ))
        self.assertEqual(broken["summary"]["guidance_warning_count"], len(broken["warnings"]))

    def bypass_fixture(self, name="bypass"):
        root = self.repository(name)
        self.bypass_files(root)
        return root

    def bypass_files(self, root):
        hook = root / ".githooks" / "pre-commit"
        hook.parent.mkdir()
        hook.write_text("#!/bin/sh\nexit 0\n")
        workflow = root / ".github" / "workflows" / "naos.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(
            "name: naos\non: [push, pull_request]\njobs:\n"
            "  governance:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: naos gate-evaluate --profile standard\n"
        )

    def bypass_report(self, root, profile="standard"):
        with patch.dict(os.environ, self.env, clear=True):
            policy = bypass.load_policy(None, None, root)
            report = bypass.build_report(root, profile, "naos", policy, 30)
        schema = json.loads((KIT / "schemas/naos/governance_bypass_posture.schema.json").read_text())
        jsonschema.validate(report, schema)
        return report

    def test_bypass_unset_configured_mismatch_and_empty_log_are_distinct(self):
        root = self.bypass_fixture()
        unset = self.bypass_report(root)
        self.assertEqual(unset["scans"]["hook"]["inspection_status"], "unset")
        self.assertTrue(unset["scans"]["hook"]["inspection_complete"])
        self.assertEqual(unset["scans"]["hook"]["git_exit_code"], 1)
        self.assertIn("governance_bypass.hooks_path_unset", {item["id"] for item in unset["findings"]})
        self.git(root, "config", "--local", "core.hooksPath", "other-hooks")
        mismatch = self.bypass_report(root)
        self.assertEqual(mismatch["scans"]["hook"]["inspection_status"], "configured")
        self.assertIn("governance_bypass.hooks_path_mismatch", {item["id"] for item in mismatch["findings"]})
        self.git(root, "config", "--local", "core.hooksPath", ".githooks")
        clean = self.bypass_report(root)
        self.assertEqual(clean["status"], "pass")
        self.assertEqual(clean["scans"]["ci"]["declaration_status"], "present")
        self.assertTrue(clean["scans"]["ci"]["inspection_complete"])
        self.assertFalse(clean["scans"]["ci"]["execution_verified"])
        self.assertFalse(clean["scans"]["ci"]["enforcement_verified"])
        self.assertEqual(clean["scans"]["bypass_commit_messages"], [])
        self.assertEqual(clean["scans"]["bypass_commit_message_inspection"],
                         {"status": "complete", "complete": True, "git_exit_code": 0})

        # Workflow-shaped text without a supported trigger/job remains unknown.
        (root / ".github/workflows/naos.yml").write_text("name: naos\nrun: naos\n")
        unsupported = self.bypass_report(root)
        self.assertEqual(unsupported["scans"]["ci"]["declaration_status"], "unknown")
        self.assertFalse(unsupported["scans"]["ci"]["inspection_complete"])
        self.assertIn("governance_bypass.ci_declaration_inspection_unknown",
                      {item["id"] for item in unsupported["findings"]})

    def test_bypass_nonrepo_config_error_and_unexpected_rc1_are_unknown(self):
        plain = self.base / "plain-bypass"
        plain.mkdir()
        self.bypass_files(plain)
        nonrepo = self.bypass_report(plain)
        self.assertEqual(nonrepo["scans"]["hook"]["inspection_status"], "read_error")
        self.assertFalse(nonrepo["scans"]["hook"]["inspection_complete"])
        self.assertEqual(nonrepo["scans"]["bypass_commit_message_inspection"]["status"], "read_error")
        self.assertNotIn("governance_bypass.hooks_path_unset", {item["id"] for item in nonrepo["findings"]})
        self.assertEqual(nonrepo["status"], "warning")
        root = self.bypass_fixture()
        self.git(root, "config", "--local", "core.hooksPath", ".githooks")
        original = bypass.run_git
        for code, stdout, stderr, error_class in [
            (128, "", "fatal: private fixture detail", "git_query_failed"),
            (1, "unexpected", "", "unexpected_query_output"),
        ]:
            with self.subTest(code=code, stdout=stdout):
                def config_failure(path, args):
                    if args[0] == "config":
                        return code, stdout, stderr
                    return original(path, args)
                with patch.object(bypass, "run_git", side_effect=config_failure):
                    report = self.bypass_report(root)
                hook = report["scans"]["hook"]
                self.assertEqual((hook["inspection_status"], hook["error_class"]),
                                 ("read_error", error_class))
                ids = {item["id"] for item in report["findings"]}
                self.assertIn("governance_bypass.hooks_path_inspection_failed", ids)
                self.assertNotIn("governance_bypass.hooks_path_unset", ids)
                self.assertTrue(report["human_review_required"])
                self.assertNotIn("private fixture detail", json.dumps(report))
                if code == 128:
                    with patch.object(bypass, "run_git", side_effect=config_failure):
                        advisory = self.bypass_report(root, "quickstart")
                    self.assertEqual(advisory["status"], "advisory")
                    self.assertEqual(advisory["findings"][0]["severity"], "advisory")

    def test_bypass_missing_git_os_error_and_failed_log_are_visible(self):
        root = self.bypass_fixture()
        self.git(root, "config", "--local", "core.hooksPath", ".githooks")
        for exception, code, error_class in [
            (FileNotFoundError("sensitive filename"), 127, "file_not_found"),
            (PermissionError("sensitive filename"), 126, "os_error"),
        ]:
            with self.subTest(error_class=error_class), patch.object(
                bypass.subprocess, "run", side_effect=exception
            ):
                report = self.bypass_report(root)
            self.assertEqual(report["status"], "warning")
            self.assertEqual(report["scans"]["hook"]["git_exit_code"], code)
            self.assertEqual(report["scans"]["hook"]["error_class"], error_class)
            self.assertEqual(report["scans"]["bypass_commit_message_inspection"]["status"], "read_error")
            self.assertNotIn("sensitive filename", json.dumps(report))
        original = bypass.run_git
        def log_failure(path, args):
            if args[0] == "log":
                return 128, "", "fatal: private fixture detail"
            return original(path, args)
        with patch.object(bypass, "run_git", side_effect=log_failure):
            report = self.bypass_report(root)
        self.assertEqual(report["scans"]["hook"]["inspection_status"], "configured")
        self.assertEqual(report["scans"]["bypass_commit_messages"], [])
        self.assertEqual(report["scans"]["bypass_commit_message_inspection"]["status"], "read_error")
        self.assertEqual({item["id"] for item in report["findings"]},
                         {"governance_bypass.commit_message_inspection_failed"})
        self.assertEqual(report["status"], "warning")
        self.assertNotIn("private fixture detail", json.dumps(report))

    def test_bypass_cli_nonrepo_inspection_warning_keeps_default_exit_policy(self):
        plain = self.base / "plain-cli"
        plain.mkdir()
        self.bypass_files(plain)
        script = KIT / "scripts" / "naos_governance_bypass_posture.py"
        for strict, expected_exit in [(False, 0), (True, 1)]:
            with self.subTest(strict=strict):
                command = [sys.executable, "-B", str(script), "--profile", "standard",
                           "--json", "--output", str(self.base / "bypass-report.json")]
                if strict:
                    command.append("--strict")
                result = subprocess.run(command, cwd=plain, env=self.env,
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, expected_exit, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                report = json.loads(result.stdout)
                schema = json.loads((KIT / "schemas/naos/governance_bypass_posture.schema.json").read_text())
                jsonschema.validate(report, schema)
                self.assertEqual(report["status"], "warning")
                self.assertFalse(report["scans"]["hook"]["inspection_complete"])
                self.assertFalse(report["scans"]["bypass_commit_message_inspection"]["complete"])
                self.assertTrue(report["human_review_required"])

    def test_unconfigured_root_offers_explicit_local_option_without_writes(self):
        root = self.repository()
        before = self.snapshot(root)
        result = self.guide(root)
        self.assertIn("git config --local core.hooksPath .githooks", result)
        self.assertIn("After activation", result)
        self.assertIn("does not prove the hook has executed", result)
        self.assertEqual(before, self.snapshot(root))

    def test_effective_local_global_and_empty_hook_values_are_preserved(self):
        for label, value, scope in [
            ("custom", "custom hooks", "--local"),
            ("already", ".githooks", "--local"),
            ("empty", "", "--local"),
            ("global", "global hooks", "--global"),
        ]:
            with self.subTest(label=label):
                root = self.repository(label)
                self.git(root, "config", scope, "core.hooksPath", value)
                before = self.snapshot(root)
                global_before = self.global_config.read_bytes()
                result = self.guide(root)
                self.assertIn("Effective core.hooksPath: " + json.dumps(value), result)
                self.assertNotIn("git config --local", result)
                self.assertEqual(before, self.snapshot(root))
                self.assertEqual(global_before, self.global_config.read_bytes())

    def test_nested_and_non_git_targets_do_not_get_configuration_commands(self):
        root = self.repository()
        nested = root / "nested"
        nested.mkdir()
        self.git(root, "config", "core.hooksPath", "custom-hooks")
        non_git = self.base / "plain"
        non_git.mkdir()
        self.assertIn("Nested target", self.guide(nested))
        self.assertIn("custom-hooks", self.guide(nested))
        self.assertIn("not a confirmed Git worktree", self.guide(non_git))
        for target in [nested, non_git, self.base / "not-created"]:
            self.assertNotIn("git config --local", self.guide(target))
        with patch.dict(os.environ, self.env, clear=True):
            self.assertTrue(adoption.detect_project_signals(nested)["has_git"])
            self.assertFalse(adoption.detect_project_signals(non_git)["has_git"])
        redirected = {**self.env, "GIT_DIR": str(root / ".git"), "GIT_WORK_TREE": str(root)}
        with patch.dict(os.environ, redirected, clear=True):
            self.assertFalse(adoption.detect_project_signals(non_git)["has_git"])
            self.assertIn("not a confirmed Git worktree", "\n".join(init.hook_activation_guidance(non_git)))

    def test_shared_worktrees_and_worktree_hook_config_are_preserved(self):
        root = self.repository()
        self.git(
            root,
            "-c",
            "user.name=Synthetic fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "fixture",
        )
        linked = self.base / "linked"
        self.git(root, "worktree", "add", "-q", "-b", "fixture-linked", str(linked))
        self.assertTrue((linked / ".git").is_file())
        for target in [root, linked]:
            self.assertNotIn("git config --local", self.guide(target))
            self.assertIn("Worktree configuration is shared", self.guide(target))
        self.git(root, "config", "extensions.worktreeConfig", "true")
        self.git(linked, "config", "--worktree", "core.hooksPath", "worktree-hooks")
        before = self.snapshot(root)
        linked_before = self.snapshot(linked)
        self.assertIn("worktree-hooks", self.guide(linked))
        self.assertEqual(before, self.snapshot(root))
        self.assertEqual(linked_before, self.snapshot(linked))

    def test_inherited_git_output_selectors_are_removed_without_losing_real_config(self):
        root = self.repository()
        self.git(root, "config", "--global", "core.hooksPath", "global-hooks")
        outputs = {name: self.base / (name.lower() + ".log") for name in
                   ("GIT_TRACE", "GIT_TRACE_PERFORMANCE", "GIT_TRACE2_EVENT", "GIT_REDIRECT_STDERR")}
        environment = {**self.env, **{name: str(path) for name, path in outputs.items()},
                       "GIT_PAGER": "synthetic-pager", "GIT_FLUSH": "1"}
        real_run = subprocess.run
        with patch.dict(os.environ, environment, clear=True), patch.object(subprocess, "run", wraps=real_run) as observed:
            guidance = "\n".join(init.hook_activation_guidance(root))
            code, inside = adoption.run_git(root, "rev-parse", "--is-inside-work-tree")
        self.assertIn('Effective core.hooksPath: "global-hooks"', guidance)
        self.assertNotIn("git config --local", guidance)
        self.assertEqual((code, inside), (0, "true"))
        self.assertGreaterEqual(len(observed.call_args_list), 2)
        for call in observed.call_args_list:
            child = call.kwargs["env"]
            self.assertEqual(child["GIT_CONFIG_GLOBAL"], str(self.global_config))
            self.assertNotIn("GIT_PAGER", child)
            self.assertNotIn("GIT_FLUSH", child)
            self.assertFalse(any(name.upper().startswith(("GIT_TRACE", "GIT_REDIRECT_")) for name in child))
        self.assertFalse(any(path.exists() for path in outputs.values()))

    def test_existing_default_hook_is_not_displaced_by_guidance(self):
        root = self.repository()
        hook = root / ".git/hooks/pre-commit"
        hook.write_text("# synthetic adopter hook\n")
        before = self.snapshot(root)
        self.assertIn("Existing default hook entries", self.guide(root))
        self.assertNotIn("git config --local", self.guide(root))
        self.assertEqual(before, self.snapshot(root))

    def test_actual_preview_prints_context_without_mutating_git_or_target(self):
        root = self.repository()
        self.git(root, "config", "core.hooksPath", "custom-hooks")
        before = self.snapshot(root)
        preview = self.base / "preview"
        result = self.cli(
            "init",
            root,
            "--tier",
            "quickstart",
            "--backend",
            "static_only",
            "--preview-dir",
            preview,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Effective core.hooksPath: "custom-hooks"', result.stdout)
        self.assertNotIn("git config --local", result.stdout)
        self.assertEqual(before, self.snapshot(root))
        self.assertTrue((preview / ".githooks/pre-commit").is_file())
        self.assertFalse((preview / ".githooks/pre-commit").stat().st_mode & 0o111)

    @unittest.skipUnless(
        (sys.platform == "win32"
         or (sys.platform == "darwin" and platform.machine().lower() in {"arm64", "aarch64"})
         or (sys.platform == "linux" and platform.machine().lower() in {"x86_64", "aarch64"}))
        and sys.implementation.name == "cpython"
        and sys.version_info[:2] in {(3, 11), (3, 12), (3, 13)},
        "Native managed adapters require macOS, Linux or Windows with CPython 3.11–3.13",
    )
    def exercise_activation_preserves_configuration_and_collision_refusal(self, profile):
        root = self.repository()
        self.git(root, "config", "core.hooksPath", "custom-hooks")
        result = self.cli(
            "init",
            root,
            "--tier",
            profile,
            "--archetype",
            "custom",
            "--backend",
            "static_only",
            "--activate",
            # Assured's complete durable journal took 82 seconds on the native
            # Ubuntu diagnostic. Give this integration call headroom while
            # retaining the other command bounds and all refusal assertions.
            timeout=180 if profile == "assured" else 90,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.git(root, "config", "--get", "core.hooksPath"), "custom-hooks"
        )
        self.assertFalse((root / ".githooks/pre-commit").stat().st_mode & 0o111)
        collision = self.repository("collision")
        hook = collision / ".githooks/pre-commit"
        hook.parent.mkdir()
        hook.write_text("existing adopter hook\n")
        before = self.snapshot(collision)
        result = self.cli(
            "init",
            collision,
            "--tier",
            profile,
            "--archetype",
            "custom",
            "--backend",
            "static_only",
            "--activate",
        )
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("pre-commit", result.stdout + result.stderr)
        self.assertEqual(before, self.snapshot(collision))

    def test_activation_preserves_configuration_and_collision_refusal(self):
        self.exercise_activation_preserves_configuration_and_collision_refusal("quickstart")

    def test_lite_activation_preserves_configuration_and_collision_refusal(self):
        self.exercise_activation_preserves_configuration_and_collision_refusal("lite")

    def test_standard_activation_preserves_configuration_and_collision_refusal(self):
        self.exercise_activation_preserves_configuration_and_collision_refusal("standard")

    def test_assured_activation_preserves_configuration_and_collision_refusal(self):
        self.exercise_activation_preserves_configuration_and_collision_refusal("assured")

    def test_blocked_adopt_init_and_first_run_show_specific_reason_without_writes(self):
        root = self.base / "blocked"
        (root / "src").mkdir(parents=True)
        (root / "docs").mkdir()
        (root / "naos").mkdir()
        (root / "src/main.py").write_text('print("synthetic")\n')
        (root / "docs/context.md").write_text("# Synthetic context\n")
        (root / "naos/capability_state.yaml").write_text(
            "capabilities:\n  - capability_id: CAP-LOCAL-CONTEXT-INDEX\n    current_maturity: L9\n"
        )
        before = self.snapshot(root)
        commands = [
            (
                "adopt",
                [
                    root,
                    "--mode",
                    "brownfield",
                    "--profile",
                    "standard",
                    "--no-write-preview",
                ],
                2,
            ),
            (
                "init",
                [
                    root,
                    "--tier",
                    "standard",
                    "--archetype",
                    "custom",
                    "--backend",
                    "static_only",
                    "--activate",
                    "--dry-run",
                ],
                4,
            ),
            ("first-run", [root, "--profile", "standard", "--mode", "brownfield"], 2),
        ]
        for command, args, expected in commands:
            with self.subTest(command=command):
                result = self.cli(command, *args)
                output = result.stdout + result.stderr
                self.assertEqual(result.returncode, expected, output)
                self.assertIn(
                    "repository_intelligence.invalid_maturity_declaration", output
                )
                self.assertIn("unsupported current_maturity: L9", output)
                self.assertIn("repository-intelligence plan", output)
                self.assertNotIn("Activate and validate the recommended", output)
                self.assertEqual(before, self.snapshot(root))
                if command == "adopt":
                    self.assertIn("not written: blocked prerequisite", output)
                    self.assertNotIn("report artifacts may be written", output)
        structured = self.cli(
            "adopt",
            root,
            "--mode",
            "brownfield",
            "--profile",
            "standard",
            "--no-write-preview",
            "--json",
        )
        self.assertEqual(structured.returncode, 2, structured.stderr)
        report = json.loads(structured.stdout)
        self.assertFalse(report["persistence_allowed"])
        self.assertIn(
            "repository_intelligence.invalid_maturity_declaration",
            report["repository_intelligence_prestart"]["finding_ids"],
        )

    def test_nonkit_explicit_no_write_reports_its_actual_cause(self):
        root = self.base / "plain"
        root.mkdir()
        before = self.snapshot(root)
        result = self.cli(
            "adopt",
            root,
            "--mode",
            "greenfield",
            "--profile",
            "quickstart",
            "--no-write-preview",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("not written: explicit --no-write-preview", result.stdout)
        self.assertNotIn("kit repository without adopter", result.stdout)
        self.assertNotIn("report artifacts may be written", result.stdout)
        self.assertEqual(before, self.snapshot(root))


if __name__ == "__main__":
    unittest.main()
