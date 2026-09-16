"""Check file and subprocess error boundaries against source, exports or a wheel.

Set NAOS_TEST_KIT to the selected kit root. All project writes are disposable.
"""
from __future__ import annotations

import importlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()


class InputErrorBoundaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        cls.adoption = importlib.import_module("naos_adoption_common")
        cls.model = importlib.import_module("naos_model_provider_policy")
        cls.summary = importlib.import_module("naos_pr_governance_summary")
        for module in (cls.adoption, cls.model, cls.summary):
            if not Path(module.__file__).resolve().is_relative_to(ROOT):
                raise AssertionError("Regression imported a different kit")

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.path = self.root / "naos" / "fixture.json"
        self.path.parent.mkdir()
        self.path.write_text("{}", encoding="utf-8")
        self.policy = {"paths": {"sessions_index": "fixture.json"}}

    def test_malformed_json_and_encoding_keep_missing_evidence_visible(self) -> None:
        # The supported Python versions reject integers above the configured
        # conversion limit with plain ValueError, rather than JSONDecodeError.
        oversized_number = b'{"number": ' + b"9" * 5000 + b"}"
        for content in (b"{broken", b"\xff", oversized_number):
            with self.subTest(content_prefix=content[:40]):
                self.path.write_bytes(content)
                self.assertEqual(self.adoption.load_structured(self.path), {})
                data, error = self.summary.load_json(self.path)
                self.assertIsNone(data)
                self.assertTrue(error)
                self.assertIsNone(self.adoption.latest_session_id(self.root, "naos", self.policy))
                self.assertIsNone(self.summary.latest_session_id(self.root, "naos", self.policy))
                with patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(self.path)}):
                    self.assertIsNone(self.summary.github_event_value())

        package_path = self.root / "package.json"
        for content in (oversized_number, b"[" * 5000 + b"]" * 5000):
            package_path.write_bytes(content)
            self.assertIsInstance(self.adoption.detect_agent_loop_signals(self.root), dict)
        with (
            patch.object(self.adoption.json, "loads", side_effect=RuntimeError("unexpected parser defect")),
            self.assertRaisesRegex(RuntimeError, "unexpected parser defect"),
        ):
            self.adoption.detect_agent_loop_signals(self.root)

        self.path.write_text("{}", encoding="utf-8")
        with patch.object(self.summary.json, "loads", side_effect=RecursionError("fixture parser depth")):
            self.assertEqual(self.adoption.load_structured(self.path), {})
            self.assertIsNone(self.summary.load_json(self.path)[0])
            self.assertIsNone(self.adoption.latest_session_id(self.root, "naos", self.policy))
            with patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(self.path)}):
                self.assertIsNone(self.summary.github_event_value())

    def test_yaml_parse_and_timestamp_errors_keep_optional_fallbacks(self) -> None:
        for content in ("broken: [", "value: 2026-99-99", "- non-mapping", "[" * 2000 + "]" * 2000):
            with self.subTest(content_prefix=content[:40]):
                path = self.path.with_suffix(".yaml")
                path.write_text(content, encoding="utf-8")
                self.assertEqual(self.adoption.load_structured(path), {})
                with patch.object(self.model, "first_existing", return_value=path):
                    self.assertEqual(self.model.collect_llm_grader_role_references(self.root, "naos"), [])
                    self.assertEqual(self.model.collect_autoresearch_references(self.root), ([], []))

    def test_non_mapping_policy_has_a_type_error(self) -> None:
        self.path.write_text("- wrong-shape", encoding="utf-8")
        with self.assertRaisesRegex(TypeError, "Expected YAML mapping"):
            self.model.load_yaml_mapping(self.path)

    def test_unexpected_reader_errors_are_not_silenced(self) -> None:
        calls = (
            lambda: self.adoption.load_structured(self.path),
            lambda: self.adoption.latest_session_id(self.root, "naos", self.policy),
            lambda: self.adoption.read_small_text(self.root, "naos/fixture.json"),
            lambda: self.adoption.ai_artifact_entry(self.root, self.path, "custom", "fixture", "review_required"),
            lambda: self.summary.load_json(self.path),
            self.summary.github_event_value,
        )
        with (
            patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(self.path)}),
            patch.object(Path, "read_text", side_effect=RuntimeError("unexpected reader defect")),
        ):
            for call in calls:
                with self.subTest(call=call), self.assertRaisesRegex(RuntimeError, "unexpected reader defect"):
                    call()

    def test_optional_policy_reader_does_not_hide_programming_errors(self) -> None:
        with (
            patch.object(self.model, "first_existing", return_value=self.path),
            patch.object(self.model, "load_yaml_mapping", side_effect=RuntimeError("unexpected loader defect")),
        ):
            with self.assertRaisesRegex(RuntimeError, "unexpected loader defect"):
                self.model.collect_llm_grader_role_references(self.root, "naos")
            with self.assertRaisesRegex(RuntimeError, "unexpected loader defect"):
                self.model.collect_autoresearch_references(self.root)

    def test_expected_git_execution_errors_keep_existing_fallbacks(self) -> None:
        errors = (
            FileNotFoundError("fixture executable missing"),
            subprocess.TimeoutExpired("git", 10),
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "fixture encoding"),
        )
        for error in errors:
            with self.subTest(error=type(error).__name__), patch.object(subprocess, "run", side_effect=error):
                self.assertEqual(self.adoption.run_git(self.root, "rev-parse", "HEAD"), (127, ""))
                self.assertIsNone(self.summary.git_value(self.root, "rev-parse", "HEAD"))

    def test_unexpected_git_errors_are_not_silenced(self) -> None:
        with patch.object(subprocess, "run", side_effect=RuntimeError("unexpected subprocess defect")):
            with self.assertRaisesRegex(RuntimeError, "unexpected subprocess defect"):
                self.adoption.run_git(self.root, "rev-parse", "HEAD")
            with self.assertRaisesRegex(RuntimeError, "unexpected subprocess defect"):
                self.summary.git_value(self.root, "rev-parse", "HEAD")

    def test_unreadable_optional_text_and_external_paths_keep_fallbacks(self) -> None:
        with patch.object(Path, "read_text", side_effect=PermissionError("fixture denied")):
            self.assertEqual(self.adoption.read_small_text(self.root, "naos/fixture.json"), "")
            self.assertEqual(self.adoption.load_structured(self.path), {})
            self.assertIsNone(self.summary.load_json(self.path)[0])
        outside = self.root.parent / "outside-fixture"
        self.assertEqual(self.adoption.relpath(self.root, outside), str(outside))

    def test_trigger_and_local_url_simplifications_preserve_results(self) -> None:
        for text in ("on: push", "on: [push]", "on: {push: {}}"):
            self.assertEqual(self.adoption.workflow_trigger_names(text), ["push"])
        self.assertEqual(self.adoption.workflow_trigger_names("broken: [\n# workflow_dispatch"), ["workflow_dispatch"])
        for host in ("localhost", "127.0.0.1", "[::1]"):
            for scheme in ("http", "https"):
                self.assertFalse(self.model.local_url_is_public(f"{scheme}://{host}:9999/path"))
        self.assertTrue(self.model.local_url_is_public("https://example.com"))


if __name__ == "__main__":
    unittest.main()
