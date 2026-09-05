#!/usr/bin/env python3
"""Public, dependency-free checks for the sanitized repository candidate."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "NAOS_PUBLIC_EXPORT_MANIFEST.json"
PUBLIC_REPOSITORY = "https://github.com/mfraile/naos-governance"
ACTIVATION_BOUNDARY = (
    "Managed `--activate` mutation is currently supported only on Darwin ARM64 "
    "with CPython"
)
INTERNAL_HISTORY_PATTERNS = (
    re.compile("ROAD" + r"MAP-[0-9]{2}", re.IGNORECASE),
    re.compile("OWNER" + r"-[0-9]{2}", re.IGNORECASE),
    re.compile("reviewer:" + r"[ \\t]+" + "codex-", re.IGNORECASE),
    re.compile("private" + r"[ -]" + "hosted", re.IGNORECASE),
    re.compile("private" + " engineering", re.IGNORECASE),
    re.compile("retained" + " private evidence", re.IGNORECASE),
    re.compile(r"\b" + "F-" + "008" + r"\b", re.IGNORECASE),
    re.compile(r"\b" + "PR" + " #" + r"[0-9]+\b", re.IGNORECASE),
    re.compile("dev/" + r"active(?:/|\*\*)", re.IGNORECASE),
    re.compile("dev/" + r"audits(?:/|\*\*)", re.IGNORECASE),
    re.compile(r"\b" + "GOV-" + r"[0-9]{3}\b", re.IGNORECASE),
    re.compile(r"\b" + "F-GOV" + r"[0-9]+", re.IGNORECASE),
    re.compile(r"\b" + "M0" + "-M9" + r"\b", re.IGNORECASE),
    re.compile(r"\b" + "P1" + "-P8" + r"\b", re.IGNORECASE),
    re.compile(r"\b" + "P6" + "-P8" + r"\b", re.IGNORECASE),
    re.compile(
        "dev/"
        + r"(?:active|audits|behavioral-battery|FEEDBACK_REAL_TEST|"
        + r"multi-agent-rebuild|superpowers-openspec-comparison|petri|bmad|"
        + r"history|architecture|decisions|demo|assets)(?:/|\*\*)",
        re.IGNORECASE,
    ),
    re.compile(r"\b" + "AC" + r"[0-9]+[A-Z]?-[0-9]+\b", re.IGNORECASE),
)


class PublicCandidateTests(unittest.TestCase):
    def test_receipt_covers_the_exact_public_tree(self) -> None:
        self.assertTrue(RECEIPT.is_file(), "sanitized export receipt is missing")
        receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
        declared = {row["path"]: row for row in receipt["files"]}
        actual = {
            path.relative_to(ROOT).as_posix(): path
            for path in ROOT.rglob("*")
            if path.is_file()
            and ".git" not in path.relative_to(ROOT).parts
            and path != RECEIPT
        }
        self.assertEqual(set(actual), set(declared))
        for relative, path in actual.items():
            with self.subTest(path=relative):
                payload = path.read_bytes()
                self.assertEqual(hashlib.sha256(payload).hexdigest(), declared[relative]["sha256"])
                self.assertEqual(len(payload), declared[relative]["bytes"])

    def test_public_repository_allowlist_and_internal_history_are_clean(self) -> None:
        receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
        history_matches = []
        repository_urls = set()
        for row in receipt["files"]:
            path = ROOT / row["path"]
            payload = path.read_bytes()
            text = payload.decode("utf-8", errors="ignore")
            repository_urls.update(
                re.findall(r"https://github\.com/mfraile/[A-Za-z0-9_.-]+", text)
            )
            for pattern in INTERNAL_HISTORY_PATTERNS:
                if pattern.search(text):
                    history_matches.append(
                        {"path": row["path"], "pattern": pattern.pattern}
                    )
        self.assertEqual(repository_urls, {PUBLIC_REPOSITORY})
        self.assertEqual(history_matches, [])
        self.assertFalse((ROOT / "dev").exists())
        self.assertFalse((ROOT / "tests").exists())
        self.assertFalse((ROOT / "configs" / "naos_public_ci.yml").exists())

    def test_release_identity_and_repository_urls_are_current(self) -> None:
        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        self.assertEqual(metadata["version"], "1.1.0")
        self.assertEqual(metadata["requires-python"], ">=3.11")
        self.assertEqual(metadata["urls"]["Homepage"], PUBLIC_REPOSITORY)
        self.assertEqual(metadata["urls"]["Repository"], PUBLIC_REPOSITORY)
        self.assertEqual(metadata["urls"]["Documentation"], f"{PUBLIC_REPOSITORY}#readme")
        self.assertEqual(metadata["urls"]["Issues"], f"{PUBLIC_REPOSITORY}/issues")

    def test_documented_greenfield_commands_preserve_new_project_semantics(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        tutorial = (
            ROOT / "docs" / "tutorials" / "INTEGRAL_TUTORIAL_QUICKSTART_FROM_SCRATCH.md"
        ).read_text(encoding="utf-8")
        quick_reference = (
            ROOT / "templates" / "structural-seeds" / "naos" / "NAOS_QUICK_REFERENCE.md"
        ).read_text(encoding="utf-8")
        lite = (
            ROOT / "docs" / "tutorials" / "INTEGRAL_TUTORIAL_LITE_FROM_SCRATCH.md"
        ).read_text(encoding="utf-8")
        standard = (
            ROOT / "docs" / "tutorials" / "INTEGRAL_TUTORIAL_STANDARD_FROM_SCRATCH.md"
        ).read_text(encoding="utf-8")
        installation_manual = (ROOT / "INSTALLATION_MANUAL.md").read_text(encoding="utf-8")
        quickstart_template = (
            ROOT / "templates" / "structural-seeds" / "NAOS_QUICKSTART.md"
        ).read_text(encoding="utf-8")
        greenfield_diagram = (
            ROOT / "docs" / "diagrams" / "greenfield-adoption-sequence.mmd"
        ).read_text(encoding="utf-8")

        self.assertNotRegex(readme, r"init --new --tier quickstart --activate")
        self.assertNotRegex(tutorial, r"init --new --tier quickstart --activate")
        self.assertIn('init "$PROJECT" --new --tier quickstart --activate', tutorial)
        self.assertNotIn("A new greenfield project | `naos-governance init .", quick_reference)
        self.assertIn("--new --tier <tier>", quick_reference)
        self.assertNotIn("Python 3.9+", lite)
        self.assertIn("Python ≥ 3.11", lite)
        self.assertIn(
            'init "$PROJECT" --new --tier lite --archetype custom --backend static_only --activate',
            lite,
        )
        self.assertIn(
            'init "$PROJECT" --new --tier standard --archetype custom --backend static_only --activate',
            standard,
        )
        self.assertIn(
            "naos-governance init /path/to/new-project --new --tier standard "
            "--archetype custom --backend static_only --activate",
            installation_manual,
        )
        self.assertIn(PUBLIC_REPOSITORY, quickstart_template)
        self.assertNotIn("init /path/to/your/project --tier lite", lite)
        self.assertNotIn("init /path/to/your/project --tier standard", standard)
        for path, content in (
            ("README.md", readme),
            ("quickstart tutorial", tutorial),
            ("lite tutorial", lite),
            ("standard tutorial", standard),
            ("installation manual", installation_manual),
            ("generated Quickstart guide", quickstart_template),
            ("generated quick reference", quick_reference),
        ):
            with self.subTest(platform_boundary=path):
                normalized = " ".join(content.replace("\n> ", "\n").split())
                self.assertIn(ACTIVATION_BOUNDARY, normalized)
        self.assertIn("Create-only activation is currently supported only on Darwin ARM64", greenfield_diagram)

    def test_public_workflow_is_read_only_and_non_publishing(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertRegex(workflow, r"actions/checkout@[0-9a-f]{40}")
        self.assertRegex(workflow, r"actions/setup-python@[0-9a-f]{40}")
        portable = workflow.split("  portable:\n", 1)[1].split("\n  activate:\n", 1)[0]
        activation = workflow.split("\n  activate:\n", 1)[1]
        self.assertIn("runs-on: ubuntu-latest", portable)
        self.assertNotIn("--activate", portable)
        for tier in ("quickstart", "lite", "standard"):
            with self.subTest(portable_preview=tier):
                self.assertIn(f'--preview-dir "$smoke_root/{tier}"', portable)
                self.assertIn(f'test ! -e "$smoke_root/{tier}-target"', portable)
        self.assertIn("runs-on: macos-15", activation)
        self.assertIn('platform.system() == "Darwin"', activation)
        self.assertIn('machine in {"arm64", "aarch64"}', activation)
        for tier in ("quickstart", "lite", "standard"):
            with self.subTest(supported_activation=tier):
                self.assertIn(f'init "$smoke_root/{tier}"', activation)
        self.assertIn("--activate", activation)
        for forbidden in (
            "pull_request_target",
            "contents: write",
            "id-token: write",
            "secrets.",
            "twine",
            "gh release",
            "git push",
            "upload-artifact",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)


if __name__ == "__main__":
    unittest.main()
