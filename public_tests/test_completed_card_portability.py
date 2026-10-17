"""Completion digest acceptance through actual registry/refresh/context consumers.

Run ``python -B public_tests/test_completed_card_portability.py``. NAOS_TEST_KIT
may name an installed candidate. Every project and Git repository is temporary;
no providers, remote hosts, user Git configuration or real approvals are used.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml
from jsonschema import Draft202012Validator

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(KIT / "scripts"))
from naos_task_lifecycle import complete_task, completed_card_digest  # noqa: E402
sys.path.insert(0, str(KIT))
import naos_init  # noqa: E402
from upgrade_contract.generated_recipes import bounded_canonical_input  # noqa: E402


class CompletedCardPortabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="naos-completed-card-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "NAOS_FIXED_TIME": "2026-10-11T00:00:00Z"}
        for name in ("NAOS_ROOT", "NAOS_PROFILE", "REGISTRY_SCHEMA", "PYTHONPATH"):
            self.env.pop(name, None)
        # Scope Git to these temporary repositories and avoid inherited routing.
        for name in list(self.env):
            if name.startswith("GIT_"):
                self.env.pop(name, None)
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)

    def fixture(self, name, ending=b"\n"):
        root = self.base / name
        (root / "naos/active").mkdir(parents=True)
        (root / "scripts").mkdir()
        (root / "schemas/naos").mkdir(parents=True)
        for filename in ("naos_task_lifecycle.py", "naos_policy.py", "naos_console.py", "naos_validate_task_registry.py"):
            shutil.copy2(KIT / "scripts" / filename, root / "scripts" / filename)
        shutil.copy2(KIT / "schemas/naos/task_registry.schema.json", root / "schemas/naos/task_registry.schema.json")
        registry = {"schema": "naos.task_registry.v2", "tasks": [{
            "id": "T-001", "title": "Portable card", "status": "in_progress", "requirement": "FR-001",
            "phase": 1, "priority": "P1", "estimate_days": 1,
        }]}
        (root / "naos/TASK_REGISTRY.yaml").write_bytes(yaml.safe_dump(registry).encode("utf-8"))
        card = ("# Active Task: T-001 - Café\n\n"
                "## Acceptance Criteria\n- [x] Keep exact content.\n"
                "## Known Risks / Gotchas\n- Synthetic fixture only.\n").encode("utf-8").replace(b"\n", ending)
        (root / "naos/active/T-001.md").write_bytes(card)
        report = complete_task(
            root=root, naos_root="naos", task_id="T-001", profile="quickstart",
            completion_provenance="Synthetic portability fixture", completed_by=None,
            verification_state="unverified", implementation_refs=[], test_refs=[],
            evidence_refs=[], decision_refs=[], unresolved_risks=[], dry_run=False,
        )
        self.assertEqual(report["status"], "completed", report)
        self.assertEqual((root / "naos/completed/T-001.md").read_bytes(), card)
        self.assertFalse((root / "naos/active/T-001.md").exists())
        history = self.history(root)
        schema = json.loads((KIT / "schemas/naos/completed_task_history.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(history)
        return root, card

    def history(self, root):
        return yaml.safe_load((root / "naos/completed_history.yaml").read_bytes())

    def write_history(self, root, history):
        (root / "naos/completed_history.yaml").write_bytes(yaml.safe_dump(history, sort_keys=False).encode("utf-8"))

    def protected(self, root):
        paths = [root / "naos/TASK_REGISTRY.yaml", root / "naos/completed_history.yaml", root / "naos/BACKLOG.md"]
        paths.extend((root / "naos/completed").glob("*.md"))
        return {p.relative_to(root).as_posix(): p.read_bytes() for p in paths if p.is_file()}

    def consumers(self, root, accepted=True, diagnostic="digest mismatch"):
        before = self.protected(root)
        commands = (
            ("registry", root / "scripts/naos_validate_task_registry.py", []),
            ("gov-refresh", KIT / "scripts/workflows/sync_from_registry.py", ["--backlog"]),
            ("task-context", KIT / "scripts/naos_task_context_pack.py", ["--task", "T-001", "--recovery-mode", "completed", "--profile", "quickstart", "--no-markdown"]),
        )
        for name, script, args in commands:
            with self.subTest(consumer=name):
                result = subprocess.run([sys.executable, "-B", str(script), *args], cwd=root,
                                        env=self.env, capture_output=True, text=True,
                                        encoding="utf-8", errors="strict", timeout=30)
                output = result.stdout + result.stderr
                if accepted:
                    self.assertEqual(result.returncode, 0, output)
                    if name == "task-context":
                        report = json.loads(result.stdout)
                        self.assertEqual(report["task_resolution"]["status"], "completed_task")
                else:
                    self.assertEqual(result.returncode, 1 if name == "registry" else 2, output)
                    self.assertIn(diagnostic, output)
        after = self.protected(root)
        if accepted:
            # Refresh may create a derived backlog; authority bytes stay exact.
            before.pop("naos/BACKLOG.md", None)
            after.pop("naos/BACKLOG.md", None)
        self.assertEqual(after, before)

    def git(self, root, *args):
        result = subprocess.run(["git", "-C", str(root), *args], env=self.env,
                                capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def clone(self, source, name, autocrlf):
        self.git(source, "init", "-q")
        self.git(source, "-c", "core.autocrlf=false", "add", ".")
        self.git(source, "-c", "user.name=Synthetic Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-qm", "Synthetic completion fixture")
        destination = self.base / name
        self.git(source, "-c", f"core.autocrlf={str(autocrlf).lower()}", "clone", "-q", str(source), str(destination))
        return destination

    def test_new_lf_and_crlf_completion_cross_checkout_consumers(self):
        for ending, autocrlf in ((b"\n", True), (b"\r\n", False)):
            with self.subTest(ending=ending, autocrlf=autocrlf):
                label = "lf" if ending == b"\n" else "crlf"
                root, card = self.fixture(label, ending)
                digest = self.history(root)["records"][0]["active_record_digest"]
                self.assertEqual(digest["canonicalization"], "crlf-to-lf-v1")
                self.assertEqual(digest["value"], hashlib.sha256(card.replace(b"\r\n", b"\n")).hexdigest())
                self.consumers(root)
                if ending == b"\r\n":
                    # Model Git's normalizing text path before a POSIX checkout.
                    (root / ".gitattributes").write_bytes(b'"/naos/completed/T-001.md" text eol=lf\n')
                clone = self.clone(root, label + "-clone", autocrlf)
                expected = card.replace(b"\r\n", b"\n")
                if autocrlf:
                    expected = expected.replace(b"\n", b"\r\n")
                self.assertEqual((clone / "naos/completed/T-001.md").read_bytes(), expected)
                self.consumers(clone)

    def test_new_digest_rejects_content_whitespace_bom_and_bare_cr_changes(self):
        root, card = self.fixture("mutations")
        for changed in (
            card.replace(b"exact content", b"altered content"),
            card.replace(b"content.", b"content. "),
            b"\xef\xbb\xbf" + card,
            card.replace(b"content.\n", b"content.\r"),
        ):
            with self.subTest(changed=changed):
                (root / "naos/completed/T-001.md").write_bytes(changed)
                self.consumers(root, accepted=False)

    def test_unmarked_historical_digests_require_exact_bytes(self):
        for ending in (b"\n", b"\r\n"):
            with self.subTest(ending=ending):
                root, card = self.fixture("legacy-lf" if ending == b"\n" else "legacy-crlf", ending)
                history = self.history(root)
                history["records"][0]["active_record_digest"] = {"algorithm": "sha256", "value": hashlib.sha256(card).hexdigest()}
                self.write_history(root, history)
                self.consumers(root)
                changed = card.replace(b"\r\n", b"\n") if ending == b"\r\n" else card.replace(b"\n", b"\r\n")
                (root / "naos/completed/T-001.md").write_bytes(changed)
                self.consumers(root, accepted=False, diagnostic="Restore the original archived bytes")
                # A reviewed restoration may reconstruct a candidate, but only
                # the original raw SHA authorizes it. The product does not write.
                candidate = changed.replace(b"\r\n", b"\n")
                if ending == b"\r\n":
                    candidate = candidate.replace(b"\n", b"\r\n")
                self.assertEqual(hashlib.sha256(candidate).hexdigest(), history["records"][0]["active_record_digest"]["value"])
                self.assertEqual(candidate, card)
                (root / "naos/completed/T-001.md").write_bytes(candidate)
                self.consumers(root)

    def test_legacy_mixed_endings_or_other_alterations_cannot_be_reconstructed_blindly(self):
        root, card = self.fixture("legacy-mixed")
        mixed = card.replace(b"Criteria\n", b"Criteria\r\n")
        history = self.history(root)
        history["records"][0]["active_record_digest"] = {"algorithm": "sha256", "value": hashlib.sha256(mixed).hexdigest()}
        self.write_history(root, history)
        (root / "naos/completed/T-001.md").write_bytes(mixed)
        self.consumers(root)
        for changed in (card, b"\xef\xbb\xbf" + card, card.replace(b"content.", b"content. ")):
            lf = changed.replace(b"\r\n", b"\n")
            for candidate in (changed, lf, lf.replace(b"\n", b"\r\n")):
                self.assertNotEqual(hashlib.sha256(candidate).hexdigest(), history["records"][0]["active_record_digest"]["value"])
            (root / "naos/completed/T-001.md").write_bytes(changed)
            self.consumers(root, accepted=False)

    def test_archive_checkout_rule_preserves_raw_history_in_real_clones(self):
        for ending in (b"\n", b"\r\n"):
            with self.subTest(ending=ending):
                label = "raw-lf" if ending == b"\n" else "raw-crlf"
                root, card = self.fixture(label, ending)
                history = self.history(root)
                history["records"][0]["active_record_digest"] = {"algorithm": "sha256", "value": hashlib.sha256(card).hexdigest()}
                self.write_history(root, history)
                template = root / "naos/completed/_TEMPLATE.md"
                template.write_bytes(b"Completed task template\n")
                generated = ["naos/TASK_REGISTRY.yaml", "naos/completed/_TEMPLATE.md"]
                naos_init._add_generated_lf_policy(
                    root, root, generated, greenfield=True, current_managed_paths=set(),
                )
                unrelated = root / "adopter.md"
                unrelated.write_bytes(b"Adopter text\n")
                clone = self.clone(root, label + "-clone", True)
                self.assertEqual((clone / "naos/completed/T-001.md").read_bytes(), card)
                self.assertEqual((clone / "adopter.md").read_bytes(), b"Adopter text\r\n")
                self.consumers(clone)

    def test_generated_profile_archive_policy_and_source_binding(self):
        for profile in ("quickstart", "lite", "standard", "assured"):
            with self.subTest(profile=profile):
                root = self.base / ("preview-" + profile)
                preview = naos_init._generate_scaffold_preview(
                    project_path=self.base / ("absent-" + profile), preview_dir=root,
                    signals=naos_init._empty_signals(), tier=profile,
                    archetype="custom", backend="static_only", memory_choice="disabled",
                    current_managed_paths=set(), existing_destination=False,
                    apply_brownfield_layout_adapter=False, ephemeral_preview=True,
                    emit_progress=False, collect_source_modes=True,
                )
                inventory = preview["source_mode_inventory"]
                inventory.require_complete()
                archive_rule = b'"/naos/completed/*.md" -text -filter -ident -working-tree-encoding'
                policy = (root / ".gitattributes").read_bytes()
                # Quickstart deliberately has no task registry/card scaffold.
                directories = [] if profile == "quickstart" else ["naos/completed"]
                if directories:
                    self.assertIn(archive_rule, policy)
                else:
                    self.assertNotIn(archive_rule, policy)
                    self.assertNotIn("naos/TASK_REGISTRY.yaml", preview["generated_files"])
                self.assertNotIn(b"\r", policy)
                artifact = next(item for item in inventory.source_artifacts
                                if item.destination == ".gitattributes")
                recipe = json.loads(artifact.artifact_bytes)
                decision = next(item for item in recipe["inputs"]
                                if item["name"] == "decision/completed_archive_directories")
                self.assertEqual(decision["sha256"], hashlib.sha256(
                    bounded_canonical_input(directories)).hexdigest())
                self.git(root, "init", "-q")
                future = "naos/completed/T-999-café.md"
                fields = self.git(root, "check-attr", "-z", "text", "filter", "ident",
                                  "working-tree-encoding", "--", future).split(b"\0")
                self.assertEqual(fields[2:-1:3], [b"unset" if directories else b"unspecified"] * 4)
                if directories:
                    template = self.git(root, "check-attr", "-z", "text", "eol", "--",
                                        "naos/completed/_TEMPLATE.md").split(b"\0")
                    self.assertEqual(template[2:-1:3], [b"set", b"lf"])
                unrelated = self.git(root, "check-attr", "-z", "text", "--", "adopter.md").split(b"\0")
                self.assertEqual(unrelated[2], b"unspecified")

    def test_unknown_or_null_canonicalization_fails_closed_in_every_consumer(self):
        root, _card = self.fixture("unknown-marker")
        original = self.history(root)
        for marker in ("lf-v999", None, 1):
            with self.subTest(marker=marker):
                history = copy.deepcopy(original)
                history["records"][0]["active_record_digest"]["canonicalization"] = marker
                self.write_history(root, history)
                self.consumers(root, accepted=False, diagnostic="canonicalization is unsupported")

    def test_card_owner_is_still_exact_after_line_ending_conversion(self):
        root, card = self.fixture("ownership")
        (root / "naos/completed/T-001.md").write_bytes(card.replace(b"T-001", b"T-002").replace(b"\n", b"\r\n"))
        self.consumers(root, accepted=False, diagnostic="Task identity mismatch")

    def test_only_explicit_crlf_pairs_are_canonicalized(self):
        original = b"x\r\ny\r\nz\rtrail \n\xff"
        self.assertEqual(completed_card_digest(original, "crlf-to-lf-v1"),
                         hashlib.sha256(b"x\ny\nz\rtrail \n\xff").hexdigest())
        self.assertEqual(completed_card_digest(original), hashlib.sha256(original).hexdigest())


if __name__ == "__main__":
    unittest.main()
