"""Generated role descriptions must not become invented kit resource URIs."""

import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(ROOT))
import naos_init  # noqa: E402


class GeneratedRoleProseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.fixtures = {}
        for profile in ("lite", "standard", "assured"):
            base = Path(cls.temporary.name).resolve() / profile
            host = base / "host"
            host.mkdir(parents=True)
            target = base / "preview"
            paths = naos_init.scaffold_files(
                host, profile, "custom", "static_only", target,
                signals=naos_init._empty_signals(), memory_choice="disabled", emit_progress=False,
            )
            cls.fixtures[profile] = target, paths

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_generated_guidance_does_not_invent_role_resource_references(self):
        inspected = set()
        for profile, (root, paths) in self.fixtures.items():
            for relative in paths:
                if not (relative.startswith((".github/", ".agents/", ".claude/")) or relative in {"AGENTS.md", "CLAUDE.md"}):
                    continue
                path = root / relative
                if path.suffix not in {".md", ".mdc"}:
                    continue
                inspected.add(profile)
                body = path.read_text(encoding="utf-8")
                with self.subTest(profile=profile, path=relative):
                    self.assertNotIn("kit://adopter", body)
                    self.assertNotIn("kit://development", body)
        self.assertEqual(inspected, {"lite", "standard", "assured"})

    def test_actual_authoring_resources_still_project_or_remain_explicit_dependencies(self):
        body = "Read templates/agents/naos-review.agent.md and templates/integrations/unselected.md."
        for profile in ("quickstart", "lite", "standard", "assured"):
            for portable in (False, True):
                with self.subTest(profile=profile, portable=portable):
                    rendered = naos_init._project_host_route_body(
                        body, portable=portable, inventory={".github/agents/naos-review.agent.md"},
                        skill_names=set(), tier=profile,
                    )
                    self.assertIn(".github/agents/naos-review.agent.md", rendered)
                    self.assertIn("kit://templates/integrations/unselected.md", rendered)
                    self.assertNotIn("kit://adopter", rendered)


if __name__ == "__main__":
    unittest.main()
