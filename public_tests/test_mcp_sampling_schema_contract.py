"""Actual MCP metadata-only report shapes and bounded schema compatibility."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
MCP_ROLES = {
    ".cursor/mcp.json": "cursor_mcp_configuration",
    ".vscode/mcp.json": "vscode_mcp_configuration",
    ".mcp.json": "workspace_mcp_configuration",
}
RAW_HASH = "raw_hash_only_sensitive_configuration"


class MCPSamplingSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="naos-mcp-schema-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.project = Path(cls.temporary.name)
        cls.marker = "SYNTHETIC_MCP_BODY_MUST_NOT_APPEAR_7301"
        cls.authored = {}
        for relative in MCP_ROLES:
            path = cls.project / relative
            path.parent.mkdir(exist_ok=True)
            path.write_text(json.dumps({"mcpServers": {"fixture": {
                "command": "synthetic-command-never-requested",
                "args": [cls.marker],
            }}}), encoding="utf-8")
            cls.authored[relative] = path.read_bytes()
        instructions = cls.project / "CLAUDE.md"
        instructions.write_text("# Synthetic project instructions\nHuman review remains required.\n",
                                encoding="utf-8")
        cls.authored["CLAUDE.md"] = instructions.read_bytes()
        cls.records = {}
        for command, collection, schema_name in (
            ("ai-artifact-inventory", "artifacts", "ai_artifact_inventory.schema.json"),
            ("ai-artifact-reconcile", "decisions", "ai_artifact_reconciliation.schema.json"),
        ):
            result = subprocess.run(
                [sys.executable, "-B", str(ROOT / "cli.py"), command, str(cls.project),
                 "--profile", "standard", "--policy", str(ROOT / "policies/default_policy.yaml"),
                 "--json"],
                cwd=cls.project, capture_output=True, text=True, encoding="utf-8",
                errors="strict", timeout=30,
            )
            if result.returncode:
                raise AssertionError(result.stdout + result.stderr)
            report = json.loads(result.stdout)
            schema = json.loads((ROOT / "schemas/naos" / schema_name).read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            cls.records[collection] = (report, schema)

    def test_actual_reports_match_the_existing_metadata_only_producer(self):
        for collection, (report, schema) in self.records.items():
            with self.subTest(collection=collection):
                self.assertEqual(list(Draft202012Validator(schema).iter_errors(report)), [])
                entries = report[collection]
                self.assertEqual(len(entries), 4)
                self.assertEqual({item["path"] for item in entries}, {*MCP_ROLES, "CLAUDE.md"})
                for item in entries:
                    relative = item["path"]
                    limit = item["deprecation_evidence"]["sample_character_limit"]
                    self.assertEqual(limit, 0 if relative in MCP_ROLES else 12000)
                    if relative in MCP_ROLES:
                        self.assertEqual(item["content_handling"], RAW_HASH)
                        self.assertEqual(item["detected_source"], MCP_ROLES[relative])
                self.assertNotIn(self.marker, json.dumps(report))
        for relative, original in self.authored.items():
            self.assertEqual((self.project / relative).read_bytes(), original)

    def test_zero_requires_exact_path_role_and_raw_hash_metadata(self):
        for collection, (report, schema) in self.records.items():
            validator = Draft202012Validator(schema["properties"][collection]["items"])
            path_field = "path" if collection == "artifacts" else "artifact_path"
            role_field = "artifact_type" if collection == "artifacts" else "detected_source"
            for original in report[collection]:
                if original["path"] not in MCP_ROLES:
                    continue
                with self.subTest(collection=collection, path=original["path"]):
                    self.assertTrue(validator.is_valid(original))
                    for key, value in (
                        (path_field, "src/unlisted-config.json"),
                        (role_field, "claude_context"),
                        ("detected_source", "unlisted_mcp_role"),
                        ("content_handling", "bounded_text_sample"),
                    ):
                        with self.subTest(field=key):
                            changed = copy.deepcopy(original)
                            changed[key] = value
                            self.assertFalse(validator.is_valid(changed))
                    missing = copy.deepcopy(original)
                    missing.pop("content_handling")
                    self.assertFalse(validator.is_valid(missing))
                    if collection == "decisions":
                        changed = copy.deepcopy(original)
                        changed["path"] = "other-alias.json"
                        self.assertFalse(validator.is_valid(changed))

    def test_legacy_limits_optional_metadata_and_other_constraints_stay_valid(self):
        for collection, (report, schema) in self.records.items():
            validator = Draft202012Validator(schema["properties"][collection]["items"])
            for original in report[collection]:
                with self.subTest(collection=collection, path=original["path"]):
                    legacy = copy.deepcopy(original)
                    legacy["deprecation_evidence"]["sample_character_limit"] = 12000
                    self.assertTrue(validator.is_valid(legacy))
                    no_metadata = copy.deepcopy(legacy)
                    no_metadata.pop("deprecation_evidence")
                    self.assertTrue(validator.is_valid(no_metadata))
                    for invalid in (-1, 1, 12001, False, None):
                        changed = copy.deepcopy(legacy)
                        changed["deprecation_evidence"]["sample_character_limit"] = invalid
                        self.assertFalse(validator.is_valid(changed))
                    false_claim = copy.deepcopy(legacy)
                    false_claim["deprecation_evidence"]["verified"] = True
                    self.assertFalse(validator.is_valid(false_claim))
                    if original["path"] not in MCP_ROLES:
                        changed = copy.deepcopy(original)
                        changed["deprecation_evidence"]["sample_character_limit"] = 0
                        changed["content_handling"] = RAW_HASH
                        self.assertFalse(validator.is_valid(changed))


if __name__ == "__main__":
    unittest.main()
