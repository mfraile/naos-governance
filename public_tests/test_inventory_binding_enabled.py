"""Inventory binding status follows the existing model-policy boolean rules."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator
import yaml

ROOT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
COMPONENT = "AI-TOOL-BINDING-CODEX-PLANNING"


class InventoryBindingEnabledTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.project = Path(temporary.name).resolve()
        (self.project / "naos").mkdir()
        self.model_path = self.project / "naos/model_provider_policy.yaml"
        self.seed = yaml.safe_load((ROOT / "templates/structural-seeds/naos/model_provider_policy.yaml").read_text(encoding="utf-8"))
        (self.project / "naos/ai_component_inventory_rules.yaml").write_bytes(
            (ROOT / "templates/structural-seeds/naos/ai_component_inventory_rules.yaml").read_bytes())
        self.environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        self.environment.pop("NAOS_ROOT", None)

    def declare(self, parent, detail):
        data = yaml.safe_load(yaml.safe_dump(self.seed))
        data["tool_model_bindings"]["codex"].update(enabled=parent, roles={"planning": detail})
        self.model_path.write_text(yaml.safe_dump(data), encoding="utf-8")

    def invoke(self, script, *options, profile="standard", expected_exit=0):
        before = hashlib.sha256(self.model_path.read_bytes()).hexdigest()
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts" / script), "--profile", profile, *options],
            cwd=self.project, env=self.environment, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, expected_exit, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(hashlib.sha256(self.model_path.read_bytes()).hexdigest(), before)
        return result

    def reports(self, *, profile="standard", strict=False, active=False):
        # This fixture declares no provider route: canonical model-policy keeps
        # its declaration-only exit, while inventory has its own completeness gate.
        canonical = json.loads(self.invoke("naos_model_provider_policy.py", "--json", profile=profile,
                                           expected_exit=0).stdout)
        result = self.invoke("naos_ai_component_inventory.py", "--json", *(["--strict"] if strict else []),
                             profile=profile, expected_exit=1 if strict and active else 0)
        inventory = json.loads(result.stdout)
        saved = json.loads((self.project / "naos/reports/ai_component_inventory.json").read_text(encoding="utf-8"))
        self.assertEqual(inventory, saved)
        schema = json.loads((ROOT / "schemas/naos/ai_component_inventory.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(inventory)
        component = next(row for row in inventory["components"] if row["component_id"] == COMPONENT)
        findings = [row for row in inventory["findings"] if row.get("component_id") == COMPONENT]
        self.assertFalse(canonical["runtime_enabled"])
        self.assertFalse(canonical["provider_calls_allowed"])
        return canonical, inventory, component, findings

    def test_child_boolean_overrides_parent_and_only_absent_key_inherits(self):
        cases = ((True, {"enabled": False}, False), (False, {"enabled": True}, True),
                 (True, {"enabled": True}, True), (False, {"enabled": False}, False),
                 (True, {}, True), (False, {}, False),
                 (True, {"enabled": None}, False), (True, {"enabled": "false"}, False),
                 (True, {"enabled": 1}, False))
        for parent, detail, enabled in cases:
            with self.subTest(parent=parent, detail=detail):
                self.declare(parent, detail)
                canonical, inventory, component, findings = self.reports(active=enabled)
                self.assertEqual(canonical["summary"]["active_tool_role_bindings"], int(enabled))
                self.assertEqual(component["status"], "active" if enabled else "declared_disabled")
                self.assertEqual(len([row for row in findings if row["id"] == "ai_component_inventory.active_declaration_incomplete"]), int(enabled))
                tool = next(row for row in inventory["components"] if row["component_id"] == "AI-TOOL-CODEX")
                self.assertEqual(tool["status"], "active" if parent else "declared_disabled")
                if "enabled" in detail and type(detail["enabled"]) is not bool:
                    self.assertTrue(any(row["id"] == "boolean_setting_invalid" for row in canonical["findings"]))

    def test_active_incomplete_bindings_keep_profile_findings_and_strict_exit(self):
        for profile in ("quickstart", "lite", "standard", "assured"):
            with self.subTest(profile=profile):
                self.declare(False, {"enabled": True})
                canonical, _, component, findings = self.reports(profile=profile, active=True)
                self.assertEqual(canonical["summary"]["active_tool_role_bindings"], 1)
                self.assertEqual(component["status"], "active")
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["severity"], "required" if profile in {"standard", "assured"} else "warning")
        self.declare(True, {"enabled": True})
        self.reports(active=True, strict=True)
        self.declare(True, {"enabled": False})
        _, _, component, findings = self.reports(strict=True)
        self.assertEqual(component["status"], "declared_disabled")
        self.assertFalse(findings)

    def test_corrected_inventory_is_current_and_status_tampering_still_refuses(self):
        self.declare(True, {"enabled": False})
        _, inventory, component, _ = self.reports()
        self.assertEqual(component["status"], "declared_disabled")
        self.invoke("naos_ai_component_inventory.py", "--check")
        component["status"] = "active"
        path = self.project / "naos/reports/ai_component_inventory.json"
        path.write_text(json.dumps(inventory), encoding="utf-8")
        tampered = path.read_bytes()
        refused = self.invoke("naos_ai_component_inventory.py", "--check", expected_exit=1)
        self.assertIn("inventory_content_mismatch", refused.stderr)
        self.assertEqual(path.read_bytes(), tampered)
