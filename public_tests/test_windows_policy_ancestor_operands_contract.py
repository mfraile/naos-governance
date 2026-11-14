"""Exact saved default-policy path metadata; portable tests are not native proof."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

import test_secret_managed_inventory_contract as fixtures


managed = fixtures.managed
common = fixtures.common
LABEL = "naos-wave1-install-2wuxk84r"
TOKEN = "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"
PREFIX = ("body", "plan", "source_policy_observation", "ancestors")


class WindowsPolicyAncestorTests(unittest.TestCase):
    def setUp(self):
        self.seed = fixtures.WindowsConstructorCoordinatesTests()
        self.seed.setUp()
        self.addCleanup(self.seed.doCleanups)
        # The portable adapter's physical root is POSIX. Keep its synthetic
        # project label short so this case isolates external policy ancestry.
        self.seed.logical = managed.PureWindowsPath(r"C:\fixture")
        self.seed.kit = (
            "C:\\Users\\fixture\\" + LABEL
            + "\\venv\\Lib\\site-packages\\naos_governance"
        )

    def prepare(self, mutate=None, *, volume=None):
        def configure(plan):
            observation = plan["source_policy_observation"]
            parts = observation["path"].split("\\")
            source_volume = volume or self.seed.identity["volume_serial_hex"]
            observation["identity"] = {
                "volume_serial_hex": source_volume,
                "file_id_hex": format(99999, "032x"),
            }
            observation["ancestors"] = [
                {
                    "name": name,
                    "volume_serial_hex": source_volume,
                    "file_id_hex": format(10000 + index, "032x"),
                }
                for index, name in enumerate(("", *parts[:-1]))
            ]
            if mutate:
                mutate(plan)
        self.seed.fixture(configure)

    def coordinates(self):
        context = self.seed.context()
        text, spans, diagnostic = self.seed.spans(self.seed.op + "/plan.json", context)
        coordinates = context.constructor_coordinates.get(managed._WINDOWS_ROOT, {})
        return text, spans, diagnostic, coordinates.get(self.seed.op + "/plan.json", {})

    def source_coordinates(self, coordinates):
        return {key: value for key, value in coordinates.items() if key[:len(PREFIX)] == PREFIX}

    def scan(self):
        with (
            patch.object(common, "_ScannerProofBudget", side_effect=lambda root: self.seed.context(True)),
            patch.object(managed, "__file__", self.seed.kit + "\\scripts\\naos_secret_managed_operands.py"),
        ):
            return common.check_secret_hygiene(
                root=self.seed.root, profile="standard", naos_root="naos",
                rules={"scan_roots": [self.seed.op + "/plan.json"], "include_root_files": False},
                rules_path=None, severity="blocking",
            )

    def test_default_policy_ancestor_names_have_exact_scoped_coordinates(self):
        self.prepare()
        text, spans, diagnostic, coordinates = self.coordinates()
        self.assertEqual(diagnostic["status"], "proved")
        ancestors = self.seed.plan["source_policy_observation"]["ancestors"]
        expected = {PREFIX + (index, "name"): row["name"] for index, row in enumerate(ancestors)}
        self.assertEqual(self.source_coordinates(coordinates), expected)
        self.assertEqual(sum(json.loads(text[a:b]) == LABEL for a, b in spans), 1)

    def test_reproduced_installation_label_is_not_an_entropy_finding(self):
        self.prepare()
        report = self.scan()
        self.assertEqual(report["summary"]["total_findings"], 0, report["findings"])

    def test_foreign_occurrence_and_neighbor_credentials_remain_scanned(self):
        self.prepare(lambda plan: plan["private_file_policy"].update(copied_parent=LABEL, api_key=TOKEN))
        text, spans, diagnostic, coordinates = self.coordinates()
        self.assertEqual(diagnostic["status"], "proved")
        self.assertTrue(self.source_coordinates(coordinates))
        self.assertEqual(sum(json.loads(text[a:b]) == LABEL for a, b in spans), 1)
        self.assertFalse(any(json.loads(text[a:b]) == TOKEN for a, b in spans))
        report = self.scan()
        self.assertGreater(report["summary"]["regex_matches"], 0)
        self.assertGreater(report["summary"]["entropy_matches"], 0)

    def test_absent_legacy_ancestry_keeps_existing_path_coordinates(self):
        self.seed.fixture()
        _, _, diagnostic, coordinates = self.coordinates()
        self.assertEqual(diagnostic["status"], "proved")
        self.assertFalse(self.source_coordinates(coordinates))
        self.assertEqual(coordinates[("body", "plan", "source_policy_observation", "path")],
                         self.seed.plan["source_policy_observation"]["path"])

    def test_malformed_ancestry_grants_no_additional_name_coordinates(self):
        for variant in ("name", "length", "shape", "volume", "identity", "file_alias", "missing_identity"):
            with self.subTest(variant=variant):
                def alter(plan):
                    observation = plan["source_policy_observation"]
                    ancestors = observation["ancestors"]
                    if variant == "name":
                        ancestors[1]["name"] = "unrelated-parent"
                    elif variant == "length":
                        ancestors.pop()
                    elif variant == "shape":
                        ancestors[1]["credential"] = TOKEN
                    elif variant == "volume":
                        ancestors[1]["volume_serial_hex"] = "f" * 16
                    elif variant == "identity":
                        ancestors[1]["file_id_hex"] = "not-a-file-id"
                    elif variant == "file_alias":
                        ancestors[1].update(observation["identity"])
                    else:
                        observation.pop("identity")
                self.prepare(alter)
                self.assertFalse(self.source_coordinates(self.coordinates()[3]))

    def test_other_source_volume_is_not_confused_with_project_volume(self):
        self.seed.kit = "D:" + self.seed.kit[2:]
        self.prepare(volume="f" * 16)
        self.assertTrue(self.source_coordinates(self.coordinates()[3]))

    def test_copied_role_pin_must_match_exact_default_policy_path(self):
        self.prepare()
        path = self.seed.plan["source_policy_observation"]["path"]
        for pin, expected in ((hashlib.sha256(path.encode()).hexdigest(), True), ("0" * 64, False)):
            with self.subTest(expected=expected), patch.object(managed, "COPIED_SOURCE_POLICY_PATH_SHA256", pin):
                self.assertEqual(bool(self.source_coordinates(self.coordinates()[3])), expected)

    def test_copied_metadata_outside_control_plan_has_no_admission(self):
        self.prepare()
        body = copy.deepcopy(self.seed.plan["source_policy_observation"])
        self.assertFalse(self.seed.spans("data/copied.json", text=json.dumps(body))[1])

    def test_additional_coordinates_obey_existing_representation_budget(self):
        self.prepare()
        context = self.seed.context()
        self.seed.spans(self.seed.op + "/plan.json", context)
        count = sum(len(row) for row in context.constructor_coordinates[managed._WINDOWS_ROOT].values())
        with patch.object(managed, "MAX_REPRESENTATIONS", count - 1):
            self.assertFalse(self.coordinates()[3])


if __name__ == "__main__":
    unittest.main()
