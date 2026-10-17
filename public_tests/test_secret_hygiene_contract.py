"""Portable secret-scan scope, noise and failure-preservation regressions."""
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator
import yaml

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
spec = importlib.util.spec_from_file_location("secret_contract_common", KIT / "scripts/naos_hygiene_common.py")
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)
SYNTHETIC = "sk-" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"
TOKEN = "aB3dE5fG7hI9jK0mN2pQ4rS6tU8vW+/="


class SecretHygieneContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos secret ü ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "naos").mkdir()

    def write(self, path, value):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value, encoding="utf-8")
        return target

    def scan(self, **rules):
        report = common.check_secret_hygiene(root=self.root, profile="standard", naos_root="naos",
                                            rules=rules, rules_path=None, severity="required")
        schema = json.loads((KIT / "schemas/naos/secret_hygiene.schema.json").read_text())
        Draft202012Validator(schema).validate(report)
        return report

    def test_root_and_selected_dotenv_json_yaml_detect_without_recursive_scope_growth(self):
        self.assertEqual(common.relpath(PureWindowsPath("C:/repo/src/example.py"),
                                        PureWindowsPath("C:/repo")), "src/example.py")
        self.assertEqual(common.relpath(PurePosixPath("/repo/src/literal\\name.py"),
                                        PurePosixPath("/repo")), "src/literal\\name.py")
        paths = [".env", ".env.local", "src/.env", "src/dev.env"]
        for path in paths:
            self.write(path, "export SERVICE_API_KEY=Synthetic1234\n")
        self.write("settings.json", '{"password": "Synthetic1234"}\n')
        self.write("settings.yaml", 'password: "Synthetic1234"\n')
        self.write("unselected/deep.env", "API_KEY=Synthetic1234\n")
        report = self.scan(scan_roots=["src"])
        self.assertEqual({item["path"] for item in report["findings"]}, set(paths + ["settings.json", "settings.yaml"]))
        self.assertEqual(report["summary"]["files_scanned"], 6)
        self.assertEqual(report["summary"]["coverage_status"], "complete")
        self.assertNotIn("Synthetic1234", json.dumps(report))

    def test_explicit_selection_exclusions_and_root_disable_are_preserved(self):
        self.write(".env", "API_KEY=Synthetic1234\n")
        self.write("src/.env", "API_KEY=Synthetic1234\n")
        self.write("src/.env.local", "API_KEY=Synthetic1234\n")
        report = self.scan(scan_roots=["src", "src/.env"], include_root_files=False, exclude_globs=["*.local"])
        self.assertEqual(report["summary"]["files_selected"], 1)
        self.assertEqual({item["path"] for item in report["findings"]}, {"src/.env"})
        self.assertEqual(self.scan(scan_roots=[".env"], include_root_files=False)["summary"]["files_selected"], 1)

    def test_quoted_prefixed_dotenv_and_escaped_assignment_values_are_detected(self):
        self.write("src/.env", 'AUTH_TOKEN="Synthetic1234"\nAUTH_TOKEN=\'Synthetic1234\'\n')
        self.write("settings.json", '{"password": "abc\\\"defghi"}\n')
        self.write("src/example.py", "password = 'abc\\'defghi'\n")
        found = [item for item in self.scan()["findings"] if item.get("pattern_id") == "assigned_secret"]
        self.assertEqual(len(found), 4)
        self.assertEqual({item["path"] for item in found}, {"src/.env", "settings.json", "src/example.py"})

        line = 'AUTH_TOKEN=Synthetic1234 # password="OtherSynthetic1234"'
        self.write("src/.env", line + "\n")
        found = [item for item in self.scan()["findings"]
                 if item.get("pattern_id") == "assigned_secret" and item["path"] == "src/.env"]
        self.assertEqual(len(found), 2)
        # Shared assignment matches point to the field name, as in the consumer contract.
        self.assertEqual({item["column"] for item in found},
                         {line.index("AUTH_TOKEN") + 1, line.index("password") + 1})

    def test_paired_literals_preserve_punctuation_tokens_without_adjacent_prose(self):
        self.write("src/example.py", 'x = "alpha1" + "Beta2"\n'
                   'sentence = "Use 3 profiles, then inspect 42 generated files. Supported 2026.09"\n'
                   f'a = "{TOKEN}"; b = \'{TOKEN.replace("+/=", "-_")}\'\n'
                   f'c = "{TOKEN}\\\"tail"\n')
        found = [item for item in self.scan()["findings"] if item["status"] == "high_entropy_literal"]
        self.assertEqual(len(found), 3)
        self.assertEqual([item["line"] for item in found], [3, 3, 4])
        self.assertEqual(len({item["id"] for item in found}), 3)

    def test_exact_placeholders_do_not_suppress_injected_keys_or_hardcoded_defaults(self):
        clean = ["[ADAPT: project scope 12345]", "[FILL: project scope 12345]", "$MY_SECRET",
                 "${MY_SECRET}", "${{ secrets.MY_SECRET }}", "${{ env.MY_SECRET }}"]
        self.write(".github/agents/example.md", "\n".join(f'password = "{value}"' for value in clean))
        self.assertEqual(self.scan()["summary"]["total_findings"], 0)
        self.write(".github/agents/example.md", f'password = "[ADAPT: {SYNTHETIC}]"\n'
                   'password = "${MY_SECRET:-Synthetic1234}"\npassword = "prefix-${MY_SECRET}"\n')
        report = self.scan()
        self.assertTrue(any(item.get("pattern_id") == "openai_style_key" for item in report["findings"]))
        assigned = [item for item in report["findings"] if item.get("pattern_id") == "assigned_secret"]
        self.assertEqual({item["line"] for item in assigned}, {2, 3})
        self.assertNotIn(SYNTHETIC, json.dumps(report))

    def test_multiple_same_line_rules_have_stable_distinct_identities(self):
        self.write("src/example.py", f'password = "{SYNTHETIC}"; token = "{SYNTHETIC}"\n')
        first = self.scan()
        identities = [item["id"] for item in first["findings"]]
        self.assertEqual(len(identities), 6)
        self.assertEqual(len(set(identities)), len(identities))
        self.assertEqual(identities, [item["id"] for item in self.scan()["findings"]])
        self.assertTrue(all(item["column"] > 0 for item in first["findings"]))

    def test_unreadable_and_invalid_utf8_are_incomplete_without_leaking_values(self):
        target = self.write("src/unreadable.txt", "clean")
        (self.root / "src/invalid.txt").write_bytes(b"\xff\xfeSynthetic1234")
        original = Path.read_bytes
        def read(path, *args, **kwargs):
            if path == target:
                raise PermissionError("Synthetic1234 must not enter report")
            return original(path, *args, **kwargs)
        with patch.object(Path, "read_bytes", read):
            report = self.scan()
        self.assertEqual(report["summary"]["files_selected"], 2)
        self.assertEqual(report["summary"]["files_scanned"], 0)
        self.assertEqual(report["summary"]["files_failed"], 2)
        self.assertEqual(report["summary"]["coverage_status"], "incomplete")
        self.assertEqual({item["status"] for item in report["findings"]}, {"read_error", "decode_error"})
        self.assertNotIn("Synthetic1234", json.dumps(report))

    def test_selected_symlink_leaves_are_unanalyzed_without_opening_targets(self):
        outside = self.root.parent / (self.root.name + "-outside-secret.txt")
        outside.write_text("AUTH_TOKEN=Synthetic1234\n")
        self.addCleanup(outside.unlink)
        self.write("src/clean.txt", "fixture text\n")
        links = [self.root / ".env", self.root / ".env.local", self.root / "src/linked.env"]
        (self.root / "src").mkdir(exist_ok=True)
        try:
            links[0].symlink_to(outside)
            links[1].symlink_to(self.root / "absent-target")
            links[2].symlink_to(outside)
        except OSError as error:
            if os.name == "nt" and getattr(error, "winerror", None) == 1314:
                self.skipTest("owned symlink creation unavailable: WinError1314")
            raise
        original = Path.read_text
        def read(path, *args, **kwargs):
            if path in links or path == outside:
                raise AssertionError("selected symlink target was read")
            return original(path, *args, **kwargs)
        with patch.object(Path, "read_text", read):
            report = self.scan()
        self.assertEqual(report["summary"]["files_selected"], 4)
        self.assertEqual(report["summary"]["files_scanned"], 1)
        self.assertEqual(report["summary"]["files_failed"], 3)
        self.assertEqual(report["summary"]["coverage_status"], "incomplete")
        self.assertEqual({item["status"] for item in report["findings"]}, {"symlink"})
        self.assertGreaterEqual(len(report["known_gaps"]), 3)
        self.assertEqual({item["path"] for item in report["findings"]},
                         {".env", ".env.local", "src/linked.env"})
        self.assertNotIn("Synthetic1234", json.dumps(report))
        self.assertNotIn(str(outside), json.dumps(report))
        strict = subprocess.run([sys.executable, "-B", str(KIT / "cli.py"), "secret-hygiene",
                                 "--profile", "standard", "--strict", "--json"],
                                cwd=self.root, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(strict.returncode, 1, strict.stderr)
        self.assertEqual(json.loads(strict.stdout)["summary"]["coverage_status"], "incomplete")

    def test_clean_control_and_invalid_root_option_are_distinct(self):
        self.write("settings.json", '{"username": "Synthetic1234", "password": "change-me"}\n')
        self.assertEqual(self.scan()["summary"]["total_findings"], 0)
        report = self.scan(include_root_files="false")
        self.assertEqual(report["findings"][0]["status"], "invalid_configuration")
        self.assertTrue(report["scans"]["include_root_files"])

    def test_entropy_literal_exceptions_do_not_hide_assignments_or_modified_values(self):
        public_name = "D3_instruction_following_behavior"
        self.write("src/example.py", f'dimension = "{public_name}"\npassword = "{public_name}"\n'
                   f'modified = "{public_name}-extra123"\ncase_changed = "{public_name.swapcase()}"\n')
        report = self.scan(entropy_allowed_values=[public_name])
        self.assertTrue(any(item.get("pattern_id") == "assigned_secret" and item["line"] == 2 for item in report["findings"]))
        entropy = [item for item in report["findings"] if item["status"] == "high_entropy_literal"]
        self.assertEqual([item["line"] for item in entropy], [3, 4])

    def test_polyglot_defaults_fallback_seed_and_actual_cli_profiles_agree(self):
        seed = yaml.safe_load((KIT / "templates/structural-seeds/naos/secret_hygiene_rules.yaml").read_text())
        spec = importlib.util.spec_from_file_location("secret_cli_defaults", KIT / "scripts/naos_secret_hygiene.py")
        cli_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli_module)
        self.assertEqual(seed["scan_roots"], cli_module.FALLBACK_RULES["scan_roots"])
        self.assertEqual(seed["suffixes"], cli_module.FALLBACK_RULES["suffixes"])
        self.assertEqual(seed["entropy_allowed_values"], [])
        self.assertEqual(cli_module.FALLBACK_RULES["entropy_allowed_values"], seed["entropy_allowed_values"])
        catalog = json.loads((KIT / "scripts/naos_secret_public_literals.json").read_text())
        self.assertTrue(any(
            group["source"] == "autoresearch/graders/static.py"
            and "D3_instruction_following_behavior" in group["values"]
            for group in catalog["groups"]
        ))
        paths = ["services/settings.ts", "packages/settings.TSX", "config/settings.properties",
                 "infra/settings.tf", "src/settings.java", "apps/settings.go", "lib/settings.cs",
                 "cmd/settings.sh", "settings.ENV", ".ENV", "config/.ENV.production", "id_ed25519"]
        for path in paths:
            self.write(path, 'API_KEY=Synthetic1234\n')
        self.write("unknown/deep/config.ts", f'x = "{SYNTHETIC}"')
        self.write("src/image.bin", "unselected suffix")
        self.write("src/vendor/settings.ts", f'x = "{SYNTHETIC}"')
        self.write("naos/secret_hygiene_rules.yaml", yaml.safe_dump({**seed, "exclude_dirs": ["vendor"]}))
        for profile in ("quickstart", "lite", "standard", "assured"):
            with self.subTest(profile=profile):
                result = subprocess.run([sys.executable, "-B", str(KIT / "cli.py"), "secret-hygiene",
                                         "--profile", profile, "--strict", "--json"], cwd=self.root,
                                        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                                        capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0 if profile == "quickstart" else 1, result.stderr)
                report = json.loads(result.stdout)
                Draft202012Validator(json.loads((KIT / "schemas/naos/secret_hygiene.schema.json").read_text())).validate(report)
                actual = {item["path"] for item in report["findings"] if item["status"] == "secret_like_pattern"}
                self.assertEqual(actual, set(paths + ["unknown/deep/config.ts"]))
                self.assertEqual(report["scans"]["coverage_basis"], "selected_files_only")
                inventory = {item["path"]: item["status"] for item in report["scans"]["scope_inventory"]}
                self.assertEqual(inventory["src/image.bin"], "unselected_suffix")
                self.assertEqual(inventory["src/vendor"], "excluded")
                self.assertEqual(inventory["unknown/deep/config.ts"], "selected")
                self.assertTrue(any(item["path"] == "unknown" and item["status"] == "selected_root" for item in report["scans"]["root_entries"]))
                self.assertEqual(report["summary"]["discovered_excluded_files"], 0)
                self.assertEqual(report["summary"]["discovered_excluded_directories"], 1)
                self.assertNotIn(SYNTHETIC, result.stdout + result.stderr)
        fallback = self.scan(**cli_module.FALLBACK_RULES)
        self.assertTrue(set(paths) <= {item["path"] for item in fallback["findings"]})

    def test_scope_counts_are_bounded_and_explicit_selection_retains_authority(self):
        self.write("src/ok.py", "value = 1")
        self.write("src/no.bin", "ignored suffix")
        self.write("services/secret.ts", f'x = "{SYNTHETIC}"')
        self.write("root.json", '{}')
        self.write("vendor/deeper/secret.py", f'x = "{SYNTHETIC}"')
        report = self.scan(scan_roots=["src", "absent"], include_root_files=False, exclude_dirs=["vendor"])
        self.assertEqual(report["summary"]["files_selected"], 1)
        self.assertEqual(report["summary"]["discovered_unselected_files"], 2)
        self.assertEqual(report["summary"]["unselected_root_directories"], 2) # services and naos
        root_entries = {item["path"]: item["status"] for item in report["scans"]["root_entries"]}
        self.assertEqual(root_entries["vendor"], "excluded")
        self.assertEqual(root_entries["services"], "unselected_directory")
        self.assertIn({"path": "absent", "status": "absent_optional"}, report["scans"]["root_selection"])
        self.assertNotIn("vendor/deeper/secret.py", json.dumps(report))
        self.assertEqual(report["summary"]["coverage_status"], "complete")
        self.assertNotIn("secret_like_pattern", {item["status"] for item in report["findings"]})

    def test_explicit_whole_and_nested_root_inventory_labels_are_accurate(self):
        self.write("custom/deep/ok.py", "value = 1")
        whole = self.scan(scan_roots=["."], include_root_files=False)
        self.assertEqual(whole["summary"]["unselected_root_directories"], 0)
        nested = self.scan(scan_roots=["custom/deep"], include_root_files=False)
        self.assertIn({"path": "custom", "kind": "directory", "status": "contains_selected_root"}, nested["scans"]["root_entries"])
        self.assertEqual(nested["summary"]["files_selected"], 1)


    def test_waivers_are_visible_bounded_and_keep_provider_and_private_key_findings(self):
        self.write("src/waivers.ts", f'password = "{SYNTHETIC}" # naos: allow-secret\n'
                   f'x = "{TOKEN}" // naos: allow-secret\n'
                   'x = "-----BEGIN OPENSSH PRIVATE KEY-----" # naos: allow-secret\n'
                   'safe = 1 # naos: allow-secret\n'
                   'password = "Synthetic1234"\n')
        report = self.scan()
        self.assertEqual(report["summary"]["inline_waivers"], 4)
        self.assertEqual(report["summary"]["suppressed_findings"], 3)
        self.assertEqual([item["line"] for item in report["waivers"]], [1, 2, 3, 4])
        self.assertEqual(report["waivers"][0]["rule_counts"], {"assigned_secret": 1, "high_entropy": 1})
        self.assertEqual(report["waivers"][2]["rule_counts"], {})
        found = {(item.get("pattern_id"), item.get("line")) for item in report["findings"]}
        self.assertIn(("openai_style_key", 1), found)
        self.assertIn(("private_key_header", 3), found)
        self.assertIn(("assigned_secret", 5), found)
        self.assertTrue(all(item["severity"] == "advisory" for item in report["findings"] if item["status"] == "inline_waiver"))
        self.assertNotIn(SYNTHETIC, json.dumps(report))
        self.assertNotIn(TOKEN, json.dumps(report))

    def test_quoted_substring_and_nontrailing_markers_never_waive(self):
        self.write("src/markers.py", 'password = "Synthetic1234 naos: allow-secret"\n'
                   'password = "Synthetic1234 # naos: allow-secret"\n'
                   'password = "Synthetic1234" # unrelated naos: allow-secret\n'
                   'password = "Synthetic1234" # naos: allow-secret extra text\n')
        report = self.scan()
        self.assertEqual(report["waivers"], [])
        self.assertEqual({item["line"] for item in report["findings"] if item.get("pattern_id") == "assigned_secret"}, {1, 2, 3, 4})

    def test_only_first_unquoted_comment_can_waive_nested_delimiters(self):
        comments = ["# documentation says # naos: allow-secret",
                    "// documentation says // naos: allow-secret",
                    "# documentation says // naos: allow-secret",
                    "// documentation says # naos: allow-secret",
                    "# # naos: allow-secret", "// // naos: allow-secret"]
        self.write("src/nested_markers.ts", "\n".join(
            'password = "Synthetic1234" ' + comment for comment in comments))
        report = self.scan()
        self.assertEqual(report["waivers"], [])
        self.assertEqual(report["summary"]["suppressed_findings"], 0)
        self.assertEqual({item["line"] for item in report["findings"]
                          if item.get("pattern_id") == "assigned_secret"}, set(range(1, 7)))
        self.assertNotIn("Synthetic1234", json.dumps(report))

    def test_first_comment_parser_respects_literal_delimiters_and_escapes(self):
        valid = [
            'password = "Synthetic1234"; label = "# documentation" # naos: allow-secret',
            'password = "Synthetic1234"; label = \'// documentation\' // naos: allow-secret',
            'password = "Synthetic1234"; label = `# // documentation` # naos: allow-secret',
            'password = "Synthetic1234"; label = "escaped \\\" # documentation" # naos: allow-secret',
            r"password = 'abc\'defghi' # naos: allow-secret",
        ]
        self.write("src/quoted_markers.ts", "\n".join(valid))
        report = self.scan()
        self.assertEqual(report["summary"]["inline_waivers"], len(valid))
        self.assertEqual([item["line"] for item in report["waivers"]], list(range(1, len(valid) + 1)))
        self.assertFalse(any(item.get("pattern_id") == "assigned_secret" for item in report["findings"]))
        for line in ['password = "Synthetic1234 # naos: allow-secret"',
                     "password = 'Synthetic1234 // naos: allow-secret'",
                     'password = `Synthetic1234 # naos: allow-secret`',
                     r'password = "Synthetic1234"; label = "escaped \" # naos: allow-secret"']:
            with self.subTest(line=line):
                self.assertFalse(common._line_allowed(line))


    def test_assignment_waiver_alone_is_advisory_in_actual_assured_cli(self):
        self.write("src/fixture.py", 'password = "Synthetic1234" # naos: allow-secret\n')
        result = subprocess.run([sys.executable, "-B", str(KIT / "cli.py"), "secret-hygiene",
                                 "--profile", "assured", "--strict", "--json"], cwd=self.root,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "advisory")
        self.assertEqual(report["summary"]["suppressed_findings"], 1)
        self.assertEqual(report["waivers"][0]["path"], "src/fixture.py")
        self.assertNotIn("Synthetic1234", result.stdout + result.stderr)


    def test_actual_cli_strict_exit_and_sarif_keep_occurrences_and_read_failure(self):
        self.write(".env", f'API_KEY={SYNTHETIC}\n')
        self.write("src/example.py", f'x = "{SYNTHETIC}"; y = "{SYNTHETIC}"\n')
        (self.root / "src/invalid.txt").write_bytes(b"\xff")
        environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        def run(*args):
            return subprocess.run([sys.executable, "-B", str(KIT / "cli.py"), *args], cwd=self.root,
                                  env=environment, capture_output=True, text=True, timeout=60)
        normal = run("secret-hygiene", "--profile", "standard", "--json")
        strict = run("secret-hygiene", "--profile", "standard", "--strict", "--json")
        self.assertEqual(normal.returncode, 0, normal.stderr)
        self.assertEqual(strict.returncode, 1, strict.stderr)
        report = json.loads(strict.stdout)
        self.assertEqual(report["summary"]["coverage_status"], "incomplete")
        exported = run("sarif-export", "--profile", "standard", "--json")
        self.assertEqual(exported.returncode, 0, exported.stderr)
        outputs = list((self.root / "naos/reports").glob("*.sarif"))
        self.assertEqual(len(outputs), 1)
        sarif = json.loads(outputs[0].read_text())
        results = sarif["runs"][0]["results"]
        fingerprints = [item["partialFingerprints"]["naosFindingFingerprint"] for item in results]
        self.assertEqual(len(fingerprints), len(set(fingerprints)))
        self.assertTrue(any("could not be read" in item["message"]["text"] for item in results))
        self.assertNotIn(SYNTHETIC, json.dumps(sarif))


if __name__ == "__main__":
    unittest.main()
