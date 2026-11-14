"""Known dotenv/key inputs must not publish guessable raw-content digests."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
SPEC = importlib.util.spec_from_file_location("secret_hash_privacy_common", KIT / "scripts/naos_hygiene_common.py")
common = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(common)


class SecretInputHashPrivacyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write(self, relative, raw):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def scan(self, **rules):
        report = common.check_secret_hygiene(
            root=self.root, profile="standard", naos_root="naos",
            rules=rules, rules_path=None, severity="required")
        schema = json.loads((KIT / "schemas/naos/secret_hygiene.schema.json").read_text())
        Draft202012Validator(schema).validate(report)
        return report

    def test_all_known_sensitive_names_omit_hash_but_keep_findings_and_coverage(self):
        names = [".env", ".env.local", ".ENV.EXAMPLE", "development.env", "app.ENV",
                 "private.pem", "PRIVATE.PEM", "private.key", "PRIVATE.KEY",
                 "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "ID_RSA"]
        files = {}
        for index, name in enumerate(names):
            # Separate directories also exercise case-insensitive native filesystems.
            relative = f"inputs/{index}/{name}"
            raw = f"DB_PASSWORD=SyntheticPrivate{index:02d}\n".encode()
            self.write(relative, raw)
            files[relative] = raw
        report = self.scan()
        rows = {row["path"]: row for row in report["scans"]["input_files"]}
        self.assertEqual(set(rows), set(files))
        self.assertEqual(report["summary"]["coverage_status"], "complete")
        self.assertEqual(report["summary"]["files_scanned"], len(files))
        self.assertEqual({f["path"] for f in report["findings"]}, set(files))
        rendered = json.dumps(report)
        for relative, raw in files.items():
            with self.subTest(path=relative):
                self.assertEqual(rows[relative], {"path": relative, "status": "read", "size_bytes": len(raw)})
                self.assertNotIn(hashlib.sha256(raw).hexdigest(), rendered)
                self.assertNotIn(raw.decode().strip().split("=", 1)[1], rendered)

    def test_low_entropy_unflagged_dotenv_is_still_not_hashable(self):
        raw = b"DB_PASSWORD=hunter2\n"
        self.write(".env", raw)
        report = self.scan()
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["scans"]["input_files"], [{"path": ".env", "status": "read", "size_bytes": len(raw)}])
        self.assertNotIn(hashlib.sha256(raw).hexdigest(), json.dumps(report))

    def test_custom_selection_does_not_restore_sensitive_hashes_or_change_normal_hashes(self):
        sensitive = b"AUTH_TOKEN=SyntheticPrivateCustom\r\n"
        ordinary = b"# Ordinary public source\r\n"
        self.write("selected/.env.local", sensitive)
        self.write("selected/normal.py", ordinary)
        self.write("outside/.env", b"DB_PASSWORD=OtherSyntheticPrivate\n")
        report = self.scan(scan_roots=["selected"], include_root_files=False, suffixes=[".py", ".env"])
        rows = {row["path"]: row for row in report["scans"]["input_files"]}
        self.assertEqual(set(rows), {"selected/.env.local", "selected/normal.py"})
        self.assertNotIn("sha256", rows["selected/.env.local"])
        self.assertEqual(rows["selected/normal.py"]["sha256"], hashlib.sha256(ordinary).hexdigest())
        self.assertEqual(rows["selected/normal.py"]["size_bytes"], len(ordinary))
        self.assertEqual(report["summary"]["files_scanned"], 2)

    def test_cli_json_and_written_report_both_omit_sensitive_hash(self):
        raw = b"DB_PASSWORD=hunter2\n"
        self.write(".env", raw)
        output = self.root / "result.json"
        process = subprocess.run(
            [sys.executable, "-B", str(KIT / "scripts/naos_secret_hygiene.py"), str(self.root),
             "--profile", "standard", "--json", "--output", str(output)],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(process.returncode, 0, process.stderr)
        emitted = json.loads(process.stdout)
        self.assertEqual(emitted, json.loads(output.read_text()))
        self.assertNotIn("sha256", emitted["scans"]["input_files"][0])
        self.assertNotIn(hashlib.sha256(raw).hexdigest(), process.stdout)


if __name__ == "__main__":
    unittest.main()
