"""Real Git fixtures for the POSIX release builder; no signing or publishing."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
SPEC = importlib.util.spec_from_file_location("release_pack", KIT / "scripts/release/pack.py")
pack = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pack)


@unittest.skipUnless(os.name == "posix", "Release packing is a POSIX CI build operation")
class ReleasePackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="naos-release-pack-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.output = self.root / "dist"
        self.output.mkdir()
        self.git("init", "-q")
        for name, body in {"__init__.py": b'__version__ = "1.1.0"\n',
                           "README.md": b"synthetic release\n", "bin/tool.sh": b"#!/bin/sh\nexit 0\n"}.items():
            target = self.root / name
            target.parent.mkdir(exist_ok=True)
            target.write_bytes(body)
        (self.root / "bin/tool.sh").chmod(0o755)
        rows = [{"path": n, "mode": "0755" if n.endswith(".sh") else "0644",
                 "bytes": len((self.root / n).read_bytes()),
                 "sha256": hashlib.sha256((self.root / n).read_bytes()).hexdigest()}
                for n in ["README.md", "__init__.py", "bin/tool.sh"]]
        self.receipt = {"schema": "naos.public_export_receipt.v1", "candidate_version": "1.1.0",
                        "archive_root": "naos-governance-1.1.0", "files": rows,
                        "source_file_count": len(rows), "source_bytes": sum(r["bytes"] for r in rows),
                        "tree_sha256": hashlib.sha256(json.dumps(rows, sort_keys=True,
                            separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()}
        self.commit_receipt()

    def git(self, *args):
        return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=Synthetic Test",
                               "-c", "user.email=synthetic@example.invalid", *args],
                              cwd=self.root, check=True, capture_output=True, timeout=15)

    def commit_receipt(self):
        (self.root / pack.RECEIPT).write_text(json.dumps(self.receipt) + "\n")
        self.git("add", "README.md", "__init__.py", "bin/tool.sh", pack.RECEIPT)
        self.git("commit", "-qm", "Synthetic release fixture", "--allow-empty")

    def test_pack_preserves_exact_members_modes_bytes_and_metadata(self):
        result = pack.pack(self.root, self.output)
        self.assertEqual(set(result["files"]), {pack.ARCHIVE, pack.RECEIPT})
        self.assertEqual((self.output / pack.RECEIPT).read_bytes(), (self.root / pack.RECEIPT).read_bytes())
        with tarfile.open(self.output / pack.ARCHIVE) as archive:
            leaves = {m.name.split("/", 1)[1]: m for m in archive if m.isfile()}
            self.assertEqual(set(leaves), {"README.md", "__init__.py", "bin/tool.sh", pack.RECEIPT})
            for name, member in leaves.items():
                self.assertEqual(archive.extractfile(member).read(), (self.root / name).read_bytes())
                self.assertEqual(member.mode, 0o755 if name.endswith(".sh") else 0o644)
                self.assertEqual((member.uid, member.gid, member.mtime, member.uname, member.gname), (0, 0, 0, "", ""))
        payload, receipt = pack.committed_payload(self.root)
        one, two = io.BytesIO(), io.BytesIO()
        pack._archive(one, payload, receipt["archive_root"])
        pack._archive(two, payload, receipt["archive_root"])
        self.assertEqual(one.getvalue(), two.getvalue())
        self.assertEqual(one.getvalue(), (self.output / pack.ARCHIVE).read_bytes())

    def test_changed_tracked_source_refuses_before_any_output(self):
        (self.root / "README.md").write_bytes(b"modified")
        with self.assertRaisesRegex(ValueError, "workspace has changed"):
            pack.pack(self.root, self.output)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_untracked_source_refuses(self):
        (self.root / "unreviewed.py").write_text("pass\n")
        with self.assertRaisesRegex(ValueError, "Untracked addition"):
            pack.pack(self.root, self.output)

    def test_receipt_must_match_git_not_just_itself(self):
        for field, value in [("mode", "0755"), ("sha256", "0" * 64), ("bytes", True)]:
            with self.subTest(field=field):
                original = copy.deepcopy(self.receipt)
                self.receipt["files"][0][field] = value
                self.commit_receipt()
                with self.assertRaisesRegex(ValueError, "bytes or mode"):
                    pack.pack(self.root, self.output)
                self.receipt = original

    def test_membership_aggregates_and_version_are_checked(self):
        for field, value in [("source_file_count", 99), ("source_bytes", 0),
                             ("tree_sha256", "0" * 64), ("candidate_version", "2.0.0"),
                             ("archive_root", "../escape")]:
            with self.subTest(field=field):
                original = copy.deepcopy(self.receipt)
                self.receipt[field] = value
                self.commit_receipt()
                with self.assertRaises(ValueError):
                    pack.pack(self.root, self.output)
                self.receipt = original

    def test_duplicate_missing_and_unknown_receipt_rows_refuse(self):
        original = copy.deepcopy(self.receipt)
        for rows in [original["files"][:-1], [original["files"][0]] * 3,
                     [dict(original["files"][0], path="unknown"), *original["files"][1:]]]:
            self.receipt = copy.deepcopy(original)
            self.receipt["files"] = rows
            self.commit_receipt()
            with self.assertRaises(ValueError):
                pack.pack(self.root, self.output)

    def test_unsafe_archive_paths_refuse(self):
        for name in ["../x", "/absolute", "a//b", "a/./b", "dev/private", ".git/config",
                     "a\\b", "C:drive", "line\nbreak"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                pack._path(name)

    def test_linked_tracked_input_refuses(self):
        (self.root / "README.md").unlink()
        (self.root / "README.md").symlink_to("__init__.py")
        self.git("add", "README.md")
        self.git("commit", "-qm", "Synthetic linked input")
        with self.assertRaisesRegex(ValueError, "ordinary public Git blobs"):
            pack.pack(self.root, self.output)

    def test_existing_output_is_preserved_and_blocks_both_creations(self):
        existing = self.output / pack.RECEIPT
        existing.write_bytes(b"existing")
        with self.assertRaisesRegex(ValueError, "already exists"):
            pack.pack(self.root, self.output)
        self.assertEqual(existing.read_bytes(), b"existing")
        self.assertFalse((self.output / pack.ARCHIVE).exists())

    def test_linked_output_directory_refuses(self):
        linked = self.root / "linked-output"
        linked.symlink_to(self.output, target_is_directory=True)
        with self.assertRaises(ValueError):
            pack.pack(self.root, linked)
        self.assertEqual(list(self.output.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
