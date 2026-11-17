"""Pack a clean public Git checkout for the manual release-provenance job.

This build-workspace helper is not an adopter command or an authorization
boundary. It uses committed blobs, checks the receipt against Git, and retains
new partial outputs on failure. It never downloads, publishes or changes refs.
"""
from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile

RECEIPT = "NAOS_PUBLIC_EXPORT_MANIFEST.json"
ARCHIVE = "naos-public-export.tar.gz"
MAX_BYTES = 64 * 1024 * 1024


def _git(root: Path, *args: str, data: bytes | None = None) -> bytes:
    return subprocess.run(
        ["git", "--no-replace-objects", *args], cwd=root, input=data,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=60,
    ).stdout


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _path(name: str) -> None:
    if (not isinstance(name, str) or not name or "\\" in name or ":" in name
            or any(ord(c) < 32 or ord(c) == 127 for c in name)
            or PurePosixPath(name).is_absolute()
            or any(p in {"", ".", "..", ".git", "dev"} for p in name.split("/"))):
        raise ValueError("Unsafe public archive path")


def committed_payload(root: Path) -> tuple[dict[str, tuple[str, bytes]], dict]:
    """Validate committed identity, workspace, receipt and exact payload modes."""
    if root.resolve() != root or root.is_symlink():
        raise ValueError("Build workspace must be a physical directory")
    if _git(root, "rev-parse", "--show-toplevel").decode().strip() != str(root):
        raise ValueError("Expected the public Git root")
    if _git(root, "status", "--porcelain=v1", "--untracked-files=no"):
        raise ValueError("Tracked build workspace has changed")
    for raw in _git(root, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0"):
        if raw and not raw.decode().startswith(("dist/", "build/", "naos_governance.egg-info/")):
            raise ValueError("Untracked addition to public build workspace")
    entries = []
    for row in _git(root, "ls-tree", "-r", "-z", "--full-tree", "HEAD").split(b"\0"):
        if not row:
            continue
        info, raw_name = row.split(b"\t", 1)
        mode, kind, oid = info.decode().split()
        name = raw_name.decode("utf-8")
        _path(name)
        if mode not in {"100644", "100755"} or kind != "blob":
            raise ValueError("Only ordinary public Git blobs can be packed")
        entries.append((name, mode, oid))
    if not entries or len(entries) > 4096:
        raise ValueError("Unexpected public Git inventory size")
    blobs = io.BytesIO(_git(root, "cat-file", "--batch",
                           data="".join(oid + "\n" for _, _, oid in entries).encode()))
    payload = {}
    total = 0
    for name, mode, oid in entries:
        header = blobs.readline().decode().strip().split()
        if len(header) != 3 or header[:2] != [oid, "blob"]:
            raise ValueError("Git blob response does not match tree")
        size = int(header[2])
        total += size
        if not 0 <= size <= MAX_BYTES or total > 256 * 1024 * 1024:
            raise ValueError("Public payload exceeds build bound")
        body = blobs.read(size)
        if len(body) != size or blobs.read(1) != b"\n":
            raise ValueError("Truncated Git blob")
        actual = root / name
        if actual.resolve() != actual or not stat.S_ISREG(actual.lstat().st_mode):
            raise ValueError("Linked or nonregular workspace input")
        if actual.read_bytes() != body:
            raise ValueError("Workspace bytes differ from committed blob")
        if name in payload:
            raise ValueError("Duplicate Git path")
        payload[name] = (mode, body)
    if blobs.read():
        raise ValueError("Extra Git blob response")
    if RECEIPT not in payload or payload[RECEIPT][0] != "100644":
        raise ValueError("Missing ordinary public export receipt")
    receipt = json.loads(payload[RECEIPT][1], object_pairs_hook=_object)
    if not isinstance(receipt, dict) or receipt.get("schema") != "naos.public_export_receipt.v1":
        raise ValueError("Unexpected public export receipt schema")
    rows = receipt.get("files")
    if not isinstance(rows, list) or len(rows) != len(payload) - 1:
        raise ValueError("Receipt membership differs from public Git")
    names = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "mode", "sha256", "bytes"}:
            raise ValueError("Malformed receipt row")
        name = row["path"]
        _path(name)
        if name == RECEIPT or name not in payload or name in names:
            raise ValueError("Receipt membership differs from public Git")
        mode, body = payload[name]
        if (row["mode"] != ("0755" if mode == "100755" else "0644")
                or type(row["bytes"]) is not int or row["bytes"] != len(body)
                or row["sha256"] != hashlib.sha256(body).hexdigest()):
            raise ValueError("Receipt bytes or mode differ from public Git")
        names.append(name)
    if set(names) != set(payload) - {RECEIPT}:
        raise ValueError("Receipt membership differs from public Git")
    encoded = json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    if (receipt.get("tree_sha256") != hashlib.sha256(encoded).hexdigest()
            or type(receipt.get("source_file_count")) is not int
            or receipt["source_file_count"] != len(rows)
            or type(receipt.get("source_bytes")) is not int
            or receipt["source_bytes"] != sum(len(payload[n][1]) for n in names)):
        raise ValueError("Receipt aggregate does not match payload")
    version_nodes = ast.parse(payload["__init__.py"][1].decode()).body
    versions = [ast.literal_eval(node.value) for node in version_nodes
                if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets)]
    if (len(versions) != 1 or not isinstance(versions[0], str)
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", versions[0])
            or receipt.get("candidate_version") != versions[0]
            or receipt.get("archive_root") != "naos-governance-" + versions[0]):
        raise ValueError("Version and archive-root identity disagree")
    return payload, receipt


def _archive(raw, payload: dict[str, tuple[str, bytes]], archive_root: str) -> None:
    directories = {PurePosixPath(archive_root)}
    for name in payload:
        directories.update(PurePosixPath(archive_root) / p
                           for p in PurePosixPath(name).parents if str(p) != ".")
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as tar:
            for directory in sorted(directories, key=str):
                info = tarfile.TarInfo(str(directory).rstrip("/") + "/")
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ""
                tar.addfile(info)
            for name in sorted(payload):
                mode, body = payload[name]
                info = tarfile.TarInfo(f"{archive_root}/{name}")
                info.size, info.mode = len(body), (0o755 if mode == "100755" else 0o644)
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ""
                tar.addfile(info, io.BytesIO(body))


def pack(root: Path, output: Path) -> dict:
    """Create absent outputs beneath a held POSIX CI-workspace directory."""
    if os.name != "posix":
        raise ValueError("Release packing requires a POSIX build workspace")
    payload, receipt = committed_payload(root)
    if output.resolve() != output or output.is_symlink():
        raise ValueError("Build output must be a physical directory")
    parent = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    written = {}
    try:
        for name in (ARCHIVE, RECEIPT):
            # Preflight both names before creating either; never overwrite.
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("Release output already exists")
        for name in (ARCHIVE, RECEIPT):
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o644, dir_fd=parent)
            with os.fdopen(fd, "w+b") as stream:
                if name == ARCHIVE:
                    _archive(stream, payload, receipt["archive_root"])
                else:
                    stream.write(payload[RECEIPT][1])
                stream.flush()
                held = os.fstat(stream.fileno())
                named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if (held.st_dev, held.st_ino, held.st_nlink) != (named.st_dev, named.st_ino, 1):
                    raise ValueError("Release output identity changed")
                stream.seek(0)
                written[name] = hashlib.file_digest(stream, "sha256").hexdigest()
    finally:
        os.close(parent)
    return {"files": written, "tree_sha256": receipt["tree_sha256"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kit", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(pack(args.kit.absolute(), args.output.absolute()), sort_keys=True))
    except (OSError, ValueError, KeyError, SyntaxError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"Release packing refused: {exc}; retain any new partial outputs for review\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
