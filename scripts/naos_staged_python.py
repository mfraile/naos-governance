"""Select staged adopter Python; unchanged manifest-recorded scaffold is omitted.

This is a lint/header selection boundary, never a secret-scanning exemption.
Local hash chains establish consistency, not authenticity or approval.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys

import naos_secret_managed_operands as managed


def _git(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(["git", *arguments], cwd=root, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError("staged Python selection not evaluated: Git command failed")
    return result.stdout


def _recorded_scaffold(context):
    """Read fully linked existing manifests; any ambiguity grants no omission."""
    inventories = []
    for family, prove, relative in (
        (managed._MANAGED_ROOT, managed._legacy_operands, "/state/manifest.json"),
        (managed._WINDOWS_ROOT, managed._windows_operands, "/manifest.json"),
        (managed._PORTABLE_ROOT, managed._portable_operands, "/manifest.json"),
    ):
        try:
            prove(context)
            manifest = context.object(family + relative)
            body = manifest if family == managed._MANAGED_ROOT else manifest["body"]
            records = {}
            for entry in body["entries"]:
                relative = entry["path"]
                if family == managed._MANAGED_ROOT:
                    identity = entry["base"]
                    size = identity["size"]
                    executable = bool(identity["mode"] & 0o111)
                elif family == managed._PORTABLE_ROOT:
                    identity = entry["content"]
                    if identity is None:
                        continue
                    size = int(identity["size_decimal"])
                    executable = identity["executable"]
                else:
                    relative = "/".join(managed._windows_relative_path(relative))
                    base = context.object(family + "/bases/" + entry["base_sha256"] + ".json")["body"]
                    identity = base["content"]
                    size = int(identity["size_decimal"])
                    # Windows scaffold mode is a Git executable bit, not a DACL.
                    executable = None
                records[relative] = (identity["sha256"], size, executable)
            inventories.append(records)
        except (OSError, ValueError, TypeError, KeyError, RecursionError, RuntimeError):
            continue
    # Coexisting active generations need an explicit reconciliation, not a guess.
    return inventories[0] if len(inventories) == 1 else {}


def selected_staged_python(root: Path) -> list[str]:
    root = root.resolve(strict=True)
    names = [os.fsdecode(raw) for raw in _git(
        root, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z",
    ).split(b"\0") if raw and raw.endswith(b".py")]
    if not names:
        return []
    context = managed.ProofBudget(root)
    recorded = _recorded_scaffold(context)
    selected = []
    for name in names:
        expected = recorded.get(name)
        if expected is None:
            selected.append(name)
            continue
        try:
            row = _git(root, "ls-files", "--stage", "-z", "--", name).split(b"\0")
            if len(row) != 2 or row[-1] != b"":
                raise ValueError("ambiguous index entry")
            metadata, indexed_name = row[0].split(b"\t", 1)
            mode, object_id, stage = metadata.split(b" ")
            if (os.fsdecode(indexed_name) != name or stage != b"0"
                    or mode not in {b"100644", b"100755"}):
                raise ValueError("nonregular or unmerged index entry")
            working = context.read(name)
            if (len(working) != expected[1]
                    or _git(root, "cat-file", "-s", object_id.decode("ascii")).strip()
                    != str(expected[1]).encode("ascii")):
                raise ValueError("changed scaffold size")
            indexed = _git(root, "cat-file", "blob", object_id.decode("ascii"))
            observed = context.root.joinpath(*name.split("/")).lstat()
            if (observed.st_nlink != 1 or not stat.S_ISREG(observed.st_mode)
                    or indexed != working or hashlib.sha256(indexed).hexdigest() != expected[0]
                    or (expected[2] is not None and (mode == b"100755") != expected[2])
                    or (expected[2] is None and mode != b"100644")
                    or (os.name != "nt" and bool(observed.st_mode & 0o111) != (mode == b"100755"))):
                raise ValueError("changed scaffold content or mode")
        except (OSError, ValueError, TypeError, KeyError, RecursionError, RuntimeError):
            selected.append(name)
    try:
        context.verify_cached()
    except (OSError, ValueError, TypeError, KeyError, RecursionError, RuntimeError):
        return names
    return selected


def check_staged_headers(root: Path, paths: list[str]) -> int:
    """Use the canonical validator with index bytes, without report publication."""
    import naos_module_header_traceability as canonical

    sources = {}
    for path in paths:
        rows = _git(root, "ls-files", "--stage", "-z", "--", path).split(b"\0")
        if len(rows) != 2 or rows[-1] != b"":
            raise RuntimeError("staged header check has an ambiguous index entry")
        metadata, name = rows[0].split(b"\t", 1)
        mode, object_id, stage = metadata.split(b" ")
        if (os.fsdecode(name) != path or stage != b"0"
                or mode not in {b"100644", b"100755"}
                or not (root / path).is_file()):
            raise RuntimeError(f"staged header source unavailable or nonregular: {path}")
        sources[path] = _git(root, "cat-file", "blob", object_id.decode("ascii")).decode(
            "utf-8", errors="ignore")
    naos_root = os.environ.get("NAOS_ROOT")
    policy = canonical.load_policy(None, naos_root, root)
    naos_root = naos_root or canonical.default_naos_root(policy)
    profile = canonical.normalize_profile(os.environ.get("NAOS_TIER"), policy)
    rules_path, rules_source = canonical.resolve_rules_path(root, naos_root, policy)
    report = canonical.build_report(root=root, profile=profile, naos_root=naos_root,
                                    policy=policy, rules_path=rules_path, rules_source=rules_source,
                                    source_texts=sources)
    for item in report["findings"]:
        # Excluded or outside-source staged files are not a configuration gap.
        # Actual selection gaps and malformed configuration remain visible.
        if item["status"] == "not_configured" and report.get("coverage", {}).get("status") == "not_assessed":
            continue
        print(f"[WARN] Module header {item['path']}: {item['message']}")
    # Hook header enforcement remains soft, including Assured.
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ruff", action="store_true")
    parser.add_argument("--headers", action="store_true")
    args = parser.parse_args(argv)
    try:
        paths = selected_staged_python(Path.cwd())
        if not paths:
            print("   no staged adopter Python; unchanged recorded scaffold omitted")
            return 0
        if args.ruff:
            return subprocess.run(["ruff", "check", "--quiet", "--", *paths], check=False).returncode
        if args.headers:
            return check_staged_headers(Path.cwd(), paths)
        for path in paths:
            print(path)
        return 0
    except (ImportError, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"[WARN] Staged Python checks not evaluated: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
