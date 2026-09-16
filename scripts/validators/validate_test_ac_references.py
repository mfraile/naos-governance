#!/usr/bin/env python3
"""
validate_test_ac_references.py — Test-Hallucination Detector (NAOS portable)

Cross-references AC / SCEN identifiers found inside test files against the
identifiers actually defined in `specs/06-acceptance.md` (or any markdown file
under SPECS_ROOT). Tests that reference a non-existent AC/SCEN are likely
"test hallucinations": the assertion looks legitimate but verifies nothing
real (closes G1).

Tier 1 action A6 (test-hallucination detector).

ENV VARS:
    SPECS_ROOT   — specs directory     (default: specs)
    TESTS_ROOT   — tests directory     (default: tests)

USAGE:
    python scripts/validators/validate_test_ac_references.py
    python scripts/validators/validate_test_ac_references.py --staged

EXIT CODES:
    0 — All AC/SCEN references in tests resolve to a defined identifier
    1 — One or more test files reference undefined AC/SCEN ids (hallucination)
    2 — Requested Git snapshot or relevant contents cannot be read
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import subprocess
import sys
from pathlib import Path

# Recognise both spec ID conventions:
#   AC-103.2, AC-103.2.1
#   SCEN-1.1, SCEN-S.1, SCEN-P.1
ID_PATTERN = re.compile(r"\b((?:AC|SCEN)-[A-Z0-9]+(?:\.[0-9]+)+)\b")
TEST_FILE_GLOBS = ("test_*.py", "*_test.py", "*.spec.ts", "*.test.ts", "*.spec.js")


def collect_defined_ids(specs_root: Path) -> set[str]:
    """Scan all .md files under specs_root for AC- / SCEN- identifiers."""
    defined: set[str] = set()
    if not specs_root.is_dir():
        return defined
    for md in specs_root.rglob("*.md"):
        text = md.read_text(encoding="utf-8")
        defined.update(ID_PATTERN.findall(text))
    return defined


def iter_test_files(tests_root: Path) -> list[Path]:
    if not tests_root.is_dir():
        return []
    files: list[Path] = []
    for pattern in TEST_FILE_GLOBS:
        files.extend(tests_root.rglob(pattern))
    return files


def git_bytes(*args: str) -> bytes:
    result = subprocess.run(["git", *args], capture_output=True, check=False)
    if result.returncode:
        raise ValueError(f"Cannot read Git snapshot: {result.stderr.decode('utf-8', errors='replace').strip()}")
    return result.stdout


def tree_blobs(tree: str) -> dict[str, tuple[str, str]]:
    """Read paths and immutable object identities from one captured Git tree."""
    entries = {}
    for record in git_bytes("ls-tree", "-r", "-z", "--full-tree", tree).split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        if kind == "blob":
            entries[os.fsdecode(raw_path)] = (mode, oid)
    return entries


def historical_definitions(specs_root: Path) -> bool:
    """Distinguish initial onboarding from removal of an authored contract.

    Only needed when the current snapshot has no definitions. A shallow clone
    cannot establish that criteria were never authored; CI fetches full history.
    Non-Git projects retain the documented initial-onboarding no-op.
    """
    probe = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, check=False)
    if probe.returncode:
        return False
    root = Path(os.fsdecode(probe.stdout).removesuffix("\n"))
    prefix = Path(os.path.abspath(specs_root)).relative_to(root).as_posix()
    head = subprocess.run(["git", "rev-parse", "--verify", "--quiet", "HEAD"], capture_output=True, check=False)
    if head.returncode:
        return False
    for revision in git_bytes("log", "--full-history", "--format=%H", "HEAD", "--", prefix).decode("ascii").splitlines():
        for path, (mode, oid) in tree_blobs(revision).items():
            if (prefix == "." or path.startswith(prefix + "/")) and path.endswith(".md"):
                if mode not in {"100644", "100755"}:
                    raise ValueError(f"Historical specification is not a regular file: {path}")
                if ID_PATTERN.search(git_bytes("cat-file", "blob", oid).decode("utf-8")):
                    return True
    if git_bytes("rev-parse", "--is-shallow-repository").strip() == b"true":
        raise ValueError("No current criteria; full Git history is required to establish an unconfigured project")
    return False


def snapshot_references(specs_root: Path, tests_root: Path) -> tuple[set[str], dict[Path, set[str]], bool]:
    """Compare index test blobs to index definitions, including spec-only edits.

    write-tree freezes the index once and rejects unmerged entries. Later reads
    use object IDs, so unstaged changes and subsequent index edits cannot mix
    the snapshots. It does not change the index or working tree.
    """
    root = Path(os.fsdecode(git_bytes("rev-parse", "--show-toplevel")).removesuffix("\n"))
    def relative(path: Path) -> str:
        # Do not resolve symlinks through the mutable working tree.
        absolute = Path(os.path.abspath(path))
        try:
            return absolute.relative_to(root).as_posix().rstrip("/")
        except ValueError as exc:
            raise ValueError(f"Staged validation root is outside Git repository: {path}") from exc

    spec_prefix = relative(specs_root)
    relative(tests_root)
    def under(path: str, prefix: str) -> bool:
        return prefix == "." or path.startswith(prefix + "/")
    def spec(path: str) -> bool:
        return under(path, spec_prefix) and path.endswith(".md")
    def test(path: str) -> bool:
        return any(fnmatch.fnmatchcase(Path(path).name, pattern) for pattern in TEST_FILE_GLOBS)
    tree = git_bytes("write-tree").decode("ascii").strip()
    current = tree_blobs(tree)
    head = subprocess.run(["git", "rev-parse", "--verify", "--quiet", "HEAD"], capture_output=True, check=False)
    previous = tree_blobs(head.stdout.decode("ascii").strip()) if head.returncode == 0 else {}
    changed = {p for p in current.keys() | previous.keys() if current.get(p) != previous.get(p)}
    changed_specs = any(spec(p) for p in changed)
    cache: dict[str, str] = {}
    def contents(entry: tuple[str, str], path: str) -> str:
        mode, oid = entry
        if mode not in {"100644", "100755"}:
            raise ValueError(f"Relevant staged path is not a regular file: {path}")
        if oid not in cache:
            cache[oid] = git_bytes("cat-file", "blob", oid).decode("utf-8")
        return cache[oid]

    defined: set[str] = set()
    for path, entry in current.items():
        if spec(path):
            defined.update(ID_PATTERN.findall(contents(entry, path)))
    # Preserve the documented greenfield no-op, but deleting the final
    # previously defined criterion is a contract edit, not initial onboarding.
    previously_configured = changed_specs and any(
        ID_PATTERN.search(contents(entry, path)) for path, entry in previous.items() if spec(path)
    )
    refs = {}
    for path, entry in current.items():
        if test(path) and (path in changed or changed_specs):
            refs[Path(path)] = set(ID_PATTERN.findall(contents(entry, path)))
    return defined, refs, bool(previously_configured)


def find_references(test_files: list[Path]) -> dict[Path, set[str]]:
    """Return {file: {ids referenced}}."""
    refs: dict[Path, set[str]] = {}
    for tf in test_files:
        text = tf.read_text(encoding="utf-8")
        ids = set(ID_PATTERN.findall(text))
        if ids:
            refs[tf] = ids
    return refs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--staged",
        action="store_true",
        help="Validate index test/spec blobs; spec changes recheck all indexed tests.",
    )
    parser.add_argument(
        "--specs-root",
        default=os.environ.get("SPECS_ROOT", "specs"),
        help="Path to specs/ directory (default: specs)",
    )
    parser.add_argument(
        "--tests-root",
        default=os.environ.get("TESTS_ROOT", "tests"),
        help="Path to tests/ directory (default: tests)",
    )
    args = parser.parse_args()

    specs_root = Path(args.specs_root)
    tests_root = Path(args.tests_root)

    if args.staged:
        try:
            defined, refs, previously_configured = snapshot_references(specs_root, tests_root)
        except (OSError, ValueError, UnicodeError) as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 2
        test_files = list(refs)
    else:
        try:
            defined = collect_defined_ids(specs_root)
            test_files = iter_test_files(tests_root)
            # Match pre-commit's recognized tracked tests, including colocated
            # tests outside TESTS_ROOT, while reading checkout bytes in CI.
            probe = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, check=False)
            if probe.returncode == 0:
                root = Path(os.fsdecode(probe.stdout).removesuffix("\n"))
                indexed = git_bytes("ls-files", "-z", "--full-name").split(b"\0")
                test_files += [root / os.fsdecode(path) for path in indexed if path and
                               any(fnmatch.fnmatchcase(Path(os.fsdecode(path)).name, pattern) for pattern in TEST_FILE_GLOBS)]
            test_files = sorted(set(test_files))
            refs = find_references(test_files)
            previously_configured = False
        except (OSError, ValueError, UnicodeError) as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 2

    if not test_files:
        # Nothing to check — silent success (avoids noisy commits in greenfield repos).
        return 0

    if not defined and not previously_configured and any(refs.values()):
        try:
            previously_configured = historical_definitions(specs_root)
        except (OSError, ValueError, UnicodeError) as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 2

    if not defined and not previously_configured:
        # Two cases collapse to the same no-op:
        #   (a) specs/ directory is missing entirely (greenfield repo)
        #   (b) specs/ exists but no AC-/SCEN- ids have been authored yet
        #       (mid-onboarding, lite tier without 06-acceptance.md, or template
        #        stubs only). Failing here would block every test commit until
        #        the user authors at least one AC — terrible first impression.
        if not specs_root.is_dir():
            print(f"[WARN] specs root '{specs_root}' missing — skipping AC reference check")
        else:
            print(f"[INFO] No AC-/SCEN- ids defined under '{specs_root}' yet — skipping AC reference check")
        return 0

    violations: list[tuple[Path, set[str]]] = []
    for tf, ids in refs.items():
        missing = ids - defined
        if missing:
            violations.append((tf, missing))

    if not violations:
        return 0

    print("[FAIL] Test files reference AC/SCEN ids that are not defined in specs:")
    for tf, missing in violations:
        for mid in sorted(missing):
            print(f"  {tf}: {mid}")
    print()
    print("Either (a) define the ids in specs/06-acceptance.md, or")
    print("       (b) remove the phantom AC/SCEN references from the tests.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
