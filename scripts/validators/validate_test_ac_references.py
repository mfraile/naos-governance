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
    python scripts/validators/validate_test_ac_references.py --staged   # only staged tests

EXIT CODES:
    0 — All AC/SCEN references in tests resolve to a defined identifier
    1 — One or more test files reference undefined AC/SCEN ids (hallucination)
    2 — SPECS_ROOT or TESTS_ROOT missing (skipped, not a failure when --staged)
"""

from __future__ import annotations

import argparse
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
        try:
            text = md.read_text(encoding="utf-8")
        except OSError:
            continue
        defined.update(ID_PATTERN.findall(text))
    return defined


def iter_test_files(tests_root: Path) -> list[Path]:
    if not tests_root.is_dir():
        return []
    files: list[Path] = []
    for pattern in TEST_FILE_GLOBS:
        files.extend(tests_root.rglob(pattern))
    return files


def staged_test_files() -> list[Path]:
    """Return only staged test files (used by pre-commit)."""
    try:
        out = subprocess.check_output(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    paths: list[Path] = []
    for line in out.splitlines():
        p = Path(line.strip())
        if not p.exists():
            continue
        name = p.name
        if any(p.match(g) for g in TEST_FILE_GLOBS) or name.startswith("test_") or name.endswith("_test.py"):
            paths.append(p)
    return paths


def find_references(test_files: list[Path]) -> dict[Path, set[str]]:
    """Return {file: {ids referenced}}."""
    refs: dict[Path, set[str]] = {}
    for tf in test_files:
        try:
            text = tf.read_text(encoding="utf-8")
        except OSError:
            continue
        ids = set(ID_PATTERN.findall(text))
        if ids:
            refs[tf] = ids
    return refs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--staged",
        action="store_true",
        help="Validate only staged test files (pre-commit mode).",
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

    defined = collect_defined_ids(specs_root)

    if args.staged:
        test_files = staged_test_files()
    else:
        test_files = iter_test_files(tests_root)

    if not test_files:
        # Nothing to check — silent success (avoids noisy commits in greenfield repos).
        return 0

    if not defined:
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

    refs = find_references(test_files)
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
