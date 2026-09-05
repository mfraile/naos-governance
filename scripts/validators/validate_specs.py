#!/usr/bin/env python3
"""
validate_specs.py — Spec-Kit specification validator (NAOS portable)

Checks:
1. Required spec files exist and are non-empty
2. FR-XXX requirements have implementation references in source
3. Spec traceability comments in key source files
4. PM framework files exist (DASHBOARD, BACKLOG, TRACEABILITY_MATRIX)

[ADAPT] Extend REQUIRED_SPECS list and pm_files list to match your project.

ENV VARS:
    NAOS_ROOT  — naos/ directory  (default: naos)
    SPECS_ROOT — specs/ directory (default: specs)
    SRC_ROOT   — source directory, comma-separated roots supported
                 (default: infer src, app, apps, packages, lib when present)

EXIT CODES:
    0 — All checks pass
    1 — One or more checks failed
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

# Shared requirement-header parser (single source of truth across cascade scripts)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import spec_header  # noqa: E402
from source_roots import (  # noqa: E402
    existing_source_roots,
    resolve_source_roots,
    source_roots_display,
)
try:
    from validator_context import is_kit_repository, print_kit_skip  # noqa: E402
except ModuleNotFoundError:
    def is_kit_repository() -> bool:
        return False

    def print_kit_skip(validator_name: str, reason: str) -> None:
        print(f"{validator_name}: SKIP")
        print(f"  - kit repo context: {reason}")

# ── Path configuration ────────────────────────────────────────────────────────
NAOS_ROOT = Path(os.getenv("NAOS_ROOT", "naos"))
SPECS_ROOT = Path(os.getenv("SPECS_ROOT", "specs"))
ACCEPTANCE_SPEC = SPECS_ROOT / "06-acceptance.md"

# ANSI codes
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"
PROFILE_IDS = {"quickstart", "lite", "standard", "assured"}
STRICT_QUALITY_PROFILES = {"standard", "assured"}
NORMATIVE_RE = re.compile(r"\b(?:SHALL|MUST)\b", re.IGNORECASE)
REQ_LINK_RE = re.compile(r"^\*\*Requirement\*\*:\s*(.+)$", re.MULTILINE)
DRAFT_MARKERS = ("[ADAPT", "ADAPT:", "TODO", "TBD")

# ── Checks ────────────────────────────────────────────────────────────────────


def configured_source_roots() -> list[Path]:
    """Return explicit or inferred source roots for brownfield adopters."""
    return resolve_source_roots(Path.cwd())


def iter_source_python_files(roots: list[Path]) -> list[Path]:
    files: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        files.extend(sorted(root.rglob("*.py")))
    return files


def validate_spec_files() -> bool:
    """Check that required spec files exist and are non-empty (>100 bytes)."""
    print(f"\n{YELLOW}Validating Spec Files …{RESET}")

    # [ADAPT] Remove or add spec filenames to match your project
    required_specs = [
        "01-problem.md",
        "02-solution.md",
        "03-requirements.md",
        "04-architecture.md",
    ]

    missing = []
    for spec in required_specs:
        spec_path = SPECS_ROOT / spec
        if not spec_path.exists():
            missing.append(spec)
        elif spec_path.stat().st_size < 100:
            missing.append(f"{spec} (empty/placeholder)")

    if missing:
        print(f"{RED}✗ Missing or incomplete spec files:{RESET}")
        for spec in missing:
            print(f"  - {SPECS_ROOT}/{spec}")
        return False

    print(f"{GREEN}✓ All {len(required_specs)} spec files exist{RESET}")
    return True


def validate_requirements() -> bool:
    """Check all FR-XXX requirements have implementation references in source."""
    print(f"\n{YELLOW}Validating Functional Requirements …{RESET}")

    req_file = SPECS_ROOT / "03-requirements.md"
    if not req_file.exists():
        print(f"{YELLOW}⚠ {req_file} not found — skipping{RESET}")
        return True
    roots = existing_source_roots()
    if not roots:
        checked = source_roots_display(configured_source_roots())
        print(f"{YELLOW}⚠ No source roots found — checked {checked}; skipping{RESET}")
        return True

    text = req_file.read_text(encoding="utf-8", errors="ignore")
    requirements = sorted(spec_header.canonical_frs(text))

    if not requirements:
        # A non-empty requirements file that yields zero parseable FR headers is a
        # real failure (header-level/format mismatch), not a pass. Returning PASS
        # here previously meant the validator silently validated nothing.
        if req_file.stat().st_size > 100:
            print(
                f"{RED}✗ No parseable FR/NFR requirement headers in {req_file}{RESET}"
            )
            print(
                "  Expected '## FR-XXX:' or '### FR-XXX:' headers — check the header level."
            )
            return False
        print(f"{YELLOW}⚠ No FR-XXX requirements found in {req_file}{RESET}")
        return True

    print(f"Found {len(requirements)} functional requirements")
    print(f"Searching source roots: {source_roots_display(roots)}")
    source_files = iter_source_python_files(roots)
    missing = []
    for req_id in requirements:
        found = any(
            req_id in py.read_text(errors="ignore") for py in source_files
        )
        if not found:
            missing.append(req_id)

    if missing:
        print(f"{RED}✗ Missing implementations:{RESET}")
        for req in missing:
            print(f"  - {req}")
        return False

    print(f"{GREEN}✓ All {len(requirements)} requirements have implementations{RESET}")
    return True


def normalize_profile(value: str | None) -> str:
    profile = (value or os.getenv("NAOS_PROFILE") or "quickstart").strip().lower()
    if profile.startswith("governance-"):
        profile = profile.removeprefix("governance-")
    if profile not in PROFILE_IDS:
        raise ValueError(
            f"Unsupported profile {value!r}; expected one of {', '.join(sorted(PROFILE_IDS))}"
        )
    return profile


def requirement_blocks(text: str) -> dict[str, str]:
    """Return requirement-id to block text using the shared H2/H3 parser."""
    matches = list(spec_header.REQ_HEADER_RE.finditer(text))
    blocks: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        blocks[match.group(1).upper()] = text[match.start() : end]
    return blocks


def is_draft_requirement(block: str) -> bool:
    upper = block.upper()
    return any(marker in upper for marker in DRAFT_MARKERS)


def acceptance_requirement_links() -> tuple[set[str], bool]:
    if not ACCEPTANCE_SPEC.exists():
        return set(), False
    text = ACCEPTANCE_SPEC.read_text(encoding="utf-8", errors="ignore")
    linked: set[str] = set()
    for match in REQ_LINK_RE.finditer(text):
        linked.update(spec_header.fr_tokens(match.group(1)))
    return linked, True


def validate_requirement_quality(strict: bool) -> bool:
    """Check bounded requirement prose and Spec 06 scenario linkage quality."""
    print(f"\n{YELLOW}Validating Requirement Quality …{RESET}")

    req_file = SPECS_ROOT / "03-requirements.md"
    if not req_file.exists():
        print(f"{YELLOW}⚠ {req_file} not found — skipping{RESET}")
        return True

    blocks = requirement_blocks(req_file.read_text(encoding="utf-8", errors="ignore"))
    if not blocks:
        print(f"{YELLOW}⚠ No parseable requirement blocks found — covered by Functional Requirements check{RESET}")
        return True

    weak_requirements = [
        req_id
        for req_id, block in sorted(blocks.items())
        if not is_draft_requirement(block) and not NORMATIVE_RE.search(block)
    ]

    linked_requirements, acceptance_present = acceptance_requirement_links()
    missing_scenarios = [
        req_id
        for req_id, block in sorted(blocks.items())
        if req_id.startswith("FR-")
        and not is_draft_requirement(block)
        and req_id not in linked_requirements
    ]

    if not weak_requirements and not missing_scenarios:
        print(f"{GREEN}✓ Requirement quality checks passed{RESET}")
        return True

    if weak_requirements:
        print(f"{YELLOW}⚠ Requirements without SHALL/MUST language:{RESET}")
        for req_id in weak_requirements:
            print(f"  - {req_id}")
    if missing_scenarios:
        if not acceptance_present:
            print(f"{YELLOW}⚠ {ACCEPTANCE_SPEC} not found — scenario links unavailable{RESET}")
        print(f"{YELLOW}⚠ Functional requirements without Spec 06 scenario links:{RESET}")
        for req_id in missing_scenarios:
            print(f"  - {req_id}")

    if strict:
        print(f"{RED}✗ Strict spec-quality mode failed{RESET}")
        return False

    print(f"{YELLOW}⚠ Requirement quality warnings are advisory in this profile/mode{RESET}")
    return True


def validate_spec_traceability() -> bool:
    """Check that key source files have traceability comments."""
    print(f"\n{YELLOW}Validating Spec Traceability …{RESET}")

    roots = existing_source_roots()
    if not roots:
        checked = source_roots_display(configured_source_roots())
        print(f"{YELLOW}⚠ No source roots found — checked {checked}; skipping{RESET}")
        return True

    api_files: list[Path] = []
    for root in roots:
        api_files.extend(
            list(root.rglob("*/main.py")) + list(root.rglob("*/engine.py"))
        )
    if not api_files:
        print(f"{YELLOW}⚠ No key implementation files found — skipping{RESET}")
        return True

    with_trace = []
    without_trace = []
    for py_file in api_files:
        try:
            content = py_file.read_text()
            if re.search(r"# (Implements|Reference|Spec).*FR-\d+", content):
                with_trace.append(py_file)
            else:
                without_trace.append(py_file)
        except Exception:
            continue

    total = len(with_trace) + len(without_trace)
    if without_trace:
        print(
            f"{YELLOW}⚠ {len(without_trace)}/{total} files missing traceability:{RESET}"
        )
        for f in without_trace[:5]:
            print(f"  - {f}")
        print(f"  Add '# Implements FR-XXX from specs/03-requirements.md' comments")
    if with_trace:
        print(f"{GREEN}✓ {len(with_trace)}/{total} files have traceability{RESET}")
    return True  # Advisory only


def validate_implementation_status() -> bool:
    """Check PM framework files exist and PROJECT_STATUS.md is recent (≤7 days)."""
    print(f"\n{YELLOW}Validating PM Framework Status Files …{RESET}")

    import time

    # [ADAPT] Add / remove PM governance files here
    pm_files = [
        NAOS_ROOT / "PROJECT_STATUS.md",
        NAOS_ROOT / "BACKLOG.md",
        NAOS_ROOT / "TRACEABILITY_MATRIX.md",
    ]

    all_exist = True
    for pm_file in pm_files:
        if not pm_file.exists():
            print(f"{RED}✗ {pm_file} not found{RESET}")
            all_exist = False

    if not all_exist:
        return False

    status_file = NAOS_ROOT / "PROJECT_STATUS.md"
    age_days = (time.time() - status_file.stat().st_mtime) / 86400
    if age_days > 7:
        print(
            f"{YELLOW}⚠ {status_file} last updated {int(age_days)} days ago — update after each sprint{RESET}"
        )
    else:
        print(
            f"{GREEN}✓ PM framework files exist and PROJECT_STATUS.md is recent{RESET}"
        )

    return True


# ── main ──────────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate NAOS spec-kit specification files.")
    parser.add_argument("--profile", default=os.getenv("NAOS_PROFILE") or "quickstart")
    parser.add_argument(
        "--strict-spec-quality",
        action="store_true",
        help="Fail on weak non-draft requirement prose or missing Spec 06 scenario links in standard/assured profiles.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    profile = normalize_profile(args.profile)
    strict_quality_requested = args.strict_spec_quality or os.getenv("NAOS_STRICT_SPEC_QUALITY") == "1"
    strict_quality = strict_quality_requested and profile in STRICT_QUALITY_PROFILES
    if is_kit_repository():
        print_kit_skip(
            "Spec-Kit Validation",
            "requires adopter specs/ and generated PM framework files",
        )
        return 0

    print(f"\n{'=' * 60}")
    print(f"{GREEN}NAOS — Spec-Kit Validation{RESET}")
    print(f"{'=' * 60}")
    if strict_quality_requested and not strict_quality:
        print(f"{YELLOW}Spec-quality strict mode is advisory for profile {profile}.{RESET}")

    checks = [
        ("Spec Files", validate_spec_files),
        ("Functional Requirements", validate_requirements),
        ("Requirement Quality", lambda: validate_requirement_quality(strict_quality)),
        ("Spec Traceability", validate_spec_traceability),
        ("Implementation Status", validate_implementation_status),
    ]

    results = []
    for name, fn in checks:
        try:
            results.append((name, fn()))
        except Exception as e:
            print(f"{RED}✗ {name} check error: {e}{RESET}")
            results.append((name, False))

    print(f"\n{'=' * 60}")
    print(f"{GREEN}Validation Summary{RESET}")
    print(f"{'=' * 60}\n")

    passed = sum(1 for _, r in results if r)
    for name, r in results:
        status = f"{GREEN}✓ PASS{RESET}" if r else f"{RED}✗ FAIL{RESET}"
        print(f"{status} — {name}")

    print(f"\n{passed}/{len(results)} checks passed")

    if passed == len(results):
        print(f"\n{GREEN}✓ All validation checks passed!{RESET}\n")
        return 0

    print(f"\n{RED}✗ Some validation checks failed{RESET}\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
