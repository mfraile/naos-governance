#!/usr/bin/env python3
"""
validate_architecture_coherence.py — Architecture coherence validator (NAOS portable)

Checks for common architectural anti-patterns across ANY project:

1. Module boundary violations — imports that cross forbidden boundaries
   defined in configs/naos_architecture_boundaries.yaml
2. Hardcoded config values in source code (values that belong in configs/)
3. Missing architecture documentation (specs/04-architecture.md)
4. Circular / cross-layer imports (heuristic check via regex)

[ADAPT] Edit BOUNDARY_CONFIG path and HARDCODE_PATTERNS to match your project.

ENV VARS:
    NAOS_ROOT  — naos/ directory  (default: naos)
    SPECS_ROOT — specs/ directory (default: specs)
    SRC_ROOT   — source directory or comma-separated roots
                 (default: infer src, app, apps, packages, lib when present)
    CONFIGS_DIR — configs/ dir   (default: configs)

EXIT CODES:
    0 — No architecture violations
    1 — Violations found
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from architecture_boundaries import (  # noqa: E402
    BoundaryPolicyError,
    find_boundary_violations,
    load_boundary_policy,
)
from source_roots import existing_source_roots  # noqa: E402
from naos_console import configure_console_output  # noqa: E402

try:
    from validator_context import is_kit_repository, print_kit_skip
except ModuleNotFoundError:

    def is_kit_repository() -> bool:
        return False

    def print_kit_skip(validator_name: str, reason: str) -> None:
        print(f"{validator_name}: SKIP")
        print(f"  - kit repo context: {reason}")


# ── Path configuration ────────────────────────────────────────────────────────
NAOS_ROOT = Path(os.getenv("NAOS_ROOT", "naos"))
SPECS_ROOT = Path(os.getenv("SPECS_ROOT", "specs"))
CONFIGS_DIR = Path(os.getenv("CONFIGS_DIR", "configs"))

BOUNDARY_CONFIG = CONFIGS_DIR / "naos_architecture_boundaries.yaml"

# [ADAPT] Patterns that suggest hardcoded values that belong in configs/
HARDCODE_PATTERNS: List[Tuple[str, str]] = [
    (r'(host|url|endpoint)\s*=\s*["\']https?://[a-zA-Z0-9._-]+', "Hardcoded URL/host"),
    (r"(port)\s*=\s*\d{4,5}(?!\s*#\s*default)", "Hardcoded port number"),
    (r"(timeout|max_retries)\s*=\s*\d+(?!\s*#\s*default)", "Hardcoded timeout/retry"),
    (
        r'(password|api_key|secret)\s*=\s*["\'][^$][^"\']+["\']',
        "Possible hardcoded credential",
    ),
]

EXCLUDE_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "tests",
    "test",
    "migrations",
}


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


def load_boundary_rules():
    """Load the shared policy, preserving malformed configuration as a finding."""
    return load_boundary_policy(BOUNDARY_CONFIG)


# ── Checks ────────────────────────────────────────────────────────────────────


def check_module_boundaries() -> Tuple[bool, List[str]]:
    """Check for imports that violate boundary rules in naos_architecture_boundaries.yaml."""
    try:
        policy = load_boundary_rules()
    except BoundaryPolicyError as exc:
        return False, [f"Malformed boundary policy: {exc}"]
    if policy.status == "unconfigured":
        return True, [
            f"Boundary policy unconfigured ({policy.placeholders} placeholder rules)"
        ]

    root = Path.cwd()
    roots = tuple(existing_source_roots(root))
    findings = [
        finding
        for py_file in _iter_source_files()
        for finding in find_boundary_violations(py_file.resolve(), root, roots, policy)
    ]
    issues = [
        f"{finding.source}:{finding.line}: {finding.severity} forbidden import '{finding.target}'"
        + (f" ({finding.reason})" if finding.reason else "")
        for finding in findings
    ]
    return not any(finding.severity == "ERROR" for finding in findings), issues


def check_hardcoded_values() -> Tuple[bool, List[str]]:
    """Warn when source files contain values that belong in configs/."""
    issues: List[str] = []

    for py_file in _iter_source_files():
        text = py_file.read_text(encoding="utf-8", errors="ignore")
        for pattern, description in HARDCODE_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                rel = _relative_to_source_root(py_file)
                issues.append(f"{rel}: {description} (move to configs/)")

    return len(issues) == 0, issues


def check_architecture_doc() -> Tuple[bool, List[str]]:
    """Verify specs/04-architecture.md exists and is non-trivial."""
    arch_doc = SPECS_ROOT / "04-architecture.md"
    if not arch_doc.exists():
        return False, [f"{arch_doc} not found — create an architecture spec"]
    if arch_doc.stat().st_size < 200:
        return False, [f"{arch_doc} looks like an empty placeholder (<200 bytes)"]
    return True, []


def check_no_config_in_source() -> Tuple[bool, List[str]]:
    """Check that config files under configs/ load from YAML, not hard-coded dicts."""
    issues: List[str] = []

    settings_pattern = re.compile(
        r"^(DATABASE_URL|API_KEY|SECRET_KEY|REDIS_URL|KAFKA_BROKERS)\s*=\s*['\"]",
        re.MULTILINE,
    )

    for py_file in _iter_source_files():
        # Only check non-test production source
        if "test" in py_file.parts:
            continue
        text = py_file.read_text(encoding="utf-8", errors="ignore")
        if settings_pattern.search(text):
            rel = _relative_to_source_root(py_file)
            issues.append(
                f"{rel}: hardcoded settings constant (use configs/*.yaml + settings)"
            )

    return len(issues) == 0, issues


# ── Helpers ───────────────────────────────────────────────────────────────────


def _iter_source_files():
    for src_root in existing_source_roots(Path.cwd()):
        for py_file in src_root.rglob("*.py"):
            if any(excl in py_file.parts for excl in EXCLUDE_DIRS):
                continue
            yield py_file


def _relative_to_source_root(py_file: Path) -> Path:
    for src_root in existing_source_roots(Path.cwd()):
        try:
            return py_file.relative_to(src_root)
        except ValueError:
            continue
    return py_file


# ── main ──────────────────────────────────────────────────────────────────────


def main() -> int:
    configure_console_output()
    if is_kit_repository():
        print_kit_skip(
            "Architecture Coherence",
            "requires adopter specs/04-architecture.md and project source boundaries",
        )
        return 0

    print(
        f"\n{Colors.BOLD}{Colors.CYAN}Architecture Coherence Validator (NAOS){Colors.END}\n"
    )

    checks = [
        ("Architecture Documentation", check_architecture_doc),
        ("Module Boundaries", check_module_boundaries),
        ("No Hardcoded Config Values", check_hardcoded_values),
        ("No Settings in Source", check_no_config_in_source),
    ]

    total = 0
    failed = []

    for name, fn in checks:
        passed, issues = fn()
        total += 1
        if passed:
            print(f"{Colors.GREEN}✓ PASS{Colors.END} — {name}")
            for issue in issues[:5]:
                print(f"  {Colors.YELLOW}→ {issue}{Colors.END}")
        else:
            failed.append(name)
            print(f"{Colors.RED}✗ FAIL{Colors.END} — {name}")
            for issue in issues[:5]:
                print(f"  {Colors.YELLOW}→ {issue}{Colors.END}")
            if len(issues) > 5:
                print(f"  {Colors.YELLOW}→ … and {len(issues) - 5} more{Colors.END}")

    print(f"\n{Colors.BOLD}Results: {total - len(failed)}/{total} passed{Colors.END}")

    if failed:
        print(f"{Colors.RED}Failed: {', '.join(failed)}{Colors.END}")
        return 1

    print(f"{Colors.GREEN}✅ Architecture coherence OK{Colors.END}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
