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

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from source_roots import existing_source_roots  # noqa: E402

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


def load_boundary_rules() -> dict:
    if not BOUNDARY_CONFIG.exists():
        return {}
    try:
        with open(BOUNDARY_CONFIG, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


# ── Checks ────────────────────────────────────────────────────────────────────


def check_module_boundaries() -> Tuple[bool, List[str]]:
    """Check for imports that violate boundary rules in naos_architecture_boundaries.yaml."""
    rules = load_boundary_rules()
    if not rules:
        return True, []  # No boundary file → skip (advisory)

    boundaries = rules.get("boundaries", [])
    if not boundaries:
        return True, []

    issues: List[str] = []

    for py_file in _iter_source_files():
        text = py_file.read_text(encoding="utf-8", errors="ignore")
        imports = re.findall(r"^(?:from|import)\s+([\w.]+)", text, re.MULTILINE)

        for boundary in boundaries:
            module = boundary.get("module", "")
            forbidden = boundary.get("forbidden_imports", [])
            if not module or not forbidden:
                continue
            if not _file_belongs_to_module(py_file, module):
                continue
            for imp in imports:
                for forbidden_prefix in forbidden:
                    if imp.startswith(forbidden_prefix):
                        rel = _relative_to_source_root(py_file)
                        issues.append(
                            f"{rel}: module '{module}' imports from forbidden '{imp}'"
                        )
                        break

    return len(issues) == 0, issues


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


def _file_belongs_to_module(py_file: Path, module: str) -> bool:
    """Return True if py_file is under the given module directory."""
    for src_root in existing_source_roots(Path.cwd()):
        module_path = src_root / module.replace(".", "/")
        try:
            py_file.relative_to(module_path)
            return True
        except ValueError:
            continue
    return False


# ── main ──────────────────────────────────────────────────────────────────────


def main() -> int:
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
