#!/usr/bin/env python3
"""
validate_project_coherence.py — Master project coherence validator (NAOS portable)

Orchestrates all sub-validators in the same directory, then runs built-in checks:
  Phase 1 — Auto-discovers and runs all validate_*.py scripts in the validators/ dir
  Phase 2 — Built-in checks: Python syntax, YAML validity, JSON validity,
             no secrets (heuristic), no large files, no temp/draft files in docs/

[ADAPT] Add project-specific checks to the builtin_checks list in main().

ENV VARS:
    NAOS_ROOT   — naos/ directory       (default: naos)
    LARGE_FILE_MB — large-file threshold in MiB  (default: 10)

EXIT CODES:
    0 — All checks pass
    1 — One or more failures
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tokenize
from pathlib import Path
from typing import Callable, List, Tuple

# ── Path configuration ────────────────────────────────────────────────────────
NAOS_ROOT = Path(os.getenv("NAOS_ROOT", "naos"))
LARGE_FILE_MB = float(os.getenv("LARGE_FILE_MB", "10"))
MIB_BYTES = 1024 * 1024

DEFAULT_VALIDATOR_TIMEOUT_SECONDS = 60
KIT_VALIDATOR_TIMEOUT_OVERRIDES_SECONDS = {
    # This kit-development validator generates four profiles sequentially. Its
    # own bounded work can consume 4 * 180s plus 2 * 60s command checks.
    "validate_profile_generated_surfaces.py": 900,
}

KIT_PRIVATE_LARGE_FILE_OVERRIDES = Path(
    "configs/naos_private_project_coherence_overrides.json"
)

EXCLUDE_DIRS = {
    ".git",
    ".naos-g1-repository-intelligence",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "checkpoints",
    "data",
    ".pytest_cache",
    "build",
    "dist",
}

GENERATED_PROJECT_VALIDATORS = {
    "validate_architecture_coherence.py": "requires adopter `specs/04-architecture.md` and project source boundaries",
    "validate_governed_debug_escalation.py": "requires adopter profile/configuration, capability state, and installed agent manifests",
    "validate_metrics_coherence.py": "requires adopter `specs/03-requirements.md` and generated dashboard metrics",
    "validate_specs.py": "requires adopter `specs/` and generated PM framework files",
    "validate_task_coherence.py": "requires adopter `naos/TASK_REGISTRY.yaml` and generated PM artefacts",
    "validate_traceability_headers.py": "requires adopter traceability headers and task registry",
}

GENERATED_ADOPTER_BASELINE_SKIP_VALIDATORS = {
    "validate_docs_consistency.py": (
        "validates canonical kit public documentation and generated-document "
        "templates, not one initialized adopter"
    ),
    "validate_governed_debug_escalation.py": (
        "validates a separately installed and owner-approved opt-in control with "
        "an explicit profile, not baseline project coherence"
    ),
    "validate_implementation_reality.py": (
        "validates canonical kit documentation against kit templates and command "
        "sources, not one initialized adopter"
    ),
    "validate_profile_generated_surfaces.py": (
        "is a kit-development generator check that imports canonical kit "
        "renderers and generates every profile"
    ),
    "validate_secure_coding_control_references.py": (
        "validates the canonical kit register and render manifest under configs/, "
        "not the adopter-local control seed"
    ),
    "validate_secure_coding_control_register.py": (
        "validates the canonical kit secure-coding register under configs/, not "
        "the adopter-local control seed"
    ),
}


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    END = "\033[0m"


def print_header(text: str, color: str = Colors.CYAN) -> None:
    print(f"\n{Colors.BOLD}{color}{'=' * 80}{Colors.END}")
    print(f"{Colors.BOLD}{color}{text:^80}{Colors.END}")
    print(f"{Colors.BOLD}{color}{'=' * 80}{Colors.END}\n")


def is_kit_repository(root: Path | None = None) -> bool:
    """Return True when running from the NAOS kit source repo, not an initialized adopter project."""
    root = root or Path.cwd()
    return (
        (root / "pyproject.toml").is_file()
        and (root / "naos_init.py").is_file()
        and (root / "templates" / "structural-seeds" / "naos" / "TASK_REGISTRY.yaml").is_file()
        and not (root / NAOS_ROOT / "TASK_REGISTRY.yaml").is_file()
    )


def should_skip_for_kit_repo(validator_path: Path, root: Path | None = None) -> tuple[bool, str]:
    if not is_kit_repository(root):
        return False, ""
    reason = GENERATED_PROJECT_VALIDATORS.get(validator_path.name)
    if not reason:
        return False, ""
    return True, reason


def is_generated_adopter_repository(root: Path | None = None) -> bool:
    """Return True for an initialized adopter carrying the generated profile contract."""
    root = root or Path.cwd()
    return (
        (root / NAOS_ROOT / "TASK_REGISTRY.yaml").is_file()
        and (root / NAOS_ROOT / "profile_generated_surface_contract.json").is_file()
    )


def should_skip_for_generated_adopter(
    validator_path: Path,
    root: Path | None = None,
) -> tuple[bool, str]:
    """Return an explicit baseline-coherence exclusion for a generated adopter."""
    if not is_generated_adopter_repository(root):
        return False, ""
    reason = GENERATED_ADOPTER_BASELINE_SKIP_VALIDATORS.get(validator_path.name)
    if not reason:
        return False, ""
    return True, reason


# ── Phase 1: sub-validator discovery & execution ──────────────────────────────


def discover_validators() -> List[Path]:
    """Discover all validate_*.py scripts in the same directory (excluding self)."""
    validators_dir = Path(__file__).parent
    validators = [
        p
        for p in sorted(validators_dir.glob("validate_*.py"))
        if p.name != "validate_project_coherence.py"
    ]
    return validators


def validator_timeout_seconds(
    validator_path: Path,
    root: Path | None = None,
) -> int:
    """Return the bounded timeout assigned to one sub-validator."""
    if not is_kit_repository(root):
        return DEFAULT_VALIDATOR_TIMEOUT_SECONDS
    return KIT_VALIDATOR_TIMEOUT_OVERRIDES_SECONDS.get(
        validator_path.name,
        DEFAULT_VALIDATOR_TIMEOUT_SECONDS,
    )


def run_validator(validator_path: Path) -> Tuple[bool, str, str]:
    name = validator_path.stem.replace("validate_", "").replace("_", " ").title()

    # Determine project root: go up until we leave kit/scripts/validators/
    # In the portable kit the validator lives at <project_root>/kit/scripts/validators/
    # or at <project_root>/scripts/validators/ — walk up to find pyproject.toml / .git
    project_root = Path.cwd()
    for ancestor in [validator_path.resolve(), *validator_path.resolve().parents]:
        if (ancestor / ".git").exists() or (ancestor / "pyproject.toml").exists():
            project_root = ancestor
            break
    timeout_seconds = validator_timeout_seconds(validator_path, project_root)

    try:
        result = subprocess.run(
            [sys.executable, str(validator_path)],
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        return result.returncode == 0, name, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, name, f"⏱ Timeout (>{timeout_seconds}s)"
    except Exception as e:
        return False, name, f"❌ Error: {e}"


# ── Phase 2: built-in checks ──────────────────────────────────────────────────


def check_python_syntax() -> Tuple[bool, List[str]]:
    issues: List[str] = []
    root = Path.cwd()
    for py_file in root.rglob("*.py"):
        if any(excl in py_file.parts for excl in EXCLUDE_DIRS):
            continue
        try:
            with tokenize.open(py_file) as source:
                compile(
                    source.read(),
                    str(py_file),
                    "exec",
                    dont_inherit=True,
                )
        except (OSError, SyntaxError, UnicodeError):
            try:
                rel = py_file.relative_to(root)
            except ValueError:
                rel = py_file
            issues.append(f"{rel}: syntax error")
    return len(issues) == 0, issues


def check_yaml_validity() -> Tuple[bool, List[str]]:
    issues: List[str] = []
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return True, []

    root = Path.cwd()
    for yf in list(root.rglob("*.yaml")) + list(root.rglob("*.yml")):
        if any(excl in yf.parts for excl in EXCLUDE_DIRS):
            continue
        try:
            yaml.safe_load(yf.read_text(encoding="utf-8"))
        except Exception as e:
            try:
                rel = yf.relative_to(root)
            except ValueError:
                rel = yf
            issues.append(f"{rel}: {e}")
    return len(issues) == 0, issues


def check_json_validity() -> Tuple[bool, List[str]]:
    issues: List[str] = []
    root = Path.cwd()
    for jf in root.rglob("*.json"):
        if any(excl in jf.parts for excl in EXCLUDE_DIRS):
            continue
        try:
            json.loads(jf.read_text(encoding="utf-8"))
        except Exception as e:
            try:
                rel = jf.relative_to(root)
            except ValueError:
                rel = jf
            issues.append(f"{rel}: {e}")
    return len(issues) == 0, issues


def check_no_secrets(root: Path | None = None) -> Tuple[bool, List[str]]:
    """Heuristic check for accidentally committed secrets."""
    issues: List[str] = []
    secret_patterns = [
        (r'password\s*=\s*["\'][^"\']{8,}["\']', "Possible hardcoded password"),
        (r'api[_-]?key\s*=\s*["\'][^"\']{20,}["\']', "Possible API key"),
        (r'secret[_-]?key\s*=\s*["\'][^"\']{20,}["\']', "Possible secret key"),
        (r"-----BEGIN (?:RSA |)PRIVATE KEY-----", "Private key detected"),
    ]
    exts = [".py", ".sh", ".yml", ".yaml", ".json", ".toml", ".env", ".conf"]
    root = (root or Path.cwd()).resolve()
    fixture_paths: set[Path] = set()
    fixture_prefixes: tuple[Path, ...] = ()
    if is_kit_repository(root):
        overrides, override_issues = kit_private_project_coherence_overrides(root)
        issues.extend(override_issues)
        fixture_paths = set(overrides["intentional_secret_fixture_paths"])
        fixture_prefixes = tuple(overrides["intentional_secret_fixture_prefixes"])
    for ext in exts:
        for fp in root.rglob(f"*{ext}"):
            if any(excl in fp.parts for excl in EXCLUDE_DIRS):
                continue
            try:
                rel_path = fp.relative_to(root)
            except ValueError:
                rel_path = fp
            if is_intentional_secret_fixture(
                rel_path,
                fixture_paths=fixture_paths,
                fixture_prefixes=fixture_prefixes,
            ):
                continue
            text = fp.read_text(encoding="utf-8", errors="ignore")
            for pattern, desc in secret_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    issues.append(f"{rel_path}: {desc}")
    return len(issues) == 0, issues


def is_intentional_secret_fixture(
    rel_path: Path,
    *,
    fixture_paths: set[Path],
    fixture_prefixes: tuple[Path, ...],
) -> bool:
    """Return true only for exact fixture paths declared by an unshipped override."""
    if rel_path in fixture_paths:
        return True
    return any(
        rel_path == prefix or prefix in rel_path.parents
        for prefix in fixture_prefixes
    )


def kit_private_project_coherence_overrides(
    root: Path,
) -> tuple[dict[str, object], list[str]]:
    """Load exact source-repository exceptions; a distributed kit needs none."""
    empty: dict[str, object] = {
        "large_file_ceilings_bytes": {},
        "intentional_secret_fixture_paths": [],
        "intentional_secret_fixture_prefixes": [],
    }
    config_path = root / KIT_PRIVATE_LARGE_FILE_OVERRIDES
    if not config_path.exists():
        return empty, []
    if config_path.is_symlink() or not config_path.is_file():
        return empty, [f"{KIT_PRIVATE_LARGE_FILE_OVERRIDES}: must be a regular file"]
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
        expected_fields = {
            "schema",
            "large_file_ceilings_bytes",
            "intentional_secret_fixture_paths",
            "intentional_secret_fixture_prefixes",
        }
        if set(data) != expected_fields:
            raise ValueError("unexpected or missing top-level fields")
        if data["schema"] != "naos.private_project_coherence_overrides.v1":
            raise ValueError("unsupported schema")
        raw_ceilings = data["large_file_ceilings_bytes"]
        if not isinstance(raw_ceilings, dict) or not raw_ceilings:
            raise ValueError("large_file_ceilings_bytes must be a non-empty object")
        ceilings: dict[Path, int] = {}
        for raw_path, raw_ceiling in raw_ceilings.items():
            if not isinstance(raw_path, str) or not raw_path:
                raise ValueError("ceiling paths must be non-empty strings")
            relative = Path(raw_path)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError(f"unsafe ceiling path: {raw_path}")
            if (
                isinstance(raw_ceiling, bool)
                or not isinstance(raw_ceiling, int)
                or raw_ceiling <= 0
            ):
                raise ValueError(f"ceiling for {raw_path} must be a positive integer")
            ceilings[relative] = raw_ceiling
        parsed_paths: dict[str, list[Path]] = {}
        for field in (
            "intentional_secret_fixture_paths",
            "intentional_secret_fixture_prefixes",
        ):
            raw_paths = data[field]
            if not isinstance(raw_paths, list) or not raw_paths:
                raise ValueError(f"{field} must be a non-empty array")
            paths: list[Path] = []
            for raw_path in raw_paths:
                if not isinstance(raw_path, str) or not raw_path:
                    raise ValueError(f"{field} entries must be non-empty strings")
                relative = Path(raw_path)
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError(f"unsafe {field} path: {raw_path}")
                paths.append(relative)
            if len(paths) != len(set(paths)):
                raise ValueError(f"{field} entries must be unique")
            parsed_paths[field] = paths
        return {
            "large_file_ceilings_bytes": ceilings,
            **parsed_paths,
        }, []
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        return empty, [f"{KIT_PRIVATE_LARGE_FILE_OVERRIDES}: invalid configuration: {exc}"]


def kit_large_file_ceilings(root: Path) -> tuple[dict[Path, int], list[str]]:
    """Load exact source-repository file ceilings; a distributed kit needs none."""
    overrides, issues = kit_private_project_coherence_overrides(root)
    return dict(overrides["large_file_ceilings_bytes"]), issues


def check_large_files(root: Path | None = None) -> Tuple[bool, List[str]]:
    issues: List[str] = []
    root = (root or Path.cwd()).resolve()
    threshold = LARGE_FILE_MB * MIB_BYTES
    kit_repo = is_kit_repository(root)
    kit_ceilings: dict[Path, int] = {}
    if kit_repo:
        kit_ceilings, config_issues = kit_large_file_ceilings(root)
        issues.extend(config_issues)
    for fp in root.rglob("*"):
        if not fp.is_file():
            continue
        if any(excl in fp.parts for excl in EXCLUDE_DIRS):
            continue
        size = fp.stat().st_size
        if size <= threshold:
            continue
        try:
            rel = fp.resolve().relative_to(root)
        except ValueError:
            rel = fp
        kit_ceiling = (
            kit_ceilings.get(rel)
            if kit_repo
            else None
        )
        if kit_ceiling is not None and size <= kit_ceiling:
            continue
        if kit_ceiling is not None:
            issues.append(
                f"{rel}: {size / MIB_BYTES:.1f} MiB "
                f"(exceeds kit canonical ceiling {kit_ceiling / MIB_BYTES:.1f} MiB)"
            )
        else:
            issues.append(
                f"{rel}: {size / MIB_BYTES:.1f} MiB (consider Git LFS / .gitignore)"
            )
    return len(issues) == 0, issues


def check_no_draft_files() -> Tuple[bool, List[str]]:
    """Check for temp/draft files that belong in docs/exploration/ only."""
    issues: List[str] = []
    root = Path.cwd()
    draft_pattern = re.compile(
        r"^(temp_|draft_|analysis_\d{4}|session_summary_)", re.IGNORECASE
    )
    for fp in root.rglob("*"):
        if not fp.is_file():
            continue
        if any(excl in fp.parts for excl in EXCLUDE_DIRS):
            continue
        if "docs/exploration" in str(fp).replace("\\", "/"):
            continue
        if draft_pattern.match(fp.name):
            try:
                rel = fp.relative_to(root)
            except ValueError:
                rel = fp
            issues.append(
                f"{rel}: temp/draft file (move to docs/exploration/ or delete)"
            )
    return len(issues) == 0, issues


# ── main ──────────────────────────────────────────────────────────────────────


def main() -> int:
    print_header("🔍 MASTER PROJECT COHERENCE VALIDATOR (NAOS)", Colors.MAGENTA)

    kit_repo = is_kit_repository()
    generated_adopter = is_generated_adopter_repository()
    if kit_repo:
        print(
            f"{Colors.CYAN}Context: NAOS kit repository detected. "
            f"Generated-project-only validators will be reported as SKIP; "
            f"run scaffold smoke to cover generated-project behaviour.{Colors.END}\n"
        )
    elif generated_adopter:
        print(
            f"{Colors.CYAN}Context: generated NAOS adopter detected. "
            f"Kit-maintainer and opt-in activation validators will be reported "
            f"as SKIP; run an opt-in validator directly only after its "
            f"prerequisites are activated.{Colors.END}\n"
        )

    total = 0
    passed_count = 0
    skipped_count = 0
    skipped: List[str] = []
    failed: List[str] = []

    # ── Phase 1: sub-validators ───────────────────────────────────────────────
    print_header("Phase 1: Sub-Validators", Colors.CYAN)
    validators = discover_validators()
    print(f"{Colors.CYAN}Discovered {len(validators)} validator(s):{Colors.END}")
    for v in validators:
        print(f"  • {v.name}")
    print()

    for validator_path in validators:
        skip, reason = should_skip_for_kit_repo(validator_path)
        skip_context = "kit repo"
        if not skip:
            skip, reason = should_skip_for_generated_adopter(validator_path)
            skip_context = "generated adopter"
        if skip:
            skipped_count += 1
            skipped.append(validator_path.stem.replace("validate_", "").replace("_", " ").title())
            print(
                f"{Colors.YELLOW}↷ SKIP{Colors.END} — "
                f"{validator_path.stem.replace('validate_', '').replace('_', ' ').title()}"
            )
            print(
                f"  {Colors.YELLOW}→ {skip_context} context: {reason}{Colors.END}"
            )
            continue

        ok, name, output = run_validator(validator_path)
        total += 1
        if ok:
            passed_count += 1
            print(f"{Colors.GREEN}✓ PASS{Colors.END} — {name}")
        else:
            failed.append(name)
            print(f"{Colors.RED}✗ FAIL{Colors.END} — {name}")
            if output.strip():
                for line in output.strip().splitlines()[:5]:
                    print(f"  {Colors.YELLOW}{line}{Colors.END}")

    # ── Phase 2: built-in checks ──────────────────────────────────────────────
    print_header("Phase 2: Built-In Quality Checks", Colors.CYAN)

    builtin_checks: List[
        Tuple[str, Callable[[], Tuple[bool, List[str]]]]
    ] = [
        ("Python Syntax", check_python_syntax),
        ("YAML Validity", check_yaml_validity),
        ("JSON Validity", check_json_validity),
        ("No Secrets", check_no_secrets),
        ("No Large Files", check_large_files),
        ("No Draft Files in Root", check_no_draft_files),
    ]

    for check_name, fn in builtin_checks:
        ok, issues = fn()
        total += 1
        if ok:
            passed_count += 1
            print(f"{Colors.GREEN}✓ PASS{Colors.END} — {check_name}")
        else:
            failed.append(check_name)
            print(f"{Colors.RED}✗ FAIL{Colors.END} — {check_name}")
            for issue in issues[:5]:
                print(f"  {Colors.YELLOW}→ {issue}{Colors.END}")
            if len(issues) > 5:
                print(f"  {Colors.YELLOW}→ … and {len(issues) - 5} more{Colors.END}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print_header("📊 VALIDATION SUMMARY", Colors.MAGENTA)
    print(f"{Colors.BOLD}Total Checks : {total}{Colors.END}")
    print(f"{Colors.GREEN}Passed       : {passed_count}{Colors.END}")
    if skipped_count:
        print(f"{Colors.YELLOW}Skipped      : {skipped_count}{Colors.END}")
    print(f"{Colors.RED}Failed       : {len(failed)}{Colors.END}\n")

    if skipped:
        if kit_repo:
            skipped_heading = "Generated-project checks skipped in kit context:"
        else:
            skipped_heading = "Non-baseline checks skipped in generated-adopter context:"
        print(f"{Colors.YELLOW}{Colors.BOLD}{skipped_heading}{Colors.END}")
        for check in skipped:
            print(f"  • {check}")
        if kit_repo:
            print(
                f"{Colors.YELLOW}Cover these with generated scaffold smoke before tagging.{Colors.END}\n"
            )
        else:
            print(
                f"{Colors.YELLOW}Run an opt-in check directly only after its explicit prerequisites are satisfied.{Colors.END}\n"
            )

    if failed:
        print(
            f"{Colors.RED}{Colors.BOLD}❌ PROJECT COHERENCE ISSUES DETECTED{Colors.END}\n"
        )
        for check in failed:
            print(f"  • {check}")
        print(
            f"\n{Colors.YELLOW}Run individual validators for detailed output{Colors.END}"
        )
        return 1

    print(
        f"{Colors.GREEN}{Colors.BOLD}✅ ALL CHECKS PASSED — PROJECT IS COHERENT!{Colors.END}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
