#!/usr/bin/env python3
"""Render and check the four shipped profile RULES documents.

``configs/profile_rules_source.yaml`` is canonical only for the exact RULES
presentation it contains: document bytes, active-table membership, documented
postures, headings, markers, and resolved kit source-path claims. Policy remains
canonical for gate severity, exit codes, and enforcement transition; the
pre-commit hook remains canonical for its executable checks.

The checked-in ``profiles/governance-*/.ai/RULES.md`` files are derived kit
outputs. Adopter-local ``.ai/RULES.md`` files are intentionally outside this
kit drift check because documented ADAPT sections remain adopter-owned.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import yaml


KIT_ROOT = Path(__file__).resolve().parent
DEFAULT_SOURCE = KIT_ROOT / "configs" / "profile_rules_source.yaml"
PROFILE_ORDER = ("quickstart", "lite", "standard", "assured")
SOURCE_SCHEMA = "naos.profile_rules_source.v1"
REPORT_SCHEMA = "naos.profile_rules_regeneration.v1"

_PROFILE_FIELDS = {
    "output_path",
    "profile_marker",
    "version",
    "kit_version",
    "active_table_heading",
    "table_rules",
    "active_rule_ids",
    "blocking_rule_ids",
    "advisory_rule_ids",
    "conditional_rule_ids",
    "adapt_rule_ids",
    "rule_heading_ids",
    "pgr_rule_ids",
    "source_path_claims",
    "sha256",
    "bytes",
    "lines",
    "content",
}


class ProfileRulesSourceError(ValueError):
    """Raised when the canonical profile-RULES source is malformed."""


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _integer_list(value: Any, field: str, profile: str) -> list[int]:
    if not isinstance(value, list) or not all(type(item) is int for item in value):
        raise ProfileRulesSourceError(f"{profile}.{field} must be a list of integers")
    if len(value) != len(set(value)):
        raise ProfileRulesSourceError(f"{profile}.{field} contains duplicate rule ids")
    return value


def _string_list(value: Any, field: str, profile: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ProfileRulesSourceError(f"{profile}.{field} must be a list of strings")
    return value


def _table_rows(content: str, heading: str, profile: str) -> list[dict[str, Any]]:
    lines = content.splitlines()
    marker = f"## {heading}"
    try:
        start = lines.index(marker)
    except ValueError as exc:
        raise ProfileRulesSourceError(f"{profile}.content is missing {marker!r}") from exc

    rows: list[dict[str, Any]] = []
    table_started = False
    for line in lines[start + 1 :]:
        if line.startswith("|"):
            table_started = True
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            match = re.match(r"^(\d+)(?:\s|$)", cells[0] if cells else "")
            if match:
                rows.append({"id": int(match.group(1)), "posture": cells[-1]})
            continue
        if table_started and rows:
            break
    if not rows:
        raise ProfileRulesSourceError(f"{profile}.content has no numeric rows under {marker!r}")
    return rows


def _rule_headings(content: str) -> tuple[list[int], list[int], list[int]]:
    heading_ids: list[int] = []
    adapt_ids: list[int] = []
    pgr_ids: list[int] = []
    for line in content.splitlines():
        match = re.match(r"^## (?:(PGR) )?Rule (\d+):\s*(.*)$", line)
        if not match:
            continue
        rule_id = int(match.group(2))
        heading_ids.append(rule_id)
        if "ADAPT" in match.group(3).upper():
            adapt_ids.append(rule_id)
        if match.group(1):
            pgr_ids.append(rule_id)
    return heading_ids, adapt_ids, pgr_ids


def _source_path_claims(content: str) -> list[str]:
    return re.findall(r"(?m)^> \*\*Source\*\*: `([^`]+)`", content)


def _posture_class(posture: str) -> str:
    normalized = posture.upper()
    if "ADAPT" in normalized:
        return "adapt"
    if "ADVISORY UNLESS" in normalized:
        return "conditional"
    if "BLOCKING" in normalized:
        return "blocking"
    if "ADVISORY" in normalized:
        return "advisory"
    return "unknown"


def _validate_profile(profile: str, entry: Any) -> None:
    if not isinstance(entry, dict):
        raise ProfileRulesSourceError(f"profiles.{profile} must be a mapping")
    fields = set(entry)
    missing = sorted(_PROFILE_FIELDS - fields)
    extra = sorted(fields - _PROFILE_FIELDS)
    if missing or extra:
        raise ProfileRulesSourceError(
            f"profiles.{profile} fields mismatch: missing={missing}, extra={extra}"
        )

    expected_output = f"profiles/governance-{profile}/.ai/RULES.md"
    if entry["output_path"] != expected_output:
        raise ProfileRulesSourceError(
            f"{profile}.output_path must be {expected_output!r}, got {entry['output_path']!r}"
        )
    expected_marker = f"governance-{profile}"
    if entry["profile_marker"] != expected_marker:
        raise ProfileRulesSourceError(
            f"{profile}.profile_marker must be {expected_marker!r}"
        )
    for field in ("version", "kit_version", "active_table_heading", "sha256", "content"):
        if not isinstance(entry[field], str):
            raise ProfileRulesSourceError(f"{profile}.{field} must be a string")
    for field in ("bytes", "lines"):
        if type(entry[field]) is not int or entry[field] < 0:
            raise ProfileRulesSourceError(f"{profile}.{field} must be a non-negative integer")

    content = entry["content"]
    raw = content.encode("utf-8")
    if not raw.endswith(b"\n"):
        raise ProfileRulesSourceError(f"{profile}.content must end with one newline")
    if _sha256(raw) != entry["sha256"]:
        raise ProfileRulesSourceError(f"{profile}.sha256 does not match content")
    if len(raw) != entry["bytes"]:
        raise ProfileRulesSourceError(f"{profile}.bytes does not match content")
    if raw.count(b"\n") != entry["lines"]:
        raise ProfileRulesSourceError(f"{profile}.lines does not match content")

    marker = re.search(
        r"(?m)^\*\*Version\*\*: ([^|]+?) \| \*\*Profile\*\*: ([^|]+?) \| "
        r"\*\*NAOS Kit\*\*: ([^\n]+)$",
        content,
    )
    if not marker:
        raise ProfileRulesSourceError(f"{profile}.content is missing its version/profile marker")
    observed_marker = tuple(part.strip() for part in marker.groups())
    expected_markers = (entry["version"], entry["profile_marker"], entry["kit_version"])
    if observed_marker != expected_markers:
        raise ProfileRulesSourceError(
            f"{profile}.content markers {observed_marker!r} do not match {expected_markers!r}"
        )

    table_rules = entry["table_rules"]
    if not isinstance(table_rules, list) or not all(
        isinstance(row, dict)
        and set(row) == {"id", "posture"}
        and type(row["id"]) is int
        and isinstance(row["posture"], str)
        for row in table_rules
    ):
        raise ProfileRulesSourceError(
            f"{profile}.table_rules must contain only id/posture mappings"
        )
    observed_rows = _table_rows(content, entry["active_table_heading"], profile)
    if observed_rows != table_rules:
        raise ProfileRulesSourceError(
            f"{profile}.table_rules do not match the active presentation table"
        )

    active = _integer_list(entry["active_rule_ids"], "active_rule_ids", profile)
    blocking = _integer_list(entry["blocking_rule_ids"], "blocking_rule_ids", profile)
    advisory = _integer_list(entry["advisory_rule_ids"], "advisory_rule_ids", profile)
    conditional = _integer_list(entry["conditional_rule_ids"], "conditional_rule_ids", profile)
    adapt = _integer_list(entry["adapt_rule_ids"], "adapt_rule_ids", profile)
    headings = _integer_list(entry["rule_heading_ids"], "rule_heading_ids", profile)
    pgr = _integer_list(entry["pgr_rule_ids"], "pgr_rule_ids", profile)
    claims = _string_list(entry["source_path_claims"], "source_path_claims", profile)

    posture_sets = [set(blocking), set(advisory), set(conditional)]
    if any(a & b for index, a in enumerate(posture_sets) for b in posture_sets[index + 1 :]):
        raise ProfileRulesSourceError(f"{profile} active posture lists overlap")
    if set().union(*posture_sets) != set(active):
        raise ProfileRulesSourceError(
            f"{profile} blocking/advisory/conditional ids must partition active_rule_ids"
        )
    if set(active) & set(adapt):
        raise ProfileRulesSourceError(f"{profile} active and ADAPT rule ids must be disjoint")

    observed_by_class: dict[str, list[int]] = {
        "blocking": [],
        "advisory": [],
        "conditional": [],
        "adapt": [],
        "unknown": [],
    }
    for row in table_rules:
        observed_by_class[_posture_class(row["posture"])].append(row["id"])
    expected_by_class = {
        "blocking": blocking,
        "advisory": advisory,
        "conditional": conditional,
        "adapt": [rule_id for rule_id in adapt if rule_id in {row["id"] for row in table_rules}],
        "unknown": [],
    }
    if observed_by_class != expected_by_class:
        raise ProfileRulesSourceError(
            f"{profile} posture lists do not match table presentation: {observed_by_class!r}"
        )

    observed_headings, observed_adapt, observed_pgr = _rule_headings(content)
    if observed_headings != headings:
        raise ProfileRulesSourceError(f"{profile}.rule_heading_ids do not match content")
    if observed_adapt != adapt:
        raise ProfileRulesSourceError(f"{profile}.adapt_rule_ids do not match ADAPT headings")
    if observed_pgr != pgr:
        raise ProfileRulesSourceError(f"{profile}.pgr_rule_ids do not match PGR headings")
    if _source_path_claims(content) != claims:
        raise ProfileRulesSourceError(f"{profile}.source_path_claims do not match content")


def load_profile_rules_source(
    path: Path = DEFAULT_SOURCE,
    *,
    claim_root: Path | None = None,
) -> dict[str, Any]:
    """Load and fully validate the canonical source contract."""

    try:
        source = path.resolve()
        default_source = DEFAULT_SOURCE.resolve()
        resolved_claim_root = (KIT_ROOT if claim_root is None else claim_root).resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ProfileRulesSourceError(
            f"canonical source or claim root cannot be resolved safely: {path}"
        ) from exc
    if claim_root is None:
        if source != default_source:
            raise ProfileRulesSourceError(
                "claim_root is required when loading a non-default canonical source"
            )
    try:
        data = yaml.load(
            source.read_text(encoding="utf-8"),
            Loader=_UniqueKeySafeLoader,
        )
    except OSError as exc:
        raise ProfileRulesSourceError(f"canonical source is unavailable: {source}") from exc
    except yaml.YAMLError as exc:
        raise ProfileRulesSourceError(f"canonical source YAML is malformed: {exc}") from exc
    if not isinstance(data, dict) or set(data) != {"schema", "profile_order", "profiles"}:
        raise ProfileRulesSourceError(
            "canonical source must contain only schema, profile_order, and profiles"
        )
    if data["schema"] != SOURCE_SCHEMA:
        raise ProfileRulesSourceError(
            f"unsupported canonical source schema: {data['schema']!r}"
        )
    if data["profile_order"] != list(PROFILE_ORDER):
        raise ProfileRulesSourceError(
            f"profile_order must be {list(PROFILE_ORDER)!r}"
        )
    profiles = data["profiles"]
    if not isinstance(profiles, dict) or list(profiles) != list(PROFILE_ORDER):
        raise ProfileRulesSourceError(
            f"profiles must be ordered exactly as {list(PROFILE_ORDER)!r}"
        )
    for profile in PROFILE_ORDER:
        _validate_profile(profile, profiles[profile])
    for profile in PROFILE_ORDER:
        for claim in profiles[profile]["source_path_claims"]:
            relative = PurePosixPath(claim)
            windows_path = PureWindowsPath(claim)
            if (
                not claim
                or relative.is_absolute()
                or windows_path.drive
                or windows_path.root
                or relative == PurePosixPath(".")
                or ".." in relative.parts
                or "\\" in claim
                or any(ord(character) < 32 for character in claim)
                or relative.as_posix() != claim
            ):
                raise ProfileRulesSourceError(
                    f"{profile}.source_path_claims must be a normalized kit-relative POSIX path: {claim!r}"
                )
            try:
                claimed_path = resolved_claim_root.joinpath(*relative.parts).resolve()
                claimed_is_file = claimed_path.is_file()
            except (OSError, RuntimeError, ValueError) as exc:
                raise ProfileRulesSourceError(
                    f"{profile}.source_path_claims cannot be resolved safely: {claim!r}"
                ) from exc
            if not claimed_path.is_relative_to(resolved_claim_root):
                raise ProfileRulesSourceError(
                    f"{profile}.source_path_claims escapes the kit root: {claim!r}"
                )
            if not claimed_is_file:
                raise ProfileRulesSourceError(
                    f"{profile}.source_path_claims does not resolve to a kit file: {claim!r}"
                )
    return data


def rendered_profile_rules(contract: dict[str, Any]) -> dict[str, bytes]:
    """Return deterministic relative output paths and exact rendered bytes."""

    return {
        contract["profiles"][profile]["output_path"]: contract["profiles"][profile][
            "content"
        ].encode("utf-8")
        for profile in PROFILE_ORDER
    }


def _first_difference(expected: bytes, actual: bytes) -> int | None:
    for index, (expected_byte, actual_byte) in enumerate(zip(expected, actual)):
        if expected_byte != actual_byte:
            return index
    if len(expected) != len(actual):
        return min(len(expected), len(actual))
    return None


def _is_kit_layout(root: Path) -> bool:
    return (root / "naos_init.py").is_file() and (root / "profiles").is_dir()


def _safe_derived_output(root: Path, relative: Path) -> tuple[Path | None, str | None]:
    """Resolve a fixed derived-output path without following symlink components."""
    candidate = root.joinpath(*relative.parts)
    current = root
    try:
        for index, part in enumerate(relative.parts):
            current = current / part
            if current.is_symlink():
                return None, f"symlink component is not allowed: {current.relative_to(root)}"
            if current.exists():
                is_leaf = index == len(relative.parts) - 1
                if is_leaf and not current.is_file():
                    return None, f"derived output is not a regular file: {relative.as_posix()}"
                if not is_leaf and not current.is_dir():
                    return None, f"derived output ancestor is not a directory: {current.relative_to(root)}"
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        return None, f"derived output cannot be resolved safely: {relative.as_posix()} ({exc})"
    if not resolved.is_relative_to(root):
        return None, f"derived output escapes the kit root: {relative.as_posix()}"
    return candidate, None


def check_profile_rules(
    root: Path = KIT_ROOT,
    source_path: Path | None = None,
) -> dict[str, Any]:
    """Check derived kit outputs without changing the filesystem."""

    try:
        root = root.resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        return {
            "schema": REPORT_SCHEMA,
            "status": "failed",
            "applicability": "kit_profile_rules",
            "profiles_checked": [],
            "findings": [{
                "profile": "all",
                "rule_id": "PROFILE_RULES_ROOT_INVALID",
                "message": f"Kit root cannot be resolved safely: {root} ({exc})",
                "suggested_fix": "Use a regular, resolvable kit root.",
            }],
        }
    explicit_source = source_path is not None
    source = source_path or root / "configs" / "profile_rules_source.yaml"
    try:
        source_is_file = source.is_file()
    except (OSError, RuntimeError, ValueError):
        source_is_file = False
    if not source_is_file and not explicit_source and not _is_kit_layout(root):
        return {
            "schema": REPORT_SCHEMA,
            "status": "not_applicable",
            "applicability": "adopter_local_rules",
            "profiles_checked": [],
            "findings": [],
            "reason": (
                "Adopter-local .ai/RULES.md is customizable; exact kit-output parity "
                "applies only where the canonical source and four kit outputs are present."
            ),
        }

    try:
        contract = load_profile_rules_source(source, claim_root=root)
    except ProfileRulesSourceError as exc:
        return {
            "schema": REPORT_SCHEMA,
            "status": "failed",
            "applicability": "kit_profile_rules",
            "profiles_checked": [],
            "findings": [
                {
                    "profile": "all",
                    "rule_id": "PROFILE_RULES_SOURCE_INVALID",
                    "message": str(exc),
                    "suggested_fix": (
                        "Restore a valid configs/profile_rules_source.yaml before regenerating outputs."
                    ),
                }
            ],
        }

    findings: list[dict[str, Any]] = []
    for profile in PROFILE_ORDER:
        entry = contract["profiles"][profile]
        relative = Path(entry["output_path"])
        output, output_error = _safe_derived_output(root, relative)
        if output_error or output is None:
            findings.append(
                {
                    "profile": profile,
                    "rule_id": "PROFILE_RULES_OUTPUT_PATH_INVALID",
                    "message": output_error or f"Derived output path is invalid: {relative.as_posix()}",
                    "suggested_fix": "Use the fixed profiles/governance-*/.ai/RULES.md output path.",
                }
            )
            continue
        expected = entry["content"].encode("utf-8")
        if not output.is_file():
            findings.append(
                {
                    "profile": profile,
                    "rule_id": "PROFILE_RULES_OUTPUT_MISSING",
                    "message": f"Derived RULES output is missing: {relative.as_posix()}",
                    "suggested_fix": "Run python3 -B naos_profile_rules.py --write.",
                }
            )
            continue
        try:
            actual = output.read_bytes()
        except OSError as exc:
            findings.append(
                {
                    "profile": profile,
                    "rule_id": "PROFILE_RULES_OUTPUT_UNREADABLE",
                    "message": f"Derived RULES output cannot be read: {relative.as_posix()} ({exc})",
                    "suggested_fix": "Restore a regular readable output before checking parity.",
                }
            )
            continue
        if actual != expected:
            findings.append(
                {
                    "profile": profile,
                    "rule_id": "PROFILE_RULES_OUTPUT_DRIFT",
                    "message": (
                        f"{relative.as_posix()} differs at byte {_first_difference(expected, actual)}; "
                        f"expected sha256={_sha256(expected)} bytes={len(expected)}, "
                        f"actual sha256={_sha256(actual)} bytes={len(actual)}."
                    ),
                    "suggested_fix": (
                        "Review the canonical source change, then run "
                        "python3 -B naos_profile_rules.py --write."
                    ),
                }
            )
    return {
        "schema": REPORT_SCHEMA,
        "status": "passed" if not findings else "failed",
        "applicability": "kit_profile_rules",
        "profiles_checked": list(PROFILE_ORDER),
        "findings": findings,
    }


def write_profile_rules(root: Path = KIT_ROOT, source_path: Path | None = None) -> dict[str, Any]:
    """Regenerate all four derived outputs after fully validating the source."""

    try:
        root = root.resolve()
        source = (source_path or root / "configs" / "profile_rules_source.yaml").resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ProfileRulesSourceError(
            "kit root or canonical source cannot be resolved safely"
        ) from exc
    contract = load_profile_rules_source(source, claim_root=root)
    rendered = rendered_profile_rules(contract)
    targets: list[tuple[Path, bytes]] = []
    for relative_text, raw in rendered.items():
        relative = Path(relative_text)
        target, target_error = _safe_derived_output(root, relative)
        if target_error or target is None:
            raise ProfileRulesSourceError(target_error or f"invalid derived output: {relative_text}")
        targets.append((target, raw))
    for target, raw in targets:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    return check_profile_rules(root, source)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check or regenerate derived profile RULES documents."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Check exact parity without writing (default).")
    mode.add_argument("--write", action="store_true", help="Regenerate all four derived outputs.")
    parser.add_argument("--root", type=Path, default=KIT_ROOT, help="Kit/package root.")
    parser.add_argument("--source", type=Path, default=None, help="Canonical source override.")
    parser.add_argument("--json", action="store_true", help="Print the full JSON report.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = (
            write_profile_rules(args.root, args.source)
            if args.write
            else check_profile_rules(args.root, args.source)
        )
    except ProfileRulesSourceError as exc:
        report = {
            "schema": REPORT_SCHEMA,
            "status": "failed",
            "applicability": "kit_profile_rules",
            "profiles_checked": [],
            "findings": [
                {
                    "profile": "all",
                    "rule_id": "PROFILE_RULES_SOURCE_INVALID",
                    "message": str(exc),
                    "suggested_fix": "Correct the canonical source before regeneration.",
                }
            ],
        }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"Profile RULES regeneration: {report['status']}")
        for item in report.get("findings") or []:
            print(f"- {item['profile']} {item['rule_id']}: {item['message']}")
            print(f"  fix: {item['suggested_fix']}")
    return 1 if report["status"] == "failed" else 0


if __name__ == "__main__":
    sys.exit(main())
