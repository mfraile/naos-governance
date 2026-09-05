#!/usr/bin/env python3
"""Validate declared profile surfaces against freshly generated NAOS projects.

This is a kit-development validator. It generates each profile in a temporary
directory and never activates files in the repository under validation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

KIT_ROOT = Path(__file__).resolve().parents[2]
if str(KIT_ROOT) not in sys.path:
    sys.path.insert(0, str(KIT_ROOT))

from naos_profile_rules import load_profile_rules_source  # noqa: E402


CONTRACT_PATH = KIT_ROOT / "configs" / "profile_generated_surface_contract.json"
RULES_SOURCE_PATH = KIT_ROOT / "configs" / "profile_rules_source.yaml"
PROFILE_TEMPLATES_PATH = KIT_ROOT / "templates" / "profiles"
PROFILE_ORDER = ("quickstart", "lite", "standard", "assured")
GENERATION_TIMEOUT_SECONDS = 180
COMMAND_TIMEOUT_SECONDS = 60
MAKE_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _validated_relative_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.drive
        or windows.root
        or posix == PurePosixPath(".")
        or ".." in posix.parts
        or "\\" in value
        or posix.as_posix() != value
    ):
        raise ValueError(f"{field} must be a normalized project-relative POSIX path: {value!r}")
    return value


def _symlink_component(root: Path, relative: str) -> str | None:
    """Return the first symlink component without traversing outside ``root``."""
    current = root
    for component in PurePosixPath(relative).parts:
        current = current / component
        if current.is_symlink():
            return current.relative_to(root).as_posix()
    return None


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    data = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_unique_json_object,
    )
    if not isinstance(data, dict):
        raise ValueError("Generated-surface contract must be a JSON object")
    if data.get("schema") != "naos.profile_generated_surface_contract.v1":
        raise ValueError(f"Unsupported generated-surface contract: {data.get('schema')!r}")
    if set(data) != {"schema", "contract_version", "profiles"}:
        raise ValueError("Generated-surface contract has unexpected or missing top-level fields")
    if type(data.get("contract_version")) is not int or data["contract_version"] != 1:
        raise ValueError("Generated-surface contract version must be exactly 1")
    profiles = data.get("profiles")
    if not isinstance(profiles, dict) or tuple(profiles) != PROFILE_ORDER:
        raise ValueError(f"Generated-surface profiles must be ordered exactly as {PROFILE_ORDER!r}")
    for profile in PROFILE_ORDER:
        entry = profiles[profile]
        if not isinstance(entry, dict) or set(entry) != {
            "required_surfaces", "prohibited_surfaces", "commands"
        }:
            raise ValueError(f"Generated-surface profile {profile!r} has invalid fields")
        for field in ("required_surfaces", "prohibited_surfaces"):
            values = entry[field]
            if (
                not isinstance(values, list)
                or not all(isinstance(value, str) and value for value in values)
                or len(values) != len(set(values))
            ):
                raise ValueError(f"{profile}.{field} must be a unique non-empty string list")
            for index, value in enumerate(values):
                _validated_relative_path(value, f"{profile}.{field}[{index}]")
        if not isinstance(entry["commands"], dict):
            raise ValueError(f"{profile}.commands must be a mapping")
        for command, command_contract in entry["commands"].items():
            if not isinstance(command, str) or not command or not isinstance(command_contract, dict):
                raise ValueError(f"{profile}.commands entries must be named mappings")
            if not MAKE_TARGET_RE.fullmatch(command):
                raise ValueError(
                    f"{profile}.commands key must be a safe Make target name: {command!r}"
                )
            if not set(command_contract) <= {"applicability", "target", "surface", "alternative"}:
                raise ValueError(f"{profile}.commands.{command} has unsupported fields")
            applicability = command_contract.get("applicability")
            if applicability not in {"available", "not_applicable"}:
                raise ValueError(f"{profile}.commands.{command}.applicability is invalid")
            for field in ("target", "alternative"):
                value = command_contract.get(field)
                if value is not None and (not isinstance(value, str) or not value):
                    raise ValueError(f"{profile}.commands.{command}.{field} must be a non-empty string")
            target = command_contract.get("target")
            if target is not None and not MAKE_TARGET_RE.fullmatch(target):
                raise ValueError(
                    f"{profile}.commands.{command}.target must be a safe Make target name"
                )
            surface = command_contract.get("surface")
            if surface is not None:
                _validated_relative_path(surface, f"{profile}.commands.{command}.surface")
            if applicability == "available" and not (
                command_contract.get("target") or command_contract.get("surface")
            ):
                raise ValueError(f"{profile}.commands.{command} needs a target or surface")
            if applicability == "not_applicable" and not command_contract.get("alternative"):
                raise ValueError(f"{profile}.commands.{command} needs an alternative")
    return data


def generate_profile(profile: str, destination: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(KIT_ROOT / "naos_init.py"),
            str(destination),
            "--tier",
            profile,
            "--archetype",
            "custom",
            "--backend",
            "static_only",
            "--memory",
            "disabled",
            "--new",
            "--activate",
        ],
        cwd=KIT_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=GENERATION_TIMEOUT_SECONDS,
    )


def validate_profile_preset_copies(
    profile: str,
    destination: Path,
    templates_path: Path = PROFILE_TEMPLATES_PATH,
) -> list[dict[str, str]]:
    """Verify the initializer's profile-preset copy boundary byte-for-byte."""
    installed_dir = destination / ".github" / "profiles"
    installed_symlink = _symlink_component(destination, ".github/profiles")
    if profile == "quickstart":
        if installed_symlink or installed_dir.exists():
            return [{
                "profile": profile,
                "kind": "prohibited_profile_preset_directory_present",
                "detail": (
                    f".github/profiles: symlink component {installed_symlink}"
                    if installed_symlink
                    else ".github/profiles"
                ),
            }]
        return []

    if templates_path.is_symlink() or not templates_path.is_dir():
        return [{
            "profile": profile,
            "kind": "profile_preset_source_missing",
            "detail": str(templates_path),
        }]
    if installed_symlink or not installed_dir.is_dir():
        return [{
            "profile": profile,
            "kind": "profile_preset_directory_missing",
            "detail": (
                f".github/profiles: symlink component {installed_symlink}"
                if installed_symlink
                else ".github/profiles"
            ),
        }]

    expected = {
        path.name: path
        for path in sorted(templates_path.iterdir())
        if path.is_file()
    }
    actual = {
        path.name: path
        for path in sorted(installed_dir.iterdir())
    }
    findings: list[dict[str, str]] = []
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    if missing:
        findings.append({
            "profile": profile,
            "kind": "profile_preset_files_missing",
            "detail": ", ".join(missing),
        })
    if unexpected:
        findings.append({
            "profile": profile,
            "kind": "unexpected_profile_preset_files",
            "detail": ", ".join(unexpected),
        })
    for name in sorted(set(expected) & set(actual)):
        installed_relative = f".github/profiles/{name}"
        symlink_component = _symlink_component(destination, installed_relative)
        if symlink_component or not actual[name].is_file():
            findings.append({
                "profile": profile,
                "kind": "invalid_profile_preset_entry",
                "detail": (
                    f"{name}: symlink component {symlink_component} is not allowed"
                    if symlink_component
                    else f"{name}: expected a regular copied file"
                ),
            })
            continue
        expected_bytes = expected[name].read_bytes()
        actual_bytes = actual[name].read_bytes()
        if actual_bytes != expected_bytes:
            findings.append({
                "profile": profile,
                "kind": "profile_preset_copy_drift",
                "detail": (
                    f"{name}: expected sha256={hashlib.sha256(expected_bytes).hexdigest()} "
                    f"bytes={len(expected_bytes)}; "
                    f"actual sha256={hashlib.sha256(actual_bytes).hexdigest()} "
                    f"bytes={len(actual_bytes)}"
                ),
            })
    return findings


def validate_generated_profile(
    profile: str,
    profile_contract: dict[str, Any],
    rules_entry: dict[str, Any],
    expected_contract_bytes: bytes | None = None,
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    with tempfile.TemporaryDirectory(prefix=f"naos-profile-{profile}-") as temp_dir:
        destination = Path(temp_dir) / "project"
        try:
            result = generate_profile(profile, destination)
        except subprocess.TimeoutExpired:
            return [{
                "profile": profile,
                "kind": "generation_timeout",
                "detail": f"naos_init exceeded {GENERATION_TIMEOUT_SECONDS} seconds",
            }]
        if result.returncode != 0:
            return [
                {
                    "profile": profile,
                    "kind": "generation_failed",
                    "detail": result.stderr.strip() or result.stdout.strip(),
                }
            ]

        for relative in profile_contract.get("required_surfaces") or []:
            required = destination / relative
            symlink_component = _symlink_component(destination, relative)
            if symlink_component or not required.is_file():
                findings.append({
                    "profile": profile,
                    "kind": "required_surface_missing",
                    "detail": (
                        f"{relative}: symlink component {symlink_component} is not allowed"
                        if symlink_component
                        else relative
                    ),
                })
        for relative in profile_contract.get("prohibited_surfaces") or []:
            prohibited = destination / relative
            symlink_component = _symlink_component(destination, relative)
            if symlink_component or prohibited.exists():
                findings.append({
                    "profile": profile,
                    "kind": "prohibited_surface_present",
                    "detail": (
                        f"{relative}: symlink component {symlink_component} is not allowed"
                        if symlink_component
                        else relative
                    ),
                })

        findings.extend(validate_profile_preset_copies(profile, destination))

        generated_contract = destination / "naos" / "profile_generated_surface_contract.json"
        generated_contract_symlink = _symlink_component(
            destination, "naos/profile_generated_surface_contract.json"
        )
        if generated_contract_symlink or not generated_contract.is_file():
            findings.append(
                {
                    "profile": profile,
                    "kind": "generated_contract_missing",
                    "detail": (
                        f"naos/profile_generated_surface_contract.json: symlink component "
                        f"{generated_contract_symlink} is not allowed"
                        if generated_contract_symlink
                        else str(generated_contract)
                    ),
                }
            )
        else:
            expected_contract = (
                expected_contract_bytes
                if expected_contract_bytes is not None
                else CONTRACT_PATH.read_bytes()
            )
            actual_contract = generated_contract.read_bytes()
            if actual_contract != expected_contract:
                findings.append({
                    "profile": profile,
                    "kind": "generated_contract_drift",
                    "detail": (
                        f"expected sha256={hashlib.sha256(expected_contract).hexdigest()} "
                        f"bytes={len(expected_contract)}; "
                        f"actual sha256={hashlib.sha256(actual_contract).hexdigest()} "
                        f"bytes={len(actual_contract)}"
                    ),
                })

        generated_rules = destination / ".ai" / "RULES.md"
        expected_rules = str(rules_entry["content"]).encode("utf-8")
        generated_rules_symlink = _symlink_component(destination, ".ai/RULES.md")
        if generated_rules_symlink or not generated_rules.is_file():
            findings.append({
                "profile": profile,
                "kind": "rules_output_missing",
                "detail": (
                    f".ai/RULES.md: symlink component {generated_rules_symlink} is not allowed"
                    if generated_rules_symlink
                    else ".ai/RULES.md"
                ),
            })
        else:
            actual_rules = generated_rules.read_bytes()
            if actual_rules != expected_rules:
                findings.append(
                    {
                        "profile": profile,
                        "kind": "rules_output_drift",
                        "detail": (
                            f".ai/RULES.md expected sha256="
                            f"{hashlib.sha256(expected_rules).hexdigest()} bytes={len(expected_rules)}; "
                            f"actual sha256={hashlib.sha256(actual_rules).hexdigest()} "
                            f"bytes={len(actual_rules)}"
                        ),
                    }
                )

        makefile = destination / "Makefile.naos"
        makefile_symlink = _symlink_component(destination, "Makefile.naos")
        makefile_valid = not makefile_symlink and makefile.is_file()
        make_text = makefile.read_text(encoding="utf-8") if makefile_valid else ""
        if makefile_symlink:
            findings.append({
                "profile": profile,
                "kind": "makefile_invalid",
                "detail": (
                    f"Makefile.naos: symlink component {makefile_symlink} is not allowed"
                ),
            })
        for command, command_contract in (profile_contract.get("commands") or {}).items():
            declared_target = command_contract.get("target")
            surface = command_contract.get("surface")
            target = declared_target or (None if surface else command)
            surface_symlink = (
                _symlink_component(destination, surface) if surface else None
            )
            if surface and (surface_symlink or not (destination / surface).is_file()):
                findings.append({
                    "profile": profile,
                    "kind": "command_surface_missing",
                    "detail": (
                        f"{command}: {surface}: symlink component {surface_symlink} is not allowed"
                        if surface_symlink
                        else f"{command}: {surface}"
                    ),
                })
            target_definition = (
                re.search(rf"(?m)^{re.escape(str(target))}\s*:(?!=)", make_text)
                if target
                else None
            )
            if target and target_definition is None:
                findings.append({"profile": profile, "kind": "make_target_missing", "detail": target})
            if command_contract.get("applicability") == "not_applicable":
                if not makefile_valid:
                    continue
                if shutil.which("make") is None:
                    findings.append({
                        "profile": profile,
                        "kind": "make_unavailable",
                        "detail": f"{target}: Make is required to execute the not-applicable contract",
                    })
                    continue
                try:
                    executed = subprocess.run(
                        ["make", "--no-print-directory", "-f", "Makefile.naos", "--", str(target)],
                        cwd=destination,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                        timeout=COMMAND_TIMEOUT_SECONDS,
                    )
                except subprocess.TimeoutExpired:
                    findings.append({
                        "profile": profile,
                        "kind": "not_applicable_command_timeout",
                        "detail": f"{target}: exceeded {COMMAND_TIMEOUT_SECONDS} seconds",
                    })
                    continue
                output = f"{executed.stdout}\n{executed.stderr}"
                alternative = str(command_contract.get("alternative"))
                if executed.returncode != 0 or "not_applicable" not in output or alternative not in output:
                    findings.append(
                        {
                            "profile": profile,
                            "kind": "not_applicable_command_contract_failed",
                            "detail": f"{target}: exit={executed.returncode} alternative={alternative!r}",
                        }
                    )
    return findings


def validate_all(
    contract: dict[str, Any],
    rules_source: dict[str, Any],
    expected_contract_bytes: bytes | None = None,
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for profile, profile_contract in (contract.get("profiles") or {}).items():
        findings.extend(
            validate_generated_profile(
                profile,
                profile_contract,
                rules_source["profiles"][profile],
                expected_contract_bytes,
            )
        )
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate profile-generated NAOS surfaces.")
    parser.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    parser.add_argument("--rules-source", type=Path, default=RULES_SOURCE_PATH)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        contract = load_contract(args.contract)
        rules_source = load_profile_rules_source(args.rules_source, claim_root=KIT_ROOT)
        findings = validate_all(
            contract,
            rules_source,
            expected_contract_bytes=args.contract.read_bytes(),
        )
    except Exception as exc:
        findings = [{"profile": "all", "kind": "validator_error", "detail": str(exc)}]
    report = {
        "schema": "naos.profile_generated_surface_validation.v1",
        "status": "passed" if not findings else "failed",
        "profiles_checked": sorted((contract.get("profiles") or {}).keys()) if "contract" in locals() else [],
        "findings": findings,
    }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"profile generated surfaces: {report['status']} ({len(findings)} finding(s))")
        for finding in findings:
            print(f"- {finding['profile']} {finding['kind']}: {finding['detail']}")
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
