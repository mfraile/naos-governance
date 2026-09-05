#!/usr/bin/env python3
"""
validate_configs.py - project-configured config validator (NAOS portable).

Validates YAML/YML/JSON config files for:
1. Parse validity - every config instance under the configured configs dir.
2. Schema validation - matching YAML/YML/JSON instances only when a
   <name>.schema.json exists under the configured schema dir.
3. Required files - project-declared config files that must exist.

This validates declared config shape only. It does not prove runtime config
correctness, feature behavior, secret safety, deployment safety, or governance
approval.

ENV VARS:
    CONFIGS_DIR       path to configs/        (default: configs)
    SCHEMA_DIR        path to schema/configs/ (default: schema/configs)
    REQUIRED_CONFIGS  comma-separated required config paths
                      (default: features.yaml)

EXIT CODES:
    0 - all configured checks passed
    1 - one or more validation errors
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

CONFIG_SUFFIXES = {".yaml", ".yml", ".json"}
DEFAULT_REQUIRED_CONFIGS = ["features.yaml"]


@dataclass
class ValidationResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    parsed_configs: list[str] = field(default_factory=list)
    schema_validated_configs: list[str] = field(default_factory=list)
    schema_files_seen: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def as_report(
        self,
        *,
        configs_dir: Path,
        schema_dir: Path,
        required_configs: list[str],
    ) -> dict[str, Any]:
        return {
            "schema": "naos.config_validation.v1",
            "status": "pass" if self.ok else "fail",
            "configs_dir": str(configs_dir),
            "schema_dir": str(schema_dir),
            "required_configs": required_configs,
            "summary": {
                "errors": len(self.errors),
                "warnings": len(self.warnings),
                "parsed_configs": len(self.parsed_configs),
                "schema_files_seen": len(self.schema_files_seen),
                "schema_validated_configs": len(self.schema_validated_configs),
            },
            "errors": self.errors,
            "warnings": self.warnings,
            "parsed_configs": self.parsed_configs,
            "schema_files_seen": self.schema_files_seen,
            "schema_validated_configs": self.schema_validated_configs,
            "limitations": [
                "Config validation checks parse validity and declared schema shape only.",
                "It does not prove runtime config correctness, feature behavior, deployment safety, approval, or compliance.",
            ],
        }


def split_config_names(values: list[str] | None, env_value: str | None) -> list[str]:
    if values:
        raw_items = values
    elif env_value:
        raw_items = env_value.split(",")
    else:
        raw_items = DEFAULT_REQUIRED_CONFIGS
    required: list[str] = []
    for item in raw_items:
        for part in str(item).split(","):
            cleaned = part.strip()
            if cleaned:
                required.append(cleaned)
    return required


def load_config(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def load_schema(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("schema must be a JSON object")
    return data


def iter_config_files(configs_dir: Path) -> list[Path]:
    files: list[Path] = []
    if not configs_dir.exists():
        return files
    for path in sorted(configs_dir.rglob("*")):
        if path.is_file() and path.suffix.lower() in CONFIG_SUFFIXES:
            files.append(path)
    return files


def matching_config_instances(configs_dir: Path, schema_path: Path) -> list[Path]:
    stem = schema_path.name.removesuffix(".schema.json")
    matches: list[Path] = []
    for suffix in (".yaml", ".yml", ".json"):
        candidate = configs_dir / f"{stem}{suffix}"
        if candidate.exists() and candidate.is_file():
            matches.append(candidate)
    return matches


def validate_parse(configs_dir: Path, result: ValidationResult) -> None:
    if not configs_dir.exists():
        result.errors.append(f"configs directory not found: {configs_dir}")
        return
    for cfg in iter_config_files(configs_dir):
        rel = cfg.relative_to(configs_dir)
        try:
            load_config(cfg)
        except yaml.YAMLError as exc:
            result.errors.append(f"{rel}: YAML parse error: {exc}")
        except json.JSONDecodeError as exc:
            result.errors.append(f"{rel}: JSON parse error: {exc}")
        except Exception as exc:
            result.errors.append(f"{rel}: could not read: {exc}")
        else:
            result.parsed_configs.append(str(rel))


def validate_schemas(configs_dir: Path, schema_dir: Path, result: ValidationResult) -> None:
    if not schema_dir.exists():
        return
    schema_files = sorted(schema_dir.glob("*.schema.json"))
    if not schema_files:
        return

    try:
        import jsonschema
    except ImportError:
        result.warnings.append(
            "jsonschema is not installed; schema validation skipped for matching config instances."
        )
        return

    for schema_path in schema_files:
        schema_rel = schema_path.relative_to(schema_dir)
        result.schema_files_seen.append(str(schema_rel))
        try:
            schema = load_schema(schema_path)
            validator_cls = jsonschema.validators.validator_for(schema)
            validator_cls.check_schema(schema)
            validator = validator_cls(schema)
        except Exception as exc:
            result.errors.append(f"{schema_rel}: invalid schema: {exc}")
            continue

        for cfg_path in matching_config_instances(configs_dir, schema_path):
            rel = cfg_path.relative_to(configs_dir)
            try:
                data = load_config(cfg_path)
                errors = sorted(validator.iter_errors(data), key=lambda err: list(err.path))
            except Exception as exc:
                result.errors.append(f"{rel}: validation error: {exc}")
                continue
            result.schema_validated_configs.append(str(rel))
            for err in errors:
                location = ".".join(str(part) for part in err.path) or "<root>"
                result.errors.append(f"{rel}: {location}: {err.message}")


def validate_required_configs(
    configs_dir: Path,
    required_configs: list[str],
    result: ValidationResult,
) -> None:
    for name in required_configs:
        if not (configs_dir / name).exists():
            result.errors.append(f"required config missing: {configs_dir / name}")


def validate(
    *,
    configs_dir: Path,
    schema_dir: Path,
    required_configs: list[str],
) -> ValidationResult:
    result = ValidationResult()
    validate_parse(configs_dir, result)
    validate_schemas(configs_dir, schema_dir, result)
    validate_required_configs(configs_dir, required_configs, result)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate NAOS project config files.")
    parser.add_argument(
        "--configs-dir",
        default=os.environ.get("CONFIGS_DIR", "configs"),
        help="Config directory to validate (default: CONFIGS_DIR or configs).",
    )
    parser.add_argument(
        "--schema-dir",
        default=os.environ.get("SCHEMA_DIR", "schema/configs"),
        help="Config schema directory (default: SCHEMA_DIR or schema/configs).",
    )
    parser.add_argument(
        "--required-config",
        action="append",
        help=(
            "Required config file relative to --configs-dir. May be repeated or "
            "comma-separated. Defaults to REQUIRED_CONFIGS or features.yaml."
        ),
    )
    parser.add_argument("--json", action="store_true", help="Emit a structured JSON report.")
    return parser


def print_human(report: dict[str, Any]) -> None:
    if report["status"] == "pass":
        print("All configs valid")
    else:
        print("Config validation failed:")
    for warning in report["warnings"]:
        print(f"  [WARN] {warning}")
    for error in report["errors"]:
        print(f"  [FAIL] {error}")
    summary = report["summary"]
    print(
        "Summary: "
        f"parsed={summary['parsed_configs']}, "
        f"schemas={summary['schema_files_seen']}, "
        f"schema_validated={summary['schema_validated_configs']}, "
        f"errors={summary['errors']}, "
        f"warnings={summary['warnings']}"
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configs_dir = Path(args.configs_dir)
    schema_dir = Path(args.schema_dir)
    required_configs = split_config_names(
        args.required_config,
        os.environ.get("REQUIRED_CONFIGS"),
    )
    result = validate(
        configs_dir=configs_dir,
        schema_dir=schema_dir,
        required_configs=required_configs,
    )
    report = result.as_report(
        configs_dir=configs_dir,
        schema_dir=schema_dir,
        required_configs=required_configs,
    )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_human(report)
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
