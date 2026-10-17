#!/usr/bin/env python3
"""NAOS AI pre-commit policy runner (v0.9.2 safe mode).

This script intentionally avoids pretending that provider-backed semantic review
is available when it has not been configured. It validates centralized AI policy
configuration and exits cleanly for disabled/static modes.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


VALID_MODES = {"disabled", "static_only", "local_ollama", "api_provider", "ide_agent"}


def _load_config(path: Path) -> dict:
    if not path.is_file():
        print(f"[WARN] AI pre-commit config not found: {path}")
        return {"ai_review": {"enabled": False, "mode": "disabled"}}
    if yaml is None:
        raise RuntimeError("PyYAML is required to read naos_ai_precommit.yaml")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError("AI configuration must be valid YAML") from exc
    if not isinstance(data, dict):
        raise ValueError("AI configuration root must be a mapping")
    return data


def _section(data: dict, key: str, label: str | None = None) -> dict:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ValueError(f"{label or key} must be a mapping when present")
    return value


def _optional_text(section: dict, key: str, label: str) -> str | None:
    value = section.get(key)
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{label} must be a string or null")
    return value


def _policy(data: dict) -> tuple[bool, str, str | None]:
    if not isinstance(data, dict):
        raise ValueError("AI configuration root must be a mapping")
    section = _section(data, "ai_review")
    fallback = _section(data, "stage2_fallback")
    grader = _section(_section(data, "grading"), "llm_grader", "grading.llm_grader")
    for mapping, label in ((data, "enabled"), (section, "ai_review.enabled")):
        if "enabled" in mapping and type(mapping["enabled"]) is not bool:
            raise ValueError(f"{label} must be a YAML Boolean")
    for mapping, key, label in ((section, "mode", "ai_review.mode"),
                                (fallback, "preferred_backend", "stage2_fallback.preferred_backend")):
        if key in mapping and not isinstance(mapping[key], str):
            raise ValueError(f"{label} must be a string")
    provider = _optional_text(section, "provider", "ai_review.provider")
    _optional_text(section, "api_key_env", "ai_review.api_key_env")
    _optional_text(grader, "api_key_env", "grading.llm_grader.api_key_env")
    enabled = section.get("enabled", data.get("enabled", True))
    mode = section.get("mode", fallback.get("preferred_backend", "static_only"))
    legacy = {"auto": "ide_agent", "ollama": "local_ollama", "agent": "ide_agent"}
    mode = legacy.get(mode, mode)
    if not enabled:
        mode = "disabled"
    return enabled, mode, provider or None


def check_config(config_path: Path) -> int:
    try:
        data = _load_config(config_path)
        enabled, mode, provider = _policy(data)
        section = _section(data, "ai_review")
        grader = _section(_section(data, "grading"), "llm_grader", "grading.llm_grader")
        env_var = section.get("api_key_env") or grader.get("api_key_env")
    except Exception as exc:
        print(f"[FAIL] Invalid AI configuration: {exc}")
        return 1
    if mode not in VALID_MODES:
        print(f"[FAIL] Invalid ai_review.mode: {mode}")
        return 1
    print(f"[OK] AI review policy: enabled={enabled} mode={mode} provider={provider or 'n/a'}")
    if mode == "api_provider":
        if env_var and not env_var.startswith("[ADAPT"):
            print(f"[INFO] API provider expects environment variable: {env_var}")
        print("[INFO] Provider execution is not performed by v0.9.2 safe mode.")
    elif mode == "local_ollama":
        print("[INFO] Ollama execution is scaffolded; v0.9.2 safe mode validates config only.")
    elif mode == "ide_agent":
        print("[INFO] IDE-agent review is a manual/delegated workflow in v0.9.2.")
    else:
        print("[INFO] Static governance remains active; AI semantic review is disabled/static-only.")
    return 0


def rebuild_embeddings(config_path: Path) -> int:
    code = check_config(config_path)
    if code != 0:
        return code
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    marker = data_dir / "rules_embeddings.status.json"
    marker.write_text(
        json.dumps(
            {
                "status": "not_built_by_v092_safe_mode",
                "config": str(config_path),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "note": "Full embedding build belongs to the provider/runtime milestone.",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"[OK] Wrote safe-mode embedding status: {marker}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate NAOS AI review policy")
    parser.add_argument(
        "--config",
        default="configs/naos_ai_precommit.yaml",
        help="Path to naos_ai_precommit.yaml",
    )
    parser.add_argument("--check-config", action="store_true", help="Validate config only")
    parser.add_argument(
        "--rebuild-embeddings",
        action="store_true",
        help="Create a safe-mode status marker; full embedding build is deferred",
    )
    parser.add_argument(
        "--review",
        action="store_true",
        help="Validate policy and explain current review mode",
    )
    args = parser.parse_args()
    config_path = Path(args.config)
    if args.rebuild_embeddings:
        return rebuild_embeddings(config_path)
    return check_config(config_path)


if __name__ == "__main__":
    sys.exit(main())
