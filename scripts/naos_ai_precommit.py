#!/usr/bin/env python3
"""NAOS AI pre-commit policy runner (v0.9.2 safe mode).

This script intentionally avoids pretending that provider-backed semantic review
is available when it has not been configured. It validates centralized AI policy
configuration and exits cleanly for disabled/static modes.
"""

from __future__ import annotations

import argparse
import json
import os
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
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _policy(data: dict) -> tuple[bool, str, str | None]:
    section = data.get("ai_review", {}) if isinstance(data, dict) else {}
    enabled = bool(section.get("enabled", data.get("enabled", True)))
    mode = str(section.get("mode", data.get("stage2_fallback", {}).get("preferred_backend", "static_only")))
    provider = section.get("provider")
    legacy = {"auto": "ide_agent", "ollama": "local_ollama", "agent": "ide_agent"}
    mode = legacy.get(mode, mode)
    if not enabled:
        mode = "disabled"
    return enabled, mode, str(provider) if provider else None


def check_config(config_path: Path) -> int:
    try:
        data = _load_config(config_path)
    except Exception as exc:
        print(f"[FAIL] Cannot load AI config: {exc}")
        return 1
    enabled, mode, provider = _policy(data)
    if mode not in VALID_MODES:
        print(f"[FAIL] Invalid ai_review.mode: {mode}")
        return 1
    print(f"[OK] AI review policy: enabled={enabled} mode={mode} provider={provider or 'n/a'}")
    if mode == "api_provider":
        env_var = data.get("ai_review", {}).get("api_key_env") or data.get("grading", {}).get("llm_grader", {}).get("api_key_env")
        if env_var and not str(env_var).startswith("[ADAPT"):
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
