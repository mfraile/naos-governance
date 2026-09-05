"""Console entry point for bounded secure-coding P3 reporting."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def main() -> int:
    script = Path(__file__).resolve().parent / "scripts" / "naos_secure_coding_reporting.py"
    spec = importlib.util.spec_from_file_location(
        "_naos_secure_coding_reporting_cli",
        script,
    )
    if spec is None or spec.loader is None:
        print(f"[ERROR] Could not load secure-coding reporting command: {script}")
        return 2
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    command = getattr(module, "main", None)
    if command is None:
        print("[ERROR] Secure-coding reporting command has no main()")
        return 2
    return int(command(sys.argv[1:]))


if __name__ == "__main__":
    raise SystemExit(main())
