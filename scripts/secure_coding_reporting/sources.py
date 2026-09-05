"""Authoritative P1/P2 source generation for P3 reporting."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parents[1]
VALIDATORS_DIR = SCRIPT_DIR / "validators"
for path in (SCRIPT_DIR, VALIDATORS_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import naos_secure_coding_controls as controls_reporter  # noqa: E402
import validate_secure_coding_control_references as reference_validator  # noqa: E402
from naos_policy import write_report  # noqa: E402
from secure_coding_reporting.portable_reference import (  # noqa: E402
    validate_portable_references,
)


def refresh(
    *,
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
    reference_path: Path,
    controls_path: Path,
    check_mode: bool,
    generated_at: str | None,
) -> None:
    """Invoke P1/P2 implementations and persist their structured results safely."""
    portable_manifest = (
        root / naos_root / "secure_coding_control_render_manifest.yaml"
    )
    if portable_manifest.exists() or portable_manifest.is_symlink():
        reference = validate_portable_references(
            root=root,
            naos_root=naos_root,
            kit_root=SCRIPT_DIR.parent,
            reference_validator=reference_validator,
        )
    else:
        reference = reference_validator.validate_references(root)
    write_report(reference_path, reference)

    defaults = controls_reporter.default_sources(root, naos_root)
    controls = controls_reporter.build_report(
        root=root,
        naos_root=naos_root,
        profile=profile,
        policy=policy,
        register_path=defaults["register"],
        routes_path=defaults["routes"],
        register_schema_path=defaults["register_schema"],
        routes_schema_path=defaults["routes_schema"],
        report_schema_path=defaults["report_schema"],
        check_mode=check_mode,
        pr_context=False,
        external_evidence_supplied=False,
        generated_at=generated_at,
    )
    write_report(controls_path, controls)
