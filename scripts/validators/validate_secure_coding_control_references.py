#!/usr/bin/env python3
"""Validate canonical control references and generated guidance without claiming security."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
TOOL_ROOT = Path(__file__).resolve().parents[1]
if str(TOOL_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOL_ROOT))

from naos_render_secure_coding_controls import DEFAULT_MANIFEST, build_plan  # noqa: E402
import validate_secure_coding_control_register as register_validator  # noqa: E402

CANONICAL_REGISTER = "configs/secure_coding_control_register.yaml"
DEFAULT_SCHEMA = ROOT / "schemas/naos/secure_coding_control_register.schema.json"
BOUNDARIES = [
    "Reference integrity does not prove secure code or correct runtime behavior.",
    "Generated summaries do not own severity, blocking, waivers, approvals, or release decisions.",
    "Standards mappings remain subject to their individual verification status.",
]


def _load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected YAML mapping: {path}")
    return value


def _finding(items: list[dict[str, str]], status: str, path: str, message: str) -> None:
    items.append({"status": status, "path": path, "message": message})


def _resolve_within_root(root: Path, raw: Path | str, *, require_relative: bool) -> Path | None:
    supplied = Path(raw)
    if require_relative and supplied.is_absolute():
        return None
    candidate = supplied.resolve() if supplied.is_absolute() else (root / supplied).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def validate_references(
    root: Path = ROOT,
    manifest_rel: Path = DEFAULT_MANIFEST,
    schema_path: Path = DEFAULT_SCHEMA,
) -> dict[str, Any]:
    root = root.resolve()
    findings: list[dict[str, str]] = []

    manifest_path = _resolve_within_root(root, manifest_rel, require_relative=True)
    if manifest_path is None:
        _finding(
            findings,
            "manifest_path_outside_repository",
            str(manifest_rel),
            "manifest must be a repository-relative path that resolves inside the repository",
        )
        return _report(findings, 0, 0, 0)
    try:
        manifest = _load_yaml(manifest_path)
    except Exception as exc:
        _finding(findings, "manifest_load_error", str(manifest_rel), str(exc))
        return _report(findings, 0, 0, 0)

    register_rel = manifest.get("register")
    if register_rel != CANONICAL_REGISTER:
        _finding(
            findings,
            "noncanonical_register_reference",
            "$.register",
            f"render manifest must reference {CANONICAL_REGISTER}",
        )
        return _report(findings, 0, len(manifest.get("targets", [])) if isinstance(manifest.get("targets"), list) else 0, 0)

    register_path = _resolve_within_root(root, CANONICAL_REGISTER, require_relative=True)
    schema_resolved = _resolve_within_root(root, schema_path, require_relative=False)
    if register_path is None:
        _finding(findings, "canonical_register_path_error", "$.register", CANONICAL_REGISTER)
        return _report(findings, 0, 0, 0)
    if schema_resolved is None:
        _finding(
            findings,
            "schema_path_outside_repository",
            str(schema_path),
            "schema must resolve inside the repository",
        )
        return _report(findings, 0, 0, 0)
    try:
        register = _load_yaml(register_path)
        schema = json.loads(schema_resolved.read_text(encoding="utf-8"))
    except Exception as exc:
        _finding(findings, "register_load_error", CANONICAL_REGISTER, str(exc))
        return _report(findings, 0, 0, 0)

    register_report = register_validator.validate_register(register, schema, root)
    for item in register_report.get("findings", []):
        _finding(
            findings,
            f"register_{item['status']}",
            item["path"],
            item["message"],
        )
    if register.get("status") != "active":
        _finding(findings, "inactive_canonical_register", "$.status", str(register.get("status")))

    renderer_rel = manifest.get("renderer")
    renderer_path = None
    if isinstance(renderer_rel, str):
        renderer_path = _resolve_within_root(root, renderer_rel, require_relative=True)
    if renderer_path is None or not renderer_path.is_file():
        _finding(findings, "missing_or_unsafe_renderer", "$.renderer", str(renderer_rel))

    targets = manifest.get("targets") if isinstance(manifest.get("targets"), list) else []
    target_controls: dict[str, set[str]] = {}
    section_pairs: set[tuple[str, str]] = set()
    for index, target in enumerate(targets):
        if not isinstance(target, dict):
            _finding(findings, "invalid_target", f"$.targets[{index}]", "target must be a mapping")
            continue
        path = target.get("path")
        section_id = target.get("section_id")
        controls = target.get("controls")
        if not isinstance(path, str) or not isinstance(section_id, str) or not isinstance(controls, list):
            _finding(findings, "invalid_target", f"$.targets[{index}]", "path, section_id, and controls are required")
            continue
        if _resolve_within_root(root, path, require_relative=True) is None:
            _finding(findings, "target_path_outside_repository", f"$.targets[{index}].path", path)
            continue
        pair = (path, section_id)
        if pair in section_pairs:
            _finding(findings, "duplicate_target_section", f"$.targets[{index}]", f"{path}#{section_id}")
        section_pairs.add(pair)
        target_controls.setdefault(path, set()).update(item for item in controls if isinstance(item, str))

    controls = register.get("controls") if isinstance(register.get("controls"), list) else []
    controls_by_id = {
        control.get("id"): control
        for control in controls
        if isinstance(control, dict) and isinstance(control.get("id"), str)
    }
    known_ids = set(controls_by_id)
    for path, ids in target_controls.items():
        for control_id in sorted(ids - known_ids):
            _finding(findings, "unknown_manifest_control", path, control_id)
        for control_id in sorted(ids & known_ids):
            control = controls_by_id[control_id]
            evaluation = control.get("evaluation") if isinstance(control.get("evaluation"), dict) else {}
            surfaces = evaluation.get("advisory_surfaces") if isinstance(evaluation.get("advisory_surfaces"), list) else []
            if path not in surfaces:
                _finding(
                    findings,
                    "undeclared_manifest_binding",
                    path,
                    f"{control_id} is rendered here but the canonical register does not declare this advisory surface",
                )

    for index, control in enumerate(controls):
        if not isinstance(control, dict) or not isinstance(control.get("id"), str):
            continue
        control_id = control["id"]
        evaluation = control.get("evaluation") if isinstance(control.get("evaluation"), dict) else {}
        surfaces = evaluation.get("advisory_surfaces") if isinstance(evaluation.get("advisory_surfaces"), list) else []
        for surface in surfaces:
            if isinstance(surface, str) and surface in target_controls and control_id not in target_controls[surface]:
                _finding(
                    findings,
                    "missing_manifest_binding",
                    f"$.controls[{index}].evaluation.advisory_surfaces",
                    f"{control_id} is declared for {surface} but absent from its generated section",
                )

    plans, render_findings = build_plan(root, manifest_rel)
    for message in render_findings:
        _finding(findings, "render_configuration_error", str(manifest_rel), message)
    for plan in plans:
        if plan.changed:
            _finding(
                findings,
                "stale_generated_section",
                str(plan.path.relative_to(root)),
                "run scripts/naos_render_secure_coding_controls.py",
            )

    return _report(findings, len(controls), len(targets), len(plans))


def _report(findings: list[dict[str, str]], controls: int, targets: int, planned_targets: int) -> dict[str, Any]:
    return {
        "validator": "validate_secure_coding_control_references",
        "status": "pass" if not findings else "fail",
        "summary": {
            "controls": controls,
            "manifest_targets": targets,
            "rendered_targets": planned_targets,
            "errors": len(findings),
        },
        "findings": findings,
        "boundaries": BOUNDARIES,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = validate_references(args.root, args.manifest, args.schema)
    except Exception as exc:
        report = {
            "validator": "validate_secure_coding_control_references",
            "status": "error",
            "summary": {"errors": 1},
            "findings": [{"status": "load_error", "path": "$", "message": str(exc)}],
            "boundaries": BOUNDARIES,
        }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"NAOS control-reference validation: {report['status']} ({report['summary'].get('errors', 0)} error(s))")
        for item in report.get("findings", []):
            print(f"- {item['status']}: {item['path']}: {item['message']}")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
