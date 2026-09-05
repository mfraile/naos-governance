#!/usr/bin/env python3
"""Render bounded secure-coding control summaries into configured guidance surfaces."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = Path("configs/secure_coding_control_render_manifest.yaml")
SECTION_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


@dataclass(frozen=True)
class PlannedUpdate:
    path: Path
    current: str
    expected: str

    @property
    def changed(self) -> bool:
        return self.current != self.expected


def _load_mapping(path: Path, label: str) -> tuple[dict[str, Any], list[str]]:
    if not path.is_file():
        return {}, [f"{label} not found: {path}"]
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return {}, [f"cannot read {label} {path}: {exc}"]
    if not isinstance(value, dict):
        return {}, [f"{label} must be a YAML mapping: {path}"]
    return value, []


def _safe_repo_path(root: Path, raw: object, label: str) -> tuple[Path | None, list[str]]:
    if isinstance(raw, Path):
        raw_text = str(raw)
    elif isinstance(raw, str):
        raw_text = raw
    else:
        return None, [f"{label} must be a non-empty repository-relative path"]
    if not raw_text.strip():
        return None, [f"{label} must be a non-empty repository-relative path"]
    supplied = Path(raw_text)
    if supplied.is_absolute():
        return None, [f"{label} must be repository-relative, not absolute: {raw_text}"]
    candidate = (root / supplied).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None, [f"{label} escapes repository root: {raw_text}"]
    return candidate, []


def _marker(section_id: str, begin: bool) -> str:
    edge = "BEGIN" if begin else "END"
    return f"<!-- {edge} NAOS GENERATED: {section_id} -->"


def render_block(
    *,
    section_id: str,
    title: str,
    control_ids: list[str],
    controls: dict[str, dict[str, Any]],
    register_rel: str,
    register_version: str,
    renderer_rel: str,
    boundary: str,
) -> str:
    lines = [
        _marker(section_id, True),
        f"## {title}",
        "",
        (
            f"> Generated from `{register_rel}` version `{register_version}` by "
            f"`{renderer_rel}`. Do not edit this section manually."
        ),
        f"> Boundary: {boundary}",
        "",
    ]
    for control_id in control_ids:
        statement = str(controls[control_id]["statement"]).strip()
        lines.append(f"- **`{control_id}`** — {statement}")
    lines.extend(["", _marker(section_id, False)])
    return "\n".join(lines)


def replace_generated_section(text: str, section_id: str, block: str) -> tuple[str, list[str]]:
    begin = _marker(section_id, True)
    end = _marker(section_id, False)
    begin_count = text.count(begin)
    end_count = text.count(end)
    if begin_count == 0 and end_count == 0:
        return text.rstrip() + "\n\n" + block + "\n", []
    if begin_count != 1 or end_count != 1:
        return text, [
            f"section {section_id!r} must contain exactly one begin and one end marker "
            f"(found begin={begin_count}, end={end_count})"
        ]
    start = text.index(begin)
    end_start = text.index(end)
    if end_start < start:
        return text, [f"section {section_id!r} markers are out of order"]
    finish = end_start + len(end)
    return text[:start] + block + text[finish:], []


def build_plan(
    root: Path = ROOT,
    manifest_rel: Path = DEFAULT_MANIFEST,
) -> tuple[list[PlannedUpdate], list[str]]:
    root = root.resolve()
    manifest_path, findings = _safe_repo_path(root, manifest_rel, "render manifest")
    if manifest_path is None:
        return [], findings
    manifest, load_findings = _load_mapping(manifest_path, "render manifest")
    findings.extend(load_findings)
    if load_findings:
        return [], findings

    if manifest.get("schema") != "naos.secure_coding_control_render_manifest.v1":
        findings.append("unsupported or missing render-manifest schema")

    register_rel = manifest.get("register")
    register_path, path_findings = _safe_repo_path(root, register_rel, "register")
    findings.extend(path_findings)
    if register_path is None:
        return [], findings
    register, load_findings = _load_mapping(register_path, "control register")
    findings.extend(load_findings)
    if load_findings:
        return [], findings

    if register.get("status") != "active":
        findings.append("canonical register status must be 'active' before rendering")

    raw_controls = register.get("controls")
    if not isinstance(raw_controls, list):
        return [], findings + ["control register controls must be a list"]
    controls: dict[str, dict[str, Any]] = {}
    for index, control in enumerate(raw_controls):
        if not isinstance(control, dict):
            findings.append(f"controls[{index}] must be a mapping")
            continue
        control_id = control.get("id")
        statement = control.get("statement")
        if not isinstance(control_id, str) or not control_id:
            findings.append(f"controls[{index}].id must be a non-empty string")
            continue
        if not isinstance(statement, str) or not statement.strip():
            findings.append(f"control {control_id} has no renderable statement")
            continue
        if control_id in controls:
            findings.append(f"duplicate control id in canonical register: {control_id}")
            continue
        controls[control_id] = control

    targets = manifest.get("targets")
    if not isinstance(targets, list) or not targets:
        return [], findings + ["render manifest targets must be a non-empty list"]

    renderer_rel = manifest.get("renderer")
    renderer_path, renderer_findings = _safe_repo_path(root, renderer_rel, "renderer")
    findings.extend(renderer_findings)
    if renderer_path is None:
        renderer_rel = "scripts/naos_render_secure_coding_controls.py"
    elif not renderer_path.is_file():
        findings.append(f"renderer not found: {renderer_rel}")
    boundary = manifest.get("boundary")
    if not isinstance(boundary, str) or not boundary.strip():
        findings.append("render manifest boundary must be non-empty text")
        boundary = "Generated summaries are not enforcement authority."

    plans: list[PlannedUpdate] = []
    seen_paths: set[Path] = set()
    seen_sections: set[tuple[Path, str]] = set()
    for index, target in enumerate(targets):
        if not isinstance(target, dict):
            findings.append(f"targets[{index}] must be a mapping")
            continue
        target_path, target_findings = _safe_repo_path(root, target.get("path"), f"targets[{index}].path")
        findings.extend(target_findings)
        if target_path is None:
            continue
        if target_path in seen_paths:
            findings.append(f"duplicate target path: {target.get('path')}")
        seen_paths.add(target_path)
        section_id = target.get("section_id")
        if not isinstance(section_id, str) or not SECTION_ID_RE.fullmatch(section_id):
            findings.append(f"targets[{index}].section_id is invalid")
            continue
        pair = (target_path, section_id)
        if pair in seen_sections:
            findings.append(f"duplicate target section: {target.get('path')}#{section_id}")
        seen_sections.add(pair)
        title = target.get("title")
        if not isinstance(title, str) or not title.strip():
            findings.append(f"targets[{index}].title must be non-empty text")
            continue
        requested = target.get("controls")
        if not isinstance(requested, list) or not requested:
            findings.append(f"targets[{index}].controls must be a non-empty list")
            continue
        control_ids: list[str] = []
        for item in requested:
            if not isinstance(item, str) or not item:
                findings.append(f"targets[{index}] contains a non-string control id")
                continue
            if item not in controls:
                findings.append(f"targets[{index}] references unknown control id: {item}")
                continue
            if item in control_ids:
                findings.append(f"targets[{index}] repeats control id: {item}")
                continue
            control_ids.append(item)
        if not target_path.is_file():
            findings.append(f"render target not found: {target.get('path')}")
            continue
        current = target_path.read_text(encoding="utf-8")
        block = render_block(
            section_id=section_id,
            title=title.strip(),
            control_ids=control_ids,
            controls=controls,
            register_rel=str(register_rel),
            register_version=str(register.get("version", "unknown")),
            renderer_rel=str(renderer_rel),
            boundary=boundary.strip(),
        )
        expected, section_findings = replace_generated_section(current, section_id, block)
        findings.extend(f"{target.get('path')}: {finding}" for finding in section_findings)
        plans.append(PlannedUpdate(target_path, current, expected))

    return plans, findings


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail when generated sections are missing or stale")
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST, help="manifest path relative to root")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    plans, findings = build_plan(args.root, args.manifest)
    if findings:
        for finding in findings:
            print(f"ERROR: {finding}", file=sys.stderr)
        return 2
    changed = [plan for plan in plans if plan.changed]
    if args.check:
        if changed:
            for plan in changed:
                print(f"STALE: {plan.path.relative_to(args.root.resolve())}", file=sys.stderr)
            return 1
        print(f"secure-coding control rendering is current ({len(plans)} targets)")
        return 0
    for plan in changed:
        plan.path.write_text(plan.expected, encoding="utf-8")
        print(f"UPDATED: {plan.path.relative_to(args.root.resolve())}")
    print(f"secure-coding control rendering complete ({len(changed)} changed, {len(plans)} targets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
