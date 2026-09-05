"""Adapt adopter paths to the unchanged P1 reference-integrity validator."""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any

import yaml

PORTABLE_SCHEMA = "naos.secure_coding_portable_reference_manifest.v1"
PORTABLE_BOUNDARY = (
    "Portable adaptation changes filesystem paths only; the P1 register, binding, "
    "renderer, generated-section, and drift checks remain authoritative."
)


def _load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected YAML mapping: {path}")
    return value


def _safe_regular_file(path: Path, label: str) -> Path:
    if path.is_symlink():
        raise ValueError(f"{label} must not be a symlink: {path}")
    if not path.is_file():
        raise ValueError(f"{label} is missing: {path}")
    return path


def _safe_relative(raw: object, label: str) -> Path:
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"{label} must be a non-empty relative path")
    path = Path(raw)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{label} must remain repository-relative: {raw}")
    return path


def _copy_file(source: Path, destination: Path, label: str) -> None:
    _safe_regular_file(source, label)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def _error_report(message: str, manifest_path: Path) -> dict[str, Any]:
    return {
        "validator": "validate_secure_coding_control_references",
        "status": "fail",
        "summary": {
            "controls": 0,
            "manifest_targets": 0,
            "rendered_targets": 0,
            "errors": 1,
        },
        "findings": [
            {
                "status": "portable_adapter_error",
                "path": str(manifest_path),
                "message": message,
            }
        ],
        "boundaries": [PORTABLE_BOUNDARY],
        "source_mode": "portable_adopter_manifest",
    }


def validate_portable_references(
    *,
    root: Path,
    naos_root: str,
    kit_root: Path,
    reference_validator: Any,
) -> dict[str, Any]:
    """Build an isolated canonical-path view and invoke the unchanged P1 validator."""
    portable_manifest_path = (
        root / naos_root / "secure_coding_control_render_manifest.yaml"
    )
    try:
        _safe_regular_file(portable_manifest_path, "portable render manifest")
        portable = _load_yaml(portable_manifest_path)
        if portable.get("schema") != PORTABLE_SCHEMA:
            raise ValueError(
                f"unsupported portable manifest schema: {portable.get('schema')!r}"
            )

        register_rel = _safe_relative(
            portable.get("register"),
            "portable register",
        )
        register_path = root / naos_root / register_rel
        register = _load_yaml(
            _safe_regular_file(register_path, "portable canonical register")
        )

        target_specs = portable.get("targets")
        if not isinstance(target_specs, list) or not target_specs:
            raise ValueError("portable manifest targets must be a non-empty list")

        canonical_manifest_path = (
            kit_root / "configs/secure_coding_control_render_manifest.yaml"
        )
        canonical_manifest = _load_yaml(
            _safe_regular_file(canonical_manifest_path, "canonical render manifest")
        )
        canonical_targets = {
            item.get("path"): item
            for item in canonical_manifest.get("targets", [])
            if isinstance(item, dict) and isinstance(item.get("path"), str)
        }

        selected_targets: list[dict[str, Any]] = []
        copy_plan: list[tuple[Path, Path, str]] = []
        selected_project_paths: list[str] = []
        for index, spec in enumerate(target_specs):
            if not isinstance(spec, dict):
                raise ValueError(f"targets[{index}] must be a mapping")
            source_rel = _safe_relative(
                spec.get("canonical_path"),
                f"targets[{index}].canonical_path",
            )
            project_rel = _safe_relative(
                spec.get("project_path"),
                f"targets[{index}].project_path",
            )
            optional = spec.get("optional") is True
            project_path = root / project_rel
            if not project_path.exists() and optional:
                continue
            _safe_regular_file(project_path, f"portable target {project_rel}")
            source_key = source_rel.as_posix()
            canonical_target = canonical_targets.get(source_key)
            if canonical_target is None:
                raise ValueError(
                    f"targets[{index}] references unknown canonical target: {source_key}"
                )
            selected_targets.append(dict(canonical_target))
            copy_plan.append(
                (
                    project_path,
                    source_rel,
                    f"portable target {project_rel}",
                )
            )
            selected_project_paths.append(project_rel.as_posix())

        if not selected_targets:
            raise ValueError("portable manifest resolved no available project targets")

        detector_catalog = register.get("detector_catalog")
        if not isinstance(detector_catalog, dict):
            raise ValueError("portable register detector_catalog must be a mapping")

        with tempfile.TemporaryDirectory(prefix="naos-p1-portable-") as temp_dir:
            virtual_root = Path(temp_dir)
            canonical_register_rel = Path(
                "configs/secure_coding_control_register.yaml"
            )
            canonical_schema_rel = Path(
                "schemas/naos/secure_coding_control_register.schema.json"
            )
            canonical_renderer_rel = Path(
                "scripts/naos_render_secure_coding_controls.py"
            )
            canonical_manifest_rel = Path(
                "configs/secure_coding_control_render_manifest.yaml"
            )

            _copy_file(
                register_path,
                virtual_root / canonical_register_rel,
                "portable canonical register",
            )
            _copy_file(
                kit_root / canonical_schema_rel,
                virtual_root / canonical_schema_rel,
                "canonical register schema",
            )
            _copy_file(
                kit_root / canonical_renderer_rel,
                virtual_root / canonical_renderer_rel,
                "canonical renderer",
            )

            for source, canonical_rel, label in copy_plan:
                _copy_file(source, virtual_root / canonical_rel, label)

            for detector_id, entry in detector_catalog.items():
                if not isinstance(entry, dict) or not isinstance(
                    entry.get("path"), str
                ):
                    continue
                detector_rel = _safe_relative(
                    entry["path"],
                    f"detector_catalog.{detector_id}.path",
                )
                project_source = root / detector_rel
                kit_source = kit_root / detector_rel
                if project_source.is_file() and not project_source.is_symlink():
                    source = project_source
                else:
                    source = kit_source
                _copy_file(
                    source,
                    virtual_root / detector_rel,
                    f"detector host {detector_id}",
                )

            canonical_view = {
                "schema": canonical_manifest.get("schema"),
                "version": canonical_manifest.get("version"),
                "register": canonical_register_rel.as_posix(),
                "renderer": canonical_renderer_rel.as_posix(),
                "boundary": canonical_manifest.get("boundary"),
                "targets": selected_targets,
            }
            manifest_destination = virtual_root / canonical_manifest_rel
            manifest_destination.parent.mkdir(parents=True, exist_ok=True)
            manifest_destination.write_text(
                yaml.safe_dump(canonical_view, sort_keys=False),
                encoding="utf-8",
            )

            report = reference_validator.validate_references(
                virtual_root,
                canonical_manifest_rel,
                virtual_root / canonical_schema_rel,
            )

        report["source_mode"] = "portable_adopter_manifest"
        report["portable_manifest"] = str(portable_manifest_path)
        report["project_targets"] = selected_project_paths
        boundaries = report.get("boundaries")
        if not isinstance(boundaries, list):
            boundaries = []
            report["boundaries"] = boundaries
        boundaries.append(PORTABLE_BOUNDARY)
        return report
    except Exception as exc:
        return _error_report(str(exc), portable_manifest_path)
