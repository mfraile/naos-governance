"""Opt-in generator source origins; never grants ownership or mutation authority."""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass
from pathlib import Path

from .portable_provenance import PortableProvenanceError, _unique_paths
from .generated_recipes import (
    MAX_INPUTS, MAX_INPUT_BYTES, MAX_TOTAL_INPUT_BYTES, MAX_STATIC_BYTES,
    RecipeInstance, RecipeLibrary, load_static_recipes,
)
from .source_modes import (
    MAX_DECLARATION_BYTES,
    MAX_ITEMS,
    MAX_LEAF_BYTES,
    SourceModeDeclaration,
    SourceModeError,
    encode_mode_rows,
    load_source_mode_declaration,
    mode_row,
)


MAX_CAPTURED_BYTES = 256 * 1024 * 1024
MAX_INVENTORY_READ_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class GeneratedSourceInventory:
    rows: tuple[dict[str, object], ...]
    unresolved_paths: tuple[str, ...]
    source_artifacts: tuple[SourceOriginArtifact, ...] = ()

    def require_complete(self) -> tuple[str, bytes]:
        """Return a portable record only if every selected leaf has an origin."""
        if self.unresolved_paths:
            raise SourceModeError("Generated leaves lack reviewed source authority: "
                                  + ", ".join(self.unresolved_paths))
        return encode_mode_rows(list(self.rows))


@dataclass(frozen=True)
class SourceOriginArtifact:
    destination: str
    kind: str
    source_reference: str
    artifact_bytes: bytes


class SourceOrigins:
    """Capture exact original kit bytes at copying sites, then final output bytes."""

    def __init__(self, kit_root: Path, declaration: SourceModeDeclaration,
                 *, output_root: Path | None = None):
        self.kit_root = kit_root.absolute()
        self.declaration = declaration
        self.output_root = output_root.absolute() if output_root is not None else None
        self._origins: dict[str, tuple[str, bytes]] = {}
        self._recipes: dict[str, RecipeInstance] = {}
        self._recipe_library: RecipeLibrary | None = None
        self._captured_bytes = 0

    @classmethod
    def from_kit(cls, kit_root: Path, *, output_root: Path | None = None) -> SourceOrigins:
        path = kit_root / "configs" / "source_modes.json"
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_DECLARATION_BYTES:
            raise SourceModeError("Missing, linked or oversized source-mode declaration")
        with path.open("rb") as stream:
            raw = stream.read(MAX_DECLARATION_BYTES + 1)
        return cls(kit_root, load_source_mode_declaration(raw), output_root=output_root)

    def _relative_output(self, destination: Path) -> str:
        if self.output_root is None:
            raise SourceModeError("Output root is required for copy capture")
        try:
            return destination.absolute().relative_to(self.output_root).as_posix()
        except ValueError as exc:
            raise SourceModeError("Copied destination is outside the preview") from exc

    @staticmethod
    def _bounded_bytes(path: Path, *, remaining: int = MAX_LEAF_BYTES) -> bytes:
        limit = min(MAX_LEAF_BYTES, remaining)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            raise SourceModeError(f"Missing, linked or oversized source/output: {path}")
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise SourceModeError(f"Oversized source/output: {path}")
        return data

    def record(self, source: Path, destination: str, *, source_bytes: bytes | None = None) -> None:
        if destination in self._recipes:
            raise SourceModeError("Generated destination already has a recipe origin")
        try:
            source_relative = source.absolute().relative_to(self.kit_root).as_posix()
        except ValueError as exc:
            raise SourceModeError("Generated source is outside the kit") from exc
        previous = self._origins.get(destination)
        remaining = MAX_CAPTURED_BYTES - self._captured_bytes + (len(previous[1]) if previous else 0)
        data = (self._bounded_bytes(source, remaining=remaining)
                if source_bytes is None else source_bytes)
        if type(data) is not bytes or len(data) > MAX_LEAF_BYTES:
            raise SourceModeError("Missing or oversized original source bytes")
        if len(data) > remaining:
            raise SourceModeError("Captured generator source bytes exceed budget")
        # Validate membership, source bytes and the canonical final destination
        # immediately. The output is rehashed after all generator transforms.
        mode_row(self.declaration, source=source_relative, source_bytes=data,
                 destination=destination, output_bytes=data)
        self._captured_bytes += len(data) - (len(previous[1]) if previous else 0)
        if self._captured_bytes > MAX_CAPTURED_BYTES:
            raise SourceModeError("Captured generator source bytes exceed budget")
        self._origins[destination] = (source_relative, data)

    def record_recipe(self, role: str, destination: str,
                      inputs: list[tuple[str, bytes]],
                      decisions: dict[str, str | int | bool]) -> None:
        """Freeze a typed canonical source artifact before its output is written."""
        if destination in self._origins or destination in self._recipes:
            raise SourceModeError("Generated destination already has an origin")
        if self._recipe_library is None:
            declaration_path = "configs/generated_source_recipes.json"
            raw = self._bounded_bytes(self.kit_root / declaration_path,
                                      remaining=MAX_STATIC_BYTES)
            declaration_row = mode_row(
                self.declaration, source=declaration_path, source_bytes=raw,
                destination=declaration_path, output_bytes=raw,
            )
            if declaration_row["executable"] is not False:
                raise SourceModeError("Generated recipe declaration must be nonexecutable")
            self._recipe_library = load_static_recipes(raw, self.kit_root)
        instance = self._recipe_library.create_instance(role, destination, inputs, decisions)
        if self._captured_bytes + len(instance.artifact_bytes) > MAX_CAPTURED_BYTES:
            raise SourceModeError("Captured generator source bytes exceed budget")
        self._captured_bytes += len(instance.artifact_bytes)
        self._recipes[destination] = instance

    def record_copied_tool_content(
        self, destination: str, inputs: list[tuple[str, bytes]],
    ) -> None:
        """Replace only the copied validator origin with its derived recipe.

        The final content table depends on other final copy outputs, so its
        source identity is a declared recipe, not an opaque copy mutation.
        """
        allowed = {
            "scripts/validators/validate_traceability_headers.py",
            "naos_tools/validators/validate_traceability_headers.py",
        }
        origin = self._origins.get(destination)
        if (destination not in allowed or origin is None
                or origin[0] != "scripts/validators/validate_traceability_headers.py"
                or destination in self._recipes):
            raise SourceModeError("Copied-tool recipe has no exact captured validator origin")
        source_relative, original = origin
        current = self._bounded_bytes(self.kit_root / source_relative)
        if current != original:
            raise SourceModeError("Copied validator source changed after capture")
        mode_row(self.declaration, source=source_relative, source_bytes=original,
                 destination=destination, output_bytes=original)
        recipe_inputs = sorted([("kit/" + source_relative, original), *inputs])
        del self._origins[destination]
        self._captured_bytes -= len(original)
        try:
            self.record_recipe("traceability_tool_content", destination, recipe_inputs,
                               {"identity_basis": "exact_final_bytes"})
        except Exception:
            self._origins[destination] = origin
            self._captured_bytes += len(original)
            raise

    @classmethod
    def capture_file_inputs(cls, paths: list[Path], root: Path,
                            *, namespace: str) -> list[tuple[str, bytes]]:
        """Capture selected exact leaf bytes before a generator consumes them."""
        if len(paths) > MAX_INPUTS:
            raise SourceModeError("Generated recipe input count exceeds bound")
        remaining = MAX_TOTAL_INPUT_BYTES
        inputs = []
        for path in paths:
            try:
                relative = path.absolute().relative_to(root.absolute()).as_posix()
            except ValueError as exc:
                raise SourceModeError("Generated recipe input escapes its root") from exc
            data = cls._bounded_bytes(path, remaining=min(MAX_INPUT_BYTES, remaining))
            remaining -= len(data)
            inputs.append((f"{namespace}/{relative}", data))
        return sorted(inputs)

    def copy2(self, source: Path, destination: Path) -> Path:
        self.record(source, self._relative_output(destination))
        return Path(shutil.copy2(source, destination))

    def rename_prefix(self, source_root: str, destination_root: str) -> None:
        prefix = source_root + "/"
        if any(path.startswith(prefix) for path in self._recipes):
            raise SourceModeError("Recipe destination cannot move after registration")
        renamed = {
            (destination_root + "/" + path[len(prefix):] if path.startswith(prefix) else path): origin
            for path, origin in self._origins.items()
        }
        if len(renamed) != len(self._origins):
            raise SourceModeError("Renamed generator origins collide")
        self._origins = renamed

    def inventory(self, outputs: list[tuple[str, Path]]) -> GeneratedSourceInventory:
        if len(outputs) > MAX_ITEMS:
            raise SourceModeError("Selected generator inventory exceeds item bound")
        try:
            _unique_paths([destination for destination, _output in outputs])
        except PortableProvenanceError as exc:
            raise SourceModeError("Selected generator destinations collide or are unsafe") from exc
        rows: list[dict[str, object]] = []
        unresolved: list[str] = []
        artifacts: list[SourceOriginArtifact] = []
        remaining = MAX_INVENTORY_READ_BYTES
        for destination, output in sorted(outputs):
            origin = self._origins.get(destination)
            recipe = self._recipes.get(destination)
            if recipe is not None:
                final = self._bounded_bytes(output, remaining=remaining)
                remaining -= len(final)
                rows.append({"destination": destination,
                             "source_sha256": recipe.sha256,
                             "source_size_decimal": str(len(recipe.artifact_bytes)),
                             "output_sha256": hashlib.sha256(final).hexdigest(),
                             "output_size_decimal": str(len(final)),
                             "executable": recipe.executable})
                artifacts.append(SourceOriginArtifact(destination, "generated_recipe",
                                                      recipe.role, recipe.artifact_bytes))
                continue
            if origin is None:
                unresolved.append(destination)
                continue
            source_relative, original = origin
            current = self._bounded_bytes(self.kit_root / source_relative, remaining=remaining)
            remaining -= len(current)
            if (len(current) != len(original)
                    or hashlib.sha256(current).digest() != hashlib.sha256(original).digest()):
                raise SourceModeError(f"Generated source changed after capture: {source_relative}")
            final = self._bounded_bytes(output, remaining=remaining)
            remaining -= len(final)
            rows.append(mode_row(self.declaration, source=source_relative,
                                 source_bytes=original, destination=destination,
                                 output_bytes=final))
            artifacts.append(SourceOriginArtifact(destination, "reviewed_source",
                                                  source_relative, original))
        return GeneratedSourceInventory(tuple(rows), tuple(unresolved), tuple(artifacts))
