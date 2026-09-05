#!/usr/bin/env python3
"""
lint_mermaid_diagrams.py — Mermaid diagram linter (NAOS portable)

Lints fenced Mermaid diagrams in Markdown and standalone ``.mmd`` sources.

Rules enforced (configurable via .ai/rules/):
  - Disallow emojis and HTML line breaks inside ```mermaid fences.
    Standalone ``.mmd`` sources may use Mermaid's ``<br/>`` label breaks.
  - Disallow raw semicolons in sequence diagrams. Mermaid treats them as
    statement separators; use the documented ``#59;`` entity in prose.
  - Enforce direction + layout constraints from .ai/rules/naos-mermaid-governance.yaml
  - Enforce node/edge counts, label lengths, required annotations from
    .ai/rules/naos-mermaid-quality-gates.json
  - Require %% Implements and %% Theme comments (if requireTitleComment=true)
  - Require legend (if requireLegend=true)

All rule config files are OPTIONAL. When absent, the linter keeps its portable
defaults for emoji, fenced-Markdown HTML breaks, and basic size limits.
This is a source-hygiene linter, not a Mermaid grammar parser or renderer; a
passing result does not prove syntax validity or rendered fidelity.

USAGE:
    python scripts/validators/lint_mermaid_diagrams.py [<root_dir_or_file>]

EXIT CODES:
    0 — No violations
    1 — Violations found
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

EMOJI_PATTERN = re.compile(r"[\U0001F300-\U0001F6FF\U0001F900-\U0001FAFF]")
BR_PATTERN = re.compile(r"<br/?>", re.IGNORECASE)
MERMAID_ENTITY_CODE_PATTERN = re.compile(r"#[0-9]+;")
NODE_LABEL_PATTERN = re.compile(r"\[(.*?)\]|\"([^\"]+)\"")
NODE_PATTERN = re.compile(r"^[ \t]*[A-Za-z0-9_]+[ \t]*\[", re.MULTILINE)
EDGE_PATTERN = re.compile(r"-->")

GOVERNANCE_CFG = Path(".ai/rules/naos-mermaid-governance.yaml")
QUALITY_CFG = Path(".ai/rules/naos-mermaid-quality-gates.json")
EXCLUDED_DIRECTORY_NAMES = {
    ".git",
    ".mypy_cache",
    ".naos-g1-repository-intelligence",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "node_modules",
}


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:  # pragma: no cover
        raise SystemExit(f"Invalid governance config {path}: {exc}") from exc


GOV_CFG = _load_json(GOVERNANCE_CFG)
Q_CFG = _load_json(QUALITY_CFG)
ALLOWED_TYPES = set(Q_CFG.get("allowedDiagramTypes", []))
ALLOWED_DIRECTIONS = set(GOV_CFG.get("layout", {}).get("allowedDirections", []))
MAX_LABEL = int(Q_CFG.get("maxLabelLength", 80))
MAX_EDGE_LABEL = int(Q_CFG.get("maxEdgeLabelLength", MAX_LABEL))
MAX_NODES = int(Q_CFG.get("maxNodes", 999))
MAX_EDGES = int(Q_CFG.get("maxEdges", 999))
MAX_LINES = int(Q_CFG.get("maxDiagramLines", 999))
REQUIRE_TITLE = Q_CFG.get("requireTitleComment", False)
REQUIRE_LEGEND = Q_CFG.get("requireLegend", False)
DISALLOW_HTML = GOV_CFG.get("layout", {}).get("disallowHTML", True)
DISALLOW_EMOJI = GOV_CFG.get("layout", {}).get("disallowEmojis", True)


def extract_mermaid_blocks(text: str) -> list[tuple[int, int, str]]:
    blocks = []
    fence = "```mermaid"
    lines = text.splitlines()
    in_block = False
    start = 0
    buf: list[str] = []
    for i, line in enumerate(lines):
        if not in_block and line.strip().startswith(fence):
            in_block = True
            start = i
            buf = []
            continue
        if in_block:
            if line.strip() == "```":
                blocks.append((start, i, "\n".join(buf)))
                in_block = False
            else:
                buf.append(line)
    return blocks


def _blocks_for_path(path: Path, text: str) -> list[tuple[int, int, str]]:
    if path.suffix.lower() == ".mmd":
        return [(0, max(0, len(text.splitlines()) - 1), text)]
    return extract_mermaid_blocks(text)


def _candidate_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if root.suffix.lower() in {".md", ".mmd"} else []
    return sorted(
        path
        for suffix in ("*.md", "*.mmd")
        for path in root.rglob(suffix)
        if path.is_file()
        and not any(part in EXCLUDED_DIRECTORY_NAMES for part in path.parts)
    )


def lint_file(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    violations: list[str] = []
    for start, end, block in _blocks_for_path(path, text):
        block_lines = block.splitlines()
        header_lines = [ln.strip() for ln in block_lines if ln.strip().startswith("%%")]
        body_lines = [
            ln for ln in block_lines if not ln.strip().startswith("%%") and ln.strip()
        ]
        first_body = body_lines[0].strip() if body_lines else ""

        if DISALLOW_EMOJI:
            emojis = EMOJI_PATTERN.findall(block)
            if emojis:
                violations.append(
                    f"{path}: lines {start + 1}-{end + 1}: emoji characters: {''.join(sorted(set(emojis)))}"
                )
        if (
            DISALLOW_HTML
            and path.suffix.lower() != ".mmd"
            and BR_PATTERN.search(block)
        ):
            violations.append(
                f"{path}: lines {start + 1}-{end + 1}: <br/> HTML breaks found"
            )

        diagram_type = first_body.split()[0] if first_body else ""
        if ALLOWED_TYPES and diagram_type and diagram_type not in ALLOWED_TYPES:
            violations.append(
                f"{path}: lines {start + 1}-{end + 1}: diagram type '{diagram_type}' not in {sorted(ALLOWED_TYPES)}"
            )

        if diagram_type in {"flowchart", "graph"} and len(first_body.split()) >= 2:
            direction = first_body.split()[1]
            if ALLOWED_DIRECTIONS and direction not in ALLOWED_DIRECTIONS:
                violations.append(
                    f"{path}: line {start + 1}: direction '{direction}' must be one of {sorted(ALLOWED_DIRECTIONS)}"
                )

        if diagram_type == "sequenceDiagram":
            for offset, line in enumerate(block_lines):
                if not line.strip() or line.lstrip().startswith("%%"):
                    continue
                without_entity_codes = MERMAID_ENTITY_CODE_PATTERN.sub("", line)
                if ";" not in without_entity_codes:
                    continue
                line_number = (
                    offset + 1
                    if path.suffix.lower() == ".mmd"
                    else start + offset + 2
                )
                violations.append(
                    f"{path}: line {line_number}: raw semicolon in sequenceDiagram; "
                    "use #59; for prose punctuation"
                )

        if REQUIRE_TITLE and not any(
            ln.startswith("%% Implements") for ln in header_lines
        ):
            violations.append(
                f"{path}: lines {start + 1}-{end + 1}: missing '%% Implements' comment"
            )
        if REQUIRE_TITLE and not any("%% Theme" in ln for ln in header_lines):
            violations.append(
                f"{path}: lines {start + 1}-{end + 1}: missing '%% Theme' comment"
            )
        if REQUIRE_LEGEND and "Legend" not in block:
            violations.append(
                f"{path}: lines {start + 1}-{end + 1}: add a Legend note per governance rules"
            )

        node_count = len(NODE_PATTERN.findall(block))
        edge_count = len(EDGE_PATTERN.findall(block))
        if node_count > MAX_NODES:
            violations.append(
                f"{path}: lines {start + 1}-{end + 1}: {node_count} nodes (max {MAX_NODES})"
            )
        if edge_count > MAX_EDGES:
            violations.append(
                f"{path}: lines {start + 1}-{end + 1}: {edge_count} edges (max {MAX_EDGES})"
            )
        if len(block_lines) > MAX_LINES:
            violations.append(
                f"{path}: lines {start + 1}-{end + 1}: {len(block_lines)} lines (max {MAX_LINES})"
            )

        for match in NODE_LABEL_PATTERN.findall(block):
            label = next((g for g in match if g), "").strip()
            label_segments = (
                BR_PATTERN.split(label.strip('"'))
                if path.suffix.lower() == ".mmd"
                else [label]
            )
            longest_segment = max(
                (len(segment.strip()) for segment in label_segments), default=0
            )
            if longest_segment > MAX_LABEL:
                violations.append(
                    f"{path}: lines {start + 1}-{end + 1}: label segment "
                    f"'{label}' exceeds {MAX_LABEL} chars"
                )

    return violations


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(".")
    if not root.exists():
        print(f"Mermaid diagram lint input does not exist: {root}")
        return 1
    source_files = _candidate_files(root)
    all_violations: list[str] = []
    for source_file in source_files:
        all_violations.extend(lint_file(source_file))
    if all_violations:
        print("Mermaid diagram lint violations:")
        for v in all_violations:
            print(f"  - {v}")
        return 1
    print(f"Mermaid diagrams OK ({len(source_files)} files scanned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
