#!/usr/bin/env python3
"""Optional dry-run mapper from Spec-Kit-style specs to NAOS review concepts."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

SCHEMA = "naos.spec_kit_mapping.v1"
NOT_CLAIMED = [
    "official Spec-Kit support",
    "official Microsoft support",
    "regulatory mapping completeness",
    "proof of compliance",
    "approval",
    "certification",
    "source of truth",
    "automatic context injection",
    "memory write-back",
    "provider/model/API call",
]


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def spec_summary(path: Path, root: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8", errors="replace")
    title = next((line.lstrip("# ").strip() for line in text.splitlines() if line.strip().startswith("#")), path.stem)
    return {
        "path": str(path.relative_to(root)),
        "title": title,
        "sha256": digest(path),
        "line_count": len(text.splitlines()),
        "suggested_naos_surfaces": [
            "task_context",
            "evidence_pack",
            "gate_status",
            "gate_evaluation",
            "control_plane_review",
        ],
        "human_review_required": True,
    }


def build_report(root: Path) -> dict[str, object]:
    specs_root = root / ".specify" / "specs"
    specs = sorted(specs_root.glob("*.md")) if specs_root.is_dir() else []
    findings = []
    if not specs:
        findings.append(
            {
                "id": "spec_kit.no_specs_found",
                "severity": "advisory",
                "message": "No .specify/specs/*.md files were found.",
            }
        )
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "project_root": str(root),
        "spec_root": str(specs_root),
        "spec_count": len(specs),
        "specs": [spec_summary(path, root) for path in specs],
        "default_write_behavior": "dry_run_no_writes",
        "recommended_naos_reports": [
            "naos/reports/task_context_pack.json",
            "naos/evidence/evidence_pack.json",
            "naos/reports/gate_status.json",
            "naos/reports/gate_evaluation.json",
            "naos/reports/control_plane_review.json",
        ],
        "findings": findings,
        "limitations": [
            "This adapter reads local Spec-Kit-style markdown files and maps them to NAOS review concepts.",
            "It does not mutate .specify/ by default.",
            "It does not install Spec-Kit or make Spec-Kit a NAOS core dependency.",
        ],
        "not_claimed": NOT_CLAIMED,
        "human_review_required": True,
        "summary": {
            "spec_count": len(specs),
            "status": "ready" if specs else "advisory",
            "human_review_required": True,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Optional dry-run Spec-Kit to NAOS mapper.")
    parser.add_argument("--project-root", default=".", help="Project root to inspect.")
    parser.add_argument("--output", help="Optional JSON report path. Omit for no file writes.")
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout.")
    parser.add_argument("--dry-run", action="store_true", help="Accepted for clarity; no writes occur unless --output is set.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.project_root).resolve()
    report = build_report(root)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json or not args.output:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
