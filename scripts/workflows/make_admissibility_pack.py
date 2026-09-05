#!/usr/bin/env python3
"""Create a dated NAOS admissibility evidence pack."""

from __future__ import annotations

import argparse
import re
import sys
from datetime import date
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

REQUIRED_ARTEFACTS = (
    "{root}/DASHBOARD.md",
    "{root}/TRACEABILITY_MATRIX.md",
    "docs/COMPLIANCE_MAPPING.md",
    "docs/OSFI_E23_MAPPING.md",
    "docs/DORA_MAPPING.md",
    "docs/ADMISSIBILITY.md",
)

OPTIONAL_CONFORMANCE = "{root}/reports/conformance_latest.json"
MISSING_CONFORMANCE_NOTE = "{root}/reports/README-MISSING-CONFORMANCE.txt"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bundle NAOS governance evidence into a dated admissibility zip."
    )
    parser.add_argument(
        "--root",
        default="naos",
        help="NAOS evidence directory containing DASHBOARD.md and TRACEABILITY_MATRIX.md.",
    )
    parser.add_argument(
        "--date",
        default=date.today().isoformat(),
        help="Pack date in YYYY-MM-DD format. Defaults to today.",
    )
    parser.add_argument(
        "--output",
        help="Optional output zip path. Defaults to <root>/admissibility-YYYY-MM-DD.zip.",
    )
    return parser.parse_args()


def _resolve(pattern: str, root: Path) -> Path:
    return Path(pattern.format(root=root.as_posix()))


def _missing_required(root: Path) -> list[Path]:
    return [path for path in (_resolve(item, root) for item in REQUIRED_ARTEFACTS) if not path.is_file()]


def _archive_name(path: Path, root: Path) -> str:
    if path.is_absolute():
        try:
            return (Path(root.name) / path.relative_to(root)).as_posix()
        except ValueError:
            return path.name
    return path.as_posix()


def _missing_conformance_text(root: Path) -> str:
    return (
        "The optional NAOS static conformance report was not present when this "
        "admissibility pack was created.\n\n"
        f"Expected path: {_resolve(OPTIONAL_CONFORMANCE, root).as_posix()}\n\n"
        "To include it, run the project's conformance check before rebuilding "
        "the pack, for example:\n\n"
        "  make -f Makefile.naos naos-conformance\n"
        "  make -f Makefile.naos admissibility-pack\n\n"
        "If the project does not use the NAOS conformance runner, attach the "
        "project's equivalent static validation evidence separately.\n"
    )


def build_pack(root: Path, pack_date: str, output: Path | None = None) -> Path:
    if not DATE_RE.match(pack_date):
        raise ValueError("--date must use YYYY-MM-DD format")

    missing = _missing_required(root)
    if missing:
        missing_list = "\n".join(f"  - {path.as_posix()}" for path in missing)
        raise FileNotFoundError(
            "Missing required admissibility artefacts. Run `make -f Makefile.naos gov-refresh` "
            "and confirm the public evidence docs are present, then retry.\n"
            f"{missing_list}"
        )

    root.mkdir(parents=True, exist_ok=True)
    output_path = output or root / f"admissibility-{pack_date}.zip"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    conformance_path = _resolve(OPTIONAL_CONFORMANCE, root)

    with ZipFile(output_path, "w", compression=ZIP_DEFLATED) as archive:
        for item in REQUIRED_ARTEFACTS:
            path = _resolve(item, root)
            archive.write(path, _archive_name(path, root))

        if conformance_path.is_file():
            archive.write(conformance_path, _archive_name(conformance_path, root))
        else:
            archive.writestr(
                _archive_name(_resolve(MISSING_CONFORMANCE_NOTE, root), root),
                _missing_conformance_text(root),
            )

        corrupt = archive.testzip()
        if corrupt:
            raise RuntimeError(f"Zip integrity check failed at {corrupt}")

    return output_path


def main() -> int:
    args = _parse_args()
    root = Path(args.root)
    output = Path(args.output) if args.output else None

    try:
        pack = build_pack(root=root, pack_date=args.date, output=output)
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        print(f"admissibility-pack: ERROR: {error}", file=sys.stderr)
        return 1

    conformance_path = _resolve(OPTIONAL_CONFORMANCE, root)
    if not conformance_path.is_file():
        print(
            "admissibility-pack: WARNING: conformance report missing; "
            f"added {_resolve(MISSING_CONFORMANCE_NOTE, root).as_posix()} to the pack.",
            file=sys.stderr,
        )

    print(f"admissibility-pack: wrote {pack.as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())