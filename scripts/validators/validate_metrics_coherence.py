#!/usr/bin/env python3
"""
validate_metrics_coherence.py — Metrics coherence validator (NAOS portable)

Ensures metrics in DASHBOARD.md and PROJECT_STATUS.md match the authoritative
source: specs/03-requirements.md (FR/NFR status lines).

USAGE:
    python kit/scripts/validators/validate_metrics_coherence.py [--verbose]

ENV VARS:
    NAOS_ROOT   — path to naos/ directory  (default: naos)
    SPECS_ROOT  — path to specs/ directory (default: specs)

EXIT CODES:
    0 — All metrics coherent
    1 — Metrics mismatch detected
    2 — Authoritative source not found

[ADAPT] section: adjust file paths or add extra files in the `main()` loop.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

try:
    from validator_context import is_kit_repository, print_kit_skip
except ModuleNotFoundError:
    def is_kit_repository() -> bool:
        return False

    def print_kit_skip(validator_name: str, reason: str) -> None:
        print(f"{validator_name}: SKIP")
        print(f"  - kit repo context: {reason}")

# ── Path configuration ────────────────────────────────────────────────────────
# [ADAPT] Override via env vars for non-standard project layouts
NAOS_ROOT = Path(os.getenv("NAOS_ROOT", "naos"))
SPECS_ROOT = Path(os.getenv("SPECS_ROOT", "specs"))

SPECS_PATH = SPECS_ROOT / "03-requirements.md"
DASHBOARD_PATH = NAOS_ROOT / "DASHBOARD.md"


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


@dataclass
class RequirementStats:
    complete: List[str]
    in_progress: List[str]
    planned: List[str]
    doc_only: List[str]

    @property
    def total(self) -> int:
        return len(self.complete) + len(self.in_progress) + len(self.planned)

    @property
    def completion_rate(self) -> float:
        return len(self.complete) / self.total * 100 if self.total else 0.0


@dataclass
class AuthoritativeMetrics:
    fr: RequirementStats
    nfr: RequirementStats
    source_file: str

    @property
    def total_complete(self) -> int:
        return len(self.fr.complete) + len(self.nfr.complete)

    @property
    def total_requirements(self) -> int:
        return self.fr.total + self.nfr.total

    @property
    def overall_rate(self) -> float:
        if self.total_requirements == 0:
            return 0.0
        return self.total_complete / self.total_requirements * 100


# ── Parsers ───────────────────────────────────────────────────────────────────


def parse_authoritative_source(
    specs_path: Path, verbose: bool = False
) -> AuthoritativeMetrics:
    """Parse specs/03-requirements.md as the SINGLE SOURCE OF TRUTH."""
    if not specs_path.exists():
        raise FileNotFoundError(f"Authoritative source not found: {specs_path}")

    content = specs_path.read_text(encoding="utf-8")
    fr_stats = RequirementStats([], [], [], [])
    nfr_stats = RequirementStats([], [], [], [])

    current_req: Optional[str] = None
    current_type: Optional[str] = None

    for line in content.split("\n"):
        fr_match = re.match(r"^## (FR-[A-Z0-9-]+):", line)
        nfr_match = re.match(r"^## (NFR-\d+):", line)

        if fr_match:
            current_req, current_type = fr_match.group(1), "FR"
        elif nfr_match:
            current_req, current_type = nfr_match.group(1), "NFR"
        elif current_req and "**Status**:" in line:
            status = line.split("**Status**:")[1].strip()

            if current_type == "FR":
                if "COMPLETE" in status.upper() or "Implemented" in status:
                    fr_stats.complete.append(current_req)
                elif "In Progress" in status:
                    fr_stats.in_progress.append(current_req)
                elif "Documentation Only" in status:
                    fr_stats.doc_only.append(current_req)
                else:
                    fr_stats.planned.append(current_req)
            elif current_type == "NFR":
                if any(
                    k in status
                    for k in ("Verified", "Implemented", "COMPLETE", "Complete")
                ):
                    nfr_stats.complete.append(current_req)
                elif "In Progress" in status:
                    nfr_stats.in_progress.append(current_req)
                else:
                    nfr_stats.planned.append(current_req)

            if verbose:
                print(f"  {current_req}: {status[:60]}")
            current_req = current_type = None

    return AuthoritativeMetrics(fr_stats, nfr_stats, str(specs_path))


def _extract_sync_block(content: str, block_name: str) -> str:
    pattern = rf"<!-- BEGIN {re.escape(block_name)} -->(.*?)<!-- END {re.escape(block_name)} -->"
    m = re.search(pattern, content, re.DOTALL)
    return m.group(1) if m else ""


def extract_metrics_from_file(file_path: Path) -> Dict[str, object]:
    """Extract numeric metrics patterns from a markdown governance file."""
    if not file_path.exists():
        return {}

    full_content = file_path.read_text(encoding="utf-8")
    sync_block = _extract_sync_block(full_content, "SYNC_METRICS_SUMMARY")
    content = sync_block if sync_block else full_content

    metrics: Dict[str, object] = {}

    # Overall totals — Format A: "38/46 requirements (82.6%)"
    m = re.search(
        r"(\d+)/(\d+)\s*requirements?\s*\(?([\d.]+)%?\)?", content, re.IGNORECASE
    )
    if m:
        metrics["total_complete"] = int(m.group(1))
        metrics["total_requirements"] = int(m.group(2))
        metrics["overall_rate"] = float(m.group(3))

    # Format B (SYNC block table): "| **All** | 44 | 41 | … | 93.2% |"
    if "total_complete" not in metrics:
        m = re.search(
            r"\*\*All\*\*\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|.*?([\d.]+)%", content
        )
        if m:
            metrics["total_requirements"] = int(m.group(1))
            metrics["total_complete"] = int(m.group(2))
            metrics["overall_rate"] = float(m.group(3))

    # FR — Format A
    m = re.search(r"Functional.*?(\d+)/(\d+)", content)
    if m:
        metrics["fr_complete"] = int(m.group(1))
        metrics["fr_total"] = int(m.group(2))
    if "fr_complete" not in metrics:
        m = re.search(r"\*\*FR\*\*\s*\|\s*(\d+)\s*\|\s*(\d+)", content)
        if m:
            metrics["fr_total"] = int(m.group(1))
            metrics["fr_complete"] = int(m.group(2))

    # NFR — Format A
    m = re.search(r"Non-Functional.*?(\d+)/(\d+)", content)
    if m:
        metrics["nfr_complete"] = int(m.group(1))
        metrics["nfr_total"] = int(m.group(2))
    if "nfr_complete" not in metrics:
        m = re.search(r"\*\*NFR\*\*\s*\|\s*(\d+)\s*\|\s*(\d+)", content)
        if m:
            metrics["nfr_total"] = int(m.group(1))
            metrics["nfr_complete"] = int(m.group(2))

    return metrics


def compare_metrics(auth: AuthoritativeMetrics, file_path: Path) -> List[str]:
    discrepancies: List[str] = []
    file_metrics = extract_metrics_from_file(file_path)

    if not file_metrics:
        if auth.total_requirements == 0:
            return []
        return [f"Could not extract metrics from {file_path}"]

    if (
        "total_complete" in file_metrics
        and file_metrics["total_complete"] != auth.total_complete
    ):
        discrepancies.append(
            f"Total complete: file shows {file_metrics['total_complete']}, authoritative is {auth.total_complete}"
        )
    if (
        "total_requirements" in file_metrics
        and file_metrics["total_requirements"] != auth.total_requirements
    ):
        discrepancies.append(
            f"Total requirements: file={file_metrics['total_requirements']}, authoritative={auth.total_requirements}"
        )
    if "fr_complete" in file_metrics and file_metrics["fr_complete"] != len(
        auth.fr.complete
    ):
        discrepancies.append(
            f"FR complete: file={file_metrics['fr_complete']}, authoritative={len(auth.fr.complete)}"
        )
    if "nfr_complete" in file_metrics and file_metrics["nfr_complete"] != len(
        auth.nfr.complete
    ):
        discrepancies.append(
            f"NFR complete: file={file_metrics['nfr_complete']}, authoritative={len(auth.nfr.complete)}"
        )
    return discrepancies


def print_authoritative_summary(auth: AuthoritativeMetrics) -> None:
    print(f"\n{Colors.CYAN}{'=' * 60}{Colors.END}")
    print(f"{Colors.BOLD}AUTHORITATIVE SOURCE: {auth.source_file}{Colors.END}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.END}")
    print(f"\n{Colors.BOLD}Functional Requirements (FR):{Colors.END}")
    print(f"  ✅ Complete : {len(auth.fr.complete)}")
    print(f"  🔄 In Progress: {len(auth.fr.in_progress)}")
    print(f"  📋 Planned  : {len(auth.fr.planned)}")
    print(
        f"  {Colors.BOLD}Total: {len(auth.fr.complete)}/{auth.fr.total} ({auth.fr.completion_rate:.1f}%){Colors.END}"
    )
    print(f"\n{Colors.BOLD}Non-Functional Requirements (NFR):{Colors.END}")
    print(f"  ✅ Verified : {len(auth.nfr.complete)}")
    print(f"  🔄 In Progress: {len(auth.nfr.in_progress)}")
    print(f"  📋 Planned  : {len(auth.nfr.planned)}")
    print(
        f"  {Colors.BOLD}Total: {len(auth.nfr.complete)}/{auth.nfr.total} ({auth.nfr.completion_rate:.1f}%){Colors.END}"
    )
    print(f"\n{Colors.CYAN}{'=' * 60}{Colors.END}")
    print(
        f"{Colors.BOLD}OVERALL: {auth.total_complete}/{auth.total_requirements} ({auth.overall_rate:.1f}%){Colors.END}"
    )
    print(f"{Colors.CYAN}{'=' * 60}{Colors.END}")


# ── main ──────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate metrics coherence")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if is_kit_repository():
        print_kit_skip(
            "Metrics Coherence",
            "requires adopter specs/03-requirements.md and generated dashboard metrics",
        )
        return 0

    print(f"{Colors.BOLD}Validating Metrics Coherence …{Colors.END}")

    try:
        auth = parse_authoritative_source(SPECS_PATH, args.verbose)
    except FileNotFoundError as e:
        print(f"{Colors.RED}ERROR: {e}{Colors.END}")
        return 2

    if args.verbose:
        print_authoritative_summary(auth)

    # [ADAPT] Add / remove files to validate here
    all_discrepancies: List[tuple] = []
    for file_path in [DASHBOARD_PATH]:
        if not file_path.exists():
            print(f"{Colors.YELLOW}WARNING: {file_path} not found{Colors.END}")
            continue
        discrepancies = compare_metrics(auth, file_path)
        if discrepancies:
            all_discrepancies.append((file_path, discrepancies))

    if all_discrepancies:
        print(f"\n{Colors.RED}{'=' * 60}{Colors.END}")
        print(f"{Colors.RED}{Colors.BOLD}METRICS COHERENCE FAILED{Colors.END}")
        print(f"{Colors.RED}{'=' * 60}{Colors.END}")
        for file_path, discrepancies in all_discrepancies:
            print(f"\n{Colors.YELLOW}{file_path}:{Colors.END}")
            for d in discrepancies:
                print(f"  ❌ {d}")
        return 1

    print(
        f"\n{Colors.GREEN}✅ All metrics are coherent with authoritative source{Colors.END}"
    )

    print(f"\n{Colors.BOLD}Authoritative values ({SPECS_PATH}):{Colors.END}")
    print(
        f"  FR   : {len(auth.fr.complete)}/{auth.fr.total} ({auth.fr.completion_rate:.1f}%)"
    )
    print(
        f"  NFR  : {len(auth.nfr.complete)}/{auth.nfr.total} ({auth.nfr.completion_rate:.1f}%)"
    )
    print(
        f"  Total: {auth.total_complete}/{auth.total_requirements} ({auth.overall_rate:.1f}%)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
