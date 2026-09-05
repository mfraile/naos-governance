"""Base grader protocol for deterministic NAOS grading foundations."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class BaseGrader(Protocol):
    """Small contract shared by deterministic and future advisory graders."""

    name: str
    version: str
    supported_dimensions: list[str]
    deterministic: bool
    advisory: bool
    required_inputs: list[str]
    forbidden_inputs: list[str]
    cost_policy: dict[str, Any]

    def grade(
        self,
        *,
        root: Path,
        profile: str,
        naos_root: str,
        policy: dict[str, Any],
        trace_report: dict[str, Any] | None,
        trace_events: list[dict[str, Any]],
        input_reports: list[dict[str, Any]],
        trace_report_path: Path | None,
        trace_file_path: Path | None,
    ) -> dict[str, Any]:
        """Return a deterministic grading report."""
