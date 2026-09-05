#!/usr/bin/env python3
"""Validate NAOS agent Markdown frontmatter."""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from frontmatter_utils import (  # type: ignore[import-not-found]
        ValidationResult,
        build_root_parser,
        candidate_files,
        collect_markdown_targets,
        is_non_empty_string,
        is_non_empty_string_list,
        parse_frontmatter,
        print_results,
    )
else:  # pragma: no cover - package import path
    from .frontmatter_utils import (
        ValidationResult,
        build_root_parser,
        candidate_files,
        collect_markdown_targets,
        is_non_empty_string,
        is_non_empty_string_list,
        parse_frontmatter,
        print_results,
    )


LEGACY_OR_UNDOCUMENTED_CORE_TOOLS = {
    "edit/rename",
    "execute/awaitTerminal",
    "execute/runTask",
    "execute/runTests",
    "read/getTaskOutput",
    "todo",
    "vscode/memory",
}

GOAL_BACKWARD_CONTRACT_START = "<!-- NAOS_GOAL_BACKWARD_CONTRACT:START -->"
GOAL_BACKWARD_CONTRACT_END = "<!-- NAOS_GOAL_BACKWARD_CONTRACT:END -->"
REVIEW_LENS_CONTRACT_START = "<!-- NAOS_REVIEW_LENS_CONTRACT:START -->"
REVIEW_LENS_CONTRACT_END = "<!-- NAOS_REVIEW_LENS_CONTRACT:END -->"
REVIEW_REPORT_CONTRACT_START = "<!-- NAOS_REVIEW_REPORT_CONTRACT:START -->"
REVIEW_REPORT_CONTRACT_END = "<!-- NAOS_REVIEW_REPORT_CONTRACT:END -->"
EXACT_REVIEW_LENS_CONTRACT = """\
Structural review guidance only; deterministic checks and executed evidence outrank model judgement.
1. `R1_GOAL_DIFF`: Use the supplied goal, AC, constraints, and exact changed paths; inspect independently of the implementer's conclusion, trace every change to the goal, and flag unscoped work.
UI boundary: for changed UI with enabled evidence declarations, run or review `naos design-traceability` and/or `naos ui-experience-quality`; do not treat either as design approval, UI quality proof, accessibility certification, brand approval, or compliance proof.
2. `R2_EDGE_COVERAGE`: Trace actual consuming paths, boundaries, negative and edge cases, propagation, and tests; preserve uncertainty, counterarguments, and falsifiers.
3. `R3_AC_SPEC`: Map every explicit AC or spec to resulting state, deliverables, tests, and evidence; bookkeeping links or passing commands alone are not proof.
4. `R4_SYNTHESIZE`: Report each lens separately, deduplicate, rank blockers first, and make an advisory recommendation only; a named human retains merge authority.
Fallback: without a task card or explicit AC/spec, mark the mapping `UNAVAILABLE`, invent nothing, continue bounded goal/diff and edge/coverage review, and assert no task/AC completion."""
EXACT_REVIEW_REPORT_CONTRACT = """\
## Report Format

```
## Review Summary
**Status**: READY_FOR_ATTRIBUTABLE_HUMAN_MERGE_DECISION / NEEDS_CHANGES / BLOCKED

## Lens 1 — Goal/Diff And Scope
[goal-to-path mapping, scope drift, authority issues]

## Lens 2 — Edge/Coverage And Propagation
[consumers, boundaries, edge cases, dependent surfaces, residual risks]

## Lens 3 — AC/Spec Evidence
[AC/spec → resulting state → test/evidence mapping and gaps]

## Synthesis
[deduplicated blocking findings first, uncertainty, falsifiers, residual risk]

## Approved Changes
[brief description of what was correctly implemented]
```"""
EXACT_GOAL_BACKWARD_CONTRACTS = {
    "naos-conformance.agent.md": """\
Structural conformance only; no live behavior/effectiveness proof.
1. `C1_INPUT`: use supplied goal/AC/constraints or named audit scope; invent nothing.
2. `C2_MAP`: Map each explicit AC to deliverables/tests/evidence.
3. `C3_TRACE`: Trace each finding, change, or pass claim backward to that map.
4. `C4_MISMATCH`: Record missing evidence, mismatch, or deferral, with reason and affected claim.
5. `C5_DENY`: absent/unresolved map denies task/AC completion, merge readiness, or complete conformance.
Fallback: without card/explicit AC, continue scoped audit; mark map `UNAVAILABLE`, invent no requirement/completion, and report findings.""",
    "naos-debug.agent.md": """\
Structural conformance only; no live behavior/effectiveness proof.
1. `D1_INPUT`: before handoff/claim, use exact failure/reproducer and supplied goal/AC/expected behavior.
2. `D2_MAP`: Map explicit expected behavior to failure/deliverable/regression evidence; invent nothing.
3. `D3_TRACE`: Trace all affected files and the full failing code to candidate cause/minimal recommendation.
4. `D4_MISMATCH`: Preserve failed hypotheses, negative/missing evidence, mismatch, and deferral.
5. `D5_DENY`: deny fix/task/merge/delegation completion until writer changes and validation pass.
Fallback: without card/AC, diagnose from symptom/reproducer; use supplied expected behavior, otherwise mark it `UNAVAILABLE`; invent nothing; without it assert no mismatch/completion.
Evidence: exact error/stack/conditions; logs/metrics/tests; 2-3 HIGH/MEDIUM/LOW causes with support/falsifiers, highest first; reproducer/diagnostics, writer commands, affected files, regression test.
Limits: no edits, agent calls, unrelated cleanup, or repeated failing command.""",
}


def validate_review_lens_contract(
    path: Path, body: str
) -> ValidationResult | None:
    if path.name != "naos-review.agent.md":
        return None

    start_count = body.count(REVIEW_LENS_CONTRACT_START)
    end_count = body.count(REVIEW_LENS_CONTRACT_END)
    passed = False
    if start_count == 1 and end_count == 1:
        before_end, _, _ = body.partition(REVIEW_LENS_CONTRACT_END)
        _, start_found, actual = before_end.partition(REVIEW_LENS_CONTRACT_START)
        passed = bool(start_found) and actual.strip() == EXACT_REVIEW_LENS_CONTRACT

    return ValidationResult(
        path,
        "review-lens-contract",
        passed,
        "required exact ordered Review lens contract or preserved UI evidence "
        "boundary is missing or changed; "
        "this proves structural conformance only, not live review behavior or "
        "operating effectiveness",
    )


def validate_review_report_contract(
    path: Path, body: str
) -> ValidationResult | None:
    if path.name != "naos-review.agent.md":
        return None

    start_count = body.count(REVIEW_REPORT_CONTRACT_START)
    end_count = body.count(REVIEW_REPORT_CONTRACT_END)
    passed = False
    if start_count == 1 and end_count == 1:
        before_end, _, _ = body.partition(REVIEW_REPORT_CONTRACT_END)
        _, start_found, actual = before_end.partition(REVIEW_REPORT_CONTRACT_START)
        passed = bool(start_found) and actual.strip() == EXACT_REVIEW_REPORT_CONTRACT

    return ValidationResult(
        path,
        "review-report-contract",
        passed,
        "required separate Review lens and synthesis report sections are missing "
        "or changed; this proves structural conformance only, not report quality",
    )


def default_agent_files(root: Path) -> list[Path]:
    files = candidate_files(
        root, "templates/agents/*.agent.md", ".github/agents/*.agent.md"
    )
    optional_dir = root / "templates" / "agents" / "optional"
    if optional_dir.is_dir():
        files.extend(sorted(optional_dir.glob("*.agent.md")))
    return files


def validate_goal_backward_contract(
    path: Path, body: str
) -> ValidationResult | None:
    expected = EXACT_GOAL_BACKWARD_CONTRACTS.get(path.name)
    if expected is None:
        return None

    start_count = body.count(GOAL_BACKWARD_CONTRACT_START)
    end_count = body.count(GOAL_BACKWARD_CONTRACT_END)
    passed = False
    if start_count == 1 and end_count == 1:
        before_end, _, _ = body.partition(GOAL_BACKWARD_CONTRACT_END)
        _, start_found, actual = before_end.partition(GOAL_BACKWARD_CONTRACT_START)
        passed = bool(start_found) and actual.strip() == expected

    return ValidationResult(
        path,
        "goal-backward-contract",
        passed,
        "required exact ordered role contract is missing or changed; this is "
        "deterministic structural conformance only, not evidence of live behavior "
        "or operating effectiveness",
    )


def validate_agent_file(path: Path) -> list[ValidationResult]:
    document = parse_frontmatter(path)
    if document.error:
        return [ValidationResult(path, "frontmatter", False, document.error)]

    tools = document.data.get("tools")
    tool_names = {str(tool) for tool in tools} if isinstance(tools, list) else set()
    stale_tools = sorted(tool_names & LEGACY_OR_UNDOCUMENTED_CORE_TOOLS)
    results = [
        ValidationResult(
            path,
            "model",
            is_non_empty_string(document.data.get("model")),
            "required non-empty string field 'model' is missing or malformed",
        ),
        ValidationResult(
            path,
            "tools",
            is_non_empty_string_list(tools),
            "required field 'tools' must be a non-empty list of strings",
        ),
        ValidationResult(
            path,
            "current-core-tools",
            not stale_tools,
            "legacy or undocumented VS Code core tool names: " + ", ".join(stale_tools),
        ),
    ]
    contract_result = validate_goal_backward_contract(path, document.body)
    if contract_result is not None:
        results.append(contract_result)
    review_result = validate_review_lens_contract(path, document.body)
    if review_result is not None:
        results.append(review_result)
    report_result = validate_review_report_contract(path, document.body)
    if report_result is not None:
        results.append(report_result)
    return results


def validate_agent_files(paths: list[Path]) -> list[ValidationResult]:
    agent_files = [path for path in paths if path.name.endswith(".agent.md")]
    results: list[ValidationResult] = []
    for path in agent_files:
        results.extend(validate_agent_file(path))
    return results


def main() -> int:
    parser = build_root_parser("Validate NAOS .agent.md frontmatter")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    targets = collect_markdown_targets(args.paths, default_agent_files(root))
    results = validate_agent_files(targets)
    return print_results("Agent Frontmatter", root, results)


if __name__ == "__main__":
    sys.exit(main())
