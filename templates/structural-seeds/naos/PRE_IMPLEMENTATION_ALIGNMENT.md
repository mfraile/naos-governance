---
schema: naos.pre_implementation_alignment.v1
mode: greenfield
task_id: null
feature_name: null
status: draft
parallel_lane_opportunity: not_applicable
parallel_lane_decision: deferred
parallel_lane_reasons: []
parallel_lane_candidate_lanes: []
questions:
  intended_user: null
  problem_statement: null
  first_vertical_slice: null
  input_output_contract: null
  edge_cases: []
  failure_modes: []
  security_privacy_assumptions: []
  existing_interfaces_touched: []
  backward_compatibility_constraints: []
  architecture_assumptions: []
  known_fragile_modules_or_risk_areas: []
  test_strategy: []
  evidence_required: []
  explicit_out_of_scope: []
  planned_change_paths: []
  out_of_scope_paths: []
  human_review_boundary: null
not_claimed:
  - requirements completeness proof
  - design approval
  - implementation approval
  - compliance proof
  - human review replacement
  - automatic lane declaration
  - handoff requirement without declared lanes
human_review_required: true
---

# Pre-Implementation Alignment

Use this file before greenfield setup, brownfield onboarding, or non-trivial
feature work. Keep the YAML frontmatter structured so
`naos-pre-implementation-alignment-review` can review it deterministically.

## Greenfield Mode

Greenfield alignment should define the intended user, problem statement, first
vertical slice, architecture assumptions, initial test/evidence strategy, and
explicit out-of-scope items before implementation begins.

## Brownfield Mode

Brownfield alignment should identify existing interfaces touched, migration or
backward-compatibility constraints, regression test strategy, known fragile
modules or risk areas, and what must not be broken.

## Feature Mode

Feature alignment should identify the task or feature, input/output contract,
first vertical slice, edge cases, failure modes, test strategy, evidence
required, explicit out-of-scope items, and human review boundary.

## Optional Path Declarations

Use `planned_change_paths` for files or directories expected to change in this
slice, and `out_of_scope_paths` for files or directories that should not change.
`naos plan-coherence --diff-base <ref>` can compare Git changed files to these
declarations as advisory implementation-scope evidence only.

## Parallel Lane Opportunity

Use `parallel_lane_opportunity` to record an advisory posture:
`not_applicable`, `sequential_recommended`, `parallel_possible`, or
`parallel_recommended`.

Use `parallel_lane_decision` to record the human/project decision:
`sequential`, `declared`, or `deferred`.

Suggested lanes are not active by themselves. Handoff evidence is required only
after `parallel_lane_decision: declared` or another reviewed project policy
explicitly declares lanes. Solo developers may use lanes as logical checkpoints
inside one checkout; worktrees are optional physical isolation, not governance
authority.

## Non-Claims

This artifact is review input. It is not requirements completeness proof, design
approval, implementation approval, compliance proof, or a replacement for human
review. It does not silently declare lanes, dispatch agents, create branches or
worktrees, approve work, merge, release, or prove compliance.
