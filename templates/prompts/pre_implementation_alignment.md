# Pre-Implementation Alignment Prompt

Use this prompt before non-trivial implementation, greenfield setup, or
brownfield onboarding. The goal is to produce or update
`naos/PRE_IMPLEMENTATION_ALIGNMENT.md` for human review.

## Instructions

1. Inspect repository files first when the answer can be found locally.
2. Ask one question at a time when information is missing or ambiguous.
3. Provide a recommended answer when the repository evidence supports one.
4. Challenge vague language and ask for concrete acceptance evidence.
5. Identify the first vertical slice before broader implementation.
6. Identify input/output contracts, edge cases, and failure modes.
7. Identify security and privacy assumptions.
8. Identify test strategy and evidence required.
9. Identify explicit out-of-scope items.
10. When implementation scope is predictable, identify optional
    `planned_change_paths` and `out_of_scope_paths` for advisory
    plan-coherence diff review.
11. Identify advisory `parallel_lane_opportunity` posture using the controlled values:
    `not_applicable`, `sequential_recommended`, `parallel_possible`, or
    `parallel_recommended`.
12. Record the human/project `parallel_lane_decision` as `sequential`, `declared`, or
    `deferred`; do not declare lanes silently.
13. Record the human review boundary.
14. Lite+: discovery/draft may change. Before implementation, require live
    `naos plan-coherence` readiness bound to 03 (Lite; never synthesize 04) or
    03+04 (Standard/Assured), task plan/alignment, current evidence, and owner
    decision. Structural changes supersede the baseline; default vertical;
    foundations name a consuming slice/result. Readiness is not authority.

## Boundaries

- Do not implement until the alignment artifact is ready for review.
- Do not claim the artifact approves design or implementation.
- Do not claim requirements completeness.
- Do not claim compliance proof.
- Do not silently inject context into any tool.
- Do not write memory.
- Do not call model/provider APIs beyond the active assistant session.
- Suggested lanes do not activate handoff; do not treat `parallel_possible` or
  `parallel_recommended` as active lanes.
- Do not create branches, worktrees, task claims, handoff requirements, or
  agent dispatch from an advisory lane suggestion.

## Output

Update or propose updates to the structured YAML frontmatter in
`naos/PRE_IMPLEMENTATION_ALIGNMENT.md`, then summarize unresolved questions and
the recommended first vertical slice. If path declarations were added, state
that `naos plan-coherence --diff-base <ref>` can compare changed files to those
declarations as review evidence only, not plan approval or semantic drift proof.
If `parallel_lane_opportunity` or `parallel_lane_decision` fields were added,
state that they are advisory planning evidence only and that handoff applies only
when lanes are explicitly declared.
