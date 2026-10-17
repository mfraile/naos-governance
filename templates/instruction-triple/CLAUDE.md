# Claude project instructions

@AGENTS.md

Use the imported selected-profile router. Markdown links below do not automatically
import their targets. `.github` agents are manual role guidance outside a qualified
host; Claude manual commands use the installed `.claude/commands/` route.

Repository evidence supports human review; it does not prove correctness.
Reports are not approval and not certification; unexecuted outcomes are not claimed.
Source artifacts remain authoritative. Human reviewers provide the human approval
required by the selected profile. NAOS is tool-neutral, deterministic and file-first;
no LLM or no model execution is implied by a report or a Markdown route.

## Before work

Read root `AGENTS.md`, `.ai/RULES.md` and `.github/project-context.md`.
Check installed availability before using an agent, prompt, skill, script or Make
target. Quickstart is research guidance; Lite has its bounded task lifecycle;
Standard and Assured provide the fuller workflow. A task recommendation cannot
activate a stronger profile or waive the current profile's gate/evidence duties.
Missing required tooling means manual source/test review or stopping the dependent
work until required evidence is available; do not claim an unavailable check ran.

Read the active task card in `naos/active/*.md` when present. Before coding, search
existing implementations, `naos/inventory/FUNCTION_INDEX.yaml`, related tests,
source-to-test mapping, schemas, capability contracts and spec/architecture context.
Prefer reuse or a targeted refactor; justify new functions and record affected files,
dependencies, risks and evidence. Present the plan and obtain required human approval.
Record `parallel_lane_opportunity` and `parallel_lane_decision`; these are advisory
and never authorize agent dispatch, branches, worktrees, implementation or merge.

## Core duties

- Keep scope bounded. Verify claims at source; distinguish inspected, executed,
  observed and inferred behavior. Do not invent evidence, APIs, citations or results.
- Protect secrets, restricted/customer data and project privacy boundaries. Preserve
  existing security, encryption, authentication, authorization, databases, public APIs
  and regulatory controls; changes require explicit authorization and review.
- Do not silently adopt, install, activate hooks/integrations, execute providers,
  enable memory/MCP access, change model/tool permissions, delegate, merge or release.
- Human approval, profile gates and no-direct-edit diagnostic role boundaries remain
  binding. Reports, indexes, traces, coordination claims and memory are review aids,
  not source authority, permission, compliance proof or automatic completion.
- Before using memory, review readiness/access and memory-use policy. Repo evidence
  outranks advisory recall. Never store secrets, customer or regulated data.
- Write memory only when memory is configured, authorized,
  verified, permitted by memory-use policy, and explicitly human-approved for durable write use.
  Human permission alone does not establish configured access. Otherwise persist the
  local compact or task-card checkpoint. Candidate learning stays proposal-only.
- $naos_checkpoint_protocol
- After changes, run applicable source/tests, module headers, spec/traceability,
  completion-evidence, claims, self-check, gate, evidence-pack and dashboard checks.
  Preserve failures and untested obligations. Never turn an unexecuted check into a pass.
- For governance/AI-surface changes, review the full affected control plane, run or
  recommend systemic impact, control-plane review, adapter coherence and AI-surface
  budget where available. Preserve anchors; never inflate thresholds to hide findings.
  Route actionable research/learning into reviewed capability, policy, task, known-gap,
  residual-risk, evidence or next-action records before treating it as active guidance.
- If architecture/specs change, verify `specs/01-problem.md`, `specs/02-solution.md`,
  `specs/03-requirements.md`, `specs/04-architecture.md`, task registry and traceability
  where applicable. Readiness is structural review evidence, not approval.
- Keep code conventions, commit/task links and the canonical module header. Do not
  duplicate status files or reports; update their authoritative source and regenerate
  only through an installed producer. Never silently remove/waive a detective check.

## Task-specific reference

Before implementation, task completion, governance review, memory decisions or
workflow changes, read the relevant protocol in
`.github/naos-guidance/claude-reference.md` and
`.github/naos-guidance/governance-reference.md`. Their detailed mandatory duties,
command semantics, domain mindsets, checkpoints and evidence boundaries still apply.
Use installed routes from AGENTS.md and the Task-Capability Matrix in `.github/copilot-instructions.md`.

## Project development commands (verify before use)

These are detected suggestions, not executed project facts. Confirm dependencies,
entrypoints and test paths in `.github/project-context.md` and actual source first.

```sh
$signal_install_cmd
$signal_migrate_cmd
$signal_run_cmd
$signal_test_cmd
```
