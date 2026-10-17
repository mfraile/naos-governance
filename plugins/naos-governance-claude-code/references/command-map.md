# NAOS Command Map For Claude Code

Use visible local commands from the project root. Prefer dry-run before
adoption or setup changes.

## Generated project host routes

Read the selected-profile root `CLAUDE.md`, which imports `@AGENTS.md`, for
installed routes and manual fallbacks. Lite and higher provide manually invoked
`.claude/commands` adapters that route to portable `.agents/skills` files; they
do not generate a `.claude/skills` mirror. Select one supported route, or read
the referenced file when invocation is unavailable. These adapters do not
translate native subagents, model selection, tools or permissions, or qualify
installed host discovery and execution. Follow
`docs/TOOL_NEUTRAL_USAGE.md#generated-project-host-routes`.

## Orientation

```bash
naos self-check --profile standard
naos setup-recommendations --profile standard
naos adapter-coherence --profile standard
```

## Greenfield / Brownfield

```bash
naos adopt . --mode greenfield --profile standard --dry-run
naos adopt . --mode brownfield --profile standard --dry-run
```

## Governance Surface Changes

```bash
naos systemic-impact --profile standard
naos control-plane-review --profile standard
naos plan-coherence --profile standard
# Add --diff-base <ref> only when comparing changed files to alignment path declarations.
naos agent-orchestration-plan --profile assured
naos behavioral-readiness --profile standard
naos ai-code-provenance --profile standard
naos compliance-posture --profile standard
naos design-traceability --profile standard
naos failure-mode-observations --profile standard
naos opencode-config-hygiene --profile standard
naos ai-surface-budget --profile standard
naos package-reality --profile standard
naos api-symbol-reality --profile standard
naos module-headers --profile standard
naos spec-pack-contract --profile standard
naos spec-pack-materialize . --profile standard --dry-run
naos spec-assembly-worksheet . --profile standard
naos spec-cascade --profile standard
naos ac-completion-evidence --profile standard
naos task-lifecycle --task T-001 --profile standard
naos task-complete --task T-001 --profile standard # add test/evidence/task_delivery decision refs for verified delivery
naos research-record naos/research/RESEARCH-001.yaml --profile standard
naos composed-traceability --profile standard
naos harness-trace-import --source naos/harness_traces/example.jsonl --profile standard
naos adapter-coherence --profile standard
```

## Learning Changes

```bash
naos learning-loop-review --profile standard
naos ai-surface-budget --profile standard
naos adapter-coherence --profile standard
```

## Evidence

```bash
naos evidence-attestation --profile standard
naos evidence-sign --profile standard
naos evidence-verify --profile standard
naos evidence-pack --profile standard
naos sarif-export --profile standard
naos ai-code-provenance --profile standard
naos compliance-posture --profile standard
naos ac-completion-evidence --profile standard
naos harness-trace-import --source naos/harness_traces/example.jsonl --profile standard
naos api-symbol-reality --profile standard
naos dashboard --profile standard
```

Reports are review evidence, not work authorization, plan approval, semantic
drift proof, runtime monitoring, harness execution, NAOS signing, third-party
signature validation, approval, or proof of compliance.
Task completion records repository state but does not authorize merge, release,
or evidence admission. Research validation does not promote candidate claims,
and composed structural links do not prove semantic correctness.
Agent-orchestration output is a local proposal only; it does not launch agents
or clients, write client configuration, mutate tasks or claims, or authorize
dispatch.

## Complete local readiness

Use `naos ci-readiness --profile standard --task TASK_ID --query QUERY --graph-path SOURCE_PATH` with actual project inputs. Exit success and semantic
gate readiness are separate. The opt-in `--finalize-dependencies` mode retains
initial diagnostics and verifies a new full self-check before final gate
evaluation; it supports Lite, Standard and Assured with current L0–L2 and targets
through L3. Lite's enabled L0 behavioral capability permits inert inspection
only; its missing-conformance warning and `not_ready` remain visible. Integrated/
native and installed-artifact qualification remain pending. It creates no missing evidence or approvals;
default readiness is unchanged. Follow `INSTALLATION_MANUAL.md` and the
project's `NAOS_QUICK_REFERENCE.md` for the current contract.
