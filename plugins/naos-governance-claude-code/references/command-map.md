# NAOS Command Map For Claude Code

Use visible local commands from the project root. Prefer dry-run before
adoption or setup changes.

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
