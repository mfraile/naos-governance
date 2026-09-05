---
name: "gov-refresh"
description: "Run the full governance refresh pipeline: rebuild function index, sync ARCH tags, update traceability matrix, dashboard, and coherence checks. Call after adding functions, changing task status, or editing specs."
parameters:
  - name: mode
    description: "Refresh mode: 'full' runs gov-refresh + truth validation, 'standard' runs gov-refresh only"
    required: false
    default: "standard"
---

# Skill: Governance Refresh

Runs `make -f Makefile.naos gov-refresh` (or `make -f Makefile.naos gov-full`) to keep all auto-generated governance artifacts accurate.

## When to Use

- After creating or modifying any function in `[ADAPT: your source directory]`
- After changing task status in `naos/TASK_REGISTRY.yaml`
- After editing spec files in `specs/`
- Before submitting a PR to ensure metrics are current
- When dashboard numbers look stale or inaccurate

## Execution

### Standard Refresh (`mode: standard`)

```bash
make -f Makefile.naos gov-refresh
```

Runs in sequence:
1. `python scripts/naos_function_index_query.py --rebuild-index` — rebuild FUNCTION_INDEX.yaml
2. Sync ARCH source tags across all project files
3. Update `naos/TRACEABILITY_MATRIX.md`
4. Run or recommend `make -f Makefile.naos naos-spec-pack-contract` and `make -f Makefile.naos naos-spec-cascade` when specs, task registry entries, source headers, source spec references, or source traceability changed
5. Refresh `naos/DASHBOARD.md` with current task/FR coherence metrics
6. Run coherence checks (orphan detection, spec alignment, boundary violations)

### Full Refresh with Truth Validation (`mode: full`)

```bash
make -f Makefile.naos gov-full
```

Runs `gov-refresh` plus `scripts/naos_validate_truth.py` — verifies `GOVERNANCE_TRUTH_TABLE.md` matches auto-computed metrics.

## Output Interpretation

| Output | Meaning |
|--------|---------|
| `✅ N/N coherence checks passed` | All governance invariants satisfied |
| `⚠️ WARNING: orphan FR detected` | FR exists with no linked task — add to TASK_REGISTRY |
| `❌ ERROR: spec alignment violation` | `Implements:` header references unknown FR — fix header |
| `📊 Dashboard updated` | `naos/DASHBOARD.md` reflects current state |

## After Running

- Read `naos/DASHBOARD.md` for updated completion metrics
- Read `naos/PROJECT_STATUS.md` for delivered requirements count
- Read `naos/reports/spec_cascade_coherence.json` when spec/source traceability
  or source spec references changed
- If metrics changed significantly, update `naos/governance/GOVERNANCE_TRUTH_TABLE.md`

## Anti-Patterns

- **NEVER** manually calculate derived metrics (task completion %, requirements delivered) — the scripts compute these correctly
- **NEVER** skip gov-refresh after adding new functions — FUNCTION_INDEX.yaml will be stale
