---
name: gov-refresh
description: Sync task-derived files and dashboard. Rebuild function and traceability indexes separately when needed.
metadata:
  naos-parameters: '[{"name":"mode","description":"Refresh mode: ''full'' runs gov-refresh + truth validation, ''standard'' runs gov-refresh only","required":false,"default":"standard"}]'
---

# Skill: Governance Refresh

## When to Use

Use after task-registry or spec-status changes, or when backlog and dashboard
status needs refresh. Review generated changes before relying on them.

## Run

```bash
make -f Makefile.naos gov-refresh
```

This runs registry sync (backlog, execution task matrix, marked project-status
sections and dashboard metrics), conditional spec-status sync, optional installed
AI catalogue/component/plan helpers, then dashboard generation. It does not
rebuild the function index or traceability matrix or run every validator.

Select additional commands for the changed inputs:

```bash
make -f Makefile.naos function-index                         # source functions
python scripts/naos_function_index_query.py --rebuild-index # derived similarity index
python scripts/workflows/generate_traceability_matrix.py   # source/spec links
make -f Makefile.naos naos-spec-pack-contract                # spec contract
make -f Makefile.naos naos-spec-cascade                      # source/spec gaps
```

`function-index` writes `naos/inventory/FUNCTION_INDEX.yaml`; the query script
writes `FUNCTION_SIMILARITY_INDEX.json`. The traceability script writes
`naos/TRACEABILITY_MATRIX.md`. Run only the applicable commands available in
the installed profile.

For truth validation after the refresh, use `make -f Makefile.naos gov-full`.
That target adds `scripts/naos_validate_truth.py`; it does not run the separate
index, matrix, or spec commands above.

## Review

Read `naos/DASHBOARD.md` and `naos/PROJECT_STATUS.md`; inspect optional helper
reports only when those helpers ran. Do not treat `gov-refresh` success as proof
that unrelated indexes, a project-defined `MASTER_INVENTORY.md`, or all
governance checks are current.
