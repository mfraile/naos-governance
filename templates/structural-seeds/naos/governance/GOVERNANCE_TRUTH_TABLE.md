# Governance Truth Table

**Version**: 0.1.0
**Last Updated**: [ADAPT: YYYY-MM-DD]
**Purpose**: Project-maintained snapshot of governance metrics, checked against source where a denominator contract exists.
**Checked By**: `scripts/naos_validate_truth.py` checks only the four task rows below (directly, or via `make -f Makefile.naos gov-full`).

---

## Canonical Metrics

Task rows are a checked snapshot of `TASK_REGISTRY.yaml`, not independent delivery authority.
Update this file when project scope changes. Requirement, specification and date rows
are not checked by `naos_validate_truth.py`; their denominators and review still need
separate validation. The date placeholders below do not record a completed review.

| Metric | Value | Source | Methodology |
|--------|-------|--------|-------------|
| **Requirements Total** | 0 | `naos/TASK_REGISTRY.yaml` | Unique FR/NFR requirement keys from task entries |
| **Requirements Marked Complete (task declarations)** | 0 | `naos/PROJECT_STATUS.md` (auto-synced) | Count of keys where all active tasks declare implemented/verified/done; not proof of delivery |
| **Requirements %** | 0% | Computed | marked complete / total using the same declared source |
| **FR Count** | 0 | `specs/03-requirements.md` | Unique H2/H3 (`##` or `###`) FR section headers; numeric or named IDs |
| **NFR Count** | 0 | `specs/03-requirements.md` | Unique H2/H3 (`##` or `###`) NFR section headers; numeric or named IDs |
| **Spec Requirements (FR+NFR)** | 0 | `specs/03-requirements.md` | FR Count + NFR Count |
| **Tasks Total** | 5 | `naos/TASK_REGISTRY.yaml` | Parsed task-list length; declared `total_tasks`, if present, must agree |
| **Tasks Complete** | 0 | `naos/TASK_REGISTRY.yaml` | Tasks satisfying canonical completed + delivered + verified lifecycle state; absorbed/deferred are not delivered |
| **Tasks %** | 0% | Computed | Tasks Complete / Tasks Total, rounded to one decimal; zero denominator gives 0% |
| **Phases** | 2 | `naos/TASK_REGISTRY.yaml` | Unique task `phase` values, not the separate phase metadata list |
| **Date** | [ADAPT: YYYY-MM-DD] | This file | Last canonical update |

The dashboard's **Declared Requirement Completion** reads status declarations
from `specs/03-requirements.md`. Task-derived and spec-derived counts must name
their source; disagreement needs review. Neither count authenticates a human
decision or proves execution, delivery, or acceptance. Missing, unknown and
negative spec statuses remain unresolved, and zero parsed requirements do not
mean completion.

> **Update procedure**: After changing the registry, run `make -f Makefile.naos gov-refresh`
> and review the derived-file diff. Update the four task rows from the parsed registry
> and canonical lifecycle semantics, then run `naos_validate_truth.py` to check those
> rows. This command does not validate requirement/spec/test rows or authenticate the date.

---

## Two Requirements Counts

There are two valid ways to count requirements:

1. **Spec-level**: Unique FR-XXX + NFR-XXX identifiers in `specs/03-requirements.md`.
   Used by `naos/DASHBOARD.md` and metrics coherence validator.

2. **Work-breakdown**: Unique normalized requirement strings extracted from task
   entries in `naos/TASK_REGISTRY.yaml`. Current sync does not require an
   FR-/NFR- prefix; the denominator needs a separate agreed contract.
   Used by `naos/PROJECT_STATUS.md` (auto-synced by `sync_from_registry.py`).

| Context | Methodology | Rationale |
|---------|-------------|-----------|
| **Stakeholder / external reporting** | Spec-level | Ground truth — every requirement in specs/, independent of task coverage |
| **Internal sprint tracking** | Work-breakdown | Reflects what has a task in TASK_REGISTRY.yaml; auto-computed |
| **Automated truth validation** | Task metrics only | `naos_validate_truth.py` checks four task rows against TASK_REGISTRY; requirement metrics remain unchecked |

**Rules**:
- Label the source and denominator for each metric; do not combine unlike counts
- Delivery % to stakeholders → spec-level denominator
- Sprint progress → work-breakdown denominator

---

## Governance Layer Architecture (4-Layer Taxonomy)

| Layer | Name | Artifacts | Nature |
|-------|------|-----------|--------|
| **1** | **Authority** | `specs/01–10` (FR/NFR, architecture, API, acceptance) | *What* the product must do |
| **2** | **Administration** | `naos/TASK_REGISTRY.yaml`, `naos/PROJECT_STATUS.md`, `naos/governance/` | *How* we track and govern work |
| **3** | **Enforcement** | `.githooks/pre-commit`, `scripts/naos_validate_truth.py`, `configs/naos_architecture_boundaries.yaml` | Automated verification gates |
| **4** | **Context** | `.ai/RULES.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, `.github/agents/` | Behavioral guidance for AI and humans |

---

## Update Procedure

1. Add/change tasks → edit `naos/TASK_REGISTRY.yaml`
2. Run `make -f Makefile.naos gov-refresh` to regenerate derived files
3. Review source-derived task metrics and the separately scoped requirement/spec metrics
4. **Update this table** with reviewed values; replace the date placeholder only after a real review
5. Run `make -f Makefile.naos gov-full`; its truth validator checks four task rows, not every governance metric
