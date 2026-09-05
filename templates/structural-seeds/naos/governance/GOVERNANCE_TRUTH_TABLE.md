# Governance Truth Table

**Version**: 0.1.0
**Last Updated**: [ADAPT: YYYY-MM-DD]
**Purpose**: Single source of truth for governance metrics canonical values.
**Enforced By**: `scripts/naos_validate_truth.py` (directly, or via `make -f Makefile.naos gov-full`)

---

## Canonical Metrics

These values are the **authoritative reference** that all governance documents must match.
Update this file when project scope changes (new requirements, phases, or tasks added).

| Metric | Value | Source | Methodology |
|--------|-------|--------|-------------|
| **Requirements Total** | 0 | `naos/TASK_REGISTRY.yaml` | Unique FR/NFR requirement keys from task entries |
| **Requirements Delivered** | 0 | `naos/PROJECT_STATUS.md` (auto-synced) | Count of keys where all active tasks are implemented/verified/done |
| **Requirements %** | 0% | Computed | delivered / total |
| **FR Count** | 0 | `specs/03-requirements.md` | Unique `## FR-XXX` section headers |
| **NFR Count** | 0 | `specs/03-requirements.md` | Unique `## NFR-XXX` section headers |
| **Spec Requirements (FR+NFR)** | 0 | `specs/03-requirements.md` | FR Count + NFR Count |
| **Tasks Total** | 0 | `naos/TASK_REGISTRY.yaml` | Count of `- id: T-` entries |
| **Tasks Complete** | 0 | `naos/DASHBOARD.md` (auto-synced) | implemented + verified + done + absorbed |
| **Tasks %** | 0% | Computed | complete / total |
| **Phases** | 0 | `naos/TASK_REGISTRY.yaml` | Unique `phase:` values |
| **Date** | [ADAPT: YYYY-MM-DD] | This file | Last canonical update |

> **Update procedure**: After running `make -f Makefile.naos gov-refresh`, read `naos/PROJECT_STATUS.md` for
> auto-computed delivered requirement count and `naos/DASHBOARD.md` for auto-computed task counts.
> Then update this table to match. Never manually calculate — the scripts are authoritative.

---

## Two Requirements Counts

There are two valid ways to count requirements:

1. **Spec-level**: Unique FR-XXX + NFR-XXX identifiers in `specs/03-requirements.md`.
   Used by `naos/DASHBOARD.md` and metrics coherence validator.

2. **Work-breakdown**: Unique requirement keys extracted from task entries in
   `naos/TASK_REGISTRY.yaml`. First key per task, FR-/NFR- prefixed only.
   Used by `naos/PROJECT_STATUS.md` (auto-synced by `sync_from_registry.py`).

| Context | Methodology | Rationale |
|---------|-------------|-----------|
| **Stakeholder / external reporting** | Spec-level | Ground truth — every requirement in specs/, independent of task coverage |
| **Internal sprint tracking** | Work-breakdown | Reflects what has a task in TASK_REGISTRY.yaml; auto-computed |
| **Automated truth validation** | Work-breakdown | `naos_validate_truth.py` uses TASK_REGISTRY by design |

**Rules**:
- Never mix denominators in the same table, report, or sentence
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
3. Read auto-computed metrics from `naos/PROJECT_STATUS.md` and `naos/DASHBOARD.md`
4. **Update this table** to match the auto-computed values
5. Run `make -f Makefile.naos gov-full` to confirm no drift between this file and derived files
