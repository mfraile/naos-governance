<!-- NAOS Spec Kit: Portable Documentation Framework -->
# Specification Index

**Project**: [ADAPT: Project Name]
**Version**: 0.1.0
**Status**: In Progress

---

## Document Flow

```
01-problem.md → 02-solution.md → 03-requirements.md
                                     ↓
04-architecture.md ←─────────────────┤
05-api.md          ←─────────────────┤
06-acceptance.md   ←─────────────────┤
07-cost-analysis.md ←────────────────┤
10-execution.md    ←─────────────────┘
```

Each upstream document gates downstream ones. Do not define architecture before requirements.

---

## Spec Files

| # | File | Purpose | Status |
|---|------|---------|--------|
| 01 | [01-problem.md](./01-problem.md) | Market pain points — PAIN-X.X anchors | Draft |
| 02 | [02-solution.md](./02-solution.md) | High-level capability overview | Draft |
| 03 | [03-requirements.md](./03-requirements.md) | FR/NFR with AC tables and systemic impacts | Draft |
| 04 | [04-architecture.md](./04-architecture.md) | ARCH components, data flow, decisions | Draft |
| 05 | [05-api.md](./05-api.md) | API contracts — API-N.M anchors | Draft |
| 06 | [06-acceptance.md](./06-acceptance.md) | Gherkin scenarios — SCEN-N.M | Draft |
| 07 | [07-cost-analysis.md](./07-cost-analysis.md) | Unit economics and scaling model | Draft |
| 08 | [08-market-analysis.md](./08-market-analysis.md) | Competitive landscape and positioning | Draft |
| 09 | [09-integration-contract.md](./09-integration-contract.md) | External API schemas and contracts | Draft |
| 10 | [10-execution.md](./10-execution.md) | Delivery phases with TASK_MATRIX sync block | Draft |

---

## Cross-Reference Conventions

- `FR-XXX` — Functional requirement (defined in 03-requirements.md)
- `NFR-XXX` — Non-functional requirement
- `ARCH-N` — Architecture component (defined in 04-architecture.md)
- `SOL-X.X` — Solution capability (defined in 02-solution.md)
- `API-N.M` — API endpoint group
- `AC-XXX-N` — Acceptance criterion
- `SCEN-N.M` — Acceptance scenario
- `PAIN-X.X` — Problem anchor
- `COST-N` — Cost-analysis section
- `MKT-N` — Market-analysis section
- `INT-N` — External integration contract
- `EXEC-N` — Execution-plan section
- `T-XXX` — Task in TASK_REGISTRY.yaml

---

## Update Procedure

1. Edit `naos/TASK_REGISTRY.yaml` to add/update tasks
2. Run `make -f Makefile.naos gov-refresh` — syncs status badges into 03-requirements.md and TASK_MATRIX into 10-execution.md
3. Never manually edit SYNC-block sections (marked `<!-- BEGIN ... -->...<!-- END ... -->`)
