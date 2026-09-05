---
marp: true
title: NAOS-Governance Reviewer Overview
---

# Reviewer View

NAOS-Governance produces local, reviewable evidence about how AI-assisted SDLC
work was structured and checked.

Primary review commands:

- `naos gate-status`
- `naos gate-evaluate`
- `naos spec-pack-contract`
- `naos spec-cascade`
- `naos evidence-pack`
- `naos dashboard --json`
- `naos pr-governance-summary`

---

# Evidence Boundary

NAOS reports can support reviewer conversations about process evidence.

They do not prove:

- legal or regulatory compliance
- certification
- secure code
- runtime safety
- complete requirements
- approval or non-repudiation

---

# What To Inspect

- Local JSON reports under `naos/reports/`
- Schemas under `schemas/naos/`
- Gate status and evaluation output
- Evidence pack and dashboard summaries
- Human decisions, waivers, residual risks, and next actions
