# NAOS Plugin Boundaries

Use this plugin as a Codex operator layer over an installed NAOS kit.

## Authority

Authoritative project governance lives in repository files:

- `naos/` project state, reports, evidence, and learning records.
- `schemas/naos/` contracts.
- `templates/` canonical generated surfaces.
- `scripts/` deterministic validators and report generators.
- human-reviewed commits and decisions.

The plugin can guide, inspect, and route. It does not approve work.

## Non-Claims

The plugin does not provide:

- hidden context injection;
- automatic memory write-back;
- provider/model/API calls;
- MCP access proof;
- hook activation;
- Git push, merge, deployment, or release authorization;
- approval, certification, or proof of compliance.

## Operating Invariants

- NAOS core is canonical; tool adapters are thin, explicit, reversible, and scoped.
- Learn anywhere, approve centrally, propagate deliberately.
- Candidate learning is proposal-only until reviewed and promoted in NAOS.
- Optional adapters can coexist; one adapter must not mutate another tool's active config.
