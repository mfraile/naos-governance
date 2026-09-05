# NAOS Governance Claude Code Plugin

This directory is the canonical repo-versioned source for the NAOS Governance
Claude Code plugin.

The plugin is an operator interface over an already-installed project-local
NAOS kit. It does not replace project-local `naos/` state, evidence, reports,
schemas, policies, learning records, or audit history.

## Boundaries

- NAOS core remains file-first, CLI-first, schema-first, and report-first.
- The plugin may guide Claude Code toward explicit local NAOS commands and
  review flows.
- V1 is skills-only: no hooks, MCP, agents, monitors, binaries, LSP, themes, or
  default settings are bundled.
- The plugin must not silently enable MCP, memory write-back, hooks, provider
  calls, Git pushes, approvals, certification, deployment, release, or
  compliance claims.
- Learning may be captured by any tool, but reviewed promotion remains
  centralized in NAOS learning lifecycle artifacts.

## Skills

- `naos-forensic-review`: lightweight scoped review of a specific artifact,
  change, or claim.
- `naos-forensic-audit`: deep NAOS-aware extension of the generic
  `forensic-audit` method for multi-pass evidence trails, false-positive
  hunting, public/private boundary review, and adapter/catalogue drift checks.
- `naos-systemic-wiring`: NAOS-aware extension of generic `systemic-wiring`
  for capability, validator, evidence, dashboard, spec-pack, and AI-surface
  propagation review.

This list describes repo-versioned plugin source contents. It is not proof of
live local plugin installation.

## Installability

For local development or testing from the kit repository:

```bash
claude --plugin-dir plugins/naos-governance-claude-code
```

Then invoke skills through the plugin namespace, for example:

```text
/naos-governance-claude-code:naos-adoption-readiness
/naos-governance-claude-code:naos-forensic-review
/naos-governance-claude-code:naos-forensic-audit
/naos-governance-claude-code:naos-adapter-coexistence
```

Validate this source before packaging or publishing when the local Claude Code
CLI supports plugin validation:

```bash
claude plugin validate plugins/naos-governance-claude-code
```

Use `--strict` only when `claude plugin validate --help` lists the option for
the installed Claude Code version.

The installed plugin copy is not source authority. Use
`naos adapter-coherence --profile <profile>` after plugin, skill, instruction,
workflow, hook, MCP-posture, or governed-learning propagation changes.
