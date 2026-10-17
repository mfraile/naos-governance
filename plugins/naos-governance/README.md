# NAOS Governance Codex Plugin

This directory is the canonical repo-versioned source for the NAOS Governance
Codex plugin.

The plugin is an operator interface over an already-installed NAOS kit. It does
not replace project-local `naos/` state, evidence, reports, schemas, policies,
or audit history.

## Boundaries

- NAOS core remains file-first, CLI-first, schema-first, and report-first.
- The plugin may guide Codex toward the right NAOS commands and review flows.
- The plugin must not silently enable MCP, memory write-back, hooks, provider
  calls, Git pushes, approvals, certification, or compliance claims.
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

The repo uses `.codex-plugin/plugin.json`, including its `interface` metadata.
OpenAI's [packaging documentation](https://developers.openai.com/plugins/build/plugins)
retains this format as a compatibility fallback. That format support does not
establish installation or execution in an installed host version. Public directory
[submission requirements](https://developers.openai.com/plugins/deploy/submission#listing-metadata) are a
separate review; their listing limits do not establish local-load invalidity.

Validate this source before installing or publishing. The following helper is
available only in environments that install it; check that the file exists before
running it. If absent, record validation as unavailable and use the current
packaging documentation for a manual source review; do not report a validator pass:

```bash
python3 "$CODEX_HOME/skills/.system/plugin-creator/scripts/validate_plugin.py" plugins/naos-governance
```

Personal marketplace installation, when desired for live local testing, is a
separate operator action. The marketplace copy is not the canonical source.
