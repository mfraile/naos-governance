# Codex, Claude Code Plugin, And MCP Adapter Architecture

NAOS ships repo-versioned optional plugin adapter sources for Codex and Claude
Code:

- `plugins/naos-governance/` - canonical Codex plugin source.
- `plugins/naos-governance-claude-code/` - canonical Claude Code plugin source.

Each plugin is an operator interface over an already-installed project-local
NAOS kit. Plugins do not replace project evidence, schemas, policies, reports,
learning records, CI workflows, or audit history.

## Architecture

```text
NAOS kit repository
  -> plugins/naos-governance/                     canonical Codex plugin source
  -> plugins/naos-governance-claude-code/         canonical Claude Code plugin source
  -> templates/integrations/           review-first optional adapter templates
  -> templates/skills/                 canonical reusable NAOS skills
  -> scripts/                          deterministic validators and reports
  -> schemas/naos/                     public control-plane contracts

Adopter project
  -> naos/                             project-local governance state
  -> naos/integrations/codex-plugin/   optional copied adapter guidance
  -> naos/integrations/claude-code-plugin/ optional copied adapter guidance
  -> naos/integrations/claude-code/     optional hook guidance
  -> tool-specific settings            reviewed and activated by the adopter

Tool runtime
  -> installed plugin copy/cache        operator UI, not source authority
```

See the diagram source at
[`docs/diagrams/naos-plugin-adapter-architecture.mmd`](diagrams/naos-plugin-adapter-architecture.mmd).

## Operating Model

The intended flow is:

1. Install or initialize NAOS in the project repository.
2. Install or refresh the desired tool plugin through that tool's plugin
   mechanism.
3. Use the plugin to select the right explicit NAOS command sequence.
4. Record outputs in project-local `naos/` reports and evidence.
5. Use `naos adapter-coherence` after plugin, skill, instruction, workflow, or
   learning propagation changes.

Plugins guide the operator, but visible local NAOS command output remains the
review evidence.

Adapter propagation is reviewed through deterministic source/target hashes in
`adapter_propagation_state.yaml`. A plugin skill, command map, reference, or
adapter template that has not been reviewed against its mapped NAOS source is a
finding. This is a critic control, not an automatic sync mechanism.

## Coexistence

NAOS adapters must coexist with VS Code, Cursor, Claude Code, Codex, Gemini CLI,
GitHub workflows, and future tools.

Core invariant:

```text
NAOS core is canonical; tool adapters are thin, explicit, reversible, and scoped.
```

Adapters may read, guide, and invoke explicit NAOS commands. They must not
overwrite another tool's active settings, silently activate hooks, inject
context, write memory, claim MCP access, push branches, approve work, deploy,
release, or certify compliance.

## Governed Learning And Propagation

Self-improvement is governed through NAOS learning lifecycle records, not
independent IDE memories or plugin-local edits.

```text
Learn anywhere -> approve centrally -> propagate deliberately -> verify adapters
```

If a lesson should change future behavior, first capture it as a candidate or
review finding. Promote it through `naos learning-loop-review` and human review
before changing skills, prompts, workflows, baselines, gates, instructions,
plugin skills, Claude Code hooks, Cursor rules, VS Code/Copilot instructions,
Gemini guidance, or MCP declarations.

## Commands

```bash
naos add setup-module codex_plugin_adapter --profile standard --dry-run
naos adapter-coherence --profile standard
naos learning-loop-review --profile standard
naos ai-surface-budget --profile standard
naos compliance-posture --profile standard
naos systemic-impact --profile standard
naos control-plane-review --profile standard
```

Setup modules copy adopter-local guidance only. They do not install Codex or
Claude Code plugins, mutate plugin caches, edit personal marketplaces, activate
hooks, write memory, mutate `.claude/settings.json`, or enable MCP.

## Claude Code Plugin V1

The Claude Code plugin v1 is skills-only. It uses the official Claude Code
plugin structure with `.claude-plugin/plugin.json` and `skills/<name>/SKILL.md`
entries. It intentionally ships no hooks, MCP servers, agents, monitors,
binaries, LSP configuration, themes, user config, or default settings.

Existing Claude Code hook templates remain separate under
`templates/integrations/claude-code/` and must be copied and activated only
through review-first manual steps.

## MCP Roadmap

Phase 1 is readiness-only. There is no active MCP server in either plugin.

Future read-only MCP tools may expose report/status inspection. Future
write-capable MCP operations require explicit human approval rules, evidence
trail, authorization boundaries, and command-specific governance. Until then,
MCP write operations remain out of scope.

## Non-Claims

The plugin adapter architecture does not provide:

- live Codex plugin installation proof;
- live Claude Code plugin installation proof;
- MCP access proof;
- automatic plugin propagation;
- automatic stale-content repair;
- automatic memory write-back;
- hidden context injection;
- hook activation;
- provider/model/API calls;
- Git push, merge, deployment, or release authorization;
- approval, certification, or proof of compliance.
