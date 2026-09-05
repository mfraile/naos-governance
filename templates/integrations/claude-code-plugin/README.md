# NAOS Optional Claude Code Plugin Adapter

This directory contains adopter-local guidance for teams that want to use the
repo-versioned NAOS Governance Claude Code plugin with this project.

The canonical plugin source remains in the NAOS kit repository under:

```text
plugins/naos-governance-claude-code/
```

This copied integration folder is not the plugin source of truth.

## Installation Model

Recommended model:

```text
project repo
  -> project-local NAOS kit/artifacts
  -> Claude Code plugin installed or loaded in Claude Code
  -> plugin operates the project-local NAOS kit through explicit commands
```

For local testing from the kit repository:

```bash
claude --plugin-dir plugins/naos-governance-claude-code
```

This setup-module copy does not mutate Claude Code plugin caches, install a
marketplace, edit `.claude/settings.json`, activate hooks, or enable MCP.

## Usage

Greenfield activation applies to a genuinely new project root. Brownfield
`init --activate` can create managed files in an existing project only when
every selected destination is absent and the repository-intelligence prestart
gate is satisfied; any collision preserves and refuses the whole request.
For a valid already managed project, `naos upgrade --plan-out` is target-read-only;
apply requires a separate `--apply-plan ... --expect-plan-digest ...`
invocation. Legacy `--force` requests refuse.

Portable preview generation is exercised on Linux with Python 3.11. Managed
`init --activate` mutation is currently supported only on Darwin ARM64 with
CPython 3.11–3.13; unsupported tuples refuse before target mutation. Use an
absent external `--preview-dir` for review when the active host is unsupported.

From the project root, use visible NAOS commands:

```bash
python -m naos_governance.cli doctor
naos-governance upgrade . --tier assured --plan-out /tmp/naos-upgrade-plan.json
naos-governance upgrade . --apply-plan /tmp/naos-upgrade-plan.json --expect-plan-digest SHA256
naos-governance first-run --profile standard --mode greenfield
naos-governance self-check --profile standard
naos-governance adapter-coherence --profile standard
naos-governance learning-loop-review --profile standard
naos-governance ai-surface-budget --profile standard
naos-governance systemic-impact --profile standard
naos-governance agent-orchestration-plan --profile assured
naos-governance control-plane-review --profile standard
naos-governance failure-mode-observations --profile standard
naos-governance opencode-config-hygiene --profile standard
naos-governance package-reality --profile standard
naos-governance api-symbol-reality --profile standard
naos-governance ac-completion-evidence --profile standard
naos-governance harness-trace-import --source naos/harness_traces/example.jsonl --profile standard
naos-governance ai-code-provenance --profile standard
```

If `naos-governance` is missing but `python -m naos_governance.cli doctor`
reports the package is importable, reinstall NAOS in the active Python
environment. If bare `naos` resolves to an editor alias, older global install,
or another tool, use `naos-governance ...` or
`python -m naos_governance.cli ...` until the command path is fixed.

## Relationship To Claude Hooks

The Claude Code plugin v1 is skills-only. Optional hook templates remain under
`naos/integrations/claude-code/` when copied with the `claude_code_hooks` setup
module. Review and activate those hooks manually only if desired.

## Propagation Rule

Learn anywhere, approve centrally, propagate deliberately.

If Claude Code discovers a lesson that should change future behavior, record it
as candidate learning or a review finding first. Promote it through NAOS
governed learning lifecycle before changing Claude plugin skills, Codex plugin
skills, Claude Code hooks, Cursor rules, VS Code/Copilot instructions, Gemini
guidance, or MCP declarations.

## Non-Claims

This adapter does not provide:

- live Claude Code plugin installation proof;
- MCP access proof;
- automatic hook activation;
- silent context injection;
- automatic memory write-back;
- automatic agent or client launch, client configuration mutation, task or
  claim mutation, or dispatch authorization;
- provider/model/API calls;
- runtime monitoring or harness execution;
- legal opinions, authorship proof, ownership proof, or publication authority;
- Claude settings mutation;
- Git push, merge, deployment, or release authorization;
- approval, certification, or proof of compliance.
