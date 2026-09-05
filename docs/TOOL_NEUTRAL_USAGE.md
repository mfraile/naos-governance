# Tool-Neutral Usage And Optional Integrations

NAOS-Governance is tool-neutral by default. The core kit works through files,
CLI commands, `Makefile.naos` targets, YAML/JSON schemas, and generated reports.
No specific AI assistant, IDE, MCP server, model provider, SaaS product, or
cloud service is required.

Optional integrations may call NAOS commands for convenience. NAOS core must not
depend on those integrations.

## Core Usage

Use the core surfaces everywhere:

```bash
naos setup-recommendations --profile standard
make -f Makefile.naos naos-self-check
make -f Makefile.naos naos-gate-status
make -f Makefile.naos naos-agentic-workflow-review
make -f Makefile.naos naos-pre-implementation-alignment-review
make -f Makefile.naos naos-duplicate-function-hygiene
make -f Makefile.naos naos-secret-hygiene
make -f Makefile.naos naos-test-quality-hygiene
make -f Makefile.naos naos-dependency-integrity
make -f Makefile.naos naos-package-reality
make -f Makefile.naos naos-api-symbol-reality
make -f Makefile.naos naos-compliance-posture
make -f Makefile.naos naos-task-lifecycle TASK=T-001
make -f Makefile.naos naos-research-record RECORD=naos/research/RESEARCH-001.yaml
make -f Makefile.naos naos-composed-traceability
make -f Makefile.naos naos-evidence-pack
make -f Makefile.naos naos-dashboard
```

The reports are review evidence. They do not approve work, prove compliance,
authorize deployment, or replace human review.

Prompts and agents may act as a natural-language router over these commands:
they can recommend the correct CLI/Make sequence for greenfield adoption,
brownfield adoption, task work, PR evidence, or governance-surface changes. The
commands remain visible and tool-neutral; NAOS does not require a specific
assistant to run them.

Native lifecycle commands use the exact id in `TASK_REGISTRY.yaml`; namespaced
ids are not shortened. `task-complete` writes durable completed history and
preserves acceptance criteria, references, risk, provenance, and the original
card digest, but it does not authorize merge, release, or evidence admission.
Research records remain candidate-only, and composed traceability reports only
the state of explicit links. Attributable human decisions use separate
`naos/human_decisions/` records rather than agent-review language.

The deterministic hygiene reports inspect local files by default. They help
surface duplicate bodies, obvious secret-like findings, weak assertion evidence,
undeclared imports, package/SBOM/provenance/hash review evidence, and explicitly
declared Python API-symbol review evidence without adding any
AI-tool, provider, model, MCP, or memory dependency by default. Package registry
metadata checks remain off by default and require explicit network consent.
API-symbol reality uses source inspection and does not import or execute target
modules.

## Governed Agentic Coding

NAOS can seed a tool-neutral operating model for AI-assisted engineering:

- `naos/agentic_workflow.yaml` declares context hygiene, alignment, vertical
  slices, feedback loops, module-design guidance, human/AI work split,
  Kanban/DAG task flow, and push/pull context.
- `naos/AGENTIC_CODING_PLAYBOOK.md` explains the operating model for adopters.
- `naos/PRE_IMPLEMENTATION_ALIGNMENT.md` records structured answers before
  greenfield setup, brownfield onboarding, or non-trivial feature work.

Review these artifacts with:

```bash
naos agentic-workflow-review --profile standard
naos pre-implementation-alignment-review --profile standard
```

These reviews are deterministic and file-first. They do not inspect chat
history, call models, prove assistant behavior, approve design or implementation,
prove requirements completeness, or replace human review.

`PRE_IMPLEMENTATION_ALIGNMENT.md` may also declare optional
`planned_change_paths` and `out_of_scope_paths`. When those declarations are
present, `naos plan-coherence --diff-base <ref>` can compare local Git changed
files to the declared paths as advisory implementation-scope evidence only; it
does not approve the plan, sequence work, or prove semantic drift.

The same planning surfaces can record optional parallel-lane posture:
`parallel_lane_opportunity` is an advisory suggestion, and
`parallel_lane_decision` is the human/project decision. For solo developers,
lanes can be logical checkpoints; for teams, lanes should map to task claims,
dependencies, path scopes, tests/checks, and handoff evidence. Suggested lanes
do not activate handoff. Declared lanes can use the generated
`naos/lane_handoffs/_TEMPLATE.yaml` as input to the existing local script:

```bash
python scripts/naos_parallel_lane_handoff.py --profile standard --handoff naos/lane_handoffs/<lane>.yaml
naos control-plane-review --profile standard
```

This stays tool-neutral and file-first. It does not create branches or
worktrees, dispatch agents, run tests, approve work, merge, release, call
models/providers, activate MCP or memory, or prove compliance.

### Optional Assured orchestration proposal

An Assured project may explicitly install a six-file, disabled-by-default
proposal module:

```bash
naos add setup-module agent_orchestration_plan --profile assured --dry-run
naos add setup-module agent_orchestration_plan --profile assured --confirm
naos agent-orchestration-plan --profile assured
```

The planner consumes the current implementation-ready planning projection,
`TASK_REGISTRY.yaml` priorities/dependencies/parallel decisions, active claims,
bounded lane paths, the project-local model-provider policy, and clean Git
state. It emits deterministic waves and client-specific declaration previews,
then requires one exact SHA-256-bound human decision. Later waves remain
conditional and must be recomputed. Path globs are component-aware: `*` and
`?` never cross `/`, while `**` is recursive. The command emits JSON only to
stdout so it cannot invalidate its own clean-worktree snapshot.

The dated client declaration contracts checked on 2026-08-30 are:

| Client | Proposal target | Model / effort fields | Current limit |
| --- | --- | --- | --- |
| Codex | `.codex/agents/{agent}.toml` | `model` / `model_reasoning_effort` | Declaration only; runtime use is not verified. |
| Claude Code | `.claude/agents/{agent}.md` | `model` / `effort` | Declaration only; frontmatter is not written. |
| Cursor | `.cursor/cli.json` | none supported | Selection fails closed because the documented project CLI contract does not expose repository-local model and effort fields. |
| GitHub Copilot CLI | `.github/agents/{agent}.agent.md` | `model` / `reasoningEffort` | Unsupported values may fall back; runtime use is not verified. |
| OpenCode | `opencode.json` | per-agent `model` / `reasoningEffort` | Reasoning-effort support varies by provider; runtime use is not verified. |

The policy fails closed when those source checks exceed its configured maximum
age. The command does not write any client configuration, launch a client, call
a provider/model, create a worktree or hook, mutate tasks or claims, close or
approve lane results, merge, push, release, or publish. Signer identity and
independent clean-execution proof are not part of this module.

## Optional Integrations

Optional templates live under `templates/integrations/` and can be copied into
adopter-local `naos/integrations/` paths through review-first setup modules:

```bash
naos add setup-module spec_kit_adapter --profile standard --dry-run
naos add setup-module claude_code_hooks --profile standard --dry-run
naos add setup-module claude_code_plugin_adapter --profile standard --dry-run
naos add setup-module codex_plugin_adapter --profile standard --dry-run
```

Remove `--dry-run` only after reviewing template files and local sensitivity
boundaries. Setup modules copy templates only; they do not activate IDE hooks or
overwrite active settings.

## Optional Adapter Surfaces

Public documentation for adapter surfaces is limited to NAOS-owned files,
setup-module ids, local report commands, and non-claims.

| NAOS surface | Public boundary |
| --- | --- |
| `plugins/naos-governance/` | Repo-versioned plugin source. Installed copies and caches are not authority. |
| `plugins/naos-governance-claude-code/` | Repo-versioned skills-only plugin source. Runtime hooks remain separate and manually activated. |
| `templates/integrations/codex-plugin/` | Optional adopter-local guidance copied only by explicit setup-module action. |
| `templates/integrations/claude-code-plugin/` | Optional adopter-local guidance copied only by explicit setup-module action. |
| `templates/integrations/claude-code/` | Optional hook guidance. Copying the template does not activate hooks or mutate settings. |
| `templates/integrations/spec-kit/` | Optional dry-run adapter guidance from local spec files into NAOS evidence/context concepts. |

## Adoption Commands Stay Tool-Neutral

The professional adoption engine runs from CLI/Make and local files:

```bash
naos adopt . --mode greenfield --profile standard --no-prompt
naos adopt . --mode brownfield --profile standard --no-prompt
naos ai-artifact-inventory . --profile standard
naos compliance-posture --profile standard
naos memory-resource-inventory . --profile standard
naos mcp-resource-inventory . --profile standard
naos adapter-coherence --profile standard
```

It inventories local AI-assistant instructions, prompts, rules, workflow files,
adapter templates, and custom governance artifacts as files. It does not make
any tool mandatory, enable hooks, silently inject context, or call
provider/model APIs.

For Codex, the canonical plugin source lives in the kit repository under
`plugins/naos-governance/`. For Claude Code, the canonical plugin source lives
under `plugins/naos-governance-claude-code/`. Installed plugin cache,
skills-directory copies, marketplace copies, or runtime-loaded plugin copies are
not source authority. Use `naos adapter-coherence` after plugin, skill,
instruction, workflow, learning, hook, or MCP-posture changes.
The report checks propagation-state hashes for mapped source/target artifacts
and flags stale or unreviewed plugin guidance; it does not auto-refresh
installed plugin copies.

## Boundaries

Optional integrations must not:

- auto-activate hooks;
- overwrite active IDE or assistant settings;
- silently inject context;
- write memory;
- call model/provider APIs;
- require secrets or provider credentials;
- add runtime MCP, Engram, vector, graph, or LLMGrader behavior;
- mutate Codex plugin caches, Claude Code plugin state, Claude settings, or marketplace files;
- deploy, publish, push, release, or approve work;
- claim certification or proof of compliance.

Deterministic repository evidence remains primary. Advisory findings may
challenge deterministic evidence but do not replace it.
