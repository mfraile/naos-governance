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

The self-check command and its Make wrapper inspect live inputs without publishing project state. For persistent evidence collection, use `naos self-check --profile standard --refresh` or `make -f Makefile.naos naos-self-check SELF_CHECK_ARGS=--refresh`. `--output <path>` alone saves only the final inspection report.

The reports are review evidence. They do not approve work, prove compliance,
authorize deployment, or replace human review.

Code-quality reports use repository-relative `/` paths on every OS. Write
duplicate allowlist entries in that format; they are matched verbatim.
Architecture ownership globs match those paths
case-sensitively, and configuration files use UTF-8. Staged checks select files
from Git and inspect their working-tree contents; they do not attest the exact
bytes staged for commit.

Project coherence checks selected file syntax, not tool semantics or complete
project safety. YAML streams support multiple documents and the validator's
finite safe CloudFormation short tags; arbitrary tags remain errors. JSON
accepts a UTF-8 BOM. Comments and trailing commas are allowed only for `.jsonc`,
`.code-workspace`, `tsconfig*.json`, VS Code `settings.json`/`launch.json`/`tasks.json`,
and `devcontainer.json`/`.devcontainer.json`; other JSON stays strict. Selected
YAML/JSON files beneath `templates/` of a contained ordinary chart with a valid
`Chart.yaml` identity are reported as `NOT_VALIDATED` until rendered and checked
with Helm; this does not skip template markers elsewhere. Symlink inputs are
refused. Existing directory exclusions remain in force, and untracked files are
included. The selected secret-pattern heuristic reuses the shared detector and
never prints matched values; it is not a general secret scan or approval.

AC/SCEN test-reference checks share the completion-evidence identifier grammar,
including `AC-001-1` and legacy dotted IDs. Recognized test filename families
cover Python, JS/TS (including JSX/TSX), Go, Java, C#, and Ruby; other names are
outside this selected check. Spec implementation-reference and matrix scans
select `.py`, `.js`, `.jsx`, `.ts`, `.tsx`, `.go`, `.java`, `.cs`, `.rb`, and `.php`
from configured/inferred roots. They compare complete FR/NFR tokens, not
substrings, and attest textual links rather than implementation correctness.
The matrix scans the finite canonical Spec-Kit inventory (including
`08-market-analysis.md`) and excludes copied-kit scripts
only by the exact init marker in the first two lines under `scripts/` or
`naos_tools/`. This lexical selection convention does not authenticate source;
markers in project source or later prose do not exempt a file. Other source
suffixes remain explicitly unassessed. `validate-all` passes its `NAOS_PROFILE`
to spec validation; existing strict-quality profile rules still apply.

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

Lane handoff path fields use repository-relative `/` separators on every OS,
for example `src/service.py` on Windows as well as macOS and Linux. Matching is
case-sensitive. Scope declarations accept directory prefixes and globs; changed
files and evidence/noise lists name individual files. Leading `./` and trailing
directory `/` remain accepted. Absolute or drive-relative paths, backslashes and
internal `.`/`..` segments produce an explicit `invalid_path` finding, including
when the path was declared generated evidence or noise. Backslashes are not
silently rewritten because they can be literal filename characters on POSIX.

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

Both the policy and request must be enabled before client-source freshness can
block a run. A disabled configuration reports `inactive` even when its client
source dates have aged past the configured limit. Client fields, paths, date
syntax and future dates are still validated; enabled use still rejects stale
contracts. An inactive report does not verify or invoke a client runtime.

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


## Generated project host routes

Generated projects include a selected-profile root `AGENTS.md` router,
`CLAUDE.md` with an explicit `@AGENTS.md` import and `GEMINI.md` with an explicit
`@./AGENTS.md` import. Read the router to identify actual installed availability
and manual fallbacks; Markdown references are instructions to read files, not
claims that hosts expand all links. Existing instruction files remain subject to
normal ownership/create-only activation controls: collisions cause whole-operation
refusal and preserve adopter files. Review ownership and migration explicitly.

Generated Claude, Copilot and Cursor core instructions keep the approval, scope,
security, evidence and memory boundaries in their entry files. Detailed protocols
are installed under `.github/naos-guidance/` and must be read for the documented
implementation, completion, governance and other task triggers. They are explicit
on-demand references, not unconditional imports. Claude imports still consume
context. A smaller entry file alone does not prove a smaller assembled request.
The profile-aware role index is `.github/NAOS_AGENTS.md`; placing an index under
`.github/agents/` would expose it to native custom-agent discovery.

Lite and higher retain their `.github` surfaces and generate distinctly named
`naos-portable-*` skill adapters plus `naos-workflow-*` prompt adapters under
`.agents/skills`. Claude receives manually invoked `.claude/commands` adapters
that instruct the operator to read those portable files. No `.claude/skills`
mirror or symlink is generated. Select one legacy or portable route; distinct
adapter names avoid same-name skill collisions in hosts that scan both roots.
Codex supports `$name`; Cursor and supported VS Code skill selectors use `/name`.
Every shared adapter includes a Codex `agents/openai.yaml` with
`policy.allow_implicit_invocation: false`; this contains no model/tool settings.
An original skill support file at that same path causes generation refusal,
rather than silently replacing its policy. Portable frontmatter contains only
`name` and `description`; host controls stay in their own formats. Claude command
wrappers set `disable-model-invocation: true`. The portable file alone cannot
enforce invocation policy in other hosts; review that host's controls before use.
Gemini skill discovery uses relevance and user consent; no arbitrary Gemini slash
command is asserted. File reading is the fallback when invocation is unavailable.
Quickstart remains research-only and does not advertise lifecycle automation.

VS Code prompt files are supported by the Local harness. Use the installed workflow
skills or explicit file-reading route for other harnesses; support is not a global
prompt-file deprecation claim. These paths reflect vendor documentation inspected
on 2026-10-16. Generation and static validation do not qualify installed host
versions, discovery, invocation or adherence.
See [Codex skills](https://learn.chatgpt.com/docs/build-skills),
[Claude skills and commands](https://code.claude.com/docs/en/skills),
[Claude imports](https://code.claude.com/docs/en/memory),
[Cursor skills](https://cursor.com/docs/skills),
[VS Code skills](https://code.visualstudio.com/docs/agent-customization/agent-skills),
[VS Code prompts](https://code.visualstudio.com/docs/agent-customization/prompt-files),
[Gemini instructions](https://geminicli.com/docs/cli/gemini-md/) and
[Gemini skills](https://geminicli.com/docs/cli/skills/).

No agent tool lists, model selection or host permissions are translated. Portable
agent references are human-authorized manual role handoffs. Debug guidance is
no-direct-edit diagnosis; implementation belongs to a separately authorized
writer, with regression evidence and human review. Unavailable profile skills
and agent files carry explicit manual fallbacks instead of assumed discovery.
All generated adapter/support files participate in generated inventory, LF policy
and source provenance. Brownfield script layout rewriting applies to their exact
installed script references before activation.

Portable workflow inputs are manual review inputs. Replace each explicit
`MANUAL_INPUT` marker with a validated project value before using a command; the
adapter does not claim that a host expands VS Code input syntax. Profile presets
describe generated availability; their context-phase suggestions do not schedule
work or invoke a runtime consumer.

AI-surface reports retain character-based estimates, configured warning/block
thresholds and explicit loading limits. On-demand guidance inventory is separate
from modeled startup context; neither is an observed provider token count. Claude's
under-200-line recommendation is advisory, and Codex's configurable instruction
byte cap is a different measure. Preserve warnings rather than tuning thresholds
merely to obtain a green report.

Windows CLI project paths retain the ordinary absolute drive-path contract.
Managed initialization uses native held reads for destination checks and a
separate internal I/O address for its owned temporary preview. This avoids
treating a deep existing file as absent because an ordinary Python path read
failed. Public extended, device and UNC paths remain refused. This handling
does not qualify deep paths in every generated script or installed AI host;
see the bounded evidence in [platform support](PLATFORM_ADAPTERS.md).
