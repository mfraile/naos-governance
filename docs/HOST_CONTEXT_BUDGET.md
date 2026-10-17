# Project instruction budget by host

`naos ai-surface-budget --json` retains the existing Claude `host_context` and
adds `host_contexts`. The character estimates describe contained project files,
not observed host requests, provider tokenizer counts or instruction adherence.

| View | Base project candidates | Conditional envelope |
| --- | --- | --- |
| Claude Code | Existing startup subset: CLAUDE files, supported explicit imports and unconditional native rules | Native paths rules remain separate; skill, command and detailed-reference bodies stay on demand |
| Cursor | Root AGENTS.md and `.cursor/rules/**/*.mdc` with boolean `alwaysApply: true` | Other project mdc rules; actual globs, relevance and manual selection are not evaluated |
| Copilot harness | `.github/copilot-instructions.md` and AGENTS.md as documented format candidates | `.github/instructions/**/*.instructions.md`; even universal applyTo patterns retain unverified host/settings/task applicability |
| VS Code Local | `.github/copilot-instructions.md` | AGENTS and Claude-format compatibility settings, targeted GitHub instructions and native Claude rules are unverified |

For the three conservative candidate views, `base_candidate_estimated_tokens`
and `all_candidate_estimated_tokens` are different measures. The latter includes
all conditional candidates as an envelope. Neither is called startup or actual
request usage. Base candidates can also be supported format alternatives; their
presence does not establish that a host enables both together. In particular,
Local Claude compatibility does not prove that every Copilot CLI/cloud request
loads CLAUDE.md. Use the actual selected harness/settings to interpret the view.

Each union counts an exact contained project path once. Different files with
equal contents are counted separately; no semantic deduplication or host
precedence is inferred. Markdown links, prose-required reads, Cursor file
mentions, skills, commands, prompts and detailed protocol bodies are not expanded
into startup candidates. Claude's existing supported explicit-import projection
remains separate and unchanged. The report preserves source paths, byte hashes,
normalized character counts and unresolved/refused inputs for every host view.
The singleton input-source map and exact-path/hash host manifest bind every read
input. Fresh-profile validation additionally checks each host input against the
complete pre-measurement generated-file content manifest; historical reports
without these additive fields remain valid.

The fixed per-view read, discovery, depth, symlink, size and identity guards are
the same as the existing Claude estimator. Unsafe or unsupported metadata makes a
view partial. Ancestor/nested scope outside this repository-root model, user or
global instructions, custom instruction directories, trust settings, actual task
paths and runtime tool reads are excluded. This is a stable-tree estimator, not a
filesystem sandbox or runtime security boundary.

Configured `combined_scenarios` remain synthetic loadouts. New host views are
metadata and do not add or retune thresholds, change strict exit policy, approve
work, or hide catalogue warnings. Use the per-host rows to inspect possible
co-fired instruction costs; do not add every on-demand catalogue body to them.

Prompt links are resolved from the source prompt and rebased for portable
workflow locations. An unavailable profile instruction becomes an explicit
manual review/required-guidance obligation, not a dangling local link. The four
original daily/weekly workflow `next_action` YAML examples are parsed as data in
generated native and portable guidance. Syntax or declared shape failure is a
finding; successful parsing does not execute a command or authorize a handoff.

Current primary documentary basis (retrieved for this bundle on 2026-10-16):
[Claude memory](https://code.claude.com/docs/en/memory),
[Cursor rules](https://cursor.com/docs/rules), and
[VS Code custom instructions](https://code.visualstudio.com/docs/agent-customization/custom-instructions).
