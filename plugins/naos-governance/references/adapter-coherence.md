# Adapter Coherence

NAOS adapters include Codex plugin skills, Claude Code templates, Cursor rules,
VS Code/Copilot instructions, Gemini CLI guidance, and future MCP declarations.

The coherence rule is:

```text
Learn anywhere -> approve centrally -> propagate deliberately -> verify adapters
```

Run:

```bash
naos adapter-coherence --profile <profile>
```

In an adopter project, use `--scope project` to review configured project host
files and generated host-surface obligations; the default `auto` scope selects
project review outside a recognized kit root. Use `--naos-root` for a remapped
state directory. Project reports mark canonical plugin/propagation review as
not assessed: copied maintainer review records are never adopter evidence.
Missing required surfaces and bounded or incomplete inspection remain findings,
not a complete host-runtime assessment.

For canonical plugin source, required skills/references, optional integration
templates and propagation review, select `--scope kit`; use
`--kit-root /absolute/kit/source` when the canonical source is separate from the
inspected project. New reports identify `review_scope` and `source_authority`.
Older v1 reports without those fields establish no inferred scope or authority.
The command does not edit adapter files.

If it reports drift, update the canonical NAOS artifact first, then regenerate or
copy adapter surfaces through reviewed setup-module or release workflows.

In kit scope, propagation review compares the mapped current source and target
bytes with `adapter_propagation_state.yaml`. A stale digest requires substantive review of
plugin impact before updating targets or recording a reasoned no-impact
review. Reviewer fields are declared metadata, not authenticated human approval;
refreshing hashes alone does not perform that review. Optional plugin summaries
remain subordinate to the canonical source and current project reports.
