# Adapter Coherence

Run adapter coherence after changes to Claude Code plugin skills, Codex plugin
skills, Claude hook templates, prompts, agents, instructions, workflows,
adapter docs, MCP posture, or governed-learning propagation.

```bash
naos adapter-coherence --profile standard
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

The report is deterministic, local, and file-first. It does not prove live
Claude Code plugin installation, live Codex plugin installation, MCP access
proof, automatic memory write-back, automatic adapter propagation, approval,
certification, or proof of compliance.

In kit scope, propagation review compares the mapped current source and target
bytes with `adapter_propagation_state.yaml`. A stale digest requires substantive review of
plugin impact before updating targets or recording a reasoned no-impact
review. Reviewer fields are declared metadata, not authenticated human approval;
refreshing hashes alone does not perform that review. Optional plugin summaries
remain subordinate to the canonical source and current project reports.
