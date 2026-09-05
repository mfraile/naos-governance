# Claude Code Plugin Boundaries

The NAOS Claude Code plugin is optional guidance over project-local NAOS
artifacts.

## Required Boundary

```text
NAOS core is canonical; tool adapters are thin, explicit, reversible, and scoped.
```

## Allowed In V1

- Read project-local NAOS files and reports when the user asks for NAOS work.
- Recommend explicit `naos` and `make -f Makefile.naos` commands.
- Explain greenfield, brownfield, audit, learning, evidence, and adapter flows.
- Point to optional Claude Code hook templates for human review.

## Forbidden In V1

- Hook activation or `.claude/settings.json` mutation.
- MCP server enablement or MCP access proof.
- Memory write-back, hidden context injection, or provider/model/API calls.
- Git push, merge, deployment, release, approval, certification, or proof of
  compliance.
- Treating plugin cache, Claude memory, or chat history as source authority.

Project-local reports remain review evidence. Humans decide disposition,
approval, waiver, release, deployment, and compliance conclusions.
