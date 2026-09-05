---
name: "naos-adapter-coexistence"
description: "Review coexistence between NAOS core and Codex, Claude Code, Cursor, VS Code, Gemini CLI, MCP, and future adapters."
parameters: []
---

# NAOS Adapter Coexistence

## When to Use

Use this skill when adding, updating, installing, or reviewing tool-specific
adapters such as Codex plugins, Claude Code hooks, Cursor rules, VS Code tasks,
Copilot instructions, Gemini CLI guidance, or MCP declarations.

## Review

```bash
naos adapter-coherence --profile <profile>
naos mcp-resource-inventory . --profile <profile>
naos memory-access --profile <profile>
```

Check that adapters:

- do not overwrite another tool's active settings;
- do not silently activate hooks or MCP servers;
- do not claim memory/MCP access from config presence alone;
- do not become the source of truth;
- point back to canonical NAOS commands and project-local artifacts.

## Boundary

Adapters can coexist by reading, guiding, and invoking explicit NAOS commands.
They must not independently promote learning, approve work, or mutate governed
artifacts without a reviewed NAOS flow.
