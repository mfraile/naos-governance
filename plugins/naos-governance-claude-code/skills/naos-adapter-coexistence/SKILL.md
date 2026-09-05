---
name: naos-adapter-coexistence
description: Review coexistence between NAOS and Claude Code, Codex, Cursor, VS Code/Copilot, Gemini CLI, MCP, and future adapters.
---

# NAOS Adapter Coexistence

Use this skill when multiple AI tools or IDE adapters are involved.

## Steps

1. Confirm the model:
   `kit per project`, `plugin per runtime`, `evidence per project`.
2. Check whether adapter guidance conflicts across Claude Code, Codex, Cursor,
   VS Code/Copilot, Gemini CLI, hooks, and MCP declarations.
3. Recommend `naos adapter-coherence --profile standard` after adapter changes.
4. Keep tool-specific caches, marketplace copies, and installed plugins
   non-authoritative.

## Boundaries

Do not overwrite another tool's active settings, activate hooks, inject hidden
context, write memory, enable MCP, call providers, push, merge, deploy, approve,
certify, or claim proof of compliance.
