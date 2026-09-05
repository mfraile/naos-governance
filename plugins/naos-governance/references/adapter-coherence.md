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

The report checks canonical plugin source, required plugin skills/references,
optional integration templates, project-local adapter copies when present, and
overclaim boundaries. It does not edit adapter files.

If it reports drift, update the canonical NAOS artifact first, then regenerate or
copy adapter surfaces through reviewed setup-module or release workflows.
