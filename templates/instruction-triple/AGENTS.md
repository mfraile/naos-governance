# NAOS project routing

Selected profile: **$naos_profile**. Repository source, configuration, tests and
executed evidence are authoritative. Read `.ai/RULES.md`,
`.github/copilot-instructions.md` and `.github/project-context.md` explicitly
before work; Markdown links alone do not imply automatic context import.

Use only the selected profile's generated routes below. Check files still exist
before invocation: this inventory describes generation, not host discovery,
activation success, permission, approval or completed work. Existing unmanaged
instruction files cause whole-operation refusal and remain unchanged; review
ownership and migration explicitly before activation.

$naos_routes

## Host routes and boundaries

Codex and Cursor use root AGENTS.md; Gemini uses GEMINI.md's explicit import;
Claude uses CLAUDE.md's explicit import (native AGENTS fallback is conditional on
client version/configuration and absence of Claude instructions).
Shared portable skills use `.agents/skills/naos-portable-*`; workflow skills use
`.agents/skills/naos-workflow-*`. Codex supports `$name`; Cursor and supported
VS Code skill selectors use `/name`. Gemini discovers enabled skills and uses
relevance plus user consent; no arbitrary Gemini slash command is asserted.
Codex adapters include `agents/openai.yaml` with implicit invocation disabled.
Other hosts use their own invocation controls; one metadata flag does not
establish identical behavior across hosts.
Claude manual commands use `/naos-portable-*` or `/naos-workflow-*` from
`.claude/commands/`. Explicitly read the listed SKILL.md or prompt file when a
host route is unavailable. Select one route per workflow; legacy `.github/skills`
names are retained alongside distinct portable names for compatibility.

VS Code Local harness supports `.github/prompts`; the Copilot harness does not load
those prompt files. Shared workflow skills provide another discoverable route.
These are source-supported paths, not executed vendor qualification. No host
agent manifests, tool permissions, models or automatic delegation are translated.
Read `.github/agents/*.agent.md` as manual role guidance outside a qualified
host; an @agent mention never authorizes dispatch by itself.

Human authorization, profile gates, no-direct-edit diagnostic roles and explicit
review remain binding. Do not silently enable hooks, integrations, memory,
providers, model/tool access, delegation, merge, release or approval.

## Security task routing

For URL fetching, untrusted inputs, query/command construction, deserialization,
authentication, browser state, secrets, personal data or dependencies in any
language/path, explicitly read `.github/naos-guidance/security-reference.md`.
Its canonical SC/AC control summaries apply beyond Python auth paths. This is an
on-demand read, not a startup import or a grant of implementation authority.
Quickstart remains research-only; retain the selected profile and approval gates.

Control lookup: `SC-SECRETS-01`, `SC-AUTHZ-01`, `SC-INJECTION-01`, `SC-SSRF-01`, `SC-CSRF-01`, `SC-ERRORS-01`, `SC-SECURITY-LOGGING-01`, `SC-CRYPTO-JWT-01`, `SC-PII-01`, `SC-DESERIAL-01`, `SC-DEPENDENCY-01`, `AC-DEP-HALLUCINATION-01`.
