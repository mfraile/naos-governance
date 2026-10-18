---
name: $adapter_name
description: $adapter_description
---

# Portable NAOS adapter: $adapter_name

Read root `AGENTS.md` first. Selected profile: **$adapter_profile**.
Original guidance: `$adapter_source`. This is an explicit alternate route; select
one adapter or legacy workflow. Host discovery and invocation are unqualified.
Prompt input markers in the original guidance are plain placeholders: obtain
values from the user's request. Original slash examples describe the legacy
workflow; invoke this adapter by its own name when supported, or read this file.
Role guidance below requires human-authorized handoff; no native agent dispatch,
tool/model permission or automatic execution is granted.

Metadata location: `.agents/skills/$adapter_name/agents/openai.yaml`, relative to
the workspace root. `agents/openai.yaml` is relative to this skill directory,
not the project root. When a required metadata read fails, read the exact path
above before concluding absence; a failed file-list/glob search is insufficient.
If that exact read fails, report the path/error and stop the selected workflow.
Do not claim the metadata was read or continue on an assumed default.

$adapter_body
