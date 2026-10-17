---
description: $adapter_description
disable-model-invocation: true
---

# Manual NAOS command: $adapter_name

Read root `AGENTS.md`, then read `$adapter_source` and follow its selected-profile
guidance using the user's request as input. This is a manual file adapter; no
native @agent dispatch, model/tool permission or automatic execution is granted.
If the referenced file is missing, stop this route and use the root router's
manual fallback; do not claim this workflow ran.
