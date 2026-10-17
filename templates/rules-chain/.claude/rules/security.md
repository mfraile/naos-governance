---
paths:
  - "**/*"
  - "*"
---

# Security task routing

For security-relevant research or changes in **any language or path**, explicitly
read `.github/naos-guidance/security-reference.md` before proceeding. This includes
URL fetching outside auth code, untrusted input, queries/commands, deserialization,
authentication/authorization, browser state, secrets, personal data and dependencies.
Use the actual project's safe APIs and approved security architecture; Python
examples are illustrations, not an instruction to import a Python module in other stacks.

Control lookup: `SC-SECRETS-01`, `SC-AUTHZ-01`, `SC-INJECTION-01`, `SC-SSRF-01`, `SC-CSRF-01`, `SC-ERRORS-01`, `SC-SECURITY-LOGGING-01`, `SC-CRYPTO-JWT-01`, `SC-PII-01`, `SC-DESERIAL-01`, `SC-DEPENDENCY-01`, `AC-DEP-HALLUCINATION-01`.
The reference preserves their canonical summaries and bounded detector coverage;
a router is neither a detector nor proof that a host loaded or followed instructions.

Do not silently apply security-sensitive remediation. Preserve source evidence,
propose the bounded fix and obtain the explicit human/profile approval required
by the selected workflow. No model/provider, tool, write, delegation or approval
authority is added. Quickstart remains research-only.
