# Security reference: task-time guidance

Read for security-relevant research or changes in any language, including outbound
URL requests, untrusted inputs, queries/commands, authentication, browser state,
personal data, dependencies and deserialization. Python imports below are
illustrations to adapt to the actual project, not required modules for TypeScript,
Java or other stacks. Resolve project-specific ADAPT choices with the owner before
implementation; this reference grants no implementation or tool authority.
The selected profile still governs: Quickstart remains research-only.

# Security Guidelines

> Canonical source: `SECURITY.md`.
> Consult `.github/project-context.md` for full security architecture context.

## Authentication & JWT

- All new endpoints MUST use: `[ADAPT: your auth dependency imports from your deps module]`.
- JWT tokens: Ed25519 (preferred) or RS256. Rotate every 60 days with 14-day overlap.
- Never hard-code JWT secrets — read from environment variables only.
- Validate `exp`, `iat`, `nbf` claims on every request. Reject expired tokens immediately.

## CSRF Protection

- All state-changing endpoints (POST/PUT/PATCH/DELETE) require CSRF token validation.
- CSRF tokens must be injected via middleware — never skip middleware for "internal" routes.
- Frontend must send CSRF token in the `X-CSRF-Token` header, not in the request body.

## SSRF Prevention

- Every user-provided URL MUST pass SSRF validation before any HTTP request is issued.
- Block private IP ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.1`, `::1`.
- Import the shared validator — do NOT re-implement inline:
  ```python
  # [ADAPT: replace with your project's SSRF validator module]
  from src.utils.validators import is_url_safe
  if not is_url_safe(url):
      raise HTTPException(status_code=422, detail="URL not permitted")
  ```

## Error Responses

- NEVER expose raw tracebacks or internal error details in API responses.
- Use a centralized error handler for all error responses. Canonical pattern:
  ```python
  raise HTTPException(status_code=403, detail="Forbidden")  # generic message
  ```
- Log full exception details server-side (WARNING level+); return only safe messages to clients.

## PII Boundary Enforcement

- Application schema: NO PII allowed — only organization/entity identifiers.
- `[ADAPT: your PII storage rule, e.g. PII lives exclusively in encrypted TENANT_DB]`
- Never log PII (names, emails, phone numbers) at any log level.
- Never include PII in LLM prompts.

## Tenant Isolation

- Always validate `tenant_id` from the authenticated session context — never trust client-provided IDs.
- `[ADAPT: if using PostgreSQL RLS, add ENABLE ROW LEVEL SECURITY + FORCE ROW LEVEL SECURITY on all tenant tables]`
- Session variable: `[ADAPT: your RLS session variable name]` for tenant-scoped queries.

## OWASP Top 10 (edit-time review)

- Injection: parameterized queries only — no f-strings in SQL/Cypher
- Broken auth: auth dependency on every endpoint, JWT validation complete
- Sensitive data: no PII in logs, responses, or application schema
- SSRF: validate all user-provided URLs via your SSRF validator before fetching
- Broken access control: `tenant_id` from session context, not from request body

## LLM / AI Security

> See `.github/instructions/ai-pipeline.instructions.md` — prompt injection, PII stripping, token limits, and output sanitisation are canonical there.

## Remediation Approval

Security-sensitive changes are not silent cleanups. For encryption, authentication,
authorization, database, public API, regulatory-control, or tenant-isolation code:

- describe the risk and proposed remediation first;
- identify related tests and evidence updates;
- record residual risk if evidence is partial;
- wait for explicit human/profile-based approval before deleting, merging, or rewriting behavior.

---

## Cookbook

### If: Adding a new tenant-scoped endpoint
**Then**: Declare both user auth and tenant auth dependencies — always both, never just one.

### If: Processing a user-provided URL (webhook, feed, onboarding source)
**Then**: Call your SSRF validator before any HTTP fetch; raise 422 if it fails
**Example**:
```python
# [ADAPT: replace with your project's SSRF validator import]
from src.utils.validators import is_url_safe
if not is_url_safe(url):
    raise HTTPException(status_code=422, detail="URL not permitted")
```

### If: Logging an error that involves request data
**Then**: Strip PII — log only org IDs and trace IDs, never names, emails, or phone numbers
**Example**:
```python
# WRONG
logger.error("Failed for user %s (%s)", user.name, user.email)

# RIGHT
logger.error("Failed for tenant_id=%s", tenant_id)
```

### If: Building context for an LLM prompt
**Then**: Strip PII — see `.github/instructions/ai-pipeline.instructions.md` prompt safety cookbook for the canonical pattern

<!-- BEGIN NAOS GENERATED: secure-coding-controls -->
## Canonical Secure-Coding Controls

> Generated from `configs/secure_coding_control_register.yaml` version `1.1.0` by `scripts/naos_render_secure_coding_controls.py`. Do not edit this section manually.
> Boundary: Generated sections are bounded requirement summaries. They do not define severity, blocking, waivers, approvals, or compliance.
> Coverage is the register's bounded evaluation category, not a blocking decision or security proof.
> These guidance surfaces do not execute detectors. Human review remains required within the stated scope.

- **`SC-SECRETS-01`** — Do not hardcode credentials or secrets in repository-managed code or configuration; use an approved secret-loading mechanism.
  - Register coverage: `direct`; detectors: `CAP-SECRET-HYGIENE`; human review: `residual_risk_acceptance`. Direct only within CAP-SECRET-HYGIENE scan scope.
- **`SC-AUTHZ-01`** — Require authentication and authorization at every state-changing or sensitive endpoint.
  - Register coverage: `none`; detectors: none; human review: `design_review`. No direct deterministic detector is wired.
- **`SC-INJECTION-01`** — Use parameterized interfaces or context-appropriate safe APIs instead of constructing queries or commands from untrusted input.
  - Register coverage: `partial`; detectors: `EXTERNAL-SARIF-INGEST`; human review: `design_review`. Partial only when relevant external SARIF is supplied.
- **`SC-SSRF-01`** — Validate and allow-list outbound request destinations and prevent access to disallowed internal, metadata, and link-local targets.
  - Register coverage: `none`; detectors: none; human review: `design_review`. No direct deterministic detector is wired.
- **`SC-CSRF-01`** — Protect state-changing browser requests against cross-site request forgery using framework-appropriate controls.
  - Register coverage: `none`; detectors: none; human review: `design_review`. No direct deterministic detector is wired.
- **`SC-ERRORS-01`** — Do not expose stack traces, internal paths, credentials, personal data, or unnecessary implementation detail in errors or logs.
  - Register coverage: `none`; detectors: none; human review: `design_review`. No direct deterministic detector is wired.
- **`SC-SECURITY-LOGGING-01`** — Record security-relevant events with sufficient context for review while excluding secrets and unnecessary personal data.
  - Register coverage: `none`; detectors: none; human review: `design_review`. No direct deterministic detector is wired.
- **`SC-CRYPTO-JWT-01`** — Use approved cryptographic primitives and verify token signatures, algorithms, claims, and key strength.
  - Register coverage: `none`; detectors: none; human review: `design_review`. No direct deterministic detector is wired.
- **`SC-PII-01`** — Minimize personal data, apply appropriate protection and access controls, and avoid unnecessary personal-data logging.
  - Register coverage: `none`; detectors: none; human review: `design_review`. No direct deterministic detector is wired.
- **`SC-DESERIAL-01`** — Do not deserialize untrusted data with unsafe mechanisms; prefer constrained formats and validate against an explicit schema.
  - Register coverage: `partial`; detectors: `EXTERNAL-SARIF-INGEST`; human review: `design_review`. Partial only when relevant external SARIF is supplied.
- **`SC-DEPENDENCY-01`** — Declare repository dependencies and reject local imports that are undeclared or unresolved under the configured dependency rules.
  - Register coverage: `direct`; detectors: `CAP-DEPENDENCY-INTEGRITY`; human review: `residual_risk_acceptance`. Direct only for configured local Python checks.
- **`AC-DEP-HALLUCINATION-01`** — Verify that an AI-suggested dependency exists, is the intended package, and has acceptable provenance before adoption.
  - Register coverage: `indirect`; detectors: `CAP-DEPENDENCY-INTEGRITY`; human review: `residual_risk_acceptance`. Indirect: no registry, identity, typosquat, or malware check.

<!-- END NAOS GENERATED: secure-coding-controls -->
