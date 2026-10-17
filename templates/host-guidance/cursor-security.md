# Cursor security reference: task-time guidance

Read alongside `.github/naos-guidance/security-reference.md` for security-relevant
work. Adapt the existing project-specific choices explicitly; this reference
grants no model, tool, implementation or approval authority.

<!-- NAOS Kit: Portable security standards. Adapt crypto specs, auth model, and network zones. -->

# [ADAPT: Project Name] — Security Standards

## 🔐 Security Architecture

[ADAPT: Describe your defense-in-depth model]

**Encryption**:
- Data at Rest: AES-256-GCM (or equivalent)
- Data in Transit: TLS 1.3 minimum
- Secrets: Environment variables / secrets manager — NEVER in code

---

## 🔑 Authentication & Authorization

[ADAPT: Replace with your auth model]

**JWT Standards** (if using JWT):
- Algorithm: Ed25519 (preferred) or RS256 — never HS256 for production
- Storage: Private key in OS keyring or KMS
- Rotation: Every 60 days with overlap window
- Public JWKs: `/.well-known/jwks.json`

**Access Control**:
- RBAC: Role-based access required on all protected routes
- Audit: Immutable logs for all access events

---

## 🛡️ Application Security Checklist

When writing code, verify:

- [ ] Input validation on ALL endpoints (especially user-supplied URLs — SSRF risk)
- [ ] SQL injection prevention (parameterized queries ONLY — never string interpolation)
- [ ] XSS protection (output encoding on all user-visible data)
- [ ] CSRF tokens on state-changing operations
- [ ] Rate limiting implemented on public endpoints
- [ ] No secrets in code (use env vars or secrets mounts)
- [ ] No PII in discovery/analytics schemas (see naos-project-governance.mdc)
- [ ] Error responses use `ExceptionHandler` — never raw tracebacks to client
- [ ] User-provided URLs pass SSRF validation before any HTTP call

Do not silently auto-fix or rewrite security, encryption, authentication, authorization, database, public API, or regulatory-control code. Propose the remediation, expected evidence updates, and residual-risk note, then wait for explicit approval.

---

## 🔒 Secret Handling Rules

1. **Never hard-code**: No API keys, passwords, tokens, or connection strings in source files
2. **Prefer short-lived tokens**: Rotate regularly, use scoped permissions
3. **Audit on load**: Log config load (not values) — detect missing secrets early
4. **Fail-fast**: Missing required secret at startup → crash loudly, not silently

**Pattern** (Python example):
```python
# [ADAPT: update import path]
from src.core.config import settings  # validates required fields at boot

# NEVER assign literal credentials here.
# Read the validated settings above; no API key belongs in source code.
```

---

## 🔍 OWASP Top 10 Checklist

| # | Risk | Mitigation |
|---|------|-----------|
| A01 | Broken Access Control | RBAC + RLS + auth dependency on all routes |
| A02 | Cryptographic Failures | TLS 1.3, AES-256-GCM, no HS256 |
| A03 | Injection | Parameterized queries only, input validation |
| A04 | Insecure Design | Threat model review, defense-in-depth |
| A05 | Security Misconfiguration | IaC review, no debug in prod |
| A06 | Vulnerable Components | Regular `pip-audit` / `npm audit` |
| A07 | Auth Failures | MFA, short-lived tokens, brute-force protection |
| A08 | Integrity Failures | Model artifact checksums, supply chain review |
| A09 | Logging Failures | Structured logs, immutable audit trail |
| A10 | SSRF | Allowlist URLs, validate redirects, no user-supplied hosts |

---

## 🗑️ Data Retention

[ADAPT: Define your retention policies]

- Logs: [ADAPT: e.g., 90 days rotating]
- User data: [ADAPT: e.g., per-tenant configurable, default 7 years]
- Audit trail: [ADAPT: e.g., immutable, 7 years]

**On delete**: Ensure cascading deletes propagate to all stores (DB, cache, vector DB, object storage).

---

## 🔑 Key Rotation

[ADAPT: Define your rotation schedule]

| Key Type | Rotation Period | Process |
|----------|----------------|---------|
| JWT signing key | [ADAPT: 60 days] | Overlap window for active sessions |
| API keys | [ADAPT: 90 days] | Rotate via secrets manager |
| DB credentials | [ADAPT: Quarterly] | Zero-downtime rotation |

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
