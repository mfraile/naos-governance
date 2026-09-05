# NAOS Threat Model

**Status**: Public, portable threat model for the kit
**Scope**: AI-assisted SDLC governance evidence and onboarding risks, not
runtime governance for deployed agents

NAOS governs development-time evidence and review workflows. It does not provide
a runtime gateway, daemon, scheduler, graph server, hosted compliance service,
identity provider, authorization system, deployment controller, or
post-deployment safety layer.

## Trust Boundaries

| Boundary | What NAOS Assumes | What Remains Outside NAOS |
| --- | --- | --- |
| Repository files | Local files can be read and validated. | Git hosting policy, branch protection, and human code review. |
| Generated reports | Reports are derived evidence and may be regenerated. | External archival, notarization, and tamper-resistant custody. |
| AI tools and IDEs | Optional integrations may call NAOS commands. | Tool behavior, model behavior, hidden context, and assistant memory. |
| CI runners | CI can run deterministic checks and collect artifacts. | Runner compromise, artifact retention policy, and secret governance. |
| Operator/team metadata | Local metadata can support coordination. | Authentication, authorization, identity proof, and access control. |
| Memory/provider surfaces | Readiness can be checked from declared files. | Live MCP/Engram behavior, private payloads, and memory write authority. |

Core kit posture:

- deterministic and file-first;
- optional integrations are convenience layers;
- no LLMGrader runtime by default;
- no memory write-back;
- no MCP/Engram runtime in core;
- no automatic context injection;
- no automatic approval;
- no proof of compliance;
- human review remains required.

## Assets

| Asset | Why It Matters |
| --- | --- |
| `TASK_REGISTRY.yaml`, task claims, and active cards | Define planned work, coordination metadata, and task evidence. |
| Specs, project context, and Pre-Implementation Alignment | Capture intent, constraints, vertical slices, and evidence expectations. |
| `.ai`, `.github`, `CLAUDE.md`, agents, prompts, skills, instructions | Shape AI tool behavior and human-mediated handoffs. |
| `FUNCTION_INDEX.yaml`, local context index, and traceability outputs | Help find existing implementation and candidate relationships. |
| Policy, gatekeepers, overlays, and team maps | Define governance configuration and profile behavior. |
| Validator reports | Provide machine-readable evidence about claims, crosswalks, tests, gates, and self-conformance. |
| Audit log and session/operator reports | Record event history and local attribution metadata. |
| Evidence pack, dashboard summary, and SARIF output | Package and display governance posture for review. |

## Threats and Controls

| Threat | Example | NAOS Control |
| --- | --- | --- |
| Context drift | Long or compacted chat becomes treated as authoritative. | Agentic workflow guidance, task context packs, and Pre-Implementation Alignment keep repository evidence primary. |
| Instruction drift | AI instructions, prompts, or skills diverge from current policy. | Systemic impact review, docs consistency checks, and frontmatter validation. |
| Silent context injection | Optional tools add hidden context or write settings without review. | Optional integration docs require manual activation, dry-run setup modules, and no silent injection. |
| MCP descriptor or endpoint substitution | A familiar server label is kept while its endpoint, transport, config shape, or execution/auth fields change. | `mcp-resource-inventory` compares sanitized static declaration metadata with an exact risk-owner policy and pinned digests; labels are not identity, unknown/drifted declarations require review, and no activation occurs. |
| MCP tool or write-authority confusion | A permitted endpoint is treated as proof that all current or future tools are safe or write-authorized. | Descriptor results remain `allowlisted_pending_activation`; remote identity, authentication, tool lists, tool safety, permissions, and write authority are explicit non-claims and separate owner decisions. |
| Memory write-back confusion | Memory recall is treated as evidence or durable truth. | Memory readiness/access/use-policy reports keep memory advisory and require human approval for durable writes. |
| Prompt/tool overreach | An assistant treats advisory output as authority. | `ADR-0010: Control-Plane Advisory Boundaries`, not-claimed fields, residual risks, and gate/evidence visibility. |
| Evidence overclaim | Reports are described as approvals or proof. | Claim-control docs, public audit playbook, non-claims, and documentation tests. |
| Report-as-approval confusion | Passing CI or a green dashboard is treated as release approval. | PR governance summary and audit docs state outputs are review evidence only. |
| Risky PR diff surfaces are missed in review | A pull request changes workflows, dependency manifests, AI prompts, governance files, or adds prompt-injection/secret-like text. | `naos pr-risk-classify` emits deterministic local diff findings for human review; it is not PR approval, security proof, malware analysis, sandbox execution, or proof of compliance. |
| Provider/API/runtime risk | A future evaluator leaks data, costs money, or drifts by model version. | Static-only default, LLMGrader readiness-only posture, and no provider calls by default. |
| Public/private artifact leakage | Internal paths, private docs, or local repo material enter public docs. | Public ADR sanitization, docs boundary tests, and sanitized export checks before publication. |
| Generated-adopter misuse | Users treat placeholders or `[ADAPT]` sections as complete. | Setup recommendations, profile guidance, and evidence reports show not-configured/missing states. |
| CI artifact sensitivity | Reports or evidence packs expose internal metadata. | PR CI template warns about artifact sensitivity and excludes context indexes/private payloads by default. |
| Optional integration risk | Hook templates are mistaken for core behavior. | Tool-neutral usage docs keep integrations optional and non-authoritative. |
| Future harness/signing overreach | Readiness metadata is mistaken for execution, signing, verification, key custody, or attestation authority. | Cross-Harness Review Readiness keeps future harness and DSSE-style planning advisory, adopter-owned, and human-reviewed. |
| Multi-user coordination risk | Two operators overwrite reports, claims, or evidence. | Session identity, operator attribution, SQLite write coordination, audit log, evidence conflicts, task claims, and team overlays provide local coordination metadata. |

## Residual Risks

- A malicious or careless actor with repository write access can edit local
  evidence files unless external repository controls prevent it.
- Deterministic validators are scoped; they do not prove semantic correctness,
  runtime behavior, or security.
- Test-evidence mapping does not prove test sufficiency.
- Static conformance does not grade live AI behavior.
- Operator attribution is local metadata, not authentication.
- Team mapping is local configuration, not team-membership proof.
- Audit logs are event records, not non-repudiation or tamper-proof storage.
- Evidence conflict detection flags review findings; it does not resolve them.
- Human reviewers can still approve weak evidence.
- Runtime monitoring, incident response, legal/regulatory determinations,
  deployment decisions, and release approval remain outside NAOS.
- A remote MCP implementation or tool list can change behind a stable endpoint;
  static offline descriptor review cannot observe or prevent that drift.

## Review Guidance

Before relying on a NAOS evidence pack:

1. confirm the selected profile and project readiness;
2. check validator report timestamps and evidence freshness;
3. review missing, not-configured, stale, advisory, experimental, and waived
   items;
4. confirm claims have local evidence and revalidation triggers;
5. inspect evidence conflicts, task claims, audit log summary, and
   session/operator metadata where team workflows are used;
6. treat external URLs and generated reports as references unless explicitly
   verified;
7. keep legal, regulatory, runtime, security, deployment, and operational
   decisions with accountable human owners.

See [docs/AUDIT_PLAYBOOK.md](AUDIT_PLAYBOOK.md) for a public deterministic audit
runbook and [docs/ASSURED_PROFILE_ACTIVATION.md](ASSURED_PROFILE_ACTIVATION.md)
for stricter profile activation guidance.
