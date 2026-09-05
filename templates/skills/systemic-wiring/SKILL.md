---
name: "systemic-wiring"
description: "Check systemic wiring consistency for any project change. Use when modules, APIs, schemas, config, docs, commands, tests, hooks, dependencies, events, migrations, infrastructure, AI-assisted changes, or observability surfaces change. Tool-neutral: usable from Claude Code, Codex, Gemini CLI, Cursor, Copilot, or by human reviewers."
parameters:
  - name: target
    description: "Changed surface: module, api, schema, event, migration, config, cli, docs, test, hook, dependency, access, infra, observability, network, ai-change, or all."
    required: false
    default: "all"
  - name: depth
    description: "Check depth: quick (triage only) or standard (full wiring check)."
    required: false
    default: "standard"
---

# Systemic Wiring

## When to Use

Use this skill when a change touches any surface that other parts of the
project depend on: modules, APIs, schemas, events, migrations, configuration,
documentation, CLI commands, build targets, hooks, tests, dependencies,
infrastructure, observability, or network contracts.

The goal is to catch orphan artifacts and broken cross-surface consistency
before they reach review or production.

## Context Budget

Before running this skill, check your project's context budget validator. This
skill is lightweight but may load large diffs, schemas, or test output during
Step 3. If budget is degraded or critical:

- Run Step 1 only (family identification) and report findings without Step 3
  commands.
- Scope Step 2 to affected families only — skip unrelated checks.
- Prefer `depth: quick` to limit output size.

## Steps

### Step 1: Identify Affected Families

Determine which of the following families the change touches. A single commit
can affect multiple families.

| Family | Examples |
|---|---|
| Module / component | Source files, classes, functions, packages |
| Public API | REST endpoints, GraphQL schema, RPC methods, SDK surface |
| Internal API | Inter-service calls, shared libraries, internal protocols |
| Schema | JSON Schema, OpenAPI, Protobuf, GraphQL SDL, AVRO, CloudEvents |
| Event / message contracts | Kafka topics, event schemas, consumer/producer wiring, schema registry, dead-letter queues |
| Database migrations | Migration files, ORM models, seed data, rollback scripts, index changes, stored procedures |
| Configuration | Environment vars, config files, feature flags, defaults |
| CLI / build | Commands, Makefile targets, scripts, entrypoints |
| Documentation | README, user/admin/operator manuals, tutorials, getting-started guides, quick reference cards, architecture diagrams (.mmd, .drawio, .puml, .svg), API docs (hand-written and auto-generated), changelogs, release notes, ADRs/RFCs/design docs, runbooks/incident playbooks, inline comments/docstrings |
| Tests | Unit, integration, e2e, contract, snapshot tests |
| Hooks / automation | Pre-commit hooks, CI steps, webhooks, event handlers |
| Dependencies | Package versions, lockfiles, vendored code, optional integrations |
| AI-assisted change | AI-generated code/deps, completion claims, AI surface files such as instructions, prompts, skills, agent manifests, and catalogues |
| Access / auth | Permissions, roles, authentication flows, secrets handling |
| Infrastructure as Code | Terraform/Pulumi/CloudFormation resources, IAM policies, network rules, secrets manager entries |
| Observability / ops | Metrics, alerts, dashboards, health check endpoints, SLOs, deployment manifests, runbooks |
| Network / service contracts | Service discovery registrations, circuit breaker config, load balancer rules, mTLS, retries |

List every affected family before proceeding.

If the project ships NAOS systemic-impact changed-path review, use the exact
stable changed-file list rather than asking the checker to infer a Git base:

```bash
naos systemic-impact \
  --profile <profile> \
  --changed-path <repo-relative-path> \
  --changed-path <another-path>
```

Keep canonical kit/development sources separate from files generated or
installed into adopter projects. A kit-only audit, plugin source, or maintainer
history file is not adopter output. A generated `.github/`, `naos/`, or Make
surface is not proof that its canonical source was reviewed.

### Step 2: Check for Orphan Artifacts and Contradictions

For each affected family, verify the change does not leave a dangling surface:

- **Module change**: Is the public API, schema, docs, and tests updated to
  match? Are callers updated or do they still reference the old interface?
  **Breaking change check**: does this remove or rename a public symbol,
  change a method signature, or alter return types? If yes — is there a
  deprecation notice, a migration path, and a major version bump?
- **API change**: Is the schema (OpenAPI, Protobuf, etc.) updated? Is the
  client SDK, docs, and contract test updated? Are consumers notified?
  **Breaking change check**: does this remove an endpoint, rename a field,
  change a required parameter, or alter an auth requirement? If yes — is there
  a versioned path (e.g. `/v2/`), a deprecation header, and a migration guide?
- **Schema change**: Is the validator, migration, and dependent code updated?
  Are generated artifacts (clients, forms, serializers) regenerated?
- **Config change**: Is the default, the docs, and the validation updated? Is
  the change backward-compatible or is a migration path provided?
- **CLI / build change**: Does help text match the implementation? Do existing
  Makefile targets and CI steps still dispatch correctly? **Breaking change
  check**: does this remove a flag, rename a subcommand, change positional
  argument order, or alter exit codes? If yes — is there a deprecation notice
  and a changelog entry?
- **Docs change**: Does the docs change contradict current code behavior? Is
  the change consistent with the changelog, release notes, and version? Are
  architecture diagrams updated to reflect structural changes (new services,
  removed components, changed data flows)? Are quick reference cards and
  cheat sheets consistent with current CLI flags, API endpoints, and config
  options? Are tutorials and getting-started guides runnable against the
  current codebase — not a stale version? Are auto-generated docs (Sphinx,
  TypeDoc, MkDocs, Swagger UI) regenerated after API or code changes, not
  left as stale cached output? Are runbooks and incident playbooks updated
  when the endpoints, commands, env vars, or escalation paths they reference
  change? Are ADRs and RFCs updated or superseded when the decision they
  record is reversed or evolved?
- **Test change**: Does the test still cover the behavior it claims to cover?
  Is coverage maintained or documented as a known gap?
- **Hook / automation change**: Is the hook reviewed as operational code? Does
  it introduce silent behavior (auto-push, auto-deploy, context injection)?
- **Dependency change**: Is the lockfile updated? Is the change declared in the
  changelog? Are optional integrations clearly marked as non-required?
- **AI-assisted change**: Does every newly added dependency exist in the
  lockfile and, when registry access is explicitly permitted, in the official
  package registry? Do imported packages map to declared dependencies? Does
  every API, method, class, option, or endpoint referenced by the change exist
  in the pinned dependency version or project source? Is every completion claim
  tied to a reproducible command, test output, validator report, or review
  evidence rather than narrative? If AI surface files changed, do catalogues,
  tier lists, plugin/adopter copies, validators, and docs still agree?
- **Access / auth change**: Is the new behavior enforced in code, not only
  documented? Are tests covering the access path?
- **Event / message contract change**: Is the event schema (AVRO, Protobuf,
  CloudEvents) versioned or backward-compatible? Are all consumers of this
  topic updated? Is the schema registry entry updated? Are dead-letter queue,
  retry policy, and consumer group config consistent with the new schema?
- **Database migration change**: Does the migration file match the ORM model
  update? Is there a rollback migration? Are seed data and fixtures updated?
  Are dependent queries, views, or stored procedures updated? Is the migration
  tested against a non-production database?
- **Infrastructure as Code change**: Does the IAM policy change follow
  least-privilege? Are dependent resources (VPCs, subnets, security groups,
  secrets manager entries) updated? Is the state file conflict-free? Is the
  plan reviewed in a non-production environment before apply?
- **Observability / ops change**: Does a new endpoint, service, feature, or
  event have a corresponding metric, alert, and dashboard entry? Is the health
  check endpoint implemented, wired into the deployment manifest, and
  registered with the load balancer or service mesh? Are SLOs and error budgets
  updated? Is the runbook updated?
- **Network / service contract change**: Is service discovery registration
  updated? Is the circuit breaker threshold calibrated for the new behavior?
  Are retry policies, timeouts, and backoff settings consistent across callers?
  Are mTLS certificates valid and rotation scheduled?

Surface any contradiction as a wiring finding with the specific file pair that
conflicts.

### Step 3: Run Available Project Checks

Run the checks the project provides. Adapt to the actual toolchain.

```bash
# Tests
# e.g.: pytest, npm test, go test ./..., cargo test, make test

# Linter / static analysis
# e.g.: ruff check ., eslint ., golangci-lint run, make lint

# Type checker (if applicable)
# e.g.: mypy ., tsc --noEmit, pyright

# Schema validation (if applicable)
# e.g.: openapi-lint, buf lint, jsonschema validate

# Dependency audit (if applicable)
# e.g.: pip audit, npm audit, cargo audit

# AI-assisted dependency/API reality check (if applicable and permitted)
# e.g.: compare changed imports to lockfiles; verify referenced symbols against pinned installed packages

# Event schema validation (if applicable)
# e.g.: buf lint, buf breaking, avro-tools compile, confluent schema-registry check

# Database migration validation (if applicable)
# e.g.: alembic check, django migrate --check, flyway validate, liquibase validate

# Infrastructure as Code validation (if applicable)
# e.g.: terraform validate && terraform plan, pulumi preview, cfn-lint, checkov

# Deployment manifest / observability validation (if applicable)
# e.g.: helm lint, kubectl apply --dry-run=client, kustomize build | kubectl apply --dry-run

# Check for uncommitted changes
git diff --check
git status --short
```

For a governed card or bounded change, run changed-path review once the diff is
stable. Record one human disposition for every emitted obligation in the
project's review record, then run:

```bash
naos systemic-impact \
  --profile <profile> \
  --changed-path <path> \
  --review-record <review.yaml> \
  --require-resolved
```

Use `updated`, `reviewed_no_change`, or `not_applicable` only with rationale
and evidence. Preserve `update_required` and `unresolved` rather than writing a
false closure. If resolving an obligation changes another file, refreeze the
path list and repeat. This is deterministic routing and human review evidence,
not semantic-completeness proof or approval.

The review record binds to the complete exact changed-path set and carries one
decision per unique affected destination. The report retains all contributing
paths so aggregation does not hide why the destination was routed.

If no automated checks exist for a given family, note that as a gap and
recommend adding one.

### Step 4: Surface Findings with Concrete Next Actions

Report each finding with:

- **Surface**: which family and which files are affected.
- **Finding type**: orphan artifact, contradiction, missing update, stale
  reference, or coverage gap.
- **Evidence**: file:line citation.
- **Next action**: what specifically needs to be updated, added, or removed.
- **Severity**: blocker (breaks build, breaks tests, breaks contract) or
  advisory (polish, consistency, future risk).

Use this format:

```markdown
## Wiring Finding: <short title>

- **Surface**: docs / README.md
- **Finding type**: contradiction
- **Evidence**: README.md:42 claims `--flag` is supported; cli.py:87 does not
  implement it.
- **Next action**: Either implement the flag or remove the claim from README.
- **Severity**: Blocker — public documentation claims behavior that does not exist.
```

## Boundaries

Do not silently rewrite unrelated artifacts. If the change reveals a gap in an
unrelated surface, surface it as a finding — do not fix it without an explicit
instruction to do so.

Do not treat the absence of a failing test as proof of correctness. A missing
test is a coverage gap, not a clean bill of health.

Do not treat hook output, memory, or chat history as source authority. Current
source files and deterministic command output outrank advisory recall.

## Cross-Tool Usage

This skill is tool-neutral:

- **Claude Code**: load as a project skill; invoke via `/systemic-wiring`.
- **Codex**: provide this file as repo context; Codex runs the steps
  autonomously and reports findings.
- **Gemini CLI**: provide as context; use terminal for commands.
- **Cursor**: load as a rules/instructions file; use terminal for Step 3.
- **Copilot / VS Code**: provide as a prompt file; run Step 3 in terminal
  tasks.
- **AGENTS.md manifests**: include as a referenced consistency check for any
  coding agent that reads repo-level instructions.
- **Human reviewers**: follow steps 1–4 manually as a pre-merge checklist.

No specific AI assistant, IDE, MCP server, or model provider is required.

## When Not To Use

- Narrow single-file typo fix with no cross-surface impact.
- Changes that are entirely internal implementation with no public API, schema,
  event, migration, docs, config, infra, or observability surface touched.

## Escalation to forensic-audit

Escalate from this skill to `forensic-audit` when ANY of the following is true:

| Condition | Reason |
|---|---|
| 5 or more families are affected by a single change | Systemic wiring check is no longer sufficient triage |
| A breaking change is detected in a public API, SDK, CLI, or event schema | Requires adversarial pass + FP hunter to confirm scope and impact |
| A security or access-control family is affected | Requires adversarial ghost hunt for overclaims and missing enforcement |
| An AI-assisted change adds dependencies, touches security surfaces, changes AI surface files, or ships completion claims without reproducible evidence | Requires AI-generation ghost hunt for hallucinated packages, fabricated APIs, stale catalogues, and unverified claims |
| A release candidate or distribution package is being reviewed | Triage is insufficient for release gates |
| IaC changes affect production IAM policies or network topology | Requires full IaC drift analysis |
| A previous wiring check found blockers that were marked "fixed" | Requires confirmation pass against the fix, not just re-triage |
| A retracted or previously disputed finding is being reopened | Requires retractions-ledger review and differently framed confirmation |
| The brief explicitly requires a release-readiness or compliance verdict | Triage cannot produce a verdict; only forensic-audit can |

## Related Skills

These specialized skills cover domain-specific HOW (recipes, patterns) while
systemic-wiring covers WHETHER the surfaces are consistently wired. They are
complementary, not overlapping:

- `cookbook-migrations` — how to write safe, idempotent migrations
- `cookbook-observability` — how to set up AI/agent session tracing
- `cookbook-docker` — how to write secure Dockerfiles
- `cookbook-configs` — how to manage config keys correctly
- `cookbook-tests` — how to write reliable test cases
- `cookbook-frontend` — how to structure frontend API calls and components
- `forensic-audit` — deep multi-pass release-readiness and security audit
