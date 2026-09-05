# Professional Adoption Engine

> _Tested with NAOS kit v1.0.0+ · Last verified 2026-06-26_

Use the professional adoption engine when you want a connected adoption record instead of a pile of isolated setup commands. It is deterministic, file-first, and local. It produces review evidence and human decision points; it does not approve work, silently overwrite files, call providers, write memory, prove secure code, prove runtime safety, or prove legal or regulatory compliance.

Core rule: challenge before build, evidence before confidence, and no edits during challenge.

## Natural-Language Router

Use the workflow router when an adopter starts with intent rather than command
names:

| User says... | Route to... | Do not hide... |
| --- | --- | --- |
| "I have a new project" | Greenfield path | whether the user wants a no-write evaluation or report-writing preview, then the generated install set and explicit activation |
| "I have an existing repo" | Brownfield path | inventories, candidate requirements, gaps, and human disposition |
| "I am unsure if this setup is safe" | challenge commands | assumptions, contradictions, missing information, and residual risks |
| "What should I decide next?" | install decision record | profile choice, module activation, artifact disposition, and candidate promotion |

Prompts and agents may recommend the next explicit command. They must not
silently run adoption, overwrite files, activate hooks, approve candidates, or
turn reports into authority.

## Greenfield Path

Use one visible preview → install-set review → activation route. A no-write
evaluation is optional and distinct from the report-writing preview:

```bash
naos adopt . --mode greenfield --profile standard --no-write-preview
naos adopt . --mode greenfield --profile standard --dry-run
naos preflight . --profile standard
naos intake . --answers naos/intake_answers.yaml --profile standard
naos install-plan . --profile standard
naos context-challenge . --challenge-mode install --profile standard
naos plan-challenge . --challenge-mode implementation-plan --profile standard
naos decision-probe . --challenge-mode decision --profile standard
naos planning-gate-review . --challenge-mode gate --profile standard
naos install-decision-record . --profile standard
naos-governance init . --tier standard --archetype custom --backend static_only --preview-dir .naos-preview
# Review .naos-preview and the install/adoption reports.
naos-governance init . --tier standard --archetype custom --backend static_only --activate
```

`--no-write-preview` writes neither reports nor activation files. Adoption
`--dry-run` writes only declared NAOS report artifacts and does not activate or
change protected project files. `init` without `--activate` writes the generated
install set to the preview directory; the final explicit `--activate` performs
installation/activation after review.

Equivalent Make wrappers are available in generated adopters:

```bash
make -f Makefile.naos naos-preflight
make -f Makefile.naos naos-intake ANSWERS=naos/intake_answers.yaml
make -f Makefile.naos naos-install-plan
make -f Makefile.naos naos-context-challenge
make -f Makefile.naos naos-plan-challenge
make -f Makefile.naos naos-decision-probe
make -f Makefile.naos naos-planning-gate-review
make -f Makefile.naos naos-install-decision-record
make -f Makefile.naos naos-adopt MODE=greenfield
```

## Brownfield Path

Brownfield adoption should inventory before planning:

```bash
naos existing-resource-inventory . --profile standard
naos ai-artifact-inventory . --profile standard
naos memory-resource-inventory . --profile standard
naos mcp-resource-inventory . --profile standard
naos repo-context-challenge . --mode brownfield --profile standard
naos plan-challenge . --challenge-mode implementation-plan --profile standard
naos decision-probe . --challenge-mode decision --profile standard
naos brownfield-baseline . --profile standard
naos requirements-reconstruct . --profile standard
naos traceability-gap-register . --profile standard
naos install-decision-record . --profile standard
naos adopt . --mode brownfield --profile standard --dry-run
```

Inspect the `descriptor_review` block in
`naos/reports/mcp_resource_inventory.json`. An exact shipped repo-local Figma
remote VS Code workspace rule
may produce `allowlisted_pending_activation`; this means only that sanitized
declaration metadata matches a risk-owner policy digest. You must still make a
separate decision to configure or start a client, authenticate externally,
invoke any tool, or permit writes. A changed endpoint, transport, field set,
client/config shape, policy digest, the desktop endpoint, and unknown servers
all remain review-required. The command performs no MCP or Figma call.

`naos adopt --dry-run` is the preview form for the orchestrator. It writes or
refreshes only deterministic NAOS report artifacts, prints what phases would
run, and does not activate hooks, CI, providers, memory write-back, MCP runtime,
external connectors, or protected-file changes.
`naos adopt --no-write-preview` evaluates the same phases without writing those
reports or any activation files.
Report-writing adoption requires secure directory-descriptor-relative creation
and replacement. A host without that primitive fails closed before report-path
creation; use `--no-write-preview` there. The portable report writer is not
treated as equivalent strict parent-swap protection.

The challenge commands in this release share one generic file-path presence
check. They enumerate local paths but do not read source or document contents.
`plan-challenge`, `decision-probe`, and `planning-gate-review` do not parse or
evaluate a plan, decision record, gate state, or prior report content. Their
reports are review prompts, not substantive gate evaluation or approval.

Candidate requirements use confidence classes:

- `confirmed_by_existing_spec`
- `supported_by_docs`
- `inferred_from_code`
- `inferred_from_tests`
- `hypothesized_requires_review`

Candidates are not requirements until a human reviewer promotes, rejects, or defers them.
Candidate requirements remain candidates until that review happens.
Candidate NFRs may be suggested from controlled evidence such as security or
privacy docs, CI/security-tooling configuration, auth/crypto/key-management
source indicators, tests, workflows, and explicit intake answers. They do not
prove security, compliance, runtime safety, or requirements completeness.

## Reconciliation

Use reconciliation reports to record intended disposition without silent overwrites:

```bash
naos ai-artifact-reconcile . --profile standard --decision review_required
naos memory-resource-reconcile . --profile standard --decision review_required
```

Decision states are `keep`, `merge`, `replace`, `quarantine`, `create`, and `review_required` for AI artifacts. Memory/MCP reconciliation records posture decisions such as `connect`, `reuse`, `repair`, `new`, `disabled`, `deferred`, and `review_required`. Reports remain advisory until reviewed.

AI artifact inventory reports include owner/source classification, compatibility
status, conflict category and reason, the compared NAOS surface, profile impact,
and a recommended decision. Reconciliation records the selected decision but
does not overwrite, merge, delete, quarantine, or create files silently.

For operator-led acceptance tests, commands that collect decisions can be run in
interactive mode:

```bash
naos intake . --interactive --profile standard
naos install-plan . --interactive --profile standard
naos ai-artifact-reconcile . --interactive --profile standard
naos memory-resource-reconcile . --interactive --profile standard
naos context-challenge . --interactive --challenge-mode install --profile standard
```

## Report Outputs

The adoption engine writes reports under `naos/reports/`, including:

- `preflight_report.json`
- `intake_report.json`
- `install_plan.json`
- `existing_resource_inventory.json`
- `ai_artifact_inventory.json`
- `memory_resource_inventory.json`
- `mcp_resource_inventory.json`
- `brownfield_baseline.json`
- `candidate_requirements.json`
- `traceability_gap_register.json`
- `install_decision_record.json`
- `context_challenge_report.json`
- `repo_context_challenge_report.json`
- `plan_challenge_report.json`
- `decision_probe_report.json`
- `adoption_summary.json`

Dashboard and evidence-pack summaries treat these as related review evidence. If a report is missing, treat that as a known adoption gap rather than guessing.

## Human Boundary

The human reviewer remains responsible for profile choice, module activation, existing artifact disposition, memory/MCP posture, candidate promotion, residual risk, and next action. The engine keeps facts, assumptions, unknowns, conflicts, candidates, and decisions visible so the adoption path stays reviewable.
