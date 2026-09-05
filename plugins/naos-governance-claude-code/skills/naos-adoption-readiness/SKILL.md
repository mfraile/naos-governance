---
name: naos-adoption-readiness
description: Route Claude Code through NAOS greenfield or brownfield adoption readiness. Use when a user asks to install, initialize, adopt, evaluate, or test NAOS in a project.
---

# NAOS Adoption Readiness

Use this skill to guide Claude Code through project-local NAOS adoption.

## Steps

1. Confirm whether the current workspace has NAOS artifacts such as `naos/`,
   `Makefile.naos`, `schemas/naos/`, or `NAOS_CATALOG.md`.
2. If NAOS is missing, recommend the appropriate adoption dry-run:
   `naos adopt . --mode greenfield --profile standard --dry-run --no-prompt` or
   `naos adopt . --mode brownfield --profile standard --dry-run --no-prompt`.
   Explain that `--dry-run` writes declared review reports, while
   `--no-write-preview` writes neither reports nor activation files. Select a
   profile by purpose and review the generated install set. Before brownfield
   activation, run source-bound `repository-intelligence plan`; when applicable,
   review and digest-confirm enrollment and activation, then validate it.
   Brownfield `init --activate` may create a managed scaffold only when every
   selected destination is absent; any collision preserves and refuses the
   whole initial request. A valid already managed project uses a target-read-only
   `naos upgrade --plan-out` invocation followed by a separate
   `--apply-plan ... --expect-plan-digest ...` invocation. Legacy `--force`
   requests refuse.
   Portable preview generation is exercised on Linux with Python 3.11, while
   managed `init --activate` mutation is currently supported only on Darwin
   ARM64 with CPython 3.11–3.13. Unsupported tuples refuse before target
   mutation; use an absent external `--preview-dir` for review instead.
3. If NAOS is present, recommend orientation commands:
   `naos setup-recommendations`, `naos add setup-module MODULE_ID --dry-run`,
   `make -f Makefile.naos validate-all` only when `Makefile.naos` is installed,
   `naos evidence-pack`, set
   `DASHBOARD_STDOUT="naos-dashboard-summary.json"`, then run
   `naos dashboard --json > "$DASHBOARD_STDOUT"`, `naos self-check`, and
   `naos spec-pack-contract`, `naos spec-pack-materialize --dry-run`,
   `naos spec-assembly-worksheet`, `naos ac-completion-evidence` when AC/SCEN
   completion is claimed, `naos harness-trace-import --source <repo-local.jsonl>`
   when a local harness export exists, `naos package-reality`,
   `naos api-symbol-reality` when API-symbol claims are declared, and
   `naos adapter-coherence`. For memory-aware adoption, run read-only
   `naos memory check`, then `naos memory-readiness`, `naos memory-access`, and
   `naos memory-use-policy`; keep every config-only access field unverified.
   Include `naos behavioral-readiness` when the user
   is preparing or maintaining behavioral baseline evidence. Include
   `naos ai-code-provenance` when AI-assisted code provenance review evidence is
   needed.
4. Keep outputs project-local. Treat reports, `validate-all`, evidence packs,
   and dashboards as review evidence, not approval. `validate-all` runs
   installed tier-appropriate validators and may skip checks not copied into the
   selected profile; assured may still block when required evidence is missing.
   Treat repository-intelligence search and graph results as source-bound
   candidates, never requirements, semantic truth, approval, or evidence of
   absence.

## Boundaries

Do not activate hooks, write memory, call providers, create baselines, enable MCP,
mutate Claude settings, approve work, deploy, push, merge, certify, or claim proof
of compliance. Do not treat AI Code Provenance as legal opinion, authorship or
ownership proof, signing, release authority, or publication authority.
Do not treat Package Reality as package safety, malware absence, vulnerability
absence, SBOM completeness, provenance authenticity, supply-chain assurance,
registry trust, or dependency suitability.
Do not treat API Symbol Reality as API semantics, runtime behavior, option
compatibility, endpoint behavior, package safety, dependency suitability, or
proof that target modules were imported.
Do not treat AC Completion Evidence as AC correctness, implementation
correctness, complete coverage, approval, certification, compliance, or
hallucination prevention.
Do not silently edit host test, lint, package, import, or coverage configuration
to make a brownfield overlay fit; a detected collision must remain reviewable
and reversible.
Do not treat Harness Trace Import as harness execution, runtime capture, hook
activation, provider/API access, memory write-back, approval, certification,
compliance proof, or behavioral correctness proof.
Do not use these adoption commands to install Engram, configure clients,
synchronize memory, call MCP, or claim live provider, project-identity, or tool
access. Policy-valid use-grade memory remains access-unverified until the
separate active-client verification boundary is satisfied.
