---
name: naos-adoption-readiness
description: Guide Codex through NAOS greenfield and brownfield adoption readiness flows over an installed project-local kit.
metadata:
  naos-parameters: '[]'
---

# NAOS Adoption Readiness

## When to Use

Use this skill when preparing greenfield or brownfield projects for real NAOS
testing, onboarding, or adoption evidence generation.

## Greenfield

Use `--no-write-preview` when the user wants evaluation without report writes.
Use adoption `--dry-run` for a preview that may write reports when prerequisites
permit persistence. A blocked prerequisite can prevent reports; read its finding
IDs and next action before continuing. Then review the
generated install set before explicit `init --activate`. Profile selection is
purpose-based, not compulsory progression.

Managed activation targets native macOS, Ubuntu and Windows 11 with CPython
3.11–3.13. Implementation and qualification are separate. Use the exact
operation/candidate evidence in the platform manual; no blanket qualification
of subsequent source changes follows. Preview generation and package
installation do not qualify filesystem recovery. Use an absent external
`--preview-dir` for review. Consult `INSTALLATION_MANUAL.md` and
`docs/PLATFORM_ADAPTERS.md` for current platform limits.

```bash
PROFILE=standard
naos adopt . --mode greenfield --profile "$PROFILE" --dry-run --no-prompt
naos setup-recommendations --profile "$PROFILE"
naos add setup-module profile_baseline --profile "$PROFILE" --dry-run
if [ -f Makefile.naos ]; then
  make -f Makefile.naos validate-all
else
  echo "Makefile.naos not installed yet; keep this as dry-run adoption evidence."
fi
naos evidence-pack --profile "$PROFILE"
DASHBOARD_STDOUT="naos-dashboard-summary.json"
naos dashboard --profile "$PROFILE" --json > "$DASHBOARD_STDOUT"
echo "Review naos/DASHBOARD.md and naos/reports/dashboard_summary.json."
naos self-check --profile "$PROFILE"
naos package-reality --profile "$PROFILE"  # when dependency/package review is needed
naos api-symbol-reality --profile "$PROFILE"  # when API-symbol claims are declared
naos spec-pack-contract --profile "$PROFILE"
naos spec-pack-materialize . --profile "$PROFILE" --dry-run
naos ac-completion-evidence --profile "$PROFILE"  # when AC/SCEN completion is claimed
naos harness-trace-import --source naos/harness_traces/example.jsonl --profile "$PROFILE"  # when a local harness export exists
naos behavioral-readiness --profile "$PROFILE"
naos ai-code-provenance --profile "$PROFILE"  # when AI-assisted code provenance review is needed
naos compliance-posture --profile "$PROFILE"  # when adopter-declared compliance posture review is needed
naos adapter-coherence --profile "$PROFILE"
```

## Brownfield

Start with source-bound repository-intelligence planning. If the executed plan
finds it applicable, review and digest-confirm enrollment and activation, then
validate it before scaffolding or adoption reports. Brownfield `init --activate`
can create one all-or-nothing managed scaffold only where every selected
destination is genuinely absent; any existing collision is preserved and the
whole initial activation refuses. A project with valid managed provenance can
plan an existing-content profile transition without target writes, then apply
only that persisted plan and exact digest in a separate invocation. Legacy
`--force` requests refuse.

```bash
PROFILE=standard
naos repository-intelligence plan . --profile "$PROFILE" --component-mode baseline --output /tmp/naos-ri-enrollment.json
# If the plan requires enrollment, review it and confirm its exact digest:
naos repository-intelligence enroll . --profile "$PROFILE" --plan /tmp/naos-ri-enrollment.json --confirm-plan-sha256 PLAN_SHA256 --reviewer-id REVIEWER
naos repository-intelligence plan . --profile "$PROFILE" --component-mode baseline --output /tmp/naos-ri-activation.json
naos repository-intelligence apply . --profile "$PROFILE" --plan /tmp/naos-ri-activation.json --confirm-plan-sha256 PLAN_SHA256 --reviewer-id REVIEWER
naos repository-intelligence validate . --profile "$PROFILE"
naos init . --tier "$PROFILE" --archetype custom --backend static_only --activate
naos upgrade . --tier assured --plan-out /tmp/naos-upgrade-plan.json
naos upgrade . --apply-plan /tmp/naos-upgrade-plan.json --expect-plan-digest SHA256
naos adopt . --mode brownfield --profile "$PROFILE" --dry-run --no-prompt
naos setup-recommendations --profile "$PROFILE"
naos add setup-module profile_baseline --profile "$PROFILE" --dry-run
if [ -f Makefile.naos ]; then
  make -f Makefile.naos validate-all
else
  echo "Makefile.naos not installed yet; keep this as dry-run adoption evidence."
fi
naos evidence-pack --profile "$PROFILE"
DASHBOARD_STDOUT="naos-dashboard-summary.json"
naos dashboard --profile "$PROFILE" --json > "$DASHBOARD_STDOUT"
echo "Review naos/DASHBOARD.md and naos/reports/dashboard_summary.json."
naos ai-artifact-inventory . --profile "$PROFILE"
naos ai-artifact-reconcile . --profile "$PROFILE"
naos spec-pack-contract --profile "$PROFILE"
naos spec-pack-materialize . --profile "$PROFILE" --dry-run
naos spec-assembly-worksheet . --profile "$PROFILE"
naos package-reality --profile "$PROFILE"  # when dependency/package review is needed
naos api-symbol-reality --profile "$PROFILE"  # when API-symbol claims are declared
naos ac-completion-evidence --profile "$PROFILE"  # when AC/SCEN completion is claimed
naos harness-trace-import --source naos/harness_traces/example.jsonl --profile "$PROFILE"  # when a local harness export exists
naos ai-code-provenance --profile "$PROFILE"
naos compliance-posture --profile "$PROFILE"
naos memory-resource-inventory . --profile <profile>
naos mcp-resource-inventory . --profile <profile>
naos memory check
naos memory-readiness --profile <profile>
naos memory-access --profile <profile>
naos memory-use-policy --profile <profile>
naos behavioral-readiness --profile <profile>
naos adapter-coherence --profile <profile>
```

## Boundary

Adoption reports, `validate-all`, evidence packs, and dashboards are review
evidence and planning inputs. They do not approve maturity, certify readiness,
create baselines, mutate external tools, prove runtime safety, or guarantee MCP
access. `validate-all` runs installed tier-appropriate validators and may skip
checks not copied into the selected profile; assured may still block when
required evidence is missing.
Repository-intelligence search and graph results are source-bound retrieval
candidates, not requirements, semantic truth, approval, or evidence of absence.
AI Code Provenance packages declared local evidence for review; it does not
provide legal opinions, authorship or ownership proof, signing, release
authority, or publication authority. Compliance Posture packages
adopter-declared regulated-context metadata for review; it does not decide
regulatory applicability, prove compliance, certify, approve, sign, release, or
publish.
Package Reality is dependency/package review evidence only; it does not prove
package safety, malware absence, vulnerability absence, SBOM completeness,
provenance authenticity, supply-chain assurance, registry trust, or dependency
suitability.
API Symbol Reality is declared Python API-symbol review evidence only; it does
not import target modules or prove API semantics, runtime behavior, option
compatibility, endpoint behavior, package safety, or dependency suitability.
AC Completion Evidence is declared evidence-presence review only; it does not
prove AC correctness, implementation correctness, complete coverage, approval,
certification, compliance, or hallucination prevention.
Harness Trace Import is local-file trace normalization only; it does not
execute harnesses, capture runtime events, activate hooks, call providers,
write memory, approve work, certify outcomes, or prove behavior.
Memory setup and reports are declaration/review surfaces only: they do not
install Engram, configure clients, synchronize memory, call MCP, or prove live
provider, project-identity, or tool access. A policy-valid use-grade item remains
access-unverified until the separate active-client verification boundary is met.

## Current evidence preconditions

Diagnostic repository-intelligence plans retain findings but cannot authorize
enrollment/apply; their bundle and generation fields are null. Keep an
actionable plan's external `bundle.path` in a private evidence directory through
operation/recovery, and use an absent explicit output path. Older diagnostic
bundles do not authorize mutation. Follow `docs/ADOPTION_GUIDE.md` for details.

Complete readiness needs actual task/query/indexed-path inputs. Its opt-in
`--finalize-dependencies` mode supports Lite, Standard and Assured with current
L0–L2 and targets through L3. Lite's enabled L0 behavioral capability permits
inert inspection only; its missing-conformance warning and `not_ready` remain
visible. Integrated/native and installed-artifact qualification remain pending,
and finalization creates no evidence or review approvals;
default behaviour is unchanged. Follow `INSTALLATION_MANUAL.md` and the project's
`NAOS_QUICK_REFERENCE.md`. Supported configuration review uses the gate's emitted
subject and actual reviewed snapshot/evidence under
`docs/CONFIGURATION_POSTURE_REVIEW.md`; it does not waive stale sources,
unrelated findings or runtime enablement.
