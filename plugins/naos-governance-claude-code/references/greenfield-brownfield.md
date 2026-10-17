# Greenfield And Brownfield Use

## Greenfield

Start with an optional no-write evaluation or the report-writing adoption
preview, then review the generated install set before explicit activation.
Profile selection is purpose-based rather than compulsory progression:

Managed activation targets native macOS, Ubuntu and Windows 11 with CPython
3.11–3.13. Consult `INSTALLATION_MANUAL.md` and `docs/PLATFORM_ADAPTERS.md` for
scoped native evidence and remaining final-candidate qualification. Preview
generation and package installation do not qualify filesystem recovery. Use an
absent external `--preview-dir` for review.

Read the generated root `CLAUDE.md` import of `AGENTS.md` and its selected-profile
host routes; read referenced portable files when manual invocation is needed.
Review the source-bound `.gitignore` exclusions for `/.naos/upgrade-v1/` and
`/.naos/local/managed-content-v3/`, while keeping `/.naos/managed-content/v3/`
portable provenance versionable. Preserve the private stores and any existing
unmanaged `.gitignore`; reconcile its rules explicitly before committing.
Follow `INSTALLATION_MANUAL.md#git-eligibility`. Hook execution and configuration
need separate review under `docs/HOOK_ACTIVATION.md`; these checks do not
activate hooks or translate host permissions.

```bash
naos adopt . --mode greenfield --profile standard --dry-run --no-prompt
naos setup-recommendations --profile standard
naos add setup-module profile_baseline --profile standard --dry-run
if [ -f Makefile.naos ]; then
  make -f Makefile.naos validate-all
else
  echo "Makefile.naos not installed yet; keep this as dry-run adoption evidence."
fi
naos evidence-pack --profile standard
DASHBOARD_STDOUT="naos-dashboard-summary.json"
naos dashboard --profile standard --json > "$DASHBOARD_STDOUT"
echo "Review naos/DASHBOARD.md and naos/reports/dashboard_summary.json."
naos package-reality --profile standard
naos api-symbol-reality --profile standard  # when API-symbol claims are declared
naos ac-completion-evidence --profile standard  # when AC/SCEN completion is claimed
naos harness-trace-import --source naos/harness_traces/example.jsonl --profile standard  # when local harness traces are provided
```

Confirm generated candidates before removing `--dry-run` or enabling optional
modules.

## Brownfield

Start with source-bound repository-intelligence planning. When the executed plan
finds it applicable, review and digest-confirm enrollment and activation, then
validate it. Brownfield `init --activate` can create one managed scaffold only
where every selected destination is absent; preserve and refuse the entire
initial request on any collision. A valid already managed project can plan a
profile transition without target writes, then apply only that persisted plan
and exact digest in a separate invocation. Legacy `--force` requests refuse.

```bash
naos repository-intelligence plan . --profile standard --component-mode baseline --output /tmp/naos-ri-enrollment.json
# If enrollment is required, review and confirm the exact plan digest:
naos repository-intelligence enroll . --profile standard --plan /tmp/naos-ri-enrollment.json --confirm-plan-sha256 PLAN_SHA256 --reviewer-id REVIEWER
naos repository-intelligence plan . --profile standard --component-mode baseline --output /tmp/naos-ri-activation.json
naos repository-intelligence apply . --profile standard --plan /tmp/naos-ri-activation.json --confirm-plan-sha256 PLAN_SHA256 --reviewer-id REVIEWER
naos repository-intelligence validate . --profile standard
naos init . --tier standard --archetype custom --backend static_only --activate
naos upgrade . --tier assured --plan-out /tmp/naos-upgrade-plan.json
naos upgrade . --apply-plan /tmp/naos-upgrade-plan.json --expect-plan-digest SHA256
naos adopt . --mode brownfield --profile standard --dry-run --no-prompt
naos setup-recommendations --profile standard
naos add setup-module profile_baseline --profile standard --dry-run
if [ -f Makefile.naos ]; then
  make -f Makefile.naos validate-all
else
  echo "Makefile.naos not installed yet; keep this as dry-run adoption evidence."
fi
naos evidence-pack --profile standard
DASHBOARD_STDOUT="naos-dashboard-summary.json"
naos dashboard --profile standard --json > "$DASHBOARD_STDOUT"
echo "Review naos/DASHBOARD.md and naos/reports/dashboard_summary.json."
naos ai-artifact-inventory . --profile standard
naos ai-artifact-reconcile . --profile standard
naos package-reality --profile standard
naos api-symbol-reality --profile standard  # when API-symbol claims are declared
naos ac-completion-evidence --profile standard  # when AC/SCEN completion is claimed
naos harness-trace-import --source naos/harness_traces/example.jsonl --profile standard  # when local harness traces are provided
naos ai-code-provenance --profile standard
naos compliance-posture --profile standard
naos memory-resource-inventory . --profile standard
naos mcp-resource-inventory . --profile standard
```

Treat unknowns and collisions as review findings. Do not silently overwrite
active project files, IDE settings, hooks, or memory configuration.
Repository-intelligence candidates do not reconstruct project-specific specs or
tasks without human review against current source.

## Current evidence preconditions

For Lite and higher, refresh `naos opencode-config-hygiene --profile <profile>`
before standalone `naos control-plane-review`; CI readiness and self-check use
that order. A shared `AGENTS.md` alone does not opt into OpenCode review.
It is included when review is enabled/declared or OpenCode-specific local
configuration or `.opencode/` surfaces exist; actual OpenCode surfaces still
require review with a disabled declaration. Review the actual local surfaces
before explicitly enabling
`naos/opencode_config_hygiene.yaml`; keep runtime, provider, model, MCP, memory,
hook and tool-mutation permissions disabled. Scheduling does not clear missing,
malformed or adverse evidence. Follow `INSTALLATION_MANUAL.md`; this is static
review guidance, not approval or native platform qualification.

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
