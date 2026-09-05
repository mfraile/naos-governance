# Greenfield And Brownfield Use

## Greenfield

Start with an optional no-write evaluation or the report-writing adoption
preview, then review the generated install set before explicit activation.
Profile selection is purpose-based rather than compulsory progression:

Portable preview generation is exercised on Linux with Python 3.11. Managed
`init --activate` mutation is currently supported only on Darwin ARM64 with
CPython 3.11–3.13; unsupported tuples refuse before target mutation. Use an
absent external `--preview-dir` for review when the active host is unsupported.

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
