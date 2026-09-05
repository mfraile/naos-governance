# Greenfield And Brownfield Plugin Flow

## Greenfield

1. Confirm the repository is the intended project root and select a profile by
   purpose rather than compulsory progression.
2. Use `--no-write-preview` for a no-side-effect evaluation or adoption
   `--dry-run` for a report-writing preview.
3. Review the generated install set, then activate explicitly.
4. Run setup recommendations, self-check, and adapter coherence.
5. Use learning-loop review before promoting project lessons.

Portable preview generation is exercised on Linux with Python 3.11. Managed
`init --activate` mutation is currently supported only on Darwin ARM64 with
CPython 3.11–3.13; unsupported tuples refuse before target mutation. Use an
absent external `--preview-dir` for review when the active host is unsupported.

Suggested commands:

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
naos self-check --profile standard
naos package-reality --profile standard
naos api-symbol-reality --profile standard  # when API-symbol claims are declared
naos ac-completion-evidence --profile standard  # when AC/SCEN completion is claimed
naos harness-trace-import --source naos/harness_traces/example.jsonl --profile standard  # when local harness traces are provided
naos ai-code-provenance --profile standard  # when AI-assisted code provenance review is needed
naos compliance-posture --profile standard  # when adopter-declared compliance posture review is needed
naos adapter-coherence --profile standard
```

## Brownfield

1. Plan source-bound repository intelligence before installation.
2. If applicable, review and digest-confirm enrollment and activation, then
   validate the generated SQLite/FTS state.
3. Use initial scaffold activation only when every selected destination is
   absent. For a valid already managed project, persist and review an external
   upgrade plan, then apply only its exact digest in a separate invocation.
4. Generate adoption evidence, inventory existing resources and AI artifacts,
   and review overlay compatibility before relying on generated guidance.
5. Inventory memory/MCP posture before claiming access.

Suggested commands:

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
# Or use --no-write-preview when no report writes are wanted.
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
naos adapter-coherence --profile standard
```

Upgrade planning and `--dry-run` are target-read-only. Apply revalidates the
persisted plan, exact digest, provenance, current content, and regenerated
sources; adopter-owned or modified paths are preserved and legacy `--force`
refuses. Generated repository-intelligence candidates do not reconstruct
project-specific specs or tasks without human review against current source.
