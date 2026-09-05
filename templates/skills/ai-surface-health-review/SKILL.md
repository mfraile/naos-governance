---
name: "ai-surface-health-review"
description: "Review and remediate NAOS AI-surface context-budget findings. Invoke when naos-ai-surface-budget reports warning/degraded posture or when slimming prompts, agents, instructions, workflows, skills, manuals, or quick references."
parameters: []
---

# Skill: AI-Surface Health Review

## When to Use

Use this skill when AI/governance instruction surfaces are too large, missing
anchors, drifting from an approved baseline, or being changed.

## Core Commands

```bash
make -f Makefile.naos naos-ai-surface-budget
# or
naos ai-surface-budget --profile <profile>
```

For source-kit checks, use:

```bash
python scripts/naos_ai_surface_budget.py --profile standard --json --no-default-baseline
```

## Interpretation

| Posture | Meaning | Action |
| --- | --- | --- |
| `healthy` | No required/blocking budget or anchor findings. | Keep report as evidence. |
| `warning` | Context pressure or baseline drift needs review. | Slim obvious duplication or record a justified residual warning. |
| `degraded` | Required/blocking budget, anchor, or drift finding exists. | Remediate before approving the surface or baseline. |

AI-surface health is deterministic context-health evidence. It does not prevent
hallucinations, score behavior, certify compliance, approve work, or replace
human review.

## Remediation Rules

1. Preserve anchors before removing text:
   - non-claim boundary;
   - human-review boundary;
   - deterministic/file-first boundary;
   - evidence hierarchy;
   - context-pressure guidance;
   - profile/gate boundary;
   - tool neutrality.
2. Reduce always-loaded files first: `AGENTS.md`, `CLAUDE.md`,
   `copilot-instructions.md`, `*.instructions.md`, Cursor rules, and common
   workflow prompts.
3. Move deep procedures into skills, quick references, docs, or generated
   reports. Keep always-loaded files as command routers and authority summaries.
4. Do not hide findings by raising thresholds unless the threshold itself is
   proven wrong after slimming and review.
5. Do not approve or rewrite `naos/baselines/ai_surface_health_baseline.json`
   automatically. Baseline updates need explicit human review.

## Safe Slimming Pattern

- Replace long repeated paragraphs with a short boundary summary plus links to
  `naos/NAOS_QUICK_REFERENCE.md` and the relevant skill.
- Keep command names visible, but group them by workflow instead of listing every
  command with full non-claims in every surface.
- Prefer one canonical explanation per topic. Other surfaces should point to it.
- Leave intentionally deep prompts, such as design elicitation prompts, intact
  unless their warning prevents practical use.

## Verification

After changes:

```bash
python scripts/naos_ai_surface_budget.py --profile standard --json --no-default-baseline
python -m pytest tests/test_ai_surface_budget.py tests/test_make_cli_tool_surface.py -q
python -m pytest tests/test_naos_add_setup_modules.py tests/test_setup_recommendations.py -q
```

For release-level changes, also run the full suite and greenfield/brownfield
activation smoke tests.

## Control-Plane Routing

If a warning or degraded finding remains intentionally, record the rationale in
control-plane review or residual-risk evidence. The finding stays visible until
a human reviewer accepts the tradeoff.
