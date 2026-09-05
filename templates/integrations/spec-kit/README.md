# NAOS Optional Spec-Kit Adapter

This directory is an optional convenience template for teams that already use
Spec-Kit-style `.specify/specs/*.md` files and want a repeatable way to relate
those specs to NAOS evidence, task context, claims, and gates.

It is not part of the NAOS core runtime. NAOS remains usable without Spec-Kit.
This adapter is not official Spec-Kit support, not official Microsoft support,
and not an endorsement by the Spec-Kit or Microsoft projects.

## What It Does

- Reads local `.specify/specs/*.md` files.
- Produces a dry-run mapping summary that links spec files to NAOS concepts:
  evidence packs, task context packs, task claims, gate review, and control-plane
  review.
- Helps reviewers decide which NAOS reports to generate for a spec-backed task.
- Leaves `.specify/` unchanged by default.

## When To Use It

Use this adapter when:

- a project already keeps requirements or design notes under `.specify/specs/`;
- a team wants NAOS evidence packs to point at spec artifacts;
- reviewers need a simple handoff from spec text to NAOS reports;
- greenfield setup, brownfield onboarding, or later adoption needs an optional
  bridge between Spec-Kit conventions and NAOS review evidence.

Do not use this adapter as proof that a spec is complete, approved, compliant,
or regulatory-ready.

## Install Options

The recommended NAOS path is review-first:

```bash
naos add setup-module spec_kit_adapter --profile standard --dry-run
naos add setup-module spec_kit_adapter --profile standard
```

The setup-module action copies this template into:

```text
naos/integrations/spec-kit/
```

It does not add Spec-Kit as a dependency, install packages, mutate `.specify/`,
or activate any hook.

## Dry-Run Mapping

If you copy the optional script, run it from the project root:

```bash
python naos/integrations/spec-kit/speckit_adapter.py --dry-run --json
```

By default the script:

- reads `.specify/specs/*.md`;
- writes nothing;
- prints a deterministic JSON summary when `--json` is provided.

To write a local mapping report explicitly:

```bash
python naos/integrations/spec-kit/speckit_adapter.py \
  --output naos/reports/spec_kit_mapping.json
```

The report is adopter-local review evidence only. It is not consumed by NAOS core
unless a team deliberately references it in evidence packs, control-plane review
items, or task context.

## Files Read And Written

Reads:

- `.specify/specs/*.md`
- optional NAOS files if reviewers cross-reference them manually

Writes by default:

- nothing

Writes only when explicitly requested:

- `naos/reports/spec_kit_mapping.json` or another `--output` path

## Relationship To NAOS

- Evidence packs can cite spec files as source artifacts.
- Task context packs can include spec references as bounded context.
- Task claims can coordinate work on spec-backed tasks.
- Gates can require evidence that a spec was reviewed.
- Control-plane review can route gaps, waivers, and residual risks.
- Pre-Implementation Alignment can use spec files as input for the intended
  user, problem statement, first vertical slice, interface assumptions, and
  evidence strategy.
- Agentic workflow review can surface gaps where spec-backed work lacks an
  alignment artifact, vertical-slice plan, or test/evidence strategy.

Deterministic repository evidence remains primary. Advisory findings may
challenge the mapping but do not replace source artifacts or human review.
The adapter can help map specs into NAOS task and evidence concepts, but it
does not prove requirements completeness or regulatory completeness.

## Non-Claims

This adapter does not claim:

- official Spec-Kit or Microsoft support;
- regulatory mapping completeness;
- proof of compliance;
- approval;
- certification;
- source-of-truth authority;
- automatic context injection;
- memory write-back;
- provider/model/API calls;
- required Spec-Kit dependency for NAOS core.
