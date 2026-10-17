# NAOS Optional Spec-Kit Adapter

This directory is an optional convenience template for teams that already use
Spec-Kit-style `specs/<feature>/spec.md` files and want a repeatable way to relate
those specs to NAOS evidence, task context, claims, and gates.

It is not part of the NAOS core runtime. NAOS remains usable without Spec-Kit.
This adapter is not official Spec-Kit support, not official Microsoft support,
and not an endorsement by the Spec-Kit or Microsoft projects.

## What It Does

- Reads markdown recursively from one selected project-contained root: current
  `specs/` by default, with historical `.specify/specs/` fallback only when
  `specs/` is absent.
- Produces a dry-run mapping summary that links spec files to NAOS concepts:
  evidence packs, task context packs, task claims, gate review, and control-plane
  review.
- Helps reviewers decide which NAOS reports to generate for a spec-backed task.
- Leaves spec files unchanged by default.

## When To Use It

Use this adapter when:

- a project already keeps requirements or design notes under `specs/` or the
  historical `.specify/specs/` layout;
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
naos add setup-module spec_kit_adapter --profile standard --confirm
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

- selects `specs/` when present, otherwise historical `.specify/specs/` when
  present, and scans markdown recursively only under that selected root;
- reports an advisory `no_specs_found` for `specs` when neither root exists;
- writes nothing;
- prints a deterministic JSON summary when `--json` is provided.

When both roots exist, `specs/` wins. To select the historical root explicitly:

```bash
python naos/integrations/spec-kit/speckit_adapter.py --specs-root .specify/specs --dry-run --json
```

An explicit `--specs-root` is authoritative, including a different contained root.
Roots are never merged. A present `specs` symlink, including a broken link, does
not trigger legacy fallback. The selected root must resolve inside the project;
references resolving outside the project are not read. Report paths use POSIX
separators.

The upstream [feature creation script](https://github.com/github/spec-kit/blob/main/scripts/bash/create-new-feature.sh)
was observed on 2026-10-15 to create `specs/<feature>/spec.md`. This supports the
current default for that observed layout; mutable upstream main is not a pinned
installed version or proof of universal Spec-Kit compatibility. The adapter does
not inspect vendor state files or execute vendor scripts.

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

- `specs/**/*.md` or historical `.specify/specs/**/*.md`, or an explicit
  project-contained root; only the selected root is scanned recursively
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
