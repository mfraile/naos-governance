# Integral Tutorial — Quickstart from Scratch

> _Tested with NAOS kit v1.1.0 candidate · Last verified 2026-09-05_

Quickstart is a bounded evaluation profile. It provides minimal guardrails, a
named read-only research route, and explicit profile-aware non-applicability.
It does not reproduce the Lite or Standard task/spec workflow.
Quickstart does not install CI by default; add CI only through an explicit,
reviewed adoption choice.

Set one absent project path and one absent external preview path for the whole
tutorial:

```bash
PROJECT=/path/to/your/new-project
PREVIEW=/tmp/naos-quickstart-preview
```

## 1. Generate and review the install set

```bash
naos-governance init "$PROJECT" --new \
  --tier quickstart \
  --preview-dir "$PREVIEW"
```

This writes only the preview directory. Review:

- `$PREVIEW/naos/profile_generated_surface_contract.json`;
- `$PREVIEW/.github/agents/naos-research.agent.md`;
- `$PREVIEW/naos/research/RECORD_TEMPLATE.yaml`;
- `$PREVIEW/schemas/naos/research_record.schema.json`; and
- the files listed as required or prohibited for `quickstart` in the generated
  contract.

## 2. Activate explicitly

> Native macOS ARM64/APFS, Ubuntu x86_64/ext4 and Windows 11 x86_64/NTFS
> have recorded Python 3.11–3.13 installation checks and selected workflow and
> recovery evidence. These are separate checks: qualification for an activation,
> update or receiving operation depends on its named route and evidence, not
> only the operating system. Linux aarch64 is not qualified. Before activation,
> check the [platform evidence and limits](../PLATFORM_ADAPTERS.md).
> Preview generation and package installation
> do not qualify filesystem recovery. On unsupported hosts, review an absent
> external `--preview-dir` without activating.

```bash
naos-governance init "$PROJECT" --new --tier quickstart --activate
```

Activation is separate from adoption evidence and install-set review. It does
not prove the project is mature, effective, secure, or usable.

## 3. Preview adoption evidence without writes

```bash
cd "$PROJECT"
naos adopt . \
  --mode greenfield \
  --profile quickstart \
  --no-write-preview
```

`--no-write-preview` writes no reports or activation files. By contrast,
`--dry-run` writes declared NAOS report artifacts but does not activate or
overwrite protected project files.

## 4. Verify the actual profile contract

```bash
naos doctor
make -f Makefile.naos gov-refresh
make -f Makefile.naos naos-readiness
```

For Quickstart, both Make targets exit successfully and print
`not_applicable` plus the supported alternative `naos doctor`. They do not run
the absent Lite/Standard governance-refresh pipeline.

The named `@naos-research` agent is available. It gathers read-only evidence
and can prepare a candidate record from
`naos/research/RECORD_TEMPLATE.yaml`. Quickstart does not generate
`/naos-design`, `@naos-plan`, `@naos-implement`, `@naos-review`, or
`/naos-task-complete`; stop at the research candidate and human review, or
deliberately select Lite if the project needs that real-project workflow.

## 5. Make one bounded project change

Initialize Git in the new project before reviewing Git diffs or committing.
Configure your Git author identity if needed before making a commit.

```bash
git init
```

1. State the exact file and behavior to change.
2. Inspect current source and tests.
3. Make the smallest coherent edit.
4. Run the project's own canonical test command.
5. Review the diff and commit. The copied hook is inactive until you explicitly
   review and integrate it from the Git worktree root. Preserve existing hook
   paths and default hooks; follow the Installation Manual's hook-integration
   boundary before claiming that a commit ran NAOS checks.

Quickstart's hook and research record provide bounded governance evidence.
They do not create a task lifecycle, approve a merge, admit evidence, or replace
repository and human authority.

## 6. Select another profile only if the purpose changes

Lite is the purpose-fit choice when the project needs generated research,
design/specification, planning, implementation, review, and native task
completion surfaces. This is a deliberate profile choice, not compulsory
progression and not proof of maturity.

→ [Integral Tutorial: Lite from Scratch](./INTEGRAL_TUTORIAL_LITE_FROM_SCRATCH.md)
