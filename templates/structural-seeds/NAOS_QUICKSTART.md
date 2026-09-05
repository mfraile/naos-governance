# NAOS Installed Profile Guide

> Installed by `naos init`; the selected profile and exact active rows are
> recorded in `.ai/RULES.md`.

> Portable preview generation is exercised on Linux with Python 3.11. Managed
> `--activate` mutation is currently supported only on Darwin ARM64 with CPython
> 3.11–3.13; Linux, Windows, and other unsupported tuples refuse before target
> mutation. This installed guide does not widen that mutation boundary.

## Verify What's Active

The table below is the **Quickstart baseline reference**. If `.ai/RULES.md`
names Lite, Standard, or Assured, use that installed file—not this baseline
table—for the active rows and postures.

| Rule | What It Does | Rule posture |
| ------ | ------------- | :-----------: |
| **Rule 1** | Requires updates to canonical files; the hook rejects defined temporary/summary patterns | 🔴 blocking |
| **Rule 2** | Requires Git history instead of `archive/`; the hook rejects archive paths | 🔴 blocking |
| **Rule 7** | Evidence-first analysis — verify before assuming | 🟡 advisory |
| **Rule 10** | Requires source verification and project approval for copyleft-risk dependencies | 🔴 blocking |
| **Rule 11** | Search before creating — reduces duplicate-implementation risk | 🟡 advisory |

Posture labels state the expected policy/human-review treatment; they are not
a count of installed executable checks. The generated hook contains no licence
scanner, and `naos init` does not install the optional `license-scan.yml`
workflow. Rule 10 is not an automated block unless the adopter separately
configures and validates an enforcing consumer.

## Representative Core Files Installed

This is a tested orientation, not a complete manifest. The generated preview
directory is the exact inventory for your run; the CLI reports its total and
the first 20 paths.

<!-- generated-quickstart-inventory:start -->

```text
.ai/RULES.md                                    # selected profile's documented rules
CLAUDE.md                                        # Claude Code project context
.github/copilot-instructions.md                  # GitHub Copilot context
.githooks/pre-commit                             # profile-scoped checks and warnings
.github/instructions/function-discovery.instructions.md  # Anti-duplication guide
Makefile.naos                                    # Governance commands
NAOS_QUICKSTART.md                               # This file
```

<!-- generated-quickstart-inventory:end -->

## Core Pre-Commit Checks

The shipped hook is the executable source for commit-time behavior. In
all generated profiles its core checks include:

1. **Defined filename patterns** — rejects paths matching the hook's session-summary regex, root-level `temp_`/`draft_`, or `analysis_YYYY` outside `docs/exploration/`
2. **Archive folders** — blocks any `archive/` directory
3. **Documentation indexing** — warns when new docs are not accompanied by the docs index

The hook also performs other core bookkeeping/hygiene checks documented in the
hook itself. It does not scan dependency licences.

### Activate the Hook

```bash
# Option A: Symlink (recommended)
ln -sf ../../.githooks/pre-commit .git/hooks/pre-commit
chmod +x .githooks/pre-commit

# Option B: Git config (all hooks in .githooks/)
git config core.hooksPath .githooks
```

## What's Next

### When Your Project Purpose Changes

```bash
# Run connected adoption evidence with the profile named in .ai/RULES.md
naos adopt . --mode greenfield --profile <profile> --no-write-preview
naos context-challenge . --challenge-mode install --profile <profile>

# Compare this existing project with Lite (no transition is applied)
naos upgrade . --tier lite --dry-run

# Compare this existing project with Standard (no transition is applied)
naos upgrade . --tier standard --dry-run

# Compare this existing project with Assured (no transition is applied)
naos upgrade . --tier assured --dry-run

# Review bounded governance evidence when available
make -f Makefile.naos naos-plan-coherence
make -f Makefile.naos naos-evidence-sign
make -f Makefile.naos naos-evidence-verify
```

These review commands are evidence surfaces only. Plan coherence does not authorize,
sequence, approve, or resolve work. Evidence signing emits an adopter-signable envelope;
verification recomputes local tamper-evidence and reports signature-entry presence, but NAOS is not
a signer, signature validator, certifier, or compliance authority.

Profile comparisons and `--dry-run` are plan-only and write nothing to the
adopter project. For a valid managed project, persist an external immutable
plan, review its `plan_sha256`, and apply only that exact plan through the
separate digest-bound invocation. Do not use `naos init --activate` or legacy
`--force` as transition substitutes.

### Tier Comparison

| | Quickstart | Lite | Standard | Assured |
| -- | :----------: | :----: | :--------: | :-------: |
| **Rules** | 5 | 9 | 19 | 19 |
| **Blocking posture** | 3 | 3 | 13 | 19 |
| **Specs** | - | 3 | 10 | 10 |
| **Agents** | 1 | 4 | 7 | 7 |
| **Pre-commit scope** | core | core | core + Standard | core + Standard + Assured |
| **Purpose** | evaluation | reduced workflow | broader evidence | strongest configured evidence |
| **Behavioral scenario metadata** | - | - | 49 scenarios | 49 scenarios |
| **Semantic runtime** | not installed | not installed | not installed | not installed |

## Learn More

- **NAOS-Governance GitHub**: <https://github.com/mfraile/naos-governance>
- **Rules reference**: `.ai/RULES.md`
- **Profile-choice guide**: `make -f Makefile.naos naos-help`
