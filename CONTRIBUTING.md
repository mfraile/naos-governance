# Contributing to NAOS

This document is for people contributing **to the NAOS-Governance kit itself** — proposing new rules, ADRs, validators, scenarios, or kit-level documentation. For the contribution guide that ships *into adopter projects* via `naos init`, see [`templates/structural-seeds/CONTRIBUTING.md`](templates/structural-seeds/CONTRIBUTING.md); that is a different file with a different audience.

## Before opening an issue or PR

1. Read [`README.md`](README.md) and [`docs/INDEX.md`](docs/INDEX.md) — most questions have answers there.
2. Check [`ROADMAP.md`](ROADMAP.md) — it gives the public direction and explicit non-goals. Detailed maintainer planning is not part of the public repository surface.
3. License: by contributing, you agree your contributions will be licensed under the Apache License 2.0 (see [`LICENSE`](LICENSE)) under the standard Developer Certificate of Origin process.

## Contribution license, copyright, and compensation

NAOS-Governance is published under Apache License 2.0 under the standard Developer Certificate of Origin process:

- You retain copyright in your own contributions.
- You license your contributions to this project under Apache License 2.0, the same license that governs the rest of the kit.
- Your contribution does not create employment, contractor, partnership, agency, royalty, commission, revenue-share, support, maintenance, or bounty obligations.
- Contributions are voluntary and unpaid.

The original kit copyright belongs to Marlon Fraile. Third-party contributions remain attributable to their contributors through the git history and applicable copyright notices.

This file is a project policy summary, not legal advice.

## Developer Certificate of Origin

NAOS-Governance uses the standard Developer Certificate of Origin (DCO) for
contributions. Add a `Signed-off-by` line to each commit:

```text
Signed-off-by: Your Name <you@example.com>
```

Use `git commit -s` to add it automatically. By signing off, you certify the
standard DCO 1.1 statement published by the Linux Foundation:
<https://developercertificate.org/>.

## How to file an issue

Use one of the four issue templates under [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/):

| Template | When to use |
| --- | --- |
| `bug-report` | The kit does not behave as documented |
| `roadmap-decision` | You want to comment on public roadmap direction, non-goals, or release priorities |
| `threat-model` | You want to add a threat, dispute a residual-risk rating, or report a real bypass observed in practice |
| `audit-playbook` | You have feedback on public compliance, assurance, or audit-facing guidance |

For security vulnerabilities: do **not** open a public issue. See [`SECURITY.md`](SECURITY.md) for coordinated disclosure.

## Pull request expectations

The kit governs other projects; it must hold itself to its own standards. Before opening a PR:

1. **Run the validators** (those that apply to the kit itself):

   ```bash
   python scripts/validators/validate_docs_consistency.py
   python scripts/validators/validate_tutorial_consistency.py
   python -m unittest discover -s tests -p 'test_*.py'
   git diff --check
   test ! -d naos
   ```

   The `unittest discover` command above is the canonical implementation-suite
   command. Pytest is optional for contributors; when installed, its default
   collection is bounded by `pyproject.toml` to `tests/test_*.py`. Validate that
   boundary with `python -m pytest --collect-only -q` rather than treating files
   under `dev/`, `templates/`, or `plugins/` as implementation tests.

2. **Update affected documentation** in the same PR — `ROADMAP.md`, `docs/INDEX.md`, `docs/GLOSSARY.md`, or other public docs if you changed public behavior or vocabulary.
3. **Keep commit messages factual** — what changed, why, and which files. The branch's commit history is the kit's own audit trail.
4. **Respect the v1.x compatibility rule**: changes on the v1.x line must preserve the portable file-first install model. Anything requiring a mandatory structured substrate, incompatible command/agent renaming, archetype layout changes, or a rewritten installation flow requires an explicitly reviewed compatibility decision and may belong in v2.0.

## Proposing a new rule

Rules in `.ai/RULES.md` are crystallised from instincts. To propose a new rule:

1. Record the pattern as an instinct first (see [`templates/skills/instinct-observer/SKILL.md`](templates/skills/instinct-observer/SKILL.md) and [`templates/instincts/schema.yaml`](templates/instincts/schema.yaml)).
2. Accumulate evidence per the schema's promotion gates (`evidence_count ≥ 10`, observed across ≥2 projects, testable via scenario).
3. Open a PR adding both the rule text *and* a corresponding scenario in [`task_battery/portable_scenarios.yaml`](task_battery/portable_scenarios.yaml).

NEVER auto-promote an instinct to a rule. Promotion requires evidence, review, and an explicit rule/scenario change.

## Proposing a new ADR

For public contributors, open a roadmap-decision issue explaining the proposed decision, affected files, alternatives considered, and expected consequences. The maintainer will decide whether the result belongs in public docs, internal decision records, or both.

## Code style

The kit's Python code lives under `scripts/`, `scripts/validators/`, `scripts/workflows/`, `autoresearch/`, `naos_init.py`, `naos_add.py`, `naos_upgrade.py`, and `cli.py`.

- Type hints (`from __future__ import annotations`).
- `ruff check` should pass on changed files.
- New scripts include a header docstring (purpose, env vars, usage, exit codes) following the pattern in existing scripts.
- No new runtime dependencies beyond `PyYAML` without a corresponding ADR.

## Naming

The public project name is NAOS-Governance. Forks are welcome under Apache
License 2.0; they should avoid presenting themselves as the upstream
NAOS-Governance project unless they are the upstream distribution. See
[`NOTICE`](NOTICE).

## CODEOWNERS

See [`.github/CODEOWNERS`](.github/CODEOWNERS) for ownership boundaries. The kit is currently a single-maintainer project; the CODEOWNERS file exists to make ownership explicit and to seed structure for future contributors.

## Acknowledging this is a kit, not a project

NAOS governs adopter projects. The artefacts that ship into adopter projects live under `templates/` and `profiles/`; the artefacts that describe the kit itself live at the kit root and under `docs/`. If your proposal touches both surfaces, name the distinction explicitly in your PR description.
