# Contributing to [ADAPT: Project Name]

Thank you for considering contributing! This guide covers the development workflow and standards.

## Prerequisites

- [ADAPT: list required tools and versions]
- Follow the setup in [QUICK_START.md](QUICK_START.md)
- Install git hooks: `git config core.hooksPath .githooks`

## Development Workflow

### 1. Before Starting Work

```bash
git pull origin main
[ADAPT: conda activate env-name | source .venv/bin/activate]
```

- Check `naos/active/*.md` for current active tasks
- Review `naos/TASK_REGISTRY.yaml` for task assignments

### 2. Making Changes

1. Create or update a story card in `naos/active/`
2. Implement changes (see [Code Standards](#code-standards) below)
3. Write tests that cover the change
4. Run the test suite (see [Running Tests](#running-tests))

### 3. Committing

```bash
# Format commit messages as:
git commit -m "feat(T-XXX): description"
git commit -m "fix(FR-XXX): description"
git commit -m "docs: description"

# After changing TASK_REGISTRY.yaml
make -f Makefile.naos gov-refresh
```

After you explicitly activate the provided **pre-commit hook**, it will:
- Attempt a best-effort sync of derived PM files if `TASK_REGISTRY.yaml` changed;
  review and stage the result because sync failure does not block the commit
- Block archive folders, backup files, and session summaries
- Warn if new docs aren't in `docs/DOCS_INDEX.md`

### 4. Pull Requests

- Reference the task ID (`T-XXX`) in the PR title
- Ensure all tests pass
- Run `make -f Makefile.naos gov-full` before marking ready for review
- One logical change per PR

---

## Code Standards

### Module Headers

```
Module: src/path/to/module.py

Purpose:
    Short module-level description.

Implements:
    - FR-XXX: Requirement/control name
    - NFR-XXX: Non-functional requirement/control name

Tasks:
    - T-XXX: Task title
    - T-YYY: Task title

Specs:
    - specs/03-requirements.md#fr-xxx
    - specs/04-architecture.md#architecture-section

Rationale:
    Short paragraph explaining why this module exists, why the logic belongs
    here, what boundary it owns, and how it avoids duplication or architecture
    drift.

Design notes:
    - Optional stable architectural constraints/patterns.
```

Use one canonical module header per source module. Update it when module purpose
or boundaries materially change; do not create duplicate/stale docstrings with
overlapping metadata.

### Configuration

Never hard-code config values — use `[ADAPT: configs/*.yaml]` and load via settings:
```python
from [ADAPT: src.core.config] import settings
```

### Database

- Use parameterized queries — never string interpolation in SQL
- [ADAPT: add your ORM/migration conventions]

### Tests

- Write tests for every new function
- [ADAPT: describe test organization: unit vs integration]
- Tests must pass before merging

---

## Running Tests

```bash
# Load environment variables
set -a && source .env && set +a

# [ADAPT: your test command]
pytest -q tests/unit tests/acceptance
```

---

## Governance Rules

This project uses **NAOS governance**. Key rules:

1. **Update existing files** — never create `archive/`, `temp_*`, `draft_*`, or `session_*.md` files
2. **No backup files** — use `git history` instead of `*.bak` files
3. **Single source of truth** — task status goes in `naos/TASK_REGISTRY.yaml`; project status in `naos/PROJECT_STATUS.md`
4. **Task traceability** — every commit references `T-XXX` or `FR-XXX`

See `.ai/RULES.md` for the complete list of rules.

---

## File Organization

```
[ADAPT: describe where different types of files go]
src/          — production code
tests/        — test code
naos/active/  — active story cards
docs/         — documentation (add to docs/DOCS_INDEX.md)
docs/exploration/ — exploratory notes, spikes, and decision inputs (exempt from governance checks)
configs/      — configuration files (no hard-coding in src/)
```

---

## Getting Help

- [ADAPT: link to chat/Slack/Discord channel]
- [ADAPT: link to issue tracker]
- Review `naos/NAOS_QUICK_REFERENCE.md` for workflow shortcuts
