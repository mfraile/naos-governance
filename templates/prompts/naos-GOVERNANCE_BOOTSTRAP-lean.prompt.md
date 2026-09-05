# 🔐 GOVERNANCE BOOTSTRAP (LEAN) — Routine Workflows

**Used by**: `/naos-d-commit`, `/naos-d-start`, `/naos-d-end`, `/naos-w-plan`, `/naos-w-review`
**Full variant**: used by `/naos-add-feature` and `/naos-m-review`
**Boundary**: The kit installs no automatic prompt loader.

---

## Step 0 — Read Active Task Card FIRST

```bash
ls naos/active/*.md   # See what's in play
# Read the card — it has pre-filtered schemas, constraints, acceptance criteria
# DO NOT expand beyond the card's stated scope
```

---

## Key Files

| Purpose | File |
|---------|------|
| Active task | `naos/active/*.md` |
| Requirements | `specs/03-requirements.md` |
| Task registry | `naos/TASK_REGISTRY.yaml` |
| Project status | `naos/PROJECT_STATUS.md` |
| Governance rules | `.ai/RULES.md` |

---

## 5 Non-Negotiable Rules

1. **Rule 1** — Update existing files only. Never create `draft_*.md`, `SESSION_SUMMARY_*.md`, or `ANALYSIS_*.md`.
2. **Rule 7** — Evidence-first. Grep before assuming. Exhaustive impact search before any change.
3. **Rule 8** — Run `make -f Makefile.naos gov-refresh` after scope changes. Individual scripts listed in full bootstrap.
4. **Rule 11** — Anti-duplication: check `naos/inventory/FUNCTION_INDEX.yaml` before creating any function.
5. **Rule 17** — Pre-coding: `python scripts/naos_function_index_query.py --package <target>` before new code.

After code changes, run or request the relevant detective checks: `make -f Makefile.naos naos-function-index-health`, `make -f Makefile.naos naos-module-headers`, `make -f Makefile.naos naos-spec-pack-contract`, `make -f Makefile.naos naos-spec-cascade`, `make -f Makefile.naos naos-test-evidence-map`, `make -f Makefile.naos naos-test-evidence`, `make -f Makefile.naos naos-ac-completion-evidence` when AC/SCEN completion is claimed, `make -f Makefile.naos naos-systemic-impact`, `make -f Makefile.naos naos-evidence-pack`, and `make -f Makefile.naos naos-dashboard`. Risky remediation is proposed patch + evidence + approval, not silent rewrite. Systemic impact, spec-pack, spec-cascade, and AC-completion reports are review aids, not proof of perfect coherence, spec quality, AC correctness, implementation correctness, complete coverage, or code correctness.

---

## Commit Format

```
feat(T-XXX): description
fix(T-XXX): description
docs: description
```

---

## Top Anti-Patterns

| ❌ Violation | ✅ Fix |
|-------------|--------|
| Creating `naos/SESSION_SUMMARY_*.md` | Update `naos/PROJECT_STATUS.md` |
| Hard-coding config values | `[ADAPT: your config access pattern, e.g., from config import settings]` |
| Editing `<!-- BEGIN SYNC_* -->` blocks manually | Update source, run `make -f Makefile.naos gov-refresh` |
