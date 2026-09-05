# Monthly Review

**Version**: 3.0.0 (Governance Trinity Edition)
**Enhancement v3.0**: **REQUIRED**: Read [Governance Bootstrap](naos-GOVERNANCE_BOOTSTRAP.prompt.md) FIRST

---

## 🔐 GOVERNANCE BOOTSTRAP (MANDATORY - READ FIRST)

**Before proceeding**, read: [Governance Bootstrap](naos-GOVERNANCE_BOOTSTRAP.prompt.md)

Review authoritative sources; this prompt neither enforces nor proves compliance.

---

Monthly governance review for {{input:month_year}}:

### ⚠️ AUTHORITATIVE SOURCES (CRITICAL)

**ALWAYS read these FIRST — they are the single source of truth:**
- `@specs/03-requirements.md` → FR/NFR status (canonical)
- `@naos/TASK_REGISTRY.yaml` → Task status (canonical)

**NEVER calculate metrics manually** — they are auto-synced from these sources.

> **⚠️ Governance metrics**: When reviewing metrics, always run `make -f Makefile.naos gov-refresh` FIRST to ensure
> auto-computed values are current, then verify `naos/governance/GOVERNANCE_TRUTH_TABLE.md`
> matches. See Update Procedure in that file.

**Review Tasks**:

1. **Governance Metrics** (run `make -f Makefile.naos gov-refresh` first, then read outputs):
   - Total commits last 30 days: `git log --oneline --since="30 days ago" | wc -l`
   - FR/NFR completed this month
   - Bypass markers (not blocker count): `git log --oneline --since="30 days ago" | grep -i "no-verify\|skip" | wc -l`
   - New unauthorized files (target: 0)
   - Spec-pack contract and spec-cascade coherence: run or recommend `make -f Makefile.naos naos-spec-pack-contract` and `make -f Makefile.naos naos-spec-cascade` when specs, task registry entries, module headers, source spec references, or source traceability changed

2. **Update `naos/PROJECT_STATUS.md`** "Metrics Summary":
   - Velocity (avg commits/week)
   - Quality (violations/commit ratio)
   - Compliance rate

3. **Lessons Learned Audit** (Pitfall Enforcement):

   **Purpose**: Review accepted lessons for governance/PM updates

   **Audit Sources** (last 30 days):
   - Pre-commit failures: Check git log for `--no-verify`
   - Test failures: `git log --oneline --since="30 days ago" | grep -i "fix test\|test fix"`
   - Commit messages: `git log --oneline --since="30 days ago" | grep -i "workaround\|hack\|temporary"`
   - Validator issues: `git log --oneline --since="30 days ago" | grep -i "fix validator\|update validator"`

   **For Each Undocumented Lesson**:

   ✅ **Step 1: Extract lesson details**
   - Symptom: What we observed
   - Discovery: When/how found
   - Root Cause: Why it happened
   - Impact: What was the consequence

   ✅ **Step 2: Check if already documented**
   - Search `CHANGELOG.md` and `naos/BACKLOG.md` for similar issues
   - If already documented: Note entry, skip to Step 5

   ✅ **Step 3: Evaluate governance update applicability**

   **Question 1**: Does this lesson require **governance update**?
   - ❓ Should `naos/governance/PROJECT_GOVERNANCE_RULES.md` add new rule?
   - ❓ Should existing rule be enhanced with this example?

   **Question 2**: Does this lesson require **PM documentation update**?
   - ❓ Should `naos/NAOS_QUICK_REFERENCE.md` add guidance?
   - ❓ Should `naos/BACKLOG.md` track this as improvement?

   **Question 3**: Does this lesson require **`.ai/` governance update**?
   - ❓ Should `.ai/RULES.md` add new guidance?

   **Question 4**: Does this lesson require **PM prompts update**?
   - ❓ Should `.github/prompts/naos-*.prompt.md` be enhanced?

   ✅ **Step 4: Document in `CHANGELOG.md` or `naos/BACKLOG.md`**
   ```markdown
   ### Lesson: [Problem Title]
   **Symptom**: [What we saw]
   **Root Cause**: [Why it happened]
   **Solution**: [Fix applied]
   **Governance Update**: [Rule added, or "N/A"]
   **Commits**: [List relevant commits]
   ```

   ✅ **Step 5: Generate action items**
   - List files to update (with specific sections/line numbers if possible)
   - Provide commit message template

4. **Identify `.ai/RULES.md` Improvements**:
   - Any recurring violations?
   - New patterns to document?
   - Examples to add?

5. **Update `CHANGELOG.md`**:
   - Add [{{input:month_year}}] section summarizing month's work
   - Move [Unreleased] items if version release planned

Follow all governance rules from `@.ai/RULES.md`. Include 3 mandatory response sections.

---
**Context Required**:
- `@.ai/RULES.md` — Governance rules
- `@naos/PROJECT_STATUS.md` — Project status
- `@CHANGELOG.md` — Recent changes
- `@naos/governance/PROJECT_GOVERNANCE_RULES.md` — Governance rules
- Git log (last 30 days): `git log --oneline --since="30 days ago"`
