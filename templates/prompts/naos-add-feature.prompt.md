# Add New Feature (FR/NFR)

**Version**: 3.0.0 (Governance Trinity Edition)
**Enhancement v3.0**: **REQUIRED**: Read [Governance Bootstrap](naos-GOVERNANCE_BOOTSTRAP.prompt.md) FIRST

---

## 🔐 GOVERNANCE BOOTSTRAP (MANDATORY - READ FIRST)

**Before proceeding**, read: [Governance Bootstrap](naos-GOVERNANCE_BOOTSTRAP.prompt.md)

Review feature discovery against specs, PM, and AI rules.

---

## 🎯 Feature Declaration

I need to track **{{input:feature_id}}** ({{input:feature_name}}).

---

## 📚 MANDATORY CONTEXT (Read ALL Before Starting)

### Phase 1: Governance & Project Context
```
@.ai/RULES.md                      (ALL governance rules)
@naos/governance/PROJECT_GOVERNANCE_RULES.md  (project-specific rules)
@CONTRIBUTING.md                    (Contribution standards)
@SECURITY.md                        (Security policies)
@naos/PROJECT_STATUS.md             (Current status, blockers)
@CHANGELOG.md                       (Recent changes)
@README.md                          (Project overview)
```

### Phase 2: Business & Technical Context
```
@specs/01-problem.md                (WHY — business problem)
@specs/02-solution.md               (WHAT — solution approach)
@specs/03-requirements.md           (HOW — read FULL FR/NFR section)
@specs/04-architecture.md           (CONSTRAINTS — architectural decisions)
@specs/10-execution.md              (Task matrix, dependencies)
[ADAPT: add your domain-specific spec files]
```

### Phase 3: Operations & Past Research
```
[ADAPT: your operations guide path]  (Operational procedures)
docs/exploration/                    (Audit for related work and decision inputs)
```

### Phase 4: Validation Questions

**Business Context**:
- ✅ What business problem does this feature solve? (from `specs/01-problem.md`)
- ✅ How does this feature fit into the high-level solution? (from `specs/02-solution.md`)
- ✅ Who are the users and what are their needs?

**Technical Context**:
- ✅ What are ALL acceptance criteria? (from `specs/03-requirements.md`)
- ✅ What architectural constraints exist? (from `specs/04-architecture.md`)
- ✅ What dependencies exist? (from `specs/10-execution.md`)

**Past Research**:
- ✅ Has this been researched before? (check `docs/exploration/` or your project decision log)
- ✅ What related features exist?
- ✅ What lessons were learned from similar features?

---

## 📝 TASKS

Update these files following `.ai/RULES.md`:

0. **FIRST**: Create `naos/active/{{input:task_id}}_story.md` using template
   - Copy from `naos/active/_TEMPLATE.md`
   - Extract schemas, existing code, acceptance criteria
   - This card is your FOCUS during implementation

1. **specs/10-execution.md** — Add {{input:task_id}} to task matrix
   - Include: ID, Title, Phase, Type, FR/NFR, Status, Owner, Target End, Acceptance

2. **naos/PROJECT_STATUS.md** — Add to work breakdown table
   - Include: FR/NFR, Title, Owner, Status, Next Action, Target, Blocked?

3. **CHANGELOG.md** — Add under [Unreleased] > Added
   - Brief description with key features
   - Reference business problem solved (WHY)

---

## ✅ GOVERNANCE-POSTURE REVIEW

**Before updating**:
1. ✅ **Rule 1**: Update existing files only (no new analysis/summary files)
2. ✅ **Rule 2**: No archive folders
3. ✅ **Rule 3**: PM status in ONE place (`naos/PROJECT_STATUS.md`)
4. ✅ **Rule 4**: Verify impact on ALL documentation
5. ✅ **Rule 8**: Inventory & Regeneration loop completed → `make -f Makefile.naos gov-refresh`
6. ✅ **Rule 9**: Apply Ultra Deep Analysis for Enhancements — evidence-first, exhaustive impact map, alternatives considered, fallback defined
7. ✅ **Rule 10**: Record source licence evidence/approval; no scanner is installed

**⚠️ Governance Metrics Lesson — Cascading Metric Effects**:
> Adding a new `planned` task to a requirement that was previously fully-delivered changes its
> delivered status. NEVER manually calculate derived metrics — run `make -f Makefile.naos gov-refresh` first,
> then read auto-computed values.

**Governance Refresh**:
```bash
make -f Makefile.naos gov-refresh   # Syncs all derived files + validates coherence
```

**Mandatory Response Sections**:
1. **📄 Files Updated (Not Created)** — List all files modified
2. **✅ Impact Validation** — Documentation impact verified per Rule 4
3. **🚫 What I Did NOT Do** — Governance violations avoided

---

**Context Required**: See "MANDATORY CONTEXT" section above
