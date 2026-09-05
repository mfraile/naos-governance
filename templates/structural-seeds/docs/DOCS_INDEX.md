# Documentation Index — [ADAPT: Project Name]

> Single source of truth for all project documentation.
> Add every new doc here when created. Pre-commit hook warns if missing.

---

## 📋 Project Governance

| File | Purpose |
| ---- | ------- |
| `README.md` | Project overview and quickstart links |
| `QUICK_START.md` | Setup guide (clone → running tests) |
| `CONTRIBUTING.md` | Development workflow and contribution guidelines |
| `CHANGELOG.md` | Release history and version notes |
| `SECURITY.md` | Security policy and vulnerability reporting |
| `.ai/RULES.md` | AI governance golden rules |
| `.ai/config.yml` | Declarative AI-tool posture/action map; host behavior is separate |
| `docs/DOCS_INDEX.md` | Single source of truth for project documentation |
| `docs/DEPRECATION_LIST.md` | Deprecation tracking and migration notes |
| `naos/PROJECT_STATUS.md` | Live project status (manual updates) |
| `naos/NAOS_QUICK_REFERENCE.md` | NAOS governance and command quick-reference map |
| `naos/DASHBOARD.md` | Auto-generated task dashboard |
| `naos/reports/plan_coherence.json` | Deterministic task-claim/registry/module-linkage review evidence when generated |
| `naos/reports/evidence_verification.json` | Local tamper-evidence and signature-entry-presence review report when generated |
| `naos/evidence/evidence_envelope.json` | Adopter-signable evidence envelope when generated; not a NAOS signature |
| `naos/BACKLOG.md` | Auto-generated backlog view |
| `naos/TASK_REGISTRY.yaml` | Single source of truth for all tasks |
| `naos/TRACEABILITY_MATRIX.md` | Auto-generated requirements-to-code/test traceability |
| `naos/RELEASE_NOTES.md` | Release notes and delivery summaries |
| `naos/governance/GOVERNANCE_TRUTH_TABLE.md` | Canonical governance metrics and evidence truth source |
| `naos/inventory/FUNCTION_INDEX.yaml` | Function inventory used for discovery and duplication checks |
| `naos/inventory/MASTER_INVENTORY.md` | Human-readable inventory summary |

---

## 📐 Specifications

| File | Purpose |
| ---- | ------- |
| `[ADAPT: specs/01-problem.md]` | Problem definition and user needs |
| `[ADAPT: specs/02-solution.md]` | Proposed solution approach |
| `[ADAPT: specs/03-requirements.md]` | Functional and non-functional requirements (FR-XXX, NFR-XXX) |
| `[ADAPT: specs/04-architecture.md]` | Technical architecture and module boundaries (ARCH-XXX) |
| `[ADAPT: specs/05-api.md]` | API endpoint definitions |
| `[ADAPT: specs/06-acceptance.md]` | Acceptance test scenarios |

---

## 🛠️ Operations

| File | Purpose |
| ---- | ------- |
| `[ADAPT: docs/operations.md]` | Production runbook |
| `[ADAPT: docs/deployment.md]` | Deployment procedures |
| `[ADAPT: docs/monitoring.md]` | Monitoring and alerting |

---

## 🔬 Exploration & Decision Inputs

> Files in `docs/exploration/` are exempt from validation rules.

| File | Purpose |
| ---- | ------- |
| `docs/exploration/` | Exploratory notes, spikes, and decision inputs (exempt from pre-commit governance checks) |

---

## 📦 Kit & Governance Tools

> NAOS governance kit documentation.

| File | Purpose |
| ---- | ------- |
| `kit/README.md` | NAOS Portable Governance Kit overview |
| `kit/INSTALLATION_MANUAL.md` | Kit installation and porting guide |
| `kit/MAINTENANCE_PLAYBOOK.md` | Governance maintenance cadences |

Common bounded review wrappers:

- `make -f Makefile.naos naos-plan-coherence`
- `make -f Makefile.naos naos-evidence-sign`
- `make -f Makefile.naos naos-evidence-verify`

These commands generate review evidence only. They do not authorize work, approve
plans, sign on behalf of NAOS, validate third-party signatures, certify controls,
or prove compliance.

---

## ✍️ How to Add a New Doc

1. Create the file in the appropriate directory
2. Add a row to this index (required)
3. Stage both files: `git add docs/your-doc.md docs/DOCS_INDEX.md`
4. The pre-commit hook will warn if you add a doc without updating this index
