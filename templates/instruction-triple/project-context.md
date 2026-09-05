# Project Context
<!-- This file is YOUR project-specific customization point for NAOS. -->
<!-- Fill in every [ADAPT] section. The AI uses this as ground truth. -->
<!-- Keep it accurate — stale context causes hallucination and drift. -->

## Identity

| Field | Value |
|-------|-------|
| **Project Name** | $signal_project_name |
| **Purpose** | [ADAPT: One sentence describing what it does] |
| **Stage** | [ADAPT: Alpha / Beta / Production] |
| **NAOS Profile** | $signal_profile |
| **Primary Language** | $signal_language |
| **Primary Framework** | $signal_framework |

---

## Tech Stack

[ADAPT: List your stack as a bullet list or table]

```
Backend:  $signal_backend_stack
Frontend: [ADAPT: framework, version or N/A]
Database: $signal_database_stack
Cache:    [ADAPT: engine or N/A]
Queue:    $signal_queue_stack
Infra:    [ADAPT: cloud, orchestration]
AI/LLM:   $signal_llm_stack
```

---

## Module Map

[ADAPT: Describe your source layout. Every top-level package should have a one-line purpose.]

```
src/
├── [module]/   — [purpose]
├── [module]/   — [purpose]
└── [module]/   — [purpose]

[ADAPT: Add additional directories as needed]
```

---

## DB Schema

[ADAPT: Describe your database structure. The AI needs this to write correct queries.]

```
[table_name]: [key columns and types — not exhaustive, just what's important]
[table_name]: [key columns and types]
```

**Schema rules** [ADAPT: specify invariants]:
- [ADAPT: e.g., "All tenant-scoped tables have tenant_id (UUID, NOT NULL)"]
- [ADAPT: e.g., "soft-deletes via deleted_at; never hard-delete user rows"]

---

## AI Pipeline

[ADAPT: Fill in if you use AI/LLM. Delete section entirely if not applicable.]

| Stage | Model | Purpose |
|-------|-------|---------|
| [ADAPT: stage] | [ADAPT: model-name] | [ADAPT: description] |

**Routing** [ADAPT: describe your confidence/routing model if applicable]:
- [ADAPT: e.g., "≥0.9 → auto-approve, 0.7-0.89 → spot check, <0.7 → human review"]

---

## Critical Constraints

[ADAPT: List the invariants that the AI MUST respect. Be specific.]

1. **[ADAPT: Constraint name]**: [ADAPT: one sentence explanation]
2. **[ADAPT: Constraint name]**: [ADAPT: one sentence explanation]

**Configuration rules**:
- [ADAPT: e.g., "Never hard-code config values — use configs/*.yaml"]
- [ADAPT: e.g., "Access via from src.core.config import settings"]

**Module rules**:
- [ADAPT: e.g., "Never import module A from module B (describe the boundary)"]

---

## Key Workflows

[ADAPT: Describe the 2-5 most important data/request flows. ASCII diagrams preferred.]

```
[ADAPT: e.g., PRIMARY FLOW]
Input → Step A → Step B → Output
```

---

## Test Execution

[ADAPT: How to run tests in this project]

```bash
# [ADAPT: Activate environment if needed]
# conda activate myenv  OR  source .venv/bin/activate

# [ADAPT: Load env vars if needed]
# set -a && source .env && set +a

# Run tests
[ADAPT: pytest -q tests/unit tests/acceptance]
```

**Known pitfalls** [ADAPT: document test gotchas]:
- [ADAPT: e.g., "Must load .env before running tests — DB_URL is required"]

---

## Key Reference Files

[ADAPT: Update paths for YOUR project. These override the defaults in copilot-instructions.md]

| Purpose | File | Editable? |
|---------|------|:---------:|
| **Active Task (READ FIRST)** | `naos/active/*.md` | ✅ Manual |
| **Requirements** | `[ADAPT: specs/03-requirements.md]` | ✅ Manual |
| **Architecture** | `[ADAPT: specs/04-architecture.md]` | ✅ Manual |
| **Task Registry** | `naos/TASK_REGISTRY.yaml` | ✅ Manual |
| **DB Models** | `[ADAPT: src/db/models.py]` | ✅ Manual |
| **API Types** | `[ADAPT: frontend/lib/api.ts or N/A]` | ✅ Manual |
| **Dashboard** | `naos/DASHBOARD.md` | 🚫 Auto-generated |
| **Function Index** | `naos/inventory/FUNCTION_INDEX.yaml` | 🚫 Auto-generated |
