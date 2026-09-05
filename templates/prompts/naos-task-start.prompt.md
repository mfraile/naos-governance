# Start Task — Create Active Story Card

**Version**: 1.0.0
**Usage**: Run this command AFTER `/naos-d-start` when ready to begin a specific task

---

## Task Declaration

I'm starting task **{{input:task_id}}** (e.g., T-202, T-145).

---

## Workflow

### Step 1: Verify Task Exists

Check `naos/TASK_REGISTRY.yaml` for the task:
- Task ID, title, requirement, acceptance criteria
- Dependencies, related tasks
- Current status
- FR/NFR links and any dependency unlocks that could affect whether work stays
  sequential or can be split into advisory lanes

**If task doesn't exist**: Stop and add it to TASK_REGISTRY first.

### Step 2: Check for Existing Card

```bash
ls naos/active/
```

If `naos/active/{{input:task_id}}_*.md` already exists, read it instead of creating new.

When a card exists, run or consult `naos task-context --task {{input:task_id}} --profile <profile>` for bounded handoff context. The pack is derived from source artifacts and deterministic reports; it is not approval, automatic context injection, or a replacement for the active card.
Run or consult `naos context-index --profile <profile>` only for generated local candidate lookup when useful, then use `naos context-query --query "<keywords>" --profile <profile>` for bounded candidate references. Treat query results as candidates, not answers. Use `naos semantic-candidates --profile <profile>` only to inspect future semantic/vector readiness; it does not enable sqlite-vec, embeddings, extension loading, providers, Engram/MCP, or memory payload search. Use `naos graph-context --profile <profile>` only to inspect future graph-context readiness, then `naos graph-query --task <TASK-ID> --profile <profile>` only for bounded explicit-link relationship candidates. Graph-query results are not truth, source authority, or implementation proof, there is no hallucination-prevention guarantee, and graph reports do not enable NetworkX, GraphML, graph databases, graph algorithms, global scans, MCP/FastMCP, Engram, or memory payload graphing. The index is cache-like and not authoritative; it does not use sqlite-vec, embeddings, graph traversal runtime, Engram/MCP, or automatic injection.
Run or consult `naos session-start --task {{input:task_id}} --profile <profile>` for lifecycle posture. The report is a bounded checklist; it does not mutate task cards, inject context automatically, approve work, or write memory.

### Step 3: Research Context (5-10 min)

Gather information for the story card:

1. **Schemas & Models** ([ADAPT: use your project's actual paths]):
   ```bash
   # [ADAPT: find related migrations]
   grep -r "{{input:task_id}}" [ADAPT: migrations_dir]/ 2>/dev/null

   # [ADAPT: check your ORM models file]
   grep -n "class\|Table" [ADAPT: models_file]

   # [ADAPT: check your JSON schemas directory]
   ls [ADAPT: schemas_dir]/
   ```

2. **Existing Code Discovery** (DO NOT RECREATE — Rule 17):
   ```bash
   # Functions already mapped to this task
   python scripts/naos_function_index_query.py --for-task {{input:task_id}}

   # All functions in the target package
   python scripts/naos_function_index_query.py --package <target_package>

   # Semantic near-matches
   python scripts/naos_function_index_query.py --similar "<planned function description>"

   # [ADAPT: search your source directory]
   grep -r "keyword" [ADAPT: source_dir]/
   ```

3. **Acceptance Criteria**:
   - From `naos/TASK_REGISTRY.yaml` description
   - From `specs/03-requirements.md` (FR/NFR section)

4. **Parallelization Opportunity (Advisory)**:
   - Classify `parallel_lane_opportunity` as `not_applicable`,
     `sequential_recommended`, `parallel_possible`, or `parallel_recommended`
   - Record `parallel_lane_decision` as `sequential`, `declared`, or `deferred`
   - Use explicit reason codes such as `independent_acceptance_criteria`,
     `distinct_path_scopes`, `dependency_unlocked`, `high_context_load`,
     `unresolved_dependency`, or `schema_or_api_decision_first`
   - For solo developers, lanes are logical checkpoints unless a worktree is
     useful for physical isolation
   - Do not treat a suggestion as an active lane; handoff applies only when
     lanes are explicitly declared

### Step 4: Create Story Card

Create file: `naos/active/{{input:task_id}}_[short_description].md`

Use template from `naos/active/_TEMPLATE.md` and fill in:

```markdown
# Active Task: {{input:task_id}} - [Title from Registry]

## Quick Reference
| Field | Value |
|-------|-------|
| **Task ID** | {{input:task_id}} |
| **Requirement** | [from registry] |
| **Spec Section** | [relevant spec file + lines] |
| **Related Tasks** | [dependencies from registry] |
| **Created** | [today's date] |
| **Owner** | [from registry or your name] |

## Schemas to Respect (DO NOT VIOLATE)
[Fill with actual DB tables, columns, JSON schema fields]

## Existing Code to Use (DO NOT RECREATE)
[Fill with actual files and functions discovered in Step 3]

## Acceptance Criteria
[From registry + specs]

## Parallelization Opportunity (Advisory)
| Field | Value |
|-------|-------|
| **Parallel Lane Opportunity** | not_applicable / sequential_recommended / parallel_possible / parallel_recommended |
| **Parallel Lane Decision** | sequential / declared / deferred |
| **Reason Codes** | [explicit reason codes or N/A] |
| **Candidate Lanes** | [logical/team lanes or N/A] |
| **Solo/Team Posture** | [logical checkpoints / task-claim lanes / N/A] |

Suggested lanes do not activate handoff. Handoff applies only after lanes are
declared.

## Pre-Coding Checklist
- [ ] Read the spec section referenced above
- [ ] Verified schema matches plan
- [ ] Ran `--for-task` and `--package` queries (Rule 17)
- [ ] Ran `--similar` for each planned new function (Rule 17)
- [ ] Populated "Existing Code to Use" with query findings
- [ ] Confirmed no duplicate functionality being created
- [ ] Recorded advisory parallel-lane opportunity and decision posture

## Completion Checklist
- [ ] All acceptance criteria satisfied
- [ ] Tests written and passing
- [ ] No schema violations introduced
- [ ] No duplicate code created
- [ ] Traceability headers added to new files
- [ ] Move this card to naos/completed/ when done
```

### Step 5: Confirm Ready

Before writing any code, verify:
- [ ] Story card created with all fields populated
- [ ] Schemas clearly documented (won't be violated)
- [ ] Existing code clearly documented (won't be duplicated)
- [ ] Acceptance criteria understood
- [ ] No scope creep planned (Rule 7: No Drift)
- [ ] Parallelization opportunity is recorded as sequential, declared, or deferred
- [ ] If lanes are declared, handoff expectations and task-claim posture are explicit

---

**Context Required**: `@naos/TASK_REGISTRY.yaml`, `@specs/03-requirements.md`, `@.ai/RULES.md`

---

## Next Action (Advisory)

When the story card is created or confirmed, move to planning and implementation only through the human-mediated handoff chain.

```yaml
next_action:
   label: "Create the implementation plan, then hand off to implementation after approval."
   preferred_command: "/naos-task-start {{input:task_id}}"
   preferred_agent: "@naos-plan"
   reason: "The task is selected; the next safe step is scoped planning before code changes."
   constraints:
      - "Keep acceptance criteria and dependencies from TASK_REGISTRY.yaml authoritative."
      - "Do not bypass @naos-review after implementation."
```
