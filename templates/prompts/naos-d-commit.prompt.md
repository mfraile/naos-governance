# Create Governance-Compliant Commit

**Version**: 2.0.0 (Governance Trinity Edition)
**Enhancement v2.0**: **REQUIRED**: Read [Governance Bootstrap (Lean)](naos-GOVERNANCE_BOOTSTRAP-lean.prompt.md) FIRST

Generate a properly formatted commit message following project governance standards.

## 🔐 GOVERNANCE BOOTSTRAP (MANDATORY - READ FIRST)

**Before proceeding**, read: [Governance Bootstrap (Lean)](naos-GOVERNANCE_BOOTSTRAP-lean.prompt.md)

Review commit references against `specs/03`, `naos/TASK_REGISTRY`, and Rule 8.

## Context Required

### ⚠️ AUTHORITATIVE SOURCES
- `@specs/03-requirements.md` → FR/NFR IDs for commit references
- `@naos/TASK_REGISTRY.yaml` → Task IDs (T-XXX) for commit references

### Core Context
- `@.ai/RULES.md` — Governance rules
- `@CONTRIBUTING.md` — Commit message conventions
- Git staged changes (automatic)

## Instructions

Analyze the currently **staged changes** and generate a governance-compliant commit message.

**Input Parameters**:
- {{change_type}}: Type of change (feat|fix|docs|chore|refactor|test)
- {{brief_description}}: One-line description of changes

**You MUST provide these 3 sections**:

### 1. Generated Commit Message
```
<type>(<scope>): <subject>

<body with detailed explanation>

<footer with references>
```

**Format Rules**:
- Type: feat|fix|docs|chore|refactor|test|style|perf
- Scope: component affected (ai|api|db|docs|tests|pm)
- Subject: imperative mood, no period, max 50 chars
- Body: explain WHAT and WHY (not HOW)
- Footer: reference FR/NFR, tasks (e.g., "Implements FR-001", "Closes T-006")

### 2. Pre-Commit Checklist
- ✅ Changes follow coding standards
- ✅ Tests added/updated for new functionality
- ✅ Documentation updated (if needed)
- ✅ No sensitive data (keys, passwords)
- ✅ All files in authorized directories
- ✅ Links in docs are valid
- ✅ Specs updated (if FR/NFR changed)
- ✅ `naos spec-pack-contract` and `naos spec-cascade` run or recommended if specs, task registry entries, source headers, source spec references, or source traceability changed

### 3. Command to Execute
```bash
git commit -m "<generated message>"
```

**Note**: If pre-commit hooks fail, use `/naos-t-precommit` to debug.

**Governance**: This commit follows all governance rules from `.ai/RULES.md`.

---

## Next Action (Advisory)

Run the commit only after reviewing the generated message and staged files. If hooks fail, diagnose the failure before retrying.

```yaml
next_action:
	label: "Commit staged changes or investigate failed pre-commit checks."
	preferred_command: "/naos-t-precommit"
	preferred_agent: "@naos-debug"
	reason: "Commit generation is complete; failed hooks require evidence-first debugging."
	constraints:
		- "Use the generated commit message only after confirming staged changes."
		- "Do not use --no-verify to bypass governance checks."
```
