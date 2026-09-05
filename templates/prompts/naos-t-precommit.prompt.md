# Fix Pre-Commit Hook Failure

Pre-commit hook failed with this error:
```
{{input:error_message}}
```

**Diagnosis**: {{input:validator_name}} validator failed.

### ⚠️ AUTHORITATIVE SOURCES
- `@specs/03-requirements.md` → FR/NFR status (canonical)
- `@naos/TASK_REGISTRY.yaml` → Task status (canonical)

**Fix Requirements**:
1. Read `@.ai/RULES.md` to understand governance requirements
2. Fix the specific issue in **{{input:failing_file}}**
3. Do NOT create new files to "fix" the problem
4. Do NOT create archive folders
5. Follow all governance rules from `.ai/RULES.md`

**Common Failures**:
- **Documentation Coherence**: Broken links, missing files in index
- **Traceability Headers**: Missing "Implements: FR-XXX" headers
- **AI Governance**: Unauthorized files, archives, session summaries
- **Spec Orphans**: New spec files not linked in README
- **Pattern Leak**: [ADAPT: your domain-specific patterns to guard against]

**Fix Strategy**:
- If broken link: Update link or create missing file
- If missing header: Add proper FR/NFR + Task ID
- If unauthorized file: Move content to authorized location
- If orphan spec: Add link in README.md

Include 3 mandatory response sections after fix.

---
**Context Required**: `@.ai/RULES.md`, `@{{input:failing_file}}`
