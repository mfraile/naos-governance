---
applyTo: "**"
---

# Function Discovery — Anti-Duplication Instruction

> Before creating any new function, class, or utility, **search the codebase first**.
> Limited task context can increase duplicate-implementation risk when related
> modules are not reviewed. File-first inventory and source search reduce that
> risk; they do not prove semantic uniqueness.

## The Protocol

### Step 1: Search Before Creating

Before writing any new function or class:

```bash
# Check the generated inventory first when present
grep -n "proposed_name" naos/inventory/FUNCTION_INDEX.yaml

# Search for existing implementations by name
grep -r "def proposed_name" src/          # Python
grep -r "function proposedName" src/      # JavaScript/TypeScript
grep -r "func ProposedName" .             # Go
grep -r "public .* proposedName" src/     # Java

# Search for same-purpose equivalents (different name, same intent)
grep -r "keyword_describing_purpose" src/
```

Also inspect related tests and `naos/test_evidence/source_to_test_map.json` when present.

### Step 2: Evaluate What Exists

If you find something similar:
- **Same purpose, same signature** → Reuse it directly (import and call)
- **Same purpose, different interface** → Extend or refactor the existing one
- **Similar but distinct purpose** → Create yours, but document why both exist

### Step 3: Create Only If Truly Novel

If no existing implementation covers your need:
- Choose a clear, non-overlapping name
- Place it in the most logical module (not the one you're currently editing)
- Add a brief docstring explaining what it does and why it's not a duplicate
- Update the canonical module header `Rationale` when the module purpose or boundary materially changes
- Record in the task handoff why existing functions were insufficient

### Step 4: Run Detective Checks

After creating or changing functions, run or request:

```bash
make -f Makefile.naos naos-function-index-health
make -f Makefile.naos naos-module-headers
make -f Makefile.naos naos-spec-pack-contract
make -f Makefile.naos naos-spec-pack-materialize
make -f Makefile.naos naos-spec-assembly-worksheet
make -f Makefile.naos naos-spec-cascade
make -f Makefile.naos naos-test-evidence-map
make -f Makefile.naos naos-test-evidence
make -f Makefile.naos naos-ac-completion-evidence
```

If specs, profile-required spec files, brownfield evidence, task registry entries, source headers, source spec references, or source traceability changed,
treat `naos spec-pack-contract`, `naos spec-pack-materialize --dry-run`, `naos spec-assembly-worksheet`, and `naos spec-cascade` findings as structural review evidence, not proof of
spec quality, filled content, promoted requirements, complete traceability, or code correctness. If overlap or duplicate intent is
suspected, produce a finding and remediation options. Do not silently merge or
rewrite security, encryption, authentication, authorization, database, public
API, or regulatory-control code without explicit approval.

## Common Duplication Patterns to Watch For

| Pattern | What Happens | Prevention |
|---------|-------------|------------|
| Config loaders | 4 different `load_config()` across modules | Search `grep -r "load.*config\|read.*config\|get.*config"` |
| HTTP clients | 3 wrappers around `requests`/`fetch` | Search `grep -r "requests\.\|httpx\.\|fetch("` |
| Date formatters | 2 date-to-string converters | Search `grep -r "strftime\|format.*date\|date.*format"` |
| Validation helpers | Multiple `is_valid_email()` variants | Search `grep -r "valid.*email\|email.*valid"` |
| Error handlers | Duplicate error response builders | Search `grep -r "error.*response\|handle.*error"` |

## Why This Matters

AI-assisted sessions can begin with limited context. Without explicit source
search, a session may recreate an existing utility, increasing maintenance cost
and inconsistent behavior. This instruction supplies a review protocol; it
cannot guarantee that all duplicate intent is found.
