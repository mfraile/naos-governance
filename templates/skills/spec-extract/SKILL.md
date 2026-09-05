---
name: "spec-extract"
description: "Extract a specific section from the requirements or architecture specs into a context-window-friendly chunk (≤5 KB). Use before implementing any feature to load only the relevant spec text rather than the full spec file."
parameters:
  - name: target
    description: "What to extract: FR or NFR ID (e.g. 'FR-023'), ARCH component (e.g. 'ARCH-N'), API path (e.g. '/api/v1/events'), or '--list-requirements' to see all IDs"
    required: true
  - name: spec_file
    description: "Override the default spec file path if needed"
    required: false
    default: ""
---

# Skill: Spec Extract

Extracts a targeted section from the spec files using `scripts/naos_extract_spec_section.py`, returning only the relevant portion (≤5 KB) for the current task.

## When to Use

- Before implementing a feature — load the specific FR/NFR section to understand requirements
- Before reviewing an API endpoint — load the API spec section
- Before modifying an architecture component — load the ARCH constraint
- When you need acceptance criteria for a specific requirement
- When `copilot-instructions.md` references a spec section you need to read

## Execution

### List All Requirement IDs

```bash
python scripts/naos_extract_spec_section.py --list-requirements
```

### Extract a Functional Requirement

```bash
python scripts/naos_extract_spec_section.py --fr FR-023
```

### Extract an Architecture Component

```bash
# [ADAPT: replace ARCH-N with the relevant component number from your specs/04-architecture.md]
python scripts/naos_extract_spec_section.py --arch ARCH-5
```

### Extract an API Spec Section

```bash
python scripts/naos_extract_spec_section.py --api "/api/v1/events"
```

## Spec Reference Guide

| Spec File | Use For |
|-----------|---------|
| `specs/03-requirements.md` | FR/NFR definitions, acceptance criteria |
| `specs/04-architecture.md` | ARCH-N component constraints |
| `specs/05-api.md` | API conventions, endpoint specs, error formats |
| `specs/06-acceptance.md` | Acceptance scenarios and test mapping |
| `specs/09-integration-contract.md` | External API integration contracts |

## Output Interpretation

The script returns:
1. The spec section header (FR-XXX title, acceptance criteria, rationale)
2. Implementation notes and constraints
3. Cross-references to related FRs/NFRs/ARCH components

## Integration with Spec Alignment Protocol (Rule 16)

After extracting a spec section:
1. Verify the FR/NFR ID is real before using it in `Implements:` headers
2. Note the exact spec section range for the story card `Spec Section` field
3. Check for related `ARCH` components that constrain the implementation
