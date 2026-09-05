---
name: "function-discovery"
description: "Search index/source before coding; reduce duplication with file-first and optional similarity evidence."
parameters:
  - name: query
    description: "Natural language description of the function you need (e.g. 'calculate confidence score for document triage')"
    required: false
    default: ""
  - name: package
    description: "Package name to list all functions (e.g. 'services', 'core', 'utils')"
    required: false
    default: ""
  - name: rebuild
    description: "Set to 'true' to rebuild the index from source before searching"
    required: false
    default: "false"
---

# Skill: Function Discovery

Queries `naos/inventory/FUNCTION_INDEX.yaml` and source files to find existing functions matching your intent. Similarity evidence is optional/project-configured; do not assume an embedding model is installed.
Core NAOS uses deterministic file-first inventory and source search. Optional
similarity providers are non-core; a project may configure a local CPU provider
such as `sentence-transformers/all-mpnet-base-v2`, but only as project-owned
evidence.

## When to Use

- **ALWAYS** before creating any new function in `[ADAPT: your source directory]`
- When unsure if a utility function already exists
- When implementing a feature that touches multiple modules
- As the first step in the Pre-Coding Context Protocol (Rule 17)

## Execution

### Intent Search (find functions by description)

```bash
python scripts/naos_function_index_query.py --similar "calculate document relevance confidence"
```

Returns: configured matches when the project has enabled similarity search. If unavailable, fall back to package inventory, text search, and direct source inspection.

### Package Inventory (list all functions in a package)

```bash
# [ADAPT: replace 'services' with your package name]
python scripts/naos_function_index_query.py --package services
```

Returns: All functions in that package directory with their descriptions.

### Rebuild Index (after adding new functions)

```bash
python scripts/naos_function_index_query.py --rebuild-index
```

Or use the `gov-refresh` skill which includes this step.

## Detection Methodology

| Method | When Used | What It Catches |
|--------|-----------|-----------------|
| **Function index** | Always, when `FUNCTION_INDEX.yaml` exists | Existing names, paths, signatures, and descriptions |
| **Text search** | Always | Naming variations and nearby domain concepts |
| **Project-configured similarity** | Only when configured by the project | Potential intent overlap; advisory unless policy says otherwise |
| **Pre-commit hook** (2g) | On git commit | Staged-only duplicate detection |

## Output Interpretation

```
# [ADAPT: the path below reflects your project's source structure]
Match: src/services/order_processor.py::calculate_order_priority
Similarity: 0.87
Description: Computes priority score for an incoming order
→ REUSE this function. Import from src.services.order_processor
```

Treat similarity scores as advisory unless the project policy explicitly says otherwise. A new function still needs a written reason when related code exists.

## Anti-Duplication Protocol (Rule 11)

If a match is found:
1. Import the existing function — do not recreate it
2. If a wrapper is needed: add docstring `"""Delegates to X.Y()"""`
3. If the existing function needs extension: modify it with backward-compatible changes

After creating a new function:
1. Run `gov-refresh` skill or `make -f Makefile.naos function-index` to update FUNCTION_INDEX.yaml
2. Run `make -f Makefile.naos naos-function-index-health`
3. Run `make -f Makefile.naos naos-test-evidence-map` and `make -f Makefile.naos naos-test-evidence`
4. Pre-commit hook (2g) will verify no obvious staged duplicates were found

Do not silently merge, delete, or rewrite security, encryption, authentication, authorization, database, public API, or regulatory-control code. Produce a finding and remediation options first.
