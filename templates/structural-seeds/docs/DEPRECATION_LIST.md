# Deprecations & Known Dead Code

> Track deprecated modules, functions, and patterns here.
> When removing something, add it here first. When removing it completely, leave the entry for one major version.

## Format

Each entry has:
- **ID**: DEP-NNN
- **What**: The deprecated item
- **Reason**: Why it was deprecated
- **Removed in**: Version or date it was fully removed
- **Replace with**: What to use instead

---

## Active Deprecations

| ID | What | Deprecated in | Reason | Replace With |
|----|------|--------------|--------|-------------|
| *— no deprecations yet —* | | | | |

---

## Completed Removals (last 2 versions)

| ID | What | Removed | Reason | Was Replaced By |
|----|------|---------|--------|----------------|
| *— none yet —* | | | | |

---

## How to Deprecate

1. Add entry to "Active Deprecations" table
2. Add deprecation warning in the code if still importable:
   ```python
   import warnings
   warnings.warn(
       "[DEP-NNN] X is deprecated and will be removed in vY. Use Z instead.",
       DeprecationWarning,
       stacklevel=2
   )
   ```
3. Document the replacement
4. Move to "Completed Removals" when the item is fully removed
