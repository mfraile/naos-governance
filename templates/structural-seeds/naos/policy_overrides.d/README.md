# NAOS Policy Overrides

Place adopter-local static YAML policy overlays in this directory as `*.yaml`.
Global overlays live directly in this directory. Team and operator scoped
overlays are optional static layers:

- `teams/<team_id>/*.yaml`
- `operators/<operator_overlay_id>/*.yaml`

Use filesystem-safe overlay IDs. Do not use raw operator identifiers as
directory names unless they are intentionally safe overlay IDs. Prefer mapping
operator identifiers to operator overlay IDs in `naos/team_operator_map.yaml`.

Supported in v1:

- YAML overlays only.
- Schema-validated, deterministic merge in sorted file order.
- Safe local policy customization for selected thresholds, report paths, dashboard
  preferences, freshness settings, and project metadata.
- Optional team/operator scoped overlays selected from local static mapping or
  explicit CLI flags.

Not supported in v1:

- Python plugin execution.
- Arbitrary code execution.
- Shell commands.
- Provider, cloud, API, MCP, Engram, semantic/vector, graph, LLMGrader, signing,
  or memory write-back enablement.
- Overrides that weaken ADR-0010: Control-Plane Advisory Boundaries, source hierarchy,
  human-review requirements, limitations, or non-claims.
- Authentication, authorization, identity-provider integration, access control,
  separation-of-duties approval, or team membership proof.
- Team-scoped gatekeeper posture that bypasses protected ADR-0010: Control-Plane Advisory Boundaries invariants,
  approval boundaries, or human-review requirements.

Run:

```bash
make -f Makefile.naos naos-policy-overrides
```

The canonical policy remains the NAOS default policy plus validated adopter
overlays. Any generated effective policy is derived and reviewable; it is not a
separate source of authority.

Team/operator overlays are configuration scopes only. They do not prove identity,
authorize work, grant access, approve policy changes, satisfy separation of
duties, validate task ownership, or resolve evidence conflicts.
