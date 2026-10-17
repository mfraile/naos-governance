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

The merge command produces a review report and, when requested, a derived
effective policy. It does not install that policy or automatically apply overlays
to other commands. Consumers keep their configured adopter or default policy
unless a reviewed policy is explicitly selected with `--policy`.

Review the applied paths and effective thresholds before selecting derived
output. Evidence budgets and allowlisted customization still need review; schema
validation is not approval. The effective policy remains derived and reviewable,
and durable policy decisions remain human-owned.

The merge validates profile control minima against the initially selected policy:
`profiles.severity_by_profile` cannot be lowered, and existing recognized
`fail_on`, `strict_fail_on`, and `transition_fail_on` entries cannot be removed.
Nonweakening additions use recognized severity values; ordinary evidence budgets
and allowlisted customization remain configurable. This is merge validation,
not access control or approval. A human-owned explicitly selected base policy
still defines its own baseline.

Derived output is used by a consumer only when explicitly selected with
`--policy`; overlays are not automatically loaded or installed.
`summary.effective_policy_written` is true only after a successful write in that
invocation. A rejected merge, stale target, dry-run, or failed write leaves it
false. Dry-run does not resolve the unused effective target; requested unsafe or
unwritable targets produce a structured finding. YAML output retains its direct
write semantics and does not claim interruption recovery.

Team/operator overlays are configuration scopes only. They do not prove identity,
authorize work, grant access, approve policy changes, satisfy separation of
duties, validate task ownership, or resolve evidence conflicts.
