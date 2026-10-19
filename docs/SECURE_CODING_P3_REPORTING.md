# Secure-Coding P3 Multidimensional Reporting

**Status**: implemented under ADR-0012 P3; bounded reporting only, not release
authorization.

This component consumes the authoritative P1 reference-integrity result and the
P2 secure-coding control/evidence routing report. It presents exactly five
independent dimensions:

1. register validity;
2. reference integrity;
3. detector evidence availability and freshness;
4. mapping verification;
5. outstanding human review.

It does **not** calculate a blended or composite security score. A valid or
available dimension does not prove control satisfaction, secure code,
vulnerability freedom, framework conformance, compliance, approval, or release
authorization.

## Commands

From the kit repository:

```bash
python scripts/naos_secure_coding_reporting.py \
  --profile standard \
  --refresh-sources
```

From an adopter project with the NAOS package installed:

```bash
python -m naos_governance.secure_coding_reporting_cli \
  --profile standard \
  --refresh-sources
```

The portable Make wrapper is seeded for Lite, Standard, and Assured projects.
Its default profile matches the selected scaffold profile; explicit
`NAOS_PROFILE` overrides remain supported. Each target uses one quoted `PYTHON`
executable, without POSIX shell probes. The Python dispatcher selects the
canonical installed module when `naos_governance` is discoverable; otherwise it
runs `NAOS_P3_SCRIPT` (default `scripts/naos_secure_coding_reporting.py`).
A present but broken module fails without falling back. A complete copied
runtime needs its existing support modules/dependencies but no NAOS package.
The script path may be overridden to an existing source-kit or copied entry,
including paths with spaces. A bare generated wrapper does not provision a
complete P3 runtime; absence of both routes remains unsupported.
GNU make can be launched from cmd.exe, PowerShell or POSIX using its
platform-default recipe shell. `PYTHON` is one executable path, not a command
plus flags; custom PowerShell recipe shells are not covered.

```bash
make -f Makefile.naos.secure-coding-reporting \
  naos-secure-coding-reporting \
  NAOS_PROFILE=standard
```

Project the same five dimensions into existing generated dashboard and evidence
artifacts by adding `--project`, or by using:

```bash
make -f Makefile.naos.secure-coding-reporting \
  naos-secure-coding-reporting-project \
  NAOS_PROFILE=standard
```

Projection is deliberately non-creative:

- `naos/reports/dashboard_summary.json` receives a
  `secure_coding_reporting` object;
- `naos/evidence/evidence_pack.json` receives the same
  `secure_coding_reporting` object;
- `naos/DASHBOARD.md` receives one bounded generated section;
- missing dashboard or evidence-pack artifacts are reported as
  `not_configured` and are not fabricated;
- every configured target is preflighted before any target is changed;
- symlink projection targets are rejected.

The supported v1 and v2 dashboard-summary and evidence-pack schemas accept this
optional projection with its five dimensions and mandatory human-review boundary.
Reports without the projection remain valid. Projection preserves existing
statuses, readiness findings and source-reference metadata; unrelated top-level
fields and malformed projection payloads remain outside the report contract.

Run dashboard/evidence generation before projection when those artifacts need to
be refreshed:

```bash
naos evidence-pack --profile standard
naos dashboard --profile standard --json
python -m naos_governance.secure_coding_reporting_cli \
  --profile standard \
  --refresh-sources \
  --project
```

## Source authority

P3 invokes, rather than reimplements:

- `scripts/validators/validate_secure_coding_control_references.py` for P1;
- `scripts/naos_secure_coding_controls.py` for P2.

Kit repositories use P1 directly. Adopter projects may contain
`naos/secure_coding_control_render_manifest.yaml`; the portable adapter builds an
isolated canonical-path view and invokes the unchanged P1 validator and renderer.
It does not mutate project guidance or create a second register.

Their structured results are persisted under `naos/reports/` and cited in the P3
report. Missing, malformed, symlinked, or contract-incompatible source reports
fail closed.

The P3 report also carries a `standards_snapshot` copied from the P2
secure-coding controls report. The snapshot records the canonical register
version and the framework/version baseline used when the report was generated
(for example ASVS, SSDF, OWASP Top 10, NIST AI RMF, CWE, ISO, and PCI entries).
It is review metadata only: the canonical register remains authoritative, and
the snapshot does not prove framework conformance, control satisfaction,
compliance, approval, or release authorization.

## Gate and decision boundary

P3 is derived presentation, not an additional gate input. G4 and G6 continue to
consume the underlying P1/P2 evidence and existing governance artifacts. The P3
report cannot change severity, gate outcomes, waivers, approvals, exceptions, or
release decisions. The capability contract declares normal G4/G6 links for
Assured L3. Its adopter-declared current and target maturity and profile
enforcement contribute to the ordinary capability maturity severity ceiling;
this relationship is not inert metadata. A below-target capability contributes
only advisory enforcement, and the ceiling cannot raise a gate above its
declared severity. This governance relationship keeps P3 report content outside gate evidence,
validators, and semantic inputs and does not promote maturity or approve work.

## Boundaries

The P3 report is deterministic file-first reporting. It makes no network calls,
does not call models or providers, does not change policy or gate outcomes, does
not grant waivers, and does not replace human review. Projection changes only
the named generated artifacts and one bounded Markdown marker region.

Portable reference manifests use native repository-relative paths. Drive-relative,
rooted, and parent-traversal operands are refused before reading or copying.
Inputs and temporary destinations must remain inside their selected project, kit,
or temporary root; symlink and Windows reparse ancestors are refused. Missing
optional targets and missing project detectors with a safe kit fallback remain
supported. POSIX literal colon and backslash filenames retain native semantics.
These are read-time containment checks, not race-free filesystem custody or
proof of secure code, control satisfaction, compliance, or human approval.
