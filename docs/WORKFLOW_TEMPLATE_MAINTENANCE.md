# Workflow template dependencies

`templates/workflows/naos-control-plane-ci.yml` is generated for Lite, Standard
and Assured. Quickstart has no default CI. Other `.yml` and `.yml.example` files
in that directory are optional project-specific examples requiring explicit
adoption; they are not copied into new projects. Public-kit CI has a separate
source, `configs/naos_public_ci.yml`, when present in the maintainer checkout.

The following release/commit pairs were verified against upstream GitHub tags
and exact `action.yml` metadata on 2026-09-24. Templates pin these commits; the
local public test `test_workflow_action_pins.py` rejects floating or unreviewed
references and mismatched version comments.

| Action | Release | Commit |
| --- | --- | --- |
| actions/checkout | v7.0.1 | 3d3c42e5aac5ba805825da76410c181273ba90b1 |
| actions/setup-python | v6.3.0 | ece7cb06caefa5fff74198d8649806c4678c61a1 |
| actions/cache | v6.1.0 | 55cc8345863c7cc4c66a329aec7e433d2d1c52a9 |
| actions/upload-artifact | v7.0.1 | 043fb46d1a93c77aae656e7c1c64a875d1fc6a0a |
| codecov/codecov-action | v7.1.1 | 303a32d7a59b442fa8d48b6a1cc6825c09c847a5 |

These templates target GitHub.com with current hosted runners. The Node 24
actions require Actions Runner 2.327.1 or later. Verify runner OS, architecture
and version separately before self-hosted use. Checkout's authenticated Git
operations inside Docker actions have an additional runner requirement; these
templates do not exercise that path. See the upstream
[checkout](https://github.com/actions/checkout),
[setup-python](https://github.com/actions/setup-python) and
[cache](https://github.com/actions/cache) requirements.

[Upload-artifact v4 and later](https://github.com/actions/upload-artifact) do not
support GitHub Enterprise Server. A GHES variant needs its own compatible
selection and execution evidence; do not substitute its v3 backport into a
GitHub.com template. Artifact names must be distinct within a run. Hidden files
are excluded by default; do not widen uploads without reviewing sensitive data.

The optional application CI template uploads coverage to Codecov only when
`NAOS_ENABLE_CODECOV` is explicitly `true`. Configure `CODECOV_TOKEN`, or an
upstream-supported public-project token opt-out, before enabling it. The
[Codecov action](https://github.com/codecov/codecov-action) can fetch its CLI at
runtime; the action commit alone does not lock that executable. No external
upload or hosted compatibility is proved by local YAML/pin checks.

## Local update procedure

1. Read the upstream release notes, resolve the selected release tag to its full
   commit through the official repository, and inspect `action.yml` at that
   commit. Review runtime floors, inputs, permissions and upload behavior.
2. Update the reviewed mapping in the public test, all corresponding template
   references and this table together. Preserve intentional version choices;
   a newer major is not automatically a requirement.
3. Run `python -B public_tests/test_workflow_action_pins.py`, relevant generated
   profile tests, and public export/package checks. Retain tag/commit evidence.
4. Record hosted checks as unexecuted until separately authorized. Do not start
   Actions, enable scheduled update jobs, or add recurring spend to validate pins.

This is a manual review mechanism. Dependabot's usual workflow discovery does
not maintain this template directory automatically. A pin test detects drift
from the reviewed selection; it does not detect a new upstream advisory or
prove a remote action's runtime behavior.
