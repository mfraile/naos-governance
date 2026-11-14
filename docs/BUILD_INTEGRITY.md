# Build dependency integrity

The repository's CI declarations use four hash-locked external dependency sets:

- `requirements-runtime.txt`: the declared runtime dependencies and their closure.
- `requirements-build.txt`: the build frontend, backend, installer and their closure.
- `requirements-ci.txt`: runtime and build sets plus the public test runner.
- `requirements-repository-intelligence.txt`: the separately installed optional graph runtime.

Install these files with `python -m pip install --require-hashes --only-binary=:all:`
and `-r <file>`. Every external requirement is an exact version with locally
recorded SHA-256 wheel digests. CI builds use `python -m build --no-isolation`
after installing the locked build set, so an isolated backend cannot fetch an
unlocked dependency. Clean preview environments install the runtime set, then
the newly built wheel through a generated local requirement carrying that
wheel's SHA-256 and `--no-deps --require-hashes`. `pip check` checks dependency
consistency afterwards.

These hashes detect different downloaded bytes; they do not establish that a
package is free of vulnerabilities or that its publisher is trustworthy. The
initial lock preparation checked official PyPI release metadata and downloaded
wheel bytes. Available wheel digests cover more platforms than NAOS qualifies:
a matching hash or successful dependency resolution does not qualify native
activation or recovery. Existing platform and operation boundaries still apply.

To update a lock, review the selected versions and the complete dependency
closure, obtain the new wheel digests from official release metadata, and
validate hash-enforced installation, builds and the affected tests in disposable
environments. Preserve the separately declared backend pins in `pyproject.toml`.
Keep platform markers, including Windows color support, and test supported
Python versions. An unexpected wheel or missing transitive pin must fail; do not
work around that failure by disabling hash checks or allowing source builds.

The exported Dependabot configuration declares weekly checks for pip and
GitHub Actions. Version-update pull requests are initially paused with
`open-pull-requests-limit: 0` for each ecosystem so the initial publication does
not start an additional version-update CI workload. Enabling those proposals
needs its own bounded CI allowance. This pause does not disable dependency hash
checks or change repository security-update settings; security updates use a
separate limit. Configuration alone does not prove hosted update execution.

The public repository's manual release-provenance workflow
at .github/workflows/release-provenance.yml runs only from main or a version-matching tag.
The operator must confirm the exact event commit; checkout and package version
are checked before the hash-locked wheel and source-archive build. The job is configured to
attest those built bytes and retains them with checksums and the verification
bundle. It has a 20-minute limit and no permission to publish a release or
package. Pushes and pull requests do not trigger it. The initial
publication guard caps the two built packages at 48 MiB and the complete retained
artifact at 50 MiB; retention stays seven days. These bounds do not establish
free storage eligibility. Confirm included storage or an effective zero-spend
stop before dispatch; if it cannot be confirmed, do not run the upload.

Every hosted attempt still requires separate execution approval. A candidate
from main is not a release; release approval must identify the source commit and
the exact artifact bytes to publish. Existing version 1.1.0 assets are not
retroactively attested. Keep downloaded release bytes identical to the attested
build and verify each actual download against the independently approved
repository, workflow, source commit and source ref, for example:

    gh attestation verify ARTIFACT --repo mfraile/naos-governance \
      --signer-workflow mfraile/naos-governance/.github/workflows/release-provenance.yml \
      --source-digest APPROVED_COMMIT --source-ref APPROVED_REF \
      --deny-self-hosted-runners

Replace the uppercase placeholders with the approved artifact, full commit and
ref before running the verification. Verification of a genuine hosted output is
a release acceptance gate; a local checksum, source-only test or workflow
declaration does not satisfy it. Provenance establishes build origin, not code
safety or human approval. No tag, release or CI execution follows from this
document.

References: [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/),
[Dependabot options](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference),
[GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations),
[GitHub CLI verification options](https://cli.github.com/manual/gh_attestation_verify).
