# Readiness and language coverage

`make -f Makefile.naos naos-readiness` reports lifecycle prerequisites separately
from advisory language applicability. `READY` means the existing lifecycle
prerequisites passed; it does not mean code controls ran or were effective.

Language signals use the existing `SRC_ROOT` source-root contract, conventional
source/test roots and flat source files. Java, Node and Go manifests also provide
signals before source exists. Installed governance tool directories are not
selected as product source by default. Set `SRC_ROOT` to the actual adopter
source roots when the layout differs; a missing/outside selected root is
reported as incomplete, not effective coverage. Excluded directories are pruned
before descent. Symlink/reparse roots and children are refused; inaccessible
selections remain incomplete and unverified. This is advisory selection rather
than a hostile-race filesystem guard. An unknown or unrecognized
language remains unverified. Language signals do not override individual
controls' configured scan roots, exclusions, manifests or gate policies.

Dependency integrity checks Python imports. Duplicate function hygiene inspects
Python bodies. API symbol reality inspects explicitly declared Python symbols.
Their Java, JavaScript/TypeScript and Go code coverage is `not_applicable`;
Python applicability remains `unverified` until the relevant executed evidence
is reviewed. Mixed projects retain the Python signal and separately show each
unsupported language, rather than implying whole-project coverage.

Package reality reviews Python package declarations and configured PyPI
SBOM/provenance evidence. Such evidence can be present in any stack, so its
overall applicability remains `unverified` even in a non-Python project. Its
Java/Node/Go language entries are `not_applicable`: a successfully produced
report does not verify Maven, npm or Go module packages. Configured auxiliary
Python package evidence is still reviewable, and existing gates still apply.

These statuses are advisory metadata, not detector results or new policy
exemptions. No detector is skipped, no existing readiness prerequisite is
relaxed, and no gate severity is changed. Run adopter-owned detectors for
unsupported languages and review their executed evidence separately.
