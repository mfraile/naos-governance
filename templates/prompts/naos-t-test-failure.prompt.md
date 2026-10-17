# Debug Test Failures

Systematic debugging of test failures to identify and fix root causes.

## Context Required

### ⚠️ AUTHORITATIVE SOURCES (for commit references)
- `@specs/03-requirements.md` → FR/NFR IDs
- `@naos/TASK_REGISTRY.yaml` → Task IDs (T-XXX)

### Core Context
- `@tests/` — Test files
- `[ADAPT: your test config file, e.g., pytest.ini, jest.config.js]` — Test configuration
- Test failure output (provide separately)
- Git recent changes

## Instructions

Analyze **test failures** and provide systematic debugging guidance to identify root causes.

### Evidence before changing the test contract

Treat the implementation under test as the initial hypothesis. Preserve the original failing output, test command, environment, and baseline test before repairs; do not replace that evidence with a later pass.

Before weakening or removing an assertion, adding or widening skip/xfail, adding retries, or increasing timeouts:
- Identify the exact specification or acceptance-criterion reference and evidence explaining why the existing test contract is wrong or why the proposed exception is needed.
- Record the proposed diff, the coverage or failure signal it removes, alternatives considered, and residual risk. Temporary exceptions need an issue reference and an expiry or removal condition.
- Obtain explicit human approval for that exact change before applying it. A passing rerun, existing skip reason, issue reference, or agent judgment is not approval.

Specification-driven test repairs remain valid when evidence establishes the intended behavior. Strengthening assertions or correcting fixtures without reducing the contract does not require this weakening approval. Existing approved native/platform skips remain valid within their approved scope. Never suppress a failure through success exits, hidden skips, fabricated results, or discarded negative evidence. Use PR-risk changed-test review together with Python test-quality structural findings; neither proves absence of tampering.

**Input Parameters**:
- {{test_name}}: Name of failing test(s)
- {{failure_output}}: Test failure output/stack trace

**You MUST provide these 3 sections**:

### 1. Failure Analysis

**Test Information**:
- **Test Name**: {{test_name}}
- **Test File**: [path to test file]
- **Failure Type**: [assertion/error/timeout/crash]
- **Affected Area**: [which feature/component]

**Failure Pattern**:
- **Frequency**: [always/intermittent/recent]
- **Environment**: [local/CI/specific conditions]
- **Related Failures**: [other tests failing similarly]

**Error Analysis**:
```
[Stack trace or error message]

Key observations:
1. [observation about error]
2. [observation about context]
3. [observation about timing]
```

**Recent Changes** (likely culprits):
```bash
# Find recent commits affecting test or code under test
git log --oneline --all -- [test_file] [source_file]
```

### 2. Debugging Strategy

**Step 1: Reproduce Locally**
```bash
# [ADAPT: your test runner command]
[test_runner] {{test_name}} -v

# With full output
[test_runner] {{test_name}} -v -s

# With debugger
[test_runner] {{test_name}} -v --pdb

# With coverage
[test_runner] {{test_name}} --cov=[module] --cov-report=term-missing
```

**Step 2: Isolate the Issue**

**Check Test Data**:
- [ ] Are test fixtures correct?
- [ ] Is test data still valid?
- [ ] Are mock objects configured properly?

**Check Dependencies**:
- [ ] Are all required packages installed?
- [ ] Correct versions of dependencies?
- [ ] Environment variables set correctly?

**Check Test Logic**:
- [ ] Are assertions correct?
- [ ] Is test testing the right thing?
- [ ] Timing issues (race conditions)?

**Check Code Under Test**:
- [ ] Recent changes to implementation?
- [ ] New requirements not reflected in test?
- [ ] Edge cases not handled?

**Step 3: Narrow Down**

**Binary Search** (if multiple changes):
```bash
git bisect start
git bisect bad HEAD
git bisect good [last_known_good_commit]
# At each step:
[test_runner] {{test_name}}
git bisect [good|bad]
```

**Step 4: Test Hypothesis**

Possible root causes to investigate:
1. **[Hypothesis 1]**: [description]
   - How to test: [specific verification]
   - Expected outcome: [what you'd see if true]

2. **[Hypothesis 2]**: [description]
   - How to test: [specific verification]
   - Expected outcome: [what you'd see if true]

### 3. Resolution & Prevention

**Likely Fix**:

**Option A**: [most likely fix]
```
# Change FROM: [old code]
# Change TO: [new code]
# Reason: [why this fixes it]
```

**Verification Steps**:
```bash
# 1. Run failing test
[test_runner] {{test_name}} -v
# Expected: PASS

# 2. Run related tests
[test_runner] tests/path/to/related/ -v

# 3. Run full test suite
[test_runner]
# Expected: No regressions
```

**Prevention Measures**:

**Improve Test Coverage**:
```
# Add test for edge case that was missed
def/it test_{{scenario}}_edge_case():
    """Test [specific edge case that caused failure]."""
    # Test implementation
```

**Improve Test Isolation**:
```
# Ensure tests don't depend on order
# Setup/teardown for each test
```

**CI/CD Improvements**:
- [ ] Add test to critical path (block merge if fails)
- [ ] Propose a timeout increase only after measured timing evidence and the approval condition above
- [ ] Configure test to run in parallel safely

**Commit the Fix**:
```bash
git add [fixed files]
git commit -m "test: fix {{test_name}} failure

Root cause: [brief explanation]
Fix: [what was changed]
Related: [FR/NFR or issue reference]

Verified:
- {{test_name}} now passes
- No test regressions"
```

**If Test is Flaky**:
- [ ] Propose retries only after retained reproducible flake evidence and the approval condition above
- [ ] Propose timeout changes only after measured timing evidence and the approval condition above
- [ ] Mock external dependencies properly
- [ ] Add synchronization if race condition
- [ ] Propose temporary xfail only with evidence, issue reference, removal condition, and explicit human approval above

**Common Patterns**:

**Pattern 1: Assertion Error** — Compare the failure with the specification; repair implementation by default. Correct test expectations only when evidence establishes the intended behavior; apply the approval condition above to weakening changes

**Pattern 2: Import Error** — Missing dependency or circular import → Install package or restructure imports

**Pattern 3: Timeout** — Investigate infinite loops or measured slow operations; optimize the implementation. Apply the approval condition above before increasing timeouts

**Pattern 4: Mock Error** — Mock not matching real interface → Update mock or use real object

**Governance**: Test fixes follow commit discipline and maintain coverage standards.
