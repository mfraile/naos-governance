# Public test fixtures

`ri_windows_saved_documents.json` contains synthetic Windows repository-intelligence
records for the portable reader and refusal tests. Its generator uses public
constants for native-looking identifiers, security hashes, timestamps, reviewer
attribution and logical roots. It rebuilds the SQLite database from toy SQL and
recomputes all dependent content hashes. These records are parser inputs, not
evidence of native Windows execution or real approval.

Regenerate into a separate file from the kit root with its requirements installed:

```sh
python -B public_tests/fixtures/generate_ri_windows_synthetic_fixture.py --output regenerated-fixture.json
```

The adjacent `ri_windows_synthetic_inputs.json` supplies the public toy content.
Exact SQLite serialization and compression bytes can differ between library
versions; regenerate the entire chain together and run the Windows RI contract
tests. A changed hash alone does not establish a regression or native evidence.
The tests consume the committed fixture without requiring local regeneration.
