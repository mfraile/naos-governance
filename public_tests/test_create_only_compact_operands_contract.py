"""Exact managed admission for the create-only digest-referencing checkpoint."""

import copy
import importlib
import unittest


class CreateOnlyCompactOperandTests(unittest.TestCase):
    def setUp(self):
        existing = importlib.import_module("test_secret_compact_checkpoint_contract")
        self.managed = existing.managed
        self.transaction = existing.tx
        self.fixture = existing.inv.ManagedInventoryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.journal_path = (
            self.fixture.relative + "/transactions/" + self.fixture.tid + "/journal.json"
        )
        self.plan_path = self.journal_path.rsplit("/", 1)[0] + "/plan.json"
        journal = copy.deepcopy(self.fixture.journal)
        raw = self.managed.canonical_bytes(journal.pop("plan")) + b"\n"
        journal.pop("integrity")
        journal.update(
            schema=self.transaction._CREATE_ONLY_COMPACT_JOURNAL_SCHEMA,
            minimum_recovery_naos_version="1.1.0",
            plan_ref=self.transaction._compact_plan_reference(raw),
        )
        self.journal = self.transaction._with_sha256_integrity(journal)
        self.fixture.write(self.journal_path, self.journal)
        (self.fixture.root / self.plan_path).write_bytes(raw)

    def test_exact_sidecar_is_managed_operand_and_constructor_spans_are_proved(self):
        proved = self.managed._legacy_operands(self.managed.ProofBudget(self.fixture.root))
        self.assertIn(self.plan_path, proved)
        _, spans, diagnostics = self.fixture.spans(
            self.fixture.report([self.plan_path, self.journal_path])
        )
        self.assertTrue(spans, diagnostics)

    def test_missing_changed_or_noncanonical_sidecar_refuses_admission(self):
        path = self.fixture.root / self.plan_path
        raw = path.read_bytes()
        for value in (b"", raw + b" ", raw.replace(b"fixture.py", b"foreign.py")):
            with self.subTest(value=value):
                path.write_bytes(value)
                with self.assertRaises((self.managed.OperandRefusal, OSError)):
                    self.managed._legacy_operands(self.managed.ProofBudget(self.fixture.root))

    def test_nonterminal_or_foreign_sidecar_reference_refuses_admission(self):
        for key, value in (("state", "APPLYING"), ("plan_ref", {
            "name": "../plan.json", "sha256": "0" * 64, "size": 1,
        })):
            journal = {k: v for k, v in self.journal.items() if k != "integrity"}
            journal[key] = value
            self.fixture.write(self.journal_path, self.transaction._with_sha256_integrity(journal))
            with self.subTest(key=key), self.assertRaises(self.managed.OperandRefusal):
                self.managed._legacy_operands(self.managed.ProofBudget(self.fixture.root))

    def test_authored_secret_in_changed_sidecar_is_not_allowlisted(self):
        path = self.fixture.root / self.plan_path
        plan = copy.deepcopy(self.fixture.plan)
        plan["inputs"] = {"authored_secret": "sk-" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"}
        path.write_bytes(self.managed.canonical_bytes(plan) + b"\n")
        common = importlib.import_module("test_secret_compact_checkpoint_contract").inv.common
        report = common.check_secret_hygiene(
            root=self.fixture.root, profile="standard", naos_root="naos",
            rules={"scan_roots": [self.plan_path], "include_root_files": False},
            rules_path=None, severity="required",
        )
        self.assertGreater(report["summary"]["regex_matches"], 0, report["findings"])


if __name__ == "__main__":
    unittest.main()
