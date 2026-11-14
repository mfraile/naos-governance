"""K5 portable output formatting; these tests do not exercise native mutation."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

KIT = Path(os.environ.get("NAOS_TEST_KIT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(KIT))
import naos_upgrade as upgrade  # noqa: E402

DETAIL = ("primary apply failure; RECOVERY_CHECKPOINT_PERSIST_FAILED: "
          "OSError: synthetic recovery checkpoint write failure; prior checkpoint may be stale")


class RecoveryCheckpointWarningTests(unittest.TestCase):
    def test_apply_output_preserves_json_and_warns_for_checkpoint_failure(self):
        for status in ("recovery_required", "rollback_incomplete"):
            with self.subTest(status=status):
                outcome = upgrade.transaction.CreateOnlyTransactionOutcome(status, "fixture-id", detail=DETAIL)
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = upgrade._emit_apply_outcome(outcome, "fixture-digest")
                self.assertEqual(code, 3)
                self.assertEqual(json.loads(out.getvalue()), {
                    "status": status, "transaction_id": "fixture-id", "receipt_path": None,
                    "plan_sha256": "fixture-digest", "detail": DETAIL})
                self.assertIn("WARNING:", err.getvalue())
                self.assertIn("RECOVERY_CHECKPOINT_PERSIST_FAILED", err.getvalue())
                self.assertIn("synthetic recovery checkpoint write failure", err.getvalue())

    def test_other_outcomes_keep_existing_status_json_and_silence(self):
        for status, detail, expected_code in (
            ("committed", None, 0), ("recovery_required", "primary failure", 3),
            ("rollback_incomplete", "rollback failed", 3),
        ):
            with self.subTest(status=status):
                outcome = upgrade.transaction.CreateOnlyTransactionOutcome(status, "fixture-id", detail=detail)
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = upgrade._emit_apply_outcome(outcome, "fixture-digest")
                self.assertEqual(code, expected_code)
                self.assertEqual(json.loads(out.getvalue())["detail"], detail)
                self.assertEqual(err.getvalue(), "")

    def test_recovery_output_formatter_preserves_json_and_warns(self):
        # Isolate the existing formatter from all native backend/mutation work.
        outcome = upgrade.transaction.CreateOnlyTransactionOutcome("recovery_required", "fixture-id", detail=DETAIL)
        out, err = io.StringIO(), io.StringIO()
        with patch.object(upgrade, "_v3_recovery_api", return_value=SimpleNamespace(has_v3_control=lambda root: False)), \
             patch.object(upgrade.naos_init, "_windows_cli", return_value=None), \
             patch.object(upgrade, "inspect_managed_content_scope", return_value=SimpleNamespace(status="valid")), \
             patch.object(upgrade, "_transaction_arguments", return_value={}), \
             patch.object(upgrade.transaction, "recover_managed_content_transactions", return_value=[outcome]), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = upgrade._recover_command(Path.cwd())
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(out.getvalue()), [{
            "status": "recovery_required", "transaction_id": "fixture-id",
            "receipt_path": None, "detail": DETAIL}])
        self.assertIn("WARNING:", err.getvalue())
        self.assertIn("synthetic recovery checkpoint write failure", err.getvalue())
