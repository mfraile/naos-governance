"""Private per-call facts for the opt-in add dry-run result; no plan authority."""
from __future__ import annotations


class BranchCollector:
    def __init__(self):
        self.route = "unselected"
        self._facts = None

    def select_route(self, route):
        if route not in {"posix_legacy", "windows_legacy", "portable_v3"}:
            raise ValueError("Unknown add applicability route")
        self.route = route

    def record(self, applicability, reason_code, *, execution_route="none",
               direct_add_allowed=False, request_sha256=None, plan_status=None,
               plan_sha256=None):
        if self._facts is not None:
            raise RuntimeError("Repeated add applicability assessment")
        if applicability not in {"ready", "blocked", "noop"}:
            raise ValueError("Unknown add applicability state")
        if execution_route not in {"none", "create_only_add", "external_reviewed_plan_apply"}:
            raise ValueError("Unknown add execution route")
        if type(direct_add_allowed) is not bool or (direct_add_allowed and
                (applicability != "ready" or execution_route != "create_only_add")):
            raise ValueError("Inconsistent direct-add applicability")
        self._facts = {"applicability": applicability,
                       "inspection_completed": True,
                       "reason_code": reason_code,
                       "execution_route": execution_route,
                       "direct_add_allowed": direct_add_allowed,
                       "request_sha256": request_sha256,
                       "plan_status": plan_status,
                       "plan_sha256": plan_sha256}

    def result(self, exit_code, *, reason_code="assessment_not_completed"):
        facts = self._facts if self._facts is not None else {
            "applicability": "unknown", "inspection_completed": False,
            "reason_code": reason_code, "execution_route": "none",
            "direct_add_allowed": False, "request_sha256": None,
            "plan_status": None, "plan_sha256": None}
        return {"schema": "naos.add.applicability.v1", **facts,
                "route": self.route, "mutation_authorized": False,
                "plan_saved": False, "exit_code": exit_code}
