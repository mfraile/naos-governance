"""Bounded, source-replayed Standard/Assured full-self-check dependency reconciliation.

No report is changed to ready. Only a complete current independent-fact proof
may resolve the exact F -> PR -> gates -> F / F -> maturity -> F component.
Unsupported checks, scopes, diagnostics and unsafe input topology fail closed.
"""

from __future__ import annotations
import ast
from contextvars import ContextVar
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import tempfile
from typing import Any
import yaml
from naos_policy import load_operand_yaml
from jsonschema import Draft202012Validator

SCHEMA = "naos.self_check_dependency_resolution.v1"
_ACTIVE: ContextVar[bool] = ContextVar(
    "naos_dependency_resolution_active", default=False
)
DEFERRED = frozenset({"naos_pr_governance_summary", "naos_capability_maturity"})
REQUIRED_GATES = tuple(f"G{i}" for i in range(7))
# A generated Standard evidence pack measured 17.8 MB in the configured
# workflow. Keep a finite cap with room for its exact JSON capture envelope.
MAX_BYTES = 64 * 1024 * 1024


class ResolutionRefusal(ValueError):
    def __init__(self, code: str, detail: str = ""):
        self.code, self.detail = code, detail
        super().__init__(f"{code}: {detail}")


def resolution_in_progress() -> bool:
    return _ACTIVE.get()


def _deny(code: str, detail: Any = "") -> None:
    raise ResolutionRefusal(code, str(detail))


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _bytes(root: Path, path: Path) -> bytes:
    from naos_evidence_contracts import _safe_file

    if _safe_file(root, path) != "available":
        _deny("unsafe_or_missing_input", path)
    meta = path.stat()
    if meta.st_size > MAX_BYTES or meta.st_nlink != 1:
        _deny("unsupported_input_size_or_links", path)
    content = path.read_bytes()
    if len(content) > MAX_BYTES:
        _deny("unsupported_input_size", path)
    return content


def _json(root: Path, path: Path) -> tuple[dict, str]:
    from naos_evidence_contracts import _json_value

    content = _bytes(root, path)
    value = _json_value(path, data=content)
    if not isinstance(value, dict):
        _deny("invalid_report_object", path)
    return value, hashlib.sha256(content).hexdigest()


def _schema(report: dict, filename: str) -> None:
    from naos_policy import kit_root

    path = kit_root() / "schemas" / "naos" / filename
    if filename == "self_check_dependency_resolution.schema.json" and not path.exists():
        path = Path(__file__).resolve().parents[1] / "schemas" / "naos" / filename
    schema = json.loads(path.read_text(encoding="utf-8"))
    errors = list(Draft202012Validator(schema).iter_errors(report))
    if errors:
        _deny("schema_invalid", f"{filename}: {errors[0].message}")


def _report_path(root: Path, naos_root: str, policy: dict, key: str) -> Path:
    from naos_policy import report_default_path

    return report_default_path(root, naos_root, policy, key)


def receipt_path(root: Path, naos_root: str, policy: dict) -> Path:
    from naos_policy import naos_root_path, safe_policy_path, evidence_pack_output_path
    from naos_ai_surfaces import checked_path

    state = naos_root_path(root, naos_root)
    selected = policy.get("paths", {}).get(
        "self_check_dependency_resolution_report",
        "self_check_dependency_resolution.json",
    )
    checked_path(root, "/".join((naos_root, policy["paths"]["reports_dir"], selected)))
    path = safe_policy_path(
        state,
        policy["paths"]["reports_dir"],
        selected,
        field="self_check_dependency_resolution_report",
    )
    aliases = {
        _report_path(root, naos_root, policy, k)
        for k in policy["paths"]
        if k.endswith("_report") and k != "self_check_dependency_resolution_report"
    }
    aliases.add(evidence_pack_output_path(root, naos_root, policy))
    if path in aliases or path.suffix != ".json" or path.parent == state:
        _deny("receipt_alias_or_invalid_destination", path)
    if path.exists():
        old, _ = _json(root, path)
        if old.get("schema") != SCHEMA:
            _deny("receipt_aliases_unrecognized_input", path)
    return path


def write_resolution(
    root: Path, receipt: dict, *, naos_root: str, policy: dict
) -> Path:
    root = root.resolve(strict=True)
    if receipt.get("schema") != SCHEMA or receipt.get("status") != "resolved":
        _deny("only_verified_resolved_receipt_may_publish")
    # The writer itself repeats verification; callers cannot supply a status flag.
    report, _ = _json(root, _report_path(root, naos_root, policy, "self_check_report"))
    checked = verify_resolution(
        root,
        receipt,
        profile=receipt.get("profile"),
        naos_root=naos_root,
        policy=policy,
        self_check_report=report,
        context=receipt.get("context", {}),
    )
    if checked.get("status") != "resolved":
        _deny("receipt_failed_publication_verification", checked.get("refusals"))
    path = receipt_path(root, naos_root, policy)
    # Do not create a directory through a symlinked ancestor.
    ancestor = path.parent
    while not ancestor.exists():
        ancestor = ancestor.parent
    if ancestor.is_symlink() or not ancestor.resolve().is_relative_to(root):
        _deny("unsafe_receipt_parent", ancestor)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".dependency-resolution-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(
                json.dumps(receipt, indent=2, allow_nan=False).encode() + b"\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        receipt_path(
            root, naos_root, policy
        )  # repeat alias/link checks immediately before replace
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path


def _input_inventory(root: Path, naos_root: str, policy: dict) -> dict[str, str]:
    """Bind authored bytes; reuse the established exact runtime projection contract."""
    from naos_policy import (
        kit_root,
        naos_root_path,
        evidence_pack_output_path,
        dashboard_output_path,
        implicit_adopter_policy_path,
    )
    from naos_systemic_family_review import (
        DERIVED_REPORT_KEYS,
        RUNTIME_OUTPUT_ROLES,
        _runtime_review_binding,
        checked_path,
    )

    state = naos_root_path(root, naos_root)
    # Exact finite registered endpoints, never the whole reports/session/audit tree.
    derived = {}
    for key in sorted(DERIVED_REPORT_KEYS):
        if key == "self_check_dependency_resolution_report":
            continue  # added exactly once below
        if key not in policy["paths"] and key not in {
            "evidence_pack_report",
            "dashboard_markdown",
        }:
            continue
        if key == "evidence_pack_report":
            path = evidence_pack_output_path(root, naos_root, policy)
        elif key == "dashboard_markdown":
            path = dashboard_output_path(root, naos_root, policy)
        else:
            path = _report_path(root, naos_root, policy, key)
        if path is None:
            continue
        ref = path.absolute().relative_to(root).as_posix()
        checked_path(root, ref)
        if ref in derived:
            _deny("derived_output_alias", ref)
        derived[ref] = key
    rules = {
        "review_binding": {
            "mode": "declared_producer_inputs",
            "derived_report_keys": sorted(set(derived.values())),
            "derived_runtime_outputs": sorted(RUNTIME_OUTPUT_ROLES),
        }
    }
    protected = [
        state / "gatekeepers.yaml",
        state / str(policy["paths"].get("capability_state", "capability_state.yaml")),
    ]
    selected_policy = policy.get("_meta", {}).get("path")
    policy_documents = set()
    if selected_policy:
        protected.append(Path(selected_policy))
        policy_documents.add(Path(selected_policy).absolute())
    # Use the actual loader's fixed implicit-policy discovery contract, not an
    # arbitrary document claiming to be policy or an untrusted schema label.
    implicit_policy = implicit_adopter_policy_path(root, naos_root)
    if implicit_policy is not None:
        policy_documents.add(implicit_policy)
    projections = _runtime_review_binding(
        root, naos_root, policy, rules, derived, protected
    )
    proof_path = receipt_path(root, naos_root, policy)
    proof_ref = proof_path.relative_to(root).as_posix()
    if (
        proof_ref in derived
        and derived[proof_ref] != "self_check_dependency_resolution_report"
    ):
        _deny("proof_aliases_existing_output")
    derived[proof_ref] = "self_check_dependency_resolution_report"
    ci_ref = (
        (state / policy["paths"]["reports_dir"] / "ci_readiness.json")
        .relative_to(root)
        .as_posix()
    )
    if ci_ref in derived:
        _deny("ci_receipt_alias")
    derived[ci_ref] = "ci_readiness"
    excluded = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules"}
    result = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in excluded for part in relative.parts):
            continue
        if path.is_symlink():
            _deny("unsafe_input_symlink", relative)
        if not path.is_file():
            continue
        ref = relative.as_posix()
        if ref in projections:
            result["project:" + ref] = projections[ref]["sha256"]
            continue
        if ref in derived:
            continue
        # Unknown report types and audit events remain byte-bound, regardless of suffix.
        content = _bytes(root, path)
        result["project:" + ref] = hashlib.sha256(content).hexdigest()
        if relative.suffix.lower() in {".yaml", ".yml", ".json"}:
            try:
                value = (
                    json.loads(content)
                    if relative.suffix == ".json"
                    else load_operand_yaml(content)
                )
            except (ValueError, yaml.YAMLError):
                continue
            value = _grader_snapshot_operand_projection(value)
            value = _regex_metadata_operand_projection(
                value, policy_document=path in policy_documents
            )
            _declared_path_topology(root, value)
    kit = kit_root().resolve()
    for family in ("scripts", "schemas", "capabilities", "autoresearch"):
        for path in sorted((kit / family).rglob("*")):
            if (
                path.is_file()
                and path.suffix in {".py", ".json", ".yaml"}
                and "__pycache__" not in path.parts
            ):
                if path.is_symlink():
                    _deny("unsafe_kit_source_symlink", path)
                result["kit:" + path.relative_to(kit).as_posix()] = hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
    return result



def _regex_metadata_operand_projection(value: Any, *, policy_document: bool) -> Any:
    """Project source-owned regex fields without removing actual path operands.

    Claims scanning uses policy claims.overclaim_patterns only as re.finditer
    patterns. Spec-pack checking likewise uses scalar reference_patterns in
    traceability_code rules as regexes. Validate the effective policy or full manifest schema and, for the
    undiscriminated policy shape, its actual selected/implicit loader endpoint.
    Keep unknown fields and pattern objects visible to the topology guard; the
    inventory already hashes the complete original document bytes.
    """
    if not isinstance(value, dict):
        return value
    if policy_document:
        from naos_policy import SAFE_FALLBACK_POLICY, deep_merge

        # The actual policy loader permits partial overrides. Validate the same
        # effective shape without inventing a full-document requirement.
        _schema(deep_merge(SAFE_FALLBACK_POLICY, value), "policy.schema.json")
        if "claims" not in value:
            return value
        projected = dict(value)
        projected["claims"] = {
            key: field for key, field in value["claims"].items()
            if key != "overclaim_patterns"
        }
        return projected
    if value.get("schema") == "naos.spec_pack_manifest.v1":
        _schema(value, "spec_pack_manifest.schema.json")
        projected = dict(value)
        if "traceability_codes" in value:
            projected["traceability_codes"] = [
                {
                    key: ([pattern for pattern in field if isinstance(pattern, dict)]
                          if key == "reference_patterns" else field)
                    for key, field in rule.items()
                }
                for rule in value["traceability_codes"]
            ]
        return projected
    return value


def _grader_snapshot_operand_projection(value: Any) -> Any:
    """Keep graded snapshot provenance distinct from selected filesystem operands.

    GraderAssessment's baseline reader compares loaded statistics/dimensions; it
    never opens a finding's source_path. StaticGrader copies this producer-origin
    annotation into the assessment and nested dimension findings. Only that
    exact field in schema-valid grading finding records is omitted from the
    topology view. The inventory still hashes the complete original bytes.
    Actual trace/baseline/input_report selectors and unknown fields are retained.
    """
    if (
        not isinstance(value, dict)
        or value.get("schema") != "naos.grader_assessment.v1"
    ):
        return value
    _schema(value, "grader_assessment.schema.json")

    def project(item: Any, *, finding_record: bool = False) -> Any:
        if isinstance(item, dict):
            is_finding = finding_record and all(
                isinstance(item.get(k), str)
                for k in ("id", "severity", "status", "message")
            )
            return {
                key: (
                    [project(child, finding_record=True) for child in field]
                    if key == "findings" and isinstance(field, list)
                    else project(field)
                )
                for key, field in item.items()
                if not (is_finding and key == "source_path" and isinstance(field, str))
            }
        if isinstance(item, list):
            return [project(child) for child in item]
        return item

    return project(value)


def _declared_path_topology(root: Path, value: Any, key: str = "") -> None:
    if isinstance(value, dict):
        for name, child in value.items():
            _declared_path_topology(root, child, str(name))
    elif isinstance(value, list):
        for child in value:
            _declared_path_topology(root, child, key)
    elif isinstance(value, str) and re.search(
        r"(path|file|root|refs?|source|input|manifest|inventory|baseline|trace)", key
    ):
        if not value or "://" in value or "\n" in value:
            return
        path = Path(value)
        windows = PureWindowsPath(value)
        # Drive-relative paths depend on a per-drive working directory. Rooted
        # Windows paths without a drive reset root/path even though is_absolute
        # is false. Reject either ambiguity before prose/glob shortcuts or joins.
        if windows.drive and not windows.root:
            _deny("escaping_declared_data_path", key)
        if windows.anchor and not path.is_absolute():
            _deny("external_declared_data_path", key)
        if (" " in value and not path.is_absolute() and not windows.anchor
                and not value.startswith(("../", "~", "./"))):
            return
        if "/" not in value and "\\" not in value:
            return
        if ".." in path.parts or ".." in windows.parts or value.startswith("~"):
            _deny("escaping_declared_data_path", key)
        if path.is_absolute():
            if not path.is_relative_to(root):
                from naos_policy import kit_root

                kit = kit_root().resolve()
                if not any(
                    path.is_relative_to(kit / d)
                    for d in ("schemas", "templates", "capabilities", "scripts")
                ):
                    _deny("external_declared_data_path", key)
                return
        else:
            path = root / path
            if not path.is_relative_to(root):
                _deny("escaping_declared_data_path", key)
        if any(ch in value for ch in "*?[]<>"):
            return  # actual selected matches validated by producer
        for ancestor in (path, *path.parents):
            if ancestor == root:
                break
            if ancestor.is_symlink():
                _deny("unsafe_declared_input_symlink", path)


def _raw_match(check: dict, data: dict, *, profile: str, policy: dict) -> None:
    from naos_policy import exit_code_for_summary

    if any(
        check.get(k) != data.get(k, {} if k == "summary" else [])
        for k in ("status", "summary", "findings")
    ):
        _deny("nested_report_mismatch", check.get("id"))
    expected = exit_code_for_summary(profile, data.get("summary", {}), policy, False)
    if type(check.get("returncode")) is not int or check["returncode"] != expected:
        _deny("producer_exit_mismatch", check.get("id"))


def _output_key(script: str) -> str:
    if script == "naos_local_context_index.py":
        return "local_context_index_report"
    if script == "naos_audit_log.py":
        return "audit_log_summary_report"
    from naos_policy import kit_root

    tree = ast.parse((kit_root() / "scripts" / script).read_text(encoding="utf-8"))
    # Only the producer's main entry owns its canonical sink. Input reads do not.
    mains = [
        n
        for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "main"
    ]
    keys = set()
    for main in mains:
        for call in ast.walk(main):
            if (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id == "report_output_path"
                and call.args
                and isinstance(call.args[-1], ast.Constant)
                and isinstance(call.args[-1].value, str)
            ):
                keys.add(call.args[-1].value)
    if len(keys) != 1:
        _deny("unsupported_producer_output_contract", script)
    return next(iter(keys))


def _replay_independent(
    check: dict, *, root: Path, profile: str, naos_root: str, policy: dict
) -> dict | None:
    """Finite actual-producer adapters for reports outside the gate registry."""
    import importlib
    from argparse import Namespace
    from naos_policy import finding_counts, exit_code_for_summary

    identity = check["id"]
    supported = {
        "naos_session_identity": "session_identity.schema.json",
        "naos_operator_attribution": "operator_attribution.schema.json",
        "naos_session_lifecycle": "session_lifecycle.schema.json",
        "naos_audit_log": "audit_log_summary.schema.json",
        "naos_behavioral_governance_readiness": "behavioral_governance_readiness.schema.json",
        "naos_agentic_workflow_review": "agentic_workflow_review.schema.json",
        "naos_pre_implementation_alignment_review": "pre_implementation_alignment_review.schema.json",
        "naos_cross_harness_review_readiness": "cross_harness_review_readiness_report.schema.json",
        "naos_evidence_conflicts": "evidence_conflict_detection.schema.json",
        "naos_opencode_config_hygiene": "opencode_config_hygiene.schema.json",
        "naos_failure_mode_posture": "failure_mode_posture.schema.json",
        "naos_failure_mode_observations": "failure_mode_observations.schema.json",
        "naos_design_traceability": "design_traceability.schema.json",
        "naos_ui_experience_quality": "ui_experience_quality.schema.json",
    }
    if identity not in supported:
        return None
    producer = importlib.import_module(identity)
    from naos_evidence_contracts import CONTROL_PLANE_REPORT_REGISTRY, reproduce_control_plane_source, _control_plane_declaration_state
    family = identity.removeprefix("naos_")
    optional_inactive = False
    if family in CONTROL_PLANE_REPORT_REGISTRY:
        descriptor = CONTROL_PLANE_REPORT_REGISTRY[family]
        optional_inactive = _control_plane_declaration_state(root, naos_root, policy, descriptor) == "inactive"
        current = reproduce_control_plane_source(family, root=root, profile=profile, naos_root=naos_root, policy=policy)
        from naos_evidence_contracts import _control_plane_projection
        stored, _ = _json(root, _report_path(root, naos_root, policy, descriptor.output_key))
        _schema(stored, supported[identity])
        _raw_match(check, stored, profile=profile, policy=policy)
        if _control_plane_projection(stored) != _control_plane_projection(current):
            _deny("independent_replayed_source_projection_mismatch", identity)
        expected_exit = exit_code_for_summary(profile, current.get("summary", {}), policy, False)
    elif identity in {"naos_session_identity", "naos_operator_attribution"}:
        from naos_session_identity import inspect_session_context

        inspected = inspect_session_context(root, naos_root, policy)
        if identity == "naos_session_identity":
            current = producer.build_identity_report(
                root, naos_root, profile, inspected
            )
        else:
            current = producer.build_report(root, naos_root, profile, inspected)
        current["inspection_only"] = True
        # These actual inspection CLIs deliberately return 0 for advisory, 2 for blocked.
        expected_exit = 2 if current["status"] == "blocked" else 0
    elif identity == "naos_session_lifecycle":
        from naos_session_identity import inspect_session_context

        rules_path, rules_source = producer.resolve_rules_path(
            root, naos_root, policy, None
        )
        rules = producer.load_yaml_mapping(rules_path)
        current = producer.build_report(
            root,
            naos_root,
            profile,
            policy,
            "session_start",
            rules,
            rules_path,
            rules_source,
            None,
            "auto",
        )
        inspected = inspect_session_context(root, naos_root, policy)
        current["findings"].extend(inspected.get("findings") or [])
        current["status"] = (
            "blocked"
            if inspected.get("status") == "blocked"
            else producer.status_from_findings(
                "session_start", rules, current["findings"]
            )
        )
        current["summary"].update(finding_counts(current["findings"]))
        current["summary"]["status"] = current["status"]
        current["summary"]["session_activity_recorded"] = False
        expected_exit = (
            2
            if inspected.get("status") == "blocked"
            else exit_code_for_summary(profile, current["summary"], policy, False)
        )
    elif identity == "naos_audit_log":
        current = producer.build_summary_report(
            root=root, naos_root=naos_root, policy=policy, profile=profile
        )
        expected_exit = exit_code_for_summary(
            profile, current.get("summary", {}), policy, False
        )
    elif identity == "naos_behavioral_governance_readiness":
        rules, source = producer.resolve_rules_path(root, naos_root, policy)
        baseline = producer.resolve_baseline_path(root, naos_root, policy, None)
        current = producer.build_report(
            root, naos_root, profile, policy, rules, source, baseline
        )
        expected_exit = exit_code_for_summary(
            profile, current.get("summary", {}), policy, False
        )
    elif identity in {
        "naos_agentic_workflow_review",
        "naos_pre_implementation_alignment_review",
    }:
        current = producer.build_report(root, naos_root, profile, policy)
        expected_exit = exit_code_for_summary(
            profile, current.get("summary", {}), policy, False
        )
    elif identity == "naos_opencode_config_hygiene":
        declaration, source = producer.resolve_declaration_path(root, naos_root, policy)
        current = producer.build_report(
            root=root, naos_root=naos_root, profile=profile, policy=policy,
            declaration_path=declaration, declaration_source=source,
        )
        expected_exit = exit_code_for_summary(
            profile, current.get("summary", {}), policy, False
        )
    elif identity == "naos_cross_harness_review_readiness":
        current, summary = producer.build_report(
            Namespace(
                profile=profile,
                naos_root=naos_root,
                policy=policy.get("_meta", {}).get("path"),
                input=None,
            )
        )
        expected_exit = exit_code_for_summary(profile, summary, policy, False)
    else:
        current = producer.build_report(
            root=root, naos_root=naos_root, policy=policy, profile=profile
        )
        expected_exit = exit_code_for_summary(
            profile, current.get("summary", {}), policy, False
        )
    _schema(current, supported[identity])
    # This producer reports structural readiness to begin baseline work, not
    # completed behavioral evaluation. Preserve its actual status and non-claims.
    accepted_statuses = ({"ready_to_baseline", "baseline_current"}
                         if identity == "naos_behavioral_governance_readiness"
                         else {"ready", "pass", "not_applicable"})
    if optional_inactive:
        accepted_statuses = accepted_statuses | {"not_configured", "disabled", "not_run"}
    if (
        current.get("findings")
        or current.get("status") not in accepted_statuses
        or any(
            finding_counts(current.get("findings", []))[k]
            for k in ("blocking", "required", "warnings", "advisory")
        )
    ):
        _deny("independent_replayed_producer_finding", identity)
    if check.get("returncode") != expected_exit or expected_exit != 0:
        _deny("independent_replayed_exit_mismatch", identity)
    if identity == "naos_audit_log":
        # Registered report writes append valid audit observations. Their exact
        # runtime projection is excluded from authored bindings; original counts
        # stay in F. Validate both historical and current clean summary shapes.
        historic = check.get("summary", {})
        if (
            set(historic) != set(current["summary"])
            or historic.get("status") != "ready"
            or any(
                type(historic.get(k)) is not int or historic[k] < 1
                for k in ("events", "event_files")
            )
            or any(
                historic.get(k) != 0
                for k in (
                    "invalid_events",
                    "missing_session_id_events",
                    "missing_operator_id_events",
                )
            )
            or check.get("status") != "ready"
            or check.get("findings") != []
        ):
            _deny("independent_replayed_content_mismatch", identity)
        observation = {
            "status": "ready",
            "findings": [],
            "invalid_events": 0,
            "missing_session_id_events": 0,
            "missing_operator_id_events": 0,
        }
    else:
        if any(
            check.get(k) != current.get(k, {} if k == "summary" else [])
            for k in ("status", "summary", "findings")
        ):
            _deny("independent_replayed_content_mismatch", identity)
        observation = {k: current.get(k) for k in ("status", "summary", "findings")}
    return {
        "check_id": identity,
        "basis": "actual_read_only_producer_reproduction",
        "schema": current["schema"],
        "producer_status": current["status"],
        "observation_sha256": _digest(observation),
    }


def _validate_current_classification(
    root: Path, profile: str, naos_root: str, policy: dict
) -> dict:
    from argparse import Namespace
    import naos_evidence_classification as classifier

    current, _ = classifier.build_report(
        Namespace(
            profile=profile,
            naos_root=naos_root,
            policy=policy.get("_meta", {}).get("path"),
            input=None,
            report=[],
        )
    )
    if (
        current["status"] != "ready"
        or current.get("findings")
        or current.get("missing_classification")
        or current.get("unknown_findings")
    ):
        _deny("current_provenance_unresolved")
    # Current classified aggregate items may legitimately change after gate output
    # refresh. Each run still reproduces and enforces every provenance predicate.
    # Historical producer evidence is separately retained, never relabelled clean.
    return {
        "status": "ready",
        "basis": "actual_current_provenance_producer_reproduction",
    }


def _preflight_attestation_raw_match(
    root: Path, profile: str, naos_root: str, policy: dict,
    report: dict, context: dict,
) -> None:
    """Reject this already-required mismatch before costly component replay.

    Equality grants no authority. The ordinary independent collector still
    rereads and checks this report, and every existing proof predicate remains.
    """
    import naos_self_check as sc
    import naos_evidence_contracts as ec

    checks = report["checks"]
    if [check["id"] for check in checks] != sc.selected_check_ids(
        root, profile, naos_root, policy, **context
    ):
        _deny("full_check_inventory_mismatch")
    plan = sc.selected_script_checks(root, profile, naos_root, policy, **context)
    selected = [
        (check, script) for check, (script, _args) in zip(checks[4:], plan)
        if check["id"] == "naos_evidence_attestation"
        or script == "naos_evidence_attestation.py"
    ]
    if len(selected) != 1 or selected[0][0]["id"] != "naos_evidence_attestation":
        _deny("unsupported_independent_producer_contract", "naos_evidence_attestation")
    check, script = selected[0]
    if script != "naos_evidence_attestation.py":
        _deny("unsupported_independent_producer_contract", check["id"])
    output_key = _output_key(script)
    descriptors = [d for d in ec.REPORT_REGISTRY.values()
                   if d.output_key == output_key]
    if len(descriptors) != 1 or descriptors[0].key != "evidence_attestation":
        _deny("unsupported_independent_producer_contract", check["id"])
    data, _sha = _json(root, _report_path(root, naos_root, policy, output_key))
    _schema(data, descriptors[0].schema_file)
    if any(data.get(key) != value for key, value in {
        "profile": profile, "project_root": str(root), "naos_root": naos_root,
    }.items()):
        _deny("independent_evidence_unresolved", f"{check['id']}:['scope_mismatch']")
    _raw_match(check, data, profile=profile, policy=policy)


def _missing_independent_gate_preflight(
    root: Path, profile: str, naos_root: str, policy: dict,
) -> bool:
    """Prove one literal enforcing prerequisite absent; never grant readiness.

    Ambiguous, optional, team-specific, unsafe and nonmissing cases retain the
    ordinary full proof. A negative result needs no source-stability claim.
    With simultaneous defects, this missing-prerequisite refusal may precede
    the ordinary inventory or attestation refusal; it never grants readiness.
    """
    import stat
    import naos_evidence_contracts as ec
    import naos_gate_status as gs
    from naos_policy import kit_root

    def local(path: Path) -> bool:
        return path.is_relative_to(root) and ".." not in path.parts

    def guarded_text(path: Path) -> str:
        if not local(path):
            _deny("unsafe_or_missing_input", path)
        # Match Path.read_text's universal-newline interpretation, with the
        # same strong operand guard as the ordinary resolution inventory.
        return _bytes(root, path).decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")

    try:
        selected_manifest = root / naos_root / "gatekeepers.yaml"
        if not local(selected_manifest) or ec._safe_file(root, selected_manifest) != "available":
            return False
        location = gs.resolve_manifest(None, naos_root)
        path = location.path if location.path.is_absolute() else root / location.path
        if location.source != "project" or not local(path):
            return False
        manifest = yaml.safe_load(_bytes(root, path))
        kit = kit_root().resolve()
        gs.validate_manifest(manifest, _schema_bytes=_bytes(kit, kit / "schemas/naos/gatekeeper.schema.json"))
        candidates = []
        for gate in manifest["gates"]:
            if (gate["id"] not in REQUIRED_GATES[:-1] or not gate.get("enabled", True)
                    or gate.get("team_overrides")
                    or gate["severity_by_profile"].get(profile) not in {"blocking", "required", "warning"}):
                continue
            for reference in gate.get("required_evidence", []):
                parts = ec._safe_parts(reference, glob_allowed=False)
                requirement = gate.get("evidence_requirements", {}).get(reference, {"type": "report"})
                if parts is None or requirement.get("optional") is True or requirement.get("type", "report") != "report":
                    continue
                descriptor, current = ec._descriptor_for(root, reference, naos_root, policy)
                if descriptor is None or descriptor.manual or not current:
                    continue
                if ec._safe_file(root, root.joinpath(*parts)) == "missing":
                    candidates.append((gate, reference, requirement))
        if not candidates:
            return False
        # Guard directories before the existing maturity helper enumerates them.
        for directory in (root / naos_root / "capabilities", root / "capabilities"):
            if not local(directory):
                return False
            availability = ec._safe_file(root, directory)
            if availability == "missing":
                continue
            if availability != "not_regular_file" or not stat.S_ISDIR(directory.lstat().st_mode):
                return False
            break
        state = root / naos_root / str(policy.get("paths", {}).get("capability_state") or "capability_state.yaml")
        if not local(state) or ec._safe_file(root, state) not in {"available", "missing"}:
            return False
        maturity = gs.build_gate_maturity_map(root, naos_root, policy, profile, _read_text=guarded_text)
        for gate, reference, requirement in candidates:
            effective, _, findings, _ = gs.apply_team_override(gate, profile, {})
            if findings or not effective["enabled"]:
                continue
            severity = effective["severity"]
            dependency = maturity.get(gate["id"], {})
            if dependency.get("capabilities"):
                ceiling = dependency.get("gated_severity") or "none"
                if gs.SEVERITY_ORDER.get(ceiling, 0) < gs.SEVERITY_ORDER.get(severity, 0):
                    severity = ceiling
            if severity not in {"blocking", "required", "warning"}:
                continue
            descriptor, current = ec._descriptor_for(root, reference, naos_root, policy)
            if descriptor is None or descriptor.manual or not current:
                continue
            # Reproduce only the existing classifier's missing branch. The
            # required current registered reference is nonoptional, so its
            # _optional_disabled check returns False without declaration reads.
            # Reobserve absence; a newly present report stays on the full path
            # and is never read here. Equivalence regressions guard future drift.
            result = ec._result(reference)
            result.update(resolved_paths=[reference], report_key=descriptor.key,
                expected_schema=descriptor.schema_id, claim_ceiling=descriptor.claim_ceiling,
                availability=ec._safe_file(root, root / reference))
            result["reason_codes"].append(result["availability"])
            if (result["availability"] == "missing" and result["applicability"] == "applicable"
                    and result["requirement_outcome"] == "unresolved"):
                return True
    except (ResolutionRefusal, OSError, ValueError, TypeError, KeyError, yaml.YAMLError):
        pass  # The original proof remains responsible for every other refusal.
    return False


def _independent_checks(
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict,
    report: dict,
    context: dict,
    gate_context: dict,
) -> list[dict]:
    import naos_self_check as sc
    import naos_evidence_contracts as ec
    from naos_policy import finding_counts, status_from_counts

    plan = sc.selected_script_checks(root, profile, naos_root, policy, **context)
    expected = sc.selected_check_ids(root, profile, naos_root, policy, **context)
    checks = report.get("checks", [])
    if [c.get("id") for c in checks] != expected:
        _deny("full_check_inventory_mismatch")
    counts = {
        **finding_counts([f for c in checks for f in c.get("findings", [])]),
        "checks": len(checks),
    }
    if report.get("summary") != counts or report.get("status") != status_from_counts(
        counts
    ):
        _deny("full_check_counter_mismatch")
    local = [
        sc.validate_capability_contracts(root, profile, naos_root, policy),
        sc.validate_gatekeeper_manifest(root, profile, naos_root, policy),
        sc.validate_maturity_and_profiles(root, profile, naos_root, policy),
        sc.validate_profile_rules_regeneration(root, profile, policy),
    ]
    decisions = []
    for stored, current in zip(checks[:4], local):
        if (
            stored != current
            or current.get("findings")
            or current.get("status") not in {"pass", "not_applicable"}
        ):
            _deny("local_validator_not_current_clean", stored.get("id"))
        decisions.append(
            {"check_id": stored["id"], "basis": "actual_local_validator_reproduction"}
        )
    descriptors = list(ec.REPORT_REGISTRY.values()) + list(
        ec.MATURITY_SUPPORT_REPORT_REGISTRY.values()
    )
    for check, (script, _args) in zip(checks[4:], plan):
        if check["id"] in DEFERRED:
            continue
        primitive = getattr(ec, "_self_check_primitive_contract", lambda *a, **k: None)(
            check, root=root, profile=profile, naos_root=naos_root, policy=policy
        )
        if primitive is not None:
            decisions.append(
                {
                    "check_id": check["id"],
                    "basis": "primitive_current_source_contract",
                    "decision": primitive,
                }
            )
            continue
        replay = _replay_independent(
            check, root=root, profile=profile, naos_root=naos_root, policy=policy
        )
        if replay is not None:
            decisions.append(replay)
            continue
        output_key = _output_key(script)
        path = _report_path(root, naos_root, policy, output_key)
        data, sha = _json(root, path)
        _raw_match(check, data, profile=profile, policy=policy)
        matching = [d for d in descriptors if d.output_key == output_key]
        if len(matching) != 1:
            _deny("unsupported_independent_producer_contract", check["id"])
        reference = path.relative_to(root).as_posix()
        req = dict(gate_context.get("evidence_requirements", {}).get(reference, {}))
        req["_self_check_gate_context"] = gate_context
        selected_consumer = (
            "gate" if matching[0].key in ec.REPORT_REGISTRY else "maturity_support"
        )
        evidence = ec.classify_evidence(
            root,
            reference,
            profile=profile,
            naos_root=naos_root,
            policy=policy,
            requirement=req,
            consumer=selected_consumer,
        )
        if evidence["requirement_outcome"] not in {"satisfied", "not_applicable"}:
            _deny(
                "independent_evidence_unresolved",
                f"{check['id']}:{evidence.get('reason_codes')}",
            )
        if evidence.get("content_sha256") != sha:
            _deny("changed_independent_evidence", reference)
        decisions.append(
            {
                "check_id": check["id"],
                "basis": "current_typed_report_contract",
                "decision": evidence,
            }
        )
    return decisions


def _collect_gate_obligations(
    root: Path, profile: str, naos_root: str, policy: dict, self_reference: str
) -> tuple[dict, dict]:
    """Run the REAL manifest evaluator; collect unsatisfied F slots, never ready."""
    import naos_gate_status as gs

    location = gs.resolve_manifest(None, naos_root)
    manifest = gs.load_manifest(location.path)
    current = gs.evaluate_manifest(manifest, profile, location, naos_root, policy)
    ids = [g["id"] for g in current["gates"]]
    if len(ids) != len(set(ids)) or not set(REQUIRED_GATES).issubset(ids):
        _deny("required_gate_inventory_mismatch")
    if current.get("protected_invariant_violations"):
        _deny("protected_gate_invariant_violation")
    # Source-owned PR predicate is explicit about valid advisory gaps. This
    # private projection removes only the separately collected internal G6 row;
    # it never leaves this collector or purports to be a complete gate report.
    from naos_evidence_contracts import _maturity_aggregate_outcome

    independent_rows = [g for g in current["gates"] if g["id"] != "G6"]
    private_projection = deepcopy(current)
    private_projection["gates"] = independent_rows
    private_projection["summary"] = {
        name: sum(g.get("status") == name for g in independent_rows)
        for name in (
            "ready",
            "blocked",
            "required_missing",
            "warning",
            "advisory_missing",
            "not_applicable",
        )
    }
    private_projection["summary"]["total"] = len(independent_rows)
    private_projection["evaluation_scope"]["selected_count"] = len(independent_rows)
    ok, reasons = _maturity_aggregate_outcome(
        private_projection, "gate_status", policy, permit_advisory_gaps=True
    )
    if not ok:
        _deny("independent_pr_gate_contract_unresolved", reasons)
    slots, optional = [], []
    for gate in current["gates"]:
        if gate["id"] not in REQUIRED_GATES:
            if (gate.get("severity") not in {"none", "advisory"}
                    and (gate.get("status") != "ready" or gate.get("readiness") != "ready")):
                _deny("unsupported_additional_enforcing_gate", gate["id"])
            optional.append(
                {
                    "id": gate["id"],
                    "status": gate["status"],
                    "severity": gate["severity"],
                }
            )
            continue
        if gate["id"] != "G6" and (
            gate.get("status") != "ready" or gate.get("readiness") != "ready"
        ):
            _deny("required_independent_gate_not_ready", gate["id"])
        if gate["id"] == "G6" and (
            any(ref != self_reference for ref in gate.get("unresolved_evidence", []))
            or gate.get("missing_evidence")
        ):
            _deny("g6_unaccounted_evidence_failure")
        if gate.get("missing_inputs") or any(
            x.get("status") != "pass" for x in gate.get("semantic_evidence", [])
        ):
            _deny("independent_gate_input_or_semantics", gate["id"])
        if any(
            x.get("severity") in {"blocking", "required", "warning"}
            for x in gate.get("team_override_findings", [])
        ):
            _deny("gate_override_finding", gate["id"])
        for evidence in gate.get("evidence_results", []):
            if evidence["reference"] == self_reference:
                if gate["id"] != "G6" or evidence.get("report_key") != "self_check":
                    _deny("unsupported_self_check_gate_edge", gate["id"])
                if any(
                    evidence.get(k) != v
                    for k, v in {
                        "availability": "available",
                        "validation": "valid",
                        "scope": "matched",
                    }.items()
                ):
                    _deny(
                        "invalid_internal_self_check_slot", evidence.get("reason_codes")
                    )
                slots.append(
                    {
                        "gate_id": gate["id"],
                        "reference": self_reference,
                        "observed_requirement_outcome": evidence["requirement_outcome"],
                    }
                )
            elif evidence["requirement_outcome"] not in {"satisfied", "not_applicable"}:
                _deny("independent_gate_evidence_unresolved", evidence["reference"])
    if len(slots) != 1:
        _deny("canonical_g6_full_self_check_required")
    g6 = next(g for g in manifest["gates"] if g["id"] == "G6")
    gate_context = {
        "gate_id": "G6",
        "evidence_requirements": {
            ref: g6.get("evidence_requirements", {}).get(
                ref, {"type": "report" if ref.endswith(".json") else "manual"}
            )
            for ref in g6.get("required_evidence", [])
        },
    }
    return {
        "status": "independent_gate_obligations_satisfied",
        "internal_slots": slots,
        "required_gate_ids": list(REQUIRED_GATES),
        "optional_gates_retained": optional,
    }, gate_context


def _collect_l3_gate_obligations(
    root: Path, profile: str, naos_root: str, policy: dict, self_reference: str,
    *, freshness_window_days: int,
) -> dict:
    """Private exact F-slot projection after full independent-check reproduction.

    Never publish this projection or change any report. Every other selected gate
    remains subject to the ordinary strict maturity aggregate predicate. Stored
    reports must bind the current manifest, independent facts and fresh scope.
    """
    import naos_gate_status as gs
    import naos_gate_evaluate as ge
    import naos_evidence_contracts as ec
    location = gs.resolve_manifest(None, naos_root)
    manifest = gs.load_manifest(location.path)
    current = gs.evaluate_manifest(manifest, profile, location, naos_root, policy)
    projected = deepcopy(current)
    internal = []
    for gate in projected["gates"]:
        selected = [e for e in gate.get("evidence_results", [])
                    if e.get("reference") == self_reference]
        if not selected:
            continue
        if gate["id"] != "G6" or len(selected) != 1:
            _deny("unsupported_l3_self_gate_edge", gate["id"])
        slot = selected[0]
        current_f, _ = _json(root, root / self_reference)
        ec._generation_age(slot, root / self_reference, current_f,
            {"freshness_window_days": freshness_window_days})
        if (slot.get("report_key") != "self_check"
                or any(slot.get(k) != v for k, v in {
                    "availability": "available", "validation": "valid", "scope": "matched"
                }.items())
                or slot.get("generation_age", {}).get("status") not in {
                    "within_window", "not_enforced"}):
            _deny("invalid_l3_self_gate_slot")
        if (gate.get("missing_inputs") or gate.get("missing_evidence")
                or any(r != self_reference for r in gate.get("unresolved_evidence", []))
                or any(e.get("requirement_outcome") not in {"satisfied", "not_applicable"}
                    for e in gate["evidence_results"] if e is not slot)
                or any(e.get("status") != "pass" for e in gate.get("semantic_evidence", []))):
            _deny("independent_l3_g6_obligation_unresolved")
        slot["requirement_outcome"] = "satisfied"
        gate["unresolved_evidence"] = []
        gate["status"] = "ready"
        gate["readiness"] = "ready"
        internal.append({"gate_id": gate["id"], "reference": self_reference})
    if len(internal) != 1:
        _deny("canonical_l3_g6_self_slot_required")
    statuses = ("ready", "blocked", "required_missing", "warning", "advisory_missing", "not_applicable")
    projected["summary"] = {name: sum(g["status"] == name for g in projected["gates"])
                            for name in statuses}
    projected["summary"]["total"] = len(projected["gates"])
    ok, reasons = ec._maturity_aggregate_outcome(projected, "gate_status", policy)
    if not ok:
        _deny("independent_l3_selected_gate_unresolved", reasons)

    # Compare precise gate obligations, not unrelated derived dashboard/audit
    # projections. The one historical F row may reflect an earlier F; it is not
    # trusted as current success. The current complete F proof owns that edge.
    independent_fields = ("id", "enabled", "severity", "missing_inputs", "semantic_evidence",
                          "team_override_findings", "team_overrides_rejected")
    gate_reports = []
    for key, schema in (("gate_status_report", "gate_status.schema.json"),
                        ("gate_evaluation_report", "gate_evaluation.schema.json")):
        path = _report_path(root, naos_root, policy, key)
        reference = path.relative_to(root).as_posix()
        stored, _ = _json(root, path)
        _schema(stored, schema)
        if any(stored.get(k) != v for k, v in {
                "profile": profile, "project_root": str(root), "naos_root": naos_root}.items()):
            _deny("l3_gate_report_scope_mismatch", reference)
        evidence = ec.classify_evidence(root, reference, profile=profile,
            naos_root=naos_root, policy=policy, consumer="maturity",
            requirement={"freshness_window_days": freshness_window_days})
        if (any(evidence.get(k) != v for k, v in {
                "availability": "available", "validation": "valid", "scope": "matched"}.items())
                or evidence.get("generation_age", {}).get("status") not in {
                    "within_window", "not_enforced"}):
            _deny("invalid_or_stale_l3_gate_report", reference)
        slots = _declared_gate_dependency_slots(root, stored, profile=profile,
                    naos_root=naos_root, policy=policy)
        if set(slots) != {"G6"} or [g["id"] for g in stored["gates"]] != [g["id"] for g in current["gates"]]:
            _deny("l3_gate_report_selection_mismatch", reference)
        expected_summary = {name: sum(g.get("status") == name for g in stored["gates"])
                            for name in statuses}
        expected_summary["total"] = len(stored["gates"])
        if stored.get("summary") != expected_summary or stored.get("protected_invariant_violations"):
            _deny("l3_recorded_gate_counter_or_invariant_invalid", reference)
        if stored.get("team_id") != current.get("team_id"):
            _deny("l3_recorded_team_context_changed", reference)
        for old, live in zip(stored["gates"], current["gates"]):
            if any(old.get(k) != live.get(k) for k in independent_fields):
                _deny("l3_independent_gate_facts_changed", old["id"])
            old_rows, live_rows = old.get("evidence_results", []), live.get("evidence_results", [])
            if [e.get("reference") for e in old_rows] != [e.get("reference") for e in live_rows]:
                _deny("l3_gate_evidence_membership_changed", old["id"])
            for prior, now in zip(old_rows, live_rows):
                if prior["reference"] != self_reference:
                    if prior != now:
                        _deny("l3_independent_gate_evidence_changed", old["id"])
                elif (any(prior.get(k) != v for k, v in {
                        "report_key": "self_check", "availability": "available", "validation": "valid", "scope": "matched"}.items())
                        or prior.get("generation_age", {}).get("status") not in {"within_window", "not_enforced"}):
                    _deny("invalid_historical_l3_self_slot")
            if old["id"] == "G6":
                unresolved = [e["reference"] for e in old_rows if e.get("requirement_outcome") == "unresolved"]
                missing = [e["reference"] for e in old_rows if e.get("availability") == "missing"
                           and e.get("requirement_outcome") == "unresolved"]
                if (any(r != self_reference for r in unresolved) or missing
                        or old.get("unresolved_evidence") != unresolved
                        or old.get("missing_evidence") != missing):
                    _deny("historical_l3_g6_not_exact_internal_edge")
                status = ({"advisory": "advisory_missing", "warning": "warning",
                           "required": "required_missing", "blocking": "blocked"}.get(old["severity"])
                          if unresolved else "ready")
                if (old.get("enabled") is not True or old.get("status") != status
                        or old.get("readiness") != ("unresolved" if unresolved else "ready")):
                    _deny("historical_l3_g6_outcome_not_reproducible")
            if old["id"] != "G6" and any(old.get(k) != live.get(k) for k in
                    ("status", "readiness", "missing_evidence", "unresolved_evidence")):
                _deny("l3_independent_gate_outcome_changed", old["id"])
        # Enforcing metadata is reproduced from the recorded ordinary rows. Its
        # nonzero exit remains historical; only the private projection advances.
        if key == "gate_evaluation_report":
            meta = stored.get("enforcement", {})
            if type(meta.get("strict")) is not bool or type(meta.get("strict_required")) is not bool:
                _deny("invalid_l3_gate_enforcement")
            expected = ge.enforcement_metadata(stored, policy,
                strict=meta["strict"], strict_required=meta["strict_required"])
            if meta != expected:
                _deny("l3_gate_enforcement_not_reproducible")
            private_evaluation = deepcopy(projected)
            private_evaluation["enforcement"] = ge.enforcement_metadata(private_evaluation, policy,
                strict=meta["strict"], strict_required=meta["strict_required"])
            ok, reasons = ec._maturity_aggregate_outcome(private_evaluation, "gate_evaluation", policy)
            if not ok:
                _deny("independent_l3_gate_enforcement_unresolved", reasons)
        gate_reports.append(reference)
    # Stable proof binds current independent evidence and selected gates. Derived
    # aggregate bytes may change when this exact proof is published and consumed.
    return {"status": "independent_l3_gate_obligations_satisfied",
            "gate_reports": gate_reports, "internal_slots": internal,
            "freshness_window_days": freshness_window_days,
            "selected_gate_ids": [g["id"] for g in projected["gates"]],
            "ready_link_ids": [g["id"] for g in projected["gates"] if g["status"] == "ready"],
            "independent_rows": [{k: g[k] for k in ("id", "status", "readiness", "severity")}
                                 for g in projected["gates"] if g["id"] != "G6"]}


def _collect_maturity_obligations(
    root: Path, profile: str, naos_root: str, policy: dict, self_reference: str
) -> dict:
    import naos_capability_maturity as maturity

    state = maturity.resolve_state_path(root, naos_root, policy, None)
    current = maturity.build_report(
        root=root, profile=profile, naos_root=naos_root, policy=policy, state_path=state
    )
    slots = []
    enabled = [c for c in current["capabilities"] if c.get("enabled")]
    if any(maturity.maturity_index(c.get(k)) is None or maturity.maturity_index(c.get(k)) >= 4
           for c in enabled for k in ("current_maturity", "target_maturity")):
        _deny("unsupported_maturity_dependency_scope")
    if any(maturity.maturity_index(c.get("current_maturity")) >= 3 for c in enabled):
        _deny("unsupported_current_maturity_dependency_scope")
    l3_caps = [c for c in enabled if max(maturity.maturity_index(c.get(k)) for k in
              ("current_maturity", "target_maturity")) == 3]
    from naos_policy import evidence_staleness_days
    state_entries = maturity.normalize_state_entries(yaml.safe_load(_bytes(root, state)), state)
    windows = [state_entries[c["capability_id"]].get("freshness_window_days", evidence_staleness_days(policy))
               for c in l3_caps]
    if any(type(window) is not int or window < 0 for window in windows):
        _deny("invalid_l3_freshness_window")
    l3 = (_collect_l3_gate_obligations(root, profile, naos_root, policy, self_reference,
                freshness_window_days=min([w for w in windows if w > 0], default=0)) if l3_caps else None)
    contracts = maturity.load_capability_contracts(root, naos_root, profile)
    allowed_l3 = set()
    for cap in enabled:
        if max(maturity.maturity_index(cap.get(k)) for k in
               ("current_maturity", "target_maturity")) == 3:
            contract = contracts.get(cap["capability_id"])
            if not isinstance(contract, dict):
                _deny("missing_l3_capability_contract", cap["capability_id"])
            linked = contract.get("gatekeepers")
            if (not isinstance(linked, list) or not linked
                    or any(not isinstance(g, str) or not re.fullmatch(r"G[0-8]", g) for g in linked)
                    or len(linked) != len(set(linked)) or not set(linked).issubset(l3["selected_gate_ids"])
                    or not set(linked) & set(l3["ready_link_ids"])):
                _deny("independent_l3_capability_gate_linkage", cap["capability_id"])
            allowed_l3.add(cap["capability_id"])
    for cap in current["capabilities"]:
        if not cap.get("enabled"):
            continue
        levels = [
            maturity.maturity_index(cap.get(k))
            for k in ("current_maturity", "target_maturity")
        ]
        if any(x is None or x >= 4 for x in levels):
            _deny("unsupported_maturity_dependency_scope", cap["capability_id"])
        findings = cap.get("blocking_findings", []) + cap.get("advisory_findings", [])
        if cap["capability_id"] in allowed_l3:
            findings = [f for f in findings if f.get("status") != "missing_gate_evidence"]
        is_self = cap["capability_id"] == "CAP-SELF-CONFORMANCE"
        if findings and (
            not is_self
            or any(
                f.get("status") not in {"missing_evidence", "unresolved_evidence"}
                for f in findings
            )
        ):
            _deny("independent_maturity_finding", cap["capability_id"])
        if is_self and findings:
            if cap.get("missing_evidence") or cap.get("stale_evidence"):
                _deny("missing_or_stale_self_maturity_evidence")
            expected_unresolved = [self_reference] + (l3["gate_reports"] if cap["capability_id"] in allowed_l3 else [])
            if sorted(cap.get("unresolved_evidence", [])) != sorted(expected_unresolved):
                _deny("unsupported_self_maturity_reference")
        if max(levels) >= 2:
            for result in cap.get("evidence_results", []):
                if result.get("stage") == "L3" and cap["capability_id"] in allowed_l3:
                    if (result["reference"] not in l3["gate_reports"]
                            or any(result.get(k) != v for k, v in {
                                "availability": "available", "validation": "valid", "scope": "matched"}.items())
                            or result.get("generation_age", {}).get("status") not in {"within_window", "not_enforced"}):
                        _deny("invalid_or_stale_l3_maturity_slot", cap["capability_id"])
                    slots.append({"capability_id": cap["capability_id"], "reference": result["reference"], "stage": "L3"})
                    continue
                if is_self and result["reference"] == self_reference:
                    if any(
                        result.get(k) != v
                        for k, v in {
                            "availability": "available",
                            "validation": "valid",
                            "scope": "matched",
                        }.items()
                    ):
                        _deny("invalid_maturity_self_slot")
                    if result.get("generation_age", {}).get("status") not in {
                        "within_window",
                        "not_enforced",
                    }:
                        _deny("stale_maturity_self_slot")
                    slots.append(
                        {
                            "capability_id": cap["capability_id"],
                            "reference": self_reference,
                        }
                    )
                elif result["requirement_outcome"] not in {
                    "satisfied",
                    "not_applicable",
                }:
                    _deny(
                        "independent_maturity_evidence_unresolved", result["reference"]
                    )
    for finding in current.get("findings", []):
        if finding.get("id") in allowed_l3 and finding.get("status") == "missing_gate_evidence":
            if (finding.get("classification_scope") != "generated_typed_evidence_requirement_observation_only"
                    or finding.get("selected_evidence_references") != l3["gate_reports"]):
                _deny("unbound_l3_maturity_observation", finding.get("id"))
            continue
        if finding.get("id") != "CAP-SELF-CONFORMANCE" or finding.get("status") not in {
            "missing_evidence",
            "unresolved_evidence",
        }:
            _deny("independent_maturity_finding", finding.get("id"))
    return {
        "status": "independent_maturity_obligations_satisfied",
        "internal_slots": slots,
        "current_findings": current["findings"],
        "capabilities": current["capabilities"],
        "l3_gate_obligations": l3,
    }


def _finding_core(finding: dict) -> dict:
    return {
        k: finding[k]
        for k in (
            "id",
            "severity",
            "status",
            "message",
            "field",
            "selected_evidence_references",
        )
        if k in finding
    }


def _collect_pr_obligations(
    root: Path, profile: str, naos_root: str, policy: dict
) -> dict:
    import naos_pr_governance_summary as pr

    current = pr.build_report(root, naos_root, profile, policy)
    allowed = {
        "pr_governance.gate_status_unresolved",
        "pr_governance.gate_evaluation_unresolved",
        "pr_governance.gates_failed",
    }
    for finding in current["findings"]:
        if finding["id"] == "pr_governance.ci_not_detected":
            # This exact producer-declared local-preview limitation is not CI proof.
            if (
                finding.get("severity") != "advisory"
                or finding.get("classification_scope")
                != "local_ci_environment_observation"
            ):
                _deny("invalid_local_preview_observation")
        elif finding["id"] in {
            "pr_governance.gate_status_advisory_unresolved",
            "pr_governance.gate_evaluation_advisory_unresolved",
        }:
            if (
                finding.get("severity") != "advisory"
                or finding.get("status") != "advisory_gates_unresolved"
                or finding.get("observed_gate_projection", {}).get("required_readiness")
                != "ready"
            ):
                _deny("invalid_non_enforcing_gate_observation")
        elif finding["id"] not in allowed:
            _deny("independent_pr_finding", finding["id"])
    return {
        "status": "independent_pr_obligations_satisfied",
        "current_findings": current["findings"],
        "ci_detected": current.get(
            "ci_detected", current.get("ci_provider") != "not_detected"
        ),
    }


def _validate_raw_aggregate(
    check: dict,
    data: dict,
    current_findings: list[dict],
    *,
    profile: str,
    policy: dict,
    node: str,
) -> list[dict]:
    _raw_match(check, data, profile=profile, policy=policy)
    if data.get("profile") != profile:
        _deny("aggregate_profile_mismatch", node)
    current_cores = [_finding_core(f) for f in current_findings]
    raw_cores = [_finding_core(f) for f in data.get("findings", [])]
    if node == "M" and raw_cores != current_cores:
        # First full F may not exist at M collection time. Its recorded absence
        # is a historical internal dependency observation, never a producer pass.
        # Current M has already proved this precise F reference present, valid,
        # scoped and fresh; complete F independent obligations are checked first.
        for f in data.get("findings", []):
            if (
                f.get("id") != "CAP-SELF-CONFORMANCE"
                or f.get("status") != "missing_evidence"
                or f.get("message")
                != "Operational maturity requires applicable satisfied evidence references."
                or f.get("severity") != __import__("naos_policy").severity_for_profile(profile, policy)
            ):
                _deny("historical_aggregate_diagnosis_not_current_reproducible", node)
            observed = f.get("observed_evidence_results")
            selected = f.get("selected_evidence_references")
            current_refs = {
                r
                for c in current_cores
                for r in c.get("selected_evidence_references", [])
            }
            if (
                not isinstance(observed, list)
                or len(observed) != 1
                or selected != [observed[0].get("reference")]
                or set(selected) != current_refs
                or observed[0].get("availability") != "missing"
                or observed[0].get("requirement_outcome") != "unresolved"
            ):
                _deny("historical_missing_evidence_not_internal_self_slot")
        if len(data.get("findings", [])) != 1:
            _deny("historical_aggregate_diagnosis_not_current_reproducible", node)
    if node == "R":
        echo_ids = {
            "pr_governance.gate_status_unresolved",
            "pr_governance.gate_evaluation_unresolved",
            "pr_governance.gates_failed",
        }
        advisory_ids = {
            "pr_governance.gate_status_advisory_unresolved",
            "pr_governance.gate_evaluation_advisory_unresolved",
        }
        # Historical echoes may differ from current gates after F collection;
        # they must still be the complete exact observations of their own raw
        # producer projection. This is not a ready-gate or approval projection.
        projections = data.get("gate_readiness")
        if not isinstance(projections, dict) or set(projections) != {
            "gate_status", "gate_evaluation"
        }:
            _deny("historical_pr_projection_inventory_invalid")
        expected_echoes = []
        for label, projection in projections.items():
            if not isinstance(projection, dict):
                _deny("historical_pr_projection_invalid", label)
            if projection.get("readiness") != "ready":
                suffix = ("advisory_unresolved" if
                    projection.get("required_readiness") == "ready" else "unresolved")
                expected_echoes.append(f"pr_governance.{label}_{suffix}")
        compact_summary = data.get("gate_evaluation_summary")
        if not isinstance(compact_summary, dict):
            _deny("historical_pr_compact_summary_invalid")
        gate_summary = compact_summary.get("summary", {})
        if not isinstance(gate_summary, dict):
            _deny("historical_pr_gate_summary_invalid")
        for key in ("blocked", "required_missing"):
            if key in gate_summary and (
                type(gate_summary[key]) is not int or gate_summary[key] < 0
            ):
                _deny("historical_pr_gate_count_invalid", key)
        if gate_summary.get("blocked") or gate_summary.get("required_missing"):
            expected_echoes.append("pr_governance.gates_failed")
        if sorted(f["id"] for f in raw_cores if f["id"] in echo_ids | advisory_ids) != sorted(expected_echoes):
            _deny("historical_pr_echo_inventory_mismatch")
        for finding in data.get("findings", []):
            if finding.get("id") not in (echo_ids | advisory_ids) - {"pr_governance.gates_failed"}:
                continue
            label = finding["id"].removeprefix("pr_governance.").split("_advisory_unresolved")[0].removesuffix("_unresolved")
            projection = projections[label]
            expected_projection = {key: projection.get(key) for key in (
                "readiness", "required_readiness", "required_reason_codes",
                "validation", "scope", "reason_codes", "source_content_sha256",
            )}
            if (finding.get("observed_gate_projection") != expected_projection
                    or finding.get("source_report_sha256") != projection.get("source_content_sha256")
                    or finding.get("reason_codes") != projection.get("reason_codes")):
                _deny("historical_pr_projection_binding_mismatch", label)
        echo_severity = "required" if profile in {"standard", "assured"} else "warning"
        raw_other = [f for f in raw_cores if f["id"] not in echo_ids | advisory_ids]
        current_other = [
            f for f in current_cores if f["id"] not in echo_ids | advisory_ids
        ]
        if raw_other != current_other:
            _deny("historical_pr_independent_diagnosis_changed")
        if len([f["id"] for f in raw_cores]) != len(set(f["id"] for f in raw_cores)):
            _deny("duplicate_pr_diagnosis")
        for f in raw_cores:
            if f["id"] in advisory_ids:
                label = (
                    f["id"]
                    .removeprefix("pr_governance.")
                    .removesuffix("_advisory_unresolved")
                )
                expected = {
                    "id": f["id"],
                    "severity": "advisory",
                    "status": "advisory_gates_unresolved",
                    "message": f"{label} has advisory gaps; enforcing gate readiness is satisfied.",
                }
                if f != expected:
                    _deny("unknown_pr_advisory_shape")
                continue
            if f["id"] not in echo_ids:
                continue
            if f["id"].endswith("_unresolved"):
                label = (
                    f["id"].removeprefix("pr_governance.").removesuffix("_unresolved")
                )
                expected = {
                    "id": f["id"],
                    "severity": echo_severity,
                    "status": "gate_unresolved",
                    "message": f"{label} has no validated, applicable ready gate result.",
                }
            else:
                expected = {
                    "id": f["id"],
                    "severity": echo_severity,
                    "status": "gates_failed",
                    "message": "Gate evaluation reports blocked or required-missing gates.",
                }
            if f != expected:
                _deny("unknown_pr_echo_shape")
    for finding in data.get("findings", []):
        if node == "M":
            if (
                finding.get("classification_scope")
                != "generated_typed_evidence_requirement_observation_only"
            ):
                _deny("unbound_maturity_provenance")
            observations = finding.get("observed_evidence_results")
            if not isinstance(observations, list) or _digest(
                observations
            ) != finding.get("observed_evaluation_sha256"):
                _deny("maturity_observation_binding_invalid")
        elif finding.get("id", "").endswith("_unresolved"):
            projection = finding.get("observed_gate_projection")
            if not isinstance(projection, dict) or projection.get(
                "source_content_sha256"
            ) != finding.get("source_report_sha256"):
                _deny("pr_observation_binding_invalid")
        if finding.get("evidence_classification") != "confirmed":
            _deny("aggregate_provenance_unresolved")
    return [
        {
            "finding": deepcopy(f),
            "disposition": (
                "non_enforcing_observation_retained"
                if f.get("severity") == "advisory"
                else "derived_dependency_observation_retained"
            ),
            "current_fact_basis": "independently_replayed_producer_and_complete_component",
        }
        for f in data.get("findings", [])
    ]


def _evaluate(
    root: Path,
    *,
    profile: str,
    naos_root: str,
    policy: dict,
    self_check_report: dict,
    context: dict,
    snapshots: dict | None = None,
) -> dict:
    if profile not in {"lite", "standard", "assured"}:
        _deny("unsupported_profile", profile)
    if Path.cwd().resolve() != root:
        _deny("producer_cwd_must_match_project_root")
    if set(context) - {"pr_base_ref", "pr_head_ref", "task", "query", "graph_path"}:
        _deny("unsupported_execution_context")
    _schema(self_check_report, "self_check.schema.json")
    if any(
        self_check_report.get(k) != v
        for k, v in {
            "profile": profile,
            "naos_root": naos_root,
            "project_root": str(root),
        }.items()
    ):
        _deny("self_check_scope_mismatch")
    if _missing_independent_gate_preflight(root, profile, naos_root, policy):
        _deny("independent_pr_gate_contract_unresolved", ["selected_gate_unresolved"])
    source_before = _input_inventory(root, naos_root, policy)
    path = _report_path(root, naos_root, policy, "self_check_report")
    raw, sha = _json(root, path)
    if raw != self_check_report:
        _deny("self_check_not_canonical_bytes")
    _preflight_attestation_raw_match(root, profile, naos_root, policy, raw, context)
    self_reference = path.relative_to(root).as_posix()
    gates, gate_context = _collect_gate_obligations(
        root, profile, naos_root, policy, self_reference
    )
    independent = _independent_checks(
        root, profile, naos_root, policy, raw, context, gate_context
    )
    collection = _validate_collection_preimages(root, naos_root, policy)
    classification = _validate_current_classification(root, profile, naos_root, policy)
    maturity = _collect_maturity_obligations(
        root, profile, naos_root, policy, self_reference
    )
    pr = _collect_pr_obligations(root, profile, naos_root, policy)
    saved_snapshots, echoes = {}, []
    for node, check_id, key, schema, findings in (
        (
            "M",
            "naos_capability_maturity",
            "capability_maturity_report",
            "capability_maturity_report.schema.json",
            maturity["current_findings"],
        ),
        (
            "R",
            "naos_pr_governance_summary",
            "pr_governance_summary_report",
            "pr_governance_summary.schema.json",
            pr["current_findings"],
        ),
    ):
        if snapshots is None:
            data, content_sha = _json(root, _report_path(root, naos_root, policy, key))
        else:
            saved = snapshots.get(node, {})
            data, content_sha = saved.get("raw_report"), saved.get("content_sha256")
            if not isinstance(data, dict) or saved.get("payload_sha256") != _digest(
                data
            ):
                _deny("aggregate_snapshot_invalid", node)
        _schema(data, schema)
        check = next(c for c in raw["checks"] if c["id"] == check_id)
        echoes.extend(
            _validate_raw_aggregate(
                check, data, findings, profile=profile, policy=policy, node=node
            )
        )
        saved_snapshots[node] = {
            "report_key": key,
            "content_sha256": content_sha,
            "payload_sha256": _digest(data),
            "raw_report": data,
            "raw_check": deepcopy(check),
        }
    if _input_inventory(root, naos_root, policy) != source_before:
        _deny("inputs_changed_during_resolution")
    if _json(root, path)[1] != sha:
        _deny("self_check_changed_during_resolution")
    return {
        "self_check_reference": self_reference,
        "self_check_sha256": sha,
        "source_bindings": source_before,
        "source_binding_sha256": _digest(source_before),
        "expected_check_ids": [c["id"] for c in raw["checks"]],
        "selected_script_plan": [
            [script, args]
            for script, args in __import__("naos_self_check").selected_script_checks(
                root, profile, naos_root, policy, **context
            )
        ],
        "independent_checks": independent,
        "gate_obligations": gates,
        "current_classification": classification,
        "attestation_collection": collection,
        "maturity_internal_slots": maturity["internal_slots"],
        **({"l3_gate_obligations": maturity["l3_gate_obligations"]}
           if maturity["l3_gate_obligations"] is not None else {}),
        "aggregate_snapshots": saved_snapshots,
        "resolved_observations": echoes,
        "raw_producer_status": raw["status"],
        "raw_summary": deepcopy(raw["summary"]),
    }


def build_resolution(
    root: Path,
    *,
    profile: str,
    naos_root: str,
    policy: dict,
    self_check_report: dict,
    context: dict | None = None,
    _snapshots: dict | None = None,
) -> dict:
    from naos_policy import controlled_utc_now_text

    root = root.resolve(strict=True)
    receipt = {
        "schema": SCHEMA,
        "generated_at": controlled_utc_now_text(),
        "profile": profile,
        "project_root": str(root),
        "naos_root": naos_root,
        "context": dict(context or {}),
        "status": "unresolved",
        "refusals": [],
        "limitations": [
            "Consumer resolution retains historical producer failures; it is not producer pass, human approval or authentication.",
            "Only configured Lite/Standard/Assured current L0-L2 with targets through L3 are supported. Lite inspection does not establish behavioral readiness. Current L3, L4/L5 and unsupported scope fail closed.",
            "Read-only source reproduction does not establish remote or native-platform acceptance.",
        ],
    }
    if _ACTIVE.get():
        receipt["refusals"] = [{"code": "recursive_resolution_refused", "detail": ""}]
        return receipt
    token = _ACTIVE.set(True)
    try:
        receipt["proof"] = _evaluate(
            root,
            profile=profile,
            naos_root=naos_root,
            policy=policy,
            self_check_report=self_check_report,
            context=receipt["context"],
            snapshots=_snapshots,
        )
        receipt["status"] = "resolved"
    except ResolutionRefusal as error:
        receipt["refusals"].append({"code": error.code, "detail": error.detail})
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        StopIteration,
        yaml.YAMLError,
    ) as error:
        receipt["refusals"].append(
            {
                "code": "source_evaluation_failed",
                "detail": f"{type(error).__name__}: {error}",
            }
        )
    finally:
        _ACTIVE.reset(token)
    return receipt


def verify_resolution(
    root: Path,
    receipt: dict,
    *,
    profile: str,
    naos_root: str,
    policy: dict,
    self_check_report: dict,
    context: dict | None = None,
) -> dict:
    try:
        _schema(receipt, "self_check_dependency_resolution.schema.json")
    except (ResolutionRefusal, OSError, ValueError, TypeError) as error:
        return {
            "status": "unresolved",
            "refusals": [{"code": "invalid_resolution_receipt", "detail": str(error)}],
        }
    current = build_resolution(
        root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        self_check_report=self_check_report,
        context=context,
        _snapshots=receipt.get("proof", {}).get("aggregate_snapshots"),
    )
    if receipt.get("schema") != SCHEMA or receipt.get("status") != "resolved":
        return {
            "status": "unresolved",
            "refusals": [{"code": "missing_completed_resolution", "detail": ""}],
        }
    fields = (
        "schema",
        "profile",
        "project_root",
        "naos_root",
        "context",
        "status",
        "proof",
    )
    if current.get("status") != "resolved":
        return current
    if any(receipt.get(k) != current.get(k) for k in fields):
        return {
            "status": "unresolved",
            "refusals": [{"code": "resolution_source_or_proof_changed", "detail": ""}],
        }
    return {
        "status": "resolved",
        "resolution": deepcopy(current["proof"]),
        "raw_producer_outcome": "retained_not_relabelled",
        "refusals": [],
    }


def full_check_inventory_matches(
    root: Path,
    report: dict,
    *,
    profile: str,
    naos_root: str,
    policy: dict,
    context: dict | None = None,
) -> bool:
    """Shared ordinary and reconciled reader precondition; no status authority."""
    import naos_self_check as sc
    from naos_policy import finding_counts, status_from_counts

    try:
        _schema(report, "self_check.schema.json")
        checks = report["checks"]
        expected = sc.selected_check_ids(
            root, profile, naos_root, policy, **dict(context or {})
        )
        counts = {
            **finding_counts([f for c in checks for f in c["findings"]]),
            "checks": len(checks),
        }
        return (
            [c["id"] for c in checks] == expected
            and report["summary"] == counts
            and report["status"] == status_from_counts(counts)
        )
    except (ResolutionRefusal, OSError, ValueError, TypeError, KeyError):
        return False


def verify_published_resolution(
    root: Path,
    *,
    profile: str,
    naos_root: str,
    policy: dict,
    expected_receipt_sha256: str | None = None,
) -> dict:
    """Reader barrier for full F AND stored gate rows carrying a resolution.

    Gate readers must call this for each nested dependency_component_resolution.
    A missing receipt, new F, changed source, or unproved slot cannot survive as
    stored readiness. Calls during collection refuse rather than return success.
    """
    if resolution_in_progress():
        return {
            "status": "unresolved",
            "refusals": [{"code": "recursive_resolution_refused", "detail": ""}],
        }
    try:
        receipt, sha = _json(root, receipt_path(root, naos_root, policy))
        if expected_receipt_sha256 is not None and expected_receipt_sha256 != sha:
            _deny("resolution_receipt_binding_changed")
        report, _ = _json(
            root, _report_path(root, naos_root, policy, "self_check_report")
        )
        result = verify_resolution(
            root,
            receipt,
            profile=profile,
            naos_root=naos_root,
            policy=policy,
            self_check_report=report,
            context=receipt.get("context"),
        )
        if result.get("status") == "resolved":
            result["receipt_sha256"] = sha
        return result
    except (ResolutionRefusal, OSError, ValueError, TypeError, KeyError) as error:
        return {
            "status": "unresolved",
            "refusals": [{"code": "resolution_reader_refused", "detail": str(error)}],
        }


def apply_self_check_resolution(
    result: dict,
    report: dict,
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict,
    requirement: dict,
) -> None:
    """Final shared F hook, after ordinary/configuration-specific classification.

    Always enforce full membership, including ordinary clean reports. Resolution
    changes only the consumer outcome; producer status/findings/return codes and
    human-review flags remain untouched. An explicit stronger current-source
    requirement is not inferred from generic typed snapshot contracts.
    """
    if not full_check_inventory_matches(
        root, report, profile=profile, naos_root=naos_root, policy=policy
    ):
        result["requirement_outcome"] = "unresolved"
        result.setdefault("reason_codes", []).append(
            "self_check_full_inventory_invalid"
        )
        return
    if result.get("requirement_outcome") in {"satisfied", "not_applicable"}:
        return
    if resolution_in_progress() or requirement.get("require_current_source") is True:
        return
    if any(
        result.get(k) != v
        for k, v in {
            "availability": "available",
            "validation": "valid",
            "scope": "matched",
        }.items()
    ):
        return
    if result.get("generation_age", {}).get("status") not in {
        "within_window",
        "not_enforced",
    }:
        return
    verified = verify_published_resolution(
        root, profile=profile, naos_root=naos_root, policy=policy
    )
    if verified.get("status") != "resolved":
        return
    proof = verified["resolution"]
    if result.get("content_sha256") != proof["self_check_sha256"]:
        return
    result["requirement_outcome"] = "satisfied"
    result.setdefault("reason_codes", []).append(
        "complete_dependency_component_resolved"
    )
    result["dependency_component_resolution"] = {
        "schema": SCHEMA,
        "receipt_sha256": verified["receipt_sha256"],
        "self_check_sha256": proof["self_check_sha256"],
        "source_binding_sha256": proof["source_binding_sha256"],
        "raw_producer_status": proof["raw_producer_status"],
        "raw_findings_retained": True,
        "human_approval_recorded": False,
    }


def _declared_gate_dependency_slots(
    root: Path, report: dict, *, profile: str, naos_root: str, policy: dict
) -> dict[str, dict]:
    """Derive full-F membership from current local declarations, never result rows."""
    import naos_gate_status as gates
    from naos_policy import naos_root_path, kit_root

    canonical = naos_root_path(root, naos_root) / "gatekeepers.yaml"
    named = Path(str(report.get("manifest", "")))
    named = named if named.is_absolute() else root / named
    source = report.get("manifest_source")
    template = gates.default_template_manifest()
    if canonical.exists() or canonical.is_symlink():
        # A stored report cannot switch away from the current project declaration
        # to a different existing manifest with fewer obligations.
        if named.absolute() != canonical.absolute() or source not in {
            "project",
            "explicit",
        }:
            _deny("gate_current_manifest_binding_mismatch")
        content = _bytes(root, canonical)
    elif source == "explicit":
        content = _bytes(root, named)
    elif source == "template" and named.absolute() == template.absolute():
        content = _bytes(kit_root().resolve(), template)
    else:
        _deny("gate_current_manifest_binding_mismatch")
    manifest = yaml.safe_load(content)
    gates.validate_manifest(manifest)
    declared = manifest["gates"]
    selected = report.get("selected_gates")
    if selected is not None:
        if (
            not isinstance(report.get("enforcement"), dict)
            or not isinstance(selected, list)
            or not selected
            or any(not isinstance(x, str) for x in selected)
            or selected != sorted(set(selected))
            or set(selected) - {g["id"] for g in declared}
        ):
            _deny("gate_declared_selection_invalid")
        declared = [g for g in declared if g["id"] in selected]
    rows = report.get("gates")
    if (
        not isinstance(rows, list)
        or any(not isinstance(g, dict) for g in rows)
        or [g.get("id") for g in rows] != [g["id"] for g in declared]
    ):
        _deny("gate_declared_membership_mismatch")
    scope = report.get("evaluation_scope", {})
    if type(scope.get("selected_count")) is not int or scope["selected_count"] != len(
        declared
    ):
        _deny("gate_declared_selection_invalid")
    reference = (
        _report_path(root, naos_root, policy, "self_check_report")
        .relative_to(root)
        .as_posix()
    )
    expected = {}
    for gate in declared:
        refs = gate["required_evidence"]
        if reference not in refs:
            continue
        if refs.count(reference) != 1:
            _deny("gate_declared_full_self_check_duplicate")
        requirement = dict(
            gate.get("evidence_requirements", {}).get(reference, {"type": "report"})
        )
        if requirement.get("type") != "report":
            _deny("gate_declared_full_self_check_type_invalid")
        requirement["_self_check_gate_context"] = {
            "gate_id": gate["id"],
            "evidence_requirements": {
                ref: gate.get("evidence_requirements", {}).get(
                    ref, {"type": "report" if ref.endswith(".json") else "manual"}
                )
                for ref in refs
            },
        }
        expected[gate["id"]] = requirement
    return expected


def enforce_gate_dependency_bindings(
    result: dict,
    report: dict,
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict,
) -> None:
    """Reconcile selected manifest obligations before trusting any stored F row."""
    import naos_evidence_contracts as ec

    reference = (
        _report_path(root, naos_root, policy, "self_check_report")
        .relative_to(root)
        .as_posix()
    )
    try:
        expected_slots = _declared_gate_dependency_slots(
            root, report, profile=profile, naos_root=naos_root, policy=policy
        )
        for gate in report["gates"]:
            rows = gate.get("evidence_results")
            if not isinstance(rows, list) or any(not isinstance(e, dict) for e in rows):
                _deny("gate_full_self_check_rows_invalid")
            matching = [
                e
                for e in rows
                if e.get("reference") == reference
                or e.get("report_key") == "self_check"
            ]
            if gate["id"] not in expected_slots:
                if matching:
                    _deny("gate_undeclared_full_self_check_row")
                continue
            if (
                len(matching) != 1
                or matching[0].get("reference") != reference
                or matching[0].get("report_key") != "self_check"
                or matching[0].get("requirement_outcome") != "satisfied"
            ):
                _deny("gate_declared_full_self_check_row_unresolved")
            evidence = matching[0]
            if resolution_in_progress():
                _deny("dependency_resolution_collection_in_progress")
            current = ec.classify_evidence(
                root,
                reference,
                profile=profile,
                naos_root=naos_root,
                policy=policy,
                requirement=expected_slots[gate["id"]],
                consumer="gate",
            )
            if current.get("requirement_outcome") != "satisfied" or current.get(
                "content_sha256"
            ) != evidence.get("content_sha256"):
                _deny("gate_full_self_check_binding_unresolved")
            if evidence.get("dependency_component_resolution") != current.get(
                "dependency_component_resolution"
            ):
                _deny("gate_dependency_resolution_binding_changed")
    except (
        ResolutionRefusal,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        yaml.YAMLError,
    ) as error:
        result["requirement_outcome"] = "unresolved"
        result.setdefault("reason_codes", []).append(
            error.code
            if isinstance(error, ResolutionRefusal)
            else "gate_current_manifest_unreadable"
        )


def dependency_inputs_path(root: Path, naos_root: str, policy: dict) -> Path:
    from naos_policy import naos_root_path, safe_policy_path
    from naos_ai_surfaces import checked_path

    checked_path(
        root, "/".join((naos_root, "dependency_inputs", "self_check_collection.json"))
    )
    path = safe_policy_path(
        naos_root_path(root, naos_root),
        "dependency_inputs",
        "self_check_collection.json",
        field="self_check_dependency_inputs",
    )
    for ancestor in (path, *path.parents):
        if ancestor == root:
            break
        if ancestor.is_symlink():
            _deny("unsafe_collection_destination", path)
    if not path.resolve().is_relative_to(root):
        _deny("unsafe_collection_destination", path)
    return path


def capture_dependency_inputs(root: Path, *, naos_root: str, policy: dict) -> Path:
    """Preserve actual F0/E0 preimages before the final full F1 collects A.

    This bounded capture has no readiness outcome. Raw acquisition failures remain
    in the saved source text. Its current bytes are bound in the final proof.
    """
    from naos_policy import evidence_pack_output_path

    root = root.resolve(strict=True)
    path = dependency_inputs_path(root, naos_root, policy)
    artifacts = []
    for key, source in (
        (
            "self_check_report",
            _report_path(root, naos_root, policy, "self_check_report"),
        ),
        ("evidence_pack_report", evidence_pack_output_path(root, naos_root, policy)),
    ):
        if source is None or source == path:
            _deny("collection_input_missing_or_alias", key)
        content = _bytes(root, source)
        raw, _ = _json(root, source)
        if key == "self_check_report":
            _schema(raw, "self_check.schema.json")
        elif raw.get("schema") not in ("naos.evidence_pack.v1", "naos.evidence_pack.v2"):
            _deny("collection_pack_schema_mismatch")
        artifacts.append(
            {
                "report_key": key,
                "reference": source.relative_to(root).as_posix(),
                "content_sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content),
                "raw_utf8": content.decode("utf-8"),
            }
        )
    captured = {
        "schema": "naos.self_check_dependency_inputs.v1",
        "project_root": str(root),
        "naos_root": naos_root,
        "purpose": "attestation_collection_preimages_only",
        "artifacts": artifacts,
    }
    data = _canonical(captured)
    if len(data) > MAX_BYTES:
        _deny("collection_snapshot_too_large")
    if path.exists():
        old, _ = _json(root, path)
        if old.get("schema") != captured["schema"]:
            _deny("collection_destination_alias")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".self-check-collection-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        dependency_inputs_path(root, naos_root, policy)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path


def _validate_collection_preimages(root: Path, naos_root: str, policy: dict) -> dict:
    from naos_policy import evidence_pack_output_path

    path = dependency_inputs_path(root, naos_root, policy)
    captured, sha = _json(root, path)
    if (
        set(captured) != {"schema", "project_root", "naos_root", "purpose", "artifacts"}
        or captured.get("schema") != "naos.self_check_dependency_inputs.v1"
        or captured.get("project_root") != str(root)
        or captured.get("naos_root") != naos_root
        or captured.get("purpose") != "attestation_collection_preimages_only"
    ):
        _deny("collection_snapshot_scope_invalid")
    expected = {
        "self_check_report": _report_path(root, naos_root, policy, "self_check_report"),
        "evidence_pack_report": evidence_pack_output_path(root, naos_root, policy),
    }
    artifacts = captured.get("artifacts")
    if not isinstance(artifacts, list) or [
        x.get("report_key") for x in artifacts
    ] != list(expected):
        _deny("collection_snapshot_inventory_invalid")
    attestation, _ = _json(
        root, _report_path(root, naos_root, policy, "evidence_attestation_report")
    )
    _schema(attestation, "evidence_attestation.schema.json")
    observed = []
    for entry in artifacts:
        if set(entry) != {
            "report_key",
            "reference",
            "content_sha256",
            "size_bytes",
            "raw_utf8",
        }:
            _deny("collection_snapshot_artifact_invalid")
        content = entry["raw_utf8"].encode("utf-8")
        if (
            hashlib.sha256(content).hexdigest() != entry["content_sha256"]
            or len(content) != entry["size_bytes"]
            or entry["reference"]
            != expected[entry["report_key"]].relative_to(root).as_posix()
        ):
            _deny("collection_snapshot_preimage_invalid")
        matching = [
            x
            for x in attestation["artifact_manifest"]
            if x.get("path") == entry["reference"]
        ]
        if (
            len(matching) != 1
            or matching[0].get("digest") != entry["content_sha256"]
            or matching[0].get("size_bytes") != entry["size_bytes"]
        ):
            _deny("attestation_collection_preimage_mismatch", entry["reference"])
        observed.append(
            {
                k: entry[k]
                for k in ("report_key", "reference", "content_sha256", "size_bytes")
            }
        )
    return {
        "reference": path.relative_to(root).as_posix(),
        "content_sha256": sha,
        "artifacts": observed,
        "purpose": "attestation_collection_preimages_only",
    }
