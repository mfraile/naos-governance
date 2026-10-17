"""Declared exact configuration review; no runtime activation or authenticated approval."""

from __future__ import annotations

import hashlib
import json
import yaml
from datetime import datetime, timedelta
from pathlib import Path

from naos_policy import controlled_now_utc, report_default_path
from naos_systemic_family_review import (
    _digest,
    _load_record,
    _local_bytes,
    _source_bytes,
)

SCHEMA = "naos.configuration_posture_review.v1"
SUPPORTED = {
    "semantic_candidate_layer": "semantic_candidate_layer_rules",
    "graph_context_readiness": "graph_context_rules",
    "local_context_index": "local_context_index_rules",
    "ai_surface_context_budget": "ai_surface_context_budget_rules",
}
INFORMATIONAL_INDEX_FINDINGS = {
    "local_context_index.sensitive_paths_excluded",
    "sqlite_write_coordination.distributed_lock_not_provided",
    "sqlite_write_coordination.session_metadata_unavailable",
}
SEMANTIC_FLAGS = (
    "semantic_runtime_enabled",
    "sqlite_vec_enabled",
    "embeddings_enabled",
    "extension_loading_allowed",
    "external_embedding_calls_allowed",
    "cloud_embedding_allowed",
)
GRAPH_FLAGS = (
    "graph_runtime_enabled",
    "global_graph_scan_allowed",
    "graph_database_allowed",
    "networkx_enabled",
    "graphml_enabled",
    "graph_algorithms_enabled",
)


def _false_fields(value: dict, fields: tuple[str, ...]) -> None:
    if any(value.get(field) is not False for field in fields):
        raise ValueError(
            "Runtime/extension/provider enablement is outside configuration review"
        )


def posture_subject(report: dict, key: str, scope: dict, rules: dict) -> dict:
    """Stable configuration/notices only; index contents are not reviewed by this subject."""
    if key not in SUPPORTED or report.get("status") not in {
        "ready",
        "advisory",
        "review_required",
        "readiness_only",
    }:
        raise ValueError("Unsupported or adverse configuration posture")
    findings = report.get("findings")
    summary = report.get("summary")
    if not isinstance(findings, list) or not isinstance(summary, dict):
        raise ValueError("Malformed findings or summary")
    for field in (
        "required",
        "blocking",
        "warnings",
        "warning",
        "errors",
        "stale_artifacts",
    ):
        if field in summary and (
            type(summary[field]) is not int or summary[field] != 0
        ):
            raise ValueError("Adverse, malformed or stale report summary")
    for item in findings:
        if (
            key != "local_context_index"
            or not isinstance(item, dict)
            or item.get("id") not in INFORMATIONAL_INDEX_FINDINGS
            or item.get("severity") != "advisory"
            or item.get("status") != "advisory"
        ):
            raise ValueError("Unknown/adverse finding cannot be acknowledged")
    ids = [item["id"] for item in findings]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate informational finding")
    if type(summary.get("total_findings")) is not int or summary[
        "total_findings"
    ] != len(findings):
        raise ValueError("Inconsistent report finding count")
    if type(summary.get("advisory")) is not int or summary["advisory"] != len(findings):
        raise ValueError("Inconsistent informational finding count")
    if key == "semantic_candidate_layer":
        _false_fields(report, SEMANTIC_FLAGS)
        _false_fields(rules, SEMANTIC_FLAGS)
        _false_fields(
            rules.get("sqlite_vec_posture", {}),
            (
                "vec0_tables_enabled",
                "vec_each_enabled",
                "knn_enabled",
                "extension_loading_required",
            ),
        )
        _false_fields(
            rules.get("extension_loading_posture", {}),
            ("allowed", "native_binary_loading_allowed"),
        )
        if report.get("profile_posture", {}).get("state") != "readiness_only":
            raise ValueError("Semantic subject is not configuration-only")
        projection = {
            name: value for name, value in report.items() if name != "generated_at"
        }
    elif key == "graph_context_readiness":
        _false_fields(report, GRAPH_FLAGS)
        _false_fields(rules, GRAPH_FLAGS)
        if report.get("profile_posture", {}).get("state") != "readiness_only":
            raise ValueError("Graph subject is not configuration-only")
        projection = {
            name: value for name, value in report.items() if name != "generated_at"
        }
    else:
        semantic = report.get("future_semantic_layer")
        graph = report.get("future_graph_layer")
        if not isinstance(semantic, dict) or not isinstance(graph, dict):
            raise ValueError("Missing deferred-runtime index posture")
        if semantic != rules.get("future_semantic_vector_layer") or graph != rules.get(
            "future_graph_layer"
        ):
            raise ValueError(
                "Index posture does not reproduce current generating rules"
            )
        if (
            semantic.get("status") != "readiness_only_deferred_runtime"
            or semantic.get("extension_loading_allowed") is not False
            or any(
                semantic.get(x) != "deferred"
                for x in ("sqlite_vec", "vec0_tables", "embeddings")
            )
        ):
            raise ValueError("Index semantic runtime must remain deferred")
        if (
            graph.get("status") != "readiness_only_deferred_runtime"
            or graph.get("global_graph_scans") != "prohibited"
            or any(
                graph.get(x) != "deferred"
                for x in ("networkx", "graphml", "graph_database", "graph_algorithms")
            )
        ):
            raise ValueError("Index graph runtime must remain deferred")
        if report.get("summary", {}).get("stale_artifacts") != 0:
            raise ValueError("Stale indexed artifacts remain unresolved")
        freshness = report.get("freshness_summary")
        artifacts = report.get("indexed_artifacts")
        if (
            not isinstance(freshness, dict)
            or not isinstance(artifacts, list)
            or any(
                type(count) is not int or count < 0 or (state != "fresh" and count != 0)
                for state, count in freshness.items()
            )
            or any(
                not isinstance(item, dict) or item.get("freshness_status") != "fresh"
                for item in artifacts
            )
        ):
            raise ValueError(
                "Observed stale/unknown indexed freshness remains unresolved"
            )
        projection = {
            name: report.get(name)
            for name in (
                "schema",
                "profile",
                "project_root",
                "naos_root",
                "rules_hash",
                "rules_path",
                "future_semantic_layer",
                "future_graph_layer",
                "memory_policy",
                "findings",
                "known_gaps",
                "residual_risks",
                "limitations",
                "not_claimed",
            )
        }
    return {
        "schema": SCHEMA + ".subject",
        "report_key": key,
        "scope": scope,
        "configuration_posture": projection,
    }


def _refuse_alias(path: Path, protected: list[Path]) -> None:
    for other in protected:
        if other.exists() and path.samefile(other):
            raise ValueError("Review file aliases a live source/output/record/evidence")


def _schema_errors(entries: list) -> None:
    from jsonschema import Draft202012Validator

    schema_path = (
        Path(__file__).resolve().parents[1]
        / "schemas/naos/configuration_posture_review.schema.json"
    )
    schema = json.loads(schema_path.read_text())
    validator = Draft202012Validator(schema)
    for entry in entries:
        if next(validator.iter_errors(entry), None) is not None:
            raise ValueError("Invalid typed configuration posture review")
    keys = [(entry["report_key"], _digest(entry["scope"])) for entry in entries]
    if len(keys) != len(set(keys)):
        raise ValueError("Duplicate configuration posture review")


def budget_warning_subject(report, scope, rules, *, root, naos_root, policy, rules_path):
    """Reproduce exact measured inputs; acknowledge only below-block file warnings."""
    from naos_ai_surface_budget import build_report, deep_merge, DEFAULT_RULES, default_baseline_path
    from naos_systemic_family_review import _review_source_paths

    if rules.get("schema") != "naos.ai_surface_context_budget_rules.v1" or type(rules.get("version")) is not int:
        raise ValueError("Malformed budget rules declaration")
    effective = deep_merge(DEFAULT_RULES, rules)
    if effective.get("token_estimation", {}).get("chars_per_token") != 4:
        raise ValueError("Disabled or altered token estimation is not reviewable")
    families = effective.get("families")
    if not isinstance(families, list) or not families:
        raise ValueError("Budget source families must remain declared")
    ids = [item.get("id") for item in families if isinstance(item, dict)]
    if (len(ids) != len(families) or any(not isinstance(value, str) or not value.strip() for value in ids)
            or len(ids) != len(set(ids))):
        raise ValueError("Duplicate or malformed budget family")
    patterns = []
    for family in families:
        warn, block = family.get("warn_tokens"), family.get("block_tokens")
        if type(warn) is not int or type(block) is not int or not 0 < warn < block:
            raise ValueError("Both finite warning and hard block thresholds are required")
        if not isinstance(family.get("patterns"), list) or not family["patterns"]:
            raise ValueError("Budget family source patterns cannot be disabled")
        patterns.extend(family["patterns"])
    for scenario in effective.get("combined_scenarios", []):
        warn, block = scenario.get("warn_tokens"), scenario.get("block_tokens")
        if type(warn) is not int or type(block) is not int or not 0 < warn < block:
            raise ValueError("Scenario thresholds cannot be disabled")
        for item in scenario.get("files", []):
            patterns.append(item if isinstance(item, str) else item["path"])
    # Validate lexical topology before the producer follows any source path.
    paths = _review_source_paths(root, {"review_source_patterns": sorted(set(patterns))}, set())
    source_files = []
    for reference in paths:
        if (root / reference).is_file():
            source_files.append({"path": reference, "sha256": hashlib.sha256(_local_bytes(root, reference)).hexdigest()})
    baseline_path = default_baseline_path(root, naos_root, effective, policy)
    baseline_ref = baseline_path.relative_to(root).as_posix()
    baseline_bytes = _local_bytes(root, baseline_ref)
    if not baseline_bytes:
        raise ValueError("Actual selected baseline must be present")
    source_files.append({"path": baseline_ref, "sha256": hashlib.sha256(baseline_bytes).hexdigest()})
    current = build_report(root=root, naos_root=naos_root, profile=scope["profile"], policy=policy,
                           rules_path=rules_path, baseline_path=baseline_path)
    projection = {k: v for k, v in report.items() if k != "generated_at"}
    if projection != {k: v for k, v in current.items() if k != "generated_at"}:
        raise ValueError("Budget report does not reproduce current source/rules/baseline")
    for family in report.get("families", []):
        if any(item["estimated_tokens"] > family["block_tokens"] for item in family["files"]):
            raise ValueError("Hard block boundary cannot be reviewed closed")
    for item in source_files:
        if hashlib.sha256(_local_bytes(root, item["path"])).hexdigest() != item["sha256"]:
            raise ValueError("Measured source changed during observation")
    findings = report.get("findings")
    if (report.get("status") != "warning" or report.get("ai_surface_health_posture") != "warning"
            or report.get("context_budget_posture") != "warning" or not findings):
        raise ValueError("Only observed file-budget warnings are reviewable")
    for finding in findings:
        if (finding.get("id") != "AI_SURFACE_FILE_BUDGET_WARNING"
                or finding.get("severity") != "warning" or finding.get("status") != "file_budget_warning"):
            raise ValueError("Adverse, anchor, baseline or unknown findings remain unresolved")
    # Overlapping declared families can emit identical occurrences for one file.
    # Exact producer reproduction above and ordered acknowledgment equality below
    # preserve their multiplicity; never collapse findings by ID or source path.
    return {"schema": SCHEMA + ".subject", "report_key": "ai_surface_context_budget", "scope": scope,
            "configuration_posture": projection, "measured_source_files": source_files}


def configuration_review_material(
    report: dict, *, root: Path, profile: str, naos_root: str, policy: dict, key: str
) -> dict:
    """Expose deterministic review input only; never fill human decision fields."""
    scope = {
        "project_root": str(root.resolve()),
        "profile": profile,
        "naos_root": naos_root,
    }
    rules_path = root / naos_root / policy["paths"][SUPPORTED[key]]
    relative_rules = rules_path.relative_to(root).as_posix()
    rule_bytes = _local_bytes(root, relative_rules)
    rules = _load_record(root, rules_path.absolute())
    rules_hash = hashlib.sha256(rule_bytes).hexdigest()
    if key != "ai_surface_context_budget" and (
        report.get("rules_hash") != rules_hash
        or Path(report.get("rules_path", "")).absolute() != rules_path.absolute()
    ):
        raise ValueError("Producer rules source binding is stale or foreign")
    subject = (budget_warning_subject(report, scope, rules, root=root, naos_root=naos_root,
                                      policy=policy, rules_path=rules_path)
               if key == "ai_surface_context_budget" else posture_subject(report, key, scope, rules))
    policy_meta = policy.get("_meta") or {}
    policy_path = Path(policy_meta["path"]) if policy_meta.get("path") else None
    policy_bytes = (
        _source_bytes(
            root,
            policy_path.absolute(),
            kit_relative="policies/default_policy.yaml"
            if policy_meta.get("source") == "kit"
            else None,
        )
        if policy_path
        else None
    )
    expected_binding = {
        "rules_sha256": rules_hash,
        "policy_sha256": hashlib.sha256(policy_bytes).hexdigest()
        if policy_bytes is not None
        else None,
        "effective_policy_sha256": _digest(
            {k: v for k, v in policy.items() if k != "_meta"}
        ),
        "subject_sha256": _digest(subject),
    }
    return {
        "schema": "naos.configuration_posture_review_subject.v1",
        "report_key": key,
        "scope": scope,
        "binding": expected_binding,
        "subject": subject,
        "finding_bindings": [
            {"id": item["id"], "sha256": _digest(item),
             **({"source": item["source"]} if key == "ai_surface_context_budget" else {})}
            for item in report["findings"]
        ],
        "limits": [
            "Deterministic subject and hashes only; no recorded human decision.",
            "Configuration/notices only; no index source correctness or runtime activation.",
        ],
    }


def apply_configuration_review(
    result: dict,
    report: dict,
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict,
    descriptor,
    requirement: dict,
    consumer: str,
    age_check,
) -> None:
    """Only an explicit typed declaration can satisfy this bounded review requirement."""
    key = descriptor.key
    if key not in SUPPORTED or consumer == "control_plane":
        return
    material = None
    if (
        result["validation"] == "valid"
        and result["scope"] == "matched"
        and result["producer_outcome"] not in {"adverse", "unknown", "not_run"}
    ):
        try:
            material = configuration_review_material(
                report,
                root=root,
                profile=profile,
                naos_root=naos_root,
                policy=policy,
                key=key,
            )
            result["configuration_posture_review_subject"] = material
        except (
            OSError,
            KeyError,
            UnicodeError,
            ValueError,
            TypeError,
            AttributeError,
            yaml.YAMLError,
        ):
            pass  # No reviewable subject does not change the legacy disposition.
    filename = policy.get("paths", {}).get(
        "evidence_review_attestations", "evidence_review_attestations.yaml"
    )
    record_path = root / naos_root / filename
    if not record_path.exists() and not record_path.is_symlink():
        return
    try:
        document = _load_record(root, record_path.absolute())
        if "configuration_posture_reviews" not in document:
            return  # Exact legacy behavior for ordinary reviewer metadata.
        entries = document["configuration_posture_reviews"]
        if not isinstance(entries, list):
            raise ValueError("Configuration posture reviews must be an array")
        _schema_errors(entries)
        scope = {
            "project_root": str(root.resolve()),
            "profile": profile,
            "naos_root": naos_root,
        }
        selected = [
            entry
            for entry in entries
            if entry["report_key"] == key and entry["scope"] == scope
        ]
        if len(selected) != 1:
            raise ValueError("Exactly one current scoped configuration review required")
        entry = selected[0]
        expected_outcome = "reviewed_budget_warnings_only" if key == "ai_surface_context_budget" else "reviewed_configuration_only"
        if entry["review_outcome"] != expected_outcome:
            raise ValueError("Review outcome does not match the exact subject")
        age_check(result, root / result["reference"], report, requirement)
        if (
            result["validation"] != "valid"
            or result["scope"] != "matched"
            or result["producer_outcome"] in {"adverse", "unknown", "not_run"}
        ):
            raise ValueError(
                "Current adverse or unvalidated evidence cannot be reviewed closed"
            )
        if requirement.get("require_current_source") is True or result[
            "generation_age"
        ]["status"] not in {"within_window", "not_enforced"}:
            raise ValueError(
                "Unresolved freshness/current-source requirement cannot be reviewed closed"
            )
        if material is None:
            raise ValueError(
                "Current source-bound configuration subject is not reviewable"
            )
        expected_binding = material["binding"]
        subject = material["subject"]
        rules_path = root / naos_root / policy["paths"][SUPPORTED[key]]
        relative_rules = rules_path.relative_to(root).as_posix()
        policy_meta = policy.get("_meta") or {}
        policy_path = Path(policy_meta["path"]) if policy_meta.get("path") else None
        if entry["binding"] != expected_binding:
            raise ValueError("Review rules/policy/current subject binding mismatch")
        reviewed_at = entry["reviewed_at"]
        if not reviewed_at.endswith("Z"):
            raise ValueError("Reviewed timestamp must explicitly use UTC Z")
        instant = datetime.fromisoformat(reviewed_at[:-1] + "+00:00")
        if instant > controlled_now_utc() + timedelta(minutes=5):
            raise ValueError("Review timestamp is in the future")
        forbidden = {
            record_path.relative_to(root).as_posix(),
            result["reference"],
            relative_rules,
        }
        if policy_path and policy_path.absolute().is_relative_to(root.absolute()):
            forbidden.add(
                policy_path.absolute().relative_to(root.absolute()).as_posix()
            )
        for item in subject.get("measured_source_files", []):
            forbidden.add(item["path"])
        snapshot = entry["subject_snapshot"]
        if snapshot["path"] in forbidden:
            raise ValueError("Review snapshot aliases a live source/output/record")
        snapshot_bytes = _local_bytes(root, snapshot["path"])
        protected = [record_path, root / result["reference"], rules_path]
        protected.extend(root / item["path"] for item in subject.get("measured_source_files", []))
        # Exact canonical reviewed producers and their aggregate cannot double
        # as immutable human notes/snapshots, including under hardlink aliases.
        for report_key in (*SUPPORTED, "self_check"):
            output_path = report_default_path(
                root, naos_root, policy, report_key + "_report"
            )
            protected.append(output_path)
            forbidden.add(output_path.relative_to(root).as_posix())
        if snapshot["path"] in forbidden:
            raise ValueError("Review snapshot aliases a canonical reviewed output")
        if policy_path:
            protected.append(policy_path)
        _refuse_alias(root / snapshot["path"], protected)
        protected.append(root / snapshot["path"])
        if (
            hashlib.sha256(snapshot_bytes).hexdigest() != snapshot["sha256"]
            or _load_record(root, root / snapshot["path"]) != subject
        ):
            raise ValueError("Immutable review subject snapshot mismatch")
        for reference, digest in entry["evidence_sha256"].items():
            if reference in forbidden or reference == snapshot["path"]:
                raise ValueError(
                    "Review evidence aliases source/output/record/snapshot"
                )
            evidence_bytes = _local_bytes(root, reference)
            if not evidence_bytes:
                raise ValueError("Review evidence must be nonempty")
            if hashlib.sha256(evidence_bytes).hexdigest() != digest:
                raise ValueError("Review evidence byte binding mismatch")
            _refuse_alias(root / reference, protected)
            protected.append(root / reference)
        acknowledgments = [
            {"id": item["id"], "sha256": _digest(item),
             **({"source": item["source"]} if key == "ai_surface_context_budget" else {})}
            for item in report["findings"]
        ]
        if entry["acknowledged_findings"] != acknowledgments:
            raise ValueError("Every informational finding must be acknowledged exactly")
        result["requirement_outcome"] = "satisfied"
        result["human_review_required"] = True
        result["configuration_posture_review"] = {
            "status": "recorded",
            "record_reference": record_path.relative_to(root).as_posix(),
            "declaration": entry,
            "limits": [
                "Declared human review, not authenticated identity or approval.",
                "Configuration and named informational notices only; no index source correctness or runtime activation is accepted.",
            ],
        }
    except (
        OSError,
        KeyError,
        UnicodeError,
        ValueError,
        TypeError,
        AttributeError,
        yaml.YAMLError,
    ) as exc:
        result["requirement_outcome"] = "unresolved"
        result["reason_codes"].append("configuration_posture_review_invalid")
        result["configuration_posture_review"] = {
            "status": "invalid",
            "reason": str(exc),
        }
