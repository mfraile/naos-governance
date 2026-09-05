#!/usr/bin/env python3
"""Shared deterministic helpers for NAOS professional adoption commands."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import unicodedata
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    build_generated_by,
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    load_policy,
    naos_root_path,
    normalize_profile,
    report_default_path,
    safe_policy_path,
    session_report_default_path,
    sessions_index_path,
    severity_for_profile,
    validate_report_write_path,
    write_report_with_session,
)

try:
    from naos_mcp_config_registry import scan_mcp_configs as _registry_scan_mcp_configs  # noqa: E402
except ImportError:  # pragma: no cover - generated adopters may predate the shared registry
    _registry_scan_mcp_configs = None

try:
    from naos_mcp_config_registry import review_mcp_descriptors as _review_mcp_descriptors  # noqa: E402
except ImportError:  # pragma: no cover - generated adopters may predate descriptor review
    _review_mcp_descriptors = None

try:
    from naos_setup_recommendations import (  # noqa: E402
        build_repository_intelligence_guidance,
    )
except ImportError:  # pragma: no cover - generated adopters may predate this integration
    build_repository_intelligence_guidance = None

try:
    from naos_repository_intelligence import (  # noqa: E402
        RepositoryIntelligenceError,
        assert_repository_intelligence_binding_unchanged,
        read_active_repository_intelligence_snapshot,
        repository_intelligence_binding,
        validate_active_generation,
    )
except ImportError:  # pragma: no cover - generated adopters may predate this integration
    RepositoryIntelligenceError = RuntimeError
    assert_repository_intelligence_binding_unchanged = None
    read_active_repository_intelligence_snapshot = None
    repository_intelligence_binding = None
    validate_active_generation = None


REPORT_SPECS: dict[str, dict[str, str]] = {
    "adopt": {
        "command": "adopt",
        "schema": "naos.adoption_summary.v1",
        "report_key": "adoption_summary_report",
        "filename": "adoption_summary.json",
        "title": "Professional Adoption Summary",
    },
    "preflight": {
        "command": "preflight",
        "schema": "naos.preflight_report.v1",
        "report_key": "preflight_report",
        "filename": "preflight_report.json",
        "title": "Preflight Report",
    },
    "intake": {
        "command": "intake",
        "schema": "naos.intake_report.v1",
        "report_key": "intake_report",
        "filename": "intake_report.json",
        "title": "Guided Intake Report",
    },
    "install_plan": {
        "command": "install-plan",
        "schema": "naos.install_plan.v1",
        "report_key": "install_plan_report",
        "filename": "install_plan.json",
        "title": "Install Plan",
    },
    "existing_resource_inventory": {
        "command": "existing-resource-inventory",
        "schema": "naos.existing_resource_inventory.v1",
        "report_key": "existing_resource_inventory_report",
        "filename": "existing_resource_inventory.json",
        "title": "Existing Resource Inventory",
    },
    "ai_artifact_inventory": {
        "command": "ai-artifact-inventory",
        "schema": "naos.ai_artifact_inventory.v1",
        "report_key": "ai_artifact_inventory_report",
        "filename": "ai_artifact_inventory.json",
        "title": "AI Artifact Inventory",
    },
    "ai_artifact_reconcile": {
        "command": "ai-artifact-reconcile",
        "schema": "naos.ai_artifact_reconciliation.v1",
        "report_key": "ai_artifact_reconciliation_report",
        "filename": "ai_artifact_reconciliation.json",
        "title": "AI Artifact Reconciliation",
    },
    "memory_resource_inventory": {
        "command": "memory-resource-inventory",
        "schema": "naos.memory_resource_inventory.v1",
        "report_key": "memory_resource_inventory_report",
        "filename": "memory_resource_inventory.json",
        "title": "Memory Resource Inventory",
    },
    "memory_resource_reconcile": {
        "command": "memory-resource-reconcile",
        "schema": "naos.memory_resource_reconciliation.v1",
        "report_key": "memory_resource_reconciliation_report",
        "filename": "memory_resource_reconciliation.json",
        "title": "Memory Resource Reconciliation",
    },
    "mcp_resource_inventory": {
        "command": "mcp-resource-inventory",
        "schema": "naos.mcp_resource_inventory.v1",
        "report_key": "mcp_resource_inventory_report",
        "filename": "mcp_resource_inventory.json",
        "title": "MCP Resource Inventory",
    },
    "brownfield_baseline": {
        "command": "brownfield-baseline",
        "schema": "naos.brownfield_baseline.v1",
        "report_key": "brownfield_baseline_report",
        "filename": "brownfield_baseline.json",
        "title": "Brownfield Baseline",
    },
    "requirements_reconstruct": {
        "command": "requirements-reconstruct",
        "schema": "naos.candidate_requirements.v1",
        "report_key": "candidate_requirements_report",
        "filename": "candidate_requirements.json",
        "title": "Candidate Requirements",
    },
    "traceability_gap_register": {
        "command": "traceability-gap-register",
        "schema": "naos.traceability_gap_register.v1",
        "report_key": "traceability_gap_register_report",
        "filename": "traceability_gap_register.json",
        "title": "Traceability Gap Register",
    },
    "install_decision_record": {
        "command": "install-decision-record",
        "schema": "naos.install_decision_record.v1",
        "report_key": "install_decision_record_report",
        "filename": "install_decision_record.json",
        "title": "Install Decision Record",
    },
    "context_challenge": {
        "command": "context-challenge",
        "schema": "naos.context_challenge_report.v1",
        "report_key": "context_challenge_report",
        "filename": "context_challenge_report.json",
        "title": "Context Challenge Report",
    },
    "repo_context_challenge": {
        "command": "repo-context-challenge",
        "schema": "naos.repo_context_challenge_report.v1",
        "report_key": "repo_context_challenge_report",
        "filename": "repo_context_challenge_report.json",
        "title": "Repo Context Challenge Report",
    },
    "plan_challenge": {
        "command": "plan-challenge",
        "schema": "naos.plan_challenge_report.v1",
        "report_key": "plan_challenge_report",
        "filename": "plan_challenge_report.json",
        "title": "Plan Challenge Report",
    },
    "decision_probe": {
        "command": "decision-probe",
        "schema": "naos.decision_probe_report.v1",
        "report_key": "decision_probe_report",
        "filename": "decision_probe_report.json",
        "title": "Decision Probe Report",
    },
    "planning_gate_review": {
        "command": "planning-gate-review",
        "schema": "naos.planning_gate_review_report.v1",
        "report_key": "planning_gate_review_report",
        "filename": "planning_gate_review_report.json",
        "title": "Planning Gate Review Report",
    },
}

NOT_CLAIMED = [
    "automatic approval",
    "legal or regulatory compliance conclusion",
    "certification",
    "secure-code proof",
    "runtime safety proof",
    "requirements completeness proof",
    "behavioral correctness proof",
    "memory authority",
    "automatic context injection",
    "memory write-back",
    "provider or model runtime",
    "human review replacement",
]

LIMITATIONS = [
    "Professional adoption reports are deterministic, file-first review evidence.",
    "Reports preserve human decision boundaries and do not approve work, certify outcomes, prove compliance, prove runtime safety, or prove complete requirements reconstruction.",
    "Inventories inspect local metadata and known project files only; memory, Engram, MCP, provider, and AI-tool findings remain advisory until reviewed by a human.",
    "Challenge reports do not edit project files and do not promote assumptions, candidates, memory, or generated context to source truth.",
]

DECISION_STATES = ["keep", "merge", "replace", "quarantine", "create", "review_required"]
CONFIDENCE_CLASSES = [
    "confirmed_by_existing_spec",
    "supported_by_docs",
    "inferred_from_code",
    "inferred_from_tests",
    "hypothesized_requires_review",
]
CANDIDATE_NON_CLAIMS = [
    "candidate requirements are not final requirements",
    "candidate NFRs do not prove security",
    "candidate NFRs do not prove compliance",
    "candidate NFRs do not prove runtime safety",
    "human review is required before promotion into specs",
]
AI_ARTIFACT_NON_CLAIMS = [
    "AI artifact classification does not approve, merge, delete, or overwrite artifacts",
    "AI artifact classification does not prove instruction correctness",
    "human review is required before changing existing AI artifacts",
]
MODES = ["greenfield", "brownfield", "upgrade", "repair", "evaluation"]
CHALLENGE_MODES = [
    "install",
    "greenfield",
    "brownfield",
    "requirements",
    "architecture",
    "task",
    "implementation-plan",
    "evidence",
    "gate",
    "decision",
    "remediation",
]
RISK_PROFILES = {"low", "medium", "high", "regulated", "unknown"}
DATA_CLASSES = {"public", "internal", "confidential", "restricted", "unknown"}
IGNORED_PARTS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    ".naos-preview",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}


def utc_now() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return slug.strip("._-") or "unknown"


def project_root(args: argparse.Namespace) -> Path:
    return Path(getattr(args, "project_path", ".") or ".").resolve()


def latest_session_id(root: Path, naos_root: str, policy: dict[str, Any]) -> str | None:
    path = sessions_index_path(root, naos_root, policy)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    value = data.get("latest_session_id") if isinstance(data, dict) else None
    return str(value) if value else None


def load_structured(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        if path.suffix.lower() == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
        else:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def write_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def report_path(root: Path, naos_root: str, policy: dict[str, Any], spec_key: str, explicit: str | None = None) -> Path | None:
    if explicit:
        absolute = Path(os.path.abspath(os.fspath(Path(explicit))))
        return absolute.parent.resolve(strict=False) / absolute.name
    configured_naos_root = naos_root_path(root, naos_root)
    if is_kit_repository(root, naos_root) and not configured_naos_root.exists():
        return None
    spec = REPORT_SPECS[spec_key]
    return report_default_path(root, naos_root, policy, spec["report_key"])


def default_report_path(
    root: Path,
    naos_root: str,
    spec_key: str,
    policy: dict[str, Any] | None = None,
) -> Path:
    if policy is not None:
        return report_default_path(root, naos_root, policy, REPORT_SPECS[spec_key]["report_key"])
    return naos_root_path(root, naos_root) / "reports" / REPORT_SPECS[spec_key]["filename"]


_ADOPTION_PHASE_REPORTS_ATTR = "_adoption_phase_reports"
_ADOPTION_REPOSITORY_INTELLIGENCE_ATTR = "_adoption_repository_intelligence"
ADOPTION_REPOSITORY_INTELLIGENCE_SCOPES = (
    "brownfield_adoption",
    "requirements_reconstruction",
    "traceability_gap_analysis",
)
ADOPTION_REQUIREMENTS_RETRIEVAL_QUERIES = (
    "requirements",
    "architecture",
    "interface",
    "workflow",
    "test",
)
ADOPTION_RETRIEVAL_ANSWER_FIELDS = (
    "first_touched_area",
    "brownfield_scope",
    "project_purpose",
)


def _adoption_retrieval_queries(args: argparse.Namespace) -> list[str]:
    answers = read_answers(args)
    answer_queries = [
        normalize_answer(answers.get(field))
        for field in ADOPTION_RETRIEVAL_ANSWER_FIELDS
    ]
    return list(
        dict.fromkeys(
            [
                *ADOPTION_REQUIREMENTS_RETRIEVAL_QUERIES,
                *[
                    value
                    for value in answer_queries
                    if value.lower() not in {"unknown", "none", "not_applicable"}
                ],
            ]
        )
    )[:12]


def _adoption_phase_reports(args: argparse.Namespace | None) -> dict[str, dict[str, Any]] | None:
    if args is None:
        return None
    reports = getattr(args, _ADOPTION_PHASE_REPORTS_ATTR, None)
    return reports if isinstance(reports, dict) else None


def _adoption_repository_intelligence(args: argparse.Namespace | None) -> dict[str, Any] | None:
    if args is None:
        return None
    context = getattr(args, _ADOPTION_REPOSITORY_INTELLIGENCE_ATTR, None)
    return context if isinstance(context, dict) else None


def _repository_intelligence_consumer_evidence(
    args: argparse.Namespace | None,
    *,
    consumer: str,
) -> dict[str, Any] | None:
    context = _adoption_repository_intelligence(args)
    if context is None:
        return None
    retrieval = context.get("retrieval") if isinstance(context.get("retrieval"), dict) else {}
    return {
        "status": "consumed",
        "consumer": consumer,
        "generation": context.get("opening_generation") or {},
        "binding_unchanged_at_open": bool(context.get("binding_unchanged")),
        "usage_scopes_authorized": bool(context.get("usage_scope_satisfied")),
        "required_usage_scopes": context.get("required_usage_scopes") or [],
        "components": context.get("components") or {},
        "coverage": context.get("coverage") or {},
        "candidate_count": len(context.get("candidates") or []),
        "retrieval_candidate_count": len(context.get("retrieval_candidates") or []),
        "fts_candidate_count": int(retrieval.get("fts_candidate_count") or 0),
        "graph_candidate_count": int(retrieval.get("graph_candidate_count") or 0),
        "graph_results_consumed": bool(retrieval.get("graph_results_consumed")),
        "ranking_effect": retrieval.get("ranking_effect") or "none",
        "relationship_count": len(context.get("relationships") or []),
        "candidate_only": True,
        "source_artifacts_remain_authoritative": True,
        "authority_effect": "none",
    }


def read_report(
    root: Path,
    naos_root: str,
    spec_key: str,
    args: argparse.Namespace | None = None,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    current_reports = _adoption_phase_reports(args)
    if current_reports is not None:
        report = current_reports.get(spec_key)
        return report if isinstance(report, dict) else {}
    return load_structured(default_report_path(root, naos_root, spec_key, policy))


def report_content_sha256(report: dict[str, Any]) -> str:
    payload = json.dumps(report, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def report_sink_identity(path: Path) -> str:
    absolute = os.path.abspath(os.fspath(path))
    return unicodedata.normalize("NFC", os.path.normcase(absolute)).casefold()


def validate_unique_report_sinks(bindings: list[tuple[str, Path | None]]) -> None:
    seen: dict[str, tuple[str, Path]] = {}
    for label, path in bindings:
        if path is None:
            continue
        identity = report_sink_identity(path)
        prior = seen.get(identity)
        if prior is not None:
            prior_label, prior_path = prior
            raise ValueError(
                "Adoption report outputs must be one-to-one; "
                f"{prior_label} ({prior_path}) and {label} ({path}) resolve to the same sink."
            )
        seen[identity] = (label, path)


def finding(item_id: str, severity: str, status: str, message: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": item_id,
        "severity": severity,
        "status": status,
        "message": message,
        "human_review_required": status not in {"ready", "present", "detected"} or severity in {"required", "blocking"},
        **extra,
    }


def should_ignore(path: Path) -> bool:
    return any(part in IGNORED_PARTS for part in path.parts)


def relpath(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except Exception:
        return str(path)


def list_files(root: Path, max_files: int = 2000) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if len(files) >= max_files:
            break
        if path.is_file() and not should_ignore(path.relative_to(root)):
            files.append(path)
    return files


def run_git(root: Path, *args: str) -> tuple[int, str]:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )
    except Exception:
        return 127, ""
    return result.returncode, result.stdout.strip()


def detect_project_signals(root: Path) -> dict[str, Any]:
    files = {relpath(root, item) for item in list_files(root, max_files=5000)}
    lower_files = {item.lower() for item in files}
    frameworks: list[str] = []
    if "pyproject.toml" in lower_files:
        frameworks.append("python")
    if "package.json" in lower_files:
        frameworks.append("node")
    if "go.mod" in lower_files:
        frameworks.append("go")
    if "pom.xml" in lower_files or "build.gradle" in lower_files:
        frameworks.append("java")
    if any("django" in item for item in lower_files):
        frameworks.append("django")
    if any("fastapi" in item for item in lower_files):
        frameworks.append("fastapi")
    if any("next" in item for item in lower_files):
        frameworks.append("nextjs")
    docs = sorted(item for item in files if item.lower().endswith((".md", ".rst", ".txt")) and (item.startswith("docs/") or item.lower() == "readme.md" or item.startswith("specs/")))[:50]
    tests = sorted(item for item in files if item.startswith("tests/") or "/test_" in item or item.endswith("_test.py"))[:50]
    source = sorted(item for item in files if item.startswith(("src/", "app/", "lib/")) or item.endswith((".py", ".ts", ".tsx", ".js", ".go", ".java")))[:80]
    workflows = sorted(item for item in files if item.startswith(".github/workflows/") or item.startswith(".gitlab/"))[:30]
    return {
        "files_scanned": len(files),
        "frameworks": sorted(set(frameworks)),
        "has_git": (root / ".git").exists(),
        "has_naos": (root / "naos").exists(),
        "has_docs": bool(docs),
        "has_tests": bool(tests),
        "has_source": bool(source),
        "has_ci": bool(workflows),
        "docs": docs,
        "tests": tests,
        "source": source,
        "workflows": workflows,
    }


def read_answers(args: argparse.Namespace) -> dict[str, Any]:
    path_text = getattr(args, "answers", None)
    if not path_text:
        return {}
    path = Path(path_text)
    data = load_structured(path)
    return data


def normalize_answer(value: Any, default: str = "unknown") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def collect_intake(args: argparse.Namespace, root: Path, profile: str) -> dict[str, Any]:
    answers = read_answers(args)
    mode = normalize_answer(getattr(args, "mode", None), "greenfield")
    fields = {
        "project_purpose": "What problem should this project solve?",
        "accountable_owner": "Who owns adoption decisions?",
        "domain": "What domain is this project in?",
        "risk_profile": "What risk profile applies?",
        "regulated_context": "Is a regulated context expected?",
        "data_class": "What data class applies?",
        "ai_tools": "Which AI tools may be used?",
        "evidence_expectations": "What evidence should reviewers expect?",
        "review_model": "Who reviews adoption and later changes?",
        "language_framework_intent": "Which language/framework is intended?",
        "memory_mcp_posture": "What memory, Engram, and MCP posture should apply?",
        "ai_artifact_disposition": "How should existing AI artifacts be handled?",
        "brownfield_scope": "What existing repo area should be adopted first?",
        "first_touched_area": "What is the first bounded touched area?",
    }
    collected: dict[str, Any] = {}
    interactive = bool(getattr(args, "interactive", False))
    no_prompt = bool(getattr(args, "no_prompt", False))
    for key, prompt in fields.items():
        value = answers.get(key)
        if value is None and interactive and not no_prompt:
            value = interactive_value(args, prompt, "unknown")
        collected[key] = normalize_answer(value)
    collected["mode"] = mode
    collected["profile"] = profile
    collected["source"] = "answer_file" if answers else ("interactive" if interactive else "non_interactive_defaults")
    collected["unknown_fields"] = sorted(key for key, value in collected.items() if value == "unknown")
    return collected


def status_for_findings(findings: list[dict[str, Any]], default: str = "ready") -> str:
    statuses = {str(item.get("status")) for item in findings}
    if "blocked" in statuses:
        return "blocked"
    if "invalid_config" in statuses or "invalid_input" in statuses:
        return "invalid_config"
    if "review_required" in statuses:
        return "review_required"
    if "warning" in statuses:
        return "warning"
    if "advisory" in statuses:
        return "advisory"
    return default


def base_report(spec_key: str, args: argparse.Namespace, root: Path, profile: str, policy: dict[str, Any], findings: list[dict[str, Any]], extra: dict[str, Any]) -> dict[str, Any]:
    spec = REPORT_SPECS[spec_key]
    generated_at = utc_now()
    naos_root = getattr(args, "naos_root", None) or default_naos_root(policy)
    summary = finding_counts(findings)
    status = extra.pop("status", None) or status_for_findings(findings, "ready")
    session_id = latest_session_id(root, naos_root, policy)
    report = {
        "schema": spec["schema"],
        "generated_at": generated_at,
        "profile": profile,
        "status": status,
        "command": spec["command"],
        "mode": normalize_answer(getattr(args, "mode", None), "not_applicable"),
        "naos_root": naos_root,
        "project_root": str(root),
        "session_id": session_id,
        "generated_by": build_generated_by(root, session_id=session_id, generated_at=generated_at),
        "human_review_required": True,
        "not_claimed": NOT_CLAIMED,
        "limitations": LIMITATIONS,
        "findings": findings,
        "known_gaps": extra.pop("known_gaps", []),
        "residual_risks": extra.pop("residual_risks", []),
        "summary": {
            **summary,
            "human_review_required": True,
        },
    }
    report.update(extra)
    return report


def emit_report(spec_key: str, report: dict[str, Any], args: argparse.Namespace, root: Path, policy: dict[str, Any]) -> int:
    naos_root = report["naos_root"]
    no_write_preview = bool(getattr(args, "no_write_preview", False))
    latest_path = None if no_write_preview else report_path(root, naos_root, policy, spec_key, getattr(args, "output", None))
    session_path = None
    if report.get("session_id") and not no_write_preview:
        session_path = session_report_default_path(root, naos_root, policy, str(report["session_id"]), REPORT_SPECS[spec_key]["report_key"])
    if not no_write_preview:
        write_report_with_session(
            latest_path,
            session_path,
            report,
            strict_parent_topology=spec_key == "adopt",
        )
    configured_naos_root = naos_root_path(root, naos_root)
    if spec_key == "intake" and latest_path is not None:
        write_yaml(configured_naos_root / "install" / "intake.yaml", report.get("intake", {}))
    if spec_key == "install_decision_record" and latest_path is not None:
        write_decision_markdown(configured_naos_root / "INSTALL_DECISION_RECORD.md", report)
    if getattr(args, "json", False):
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_human_summary(REPORT_SPECS[spec_key]["title"], report, latest_path)
    return exit_code_for_summary(report["profile"], report["summary"], policy, bool(getattr(args, "strict", False)))


def print_human_summary(title: str, report: dict[str, Any], path: Path | None) -> None:
    print(f"{title}: {report.get('status')}")
    print(f"  report: {path if path is not None else '(not written: kit repository without adopter NAOS root)'}")
    print(f"  mode: {report.get('mode')}")
    if report.get("dry_run"):
        print("  dry-run preview: true (report artifacts may be written)")
        for item in (report.get("dry_run_preview") or [])[:4]:
            print(f"  preview: {item}")
    print(f"  findings: {report.get('summary', {}).get('total_findings', 0)}")
    for item in (report.get("findings") or [])[:5]:
        print(f"  - {item.get('status')}: {item.get('message')}")
    print("  human review required: true")


def write_decision_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        "# NAOS Install / Adoption Decision Record",
        "",
        f"Generated: {report.get('generated_at')}",
        f"Status: {report.get('status')}",
        f"Mode: {report.get('mode')}",
        "",
        "## Decisions",
        "",
    ]
    for decision in report.get("decisions") or []:
        lines.append(f"- {decision.get('decision_id')}: {decision.get('selected_option')} ({decision.get('status')})")
    lines.extend(
        [
            "",
            "## Boundaries",
            "",
            "This record captures human-review inputs and residual risk. It is not approval, certification, legal or regulatory compliance evidence, runtime safety proof, or requirements completeness proof.",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_preflight(args: argparse.Namespace, root: Path, profile: str, policy: dict[str, Any]) -> dict[str, Any]:
    severity = severity_for_profile(profile, policy)
    signals = detect_project_signals(root)
    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    git_code, git_status = run_git(root, "status", "--short")
    checks.append({"id": "git_repository", "status": "present" if signals["has_git"] else "missing", "human_review_required": not signals["has_git"]})
    checks.append({"id": "working_tree", "status": "dirty" if git_status else "clean", "details": git_status.splitlines()[:20]})
    checks.append({"id": "naos_state", "status": "present" if signals["has_naos"] else "not_present"})
    checks.append({"id": "python", "status": "present", "version": sys.version.split()[0]})
    checks.append({"id": "write_scope", "status": "writable" if os.access(root, os.W_OK) else "blocked"})
    if git_code != 0:
        findings.append(finding("preflight.git_missing", "advisory", "advisory", "No local git repository was detected; adoption can continue, but review provenance is weaker."))
    if git_status:
        findings.append(finding("preflight.working_tree_dirty", "advisory", "review_required", "Working tree has local changes; review before activation or reconciliation.", changed_paths=git_status.splitlines()[:50]))
    if not os.access(root, os.W_OK):
        findings.append(finding("preflight.write_scope_blocked", severity, "blocked", "Project path is not writable."))
    return base_report(
        "preflight",
        args,
        root,
        profile,
        policy,
        findings,
        {
            "checks": checks,
            "project_signals": signals,
            "recovery_actions": [
                "Commit or stash unrelated work before risky activation.",
                "Run inventories before reconciliation in brownfield projects.",
                "Use --no-prompt in CI to avoid hanging.",
            ],
        },
    )


def build_intake(args: argparse.Namespace, root: Path, profile: str, policy: dict[str, Any]) -> dict[str, Any]:
    severity = severity_for_profile(profile, policy, advisory=profile in {"quickstart", "lite"})
    intake = collect_intake(args, root, profile)
    findings: list[dict[str, Any]] = []
    required_by_mode = ["project_purpose", "accountable_owner", "risk_profile", "data_class", "review_model"]
    if intake.get("mode") == "brownfield":
        required_by_mode.extend(["brownfield_scope", "first_touched_area"])
    missing = [key for key in required_by_mode if intake.get(key) == "unknown"]
    for key in missing:
        findings.append(finding(f"intake.missing.{key}", severity, "review_required", f"Guided intake is missing {key}.", field=key))
    return base_report(
        "intake",
        args,
        root,
        profile,
        policy,
        findings,
        {
            "intake": intake,
            "missing_information": missing,
            "assumptions": [
                {"id": "intake.non_interactive_defaults", "description": "Unknown values were preserved instead of guessed.", "status": "review_required"}
            ],
        },
    )


def resource_inventory(root: Path) -> list[dict[str, Any]]:
    signals = detect_project_signals(root)
    resources: list[dict[str, Any]] = []
    categories = [
        ("docs", signals["docs"]),
        ("tests", signals["tests"]),
        ("source", signals["source"]),
        ("workflows", signals["workflows"]),
    ]
    for category, paths in categories:
        for path in paths:
            resources.append(
                {
                    "resource_id": safe_slug(path),
                    "category": category,
                    "path": path,
                    "owner": "unknown",
                    "source": "local_file",
                    "status": "detected",
                    "decision_state": "review_required",
                    "human_review_required": True,
                }
            )
    naos_paths = sorted(relpath(root, p) for p in (root / "naos").rglob("*") if p.is_file())[:100] if (root / "naos").exists() else []
    for path in naos_paths:
        resources.append(
            {
                "resource_id": safe_slug(path),
                "category": "naos_artifact",
                "path": path,
                "owner": "NAOS/adopter",
                "source": "local_file",
                "status": "detected",
                "decision_state": "keep",
                "human_review_required": False,
            }
        )
    return resources


def build_existing_resource_inventory(args: argparse.Namespace, root: Path, profile: str, policy: dict[str, Any]) -> dict[str, Any]:
    resources = resource_inventory(root)
    findings: list[dict[str, Any]] = []
    if not resources:
        findings.append(finding("existing_resource_inventory.empty", "advisory", "advisory", "No project resources were detected in the configured scan scope."))
    return base_report(
        "existing_resource_inventory",
        args,
        root,
        profile,
        policy,
        findings,
        {
            "resources": resources,
            "resources_by_category": count_by(resources, "category"),
            "scan_scope": {"root": str(root), "ignored_parts": sorted(IGNORED_PARTS)},
        },
    )


AI_ARTIFACT_PATTERNS = [
    ("claude_context", "CLAUDE.md", "third-party"),
    ("agents_context", "AGENTS.md", "third-party"),
    ("copilot_instructions", ".github/copilot-instructions.md", "third-party"),
    ("github_agents", ".github/agents", "third-party"),
    ("github_prompts", ".github/prompts", "third-party"),
    ("github_skills", ".github/skills", "third-party"),
    ("github_instructions", ".github/instructions", "third-party"),
    ("cursor_rules", ".cursor/rules", "third-party"),
    ("claude_hooks", ".claude/settings.json", "third-party"),
    ("codex_instructions", "AGENTS.md", "third-party"),
    ("gemini_context", "GEMINI.md", "third-party"),
    ("spec_kit", ".specify", "third-party"),
    ("bmad", ".bmad", "third-party"),
    ("gsd", ".gsd", "third-party"),
]


def ai_artifacts(root: Path) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for artifact_type, pattern, owner in AI_ARTIFACT_PATTERNS:
        path = root / pattern
        if path.exists():
            status = "compatible" if pattern.startswith("naos/") else "review_required"
            if path.is_dir():
                for child in sorted(p for p in path.rglob("*") if p.is_file())[:50]:
                    artifacts.append(ai_artifact_entry(root, child, artifact_type, owner, status))
            else:
                artifacts.append(ai_artifact_entry(root, path, artifact_type, owner, status))
    for path in list_files(root, max_files=5000):
        rel = relpath(root, path)
        lower = rel.lower()
        if any(token in lower for token in ["prompt", "rule", "workflow"]) and rel not in {item["path"] for item in artifacts}:
            if lower.endswith((".md", ".yaml", ".yml", ".json", ".txt")):
                artifacts.append(ai_artifact_entry(root, path, "custom_ai_artifact", "user-owned", "review_required"))
    return sorted(artifacts, key=lambda item: item["path"])


def ai_artifact_entry(root: Path, path: Path, artifact_type: str, owner: str, status: str) -> dict[str, Any]:
    rel = relpath(root, path)
    lower_rel = rel.lower()
    try:
        sample = path.read_text(encoding="utf-8", errors="ignore")[:12000].lower()
    except Exception:
        sample = ""
    likely_naos = rel.startswith(("naos/", "templates/")) or "naos" in sample[:2000] or "NAOS" in path.name
    stale_signal = any(token in lower_rel or token in sample for token in ["stale", "deprecated", "legacy", "archive", "old instructions"])
    instruction_surface = artifact_type in {
        "claude_context",
        "agents_context",
        "copilot_instructions",
        "github_agents",
        "github_prompts",
        "github_skills",
        "github_instructions",
        "cursor_rules",
        "claude_hooks",
        "codex_instructions",
        "gemini_context",
    }
    workflow_surface = "workflow" in artifact_type or lower_rel.startswith(".github/workflows/")
    detected_owner = "NAOS-owned" if likely_naos else ("user-owned" if workflow_surface or artifact_type == "custom_ai_artifact" else owner)
    if likely_naos:
        status = "compatible"
        conflict_category = "none"
        conflict_reason = "Artifact appears NAOS-compatible or NAOS-owned based on path/content markers."
        recommended_decision = "keep"
        profile_impact = "low"
    elif stale_signal:
        status = "stale"
        conflict_category = "stale_instruction_surface"
        conflict_reason = "Artifact path or content contains stale/legacy/deprecated markers."
        recommended_decision = "quarantine"
        profile_impact = "standard_and_assured_review_required"
    elif instruction_surface:
        status = "conflicting"
        conflict_category = "instruction_surface_overlap"
        conflict_reason = "Existing AI instruction surface may overlap or conflict with generated NAOS guidance until reviewed."
        recommended_decision = "merge"
        profile_impact = "standard_and_assured_review_required"
    elif workflow_surface:
        status = "review_required"
        conflict_category = "workflow_surface_review"
        conflict_reason = "Existing workflow can affect governance automation and should be reviewed before NAOS CI activation."
        recommended_decision = "review_required"
        profile_impact = "review_required_before_ci_activation"
    else:
        status = "unknown"
        conflict_category = "unknown_ai_surface"
        conflict_reason = "Artifact matches a prompt/rule/workflow pattern but ownership and compatibility are unknown."
        recommended_decision = "review_required"
        profile_impact = "review_required"
    classifications = list(dict.fromkeys([detected_owner, status, "review_required" if status != "compatible" else "compatible"]))
    return {
        "artifact_id": safe_slug(rel),
        "artifact_type": artifact_type,
        "path": rel,
        "classification": detected_owner,
        "classifications": classifications,
        "detected_owner": detected_owner,
        "detected_source": artifact_type,
        "status": status,
        "conflict_category": conflict_category,
        "conflict_reason": conflict_reason,
        "compared_surface": "NAOS generated AI instruction and governance surfaces",
        "profile_impact": profile_impact,
        "recommended_decision": recommended_decision,
        "decision_state": recommended_decision,
        "human_review_required": status != "compatible",
        "human_review_boundary": "Humans decide whether to keep, merge, replace, quarantine, create, or leave review-required; NAOS does not overwrite artifacts.",
        "non_claims": AI_ARTIFACT_NON_CLAIMS,
    }


def build_ai_artifact_inventory(args: argparse.Namespace, root: Path, profile: str, policy: dict[str, Any]) -> dict[str, Any]:
    artifacts = ai_artifacts(root)
    findings: list[dict[str, Any]] = []
    for item in artifacts:
        if item["status"] in {"conflicting", "stale", "unknown", "review_required"}:
            findings.append(
                finding(
                    f"ai_artifact_inventory.review.{item['artifact_id']}",
                    "advisory",
                    "review_required",
                    "AI artifact requires ownership/source/collision review.",
                    artifact_path=item["path"],
                    detected_owner=item.get("detected_owner"),
                    conflict_category=item.get("conflict_category"),
                    conflict_reason=item.get("conflict_reason"),
                    compared_surface=item.get("compared_surface"),
                    recommended_decision=item.get("recommended_decision"),
                )
            )
    return base_report(
        "ai_artifact_inventory",
        args,
        root,
        profile,
        policy,
        findings,
        {
            "artifacts": artifacts,
            "artifact_counts": count_by(artifacts, "artifact_type"),
            "classification_counts": count_by(artifacts, "classification"),
            "status_counts": count_by(artifacts, "status"),
            "conflict_counts": count_by(artifacts, "conflict_category"),
        },
    )


def build_ai_artifact_reconcile(args: argparse.Namespace, root: Path, profile: str, policy: dict[str, Any]) -> dict[str, Any]:
    inventory = read_report(
        root,
        getattr(args, "naos_root", None) or default_naos_root(policy),
        "ai_artifact_inventory",
        args,
        policy,
    )
    artifacts = inventory.get("artifacts") if isinstance(inventory.get("artifacts"), list) else ai_artifacts(root)
    default_decision = getattr(args, "decision", None) or "review_required"
    decisions = []
    findings: list[dict[str, Any]] = []
    for item in artifacts:
        recommended = item.get("recommended_decision") or item.get("decision_state") or "review_required"
        selected = item.get("decision_state") if item.get("status") == "compatible" else default_decision
        if getattr(args, "interactive", False) and not getattr(args, "no_prompt", False) and item.get("status") != "compatible":
            selected = interactive_choice(
                args,
                f"Disposition for {item.get('path')}",
                DECISION_STATES,
                str(recommended if recommended in DECISION_STATES else "review_required"),
            )
        selected = selected if selected in DECISION_STATES else "review_required"
        decision = {
            "artifact_id": item.get("artifact_id"),
            "path": item.get("path"),
            "artifact_path": item.get("path"),
            "detected_owner": item.get("detected_owner") or item.get("classification"),
            "detected_source": item.get("detected_source") or item.get("artifact_type"),
            "conflict_category": item.get("conflict_category"),
            "conflict_reason": item.get("conflict_reason"),
            "compared_surface": item.get("compared_surface"),
            "profile_impact": item.get("profile_impact"),
            "recommended_decision": recommended,
            "selected_option": selected,
            "available_options": DECISION_STATES,
            "write_required": selected in {"merge", "replace", "quarantine", "create"},
            "write_performed": False,
            "status": "review_required" if selected == "review_required" else "recorded",
            "human_review_required": selected != "keep",
            "human_review_boundary": item.get("human_review_boundary") or "Humans decide artifact disposition; NAOS does not overwrite, merge, quarantine, or delete artifacts.",
            "non_claims": AI_ARTIFACT_NON_CLAIMS,
        }
        decisions.append(decision)
        if decision["human_review_required"]:
            findings.append(
                finding(
                    f"ai_artifact_reconcile.{item.get('artifact_id')}",
                    severity_for_profile(profile, policy),
                    "review_required",
                    "AI artifact disposition requires human review.",
                    artifact_path=item.get("path"),
                    conflict_category=item.get("conflict_category"),
                    recommended_decision=recommended,
                )
            )
    return base_report(
        "ai_artifact_reconcile",
        args,
        root,
        profile,
        policy,
        findings,
        {
            "decisions": decisions,
            "write_mode": "explicit_write" if getattr(args, "write", False) else "dry_run",
            "write_boundary": "This report records decisions only; no artifact is overwritten, merged, deleted, or quarantined by this command.",
            "decision_states": DECISION_STATES,
        },
    )


FALLBACK_WORKSPACE_MCP_CONFIG_PATHS = (
    ".vscode/mcp.json",
    ".cursor/mcp.json",
    ".mcp.json",
    ".ai/mcp.json",
    "mcp.json",
)
MEMORY_CONFIG_PATHS = ("configs/naos_memory.yaml", "naos/configs/naos_memory.yaml")
ENGRAM_TOOLKIT_REQUIRED_MARKERS = ("config/projects.json",)
ENGRAM_TOOLKIT_ENTRYPOINT_MARKERS = ("scripts/setup.sh", "scripts/setup.ps1")
ENGRAM_BINARY_NAMES = ("engram", "engram-mcp", "mcp-engram", "engram-mcp-wrapper")
MEMORY_RECONCILIATION_OPTIONS = ["connect", "reuse", "repair", "new", "disabled", "deferred", "review_required"]


def _symbolic_project_path(root: Path, value: str | Path) -> str:
    path = Path(value).expanduser()
    if not path.is_absolute():
        return path.as_posix()
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        pass
    try:
        return "~/" + path.resolve().relative_to(Path.home().resolve()).as_posix()
    except (OSError, ValueError):
        return "<external-path-redacted>"


def _path_inside_project(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, RuntimeError, ValueError):
        return False


def _fallback_scan_mcp_configs(root: Path) -> list[dict[str, Any]]:
    return [
        {
            "config_id": f"fallback_workspace_{hashlib.sha256(relative.encode('utf-8')).hexdigest()[:12]}",
            "path": relative,
            "exists": (root / relative).is_file(),
            "status": "declared_unverified",
            "scope": "workspace",
            "kind": "server_definition",
            "clients": [],
            "servers": [],
            "engram_servers": [],
            "engram_projects": [],
            "has_secret_like_key": False,
        }
        for relative in FALLBACK_WORKSPACE_MCP_CONFIG_PATHS
    ]


def mcp_configs(root: Path, *, include_server_declarations: bool = False) -> list[dict[str, Any]]:
    discovery_source = "shared_registry"
    try:
        rows = _registry_scan_mcp_configs(root) if _registry_scan_mcp_configs is not None else _fallback_scan_mcp_configs(root)
    except (OSError, TypeError, ValueError):
        rows = _fallback_scan_mcp_configs(root)
        discovery_source = "fallback_registry"
    if _registry_scan_mcp_configs is None:
        discovery_source = "fallback_registry"

    configs: list[dict[str, Any]] = []
    for row in rows if isinstance(rows, list) else []:
        if (
            not isinstance(row, dict)
            or not row.get("exists")
            or str(row.get("kind") or "server_definition") != "server_definition"
        ):
            continue
        path = _symbolic_project_path(root, str(row.get("path") or "unknown"))
        registry_id = str(row.get("config_id") or "").strip()
        config_id = registry_id or f"workspace_{hashlib.sha256(path.encode('utf-8')).hexdigest()[:12]}"
        config = {
            "config_id": config_id,
            "path": path,
            "status": str(row.get("status") or "declared_unverified"),
            "authorization_status": "unknown",
            "human_review_required": True,
            "scope": str(row.get("scope") or "workspace"),
            "kind": str(row.get("kind") or "server_definition"),
            "clients": sorted(str(item) for item in (row.get("clients") or []) if item),
            "server_count": len(row.get("servers") or []),
            "engram_server_count": len(row.get("engram_servers") or []),
            "engram_projects": sorted(str(item) for item in (row.get("engram_projects") or []) if item),
            "has_secret_like_key": bool(row.get("has_secret_like_key")),
            "discovery_source": discovery_source,
            "configuration_presence_only": True,
            "live_access_verified": False,
        }
        if include_server_declarations:
            config["server_declarations"] = [
                dict(item)
                for item in row.get("server_declarations", [])
                if isinstance(item, dict)
            ]
        configs.append(config)
    return configs


def _mcp_descriptor_rules(
    root: Path,
    args: argparse.Namespace,
    policy: dict[str, Any],
) -> tuple[dict[str, Any] | None, str]:
    naos_root = getattr(args, "naos_root", None) or default_naos_root(policy)
    artifacts = policy.get("artifacts") if isinstance(policy.get("artifacts"), dict) else {}
    filename = str(artifacts.get("memory_mcp_inventory_rules") or "memory_mcp_inventory_rules.yaml")
    symbolic_path = (Path(naos_root) / filename).as_posix()
    try:
        path = safe_policy_path(
            naos_root_path(root, naos_root),
            filename,
            field="artifacts.memory_mcp_inventory_rules",
        )
    except (OSError, RuntimeError, ValueError):
        return {"_descriptor_review_load_error": "unsafe_rules_path"}, symbolic_path
    if not path.exists():
        return None, symbolic_path
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError):
        return {"_descriptor_review_load_error": "invalid_rules_document"}, symbolic_path
    if not isinstance(loaded, dict):
        return {"_descriptor_review_load_error": "invalid_rules_document"}, symbolic_path
    return loaded, symbolic_path


def project_identity_configs(root: Path) -> list[dict[str, Any]]:
    """Return project-identity declarations separately from MCP server configs."""

    try:
        rows = _registry_scan_mcp_configs(root) if _registry_scan_mcp_configs is not None else []
    except (OSError, TypeError, ValueError):
        rows = []

    configs: list[dict[str, Any]] = []
    for row in rows if isinstance(rows, list) else []:
        if (
            not isinstance(row, dict)
            or not row.get("exists")
            or str(row.get("kind") or "") != "project_identity"
        ):
            continue
        path = _symbolic_project_path(root, str(row.get("path") or "unknown"))
        registry_id = str(row.get("config_id") or "").strip()
        config_id = registry_id or f"project_identity_{hashlib.sha256(path.encode('utf-8')).hexdigest()[:12]}"
        configs.append(
            {
                "config_id": config_id,
                "path": path,
                "status": str(row.get("status") or "declared_unverified"),
                "scope": str(row.get("scope") or "workspace"),
                "kind": "project_identity",
                "engram_projects": sorted(
                    str(item) for item in (row.get("engram_projects") or []) if item
                ),
                "configuration_presence_only": True,
                "live_identity_verified": False,
            }
        )
    return configs


def _memory_config_metadata(root: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "data_dir": None,
        "config_path": None,
        "malformed": False,
        "replication_profile": "local",
        "replication_mode": "local_only",
    }
    for relative in MEMORY_CONFIG_PATHS:
        path = root / relative
        if not path.is_file():
            continue
        result["config_path"] = relative
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, UnicodeError, yaml.YAMLError):
            result["malformed"] = True
            return result
        if not isinstance(data, dict):
            result["malformed"] = True
            return result
        memory = data.get("memory", data)
        if not isinstance(memory, dict):
            result["malformed"] = True
            return result

        replication = memory.get("replication_profile", "local")
        if not isinstance(replication, str) or not replication.strip():
            result["malformed"] = True
            result["replication_profile"] = "invalid"
            result["replication_mode"] = "invalid_or_unknown"
        else:
            replication = replication.strip()
            result["replication_profile"] = replication
            result["replication_mode"] = "local_only" if replication == "local" else "configured_non_local_unverified"

        declared = memory.get("data_dir")
        if declared in (None, ""):
            return result
        if not isinstance(declared, str) or not declared.strip():
            result["malformed"] = True
            return result
        result["data_dir"] = declared.strip()
        return result
    return result


def _engram_data_paths(root: Path) -> tuple[Path, str, str, str, str | None, str, str]:
    metadata = _memory_config_metadata(root)
    config_path = metadata.get("config_path")
    malformed = bool(metadata.get("malformed"))
    replication_profile = str(metadata.get("replication_profile") or "invalid")
    replication_mode = str(metadata.get("replication_mode") or "invalid_or_unknown")
    invalid_config_path = str(config_path) if malformed and config_path else None
    configured = str(os.environ.get("ENGRAM_DATA_DIR") or "").strip()
    if configured:
        try:
            data_dir = Path(configured).expanduser()
            if not data_dir.is_absolute():
                data_dir = root / data_dir
            return (
                data_dir,
                "$ENGRAM_DATA_DIR",
                "$ENGRAM_DATA_DIR/engram.db",
                "environment",
                invalid_config_path,
                replication_profile,
                replication_mode,
            )
        except (OSError, RuntimeError, ValueError):
            malformed = True
            invalid_config_path = "$ENGRAM_DATA_DIR"

    declared = metadata.get("data_dir")
    if declared:
        try:
            data_dir = Path(str(declared)).expanduser()
            if not data_dir.is_absolute():
                data_dir = root / data_dir
            symbolic_data_dir = _symbolic_project_path(root, data_dir)
            symbolic_database = _symbolic_project_path(root, data_dir / "engram.db")
            if symbolic_data_dir == "<external-path-redacted>":
                symbolic_database = "<external-path-redacted>/engram.db"
            return (
                data_dir,
                symbolic_data_dir,
                symbolic_database,
                "config",
                invalid_config_path,
                replication_profile,
                replication_mode,
            )
        except (OSError, RuntimeError, ValueError):
            malformed = True

    data_dir = Path.home() / ".engram"
    return (
        data_dir,
        "~/.engram",
        "~/.engram/engram.db",
        "default",
        invalid_config_path,
        replication_profile,
        replication_mode,
    )


def _engram_toolkit_markers(candidate: Path) -> list[str]:
    required = [marker for marker in ENGRAM_TOOLKIT_REQUIRED_MARKERS if (candidate / marker).is_file()]
    entrypoints = [marker for marker in ENGRAM_TOOLKIT_ENTRYPOINT_MARKERS if (candidate / marker).is_file()]
    if len(required) != len(ENGRAM_TOOLKIT_REQUIRED_MARKERS) or not entrypoints:
        return []
    return sorted(required + entrypoints)


def memory_states(root: Path) -> list[dict[str, Any]]:
    states: list[dict[str, Any]] = []
    engram_name = next((name for name in ENGRAM_BINARY_NAMES if shutil.which(name)), None)
    states.append(
        {
            "resource_id": "engram_binary",
            "resource_type": "engram_binary",
            "status": "detected" if engram_name else "not_detected",
            "path": f"$PATH/{engram_name}" if engram_name else None,
            "classification": "path_available_binary" if engram_name else "absent",
            "human_review_required": bool(engram_name),
            "metadata_only": True,
            "path_redacted": bool(engram_name),
        }
    )

    (
        data_dir,
        symbolic_data_dir,
        symbolic_database,
        data_dir_source,
        invalid_config_path,
        replication_profile,
        replication_mode,
    ) = _engram_data_paths(root)
    data_dir_exists = data_dir.is_dir()
    database = data_dir / "engram.db"
    database_exists = database.is_file()
    configured_data_dir = data_dir_source in {"environment", "config"}
    prohibited_project_local_data_dir = _path_inside_project(data_dir, root)
    prohibited_project_local_database = prohibited_project_local_data_dir or (
        database_exists and _path_inside_project(database, root)
    )
    if invalid_config_path:
        states.append(
            {
                "resource_id": "engram_memory_config",
                "resource_type": "memory_configuration",
                "status": "invalid_config",
                "path": invalid_config_path,
                "classification": "malformed_memory_configuration",
                "human_review_required": True,
                "metadata_only": True,
                "path_redacted": False,
                "fallback_used": "~/.engram",
                "memory_payloads_read": False,
            }
        )
    states.extend(
        [
            {
                "resource_id": "engram_data_dir",
                "resource_type": "engram_data_dir",
                "status": (
                    "prohibited_location"
                    if prohibited_project_local_data_dir
                    else ("detected" if data_dir_exists else "not_detected")
                ),
                "path": symbolic_data_dir,
                "classification": (
                    "prohibited_project_local_data_dir"
                    if prohibited_project_local_data_dir
                    else ("configured_local_data_dir" if configured_data_dir else "default_local_data_dir")
                ),
                "data_dir_source": data_dir_source,
                "store_location_status": (
                    "prohibited_project_local"
                    if prohibited_project_local_data_dir
                    else "allowed_external_user_store"
                ),
                "human_review_required": prohibited_project_local_data_dir or configured_data_dir or data_dir_exists,
                "metadata_only": True,
                "path_redacted": True,
                "replication_profile_declared": replication_profile,
                "replication_mode": replication_mode,
                "git_memory_chunks_used": False,
            },
            {
                "resource_id": "engram_database",
                "resource_type": "engram_database",
                "status": (
                    "prohibited_location"
                    if prohibited_project_local_database
                    else ("detected" if database_exists else "not_detected")
                ),
                "path": symbolic_database,
                "classification": (
                    "prohibited_project_local_database"
                    if prohibited_project_local_database
                    else ("local_sqlite_database" if database_exists else "absent_local_database")
                ),
                "data_dir_source": data_dir_source,
                "store_location_status": (
                    "prohibited_project_local"
                    if prohibited_project_local_database
                    else "allowed_external_user_store"
                ),
                "human_review_required": prohibited_project_local_database or database_exists,
                "metadata_only": True,
                "path_redacted": True,
                "database_symlink": database.is_symlink(),
                "replication_profile_declared": replication_profile,
                "replication_mode": replication_mode,
                "git_memory_chunks_used": False,
            },
        ]
    )

    toolkit = Path.home() / "engram-memories"
    toolkit_markers = _engram_toolkit_markers(toolkit)
    if toolkit_markers:
        states.append(
            {
                "resource_id": "engram_management_toolkit",
                "resource_type": "management_toolkit",
                "status": "detected_unverified",
                "path": "~/engram-memories",
                "classification": "optional_management_toolkit_candidate",
                "human_review_required": True,
                "metadata_only": True,
                "path_redacted": True,
                "marker_files": toolkit_markers,
                "memory_store": False,
                "memory_transport": False,
            }
        )

    for config in mcp_configs(root):
        states.append(
            {
                "resource_id": f"mcp_{config['config_id']}",
                "resource_type": "mcp",
                "status": "declared_unverified",
                "path": config["path"],
                "classification": "declared_but_unverified_mcp",
                "human_review_required": True,
                "metadata_only": True,
                "path_redacted": False,
                "live_access_verified": False,
            }
        )
    for identity in project_identity_configs(root):
        states.append(
            {
                "resource_id": f"project_identity_{identity['config_id']}",
                "resource_type": "project_identity_declaration",
                "status": "declared_unverified",
                "path": identity["path"],
                "classification": "declared_but_unverified_project_identity",
                "human_review_required": True,
                "metadata_only": True,
                "path_redacted": False,
                "project_candidates": identity["engram_projects"],
                "live_identity_verified": False,
            }
        )
    if (root / ".env").exists() or os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY"):
        states.append(
            {
                "resource_id": "provider_api_mode",
                "resource_type": "provider",
                "status": "configured_but_unverified",
                "path": "environment_or_.env",
                "classification": "provider_api_mode_without_credential_validation",
                "human_review_required": True,
                "metadata_only": True,
                "path_redacted": True,
            }
        )
    ollama = shutil.which("ollama")
    if ollama:
        states.append(
            {
                "resource_id": "local_ollama",
                "resource_type": "local_runtime",
                "status": "detected",
                "path": "$PATH/ollama",
                "classification": "local_ollama_mode",
                "human_review_required": True,
                "metadata_only": True,
                "path_redacted": True,
            }
        )
    states.append(
        {
            "resource_id": "static_only",
            "resource_type": "adoption_mode",
            "status": "available",
            "path": None,
            "classification": "static_only_mode",
            "human_review_required": False,
            "metadata_only": True,
            "path_redacted": False,
        }
    )
    return states


def build_memory_resource_inventory(args: argparse.Namespace, root: Path, profile: str, policy: dict[str, Any]) -> dict[str, Any]:
    resources = memory_states(root)
    findings = [
        finding(f"memory_resource_inventory.review.{item['resource_id']}", "advisory", "review_required", "Memory/Engram/MCP state requires human posture decision.", resource_id=item["resource_id"])
        for item in resources
        if item.get("human_review_required")
    ]
    replication_modes = {
        str(item.get("replication_mode"))
        for item in resources
        if item.get("resource_type") in {"engram_data_dir", "engram_database"} and item.get("replication_mode")
    }
    replication_mode = next(iter(replication_modes)) if len(replication_modes) == 1 else "invalid_or_unknown"
    replication_profiles = {
        str(item.get("replication_profile_declared"))
        for item in resources
        if item.get("resource_type") == "engram_data_dir" and item.get("replication_profile_declared")
    }
    replication_profile = next(iter(replication_profiles)) if len(replication_profiles) == 1 else "invalid"
    if replication_mode != "local_only":
        findings.append(
            finding(
                "memory_resource_inventory.replication_not_local",
                severity_for_profile(profile, policy),
                "review_required",
                "Memory configuration declares a non-local or invalid replication profile; the inventory did not normalize it to local-only.",
                replication_profile=replication_profile,
                replication_mode=replication_mode,
            )
        )
    prohibited_resources = [
        str(item.get("resource_id"))
        for item in resources
        if item.get("store_location_status") == "prohibited_project_local"
    ]
    if prohibited_resources:
        findings.append(
            finding(
                "memory_resource_inventory.prohibited_project_local_store",
                severity_for_profile(profile, policy),
                "review_required",
                "Engram data or its derived database resolves inside the project; it must not be connected, reused, or indexed there.",
                resource_ids=prohibited_resources,
                required_action="Move the Engram data directory outside the repository before connecting or reusing it.",
            )
        )
    observation_sha256 = _memory_observation_sha256(resources)
    return base_report(
        "memory_resource_inventory",
        args,
        root,
        profile,
        policy,
        findings,
        {
            "resources": resources,
            "resource_counts": count_by(resources, "classification"),
            "memory_remains_advisory": True,
            "inspection_mode": "metadata_only",
            "memory_payloads_read": False,
            "provider_calls_performed": False,
            "replication_profile_declared": replication_profile,
            "replication_mode": replication_mode,
            "git_memory_chunks_used": False,
            "inventory_observation_sha256": observation_sha256,
        },
    )


def _memory_observation_sha256(resources: list[dict[str, Any]]) -> str:
    encoded = json.dumps(resources, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _valid_memory_resources(value: Any) -> list[dict[str, Any]] | None:
    if not isinstance(value, list) or not value:
        return None
    resources: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            return None
        resource_id = item.get("resource_id")
        if not isinstance(resource_id, str) or not resource_id or resource_id in seen_ids:
            return None
        if not isinstance(item.get("resource_type"), str) or not isinstance(item.get("status"), str) or not isinstance(item.get("classification"), str):
            return None
        if item.get("path") is not None and not isinstance(item.get("path"), str):
            return None
        if not isinstance(item.get("human_review_required"), bool):
            return None
        seen_ids.add(resource_id)
        resources.append(item)
    return resources


def _same_resolved_path(value: Any, expected: Path) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        return Path(value).resolve() == expected.resolve()
    except (OSError, RuntimeError, ValueError):
        return False


def _validated_persisted_memory_inventory(
    inventory: dict[str, Any],
    *,
    root: Path,
    profile: str,
    fresh_resources: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]] | None, str, str]:
    current_observation = _memory_observation_sha256(fresh_resources)
    resources = _valid_memory_resources(inventory.get("resources"))
    if resources is None:
        return None, "invalid_resource_shape", current_observation
    if inventory.get("schema") != "naos.memory_resource_inventory.v1":
        return None, "schema_mismatch", current_observation
    schema_path = SCRIPT_DIR.parent / "schemas" / "naos" / "memory_resource_inventory.schema.json"
    if not schema_path.is_file():
        return None, "schema_unavailable", current_observation
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, "schema_unavailable", current_observation
    if any(Draft202012Validator(schema).iter_errors(inventory)):
        return None, "schema_validation_failed", current_observation
    if not _same_resolved_path(inventory.get("project_root"), root):
        return None, "project_mismatch", current_observation
    if inventory.get("profile") != profile:
        return None, "profile_mismatch", current_observation
    if (
        inventory.get("memory_remains_advisory") is not True
        or inventory.get("inspection_mode") != "metadata_only"
        or inventory.get("memory_payloads_read") is not False
        or inventory.get("provider_calls_performed") is not False
        or inventory.get("git_memory_chunks_used") is not False
    ):
        return None, "metadata_boundary_mismatch", current_observation
    persisted_observation = inventory.get("inventory_observation_sha256")
    if not isinstance(persisted_observation, str) or persisted_observation != _memory_observation_sha256(resources):
        return None, "inventory_fingerprint_invalid", current_observation
    if persisted_observation != current_observation:
        return None, "current_observation_changed", current_observation
    return resources, "accepted", current_observation


def _dict_items(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _memory_reconciliation_options(item: dict[str, Any]) -> list[str]:
    """Return dispositions that are coherent with observed metadata only."""

    if item.get("classification") == "static_only_mode":
        return ["disabled", "deferred", "review_required"]
    if item.get("store_location_status") == "prohibited_project_local":
        return ["repair", "disabled", "deferred", "review_required"]
    status = str(item.get("status") or "")
    resource_type = str(item.get("resource_type") or "")
    if status in {"invalid_config", "prohibited_location"}:
        return ["repair", "disabled", "deferred", "review_required"]
    if status in {"not_detected", "absent"}:
        if resource_type in {"engram_data_dir", "engram_database"}:
            return ["new", "disabled", "deferred", "review_required"]
        return ["disabled", "deferred", "review_required"]
    return list(MEMORY_RECONCILIATION_OPTIONS)


def build_memory_resource_reconcile(args: argparse.Namespace, root: Path, profile: str, policy: dict[str, Any]) -> dict[str, Any]:
    naos_root = getattr(args, "naos_root", None) or default_naos_root(policy)
    inventory_path = default_report_path(root, naos_root, "memory_resource_inventory", policy)
    current_reports = _adoption_phase_reports(args)
    inventory = read_report(root, naos_root, "memory_resource_inventory", args, policy)
    fresh_resources = memory_states(root)
    persisted_resources: list[dict[str, Any]] | None = None
    inventory_validation = "missing"
    current_observation = _memory_observation_sha256(fresh_resources)
    inventory_available = (
        "memory_resource_inventory" in current_reports
        if current_reports is not None
        else inventory_path.exists()
    )
    if inventory_available:
        persisted_resources, inventory_validation, current_observation = _validated_persisted_memory_inventory(
            inventory,
            root=root,
            profile=profile,
            fresh_resources=fresh_resources,
        )
    resources = persisted_resources if persisted_resources is not None else fresh_resources
    resources_source = (
        "fresh_metadata_scan"
        if current_reports is not None
        else ("persisted_inventory" if persisted_resources is not None else "fresh_metadata_scan")
    )
    selected = getattr(args, "decision", None) or "review_required"
    options = MEMORY_RECONCILIATION_OPTIONS
    if selected not in options:
        selected = "review_required"
    decisions = []
    for item in resources:
        prohibited_location = item.get("store_location_status") == "prohibited_project_local"
        item_options = _memory_reconciliation_options(item)
        requested = "disabled" if item.get("classification") == "static_only_mode" else selected
        chosen = requested if requested in item_options else "review_required"
        if getattr(args, "interactive", False) and not getattr(args, "no_prompt", False) and item.get("human_review_required"):
            interactive_default = chosen if chosen in item_options else "review_required"
            chosen = interactive_choice(
                args,
                f"Memory/MCP disposition for {item.get('resource_id')}",
                item_options,
                interactive_default,
            )
        decision_status = "review_required" if chosen == "review_required" else "recorded"
        decisions.append(
            {
                "resource_id": item.get("resource_id"),
                "requested_option": requested,
                "selected_option": chosen,
                "available_options": item_options,
                "prohibited_project_local_store": prohibited_location,
                "resource_status_incompatible": requested not in item_options,
                "requested_option_rejected": requested not in item_options,
                "write_requested": bool(getattr(args, "write", False)),
                "write_performed": False,
                "human_review_required": decision_status == "review_required" or bool(item.get("human_review_required", True)),
                "status": decision_status,
                "memory_remains_advisory": True,
                "human_review_boundary": "Memory, Engram, MCP, and provider posture decisions remain adopter-owned and advisory until human review.",
            }
        )
    findings: list[dict[str, Any]] = []
    if inventory_available and persisted_resources is None:
        findings.append(
            finding(
                f"memory_resource_reconcile.inventory_{inventory_validation}",
                severity_for_profile(profile, policy),
                "review_required",
                "Memory inventory was rejected as malformed, foreign, stale, or outside the metadata-only boundary; reconciliation used a fresh metadata-only scan.",
                source_report=(
                    "current_invocation:memory_resource_inventory"
                    if current_reports is not None
                    else relpath(root, inventory_path)
                ),
                validation_reason=inventory_validation,
            )
        )
    findings.extend(
        finding(
            f"memory_resource_reconcile.{item.get('resource_id')}",
            severity_for_profile(profile, policy),
            "review_required",
            "Memory/MCP disposition requires human review.",
            resource_id=item.get("resource_id"),
        )
        for item in decisions
        if item.get("status") == "review_required"
    )
    rejected_project_local = [
        str(item.get("resource_id"))
        for item in decisions
        if item.get("prohibited_project_local_store") and item.get("requested_option_rejected")
    ]
    if rejected_project_local:
        findings.append(
            finding(
                "memory_resource_reconcile.prohibited_project_local_store",
                severity_for_profile(profile, policy),
                "review_required",
                "A connect, reuse, or new-store disposition was rejected because the Engram store resolves inside the project.",
                resource_ids=rejected_project_local,
                allowed_options=["repair", "disabled", "deferred", "review_required"],
            )
        )
    rejected_incompatible = [
        str(item.get("resource_id"))
        for item in decisions
        if item.get("requested_option_rejected") and not item.get("prohibited_project_local_store")
    ]
    if rejected_incompatible:
        findings.append(
            finding(
                "memory_resource_reconcile.resource_status_incompatible",
                severity_for_profile(profile, policy),
                "review_required",
                "A requested disposition was rejected because the observed resource state cannot support it.",
                resource_ids=rejected_incompatible,
                required_action="Choose a disposition offered for each resource; absent provider binaries cannot be connected by NAOS.",
            )
        )
    if getattr(args, "write", False):
        findings.append(
            finding(
                "memory_resource_reconcile.write_not_supported",
                "advisory",
                "advisory",
                "Write was requested, but memory reconciliation is report-only and did not mutate provider or client state.",
            )
        )
    return base_report(
        "memory_resource_reconcile",
        args,
        root,
        profile,
        policy,
        findings,
        {
            "decisions": decisions,
            "resources_source": resources_source,
            "source_inventory_validation": {
                "status": "accepted" if persisted_resources is not None else ("missing" if inventory_validation == "missing" else "rejected"),
                "reason": inventory_validation,
                "current_observation_sha256": current_observation,
                "project_root_match_required": True,
                "profile_match_required": True,
                "metadata_boundary_required": True,
            },
            "write_mode": "dry_run",
            "write_requested": bool(getattr(args, "write", False)),
            "write_performed": False,
            "provider_or_client_mutation_performed": False,
            "memory_remains_advisory": True,
        },
    )


def build_mcp_resource_inventory(args: argparse.Namespace, root: Path, profile: str, policy: dict[str, Any]) -> dict[str, Any]:
    configs = mcp_configs(root, include_server_declarations=True)
    rules_payload, rules_path = _mcp_descriptor_rules(root, args, policy)
    if _review_mcp_descriptors is None:
        descriptor_review = {
            "status": "invalid_rules",
            "rules_path": rules_path,
            "rules_sha256": None,
            "expected_rules_sha256": "2a5b39d7f89673df223f35890393da528ae413b4979e3766be155aea37c30375",
            "policy_integrity_status": "missing",
            "policy_schema": "naos.mcp_descriptor_review_policy.v1",
            "policy_version": "1.0.0",
            "policy_rule_count": 0,
            "declaration_count": sum(len(item.get("server_declarations") or []) for item in configs),
            "summary": {
                "allowlisted_pending_activation": 0,
                "review_required": sum(len(item.get("server_declarations") or []) for item in configs),
            },
            "activation_performed": False,
            "authentication_verified": False,
            "live_access_verified": False,
            "tool_authority_verified": False,
            "write_authority_verified": False,
            "provider_calls_performed": False,
            "remote_identity_verified": False,
            "declaration_reviews": [],
            "non_claims": ["descriptor reviewer unavailable; no declaration is allowlisted"],
        }
    else:
        descriptor_review = _review_mcp_descriptors(
            configs,
            rules_payload,
            rules_path=rules_path,
        )

    paths_by_config = {item["config_id"]: item["path"] for item in configs}
    reviewed_config_ids: set[str] = set()
    findings: list[dict[str, Any]] = []
    for item in descriptor_review.get("declaration_reviews", []):
        if not isinstance(item, dict):
            continue
        config_id = str(item.get("config_id") or "unknown")
        reviewed_config_ids.add(config_id)
        if item.get("status") == "allowlisted_pending_activation":
            findings.append(
                finding(
                    f"mcp_resource_inventory.{config_id}.{str(item.get('declaration_ref') or '')[:12]}",
                    "advisory",
                    "allowlisted_pending_activation",
                    "Static MCP declaration matches a risk-owner policy rule; activation, authentication, tools, and writes remain unverified and separately authorized.",
                    path=paths_by_config.get(config_id, "unknown"),
                )
            )
        else:
            findings.append(
                finding(
                    f"mcp_resource_inventory.{config_id}.{str(item.get('declaration_ref') or '')[:12]}",
                    "advisory",
                    "review_required",
                    "Declared MCP server does not match a valid risk-owner descriptor rule and requires review.",
                    path=paths_by_config.get(config_id, "unknown"),
                    reason_codes=item.get("reason_codes", []),
                )
            )
    for item in configs:
        if item["config_id"] in reviewed_config_ids:
            continue
        findings.append(
            finding(
                f"mcp_resource_inventory.{item['config_id']}",
                "advisory",
                "review_required",
                "Declared MCP config has no statically reviewable server declaration and may require authorization review.",
                path=item["path"],
            )
        )
    return base_report(
        "mcp_resource_inventory",
        args,
        root,
        profile,
        policy,
        findings,
        {
            "mcp_configs": configs,
            "mcp_config_count": len(configs),
            "descriptor_review": descriptor_review,
            "descriptor_review_summary": dict(descriptor_review.get("summary") or {}),
            "configuration_presence_only": True,
            "live_access_verified": False,
            "provider_calls_performed": False,
            "activation_performed": False,
            "authentication_verified": False,
            "tool_authority_verified": False,
            "write_authority_verified": False,
        },
    )


def count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def count_candidate_types(candidates: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {"FR": 0, "NFR": 0}
    for item in candidates:
        value = str(item.get("candidate_type") or item.get("type") or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def interactive_value(args: argparse.Namespace, prompt: str, default: str = "unknown") -> str:
    if not getattr(args, "interactive", False) or getattr(args, "no_prompt", False):
        return default
    try:
        print(f"{prompt} [{default}]: ", end="", file=sys.stderr, flush=True)
        entered = input().strip()
    except EOFError:
        return default
    return entered or default


def interactive_choice(args: argparse.Namespace, prompt: str, choices: list[str], default: str) -> str:
    value = interactive_value(args, f"{prompt} ({'/'.join(choices)})", default)
    return value if value in choices else default


def load_reports(
    root: Path,
    naos_root: str,
    keys: list[str],
    args: argparse.Namespace | None = None,
    policy: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    reports = []
    for key in keys:
        path = default_report_path(root, naos_root, key, policy)
        data = read_report(root, naos_root, key, args, policy)
        reports.append({"report_id": key, "path": str(path), "present": bool(data), "status": data.get("status") if data else "missing", "human_review_required": data.get("human_review_required", True) if data else True})
    return reports


def build_install_plan(args: argparse.Namespace, root: Path, profile: str, policy: dict[str, Any]) -> dict[str, Any]:
    naos_root = getattr(args, "naos_root", None) or default_naos_root(policy)
    reports = load_reports(root, naos_root, ["preflight", "intake", "existing_resource_inventory", "ai_artifact_inventory", "memory_resource_inventory", "mcp_resource_inventory"], args, policy)
    missing = [item for item in reports if not item["present"]]
    findings = [finding(f"install_plan.missing.{item['report_id']}", "advisory", "advisory", f"Recommended upstream report is missing: {item['report_id']}.", report_id=item["report_id"]) for item in missing]
    mode = normalize_answer(getattr(args, "mode", None), "greenfield")
    recommendations = [
        {"id": "profile_recommendation", "recommendation": profile, "rationale": "Selected profile is retained; human may override with recorded residual risk.", "human_review_required": True},
        {"id": "module_recommendation", "recommendation": "run setup-recommendations", "rationale": "Module recommendations remain deterministic and optional.", "human_review_required": True},
    ]
    activation = {
        "init_command": f"naos init . --tier {profile} --activate",
        "hook_ci_boundary": "Hooks, CI, provider/API runtime, memory write-back, and hidden context injection are not auto-enabled.",
        "write_posture": "preview_first_explicit_activation",
    }
    repository_intelligence = _repository_intelligence_consumer_evidence(
        args,
        consumer="install_plan",
    )
    if repository_intelligence is not None:
        activation["repository_intelligence"] = (
            "reuse_validated_current_generation_without_new_activation"
        )
    interactive_decisions: list[dict[str, Any]] = []
    if getattr(args, "interactive", False) and not getattr(args, "no_prompt", False):
        selected = interactive_choice(
            args,
            "Install plan disposition",
            ["defer", "activate_after_review", "repair_first", "review_required"],
            "review_required",
        )
        interactive_decisions.append(
            {
                "decision_id": "install_plan_disposition",
                "selected_option": selected,
                "available_options": ["defer", "activate_after_review", "repair_first", "review_required"],
                "status": "recorded" if selected != "review_required" else "review_required",
                "human_review_required": True,
            }
        )
    return base_report(
        "install_plan",
        args,
        root,
        profile,
        policy,
        findings,
        {
            "reports_considered": reports,
            "recommendations": recommendations,
            "activation_plan": activation,
            "mode": mode,
            "repository_intelligence": repository_intelligence,
            "interactive_review_decisions": interactive_decisions,
            "user_decisions": interactive_decisions,
        },
    )


def build_brownfield_baseline(args: argparse.Namespace, root: Path, profile: str, policy: dict[str, Any]) -> dict[str, Any]:
    naos_root = getattr(args, "naos_root", None) or default_naos_root(policy)
    keys = [
        "preflight",
        "existing_resource_inventory",
        "ai_artifact_inventory",
        "memory_resource_inventory",
        "mcp_resource_inventory",
        "install_plan",
        "requirements_reconstruct",
        "traceability_gap_register",
    ]
    reports = load_reports(root, naos_root, keys, args, policy)
    missing = [item for item in reports if not item["present"]]
    findings = [finding(f"brownfield_baseline.missing.{item['report_id']}", "advisory", "advisory", f"Baseline input missing: {item['report_id']}.", report_id=item["report_id"]) for item in missing]
    return base_report(
        "brownfield_baseline",
        args,
        root,
        profile,
        policy,
        findings,
        {
            "reports_considered": reports,
            "baseline_scope": "deterministic_file_first",
            "approval_status": "not_approval",
            "repository_intelligence": _repository_intelligence_consumer_evidence(
                args,
                consumer="brownfield_baseline",
            ),
        },
    )


NFR_PATH_TOKENS = [
    "security",
    "privacy",
    "threat",
    "auth",
    "crypto",
    "key",
    "secret",
    "dependabot",
    "codeql",
    "semgrep",
    "bandit",
    "pip-audit",
    "trivy",
    "safety",
    ".github/workflows",
]
NFR_CONTENT_TOKENS = [
    "security",
    "privacy",
    "authentication",
    "authorization",
    "encrypt",
    "secret",
    "token",
    "audit",
    "logging",
    "dependency",
    "vulnerability",
    "ci",
    "workflow",
    "backup",
    "availability",
]
AGENT_LOOP_EXPLICIT_TOKENS = [
    "agent_loop",
    "agent-loop",
    "agent loop",
    "governed agent loop",
    "loop engineering",
    "/loop",
    "autonomous loop",
    "afk task",
    "afk candidate",
    "scheduled agent",
    "agentic loop",
]
AGENT_LOOP_AI_TOKENS = [
    "ai agent",
    "ai assistant",
    "claude",
    "coding agent",
    "codex",
    "copilot",
    "gemini",
    "llm",
    "mcp",
    "openai",
    "anthropic",
]
AGENT_LOOP_AUTOMATION_TOKENS = [
    "cron:",
    "daemon",
    "hooks",
    "posttooluse",
    "pretooluse",
    "schedule",
    "scheduler",
    "while true",
    "workflow_dispatch",
]


def read_small_text(root: Path, rel: str, limit: int = 8000) -> str:
    try:
        return (root / rel).read_text(encoding="utf-8", errors="ignore")[:limit]
    except Exception:
        return ""


def contains_any_token(text: str, tokens: list[str]) -> bool:
    lower = text.lower()
    return any(token in lower for token in tokens)


def workflow_trigger_names(text: str) -> list[str]:
    try:
        loaded = yaml.safe_load(text) or {}
    except Exception:
        loaded = {}
    workflow_on: Any = None
    if isinstance(loaded, dict):
        workflow_on = loaded.get("on")
        if workflow_on is None:
            workflow_on = loaded.get(True)
    names: list[str] = []
    if isinstance(workflow_on, str):
        names.append(workflow_on)
    elif isinstance(workflow_on, list):
        names.extend(str(item) for item in workflow_on)
    elif isinstance(workflow_on, dict):
        names.extend(str(item) for item in workflow_on)
    lower = text.lower()
    if "workflow_dispatch" in lower and "workflow_dispatch" not in names:
        names.append("workflow_dispatch")
    if re.search(r"(?m)^\s*-\s*cron\s*:", lower) and "schedule" not in names:
        names.append("schedule")
    if re.search(r"(?m)^\s*schedule\s*:", lower) and "schedule" not in names:
        names.append("schedule")
    return sorted({name.lower() for name in names})


def makefile_targets(text: str) -> list[str]:
    return sorted(
        {
            match.group(1).lower()
            for match in re.finditer(r"(?m)^([A-Za-z0-9_.-]+)\s*:", text)
            if not match.group(1).startswith(".")
        }
    )


def signal_entry(path: str, signal_type: str, strength: str, reason: str, trigger: bool) -> dict[str, Any]:
    return {
        "path": path,
        "signal_type": signal_type,
        "strength": strength,
        "reason": reason,
        "candidate_trigger": trigger,
    }


def detect_agent_loop_signals(root: Path) -> dict[str, Any]:
    """Detect strong, review-only agent-loop declaration candidates from local files."""
    files = sorted(relpath(root, item) for item in list_files(root, max_files=5000))
    signals: list[dict[str, Any]] = []
    weak_signals: list[dict[str, Any]] = []

    workflow_paths = [
        path
        for path in files
        if path.startswith(".github/workflows/") and path.lower().endswith((".yml", ".yaml"))
    ][:30]
    for path in workflow_paths:
        text = read_small_text(root, path, limit=12000)
        triggers = workflow_trigger_names(text)
        explicit_loop = contains_any_token(f"{path}\n{text}", AGENT_LOOP_EXPLICIT_TOKENS)
        ai_marker = contains_any_token(text, AGENT_LOOP_AI_TOKENS)
        has_schedule = "schedule" in triggers
        has_manual = "workflow_dispatch" in triggers
        if has_schedule and (explicit_loop or ai_marker):
            signals.append(signal_entry(path, "scheduled_agent_workflow", "strong", "Scheduled workflow also contains AI/agent or explicit loop markers.", True))
        elif has_manual and explicit_loop:
            signals.append(signal_entry(path, "manual_agent_loop_workflow", "strong", "Manual workflow contains explicit agent-loop markers.", True))
        elif explicit_loop and contains_any_token(text, AGENT_LOOP_AUTOMATION_TOKENS):
            signals.append(signal_entry(path, "agent_loop_workflow", "strong", "Workflow contains explicit agent-loop and automation markers.", True))
        elif has_schedule or has_manual:
            weak_signals.append(signal_entry(path, "workflow_trigger", "weak", "Workflow trigger alone is insufficient evidence of an agent loop.", False))

    claude_settings = ".claude/settings.json"
    if claude_settings in files:
        text = read_small_text(root, claude_settings, limit=12000)
        explicit_loop = contains_any_token(text, AGENT_LOOP_EXPLICIT_TOKENS)
        automation_marker = contains_any_token(text, AGENT_LOOP_AUTOMATION_TOKENS)
        hook_marker = contains_any_token(text, ["hooks", "pretooluse", "posttooluse"])
        if explicit_loop or (hook_marker and automation_marker and contains_any_token(text, AGENT_LOOP_AI_TOKENS)):
            signals.append(signal_entry(claude_settings, "claude_agent_loop_hook", "strong", "Claude settings contain hook automation with agent-loop markers.", True))
        elif hook_marker:
            weak_signals.append(signal_entry(claude_settings, "claude_hook_config", "weak", "Hook configuration alone is insufficient evidence of a governed agent loop.", False))

    for path in ["Makefile", "makefile", "GNUmakefile"]:
        if path not in files:
            continue
        text = read_small_text(root, path, limit=12000)
        targets = makefile_targets(text)
        explicit_loop = contains_any_token(f"{path}\n{text}", AGENT_LOOP_EXPLICIT_TOKENS)
        ai_marker = contains_any_token(text, AGENT_LOOP_AI_TOKENS)
        automation_marker = contains_any_token(text, AGENT_LOOP_AUTOMATION_TOKENS)
        loop_targets = [target for target in targets if "loop" in target or target in {"afk", "agent-watch", "agentic"}]
        watch_targets = [target for target in targets if target == "watch" or target.endswith("-watch")]
        if explicit_loop or (loop_targets and (ai_marker or automation_marker)):
            signals.append(signal_entry(path, "make_agent_loop_target", "strong", "Makefile target contains loop/AFK plus AI or automation markers.", True))
        elif loop_targets or watch_targets:
            weak_signals.append(signal_entry(path, "make_automation_target", "weak", "Makefile loop/watch target lacks enough AI/agent evidence for a candidate.", False))

    if "package.json" in files:
        text = read_small_text(root, "package.json", limit=12000)
        try:
            package_data = json.loads(text)
        except Exception:
            package_data = {}
        scripts = package_data.get("scripts") if isinstance(package_data, dict) else {}
        if isinstance(scripts, dict):
            strong_scripts = []
            weak_scripts = []
            for name, command in scripts.items():
                script_text = f"{name}\n{command}"
                explicit_loop = contains_any_token(script_text, AGENT_LOOP_EXPLICIT_TOKENS)
                ai_marker = contains_any_token(str(command), AGENT_LOOP_AI_TOKENS)
                automation_marker = contains_any_token(script_text, AGENT_LOOP_AUTOMATION_TOKENS)
                loop_named = any(token in str(name).lower() for token in ["loop", "afk", "agent"])
                watch_named = "watch" in str(name).lower()
                if explicit_loop or (loop_named and ai_marker and automation_marker):
                    strong_scripts.append(str(name))
                elif loop_named or watch_named:
                    weak_scripts.append(str(name))
            if strong_scripts:
                signals.append(signal_entry("package.json", "package_agent_loop_script", "strong", f"Package scripts suggest agent-loop automation: {', '.join(sorted(strong_scripts)[:5])}.", True))
            elif weak_scripts:
                weak_signals.append(signal_entry("package.json", "package_automation_script", "weak", f"Package scripts are automation-like but not enough for an agent-loop candidate: {', '.join(sorted(weak_scripts)[:5])}.", False))

    triggering = [item for item in signals if item.get("candidate_trigger")]
    evidence_refs = sorted({str(item["path"]) for item in triggering})
    return {
        "status": "candidate_suggested" if triggering else "no_candidate",
        "candidate_id": "NFR-AGENT-LOOP-001" if triggering else None,
        "evidence_refs": evidence_refs,
        "signals": triggering,
        "weak_signals": weak_signals[:20],
        "detection_boundary": "proposal_only_no_active_agent_loop_file_no_runtime_execution",
    }


def nfr_title_for(path: str, text: str) -> str:
    lower = f"{path}\n{text}".lower()
    if any(token in lower for token in ["auth", "authentication", "authorization"]):
        return "Candidate security requirement for authentication and authorization review"
    if any(token in lower for token in ["privacy", "data class", "personal data", "pii"]):
        return "Candidate privacy and data-handling requirement"
    if any(token in lower for token in ["secret", "token", "key", "crypto", "encrypt"]):
        return "Candidate secret, key-management, or encryption requirement"
    if any(token in lower for token in ["dependabot", "codeql", "semgrep", "bandit", "pip-audit", "trivy", "safety", "vulnerability"]):
        return "Candidate dependency and security-tooling requirement"
    if any(token in lower for token in ["ci", "workflow", ".github/workflows"]):
        return "Candidate CI evidence and review requirement"
    if any(token in lower for token in ["backup", "availability", "recovery"]):
        return "Candidate availability and recovery requirement"
    return "Candidate non-functional requirement from controlled local evidence"


def nfr_supported(path: str, text: str) -> bool:
    lower = f"{path}\n{text}".lower()
    return any(token in lower for token in NFR_PATH_TOKENS) or any(token in lower for token in NFR_CONTENT_TOKENS)


def confidence_for_source(path: str, source_kind: str) -> str:
    if path.startswith("specs/"):
        return "confirmed_by_existing_spec"
    if source_kind in {"docs", "intake"}:
        return "supported_by_docs"
    if source_kind == "tests":
        return "inferred_from_tests"
    if source_kind == "source":
        return "inferred_from_code"
    return "hypothesized_requires_review"


def looks_like_generated_naos_doc(root: Path, path: str) -> bool:
    if not path.startswith(("docs/", "specs/")):
        return False
    sample = read_small_text(root, path, limit=4000).lower()
    if any(token in sample for token in ["auto-generated: copied by naos init", "naos portable governance kit", "<!-- adapt:", "adapt:"]):
        return True
    return "naos" in sample and any(token in sample for token in ["governance", "adopter", "profile", "capability", "evidence pack"])


def looks_like_generated_naos_source(root: Path, path: str) -> bool:
    if not path.endswith((".py", ".ts", ".tsx", ".js", ".go", ".java", ".yml", ".yaml")):
        return False
    sample = read_small_text(root, path, limit=1200).lower()
    return any(token in sample for token in ["auto-generated: copied by naos init", "naos portable governance kit"])


def project_evidence_paths(root: Path, paths: list[str]) -> list[str]:
    generated_prefixes = (
        "naos/",
        "schemas/naos/",
        "templates/",
        "capabilities/",
        "policies/",
        "scripts/naos_",
        ".naos-preview/",
        ".github/autoresearch/",
        ".github/workflows/naos-",
    )
    generated_exact = {"Makefile.naos", "cli.py", "naos_init.py", "naos_add.py", "naos_upgrade.py"}
    return [
        path
        for path in paths
        if path not in generated_exact
        and not path.startswith(generated_prefixes)
        and not looks_like_generated_naos_doc(root, path)
        and not looks_like_generated_naos_source(root, path)
    ]


def build_requirements_reconstruct(args: argparse.Namespace, root: Path, profile: str, policy: dict[str, Any]) -> dict[str, Any]:
    signals = detect_project_signals(root)
    agent_loop_discovery = detect_agent_loop_signals(root)
    naos_root = getattr(args, "naos_root", None) or default_naos_root(policy)
    intake_report = read_report(root, naos_root, "intake", args, policy)
    intake = intake_report.get("intake") if isinstance(intake_report.get("intake"), dict) else {}
    docs = project_evidence_paths(root, signals["docs"])
    source = project_evidence_paths(root, signals["source"])
    tests = project_evidence_paths(root, signals["tests"])
    workflows = project_evidence_paths(root, signals["workflows"])
    repository_context = _adoption_repository_intelligence(args)
    repository_candidates = (
        repository_context.get("candidates")
        if isinstance(repository_context, dict)
        and isinstance(repository_context.get("candidates"), list)
        else []
    )
    retrieval_candidates = (
        repository_context.get("retrieval_candidates")
        if isinstance(repository_context, dict)
        and isinstance(repository_context.get("retrieval_candidates"), list)
        else []
    )
    repository_by_path = {
        str(item.get("source_path")): item
        for item in repository_candidates
        if isinstance(item, dict) and item.get("source_path")
    }
    for item in retrieval_candidates:
        if not isinstance(item, dict) or not item.get("source_path"):
            continue
        path = str(item["source_path"])
        repository_by_path.setdefault(
            path,
            {
                "source_path": path,
                "source_sha256": item.get("source_sha256"),
                "family_id": item.get("family_id"),
                "authority_level": item.get("authority_level"),
                "source_revalidated": item.get("source_revalidated") is True,
                "candidate_only": True,
            },
        )
    retrieval_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    retrieval_rank_by_path: dict[str, int] = {}
    for rank, item in enumerate(retrieval_candidates):
        if not isinstance(item, dict) or not item.get("source_path"):
            continue
        path = str(item["source_path"])
        retrieval_by_path[path].append(item)
        retrieval_rank_by_path.setdefault(path, rank)

    def paths_for_families(*family_ids: str) -> list[str]:
        allowed = set(family_ids)
        return sorted(
            path
            for path, item in repository_by_path.items()
            if str(item.get("family_id") or "") in allowed
        )

    if repository_candidates:
        docs = list(dict.fromkeys([*docs, *paths_for_families("documentation", "specifications")]))
        source = list(dict.fromkeys([*source, *paths_for_families("source", "migrations")]))
        tests = list(dict.fromkeys([*tests, *paths_for_families("tests")]))
        workflows = list(
            dict.fromkeys(
                [
                    *workflows,
                    *[
                        path
                        for path in paths_for_families("build_and_configuration")
                        if path.startswith((".github/workflows/", ".gitlab/"))
                    ],
                ]
            )
        )
    evidence_limit = 100 if repository_candidates else 12
    candidates: list[dict[str, Any]] = []
    for index, path in enumerate(docs[:evidence_limit], start=1):
        confidence = confidence_for_source(path, "docs")
        text = read_small_text(root, path)
        candidates.append(
            candidate(
                f"FR-DOC-{index:03d}",
                "FR",
                f"Candidate functional requirement from {path}",
                f"Local documentation was detected at {path}; reviewers should confirm any described behavior before promotion.",
                [path],
                confidence,
                "documentation",
                ["Which statements in this document should become authoritative requirements?"],
            )
        )
        if nfr_supported(path, text):
            candidates.append(
                candidate(
                    f"NFR-DOC-{index:03d}",
                    "NFR",
                    nfr_title_for(path, text),
                    f"Controlled local documentation at {path} references non-functional, security, privacy, CI, or operating constraints.",
                    [path],
                    confidence,
                    "documentation",
                    ["Which NFR wording should be adopted, rejected, or deferred by a human reviewer?"],
                )
            )
    for index, path in enumerate(source[:evidence_limit], start=1):
        text = read_small_text(root, path)
        candidates.append(
            candidate(
                f"FR-CODE-{index:03d}",
                "FR",
                f"Candidate behavior inferred from source file {path}",
                f"Source file {path} indicates behavior that may need a formal requirement, but code evidence is not requirements authority.",
                [path],
                "inferred_from_code",
                "source_code",
                ["Does this source behavior reflect intended product behavior or incidental implementation?"],
            )
        )
        if nfr_supported(path, text):
            candidates.append(
                candidate(
                    f"NFR-CODE-{index:03d}",
                    "NFR",
                    nfr_title_for(path, text),
                    f"Source file {path} contains non-functional or security-related indicators; reviewers must decide whether a candidate NFR is warranted.",
                    [path],
                    "inferred_from_code",
                    "source_code",
                    ["Does this code indicator represent an intended security/privacy/operational requirement?"],
                )
            )
    for index, path in enumerate((tests + workflows)[:evidence_limit], start=1):
        text = read_small_text(root, path)
        candidates.append(
            candidate(
                f"FR-TEST-{index:03d}",
                "FR",
                f"Candidate behavior inferred from test or workflow file {path}",
                f"Test or workflow evidence at {path} suggests an expected behavior, but it must be reviewed before becoming a requirement.",
                [path],
                "inferred_from_tests",
                "tests_or_ci",
                ["Is this test or workflow evidence intentionally required behavior?"],
            )
        )
        if nfr_supported(path, text):
            candidates.append(
                candidate(
                    f"NFR-TEST-{index:03d}",
                    "NFR",
                    nfr_title_for(path, text),
                    f"Test or CI evidence at {path} references non-functional, security, privacy, or operating constraints.",
                    [path],
                    "inferred_from_tests",
                    "tests_or_ci",
                    ["Should this test or CI evidence become a formal NFR, or remain supporting evidence only?"],
                )
            )
    represented_paths = {
        str(path)
        for item in candidates
        for path in (item.get("evidence_refs") or [])
        if isinstance(path, str) and path
    }
    retrieval_confidence = {
        "specifications": "supported_by_docs",
        "documentation": "supported_by_docs",
        "tests": "inferred_from_tests",
        "migrations": "inferred_from_code",
        "source": "inferred_from_code",
        "build_and_configuration": "inferred_from_code",
    }
    for path, _rank in sorted(
        retrieval_rank_by_path.items(), key=lambda item: (item[1], item[0])
    ):
        if path in represented_paths:
            continue
        source_record = repository_by_path.get(path) or {}
        family_id = str(source_record.get("family_id") or "")
        confidence = retrieval_confidence.get(family_id)
        if confidence is None or source_record.get("source_revalidated") is not True:
            continue
        stable_suffix = hashlib.sha256(path.encode("utf-8")).hexdigest()[:16].upper()
        candidates.append(
            candidate(
                f"FR-RETRIEVAL-{stable_suffix}",
                "FR",
                f"Candidate behavior surfaced by repository retrieval from {path}",
                (
                    f"Source-bound repository retrieval ranked {path} outside the normal "
                    "bounded evidence prefix; reviewers must inspect the source before "
                    "promotion."
                ),
                [path],
                confidence,
                f"repository_intelligence_retrieval_{family_id}",
                [
                    "Does this retrieved evidence represent intended behavior or only an implementation detail?"
                ],
            )
        )
        represented_paths.add(path)
    intake_nfr_fields = {
        "regulated_context": intake.get("regulated_context"),
        "data_class": intake.get("data_class"),
        "evidence_expectations": intake.get("evidence_expectations"),
        "review_model": intake.get("review_model"),
        "memory_mcp_posture": intake.get("memory_mcp_posture"),
    }
    explicit_intake = {key: value for key, value in intake_nfr_fields.items() if value and str(value).lower() not in {"unknown", "no", "none", "not_applicable"}}
    if explicit_intake:
        candidates.append(
            candidate(
                "NFR-INTAKE-001",
                "NFR",
                "Candidate NFR from explicit intake answers",
                "Guided intake captured regulated-context, data-class, evidence, review-model, or memory/MCP posture answers that may require non-functional requirements.",
                ["naos/reports/intake_report.json"],
                "supported_by_docs",
                "intake_answers",
                ["Which intake answers should become authoritative NFRs or review constraints?"],
            )
        )
    if agent_loop_discovery["status"] == "candidate_suggested":
        confidence = "inferred_from_tests" if any(path.startswith(".github/workflows/") for path in agent_loop_discovery["evidence_refs"]) else "inferred_from_code"
        agent_loop_candidate = candidate(
            "NFR-AGENT-LOOP-001",
            "NFR",
            "Candidate governed agent-loop declaration review",
            "Controlled local automation evidence suggests this project may need a governed agent-loop declaration, but this report only proposes a human-reviewed candidate.",
            agent_loop_discovery["evidence_refs"],
            confidence,
            "agent_loop_signal_detection",
            [
                "Does the detected automation actually run an AI/agent loop, or is it ordinary CI/tooling?",
                "Who owns the trigger, scope, budget caps, evaluator, kill switch, and human approval gates if a loop exists?",
                "Should this become active governance, remain a candidate, or be explicitly rejected as not applicable?",
            ],
        )
        agent_loop_candidate.update(
            {
                "proposal_only": True,
                "active_file_written": False,
                "candidate_output_only": "candidate_requirements.json",
                "detected_loop_signals": agent_loop_discovery["signals"],
                "weak_non_triggering_signals": agent_loop_discovery["weak_signals"],
                "prohibited_actions": [
                    "does not write naos/agent_loop.yaml",
                    "does not create agent_loop.candidate.yaml",
                    "does not start schedulers, daemons, hooks, or runtime loops",
                    "does not call LLMs or external providers",
                    "does not change public documentation, publication state, signing, or export artifacts",
                ],
                "non_claims": CANDIDATE_NON_CLAIMS
                + [
                    "agent-loop candidate does not prove that a runtime loop exists",
                    "agent-loop candidate does not create active governance",
                    "agent-loop candidate does not authorize automation execution",
                ],
            }
        )
        candidates.append(agent_loop_candidate)
    if not candidates:
        candidates.append(
            candidate(
                "FR-HYP-001",
                "FR",
                "No direct requirements evidence found; project purpose requires human review.",
                "No controlled source, doc, test, workflow, or intake evidence was sufficient for concrete reconstruction.",
                [],
                "hypothesized_requires_review",
                "missing_evidence",
                ["What source evidence should reviewers provide before requirements are reconstructed?"],
            )
        )
    native_candidate_order = {
        str(item.get("candidate_id")): index for index, item in enumerate(candidates)
    }
    if repository_by_path:
        for item in candidates:
            evidence = [
                {
                    "path": path,
                    "source_sha256": repository_by_path[path].get("source_sha256"),
                    "family_id": repository_by_path[path].get("family_id"),
                    "authority_level": repository_by_path[path].get("authority_level"),
                    "source_revalidated": repository_by_path[path].get("source_revalidated") is True,
                    "retrieval_lanes": sorted(
                        {
                            str(match.get("lane") or "")
                            for match in retrieval_by_path.get(path, [])
                            if str(match.get("lane") or "")
                        }
                    ),
                    "retrieval_matches": [
                        {
                            "lane": match.get("lane"),
                            "match_reason": (match.get("retrieval") or {}).get(
                                "match_reason"
                            ),
                            "score_type": (match.get("retrieval") or {}).get(
                                "score_type"
                            ),
                            "score": (match.get("retrieval") or {}).get("score"),
                            "query": (match.get("retrieval") or {}).get("query"),
                            "relationship_ids": [
                                step.get("relationship_id")
                                for step in (
                                    (match.get("retrieval") or {}).get("edge_path")
                                    or []
                                )
                                if isinstance(step, dict)
                            ],
                        }
                        for match in retrieval_by_path.get(path, [])
                    ],
                    "candidate_only": True,
                    "authority_effect": "none",
                }
                for path in item.get("evidence_refs") or []
                if path in repository_by_path
            ]
            if evidence:
                item["repository_intelligence_evidence"] = evidence
                ranks = [
                    retrieval_rank_by_path[path]
                    for path in item.get("evidence_refs") or []
                    if path in retrieval_rank_by_path
                ]
                if ranks:
                    item["repository_intelligence_review_priority"] = {
                        "rank": min(ranks),
                        "effect": "review_order_only",
                        "authority_effect": "none",
                    }
        candidates.sort(
            key=lambda item: (
                0
                if isinstance(item.get("repository_intelligence_review_priority"), dict)
                else 1,
                int(
                    (
                        item.get("repository_intelligence_review_priority") or {}
                    ).get("rank")
                    or 0
                ),
                native_candidate_order.get(str(item.get("candidate_id")), len(candidates)),
            )
        )
    findings = [
        finding(
            f"requirements_reconstruct.review.{item['candidate_id']}",
            "advisory",
            "review_required",
            "Candidate requirement requires human review before promotion.",
            candidate_id=item["candidate_id"],
            candidate_type=item["candidate_type"],
            confidence_class=item["confidence_class"],
        )
        for item in candidates
        if item["confidence_class"] != "confirmed_by_existing_spec"
    ]
    return base_report(
        "requirements_reconstruct",
        args,
        root,
        profile,
        policy,
        findings,
        {
            "candidates": candidates,
            "candidate_counts": count_candidate_types(candidates),
            "candidate_type_counts": count_candidate_types(candidates),
            "agent_loop_discovery": agent_loop_discovery,
            "confidence_classes": CONFIDENCE_CLASSES,
            "promotion_rule": "human_review_required",
            "non_claims": CANDIDATE_NON_CLAIMS,
            "repository_intelligence": _repository_intelligence_consumer_evidence(
                args,
                consumer="requirements_reconstruct",
            ),
        },
    )


def candidate(
    candidate_id: str,
    candidate_type: str,
    title: str,
    rationale: str,
    evidence_refs: list[str],
    confidence: str,
    source_basis: str,
    open_questions: list[str] | None = None,
) -> dict[str, Any]:
    normalized_type = candidate_type if candidate_type in {"FR", "NFR"} else "FR"
    legacy_type = "functional" if normalized_type == "FR" else "non_functional"
    return {
        "candidate_id": candidate_id,
        "candidate_type": normalized_type,
        "type": legacy_type,
        "title": title,
        "text": title,
        "rationale": rationale,
        "evidence_refs": evidence_refs,
        "confidence_class": confidence if confidence in CONFIDENCE_CLASSES else "hypothesized_requires_review",
        "source_basis": source_basis,
        "open_questions": open_questions or ["Human reviewer must decide whether to promote, reject, or defer this candidate."],
        "human_review_required": True,
        "non_claims": CANDIDATE_NON_CLAIMS,
        "review_state": "human_review_required",
        "promoted_to_authority": False,
    }


def build_traceability_gap_register(args: argparse.Namespace, root: Path, profile: str, policy: dict[str, Any]) -> dict[str, Any]:
    naos_root = getattr(args, "naos_root", None) or default_naos_root(policy)
    candidates_report = read_report(root, naos_root, "requirements_reconstruct", args, policy)
    candidates = candidates_report.get("candidates") if isinstance(candidates_report.get("candidates"), list) else []
    gaps: list[dict[str, Any]] = []
    for item in candidates:
        if item.get("confidence_class") != "confirmed_by_existing_spec":
            gaps.append(
                {
                    "gap_id": f"GAP-{safe_slug(str(item.get('candidate_id')))}",
                    "gap_type": "candidate_requires_review",
                    "evidence_refs": item.get("evidence_refs") or [],
                    "owner": "unknown",
                    "confidence": item.get("confidence_class"),
                    "next_action": "Human reviewer must confirm, reject, or defer the candidate before promotion.",
                    "closure_state": "open",
                    "human_review_required": True,
                    "repository_intelligence_evidence": item.get(
                        "repository_intelligence_evidence"
                    )
                    or [],
                    "repository_intelligence_authority_effect": "none",
                }
            )
    if not gaps:
        gaps.append({"gap_id": "GAP-BASELINE-001", "gap_type": "baseline_review", "evidence_refs": [], "owner": "unknown", "confidence": "unknown", "next_action": "Review traceability manually.", "closure_state": "open", "human_review_required": True})
    findings = [finding(f"traceability_gap_register.{item['gap_id']}", severity_for_profile(profile, policy), "review_required", "Traceability gap requires owner decision.", gap_id=item["gap_id"]) for item in gaps]
    return base_report(
        "traceability_gap_register",
        args,
        root,
        profile,
        policy,
        findings,
        {
            "gaps": gaps,
            "closure_rule": "explicit_evidence_or_human_decision_required",
            "repository_intelligence": _repository_intelligence_consumer_evidence(
                args,
                consumer="traceability_gap_register",
            ),
        },
    )


def build_install_decision_record(args: argparse.Namespace, root: Path, profile: str, policy: dict[str, Any]) -> dict[str, Any]:
    naos_root = getattr(args, "naos_root", None) or default_naos_root(policy)
    report_keys = [
        "preflight",
        "intake",
        "existing_resource_inventory",
        "ai_artifact_inventory",
        "ai_artifact_reconcile",
        "memory_resource_inventory",
        "memory_resource_reconcile",
        "mcp_resource_inventory",
        "install_plan",
        "requirements_reconstruct",
        "traceability_gap_register",
        "context_challenge",
        "repo_context_challenge",
        "plan_challenge",
        "decision_probe",
        "planning_gate_review",
        "brownfield_baseline",
    ]
    report_refs = load_reports(root, naos_root, report_keys, args, policy)
    reports = {key: read_report(root, naos_root, key, args, policy) for key in report_keys}
    intake = reports["intake"].get("intake") if isinstance(reports["intake"].get("intake"), dict) else {}
    project_signals = reports["preflight"].get("project_signals") if isinstance(reports["preflight"].get("project_signals"), dict) else detect_project_signals(root)
    resources = reports["existing_resource_inventory"].get("resources") if isinstance(reports["existing_resource_inventory"].get("resources"), list) else []
    artifacts = reports["ai_artifact_inventory"].get("artifacts") if isinstance(reports["ai_artifact_inventory"].get("artifacts"), list) else []
    memory_resources = _dict_items(reports["memory_resource_inventory"].get("resources"))
    mcp_configs_report = reports["mcp_resource_inventory"].get("mcp_configs") if isinstance(reports["mcp_resource_inventory"].get("mcp_configs"), list) else []
    mcp_descriptor_review = (
        reports["mcp_resource_inventory"].get("descriptor_review")
        if isinstance(reports["mcp_resource_inventory"].get("descriptor_review"), dict)
        else {}
    )
    candidates = reports["requirements_reconstruct"].get("candidates") if isinstance(reports["requirements_reconstruct"].get("candidates"), list) else []
    gaps = reports["traceability_gap_register"].get("gaps") if isinstance(reports["traceability_gap_register"].get("gaps"), list) else []
    ai_decisions = reports["ai_artifact_reconcile"].get("decisions") if isinstance(reports["ai_artifact_reconcile"].get("decisions"), list) else []
    memory_decisions = _dict_items(reports["memory_resource_reconcile"].get("decisions"))
    challenge_keys = ["context_challenge", "repo_context_challenge", "plan_challenge", "decision_probe", "planning_gate_review"]
    challenge_reports = [
        {
            "report_id": key,
            "present": bool(reports[key]),
            "status": reports[key].get("status") if reports[key] else "missing",
            "facts_confirmed": reports[key].get("facts_confirmed", []) if reports[key] else [],
            "assumptions_detected": reports[key].get("assumptions_detected", []) if reports[key] else [],
            "missing_information": reports[key].get("missing_information", []) if reports[key] else [],
            "decisions_required": reports[key].get("decisions_required", []) if reports[key] else [],
            "evidence_used": reports[key].get("evidence_used", []) if reports[key] else [],
            "challenge_scope": reports[key].get("challenge_scope", "missing") if reports[key] else "missing",
            "existing_reports_evaluated": reports[key].get("existing_reports_evaluated", False) if reports[key] else False,
            "substantive_plan_or_gate_evaluation_performed": reports[key].get("substantive_plan_or_gate_evaluation_performed", False) if reports[key] else False,
            "scope_limitation": reports[key].get("scope_limitation", "") if reports[key] else "",
            "no_edit_confirmation": reports[key].get("no_edit_confirmation", False) if reports[key] else False,
        }
        for key in challenge_keys
    ]
    discovered_facts = [
        {"fact_id": "project.has_git", "value": bool(project_signals.get("has_git")), "source": "preflight"},
        {"fact_id": "project.has_docs", "value": bool(project_signals.get("has_docs")), "source": "preflight"},
        {"fact_id": "project.has_tests", "value": bool(project_signals.get("has_tests")), "source": "preflight"},
        {"fact_id": "project.has_source", "value": bool(project_signals.get("has_source")), "source": "preflight"},
        {"fact_id": "inventory.resources_detected", "value": len(resources), "source": "existing_resource_inventory"},
        {"fact_id": "inventory.ai_artifacts_detected", "value": len(artifacts), "source": "ai_artifact_inventory"},
        {"fact_id": "inventory.memory_resources_detected", "value": len(memory_resources), "source": "memory_resource_inventory"},
        {"fact_id": "inventory.mcp_configs_detected", "value": len(mcp_configs_report), "source": "mcp_resource_inventory"},
        {
            "fact_id": "inventory.mcp_descriptor_review_status",
            "value": str(mcp_descriptor_review.get("status") or "not_available"),
            "source": "mcp_resource_inventory",
        },
        {
            "fact_id": "inventory.mcp_descriptors_allowlisted_pending_activation",
            "value": int((mcp_descriptor_review.get("summary") or {}).get("allowlisted_pending_activation") or 0),
            "source": "mcp_resource_inventory",
        },
    ]
    assumptions = []
    for report in reports.values():
        for item in report.get("assumptions", []) if isinstance(report, dict) else []:
            assumptions.append(item)
    for challenge in challenge_reports:
        for item in challenge.get("assumptions_detected", []):
            assumptions.append({"id": safe_slug(str(item)), "description": item, "source": challenge["report_id"], "status": "review_required"})
    missing_information = sorted(set(reports["intake"].get("missing_information", []) if isinstance(reports["intake"].get("missing_information"), list) else []))
    for challenge in challenge_reports:
        for item in challenge.get("missing_information", []):
            if item not in missing_information:
                missing_information.append(item)
    collisions = [
        {
            "artifact_path": item.get("path"),
            "detected_owner": item.get("detected_owner"),
            "conflict_category": item.get("conflict_category"),
            "conflict_reason": item.get("conflict_reason"),
            "recommended_decision": item.get("recommended_decision"),
            "human_review_required": item.get("human_review_required", True),
        }
        for item in artifacts
        if item.get("status") in {"conflicting", "stale", "unknown", "review_required"}
    ]
    files_skipped = [
        {"path": ref["path"], "reason": "upstream report missing"} for ref in report_refs if not ref["present"]
    ]
    files_created: list[dict[str, Any]] = []
    files_refreshed: list[dict[str, Any]] = []
    files_planned: list[dict[str, Any]] = []
    current_invocation_reports = _adoption_phase_reports(args)
    if current_invocation_reports is not None:
        planned_outputs = []
        for ref in report_refs:
            if not ref["present"]:
                continue
            actual_output = report_path(root, naos_root, policy, ref["report_id"])
            if actual_output is None:
                files_skipped.append(
                    {
                        "path": ref["path"],
                        "reason": "no adopter NAOS report output path",
                    }
                )
                continue
            planned_outputs.append(
                {
                    "path": str(actual_output),
                    "source": ref["report_id"],
                    "write_context": "orchestrated_adopt_latest_report",
                }
            )
        decision_output = report_path(root, naos_root, policy, "install_decision_record")
        adoption_output = report_path(
            root,
            naos_root,
            policy,
            "adopt",
            getattr(args, "output", None),
        )
        if decision_output is not None:
            planned_outputs.append(
                {
                    "path": str(decision_output),
                    "source": "install_decision_record",
                    "write_context": "orchestrated_adopt_latest_report",
                }
            )
        if adoption_output is not None:
            planned_outputs.append(
                {
                    "path": str(adoption_output),
                    "source": "adopt",
                    "write_context": "orchestrated_adopt_latest_report",
                }
            )
        if getattr(args, "no_write_preview", False):
            files_skipped.extend(
                {"path": item["path"], "reason": "no-write preview"}
                for item in planned_outputs
            )
        else:
            files_planned = planned_outputs
    else:
        decision_output = report_path(
            root,
            naos_root,
            policy,
            "install_decision_record",
            getattr(args, "output", None),
        )
        if decision_output is not None:
            files_planned.extend(
                [
                    {
                        "path": str(decision_output),
                        "source": "install_decision_record",
                        "write_context": "standalone_latest_report",
                        "state_at_record_construction": "pending",
                    },
                    {
                        "path": str(naos_root_path(root, naos_root) / "INSTALL_DECISION_RECORD.md"),
                        "source": "install_decision_record",
                        "write_context": "standalone_markdown_sidecar",
                        "state_at_record_construction": "pending",
                    },
                ]
            )
    protected_files = sorted(
        set(
            [item.get("path") for item in artifacts if item.get("path")]
            + [item.get("path") for item in resources if item.get("path") and not str(item.get("path")).startswith(f"{naos_root}/")]
        )
    )
    files_preserved = [{"path": path, "reason": "existing project artifact; no silent overwrite"} for path in protected_files[:100]]
    candidate_summary = {
        "total": len(candidates),
        "by_type": count_candidate_types(candidates),
        "by_confidence": count_by(candidates, "confidence_class"),
        "human_review_required": True,
        "non_claims": CANDIDATE_NON_CLAIMS,
    }
    traceability_summary = {
        "gap_count": len(gaps),
        "open_gaps": len([item for item in gaps if item.get("closure_state") != "closed"]),
        "human_review_required": True,
    }
    gate_readiness_baseline = {
        "status": "not_executed_by_install_decision_record",
        "next_action": "Run naos gate-status and naos gate-evaluate after adoption evidence is reviewed.",
        "approval_status": "not_approval",
    }
    decisions = [
        {
            "decision_id": "profile",
            "selected_option": profile,
            "status": "recorded",
            "evidence_refs": [item["path"] for item in report_refs if item["present"]],
            "alternatives": ["quickstart", "lite", "standard", "assured"],
            "residual_risk": "Profile controls readiness posture but does not approve maturity.",
            "human_review_required": True,
        },
        {
            "decision_id": "activation",
            "selected_option": "explicit_human_activation_required",
            "status": "review_required",
            "evidence_refs": [item["path"] for item in report_refs if item["present"]],
            "alternatives": ["defer", "activate_after_review", "repair_first"],
            "residual_risk": "Writes must remain preview-first and explicit.",
            "human_review_required": True,
        },
    ]
    decisions.extend(
        {
            "decision_id": f"ai_artifact.{item.get('artifact_id')}",
            "selected_option": item.get("selected_option"),
            "status": item.get("status", "review_required"),
            "evidence_refs": [default_report_path(root, naos_root, "ai_artifact_reconcile", policy).as_posix()],
            "alternatives": item.get("available_options", DECISION_STATES),
            "residual_risk": item.get("human_review_boundary", "Human review required before changing AI artifacts."),
            "human_review_required": item.get("human_review_required", True),
        }
        for item in ai_decisions
    )
    decisions.extend(
        {
            "decision_id": f"memory_resource.{item.get('resource_id')}",
            "selected_option": item.get("selected_option"),
            "status": item.get("status", "review_required"),
            "evidence_refs": [default_report_path(root, naos_root, "memory_resource_reconcile", policy).as_posix()],
            "alternatives": item.get("available_options", []),
            "residual_risk": item.get("human_review_boundary", "Memory/MCP decisions remain advisory and human-owned."),
            "human_review_required": item.get("human_review_required", True),
        }
        for item in memory_decisions
    )
    findings = [finding("install_decision_record.activation", severity_for_profile(profile, policy), "review_required", "Activation and durable adoption decisions require human review.")]
    if collisions:
        findings.append(finding("install_decision_record.ai_collisions", severity_for_profile(profile, policy), "review_required", "AI artifact collisions or review-required surfaces must be decided before activation.", collision_count=len(collisions)))
    if gaps:
        findings.append(finding("install_decision_record.traceability_gaps", "advisory", "review_required", "Traceability gaps remain open until owner decisions close them.", gap_count=len(gaps)))
    return base_report(
        "install_decision_record",
        args,
        root,
        profile,
        policy,
        findings,
        {
            "adoption_mode": normalize_answer(getattr(args, "mode", None), "greenfield"),
            "selected_profile": profile,
            "command_invocation": {
                "command": REPORT_SPECS["install_decision_record"]["command"],
                "mode": normalize_answer(getattr(args, "mode", None), "greenfield"),
                "interactive": bool(getattr(args, "interactive", False)),
                "write_requested": bool(getattr(args, "write", False)),
            },
            "project_path": str(root),
            "preflight_summary": {
                "status": reports["preflight"].get("status", "missing") if reports["preflight"] else "missing",
                "project_signals": project_signals,
            },
            "intake_answers_summary": {
                "source": intake.get("source", "missing"),
                "known_answers": {key: value for key, value in intake.items() if value != "unknown"},
                "unknown_fields": intake.get("unknown_fields", []),
            },
            "discovered_facts": discovered_facts,
            "assumptions": assumptions,
            "inferred_candidates": [
                {
                    "candidate_id": item.get("candidate_id"),
                    "candidate_type": item.get("candidate_type"),
                    "title": item.get("title"),
                    "confidence_class": item.get("confidence_class"),
                    "source_basis": item.get("source_basis"),
                    "human_review_required": True,
                }
                for item in candidates
            ],
            "missing_information": missing_information,
            "existing_resource_inventory_summary": {
                "resource_count": len(resources),
                "by_category": count_by(resources, "category"),
                "review_required": len([item for item in resources if item.get("human_review_required")]),
            },
            "ai_artifact_inventory_summary": {
                "artifact_count": len(artifacts),
                "by_status": count_by(artifacts, "status"),
                "collision_count": len(collisions),
            },
            "memory_mcp_inventory_summary": {
                "memory_resource_count": len(memory_resources),
                "mcp_config_count": len(mcp_configs_report),
                "mcp_descriptor_review_status": str(mcp_descriptor_review.get("status") or "not_available"),
                "mcp_descriptor_review_summary": dict(mcp_descriptor_review.get("summary") or {}),
                "mcp_activation_performed": False,
                "memory_remains_advisory": True,
            },
            "reconciliation_decisions": {
                "ai_artifacts": ai_decisions,
                "memory_resources": memory_decisions,
            },
            "files_created": files_created,
            "files_refreshed": files_refreshed,
            "files_planned": files_planned,
            "file_write_inventory_scope": "At record construction, files_created and files_refreshed include only writes already completed; files_planned contains current or future sinks whose success is not yet known.",
            "files_skipped": files_skipped,
            "files_preserved": files_preserved,
            "protected_files": protected_files,
            "collisions": collisions,
            "challenge_reports": challenge_reports,
            "gate_readiness_baseline_summary": gate_readiness_baseline,
            "candidate_fr_nfr_summary": candidate_summary,
            "traceability_gap_summary": traceability_summary,
            "repository_intelligence": _repository_intelligence_consumer_evidence(
                args,
                consumer="install_decision_record",
            ),
            "residual_risks": [
                "Human reviewers must approve adoption decisions before activation.",
                "Candidate requirements remain candidates until promoted by humans.",
                "Memory, Engram, MCP, and AI artifact findings remain advisory.",
            ],
            "user_decisions": decisions,
            "decisions": decisions,
            "next_actions": [
                "Review AI artifact and memory/MCP reconciliation decisions.",
                "Resolve or accept traceability gaps.",
                "Run gate-status and gate-evaluate after adoption evidence is reviewed.",
            ],
            "human_review_boundary": "The install decision record summarizes adoption evidence and decisions; it does not approve activation, certify maturity, prove compliance, prove runtime safety, or finalize requirements.",
            "non_claims": CANDIDATE_NON_CLAIMS + AI_ARTIFACT_NON_CLAIMS,
            "report_refs": report_refs,
        },
    )


def build_challenge(spec_key: str, args: argparse.Namespace, root: Path, profile: str, policy: dict[str, Any]) -> dict[str, Any]:
    mode = normalize_answer(getattr(args, "challenge_mode", None) or getattr(args, "mode", None), "install")
    if mode not in CHALLENGE_MODES and mode not in MODES:
        mode = "install"
    signals = detect_project_signals(root)
    facts = []
    if signals["has_docs"]:
        facts.append("Local documentation files were detected.")
    if signals["has_source"]:
        facts.append("Local source files were detected.")
    if signals["has_tests"]:
        facts.append("Local test files were detected.")
    assumptions = [
        "Unknown intake answers remain assumptions until answered or explicitly deferred.",
        "Detected artifacts indicate review needs, not authority.",
    ]
    missing = []
    if not signals["has_docs"]:
        missing.append("project documentation or specs")
    if not signals["has_tests"]:
        missing.append("test evidence")
    decisions_required = [
        "Confirm whether missing information should be answered, deferred, or treated as residual risk.",
        "Confirm whether candidate requirements may be promoted, rejected, or left for later review.",
    ]
    risks = [
        "Proceeding without context can blur facts, assumptions, and candidate evidence.",
        "Memory, generated context, and AI artifacts can be over-trusted unless kept advisory.",
    ]
    findings = [
        finding(f"{spec_key}.missing.{safe_slug(item)}", severity_for_profile(profile, policy, advisory=profile in {"quickstart", "lite"}), "review_required", f"Challenge found missing information: {item}.", missing=item)
        for item in missing
    ]
    interactive_answers: list[dict[str, Any]] = []
    if getattr(args, "interactive", False) and not getattr(args, "no_prompt", False):
        questions = [f"What is the accepted disposition for {item}?" for item in missing] or ["What should reviewers challenge next?"]
        for question in questions:
            answer = interactive_value(args, question, "review_required")
            interactive_answers.append({"question": question, "answer": answer, "human_review_required": True})
    enumerated_paths = list(
        dict.fromkeys(signals["docs"][:20] + signals["source"][:20] + signals["tests"][:20])
    )
    return base_report(
        spec_key,
        args,
        root,
        profile,
        policy,
        findings,
        {
            "challenge_mode": mode,
            "source_file_paths_enumerated": enumerated_paths,
            "evidence_used": ["local_file_paths"],
            "challenge_scope": "generic_local_file_path_posture",
            "existing_reports_evaluated": False,
            "substantive_plan_or_gate_evaluation_performed": False,
            "scope_limitation": "This generic challenge report enumerates local file-path signals only; it does not read or evaluate a plan, source-file contents, decision record, gate state, or prior report content.",
            "facts_confirmed": facts,
            "assumptions_detected": assumptions,
            "inferred_candidates": [{"id": "candidate.context.review", "description": "Context appears reviewable only after missing information is handled.", "confidence": "hypothesized_requires_review"}],
            "missing_information": missing,
            "contradictions": [],
            "risks": risks,
            "residual_risks": ["Human reviewers must decide whether to proceed with unresolved context."],
            "user_questions": [f"What is the accepted disposition for {item}?" for item in missing],
            "interactive_answers": interactive_answers,
            "decisions_required": decisions_required,
            "confidence_classification": "hypothesized_requires_review" if missing else "file_presence_observed",
            "next_recommended_naos_action": "Resolve missing information or record residual risk before build.",
            "no_edit_confirmation": True,
            "human_review_boundary": "Challenge reports do not edit files, approve work, or promote candidates to authority.",
        },
    )


def build_adopt(args: argparse.Namespace, root: Path, profile: str, policy: dict[str, Any]) -> dict[str, Any]:
    mode = normalize_answer(getattr(args, "mode", None), "greenfield")
    if mode not in MODES:
        mode = "greenfield"
    no_write_preview = bool(getattr(args, "no_write_preview", False))
    dry_run = bool(getattr(args, "dry_run", False) or no_write_preview)
    prestart_naos_root = getattr(args, "naos_root", None) or default_naos_root(policy)
    repository_intelligence_modes = {"brownfield", "repair", "evaluation"}
    repository_intelligence_snapshot: dict[str, Any] | None = None
    if mode in repository_intelligence_modes and build_repository_intelligence_guidance is not None:
        repository_intelligence_prestart = build_repository_intelligence_guidance(
            root,
            prestart_naos_root,
            profile,
            required_usage_scopes=ADOPTION_REPOSITORY_INTELLIGENCE_SCOPES,
        )
        if repository_intelligence_prestart.get("lifecycle_status") == "validated_current":
            if read_active_repository_intelligence_snapshot is None:
                repository_intelligence_prestart = {
                    "applicable": False,
                    "applicability_status": "undetermined",
                    "lifecycle_status": "blocked",
                    "continuation_allowed": False,
                    "recommendation": "blocked_prerequisite",
                    "selected_profile": profile,
                    "engine_execution": "refused",
                    "plan_status": "blocked_prerequisite",
                    "required_usage_scopes": list(ADOPTION_REPOSITORY_INTELLIGENCE_SCOPES),
                    "usage_scope_satisfied": False,
                    "error": "The repository-intelligence consumer runtime is unavailable.",
                    "installation": {
                        "automatic": False,
                        "explicit_digest_confirmation_required": False,
                        "capability_enrollment_required": False,
                        "transaction_and_recovery_required": True,
                        "source_artifacts_remain_authoritative": True,
                        "next_action": "Repair the generated repository-intelligence runtime before onboarding.",
                    },
                    "not_claimed": ["repository-intelligence consumption", "activation readiness"],
                }
            else:
                try:
                    repository_intelligence_snapshot = read_active_repository_intelligence_snapshot(
                        root,
                        naos_root=prestart_naos_root,
                        required_usage_scopes=ADOPTION_REPOSITORY_INTELLIGENCE_SCOPES,
                        retrieval_queries=_adoption_retrieval_queries(args),
                        limit=500,
                    )
                except (RepositoryIntelligenceError, OSError, RuntimeError, ValueError) as exc:
                    repository_intelligence_prestart = {
                        **repository_intelligence_prestart,
                        "applicable": False,
                        "applicability_status": "undetermined",
                        "lifecycle_status": "blocked",
                        "continuation_allowed": False,
                        "recommendation": "blocked_prerequisite",
                        "engine_execution": "refused",
                        "plan_status": "blocked_prerequisite",
                        "usage_scope_satisfied": False,
                        "error": str(exc),
                        "not_claimed": ["repository-intelligence consumption", "activation readiness"],
                    }
    else:
        applicable_mode = mode in repository_intelligence_modes
        repository_intelligence_prestart = {
            "applicable": False,
            "applicability_status": (
                "undetermined" if applicable_mode else "not_applicable"
            ),
            "lifecycle_status": "blocked" if applicable_mode else "not_applicable",
            "continuation_allowed": not applicable_mode,
            "recommendation": "blocked_prerequisite" if applicable_mode else "not_applicable_for_mode",
            "selected_profile": profile,
            "engine_execution": "not_run",
            "plan_status": "blocked_prerequisite" if applicable_mode else "not_applicable",
            "reason_codes": [
                "setup_recommendation_runtime_unavailable"
                if applicable_mode
                else "mode_does_not_require_repository_intelligence"
            ],
            "required_usage_scopes": (
                list(ADOPTION_REPOSITORY_INTELLIGENCE_SCOPES) if applicable_mode else []
            ),
            "usage_scope_satisfied": not applicable_mode,
            "installation": {
                "automatic": False,
                "explicit_digest_confirmation_required": False,
                "capability_enrollment_required": False,
                "transaction_and_recovery_required": applicable_mode,
                "source_artifacts_remain_authoritative": True,
                "next_action": (
                    "Repository-intelligence pre-start guidance applies to brownfield, repair, and evaluation modes."
                    if not applicable_mode
                    else "Repair the generated setup-recommendation runtime before onboarding."
                ),
            },
            "not_claimed": [
                "repository-intelligence applicability",
                "activation readiness",
            ],
        }
        if applicable_mode:
            repository_intelligence_prestart["error"] = (
                "The generated setup-recommendation runtime is unavailable."
            )
    continuation_allowed = bool(repository_intelligence_prestart.get("continuation_allowed"))
    if mode in repository_intelligence_modes and not continuation_allowed:
        lifecycle_status = str(
            repository_intelligence_prestart.get("lifecycle_status") or "blocked"
        )
        finding_status = "review_required" if lifecycle_status == "activation_required" else "blocked"
        action = str(
            (repository_intelligence_prestart.get("installation") or {}).get("next_action")
            or "Resolve repository-intelligence pre-start requirements before onboarding."
        )
        return base_report(
            "adopt",
            args,
            root,
            profile,
            policy,
            [
                finding(
                    "adopt.repository_intelligence_action_required",
                    severity_for_profile(profile, policy),
                    finding_status,
                    action,
                    lifecycle_status=lifecycle_status,
                )
            ],
            {
                "mode": mode,
                "dry_run": dry_run,
                "preview_only": dry_run,
                "no_write_preview": True,
                "persistence_allowed": False,
                "continuation_allowed": False,
                "report_writes_performed": False,
                "activation_planned": False,
                "protected_file_changes": [],
                "repository_intelligence_prestart": repository_intelligence_prestart,
                "repository_intelligence_consumption": {
                    "status": lifecycle_status,
                    "consumed": False,
                    "candidate_only": True,
                    "source_artifacts_remain_authoritative": True,
                },
                "phases": [],
                "reports_generated": [],
                "dry_run_preview": [
                    "Would stop before adoption phases and report persistence.",
                    action,
                ]
                if dry_run
                else [],
                "activation_boundary": "Repository intelligence must be explicitly enrolled, activated, current, and validated before applicable onboarding phases run.",
            },
        )
    phase_args = argparse.Namespace(**vars(args))
    current_reports: dict[str, dict[str, Any]] = {}
    setattr(phase_args, _ADOPTION_PHASE_REPORTS_ATTR, current_reports)
    if repository_intelligence_snapshot is not None:
        setattr(
            phase_args,
            _ADOPTION_REPOSITORY_INTELLIGENCE_ATTR,
            repository_intelligence_snapshot,
        )
    evaluated_reports: list[tuple[str, dict[str, Any], Path | None, Path | None]] = []
    phases = [
        ("preflight", build_preflight),
        ("intake", build_intake),
        ("existing_resource_inventory", build_existing_resource_inventory),
        ("ai_artifact_inventory", build_ai_artifact_inventory),
        ("ai_artifact_reconcile", build_ai_artifact_reconcile),
        ("memory_resource_inventory", build_memory_resource_inventory),
        ("memory_resource_reconcile", build_memory_resource_reconcile),
        ("mcp_resource_inventory", build_mcp_resource_inventory),
        ("install_plan", build_install_plan),
        ("context_challenge", lambda a, r, p, pol: build_challenge("context_challenge", a, r, p, pol)),
    ]
    if mode in {"brownfield", "repair", "evaluation"}:
        phases.extend(
            [
                ("repo_context_challenge", lambda a, r, p, pol: build_challenge("repo_context_challenge", a, r, p, pol)),
                ("requirements_reconstruct", build_requirements_reconstruct),
                ("traceability_gap_register", build_traceability_gap_register),
                ("brownfield_baseline", build_brownfield_baseline),
            ]
        )
    phases.extend(
        [
            ("plan_challenge", lambda a, r, p, pol: build_challenge("plan_challenge", a, r, p, pol)),
            ("decision_probe", lambda a, r, p, pol: build_challenge("decision_probe", a, r, p, pol)),
            ("planning_gate_review", lambda a, r, p, pol: build_challenge("planning_gate_review", a, r, p, pol)),
            ("install_decision_record", build_install_decision_record),
        ]
    )
    for key, builder in phases:
        report = builder(phase_args, root, profile, policy)
        current_reports[key] = report
        path = report_path(root, report["naos_root"], policy, key, None)
        session_path = None
        if report.get("session_id"):
            session_path = session_report_default_path(root, report["naos_root"], policy, str(report["session_id"]), REPORT_SPECS[key]["report_key"])
        evaluated_reports.append((key, report, path, session_path))
    if repository_intelligence_snapshot is not None:
        try:
            if (
                validate_active_generation is None
                or repository_intelligence_binding is None
                or assert_repository_intelligence_binding_unchanged is None
            ):
                raise RepositoryIntelligenceError(
                    "The repository-intelligence closing-validation runtime is unavailable."
                )
            closing_context = validate_active_generation(
                root,
                naos_root=prestart_naos_root,
                require_current_source=True,
            )
            closing_binding = repository_intelligence_binding(closing_context)
            assert_repository_intelligence_binding_unchanged(
                repository_intelligence_snapshot.get("opening_generation") or {},
                closing_binding,
            )
            repository_intelligence_consumption = {
                "status": "consumed",
                "opening_generation": repository_intelligence_snapshot.get(
                    "opening_generation"
                )
                or {},
                "closing_generation": closing_binding,
                "binding_unchanged": True,
                "usage_scopes_authorized": True,
                "required_usage_scopes": repository_intelligence_snapshot.get(
                    "required_usage_scopes"
                )
                or [],
                "components_used": repository_intelligence_snapshot.get("components")
                or {},
                "candidate_count": len(
                    repository_intelligence_snapshot.get("candidates") or []
                ),
                "retrieval_candidate_count": len(
                    repository_intelligence_snapshot.get("retrieval_candidates") or []
                ),
                "fts_candidate_count": int(
                    (
                        repository_intelligence_snapshot.get("retrieval") or {}
                    ).get("fts_candidate_count")
                    or 0
                ),
                "graph_candidate_count": int(
                    (
                        repository_intelligence_snapshot.get("retrieval") or {}
                    ).get("graph_candidate_count")
                    or 0
                ),
                "graph_results_consumed": bool(
                    (
                        repository_intelligence_snapshot.get("retrieval") or {}
                    ).get("graph_results_consumed")
                ),
                "relationship_count": len(
                    repository_intelligence_snapshot.get("relationships") or []
                ),
                "candidate_only": True,
                "source_artifacts_remain_authoritative": True,
                "consumer_reports": [item[0] for item in evaluated_reports],
            }
        except (RepositoryIntelligenceError, OSError, RuntimeError, ValueError) as exc:
            return base_report(
                "adopt",
                args,
                root,
                profile,
                policy,
                [
                    finding(
                        "adopt.repository_intelligence_changed_before_persistence",
                        severity_for_profile(profile, policy),
                        "blocked",
                        f"Repository-intelligence closing validation refused report persistence: {exc}",
                    )
                ],
                {
                    "mode": mode,
                    "dry_run": dry_run,
                    "preview_only": dry_run,
                    "no_write_preview": True,
                    "persistence_allowed": False,
                    "continuation_allowed": False,
                    "report_writes_performed": False,
                    "activation_planned": False,
                    "protected_file_changes": [],
                    "repository_intelligence_prestart": repository_intelligence_prestart,
                    "repository_intelligence_consumption": {
                        "status": "blocked",
                        "consumed": False,
                        "error": str(exc),
                        "candidate_only": True,
                        "source_artifacts_remain_authoritative": True,
                    },
                    "phases": [],
                    "reports_generated": [],
                    "dry_run_preview": [
                        "Would persist no reports because the active intelligence binding or source changed."
                    ]
                    if dry_run
                    else [],
                    "activation_boundary": "Source-current repository intelligence is revalidated before any adoption report write.",
                },
            )
    else:
        repository_intelligence_consumption = {
            "status": "not_applicable",
            "consumed": False,
            "candidate_only": True,
            "source_artifacts_remain_authoritative": True,
        }
    naos_root = getattr(args, "naos_root", None) or default_naos_root(policy)
    adoption_path = report_path(root, naos_root, policy, "adopt", getattr(args, "output", None))
    adoption_session_path = None
    session_id = latest_session_id(root, naos_root, policy)
    if session_id:
        adoption_session_path = session_report_default_path(
            root,
            naos_root,
            policy,
            session_id,
            REPORT_SPECS["adopt"]["report_key"],
        )
    sink_bindings = [
        binding
        for key, _, latest_path, session_path in evaluated_reports
        for binding in ((f"{key}.latest", latest_path), (f"{key}.session", session_path))
    ] + [
        ("adopt.latest", adoption_path),
        ("adopt.session", adoption_session_path),
    ]
    validate_unique_report_sinks(sink_bindings)
    if not no_write_preview:
        for _, sink in sink_bindings:
            validate_report_write_path(sink)
        sink_preexisting = {
            label: bool(sink is not None and sink.exists())
            for label, sink in sink_bindings
        }
        completed_bindings: list[tuple[str, Path]] = []
        for key, report, path, session_path in evaluated_reports:
            if key == "install_decision_record":
                completed_outputs = [
                    {
                        "path": str(sink),
                        "source": label.rsplit(".", 1)[0],
                        "write_context": f"orchestrated_adopt_{label.rsplit('.', 1)[1]}_report",
                        "state_at_record_persistence": "completed",
                    }
                    for label, sink in completed_bindings
                ]
                report["files_created"] = [
                    item
                    for (label, _), item in zip(completed_bindings, completed_outputs)
                    if not sink_preexisting[label]
                ]
                report["files_refreshed"] = [
                    item
                    for (label, _), item in zip(completed_bindings, completed_outputs)
                    if sink_preexisting[label]
                ]
                pending_bindings = [
                    (label, sink)
                    for label, sink in sink_bindings
                    if sink is not None
                    and (
                        label.startswith("install_decision_record.")
                        or label.startswith("adopt.")
                    )
                ]
                report["files_planned"] = [
                    {
                        "path": str(sink),
                        "source": label.rsplit(".", 1)[0],
                        "write_context": f"orchestrated_adopt_{label.rsplit('.', 1)[1]}_report",
                        "planned_action": (
                            "refresh" if sink_preexisting[label] else "create"
                        ),
                        "state_at_record_persistence": "pending",
                    }
                    for label, sink in pending_bindings
                ]
                report["file_write_inventory_scope"] = (
                    "files_created and files_refreshed contain only prior phase sinks whose writes completed before this decision record was persisted; "
                    "the decision-record and adoption-summary sinks remain files_planned because their later write success is not yet known."
                )
            write_report_with_session(
                path,
                session_path,
                report,
                strict_parent_topology=True,
            )
            for label, sink in (
                (f"{key}.latest", path),
                (f"{key}.session", session_path),
            ):
                if sink is not None:
                    completed_bindings.append((label, sink))
    else:
        decision_report = current_reports.get("install_decision_record")
        if isinstance(decision_report, dict):
            decision_report["files_created"] = []
            decision_report["files_refreshed"] = []
            decision_report["files_planned"] = []
            existing_skips = {
                (str(item.get("path")), str(item.get("reason")))
                for item in decision_report.get("files_skipped", [])
                if isinstance(item, dict)
            }
            for _, sink in sink_bindings:
                if sink is None:
                    continue
                item = {"path": str(sink), "reason": "no-write preview"}
                identity = (item["path"], item["reason"])
                if identity not in existing_skips:
                    decision_report.setdefault("files_skipped", []).append(item)
                    existing_skips.add(identity)
            decision_report["file_write_inventory_scope"] = (
                "No report sinks were written because --no-write-preview was selected."
            )
    phase_report_write_available = any(
        latest_path is not None or session_path is not None
        for _, _, latest_path, session_path in evaluated_reports
    )
    report_writes_performed = bool(
        not no_write_preview
        and (
            phase_report_write_available
            or adoption_path is not None
            or adoption_session_path is not None
        )
    )
    generated_reports = [
            {
                "report_id": key,
                "path": str(path) if path is not None and not no_write_preview else None,
                "session_path": str(session_path) if session_path is not None and not no_write_preview else None,
                "status": report.get("status"),
                "write_status": (
                    "not_written_preview"
                    if no_write_preview
                    else (
                        "written"
                        if path is not None or session_path is not None
                        else "not_written_no_output_path"
                    )
                ),
                "report_content_sha256": report_content_sha256(report),
            }
            for key, report, path, session_path in evaluated_reports
        ]
    findings = [
        finding("adopt.human_activation_required", severity_for_profile(profile, policy, advisory=profile in {"quickstart", "lite"}), "review_required", "Professional adoption generated review evidence; human activation and durable decisions remain required.")
    ]
    if repository_intelligence_prestart.get("engine_execution") == "refused" or repository_intelligence_prestart.get("plan_status") == "blocked_prerequisite":
        findings.append(
            finding(
                "adopt.repository_intelligence_blocked",
                severity_for_profile(
                    profile,
                    policy,
                    advisory=profile in {"quickstart", "lite"},
                ),
                "blocked",
                (
                    "Repository-intelligence pre-start inspection could not establish an activation-ready plan: "
                    f"{repository_intelligence_prestart.get('error') or 'resolve the recorded blocking findings.'}"
                ),
            )
        )
    elif repository_intelligence_prestart.get("applicable"):
        validated_current = (
            repository_intelligence_prestart.get("lifecycle_status")
            == "validated_current"
        )
        findings.append(
            finding(
                "adopt.repository_intelligence_prestart",
                severity_for_profile(
                    profile,
                    policy,
                    advisory=profile in {"quickstart", "lite"},
                ),
                "review_required",
                (
                    "Adoption consumed one validated, source-current repository-intelligence "
                    "generation as candidate-only navigation evidence."
                    if validated_current
                    else (
                        "Executed source-bound inspection found a multi-surface brownfield "
                        "repository. Review the SQLite/FTS baseline and any evidence-eligible "
                        "NetworkX/GraphML option before activation."
                    )
                ),
            )
        )
    elif repository_intelligence_prestart.get("engine_execution") == "completed" and mode in {"brownfield", "repair", "evaluation"}:
        findings.append(
            finding(
                "adopt.repository_intelligence_not_applicable",
                "advisory",
                "not_applicable",
                "Executed inspection found no multi-surface repository-intelligence activation need for this project.",
            )
        )
    if dry_run:
        findings.append(
            finding(
                "adopt.dry_run_preview",
                "advisory",
                "advisory",
                (
                    "Dry-run preview completed without activation; eligible NAOS report artifacts were written."
                    if report_writes_performed
                    else "Dry-run preview completed without activation; no NAOS report artifacts were written."
                ),
                preview_only=True,
            )
        )
    reports_root = default_report_path(root, naos_root, "preflight", policy).parent
    if no_write_preview:
        report_preview = "Would not write report artifacts (--no-write-preview)."
    elif phase_report_write_available:
        report_preview = f"Would write or refresh deterministic NAOS report artifacts under {reports_root}."
    elif adoption_path is not None:
        report_preview = (
            f"Would write the adoption summary to {adoption_path}; no child phase report output path is available."
        )
    else:
        report_preview = "Would not write report artifacts because no adopter NAOS report output path is available."
    return base_report(
        "adopt",
        args,
        root,
        profile,
        policy,
        findings,
        {
            "mode": mode,
            "dry_run": dry_run,
            "preview_only": dry_run,
            "no_write_preview": no_write_preview,
            "persistence_allowed": True,
            "continuation_allowed": True,
            "report_writes_performed": report_writes_performed,
            "activation_planned": False,
            "protected_file_changes": [],
            "repository_intelligence_prestart": repository_intelligence_prestart,
            "repository_intelligence_consumption": repository_intelligence_consumption,
            "phases": [item[0] for item in phases],
            "reports_generated": generated_reports,
            "dry_run_preview": [
                f"Would run adoption phases for mode {mode}: {', '.join(item[0] for item in phases)}.",
                report_preview,
                "Would not activate hooks, CI, providers, memory write-back, MCP runtime, or external connectors.",
                "Would not overwrite protected project files; durable activation remains a human-reviewed separate decision.",
            ]
            if dry_run
            else [],
            "activation_boundary": "naos adopt does not silently overwrite project files, enable hooks/CI, call providers, write memory, or approve work.",
        },
    )


BUILDERS = {
    "adopt": build_adopt,
    "preflight": build_preflight,
    "intake": build_intake,
    "install_plan": build_install_plan,
    "existing_resource_inventory": build_existing_resource_inventory,
    "ai_artifact_inventory": build_ai_artifact_inventory,
    "ai_artifact_reconcile": build_ai_artifact_reconcile,
    "memory_resource_inventory": build_memory_resource_inventory,
    "memory_resource_reconcile": build_memory_resource_reconcile,
    "mcp_resource_inventory": build_mcp_resource_inventory,
    "brownfield_baseline": build_brownfield_baseline,
    "requirements_reconstruct": build_requirements_reconstruct,
    "traceability_gap_register": build_traceability_gap_register,
    "install_decision_record": build_install_decision_record,
    "context_challenge": lambda args, root, profile, policy: build_challenge("context_challenge", args, root, profile, policy),
    "repo_context_challenge": lambda args, root, profile, policy: build_challenge("repo_context_challenge", args, root, profile, policy),
    "plan_challenge": lambda args, root, profile, policy: build_challenge("plan_challenge", args, root, profile, policy),
    "decision_probe": lambda args, root, profile, policy: build_challenge("decision_probe", args, root, profile, policy),
    "planning_gate_review": lambda args, root, profile, policy: build_challenge("planning_gate_review", args, root, profile, policy),
}


DIRECT_REPOSITORY_INTELLIGENCE_CONSUMERS = {
    "requirements_reconstruct",
    "traceability_gap_register",
    "brownfield_baseline",
}


def _attach_direct_repository_intelligence(
    spec_key: str,
    args: argparse.Namespace,
    root: Path,
    profile: str,
    policy: dict[str, Any],
) -> str | None:
    """Attach a current source-bound snapshot to advertised brownfield phases."""

    mode = normalize_answer(getattr(args, "mode", None), "greenfield")
    if (
        spec_key not in DIRECT_REPOSITORY_INTELLIGENCE_CONSUMERS
        or mode not in {"brownfield", "repair", "evaluation"}
        or build_repository_intelligence_guidance is None
    ):
        return None
    naos_root = getattr(args, "naos_root", None) or default_naos_root(policy)
    guidance = build_repository_intelligence_guidance(
        root,
        naos_root,
        profile,
        required_usage_scopes=ADOPTION_REPOSITORY_INTELLIGENCE_SCOPES,
    )
    if guidance.get("lifecycle_status") != "validated_current":
        state_root = root / ".naos/upgrade-v1/state/repository-intelligence"
        if state_root.exists():
            return str(
                guidance.get("error")
                or (guidance.get("installation") or {}).get("next_action")
                or "Repository intelligence is present but is not validated-current."
            )
        return None
    if read_active_repository_intelligence_snapshot is None:
        return "The repository-intelligence consumer runtime is unavailable."
    try:
        snapshot = read_active_repository_intelligence_snapshot(
            root,
            naos_root=naos_root,
            required_usage_scopes=ADOPTION_REPOSITORY_INTELLIGENCE_SCOPES,
            retrieval_queries=_adoption_retrieval_queries(args),
            limit=500,
        )
    except (RepositoryIntelligenceError, OSError, RuntimeError, ValueError) as exc:
        return str(exc)
    setattr(args, _ADOPTION_REPOSITORY_INTELLIGENCE_ATTR, snapshot)
    return None


def _revalidate_direct_repository_intelligence(
    args: argparse.Namespace,
    root: Path,
    policy: dict[str, Any],
) -> str | None:
    snapshot = _adoption_repository_intelligence(args)
    if snapshot is None:
        return None
    if (
        validate_active_generation is None
        or repository_intelligence_binding is None
        or assert_repository_intelligence_binding_unchanged is None
    ):
        return "The repository-intelligence closing-validation runtime is unavailable."
    try:
        naos_root = getattr(args, "naos_root", None) or default_naos_root(policy)
        closing = validate_active_generation(
            root,
            naos_root=naos_root,
            require_current_source=True,
        )
        assert_repository_intelligence_binding_unchanged(
            snapshot.get("opening_generation") or {},
            repository_intelligence_binding(closing),
        )
    except (RepositoryIntelligenceError, OSError, RuntimeError, ValueError) as exc:
        return str(exc)
    return None


def build_parser(spec_key: str) -> argparse.ArgumentParser:
    spec = REPORT_SPECS[spec_key]
    parser = argparse.ArgumentParser(
        prog=f"naos {spec['command']}",
        description=f"{spec['title']} - deterministic, file-first, human-reviewed adoption evidence.",
    )
    parser.add_argument("project_path", nargs="?", default=".", help="Project root to inspect (default: current directory).")
    parser.add_argument("--profile", default=None, help="NAOS profile: quickstart, lite, standard, or assured.")
    parser.add_argument("--naos-root", default=None, help="NAOS root directory (default from policy or naos).")
    parser.add_argument("--policy", help="Optional policy file.")
    default_mode = (
        "brownfield"
        if spec_key in DIRECT_REPOSITORY_INTELLIGENCE_CONSUMERS
        else "greenfield"
    )
    parser.add_argument(
        "--mode",
        choices=MODES,
        default=default_mode,
        help=f"Adoption mode (default: {default_mode}).",
    )
    parser.add_argument("--challenge-mode", choices=CHALLENGE_MODES, default=None, help="Challenge-specific mode.")
    parser.add_argument("--answers", help="YAML or JSON answer file for non-interactive intake/challenge/adoption.")
    parser.add_argument("--interactive", action="store_true", help="Prompt for missing answers or review decisions where supported.")
    parser.add_argument("--no-prompt", action="store_true", help="Never prompt; preserve missing information as review-required output.")
    if spec_key == "adopt":
        preview_mode = parser.add_mutually_exclusive_group()
        preview_mode.add_argument(
            "--dry-run",
            action="store_true",
            help="Run report-writing preview: writes declared NAOS reports but performs no activation or protected-file changes.",
        )
        preview_mode.add_argument(
            "--no-write-preview",
            action="store_true",
            help="Evaluate the adoption preview without writing reports, activation files, or protected-file changes.",
        )
    parser.add_argument("--decision", help="Default reconciliation decision where supported.")
    parser.add_argument("--write", action="store_true", help="Allow supported explicit writes. Most adoption commands remain report-only.")
    parser.add_argument("--output", help="Explicit report output path.")
    parser.add_argument("--json", action="store_true", help="Print full JSON report to stdout.")
    parser.add_argument("--strict", action="store_true", help="Use strict profile exit-code behavior.")
    return parser


def main_for(spec_key: str, argv: list[str] | None = None) -> int:
    parser = build_parser(spec_key)
    args = parser.parse_args(argv)
    if spec_key == "adopt" and (getattr(args, "dry_run", False) or getattr(args, "no_write_preview", False)):
        args.no_prompt = True
        args.write = False
    root = project_root(args)
    policy = load_policy(args.policy, args.naos_root, root)
    profile = normalize_profile(args.profile, policy)
    repository_error = _attach_direct_repository_intelligence(
        spec_key, args, root, profile, policy
    )
    if repository_error is not None:
        parser.error(f"repository-intelligence precondition failed: {repository_error}")
    report = BUILDERS[spec_key](args, root, profile, policy)
    repository_error = _revalidate_direct_repository_intelligence(args, root, policy)
    if repository_error is not None:
        parser.error(f"repository-intelligence changed during evaluation: {repository_error}")
    action_required = bool(
        spec_key == "adopt" and not report.get("continuation_allowed", True)
    )
    if action_required or not report.get("persistence_allowed", True):
        args.no_write_preview = True
    result = emit_report(spec_key, report, args, root, policy)
    return max(result, 2) if action_required else result
