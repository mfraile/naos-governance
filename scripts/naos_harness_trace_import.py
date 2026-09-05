#!/usr/bin/env python3
"""Import local harness JSONL/NDJSON records as declared NAOS trace events."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_agent_trace_validate import (  # noqa: E402
    ACTION_TYPES,
    AUTHORITY_LAYERS,
    LIFECYCLE_PHASES,
    REVIEW_STATUS_VALUES,
    TRACE_ORIGINS,
    TRACE_STATUS_VALUES,
    trace_default_path,
    validate_event,
)
from naos_policy import (  # noqa: E402
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    load_policy,
    normalize_profile,
    report_default_path,
    severity_for_profile,
    write_report,
)


REPORT_SCHEMA = "naos.harness_trace_import.v1"
SUPPORTED_FORMATS = {"jsonl", "ndjson"}
DEFAULT_LIMITATIONS = [
    "Harness trace import reads explicit local JSONL/NDJSON files only.",
    "Imported events are declared records for review; they are not runtime capture.",
    "The importer does not execute commands, activate hooks, call providers, access the network, read memory payloads, or write memory.",
]
DEFAULT_NOT_CLAIMED = [
    "runtime trace capture",
    "harness execution",
    "command execution",
    "Claude hook activation",
    "provider/API call",
    "network access",
    "memory write-back",
    "memory payload access",
    "behavioral correctness proof",
    "approval",
    "certification",
    "compliance proof",
    "hallucination prevention",
]


def utc_now() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def repo_relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def resolve_repo_path(root: Path, value: str | None) -> Path | None:
    if not value:
        return None
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    return path


def short_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")
    return slug[:64] or "trace"


def as_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None and str(item) != ""]
    if isinstance(value, str) and value:
        return [value]
    return []


def first_string(record: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = record.get(key)
        if value is not None and str(value) != "":
            return str(value)
    return None


def normalize_enum(value: str | None, allowed: set[str], default: str) -> str:
    if value and value in allowed:
        return value
    return default


def normalize_timestamp(value: str | None, imported_at: str) -> str:
    if not value:
        return imported_at
    raw = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return imported_at
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def record_source_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def finding(item_id: str, severity: str, status: str, message: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": item_id,
        "severity": severity,
        "status": status,
        "message": message,
        "human_review_required": True,
        **extra,
    }


def load_jsonl(source: Path, severity: str) -> tuple[list[tuple[int, dict[str, Any]]], list[dict[str, Any]]]:
    records: list[tuple[int, dict[str, Any]]] = []
    findings: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
        text = raw_line.strip()
        if not text:
            continue
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            findings.append(
                finding(
                    f"harness_trace_import.line_{line_number}",
                    severity,
                    "invalid_jsonl_record",
                    f"Line {line_number} is not valid JSON: {exc.msg}",
                    line_number=line_number,
                )
            )
            continue
        if not isinstance(parsed, dict):
            findings.append(
                finding(
                    f"harness_trace_import.line_{line_number}",
                    severity,
                    "non_object_record",
                    f"Line {line_number} must be a JSON object.",
                    line_number=line_number,
                )
            )
            continue
        records.append((line_number, parsed))
    return records, findings


def normalize_record(record: dict[str, Any], *, line_number: int, source_rel: str, source_hash: str, imported_at: str) -> dict[str, Any]:
    event_id = first_string(record, "event_id", "id", "trace_id")
    if not event_id:
        event_id = f"harness-{short_slug(Path(source_rel).stem)}-{line_number}"
    task_id = first_string(record, "task_id", "task", "task_ref")
    referenced_tasks = as_string_list(record.get("referenced_tasks"))
    if task_id and task_id not in referenced_tasks:
        referenced_tasks.append(task_id)
    source_refs = as_string_list(record.get("source_references"))
    if source_rel not in source_refs:
        source_refs.append(source_rel)
    limitations = as_string_list(record.get("limitations")) + DEFAULT_LIMITATIONS
    not_claimed = as_string_list(record.get("not_claimed")) + DEFAULT_NOT_CLAIMED
    event = {
        "event_id": event_id,
        "generated_at": normalize_timestamp(first_string(record, "generated_at", "timestamp", "time", "created_at"), imported_at),
        "session_id": first_string(record, "session_id", "session", "run_id") or "unknown-session",
        "task_id": task_id,
        "agent_or_surface": first_string(record, "agent_or_surface", "agent", "surface", "tool", "harness_name") or "harness_trace_import",
        "lifecycle_phase": normalize_enum(first_string(record, "lifecycle_phase", "phase"), LIFECYCLE_PHASES, "unknown"),
        "action_type": normalize_enum(first_string(record, "action_type", "action", "type"), ACTION_TYPES, "unknown"),
        "input_artifacts": as_string_list(record.get("input_artifacts")),
        "output_artifacts": as_string_list(record.get("output_artifacts")),
        "referenced_specs": as_string_list(record.get("referenced_specs")),
        "referenced_tasks": referenced_tasks,
        "referenced_capabilities": as_string_list(record.get("referenced_capabilities")),
        "commands_run": as_string_list(record.get("commands_run")),
        "files_read": as_string_list(record.get("files_read")),
        "files_modified": as_string_list(record.get("files_modified")),
        "reports_generated": as_string_list(record.get("reports_generated")),
        "evidence_refs": as_string_list(record.get("evidence_refs")),
        "memory_refs": as_string_list(record.get("memory_refs")),
        "advisory_controls_used": as_string_list(record.get("advisory_controls_used")),
        "deterministic_controls_used": as_string_list(record.get("deterministic_controls_used")),
        "source_references": source_refs,
        "source_hashes": {source_rel: f"sha256:{source_hash}"},
        "profile": record.get("profile") if record.get("profile") in {"quickstart", "lite", "standard", "assured"} else None,
        "authority_layer": normalize_enum(first_string(record, "authority_layer"), AUTHORITY_LAYERS, "record_only"),
        "trace_origin": normalize_enum(first_string(record, "trace_origin"), TRACE_ORIGINS, "tool_declared"),
        "trace_status": normalize_enum(first_string(record, "trace_status"), TRACE_STATUS_VALUES, "declared"),
        "confidence": record.get("confidence") if isinstance(record.get("confidence"), (int, float)) else None,
        "residual_risks": as_string_list(record.get("residual_risks")),
        "forbidden_payload_check": {"performed": False, "status": "not_performed_by_importer", "notes": ["Run naos agent-traces after import for payload review."]},
        "review_status": normalize_enum(first_string(record, "review_status"), REVIEW_STATUS_VALUES, "review_pending"),
        "reviewer": first_string(record, "reviewer"),
        "reviewed_at": first_string(record, "reviewed_at"),
        "human_review_required": True,
        "limitations": sorted(dict.fromkeys(limitations)),
        "not_claimed": sorted(dict.fromkeys(not_claimed)),
    }
    return {key: value for key, value in event.items() if value not in (None, [], {})}


def load_existing_trace_file(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]], str | None]:
    if not path.exists():
        return {"version": 1, "events": []}, [], None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return {"version": 1, "events": []}, [], str(exc)
    if isinstance(data, list):
        events = [item for item in data if isinstance(item, dict)]
        return {"version": 1, "events": events}, events, None
    if isinstance(data, dict):
        raw_events = data.get("events") or []
        events = [item for item in raw_events if isinstance(item, dict)]
        data["events"] = events
        return data, events, None
    return {"version": 1, "events": []}, [], "trace file must be a mapping with events or a list of events"


def write_trace_file(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.is_symlink():
        raise ValueError(f"Refusing to write trace events through symlink: {path}")
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def build_report(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    severity = severity_for_profile(profile, policy)
    imported_at = utc_now()
    findings: list[dict[str, Any]] = []

    source = resolve_repo_path(root, args.source)
    target_trace_file = resolve_repo_path(root, args.trace_file) if args.trace_file else trace_default_path(root, naos_root, policy)
    output = Path(args.output) if args.output else report_default_path(root, naos_root, policy, "harness_trace_import_report")

    if source is None:
        findings.append(finding("harness_trace_import.source", severity, "missing_source", "--source is required."))
    elif not is_within(source, root):
        findings.append(
            finding(
                "harness_trace_import.source_scope",
                severity,
                "source_outside_project",
                f"Harness trace source must be inside the project: {source}",
                source_path=str(source),
            )
        )
    elif not source.exists():
        findings.append(
            finding(
                "harness_trace_import.source_missing",
                severity,
                "source_missing",
                f"Harness trace source file does not exist: {source}",
                source_path=repo_relative(root, source),
            )
        )
    elif not source.is_file():
        findings.append(
            finding(
                "harness_trace_import.source_not_file",
                severity,
                "source_not_file",
                f"Harness trace source must be a file: {source}",
                source_path=repo_relative(root, source),
            )
        )

    if target_trace_file is not None and not is_within(target_trace_file, root):
        findings.append(
            finding(
                "harness_trace_import.target_scope",
                severity,
                "target_outside_project",
                f"Target trace file must be inside the project: {target_trace_file}",
                target_trace_file=str(target_trace_file),
            )
        )
    if args.source_format not in SUPPORTED_FORMATS:
        findings.append(
            finding(
                "harness_trace_import.source_format",
                severity,
                "unsupported_source_format",
                f"Unsupported source format: {args.source_format}",
                supported_formats=sorted(SUPPORTED_FORMATS),
            )
        )

    source_hash: str | None = None
    source_rel = repo_relative(root, source) if source else None
    raw_record_count = 0
    normalized_events: list[dict[str, Any]] = []
    if not findings and source is not None:
        source_hash = record_source_hash(source)
        records, parse_findings = load_jsonl(source, severity)
        findings.extend(parse_findings)
        raw_record_count = len(records) + len(parse_findings)
        for line_number, record in records:
            event = normalize_record(
                record,
                line_number=line_number,
                source_rel=source_rel or str(source),
                source_hash=source_hash,
                imported_at=imported_at,
            )
            _, event_findings = validate_event(event, profile, policy)
            if event_findings:
                findings.append(
                    finding(
                        f"harness_trace_import.line_{line_number}.normalized_event",
                        severity,
                        "normalized_event_invalid",
                        f"Normalized event from line {line_number} did not pass NAOS trace validation.",
                        line_number=line_number,
                        event_id=event.get("event_id"),
                        event_findings=event_findings,
                    )
                )
            else:
                normalized_events.append(event)

    trace_data: dict[str, Any] = {"version": 1, "events": []}
    existing_events: list[dict[str, Any]] = []
    written = False
    if args.write_events and target_trace_file is not None and not any(item.get("status") in {"source_outside_project", "target_outside_project", "source_missing", "source_not_file", "unsupported_source_format", "invalid_jsonl_record", "normalized_event_invalid"} for item in findings):
        trace_data, existing_events, load_error = load_existing_trace_file(target_trace_file)
        if load_error:
            findings.append(
                finding(
                    "harness_trace_import.target_invalid",
                    severity,
                    "invalid_target_trace_file",
                    f"Target trace file could not be parsed: {load_error}",
                    target_trace_file=repo_relative(root, target_trace_file),
                )
            )
        existing_ids = {str(event.get("event_id")) for event in existing_events if event.get("event_id")}
        duplicate_ids = sorted(str(event.get("event_id")) for event in normalized_events if str(event.get("event_id")) in existing_ids)
        if duplicate_ids:
            findings.append(
                finding(
                    "harness_trace_import.duplicate_event_ids",
                    severity,
                    "duplicate_event_ids",
                    "Imported events would duplicate existing trace event ids.",
                    duplicate_event_ids=duplicate_ids,
                )
            )
        if not any(item.get("status") in {"invalid_target_trace_file", "duplicate_event_ids"} for item in findings):
            trace_data.setdefault("version", 1)
            trace_data["events"] = existing_events + normalized_events
            write_trace_file(target_trace_file, trace_data)
            written = True

    summary = finding_counts(findings)
    summary.update(
        {
            "raw_records": raw_record_count,
            "imported_events": len(normalized_events),
            "rejected_records": max(raw_record_count - len(normalized_events), 0),
            "written_events": len(normalized_events) if written else 0,
        }
    )
    if not args.source:
        status = "not_configured"
    elif any(item.get("severity") == "blocking" for item in findings):
        status = "blocked"
    elif findings:
        status = "review_required"
    elif written:
        status = "written"
    elif normalized_events:
        status = "ready"
    else:
        status = "no_events"
    report = {
        "schema": REPORT_SCHEMA,
        "generated_at": imported_at,
        "profile": profile,
        "status": status,
        "mode": "write_events" if args.write_events else "report_only",
        "naos_root": naos_root,
        "project_root": str(root),
        "source_path": repo_relative(root, source) if source else None,
        "source_format": args.source_format,
        "source_present": bool(source and source.exists()),
        "source_sha256": f"sha256:{source_hash}" if source_hash else None,
        "target_trace_file": repo_relative(root, target_trace_file) if target_trace_file else None,
        "write_events": bool(args.write_events),
        "events_written": written,
        "raw_record_count": raw_record_count,
        "imported_event_count": len(normalized_events),
        "rejected_record_count": max(raw_record_count - len(normalized_events), 0),
        "normalized_events": normalized_events,
        "findings": findings,
        "known_gaps": [
            "The importer only supports local JSONL/NDJSON records.",
            "Imported records can be incomplete, stale, or inaccurate.",
            "Run naos agent-traces after write mode to validate the combined trace file.",
        ],
        "limitations": DEFAULT_LIMITATIONS,
        "not_claimed": DEFAULT_NOT_CLAIMED,
        "human_review_required": bool(findings or normalized_events),
        "summary": summary,
    }
    return report, {"root": root, "profile": profile, "policy": policy, "output": output}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Import local harness JSONL/NDJSON records as declared NAOS trace events.")
    parser.add_argument("--source", help="Repo-local JSONL/NDJSON harness trace file to import.")
    parser.add_argument("--source-format", default="jsonl", choices=sorted(SUPPORTED_FORMATS))
    parser.add_argument("--trace-file", help="Target NAOS trace YAML. Defaults to NAOS_ROOT/agent_trace_events.yaml.")
    parser.add_argument("--write-events", action="store_true", help="Append normalized events to the target trace file. Default is report-only.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report, context = build_report(args)
    write_report(context["output"], report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            "NAOS harness trace import: "
            f"{report['status']} "
            f"({report['imported_event_count']} imported, {report['rejected_record_count']} rejected) -> {context['output']}"
        )
    return exit_code_for_summary(context["profile"], report["summary"], context["policy"], args.strict)


if __name__ == "__main__":
    sys.exit(main())
