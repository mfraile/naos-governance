#!/usr/bin/env python3
"""Generate and project five independent secure-coding governance dimensions."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    dashboard_output_path,
    default_naos_root,
    evidence_pack_output_path,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    kit_root,
    load_policy,
    normalize_profile,
    report_default_path,
    severity_for_profile,
    status_from_counts,
    write_report,
)
from secure_coding_reporting.model import (  # noqa: E402
    DIMENSION_KEYS,
    LIMITATIONS,
    NOT_CLAIMED,
    SCHEMA_ID,
    build_report,
    empty_standards_snapshot,
    finding,
    schema_errors,
    timestamp,
)
from secure_coding_reporting.projection import project  # noqa: E402
from secure_coding_reporting.sources import refresh  # noqa: E402


def within(path: Path, parent: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except ValueError:
        return False


def bounded(
    value: str | Path | None,
    *,
    root: Path,
    default: Path,
    label: str,
) -> Path:
    candidate = (
        default
        if value is None
        else Path(value).expanduser().resolve(strict=False)
    )
    if not (within(candidate, root) or within(candidate, kit_root())):
        raise ValueError(
            f"{label} must remain within the project or installed kit: {candidate}"
        )
    return candidate


def refresh_summary(report: dict) -> None:
    counts = finding_counts(report.get("findings", []))
    report.setdefault("summary", {}).update(counts)
    report["status"] = status_from_counts(counts)


def error_dimensions(message: str) -> dict:
    return {
        "register_validity": {
            "state": "invalid",
            "source": "P3 exception fallback",
            "details": {"error": message},
        },
        "reference_integrity": {
            "state": "invalid",
            "source": "P3 exception fallback",
            "details": {"error": message},
        },
        "detector_evidence": {
            "state": "invalid",
            "source": "P3 exception fallback",
            "details": {"error": message},
        },
        "mapping_verification": {
            "state": "review_required",
            "source": "P3 exception fallback",
            "details": {"error": message},
        },
        "human_review": {
            "state": "required",
            "source": "P3 exception fallback",
            "details": {"error": message},
        },
    }


def build_error_report(
    *,
    root: Path,
    naos_root: str,
    profile: str,
    check_mode: bool,
    generated_at: str | None,
    item: dict,
) -> dict:
    counts = finding_counts([item])
    return {
        "schema": SCHEMA_ID,
        "generated_at": timestamp(generated_at),
        "profile": profile,
        "status": status_from_counts(counts),
        "project_root": str(root),
        "naos_root": naos_root,
        "deterministic": True,
        "check_mode": check_mode,
        "sources": {},
        "standards_snapshot": empty_standards_snapshot("unavailable"),
        "summary": {
            **counts,
            "dimensions": 5,
            "dimension_keys": list(DIMENSION_KEYS),
            "human_review_required": True,
        },
        "dimensions": error_dimensions(str(item.get("message") or "unknown error")),
        "projection": {},
        "findings": [item],
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--naos-root")
    parser.add_argument("--profile")
    parser.add_argument("--policy")
    parser.add_argument("--reference-report")
    parser.add_argument("--controls-report")
    parser.add_argument("--schema")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--refresh-sources", action="store_true")
    parser.add_argument("--project", action="store_true")
    parser.add_argument("--dashboard-summary")
    parser.add_argument("--dashboard-markdown")
    parser.add_argument("--evidence-pack")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--generated-at")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    defaults = {
        "reference": report_default_path(
            root,
            naos_root,
            policy,
            "secure_coding_reference_integrity_report",
        ),
        "controls": report_default_path(
            root,
            naos_root,
            policy,
            "secure_coding_controls_report",
        ),
        "schema": root / "schemas/naos/secure_coding_reporting.schema.json",
        "output": report_default_path(
            root,
            naos_root,
            policy,
            "secure_coding_reporting_report",
        ),
        "dashboard_summary": report_default_path(
            root,
            naos_root,
            policy,
            "dashboard_summary_report",
        ),
        "dashboard_markdown": dashboard_output_path(root, naos_root, policy)
        or root / naos_root / "DASHBOARD.md",
        "evidence_pack": evidence_pack_output_path(root, naos_root, policy)
        or root / naos_root / "evidence" / "evidence_pack.json",
    }
    if not defaults["schema"].is_file():
        defaults["schema"] = (
            kit_root() / "schemas/naos/secure_coding_reporting.schema.json"
        )

    output: Path | None = None
    try:
        if args.output is not None or not args.check:
            output = bounded(
                args.output,
                root=root,
                default=defaults["output"],
                label="P3 report output",
            )
        reference_path = bounded(
            args.reference_report,
            root=root,
            default=defaults["reference"],
            label="reference report",
        )
        controls_path = bounded(
            args.controls_report,
            root=root,
            default=defaults["controls"],
            label="controls report",
        )
        schema_path = bounded(
            args.schema,
            root=root,
            default=defaults["schema"],
            label="report schema",
        )
        if args.refresh_sources:
            refresh(
                root=root,
                naos_root=naos_root,
                profile=profile,
                policy=policy,
                reference_path=reference_path,
                controls_path=controls_path,
                check_mode=args.check,
                generated_at=args.generated_at,
            )
        report = build_report(
            root=root,
            naos_root=naos_root,
            profile=profile,
            policy=policy,
            reference_path=reference_path,
            controls_path=controls_path,
            check_mode=args.check,
            generated_at=args.generated_at,
        )
        errors = schema_errors(report, schema_path)
        if errors:
            severity = (
                "advisory"
                if is_kit_repository(root, naos_root)
                else severity_for_profile(profile, policy)
            )
            for index, item in enumerate(errors, 1):
                report["findings"].append(
                    finding(
                        f"report-schema:{index}",
                        severity,
                        "schema_error",
                        item["message"],
                        item["path"],
                    )
                )
            refresh_summary(report)
        if args.project and not errors:
            projection = project(
                report=report,
                dashboard_summary=bounded(
                    args.dashboard_summary,
                    root=root,
                    default=defaults["dashboard_summary"],
                    label="dashboard summary",
                ),
                dashboard_markdown=bounded(
                    args.dashboard_markdown,
                    root=root,
                    default=defaults["dashboard_markdown"],
                    label="dashboard markdown",
                ),
                evidence_pack=bounded(
                    args.evidence_pack,
                    root=root,
                    default=defaults["evidence_pack"],
                    label="evidence pack",
                ),
            )
            report["projection"] = projection
            severity = (
                "advisory"
                if is_kit_repository(root, naos_root)
                else severity_for_profile(profile, policy)
            )
            for name, result in projection.items():
                if result.get("state") == "projected":
                    continue
                report["findings"].append(
                    finding(
                        f"projection:{name}",
                        severity,
                        "projection_not_completed",
                        str(
                            result.get("message")
                            or f"Projection state is {result.get('state')!r}."
                        ),
                        str(result.get("path") or name),
                    )
                )
            refresh_summary(report)
    except Exception as exc:
        severity = (
            "advisory"
            if is_kit_repository(root, naos_root)
            else severity_for_profile(profile, policy)
        )
        item = finding(
            "secure-coding-reporting:load",
            severity,
            "load_error",
            str(exc),
        )
        report = build_error_report(
            root=root,
            naos_root=naos_root,
            profile=profile,
            check_mode=args.check,
            generated_at=args.generated_at,
            item=item,
        )

    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            f"NAOS secure-coding multidimensional reporting: {report['status']} "
            f"({report.get('summary', {}).get('total_findings', 0)} finding(s); "
            f"{report.get('summary', {}).get('dimensions', 0)} independent dimensions)"
        )
        for finding_item in report.get("findings", []):
            print(
                f"- {finding_item.get('severity')}: "
                f"{finding_item.get('status')}: {finding_item.get('message')}"
            )
    return exit_code_for_summary(
        profile,
        report.get("summary", {}),
        policy,
        args.strict,
    )


if __name__ == "__main__":
    raise SystemExit(main())
