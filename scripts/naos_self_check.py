#!/usr/bin/env python3
"""Aggregate NAOS self-conformance checks into one summary JSON."""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    controlled_utc_now_text,
    exit_code_for_summary,
    finding_counts,
    kit_root,
    load_policy,
    normalize_profile,
    report_output_path,
    severity_for_profile,
    status_from_counts,
    supported_profiles,
    write_report,
)
from naos_systemic_impact import (  # noqa: E402
    build_actionable_presentation,
    finding_occurrence,
    presentation_lines,
)

CAPABILITY_REQUIRED_FIELDS = {
    "id",
    "name",
    "description",
    "status",
    "default_maturity",
    "minimum_profile",
    "profiles",
    "authority",
    "allowed_resources",
    "prohibited_resources",
    "constraints",
    "required_evidence",
    "validators",
    "gatekeepers",
    "dashboard_signals",
    "maturity_path",
    "known_limitations",
    "not_claimed",
    "related_docs",
    "related_scripts",
}
CAPABILITY_ID_RE = re.compile(r"^CAP-[A-Z0-9-]+$")
GATE_ID_RE = re.compile(r"^G[0-9]+$")
MATURITY_LEVELS = {"L0", "L1", "L2", "L3", "L4", "L5"}
PROFILE_IDS = {"quickstart", "lite", "standard", "assured"}
CAPABILITY_STATUS_VALUES = {"active", "scaffolded", "experimental", "planned", "deprecated"}
ENFORCEMENT_VALUES = {"none", "advisory", "warning", "required", "blocking", "not_applicable"}
VALIDATOR_STATUS_VALUES = {"available", "planned", "external", "manual"}
PROFILE_BEHAVIOR_REQUIRED_FIELDS = {"target_maturity", "enforcement", "notes"}
GATE_REQUIRED_FIELDS = {
    "id",
    "name",
    "purpose",
    "profile_behavior",
    "required_inputs",
    "required_evidence",
    "validators",
    "outputs",
    "severity_by_profile",
    "maturity_dependency",
    "known_limitations",
}


def check_status(findings: list[dict[str, Any]]) -> str:
    return status_from_counts(finding_counts(findings))



SELF_CHECK_CHILD_TIMEOUT_SECONDS = 180


def _child_platform() -> str:
    return os.name


def _run_check_child(command, *, cwd):
    """Bound the direct child and independently snapshot regular-file capture.

    No pipe EOF/reader thread is required. Independent reader handles never seek
    the inherited writers' shared offsets. Timeout captures are retained; their
    snapshots do not claim complete descendant output or whole-tree retirement.
    """
    import base64
    import hashlib
    platform_name = _child_platform()
    capture_root = Path(tempfile.mkdtemp(prefix="naos-self-check-child-"))
    paths = {name: capture_root / name for name in ("stdout", "stderr")}
    captured, snapshots = {}, {}
    evidence = None
    interrupted = None
    with os.fdopen(os.open(paths["stdout"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stdout_file, os.fdopen(os.open(paths["stderr"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stderr_file:
        process = subprocess.Popen(command, cwd=cwd, stdout=stdout_file, stderr=stderr_file,
                                   start_new_session=platform_name == "posix")
        try:
            process.wait(timeout=SELF_CHECK_CHILD_TIMEOUT_SECONDS)
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
            interrupted = error if isinstance(error, KeyboardInterrupt) else None
            evidence = {"timeout_seconds": SELF_CHECK_CHILD_TIMEOUT_SECONDS,
                        "trigger": type(error).__name__, "direct_pid": process.pid,
                        "tree_quiescence_proven": False, "cleanup_errors": [],
                        "cleanup_helper_invoked": False, "output_capture": "regular_file_bounded_snapshot"}
            if platform_name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    evidence["cleanup_attempt"] = "SIGKILL owned session process group"
                except OSError as cleanup_error:
                    evidence["cleanup_errors"].append(str(cleanup_error))
            else:
                evidence["cleanup_attempt"] = "owned direct child termination only; descendants unproven"
            if process.poll() is None:
                try:
                    process.kill()
                except OSError as cleanup_error:
                    evidence["cleanup_errors"].append(str(cleanup_error))
            try:
                process.wait(timeout=5)
                evidence["direct_child_reaped"] = True
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as reap_error:
                evidence["direct_child_reaped"] = False
                evidence["reap_error"] = type(reap_error).__name__
                if isinstance(reap_error, KeyboardInterrupt):
                    interrupted = reap_error
            evidence["direct_returncode"] = process.returncode
        for key, path in paths.items():
            with path.open("rb") as reader:
                observed_size = os.fstat(reader.fileno()).st_size
                raw = reader.read(observed_size)
            captured[key] = raw.decode("utf-8", errors="replace")
            snapshots[key] = captured[key]
            snapshots[key + "_base64"] = base64.b64encode(raw).decode("ascii")
            snapshots[key + "_sha256"] = hashlib.sha256(raw).hexdigest()
            snapshots[key + "_observed_size"] = observed_size
            snapshots[key + "_snapshot_bytes"] = len(raw)
    if evidence is None:
        try:
            for path in paths.values():
                path.unlink()
            capture_root.rmdir()
        except OSError as cleanup_error:
            evidence = {"trigger": "CaptureCleanupIncomplete", "direct_pid": process.pid,
                        "direct_returncode": process.returncode, "direct_child_reaped": True,
                        "tree_quiescence_proven": False, "cleanup_helper_invoked": False,
                        "cleanup_errors": [str(cleanup_error)]}
    if evidence is not None:
        evidence.update(snapshots)
        evidence["capture_root"] = str(capture_root)
        evidence["capture_retained"] = capture_root.exists()
        evidence["descendant_output_complete"] = False
    if interrupted is not None:
        print(json.dumps({"self_check_child_interrupted": evidence}), file=sys.stderr, flush=True)
        raise interrupted
    code = (125 if evidence.get("trigger") == "CaptureCleanupIncomplete" else 124) if evidence else process.returncode
    result = subprocess.CompletedProcess(command, code, captured["stdout"], captured["stderr"])
    result.timeout_evidence = evidence
    return result


def _child_timeout_payload(result, severity):
    evidence = getattr(result, "timeout_evidence", None)
    if evidence is None:
        return None
    timed_out = evidence.get("trigger") != "CaptureCleanupIncomplete"
    return {"status": "error", "summary": {"total_findings": 1}, "findings": [{
        "id": "SELF_CHECK_CHILD_TIMEOUT" if timed_out else "SELF_CHECK_CAPTURE_CLEANUP_INCOMPLETE", "severity": severity,
        "status": "script_timeout" if timed_out else "script_capture_cleanup_incomplete",
        "message": ("Self-check producer exceeded its child timeout; output is retained." if timed_out
                    else "Direct producer exited, but capture cleanup remained incomplete; output snapshot is retained."),
        "timeout_evidence": evidence}]}

def first_existing_dir(paths: list[Path]) -> Path:
    for path in paths:
        if path.is_dir():
            return path
    return paths[0]


def first_existing_file(paths: list[Path]) -> Path:
    for path in paths:
        if path.is_file():
            return path
    return paths[0]


def validate_capability_contracts(root: Path, profile: str, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    severity = severity_for_profile(profile, policy)
    findings: list[dict[str, Any]] = []
    capabilities_dir = first_existing_dir(
        [
            root / naos_root / "capabilities",
            kit_root() / "capabilities",
        ]
    )
    # Copied adopter helpers also call their parent the kit root. Only the
    # complete executing kit layout may supply fallback cards; this is a
    # layout distinction, not authentication of the declaration or its cards.
    executing_kit = kit_root()
    if capabilities_dir == executing_kit / "capabilities" and not (
        (executing_kit / "naos_init.py").is_file()
        and (executing_kit / "configs" / "source_modes.json").is_file()
    ):
        capabilities_dir = root / naos_root / "capabilities"
    contracts = sorted(p for p in capabilities_dir.glob("*.yaml") if not p.name.startswith("_"))
    if not contracts:
        findings.append({"id": str(capabilities_dir), "severity": severity,
                         "status": "missing_capability_contracts",
                         "message": "No NAOS capability contracts found in the selected directory."})
    ids: list[str] = []
    for path in contracts:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if data is None:
                data = {}
        except Exception as exc:
            findings.append({"id": str(path), "severity": severity, "status": "parse_error", "message": str(exc)})
            continue
        if not isinstance(data, dict):
            findings.append({"id": str(path), "severity": severity, "status": "parse_error",
                             "message": "Capability contract must be a mapping."})
            continue
        missing = sorted(CAPABILITY_REQUIRED_FIELDS - set(data))
        if missing:
            findings.append(
                {
                    "id": str(path),
                    "severity": severity,
                    "status": "missing_fields",
                    "message": f"Missing required fields: {', '.join(missing)}",
                }
            )
        findings.extend(validate_capability_contract_values(path, data, severity))
        cap_id = data.get("id")
        if cap_id:
            ids.append(str(cap_id))
        if data.get("status") == "experimental":
            if data.get("default_maturity") != "L0" or data.get("enforcement_default") != "advisory":
                findings.append(
                    {
                        "id": str(cap_id or path),
                        "severity": severity,
                        "status": "experimental_policy_mismatch",
                        "message": "Experimental capabilities must default to L0 and advisory enforcement.",
                    }
                )
    duplicates = sorted({item for item in ids if ids.count(item) > 1})
    for item in duplicates:
        findings.append({"id": item, "severity": severity, "status": "duplicate_capability_id", "message": "Duplicate capability ID."})
    return {
        "id": "capability_contract_validation",
        "status": check_status(findings),
        "capabilities_dir": str(capabilities_dir),
        "contracts": len(contracts),
        "findings": findings,
    }


def value_finding(path: Path, field: str, severity: str, message: str) -> dict[str, Any]:
    return {
        "id": str(path),
        "severity": severity,
        "status": "schema_constraint_violation",
        "field": field,
        "message": message,
    }


def validate_capability_contract_values(path: Path, data: dict[str, Any], severity: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    cap_id = data.get("id")
    if not isinstance(cap_id, str) or not CAPABILITY_ID_RE.match(cap_id):
        findings.append(value_finding(path, "id", severity, "Capability id must match CAP-* pattern."))

    status = data.get("status")
    if status not in CAPABILITY_STATUS_VALUES:
        findings.append(value_finding(path, "status", severity, "Capability status is not one of the schema enum values."))

    default_maturity = data.get("default_maturity")
    if default_maturity not in MATURITY_LEVELS:
        findings.append(value_finding(path, "default_maturity", severity, "default_maturity must be L0-L5."))

    minimum_profile = data.get("minimum_profile")
    if minimum_profile not in PROFILE_IDS:
        findings.append(value_finding(path, "minimum_profile", severity, "minimum_profile must be quickstart, lite, standard, or assured."))

    enforcement_default = data.get("enforcement_default")
    if enforcement_default is not None and enforcement_default not in ENFORCEMENT_VALUES - {"not_applicable"}:
        findings.append(value_finding(path, "enforcement_default", severity, "enforcement_default is not a valid enforcement value."))

    profiles = data.get("profiles")
    if not isinstance(profiles, dict):
        findings.append(value_finding(path, "profiles", severity, "profiles must be a mapping."))
    else:
        missing_profiles = sorted(PROFILE_IDS - set(profiles))
        if missing_profiles:
            findings.append(value_finding(path, "profiles", severity, f"Missing profile behavior entries: {', '.join(missing_profiles)}."))
        for profile_id, behavior in profiles.items():
            if profile_id not in PROFILE_IDS:
                findings.append(value_finding(path, f"profiles.{profile_id}", severity, "Unknown profile id."))
                continue
            if not isinstance(behavior, dict):
                findings.append(value_finding(path, f"profiles.{profile_id}", severity, "Profile behavior must be a mapping."))
                continue
            missing_behavior = sorted(PROFILE_BEHAVIOR_REQUIRED_FIELDS - set(behavior))
            if missing_behavior:
                findings.append(
                    value_finding(
                        path,
                        f"profiles.{profile_id}",
                        severity,
                        f"Missing profile behavior fields: {', '.join(missing_behavior)}.",
                    )
                )
            if behavior.get("target_maturity") not in MATURITY_LEVELS:
                findings.append(value_finding(path, f"profiles.{profile_id}.target_maturity", severity, "target_maturity must be L0-L5."))
            if behavior.get("enforcement") not in ENFORCEMENT_VALUES:
                findings.append(value_finding(path, f"profiles.{profile_id}.enforcement", severity, "enforcement is not a valid enforcement value."))

    validators = data.get("validators")
    if isinstance(validators, list):
        for index, validator in enumerate(validators):
            field = f"validators[{index}]"
            if not isinstance(validator, dict):
                findings.append(value_finding(path, field, severity, "Validator entry must be a mapping."))
                continue
            if not validator.get("id"):
                findings.append(value_finding(path, f"{field}.id", severity, "Validator entry must include id."))
            if validator.get("status") not in VALIDATOR_STATUS_VALUES:
                findings.append(value_finding(path, f"{field}.status", severity, "Validator status is not a valid schema value."))
    else:
        findings.append(value_finding(path, "validators", severity, "validators must be a list."))

    gatekeepers = data.get("gatekeepers")
    if isinstance(gatekeepers, list):
        for gate_id in gatekeepers:
            if not isinstance(gate_id, str) or not GATE_ID_RE.match(gate_id):
                findings.append(value_finding(path, "gatekeepers", severity, "Gatekeeper id must match G[0-9]+."))
    else:
        findings.append(value_finding(path, "gatekeepers", severity, "gatekeepers must be a list."))

    maturity_path = data.get("maturity_path")
    if isinstance(maturity_path, dict):
        missing_levels = sorted(MATURITY_LEVELS - set(maturity_path))
        if missing_levels:
            findings.append(value_finding(path, "maturity_path", severity, f"Missing maturity levels: {', '.join(missing_levels)}."))
    else:
        findings.append(value_finding(path, "maturity_path", severity, "maturity_path must be a mapping."))

    return findings


def resolve_gatekeeper_manifest(root: Path, naos_root: str) -> Path:
    project_manifest = root / naos_root / "gatekeepers.yaml"
    if project_manifest.exists():
        return project_manifest
    return first_existing_file(
        [
            root / "templates" / "structural-seeds" / "naos" / "gatekeepers.yaml",
            kit_root() / "templates" / "structural-seeds" / "naos" / "gatekeepers.yaml",
        ]
    )


def validate_gatekeeper_manifest(root: Path, profile: str, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    severity = severity_for_profile(profile, policy)
    manifest_path = resolve_gatekeeper_manifest(root, naos_root)
    findings: list[dict[str, Any]] = []
    try:
        data = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return {
            "id": "gatekeeper_manifest_validation",
            "status": "blocked" if profile == "assured" else "required_missing",
            "manifest": str(manifest_path),
            "findings": [{"id": str(manifest_path), "severity": severity, "status": "parse_error", "message": str(exc)}],
        }
    gates = data.get("gates") or []
    if not isinstance(gates, list):
        findings.append({"id": "gates", "severity": severity, "status": "invalid_manifest", "message": "gates must be a list."})
        gates = []
    gate_ids = [str(gate.get("id")) for gate in gates if isinstance(gate, dict) and gate.get("id")]
    expected_ids = {f"G{i}" for i in range(9)}
    missing_ids = sorted(expected_ids - set(gate_ids))
    if missing_ids:
        findings.append(
            {
                "id": "gate_ids",
                "severity": severity,
                "status": "missing_gates",
                "message": f"Missing gates: {', '.join(missing_ids)}",
            }
        )
    for gate in gates:
        if not isinstance(gate, dict):
            continue
        missing = sorted(GATE_REQUIRED_FIELDS - set(gate))
        if missing:
            findings.append(
                {
                    "id": gate.get("id", "unknown"),
                    "severity": severity,
                    "status": "missing_fields",
                    "message": f"Missing required fields: {', '.join(missing)}",
                }
            )
    return {
        "id": "gatekeeper_manifest_validation",
        "status": check_status(findings),
        "manifest": str(manifest_path),
        "gates": len(gates),
        "findings": findings,
    }


def validate_maturity_and_profiles(root: Path, profile: str, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    severity = severity_for_profile(profile, policy)
    findings: list[dict[str, Any]] = []
    maturity_path = first_existing_file(
        [
            root / naos_root / "maturity_levels.yaml",
            root / "templates" / "structural-seeds" / "naos" / "maturity_levels.yaml",
            kit_root() / "templates" / "structural-seeds" / "naos" / "maturity_levels.yaml",
        ]
    )
    profile_dir = first_existing_dir(
        [
            root / ".github" / "profiles",
            root / "templates" / "profiles",
            kit_root() / "templates" / "profiles",
        ]
    )
    profile_paths = sorted(profile_dir.glob("governance-*.yaml"))
    try:
        maturity = yaml.safe_load(maturity_path.read_text(encoding="utf-8"))
    except Exception as exc:
        findings.append({"id": str(maturity_path), "severity": severity, "status": "parse_error", "message": str(exc)})
    else:
        try:
            from jsonschema import Draft202012Validator

            # Validate with this kit's schema, not an adopter-supplied replacement.
            schema_path = kit_root() / "schemas" / "naos" / "capability_maturity.schema.json"
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            for error in Draft202012Validator(schema).iter_errors(maturity):
                field = ".".join(str(part) for part in error.absolute_path) or "model"
                findings.append(value_finding(maturity_path, field, severity, error.message))
        except Exception as exc:
            findings.append({"id": str(maturity_path), "severity": severity,
                             "status": "schema_validation_error", "message": str(exc)})
        levels = maturity.get("levels") if isinstance(maturity, dict) else None
        level_ids = {str(level.get("id")) for level in levels if isinstance(level, dict)} if isinstance(levels, list) else set()
        if level_ids != MATURITY_LEVELS:
            findings.append({"id": "maturity_levels", "severity": severity, "status": "invalid_levels", "message": "Expected L0-L5 maturity levels."})
    found_profiles: set[str] = set()
    for path in profile_paths:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            findings.append({"id": str(path), "severity": severity, "status": "parse_error", "message": str(exc)})
            continue
        profile_id = str(data.get("id", "")).removeprefix("governance-")
        if profile_id:
            found_profiles.add(profile_id)
        if "capabilities" not in data or "gate_policy" not in data:
            findings.append({"id": str(path), "severity": severity, "status": "missing_profile_policy", "message": "Profile lacks capabilities or gate_policy section."})
    missing_profiles = sorted(set(supported_profiles(policy)) - found_profiles)
    if missing_profiles:
        findings.append({"id": "profiles", "severity": severity, "status": "missing_profiles", "message": f"Missing profiles: {', '.join(missing_profiles)}"})
    return {
        "id": "maturity_profile_parsing",
        "status": check_status(findings),
        "maturity_path": str(maturity_path),
        "profile_dir": str(profile_dir),
        "profiles": sorted(found_profiles),
        "findings": findings,
    }


def validate_profile_rules_regeneration(
    root: Path,
    profile: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Surface exact derived RULES drift only for a kit/package layout.

    Adopter-local ``.ai/RULES.md`` is intentionally not compared with kit
    bytes. That file may contain authorized project adaptations, while the
    canonical source and all four derived profile outputs remain kit resources.
    """

    canonical_source = root / "configs" / "profile_rules_source.yaml"
    renderer = root / "naos_profile_rules.py"
    kit_outputs = root / "profiles"
    derived_outputs = [
        kit_outputs / f"governance-{tier}" / ".ai" / "RULES.md"
        for tier in ("quickstart", "lite", "standard", "assured")
    ]
    is_kit_layout = (
        canonical_source.is_file()
        or renderer.is_file()
        or ((root / "naos_init.py").is_file() and all(path.is_file() for path in derived_outputs))
    )
    if not is_kit_layout:
        return {
            "id": "profile_rules_regeneration",
            "status": "not_applicable",
            "applicability": "adopter_local_rules",
            "reason": (
                "Adopter-local .ai/RULES.md may contain authorized ADAPT changes; "
                "exact kit-output parity is not applied."
            ),
            "findings": [],
        }

    severity = severity_for_profile(profile, policy)
    missing = [
        path.relative_to(root).as_posix()
        for path in (canonical_source, renderer, *derived_outputs)
        if not path.exists()
    ]
    if missing:
        findings = [
            {
                "id": "PROFILE_RULES_KIT_INPUT_MISSING",
                "severity": severity,
                "status": "profile_rules_kit_input_missing",
                "message": f"Kit profile-RULES resources are incomplete: {', '.join(missing)}.",
            }
        ]
        return {
            "id": "profile_rules_regeneration",
            "status": check_status(findings),
            "applicability": "kit_profile_rules",
            "findings": findings,
        }

    result = _run_check_child(
        [sys.executable, str(renderer), "--check", "--root", str(root), "--json"], cwd=root)

    try:
        payload = _child_timeout_payload(result, severity) or json.loads(result.stdout)
    except json.JSONDecodeError:
        payload = {
            "status": "failed",
            "findings": [
                {
                    "profile": "all",
                    "rule_id": "PROFILE_RULES_CHECK_ERROR",
                    "message": (result.stderr or result.stdout or "No renderer output").strip(),
                }
            ],
        }
    findings = [
        {
            "id": str(item.get("rule_id") or "PROFILE_RULES_CHECK_FAILED"),
            "profile": str(item.get("profile") or "all"),
            "severity": severity,
            "status": "profile_rules_drift",
            "message": str(item.get("message") or "Profile RULES parity failed."),
            **({"timeout_evidence": item["timeout_evidence"]} if "timeout_evidence" in item else {}),
            "suggested_fix": str(
                item.get("suggested_fix") or "Regenerate the derived profile RULES outputs."
            ),
        }
        for item in payload.get("findings") or []
    ]
    if result.returncode != 0 and not findings:
        findings.append(
            {
                "id": "PROFILE_RULES_CHECK_ERROR",
                "severity": severity,
                "status": "profile_rules_check_error",
                "message": f"Profile RULES renderer exited {result.returncode} without a finding.",
            }
        )
    return {
        "id": "profile_rules_regeneration",
        "status": check_status(findings),
        "applicability": "kit_profile_rules",
        "renderer_status": payload.get("status", "unknown"),
        "profiles_checked": payload.get("profiles_checked", []),
        "findings": findings,
    }


def run_json_script(
    script: str,
    args: list[str],
    profile: str,
    policy: dict[str, Any],
    naos_root: str,
    policy_path: str | None,
) -> dict[str, Any]:
    command = [
        sys.executable,
        str(Path(__file__).resolve().parent / script),
        "--profile",
        profile,
        "--naos-root",
        naos_root,
        "--json",
        *args,
    ]
    if policy_path:
        command.extend(["--policy", policy_path])
    from naos_self_check_inspection import producer_command, complete_producer
    inspected_command = producer_command(script, command[2:])
    if inspected_command is not None:
        command = inspected_command
    # An unscoped diagnostic must not replace a previous scoped query receipt.
    # The actual producer still runs and its no_query/no_seed findings remain.
    unscoped_query = script in {"naos_local_context_query.py", "naos_graph_context_query.py"} and not args
    if unscoped_query and inspected_command is None:
        with tempfile.TemporaryDirectory(prefix="naos-context-inspection-") as directory:
            command.extend(["--output", str(Path(directory) / "diagnostic.json")])
            result = _run_check_child(command, cwd=Path.cwd())
    else:
        result = _run_check_child(command, cwd=Path.cwd())
    payload: dict[str, Any]
    try:
        payload = _child_timeout_payload(result, severity_for_profile(profile, policy)) or json.loads(result.stdout)
    except json.JSONDecodeError:
        payload = {
            "schema": f"naos.{Path(script).stem}.error",
            "status": "error",
            "summary": {"total_findings": 1},
            "findings": [
                {
                    "id": script,
                    "severity": severity_for_profile(profile, policy),
                    "status": "script_error",
                    "message": (result.stderr or result.stdout or "No output").strip(),
                }
            ],
        }
    if not isinstance(payload, dict):
        payload = {"schema": f"naos.{Path(script).stem}.error", "status": "error",
                   "summary": {"total_findings": 1}, "findings": [{"id": script,
                       "severity": severity_for_profile(profile, policy), "status": "script_error",
                       "message": "Producer JSON must be an object."}]}
    complete_producer(script, payload, result.returncode)
    check = {
        "id": Path(script).stem,
        "returncode": result.returncode,
        "status": payload.get("status", "unknown"),
        "summary": payload.get("summary", {}),
        "findings": payload.get("findings", []),
    }
    if unscoped_query:
        check["publication"] = {
            "mode": "invocation_only_no_context",
            "default_receipt": "preserved_not_validated",
        }
    return check


def aggregate_checks(checks: list[dict[str, Any]]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for check in checks:
        findings.extend(check.get("findings") or [])
    summary = finding_counts(findings)
    summary["checks"] = len(checks)
    status = status_from_counts(summary)
    return {"status": status, "summary": summary, "findings": findings}


def self_check_finding_occurrences(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Return nested self-check findings with stable positional identities."""
    occurrences: list[dict[str, Any]] = []
    order = 0
    for check_index, check in enumerate(report.get("checks") or []):
        if not isinstance(check, dict):
            continue
        check_id = str(check.get("id") or "unknown")
        for finding_index, item in enumerate(check.get("findings") or []):
            if not isinstance(item, dict):
                continue
            occurrences.append(
                finding_occurrence(
                    source="self-check",
                    identity=(
                        f"self-check/check[{check_index}]={check_id}"
                        f"/finding[{finding_index}]"
                    ),
                    order=order,
                    finding=item,
                    family_label=f"self-check[{check_index}]:{check_id}",
                    parent_evidence=check,
                )
            )
            order += 1
    return occurrences


def selected_script_checks(
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    *,
    pr_base_ref: str | None = None,
    pr_head_ref: str | None = None,
    task: str | None = None,
    query: str | None = None,
    graph_path: str | None = None,
) -> list[tuple[str, list[str]]]:
    """Canonical full self-check producer plan; evaluating it runs no producer."""
    task = task if task is not None else os.environ.get("TASK") or os.environ.get("NAOS_TASK") or None
    for name, value in (("task", task), ("query", query), ("graph-path", graph_path)):
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise ValueError(f"Explicit {name} context must be a nonempty string")
    task_options = ["--task", task] if task is not None else []
    query_options = task_options + (["--query", query] if query is not None else [])
    graph_options = task_options + (["--path", graph_path] if graph_path is not None else [])
    pr_options = []
    if pr_base_ref is not None or pr_head_ref is not None:
        if not all(isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{40}", value)
                   for value in (pr_base_ref, pr_head_ref)):
            raise ValueError("PR comparison requires explicit full 40-character base and head commit SHAs")
        pr_options = ["--base-ref", pr_base_ref, "--head-ref", pr_head_ref]
    return [
        ("naos_setup_recommendations.py", []),
        ("naos_governance_bypass_posture.py", []),
        ("naos_external_evidence_ingest.py", []),
        ("naos_evidence_attestation.py", []),
        ("naos_memory_context_readiness.py", []),
        ("naos_memory_provider_access.py", []),
        ("naos_memory_use_policy.py", []),
        ("naos_learning_loop_review.py", []),
        ("naos_local_context_index.py", []),
        ("naos_local_context_query.py", query_options),
        ("naos_semantic_candidate_readiness.py", []),
        ("naos_graph_context_readiness.py", []),
        ("naos_graph_context_query.py", graph_options),
        ("naos_task_context_pack.py", task_options),
        ("naos_session_identity.py", ["--inspect-session"]),
        ("naos_operator_attribution.py", ["--inspect-session"]),
        ("naos_session_lifecycle.py", ["--mode", "session_start", "--inspect-session"]),
        ("naos_policy_overrides.py", ["--dry-run"]),
        ("naos_audit_log.py", ["--summary"]),
        ("naos_task_claims.py", ["--action", "list"]),
        ("naos_agent_trace_validate.py", []),
        ("naos_ai_surface_budget.py", []),
        ("naos_static_grader.py", []),
        ("naos_grader_assessment.py", ["--mode", "assess"]),
        ("naos_llm_grader_readiness.py", []),
        ("naos_pr_risk_classification.py", pr_options),
        ("naos_pr_governance_summary.py", []),
        ("naos_agentic_workflow_review.py", []),
        ("naos_pre_implementation_alignment_review.py", []),
        ("naos_calibration_shadow.py", []),
        # Refresh routing inputs before classification. Keep aggregate producers
        # later: classifying their copied findings here amplifies fresh diagnostics.
        *(
            [("naos_ai_component_inventory.py", [])]
            if profile in {"standard", "assured"}
            else []
        ),
        *(
            [("naos_agent_sponsor_registry.py", [])]
            if (root / naos_root / str(policy.get("paths", {}).get("agent_sponsor_registry") or "agent_sponsor_registry.yaml")).is_file()
            and (Path(__file__).resolve().parent / "naos_agent_sponsor_registry.py").is_file()
            else []
        ),
        *(
            [("naos_aivss_arithmetic_verification.py", [])]
            if (root / naos_root / str(policy.get("paths", {}).get("aivss_assessments") or "aivss_assessments.yaml")).is_file()
            and (Path(__file__).resolve().parent / "naos_aivss_arithmetic_verification.py").is_file()
            else []
        ),
        ("naos_model_provider_policy.py", []),
        ("naos_model_telemetry_evidence.py", []),
        ("naos_failure_mode_posture.py", []),
        ("naos_opencode_config_hygiene.py", []),
        ("naos_design_traceability.py", []),
        ("naos_ui_experience_quality.py", []),
        ("naos_failure_mode_observations.py", []),
        ("naos_control_plane_review.py", []),
        ("naos_evidence_classification.py", []),
        ("naos_cross_harness_review_readiness.py", []),
        ("naos_systemic_impact.py", []),
        # Readiness fingerprints systemic output; collect it after that producer.
        ("naos_behavioral_governance_readiness.py", []),
        ("naos_module_header_traceability.py", []),
        ("naos_detect_spec_drift.py", []),
        ("naos_validate_claims.py", []),
        ("naos_validate_roadmap_crosswalk.py", []),
        ("naos_function_index_health.py", []),
        ("naos_evidence_conflicts.py", []),
        ("naos_validate_test_evidence.py", ["--advisory"]),
        ("naos_capability_maturity.py", []),
    ]


def selected_check_ids(
    root: Path, profile: str, naos_root: str, policy: dict[str, Any], **context: Any,
) -> list[str]:
    """Exact full inventory shared by execution and dependency-proof readers."""
    return [
        "capability_contract_validation", "gatekeeper_manifest_validation",
        "maturity_profile_parsing", "profile_rules_regeneration",
        *(Path(script).stem for script, _ in selected_script_checks(
            root, profile, naos_root, policy, **context)),
    ]


def build_report(
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    policy_path: str | None,
    *,
    pr_base_ref: str | None = None,
    pr_head_ref: str | None = None,
    task: str | None = None,
    query: str | None = None,
    graph_path: str | None = None,
    refresh: bool = False,
) -> dict[str, Any]:
    scripts = selected_script_checks(
        root, profile, naos_root, policy, pr_base_ref=pr_base_ref, pr_head_ref=pr_head_ref,
        task=task, query=query, graph_path=graph_path,
    )
    from contextlib import ExitStack
    from naos_self_check_inspection import create_inspection_context, activate_inspection
    with ExitStack() as stack:
        if not refresh:
            directory = stack.enter_context(tempfile.TemporaryDirectory(prefix="naos-self-check-inspection-"))
            context_path = create_inspection_context(root, naos_root, profile, policy, scripts, Path(directory), policy_argument=policy_path)
            stack.enter_context(activate_inspection(context_path))
        checks = [
            validate_capability_contracts(root, profile, naos_root, policy),
            validate_gatekeeper_manifest(root, profile, naos_root, policy),
            validate_maturity_and_profiles(root, profile, naos_root, policy),
            validate_profile_rules_regeneration(root, profile, policy),
            *(run_json_script(script, arguments, profile, policy, naos_root, policy_path)
              for script, arguments in scripts),
        ]
    aggregate = aggregate_checks(checks)
    return {
        "schema": "naos.self_check.v1",
        "generated_at": controlled_utc_now_text(),
        "profile": profile,
        "project_root": str(root.resolve()),
        "naos_root": naos_root,
        "status": aggregate["status"],
        "summary": aggregate["summary"],
        "checks": checks,
        "limitations": [
            "Self-check aggregates configured file-first evidence only.",
            "Quickstart and lite do not fail hard unless strict behavior is requested.",
            "Test evidence validation runs in advisory mode unless separately configured.",
            "Exact profile-RULES parity applies to kit/package resources, not adopter-local ADAPT edits.",
        ],
    }


def finalize_dependencies(
    root: Path, profile: str, naos_root: str, policy: dict[str, Any],
    *, context: dict[str, Any],
) -> dict[str, Any]:
    """Finalize the existing full report without rerunning or rewriting it.

    The bounded resolver recomputes every required predicate before its separate
    receipt is published. A stored status flag is never sufficient authority.
    """
    from naos_self_check_dependency_resolution import (
        _json, build_resolution, write_resolution,
    )
    path = report_output_path(root, naos_root, policy, "self_check_report")
    report, _ = _json(root, path)
    resolution = build_resolution(
        root, profile=profile, naos_root=naos_root, policy=policy,
        self_check_report=report, context=context,
    )
    if resolution.get("status") == "resolved":
        # Publication revalidates the complete proof and its current inputs.
        write_resolution(root, resolution, naos_root=naos_root, policy=policy)
    return resolution


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run NAOS self-conformance checks.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--output")
    parser.add_argument("--refresh", action="store_true", help="Explicitly publish child reports and retain independent producer state/audit behavior; default is live inspection")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--all",
        action="store_true",
        help="Show every human-readable finding occurrence; JSON is always complete.",
    )
    parser.add_argument("--pr-base-ref", help="Explicit full base commit SHA for PR self-check")
    parser.add_argument("--pr-head-ref", help="Explicit full head commit SHA for PR self-check")
    parser.add_argument("--task", default=os.environ.get("TASK") or os.environ.get("NAOS_TASK") or None,
                        help="Explicit task id for task pack and local/graph queries; defaults to TASK/NAOS_TASK")
    parser.add_argument("--query", help="Literal bounded local-context query forwarded to its producer")
    parser.add_argument("--graph-path", help="Exact indexed source path for graph-query --path")
    parser.add_argument("--capture-dependency-inputs", action="store_true",
                        help="Preserve current full self-check/evidence-pack bytes for the next collection; no approval or readiness claim")
    parser.add_argument("--finalize-dependencies", action="store_true",
                        help="Validate dependencies of the existing full self-check and publish a separate proof; does not rerun checks")
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or str(policy.get("paths", {}).get("default_naos_root") or "naos")
    profile = normalize_profile(args.profile, policy)
    policy_path = args.policy or policy.get("_meta", {}).get("path")
    if args.refresh and (args.capture_dependency_inputs or args.finalize_dependencies):
        print("NAOS self-check input error: --refresh cannot combine with dependency capture/finalization", file=sys.stderr)
        return 2
    if args.capture_dependency_inputs:
        if args.finalize_dependencies or args.output is not None:
            print("NAOS dependency capture error: capture requires canonical inputs and cannot combine with finalization or --output", file=sys.stderr)
            return 2
        try:
            from naos_self_check_dependency_resolution import capture_dependency_inputs
            path = capture_dependency_inputs(root, naos_root=naos_root, policy=policy)
        except (OSError, ValueError, TypeError) as error:
            print(f"NAOS dependency capture error: {error}", file=sys.stderr)
            return 2
        print(f"NAOS dependency input bytes captured: {path}")
        return 0
    if args.finalize_dependencies:
        if args.output is not None:
            print("NAOS self-check input error: finalization uses the canonical full report and a separate proof destination; --output is not accepted", file=sys.stderr)
            return 2
        try:
            resolution = finalize_dependencies(root, profile, naos_root, policy, context={
                "pr_base_ref": args.pr_base_ref, "pr_head_ref": args.pr_head_ref,
                "task": args.task, "query": args.query, "graph_path": args.graph_path,
            })
        except (OSError, ValueError, TypeError) as error:
            print(f"NAOS dependency finalization error: {error}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(resolution, indent=2))
        else:
            print(f"NAOS self-check dependency resolution: {resolution['status']}")
            for refusal in resolution.get("refusals", []):
                print(f"- {refusal['code']}: {refusal.get('detail', '')}")
        return 0 if resolution.get("status") == "resolved" else 1
    try:
        report = build_report(root, profile, naos_root, policy, policy_path,
                              pr_base_ref=args.pr_base_ref, pr_head_ref=args.pr_head_ref,
                              task=args.task, query=args.query, graph_path=args.graph_path, refresh=args.refresh)
    except ValueError as error:
        print(f"NAOS self-check input error: {error}", file=sys.stderr)
        return 2
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "self_check_report") if args.refresh else None
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"NAOS self-check: {report['status']} ({report['summary']['total_findings']} findings)")
        presentation = build_actionable_presentation(
            self_check_finding_occurrences(report),
            expansion_command="naos self-check --all",
            show_all=args.all,
            limitations=report.get("limitations") or [],
        )
        for line in presentation_lines(presentation):
            print(line)
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
