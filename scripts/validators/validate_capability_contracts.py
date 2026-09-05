#!/usr/bin/env python3
"""Validate NAOS capability cards against contract and ADR-0010: Control-Plane Advisory Boundaries."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml


RULE_SCHEMA_INVALID = "CAPCONTRACT_SCHEMA_INVALID"
RULE_DUPLICATE_ID = "CAPCONTRACT_DUPLICATE_ID"
RULE_MISSING_FIELD = "CAPCONTRACT_MISSING_FIELD"
RULE_ADVISORY_NO_RESIDUAL_RISK = "CAPCONTRACT_ADVISORY_NO_RESIDUAL_RISK"
RULE_ADVISORY_AUTHORITY_OVERCLAIM = "CAPCONTRACT_ADVISORY_AUTHORITY_OVERCLAIM"
RULE_DETERMINISTIC_PROOF_OVERCLAIM = "CAPCONTRACT_DETERMINISTIC_PROOF_OVERCLAIM"
RULE_READINESS_RUNTIME_OVERCLAIM = "CAPCONTRACT_READINESS_RUNTIME_OVERCLAIM"
RULE_REFERENCE_MISSING = "CAPCONTRACT_REFERENCE_MISSING"
RULE_HASH_SIGNING_OVERCLAIM = "CAPCONTRACT_HASH_SIGNING_OVERCLAIM"
RULE_SOURCE_OF_TRUTH_CONFUSION = "CAPCONTRACT_SOURCE_OF_TRUTH_CONFUSION"

CAPABILITY_ID_RE = re.compile(r"^CAP-[A-Z0-9-]+$")
GATE_ID_RE = re.compile(r"^G[0-9]+$")
CLI_COMMAND_RE = re.compile(r"\bnaos\s+([a-z0-9][a-z0-9-]*)\b")
MAKE_TARGET_RE = re.compile(r"\bmake\s+-f\s+Makefile\.naos\s+([A-Za-z0-9_-]+)\b")

MATURITY_LEVELS = {"L0", "L1", "L2", "L3", "L4", "L5"}
PROFILE_IDS = {"quickstart", "lite", "standard", "assured"}
CAPABILITY_STATUS_VALUES = {"active", "scaffolded", "experimental", "planned", "deprecated"}
ENFORCEMENT_VALUES = {"none", "advisory", "warning", "required", "blocking", "not_applicable"}
VALIDATOR_STATUS_VALUES = {"available", "planned", "external", "manual"}
PROFILE_BEHAVIOR_REQUIRED_FIELDS = {"target_maturity", "enforcement", "notes"}

CLASSIFICATIONS = {
    "deterministic_primary",
    "advisory_complementary",
    "readiness_only",
    "evidence_packaging",
    "routing_or_review",
    "setup_or_onboarding",
    "lifecycle_or_context",
    "future_or_deferred",
}

SAFE_CONTEXT_KEYS = {
    "not_claimed",
    "prohibited_resources",
    "known_limitations",
    "constraints",
    "limitations",
    "residual_risks",
    "forbidden_uses",
}
SAFE_BOUNDARY_TERMS = (
    "not ",
    "not_",
    "never",
    "does not",
    "do not",
    "cannot",
    "must not",
    "may not",
    "no ",
    "without",
    "unless",
    "non-authoritative",
    "deferred",
    "disabled",
    "bounded",
    "not claimed",
    "posture",
    "hierarchy",
)
SOURCE_OF_TRUTH_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"\bsource[- ]of[- ]truth\b",
        r"\bauthoritative truth\b",
        r"\btruth store\b",
        r"\bsemantic answer\b",
        r"\bgraph truth\b",
        r"\bmemory as evidence\b",
        r"\bmemory as approval\b",
    ]
]
ADVISORY_AUTHORITY_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"\badvisory controls replace\b",
        r"\bprobabilistic authority\b",
        r"\badvisory .* approve\b",
        r"\badvisory .* certify\b",
        r"\badvisory .* promote\b",
        r"\bsemantic .* approve\b",
        r"\bgraph .* prove\b",
        r"\bmemory .* approve\b",
        r"\bLLM judge approval\b",
    ]
]
DETERMINISTIC_PROOF_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"\bcomplete proof\b",
        r"\bperfect proof\b",
        r"\bproof of correctness\b",
        r"\bhallucination prevention\b",
        r"\bhallucination-proof\b",
        r"\bcompliance proof\b",
        r"\bcompliance certification\b",
        r"\blegal compliance proof\b",
        r"\bruntime safety proof\b",
    ]
]
READINESS_RUNTIME_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"\benabled by default\b",
        r"\binstalls? sqlite-vec\b",
        r"\bloads? extension\b",
        r"\benable_load_extension\b",
        r"\bload_extension\b",
        r"\buses? NetworkX\b",
        r"\buses? GraphML\b",
        r"\bcalls? Engram\b",
        r"\bcalls? MCP\b",
        r"\bwrites? memory\b",
        r"\bmemory write-back enabled\b",
        r"\bLLMGrader runtime\b",
        r"\bcloud memory enabled\b",
    ]
]
HASH_SIGNING_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"\bcryptographic signing\b",
        r"\bsignature verification\b",
        r"\bdigital signature\b",
        r"\btamper-proof\b",
        r"\bcertified evidence\b",
        r"\bquantum-proof\b",
        r"\bNAOS signs\b",
    ]
]

GENERATED_REFERENCE_PREFIXES = (
    "naos/reports/",
    "naos/evidence/",
    "naos/test_evidence/",
    "naos/context_index/",
    "naos/context_queries/",
    "naos/active/",
    "naos/capabilities/",
    "naos/",
)
CHECKABLE_REFERENCE_PREFIXES = (
    "scripts/",
    "schemas/",
    "templates/",
    "docs/",
    "policies/",
    "capabilities/",
    "configs/",
    "task_battery/",
    "autoresearch/",
    ".github/",
)
CHECKABLE_ROOT_FILES = {
    "README.md",
    "INSTALLATION_MANUAL.md",
    "NAOS_CATALOG.md",
    "KNOWN_LIMITATIONS.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "RELEASE_NOTES.md",
}


@dataclass(frozen=True)
class Finding:
    file: str
    capability_id: str | None
    severity: str
    rule_id: str
    message: str
    suggested_fix: str


def load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def finding(
    path: Path,
    root: Path,
    capability_id: Any,
    severity: str,
    rule_id: str,
    message: str,
    suggested_fix: str,
) -> Finding:
    return Finding(
        file=relative(path, root),
        capability_id=str(capability_id) if capability_id else None,
        severity=severity,
        rule_id=rule_id,
        message=message,
        suggested_fix=suggested_fix,
    )


def iter_scalar_values(value: Any, key_path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from iter_scalar_values(child, (*key_path, str(key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from iter_scalar_values(child, (*key_path, str(index)))
    elif isinstance(value, str):
        yield key_path, value


def capability_text(data: dict[str, Any]) -> str:
    return "\n".join(value for _, value in iter_scalar_values(data))


def path_has_key(key_path: tuple[str, ...], names: set[str]) -> bool:
    return any(part in names for part in key_path)


def is_bounded_context(key_path: tuple[str, ...], text: str) -> bool:
    if path_has_key(key_path, SAFE_CONTEXT_KEYS):
        return True
    lower = text.lower()
    return any(term in lower for term in SAFE_BOUNDARY_TERMS)


def normalize_identifier(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def expected_filename_stem(capability_id: str) -> str:
    return normalize_identifier(capability_id.removeprefix("CAP-"))


def validate_schema_contract(
    path: Path,
    root: Path,
    data: Any,
    schema: dict[str, Any],
) -> list[Finding]:
    findings: list[Finding] = []
    cap_id = data.get("id") if isinstance(data, dict) else None
    if not isinstance(data, dict):
        return [
            finding(
                path,
                root,
                cap_id,
                "error",
                RULE_SCHEMA_INVALID,
                "Capability card must parse to a YAML mapping.",
                "Replace the file body with a mapping that follows schemas/naos/capability.schema.json.",
            )
        ]

    for field in schema.get("required", []):
        if field not in data:
            findings.append(
                finding(
                    path,
                    root,
                    cap_id,
                    "error",
                    RULE_MISSING_FIELD,
                    f"Missing required field: {field}.",
                    f"Add `{field}` according to schemas/naos/capability.schema.json.",
                )
            )

    findings.extend(validate_schema_values(path, root, data))
    if isinstance(cap_id, str) and CAPABILITY_ID_RE.match(cap_id):
        expected_stem = expected_filename_stem(cap_id)
        if path.stem != expected_stem:
            findings.append(
                finding(
                    path,
                    root,
                    cap_id,
                    "warning",
                    RULE_SCHEMA_INVALID,
                    f"Capability filename `{path.stem}` does not match normalized id `{expected_stem}`.",
                    "Rename the capability card or explain the legacy exception before public release.",
                )
            )
    return findings


def validate_schema_values(path: Path, root: Path, data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    cap_id = data.get("id")

    if not isinstance(cap_id, str) or not CAPABILITY_ID_RE.match(cap_id):
        findings.append(
            finding(path, root, cap_id, "error", RULE_SCHEMA_INVALID, "Capability id must match CAP-*.", "Use an id like CAP-EXAMPLE-NAME.")
        )

    status = data.get("status")
    if status not in CAPABILITY_STATUS_VALUES:
        findings.append(
            finding(
                path,
                root,
                cap_id,
                "error",
                RULE_SCHEMA_INVALID,
                "Capability status is not one of the canonical schema values.",
                f"Use one of: {', '.join(sorted(CAPABILITY_STATUS_VALUES))}.",
            )
        )

    if data.get("default_maturity") not in MATURITY_LEVELS:
        findings.append(
            finding(path, root, cap_id, "error", RULE_SCHEMA_INVALID, "default_maturity must be L0-L5.", "Set default_maturity to an L0-L5 value.")
        )

    if data.get("minimum_profile") not in PROFILE_IDS:
        findings.append(
            finding(
                path,
                root,
                cap_id,
                "error",
                RULE_SCHEMA_INVALID,
                "minimum_profile must be quickstart, lite, standard, or assured.",
                "Use a supported NAOS profile id.",
            )
        )

    enforcement_default = data.get("enforcement_default")
    if enforcement_default is not None and enforcement_default not in ENFORCEMENT_VALUES - {"not_applicable"}:
        findings.append(
            finding(path, root, cap_id, "error", RULE_SCHEMA_INVALID, "enforcement_default is invalid.", "Use none, advisory, warning, required, or blocking.")
        )

    profiles = data.get("profiles")
    if not isinstance(profiles, dict):
        findings.append(finding(path, root, cap_id, "error", RULE_SCHEMA_INVALID, "profiles must be a mapping.", "Add profile behavior entries."))
    else:
        missing_profiles = sorted(PROFILE_IDS - set(profiles))
        if missing_profiles:
            findings.append(
                finding(
                    path,
                    root,
                    cap_id,
                    "error",
                    RULE_SCHEMA_INVALID,
                    f"Missing profile behavior entries: {', '.join(missing_profiles)}.",
                    "Add quickstart, lite, standard, and assured profile behavior.",
                )
            )
        for profile_id, behavior in profiles.items():
            if profile_id not in PROFILE_IDS:
                findings.append(
                    finding(path, root, cap_id, "error", RULE_SCHEMA_INVALID, f"Unknown profile id `{profile_id}`.", "Use a supported NAOS profile.")
                )
                continue
            if not isinstance(behavior, dict):
                findings.append(
                    finding(path, root, cap_id, "error", RULE_SCHEMA_INVALID, f"profiles.{profile_id} must be a mapping.", "Add target_maturity, enforcement, and notes.")
                )
                continue
            missing_behavior = sorted(PROFILE_BEHAVIOR_REQUIRED_FIELDS - set(behavior))
            if missing_behavior:
                findings.append(
                    finding(
                        path,
                        root,
                        cap_id,
                        "error",
                        RULE_SCHEMA_INVALID,
                        f"profiles.{profile_id} is missing: {', '.join(missing_behavior)}.",
                        "Add target_maturity, enforcement, and notes.",
                    )
                )
            if behavior.get("target_maturity") not in MATURITY_LEVELS:
                findings.append(
                    finding(path, root, cap_id, "error", RULE_SCHEMA_INVALID, f"profiles.{profile_id}.target_maturity must be L0-L5.", "Use an L0-L5 target.")
                )
            if behavior.get("enforcement") not in ENFORCEMENT_VALUES:
                findings.append(
                    finding(path, root, cap_id, "error", RULE_SCHEMA_INVALID, f"profiles.{profile_id}.enforcement is invalid.", "Use a schema-supported enforcement value.")
                )

    validators = data.get("validators")
    if not isinstance(validators, list):
        findings.append(finding(path, root, cap_id, "error", RULE_SCHEMA_INVALID, "validators must be a list.", "Add validator entries or an empty list."))
    else:
        for index, validator in enumerate(validators):
            if not isinstance(validator, dict):
                findings.append(
                    finding(path, root, cap_id, "error", RULE_SCHEMA_INVALID, f"validators[{index}] must be a mapping.", "Use id/status/script keys.")
                )
                continue
            if not validator.get("id"):
                findings.append(
                    finding(path, root, cap_id, "error", RULE_SCHEMA_INVALID, f"validators[{index}] is missing id.", "Add a stable validator id.")
                )
            if validator.get("status") not in VALIDATOR_STATUS_VALUES:
                findings.append(
                    finding(path, root, cap_id, "error", RULE_SCHEMA_INVALID, f"validators[{index}].status is invalid.", "Use available, planned, external, or manual.")
                )

    gatekeepers = data.get("gatekeepers")
    if not isinstance(gatekeepers, list):
        findings.append(finding(path, root, cap_id, "error", RULE_SCHEMA_INVALID, "gatekeepers must be a list.", "Add gate ids or an empty list."))
    else:
        for gate_id in gatekeepers:
            if not isinstance(gate_id, str) or not GATE_ID_RE.match(gate_id):
                findings.append(
                    finding(path, root, cap_id, "error", RULE_SCHEMA_INVALID, "Gatekeeper id must match G[0-9]+.", "Use gate ids like G2.")
                )

    maturity_path = data.get("maturity_path")
    if not isinstance(maturity_path, dict):
        findings.append(finding(path, root, cap_id, "error", RULE_SCHEMA_INVALID, "maturity_path must be a mapping.", "Add L0-L5 maturity text."))
    else:
        missing_levels = sorted(MATURITY_LEVELS - set(maturity_path))
        if missing_levels:
            findings.append(
                finding(path, root, cap_id, "error", RULE_SCHEMA_INVALID, f"Missing maturity levels: {', '.join(missing_levels)}.", "Add all L0-L5 maturity levels.")
            )

    return findings


def classify_capability(data: dict[str, Any]) -> set[str]:
    text = capability_text(data).lower()
    cap_id = str(data.get("id", "")).lower()
    name = str(data.get("name", "")).lower()
    status = str(data.get("status", "")).lower()
    blob = "\n".join([text, cap_id, name, status])
    classes: set[str] = set()

    if status in {"scaffolded", "experimental", "planned"} or any(term in blob for term in ["readiness", "deferred", "future", "disabled", "scaffold"]):
        classes.add("readiness_only")
    if status in {"experimental", "planned"} or any(term in blob for term in ["future", "deferred", "not implemented", "runtime is disabled"]):
        classes.add("future_or_deferred")
    advisory_terms = [
        "semantic",
        "similarity",
        "embedding",
        "vector",
        "memory",
        "engram",
        "mcp",
        "llmgrader",
        "probabilistic",
        "llm judging",
        "llm-backed",
        "model-backed",
        "provider-backed scoring",
        "graph analytics",
        "graph algorithm",
        "semantic graph",
    ]
    if any(term in blob for term in advisory_terms):
        classes.add("advisory_complementary")
    if any(term in blob for term in ["evidence", "dashboard", "attestation", "digest", "reviewer metadata"]):
        classes.add("evidence_packaging")
    if any(term in blob for term in ["control-plane", "review", "routing", "gatekeeper", "systemic impact", "claims validation"]):
        classes.add("routing_or_review")
    if any(term in blob for term in ["setup", "onboarding", "adopter", "installation"]):
        classes.add("setup_or_onboarding")
    if any(term in blob for term in ["context", "session", "task context", "local index", "query", "memory", "graph", "semantic"]):
        classes.add("lifecycle_or_context")
    if any(term in blob for term in ["deterministic", "static", "validator", "schema", "config", "source", "test", "fts", "explicit link", "hash"]):
        classes.add("deterministic_primary")

    if not classes:
        classes.add("deterministic_primary")

    return classes & CLASSIFICATIONS


def has_nonempty_field(data: dict[str, Any], names: set[str]) -> bool:
    for name in names:
        value = data.get(name)
        if value:
            return True
    return False


def nested_contains(data: Any, terms: tuple[str, ...]) -> bool:
    text = capability_text(data).lower()
    return any(term in text for term in terms)


def validate_adr_boundaries(path: Path, root: Path, data: dict[str, Any], classes: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    cap_id = data.get("id")

    if "advisory_complementary" in classes:
        if not nested_contains(data, ("human review", "human-review", "human_review_required", "review required", "manual review")):
            findings.append(
                finding(
                    path,
                    root,
                    cap_id,
                    "error",
                    RULE_ADVISORY_NO_RESIDUAL_RISK,
                    "Advisory capability lacks an explicit human-review boundary.",
                    "State that advisory output requires human review before durable decisions.",
                )
            )
        if not (has_nonempty_field(data, {"known_limitations"}) or nested_contains(data, ("residual risk", "residual-risk", "known gap"))):
            findings.append(
                finding(
                    path,
                    root,
                    cap_id,
                    "error",
                    RULE_ADVISORY_NO_RESIDUAL_RISK,
                    "Advisory capability lacks residual-risk or equivalent limitation posture.",
                    "Add residual risks, known gaps, or known limitations.",
                )
            )
        if not has_nonempty_field(data, {"not_claimed"}):
            findings.append(
                finding(
                    path,
                    root,
                    cap_id,
                    "error",
                    RULE_ADVISORY_NO_RESIDUAL_RISK,
                    "Advisory capability lacks not_claimed boundaries.",
                    "Add not_claimed entries for authority, approval, certification, and proof boundaries.",
                )
            )

    if "deterministic_primary" in classes:
        authority = data.get("authority") if isinstance(data.get("authority"), dict) else {}
        deterministic_inputs = bool(authority.get("may_read") or data.get("allowed_resources") or data.get("required_evidence"))
        outputs = bool(authority.get("may_write") or data.get("required_evidence") or data.get("dashboard_signals"))
        if not deterministic_inputs:
            findings.append(
                finding(
                    path,
                    root,
                    cap_id,
                    "error",
                    RULE_MISSING_FIELD,
                    "Deterministic capability does not identify source artifacts or deterministic inputs.",
                    "Declare may_read, allowed_resources, or required_evidence.",
                )
            )
        if not outputs:
            findings.append(
                finding(
                    path,
                    root,
                    cap_id,
                    "error",
                    RULE_MISSING_FIELD,
                    "Deterministic capability does not identify report/evidence output.",
                    "Declare may_write, required_evidence, or dashboard_signals.",
                )
            )
        if not has_nonempty_field(data, {"known_limitations"}):
            findings.append(
                finding(path, root, cap_id, "error", RULE_MISSING_FIELD, "Deterministic capability lacks known limitations.", "Add known_limitations.")
            )

    if {"readiness_only", "future_or_deferred"} & classes:
        if not nested_contains(data, ("readiness", "deferred", "future", "disabled", "not implemented", "scaffold", "experimental", "advisory")):
            findings.append(
                finding(
                    path,
                    root,
                    cap_id,
                    "error",
                    RULE_READINESS_RUNTIME_OVERCLAIM,
                    "Readiness/deferred capability lacks explicit disabled/readiness/deferred posture.",
                    "Declare disabled, readiness-only, future, deferred, or experimental posture.",
                )
            )

    findings.extend(scan_overclaims(path, root, data, classes))
    return findings


def scan_overclaims(path: Path, root: Path, data: dict[str, Any], classes: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    cap_id = data.get("id")
    for key_path, text in iter_scalar_values(data):
        if is_bounded_context(key_path, text):
            continue

        if any(pattern.search(text) for pattern in SOURCE_OF_TRUTH_PATTERNS):
            findings.append(
                finding(
                    path,
                    root,
                    cap_id,
                    "error",
                    RULE_SOURCE_OF_TRUTH_CONFUSION,
                    f"Unbounded source-authority phrase at {'.'.join(key_path)}: {text}",
                    "Rewrite to state that repository/source artifacts remain authoritative and outputs are bounded aids.",
                )
            )

        if any(pattern.search(text) for pattern in ADVISORY_AUTHORITY_PATTERNS):
            findings.append(
                finding(
                    path,
                    root,
                    cap_id,
                    "error",
                    RULE_ADVISORY_AUTHORITY_OVERCLAIM,
                    f"Unbounded advisory authority phrase at {'.'.join(key_path)}: {text}",
                    "State that advisory controls may challenge deterministic controls but may not replace or approve them.",
                )
            )

        if "deterministic_primary" in classes and any(pattern.search(text) for pattern in DETERMINISTIC_PROOF_PATTERNS):
            findings.append(
                finding(
                    path,
                    root,
                    cap_id,
                    "error",
                    RULE_DETERMINISTIC_PROOF_OVERCLAIM,
                    f"Unbounded deterministic proof phrase at {'.'.join(key_path)}: {text}",
                    "Bound deterministic controls as reproducible/reviewable aids, not complete proof.",
                )
            )

        if {"readiness_only", "future_or_deferred"} & classes and any(pattern.search(text) for pattern in READINESS_RUNTIME_PATTERNS):
            findings.append(
                finding(
                    path,
                    root,
                    cap_id,
                    "error",
                    RULE_READINESS_RUNTIME_OVERCLAIM,
                    f"Readiness/deferred capability appears to claim active runtime at {'.'.join(key_path)}: {text}",
                    "Mark runtime behavior as disabled, deferred, optional, or project-configured only.",
                )
            )

        if any(pattern.search(text) for pattern in HASH_SIGNING_PATTERNS):
            findings.append(
                finding(
                    path,
                    root,
                    cap_id,
                    "error",
                    RULE_HASH_SIGNING_OVERCLAIM,
                    f"Unbounded hash/signing phrase at {'.'.join(key_path)}: {text}",
                    "Use checksum/digest language unless actual signing is implemented; adopters own keys and signing authority.",
                )
            )

    return deduplicate_findings(findings)


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for item in findings:
        key = (item.file, item.rule_id, item.message)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def strip_reference_args(value: str) -> str:
    return value.split()[0].strip("\"'")


def is_generated_reference(value: str) -> bool:
    clean = strip_reference_args(value)
    return clean.startswith(GENERATED_REFERENCE_PREFIXES) or "*" in clean or clean.endswith("/")


def is_checkable_reference(value: str) -> bool:
    clean = strip_reference_args(value)
    return clean in CHECKABLE_ROOT_FILES or clean.startswith(CHECKABLE_REFERENCE_PREFIXES)


def validate_references(path: Path, root: Path, data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    cap_id = data.get("id")

    for key_path, value in iter_scalar_values(data):
        if not key_path or key_path[0] not in {"related_docs", "related_scripts"}:
            continue
        if not is_checkable_reference(value) or is_generated_reference(value):
            continue
        reference = strip_reference_args(value)
        if not (root / reference).exists():
            findings.append(
                finding(
                    path,
                    root,
                    cap_id,
                    "error",
                    RULE_REFERENCE_MISSING,
                    f"Referenced path does not exist at {'.'.join(key_path)}: {reference}",
                    "Create the referenced artifact, remove the stale reference, or mark it as generated/future/manual.",
                )
            )

    validators = data.get("validators")
    if isinstance(validators, list):
        for index, validator in enumerate(validators):
            if not isinstance(validator, dict):
                continue
            script = validator.get("script")
            status = validator.get("status")
            if script and status == "available":
                reference = strip_reference_args(str(script))
                if not (root / reference).exists():
                    findings.append(
                        finding(
                            path,
                            root,
                            cap_id,
                            "error",
                            RULE_REFERENCE_MISSING,
                            f"Available validator script is missing at validators[{index}]: {reference}",
                            "Create the script or change the validator status to planned/manual/external.",
                        )
                    )

    cli_commands = load_cli_commands(root)
    make_targets = load_make_targets(root)
    for key_path, value in iter_scalar_values(data):
        for command in CLI_COMMAND_RE.findall(value):
            if command not in cli_commands:
                findings.append(
                    finding(
                        path,
                        root,
                        cap_id,
                        "error",
                        RULE_REFERENCE_MISSING,
                        f"Referenced CLI command `naos {command}` is not present in cli.py at {'.'.join(key_path)}.",
                        "Add the CLI command or remove the stale capability-card reference.",
                    )
                )
        for target in MAKE_TARGET_RE.findall(value):
            if target not in make_targets:
                findings.append(
                    finding(
                        path,
                        root,
                        cap_id,
                        "error",
                        RULE_REFERENCE_MISSING,
                        f"Referenced Make target `{target}` is not present in templates/Makefile.naos at {'.'.join(key_path)}.",
                        "Add the Make target or remove the stale capability-card reference.",
                    )
                )

    return deduplicate_findings(findings)


def load_cli_commands(root: Path) -> set[str]:
    cli_path = root / "cli.py"
    if not cli_path.exists():
        return set()
    text = cli_path.read_text(encoding="utf-8")
    commands = set(re.findall(r'"([a-z0-9][a-z0-9-]*)":\s*"scripts/', text))
    commands.update(re.findall(r'if command == "([a-z0-9][a-z0-9-]*)"', text))
    commands.update({"init", "add", "upgrade", "memory"})
    return commands


def load_make_targets(root: Path) -> set[str]:
    makefile = root / "templates" / "Makefile.naos"
    if not makefile.exists():
        return set()
    return set(re.findall(r"^([A-Za-z0-9_-]+):", makefile.read_text(encoding="utf-8"), flags=re.MULTILINE))


def validate_capability_cards(root: Path) -> dict[str, Any]:
    schema_path = root / "schemas" / "naos" / "capability.schema.json"
    schema = load_json(schema_path) if schema_path.exists() else {"required": []}
    capabilities_dir = root / "capabilities"
    installable_capabilities_dir = (
        root / "templates" / "setup-modules" / "capabilities"
    )
    findings: list[Finding] = []
    cards: list[dict[str, Any]] = []
    seen_ids: dict[str, Path] = {}

    capability_paths = [
        *capabilities_dir.glob("*.yaml"),
        *installable_capabilities_dir.glob("*.yaml"),
    ]
    for path in sorted(capability_paths):
        if path.name.startswith("_"):
            continue
        try:
            data = load_yaml(path)
        except Exception as exc:
            findings.append(
                finding(
                    path,
                    root,
                    None,
                    "error",
                    RULE_SCHEMA_INVALID,
                    f"YAML parse failed: {exc}",
                    "Fix YAML syntax.",
                )
            )
            continue
        card_findings = validate_schema_contract(path, root, data, schema)
        if isinstance(data, dict):
            cap_id = data.get("id")
            if isinstance(cap_id, str):
                if cap_id in seen_ids:
                    card_findings.append(
                        finding(
                            path,
                            root,
                            cap_id,
                            "error",
                            RULE_DUPLICATE_ID,
                            f"Duplicate capability id also used by {relative(seen_ids[cap_id], root)}.",
                            "Give each capability card a unique id.",
                        )
                    )
                else:
                    seen_ids[cap_id] = path
            classes = classify_capability(data)
            card_findings.extend(validate_adr_boundaries(path, root, data, classes))
            card_findings.extend(validate_references(path, root, data))
            cards.append({"file": relative(path, root), "id": cap_id, "classifications": sorted(classes)})
        findings.extend(card_findings)

    counts = {
        "error": sum(1 for item in findings if item.severity == "error"),
        "warning": sum(1 for item in findings if item.severity == "warning"),
        "info": sum(1 for item in findings if item.severity == "info"),
    }
    return {
        "schema": "naos.capability_contract_validation.v1",
        "status": "fail" if counts["error"] else "pass",
        "root": str(root),
        "capabilities_dir": str(capabilities_dir),
        "installable_capabilities_dir": str(installable_capabilities_dir),
        "capability_count": len(cards),
        "active_capability_count": sum(
            1 for item in cards if item["file"].startswith("capabilities/")
        ),
        "installable_capability_count": sum(
            1
            for item in cards
            if item["file"].startswith("templates/setup-modules/capabilities/")
        ),
        "schema_path": str(schema_path),
        "cards": cards,
        "counts": counts,
        "findings": [asdict(item) for item in findings],
    }


def print_text_report(report: dict[str, Any]) -> None:
    status = report["status"].upper()
    print(f"Capability Contract Validation: {status}")
    print(f"  capabilities: {report['capability_count']}")
    print(f"  findings: {report['counts']}")
    for item in report["findings"]:
        print(
            f"  - [{item['severity']}] {item['rule_id']} "
            f"{item['file']} ({item.get('capability_id') or 'unknown'}): {item['message']}"
        )
        print(f"    fix: {item['suggested_fix']}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate NAOS capability-card contracts and ADR-0010: Control-Plane Advisory Boundaries.")
    parser.add_argument("--root", default=".", help="Repository root to validate.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = Path(args.root).resolve()
    report = validate_capability_cards(root)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_text_report(report)
    return 1 if report["status"] == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())
