#!/usr/bin/env python3
"""Validate NAOS profile x maturity control-coherence invariants.

Root-cause guard (CG4 / AP1): prior validators check intra-artifact *shape*
(`validate_capability_contracts.py`) and field *values* (`naos_self_check.py`)
but nothing asserted *inter-artifact* monotonicity or that the declared 2-D
control lattice (profile severity x capability maturity) has a syntactic
consumer reference.
That blind spot let the profile control ramp drift (quickstart enforcing more
than lite in static samples) and left per-capability `enforcement`/
`target_maturity` without a guarded named-consumer reference.

This validator asserts, deterministically and in CI:

  C1  severity_by_profile monotonic: advisory < warning < required < blocking.
  C2  per-capability profiles.<p>.enforcement non-decreasing quickstart->assured.
  C3  per-capability profiles.<p>.target_maturity non-decreasing quickstart->assured.
  C4  exit_code.fail_on monotonic across profiles (each superset of previous) and
      fail_on subset of strict_fail_on per profile.
  C5  capability_state seed capability ids exist in capability contracts.
  C6  declared-vs-referenced: the maturity evaluator contains a syntactic call
      to effective_enforcement. This guard does not prove reachability or that
      the returned value controls a runtime decision.
  C7  each derived kit profile RULES file is byte-exact against the independent
      canonical RULES source contract.
  C8  kit profile-summary active and BLOCKING posture counts equal the canonical
      row counts;
      this exact kit-only invariant is not applicable when the canonical source
      is absent from a generated adopter root.
  C9  copied reference presets resolve to canonical active RULES membership.
  C10 profile-schema portability tiers remain classification metadata and do
      not make stale claims about profile membership.

It is deterministic review evidence. It is not approval, certification, or proof
of compliance, and it does not evaluate adopter runtime state.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

VALIDATOR_KIT_ROOT = Path(__file__).resolve().parents[2]
if str(VALIDATOR_KIT_ROOT) not in sys.path:
    sys.path.insert(0, str(VALIDATOR_KIT_ROOT))

try:
    from naos_profile_rules import check_profile_rules, load_profile_rules_source
except ImportError:  # Generated adopter validators do not carry kit-only source data.
    check_profile_rules = None  # type: ignore[assignment]
    load_profile_rules_source = None  # type: ignore[assignment]

PROFILE_ORDER = ["quickstart", "lite", "standard", "assured"]
SEVERITY_RANK = {"advisory": 0, "warning": 1, "required": 2, "blocking": 3}
ENFORCEMENT_RANK = {"none": 0, "not_applicable": 0, "advisory": 1, "warning": 2, "required": 3, "blocking": 4}
MATURITY_RANK = {"L0": 0, "L1": 1, "L2": 2, "L3": 3, "L4": 4, "L5": 5}
FAIL_ON_RANK = {"advisory": 0, "warning": 1, "required": 2, "blocking": 3}
EXPECTED_PORTABILITY_DESCRIPTIONS = {
    "tier_1_core": "Portable core methodology; profile membership is defined by the canonical RULES source",
    "tier_2_quality": "Quality methodology and governance machinery; profile membership is defined by the canonical RULES source",
    "tier_3_advanced": "Advanced-governance portability classification; profile membership is defined by the canonical RULES source",
}


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


@dataclass(frozen=True)
class Finding:
    file: str
    capability_id: str | None
    severity: str
    rule_id: str
    message: str
    suggested_fix: str


def finding(file: str, cap: str | None, severity: str, rule_id: str, message: str, fix: str) -> Finding:
    return Finding(file=file, capability_id=cap, severity=severity, rule_id=rule_id, message=message, suggested_fix=fix)


def load_yaml(path: Path) -> Any:
    return yaml.load(
        path.read_text(encoding="utf-8"),
        Loader=_UniqueKeySafeLoader,
    ) or {}


def _non_decreasing(values: list[int | None]) -> bool:
    seen = [v for v in values if v is not None]
    return all(a <= b for a, b in zip(seen, seen[1:]))


def check_severity_by_profile(policy: dict[str, Any], rel: str) -> list[Finding]:
    findings: list[Finding] = []
    mapping = (policy.get("profiles") or {}).get("severity_by_profile") or {}
    ranks = [SEVERITY_RANK.get(str(mapping.get(p))) for p in PROFILE_ORDER]
    if any(r is None for r in ranks):
        findings.append(finding(rel, None, "error", "CTRLCOH_SEVERITY_INVALID",
                                 f"severity_by_profile must define all profiles with valid severities; got {mapping}.",
                                 "Set quickstart/lite/standard/assured to advisory/warning/required/blocking."))
        return findings
    if not _non_decreasing(ranks):
        findings.append(finding(rel, None, "error", "CTRLCOH_SEVERITY_NONMONOTONIC",
                                 f"severity_by_profile is not non-decreasing quickstart->assured: {mapping}.",
                                 "Order severities so control increases: advisory<=warning<=required<=blocking."))
    return findings


def check_exit_code_ramp(policy: dict[str, Any], rel: str) -> list[Finding]:
    findings: list[Finding] = []
    exit_code = (policy.get("profiles") or {}).get("exit_code") or {}
    prev_set: set[str] = set()
    prev_profile = None
    for profile in PROFILE_ORDER:
        block = exit_code.get(profile) or {}
        fail_on = set(str(s) for s in block.get("fail_on") or [])
        strict = set(str(s) for s in block.get("strict_fail_on") or [])
        if not fail_on <= strict:
            findings.append(finding(rel, None, "error", "CTRLCOH_FAILON_NOT_SUBSET_STRICT",
                                    f"{profile}: fail_on {sorted(fail_on)} must be a subset of strict_fail_on {sorted(strict)}.",
                                    "Ensure strict mode is at least as strict as default."))
        if prev_profile is not None and not prev_set <= fail_on:
            findings.append(finding(rel, None, "error", "CTRLCOH_FAILON_NONMONOTONIC",
                                    f"{profile}.fail_on {sorted(fail_on)} must be a superset of {prev_profile}.fail_on {sorted(prev_set)} (graduated ramp).",
                                    "Each profile must enforce at least what the previous one enforces."))
        prev_set = fail_on
        prev_profile = profile
    return findings


def check_capability(path: Path, data: dict[str, Any], rel: str) -> list[Finding]:
    findings: list[Finding] = []
    cap_id = data.get("id")
    profiles = data.get("profiles")
    if not isinstance(profiles, dict):
        return findings  # shape is validated by validate_capability_contracts.py
    invalid_entries = [p for p in PROFILE_ORDER if not isinstance(profiles.get(p), dict)]
    if invalid_entries:
        findings.append(finding(
            rel,
            cap_id,
            "error",
            "CTRLCOH_CAP_PROFILE_INVALID",
            f"{cap_id}: profile entries must be mappings for {', '.join(invalid_entries)}.",
            "Define an enforcement and target_maturity mapping for every supported profile.",
        ))
        return findings
    enforcement_values = [str(profiles[p].get("enforcement")) for p in PROFILE_ORDER]
    maturity_values = [str(profiles[p].get("target_maturity")) for p in PROFILE_ORDER]
    enf_ranks = [ENFORCEMENT_RANK.get(value) for value in enforcement_values]
    mat_ranks = [MATURITY_RANK.get(value) for value in maturity_values]
    if any(rank is None for rank in enf_ranks):
        findings.append(finding(
            rel,
            cap_id,
            "error",
            "CTRLCOH_CAP_ENFORCEMENT_INVALID",
            f"{cap_id}: invalid per-profile enforcement values {enforcement_values!r}.",
            "Use only supported enforcement values for every profile.",
        ))
    elif not _non_decreasing(enf_ranks):
        findings.append(finding(rel, cap_id, "error", "CTRLCOH_CAP_ENFORCEMENT_NONMONOTONIC",
                                f"{cap_id}: per-profile enforcement must not decrease quickstart->assured.",
                                "Order enforcement so control increases across profiles."))
    if any(rank is None for rank in mat_ranks):
        findings.append(finding(
            rel,
            cap_id,
            "error",
            "CTRLCOH_CAP_MATURITY_INVALID",
            f"{cap_id}: invalid per-profile target_maturity values {maturity_values!r}.",
            "Use only L0 through L5 for every profile.",
        ))
    elif not _non_decreasing(mat_ranks):
        findings.append(finding(rel, cap_id, "error", "CTRLCOH_CAP_MATURITY_NONMONOTONIC",
                                f"{cap_id}: per-profile target_maturity must not decrease quickstart->assured.",
                                "Order target_maturity so depth increases across profiles."))
    return findings


def check_state_ids(state_path: Path, contract_ids: set[str], rel: str) -> list[Finding]:
    findings: list[Finding] = []
    if not state_path.exists():
        return findings
    data = load_yaml(state_path)
    for entry in data.get("capabilities") or []:
        cap_id = entry.get("capability_id")
        if cap_id and cap_id not in contract_ids:
            findings.append(finding(rel, cap_id, "error", "CTRLCOH_STATE_ID_ORPHAN",
                                    f"capability_state references {cap_id} which has no capability contract.",
                                    "Remove the orphan state entry or add the contract."))
    return findings


def check_gatekeeper_refs(data: dict[str, Any], gate_ids: set[str], rel: str) -> list[Finding]:
    """Every capability.gatekeepers id must exist in the gatekeeper manifest.

    Supports CG2: the gate<->capability linkage that drives maturity-gated gate
    severity is only sound if the referenced gates actually exist.
    """
    findings: list[Finding] = []
    if not gate_ids:
        return findings  # manifest not found; skip rather than false-fail
    cap_id = data.get("id")
    for gk in data.get("gatekeepers") or []:
        if str(gk) not in gate_ids:
            findings.append(finding(rel, cap_id, "error", "CTRLCOH_GATEKEEPER_REF_UNKNOWN",
                                    f"{cap_id}: gatekeepers references unknown gate '{gk}'.",
                                    "Reference an existing gate id from the gatekeeper manifest, or add the gate."))
    return findings


def load_gate_ids(root: Path) -> set[str]:
    manifest = root / "templates" / "structural-seeds" / "naos" / "gatekeepers.yaml"
    if not manifest.exists():
        manifest = root / "naos" / "gatekeepers.yaml"
    if not manifest.exists():
        return set()
    data = load_yaml(manifest)
    return {str(g.get("id")) for g in (data.get("gates") or []) if isinstance(g, dict) and g.get("id")}


def _extract_profiles_dict(root: Path) -> dict[str, Any] | None:
    """Side-effect-free exact read of the module-level PROFILES literal.

    Multiple definitions or module-level mutations are ambiguous for a static
    coherence check and therefore fail closed instead of accepting the first
    literal assignment encountered.
    """
    src = root / "naos_init.py"
    if not src.exists():
        return None
    try:
        tree = ast.parse(src.read_text(encoding="utf-8"))
    except Exception:
        return None

    def root_name(node: ast.AST) -> str | None:
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        return node.id if isinstance(node, ast.Name) else None

    class ProfileDefinitionVisitor(ast.NodeVisitor):
        MUTATING_METHODS = {
            "clear", "pop", "popitem", "setdefault", "update",
            "__delitem__", "__init__", "__ior__", "__setitem__",
        }

        def __init__(self) -> None:
            self.values: list[ast.AST] = []
            self.ambiguous = False
            self.aliases = {"PROFILES"}

        def references_alias(self, node: ast.AST | None) -> bool:
            return node is not None and any(
                isinstance(item, ast.Name)
                and isinstance(item.ctx, ast.Load)
                and item.id in self.aliases
                for item in ast.walk(node)
            )

        def scope_may_mutate(self, node: ast.AST) -> bool:
            """Conservatively detect mutation of PROFILES from a nested scope."""
            aliases = set(self.aliases)

            def references(node_to_check: ast.AST | None) -> bool:
                return node_to_check is not None and any(
                    isinstance(item, ast.Name)
                    and isinstance(item.ctx, ast.Load)
                    and item.id in aliases
                    for item in ast.walk(node_to_check)
                )

            changed = True
            while changed:
                changed = False
                for item in ast.walk(node):
                    value: ast.AST | None = None
                    targets: list[ast.AST] = []
                    if isinstance(item, ast.Assign):
                        value = item.value
                        targets = list(item.targets)
                    elif isinstance(item, ast.AnnAssign):
                        value = item.value
                        targets = [item.target]
                    if references(value):
                        for target in targets:
                            if isinstance(target, ast.Name) and target.id not in aliases:
                                aliases.add(target.id)
                                changed = True

            for item in ast.walk(node):
                if isinstance(item, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                    targets = (
                        list(item.targets)
                        if isinstance(item, ast.Assign)
                        else [item.target]
                    )
                    if any(root_name(target) in aliases for target in targets):
                        return True
                if isinstance(item, ast.Delete) and any(
                    root_name(target) in aliases for target in item.targets
                ):
                    return True
                if isinstance(item, ast.Call):
                    function = item.func
                    if (
                        isinstance(function, ast.Attribute)
                        and root_name(function.value) in aliases
                        and function.attr in self.MUTATING_METHODS
                    ):
                        return True
            return False

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            # A callable can mutate the module-global PROFILES mapping after
            # import. Fail closed instead of trying to prove reachability or
            # local-name shadowing in a static literal reader.
            if self.scope_may_mutate(node):
                self.ambiguous = True

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            if self.scope_may_mutate(node):
                self.ambiguous = True

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            if self.scope_may_mutate(node):
                self.ambiguous = True

        def visit_Lambda(self, node: ast.Lambda) -> None:
            if self.scope_may_mutate(node):
                self.ambiguous = True

        def visit_Assign(self, node: ast.Assign) -> None:
            direct = [
                target
                for target in node.targets
                if isinstance(target, ast.Name) and target.id == "PROFILES"
            ]
            derived = [
                target
                for target in node.targets
                if root_name(target) in self.aliases and target not in direct
            ]
            if direct:
                if len(node.targets) != 1 or len(direct) != 1:
                    self.ambiguous = True
                self.values.append(node.value)
            if derived:
                self.ambiguous = True
            if self.references_alias(node.value):
                aliases = [target.id for target in node.targets if isinstance(target, ast.Name)]
                if not aliases or direct:
                    self.ambiguous = True
                self.aliases.update(aliases)
            self.visit(node.value)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            if isinstance(node.target, ast.Name) and node.target.id == "PROFILES":
                if node.value is None:
                    self.ambiguous = True
                else:
                    self.values.append(node.value)
                    self.visit(node.value)
            elif root_name(node.target) in self.aliases:
                self.ambiguous = True
            elif self.references_alias(node.value) and isinstance(node.target, ast.Name):
                self.aliases.add(node.target.id)
                if node.value is not None:
                    self.visit(node.value)

        def visit_AugAssign(self, node: ast.AugAssign) -> None:
            if root_name(node.target) in self.aliases:
                self.ambiguous = True
            self.generic_visit(node)

        def visit_Delete(self, node: ast.Delete) -> None:
            if any(root_name(target) in self.aliases for target in node.targets):
                self.ambiguous = True

        def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
            if root_name(node.target) in self.aliases:
                self.ambiguous = True
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            function = node.func
            if (
                isinstance(function, ast.Attribute)
                and root_name(function.value) in self.aliases
                and function.attr in self.MUTATING_METHODS
            ):
                self.ambiguous = True
            if any(self.references_alias(argument) for argument in node.args) or any(
                self.references_alias(keyword.value) for keyword in node.keywords
            ):
                self.ambiguous = True
            self.generic_visit(node)

    visitor = ProfileDefinitionVisitor()
    visitor.visit(tree)
    if visitor.ambiguous or len(visitor.values) != 1:
        return None
    try:
        value = ast.literal_eval(visitor.values[0])
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def check_rules_blocking_monotonic(root: Path) -> list[Finding]:
    """Check kit active/posture-count equality when canonical authority exists.

    ``rules_active`` counts canonical active rows; ``rules_blocking`` counts the
    documented BLOCKING subset. Neither is a count of executable hook checks,
    policy gate severity, or exit-code behavior. Generated adopter roots do not
    carry the canonical source, so this kit-only invariant is not applicable.
    """
    findings: list[Finding] = []
    canonical_source = root / "configs" / "profile_rules_source.yaml"
    if not canonical_source.is_file() or load_profile_rules_source is None:
        return findings
    try:
        contract = load_profile_rules_source(canonical_source, claim_root=root)
    except Exception:
        return findings  # The exact-source check reports the canonical error.

    profiles = _extract_profiles_dict(root)
    if not isinstance(profiles, dict):
        findings.append(finding(
            "naos_init.py",
            None,
            "error",
            "CTRLCOH_RULES_BLOCKING_PROFILES_UNREADABLE",
            "Canonical profile RULES source is present, but naos_init.PROFILES is missing or not statically readable.",
            "Restore the literal naos_init.PROFILES mapping before claiming kit count coherence.",
        ))
        return findings

    actual_keys = set(profiles)
    expected_keys = set(PROFILE_ORDER)
    if actual_keys != expected_keys:
        missing = sorted(expected_keys - actual_keys)
        unexpected = sorted(actual_keys - expected_keys, key=str)
        findings.append(finding(
            "naos_init.py",
            None,
            "error",
            "CTRLCOH_RULES_BLOCKING_PROFILE_SET_MISMATCH",
            "Canonical profile RULES source is present, but naos_init.PROFILES "
            f"does not define the exact supported profile set; missing={missing!r}, "
            f"unexpected={unexpected!r}.",
            "Define exactly quickstart, lite, standard, and assured in naos_init.PROFILES.",
        ))
        return findings

    invalid_entries = [
        profile
        for profile in PROFILE_ORDER
        if not isinstance(profiles.get(profile), dict)
    ]
    if invalid_entries:
        findings.append(finding(
            "naos_init.py",
            None,
            "error",
            "CTRLCOH_RULES_BLOCKING_PROFILES_UNREADABLE",
            "Canonical profile RULES source is present, but naos_init.PROFILES "
            "contains missing or non-mapping profile entries: "
            + ", ".join(invalid_entries)
            + ".",
            "Restore a literal mapping for every naos_init.PROFILES profile before claiming kit count coherence.",
        ))
        return findings

    invalid_counts = [
        f"{profile}.{field}"
        for profile in PROFILE_ORDER
        for field in ("rules_active", "rules_blocking")
        if type(profiles[profile].get(field)) is not int
    ]
    if invalid_counts:
        findings.append(finding(
            "naos_init.py",
            None,
            "error",
            "CTRLCOH_RULES_BLOCKING_PROFILES_UNREADABLE",
            "Canonical profile RULES source is present, but naos_init.PROFILES "
            "contains missing or non-integer rules_active/rules_blocking values: "
            + ", ".join(invalid_counts)
            + ".",
            "Restore integer rules_active and rules_blocking values for every profile before claiming kit count coherence.",
        ))
        return findings

    actual_active = [profiles[profile]["rules_active"] for profile in PROFILE_ORDER]
    expected_active = [
        len(contract["profiles"][profile]["active_rule_ids"])
        for profile in PROFILE_ORDER
    ]
    if actual_active != expected_active:
        details = []
        for profile, observed, wanted in zip(PROFILE_ORDER, actual_active, expected_active):
            if observed != wanted:
                ids = contract["profiles"][profile]["active_rule_ids"]
                details.append(
                    f"{profile}: actual={observed!r}, expected={wanted}, ids={ids}"
                )
        findings.append(finding(
            "naos_init.py",
            None,
            "error",
            "CTRLCOH_RULES_ACTIVE_SOURCE_MISMATCH",
            "naos_init PROFILES rules_active must equal canonical active-row counts; "
            + "; ".join(details),
            "Align each profile summary count with configs/profile_rules_source.yaml active_rule_ids.",
        ))

    actual_blocking = [profiles[profile]["rules_blocking"] for profile in PROFILE_ORDER]
    expected_blocking = [
        len(contract["profiles"][profile]["blocking_rule_ids"])
        for profile in PROFILE_ORDER
    ]
    if actual_blocking != expected_blocking:
        details = []
        for profile, observed, wanted in zip(PROFILE_ORDER, actual_blocking, expected_blocking):
            if observed != wanted:
                ids = contract["profiles"][profile]["blocking_rule_ids"]
                details.append(
                    f"{profile}: actual={observed!r}, expected={wanted}, ids={ids}"
                )
        findings.append(finding(
            "naos_init.py",
            None,
            "error",
            "CTRLCOH_RULES_BLOCKING_SOURCE_MISMATCH",
            "naos_init PROFILES rules_blocking must equal canonical BLOCKING row counts; "
            + "; ".join(details),
            "Align each profile summary count with configs/profile_rules_source.yaml blocking_rule_ids.",
        ))
    return findings


def check_profile_preset_membership(root: Path) -> list[Finding]:
    """Bind copied reference presets to canonical active RULES membership."""
    canonical_source = root / "configs" / "profile_rules_source.yaml"
    if not canonical_source.is_file() or load_profile_rules_source is None:
        return []
    try:
        contract = load_profile_rules_source(canonical_source, claim_root=root)
    except Exception:
        return []  # The exact-source check reports the canonical error.

    findings: list[Finding] = []
    for profile in PROFILE_ORDER:
        relative = f"templates/profiles/governance-{profile}.yaml"
        path = root / relative
        if not path.is_file():
            findings.append(finding(
                relative,
                None,
                "error",
                "CTRLCOH_PROFILE_PRESET_MISSING",
                f"Canonical profile {profile} has no reference preset.",
                "Restore the reference preset or remove it from the generated-surface contract.",
            ))
            continue
        try:
            preset = load_yaml(path)
        except Exception as exc:
            findings.append(finding(
                relative,
                None,
                "error",
                "CTRLCOH_PROFILE_PRESET_UNREADABLE",
                f"Reference preset is not readable YAML: {exc}",
                "Restore a readable preset with canonical active_rule_ids.",
            ))
            continue
        expected_preset_id = f"governance-{profile}"
        observed_preset_id = preset.get("id") if isinstance(preset, dict) else None
        if observed_preset_id != expected_preset_id:
            findings.append(finding(
                relative,
                None,
                "error",
                "CTRLCOH_PROFILE_PRESET_ID_MISMATCH",
                f"Reference preset id={observed_preset_id!r}; expected {expected_preset_id!r}.",
                "Align the top-level preset id with its canonical profile filename.",
            ))
        rules = preset.get("rules") if isinstance(preset, dict) else None
        observed = rules.get("active_rule_ids") if isinstance(rules, dict) else None
        expected = contract["profiles"][profile]["active_rule_ids"]
        observed_is_integer_list = (
            isinstance(observed, list)
            and all(type(identifier) is int for identifier in observed)
        )
        if not observed_is_integer_list or observed != expected:
            findings.append(finding(
                relative,
                None,
                "error",
                "CTRLCOH_PROFILE_PRESET_MEMBERSHIP_MISMATCH",
                f"Reference preset active_rule_ids={observed!r}; canonical {profile} active_rule_ids={expected!r}.",
                "Align rules.active_rule_ids with configs/profile_rules_source.yaml.",
            ))
        included = rules.get("included") if isinstance(rules, dict) else None
        if not isinstance(included, list):
            included_matches = False
        else:
            references: list[str] = []
            malformed: list[Any] = []
            explicit_ids: list[int] = []
            for item in included:
                if not isinstance(item, dict):
                    malformed.append(item)
                    continue
                identifier = item.get("id")
                reference = item.get("see")
                if identifier is None and reference is None:
                    malformed.append(item)
                    continue
                if reference is not None:
                    if isinstance(reference, str):
                        references.append(reference)
                    else:
                        malformed.append(item)
                if identifier is not None:
                    match = (
                        re.fullmatch(r"RULES-(\d+)", identifier)
                        if isinstance(identifier, str)
                        else None
                    )
                    if match:
                        explicit_ids.append(int(match.group(1)))
                    else:
                        malformed.append(item)
            if references:
                included_matches = (
                    profile == "assured"
                    and references == ["governance-standard.yaml#rules.included"]
                    and not explicit_ids
                    and not malformed
                    and observed == contract["profiles"]["standard"]["active_rule_ids"]
                )
            else:
                included_matches = not malformed and explicit_ids == observed
        if not included_matches:
            findings.append(finding(
                relative,
                None,
                "error",
                "CTRLCOH_PROFILE_PRESET_INCLUDED_MISMATCH",
                "Reference preset rules.included does not resolve to its active_rule_ids declaration.",
                "Align the explicit RULES ids, or use the exact Assured-to-Standard reference.",
            ))
    return findings


def check_profile_schema_portability_claims(root: Path) -> list[Finding]:
    """Keep portability-tier metadata separate from canonical membership."""
    canonical_source = root / "configs" / "profile_rules_source.yaml"
    schema_path = root / "templates" / "profiles" / "schema.yaml"
    if not canonical_source.is_file() or not schema_path.is_file():
        return []
    try:
        schema = load_yaml(schema_path)
    except Exception as exc:
        return [finding(
            "templates/profiles/schema.yaml",
            None,
            "error",
            "CTRLCOH_PROFILE_SCHEMA_UNREADABLE",
            f"Reference profile schema is not readable YAML: {exc}",
            "Restore readable portability-tier metadata.",
        )]
    findings: list[Finding] = []
    profile_schema = schema.get("profile_schema") if isinstance(schema, dict) else None
    tiers = (
        profile_schema.get("rule_portability_levels")
        if isinstance(profile_schema, dict)
        else None
    )
    if not isinstance(tiers, dict):
        return [finding(
            "templates/profiles/schema.yaml",
            None,
            "error",
            "CTRLCOH_PROFILE_SCHEMA_UNREADABLE",
            "Reference profile schema has no mapping at profile_schema.rule_portability_levels.",
            "Restore readable portability-tier metadata.",
        )]
    if set(tiers) != set(EXPECTED_PORTABILITY_DESCRIPTIONS):
        findings.append(finding(
            "templates/profiles/schema.yaml",
            None,
            "error",
            "CTRLCOH_PROFILE_SCHEMA_PORTABILITY_DRIFT",
            "Reference profile schema portability-tier keys do not match the frozen kit taxonomy.",
            "Restore the three reviewed portability tiers or update this guard with an explicit source change.",
        ))
        return findings
    for tier, expected_description in EXPECTED_PORTABILITY_DESCRIPTIONS.items():
        definition = tiers[tier]
        description = definition.get("description") if isinstance(definition, dict) else None
        if description != expected_description:
            findings.append(finding(
                "templates/profiles/schema.yaml",
                None,
                "error",
                "CTRLCOH_PROFILE_SCHEMA_PORTABILITY_DRIFT",
                f"Portability tier {tier!r} description={description!r}; expected {expected_description!r}.",
                "Keep taxonomy wording exact; canonical membership belongs in configs/profile_rules_source.yaml.",
            ))
    return findings


def check_profile_rules_exact(root: Path) -> tuple[list[Finding], dict[str, Any]]:
    """C7: compare kit outputs with the non-output canonical RULES source.

    Generated adopter roots are explicitly not applicable: their local
    ``.ai/RULES.md`` can contain authorized ADAPT changes and must not be treated
    as a corrupted kit artifact.
    """

    if check_profile_rules is None:
        canonical_source = root / "configs" / "profile_rules_source.yaml"
        if canonical_source.is_file():
            report = {
                "schema": "naos.profile_rules_regeneration.v1",
                "status": "failed",
                "applicability": "kit_profile_rules",
                "profiles_checked": [],
                "findings": [
                    {
                        "profile": "all",
                        "rule_id": "PROFILE_RULES_RENDERER_UNAVAILABLE",
                        "message": "naos_profile_rules.py is unavailable beside the canonical source.",
                        "suggested_fix": "Restore the packaged naos_profile_rules.py renderer.",
                    }
                ],
            }
        else:
            report = {
                "schema": "naos.profile_rules_regeneration.v1",
                "status": "not_applicable",
                "applicability": "adopter_local_rules",
                "profiles_checked": [],
                "findings": [],
                "reason": "Exact kit-output parity does not apply to adopter-local RULES.",
            }
    else:
        report = check_profile_rules(root)

    findings = [
        finding(
            str(item.get("profile") or "all"),
            None,
            "error",
            str(item.get("rule_id") or "PROFILE_RULES_CHECK_FAILED"),
            str(item.get("message") or "Profile RULES exact-parity check failed."),
            str(item.get("suggested_fix") or "Regenerate the derived profile RULES outputs."),
        )
        for item in report.get("findings") or []
    ]
    return findings, report


def _calls_effective_enforcement(src: Path) -> bool:
    """True iff the module contains a syntactic effective_enforcement(...) call.

    AST-based so that a mere import, comment, or string mention does not satisfy
    the guard. It intentionally does not claim reachability or result use.
    """
    try:
        tree = ast.parse(src.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else (
            func.attr if isinstance(func, ast.Attribute) else None)
        if name == "effective_enforcement":
            return True
    return False


def check_consumed(root: Path) -> list[Finding]:
    """C6: require a syntactic consumer reference for the 2-D lattice.

    Asserts a call expression in at least one named consumer — the maturity
    evaluator or gate-status layer — rather than a substring match. It does not
    prove reachability or that the returned value controls a runtime decision.
    """
    findings: list[Finding] = []
    root = root.resolve()
    executing_tool_root = Path(__file__).resolve().parent.parent
    tool_roots = (
        [executing_tool_root]
        if executing_tool_root.parent == root
        else [root / "scripts", root / "naos_tools"]
    )
    consumers = [
        tool_root / filename
        for tool_root in tool_roots
        for filename in ("naos_capability_maturity.py", "naos_gate_status.py")
    ]
    present = [c for c in consumers if c.exists()]
    if not present:
        findings.append(
            finding(
                str(tool_roots[0]),
                None,
                "error",
                "CTRLCOH_CONSUMERS_MISSING",
                "Neither required profile-control consumer is present under the generated tool root.",
                "Restore naos_capability_maturity.py or naos_gate_status.py in the active generated tool root.",
            )
        )
        return findings
    if not any(_calls_effective_enforcement(c) for c in present):
        rel = present[0].relative_to(root).as_posix()
        findings.append(finding(rel, None, "error", "CTRLCOH_LATTICE_NOT_CONSUMED",
                                "Per-capability enforcement/target_maturity has no syntactic effective_enforcement(...) call in the named consumer files.",
                                "Add and separately test a reachable effective_enforcement(declared, current, target) decision in the maturity evaluator or gate-status layer."))
    return findings


def build_report(root: Path, policy_path: Path, capabilities_dir: Path, state_path: Path) -> dict[str, Any]:
    findings: list[Finding] = []
    if policy_path.exists():
        policy = load_yaml(policy_path)
        policy_rel = policy_path.relative_to(root).as_posix() if policy_path.is_relative_to(root) else str(policy_path)
        findings += check_severity_by_profile(policy, policy_rel)
        findings += check_exit_code_ramp(policy, policy_rel)
    else:
        findings.append(finding(str(policy_path), None, "warning", "CTRLCOH_POLICY_MISSING",
                                "No default_policy.yaml found; profile/exit-code coherence not checked.",
                                "Provide --policy or run inside a kit/adopter root with a policy."))

    gate_ids = load_gate_ids(root)
    contract_ids: set[str] = set()
    for cap_path in sorted(capabilities_dir.glob("*.yaml")):
        if cap_path.name.startswith("_"):
            continue
        data = load_yaml(cap_path)
        if not isinstance(data, dict) or not data.get("id"):
            continue
        contract_ids.add(str(data["id"]))
        rel = cap_path.relative_to(root).as_posix()
        findings += check_capability(cap_path, data, rel)
        findings += check_gatekeeper_refs(data, gate_ids, rel)

    findings += check_state_ids(state_path, contract_ids, state_path.relative_to(root).as_posix() if state_path.exists() else str(state_path))
    findings += check_consumed(root)
    findings += check_rules_blocking_monotonic(root)
    findings += check_profile_preset_membership(root)
    findings += check_profile_schema_portability_claims(root)
    profile_rules_findings, profile_rules_report = check_profile_rules_exact(root)
    findings += profile_rules_findings

    counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in ("error", "warning", "info")}
    status = "fail" if counts["error"] else "pass"
    return {
        "status": status,
        "capability_count": len(contract_ids),
        "counts": counts,
        "findings": [asdict(f) for f in findings],
        "profile_rules": profile_rules_report,
    }


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate NAOS profile x maturity control coherence.")
    parser.add_argument("--root", default=".", help="Repository or generated-project root.")
    parser.add_argument("--policy", default=None, help="Path to default_policy.yaml.")
    parser.add_argument("--capabilities", default=None, help="Path to capabilities directory.")
    parser.add_argument("--state", default=None, help="Path to capability_state.yaml.")
    parser.add_argument("--json", action="store_true", help="Print full JSON report.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = Path(args.root).resolve()
    policy_path = Path(args.policy) if args.policy else root / "policies" / "default_policy.yaml"
    if not policy_path.exists():
        # generated adopter projects keep policy under naos/policy/
        alt = root / "naos" / "policy" / "default_policy.yaml"
        if alt.exists():
            policy_path = alt
    if args.capabilities:
        capabilities_dir = Path(args.capabilities)
    else:
        # adopter (naos/capabilities) or kit (capabilities) layout
        capabilities_dir = next(
            (c for c in (root / "naos" / "capabilities", root / "capabilities") if c.is_dir()),
            root / "capabilities",
        )
    if args.state:
        state_path = Path(args.state)
    else:
        adopter_state = root / "naos" / "capability_state.yaml"
        state_path = adopter_state if adopter_state.exists() else root / "templates" / "structural-seeds" / "naos" / "capability_state.yaml"

    report = build_report(root, policy_path, capabilities_dir, state_path)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"Profile Control Coherence: {'PASS' if report['status'] == 'pass' else 'FAIL'}")
        print(f"  capabilities: {report['capability_count']}")
        print(f"  findings: {report['counts']}")
        for item in report["findings"]:
            print(f"    [{item['severity']}] {item['rule_id']}: {item['message']}")
            print(f"      fix: {item['suggested_fix']}")
    return 1 if report["status"] == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())
