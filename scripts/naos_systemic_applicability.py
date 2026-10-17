"""Explicit repository-role projection for systemic artifact declarations.

Missing artifacts never select a role or prove inapplicability. Callers obtain
the role from the existing repository contract and retain rejected declarations
as unresolved findings. This module does not grant review or execution authority.
"""

from __future__ import annotations

import re
from typing import Any

import yaml


REPOSITORY_ROLES = {"kit_source", "adopter_project"}
ROLE_PATTERN_FIELDS = ("file_patterns", "minimum_expected", "review_source_patterns")


def validate_review_patterns(patterns: Any) -> None:
    """Review inputs use explicit portable project-relative glob patterns."""
    if (
        not isinstance(patterns, list)
        or not patterns
        or any(not isinstance(item, str) or not item for item in patterns)
        or len(patterns) != len(set(patterns))
    ):
        raise ValueError("review_source_patterns must contain unique nonempty patterns")
    for pattern in patterns:
        if (
            "\\" in pattern
            or ":" in pattern
            or any(ord(char) < 32 for char in pattern)
            or any(part in {"", ".", ".."} for part in pattern.split("/"))
        ):
            raise ValueError(
                "review_source_patterns must remain project-relative and portable"
            )


def validate_adopter_routing(routing: Any) -> None:
    """Reject ambiguous authored routes before matching or review closure.

    Legacy routes without adopter_patterns retain their validation controls.
    Authored routes satisfy the existing routing-family shape, with the new
    explicit pattern field; target existence/duplicate IDs remain the existing
    relationship-integrity check's responsibility.
    """
    if not isinstance(routing, dict):
        raise ValueError("changed_path_routing must be a mapping")
    routes = routing.get("routing_families", [])
    if not isinstance(routes, list):
        raise ValueError("routing_families must be a list")
    for route in routes:
        if not isinstance(route, dict):
            raise ValueError("routing_families entries must be mappings")
        if "adopter_patterns" not in route:
            continue
        route_id = route.get("route_id")
        if not isinstance(route_id, str) or re.fullmatch(r"route_[a-z0-9_]+", route_id) is None:
            raise ValueError("Authored adopter route_id must match route_[a-z0-9_]+")
        if not isinstance(route.get("name"), str) or not route["name"].strip():
            raise ValueError("Authored adopter route name must be a nonempty string")
        for field in ("source_patterns", "generated_patterns", "review_triggers", "targets"):
            values = route.get(field)
            if (
                not isinstance(values, list)
                or (field in {"review_triggers", "targets"} and not values)
                or any(not isinstance(value, str) or not value.strip() for value in values)
            ):
                raise ValueError(f"Authored adopter route {field} must have its declared string-list shape")
        if "required_review_outputs" in route and (
            not isinstance(route["required_review_outputs"], list)
            or any(not isinstance(value, str) for value in route["required_review_outputs"])
        ):
            raise ValueError("Authored adopter route required_review_outputs must be a string list")
        try:
            validate_review_patterns(route["adopter_patterns"])
            if any(not item.strip() for item in route["adopter_patterns"]):
                raise ValueError("patterns must not be blank")
        except ValueError as exc:
            raise ValueError(f"adopter_patterns: {exc}") from exc


def load_rule_document(text: str) -> dict[str, Any]:
    """Reject ambiguous explicit keys/identities; retain YAML merge precedence."""

    class RuleLoader(yaml.SafeLoader):
        def flatten_mapping(self, node):
            # SafeLoader may flatten an anchored mapping more than once. Check
            # its explicit syntax once, before merge expansion adds inherited keys.
            checked = getattr(self, "checked_mappings", set())
            if id(node) not in checked:
                seen = set()
                for key_node, _ in node.value:
                    key = (
                        "<<"
                        if key_node.tag == "tag:yaml.org,2002:merge"
                        else self.construct_object(key_node)
                    )
                    if not isinstance(key, str) or key in seen:
                        raise ValueError(
                            "Duplicate or nonstring systemic rules mapping key"
                        )
                    seen.add(key)
                checked.add(id(node))
                self.checked_mappings = checked
            return super().flatten_mapping(node)

    document = yaml.load(text, Loader=RuleLoader)
    if not isinstance(document, dict):
        raise ValueError("Systemic rules must be a mapping")
    for field, identity in (
        ("artifact_families", "family_id"),
        ("review_surfaces", "surface_id"),
    ):
        rows = document.get(field, [])
        if not isinstance(rows, list):
            raise ValueError(f"{field} must be a list")
        seen = set()
        for row in rows:
            name = row.get(identity) if isinstance(row, dict) else None
            if not isinstance(name, str) or not name or name in seen:
                raise ValueError(f"Invalid or duplicate {identity}")
            seen.add(name)
    validate_adopter_routing(document.get("changed_path_routing", {}))
    return document


def role_family(family: dict[str, Any], repository_role: str) -> dict[str, Any]:
    """Validate and project explicitly declared patterns without mutating rules."""
    if repository_role not in REPOSITORY_ROLES:
        raise ValueError("Unknown repository role")
    result = dict(family)
    if "review_source_patterns" in family:
        validate_review_patterns(family["review_source_patterns"])
    roles = family.get("repository_roles", sorted(REPOSITORY_ROLES))
    if (
        not isinstance(roles, list)
        or not roles
        or any(
            not isinstance(role, str) or role not in REPOSITORY_ROLES for role in roles
        )
        or len(roles) != len(set(roles))
    ):
        raise ValueError(
            "repository_roles must be a unique nonempty list of supported roles"
        )
    # Validate all branches: a malformed declaration must not become a valid
    # exemption simply because the caller selected another role.
    for field in ROLE_PATTERN_FIELDS:
        key = field + "_by_role"
        if key not in family:
            continue
        mapping = family[key]
        if (
            not isinstance(mapping, dict)
            or not mapping
            or set(mapping) - REPOSITORY_ROLES
        ):
            raise ValueError(f"{key} must map supported roles to pattern lists")
        for patterns in mapping.values():
            if field == "review_source_patterns":
                validate_review_patterns(patterns)
            if (
                not isinstance(patterns, list)
                or not patterns
                or any(
                    not isinstance(pattern, str) or not pattern.strip()
                    for pattern in patterns
                )
                or len(patterns) != len(set(patterns))
            ):
                raise ValueError(
                    f"{key} must contain nonempty unique string pattern lists"
                )
        if repository_role in mapping:
            result[field] = list(mapping[repository_role])
    result["_role_applicability"] = {
        "repository_role": repository_role,
        "applicable": repository_role in roles,
        "declared_roles": list(roles),
        "reason": (
            "Repository role included in explicit declaration."
            if "repository_roles" in family and repository_role in roles
            else "Repository role excluded by explicit declaration."
            if repository_role not in roles
            else "No role restriction declared; existing applicability retained."
        ),
    }
    return result
