"""Shared parser and Python import matcher for adopter architecture boundaries."""

from __future__ import annotations

import ast
import fnmatch
from dataclasses import dataclass
from pathlib import Path

import yaml


class BoundaryPolicyError(ValueError):
    """The configured boundary policy cannot be interpreted safely."""


@dataclass(frozen=True)
class BoundaryRule:
    source: str
    target: str
    reason: str
    severity: str = "ERROR"
    legacy: bool = False


@dataclass(frozen=True)
class BoundaryPolicy:
    rules: tuple[BoundaryRule, ...]
    exceptions: tuple[BoundaryRule, ...]
    placeholders: int = 0

    @property
    def status(self) -> str:
        return "configured" if self.rules else "unconfigured"


@dataclass(frozen=True)
class BoundaryFinding:
    source: str
    target: str
    reason: str
    severity: str
    line: int


def _pattern(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BoundaryPolicyError(f"{label} must be a nonempty string")
    return value.strip()


def _is_placeholder(value: str) -> bool:
    return value.startswith("[ADAPT:") and value.endswith("]")


def _path_rules(
    items: object, label: str, *, exceptions: bool = False
) -> tuple[list[BoundaryRule], int]:
    if not isinstance(items, list):
        raise BoundaryPolicyError(f"{label} must be a list")
    rules: list[BoundaryRule] = []
    placeholders = 0
    for number, item in enumerate(items, 1):
        at = f"{label}[{number}]"
        if not isinstance(item, dict):
            raise BoundaryPolicyError(f"{at} must be a mapping")
        source = _pattern(item.get("from"), f"{at}.from")
        target = _pattern(item.get("to"), f"{at}.to")
        if _is_placeholder(source) or _is_placeholder(target):
            if _is_placeholder(source) and _is_placeholder(target) and not exceptions:
                placeholders += 1
                continue
            raise BoundaryPolicyError(f"{at} has an incomplete placeholder")
        reason = item.get("reason", "")
        if not isinstance(reason, str):
            raise BoundaryPolicyError(f"{at}.reason must be a string")
        severity = item.get("severity", "ERROR")
        if severity not in ("ERROR", "WARNING"):
            raise BoundaryPolicyError(f"{at}.severity must be ERROR or WARNING")
        rules.append(BoundaryRule(source, target, reason, severity))
    return rules, placeholders


def load_boundary_policy(path: Path) -> BoundaryPolicy:
    """Accept the shipped from/to form and historic boundaries[].module form."""
    if not path.exists():
        return BoundaryPolicy((), ())
    try:
        with path.open(encoding="utf-8") as stream:
            data = yaml.safe_load(stream)
    except (OSError, yaml.YAMLError) as exc:
        raise BoundaryPolicyError(f"cannot read {path}: {exc}") from exc
    if data is None:
        return BoundaryPolicy((), ())
    if not isinstance(data, dict):
        raise BoundaryPolicyError("boundary policy must be a mapping")
    rules, placeholders = _path_rules(
        data.get("forbidden_imports", []), "forbidden_imports"
    )
    exceptions, _ = _path_rules(
        data.get("allowed_exceptions", []), "allowed_exceptions", exceptions=True
    )
    legacy = data.get("boundaries", [])
    if not isinstance(legacy, list):
        raise BoundaryPolicyError("boundaries must be a list")
    for number, item in enumerate(legacy, 1):
        at = f"boundaries[{number}]"
        if not isinstance(item, dict):
            raise BoundaryPolicyError(f"{at} must be a mapping")
        module = _pattern(item.get("module"), f"{at}.module")
        imports = item.get("forbidden_imports")
        if not isinstance(imports, list) or not imports:
            raise BoundaryPolicyError(f"{at}.forbidden_imports must be a nonempty list")
        severity = item.get("severity", "ERROR")
        if severity not in ("ERROR", "WARNING"):
            raise BoundaryPolicyError(f"{at}.severity must be ERROR or WARNING")
        for index, target in enumerate(imports, 1):
            target = _pattern(target, f"{at}.forbidden_imports[{index}]")
            rules.append(
                BoundaryRule(
                    module,
                    target,
                    f"module '{module}' forbids '{target}'",
                    severity,
                    True,
                )
            )
    return BoundaryPolicy(tuple(rules), tuple(exceptions), placeholders)


def _path_matches(pattern: str, path: str) -> bool:
    normalized = pattern.replace("\\", "/")
    if "/" not in normalized and not normalized.endswith(".py"):
        normalized = normalized.replace(".", "/")
    return fnmatch.fnmatchcase(path, normalized)


def _source_prefix(source_root: Path, root: Path) -> str:
    if source_root.is_absolute():
        source_root = source_root.relative_to(root)
    normalized = source_root.as_posix().rstrip("/")
    return "" if normalized == "." else normalized


def _target_paths(imported: str, roots: tuple[Path, ...], root: Path) -> set[str]:
    base = imported.replace(".", "/")
    candidates = {base, base + ".py", base + "/__init__.py"}
    for source_root in roots:
        prefix = _source_prefix(source_root, root)
        if not prefix or base.startswith(prefix + "/"):
            continue
        candidate = prefix + "/" + base
        # An unqualified import is project-local only when a source target exists.
        if (root / (candidate + ".py")).exists() or (root / candidate).is_dir():
            candidates.update(
                (candidate, candidate + ".py", candidate + "/__init__.py")
            )
    return candidates


def _imports(path: Path, root: Path) -> list[tuple[str, int]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return []
    package = path.relative_to(root).with_suffix("").parts[:-1]
    imports: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend((alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            prefix = package[: len(package) - node.level + 1] if node.level else ()
            base = ".".join((*prefix, *(node.module.split(".") if node.module else ())))
            if base:
                imports.append((base, node.lineno))
            for alias in node.names:
                if alias.name != "*" and base:
                    imports.append((base + "." + alias.name, node.lineno))
    return imports


def find_boundary_violations(
    path: Path, root: Path, roots: tuple[Path, ...], policy: BoundaryPolicy
) -> list[BoundaryFinding]:
    """Match a source file's imports against one normalized policy."""
    source = path.relative_to(root).as_posix()
    findings: list[BoundaryFinding] = []
    seen: set[tuple[str, int, BoundaryRule]] = set()
    for imported, line in _imports(path, root):
        targets = _target_paths(imported, roots, root)
        for rule in policy.rules:
            if rule.legacy:
                module = rule.source.replace(".", "/")
                belongs = any(
                    source.startswith(
                        "/".join(
                            part for part in (_source_prefix(p, root), module) if part
                        )
                        + "/"
                    )
                    for p in roots
                )
                matched = imported == rule.target or imported.startswith(
                    rule.target + "."
                )
            else:
                belongs = _path_matches(rule.source, source)
                matched = any(_path_matches(rule.target, target) for target in targets)
            if not belongs or not matched or (imported, line, rule) in seen:
                continue
            exempt = any(
                _path_matches(exception.source, source)
                and any(_path_matches(exception.target, target) for target in targets)
                for exception in policy.exceptions
            )
            if not exempt:
                findings.append(
                    BoundaryFinding(source, imported, rule.reason, rule.severity, line)
                )
                seen.add((imported, line, rule))
    return findings
