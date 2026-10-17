#!/usr/bin/env python3
"""Shared source-root resolution for brownfield NAOS adopters."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping

DEFAULT_SOURCE_ROOT_NAMES = ("src", "app", "apps", "packages", "lib")


def split_source_root(value: str | None) -> list[Path]:
    """Parse a comma-separated source-root value into paths."""
    return [Path(item.strip()) for item in (value or "").split(",") if item.strip()]


def resolve_source_roots(
    root: Path | None = None,
    src_root: str | None = None,
    *,
    env: Mapping[str, str] | None = None,
    fallback: bool = True,
    absolute: bool = False,
) -> list[Path]:
    """Return explicit or inferred source roots.

    Explicit ``SRC_ROOT`` values are returned even when they do not exist, so
    callers can report exactly what was configured. Without an explicit value,
    common brownfield roots are inferred when present.
    """
    base = root or Path.cwd()
    source_value = src_root
    if source_value is None:
        source_value = (env or os.environ).get("SRC_ROOT")

    if source_value:
        roots = split_source_root(source_value)
    else:
        roots = [
            Path(name)
            for name in DEFAULT_SOURCE_ROOT_NAMES
            if (base / name).is_dir()
        ]
        if not roots and fallback:
            roots = [Path("src")]

    if absolute:
        return [path if path.is_absolute() else base / path for path in roots]
    return roots


def existing_source_roots(
    root: Path | None = None,
    src_root: str | None = None,
    *,
    env: Mapping[str, str] | None = None,
    absolute: bool = False,
) -> list[Path]:
    """Return configured source roots that currently exist."""
    base = root or Path.cwd()
    roots = resolve_source_roots(base, src_root, env=env, absolute=absolute)
    existing: list[Path] = []
    for path in roots:
        candidate = path if path.is_absolute() else base / path
        if candidate.exists():
            existing.append(path)
    return existing


def source_roots_display(roots: list[Path]) -> str:
    """Render source roots for human-readable messages."""
    return ", ".join(str(root) for root in roots) if roots else "none"


def source_exclusion_reason(path: Path, project_root: Path, patterns: list[str]) -> str | None:
    """Lexical, case-sensitive project-relative selection; not a filesystem guard."""
    try:
        relative = path.relative_to(project_root)
    except ValueError:
        return "outside_project"
    if ".." in relative.parts:
        return "outside_project"
    for pattern in patterns:
        if pattern.startswith("."):
            if relative.suffix == pattern:
                return "suffix:" + pattern
        elif pattern in relative.parent.parts:
            return "directory:" + pattern
    return None


def iter_function_index_modules(index: dict, prefix: tuple[str, ...] = (), _ancestors: frozenset[int] = frozenset()):
    """Yield code leaves at any depth, including legacy file/directory collisions."""
    if id(index) in _ancestors:
        raise ValueError("Cyclic function index mapping")
    ancestors = _ancestors | {id(index)}
    for key, value in index.items():
        if not isinstance(value, dict):
            continue
        parts = prefix if key == "_self" else (*prefix, str(key))
        if any(field in value for field in ("public", "classes", "purpose")):
            yield parts, value
        yield from iter_function_index_modules(value, parts, ancestors)


# Finite lexical reference coverage, not language parsing or implementation proof.
IMPLEMENTATION_SUFFIXES = frozenset({".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".cs", ".rb", ".php"})


def implementation_source_files(roots: list[Path]) -> list[Path]:
    """Lexical suffix selection and root deduplication, not a confinement guard."""
    files: dict[Path, Path] = {}
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if path.suffix in IMPLEMENTATION_SUFFIXES:
                if path.is_file():
                    files.setdefault(Path(os.path.abspath(path)), path)
    return sorted(files.values())


INFERRED_ADOPTER_ROOTS = frozenset({"src", "app", "apps", "packages", "services", "lib", "libs", "cmd", "tests"})

def native_adopter_root_aliases(root: Path, physical_names):
    """Known root spelling only after actual no-link directory identity matches."""
    import stat
    def directory_identity(path):
        try:
            m = path.lstat()
        except OSError:
            return None
        if not stat.S_ISDIR(m.st_mode) or stat.S_ISLNK(m.st_mode) or getattr(m, "st_file_attributes", 0) & 0x400:
            return None
        return m.st_dev, m.st_ino
    if directory_identity(root) is None:
        return {}
    known = {identity: name for name in sorted(INFERRED_ADOPTER_ROOTS)
             if (identity := directory_identity(root / name)) is not None}
    return {name: known[identity] for name in set(physical_names)
            if (identity := directory_identity(root / name)) in known}


def is_native_python_package_marker(path: Path):
    """Exact __init__.py, or its observed native filename alias; no body read."""
    import stat
    try:
        parent = path.parent.lstat()
        actual, expected = path.lstat(), (path.parent / "__init__.py").lstat()
    except OSError:
        return False
    return (stat.S_ISDIR(parent.st_mode) and not stat.S_ISLNK(parent.st_mode)
            and not getattr(parent, "st_file_attributes", 0) & 0x400
            and all(stat.S_ISREG(m.st_mode) and m.st_nlink == 1
                    and not getattr(m, "st_file_attributes", 0) & 0x400 for m in (actual, expected))
            and (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino))


def declared_package_roots(root: Path):
    """Concrete supported pyproject roots; declarations do not prove runtime imports."""
    import stat
    import tomllib
    from pathlib import PureWindowsPath
    from naos_secret_managed_operands import ProofBudget, OperandRefusal
    project = root / "pyproject.toml"
    try:
        before = project.lstat()
    except FileNotFoundError:
        return [], []
    except OSError:
        return [], [{"path": "pyproject.toml", "status": "package_declaration_unreadable"}]
    class UnassessedDeclaration(ValueError):pass
    rows = []
    try:
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 1024 * 1024 or getattr(before, "st_file_attributes", 0) & 0x400:
            raise ValueError("unsupported declaration snapshot")
        observer = ProofBudget(root)
        data = tomllib.loads(observer.read("pyproject.toml").decode("utf-8"))
        observer.verify_cached()
        if project.lstat().st_nlink != 1:raise ValueError("declaration link count changed")
        def table(parent, key):
            value = parent.get(key, {})
            if not isinstance(value, dict):raise ValueError("invalid package table")
            return value
        def path(value, *, allow_root=False):
            if not isinstance(value, str):raise ValueError("package path must be string")
            if value.count("/") + value.count("\\") >= 64:raise ValueError("package path depth limit")
            if value == ".":
                if not allow_root:raise UnassessedDeclaration("broad root without concrete package names")
                return root
            windows = PureWindowsPath(value);ref = Path(value)
            if (not value or ref.is_absolute() or windows.drive or windows.root or value in {".", ""}
                or any(part in {"..", "."} for part in value.replace("\\", "/").split("/"))
                or any(char in value for char in "*?[]{}") or any(ord(char) < 32 or ord(char) == 127 for char in value) or "\\" in value or ":" in value):raise ValueError("nonconcrete package root")
            candidate = root / ref
            for ancestor in reversed([candidate, *candidate.parents]):
                if not ancestor.is_relative_to(root):continue
                m = ancestor.lstat()
                if stat.S_ISLNK(m.st_mode) or getattr(m, "st_file_attributes", 0) & 0x400:raise ValueError("linked package root")
                if ancestor != candidate and not stat.S_ISDIR(m.st_mode):raise ValueError("non-directory package ancestor")
            if not stat.S_ISDIR(m.st_mode) and not (stat.S_ISREG(m.st_mode) and m.st_nlink == 1 and candidate.suffix == ".py"):raise ValueError("unsupported package root kind")
            return candidate
        def add(value, *, name=None, namespace=False, flat_only=False):
            if len(rows) >= 256:raise ValueError("package declaration entry limit")
            if name and (name.count(".") >= 64 or not all(part.isidentifier() for part in name.split("."))):raise ValueError("invalid declared package name")
            rows.append({"root": path(value, allow_root=flat_only), "name": name, "namespace": namespace, "flat_only": flat_only})
        tool = table(data, "tool");setuptools = table(tool, "setuptools")
        package_dirs = table(setuptools, "package-dir")
        for name, value in package_dirs.items():
            if value == "." and not name:continue  # Resolve only exact listed/find names below.
            add(value, name=name or None, flat_only=value == "." and bool(name))
        packages = setuptools.get("packages", {})
        if isinstance(packages, dict):
            find = table(packages, "find")
            where = find.get("where", [])
            if not isinstance(where, list) or type(find.get("namespaces", True)) is not bool:raise ValueError("invalid package finder")
            for value in where:
                if value != ".":add(value, namespace=find.get("namespaces", True));continue
                include = find.get("include", [])
                if not isinstance(include, list) or not include:raise UnassessedDeclaration("where root requires finite exact include names")
                for name in include:
                    if not isinstance(name, str) or not all(part.isidentifier() for part in name.split(".")):
                        raise UnassessedDeclaration("broad find include remains unassessed")
                    add(name.replace(".", "/"), name=name, namespace=find.get("namespaces", True))
        elif isinstance(packages, list):
            for name in packages:
                if not isinstance(name, str) or not all(part.isidentifier() for part in name.split(".")):raise ValueError("invalid listed package")
                mappings = [(key, value) for key, value in package_dirs.items() if key and (name == key or name.startswith(key + "."))]
                if mappings:
                    key, base = max(mappings, key=lambda item: len(item[0]))
                    tail = name[len(key):].lstrip(".").replace(".", "/")
                    if not tail:continue  # Exact mapping was admitted above.
                    add(("" if base == "." else base + "/") + tail, name=name)
                else:
                    base = package_dirs.get("", "")
                    add(("" if base in {"", "."} else base + "/") + name.replace(".", "/"), name=name)
        else:raise ValueError("invalid setuptools packages")
        poetry = table(tool, "poetry")
        declarations = poetry.get("packages", [])
        if not isinstance(declarations, list):raise ValueError("invalid Poetry packages")
        for declaration in declarations:
            if not isinstance(declaration, dict) or not isinstance(declaration.get("include"), str) or not isinstance(declaration.get("from", ""), str):raise ValueError("invalid Poetry package")
            include = declaration["include"];base = declaration.get("from", "")
            if base == ".":base = ""
            add(base + "/" + include if base else include, name=include.rsplit("/", 1)[-1].removesuffix(".py"))
        wheel = table(table(table(table(tool, "hatch"), "build"), "targets"), "wheel")
        declarations = wheel.get("packages", [])
        if not isinstance(declarations, list):raise ValueError("invalid Hatch wheel packages")
        for value in declarations:add(value, name=value.rsplit("/", 1)[-1] if isinstance(value, str) else None)
        return rows, []
    except UnassessedDeclaration:
        return [], [{"path": "pyproject.toml", "status": "package_declaration_unassessed"}]
    except (OSError, ValueError, UnicodeError, RecursionError, OperandRefusal):
        return [], [{"path": "pyproject.toml", "status": "package_declaration_invalid"}]


def declared_path_contains(root: Path, path: Path, declared: Path):
    """Concrete declaration prefix with native alias identity, no case folding."""
    import stat
    depth = len(declared.relative_to(root).parts)
    parts = path.relative_to(root).parts
    if len(parts) < depth:return False
    prefix = root.joinpath(*parts[:depth])
    try:
        actual, expected = prefix.lstat(), declared.lstat()
    except OSError:return False
    return (not any(stat.S_ISLNK(m.st_mode) or getattr(m, "st_file_attributes", 0) & 0x400 for m in (actual, expected))
            and (actual.st_dev, actual.st_ino, stat.S_IFMT(actual.st_mode)) == (expected.st_dev, expected.st_ino, stat.S_IFMT(expected.st_mode)))


def declared_package_selects(root: Path, path: Path, declaration):
    if declaration.get("flat_only"):
        return path.parent == root
    return declared_path_contains(root, path, declaration["root"])


def inferred_adopter_python_files(root: Path, *, inventory=None, pruned_directories=None):
    return inferred_adopter_implementation_files(root, inventory=inventory, pruned_directories=pruned_directories, suffixes={".py"})


def inferred_adopter_implementation_files(root: Path, *, inventory=None, pruned_directories=None, suffixes=IMPLEMENTATION_SUFFIXES):
    """Additive bounded inference; existing source-root APIs stay unchanged.

    A supplied no-follow metadata inventory shares its caller's traversal budget.
    Context discovery otherwise uses its own 50000-entry/64-depth metadata bound.
    Unknown layouts and non-Python semantics are not inferred.
    """
    import stat
    root = root.absolute()
    issues = []
    if inventory is None:
        inventory = {};pending = [root];seen = set();reserved = {root}
        excluded = {".git", ".hg", ".svn", ".naos", ".venv", "venv", "node_modules", "dev", "dist", "build", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", "htmlcov"}
        while pending:
            path = pending.pop()
            if path in seen:continue
            seen.add(path)
            if len(seen) > 50000:
                issues.append({"path": ".", "status": "entry_limit"});break
            rel = path.relative_to(root)
            if len(rel.parts) > 64:
                issues.append({"path": rel.as_posix(), "status": "depth_limit"});continue
            if any(part in excluded for part in rel.parts):
                if pruned_directories is not None:
                    try:
                        m = path.lstat()
                        if stat.S_ISDIR(m.st_mode) and not stat.S_ISLNK(m.st_mode) and not getattr(m, "st_file_attributes", 0) & 0x400:
                            pruned_directories.append({"path": rel.as_posix(), "kind": "directory", "descendants_enumerated": False})
                    except OSError:
                        pass  # Excluded namespace stays pruned; no observed directory claim.
                continue
            try:
                m = path.lstat()
                if stat.S_ISLNK(m.st_mode) or getattr(m, "st_file_attributes", 0) & 0x400:
                    issues.append({"path": rel.as_posix(), "status": "symlink"});continue
                if stat.S_ISDIR(m.st_mode):
                    inventory[path] = "directory";children = []
                    with os.scandir(path) as entries:
                        for entry in entries:
                            if len(reserved) >= 50000:
                                issues.append({"path": rel.as_posix(), "status": "entry_limit"});break
                            child = path / entry.name
                            reserved.add(child)
                            children.append(child)
                    pending.extend(reversed(sorted(children)))
                elif stat.S_ISREG(m.st_mode):
                    if m.st_nlink != 1:
                        issues.append({"path": rel.as_posix(), "status": "hardlink"});continue
                    inventory[path] = "selected" if path.suffix in suffixes else "unselected_suffix"
                else:issues.append({"path": rel.as_posix(), "status": "nonregular"})
            except OSError:issues.append({"path": rel.as_posix(), "status": "discovery_error"})
    discovered = sorted(path for path, status in inventory.items() if status in {"selected", "unselected_suffix"} and path.suffix in suffixes)
    declarations, declaration_issues = declared_package_roots(root)
    issues.extend(declaration_issues)
    aliases = native_adopter_root_aliases(root, (path.relative_to(root).parts[0] for path in discovered if len(path.relative_to(root).parts) > 1))
    packages = {path.relative_to(root).parts[0] for path in discovered
                if len(path.relative_to(root).parts) == 2 and is_native_python_package_marker(path)}
    # A supplied inventory may name the same native common directory twice.
    # Deduplicate only that known root alias and identical remaining spelling;
    # this is not hardlink/file-name normalization or a general identity proof.
    files, logical = [], set()
    for path in discovered:
        parts = path.relative_to(root).parts
        if (len(parts) != 1 and parts[0] not in aliases and parts[0] not in packages
            and not any(declared_package_selects(root, path, row) for row in declarations)):
            continue
        key = (aliases.get(parts[0], parts[0]), parts[1:]) if len(parts) > 1 else (parts[0], ())
        if key not in logical:
            logical.add(key);files.append(path)
    return files, issues
