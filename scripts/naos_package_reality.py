#!/usr/bin/env python3
"""Review declared Python package reality without network calls by default."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    load_policy,
    normalize_profile,
    report_output_path,
    severity_for_profile,
    status_from_counts,
    write_report,
)


SCHEMA = "naos.package_reality.v1"
NOT_CLAIMED = [
    "package safety proof",
    "malware detection",
    "vulnerability scanning",
    "supply-chain assurance",
    "registry trust proof",
    "license approval",
    "dependency freshness proof",
    "installation approval",
    "SBOM completeness proof",
    "provenance authenticity proof",
    "hash attestation proof",
    "approval",
    "certification",
    "proof of compliance",
    "hallucination prevention",
]
LIMITATIONS = [
    "Offline mode checks repository-local declarations, lock-style pins, configured allowlists, and optional documentation install snippets only.",
    "Online registry checks are disabled by default and require explicit operator consent.",
    "Registry existence does not prove a package is safe, maintained, vulnerability-free, legitimate, or appropriate for use.",
    "Name-similarity findings are heuristic review evidence and can false-positive on legitimate package names.",
    "Private registries and non-PyPI package sources require adopter-owned review and allowlists.",
    "Local SBOM and provenance inputs are checked for declared evidence shape only; they are not proof that the inventory is complete, authentic, or current.",
    "Hash cross-checks compare configured local evidence only; they do not download artifacts or verify registry-hosted distributions.",
]
DEFAULT_RULES = {
    "manifest_files": ["pyproject.toml", "requirements.txt", "requirements/*.txt"],
    "lock_files": ["requirements.txt", "requirements/*.txt", "poetry.lock", "uv.lock", "Pipfile.lock"],
    "docs_roots": ["README.md", "docs", "INSTALLATION_MANUAL.md"],
    "sbom_files": ["bom.json", "*.cdx.json", "sbom/*.json", "sbom/*.cdx.json"],
    "provenance_files": ["naos/package_reality_provenance.yaml"],
    "exclude_dirs": [".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__", "dev"],
    "allowlisted_packages": [],
    "known_packages": [
        "beautifulsoup4",
        "click",
        "django",
        "fastapi",
        "flask",
        "httpx",
        "jinja2",
        "jsonschema",
        "numpy",
        "pandas",
        "pillow",
        "pydantic",
        "pytest",
        "python-dotenv",
        "pyyaml",
        "requests",
        "scikit-learn",
        "sqlalchemy",
        "typer",
        "uvicorn",
    ],
    "typo_distance_threshold": 1,
    "require_lockfile_entries": True,
    "require_declared_packages_in_sbom": False,
    "scan_docs_by_default": False,
}
PROVENANCE_SCHEMA = "naos.package_reality_provenance.v1"
HASH_ALG_ALIASES = {
    "SHA256": "SHA-256",
    "SHA-256": "SHA-256",
    "SHA384": "SHA-384",
    "SHA-384": "SHA-384",
    "SHA512": "SHA-512",
    "SHA-512": "SHA-512",
    "MD5": "MD5",
    "BLAKE2B256": "BLAKE2B-256",
    "BLAKE2B-256": "BLAKE2B-256",
}
HASH_HEX_LENGTHS = {
    "MD5": 32,
    "SHA-256": 64,
    "SHA-384": 96,
    "SHA-512": 128,
    "BLAKE2B-256": 64,
}
PROVENANCE_EVIDENCE_OUTCOMES = {"present", "passing", "reviewed"}


def utc_now() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def strip_inline_comment(line: str) -> str:
    in_quote: str | None = None
    for index, char in enumerate(line):
        if char in {"'", '"'}:
            in_quote = None if in_quote == char else char
        if char == "#" and in_quote is None:
            return line[:index]
    return line


def parse_requirement_line(line: str) -> tuple[str | None, bool]:
    cleaned = strip_inline_comment(line).strip()
    if not cleaned or cleaned.startswith(("-", "git+", "http://", "https://")):
        return None, False
    match = re.match(r"([A-Za-z0-9][A-Za-z0-9_.-]*)(.*)", cleaned)
    if not match:
        return None, False
    name = normalize_package_name(match.group(1))
    suffix = match.group(2)
    pinned = "==" in suffix or "===" in suffix or " @ " in cleaned or cleaned.startswith(f"{match.group(1)} @")
    return name, pinned


def add_package(packages: dict[str, dict[str, Any]], name: str, source: str, *, pinned: bool) -> None:
    item = packages.setdefault(
        name,
        {
            "name": name,
            "sources": [],
            "pinned_sources": [],
            "declared": False,
            "lockfile_entry": False,
        },
    )
    item["sources"].append(source)
    item["declared"] = True
    if pinned:
        item["pinned_sources"].append(source)
        item["lockfile_entry"] = True


def parse_requirements(path: Path, root: Path, packages: dict[str, dict[str, Any]]) -> None:
    rel = relative(path, root)
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        name, pinned = parse_requirement_line(line)
        if name:
            add_package(packages, name, rel, pinned=pinned)


def parse_pyproject(path: Path, root: Path, packages: dict[str, dict[str, Any]]) -> None:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return
    rel = relative(path, root)
    project = data.get("project") if isinstance(data, dict) else {}
    deps = list(project.get("dependencies") or []) if isinstance(project, dict) else []
    optional = project.get("optional-dependencies") if isinstance(project, dict) else {}
    if isinstance(optional, dict):
        for values in optional.values():
            if isinstance(values, list):
                deps.extend(values)
    poetry_deps = (((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}) if isinstance(data, dict) else {}
    if isinstance(poetry_deps, dict):
        deps.extend(name for name in poetry_deps if str(name).lower() != "python")
    for dep in deps:
        name, pinned = parse_requirement_line(str(dep))
        if name and name != "python":
            add_package(packages, name, rel, pinned=pinned)


def load_declared_packages(root: Path, rules: dict[str, Any]) -> dict[str, dict[str, Any]]:
    packages: dict[str, dict[str, Any]] = {}
    for path in expand_patterns(root, list_value(rules.get("manifest_files"))):
        if path.name == "pyproject.toml":
            parse_pyproject(path, root, packages)
        elif path.suffix == ".txt":
            parse_requirements(path, root, packages)
    return packages


def load_lockfile_packages(root: Path, rules: dict[str, Any]) -> set[str]:
    locked: set[str] = set()
    for path in expand_patterns(root, list_value(rules.get("lock_files"))):
        text = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix == ".txt":
            for line in text.splitlines():
                name, pinned = parse_requirement_line(line)
                if name and pinned:
                    locked.add(name)
        elif path.name == "poetry.lock":
            locked.update(normalize_package_name(match.group(1)) for match in re.finditer(r'^name\s*=\s*"([^"]+)"', text, re.MULTILINE))
        elif path.name == "uv.lock":
            locked.update(normalize_package_name(match.group(1)) for match in re.finditer(r'^name\s*=\s*"([^"]+)"', text, re.MULTILINE))
        elif path.name == "Pipfile.lock":
            try:
                data = json.loads(text)
            except Exception:
                data = {}
            for section in ("default", "develop"):
                value = data.get(section) if isinstance(data, dict) else {}
                if isinstance(value, dict):
                    locked.update(normalize_package_name(name) for name in value)
    return locked


def list_value(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return [str(value)] if str(value) else []


def expand_patterns(root: Path, patterns: list[str]) -> list[Path]:
    paths: list[Path] = []
    for pattern in patterns:
        candidate = root / pattern
        if any(ch in pattern for ch in "*?["):
            paths.extend(path for path in root.glob(pattern) if path.is_file())
        elif candidate.is_file():
            paths.append(candidate)
    return sorted(set(paths))


def relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def is_within_root(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def project_reference_path(root: Path, raw_path: Any) -> Path:
    value = str(raw_path or "").strip()
    if not value:
        return root
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    return candidate


def normalize_hash_alg(value: Any) -> str | None:
    raw = str(value or "").strip().upper()
    if not raw:
        return None
    compact = re.sub(r"[\s_]+", "-", raw)
    compact = compact.replace("BLAKE2B-", "BLAKE2B")
    return HASH_ALG_ALIASES.get(compact, HASH_ALG_ALIASES.get(raw.replace("_", "").replace("-", "")))


def normalize_hash_value(value: Any) -> str | None:
    raw = str(value or "").strip().lower()
    if not raw:
        return None
    if ":" in raw:
        raw = raw.rsplit(":", 1)[-1]
    return raw


def parse_hash_entries(raw_hashes: Any) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    entries: list[dict[str, str]] = []
    issues: list[dict[str, Any]] = []
    if raw_hashes is None:
        return entries, issues
    if not isinstance(raw_hashes, list):
        return entries, [{"status": "hashes_not_list", "message": "Hash entries must be a list."}]
    for index, item in enumerate(raw_hashes):
        if not isinstance(item, dict):
            issues.append({"status": "hash_entry_invalid", "index": index, "message": "Hash entry must be an object."})
            continue
        alg = normalize_hash_alg(item.get("alg") or item.get("algorithm"))
        value = normalize_hash_value(item.get("content") or item.get("value") or item.get("hash"))
        if not alg or not value:
            issues.append({"status": "hash_entry_invalid", "index": index, "message": "Hash entry requires alg and content/value."})
            continue
        expected_length = HASH_HEX_LENGTHS.get(alg)
        if expected_length and (len(value) != expected_length or not re.fullmatch(r"[a-f0-9]+", value)):
            issues.append(
                {
                    "status": "hash_value_invalid",
                    "index": index,
                    "alg": alg,
                    "message": f"Hash value for {alg} must be {expected_length} hexadecimal characters.",
                }
            )
            continue
        entries.append({"alg": alg, "value": value})
    return entries, issues


def parse_pypi_purl(purl: Any) -> dict[str, Any]:
    raw = str(purl or "").strip()
    if not raw:
        return {"type": None, "name": None, "version": None, "valid": False}
    if not raw.startswith("pkg:"):
        return {"type": None, "name": None, "version": None, "valid": False}
    body = raw[4:].split("#", 1)[0].split("?", 1)[0]
    package_type, sep, remainder = body.partition("/")
    if not sep:
        return {"type": package_type, "name": None, "version": None, "valid": False}
    name_part, _, version = remainder.rpartition("@")
    if not name_part:
        name_part = remainder
        version = None
    name_part = urllib.parse.unquote(name_part)
    if package_type.lower() != "pypi" or "/" in name_part or not name_part:
        return {"type": package_type.lower(), "name": None, "version": version, "valid": False}
    return {
        "type": "pypi",
        "name": normalize_package_name(name_part),
        "version": urllib.parse.unquote(version) if version else None,
        "valid": True,
    }


def load_sbom_evidence(root: Path, rules: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    sbom_files: list[dict[str, Any]] = []
    components: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    for path in expand_patterns(root, list_value(rules.get("sbom_files"))):
        rel = relative(path, root)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            issues.append({"status": "sbom_json_invalid", "path": rel, "message": f"SBOM JSON could not be parsed: {exc}"})
            continue
        if not isinstance(data, dict):
            issues.append({"status": "sbom_shape_invalid", "path": rel, "message": "SBOM root must be an object."})
            continue
        raw_components = data.get("components") or []
        if data.get("bomFormat") != "CycloneDX" or not isinstance(raw_components, list):
            issues.append(
                {
                    "status": "sbom_unrecognized_format",
                    "path": rel,
                    "message": "Configured SBOM file is not a CycloneDX JSON object with a components list.",
                }
            )
            continue
        sbom_file = {
            "path": rel,
            "bom_format": data.get("bomFormat"),
            "spec_version": data.get("specVersion"),
            "serial_number": data.get("serialNumber"),
            "component_count": len(raw_components),
            "pypi_component_count": 0,
        }
        for index, component in enumerate(raw_components):
            if not isinstance(component, dict):
                issues.append({"status": "sbom_component_invalid", "path": rel, "component_index": index, "message": "SBOM component must be an object."})
                continue
            purl = parse_pypi_purl(component.get("purl"))
            hashes, hash_issues = parse_hash_entries(component.get("hashes"))
            for issue in hash_issues:
                issues.append({"path": rel, "component_index": index, "status": f"sbom_{issue['status']}", "message": issue["message"]})
            name = purl["name"] if purl.get("valid") else normalize_package_name(str(component.get("name") or ""))
            item = {
                "path": rel,
                "bom_ref": component.get("bom-ref"),
                "name": name or None,
                "raw_name": component.get("name"),
                "version": purl.get("version") or component.get("version"),
                "purl": component.get("purl"),
                "purl_type": purl.get("type"),
                "purl_valid": bool(purl.get("valid")),
                "hashes": hashes,
            }
            if purl.get("type") == "pypi" and not purl.get("valid"):
                issues.append(
                    {
                        "status": "sbom_pypi_purl_invalid",
                        "path": rel,
                        "component_index": index,
                        "message": "SBOM component has a malformed PyPI package URL.",
                        "purl": component.get("purl"),
                    }
                )
            if item["name"] and item["purl_type"] == "pypi":
                components.append(item)
                sbom_file["pypi_component_count"] += 1
        sbom_files.append(sbom_file)
    return sbom_files, components, issues


def load_provenance_evidence(root: Path, rules: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    provenance_files: list[dict[str, Any]] = []
    packages: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    for path in expand_patterns(root, list_value(rules.get("provenance_files"))):
        rel = relative(path, root)
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            issues.append({"status": "provenance_yaml_invalid", "path": rel, "message": f"Provenance manifest could not be parsed: {exc}"})
            continue
        if not isinstance(data, dict):
            issues.append({"status": "provenance_shape_invalid", "path": rel, "message": "Provenance manifest root must be an object."})
            continue
        if data.get("schema") not in {None, PROVENANCE_SCHEMA}:
            issues.append(
                {
                    "status": "provenance_schema_unrecognized",
                    "path": rel,
                    "message": f"Provenance manifest schema is not {PROVENANCE_SCHEMA}.",
                    "schema": data.get("schema"),
                }
            )
        raw_packages = data.get("packages") or []
        if not isinstance(raw_packages, list):
            issues.append({"status": "provenance_packages_not_list", "path": rel, "message": "Provenance packages must be a list."})
            raw_packages = []
        provenance_file = {"path": rel, "schema": data.get("schema"), "package_count": len(raw_packages)}
        for index, package in enumerate(raw_packages):
            if not isinstance(package, dict):
                issues.append({"status": "provenance_package_invalid", "path": rel, "package_index": index, "message": "Provenance package must be an object."})
                continue
            raw_name = str(package.get("name") or "").strip()
            if not raw_name:
                issues.append({"status": "provenance_package_name_missing", "path": rel, "package_index": index, "message": "Provenance package requires a name."})
                continue
            hashes, hash_issues = parse_hash_entries(package.get("expected_hashes") or [])
            for issue in hash_issues:
                issues.append({"path": rel, "package": normalize_package_name(raw_name), "status": f"provenance_{issue['status']}", "message": issue["message"]})
            evidence_items = package.get("evidence") or []
            if not isinstance(evidence_items, list):
                issues.append({"status": "provenance_evidence_not_list", "path": rel, "package": normalize_package_name(raw_name), "message": "Package evidence must be a list."})
                evidence_items = []
            normalized_evidence: list[dict[str, Any]] = []
            for evidence_index, evidence in enumerate(evidence_items):
                if not isinstance(evidence, dict):
                    issues.append(
                        {
                            "status": "provenance_evidence_invalid",
                            "path": rel,
                            "package": normalize_package_name(raw_name),
                            "evidence_index": evidence_index,
                            "message": "Evidence item must be an object.",
                        }
                    )
                    continue
                outcome = str(evidence.get("outcome") or "").strip().lower()
                evidence_path = evidence.get("path")
                item = {
                    "type": str(evidence.get("type") or "").strip() or "unspecified",
                    "path": str(evidence_path or "").strip() or None,
                    "command": evidence.get("command"),
                    "outcome": outcome or None,
                    "notes": evidence.get("notes"),
                }
                if outcome not in PROVENANCE_EVIDENCE_OUTCOMES:
                    issues.append(
                        {
                            "status": "provenance_evidence_outcome_invalid",
                            "path": rel,
                            "package": normalize_package_name(raw_name),
                            "evidence_index": evidence_index,
                            "message": "Evidence outcome must be present, passing, or reviewed.",
                        }
                    )
                if not evidence_path:
                    issues.append(
                        {
                            "status": "provenance_evidence_path_missing",
                            "path": rel,
                            "package": normalize_package_name(raw_name),
                            "evidence_index": evidence_index,
                            "message": "Evidence item requires an in-project path.",
                        }
                    )
                else:
                    resolved = project_reference_path(root, evidence_path)
                    if not is_within_root(resolved, root):
                        issues.append(
                            {
                                "status": "provenance_evidence_path_outside_project",
                                "path": rel,
                                "package": normalize_package_name(raw_name),
                                "evidence_index": evidence_index,
                                "evidence_path": str(evidence_path),
                                "message": "Evidence path must stay inside the project root.",
                            }
                        )
                    elif not resolved.exists():
                        issues.append(
                            {
                                "status": "provenance_evidence_path_missing_on_disk",
                                "path": rel,
                                "package": normalize_package_name(raw_name),
                                "evidence_index": evidence_index,
                                "evidence_path": str(evidence_path),
                                "message": "Evidence path does not exist.",
                            }
                        )
                normalized_evidence.append(item)
            packages.append(
                {
                    "path": rel,
                    "name": normalize_package_name(raw_name),
                    "version": package.get("version"),
                    "source": package.get("source"),
                    "evidence": normalized_evidence,
                    "expected_hashes": hashes,
                }
            )
        provenance_files.append(provenance_file)
    return provenance_files, packages, issues


def docs_files(root: Path, rules: dict[str, Any]) -> list[Path]:
    suffixes = {".md", ".rst", ".txt"}
    exclude_dirs = {str(item) for item in rules.get("exclude_dirs") or []}
    result: list[Path] = []
    for raw in list_value(rules.get("docs_roots")):
        candidate = root / raw
        if candidate.is_file() and candidate.suffix in suffixes:
            result.append(candidate)
        elif candidate.is_dir():
            for path in sorted(candidate.rglob("*")):
                if path.is_file() and path.suffix in suffixes:
                    try:
                        rel = path.relative_to(root)
                    except ValueError:
                        rel = path
                    if not any(part in exclude_dirs for part in rel.parts):
                        result.append(path)
    return sorted(set(result))


INSTALL_COMMAND_RE = re.compile(
    r"\b(?:python\s+-m\s+pip|pip|pip3|uv|poetry|pipenv)\s+(?:install|add)\s+([^\n`;&|]+)",
    re.IGNORECASE,
)


def parse_install_packages(command_args: str) -> list[tuple[str, bool]]:
    packages: list[tuple[str, bool]] = []
    for token in command_args.split():
        if token.startswith("-") or token in {"install", "add"}:
            continue
        name, pinned = parse_requirement_line(token)
        if name:
            packages.append((name, pinned))
    return packages


def scan_docs_install_snippets(root: Path, rules: dict[str, Any]) -> list[dict[str, Any]]:
    snippets: list[dict[str, Any]] = []
    for path in docs_files(root, rules):
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            for match in INSTALL_COMMAND_RE.finditer(line):
                for name, pinned in parse_install_packages(match.group(1)):
                    snippets.append({"package": name, "path": relative(path, root), "line": line_no, "pinned": pinned})
    return snippets


def edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for index_a, char_a in enumerate(a, start=1):
        current = [index_a]
        for index_b, char_b in enumerate(b, start=1):
            current.append(
                min(
                    previous[index_b] + 1,
                    current[index_b - 1] + 1,
                    previous[index_b - 1] + (0 if char_a == char_b else 1),
                )
            )
        previous = current
    return previous[-1]


def nearest_known_package(name: str, known: set[str], threshold: int) -> tuple[str | None, int | None]:
    best_name: str | None = None
    best_distance: int | None = None
    for candidate in known:
        if candidate == name or abs(len(candidate) - len(name)) > threshold:
            continue
        distance = edit_distance(name, candidate)
        if distance <= threshold and (best_distance is None or distance < best_distance):
            best_name = candidate
            best_distance = distance
    return best_name, best_distance


def finding(finding_id: str, severity: str, status: str, message: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "status": status,
        "message": message,
        "human_review_required": True,
        "not_claimed": NOT_CLAIMED,
        **extra,
    }


def findings_from_issues(prefix: str, issues: list[dict[str, Any]], severity: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for index, issue in enumerate(issues, start=1):
        status = str(issue.get("status") or "issue")
        message = str(issue.get("message") or status)
        extra = {key: value for key, value in issue.items() if key not in {"status", "message"}}
        result.append(finding(f"package_reality.{prefix}.{status}.{index}", severity, status, message, **extra))
    return result


def pypi_package_metadata(name: str, timeout: float) -> dict[str, Any]:
    url = f"https://pypi.org/pypi/{name}/json"
    request = urllib.request.Request(url, headers={"User-Agent": "naos-package-reality/2.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - explicit opt-in registry check.
            if 200 <= response.status < 300:
                try:
                    payload = json.loads(response.read().decode("utf-8"))
                except Exception as exc:
                    return {"status": "lookup_error", "registry": "pypi", "error": f"invalid JSON response: {exc}"}
                info = payload.get("info") if isinstance(payload, dict) else {}
                releases = payload.get("releases") if isinstance(payload, dict) else {}
                latest_version = info.get("version") if isinstance(info, dict) else None
                latest_files = releases.get(latest_version) if isinstance(releases, dict) and latest_version else []
                latest_hashes: dict[str, int] = {}
                if isinstance(latest_files, list):
                    for file_info in latest_files:
                        digests = file_info.get("digests") if isinstance(file_info, dict) else {}
                        if isinstance(digests, dict):
                            for alg, value in digests.items():
                                if value:
                                    latest_hashes[str(alg)] = latest_hashes.get(str(alg), 0) + 1
                return {
                    "status": "found",
                    "registry": "pypi",
                    "latest_version": latest_version,
                    "project_url": info.get("project_url") if isinstance(info, dict) else None,
                    "latest_release_files": len(latest_files) if isinstance(latest_files, list) else 0,
                    "latest_release_digest_counts": latest_hashes,
                }
            return {"status": "lookup_error", "registry": "pypi", "error": f"unexpected status {response.status}"}
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"status": "not_found", "registry": "pypi", "error": None}
        return {"status": "lookup_error", "registry": "pypi", "error": f"HTTP {exc.code}"}
    except Exception as exc:
        return {"status": "lookup_error", "registry": "pypi", "error": str(exc)}


def merge_rules(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_rules(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_rules(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def default_rules_path(root: Path, naos_root: str) -> Path | None:
    project_rules = root / naos_root / "package_reality_rules.yaml"
    if project_rules.exists() and not is_kit_repository(root, naos_root):
        return project_rules
    template_rules = Path(__file__).resolve().parents[1] / "templates" / "structural-seeds" / "naos" / "package_reality_rules.yaml"
    return template_rules if template_rules.exists() else None


def build_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    rules_path: str | None,
    registry_mode: str,
    allow_network: bool,
    scan_docs: bool,
    timeout: float,
) -> dict[str, Any]:
    severity = severity_for_profile(profile, policy)
    packages = load_declared_packages(root, rules)
    locked = load_lockfile_packages(root, rules)
    allowlisted = {normalize_package_name(item) for item in list_value(rules.get("allowlisted_packages"))}
    known = {normalize_package_name(item) for item in list_value(rules.get("known_packages"))}
    threshold = int(rules.get("typo_distance_threshold") or 0)
    require_lockfile_entries = bool(rules.get("require_lockfile_entries", True))
    require_declared_packages_in_sbom = bool(rules.get("require_declared_packages_in_sbom", False))
    docs_enabled = scan_docs or bool(rules.get("scan_docs_by_default", False))
    docs_snippets = scan_docs_install_snippets(root, rules) if docs_enabled else []
    sbom_files, sbom_components, sbom_issues = load_sbom_evidence(root, rules)
    provenance_files, provenance_packages, provenance_issues = load_provenance_evidence(root, rules)
    findings: list[dict[str, Any]] = []
    registry_results: dict[str, dict[str, Any]] = {}
    findings.extend(findings_from_issues("sbom", sbom_issues, "advisory" if severity == "advisory" else "warning"))
    findings.extend(findings_from_issues("provenance", provenance_issues, severity))

    for name, item in sorted(packages.items()):
        if name in locked:
            item["lockfile_entry"] = True
        if require_lockfile_entries and name not in locked and name not in allowlisted:
            findings.append(
                finding(
                    f"package_reality.lockfile_missing.{name}",
                    severity,
                    "lockfile_entry_missing",
                    f"Declared package '{name}' does not have a detected lock-style pinned entry.",
                    package=name,
                    sources=item["sources"],
                )
            )
        near, distance = nearest_known_package(name, known, threshold)
        if near and name not in allowlisted:
            findings.append(
                finding(
                    f"package_reality.typo_near_known_package.{name}",
                    severity,
                    "typo_near_known_package",
                    f"Package '{name}' is edit-distance {distance} from known package '{near}'.",
                    package=name,
                    nearest_known_package=near,
                    edit_distance=distance,
                    sources=item["sources"],
                )
            )

    declared_names = set(packages)
    local_package_names = declared_names | locked | allowlisted
    provenance_names = {item["name"] for item in provenance_packages}
    sbom_names = {item["name"] for item in sbom_components if item.get("name")}
    local_or_provenance_names = local_package_names | provenance_names

    for component in sbom_components:
        name = component.get("name")
        if name and name not in local_or_provenance_names:
            findings.append(
                finding(
                    f"package_reality.sbom_component_not_declared_or_locked.{name}",
                    severity,
                    "sbom_component_not_declared_or_locked",
                    f"SBOM PyPI component '{name}' is not declared, locked, allowlisted, or covered by provenance evidence.",
                    package=name,
                    path=component.get("path"),
                    purl=component.get("purl"),
                    version=component.get("version"),
                )
            )

    if require_declared_packages_in_sbom and sbom_files:
        for name in sorted(declared_names - sbom_names - allowlisted):
            findings.append(
                finding(
                    f"package_reality.declared_package_missing_from_sbom.{name}",
                    severity,
                    "declared_package_missing_from_sbom",
                    f"Declared package '{name}' is not present in configured CycloneDX PyPI SBOM evidence.",
                    package=name,
                    sources=packages[name]["sources"],
                )
            )

    for package in provenance_packages:
        name = package["name"]
        if name not in local_package_names:
            findings.append(
                finding(
                    f"package_reality.provenance_package_not_declared_or_locked.{name}",
                    severity,
                    "provenance_package_not_declared_or_locked",
                    f"Provenance package '{name}' is not declared, locked, or allowlisted in local package evidence.",
                    package=name,
                    path=package.get("path"),
                    version=package.get("version"),
                )
            )

    sbom_hashes_by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for component in sbom_components:
        if component.get("name"):
            sbom_hashes_by_name[component["name"]].append(component)

    for package in provenance_packages:
        name = package["name"]
        expected_hashes = package.get("expected_hashes") or []
        if not expected_hashes:
            continue
        comparable_components = [
            component
            for component in sbom_hashes_by_name.get(name, [])
            if not package.get("version") or not component.get("version") or str(package.get("version")) == str(component.get("version"))
        ]
        if not comparable_components:
            continue
        observed_by_alg: dict[str, set[str]] = defaultdict(set)
        for component in comparable_components:
            for hash_entry in component.get("hashes") or []:
                observed_by_alg[hash_entry["alg"]].add(hash_entry["value"])
        for expected in expected_hashes:
            observed = observed_by_alg.get(expected["alg"], set())
            if not observed:
                findings.append(
                    finding(
                        f"package_reality.provenance_hash_not_observed.{name}.{expected['alg']}",
                        "advisory" if severity == "advisory" else "warning",
                        "provenance_hash_not_observed_in_sbom",
                        f"Provenance declares a {expected['alg']} hash for package '{name}', but comparable SBOM components do not expose that algorithm.",
                        package=name,
                        path=package.get("path"),
                        alg=expected["alg"],
                    )
                )
            elif expected["value"] not in observed:
                findings.append(
                    finding(
                        f"package_reality.provenance_hash_mismatch.{name}.{expected['alg']}",
                        severity,
                        "provenance_hash_mismatch",
                        f"Provenance {expected['alg']} hash for package '{name}' does not match comparable SBOM component hashes.",
                        package=name,
                        path=package.get("path"),
                        alg=expected["alg"],
                    )
                )

    for snippet in docs_snippets:
        name = snippet["package"]
        if name not in declared_names and name not in allowlisted:
            findings.append(
                finding(
                    f"package_reality.docs_install_not_declared.{snippet['path']}.{snippet['line']}.{name}",
                    severity,
                    "docs_install_package_not_declared",
                    f"Documentation install snippet references package '{name}' that is not declared in package manifests.",
                    package=name,
                    path=snippet["path"],
                    line=snippet["line"],
                )
            )
        if not snippet["pinned"]:
            findings.append(
                finding(
                    f"package_reality.docs_install_unpinned.{snippet['path']}.{snippet['line']}.{name}",
                    "advisory" if severity == "advisory" else severity,
                    "docs_install_package_unpinned",
                    f"Documentation install snippet references package '{name}' without an exact version pin.",
                    package=name,
                    path=snippet["path"],
                    line=snippet["line"],
                )
            )

    network_used = False
    if registry_mode == "online" and not allow_network:
        findings.append(
            finding(
                "package_reality.registry_consent_missing",
                severity,
                "registry_check_requires_consent",
                "Online registry mode was requested but --allow-network was not provided.",
                registry_mode=registry_mode,
            )
        )
    elif registry_mode == "online" and allow_network:
        network_used = True
        for name in sorted(declared_names | {item["package"] for item in docs_snippets}):
            if name in allowlisted:
                registry_results[name] = {"status": "allowlisted_not_checked"}
                continue
            registry_results[name] = pypi_package_metadata(name, timeout)
            status = registry_results[name].get("status")
            error = registry_results[name].get("error")
            if status == "not_found":
                findings.append(
                    finding(
                        f"package_reality.registry_not_found.{name}",
                        severity,
                        "registry_package_not_found",
                        f"Package '{name}' was not found in the configured registry.",
                        package=name,
                        registry="pypi",
                    )
                )
            elif status == "lookup_error":
                findings.append(
                    finding(
                        f"package_reality.registry_lookup_error.{name}",
                        "advisory" if severity == "advisory" else "warning",
                        "registry_lookup_error",
                        f"Package '{name}' registry lookup failed: {error}",
                        package=name,
                        registry="pypi",
                    )
                )

    declared_by_source: dict[str, list[str]] = defaultdict(list)
    for name, item in sorted(packages.items()):
        for source in item["sources"]:
            declared_by_source[source].append(name)

    summary = finding_counts(findings)
    summary.update(
        {
            "declared_packages": len(declared_names),
            "locked_packages": len(locked),
            "declared_without_lockfile_entry": sum(1 for name in declared_names if name not in locked and name not in allowlisted),
            "docs_install_snippets": len(docs_snippets),
            "docs_scanned": docs_enabled,
            "sbom_files": len(sbom_files),
            "sbom_pypi_components": len(sbom_components),
            "sbom_components_not_declared_or_locked": sum(
                1 for item in sbom_components if item.get("name") and item["name"] not in local_or_provenance_names
            ),
            "provenance_files": len(provenance_files),
            "provenance_packages": len(provenance_packages),
            "provenance_evidence_items": sum(len(item.get("evidence") or []) for item in provenance_packages),
            "provenance_expected_hashes": sum(len(item.get("expected_hashes") or []) for item in provenance_packages),
            "registry_mode": registry_mode,
            "registry_checked_packages": len(registry_results),
            "network_used": network_used,
        }
    )
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "profile": profile,
        "status": status_from_counts(summary),
        "project_root": str(root),
        "naos_root": naos_root,
        "rules_path": rules_path,
        "deterministic": True,
        "registry_mode": registry_mode,
        "network_used": network_used,
        "cost_posture": {
            "cost_incurred_by_default": False,
            "cost_usd": 0.0,
            "external_api_required": registry_mode == "online",
            "provider_dependency_required": False,
            "model_dependency_required": False,
            "human_approval_required_before_cost": True,
        },
        "summary": summary,
        "scans": {
            "manifest_files": sorted(declared_by_source),
            "declared_packages": [
                {
                    "name": name,
                    "sources": sorted(set(item["sources"])),
                    "lockfile_entry": bool(item.get("lockfile_entry")),
                    "pinned_sources": sorted(set(item.get("pinned_sources") or [])),
                    "allowlisted": name in allowlisted,
                    "registry": registry_results.get(name, {"status": "not_checked"}),
                }
                for name, item in sorted(packages.items())
            ],
            "locked_packages": sorted(locked),
            "docs_install_snippets": docs_snippets,
            "sbom_files": sbom_files,
            "sbom_components": sbom_components,
            "provenance_files": provenance_files,
            "provenance_packages": provenance_packages,
            "allowlisted_packages": sorted(allowlisted),
            "known_packages": sorted(known),
        },
        "findings": findings,
        "waivers": [],
        "known_gaps": [
            "Private registries and non-PyPI sources require adopter-owned allowlists or external review evidence.",
            "Offline mode cannot confirm registry existence.",
            "SBOM evidence is consumed only when a configured local CycloneDX JSON file exists.",
            "Provenance evidence is declared by the adopter and is not independently authenticated by this command.",
        ],
        "residual_risks": [
            "A package can exist in a registry and still be malicious, abandoned, vulnerable, or inappropriate.",
            "Package names in generated docs or code can be selectively missed if project-specific install patterns are not configured.",
            "SBOM or provenance files can be stale, incomplete, or generated from the wrong environment.",
        ],
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": bool(findings),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Review declared Python package, SBOM, provenance, hash, and opt-in registry evidence without network calls by default.")
    parser.add_argument("project_path", nargs="?", default=".")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--rules", help="Optional explicit package_reality_rules.yaml path.")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--registry-mode", choices=["offline", "online"], default="offline")
    parser.add_argument("--allow-network", action="store_true", help="Permit explicit online registry metadata lookups.")
    parser.add_argument("--scan-docs", action="store_true", help="Scan configured docs roots for Python install snippets.")
    parser.add_argument("--timeout", type=float, default=5.0, help="Network timeout for explicit online registry mode.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.project_path).resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    rules_path = Path(args.rules) if args.rules else default_rules_path(root, naos_root)
    rules = merge_rules(DEFAULT_RULES, load_rules(rules_path))
    report = build_report(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        rules=rules,
        rules_path=str(rules_path) if rules_path else None,
        registry_mode=args.registry_mode,
        allow_network=args.allow_network,
        scan_docs=args.scan_docs,
        timeout=args.timeout,
    )
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "package_reality_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            f"NAOS package reality: {report['status']} "
            f"({report['summary'].get('total_findings', 0)} findings, "
            f"registry_mode={report['registry_mode']}, network_used={report['network_used']}, "
            f"sbom_pypi_components={report['summary'].get('sbom_pypi_components', 0)}, "
            f"provenance_packages={report['summary'].get('provenance_packages', 0)}) -> {output}"
        )
    return exit_code_for_summary(profile, report["summary"], policy, args.strict and not is_kit_repository(root, naos_root))


if __name__ == "__main__":
    raise SystemExit(main())
