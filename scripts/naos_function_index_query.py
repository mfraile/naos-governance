#!/usr/bin/env python3
"""
Function Index Query Tool — queryable interface to FUNCTION_INDEX.yaml.

Portable governance script — path-parameterized via NAOS_ROOT / SRC_ROOT env vars.
Provides package awareness, optional project-configured similarity, and task-based
function lookup. Builds a token index by default. Embeddings are used only when
the project explicitly enables an optional similarity provider and model in
configs/naos_ai_precommit.yaml.

Usage:
    python scripts/naos_function_index_query.py --rebuild-index
    python scripts/naos_function_index_query.py --package services
    python scripts/naos_function_index_query.py --similar "validate document"
    python scripts/naos_function_index_query.py --for-task T-253

Environment variables:
    NAOS_ROOT   Path to the naos/ governance directory (default: naos)
    SRC_ROOT    Path to the source directory (default: src)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
NAOS_ROOT = ROOT / os.getenv("NAOS_ROOT", "naos")
SRC_ROOT_VAL = os.getenv("SRC_ROOT", "src")
FUNCTION_INDEX_PATH = NAOS_ROOT / "inventory" / "FUNCTION_INDEX.yaml"
SIMILARITY_INDEX_PATH = NAOS_ROOT / "inventory" / "FUNCTION_SIMILARITY_INDEX.json"
TASK_REGISTRY_PATH = NAOS_ROOT / "TASK_REGISTRY.yaml"
AI_PRECOMMIT_CONFIG_PATH = ROOT / "configs" / "naos_ai_precommit.yaml"

# Output budget
DEFAULT_OUTPUT_CAP = 5 * 1024  # 5 KB
TIER2_CAP = 8 * 1024  # 8 KB

# Stopwords for tokenization
STOPWORDS = frozenset(
    {
        "a",
        "an",
        "the",
        "and",
        "or",
        "of",
        "to",
        "in",
        "for",
        "is",
        "it",
        "on",
        "at",
        "by",
        "from",
        "with",
        "as",
        "be",
        "was",
        "are",
        "has",
        "this",
        "that",
        "def",
        "class",
        "self",
        "return",
        "none",
        "true",
        "false",
    }
)

TAG_ONLY_PREFIX = "[TAG ONLY]"


# ---------------------------------------------------------------------------
# Loading helpers
# ---------------------------------------------------------------------------


def load_function_index() -> dict:
    """Parse FUNCTION_INDEX.yaml into a dict."""
    if not FUNCTION_INDEX_PATH.exists():
        print(
            f"ERROR: {FUNCTION_INDEX_PATH} not found. Run: make -f Makefile.naos gov-refresh",
            file=sys.stderr,
        )
        sys.exit(1)
    with open(FUNCTION_INDEX_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _load_task_registry() -> dict:
    """Load TASK_REGISTRY.yaml."""
    if not TASK_REGISTRY_PATH.exists():
        return {}
    with open(TASK_REGISTRY_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _load_optional_similarity_filter() -> dict:
    """Load disabled-by-default optional similarity provider config."""
    default = {
        "enabled": False,
        "provider": None,
        "model": None,
        "device": None,
        "index_path": None,
        "evidence_required": True,
    }
    if not AI_PRECOMMIT_CONFIG_PATH.exists():
        return default
    try:
        with open(AI_PRECOMMIT_CONFIG_PATH, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError):
        return default
    configured = data.get("optional_similarity_filter") or {}
    if not isinstance(configured, dict):
        return default
    merged = dict(default)
    merged.update({key: configured.get(key, value) for key, value in default.items()})
    return merged


# ---------------------------------------------------------------------------
# Tokenization
# ---------------------------------------------------------------------------


def _tokenize(text: str) -> set[str]:
    """Split text on _ and camelCase boundaries, lowercase, remove stopwords."""
    if not text:
        return set()
    text = re.sub(r"([a-z])([A-Z])", r"\1_\2", text)
    tokens = re.split(r"[^a-zA-Z0-9]+", text.lower())
    return {t for t in tokens if t and len(t) > 1 and t not in STOPWORDS}


# ---------------------------------------------------------------------------
# Similarity functions
# ---------------------------------------------------------------------------


def _jaccard_similarity(a: set, b: set) -> float:
    """Jaccard similarity: |intersection| / |union|."""
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _cosine_similarity(vec_a: list[float], vec_b: list[float]) -> float:
    """Cosine similarity using numpy if available, else pure Python."""
    try:
        import numpy as np

        a = np.array(vec_a, dtype=np.float32)
        b = np.array(vec_b, dtype=np.float32)
        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return float(np.dot(a, b) / (norm_a * norm_b))
    except ImportError:
        dot = sum(x * y for x, y in zip(vec_a, vec_b))
        norm_a = sum(x * x for x in vec_a) ** 0.5
        norm_b = sum(x * x for x in vec_b) ** 0.5
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)


# ---------------------------------------------------------------------------
# Graduated truncation
# ---------------------------------------------------------------------------


def _truncate_output(text: str, cap: int = DEFAULT_OUTPUT_CAP) -> str:
    """Apply graduated truncation to output."""
    if len(text.encode("utf-8")) <= cap:
        return text
    encoded = text.encode("utf-8")[:cap]
    truncated = encoded.decode("utf-8", errors="ignore")
    last_nl = truncated.rfind("\n")
    if last_nl > cap // 2:
        truncated = truncated[:last_nl]
    return truncated + "\n[truncated — run --package <subpackage> for details]"


# ---------------------------------------------------------------------------
# --rebuild-index
# ---------------------------------------------------------------------------


def build_similarity_index() -> None:
    """Build token index plus optional project-configured embeddings."""
    index = load_function_index()
    entries: dict[str, dict] = {}
    descriptions: list[tuple[str, str]] = []
    module_count = 0
    func_count = 0
    tag_only_count = 0

    for package, modules in index.items():
        if not isinstance(modules, dict):
            continue
        for module_name, module_data in modules.items():
            if not isinstance(module_data, dict):
                continue
            module_count += 1
            purpose = module_data.get("purpose", "")
            is_tag_only = isinstance(purpose, str) and purpose.strip().startswith(
                TAG_ONLY_PREFIX
            )
            if is_tag_only:
                tag_only_count += 1

            module_path = f"{SRC_ROOT_VAL}/{package}/{module_name}.py"

            for func_str in module_data.get("public", []):
                if not isinstance(func_str, str):
                    continue
                func_count += 1
                func_name = func_str.split("(")[0].strip().strip("'\"")
                doc = ""
                if "#" in func_str:
                    doc = func_str.split("#", 1)[1].strip()

                key = f"{package}.{module_name}.{func_name}"
                name_tokens = _tokenize(func_name)
                doc_tokens = set() if is_tag_only else _tokenize(doc)

                entry: dict = {
                    "tokens": sorted(name_tokens),
                    "doc_tokens": sorted(doc_tokens),
                    "signature": func_str.split("#")[0].strip().strip("'\""),
                    "module": module_path,
                }
                entries[key] = entry

                if not is_tag_only and doc:
                    descriptions.append((key, f"{func_name} {doc}"))
                elif not is_tag_only:
                    descriptions.append((key, func_name))

            for cls_str in module_data.get("classes", []):
                if not isinstance(cls_str, str):
                    continue
                cls_name = cls_str.split("[")[0].strip()
                key = f"{package}.{module_name}.{cls_name}"
                name_tokens = _tokenize(cls_name)

                entry = {
                    "tokens": sorted(name_tokens),
                    "doc_tokens": []
                    if is_tag_only
                    else sorted(_tokenize(purpose) if purpose else set()),
                    "signature": cls_str,
                    "module": module_path,
                }
                entries[key] = entry

                if not is_tag_only:
                    descriptions.append(
                        (key, f"{cls_name} {purpose}" if purpose else cls_name)
                    )

    # Optional semantic provider: disabled by default and project-configured only.
    has_embeddings = False
    similarity_config = _load_optional_similarity_filter()
    embedding_model = similarity_config.get("model")
    embedding_provider = similarity_config.get("provider")
    embedding_device = similarity_config.get("device")
    embedding_dim = None

    if similarity_config.get("enabled"):
        if embedding_provider != "local_sentence_transformers" or not embedding_model:
            print(
                "  WARNING: optional similarity is enabled, but provider/model "
                "is not configured for local_sentence_transformers; index built "
                "with Jaccard tokens only"
            )
        else:
            try:
                from sentence_transformers import SentenceTransformer

                print(
                    "  Loading optional similarity provider "
                    f"{embedding_provider} / {embedding_model}..."
                )
                if embedding_device:
                    model = SentenceTransformer(embedding_model, device=embedding_device)
                else:
                    model = SentenceTransformer(embedding_model)
                texts = [desc for _, desc in descriptions]
                if texts:
                    print(f"  Computing embeddings for {len(texts)} entries...")
                    vectors = model.encode(
                        texts, show_progress_bar=False, normalize_embeddings=True
                    )
                    embedding_dim = vectors.shape[1]
                    for i, (key, _) in enumerate(descriptions):
                        if key in entries:
                            entries[key]["embedding"] = [
                                round(float(v), 6) for v in vectors[i]
                            ]
                    has_embeddings = True
                    print(f"  Embeddings computed ({embedding_dim}-dim vectors)")
            except ImportError:
                print(
                    "  WARNING: optional provider local_sentence_transformers is "
                    "configured, but sentence-transformers is not installed; "
                    "index built with Jaccard tokens only"
                )
            except Exception as e:
                print(
                    "  WARNING: optional similarity embedding failed "
                    f"({e}); falling back to Jaccard tokens only"
                )
    else:
        print("  Optional similarity provider disabled; index built with Jaccard tokens only")

    meta = {
        "_meta": {
            "generated": datetime.now(UTC).isoformat(),
            "modules": module_count,
            "functions": func_count,
            "entries": len(entries),
            "filtered_tag_only": tag_only_count,
            "has_embeddings": has_embeddings,
            "embedding_model": embedding_model if has_embeddings else None,
            "embedding_provider": embedding_provider if has_embeddings else None,
            "embedding_device": embedding_device if has_embeddings else None,
            "embedding_dim": embedding_dim if has_embeddings else None,
            "optional_similarity_filter": {
                "enabled": bool(similarity_config.get("enabled")),
                "provider": embedding_provider,
                "model": embedding_model,
                "device": embedding_device,
                "evidence_required": bool(
                    similarity_config.get("evidence_required", True)
                ),
            },
        },
        "entries": entries,
    }

    SIMILARITY_INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(SIMILARITY_INDEX_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=None, separators=(",", ":"))

    file_size = SIMILARITY_INDEX_PATH.stat().st_size
    print(f"\n  Index written: {SIMILARITY_INDEX_PATH}")
    print(
        f"  Modules: {module_count}, Functions: {func_count}, Entries: {len(entries)}"
    )
    print(f"  [TAG ONLY] filtered: {tag_only_count}")
    print(f"  Embeddings: {'yes (project-configured)' if has_embeddings else 'no (Jaccard only)'}")
    print(f"  File size: {file_size / 1024:.1f} KB")


# ---------------------------------------------------------------------------
# --package
# ---------------------------------------------------------------------------


def query_package(package_name: str) -> str:
    """List functions in a package from FUNCTION_INDEX."""
    index = load_function_index()

    results: list[str] = []
    for pkg, modules in index.items():
        if not isinstance(modules, dict):
            continue
        if pkg != package_name and not pkg.startswith(package_name):
            continue

        for mod_name, mod_data in modules.items():
            if not isinstance(mod_data, dict):
                continue
            purpose = mod_data.get("purpose", "")
            used_by = mod_data.get("used_by", [])

            results.append(f"\n## {pkg}.{mod_name}")
            if purpose:
                results.append(f"  Purpose: {purpose}")
            for func_str in mod_data.get("public", []):
                results.append(f"  - {func_str}")
            for cls_str in mod_data.get("classes", []):
                results.append(f"  - [class] {cls_str}")
            if used_by:
                results.append(f"  Used by: {', '.join(str(u) for u in used_by)}")

    if not results:
        return f"No package matching '{package_name}' found in FUNCTION_INDEX."

    output = f"# Functions in {SRC_ROOT_VAL}/{package_name}/\n" + "\n".join(results)
    return _truncate_output(output)


# ---------------------------------------------------------------------------
# --similar
# ---------------------------------------------------------------------------


def _load_similarity_index() -> dict | None:
    """Load the pre-computed similarity index."""
    if not SIMILARITY_INDEX_PATH.exists():
        return None
    with open(SIMILARITY_INDEX_PATH, encoding="utf-8") as f:
        return json.load(f)


def query_similar(phrase: str) -> str:
    """Find functions similar to a description phrase."""
    sim_index = _load_similarity_index()

    if sim_index is None:
        return (
            "Similarity index not found. Run: "
            "python scripts/naos_function_index_query.py --rebuild-index"
        )

    meta = sim_index.get("_meta", {})
    entries = sim_index.get("entries", {})
    has_embeddings = meta.get("has_embeddings", False)

    results: list[tuple[float, str, str, str]] = []

    if has_embeddings:
        try:
            from sentence_transformers import SentenceTransformer

            model_name = meta.get("embedding_model")
            if not model_name:
                raise ValueError("similarity index metadata is missing embedding_model")
            device = meta.get("embedding_device")
            if device:
                model = SentenceTransformer(model_name, device=device)
            else:
                model = SentenceTransformer(model_name)
            query_vec = model.encode([phrase], normalize_embeddings=True)[0].tolist()

            for key, entry in entries.items():
                if "embedding" not in entry:
                    continue
                score = _cosine_similarity(query_vec, entry["embedding"])
                if score > 0.5:
                    results.append((score, key, entry.get("signature", ""), "cosine"))

            results.sort(key=lambda x: x[0], reverse=True)
            results = results[:10]

            if results:
                provider = meta.get("embedding_provider") or "project-configured"
                lines = [f'# Similar to: "{phrase}" (cosine similarity, {provider})\n']
                for score, key, sig, method in results:
                    module = entries[key].get("module", "")
                    lines.append(f"  {score:.3f}  {key}")
                    lines.append(f"         {sig}")
                    lines.append(f"         ({module})")
                return _truncate_output("\n".join(lines))
        except ImportError:
            pass

    # Jaccard fallback
    query_tokens = _tokenize(phrase)
    for key, entry in entries.items():
        entry_tokens = set(entry.get("tokens", [])) | set(entry.get("doc_tokens", []))
        score = _jaccard_similarity(query_tokens, entry_tokens)
        if score > 0.3:
            results.append((score, key, entry.get("signature", ""), "jaccard"))

    results.sort(key=lambda x: x[0], reverse=True)
    results = results[:10]

    if not results:
        return f'No similar functions found for: "{phrase}"'

    lines = [f'# Similar to: "{phrase}" (Jaccard token similarity)\n']
    for score, key, sig, method in results:
        module = entries[key].get("module", "") if entries.get(key) else ""
        lines.append(f"  {score:.3f}  {key}")
        lines.append(f"         {sig}")
        if module:
            lines.append(f"         ({module})")
    return _truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# --for-task
# ---------------------------------------------------------------------------


def query_for_task(task_id: str) -> str:
    """Find functions relevant to a task's FR/ARCH references."""
    registry = _load_task_registry()
    index = load_function_index()

    tasks = registry.get("tasks", registry)
    task_entry = None
    if isinstance(tasks, list):
        for t in tasks:
            if isinstance(t, dict) and t.get("id") == task_id:
                task_entry = t
                break
    elif isinstance(tasks, dict):
        task_entry = tasks.get(task_id)

    if not task_entry:
        return f"Task {task_id} not found in TASK_REGISTRY.yaml"

    requirements = []
    if isinstance(task_entry, dict):
        reqs = task_entry.get("requirement", task_entry.get("implements", []))
        if isinstance(reqs, str):
            requirements = [r.strip() for r in reqs.split(",")]
        elif isinstance(reqs, list):
            requirements = [str(r).strip() for r in reqs]

    if not requirements:
        return f"Task {task_id} has no requirements/implements references"

    results: list[str] = [
        f"# Functions for {task_id} (requirements: {', '.join(requirements)})\n"
    ]

    for pkg, modules in index.items():
        if not isinstance(modules, dict):
            continue
        for mod_name, mod_data in modules.items():
            if not isinstance(mod_data, dict):
                continue
            purpose = mod_data.get("purpose", "")

            if isinstance(purpose, str) and purpose.strip().startswith(TAG_ONLY_PREFIX):
                continue

            purpose_str = str(purpose).upper()
            matches = [r for r in requirements if r.upper() in purpose_str]
            if not matches:
                continue

            results.append(f"\n## {pkg}.{mod_name}")
            results.append(f"  Purpose: {purpose}")
            results.append(f"  Matches: {', '.join(matches)}")
            for func_str in mod_data.get("public", []):
                results.append(f"  - {func_str}")

    if len(results) == 1:
        return (
            f"No functions found matching requirements for {task_id}: "
            f"{', '.join(requirements)}"
        )

    return _truncate_output("\n".join(results))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Function Index Query Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --rebuild-index                    # Build/refresh similarity index
  %(prog)s --package services                 # List functions in src/services/
  %(prog)s --similar "validate document"      # Find similar functions
  %(prog)s --for-task T-253                   # Functions for a task's FRs
""",
    )
    parser.add_argument(
        "--rebuild-index",
        action="store_true",
        help="Build/refresh FUNCTION_SIMILARITY_INDEX.json",
    )
    parser.add_argument(
        "--package",
        type=str,
        help="List functions in a package (e.g., 'services', 'api.routes')",
    )
    parser.add_argument(
        "--similar",
        type=str,
        help="Find functions similar to a description phrase",
    )
    parser.add_argument(
        "--for-task",
        type=str,
        help="Find functions relevant to a task's FR/ARCH references",
    )

    args = parser.parse_args()

    if args.rebuild_index:
        print("Building similarity index...")
        build_similarity_index()
        return 0

    if args.package:
        print(query_package(args.package))
        return 0

    if args.similar:
        print(query_similar(args.similar))
        return 0

    if args.for_task:
        print(query_for_task(args.for_task))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
