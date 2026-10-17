"""Explicit custody for one live self-check, without changing project identity.

Only the selected producer sinks are mapped. This is not a general filesystem
view: authored and external inputs retain their normal project paths and checks.
The subprocess entry invokes one existing producer under this process-local
context; no environment suppression or Path interception is used.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import fnmatch
import hashlib
import json
from pathlib import Path
import runpy
import stat
import sys

_ACTIVE = ContextVar("naos_self_check_inspection", default=None)


def _regular(base: Path, path: Path) -> bool:
    try:
        current = base
        for part in path.relative_to(base).parts:
            current /= part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                return False
        return path.is_file() and path.stat().st_nlink == 1 and path.resolve().is_relative_to(base.resolve())
    except (OSError, ValueError):
        return False


def _context(root: Path | None = None, naos_root: str | None = None):
    context = _ACTIVE.get()
    if context is None:
        return None
    if root is not None and Path(root).resolve() != Path(context["root"]):
        return None
    if naos_root is not None and naos_root != context["naos_root"]:
        return None
    return context


def inspection_active(root: Path, naos_root: str) -> bool:
    return _context(root, naos_root) is not None


def inspection_logical_path(root: Path, naos_root: str, physical_path: Path) -> Path:
    context = _context(root, naos_root)
    path = Path(physical_path).absolute()
    if context:
        for logical, entry in context["sinks"].items():
            if path in {Path(entry["physical"]), Path(entry["unavailable"])}:
                return Path(logical)
    return Path(physical_path)


def logical_path(root: Path, path: Path) -> Path:
    """Logical identity for existing generic report readers (no routing grant)."""
    context = _context(root)
    return inspection_logical_path(root, context["naos_root"], path) if context else path


def _sink_entry(context, path: Path):
    entry = context["sinks"].get(str(path))
    if entry is not None:
        return entry
    # Existing aliases on case-insensitive volumes must not fall through to old
    # canonical bytes. Native identity is only an in-run routing guard, checked
    # after both operands' topology; private content hashes remain authoritative.
    root = Path(context["root"])
    if not _regular(root, path):
        return None
    for logical, value in context["sinks"].items():
        selected = Path(logical)
        try:
            if _regular(root, selected) and path.samefile(selected):
                return value
        except OSError:
            continue
    return None


def inspection_output_path(root: Path, naos_root: str, logical_path: Path) -> Path:
    context = _context(root, naos_root)
    if context is None:
        return logical_path
    logical = inspection_logical_path(root, naos_root, logical_path).absolute()
    entry = _sink_entry(context, logical)
    if entry is None or context.get("producer") not in {None, entry["owner"]}:
        raise ValueError(f"Unowned self-check inspection output: {logical}")
    return Path(entry["physical"])


def inspection_report_output_path(root: Path, naos_root: str, path: Path) -> Path:
    """Lookup may describe another producer; write_report enforces ownership."""
    context = _context(root, naos_root)
    if context is None:
        return path
    entry = _sink_entry(context, inspection_logical_path(root, naos_root, path).absolute())
    return Path(entry["physical"]) if entry else path


def inspection_publish_path(path: Path) -> Path:
    context = _context()
    if context is None:
        return path
    return inspection_output_path(Path(context["root"]), context["naos_root"], path)


def inspection_input_path(root: Path, naos_root: str, logical_path: Path) -> Path:
    context = _context(root, naos_root)
    if context is None:
        return logical_path
    logical = inspection_logical_path(root, naos_root, logical_path).absolute()
    entry = _sink_entry(context, logical)
    if entry is None:
        return logical_path
    if entry.get("sha256") is None:
        missing = Path(entry["unavailable"])
        if missing.exists() or missing.is_symlink():
            raise ValueError(f"Unadmitted inspection input appeared: {logical}")
        return missing
    physical = Path(entry["physical"])
    if not _regular(Path(context["directory"]), physical):
        raise ValueError(f"Unsafe inspection input: {logical}")
    if hashlib.sha256(physical.read_bytes()).hexdigest() != entry["sha256"]:
        raise ValueError(f"Changed inspection input: {logical}")
    return physical


def inspection_read_path(path: Path) -> Path:
    context = _context()
    return inspection_input_path(Path(context["root"]), context["naos_root"], path) if context else path


def inspection_validation_root(root: Path, path: Path) -> Path:
    context = _context(root)
    if context and logical_path(root, path) != path:
        return Path(context["directory"])
    return root


def inspection_candidates(root: Path, pattern: str, candidates) -> list[Path]:
    """Return logical refs; pending/failed selected receipts never use old files."""
    context = _context(root)
    if context is None:
        return list(candidates)
    paths = {str(logical_path(root, p).absolute()) for p in candidates}
    paths.update(logical for logical in context["sinks"]
                 if fnmatch.fnmatchcase(Path(logical).relative_to(root).as_posix(), pattern))
    return [Path(p) for p in sorted(paths)
            if inspection_input_path(root, context["naos_root"], Path(p)).is_file()]


def create_inspection_context(root, naos_root, profile, policy, producers, directory, *, policy_argument=None):
    """Build sinks from the existing finite producer plan and policy path rules."""
    from naos_policy import naos_root_path, safe_policy_path
    from naos_self_check_dependency_resolution import _output_key
    root, directory = Path(root).resolve(), Path(directory).resolve()
    if directory.is_relative_to(root):
        raise ValueError("Inspection custody must be outside the project")
    directory.mkdir(parents=True, exist_ok=True)
    sinks, selected = {}, {}
    state = naos_root_path(root, naos_root)
    def logical_report(key):
        paths = policy.get("paths", {})
        return safe_policy_path(state, str(paths.get("reports_dir") or "reports"),
                                str(paths.get(key) or key), field=key)
    def add(path, owner, primary=False):
        if path is None:
            return
        path = Path(path).absolute()
        ref = path.relative_to(root)
        if path.resolve() != path or path in [Path(policy.get("_meta", {}).get("path") or root)]:
            raise ValueError("Inspection sink aliases source or policy")
        if primary and path.suffix != ".json":
            raise ValueError("A selected report sink must retain its JSON role")
        if path.exists() and not _regular(root, path):
            raise ValueError("Inspection sink aliases an existing project operand")
        if str(path) in sinks and sinks[str(path)]["owner"] != owner:
            raise ValueError("Inspection sink has multiple owners")
        sinks[str(path)] = {"owner": owner, "physical": str(directory / "files" / ref),
                            "unavailable": str(directory / "pending" / ref), "sha256": None,
                            "primary": primary}
    for script, arguments in producers:
        key = "task_claim_report" if script == "naos_task_claims.py" else _output_key(script)
        selected[script] = list(arguments)
        add(logical_report(key), script, True)
    add(logical_report("self_check_report"), "naos_self_check.py")
    state = naos_root_path(root, naos_root)
    if "naos_local_context_index.py" in selected:
        from naos_local_context_index import resolve_rules_path, load_yaml_mapping
        rules_path, _ = resolve_rules_path(root, naos_root, policy, None)
        rules = load_yaml_mapping(rules_path)
        configured = policy.get("paths", {}).get("local_context_index_sqlite")
        db = safe_policy_path(state, str(configured or (rules.get("sqlite_artifact") or {}).get("path") or "context_index/local_context_index.sqlite"), field="local_context_index_sqlite")
        add(db, "naos_local_context_index.py")
        if db is not None:
            lock = policy.get("paths", {}).get("local_context_index_db_lock")
            logical_lock = safe_policy_path(state, str(lock), field="local_context_index_db_lock") if lock else db.with_name(db.name + ".lock")
            add(logical_lock, "naos_local_context_index.py")
        add(logical_report("sqlite_write_coordination_report"), "naos_local_context_index.py")
    # Task-specific Markdown is an exact selected sink, not a directory grant.
    task_args = selected.get("naos_task_context_pack.py", [])
    if "--task" in task_args:
        import re
        task = task_args[task_args.index("--task") + 1]
        safe_task = re.sub(r"[^A-Za-z0-9_.-]+", "_", task.upper())
        markdown = safe_policy_path(state, str(policy.get("paths", {}).get("task_context_pack_markdown_dir") or "context_packs"), safe_task + ".md", field="task_context_pack_markdown_dir")
        add(markdown, "naos_task_context_pack.py")
    policy_path = policy.get("_meta", {}).get("path")
    context = {"schema": "naos.self_check_inspection.v1", "root": str(root), "naos_root": naos_root,
               "profile": profile, "directory": str(directory), "policy_path": policy_path,
               "policy_argument": policy_argument if policy_argument is not None else policy_path,
               "policy_sha256": hashlib.sha256(Path(policy_path).read_bytes()).hexdigest() if policy_path else None,
               "selected": selected, "sinks": sinks,
               "producer_sha256": {script: hashlib.sha256(Path(__file__).with_name(script).read_bytes()).hexdigest() for script in selected}}
    path = directory / "context.json"
    path.write_text(json.dumps(context, indent=2) + "\n", encoding="utf-8")
    return path


@contextmanager
def activate_inspection(context_path: Path, producer: str | None = None):
    path = Path(context_path).absolute()
    if not _regular(path.parent, path):
        raise ValueError("Unsafe inspection context")
    context = json.loads(path.read_text(encoding="utf-8"))
    if context.get("schema") != "naos.self_check_inspection.v1" or Path(context["directory"]) != path.parent:
        raise ValueError("Invalid inspection context")
    root = Path(context["root"])
    if root.resolve() != root or Path.cwd().resolve() != root or path.parent.is_relative_to(root):
        raise ValueError("Inspection project identity mismatch")
    selected_policy = context["policy_path"]
    if selected_policy and hashlib.sha256(Path(selected_policy).read_bytes()).hexdigest() != context["policy_sha256"]:
        raise ValueError("Inspection policy changed")
    if producer is not None and producer not in context["selected"]:
        raise ValueError("Unselected inspection producer")
    for script in context["selected"]:
        if Path(script).name != script or hashlib.sha256(Path(__file__).with_name(script).read_bytes()).hexdigest() != context["producer_sha256"][script]:
            raise ValueError("Inspection producer source changed")
    for logical, entry in context["sinks"].items():
        ref = Path(logical).relative_to(root)
        if ".." in ref.parts or Path(entry["physical"]) != path.parent / "files" / ref or Path(entry["unavailable"]) != path.parent / "pending" / ref:
            raise ValueError("Invalid inspection custody binding")
        if entry["owner"] not in {*context["selected"], "naos_self_check.py"}:
            raise ValueError("Unknown inspection owner")
    context["producer"] = producer
    context["context_path"] = str(path)
    token = _ACTIVE.set(context)
    try:
        yield context
    finally:
        _ACTIVE.reset(token)


def complete_producer(script: str, payload: dict, returncode: int):
    """Admit only real parsed output; adverse findings are not a failed process."""
    context = _context()
    if context is None:
        return
    logicalize_payload(payload)
    valid = (returncode in {0, 1, 2} and isinstance(payload, dict)
             and isinstance(payload.get("schema"), str) and not payload["schema"].endswith(".error")
             and isinstance(payload.get("summary"), dict) and isinstance(payload.get("findings"), list))
    valid = valid and all(payload.get(k, v) == v for k, v in
                          {"project_root": context["root"], "naos_root": context["naos_root"], "profile": context["profile"]}.items())
    for entry in context["sinks"].values():
        if entry["owner"] != script:
            continue
        entry["sha256"] = None
        path = Path(entry["physical"])
        if valid and entry["primary"] and not path.exists():
            from naos_policy import write_report
            write_report(path, payload)
        if valid and _regular(Path(context["directory"]), path):
            if entry["primary"]:
                try:
                    if json.loads(path.read_text(encoding="utf-8")) != payload:
                        continue
                except (OSError, ValueError):
                    continue
            entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    persisted = {k: v for k, v in context.items() if k not in {"producer", "context_path"}}
    Path(context["context_path"]).write_text(json.dumps(persisted, indent=2) + "\n", encoding="utf-8")


def producer_command(script: str, arguments: list[str]) -> list[str] | None:
    context = _context()
    if context is None:
        return None
    return [sys.executable, "-B", str(Path(__file__).resolve()), context["context_path"], script, *arguments]


def _invoke(context_path, script, arguments):
    with activate_inspection(Path(context_path), script) as context:
        expected = ["--profile", context["profile"], "--naos-root", context["naos_root"], "--json", *context["selected"][script]]
        if context["policy_argument"]:
            expected += ["--policy", context["policy_argument"]]
        if arguments != expected:
            raise ValueError("Inspection producer invocation mismatch")
        sys.argv = [str(Path(__file__).with_name(script)), *arguments]
        runpy.run_path(sys.argv[0], run_name="__main__")


def logicalize_payload(value):
    """Normalize exact owned path fields, never findings or status semantics."""
    context = _context()
    if context is None:
        return value
    aliases = {entry[k]: logical for logical, entry in context["sinks"].items()
               for k in ("physical", "unavailable")}
    def visit(item):
        if isinstance(item, dict):
            for key in item:
                item[key] = visit(item[key])
        elif isinstance(item, list):
            for i in range(len(item)):
                item[i] = visit(item[i])
        elif isinstance(item, str):
            return aliases.get(item, item)
        return item
    return visit(value)


def inspection_session_copy_active() -> bool:
    return _context() is not None


if __name__ == "__main__":
    # Import the canonical helper so producer imports see the same ContextVar.
    import naos_self_check_inspection
    naos_self_check_inspection._invoke(sys.argv[1], sys.argv[2], sys.argv[3:])

