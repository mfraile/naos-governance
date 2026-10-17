"""Native anchored Windows publication for strict local JSON reports.

Reports authorize refreshing a name under pinned no-follow parents, not a
compare-and-swap of the previous leaf identity. No provider or recovery journal.
"""

from __future__ import annotations

from contextlib import ExitStack
import hashlib
import importlib.util
import ntpath
import os
from pathlib import Path
import secrets
import sys


def _load_handles():
    # Generated adopters receive a byte-derived sibling of the canonical module.
    sibling = Path(__file__).with_name("naos_windows_handles.py")
    source = (
        sibling
        if sibling.is_file()
        else Path(__file__).resolve().parents[1] / "upgrade_contract/windows_handles.py"
    )
    name = "_naos_report_windows_handles"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, source)
    if spec is None or spec.loader is None:
        raise RuntimeError("Native report primitives are unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


wh = _load_handles()
MISSING = 0xC0000034
COLLISION = 0xC0000035


def _parent(handles, stack: ExitStack, absolute: str):
    drive, tail = ntpath.splitdrive(absolute)
    parts = tail.strip("\\").split("\\")
    filename = parts.pop()
    wh.validate_component(filename)
    drive += "\\"
    parent = stack.enter_context(handles.open_root(drive, for_publish=not parts))
    held = [parent]
    for index, name in enumerate(parts):
        final = index == len(parts) - 1
        try:
            child = handles.open_child(
                parent,
                name,
                kind="directory",
                for_publish=final,
                pin_for_read=not final,
            )
        except wh.WindowsHandleError as exc:
            if exc.operation != "NtCreateFile" or exc.ntstatus != MISSING:
                raise
            identity = parent.info().identity
            writer = (
                handles.open_root(drive, for_publish=True)
                if index == 0
                else handles.open_child(
                    held[-2], parts[index - 1], kind="directory", for_publish=True
                )
            )
            writer = stack.enter_context(writer)
            if writer.info().identity != identity or parent.info().identity != identity:
                raise wh.UnsafeWindowsPath(
                    "Report parent changed before directory creation"
                )
            # Match ordinary new-output inheritance; do not modify existing ACLs.
            child = handles.create_report_child(writer, name, kind="directory")
            if parent.info().identity != identity:
                child.close()
                raise wh.UnsafeWindowsPath(
                    "Report parent changed during directory creation"
                )
        parent = stack.enter_context(child)
        held.append(parent)
    return parent, filename


def _security_tuple(handle):
    value = handle.security()
    return value.owner_sid, value.group_sid, value.dacl, value.protected


def _digest(handle) -> str:
    before = handle.info()
    remaining = before.size
    handle.seek(0)
    digest = hashlib.sha256()
    while remaining:
        block = handle.read(min(remaining, 1024 * 1024))
        if not block:
            raise wh.UnsafeWindowsPath("Report ended before its observed size")
        digest.update(block)
        remaining -= len(block)
    if handle.info() != before:
        raise wh.UnsafeWindowsPath("Report changed during readback")
    return digest.hexdigest()


def write_strict_report(path: Path, data: str, *, private_new_file: bool = False,
                        require_existing_write_access: bool = False,
                        expected_preimage_sha256: str | None = None,
                        expect_absent: bool = False) -> None:
    """Publish text, optionally using private security for an absent new file.

    Existing supported security is preserved regardless of this creation policy.
    A private-creation verification refusal before handle return can leave an
    empty stage: no payload was written and no unregistered pathname is deleted.
    Publication is name refresh, not leaf CAS or a crash-durable transaction.
    """
    if type(private_new_file) is not bool:
        raise ValueError("private_new_file must be a boolean")
    if type(require_existing_write_access) is not bool or type(expect_absent) is not bool:
        raise ValueError("Trace publication flags must be boolean")
    if expected_preimage_sha256 is not None and (
        not isinstance(expected_preimage_sha256, str) or len(expected_preimage_sha256) != 64
        or any(char not in "0123456789abcdef" for char in expected_preimage_sha256)
    ):
        raise ValueError("Expected preimage must be a lowercase SHA256 digest")
    if expect_absent and expected_preimage_sha256 is not None:
        raise ValueError("Absent publication cannot declare a preimage")
    if os.name != "nt":
        raise RuntimeError("Native Windows report publication requires Windows")
    absolute = os.path.abspath(os.fspath(path))
    wh.validate_root_path(absolute)
    payload = data.encode("utf-8")
    handles = wh.WindowsHandles()
    with ExitStack() as stack:
        parent, name = _parent(handles, stack, absolute)
        existing = None
        try:
            existing = stack.enter_context(
                handles.open_child(parent, name, kind="file",
                                   pin_for_read=not require_existing_write_access,
                                   for_write=require_existing_write_access)
            )
        except wh.WindowsHandleError as exc:
            if exc.operation != "NtCreateFile" or exc.ntstatus != MISSING:
                raise
        if expect_absent and existing is not None:
            raise wh.UnsafeWindowsPath("Trace target appeared before publication")
        if expected_preimage_sha256 is not None and (existing is None or _digest(existing) != expected_preimage_sha256):
            raise wh.UnsafeWindowsPath("Trace target preimage changed before staging")
        old_security = _security_tuple(existing) if existing is not None else None
        old_info = existing.info() if existing is not None else None
        temporary = None
        stage = None
        stage_identity = None
        try:
            for _ in range(8):
                candidate = f".naos-report-{os.getpid()}-{secrets.token_hex(8)}.tmp"
                try:
                    stage = (
                        handles.create_private_file(parent, candidate)
                        if existing is not None or private_new_file
                        else handles.create_report_child(parent, candidate, kind="file")
                    )
                    temporary = candidate
                    stage_identity = stage.info().identity
                    break
                except wh.WindowsHandleError as exc:
                    if exc.ntstatus != COLLISION:
                        raise
            else:
                raise FileExistsError("Unable to allocate a unique report staging file")
            # Apply/verify permissions before payload; a failed copy leaves no data.
            if existing is not None:
                handles.copy_report_security(existing, stage)
            expected_security = _security_tuple(stage)
            stage.write_all(payload)
            if existing is not None:
                handles.copy_supported_file_attributes(
                    existing, stage, expected_attributes=old_info.attributes
                )
                if (
                    _security_tuple(existing) != old_security
                    or existing.info() != old_info
                ):
                    raise wh.UnsafeWindowsPath("Existing report changed during staging")
            stage.flush()
            expected_attributes = (
                old_info.attributes if old_info is not None else stage.info().attributes
            )
            expected_hash = hashlib.sha256(payload).hexdigest()
            if (
                _digest(stage) != expected_hash
                or _security_tuple(stage) != expected_security
            ):
                raise wh.UnsafeWindowsPath("Report staging verification failed")
            if existing is not None:
                if (
                    _security_tuple(existing) != old_security
                    or existing.info() != old_info
                ):
                    raise wh.UnsafeWindowsPath(
                        "Existing report changed before publication"
                    )
                if expected_preimage_sha256 is not None and _digest(existing) != expected_preimage_sha256:
                    raise wh.UnsafeWindowsPath("Trace target preimage changed before publication")
                existing.close()
                handles.replace_report(stage, parent, name)
            else:
                # Preserve a concurrently created foreign leaf on first publication.
                handles.rename_no_replace(stage, parent, name)
            temporary = None
            stage.close()
            stage = None

            def verify(handle, *, attributes: bool = True):
                info = handle.info()
                if (
                    info.identity != stage_identity
                    or _digest(handle) != expected_hash
                    or _security_tuple(handle) != expected_security
                    or (attributes and info.attributes != expected_attributes)
                ):
                    raise wh.UnsafeWindowsPath("Published report verification failed")
                return info

            with handles.open_child(
                parent, name, kind="file", pin_for_read=True
            ) as published:
                info = verify(published, attributes=False)
            if info.attributes != expected_attributes:
                # NTFS may add ARCHIVE at rename/close. Restore only qualified
                # NORMAL/ARCHIVE on the exact published report, never by pathname.
                if (expected_attributes, info.attributes) != (0x80, 0x20):
                    raise wh.UnsafeWindowsPath(
                        "Unexpected published report attributes preserved"
                    )
                with handles.open_child(
                    parent, name, kind="file", for_metadata_restore=True
                ) as metadata:
                    current = verify(metadata, attributes=False)
                    if (expected_attributes, current.attributes) != (0x80, 0x20):
                        raise wh.UnsafeWindowsPath(
                            "Report attributes changed before metadata restoration"
                        )
                    handles.restore_rename_metadata(
                        metadata,
                        creation_time=current.created_time,
                        attributes=expected_attributes,
                    )
            with handles.open_child(
                parent, name, kind="file", pin_for_read=True
            ) as published:
                verify(published)
        finally:
            if stage is not None:
                stage.close()
            if temporary is not None:
                # Only delete our exact stage. Never delete a foreign name occupant.
                with handles.open_child(
                    parent, temporary, kind="file", for_delete=True
                ) as cleanup:
                    if cleanup.info().identity != stage_identity:
                        raise wh.UnsafeWindowsPath(
                            "Foreign report staging object preserved"
                        )
                    handles.delete_exact(parent, temporary, cleanup)
