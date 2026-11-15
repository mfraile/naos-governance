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
import time


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


def _retry_windows_publication(action, enabled: bool):
    """Retry only this held stage's native rename, with the legacy session cap."""
    for attempt in range(4 if enabled else 1):
        try:
            return action()
        except OSError as exc:
            if (not enabled or sys.platform != 'win32'
                    or not isinstance(exc, (PermissionError, wh.WindowsHandleError))
                    or getattr(exc, 'winerror', None) not in {5, 32, 33} or attempt == 3):
                raise
            time.sleep(0.05 * (2 ** attempt))


class _CleanupStack(ExitStack):
    def __init__(self, note):
        super().__init__()
        self.note = note

    def __exit__(self, kind, error, traceback):
        try:
            return super().__exit__(kind, error, traceback)
        except Exception as cleanup_error:
            if error is None or self.note is None or cleanup_error is error:
                raise
            error.add_note(f'{self.note}: {type(cleanup_error).__name__}')
            return False


def _parent(handles, stack: ExitStack, absolute: str, *, create_parents: bool = True):
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
            if not create_parents or exc.operation != "NtCreateFile" or exc.ntstatus != MISSING:
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


def ensure_report_directory(path: Path) -> tuple[int, bytes]:
    """Prepare directories with pinned no-reparse handles; create no file."""
    if os.name != "nt":
        raise RuntimeError("Native Windows directory preparation requires Windows")
    absolute = os.path.abspath(os.fspath(path / ".naos-directory-probe"))
    wh.validate_root_path(absolute)
    handles = wh.WindowsHandles()
    with ExitStack() as stack:
        parent, _name = _parent(handles, stack, absolute)
        return parent.info().identity


def report_parent_identity(path: Path) -> tuple[int, bytes]:
    """Observe the selected report parent through native no-reparse handles."""
    if os.name != "nt":
        raise RuntimeError("Native Windows report-parent observation requires Windows")
    absolute = os.path.abspath(os.fspath(path))
    wh.validate_root_path(absolute)
    handles = wh.WindowsHandles()
    with ExitStack() as stack:
        parent, _name = _parent(handles, stack, absolute, create_parents=False)
        return parent.info().identity


def probe_strict_report_output(path: Path, *, expect_absent: bool) -> tuple[int, bytes]:
    """Test report write authority and remove only our held probe stage."""
    if os.name != "nt":
        raise RuntimeError("Native Windows report probing requires Windows")
    absolute = os.path.abspath(os.fspath(path))
    wh.validate_root_path(absolute)
    handles = wh.WindowsHandles()
    with ExitStack() as stack:
        parent, name = _parent(handles, stack, absolute, create_parents=False)
        existing = None
        try:
            existing = stack.enter_context(
                handles.open_child(parent, name, kind="file", for_write=True)
            )
        except wh.WindowsHandleError as exc:
            if exc.operation != "NtCreateFile" or exc.ntstatus != MISSING:
                raise
        if (existing is None) != expect_absent:
            raise wh.UnsafeWindowsPath("Report output changed during preflight")
        if existing is None:
            stage = None
            candidate = None
            for _ in range(8):
                candidate = f".naos-spec-pack-report-probe-{os.getpid()}-{secrets.token_hex(8)}"
                try:
                    stage = handles.create_report_child(parent, candidate, kind="file")
                    break
                except wh.WindowsHandleError as exc:
                    if exc.ntstatus != COLLISION:
                        raise
            if stage is None or candidate is None:
                raise FileExistsError("Unable to allocate a report probe")
            stage_identity = stage.info().identity
            stage.close()
            with handles.open_child(parent, candidate, kind="file", for_delete=True) as cleanup:
                if cleanup.info().identity != stage_identity:
                    raise wh.UnsafeWindowsPath("Foreign report probe preserved")
                handles.delete_exact(parent, candidate, cleanup)
        return parent.info().identity


class _BorrowedReportStream:
    """Seekable ZIP I/O through an owned native handle; never owns its close."""
    def __init__(self, handle):
        self._handle = handle
        self._position = handle.seek(0)

    def seekable(self):
        return True

    def tell(self):
        return self._position

    def seek(self, offset, whence=0):
        if whence not in (0, 1, 2):
            raise ValueError("Invalid seek origin")
        base = 0 if whence == 0 else self._position if whence == 1 else self._handle.info().size
        target = base + offset
        if target < 0:
            raise OSError(22, "Negative file offset")
        self._position = self._handle.seek(target)
        return self._position

    def read(self, size=-1):
        remaining = max(0, self._handle.info().size - self._position)
        count = remaining if size is None or size < 0 else min(size, remaining)
        blocks = []
        while count:
            block = self._handle.read(min(count, 1024 * 1024))
            if not block:
                break
            blocks.append(block)
            count -= len(block)
            self._position += len(block)
        return b"".join(blocks)

    def write(self, data):
        data = data if isinstance(data, bytes) else memoryview(data).tobytes()
        self._handle.write_all(data)
        self._position += len(data)
        return len(data)

    def flush(self):
        self._handle.flush()


def write_strict_report(path: Path, data: str | bytes, *, private_new_file: bool = False,
                        require_existing_write_access: bool = False,
                        create_parents: bool = True,
                        expected_preimage_sha256: str | None = None,
                        expect_absent: bool = False,
                        binary_producer=None,
                        retry_windows_sharing: bool = False,
                        cleanup_error_note: str | None = None,
                        expected_parent_identity: tuple[int, bytes] | None = None) -> None:
    """Publish text or serialized bytes with supported native security.

    Existing supported security is preserved regardless of this creation policy.
    A private-creation verification refusal before handle return can leave an
    empty stage: no payload was written and no unregistered pathname is deleted.
    Publication is name refresh, not leaf CAS or a crash-durable transaction.
    Session callers may retry the held-stage rename at most four times for
    native errors 5/32/33, with 0.05/0.1/0.2-second delays. Optional cleanup notes
    preserve the primary error when ordinary cleanup also fails.
    """
    binary = binary_producer is not None
    if type(private_new_file) is not bool:
        raise ValueError("private_new_file must be a boolean")
    if any(type(value) is not bool for value in (require_existing_write_access, expect_absent, create_parents, retry_windows_sharing)):
        raise ValueError("Trace publication flags must be boolean")
    if cleanup_error_note is not None and (not isinstance(cleanup_error_note, str) or not cleanup_error_note):
        raise ValueError('Cleanup error note must be nonempty text')
    if not isinstance(data, (str, bytes)):
        raise TypeError("Publication content must be text or immutable bytes")
    if binary:
        from naos_trace_atomic_write import BinaryProducer
        if not isinstance(binary_producer, BinaryProducer) or data not in ("", b""):
            raise TypeError("Binary publication requires a binary producer and an empty payload")
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
    payload = data.encode("utf-8") if isinstance(data, str) else data
    handles = wh.WindowsHandles()
    with _CleanupStack(cleanup_error_note) as stack:
        parent, name = _parent(handles, stack, absolute, create_parents=create_parents)
        if (expected_parent_identity is not None
                and parent.info().identity != expected_parent_identity):
            raise wh.UnsafeWindowsPath("Report parent changed after preflight")
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
        old_digest = _digest(existing) if binary and existing is not None else None
        temporary = None
        stage = None
        stage_identity = None
        pending_error = None
        try:
            for _ in range(8):
                candidate = f".naos-report-{os.getpid()}-{secrets.token_hex(8)}.tmp"
                try:
                    if existing is not None:
                        stage = handles.create_private_report_stage(parent, candidate, existing)
                    elif private_new_file:
                        stage = handles.create_private_file(parent, candidate)
                    else:
                        stage = handles.create_report_child(parent, candidate, kind="file")
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
                if (_security_tuple(existing) != old_security
                        or _security_tuple(stage) != old_security):
                    raise wh.UnsafeWindowsPath("Existing report security changed before payload")
            expected_security = _security_tuple(stage)
            if binary:
                expected_size, expected_hash = binary_producer.render(_BorrowedReportStream(stage))
            else:
                stage.write_all(payload)
                expected_hash = hashlib.sha256(payload).hexdigest()
            if existing is not None:
                handles.copy_supported_file_attributes(
                    existing, stage, expected_attributes=old_info.attributes
                )
                if (
                    _security_tuple(existing) != old_security
                    or existing.info() != old_info
                    or (binary and _digest(existing) != old_digest)
                ):
                    raise wh.UnsafeWindowsPath("Existing report changed during staging")
            stage.flush()
            expected_attributes = (
                old_info.attributes if old_info is not None else stage.info().attributes
            )
            if (
                _digest(stage) != expected_hash
                or _security_tuple(stage) != expected_security
                or (binary and stage.info().size != expected_size)
            ):
                raise wh.UnsafeWindowsPath("Report staging verification failed")
            if existing is not None:
                if (
                    _security_tuple(existing) != old_security
                    or existing.info() != old_info
                    or (binary and _digest(existing) != old_digest)
                ):
                    raise wh.UnsafeWindowsPath(
                        "Existing report changed before publication"
                    )
                if expected_preimage_sha256 is not None and _digest(existing) != expected_preimage_sha256:
                    raise wh.UnsafeWindowsPath("Trace target preimage changed before publication")
                existing.close()
                _retry_windows_publication(lambda: handles.replace_report(stage, parent, name), retry_windows_sharing)
            else:
                # Preserve a concurrently created foreign leaf on first publication.
                _retry_windows_publication(lambda: handles.rename_no_replace(stage, parent, name), retry_windows_sharing)
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
        except BaseException as error:
            pending_error = error
            raise
        finally:
            def cleanup_stage():
                if stage is not None:
                    stage.close()
                if temporary is not None:
                    # Only delete our exact stage. Never delete a foreign name occupant.
                    with handles.open_child(
                        parent, temporary, kind="file", for_delete=True
                    ) as cleanup:
                        if cleanup.info().identity != stage_identity:
                            raise wh.UnsafeWindowsPath("Foreign report staging object preserved")
                        handles.delete_exact(parent, temporary, cleanup)
            # Keep this native byte API independent of the YAML policy layer.
            try:
                cleanup_stage()
            except Exception as cleanup_error:
                if pending_error is None or cleanup_error_note is None:
                    raise
                pending_error.add_note(
                    f'{cleanup_error_note}: {type(cleanup_error).__name__}'
                )
