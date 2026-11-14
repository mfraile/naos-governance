"""Atomic trace-name publication with bounded existing write/metadata preservation.

Publication retains the report writers' name-refresh gap. No writer lock or
power-loss durability claim. Unsupported metadata refuses before publication.
Failed unpublished POSIX stages are left for manual review without name deletion.
"""
from __future__ import annotations

import hashlib
import ctypes
import importlib
import os
from pathlib import Path
import secrets
import stat
import sys
import types
from contextlib import contextmanager
from dataclasses import dataclass
from typing import BinaryIO, Callable

from naos_policy import _open_report_parent_fd, _report_metadata_at, _secure_directory_fd_writes_supported


def _metadata_module():
    sibling = Path(__file__).with_name('naos_posix_metadata')
    directory = sibling if sibling.is_dir() else Path(__file__).resolve().parents[1] / 'upgrade_contract'
    if not all((directory / filename).is_file() for filename in ('security.py', 'linux_primitives.py')):
        raise ValueError('Trace atomic publication metadata helper distribution is incomplete')
    name = '_naos_trace_posix_metadata'
    if name not in sys.modules:
        package = types.ModuleType(name)
        package.__path__ = [str(directory)]
        sys.modules[name] = package
    return importlib.import_module(name + '.security')


def _bytes(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks = []
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            return b''.join(chunks)
        chunks.append(block)


def _digest_fd(descriptor: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while block := os.read(descriptor, 1024 * 1024):
        digest.update(block)
    return digest.hexdigest()


def _stream_fingerprint(stream) -> tuple[int, str]:
    size = stream.seek(0, os.SEEK_END)
    stream.seek(0)
    remaining = size
    digest = hashlib.sha256()
    while remaining:
        block = stream.read(min(remaining, 1024 * 1024))
        if not isinstance(block, bytes) or not block or len(block) > remaining:
            raise ValueError('Binary stage ended before its observed size')
        digest.update(block)
        remaining -= len(block)
    return size, digest.hexdigest()


def _source_identity(info):
    # Windows lstat/fstat can expose different ctime meanings. Compare their
    # common fields; reads do not require any file/directory mutation authority.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns)


@contextmanager
def read_trace_source(path: Path):
    """Read a regular single-link preimage; close this context before publishing.

    Reuse observational resource checks plus lstat/fstat identity observations,
    including reparse refusal. Named-file reads need search authority, not parent
    directory listing or mutation authority. This is not a concurrent-filesystem
    sandbox; publication independently enforces the exact preimage and its native
    output boundary. Missing inputs create no directories; unsafe is not absent.
    """
    from naos_resource_boundary import resource_reference

    descriptor = -1
    try:
        missing = False
        try:
            absolute = path.absolute()
            resource_reference(absolute, Path(absolute.anchor))
            before = absolute.lstat()
            if before.st_nlink != 1:
                raise ValueError('Refusing multiply-linked trace source')
            flags = (os.O_RDONLY | getattr(os, 'O_BINARY', 0)
                     | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
            descriptor = os.open(absolute, flags)
        except FileNotFoundError:
            missing = True
        if missing:
            yield None
            return
        held = os.fstat(descriptor)
        if not stat.S_ISREG(held.st_mode) or _source_identity(before) != _source_identity(held):
            raise ValueError('Trace source identity changed before reading')
        with os.fdopen(descriptor, 'rb') as stream:
            descriptor = -1
            yield stream
            after = os.fstat(stream.fileno())
            resource_reference(absolute, Path(absolute.anchor))
            named = absolute.lstat()
            if (_source_identity(held) != _source_identity(after)
                    or _source_identity(after) != _source_identity(named)):
                raise ValueError('Trace source changed during reading')
    finally:
        if descriptor >= 0:
            os.close(descriptor)


@dataclass(frozen=True)
class BinaryProducer:
    """Trusted producer and validator for one held, seekable publication stage."""
    produce: Callable[[BinaryIO], None]
    validate: Callable[[BinaryIO], None]

    def __post_init__(self):
        if not callable(self.produce) or not callable(self.validate):
            raise TypeError('Binary publication requires producer and validator callbacks')

    def render(self, stream) -> tuple[int, str]:
        self.produce(stream)
        stream.flush()
        expected = _stream_fingerprint(stream)
        stream.seek(0)
        self.validate(stream)
        stream.flush()
        if _stream_fingerprint(stream) != expected:
            raise ValueError('Binary staging content changed during validation')
        return expected


def _metadata_key(value):
    return tuple(value[key] for key in ('uid', 'gid', 'mode', 'flags', 'acl_entries', 'xattrs'))


def _run_cleanup(action, pending_error, note):
    """Opt-in preservation of this operation's primary error during cleanup."""
    try:
        action()
    except Exception as cleanup_error:
        if pending_error is None or note is None:
            raise
        pending_error.add_note(f'{note}: {type(cleanup_error).__name__}')


def _report_retained_stage(location: Path, error: BaseException) -> None:
    """Report an observed name, without authenticating its present occupant."""
    note = (
        f'Unpublished POSIX stage retained without automatic deletion; last observed location: {str(location)!r}. '
        'The name may have moved or identify a foreign occupant; review manually.'
    )
    BaseException.add_note(error, note)
    try:
        print(note, file=sys.stderr)
    except Exception:
        # A broken diagnostic sink must not replace the operation's primary error.
        # The exception note remains available even when stderr cannot be written.
        pass


def _stage_name_matches(parent: int, name: str, descriptor: int) -> bool:
    """Qualify the name against our still-held unique regular staging object."""
    try:
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        held = os.fstat(descriptor)
    except OSError:
        return False
    return (stat.S_ISREG(named.st_mode) and named.st_nlink == 1
            and stat.S_ISREG(held.st_mode) and held.st_nlink == 1
            and (named.st_dev, named.st_ino) == (held.st_dev, held.st_ino))


def _publish_no_replace(parent: int, source: str, destination: str, metadata) -> None:
    """Native create-only rename, using the managed-transaction ABI precedent."""
    if sys.platform == 'linux':
        metadata.linux_primitives.rename_at(parent, source, parent, destination)
        return
    if sys.platform != 'darwin':
        raise ValueError('Create-only atomic publication primitives unavailable')
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameatx_np
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    # RENAME_EXCL | RENAME_NOFOLLOW_ANY, as transaction.rename_no_replace_at.
    if rename(parent, os.fsencode(source), parent, os.fsencode(destination), 0x00000004 | 0x00000010) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number), destination)


def publish_trace(path: Path, content: str | bytes | BinaryProducer, original: bytes | None, *,
                  strict_parent_topology: bool = False,
                  observe_current: bool = False,
                  private_new_file: bool = False,
                  create_only: bool = False,
                  fsync_parent: bool = False,
                  search_only_ancestors: bool = False,
                  create_parents: bool = True,
                  require_existing_write_access: bool = True,
                  expected_preimage_sha256: str | None = None,
                  posix_creation_mode: int | None = None,
                  preserve_existing_posix_mode: bool = True,
                  retry_windows_sharing: bool = False,
                  cleanup_error_note: str | None = None) -> None:
    """Publish a bound trace, or explicitly observe a replaceable text output.

    Existing callers retain their supplied-preimage checks. Output callers may
    capture the current preimage through the held, no-follow source descriptor.
    POSIX state callers can request 0600/0666 creation filtered by the current
    umask, and opt out of preserving an old POSIX mode. This never changes the
    process umask. Native Windows security preservation is independent of these
    POSIX options. Retry and cleanup options are opt-in compatibility policies.
    Failed unpublished POSIX stages are retained without deleting their names;
    stderr and the primary exception note report the last observed location.
    That location does not authenticate a present occupant. Windows is unchanged.
    POSIX callers can retain a directory-sync attempt through the held parent
    after publication. A sync failure preserves the complete published file.
    Native Windows retains its existing handle-flush behavior.
    Search-only POSIX ancestor handles are opt-in; the final parent retains its
    read handle for metadata operations and optional directory sync.
    """
    binary = isinstance(content, BinaryProducer)
    if not isinstance(content, (str, bytes, BinaryProducer)):
        raise TypeError('Publication content must be text, immutable bytes or a binary producer')
    if binary and ((not observe_current and not create_only) or original is not None):
        raise ValueError('Binary publication requires observed-current or create-only output')
    if expected_preimage_sha256 is not None:
        if (not binary or not observe_current
                or not isinstance(expected_preimage_sha256, str)
                or len(expected_preimage_sha256) != 64
                or any(char not in '0123456789abcdef' for char in expected_preimage_sha256)):
            raise ValueError('Expected binary preimage must be a lowercase SHA256 digest')
    if any(type(value) is not bool for value in (private_new_file, create_only, fsync_parent, search_only_ancestors,
                                               create_parents, require_existing_write_access,
                                               preserve_existing_posix_mode, retry_windows_sharing)):
        raise ValueError('Publication modes must be booleans')
    if posix_creation_mode is not None and (type(posix_creation_mode) is not int or posix_creation_mode not in {0o600, 0o666}):
        raise ValueError('POSIX creation mode must be 0600 or 0666')
    if not preserve_existing_posix_mode and posix_creation_mode is None:
        raise ValueError('Mode reset requires an explicit POSIX creation mode')
    if cleanup_error_note is not None and (not isinstance(cleanup_error_note, str) or not cleanup_error_note):
        raise ValueError('Cleanup error note must be nonempty text')
    if create_only and (original is not None or observe_current):
        raise ValueError('Create-only publication cannot replace an observed preimage')
    if os.name == 'nt':
        import naos_windows_report as native
        options = {}
        if retry_windows_sharing:
            options['retry_windows_sharing'] = True
        if cleanup_error_note is not None:
            options['cleanup_error_note'] = cleanup_error_note
        try:
            native.write_strict_report(path, "" if binary else content, private_new_file=private_new_file,
                                       require_existing_write_access=require_existing_write_access,
                                       create_parents=create_parents and expected_preimage_sha256 is None,
                                       expected_preimage_sha256=hashlib.sha256(original).hexdigest() if original is not None else expected_preimage_sha256,
                                       expect_absent=create_only or (original is None and not observe_current),
                                       **options,
                                       **({"binary_producer": content} if binary else {}))
        except native.wh.WindowsHandleError as exc:
            if (create_only and exc.ntstatus == native.COLLISION
                    and exc.operation == 'NtSetInformationFile(FileRenameInformation)'):
                raise FileExistsError(f'Create-only output appeared before publication: {path}') from exc
            raise
        except native.wh.UnsafeWindowsPath as exc:
            if create_only and str(exc) == 'Trace target appeared before publication':
                raise FileExistsError(f'Create-only output already exists: {path}') from exc
            raise
        return
    if not _secure_directory_fd_writes_supported() or not callable(getattr(os, 'fchown', None)):
        raise ValueError('Trace atomic publication metadata primitives unavailable')
    display_parent = path.absolute().parent
    metadata = _metadata_module()
    parent, name = _open_report_parent_fd(path, strict_parent_topology=strict_parent_topology,
                                        create_parents=create_parents and expected_preimage_sha256 is None,
                                        search_only_ancestors=search_only_ancestors)
    source = stage = -1
    temporary = None
    pending_error = None
    try:
        leaf = _report_metadata_at(parent, name, path)
        if expected_preimage_sha256 is not None and leaf is None:
            raise ValueError('Trace target preimage disappeared before staging')
        if create_only and leaf is not None:
            raise FileExistsError(f'Create-only output already exists: {path}')
        if not observe_current and (leaf is None) != (original is None):
            raise ValueError('Trace target changed before staging')
        observed = None
        original_digest = None
        if leaf is not None:
            # Report/trace callers retain actual write-open authority. Config
            # callers may explicitly retain their prior parent-authorized rename.
            try:
                access = os.O_RDWR if require_existing_write_access else os.O_RDONLY
                source = os.open(name, access | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            except PermissionError as exc:
                if not observe_current:
                    raise
                requirement = 'readable and writable' if require_existing_write_access else 'readable'
                raise ValueError(
                    f'Refusing publication: existing output must be {requirement} '
                    'to preserve its metadata; destination left unchanged'
                ) from exc
            observed = metadata.observe_created_file_metadata_fd(source)
            if observe_current:
                if binary:
                    original_digest = _digest_fd(source)
                    if expected_preimage_sha256 is not None and original_digest != expected_preimage_sha256:
                        raise ValueError('Trace target preimage changed before staging')
                else:
                    original = _bytes(source)
            content_changed = _digest_fd(source) != original_digest if binary else _bytes(source) != original
            if (observed['device'], observed['inode']) != (leaf.st_dev, leaf.st_ino) or content_changed:
                raise ValueError('Trace target changed before staging')
            if not metadata.supported_metadata_flags(observed) or observed['acl_entries']:
                raise ValueError('Trace metadata preservation does not support these flags/ACLs')
        for _ in range(8):
            candidate = '.naos-trace-' + str(os.getpid()) + '-' + secrets.token_hex(8) + '.tmp'
            try:
                mode = 0o600 if private_new_file else (0o666 if posix_creation_mode is None else posix_creation_mode)
                stage = os.open(candidate, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
                temporary = candidate
                break
            except FileExistsError:
                continue
        else:
            raise FileExistsError('Cannot allocate trace publication stage')
        if private_new_file:
            # The prior private-config writer established mode 0600 explicitly,
            # even when umask masks owner bits. Only our held empty stage changes.
            os.fchmod(stage, 0o600)
        elif posix_creation_mode is not None and not os.fstat(stage).st_mode & stat.S_IRUSR:
            raise ValueError(
                'Refusing publication: owner-read is masked by the creation permissions; '
                'metadata cannot be safely verified; destination left unchanged and process umask preserved'
            )
        initial = metadata.observe_created_file_metadata_fd(stage)
        if private_new_file and initial['mode'] != 0o600:
            raise ValueError('Private publication stage permissions must be 0600')
        if not metadata.supported_metadata_flags(initial) or initial['acl_entries']:
            raise ValueError('Trace staging metadata is unsupported')
        output_mode = observed['mode'] if observed is not None and preserve_existing_posix_mode else initial['mode']
        if observed is not None:
            if (initial['uid'], initial['gid']) != (observed['uid'], observed['gid']):
                os.fchown(stage, observed['uid'], observed['gid'])
            os.fchmod(stage, output_mode)
            secured = metadata.observe_created_file_metadata_fd(stage)
            if tuple(secured[key] for key in ('uid', 'gid', 'mode')) != (observed['uid'], observed['gid'], output_mode):
                raise ValueError('Trace staging permissions could not be preserved before payload')
            if observed['platform'] == 'Linux':
                metadata.linux_primitives.copy_data_and_xattrs(source, stage)
            else:
                # Same bounded native xattr copy used by v3_publication_stage.
                libc = ctypes.CDLL(None, use_errno=True)
                copy = libc.fcopyfile
                copy.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
                copy.restype = ctypes.c_int
                if copy(source, stage, None, 0x00000004) != 0:  # COPYFILE_XATTR
                    raise OSError(ctypes.get_errno(), 'Native trace xattr preservation failed')
        os.lseek(stage, 0, os.SEEK_SET)
        if binary:
            os.ftruncate(stage, 0)
            with os.fdopen(os.dup(stage), 'r+b', buffering=0) as stream:
                payload_size, payload_digest = content.render(stream)
        else:
            payload = content.encode('utf-8') if isinstance(content, str) else content
            remaining = memoryview(payload)
            while remaining:
                written = os.write(stage, remaining)
                if written <= 0:
                    raise OSError('Trace staging write made no progress')
                remaining = remaining[written:]
            payload_size = len(payload)
        os.ftruncate(stage, payload_size)
        if observed is not None:
            os.fchmod(stage, output_mode)
        os.fsync(stage)
        staged = metadata.observe_created_file_metadata_fd(stage)
        expected = {**observed, 'mode': output_mode} if observed is not None else initial
        content_changed = (os.fstat(stage).st_size != payload_size or _digest_fd(stage) != payload_digest) if binary else _bytes(stage) != payload
        if _metadata_key(staged) != _metadata_key(expected) or content_changed:
            raise ValueError('Trace staging bytes/metadata preservation could not be verified')
        current = _report_metadata_at(parent, name, path)
        if observed is not None:
            if current is None or (current.st_dev, current.st_ino) != (observed['device'], observed['inode']):
                raise ValueError('Trace target identity changed before publication')
            content_changed = _digest_fd(source) != original_digest if binary else _bytes(source) != original
            if metadata.observe_created_file_metadata_fd(source) != observed or content_changed:
                raise ValueError('Trace target content/metadata changed before publication')
        elif current is not None:
            raise ValueError('Trace target appeared before publication')
        if not _stage_name_matches(parent, temporary, stage):
            raise ValueError('Trace staging name no longer identifies the held stage; foreign occupant preserved')
        # Whole-file rename publication; the name can change after the last check.
        if create_only:
            _publish_no_replace(parent, temporary, name, metadata)
        else:
            os.rename(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        temporary = None
        if fsync_parent:
            os.fsync(parent)
    except BaseException as error:
        pending_error = error
        if temporary is not None:
            _report_retained_stage(display_parent / temporary, error)
        raise
    finally:
        def cleanup():
            try:
                if source >= 0:
                    os.close(source)
            finally:
                try:
                    if stage >= 0:
                        os.close(stage)
                finally:
                    os.close(parent)
        _run_cleanup(cleanup, pending_error, cleanup_error_note)
