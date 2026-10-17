"""Continuous native custody of the latest journal in a multi-journal store.

This internal mechanism pins identities/protections and holds the existing scope
lock. It does not validate journal semantics, approve a plan, freeze inventories,
or authorize mutation. Operation inspectors must finish fresh immutable reads
before and after every approved mutation, as in the initial rebind lifecycle.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
from types import SimpleNamespace

from . import local_binding as lb
from . import rebind_store_inspection as store
from .rebind_publication import _PosixCustodyReader


class OperationCustodyError(ValueError):
    """Existing local custody could not be held continuously."""


def _directories(journal_ids):
    if (type(journal_ids) is not tuple or not journal_ids
            or len(journal_ids) > lb.MAX_JOURNALS
            or any(type(name) is not str or name != f'J{index:08d}'
                   for index, name in enumerate(journal_ids, 1))):
        raise OperationCustodyError('Complete ordered journal IDs are required')
    # Historical records are checked by fresh immutable inspectors. Holding two
    # native handles for every historical journal would exhaust platform limits
    # before the codec's supported history bound. Mutation custody only exposes
    # the latest existing journal, with constant directory-handle usage.
    journal = store.ROOT + '/journals/' + journal_ids[-1]
    return (*lb.CONTROL_DIRECTORIES, journal, journal + '/progress')


class _PosixReader(_PosixCustodyReader):
    """Reuse initial lifecycle custody checks with explicit journal coverage."""

    def __init__(self, root, stack, directories):
        from .working_tree_capture_posix import _Reader
        from .portable_provenance_posix import _witness
        self.reader = stack.enter_context(_Reader(Path(root)))
        self.fds = {'': self.reader.root_fd}
        self.witnesses = {}
        for path in directories:
            with ExitStack() as temporary:
                fd = self.reader._walk(path, temporary)
                if fd is None:
                    raise OperationCustodyError('Required journal directory is absent')
                pin = os.dup(fd)
                stack.callback(os.close, pin)
                self.fds[path] = pin
                self.witnesses[path] = lb.project_posix_witness(
                    _witness(pin, leaf=False, label=path).metadata)
        self.check()


def _windows_check(reader):
    # Custody spans our own directory-content mutations. Full metadata and
    # inventory stability belong to the separate immutable inspection lane.
    # Identity, protections, supported metadata and namespace remain mandatory.
    for key, held in reader.directories.items():
        expected = reader.baselines[key][1]
        if reader._observe(held, directory=True)[1] != expected:
            raise OperationCustodyError('Pinned directory identity or protection changed')
        opened = (reader.handles.open_child(reader.directories[key[:-1]], key[-1],
                  kind='directory', pin_for_read=True) if key
                  else reader.handles.open_root(reader.drive))
        with opened:
            if reader._observe(opened, directory=True)[1] != expected:
                raise OperationCustodyError('Pinned directory namespace changed')


class _OperationStore(store._NativeStore):
    def check_lock(self):
        if self.lock_handle is None:
            raise OperationCustodyError('An acquired operation lock is required')
        if self.windows:
            _windows_check(self.reader)
        else:
            self.reader.check()
        super().check_lock()
        receiving_legacy = getattr(self, 'receiving_legacy', None)
        if receiving_legacy is not None:
            # Primitive guards retain current pins/lock checks. Complete legacy
            # proof belongs to the explicit immutable/mutation boundaries.
            receiving_legacy.check_lock()


@contextmanager
def _held_operation_store(project_root, *, journal_ids, handles=None):
    """Hold the latest existing journal without treating the list as proof.

    A separate inspector must compare this list to complete native enumeration
    and validated registration/terminal records. Unknown/partial histories are
    never accepted by this helper as a quiescent or mutation-eligible store.
    Historical directories are not held across mutation; the after-inspector
    must detect any history substitution. A new journal must be witnessed and
    pinned separately before this helper can expose it for writes.
    """
    directories = _directories(journal_ids)
    windows = handles is not None or os.name == 'nt'
    try:
        with ExitStack() as stack:
            if windows:
                from .working_tree_capture_windows import _Capture
                from .windows_handles import WindowsHandles
                reader = _Capture(handles if handles is not None else WindowsHandles(),
                                  str(project_root), stack)
            else:
                reader = _PosixReader(project_root, stack, directories)
            native = _OperationStore(SimpleNamespace(working_reader=reader), windows)
            # All local store/journal storage must satisfy the existing private
            # policy. .naos itself remains an adopter-owned control ancestor.
            for path in directories[1:]:
                native.directory(path)
            with native.locked():
                native.check_lock()
                yield native
                native.check_lock()
    except OperationCustodyError:
        raise
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise OperationCustodyError(f'Native operation custody refused: {exc}') from exc
