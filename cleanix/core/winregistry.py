"""The registry backend abstraction.

All registry I/O goes through :class:`RegistryBackend`. The real ``winreg``
implementation lives in ``winregistry_win`` (imported lazily, Windows only);
tests install an in-memory fake with :func:`set_backend`. This module imports
on every platform.
"""

from __future__ import annotations

import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, List, Optional, Protocol, Tuple, Union

REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_BIG_ENDIAN = 5
REG_LINK = 6
REG_MULTI_SZ = 7
REG_QWORD = 11


@dataclass(frozen=True)
class RegValue:
    name: str
    type: int
    data: Union[str, int, bytes, Tuple[str, ...]]


class RegistryError(Exception):
    """Any registry failure."""


class KeyMissing(RegistryError):
    """The key or value does not exist."""


class AccessDenied(RegistryError):
    """Windows refused access to the key or value."""


class RegistryUnavailable(RegistryError):
    """There is no registry on this platform (or no backend was installed)."""


class RegistryBackend(Protocol):
    """Registry operations. ``hive`` is ``"HKCU"`` or ``"HKLM"``; ``key`` is
    the physical path below the hive (``WOW6432Node`` spelled out)."""

    def subkeys(self, hive: str, key: str) -> List[str]: ...

    def values(self, hive: str, key: str) -> List[RegValue]: ...

    def key_exists(self, hive: str, key: str) -> bool: ...

    def is_link(self, hive: str, key: str) -> bool: ...

    def can_delete(self, hive: str, key: str, value: Optional[str]) -> bool: ...

    def delete_key(self, hive: str, key: str) -> None:
        """Delete a leaf key only."""

    def delete_value(self, hive: str, key: str, name: str) -> None: ...

    def create_key(self, hive: str, key: str) -> None:
        """Create the key and any missing parents; idempotent."""

    def set_value(self, hive: str, key: str, value: RegValue) -> None: ...


class _UnavailableBackend:
    """Every call raises :class:`RegistryUnavailable`."""

    def _fail(self, *_a, **_k):
        raise RegistryUnavailable("the Windows registry is not available here")

    subkeys = values = key_exists = is_link = can_delete = _fail
    delete_key = delete_value = create_key = set_value = _fail


_lock = threading.Lock()
_override: Optional[RegistryBackend] = None
_real: Optional[RegistryBackend] = None


def set_backend(b: Optional[RegistryBackend]) -> None:
    """Install ``b`` as the backend (``None`` restores the default)."""
    global _override
    _override = b


def backend_override() -> Optional[RegistryBackend]:
    """The installed override, or ``None``."""
    return _override


@contextmanager
def using_backend(b: Optional[RegistryBackend]) -> Iterator[Optional[RegistryBackend]]:
    global _override
    previous = _override
    _override = b
    try:
        yield b
    finally:
        _override = previous


def get_backend() -> RegistryBackend:
    """The override if set, else the real backend on Windows, else a backend
    whose every method raises :class:`RegistryUnavailable`."""
    global _real
    if _override is not None:
        return _override
    if sys.platform != "win32":
        return _UnavailableBackend()
    with _lock:
        if _real is None:
            try:
                from cleanix.core.winregistry_win import WinRegBackend

                _real = WinRegBackend()
            except ImportError:
                return _UnavailableBackend()
        return _real
