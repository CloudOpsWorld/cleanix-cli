"""The ``winreg`` implementation of :class:`~cleanix.core.winregistry.RegistryBackend`.

This is the only module that imports ``winreg``, and it does so lazily in
:class:`WinRegBackend`'s constructor, so the module itself imports on every OS.
:func:`cleanix.core.winregistry.get_backend` builds it only on win32.

Rules every method follows:

* ``hive`` is exactly ``"HKCU"`` or ``"HKLM"``; anything else is a
  :class:`ValueError` raised before any registry call. ``key`` is a physical
  path below the hive (``WOW6432Node`` spelled out); an empty key or an empty
  component is a :class:`ValueError` (a caller bug).
* A key or value name containing NUL (which only registry data can supply,
  e.g. an odd subkey name met during a scan) raises
  :class:`InvalidRegistryName`, which is both a :class:`RegistryError` and a
  :class:`ValueError`, so a snapshot or detector skips it instead of crashing.
* Every open, create and delete carries ``KEY_WOW64_64KEY``: there is no
  registry redirection, and the 32-bit view is reached only through explicit
  ``WOW6432Node`` paths.
* Links: ``is_link`` and ``key_exists`` open the key itself with
  ``REG_OPTION_OPEN_LINK``; ``delete_key``, ``delete_value`` and ``set_value``
  check the key through an ``REG_OPTION_OPEN_LINK`` handle and refuse a
  registry link.
* Deletes are leaf-only (``DeleteKeyEx``, never a tree delete) and values are
  deleted by exact name.
* Every ``OSError`` becomes :class:`KeyMissing` (not found),
  :class:`AccessDenied` (denied) or :class:`RegistryError` (anything else,
  e.g. in use / marked for deletion). Handles are always closed; a failing
  close never masks the error already in flight.

Residual race (plan ruling R17): ``delete_key`` checks link-ness and
leaf-ness on a handle immediately before ``DeleteKeyEx``, but ``DeleteKeyEx``
resolves the path again. ``RegDeleteKeyEx`` very likely follows a link in the
last path component, so if the leaf is replaced by a registry link inside that
window, the link's TARGET key (when it is a leaf) may be deleted, not merely a
stale entry. The window is kept minimal (no work between the check and the
delete), the caller (Task 11) re-verifies the target's fingerprint
immediately before calling ``delete_key``, and Task 14 measures the real
behaviour.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator, List, Optional

from cleanix.core.winregistry import (
    REG_LINK,
    REG_MULTI_SZ,
    AccessDenied,
    KeyMissing,
    RegistryError,
    RegValue,
)

DELETE = 0x00010000  # standard access right; not exported by winreg
_ERROR_FILE_NOT_FOUND = 2
_ERROR_PATH_NOT_FOUND = 3
_ERROR_ACCESS_DENIED = 5
_ERROR_NO_MORE_ITEMS = 259
_LINK_VALUE = "SymbolicLinkValue"


class InvalidRegistryName(RegistryError, ValueError):
    """A key or value name the registry API cannot take (embedded NUL)."""


def _map_error(exc: BaseException, what: str) -> RegistryError:
    if isinstance(exc, ValueError):
        return InvalidRegistryName(f"invalid name: {what!r}")
    winerror = getattr(exc, "winerror", None)
    if isinstance(exc, FileNotFoundError) or winerror in (
        _ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND
    ):
        return KeyMissing(what)
    if isinstance(exc, PermissionError) or winerror == _ERROR_ACCESS_DENIED:
        return AccessDenied(what)
    return RegistryError(f"{what}: {exc}")


@contextmanager
def _mapped(what: str) -> Iterator[None]:
    try:
        yield
    except (OSError, ValueError) as exc:
        if isinstance(exc, RegistryError):
            raise
        raise _map_error(exc, what) from exc


def _is_missing(exc: OSError) -> bool:
    return isinstance(exc, FileNotFoundError) or getattr(exc, "winerror", None) in (
        _ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND
    )


def _is_denied(exc: OSError) -> bool:
    return isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == _ERROR_ACCESS_DENIED


def _is_end(exc: OSError) -> bool:
    return getattr(exc, "winerror", None) == _ERROR_NO_MORE_ITEMS


def _check_key(key: Any) -> str:
    if not isinstance(key, str) or not key or any(p == "" for p in key.split("\\")):
        raise ValueError(f"malformed registry key: {key!r}")
    if "\x00" in key:
        raise InvalidRegistryName(f"invalid name: {key!r}")
    return key


def _check_name(name: Any) -> str:
    if not isinstance(name, str):
        raise ValueError(f"malformed value name: {name!r}")
    if "\x00" in name:
        raise InvalidRegistryName(f"invalid name: {name!r}")
    return name


def _norm_data(data: Any) -> Any:
    """Match regsnap: REG_MULTI_SZ is a tuple, binary is bytes, no data is b""."""
    if data is None:
        return b""
    if isinstance(data, list):
        return tuple(data)
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    return data


class WinRegBackend:
    """Registry access through ``winreg`` (or an injected stand-in)."""

    def __init__(self, winreg_module: Any = None) -> None:
        if winreg_module is None:
            import winreg as winreg_module  # Windows only; see module docstring
        self._w = winreg_module
        self._hives = {
            "HKCU": winreg_module.HKEY_CURRENT_USER,
            "HKLM": winreg_module.HKEY_LOCAL_MACHINE,
        }

    # -- helpers -------------------------------------------------------------
    def _root(self, hive: Any) -> Any:
        if not isinstance(hive, str) or hive not in self._hives:
            raise ValueError(f"hive not allowed: {hive!r}")
        return self._hives[hive]

    def _view(self, access: int) -> int:
        return access | self._w.KEY_WOW64_64KEY

    def _close(self, handle: Any, what: str) -> None:
        """Close ``handle`` after a successful operation; a close failure is
        a :class:`RegistryError`. (On the error path, see _close_quietly.)"""
        try:
            self._w.CloseKey(handle)
        except OSError as exc:
            raise RegistryError(f"{what}: closing the key failed: {exc}") from exc

    @contextmanager
    def _open(self, hive: str, key: str, access: int, options: int = 0) -> Iterator[Any]:
        """Open ``hive\\key`` (64-bit view) and always close the handle.
        Opening errors are mapped; errors inside the block propagate as is."""
        root = self._root(hive)
        _check_key(key)
        what = f"{hive}\\{key}"
        with _mapped(what):
            handle = self._w.OpenKeyEx(root, key, options, self._view(access))
        try:
            yield handle
        except BaseException:
            self._close_quietly(handle)
            raise
        self._close(handle, what)

    def _close_quietly(self, handle: Any) -> None:
        try:
            self._w.CloseKey(handle)
        except OSError:
            pass  # the exception already in flight is the one to report

    def _handle_is_link(self, h: Any, what: str) -> bool:
        try:
            _data, typ = self._w.QueryValueEx(h, _LINK_VALUE)
        except OSError as exc:
            if _is_missing(exc):
                return False
            raise _map_error(exc, what) from exc
        except ValueError as exc:
            raise _map_error(exc, what) from exc
        return typ == REG_LINK

    def _refuse_link(self, h: Any, what: str) -> None:
        if self._handle_is_link(h, what):
            raise RegistryError(f"refusing to modify a registry link: {what}")

    def _enumerate(self, h: Any, fn: Any, what: str) -> List[Any]:
        out: List[Any] = []
        i = 0
        while True:
            try:
                out.append(fn(h, i))
            except OSError as exc:
                if _is_end(exc):
                    return out
                raise _map_error(exc, what) from exc
            except ValueError as exc:
                raise _map_error(exc, what) from exc
            i += 1

    # -- RegistryBackend -----------------------------------------------------
    def subkeys(self, hive: str, key: str) -> List[str]:
        what = f"{hive}\\{key}"
        with self._open(hive, key, self._w.KEY_ENUMERATE_SUB_KEYS) as h:
            return self._enumerate(h, self._w.EnumKey, what)

    def values(self, hive: str, key: str) -> List[RegValue]:
        what = f"{hive}\\{key}"
        with self._open(hive, key, self._w.KEY_QUERY_VALUE) as h:
            raw = self._enumerate(h, self._w.EnumValue, what)
        return [RegValue(name, typ, _norm_data(data)) for name, data, typ in raw]

    def key_exists(self, hive: str, key: str) -> bool:
        """Whether the key itself exists; a link counts even if dangling."""
        try:
            with self._open(hive, key, self._w.KEY_QUERY_VALUE, self._w.REG_OPTION_OPEN_LINK):
                return True
        except KeyMissing:
            return False
        except AccessDenied:
            return True  # Windows found the key and refused the access

    def is_link(self, hive: str, key: str) -> bool:
        what = f"{hive}\\{key}"
        with self._open(hive, key, self._w.KEY_QUERY_VALUE, self._w.REG_OPTION_OPEN_LINK) as h:
            return self._handle_is_link(h, what)

    def can_delete(self, hive: str, key: str, value: Optional[str]) -> bool:
        """Whether this process may delete the key (``value`` None) or the
        value. Missing or denied is False; any other failure raises."""
        what = f"{hive}\\{key}"
        if value is None:
            access = DELETE | self._w.KEY_ENUMERATE_SUB_KEYS | self._w.KEY_QUERY_VALUE
        else:
            _check_name(value)
            access = self._w.KEY_SET_VALUE | self._w.KEY_QUERY_VALUE
        try:
            with self._open(hive, key, access) as h:
                if value is not None:
                    try:
                        self._w.QueryValueEx(h, value)
                    except OSError as exc:
                        if _is_missing(exc) or _is_denied(exc):
                            return False
                        raise _map_error(exc, what) from exc
                    except ValueError as exc:
                        raise _map_error(exc, what) from exc
                return True
        except (KeyMissing, AccessDenied):
            return False

    def delete_key(self, hive: str, key: str) -> None:
        """Delete a leaf key. A key with subkeys or a registry link is
        refused with :class:`RegistryError` and nothing is deleted. See the
        module docstring for the residual race (R17)."""
        root = self._root(hive)
        what = f"{hive}\\{key}"
        with self._open(
            hive, key,
            self._w.KEY_QUERY_VALUE | self._w.KEY_ENUMERATE_SUB_KEYS,
            self._w.REG_OPTION_OPEN_LINK,
        ) as h:
            self._refuse_link(h, what)
            with _mapped(what):
                n_subkeys = self._w.QueryInfoKey(h)[0]
        if n_subkeys:
            raise RegistryError(f"key has subkeys: {what}")
        with _mapped(what):  # nothing else between the check and the delete
            self._w.DeleteKeyEx(root, key, self._w.KEY_WOW64_64KEY, 0)

    def delete_value(self, hive: str, key: str, name: str) -> None:
        _check_name(name)
        what = f"{hive}\\{key}"
        # One handle to the key itself (never a link target): the link check
        # and the delete act on the same key.
        with self._open(
            hive, key,
            self._w.KEY_QUERY_VALUE | self._w.KEY_SET_VALUE,
            self._w.REG_OPTION_OPEN_LINK,
        ) as h:
            self._refuse_link(h, what)
            with _mapped(f"{what}\\{name}"):
                self._w.DeleteValue(h, name)

    def create_key(self, hive: str, key: str) -> None:
        root = self._root(hive)
        _check_key(key)
        what = f"{hive}\\{key}"
        with _mapped(what):
            handle = self._w.CreateKeyEx(root, key, 0, self._view(self._w.KEY_WRITE))
        self._close(handle, what)

    def set_value(self, hive: str, key: str, value: RegValue) -> None:
        _check_name(value.name)
        what = f"{hive}\\{key}"
        data = value.data
        if value.type == REG_MULTI_SZ and isinstance(data, tuple):
            data = list(data)  # winreg accepts only a list for REG_MULTI_SZ
        with self._open(
            hive, key,
            self._w.KEY_QUERY_VALUE | self._w.KEY_SET_VALUE,
            self._w.REG_OPTION_OPEN_LINK,
        ) as h:
            self._refuse_link(h, what)
            with _mapped(f"{what}\\{value.name}"):
                self._w.SetValueEx(h, value.name, 0, value.type, data)
