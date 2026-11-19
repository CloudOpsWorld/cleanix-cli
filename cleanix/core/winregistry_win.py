"""The ``winreg`` implementation of :class:`~cleanix.core.winregistry.RegistryBackend`.

This is the only module that imports ``winreg``, and it does so lazily in
:class:`WinRegBackend`'s constructor, so the module itself imports on every OS.
:func:`cleanix.core.winregistry.get_backend` builds it only on win32.

Rules every method follows:

* ``hive`` is exactly ``"HKCU"`` or ``"HKLM"``; anything else is a
  :class:`ValueError` raised before any registry call. ``key`` is a physical
  path below the hive (``WOW6432Node`` spelled out); malformed keys (empty,
  empty components, NUL) are a :class:`ValueError` too.
* Every open, create and delete carries ``KEY_WOW64_64KEY``: there is no
  registry redirection, and the 32-bit view is reached only through explicit
  ``WOW6432Node`` paths.
* Links are never followed where it matters: ``is_link`` opens the key itself
  with ``REG_OPTION_OPEN_LINK``, and ``delete_key``/``delete_value``/
  ``set_value`` refuse a key that is a registry link.
* Deletes are leaf-only (``DeleteKeyEx``, never a tree delete) and values are
  deleted by exact name.
* Every ``OSError`` becomes :class:`KeyMissing` (not found),
  :class:`AccessDenied` (denied) or :class:`RegistryError` (anything else,
  e.g. in use / marked for deletion). Handles are always closed.

The leaf and link checks in ``delete_key`` run immediately before
``DeleteKeyEx``; the remaining window between the caller's final fingerprint
check and the delete is accepted (plan ruling R17).
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


def _map_error(exc: OSError, what: str) -> RegistryError:
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
    except OSError as exc:
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
    if (
        not isinstance(key, str)
        or not key
        or "\x00" in key
        or any(part == "" for part in key.split("\\"))
    ):
        raise ValueError(f"malformed registry key: {key!r}")
    return key


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

    @contextmanager
    def _open(self, hive: str, key: str, access: int, options: int = 0) -> Iterator[Any]:
        """Open ``hive\\key`` (64-bit view) and always close the handle.
        Opening errors are mapped; errors inside the block propagate as is."""
        root = self._root(hive)
        _check_key(key)
        with _mapped(f"{hive}\\{key}"):
            handle = self._w.OpenKeyEx(root, key, options, self._view(access))
        try:
            yield handle
        finally:
            self._w.CloseKey(handle)

    def _handle_is_link(self, h: Any, what: str) -> bool:
        try:
            _data, typ = self._w.QueryValueEx(h, _LINK_VALUE)
        except OSError as exc:
            if _is_missing(exc):
                return False
            raise _map_error(exc, what) from exc
        return typ == REG_LINK

    def _refuse_link(self, h: Any, what: str) -> None:
        if self._handle_is_link(h, what):
            raise RegistryError(f"refusing to modify a registry link: {what}")

    # -- RegistryBackend -----------------------------------------------------
    def subkeys(self, hive: str, key: str) -> List[str]:
        what = f"{hive}\\{key}"
        out: List[str] = []
        with self._open(hive, key, self._w.KEY_ENUMERATE_SUB_KEYS | self._w.KEY_QUERY_VALUE) as h:
            i = 0
            while True:
                try:
                    out.append(self._w.EnumKey(h, i))
                except OSError as exc:
                    if _is_end(exc):
                        break
                    raise _map_error(exc, what) from exc
                i += 1
        return out

    def values(self, hive: str, key: str) -> List[RegValue]:
        what = f"{hive}\\{key}"
        out: List[RegValue] = []
        with self._open(hive, key, self._w.KEY_QUERY_VALUE) as h:
            i = 0
            while True:
                try:
                    name, data, typ = self._w.EnumValue(h, i)
                except OSError as exc:
                    if _is_end(exc):
                        break
                    raise _map_error(exc, what) from exc
                out.append(RegValue(name, typ, _norm_data(data)))
                i += 1
        return out

    def key_exists(self, hive: str, key: str) -> bool:
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
                return True
        except (KeyMissing, AccessDenied):
            return False

    def delete_key(self, hive: str, key: str) -> None:
        """Delete a leaf key. A key with subkeys or a registry link is
        refused with :class:`RegistryError` and nothing is deleted."""
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
        with _mapped(what):
            self._w.DeleteKeyEx(root, key, self._w.KEY_WOW64_64KEY, 0)

    def delete_value(self, hive: str, key: str, name: str) -> None:
        if not isinstance(name, str) or "\x00" in name:
            raise ValueError(f"malformed value name: {name!r}")
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
        with _mapped(f"{hive}\\{key}"):
            handle = self._w.CreateKeyEx(root, key, 0, self._view(self._w.KEY_WRITE))
        self._w.CloseKey(handle)

    def set_value(self, hive: str, key: str, value: RegValue) -> None:
        if not isinstance(value.name, str) or "\x00" in value.name:
            raise ValueError(f"malformed value name: {value.name!r}")
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
