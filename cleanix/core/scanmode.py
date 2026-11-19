"""Scan mode: is this scan run by the elevated helper?

The elevated helper scans as an administrator for ANOTHER account (the
invoking user). Its HKCU is the administrator's hive and its environment is
not the user's, so registry detectors must never read HKCU and must judge
evidence with ``owner_matches=False`` (ruling R15). ``RegistryDetector``
reads :func:`is_helper_mode` to decide that.

Two switches, either one is enough:

* :func:`enable_process_helper_mode` -- process-wide, called once at helper
  startup (``cleanix.elevated.main``) before any scan, so every thread
  (the engine scans on a thread pool) sees it. It is never switched off.
* :func:`helper_mode` / :func:`set_helper_mode` -- a context-local switch for
  one scan (the engine copies the context into its worker threads).
"""

from __future__ import annotations

import contextvars
import threading
from contextlib import contextmanager
from typing import Iterator

_local: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "cleanix_helper_mode", default=False
)
_lock = threading.Lock()
_process = False


def enable_process_helper_mode() -> None:
    """Switch helper mode on for the whole process (never switched off)."""
    global _process
    with _lock:
        _process = True


def process_helper_mode_enabled() -> bool:
    return _process


def set_helper_mode(on: bool) -> None:
    """Set the context-local switch (prefer :func:`helper_mode`)."""
    _local.set(bool(on))


@contextmanager
def helper_mode() -> Iterator[None]:
    """Helper mode for the code run inside the ``with`` block."""
    token = _local.set(True)
    try:
        yield
    finally:
        _local.reset(token)


def is_helper_mode() -> bool:
    return _process or _local.get()
