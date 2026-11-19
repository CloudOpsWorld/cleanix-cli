"""Scan-mode flags shared by the registry detectors and the elevated helper.

Helper mode means "the process scanning is the elevated helper": its
environment and HKCU hive do not describe the user whose data is being
judged, so per-user registry evidence must never be trusted. The flag is a
:mod:`contextvars` variable, so concurrent scans on different threads are
isolated from each other.
"""

from __future__ import annotations

import contextlib
import contextvars
import threading
from typing import Iterator

_helper: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "cleanix_helper_mode", default=False
)


_process_lock = threading.Lock()
_process_flag = False


def enable_process_helper_mode() -> None:
    """Mark this whole process as a single-purpose helper (set once at startup).

    Visible from every thread, including ones started outside any copied
    context (GUI workers, foreign pools). Never reset in production."""
    global _process_flag
    with _process_lock:
        _process_flag = True


def process_helper_mode_enabled() -> bool:
    with _process_lock:
        return _process_flag


def _reset_for_tests() -> None:
    global _process_flag
    with _process_lock:
        _process_flag = False


def is_helper_mode() -> bool:
    return _helper.get() or process_helper_mode_enabled()


def set_helper_mode(value: bool) -> None:
    """Set the flag for the current context (prefer :func:`helper_mode`)."""
    _helper.set(bool(value))


@contextlib.contextmanager
def helper_mode(active: bool = True) -> Iterator[None]:
    token = _helper.set(bool(active))
    try:
        yield
    finally:
        _helper.reset(token)
