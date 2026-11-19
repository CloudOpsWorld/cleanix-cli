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
from typing import Iterator

_helper: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "cleanix_helper_mode", default=False
)


def is_helper_mode() -> bool:
    return _helper.get()


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
