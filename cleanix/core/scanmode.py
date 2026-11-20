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
from typing import Callable, Iterator, Optional

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


# --------------------------------------------------------------------------
# evidence trust (system-wide findings judged by the elevated helper)
# --------------------------------------------------------------------------
# A detector that calls something "missing" from the absence of an absolute
# path (a menu entry's program, a unit link's target) must not trust that
# absence when an ordinary user could have caused it (the path lies in, or
# below, a folder the user can write). In helper mode, and in strict mode
# (the act-time re-checks of the helper's findings action), such evidence is
# judged by the rule the helper registers (the parent-chain rule bound to the
# requesting user); with no rule registered every absence is "unknown".
EvidenceRule = Callable[[str], Optional[str]]
_evidence_rule: contextvars.ContextVar[Optional[EvidenceRule]] = contextvars.ContextVar(
    "cleanix_evidence_rule", default=None
)
_strict: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "cleanix_evidence_strict", default=False
)
NO_EVIDENCE_RULE = "its absence cannot be judged here"


@contextlib.contextmanager
def evidence_rule(rule: Optional[EvidenceRule]) -> Iterator[None]:
    """Judge absence evidence with ``rule`` (path -> problem or None)."""
    token = _evidence_rule.set(rule)
    try:
        yield
    finally:
        _evidence_rule.reset(token)


@contextlib.contextmanager
def strict_evidence(active: bool = True) -> Iterator[None]:
    """Judge absence evidence as in helper mode (act-time re-checks)."""
    token = _strict.set(bool(active))
    try:
        yield
    finally:
        _strict.reset(token)


def evidence_problem(path: str) -> Optional[str]:
    """Why the absence of ``path`` is not trustworthy evidence, or None.

    Always None outside helper/strict mode (ordinary scans are unchanged).
    Inside it: the registered rule decides; no rule, or a rule that raises,
    means not trustworthy (fail closed)."""
    if not (is_helper_mode() or _strict.get()):
        return None
    rule = _evidence_rule.get()
    if rule is None:
        return NO_EVIDENCE_RULE
    try:
        return rule(str(path))
    except Exception:  # noqa: BLE001 - fail closed
        return NO_EVIDENCE_RULE
