"""Multi-user scanning context.

Per-user cleaners operate relative to "the home directory". When cleanix runs
unprivileged that's just the invoking user. When it runs as root it should sweep
*every* real user's home. This module resolves the set of target users and lets
the engine bind a "current user" while a cleaner runs, so cleaners can stay
written against a single home and automatically apply to each user.
"""

from __future__ import annotations

import contextlib
import contextvars
import os
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

try:
    import pwd  # POSIX only (Linux, macOS, BSD)
except ImportError:  # pragma: no cover - non-POSIX
    pwd = None  # type: ignore

from cleanix.core.platform import MACOS, current_os

# Homes that are never real user homes even if they appear in passwd.
_BOGUS_HOMES = {"/", "", "/nonexistent", "/dev/null", "/var/empty", "/run/nologin"}


@dataclass(frozen=True)
class TargetUser:
    name: str
    home: Path
    uid: int
    gid: int
    is_invoker: bool  # the user who launched cleanix (honors their XDG env)


def is_effective_root() -> bool:
    if sys.platform == "win32":
        from cleanix.core import winenv

        return winenv.is_admin()
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _default_min_uid() -> int:
    # Human accounts start at 501 on macOS, 1000 on Linux/BSD.
    return 500 if current_os() == MACOS else 1000


@lru_cache(maxsize=1)
def invoking_user() -> TargetUser:
    """The real user who launched cleanix (honoring ``sudo``)."""
    sudo_user = os.environ.get("SUDO_USER")
    if pwd is not None:
        try:
            if sudo_user and is_effective_root():
                pw = pwd.getpwnam(sudo_user)
            else:
                pw = pwd.getpwuid(os.geteuid())
            return TargetUser(pw.pw_name, Path(pw.pw_dir), pw.pw_uid, pw.pw_gid, True)
        except (KeyError, OSError):
            pass
    home = Path(os.path.expanduser("~"))
    uid = os.geteuid() if hasattr(os, "geteuid") else 0
    return TargetUser(os.environ.get("USER") or os.environ.get("USERNAME") or "user", home, uid, uid, True)


def _all_users(min_uid: int) -> List[TargetUser]:
    invoker = invoking_user()
    if pwd is None:
        return [invoker]

    seen_homes = set()
    users: List[TargetUser] = []
    for pw in pwd.getpwall():
        # Root plus real human accounts (uid >= min_uid); skip service accounts.
        if pw.pw_uid != 0 and pw.pw_uid < min_uid:
            continue
        home = Path(pw.pw_dir)
        if str(home) in _BOGUS_HOMES or not home.is_dir():
            continue
        if str(home) in seen_homes:
            continue
        seen_homes.add(str(home))
        users.append(
            TargetUser(
                pw.pw_name, home, pw.pw_uid, pw.pw_gid,
                is_invoker=(pw.pw_name == invoker.name),
            )
        )
    if not users:
        users = [invoker]
    return users


# --- configuration / caching -------------------------------------------------
_all_users_flag: Optional[bool] = None
_min_uid_override: Optional[int] = None
_cached_targets: Optional[List[TargetUser]] = None


def configure(all_users: Optional[bool] = None, min_uid: Optional[int] = None) -> None:
    """Set scanning scope. ``all_users=None`` means "all users iff root"."""
    global _all_users_flag, _min_uid_override, _cached_targets
    _all_users_flag = all_users
    _min_uid_override = min_uid
    _cached_targets = None  # invalidate


def get_target_users() -> List[TargetUser]:
    """The users whose homes should be scanned, per current configuration."""
    global _cached_targets
    if _cached_targets is not None:
        return _cached_targets

    want_all = _all_users_flag
    if want_all is None:
        want_all = is_effective_root()

    if want_all:
        min_uid = _min_uid_override if _min_uid_override is not None else _default_min_uid()
        _cached_targets = _all_users(min_uid)
    else:
        _cached_targets = [invoking_user()]
    return _cached_targets


def scanning_all_users() -> bool:
    return len(get_target_users()) > 1


# --- current-user binding ----------------------------------------------------
_current: contextvars.ContextVar[Optional[TargetUser]] = contextvars.ContextVar(
    "cleanix_current_user", default=None
)


def current_user() -> TargetUser:
    return _current.get() or invoking_user()


@contextlib.contextmanager
def use_user(user: TargetUser):
    token = _current.set(user)
    try:
        yield user
    finally:
        _current.reset(token)
