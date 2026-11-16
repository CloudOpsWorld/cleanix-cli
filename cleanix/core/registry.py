"""Cleaner discovery and selection."""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from cleanix.cleaners import ALL_CLEANERS
from cleanix.cleaners.base import Cleaner
from cleanix.config import Config
from cleanix.core import platform as _plat


def build_cleaners(
    config: Config,
    only: Optional[Sequence[str]] = None,
    exclude: Optional[Sequence[str]] = None,
) -> List[Cleaner]:
    """Instantiate the selected cleaners in registry order.

    ``only`` restricts to the given ids (case-insensitive). ``exclude`` and the
    config's ``disabled_cleaners`` remove ids. ``only`` wins over disables so a
    user can force a specific cleaner even if it is disabled by default.
    """
    only_set = {c.lower() for c in only} if only else None
    exclude_set = {c.lower() for c in (exclude or [])}
    disabled = {c.lower() for c in config.disabled_cleaners}

    selected: List[Cleaner] = []
    for cls in ALL_CLEANERS:
        cid = cls.id.lower()
        instance = cls(config)
        if only_set is not None:
            # Explicit selection wins even over platform/disable filters.
            if cid not in only_set:
                continue
            # ... except on Windows, where a POSIX cleaner must never run: it
            # is still listed, but its scan reports it as unsupported.
            if _plat.is_windows() and not instance.supported():
                instance.unsupported_platform = True
        else:
            if cid in exclude_set or cid in disabled:
                continue
            # Skip cleaners that don't apply to this operating system.
            if not instance.supported():
                continue
            # Skip opt-in-only cleaners unless explicitly selected.
            if not instance.default_enabled:
                continue
        selected.append(instance)
    return selected


def known_ids() -> List[str]:
    return [c.id for c in ALL_CLEANERS]


def describe_all(config: Config) -> Dict[str, Cleaner]:
    return {c.id: c(config) for c in ALL_CLEANERS}


def unknown_ids(ids: Sequence[str]) -> List[str]:
    known = {i.lower() for i in known_ids()}
    return [i for i in ids if i.lower() not in known]
