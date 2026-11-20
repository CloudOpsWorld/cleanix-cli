"""Act-time re-verification of system-wide findings (elevated helper only).

The helper's own scan already re-ran the detector, but a package may be
installed (or an app, a program, a unit) between that scan and the removal.
So right before each removal -- through :func:`actions.act`'s root-mode
check, which runs up front and again in the Engine precheck -- the finding's
ORIGINAL evidence is checked once more by its detector's own re-verifier.

One table, keyed by cleaner id (:data:`REVERIFIERS`). A scenario without an
entry is refused in root mode (:data:`NO_REVERIFIER`); every re-verifier
fails closed: unknown, unreadable, timed out or unconfirmable evidence is a
skip reason, never a pass. Re-verifiers run with strict evidence
(``scanmode.strict_evidence``): an absence an ordinary user could have
caused is "unknown" (see ``scanmode.evidence_problem``).

Only PATH remedies are re-verified here (Task 9a). LAUNCH_JOB, SYSTEMD_UNIT
and PKG_RECEIPT system findings carry no remedy yet and are refused by the
helper before this is reached.
"""

from __future__ import annotations

from typing import Callable, Dict, Optional

from cleanix.config import Config
from cleanix.core import scanmode
from cleanix.core.models import CleanableItem

NO_REVERIFIER = ("this kind of system-wide finding cannot be re-checked right "
                 "before removal; nothing was done")

Reverifier = Callable[[CleanableItem, Config], Optional[str]]


def _orphan_files(item: CleanableItem, config: Config) -> Optional[str]:
    from cleanix.cleaners import orphan_files

    return orphan_files.reverify_system_item(item.path or "", config)


def _orphan_app_data(item: CleanableItem, config: Config) -> Optional[str]:
    from cleanix.cleaners import orphan_app_data

    return orphan_app_data.reverify_system_item(item.path or "", config)


def _stale_launchers(item: CleanableItem, config: Config) -> Optional[str]:
    from cleanix.cleaners import stale_launchers

    return stale_launchers.reverify_system_item(item.path or "", config)


def _stale_services(item: CleanableItem, config: Config) -> Optional[str]:
    from cleanix.cleaners import stale_services

    return stale_services.reverify_system_item(item.path or "", config)


# cleaner id -> re-verifier of its system-wide PATH findings. Scenarios that
# emit no system-wide PATH remedy (orphan_launch_jobs, stale_receipts: their
# kinds are Task 9b) deliberately have none: refused.
REVERIFIERS: Dict[str, Reverifier] = {
    "orphan_files": _orphan_files,
    "orphan_app_data": _orphan_app_data,
    "stale_launchers": _stale_launchers,
    "stale_services": _stale_services,
}


def has_reverifier(cleaner_id: str) -> bool:
    return cleaner_id in REVERIFIERS


def reverify(item: CleanableItem, config: Config) -> Optional[str]:
    """Why ``item`` (a system-wide PATH finding) must not be removed now,
    or None when its detector's evidence still holds. Unknown scenario,
    an exception or an unconfirmable answer: a reason (fail closed)."""
    fn = REVERIFIERS.get(item.cleaner_id)
    if fn is None or not item.path:
        return NO_REVERIFIER
    try:
        with scanmode.strict_evidence():
            why = fn(item, config)
    except Exception as exc:  # noqa: BLE001 - fail closed
        return f"could not be re-checked ({str(exc) or type(exc).__name__})"
    return why
