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

PATH remedies (Task 9a) and the system-wide LAUNCH_JOB, SYSTEMD_UNIT and
PKG_RECEIPT remedies (Task 9b) are re-verified here; each re-verifier binds
the remedy kind to its scenario (a kind its scenario never offers is
refused).
"""

from __future__ import annotations

import contextvars
from typing import Any, Callable, Dict, List, Optional, Sequence

from cleanix.config import Config
from cleanix.core import scanmode
from cleanix.core.models import CleanableItem
from cleanix.core.remedy import RemedyKind

NO_REVERIFIER = ("this kind of system-wide finding cannot be re-checked right "
                 "before removal; nothing was done")
WRONG_KIND = "this scenario never offers this kind of action; nothing was done"

Reverifier = Callable[[CleanableItem, Config], Optional[str]]

# Per-batch store (one ``actions.act`` root-mode batch) and the phase of the
# current check: "verify" (up front, for the whole batch) or "removal"
# (right before that item's own removal). Only what may be shared within a
# phase is cached (see :func:`cached`); ownership is re-queried fresh in the
# removal phase.
VERIFY = "verify"
REMOVAL = "removal"
_store: "contextvars.ContextVar[Optional[Dict[Any, Any]]]" = contextvars.ContextVar(
    "cleanix_reverify_store", default=None)
_phase: "contextvars.ContextVar[str]" = contextvars.ContextVar(
    "cleanix_reverify_phase", default="")


def cached(key: str, build: Callable[[], Any]) -> Any:
    """``build()`` at most once per (batch, phase); every call outside a
    batch builds afresh. Used for the installed-app inventory: built once
    up front and once more before the first removal of the batch."""
    store = _store.get()
    if store is None:
        return build()
    k = (key, _phase.get())
    if k not in store:
        store[k] = build()
    return store[k]


def prefetched(key: str) -> Any:
    """What :func:`prefetch` stored for ``key`` in the current phase, or None."""
    store = _store.get()
    if store is None:
        return None
    return store.get(("prefetch:" + key, _phase.get()))


def _orphan_files(item: CleanableItem, config: Config) -> Optional[str]:
    from cleanix.cleaners import orphan_files

    return orphan_files.reverify_system_item(item.path or "", config)


def _orphan_app_data(item: CleanableItem, config: Config) -> Optional[str]:
    from cleanix.cleaners import orphan_app_data

    return orphan_app_data.reverify_system_item(item.path or "", config)


def _stale_launchers(item: CleanableItem, config: Config) -> Optional[str]:
    from cleanix.cleaners import stale_launchers

    return stale_launchers.reverify_system_item(item.path or "", config)


def _kind(item: CleanableItem) -> Optional[RemedyKind]:
    return item.remedy.kind if item.remedy is not None else None


def _stale_services(item: CleanableItem, config: Config) -> Optional[str]:
    from cleanix.cleaners import stale_services

    kind = _kind(item)
    if kind is RemedyKind.SYSTEMD_UNIT:
        return stale_services.reverify_system_unit(item, config)
    if kind is not RemedyKind.PATH:
        return WRONG_KIND
    return stale_services.reverify_system_item(item.path or "", config)


def _orphan_launch_jobs(item: CleanableItem, config: Config) -> Optional[str]:
    from cleanix.cleaners import orphan_launch_jobs

    if _kind(item) is not RemedyKind.LAUNCH_JOB:
        return WRONG_KIND
    return orphan_launch_jobs.reverify_system_item(item, config)


def _stale_receipts(item: CleanableItem, config: Config) -> Optional[str]:
    from cleanix.cleaners import stale_receipts

    if _kind(item) is not RemedyKind.PKG_RECEIPT:
        return WRONG_KIND
    return stale_receipts.reverify_system_item(item, config)


def _path_only(fn: Reverifier) -> Reverifier:
    def check(item: CleanableItem, config: Config) -> Optional[str]:
        if _kind(item) is not RemedyKind.PATH:
            return WRONG_KIND
        return fn(item, config)

    return check


# cleaner id -> re-verifier of its system-wide findings (each bound to the
# remedy kinds its detector offers system-wide).
REVERIFIERS: Dict[str, Reverifier] = {
    "orphan_files": _path_only(_orphan_files),
    "orphan_app_data": _path_only(_orphan_app_data),
    "stale_launchers": _path_only(_stale_launchers),
    "stale_services": _stale_services,
    "orphan_launch_jobs": _orphan_launch_jobs,
    "stale_receipts": _stale_receipts,
}


def has_reverifier(cleaner_id: str) -> bool:
    return cleaner_id in REVERIFIERS


def reverify(item: CleanableItem, config: Config, *, phase: str = "",
             store: Optional[Dict[Any, Any]] = None) -> Optional[str]:
    """Why ``item`` (a system-wide PATH finding) must not be removed now,
    or None when its detector's evidence still holds. Unknown scenario,
    an exception or an unconfirmable answer: a reason (fail closed).
    ``store``/``phase``: the batch cache (see :func:`cached`)."""
    fn = REVERIFIERS.get(item.cleaner_id)
    if fn is None or not item.path:
        return NO_REVERIFIER
    t_store = _store.set(store)
    t_phase = _phase.set(phase)
    try:
        with scanmode.strict_evidence():
            why = fn(item, config)
    except Exception as exc:  # noqa: BLE001 - fail closed
        return f"could not be re-checked ({str(exc) or type(exc).__name__})"
    finally:
        _phase.reset(t_phase)
        _store.reset(t_store)
    return why


def _prefetch_orphan_files(paths: List[str], config: Config) -> Any:
    from cleanix.cleaners import orphan_files

    return orphan_files.prefetch_unowned(paths, config)


# cleaner id -> one batched query for the up-front ("verify") phase. Its
# answer replaces that phase's per-item query; the removal phase always
# queries afresh, right before each removal.
PREFETCH: Dict[str, Callable[[List[str], Config], Any]] = {
    "orphan_files": _prefetch_orphan_files,
}


def prefetch(items: Sequence[CleanableItem], config: Config,
             store: Dict[Any, Any], phase: str) -> None:
    """Run the batched queries of :data:`PREFETCH` for ``items`` into
    ``store`` (best effort: a failure just leaves the per-item queries)."""
    by_cid: Dict[str, List[str]] = {}
    for item in items:
        if item.cleaner_id in PREFETCH and item.path:
            by_cid.setdefault(item.cleaner_id, []).append(item.path)
    for cid, paths in by_cid.items():
        try:
            with scanmode.strict_evidence():
                result = PREFETCH[cid](paths, config)
        except Exception:  # noqa: BLE001 - fall back to per-item queries
            continue
        if result is not None:
            store[("prefetch:" + cid, phase)] = result
