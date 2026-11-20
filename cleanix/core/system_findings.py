"""System-wide (``requires_root``) findings for the CLI: which ones may be
offered to the elevated helper, what acting on them means, one helper run
per batch, and plain-language text for the helper's per-item outcomes.

Nothing here acts on an item in this process: system-wide findings are only
ever acted on by the elevated helper (``cleanix.elevated``), which scans
again itself and acts only on items its own scan still reports. The normal
in-process path (``actions.act`` as called by the CLI and the GUI) keeps skipping
them with "needs an elevated run". Every check here mirrors a check of
``elevate_launch.run_findings_request`` per item, so one unsuitable item is
listed as "not offered" instead of refusing the whole batch.

All returned text is plain (unescaped): print helper-originated text with
``report.helper_safe`` and the rest with ``report.safe``.
"""

from __future__ import annotations

import os
import posixpath
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from cleanix.core.models import CleanableItem, item_key
from cleanix.core.quarantine import CROSS_FILESYSTEM_QUARANTINE

# The phrase an interactive user types to act on a batch of system-wide items.
CONFIRM_PHRASE = "DELETE SYSTEM FILES"

NOT_ON_WINDOWS = ("system-wide findings are not supported on Windows (the "
                  "administrator helper never acts on them here)")
CANNOT_CHECK = "it cannot be checked for the administrator helper"
NO_REMEDY = "no safe action is known for it (report only)"
DUPLICATE = "duplicates are not handled with administrator rights"
NOT_ALLOWLISTED = "the administrator helper does not act on this scenario"
KIND_NOT_HERE = "this kind of finding is not handled with administrator rights on this system"
NO_FINGERPRINT = "it has no evidence fingerprint to re-check it by"
LISTED_TWICE = "listed twice"
NOT_ELEVATED = ("needs a terminal to type the confirmation in (system-wide items "
                "are never acted on without it)")
SETTINGS_MISMATCH = ("the administrator scan did not report this item (it uses "
                     "default settings, e.g. orphan_min_age_days / orphan_max_items, "
                     "so a changed setting can hide items)")
NOT_REPORTED = "the administrator helper did not report on it; nothing is known about it"
# The quarantine's own wording (quarantine.CROSS_FILESYSTEM_QUARANTINE) and
# nothing else: a refused permanent deletion that mentions "another
# filesystem" (root_delete) is a real failure, not this limitation.
CROSS_FILESYSTEM = CROSS_FILESYSTEM_QUARANTINE

# How each front end says "delete permanently" in the hint below.
CLI_PERMANENT = "run again with --permanent"
CLI_PERMANENT_SCOPE = ("--permanent applies to every item of that run, so name "
                       "only the items you mean")
GUI_PERMANENT = "tick 'Delete permanently (no Undo)' and act on it again"
GUI_PERMANENT_SCOPE = ("that setting applies to every item you act on, so select "
                       "only the items you mean")


def cross_filesystem_hint(how: str = CLI_PERMANENT,
                          scope: str = CLI_PERMANENT_SCOPE) -> str:
    """The advice for an item on another filesystem than the administrator
    quarantine; ``how``/``scope`` name the caller's own control."""
    return ("It is on another filesystem than the administrator quarantine, so it "
            f"cannot be moved there. To remove it anyway, {how}: that DELETES it "
            f"permanently, with no undo and no copy kept ({scope}).")


CROSS_FILESYSTEM_HINT = cross_filesystem_hint()

# -- beta gate ----------------------------------------------------------------
# System-wide acting is a beta feature, OFF unless this is exactly "1".
BETA_ENV = "CLEANIX_BETA_SYSTEM_ACTIONS"
BETA_OFF = ("system-wide actions are a beta feature not yet verified on real "
            "systems; set CLEANIX_BETA_SYSTEM_ACTIONS=1 to enable (see "
            "docs/findings-verification.md)")
RUN_AS_USER = ("run cleanix as your normal user; it asks for administrator "
               "rights itself")
FROZEN_BINARY = ("the standalone binary cannot start the administrator helper; "
                 "install with pip/pipx to act on system-wide findings")
TOO_LARGE = "the administrator request would be too large; run again for the rest"

_FP_MIN = -(2 ** 63)
_FP_MAX = 2 ** 64


@dataclass
class SystemPlan:
    """``offered``: system-wide findings the helper may be asked to act on
    (input order); ``not_offered``: (item, reason) for the rest."""

    offered: List[CleanableItem] = field(default_factory=list)
    not_offered: List[Tuple[CleanableItem, str]] = field(default_factory=list)


def _kind(item: CleanableItem) -> str:
    remedy = getattr(item, "remedy", None)
    return str(getattr(getattr(remedy, "kind", None), "value", "") or "")


def _fingerprint_ok(fp) -> bool:
    try:
        values = tuple(fp)
    except TypeError:
        return False
    if len(values) != 4:
        return False
    if any(type(v) is not int or not (_FP_MIN <= v < _FP_MAX) for v in values):
        return False
    return any(values)


def _item_problem(item: CleanableItem, ctx) -> Optional[str]:
    from cleanix.core import elevate

    allowed, roots, never, dirs, kinds = ctx
    remedy = getattr(item, "remedy", None)
    if remedy is None or not item.report_only:
        return NO_REMEDY
    if remedy.group:
        return DUPLICATE
    if item.cleaner_id not in allowed:
        return NOT_ALLOWLISTED
    kind = _kind(item)
    if kind not in kinds:
        return KIND_NOT_HERE
    if not _fingerprint_ok(remedy.fingerprint):
        return NO_FINGERPRINT
    try:
        cid, path = elevate.finding_key_parts(item_key(item))
    except ValueError as exc:
        return f"its path cannot be sent to the administrator helper ({exc})"
    problem = (elevate.finding_path_problem(cid, path, roots, never)
               or elevate.finding_kind_problem(cid, kind, path, dirs))
    if problem:
        return f"the administrator helper never acts on it ({problem})"
    return None


def is_frozen() -> bool:
    """A standalone (PyInstaller) binary: it cannot start the helper
    (``python -I -m cleanix.elevated``). A seam for tests."""
    import sys

    return bool(getattr(sys, "frozen", False))


def euid_is_root() -> bool:
    """POSIX effective uid 0 (never true on Windows). A seam for tests."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def beta_enabled() -> bool:
    return os.environ.get(BETA_ENV) == "1"


def gate_problem() -> Optional[str]:
    """Why no system-wide item may be offered at all in this process, or
    None. The single client-side gate (CLI ``--act-on``, ``review`` and the
    GUI all plan through :func:`plan`); the helper is not gated."""
    if is_frozen():
        return FROZEN_BINARY
    if euid_is_root():
        return RUN_AS_USER
    if not beta_enabled():
        return BETA_OFF
    return None


def _request_size(items: Sequence[CleanableItem]) -> int:
    """Bytes of the request the helper would be sent for ``items`` (the
    larger of the two ``permanent`` spellings)."""
    from cleanix.core import elevate

    sizes = []
    for permanent in (False, True):
        sel = elevate.Selection(
            invoking_user=invoking_user_name(), only=[], keys=[], use_quarantine=False,
            findings=elevate.findings_request_for(list(items), permanent=permanent))
        sizes.append(len(elevate.request_bytes(sel)))
    return max(sizes)


def _fit_request(out: SystemPlan) -> None:
    """Move offered items that would make the request too large (the
    helper refuses it, after the typed phrase) to ``not_offered``. Never
    raises: when the size cannot be computed nothing is offered."""
    from cleanix.core import elevate

    offered = out.offered
    try:
        if not offered or _request_size(offered) <= elevate.MAX_REQUEST_BYTES:
            return
        lo, hi = 0, len(offered)  # largest prefix that fits
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if _request_size(offered[:mid]) <= elevate.MAX_REQUEST_BYTES:
                lo = mid
            else:
                hi = mid - 1
    except Exception:  # noqa: BLE001 - fail closed
        out.not_offered.extend((i, CANNOT_CHECK) for i in offered)
        out.offered = []
        return
    out.not_offered.extend((i, TOO_LARGE) for i in offered[lo:])
    out.offered = offered[:lo]


def plan(items: Sequence[CleanableItem]) -> SystemPlan:
    """Split system-wide findings into those the helper may be asked to act
    on and those it never would (with the reason). Mirrors, per item, the
    caller-side checks of ``elevate_launch.run_findings_request`` and the
    request limits (count, scenarios and the serialized size). Never
    raises: on doubt an item is not offered.

    The beta gate (:func:`gate_problem`) applies first: in a frozen binary,
    in a root process, or unless ``CLEANIX_BETA_SYSTEM_ACTIONS=1``, NOTHING
    is offered."""
    from cleanix import elevated
    from cleanix.core import elevate

    items = list(items)
    out = SystemPlan()
    try:
        supported = bool(elevated._findings_supported())
    except Exception:  # noqa: BLE001
        supported = False
    if not supported:
        out.not_offered = [(i, NOT_ON_WINDOWS) for i in items]
        return out
    try:
        gate = gate_problem()
    except Exception:  # noqa: BLE001 - fail closed
        gate = CANNOT_CHECK
    if gate is not None:
        out.not_offered = [(i, gate) for i in items]
        return out
    try:
        ctx = (frozenset(elevated.admin_finding_ids()), elevated.finding_path_roots(),
               tuple(elevated.root_quarantine_never()), elevated.finding_kind_dirs(),
               frozenset(elevated.helper_finding_kinds()))
    except Exception:  # noqa: BLE001 - fail closed
        out.not_offered = [(i, CANNOT_CHECK) for i in items]
        return out
    seen = set()
    scenarios: List[str] = []
    for item in items:
        try:
            why = _item_problem(item, ctx)
        except Exception:  # noqa: BLE001 - fail closed
            why = CANNOT_CHECK
        key = item_key(item) if why is None else ""
        if why is None and key in seen:
            why = LISTED_TWICE
        if why is None and len(out.offered) >= elevate.MAX_FINDING_ITEMS:
            why = (f"too many system-wide items for one administrator run (at most "
                   f"{elevate.MAX_FINDING_ITEMS}); run again for the rest")
        if (why is None and item.cleaner_id not in scenarios
                and len(scenarios) >= elevate.MAX_FINDING_SCENARIOS):
            why = "too many scenarios for one administrator run; run again for the rest"
        if why is not None:
            out.not_offered.append((item, why))
            continue
        seen.add(key)
        if item.cleaner_id not in scenarios:
            scenarios.append(item.cleaner_id)
        out.offered.append(item)
    _fit_request(out)
    return out


def root_quarantine_dir() -> str:
    """The helper's root-owned quarantine (``/var/lib/cleanix/quarantine``;
    macOS ``/Library/Application Support/Cleanix/quarantine``)."""
    from cleanix import elevated

    parent, own = elevated._root_quarantine_location()
    return posixpath.join(parent, *own)


def what_happens(item: CleanableItem, permanent: bool) -> str:
    """What the helper does to ``item`` (preview and confirmation). Never an
    Undo: there is no restore or purge for the administrator quarantine."""
    kind = _kind(item)
    copy = (f"a copy is kept in {root_quarantine_dir()} for manual recovery; "
            "the exact folder is shown after the run")
    if kind == "launch_job":
        return f"PERMANENT: the job's file is removed ({copy})"
    if kind == "systemd_unit":
        return f"PERMANENT: the service is disabled and its unit file removed ({copy})"
    if kind == "pkg_receipt":
        return f"PERMANENT: the install record is forgotten (pkgutil --forget; {copy})"
    if permanent:
        return "PERMANENT: deleted with administrator rights; no undo and no copy"
    return ("moved to a root-only quarantine you cannot restore from yet (Cleanix "
            "has no restore or purge for it yet, so the space is not freed)")


def invoking_user_name() -> str:
    """The account name the helper resolves from our uid (POSIX: the passwd
    name of the real uid -- under sudo that is root, matching ``--uid``)."""
    if os.name != "nt":
        try:
            import pwd

            return pwd.getpwuid(os.getuid()).pw_name
        except Exception:  # noqa: BLE001
            pass
    import getpass

    return getpass.getuser()


def _is_posix() -> bool:
    return os.name != "nt"


def _process_is_root() -> bool:
    from cleanix.core import utils

    return bool(utils.is_root())


def _default_config_path() -> Optional[str]:
    """The ``--config`` for the helper, consistent with the identity sent
    with the request (``--uid`` and ``invoking_user`` come from the real
    uid). As a normal user: the user's own config file, as the GUI does.
    In a root process (e.g. under sudo, where HOME / XDG_CONFIG_HOME may
    still point at the invoking user's files, which the helper would refuse
    as not owned by uid 0): None, so the helper reads the config of the
    account it binds (root) itself."""
    if _is_posix() and _process_is_root():
        return None
    try:
        from cleanix import config as config_mod

        return str(config_mod.config_file_path())
    except Exception:  # noqa: BLE001 - the helper then uses defaults
        return None


def run_batch(items: Sequence[CleanableItem], permanent: bool, *,
              launcher: Optional[Callable[[List[str]], int]] = None,
              config_path: Optional[str] = None):
    """One helper run (one administrator prompt) for the offered ``items``;
    the helper's ``HelperResult``. Raises what
    ``elevate_launch.run_findings_request`` raises (ValueError before any
    prompt; ElevationDeclined / ElevationUnavailable / ElevationFailed)."""
    from cleanix.core import elevate, elevate_launch

    request = elevate.findings_request_for(list(items), permanent=permanent)
    if config_path is None:
        config_path = _default_config_path()
    return elevate_launch.run_findings_request(
        request, invoking_user_name(), launcher=launcher, config_path=config_path)


# --------------------------------------------------------------------------
# outcomes
# --------------------------------------------------------------------------
def outcomes_by_key(result) -> Dict[str, object]:
    return {o.key: o for o in getattr(result, "findings", []) or []}


def is_cross_filesystem(outcome) -> bool:
    return (outcome is not None and outcome.status == "not_removed"
            and CROSS_FILESYSTEM in (outcome.reason or ""))


def outcome_lines(item: CleanableItem, outcome, permanent: bool, *,
                  cross_fs_hint: str = CROSS_FILESYSTEM_HINT) -> List[str]:
    """Plain lines for one item's helper outcome (helper text included:
    print them with ``report.helper_safe``). ``cross_fs_hint``: the advice
    for an item on another filesystem than the administrator quarantine,
    naming the caller's own "delete permanently" control (default: the
    CLI's ``--permanent``)."""
    from cleanix.core.utils import human_size

    if outcome is None:
        return [f"not done: {NOT_REPORTED}"]
    status = outcome.status
    lines: List[str] = []
    if status == "removed":
        kind = _kind(item)
        if kind and kind != "path":
            lines.append(f"removed permanently ({human_size(outcome.freed)})")
        elif permanent:
            lines.append(f"deleted permanently, no undo ({human_size(outcome.freed)})")
        else:
            lines.append("moved to the root-only quarantine (you cannot restore "
                         f"from it yet; {human_size(outcome.freed)} moved, no space "
                         "freed)")
    elif status == "not_removed":
        lines.append(f"NOT removed: {outcome.reason or 'no reason given'}")
        if outcome.freed:
            lines.append(f"{human_size(outcome.freed)} were freed before it stopped")
        if is_cross_filesystem(outcome):
            lines.append(cross_fs_hint)
    elif status == "skipped":
        lines.append(f"skipped: {outcome.reason or 'no reason given'}")
    elif status == "refused":
        lines.append(f"refused by the administrator helper: "
                     f"{outcome.reason or 'no reason given'}")
    elif status == "not_found":
        lines.append(f"not done: {SETTINGS_MISMATCH}")
    else:  # never produced by read_result
        lines.append(f"unknown outcome: {status}")
    if outcome.note:
        lines.append(f"note: {outcome.note}")
    return lines


@dataclass
class Tally:
    """What the helper really did, by effect: ``moved`` items went into the
    root-only quarantine (no space freed: there is no purge for it);
    ``deleted`` items were removed for good (permanent paths, job / unit /
    receipt files), and ``freed`` counts only their bytes (including bytes
    of a partial permanent removal)."""

    moved: int = 0
    moved_bytes: int = 0
    deleted: int = 0
    freed: int = 0


def tally(result, items: Sequence[CleanableItem], permanent: bool) -> Tally:
    got = outcomes_by_key(result)
    out = Tally()
    for item in items:
        o = got.get(item_key(item))
        if o is None:
            continue
        kind = _kind(item)
        quarantined = (kind in ("", "path")) and not permanent
        if o.status == "removed":
            if quarantined:
                out.moved += 1
                out.moved_bytes += max(0, int(o.freed))
            else:
                out.deleted += 1
                out.freed += max(0, int(o.freed))
        elif o.freed and not quarantined:
            out.freed += max(0, int(o.freed))  # e.g. "partially removed"
    return out


def batch_failed(result, items: Sequence[CleanableItem]) -> bool:
    """A real failure of the helper run (exit 2): it hit its deadline,
    left a requested item unreported (refused or crashed before it), or
    could not remove / refused an item. Skips, "not found" and items on
    another filesystem (a limitation, explained with a --permanent hint)
    are not failures."""
    if result.deadline_hit:
        return True
    got = outcomes_by_key(result)
    for item in items:
        o = got.get(item_key(item))
        if o is None:
            return True
        if o.status == "refused":
            return True
        if o.status == "not_removed" and not is_cross_filesystem(o):
            return True
    return False


def nothing_removed(result) -> bool:
    """True only when the result shows that nothing at all was removed or
    moved (no item removed, no bytes freed, no item possibly acted on when
    the helper stopped, no deadline)."""
    from cleanix import elevated

    if result.deadline_hit or result.removed or result.freed:
        return False
    for o in getattr(result, "findings", []) or []:
        if o.status == "removed" or o.freed:
            return False
        if elevated.STOPPED_WHILE_ACTING in (o.reason or ""):
            return False
    return True
