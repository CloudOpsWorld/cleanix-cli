"""The Review tab's act flow, without Qt: plan, act, and plain-text reports.

How a ticked selection is acted on (the same order and wording as the
CLI's ``clean --act-on``):

1. :func:`build_plan` (read-only, run in a worker): duplicate copies are
   planned around the copies the user keeps
   (:func:`findings.plan_duplicates_keeping`, with the kept copies passed in
   together with the copies), every user-space item is dry-run through
   :func:`service.act` so the confirmation shows the executor's own
   verdicts, and the system-wide items are planned again on the actual
   selection (:func:`system_findings.plan`). Nothing is moved or deleted.
2. The owner shows ONE confirmation built from :func:`confirm_text`; for
   system-wide items the exact phrase ``DELETE SYSTEM FILES`` must be typed.
3. :func:`run_act` (in a worker): the user-space items go through
   :func:`service.act` FIRST (quarantine with Undo, or permanent); then,
   unless a cancel was requested, the offered system-wide items go to the
   elevated helper in one batch (:func:`system_findings.run_batch`, one
   administrator prompt). This module never acts on a system-wide item
   itself and never asks the executor for root behaviour.
4. :func:`result_text` describes what happened; helper-originated text is
   passed through :func:`report.helper_safe`, everything else through
   :func:`review_view.shown`-equivalent escaping. Callers show it as plain
   text only.

History: the user-space batch is recorded by :func:`service.act` itself;
the helper's removals are recorded here with the CLI's modes:
"administrator" (real freed bytes) and "administrator-quarantine" (moved
into the root-only quarantine, freed 0).
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from cleanix.core import findings, report, service, system_findings
from cleanix.core.models import CleanableItem, _visible
from cleanix.core.remedy import RemedyKind
from cleanix.core.utils import human_size

CONFIRM_PHRASE = system_findings.CONFIRM_PHRASE

NONE_REMOVED = "none of the system-wide items was removed"
SYSTEM_NOT_UNDONE = (
    "None of the system-wide items can be undone from Cleanix. The administrator "
    "helper scans again itself and acts only on items its own scan still reports.")
PROMPT_FOLLOWS = ("After you click Act, your files are acted on first; then the "
                  "administrator prompt follows (one prompt for all system-wide "
                  "items).")
ADMIN_WAIT = ("Waiting for administrator permission... (it cannot be stopped from "
              "here: decline the prompt to leave the system-wide items alone)")

# System part statuses (ActOutcome.system_status).
SYS_NONE = "none"            # no system-wide items in this act
SYS_DONE = "done"            # the helper ran and wrote a result
SYS_STOPPED = "stopped"      # cancelled before the administrator step
SYS_SKIPPED = "skipped"      # the user part failed: never launched
SYS_DECLINED = "declined"
SYS_UNAVAILABLE = "unavailable"
SYS_NOT_STARTED = "not_started"
SYS_NOT_SENT = "not_sent"    # ValueError / OSError before any prompt
SYS_TIMEOUT = "timeout"
SYS_FAILED = "failed"        # unknown outcome

_JOB_KINDS = (RemedyKind.LAUNCH_JOB, RemedyKind.SYSTEMD_UNIT, RemedyKind.PKG_RECEIPT)


def shown(text) -> str:
    """Display form of text from our own scan or executor (descriptions,
    paths, reasons): control / bidi characters shown as escapes."""
    return _visible(str(text or ""))


def helper_text(text) -> str:
    """Display form of text written by the elevated helper."""
    return report.helper_safe(text if text is not None else "")


def _key(item: CleanableItem) -> str:
    return findings.path_key(item.path) if item.path else f"id:{id(item)}"


def _is_job(item: CleanableItem) -> bool:
    remedy = item.remedy
    return remedy is not None and remedy.kind in _JOB_KINDS


def _real_size(item: CleanableItem) -> int:
    from cleanix.gui.review_view import real_size  # Qt module: lazy

    return real_size(item)


# ===================================================================== plan
@dataclass
class ActPlan:
    """What the confirmation lists and :func:`run_act` acts on."""

    permanent: bool
    # User-space items to act on (dry-run eligible; duplicate copies are the
    # stamped copies from plan_duplicates_keeping), in order.
    user_items: List[CleanableItem] = field(default_factory=list)
    # User-space items that will NOT be acted on, with the reason.
    user_skipped: List[Tuple[CleanableItem, str]] = field(default_factory=list)
    # The duplicate copies that stay (never acted on).
    kept: List[CleanableItem] = field(default_factory=list)
    system_offered: List[CleanableItem] = field(default_factory=list)
    system_not_offered: List[Tuple[CleanableItem, str]] = field(default_factory=list)
    cancelled: bool = False

    @property
    def has_system(self) -> bool:
        return bool(self.system_offered)

    @property
    def empty(self) -> bool:
        return not self.user_items and not self.system_offered


def build_plan(user_items: Sequence[CleanableItem],
               system_items: Sequence[CleanableItem],
               survivors: Mapping[str, CleanableItem],
               permanent: bool, config, *,
               cancel: Optional[Callable[[], bool]] = None) -> ActPlan:
    """Plan an act without changing anything (see the module docstring)."""
    plan = ActPlan(permanent=bool(permanent))
    user_items = [i for i in user_items if not i.requires_root]
    dups = [i for i in user_items if i.remedy is not None and i.remedy.group]
    dup_ids = {id(i) for i in dups}
    rest = [i for i in user_items if id(i) not in dup_ids]
    candidates: List[CleanableItem] = list(rest)
    if dups:
        # The kept copies MUST be supplied with the copies, or every group is
        # skipped ("not one of the chosen copies").
        keep = [s for s in survivors.values() if id(s) not in dup_ids]
        dplan = findings.plan_duplicates_keeping(dups + keep, survivors)
        kept_ids = {id(k) for k in dplan.kept}
        plan.kept = list(dplan.kept)
        plan.user_skipped.extend((i, why) for i, why in dplan.skipped
                                 if id(i) not in kept_ids)
        candidates.extend(dplan.items)
    if candidates:
        pre = service.act(candidates, config, dry_run=True, permanent=permanent,
                          record_history=False, cancel=cancel)
        if getattr(pre, "cancelled", False) or (cancel is not None and cancel()):
            plan.cancelled = True
        skip: Dict[str, str] = {}
        for i, why in getattr(pre, "skipped", []) or []:
            skip.setdefault(_key(i), why)
        for o in pre.result.outcomes:
            if o.error and _key(o.item) not in skip:
                skip[_key(o.item)] = o.error
        processed = {_key(o.item) for o in pre.result.outcomes}
        for i in candidates:
            k = _key(i)
            if k in skip:
                plan.user_skipped.append((i, skip[k]))
            elif k in processed:
                plan.user_items.append(i)
            else:  # never reached the executor (cancelled while checking)
                plan.user_skipped.append((i, "not checked (stopped)"))
    if system_items:
        splan = system_findings.plan(list(system_items))
        plan.system_offered = list(splan.offered)
        plan.system_not_offered = list(splan.not_offered)
    return plan


def _line(item: CleanableItem) -> str:
    where = shown(item.path or "")
    head = f"  {human_size(_real_size(item)):>10}  {shown(item.description)}"
    return f"{head}\n              {where}" if where else head


def user_effect(item: CleanableItem, permanent: bool) -> str:
    if _is_job(item):
        return ("permanent: the job is stopped and its file removed (a copy of "
                "the file is kept for manual recovery)")
    if permanent:
        return "deleted permanently (no Undo)"
    return "moves to quarantine (Undo available)"


def headline(plan: ActPlan) -> str:
    n_user, n_sys = len(plan.user_items), len(plan.system_offered)
    if plan.empty:
        return "Nothing can be acted on: every selected item was skipped (see why below)."
    parts = []
    if n_user:
        parts.append(f"{n_user} of your item(s)")
    if n_sys:
        parts.append(f"{n_sys} system-wide item(s)")
    return f"Act on {' and '.join(parts)}?"


def bucket_lines(plan: ActPlan) -> List[str]:
    """Counts and sizes per kind of effect: the Review footer's wording."""
    from cleanix.gui.review_view import footer_lines  # Qt module: lazy

    return footer_lines(list(plan.user_items) + list(plan.system_offered),
                        plan.permanent)


def confirm_text(plan: ActPlan) -> str:
    """The full listing shown in the confirmation (plain text)."""
    out: List[str] = []
    if plan.user_items:
        out.append("Your files (acted on first):")
        for i in plan.user_items:
            out.append(_line(i))
            out.append(f"              -> {user_effect(i, plan.permanent)}")
            kept = findings.survivor_of(i)
            if kept is not None:
                out.append(f"              (keeps {shown(kept.path)})")
        out.append("")
    if plan.user_skipped or plan.kept:
        out.append("Not acted on (checked just now):")
        for i in plan.kept:
            out.append(_line(i))
            out.append("              -> kept: this is the copy that stays")
        for i, why in plan.user_skipped:
            out.append(_line(i))
            out.append(f"              -> skipped: {shown(why)}")
        out.append("")
    if plan.system_offered:
        out.append("System-wide items (need administrator rights; acted on after "
                   "your files, by the administrator helper):")
        for i in plan.system_offered:
            out.append(_line(i))
            out.append("              -> "
                       + shown(system_findings.what_happens(i, plan.permanent)))
        out.append(SYSTEM_NOT_UNDONE)
        out.append("")
    if plan.system_not_offered:
        out.append("System-wide items not offered:")
        for i, why in plan.system_not_offered:
            out.append(_line(i))
            out.append(f"              -> not offered: {shown(why)}")
        out.append("")
    return "\n".join(out).rstrip("\n")


def phrase_ok(text: str) -> bool:
    """Exactly the phrase: no stripping, no case folding."""
    return text == CONFIRM_PHRASE


# ===================================================================== act
@dataclass
class ActOutcome:
    plan: ActPlan
    user_summary: Optional[object] = None      # actions.ActSummary
    user_error: str = ""
    user_cancelled: bool = False
    system_status: str = SYS_NONE
    system_detail: str = ""                    # raw exception text (helper_text it)
    result: Optional[object] = None            # elevate.HelperResult
    tally: Optional[system_findings.Tally] = None
    late_cancel: bool = False


def _is_timeout(exc: BaseException) -> bool:
    import subprocess

    if isinstance(exc.__cause__, (TimeoutError, subprocess.TimeoutExpired)):
        return True
    return getattr(exc, "exit_code", None) is None and "timed out" in str(exc).lower()


def record_system_history(tally: system_findings.Tally) -> None:
    """The CLI's history entries for a helper batch. Never raises."""
    try:
        from cleanix.core import history

        if tally.deleted or tally.freed:
            history.record(tally.freed, tally.deleted, mode="administrator")
        if tally.moved:
            history.record(0, tally.moved, mode="administrator-quarantine")
    except Exception:  # noqa: BLE001 - history is best-effort
        pass


def run_act(plan: ActPlan, config, *,
            launcher: Optional[Callable[[List[str]], int]] = None,
            cancel: Optional[Callable[[], bool]] = None,
            progress: Optional[Callable[[str, int, int], None]] = None,
            admin_wait: Optional[Callable[[], None]] = None) -> ActOutcome:
    """Act on ``plan``: user-space items first, then the system batch.
    Raises only BaseException (e.g. KeyboardInterrupt)."""
    out = ActOutcome(plan=plan)
    stopped = lambda: bool(cancel is not None and cancel())  # noqa: E731
    if plan.user_items:
        try:
            out.user_summary = service.act(
                plan.user_items, config, dry_run=False, permanent=plan.permanent,
                progress=progress, cancel=cancel)
            out.user_cancelled = bool(getattr(out.user_summary, "cancelled", False))
        except service.Cancelled:
            out.user_cancelled = True
        except Exception as exc:  # noqa: BLE001 - reported, system part not run
            out.user_error = str(exc) or type(exc).__name__
    if not plan.system_offered:
        return out
    if out.user_error:
        out.system_status = SYS_SKIPPED
        return out
    if out.user_cancelled or stopped():
        out.system_status = SYS_STOPPED
        return out
    from cleanix.core import elevate_launch as el

    if admin_wait is not None:
        admin_wait()
    try:
        result = system_findings.run_batch(plan.system_offered, plan.permanent,
                                           launcher=launcher)
    except ValueError as exc:
        out.system_status, out.system_detail = SYS_NOT_SENT, str(exc)
        return out
    except OSError as exc:
        out.system_status, out.system_detail = SYS_NOT_SENT, str(exc)
        return out
    except el.ElevationDeclined as exc:
        out.system_status, out.system_detail = SYS_DECLINED, str(exc)
        return out
    except el.ElevationUnavailable as exc:
        out.system_status, out.system_detail = SYS_UNAVAILABLE, str(exc)
        return out
    except el.ElevationNotStarted as exc:  # before ElevationFailed (subclass)
        out.system_status, out.system_detail = SYS_NOT_STARTED, str(exc)
        return out
    except el.ElevationFailed as exc:
        out.system_status = SYS_TIMEOUT if _is_timeout(exc) else SYS_FAILED
        out.system_detail = str(exc)
        return out
    except Exception as exc:  # noqa: BLE001 - unknown: treat as unknown outcome
        out.system_status, out.system_detail = SYS_FAILED, str(exc) or type(exc).__name__
        return out
    out.system_status = SYS_DONE
    out.result = result
    out.late_cancel = stopped()
    out.tally = system_findings.tally(result, plan.system_offered, plan.permanent)
    record_system_history(out.tally)
    return out


# ================================================================= results
def _user_lines(out: ActOutcome) -> List[str]:
    plan = out.plan
    lines: List[str] = []
    if not plan.user_items:
        return lines
    s = out.user_summary
    if out.user_error:
        lines.append(f"Your files: the action failed ({shown(out.user_error)}); "
                     "scan again to see what is left.")
        return lines
    if s is None:
        lines.append("Your files: stopped before anything was done.")
        return lines
    outcomes = {_key(o.item): o for o in s.result.outcomes}
    skipped = {_key(i): why for i, why in getattr(s, "skipped", []) or []}
    removed = sum(1 for o in s.result.outcomes if o.removed)
    lines.append(f"Your files: acted on {removed} of {len(plan.user_items)} item(s) "
                 f"({human_size(s.freed)}).")
    for i in plan.user_items:
        k = _key(i)
        o = outcomes.get(k)
        lines.append(f"  {shown(i.description)}  ({shown(i.path or '')})")
        if k in skipped:
            lines.append(f"      skipped: {shown(skipped[k])}")
        elif o is None:
            lines.append("      not done (stopped before it was reached)")
        elif o.removed:
            if _is_job(i):
                lines.append("      removed permanently (a copy of the file is kept)")
            elif plan.permanent:
                lines.append("      deleted permanently, no Undo")
            else:
                lines.append("      moved to the quarantine (Undo available)")
        else:
            lines.append(f"      error: {shown(o.error or 'not removed')}")
        if o is not None and o.note:
            lines.append(f"      note: {shown(o.note)}")
    if out.user_cancelled:
        lines.append("Stopped: the items above marked 'not done' were left alone.")
    if s.quarantine_run:
        lines.append(f"Quarantine run {shown(s.quarantine_run)}: Undo it from the "
                     "Quarantine tab; space is freed when the quarantine is emptied.")
    elif plan.permanent and s.removed:
        lines.append("Deleted permanently; there is no Undo.")
    backup = getattr(s, "backup_run", None)
    if backup:
        lines.append(f"Copies of removed job/service files are kept in run "
                     f"{shown(backup)} for manual recovery (this is not an Undo; "
                     "emptying the quarantine deletes these copies too).")
    if getattr(s, "undo_record_error", None):
        lines.append(f"Warning: {shown(s.undo_record_error)}")
    return lines


def _system_failure_line(out: ActOutcome) -> str:
    st = out.system_status
    detail = helper_text(out.system_detail)
    if st == SYS_STOPPED:
        return ("Stopped before the administrator step: " + NONE_REMOVED + ".")
    if st == SYS_SKIPPED:
        return ("The system-wide items were not touched because acting on your "
                f"files failed; {NONE_REMOVED}.")
    if st == SYS_DECLINED:
        return f"Administrator permission was declined; {NONE_REMOVED}."
    if st == SYS_UNAVAILABLE:
        return (f"Acting with administrator rights is not available on this system "
                f"({detail}); {NONE_REMOVED}.")
    if st == SYS_NOT_STARTED:
        return f"The administrator helper did not run ({detail}); {NONE_REMOVED}."
    if st == SYS_NOT_SENT:
        return (f"The administrator request was not sent ({detail}). No prompt was "
                f"shown; {NONE_REMOVED}.")
    if st == SYS_TIMEOUT:
        return (f"The administrator helper timed out ({detail}): the outcome is "
                "unknown, items may already have been removed and it may still be "
                "running. Scan again later to see what is left.")
    return (f"The administrator helper failed ({detail}): the outcome is unknown; "
            "items may already have been removed. Scan again to see what is left.")


def _system_lines(out: ActOutcome) -> List[str]:
    plan = out.plan
    lines: List[str] = []
    items = plan.system_offered
    if not items:
        return lines
    if out.system_status != SYS_DONE or out.result is None:
        lines.append("System-wide items: " + _system_failure_line(out))
        if plan.user_items and out.user_summary is not None and not out.user_error:
            lines.append("Your files above were already acted on.")
        return lines
    res = out.result
    got = system_findings.outcomes_by_key(res)
    from cleanix.core.models import item_key

    lines.append("System-wide items (administrator helper):")
    for i in items:
        lines.append(f"  {shown(i.description)}  ({shown(i.path or '')})")
        for line in system_findings.outcome_lines(i, got.get(item_key(i)), plan.permanent):
            lines.append(f"      {helper_text(line)}")
    if not res.findings and res.errors:
        lines.append("The administrator helper refused the request:")
        lines.extend(f"  {helper_text(e)}" for e in res.errors[:10])
    t = out.tally or system_findings.tally(res, items, plan.permanent)
    if t.deleted or t.freed or not t.moved:
        lines.append(f"Administrator helper: removed {t.deleted} item(s) permanently, "
                     f"freed {human_size(t.freed)}.")
    if t.moved:
        lines.append(f"Administrator helper: moved {t.moved} item(s) "
                     f"({human_size(t.moved_bytes)}) into the root-only quarantine; no "
                     "space was freed (there is no purge for it yet).")
    try:
        qdir = system_findings.root_quarantine_dir()
    except Exception:  # noqa: BLE001
        qdir = "the root-only quarantine"
    if res.quarantine_run:
        lines.append(f"Root-only quarantine run {helper_text(res.quarantine_run)} in "
                     f"{helper_text(qdir)}. You cannot restore from it yet (Cleanix has "
                     "no restore or purge for it), so it is not in the Quarantine tab.")
    if res.backup_run:
        where = posixpath.join(qdir, res.backup_run, "files")
        lines.append(f"Copies of the removed job/service/receipt files are kept in "
                     f"{helper_text(where)} for manual recovery (root-only; this is "
                     "not an Undo).")
    if res.deadline_hit:
        lines.append("The administrator helper reached its time limit; some items "
                     "were not processed.")
        if any(system_findings._kind(i) == "systemd_unit" for i in items):
            lines.append("If service units were removed, run `systemctl "
                         "daemon-reload` as root.")
    if system_findings.nothing_removed(res):
        lines.append("Nothing was removed by the administrator helper.")
    if out.late_cancel:
        lines.append("Cancel arrived after administrator permission was given; that "
                     "step could not be stopped.")
    return lines


def result_text(out: ActOutcome) -> str:
    """Everything that happened, as plain text (one block per part)."""
    blocks = []
    user = _user_lines(out)
    if user:
        blocks.append("\n".join(user))
    sysl = _system_lines(out)
    if sysl:
        blocks.append("\n".join(sysl))
    plan = out.plan
    if plan.user_skipped or plan.system_not_offered:
        rest = ["Not acted on:"]
        rest += [f"  {shown(i.description)}: skipped: {shown(why)}"
                 for i, why in plan.user_skipped]
        rest += [f"  {shown(i.description)}: not offered: {shown(why)}"
                 for i, why in plan.system_not_offered]
        blocks.append("\n".join(rest))
    blocks.append("Scan for findings again to see what is left.")
    return "\n\n".join(blocks)


def status_line(out: ActOutcome) -> str:
    """One short line for the tab's status label."""
    parts = []
    s = out.user_summary
    if out.plan.user_items:
        if out.user_error:
            parts.append("your files: failed")
        elif s is not None:
            parts.append(f"your files: {s.removed} done")
        else:
            parts.append("your files: stopped")
    if out.plan.system_offered:
        if out.system_status == SYS_DONE and out.tally is not None:
            parts.append(f"system-wide: {out.tally.deleted + out.tally.moved} done")
        elif out.system_status in (SYS_TIMEOUT, SYS_FAILED):
            parts.append("system-wide: outcome unknown")
        else:
            parts.append("system-wide: none removed")
    return ("Done (" + "; ".join(parts) + "). Scan again to see what is left."
            if parts else "Nothing was done.")
