"""Interactive review of findings: one prompt per item, nothing deleted unless
the user answers ``d`` (or ``g``) for it.

The walk is category -> scenario group -> item. Deletions go through the
``act`` callable (``service.act`` in the CLI), so quarantine, the safety guard,
history and the staleness re-checks are exactly those of ``clean --act-on``.
``requires_root`` (system-wide) items are never acted on here: when the
caller passes ``system``, the chosen ones are collected and handed to it once
at the end (the CLI sends them to the elevated helper after one typed
confirmation). For duplicate groups the copy that stays is chosen with
``keep`` and is never offered.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from cleanix.core import findings
from cleanix.core.curation import safety_of
from cleanix.core.models import CleanableItem, CleanOutcome
from cleanix.core.report import safe
from cleanix.core.utils import human_size

# The one place the undo command is spelled (cli.py imports it from here).
RESTORE_CMD = "cleanix restore"


def is_job(item: CleanableItem) -> bool:
    """A launch job / systemd unit finding: always removed permanently."""
    from cleanix.core import remedy_exec

    return item.remedy is not None and item.remedy.kind in remedy_exec.KINDS


# Preview/prompt text for a user-level launch job / unit: the copy-only run
# that will hold the backup does not exist yet, so no folder is named here
# (the real one is printed after the run, see backup_line).
JOB_PLANNED = ("permanent: the job is stopped and its file removed (a backup copy "
               "is kept for manual recovery; its location is shown after the run)")
PURGE_CMD = "cleanix quarantine empty"


def undo_line(item: CleanableItem, permanent: bool) -> str:
    """What acting on ``item`` does, by remedy kind (unescaped text).
    System-wide items: never an Undo (see ``system_findings.what_happens``)."""
    if item.requires_root:
        from cleanix.core import system_findings

        return system_findings.what_happens(item, permanent)
    if is_job(item):
        return JOB_PLANNED
    return ("permanent, no undo" if permanent else
            f"kept in quarantine; undo with `{RESTORE_CMD}`")


def backup_line(run_id: str) -> str:
    """Where the copies of removed job files are (unescaped text)."""
    from cleanix.core import quarantine

    return (f"Copies of the removed job/service files are kept in "
            f"{quarantine.quarantine_root() / run_id / 'files'} for manual "
            f"recovery; `{RESTORE_CMD}` does not bring them back, and "
            f"`{PURGE_CMD}` deletes these copies too.")
PROMPT = "  [d]elete  [s]kip  [g] delete rest of group  [n] skip rest of group  [q]uit  [?] "
HELP = (
    "  d  delete this item\n"
    "  s  skip this item (also: just press Enter)\n"
    "  g  delete this item and all remaining items of this group\n"
    "  n  skip this item and the rest of this group\n"
    "  q  quit the review\n"
    "  ?  show this help")


@dataclass
class ReviewResult:
    removed: int = 0
    freed: int = 0
    declined: int = 0  # items the user chose not to delete
    skipped: List[Tuple[CleanableItem, str]] = field(default_factory=list)
    errors: List[CleanOutcome] = field(default_factory=list)
    runs: List[str] = field(default_factory=list)
    backups: List[str] = field(default_factory=list)  # copy-only runs (jobs)
    notes: List[Tuple[CleanableItem, str]] = field(default_factory=list)
    undo_errors: List[str] = field(default_factory=list)
    quit: bool = False  # the user answered q
    aborted: bool = False  # Ctrl-C or end of input
    # System-wide items the user chose (d/g): collected and handed to the
    # ``system`` callback ONCE, at the end of the review or at q.
    system_chosen: int = 0
    system_code: int = 0  # the callback's exit code (0 ok, 1 abort, 2 error)

    @property
    def failed(self) -> bool:
        return bool(self.errors or self.undo_errors)


class _Stop(Exception):
    pass


def _record(res: ReviewResult, summary, console) -> None:
    res.removed += summary.removed
    res.freed += summary.freed
    res.skipped.extend(getattr(summary, "skipped", []))
    res.errors.extend(summary.errors)
    if summary.quarantine_run:
        res.runs.append(summary.quarantine_run)
    backup = getattr(summary, "backup_run", None)
    if backup and backup not in res.backups:
        res.backups.append(backup)
    if summary.undo_record_error:
        res.undo_errors.append(summary.undo_record_error)
    for item, why in getattr(summary, "skipped", []):
        console.print(f"    [yellow]skipped:[/yellow] {safe(why)}")
    for o in summary.errors:
        console.print(f"    [red]error:[/red] {safe(o.error)}")
    for o in getattr(getattr(summary, "result", None), "outcomes", None) or []:
        if getattr(o, "note", None):
            res.notes.append((o.item, o.note))
            console.print(f"    [yellow]note:[/yellow] {safe(o.note)}")
    if summary.undo_record_error:
        console.print(f"    [red]{safe(summary.undo_record_error)}[/red]")
    if summary.removed:
        console.print(f"    [green]removed {summary.removed} item(s), "
                      f"freed {human_size(summary.freed)}[/green]")


def _describe(console, item: CleanableItem, category: str, undo: str,
              survivor: Optional[str]) -> None:
    console.print(f"\n[bold]{safe(item.description)}[/bold]")
    console.print(f"  path:    {safe(item.path or '')}")
    console.print(f"  size:    {human_size(item.size)}")
    console.print(f"  kind:    {safe(category)}; "
                  f"safety: {safe(safety_of(item, None).value)}")
    if item.hint:
        console.print(f"  hint:    {safe(item.hint)}")
    if survivor is not None:
        console.print(f"  keeps:   {safe(survivor)} (this copy stays)")
    console.print(f"  [dim]if deleted: {safe(undo)}[/dim]")


def run(groups: List[findings.FindingGroup],
        ask: Callable[[str], str],
        act: Callable[[List[CleanableItem]], object],
        console,
        *, keep: Optional[str] = None,
        permanent: bool = False,
        notes: Optional[List[str]] = None,
        system: Optional[Callable[[List[CleanableItem]], int]] = None,
        system_plan=None) -> ReviewResult:
    """Walk ``groups`` asking about every item; apply each decision with
    ``act`` at once. Returns what was done (also printed as a summary).
    ``notes`` are shown before the first prompt and again in the summary.

    System-wide (``requires_root``) items are only reviewed when ``system``
    and ``system_plan`` (``system_findings.SystemPlan``) are given: offered
    items get the same per-item prompt, but a ``d``/``g`` only COLLECTS
    them; ``system(chosen)`` is called once at the end of the review (or at
    ``q``) -- one confirmation, one administrator prompt -- and returns an
    exit code. Items that are not offered are listed with the reason. On
    Ctrl-C / end of input the collected items are not acted on."""
    banner = list(notes or [])
    res = ReviewResult()
    offered: Set[int] = set()
    blocked: Dict[int, str] = {}
    if system is not None and system_plan is not None:
        offered = {id(i) for i in system_plan.offered}
        blocked = {id(i): why for i, why in system_plan.not_offered}
    pending: List[CleanableItem] = []
    # Plan every group up front: nothing is asked before the data is sound.
    plans: Dict[int, Tuple[List[CleanableItem], List[Tuple[CleanableItem, str]],
                           List[CleanableItem]]] = {}
    for gi, g in enumerate(groups):
        its = [i for i in g.items if not i.requires_root or id(i) in offered]
        not_offered = [(i, f"not offered: {blocked[id(i)]}") for i in g.items
                       if i.requires_root and id(i) in blocked]
        dups = [i for i in its if i.remedy is not None and i.remedy.group]
        rest = [i for i in its if not (i.remedy is not None and i.remedy.group)]
        notes: List[Tuple[CleanableItem, str]] = []
        kept: List[CleanableItem] = []
        if dups:
            if not keep:
                raise ValueError("reviewing duplicates needs a keep policy")
            plan = findings.plan_duplicates(dups, keep)
            rest = rest + list(plan.items)
            kept = list(plan.kept)
            kept_ids = {id(k) for k in kept}
            notes = [(i, w) for i, w in plan.skipped if id(i) not in kept_ids]
        plans[gi] = (rest, not_offered + notes, kept)

    def queue(items: List[CleanableItem]) -> None:
        pending.extend(items)
        console.print(f"    [yellow]{len(items)} system-wide item(s) queued: they "
                      "are acted on together, after one confirmation, at the end "
                      "of the review[/yellow]")

    def decide(prompt: str) -> str:
        while True:
            try:
                raw = ask(prompt)
            except (EOFError, KeyboardInterrupt):
                res.aborted = True
                raise _Stop()
            ans = (raw or "").strip().lower()
            if ans == "":
                return "s"
            if ans in ("d", "s", "g", "n", "q"):
                return ans
            if ans == "?":
                console.print(HELP)
            else:
                console.print(f"  [yellow]Not understood: {safe(raw)!s}. "
                              "Press ? for help.[/yellow]")

    for n in banner:
        console.print(f"[yellow]{safe(n)}[/yellow]")
    try:
        last_cat = None
        for gi, g in enumerate(groups):
            todo, notes, kept = plans[gi]
            if not todo and not notes:
                continue
            if g.category != last_cat:
                console.print(f"\n[bold cyan]{safe(g.category)}[/bold cyan]")
                last_cat = g.category
            console.print(f"[bold]{safe(g.title)}[/bold]")
            for i, why in notes:
                console.print(f"  [yellow]skipped:[/yellow] "
                              f"{safe(i.description)}: {safe(why)}")
                res.skipped.append((i, why))
            idx = 0
            while idx < len(todo):
                item = todo[idx]
                kept_copy = findings.survivor_of(item)
                _describe(console, item, g.category, undo_line(item, permanent),
                          kept_copy.path if kept_copy else None)
                ans = decide(PROMPT)
                if ans == "q":
                    res.quit = True
                    raise _Stop()
                if ans == "s":
                    res.declined += 1
                    idx += 1
                elif ans == "n":
                    res.declined += len(todo) - idx
                    break
                elif ans == "d":
                    if id(item) in offered:
                        queue([item])
                    else:
                        _record(res, act([item]), console)
                    idx += 1
                else:  # g
                    rest_items = todo[idx:]
                    users = [x for x in rest_items if id(x) not in offered]
                    systems = [x for x in rest_items if id(x) in offered]
                    if users:
                        _record(res, act(users), console)
                    if systems:
                        queue(systems)
                    break
    except _Stop:
        pass
    if pending:
        res.system_chosen = len(pending)
        if res.aborted:
            for i in pending:
                res.skipped.append((i, "not done: the review was interrupted before "
                                       "the system-wide batch"))
        else:
            res.system_code = int(system(list(pending)))  # type: ignore[misc]
    _print_summary(res, console, permanent, banner)
    return res


def _print_summary(res: ReviewResult, console, permanent: bool,
                   notes: List[str]) -> None:
    console.print()
    if res.aborted:
        console.print("[yellow]Review interrupted; summary of what was "
                      "already done:[/yellow]")
    elif res.quit:
        console.print("[yellow]Review stopped; nothing further was touched."
                      "[/yellow]")
    console.print(f"[green]Removed {res.removed} item(s), freed "
                  f"{human_size(res.freed)}.[/green]  "
                  f"Left alone by you: {res.declined}.")
    if res.system_chosen and not res.aborted:
        console.print(f"System-wide items chosen: {res.system_chosen} (their "
                      "outcome is listed above; they are not counted here).")
    for run_id in res.runs:
        r = safe(run_id)
        console.print(f"[cyan]Quarantine run '{r}':[/cyan] undo with "
                      f"[bold]{RESTORE_CMD} {r}[/bold]")
    if res.runs:
        console.print("Space is reclaimed once you run "
                      "[bold]cleanix quarantine empty[/bold].")
    elif permanent and res.removed:
        console.print("[dim]Deleted permanently; there is no undo.[/dim]")
    for run_id in res.backups:
        console.print(f"[cyan]{safe(backup_line(run_id))}[/cyan]")
    if res.notes:
        console.print(f"\n[yellow]Notes on {len(res.notes)} item(s):[/yellow]")
        for i, note in res.notes:
            console.print(f"  {safe(getattr(i, 'description', ''))}: {safe(note)}")
    if res.skipped:
        console.print(f"\n[yellow]Skipped {len(res.skipped)} item(s):[/yellow]")
        for i, why in res.skipped:
            console.print(f"  {safe(getattr(i, 'description', ''))}: {safe(why)}")
    if res.errors:
        console.print(f"\n[red]{len(res.errors)} error(s):[/red]")
        for o in res.errors:
            console.print(f"  [red]![/red] {safe(o.item.description)}: "
                          f"{safe(o.error)}")
    for n in notes:
        console.print(f"[yellow]{safe(n)}[/yellow]")
    for e in res.undo_errors:
        console.print(f"[red]{safe(e)}[/red]")
