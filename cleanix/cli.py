"""Command-line interface for cleanix.

Subcommands:
    list      show available cleaners
    scan      analyze the system (read-only)
    clean     remove junk (dry-run unless --execute; confirmation required)
    schedule  install/uninstall/status of the periodic analysis job
              (systemd timer on Linux/BSD, launchd agent on macOS)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from rich.console import Console
from rich.prompt import Confirm, Prompt

from cleanix import __version__
from cleanix.config import Config
from cleanix.core.engine import Engine
from cleanix.core.models import ItemKind, ScanResult, _visible, item_target
from cleanix.core.registry import build_cleaners, describe_all, unknown_ids
from cleanix.core.report import (
    registry_items,
    registry_notice,
    safe,
    render_clean_summary,
    render_registry_items,
    render_report_only,
    render_scan_table,
    scan_to_json,
)
from cleanix.core.utils import human_size, is_root


def _split_csv(value: Optional[str]) -> Optional[List[str]]:
    if not value:
        return None
    return [v.strip() for v in value.split(",") if v.strip()]


def _load_config() -> Config:
    return Config.load()


def _add_profile(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--profile",
        choices=["safe", "balanced", "aggressive"],
        default=None,
        help="preset bundle of opt-in settings: 'safe' disables aggressive "
        "cleaners, 'aggressive' enables offline-repo/backup/locale/all-image "
        "pruning (never volumes)",
    )


def _apply_profile(config: Config, profile: Optional[str]) -> Config:
    """Layer a named profile over the loaded config (CLI > profile > file)."""
    if not profile or profile == "balanced":
        return config
    if profile == "safe":
        config.docker_prune_all_images = False
        config.docker_prune_volumes = False
        config.remove_backup_files = False
        config.purge_unused_locales = False
        config.include_offline_repos = False
        config.remove_old_kernels = False
    elif profile == "aggressive":
        # Enable the safe-but-thorough opt-ins. Volumes stay OFF even here —
        # they can hold real data and must be an explicit, separate choice.
        config.docker_prune_all_images = True
        config.remove_backup_files = True
        config.purge_unused_locales = True
        config.include_offline_repos = True
        config.remove_old_kernels = True
        config.keep_kernels = min(config.keep_kernels, 1)
        config.keep_backups = min(config.keep_backups, 1)
    return config


_SIZE_UNITS = {"": 1, "B": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}


def _parse_size(text: Optional[str]) -> int:
    """Parse a human size like ``100M`` / ``1.5G`` into bytes (0 if None)."""
    if not text:
        return 0
    m = re.fullmatch(r"\s*([\d.]+)\s*([KMGT]?)i?[Bb]?\s*", text, re.IGNORECASE)
    if not m:
        raise SystemExit(f"invalid --min-size {text!r}; use e.g. 100M, 1.5G")
    return int(float(m.group(1)) * _SIZE_UNITS[m.group(2).upper()])


def _apply_min_size(result: ScanResult, min_bytes: int) -> None:
    """Drop PATH items below ``min_bytes`` in place (command items are kept,
    since their reclaim isn't a single measurable file)."""
    if min_bytes <= 0:
        return
    from cleanix.core.models import ItemKind

    for r in result.reports:
        r.items = [
            i for i in r.items
            if i.kind is not ItemKind.PATH or i.size >= min_bytes
        ]


def _effective_only(args: argparse.Namespace, console: Console) -> Optional[List[str]]:
    """The ``--only`` list, extended by ``--registry`` (R14): the five registry
    detectors are added to any explicit ``--only``; alone they are the whole
    selection. Never implied by anything else."""
    only = _split_csv(args.only)
    if not getattr(args, "registry", False):
        return only
    from cleanix.core import catalog
    from cleanix.core import platform as plat

    if not plat.is_windows():
        console.print("Registry cleanup is only available on Windows.")
        raise SystemExit(2)
    merged = list(only or [])
    have = {c.lower() for c in merged}
    merged.extend(c for c in catalog.REGISTRY_IDS if c not in have)
    return merged


def _require_nonempty_selection(args: argparse.Namespace) -> None:
    """Reject `--only ''` / `--exclude ''` (a blank filter is almost always a
    scripting typo, and silently means 'no filter')."""
    for flag in ("only", "exclude"):
        raw = getattr(args, flag, None)
        if raw is not None and not _split_csv(raw):
            raise SystemExit(f"--{flag} was given but empty; omit it to select all")


def _elevate_text() -> str:
    """How to get elevated rights, worded for the current OS."""
    from cleanix.core import platform as plat

    if plat.is_windows():
        return "run from an elevated (Administrator) terminal"
    return "re-run with sudo"


def _is_elevated() -> bool:
    """Administrator on Windows, root elsewhere (patchable for tests)."""
    from cleanix.core import platform as plat
    from cleanix.core import winenv

    if plat.is_windows():
        return bool(winenv.is_admin())
    return is_root()


def _stdin_is_tty() -> bool:
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def _disk_label() -> str:
    """The volume reported by _disk_free(): the system drive on Windows."""
    from cleanix.core import platform as plat
    from cleanix.core import winenv

    return winenv.system_drive() + "\\" if plat.is_windows() else "/"


def _disk_free(path: Optional[str] = None) -> Optional[int]:
    import shutil as _shutil

    if path is None:
        from cleanix.core import platform as plat
        from cleanix.core import winenv

        path = winenv.system_drive() + "\\" if plat.is_windows() else "/"

    try:
        return _shutil.disk_usage(path).free
    except OSError:
        return None


def _interactive_select(items: list, console: Console) -> list:
    """Let the user drop individual items from a numbered checklist."""
    if not console.is_terminal:
        return items
    ordered = sorted(items, key=lambda i: i.size, reverse=True)
    console.print("\n[bold]Select items to remove[/bold] "
                  "(all selected by default):")
    for idx, i in enumerate(ordered, 1):
        label = (safe(item_target(i)) if i.kind is ItemKind.REGISTRY
                 else safe(i.description))
        console.print(f"  [cyan]{idx:>3}[/cyan]  {human_size(i.size):>10}  "
                      f"{label}")
    raw = Prompt.ask(
        "Enter numbers to SKIP (comma/space/ranges, e.g. 1,3-5), "
        "or press Enter to remove all",
        default="",
    )
    skip: set = set()
    for tok in raw.replace(",", " ").split():
        if "-" in tok:
            try:
                a, b = tok.split("-", 1)
                skip.update(range(int(a), int(b) + 1))
            except ValueError:
                continue
        elif tok.isdigit():
            skip.add(int(tok))
    kept = [i for idx, i in enumerate(ordered, 1) if idx not in skip]
    console.print(f"[dim]Keeping {len(kept)} of {len(ordered)} item(s).[/dim]")
    return kept


def _write_simulation(items: list, console: Console) -> int:
    """Write the exact paths/commands a real clean would act on, delete nothing."""
    from cleanix.core.history import state_dir

    lines = []
    for i in sorted(items, key=lambda x: x.size, reverse=True):
        if i.kind is ItemKind.COMMAND:
            target = "$ " + item_target(i)
        else:
            target = item_target(i)
        root = " [root]" if i.requires_root else ""
        lines.append(f"{human_size(i.size):>10}  {target}{root}")
    body = "\n".join(lines) + "\n"
    out = state_dir() / "last-simulation.txt"
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(body, encoding="utf-8")
        where = str(out)
    except OSError:
        where = None
    console.print(
        f"[cyan]Simulation:[/cyan] {len(items)} item(s), "
        f"{human_size(sum(i.size for i in items))} would be reclaimed. "
        "[dim]Nothing was deleted.[/dim]"
    )
    console.print(safe(body.rstrip()))
    if where:
        console.print(f"[dim]Written to {safe(where)}[/dim]")
    return 0


def _configure_scope(args: argparse.Namespace) -> None:
    """Decide whose homes to scan and apply it to the context layer."""
    from cleanix.core import context

    all_users: Optional[bool] = None  # None => all users iff root
    if getattr(args, "all_users", False):
        all_users = True
    elif getattr(args, "current_user", False):
        all_users = False
    context.configure(all_users=all_users, min_uid=getattr(args, "min_uid", None))


def _scope_note(console: Console) -> None:
    from cleanix.core import context

    if context.scanning_all_users():
        users = context.get_target_users()
        names = ", ".join(u.name for u in users)
        console.print(
            f"[cyan]Scanning {len(users)} users system-wide:[/cyan] {names}"
        )
    elif not context.is_effective_root():
        # Hint that more is available with sudo.
        pass


def _make_engine(
    config: Config, only: Optional[List[str]], exclude: Optional[List[str]]
) -> Engine:
    for group in (only, exclude):
        if group:
            bad = unknown_ids(group)
            if bad:
                raise SystemExit(
                    f"unknown cleaner id(s): {', '.join(bad)}. "
                    f"Run `cleanix list` to see valid ids."
                )
    # Apply the user's extra protected-paths to the safety guard.
    from cleanix.core import safety
    safety.set_protected_globs(config.protected_globs)

    cleaners = build_cleaners(config, only=only, exclude=exclude)
    if not cleaners:
        raise SystemExit("no cleaners selected")
    return Engine(cleaners)


def _scan(engine: Engine, console: Console, *, quiet: bool = False):
    """Scan with a live progress bar when attached to a terminal."""
    if quiet or not console.is_terminal:
        return engine.scan()
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning", total=len(engine.cleaners))

        def cb(name: str) -> None:
            progress.update(task, advance=1, description=f"Scanning {name}")

        return engine.scan(progress=cb)


# -- commands ---------------------------------------------------------------
def cmd_list(args: argparse.Namespace, console: Console) -> int:
    from rich.table import Table

    from cleanix.core.platform import ALL, os_label

    config = _load_config()
    table = Table(title=f"Cleaners (this system: {os_label()})")
    table.add_column("id", style="cyan")
    table.add_column("name")
    table.add_column("root?", justify="center")
    table.add_column("platforms", style="magenta")
    table.add_column("here?", justify="center")
    table.add_column("default", justify="center")
    table.add_column("description", style="dim")
    for cid, cleaner in describe_all(config).items():
        plats = "all" if ALL in cleaner.platforms else ",".join(cleaner.platforms)
        here = cleaner.supported()
        if not args.all and not here:
            continue
        table.add_row(
            cid,
            cleaner.name,
            "yes" if cleaner.requires_root else "no",
            plats,
            "[green]✓[/green]" if here else "[dim]–[/dim]",
            "on" if cleaner.default_enabled else "[yellow]opt-in[/yellow]",
            cleaner.description,
        )
    console.print(table)
    if not args.all:
        console.print(
            "[dim]Showing cleaners for this OS. Use --all to list every "
            "platform's cleaners.[/dim]"
        )
    return 0


def _run_scan(args: argparse.Namespace, console: Console) -> ScanResult:
    _require_nonempty_selection(args)
    _configure_scope(args)
    config = _apply_profile(_load_config(), getattr(args, "profile", None))
    engine = _make_engine(config, _effective_only(args, console),
                          _split_csv(args.exclude))
    result = _scan(engine, console, quiet=args.summary or args.json)
    _apply_min_size(result, _parse_size(getattr(args, "min_size", None)))
    return result


def cmd_scan(args: argparse.Namespace, console: Console) -> int:
    # Fast path: summarize a previously-written JSON report instead of
    # re-scanning the whole system (used by the scheduled-run notification so a
    # niced background job scans exactly once).
    if args.summary and getattr(args, "input", None):
        try:
            data = json.loads(Path(args.input).expanduser().read_text(encoding="utf-8-sig"))
            items = data.get("cleanable_items", data.get("total_items", 0))
            human = data.get("cleanable_human", data.get("total_human", "0 B"))
            print(f"{items} item(s), {human} reclaimable")
            return 0
        except (OSError, ValueError):
            print("scan complete")
            return 0

    result = _run_scan(args, console)

    if not args.summary and not args.json:
        _scope_note(console)

    if args.summary:
        # One-liner, e.g. for desktop notifications.
        print(
            f"{result.total_items} item(s), "
            f"{human_size(result.total_size)} reclaimable"
        )
        return 0

    if args.json:
        payload = scan_to_json(result)
        if args.output:
            Path(args.output).expanduser().write_text(payload, encoding="utf-8")
            if not args.quiet:
                console.print(f"[green]Wrote report to {safe(args.output)}[/green]")
        else:
            print(payload)
        return 0

    if not args.quiet:
        render_scan_table(
            result, console,
            sort=getattr(args, "sort", "none"),
            top=getattr(args, "top", 0),
        )
        if result.report_only_items():
            console.print()
            render_report_only(result, console)
        reg_items = registry_items(result.cleanable_items())
        if reg_items:
            console.print()
            render_registry_items(reg_items, console)
        if result.cleanable_items():
            console.print(
                "\nRun [bold]cleanix clean[/bold] to preview removal, or "
                "[bold]cleanix clean --execute[/bold] to reclaim this space."
            )
    return 0


def cmd_explain(args: argparse.Namespace, console: Console) -> int:
    """Show exactly which paths/commands one cleaner would consider, and why
    it is safe — a read-only, per-item view for building trust."""
    from rich.table import Table

    cid = args.cleaner_id
    if unknown_ids([cid]):
        console.print(f"[red]unknown cleaner id: {cid}[/red] "
                      "(run `cleanix list`)")
        return 1
    _require_nonempty_selection(args)
    _configure_scope(args)
    config = _load_config()
    engine = _make_engine(config, only=[cid], exclude=None)
    report = _scan(engine, console, quiet=True).reports[0]

    console.print(f"[bold cyan]{safe(report.name)}[/bold cyan] — "
                  f"{safe(report.description)}")
    if not report.ran:
        console.print(f"[yellow]skipped: {safe(report.skipped_reason)}[/yellow]")
        return 0
    if not report.items:
        console.print("[green]nothing found — clean.[/green]")
        return 0
    table = Table(show_lines=False)
    table.add_column("Size", justify="right", style="green")
    table.add_column("Kind", style="magenta")
    table.add_column("Root?", justify="center")
    table.add_column("Delete?", justify="center")
    table.add_column("Path / command", style="cyan", overflow="fold")
    for i in sorted(report.items, key=lambda x: x.size, reverse=True):
        table.add_row(
            human_size(i.size),
            i.kind.value,
            "yes" if i.requires_root else "no",
            "[yellow]report-only[/yellow]" if i.report_only else "yes",
            safe(item_target(i)),
        )
    console.print(table)
    console.print(f"[dim]{report.count} item(s), "
                  f"{human_size(report.total_size)} total. This was read-only; "
                  f"nothing was removed.[/dim]")
    return 0


# Selections that make no sense together with --act-on (it names its own
# scenarios and always scans exactly those).
_ACT_ON_CONFLICTS = (
    ("only", "--only"), ("exclude", "--exclude"), ("registry", "--registry"),
    ("profile", "--profile"), ("simulate", "--simulate"),
    ("interactive", "--interactive"), ("quarantine", "--quarantine"),
    ("min_size", "--min-size"),
)
_BLANKET_WORDS = ("all", "*", "everything")
RESTORE_CMD = "cleanix restore"


def _resolve_act_scenarios(raw: str, config: Config, flag: str = "--act-on"):
    """Turn the --act-on value into cleaner ids: (ids, None) or (None, error).

    Accepts finding cleaner ids and finding category names (case-insensitive;
    a category expands to its scenarios that apply to this system). Never a
    blanket word."""
    from cleanix.core import findings

    tokens = [t.strip() for t in raw.split(",")]
    if not raw.strip() or any(not t for t in tokens):
        return None, (f"{flag} needs scenario ids or category names "
                      "(empty entries are not allowed)")
    categories = {c.lower(): c for c in findings.CATEGORY_ORDER}
    finding_ids = {k.lower(): k for k in findings.FINDING_CATEGORIES}
    applicable = None
    ids: List[str] = []
    for tok in tokens:
        low = tok.lower()
        if low in _BLANKET_WORDS:
            return None, (f"{flag} does not accept {tok!r}: name the scenarios "
                          "or categories explicitly (see `cleanix list`)")
        cat = categories.get(low)
        if cat is not None:
            if applicable is None:
                applicable = {cid for cid, c in describe_all(config).items()
                              if c.supported()}
            new = [cid for cid, c in findings.FINDING_CATEGORIES.items()
                   if c == cat and cid in applicable]
            if not new:
                return None, (f"no scenario in category {cat!r} applies to "
                              "this system")
        elif low in finding_ids:
            new = [finding_ids[low]]
        elif unknown_ids([tok]):
            return None, (f"unknown scenario {tok!r}. Use a findings cleaner id "
                          "or one of the categories: "
                          + ", ".join(findings.CATEGORY_ORDER[:-1]))
        else:
            return None, (f"{tok!r} is not a findings scenario: it is an "
                          f"ordinary cleaner (use --only without {flag})")
        for cid in new:
            if cid not in ids:
                ids.append(cid)
    return ids, None


def _act_error(console: Console, message: str) -> int:
    console.print(f"[red]{safe(message)}[/red]")
    return 2


def _act_line(console: Console, item, action: str) -> None:
    """One finding: size and label, then what will happen (``action`` must
    already be markup-safe)."""
    console.print(f"  {human_size(item.size):>10}  {safe(item.description)}")
    console.print(f"              [dim]-> {action}[/dim]")


def cmd_clean_act_on(args: argparse.Namespace, console: Console) -> int:
    """`clean --act-on`: act on report-only findings the user named.

    Preview by default; --execute acts (one confirmation unless --yes).
    Quarantine unless --permanent. Scans only the named scenarios."""
    from cleanix.core import findings, service

    for attr, flag in _ACT_ON_CONFLICTS:
        val = getattr(args, attr, None)
        used = (val is not None) if attr in ("only", "exclude", "profile") else bool(val)
        if used:
            return _act_error(
                console, f"--act-on cannot be combined with {flag}: it names "
                "its own scenarios")
    config = _load_config()
    ids, err = _resolve_act_scenarios(args.act_on, config)
    if err:
        return _act_error(console, err)
    keep = getattr(args, "keep", None)
    keep_help = "|".join(findings.KEEP_POLICIES)
    if keep and "duplicates" not in ids:
        return _act_error(
            console, "--keep only applies to the duplicates scenario; "
            "add duplicates to --act-on or drop --keep")
    if "duplicates" in ids and not keep:
        return _act_error(
            console, f"the duplicates scenario needs --keep ({keep_help}) "
            "to choose which copy stays")
    permanent = bool(getattr(args, "permanent", False))

    _configure_scope(args)
    engine = _make_engine(config, ids, None)
    _scope_note(console)
    scan = _scan(engine, console)
    groups = findings.group_findings(scan)
    all_items = [i for g in groups for i in g.items]
    if not all_items:
        console.print("[green]Nothing found for the named scenarios.[/green]")
        return 0

    root_items = [i for i in all_items if i.requires_root]
    rest = [i for i in all_items if not i.requires_root]
    dups = [i for i in rest if i.remedy is not None and i.remedy.group]
    dup_ids = {id(i) for i in dups}
    to_act = [i for i in rest if id(i) not in dup_ids]
    plan_skipped: List[Tuple[object, str]] = []
    kept_ids = set()
    if dups:
        if not keep:
            return _act_error(
                console, f"duplicate findings need --keep ({keep_help})")
        plan = findings.plan_duplicates(dups, keep)
        to_act += plan.items
        plan_skipped = list(plan.skipped)
        kept_ids = {id(i) for i in plan.kept}

    # Dry-run pass: the real verdict (and reason) for every item.
    pre = service.act(to_act, config, dry_run=True, permanent=permanent,
                      record_history=False)
    key = findings.path_key
    skip_by_path: Dict[str, str] = {
        key(i.path): why for i, why in plan_skipped + list(pre.skipped)
        if getattr(i, "path", None)}
    stamped = {key(i.path): i for i in to_act if i.path}
    kept_paths = {key(i.path) for i in plan.kept} if dups else set()
    eligible = [i for i in to_act if key(i.path) not in skip_by_path]

    undo = ("permanent, no undo" if permanent else
            f"kept in quarantine; undo with `{RESTORE_CMD}`")
    verb = "delete" if permanent else "quarantine"
    for category in findings.CATEGORY_ORDER:
        shown = []
        for g in groups:
            if g.category != category:
                continue
            its = [i for i in g.items if not i.requires_root]
            if its:
                shown.append((g, its))
        if not shown:
            continue
        console.print(f"\n[bold cyan]{safe(category)}[/bold cyan]")
        for g, its in shown:
            console.print(f"[bold]{safe(g.title)}[/bold]")
            for i in its:
                k = key(i.path) if i.path else ""
                why = skip_by_path.get(k)
                if why is not None:
                    label = why if k in kept_paths else f"skipped: {why}"
                    _act_line(console, i, safe(label))
                    continue
                action = f"{verb}: {undo}"
                kept = findings.survivor_of(stamped[k]) if k in stamped else None
                if kept is not None:
                    action += f" (keeps {safe(kept.path)})"
                _act_line(console, i, action)
    if root_items:
        console.print("\n[yellow]Needs an elevated run (not done here)[/yellow]")
        for i in root_items:
            _act_line(console, i, "not done here: needs an elevated run")

    total = sum(i.size for i in eligible)
    if not eligible:
        console.print("\nNothing can be acted on right now.")
        return 0
    if not args.execute:
        console.print(
            f"\n[yellow]Preview: {len(eligible)} item(s), up to "
            f"{human_size(total)}, would be "
            f"{'deleted' if permanent else 'quarantined'}.[/yellow]")
        console.print("[dim]This was a dry run. Add [bold]--execute[/bold] to "
                      "act on these items.[/dim]")
        return 0

    if not args.yes:
        console.print()
        if not _stdin_is_tty():
            console.print(
                "[red]Refusing to act without a terminal to confirm in; pass "
                "--yes to proceed. Nothing was changed.[/red]")
            return 2
        try:
            confirmed = Confirm.ask(
                f"{'Permanently delete' if permanent else 'Quarantine'} "
                f"{len(eligible)} item(s), up to {human_size(total)}?",
                default=False)
        except (EOFError, OSError):
            console.print(
                "[red]Cannot ask for confirmation without a terminal; pass "
                "--yes to proceed. Nothing was changed.[/red]")
            return 2
        if not confirmed:
            console.print("Aborted. Nothing was changed.")
            return 1

    with console.status("Working..."):
        summary = service.act(to_act, config, dry_run=False, permanent=permanent)
    console.print()
    console.print(
        f"[green]Freed {human_size(summary.freed)} across {summary.removed} "
        f"item(s).[/green]")
    if summary.quarantine_run:
        run = safe(summary.quarantine_run)
        console.print(
            f"[cyan]Quarantine run '{run}':[/cyan] undo with "
            f"[bold]{RESTORE_CMD} {run}[/bold]; space is reclaimed once you run "
            f"[bold]cleanix quarantine empty[/bold].")
    elif permanent and summary.removed:
        console.print("[dim]Deleted permanently; there is no undo.[/dim]")
    skipped = [(i, w) for i, w in plan_skipped if id(i) not in kept_ids]
    skipped += list(summary.skipped)
    skipped += [(i, "needs an elevated run (not done here)") for i in root_items]
    if skipped:
        console.print(f"\n[yellow]Skipped {len(skipped)} item(s):[/yellow]")
        for i, why in skipped:
            console.print(f"  {safe(getattr(i, 'description', ''))}: {safe(why)}")
    if summary.undo_record_error:
        console.print(f"[red]{safe(summary.undo_record_error)}[/red]")
    for o in summary.errors:
        console.print(
            f"  [red]![/red] {safe(o.item.description)}: {safe(o.error)}")
    # Same convention as plain `clean`: 2 on real errors, 1 only for a user
    # abort (above), 0 for success (skips are not failures).
    return 2 if summary.errors or summary.undo_record_error else 0


def cmd_review(args: argparse.Namespace, console: Console) -> int:
    """`review`: walk findings one item at a time; delete only on an explicit
    `d` (or `g`) per item. Needs a terminal."""
    from cleanix.core import findings, review, service

    config = _load_config()
    targets = list(getattr(args, "targets", None) or [])
    keep = getattr(args, "keep", None)
    keep_help = "|".join(findings.KEEP_POLICIES)
    if targets:
        ids, err = _resolve_act_scenarios(",".join(targets), config, "review")
        if err:
            return _act_error(console, err)
        if keep and "duplicates" not in ids:
            return _act_error(
                console, "--keep only applies to the duplicates scenario; "
                "add duplicates to the review or drop --keep")
        if "duplicates" in ids and not keep:
            return _act_error(
                console, f"the duplicates scenario needs --keep ({keep_help}) "
                "to choose which copy stays")
    else:
        applicable = {cid for cid, c in describe_all(config).items()
                      if c.supported()}
        ids = [cid for cid in findings.FINDING_CATEGORIES if cid in applicable]
        if not ids:
            console.print("No findings scenario applies to this system.")
            return 0
    permanent = bool(getattr(args, "permanent", False))
    if not _stdin_is_tty():
        return _act_error(
            console, "review is interactive and needs a terminal; run it in "
            "one (or use `clean --act-on` with --execute). Nothing was changed.")

    _configure_scope(args)
    engine = _make_engine(config, ids, None)
    _scope_note(console)
    scan = _scan(engine, console)
    groups = findings.group_findings(scan)
    groups = [g for g in groups if any(not i.requires_root for i in g.items)]
    if not groups:
        console.print("[green]Nothing found to review.[/green]")
        return 0
    has_dups = any(i.remedy is not None and i.remedy.group
                   for g in groups for i in g.items if not i.requires_root)
    if has_dups and not keep:
        return _act_error(
            console, f"duplicate findings need --keep ({keep_help}) to choose "
            "which copy stays")

    def ask(prompt: str) -> str:
        return input(prompt)

    def act(items):
        return service.act(items, config, dry_run=False, permanent=permanent)

    res = review.run(groups, ask, act, console, keep=keep, permanent=permanent)
    if res.failed:
        return 2
    return 1 if res.aborted else 0


def cmd_clean(args: argparse.Namespace, console: Console) -> int:
    if getattr(args, "act_on", None) is not None:
        return cmd_clean_act_on(args, console)
    for attr, flag in (("keep", "--keep"), ("permanent", "--permanent")):
        if getattr(args, attr, None):
            return _act_error(console, f"{flag} only applies with --act-on")
    _require_nonempty_selection(args)
    _configure_scope(args)
    config = _apply_profile(_load_config(), getattr(args, "profile", None))
    only = _effective_only(args, console)
    engine = _make_engine(config, only, _split_csv(args.exclude))

    _scope_note(console)
    scan = _scan(engine, console)
    _apply_min_size(scan, _parse_size(getattr(args, "min_size", None)))

    if scan.total_items == 0:
        console.print("[green]Nothing to clean — system is tidy.[/green]")
        return 0

    render_scan_table(scan, console)
    if scan.report_only_items():
        console.print()
        render_report_only(scan, console)

    # Report-only items are never deleted — exclude them from the clean set.
    items = scan.cleanable_items()
    if not items:
        console.print(
            "\n[green]Nothing to clean.[/green] (Any findings above are "
            "report-only and must be removed manually.)"
        )
        return 0
    reg_items = registry_items(items)
    if reg_items:
        console.print()
        render_registry_items(reg_items, console)
        # Registry cleaners are opt-in: a registry item is only ever acted on
        # when its cleaner was named explicitly (--only or --registry).
        named = {c.lower() for c in (only or [])}
        if any(i.cleaner_id.lower() not in named for i in reg_items):
            console.print(
                "\n[red]Registry cleaners must be selected explicitly with "
                "--registry or --only (for example --only win_reg_uninstall). "
                "Nothing was changed.[/red]"
            )
            return 2
    # Registry items get their own elevation message below.
    root_items = [i for i in items
                  if i.requires_root and i.kind is not ItemKind.REGISTRY]
    if root_items and not is_root():
        console.print(
            f"\n[yellow]{len(root_items)} item(s) require root and will be "
            f"skipped. {_elevate_text().capitalize()} to include them.[/yellow]"
        )

    # --simulate: write the exact target list without touching anything.
    if getattr(args, "simulate", False):
        return _write_simulation(items, console)

    # --interactive: let the user curate the set before anything is removed.
    if getattr(args, "interactive", False) and not args.yes:
        items = _interactive_select(items, console)
        if not items:
            console.print("Nothing selected. Nothing was deleted.")
            return 0

    # Everything below works on the final selection: recompute the registry
    # subset so a deselected entry is neither listed nor removed.
    reg_items = registry_items(items)

    # Machine-wide registry entries can only be removed from an elevated
    # terminal; the rest of the selection still goes ahead.
    skipped_hklm = []
    if reg_items and not _is_elevated():
        skipped_hklm = [
            i for i in reg_items if i.reg is not None and i.reg.hive == "HKLM"
        ]
        if skipped_hklm:
            n = len(skipped_hklm)
            console.print(
                f"\n[yellow]{n} machine-wide (HKLM) registry entr"
                f"{'y' if n == 1 else 'ies'} need an elevated "
                f"(Administrator) terminal and will be skipped; "
                f"{_elevate_text()} to include them.[/yellow]"
            )
            items = [i for i in items if i not in skipped_hklm]
            reg_items = [i for i in reg_items if i not in skipped_hklm]
            if not items:
                console.print("Nothing was changed.")
                return 1 if args.execute else 0

    dry_run = not args.execute
    if dry_run:
        result = engine.clean(items, dry_run=True)
        console.print()
        render_clean_summary(result, console)
        if reg_items:
            console.print("[bold]Registry entries that would be removed:[/bold]")
            for i in reg_items:
                console.print(f"  {safe(item_target(i))}")
            console.print("[dim]Nothing in the registry was touched.[/dim]")
        console.print(
            "\n[dim]This was a dry run. Add [bold]--execute[/bold] to actually "
            "remove these items.[/dim]"
        )
        return 0

    # Real deletion — require confirmation unless --yes.
    plain_items = [i for i in items if i.kind is not ItemKind.REGISTRY]
    permanent = bool(plain_items) and not args.quarantine
    if reg_items:
        console.print("\n[bold]These registry entries will be removed:[/bold]")
        for i in reg_items:
            console.print(f"  {safe(item_target(i))}")
    if permanent and reg_items:
        console.print("[yellow]Files and commands will be permanently "
                      "removed.[/yellow]")
    if reg_items:
        console.print(f"[yellow]{safe(registry_notice())}[/yellow]")
    if not args.yes:
        console.print()
        try:
            confirmed = Confirm.ask(
                f"{'Permanently remove' if permanent else 'Remove'} "
                f"{len(items)} item(s) and reclaim up to "
                f"{human_size(sum(i.size for i in items))}?",
                default=False,
            )
        except (EOFError, OSError):
            console.print(
                "[red]Cannot ask for confirmation without a terminal; pass "
                "--yes to proceed. Nothing was changed.[/red]"
            )
            return 2
        if not confirmed:
            console.print("Aborted. Nothing was deleted.")
            return 1

    quarantine = None
    summary = None
    free_before = _disk_free()
    if reg_items:
        # The service layer always backs registry entries up first (it creates
        # the backup run), records history (with the registry count) and
        # saves the run.
        from cleanix.core import service

        with console.status("Cleaning..."):
            summary = service.clean(
                items, config, dry_run=False, use_quarantine=bool(args.quarantine)
            )
        result = summary.result
        # The run id, restore hint and undo error come first and in plain
        # text: nothing printed afterwards may hide them.
        _print_registry_outcome(summary, args, console)
    else:
        if args.quarantine:
            from cleanix.core import quarantine as qmod
            quarantine = qmod.new_run()
        with console.status("Cleaning..."):
            result = engine.clean(items, dry_run=False, quarantine=quarantine)
    console.print()
    try:
        render_clean_summary(result, console)
    except Exception:  # noqa: BLE001 - never hide the outcome over formatting
        for o in result.errors:
            print(f"  ! {o.item.description!r}: {o.error!r}")

    # Show the real filesystem free-space change (an honest cross-check against
    # the estimated bytes — e.g. Docker's VM disk not shrinking on macOS).
    free_after = _disk_free()
    if free_before is not None and free_after is not None:
        gained = free_after - free_before
        console.print(
            f"[dim]Disk free on {_disk_label()} : {human_size(free_before)} → "
            f"{human_size(free_after)} ({'+' if gained >= 0 else ''}"
            f"{human_size(gained)}).[/dim]"
        )

    # Record history, write a per-file audit manifest, and finalize quarantine.
    from cleanix.core import history
    if summary is not None:
        manifest = summary.manifest_path or ""
    else:
        history.record(result.freed, result.removed_count,
                       mode="quarantine" if quarantine else "delete")
        manifest = history.write_manifest(result)
    if manifest:
        console.print(f"[dim]Audit log: {safe(manifest)}[/dim]")
    if quarantine is not None and quarantine.items:
        quarantine.save()
        console.print(
            f"\n[cyan]Moved {len(quarantine.items)} item(s) to quarantine "
            f"'{quarantine.run_id}'.[/cyan] Space is reclaimed once you run "
            f"[bold]cleanix quarantine empty[/bold]; undo with "
            f"[bold]cleanix restore[/bold]."
        )
    if result.errors:
        return 2
    return 1 if skipped_hklm else 0


def _print_registry_outcome(summary, args, console: Console) -> None:
    """After a clean that included registry entries: what was removed and what
    the user may truthfully do about it (read from regpromises)."""
    from cleanix.core import regpromises

    outcomes = summary.result.outcomes
    reg_done = [o for o in outcomes
                if o.removed and o.item.kind is ItemKind.REGISTRY]
    files_done = [o for o in outcomes
                  if o.removed and o.item.kind is ItemKind.PATH]
    run_id = summary.quarantine_run

    # Plain text (markup off) so nothing can swallow these lines.
    def plain(text: str) -> None:
        console.print(_visible(text), markup=False, highlight=False)

    if reg_done:
        if not regpromises.registry_undo_shipped():
            plain("")
            plain(registry_notice())
        elif run_id:
            plain("")
            plain(f"Registry backup saved in run '{run_id}'; undo with "
                  f"cleanix restore {run_id}.")
            if any(o.item.reg is not None and o.item.reg.hive == "HKLM"
                   for o in reg_done):
                plain("Restoring HKLM entries needs an Administrator terminal.")
    if summary.undo_record_error:
        plain(summary.undo_record_error)
    if args.quarantine and files_done and run_id:
        plain(f"Moved {len(files_done)} item(s) to quarantine '{run_id}'. "
              "Space is reclaimed once you run cleanix quarantine empty.")


def cmd_config(args: argparse.Namespace, console: Console) -> int:
    from rich.table import Table

    from cleanix import config as cfgmod

    action = args.config_action
    path = cfgmod.config_file_path()

    if action == "path":
        console.print(str(path))
        return 0

    if action == "list":
        overrides = cfgmod.read_user_overrides()
        effective = Config.load()
        table = Table(title=f"Cleanix configuration ({path})")
        table.add_column("key", style="cyan")
        table.add_column("value", style="green")
        table.add_column("source")
        table.add_column("description", style="dim")
        for name in cfgmod.field_names():
            value = getattr(effective, name)
            overridden = name in overrides
            table.add_row(
                name,
                _fmt_value(value),
                "[yellow]set[/yellow]" if overridden else "default",
                cfgmod.FIELD_HELP.get(name, ""),
            )
        console.print(table)
        return 0

    if action == "get":
        effective = Config.load()
        if args.key not in cfgmod.field_names():
            console.print(f"[red]unknown key: {args.key}[/red]")
            return 1
        console.print(_fmt_value(getattr(effective, args.key)))
        return 0

    if action == "set":
        try:
            value = cfgmod.coerce_value(args.key, args.value)
        except KeyError:
            console.print(f"[red]unknown key: {args.key}[/red]")
            return 1
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")
            return 1
        cfgmod.write_user_override(args.key, value)
        console.print(f"[green]{args.key}[/green] = {_fmt_value(value)}  ({path})")
        return 0

    if action == "unset":
        if cfgmod.remove_user_override(args.key):
            console.print(f"[green]reverted {args.key} to its default[/green]")
        else:
            console.print(f"[dim]{args.key} was not overridden[/dim]")
        return 0

    return 1


def _fmt_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value) if value else "[]"
    return str(value)


def _run_reset_command(cmd: List[str]) -> int:
    """Execute a reset command with inherited stdio (patchable for tests)."""
    import subprocess

    return subprocess.run(cmd).returncode


def _execute_reset(args: argparse.Namespace, console: Console, plan) -> int:
    import sys as _sys

    from cleanix import reset as resetmod

    # 1) Only reversible strategies with defined actions may execute.
    if not plan.reversible or not plan.actions:
        console.print(
            "\n[red]Execution is only available on reversible systems[/red] "
            "(NixOS, rpm-ostree, openSUSE MicroOS, Guix). This system's reset is "
            "not reversible, so cleanix will not run it — use the plan above with "
            "a snapshot restore or reinstall."
        )
        return 1

    # 2) Show exactly what will run and how to undo it.
    from rich.panel import Panel

    lines = []
    for a in plan.actions:
        lines.append(f"[cyan]$ {' '.join(a.command)}[/cyan]")
        lines.append(f"    [dim]{a.description}[/dim]")
        if a.undo:
            lines.append(f"    [dim]undo: {a.undo}[/dim]")
    console.print(
        Panel("\n".join(lines), title="Reversible actions to execute",
              border_style="red")
    )

    # 3) Privilege check.
    needs_root = any(a.requires_root for a in plan.actions)
    if needs_root and not is_root():
        console.print(
            f"[red]These actions require root — {_elevate_text()}.[/red]"
        )
        return 1

    # 4) Refuse non-interactive execution; require a typed confirmation phrase.
    if not _sys.stdin.isatty():
        console.print(
            "[red]Refusing to reset non-interactively.[/red] Run in a terminal."
        )
        return 1
    phrase = resetmod.confirmation_phrase()
    console.print(
        "\n[bold red]This will change your system state.[/bold red] It is "
        "reversible (see 'undo' above), but take a snapshot first if unsure."
    )
    answer = Prompt.ask(f'Type [bold]{phrase}[/bold] to proceed (anything else aborts)')
    if answer.strip() != phrase:
        console.print("Aborted. Nothing was changed.")
        return 1

    # 5) Run.
    results = resetmod.execute_actions(plan, _run_reset_command)
    failed = [(a, c) for a, c in results if c != 0]
    for a, c in results:
        status = "[green]ok[/green]" if c == 0 else f"[red]failed (exit {c})[/red]"
        console.print(f"  {status}: {' '.join(a.command)}")
    if failed:
        console.print("[red]Reset stopped on failure.[/red]")
        return 2
    console.print(
        "\n[green]Reset actions completed.[/green] Reboot to boot the reset "
        "state; use the 'undo' commands above to revert if needed."
    )
    return 0


def cmd_factory_reset(args: argparse.Namespace, console: Console) -> int:
    from rich.panel import Panel

    from cleanix.core import platform as plat

    if plat.is_windows():
        console.print(
            "[red]factory-reset is not supported on Windows.[/red] Use "
            "Settings > System > Recovery (Reset this PC) instead."
        )
        return 1

    from cleanix.reset import build_plan

    plan = build_plan(args.scope)
    rev = (
        "[green]reversible[/green]" if plan.reversible
        else "[red]NOT reversible[/red]"
    )
    console.print(
        Panel(
            f"[bold]Detected:[/bold] {plan.strategy}   ({rev})\n\n{plan.summary}",
            title="Factory-reset plan (advisory — cleanix will NOT run these)",
            border_style="red",
        )
    )
    console.print("\n[bold]Before you start:[/bold]")
    for pre in plan.prerequisites:
        console.print(f"  [yellow]•[/yellow] {pre}")

    for i, tier in enumerate(plan.tiers, 1):
        body = f"[dim]{tier.warning}[/dim]\n"
        for step in tier.steps:
            if step.startswith(" ") or any(
                step.startswith(c) for c in ("sudo ", "rm ", "tar ", "cleanix ",
                                             "rpm-ostree", "snapper", "guix",
                                             "nixos", "apt", "dnf", "pacman",
                                             "flatpak", "ostree", "System Settings")
            ):
                body += f"\n    [cyan]$ {step.strip()}[/cyan]"
            else:
                body += f"\n  {step}"
        console.print(Panel(body, title=f"Tier {i}: {tier.title}", border_style="yellow"))

    if args.execute:
        return _execute_reset(args, console, plan)

    if plan.reversible and plan.actions:
        console.print(
            "\n[dim]This is a plan. To have cleanix run the reversible "
            "rollback for you, re-run with [bold]--execute[/bold].[/dim]"
        )
    else:
        console.print(
            "\n[dim]This is a plan only. This system's reset is not reversible, "
            "so cleanix will not run it — use a snapshot restore or reinstall.[/dim]"
        )
    return 0


def _fmt_time(ts: float) -> str:
    import datetime as _dt

    if not ts:
        return "never"
    return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def cmd_info(args: argparse.Namespace, console: Console) -> int:
    import platform as _plat

    from rich.table import Table

    from cleanix import __version__
    from cleanix import config as cfgmod
    from cleanix.cleaners.base import SCOPE_SYSTEM
    from cleanix.core import context, history, quarantine
    from cleanix.core.platform import os_label
    from cleanix.core.registry import describe_all
    from cleanix.core.utils import is_root, which

    config = _load_config()
    cleaners = describe_all(config)
    applicable = [c for c in cleaners.values() if c.supported()]
    sys_n = sum(1 for c in applicable if c.scope == SCOPE_SYSTEM)

    pkg_mgrs = [
        m for m in (
            "apt-get", "dnf", "yum", "pacman", "zypper", "apk", "xbps-install",
            "emerge", "eopkg", "swupd", "flatpak", "snap", "nix", "guix",
            "brew", "port", "pkg", "conda", "mamba",
        ) if which(m)
    ]

    st = history.stats()
    tbl = Table(title=f"Cleanix {__version__}", show_header=False)
    tbl.add_column("k", style="cyan", no_wrap=True)
    tbl.add_column("v")
    tbl.add_row("Operating system", f"{os_label()}  (kernel {_plat.release()})")
    tbl.add_row("Running as", "root" if is_root() else context.invoking_user().name)
    tbl.add_row("Applicable cleaners", f"{len(applicable)} ({sys_n} system, "
                f"{len(applicable)-sys_n} per-user) of {len(cleaners)} total")
    tbl.add_row("Package managers", ", ".join(pkg_mgrs) or "none detected")
    tbl.add_row("Config file", str(cfgmod.config_file_path()))
    tbl.add_row("Lifetime cleaned", f"{human_size(st['total_freed'])} across "
                f"{st['runs']} run(s); last {_fmt_time(st['last_time'])}")
    tbl.add_row("Quarantine", f"{human_size(quarantine.total_size())} in "
                f"{len(quarantine.list_runs())} run(s)")
    console.print(tbl)
    return 0


def cmd_stats(args: argparse.Namespace, console: Console) -> int:
    from cleanix.core import history

    st = history.stats()
    console.print(
        f"[green]Lifetime:[/green] {human_size(st['total_freed'])} freed across "
        f"{st['total_items']} item(s) in {st['runs']} run(s)."
    )
    for e in st["entries"][-10:]:
        console.print(
            f"  {_fmt_time(e.get('time', 0))}  "
            f"{human_size(e.get('freed', 0)):>10}  "
            f"{e.get('items', 0):>4} items  ({e.get('mode', 'delete')})"
        )
    return 0


def _sparkline(values: List[float]) -> str:
    bars = "▁▂▃▄▅▆▇█"
    nums = [v for v in values if v is not None]
    if not nums:
        return ""
    hi = max(nums)
    if hi <= 0:
        return bars[0] * len(nums)
    return "".join(bars[min(len(bars) - 1, int(v / hi * (len(bars) - 1)))]
                   for v in nums)


def cmd_dashboard(args: argparse.Namespace, console: Console) -> int:
    """A at-a-glance view: lifetime reclaim trend + the last scheduled scan."""
    from rich.panel import Panel
    from rich.table import Table

    from cleanix.core import history

    st = history.stats()
    entries = st["entries"]
    freed_series = [e.get("freed", 0) for e in entries[-30:]]

    header = (
        f"[bold]{human_size(st['total_freed'])}[/bold] reclaimed across "
        f"[bold]{st['runs']}[/bold] run(s), "
        f"[bold]{st['total_items']}[/bold] item(s).\n"
    )
    if freed_series:
        header += (
            f"Recent runs: [green]{_sparkline(freed_series)}[/green]  "
            f"(last: {human_size(freed_series[-1])} on "
            f"{_fmt_time(st['last_time'])})"
        )
    else:
        header += "[dim]No clean runs recorded yet.[/dim]"
    console.print(Panel(header, title="Cleanix dashboard", expand=False))

    # The most recent scheduled/read-only scan report, if one exists.
    from cleanix.core.history import state_dir

    report = state_dir() / "last-scan.json"
    if report.exists():
        try:
            data = json.loads(report.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            data = None
        if data:
            console.print(
                f"\n[cyan]Last scan[/cyan] ({data.get('generated_at', '?')}): "
                f"{data.get('cleanable_human', '0 B')} cleanable, "
                f"{data.get('report_only_human', '0 B')} to review."
            )
            cleaners = sorted(
                (c for c in data.get("cleaners", []) if c.get("bytes", 0) > 0),
                key=lambda c: c.get("bytes", 0), reverse=True,
            )[:8]
            if cleaners:
                table = Table(show_header=True, header_style="dim")
                table.add_column("Top sources", style="cyan")
                table.add_column("Reclaimable", justify="right", style="green")
                for c in cleaners:
                    table.add_row(c.get("name", c.get("id", "?")),
                                  c.get("human", human_size(c.get("bytes", 0))))
                console.print(table)
    else:
        console.print(
            "\n[dim]No scan report yet. Run `cleanix scan --json --output "
            f"{report}` (the scheduler does this automatically).[/dim]"
        )
    return 0


def cmd_restore(args: argparse.Namespace, console: Console) -> int:
    from cleanix.core import quarantine

    if getattr(args, "yes", False) and not args.run_id:
        console.print(
            "[red]--yes needs an explicit run id; it is never accepted for "
            "the latest run. Nothing was restored.[/red]"
        )
        return 2
    run_id = args.run_id or quarantine.latest_run()
    if not run_id:
        console.print("[yellow]Nothing in quarantine to restore.[/yellow]")
        return 1

    # Machine-wide (HKLM) registry entries: show exactly what would be
    # written and get an explicit confirmation before allowing it.
    allow_machine = False
    from cleanix.core import regpromises

    info = next((r for r in quarantine.list_runs() if r["run_id"] == run_id), None)
    if (info and info.get("registry_admin")
            and regpromises.registry_undo_shipped()):
        if not _is_elevated():
            console.print(
                "[yellow]This run contains machine-wide (HKLM) registry "
                "entries. Restoring them needs an Administrator terminal: "
                f"open one and run `cleanix restore {safe(run_id)}`. Other entries "
                "in the run are restored now.[/yellow]"
            )
        else:
            try:
                lines = quarantine.describe_registry_entries(run_id)
            except FileNotFoundError as exc:
                console.print(f"[red]{safe(exc)}[/red]")
                return 1
            if lines:
                console.print("\n[bold]Registry entries that will be written:[/bold]")
                for line in lines:
                    console.print(f"  {safe(line)}")
                if not getattr(args, "yes", False):
                    if not _stdin_is_tty():
                        console.print(
                            "[red]Refusing to restore machine-wide registry "
                            "entries non-interactively. Run in a terminal, or "
                            "pass the run id with --yes.[/red]"
                        )
                        return 2
                    try:
                        answer = Prompt.ask(
                            "Type [bold]yes[/bold] to write these entries "
                            "(anything else aborts)"
                        )
                    except (EOFError, OSError):
                        console.print(
                            "[red]Cannot ask for confirmation without a "
                            "terminal. Nothing was restored.[/red]"
                        )
                        return 2
                    if answer.strip() != "yes":
                        console.print("Aborted. Nothing was restored.")
                        return 1
                allow_machine = True
    try:
        if allow_machine:
            res = quarantine.restore(run_id, allow_machine_restore=True)
        else:
            res = quarantine.restore(run_id)
    except FileNotFoundError as exc:
        console.print(f"[red]{safe(exc)}[/red]")
        return 1
    console.print(
        f"[green]Restored {len(res['restored'])} item(s)[/green] from "
        f"'{safe(run_id)}'."
    )
    for path, why in res["failed"]:
        console.print(f"  [red]![/red] {safe(path)}: {safe(why)}")
    for path, why in res.get("not_restored", []):
        console.print(f"  [yellow]-[/yellow] {safe(path)}: {safe(why)}")
    return 0 if not res["failed"] else 2


def cmd_quarantine(args: argparse.Namespace, console: Console) -> int:
    from rich.table import Table

    from cleanix.core import quarantine

    if args.quarantine_action == "list":
        runs = quarantine.list_runs()
        if not runs:
            console.print("[dim]Quarantine is empty.[/dim]")
            return 0
        tbl = Table(title="Quarantine runs")
        tbl.add_column("run id", style="cyan")
        tbl.add_column("when")
        tbl.add_column("items", justify="right")
        tbl.add_column("size", justify="right", style="green")
        for r in runs:
            tbl.add_row(r["run_id"], _fmt_time(r["created"]),
                        str(r["count"]), human_size(r["size"]))
        console.print(tbl)
        return 0

    # empty
    if args.all or not args.run_id:
        freed, errors = quarantine.purge_all_detailed()
        console.print(f"[green]Emptied quarantine, reclaimed {human_size(freed)}.[/green]")
    else:
        freed, errors = quarantine.purge_detailed(args.run_id)
        console.print(f"[green]Removed run '{args.run_id}', reclaimed {human_size(freed)}.[/green]")
    for err in errors:
        console.print(f"[red]Could not remove:[/red] {err}")
    return 1 if errors else 0


def cmd_gui(args: argparse.Namespace, console: Console) -> int:
    from cleanix.gui import app

    try:
        app.require_qt()
    except app.GuiUnavailable as exc:
        console.print(str(exc), markup=False, highlight=False)
        return 1
    return app.main([sys.argv[0]])


def cmd_completion(args: argparse.Namespace, console: Console) -> int:
    from cleanix.completion import generate

    # Print raw script to stdout so it can be redirected/sourced.
    print(generate(args.shell))
    return 0


def cmd_schedule(args: argparse.Namespace, console: Console) -> int:
    from cleanix.scheduler import backend

    sched = backend()  # systemd on Linux/BSD, launchd on macOS
    try:
        if args.action == "install":
            console.print(sched.install(args.frequency))
        elif args.action == "uninstall":
            console.print(sched.uninstall())
        else:  # status
            console.print(sched.status())
    except (RuntimeError, ValueError) as exc:
        console.print(f"[red]{exc}[/red]")
        return 1
    return 0


# -- parser -----------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cleanix",
        description="A safe, thorough scheduled system cleaner for Linux, macOS, BSD and Windows.",
    )
    parser.add_argument(
        "--version", action="version", version=f"cleanix {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_selection(p: argparse.ArgumentParser, registry: bool = False) -> None:
        p.add_argument(
            "--only",
            metavar="IDS",
            help="comma-separated cleaner ids to include exclusively",
        )
        p.add_argument(
            "--exclude",
            metavar="IDS",
            help="comma-separated cleaner ids to skip",
        )
        if registry:
            p.add_argument(
                "--registry",
                action="store_true",
                help="Windows only: select the five opt-in registry cleaners "
                "(alone: only those; with --only: added to it)",
            )
        scope = p.add_mutually_exclusive_group()
        scope.add_argument(
            "--all-users",
            action="store_true",
            help="scan every user's home + the whole system (default when root)",
        )
        scope.add_argument(
            "--current-user",
            action="store_true",
            help="only scan the invoking user's home (even when running as root)",
        )
        p.add_argument(
            "--min-uid",
            type=int,
            default=None,
            metavar="N",
            help="lowest uid treated as a real user when scanning all users",
        )

    p_list = sub.add_parser("list", help="list available cleaners")
    p_list.add_argument(
        "--all",
        action="store_true",
        help="include cleaners for other operating systems",
    )
    p_list.set_defaults(func=cmd_list)

    p_scan = sub.add_parser("scan", help="analyze the system (read-only)")
    add_selection(p_scan, registry=True)
    p_scan.add_argument("--json", action="store_true", help="emit JSON")
    p_scan.add_argument(
        "--output", metavar="FILE", help="write JSON report to FILE"
    )
    p_scan.add_argument(
        "--quiet", action="store_true", help="suppress the human-readable table"
    )
    p_scan.add_argument(
        "--summary",
        action="store_true",
        help="print a one-line summary (for notifications)",
    )
    p_scan.add_argument(
        "--sort",
        choices=["none", "size", "name"],
        default="none",
        help="sort the results table",
    )
    p_scan.add_argument(
        "--top",
        type=int,
        default=0,
        metavar="N",
        help="show only the N cleaners with the most to reclaim",
    )
    p_scan.add_argument(
        "--min-size",
        metavar="SIZE",
        default=None,
        help="ignore items smaller than SIZE (e.g. 100M, 1.5G)",
    )
    p_scan.add_argument(
        "--input",
        metavar="FILE",
        default=None,
        help="with --summary, summarize a previously written JSON report "
        "instead of re-scanning",
    )
    _add_profile(p_scan)
    p_scan.set_defaults(func=cmd_scan)

    p_clean = sub.add_parser(
        "clean", help="remove junk (dry-run unless --execute)"
    )
    add_selection(p_clean, registry=True)
    p_clean.add_argument(
        "--execute",
        action="store_true",
        help="actually delete (default is a dry-run preview)",
    )
    p_clean.add_argument(
        "--yes",
        action="store_true",
        help="skip the confirmation prompt (implies non-interactive)",
    )
    p_clean.add_argument(
        "--quarantine",
        action="store_true",
        help="move items to a reversible quarantine instead of deleting "
        "(undo with `cleanix restore`)",
    )
    p_clean.add_argument(
        "--min-size",
        metavar="SIZE",
        default=None,
        help="only remove items at least SIZE (e.g. 100M, 1.5G)",
    )
    p_clean.add_argument(
        "--simulate",
        action="store_true",
        help="write the exact list of paths/commands that --execute would act "
        "on to a file, without deleting anything",
    )
    p_clean.add_argument(
        "--interactive",
        action="store_true",
        help="pick individual items to remove from a checklist before cleaning",
    )
    p_clean.add_argument(
        "--act-on",
        metavar="SCENARIOS",
        default=None,
        help="act on report-only findings: comma-separated finding ids "
        "(e.g. big_files,duplicates) or category names; preview unless "
        "--execute; quarantined unless --permanent",
    )
    p_clean.add_argument(
        "--keep",
        choices=["oldest", "newest", "shortest-path"],
        default=None,
        help="with --act-on duplicates: which copy of each group stays",
    )
    p_clean.add_argument(
        "--permanent",
        action="store_true",
        help="with --act-on: delete instead of quarantining (no undo)",
    )
    _add_profile(p_clean)
    p_clean.set_defaults(func=cmd_clean)

    p_review = sub.add_parser(
        "review",
        help="walk findings one item at a time and choose what to delete "
        "(interactive)",
    )
    p_review.add_argument(
        "targets",
        nargs="*",
        metavar="IDS_OR_CATEGORIES",
        help="finding ids or category names to review (default: every "
        "findings scenario that applies to this system)",
    )
    p_review.add_argument(
        "--keep",
        choices=["oldest", "newest", "shortest-path"],
        default=None,
        help="which copy of each duplicate group stays (required to review "
        "duplicates)",
    )
    p_review.add_argument(
        "--permanent",
        action="store_true",
        help="delete instead of quarantining (no undo)",
    )
    p_review.set_defaults(func=cmd_review)

    p_explain = sub.add_parser(
        "explain", help="show exactly what one cleaner would consider (read-only)"
    )
    p_explain.add_argument("cleaner_id", help="the cleaner id to explain")
    add_selection(p_explain)
    p_explain.set_defaults(func=cmd_explain)

    p_sched = sub.add_parser(
        "schedule", help="manage the periodic analysis timer"
    )
    p_sched.add_argument(
        "action", choices=["install", "uninstall", "status"]
    )
    p_sched.add_argument(
        "--frequency",
        default="weekly",
        choices=["hourly", "daily", "weekly", "monthly"],
        help="how often to run the analysis (default: weekly)",
    )
    p_sched.set_defaults(func=cmd_schedule)

    # config
    p_cfg = sub.add_parser("config", help="view and change configuration")
    cfg_sub = p_cfg.add_subparsers(dest="config_action", required=True)
    cfg_sub.add_parser("list", help="show all settings, values, and sources")
    cfg_sub.add_parser("path", help="print the config file path")
    cfg_get = cfg_sub.add_parser("get", help="print one setting's value")
    cfg_get.add_argument("key")
    cfg_set = cfg_sub.add_parser("set", help="change a setting")
    cfg_set.add_argument("key")
    cfg_set.add_argument("value")
    cfg_unset = cfg_sub.add_parser("unset", help="revert a setting to its default")
    cfg_unset.add_argument("key")
    p_cfg.set_defaults(func=cmd_config)

    # completion
    p_comp = sub.add_parser("completion", help="print a shell-completion script")
    p_comp.add_argument("shell", choices=["bash", "zsh", "fish"])
    p_comp.set_defaults(func=cmd_completion)

    # info / stats
    p_info = sub.add_parser("info", help="show environment & cleanix status")
    p_info.set_defaults(func=cmd_info)
    p_stats = sub.add_parser("stats", help="show lifetime clean statistics")
    p_stats.set_defaults(func=cmd_stats)
    p_dash = sub.add_parser(
        "dashboard", help="reclaim trend + last scan at a glance"
    )
    p_dash.set_defaults(func=cmd_dashboard)

    # restore / quarantine
    p_restore = sub.add_parser("restore", help="undo a clean from quarantine")
    p_restore.add_argument("run_id", nargs="?", help="run id (default: latest)")
    p_restore.add_argument(
        "--yes",
        action="store_true",
        help="skip the typed confirmation for machine-wide registry entries "
        "(only together with an explicit run id)",
    )
    p_restore.set_defaults(func=cmd_restore)

    p_quar = sub.add_parser("quarantine", help="manage the quarantine store")
    quar_sub = p_quar.add_subparsers(dest="quarantine_action", required=True)
    quar_sub.add_parser("list", help="list quarantine runs")
    q_empty = quar_sub.add_parser("empty", help="permanently reclaim quarantined space")
    q_empty.add_argument("run_id", nargs="?", help="run id (default: all)")
    q_empty.add_argument("--all", action="store_true", help="empty every run")
    p_quar.set_defaults(func=cmd_quarantine)

    # factory-reset (advisory plan)
    p_reset = sub.add_parser(
        "factory-reset",
        help="show a plan to restore the OS toward factory settings",
    )
    p_reset.add_argument(
        "--scope",
        choices=["user", "packages", "system", "full"],
        default="full",
        help="how much to reset (default: full)",
    )
    p_reset.add_argument(
        "--execute",
        action="store_true",
        help="run the reversible rollback (only on NixOS/rpm-ostree/MicroOS/Guix; "
        "requires a typed confirmation)",
    )
    p_reset.set_defaults(func=cmd_factory_reset)

    p_gui = sub.add_parser("gui", help="launch the desktop GUI (requires the gui extra)")
    p_gui.set_defaults(func=cmd_gui)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if sys.platform == "win32":
        # Redirected/scheduled output defaults to a legacy code page that
        # cannot encode the table glyphs; never crash on rendering.
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, ValueError, OSError):
                pass
    console = Console()
    try:
        return args.func(args, console)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
