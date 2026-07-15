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
from typing import List, Optional

from rich.console import Console
from rich.prompt import Confirm, Prompt

from cleanix import __version__
from cleanix.config import Config
from cleanix.core.engine import Engine
from cleanix.core.models import ScanResult
from cleanix.core.registry import build_cleaners, describe_all, unknown_ids
from cleanix.core.report import (
    render_clean_summary,
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


def _require_nonempty_selection(args: argparse.Namespace) -> None:
    """Reject `--only ''` / `--exclude ''` (a blank filter is almost always a
    scripting typo, and silently means 'no filter')."""
    for flag in ("only", "exclude"):
        raw = getattr(args, flag, None)
        if raw is not None and not _split_csv(raw):
            raise SystemExit(f"--{flag} was given but empty; omit it to select all")


def _disk_free(path: str = "/") -> Optional[int]:
    import shutil as _shutil

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
        console.print(f"  [cyan]{idx:>3}[/cyan]  {human_size(i.size):>10}  "
                      f"{i.description}")
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
        target = i.path or ("$ " + " ".join(i.command or []))
        root = " [root]" if i.requires_root else ""
        lines.append(f"{human_size(i.size):>10}  {target}{root}")
    body = "\n".join(lines) + "\n"
    out = state_dir() / "last-simulation.txt"
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(body)
        where = str(out)
    except OSError:
        where = None
    console.print(
        f"[cyan]Simulation:[/cyan] {len(items)} item(s), "
        f"{human_size(sum(i.size for i in items))} would be reclaimed. "
        "[dim]Nothing was deleted.[/dim]"
    )
    console.print(body.rstrip())
    if where:
        console.print(f"[dim]Written to {where}[/dim]")
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
    engine = _make_engine(config, _split_csv(args.only), _split_csv(args.exclude))
    result = _scan(engine, console, quiet=args.summary or args.json)
    _apply_min_size(result, _parse_size(getattr(args, "min_size", None)))
    return result


def cmd_scan(args: argparse.Namespace, console: Console) -> int:
    # Fast path: summarize a previously-written JSON report instead of
    # re-scanning the whole system (used by the scheduled-run notification so a
    # niced background job scans exactly once).
    if args.summary and getattr(args, "input", None):
        try:
            data = json.loads(Path(args.input).expanduser().read_text())
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
            Path(args.output).expanduser().write_text(payload)
            if not args.quiet:
                console.print(f"[green]Wrote report to {args.output}[/green]")
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

    console.print(f"[bold cyan]{report.name}[/bold cyan] — {report.description}")
    if not report.ran:
        console.print(f"[yellow]skipped: {report.skipped_reason}[/yellow]")
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
        target = i.path or " ".join(i.command or [])
        table.add_row(
            human_size(i.size),
            i.kind.value,
            "yes" if i.requires_root else "no",
            "[yellow]report-only[/yellow]" if i.report_only else "yes",
            target,
        )
    console.print(table)
    console.print(f"[dim]{report.count} item(s), "
                  f"{human_size(report.total_size)} total. This was read-only; "
                  f"nothing was removed.[/dim]")
    return 0


def cmd_clean(args: argparse.Namespace, console: Console) -> int:
    _require_nonempty_selection(args)
    _configure_scope(args)
    config = _apply_profile(_load_config(), getattr(args, "profile", None))
    engine = _make_engine(config, _split_csv(args.only), _split_csv(args.exclude))

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
    root_items = [i for i in items if i.requires_root]
    if root_items and not is_root():
        console.print(
            f"\n[yellow]{len(root_items)} item(s) require root and will be "
            f"skipped. Re-run with sudo to include them.[/yellow]"
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

    dry_run = not args.execute
    if dry_run:
        result = engine.clean(items, dry_run=True)
        console.print()
        render_clean_summary(result, console)
        console.print(
            "\n[dim]This was a dry run. Add [bold]--execute[/bold] to actually "
            "remove these items.[/dim]"
        )
        return 0

    # Real deletion — require confirmation unless --yes.
    if not args.yes:
        console.print()
        confirmed = Confirm.ask(
            f"Permanently remove {len(items)} item(s) and reclaim up to "
            f"{human_size(scan.cleanable_size)}?",
            default=False,
        )
        if not confirmed:
            console.print("Aborted. Nothing was deleted.")
            return 1

    quarantine = None
    if args.quarantine:
        from cleanix.core import quarantine as qmod
        quarantine = qmod.new_run()

    free_before = _disk_free()
    with console.status("Cleaning..."):
        result = engine.clean(items, dry_run=False, quarantine=quarantine)
    console.print()
    render_clean_summary(result, console)

    # Show the real filesystem free-space change (an honest cross-check against
    # the estimated bytes — e.g. Docker's VM disk not shrinking on macOS).
    free_after = _disk_free()
    if free_before is not None and free_after is not None:
        gained = free_after - free_before
        console.print(
            f"[dim]Disk free on / : {human_size(free_before)} → "
            f"{human_size(free_after)} ({'+' if gained >= 0 else ''}"
            f"{human_size(gained)}).[/dim]"
        )

    # Record history, write a per-file audit manifest, and finalize quarantine.
    from cleanix.core import history
    history.record(result.freed, result.removed_count,
                   mode="quarantine" if quarantine else "delete")
    manifest = history.write_manifest(result)
    if manifest:
        console.print(f"[dim]Audit log: {manifest}[/dim]")
    if quarantine is not None and quarantine.items:
        quarantine.save()
        console.print(
            f"\n[cyan]Moved {len(quarantine.items)} item(s) to quarantine "
            f"'{quarantine.run_id}'.[/cyan] Space is reclaimed once you run "
            f"[bold]cleanix quarantine empty[/bold]; undo with "
            f"[bold]cleanix restore[/bold]."
        )
    return 0 if not result.errors else 2


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
        defaults = Config()
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
            "[red]These actions require root — re-run with sudo.[/red]"
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

    from cleanix import __version__, config as cfgmod
    from cleanix.core import context, history, quarantine
    from cleanix.core.platform import current_distro, os_label
    from cleanix.core.registry import describe_all
    from cleanix.core.utils import is_root, which
    from cleanix.cleaners.base import SCOPE_SYSTEM

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


def cmd_restore(args: argparse.Namespace, console: Console) -> int:
    from cleanix.core import quarantine

    run_id = args.run_id or quarantine.latest_run()
    if not run_id:
        console.print("[yellow]Nothing in quarantine to restore.[/yellow]")
        return 1
    try:
        res = quarantine.restore(run_id)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        return 1
    console.print(
        f"[green]Restored {len(res['restored'])} item(s)[/green] from '{run_id}'."
    )
    for path, why in res["failed"]:
        console.print(f"  [red]![/red] {path}: {why}")
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
        freed = quarantine.purge_all()
        console.print(f"[green]Emptied quarantine, reclaimed {human_size(freed)}.[/green]")
    else:
        freed = quarantine.purge(args.run_id)
        console.print(f"[green]Removed run '{args.run_id}', reclaimed {human_size(freed)}.[/green]")
    return 0


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
        description="A safe, thorough scheduled system cleaner for Linux, macOS and BSD.",
    )
    parser.add_argument(
        "--version", action="version", version=f"cleanix {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_selection(p: argparse.ArgumentParser) -> None:
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
    add_selection(p_scan)
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
    add_selection(p_clean)
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
    _add_profile(p_clean)
    p_clean.set_defaults(func=cmd_clean)

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

    # restore / quarantine
    p_restore = sub.add_parser("restore", help="undo a clean from quarantine")
    p_restore.add_argument("run_id", nargs="?", help="run id (default: latest)")
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

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console()
    try:
        return args.func(args, console)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
