"""Rendering scan/clean results as rich tables or JSON."""

from __future__ import annotations

import json
from typing import Any, Dict

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from cleanix.core import regpromises
from cleanix.core.catalog import REGISTRY_IDS
from cleanix.core.models import (
    CleanResult,
    ItemKind,
    ScanResult,
    _visible,
    item_target,
)
from cleanix.core.utils import human_size


def render_scan_table(
    result: ScanResult, console: Console, *, sort: str = "none", top: int = 0
) -> None:
    table = Table(title="Cleanix — scan results", show_lines=False)
    table.add_column("Cleaner", style="cyan", no_wrap=True)
    table.add_column("Items", justify="right")
    table.add_column("Reclaimable", justify="right", style="green")
    table.add_column("Notes", style="dim")

    reports = list(result.reports)
    if sort == "size":
        reports.sort(key=lambda r: r.total_size, reverse=True)
    elif sort == "name":
        reports.sort(key=lambda r: r.name.lower())
    if top and top > 0:
        # Show only the N with something to clean; keep the rest out of the way.
        nonempty = [r for r in reports if r.count]
        reports = (nonempty if sort != "none" else
                   sorted(nonempty, key=lambda r: r.total_size, reverse=True))[:top]

    for report in reports:
        if not report.ran:
            table.add_row(safe(report.name), "-", "-", safe(report.skipped_reason or "skipped"))
            continue
        if report.count == 0:
            table.add_row(safe(report.name), "0", "-", "clean")
            continue
        note = safe(report.description)
        if report.incomplete:
            note = f"[yellow]incomplete: {safe(report.incomplete)}[/yellow]"
        size_cell = human_size(report.total_size)
        if report.report_only:
            note = "[yellow]report only — review manually[/yellow]"
            size_cell = f"[yellow]{size_cell}[/yellow]"
        table.add_row(safe(report.name), str(report.count), size_cell, note)

    table.add_section()
    table.add_row(
        "[bold]TOTAL (cleanable)[/bold]",
        f"[bold]{len(result.cleanable_items())}[/bold]",
        f"[bold]{human_size(result.cleanable_size)}[/bold]",
        "",
    )
    if result.report_only_items():
        table.add_row(
            "[yellow]report-only[/yellow]",
            f"[yellow]{len(result.report_only_items())}[/yellow]",
            f"[yellow]{human_size(result.report_only_size)}[/yellow]",
            "[dim]not deleted by cleanix[/dim]",
        )
    console.print(table)


def safe(text) -> str:
    """Make any externally derived string (item descriptions, targets, errors,
    hints, run ids) safe to embed in rich markup: control, format and bidi
    characters are shown as escapes and markup brackets are escaped. The single
    output layer for everything that may come from the registry."""
    return escape(_visible(str(text)))


def registry_notice() -> str:
    """What may truthfully be promised about registry removal right now; read
    from ``regpromises`` so every UI changes in one place."""
    if not regpromises.registry_undo_shipped():
        return regpromises.PERMANENT_LINE
    return (
        "Registry entries are backed up before removal. HKCU entries can be "
        "restored with `cleanix restore <run>`; HKLM entries are backed up "
        "too, but restoring them needs an Administrator terminal."
    )


def registry_items(items) -> list:
    return [i for i in items if i.kind is ItemKind.REGISTRY]


def render_registry_items(items: list, console: Console) -> None:
    """List registry findings with their exact (escaped) targets and evidence."""
    if not items:
        return
    table = Table(title="Registry entries", title_style="cyan")
    table.add_column("Hive", style="magenta")
    table.add_column("Target", style="cyan", overflow="fold")
    table.add_column("Evidence", overflow="fold")
    table.add_column("Hint", style="dim", overflow="fold")
    for i in items:
        table.add_row(
            i.reg.hive if i.reg else "",
            safe(item_target(i)),
            safe(i.description),
            safe(i.hint or ""),
        )
    console.print(table)
    console.print(f"[yellow]{safe(registry_notice())}[/yellow]")


def render_report_only(result: ScanResult, console: Console) -> None:
    """List report-only findings with manual-removal hints."""
    items = result.report_only_items()
    if not items:
        return
    table = Table(
        title="Report-only — review and remove manually (never auto-deleted)",
        title_style="yellow",
    )
    table.add_column("Size", justify="right", style="yellow")
    table.add_column("What", style="cyan")
    table.add_column("How to remove", style="dim")
    for i in sorted(items, key=lambda x: x.size, reverse=True):
        table.add_row(human_size(i.size), safe(i.description), safe(i.hint or ""))
    console.print(table)


def render_clean_summary(result: CleanResult, console: Console) -> None:
    verb = "Would free" if result.dry_run else "Freed"
    style = "yellow" if result.dry_run else "green"
    console.print(
        f"[{style}]{verb} {human_size(result.freed)} "
        f"across {result.removed_count if not result.dry_run else len(result.outcomes)} "
        f"item(s).[/{style}]"
    )
    for outcome in result.errors:
        console.print(
            f"  [red]![/red] {safe(outcome.item.description)}: {safe(outcome.error)}"
        )


SCHEMA_VERSION = 1


def scan_to_dict(result: ScanResult) -> Dict[str, Any]:
    import platform
    import socket
    import time

    from cleanix import __version__
    from cleanix.core.platform import os_label

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime()),
        "cleanix_version": __version__,
        "host": socket.gethostname(),
        "os": os_label(),
        "platform": platform.system().lower(),
        "total_items": result.total_items,
        "total_bytes": result.total_size,
        "total_human": human_size(result.total_size),
        # Split totals: what cleanix would delete vs. what it only reports.
        "cleanable_items": len(result.cleanable_items()),
        "cleanable_bytes": result.cleanable_size,
        "cleanable_human": human_size(result.cleanable_size),
        "report_only_items": len(result.report_only_items()),
        "report_only_bytes": result.report_only_size,
        "report_only_human": human_size(result.report_only_size),
        "cleaners": [
            {
                "id": r.cleaner_id,
                "name": r.name,
                "ran": r.ran,
                "skipped_reason": r.skipped_reason,
                "incomplete": r.incomplete,
                "registry": r.cleaner_id in REGISTRY_IDS,
                "count": r.count,
                "bytes": r.total_size,
                "human": human_size(r.total_size),
                "items": [
                    {
                        "description": i.description,
                        "bytes": i.size,
                        "path": i.path,
                        "command": list(i.command) if i.command else None,
                        "requires_root": i.requires_root,
                        "report_only": i.report_only,
                        "hint": i.hint,
                        # Additive: registry findings carry their target here.
                        "kind": i.kind.value,
                        "target": item_target(i),
                        "registry": (
                            {"hive": i.reg.hive, "key": i.reg.key,
                             "value": i.reg.value}
                            if i.reg is not None else None
                        ),
                    }
                    for i in r.items
                ],
            }
            for r in result.reports
        ],
    }


def scan_to_json(result: ScanResult) -> str:
    return json.dumps(scan_to_dict(result), indent=2)
