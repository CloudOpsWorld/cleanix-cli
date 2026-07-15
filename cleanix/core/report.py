"""Rendering scan/clean results as rich tables or JSON."""

from __future__ import annotations

import json
from typing import Any, Dict

from rich.console import Console
from rich.table import Table

from cleanix.core.models import CleanResult, ScanResult
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
            table.add_row(report.name, "-", "-", report.skipped_reason or "skipped")
            continue
        if report.count == 0:
            table.add_row(report.name, "0", "-", "clean")
            continue
        note = report.description
        size_cell = human_size(report.total_size)
        if report.report_only:
            note = "[yellow]report only — review manually[/yellow]"
            size_cell = f"[yellow]{size_cell}[/yellow]"
        table.add_row(report.name, str(report.count), size_cell, note)

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
        table.add_row(human_size(i.size), i.description, i.hint or "")
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
            f"  [red]![/red] {outcome.item.description}: {outcome.error}"
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
                    }
                    for i in r.items
                ],
            }
            for r in result.reports
        ],
    }


def scan_to_json(result: ScanResult) -> str:
    return json.dumps(scan_to_dict(result), indent=2)
