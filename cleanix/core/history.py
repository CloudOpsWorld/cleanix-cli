"""Clean-run history and lifetime statistics."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List

from cleanix.core.context import invoking_user


def state_dir() -> Path:
    from cleanix.core import platform as plat
    from cleanix.core import winenv

    if plat.is_windows():
        return winenv.local_appdata() / "cleanix"
    return invoking_user().home / ".local" / "state" / "cleanix"


def _history_file() -> Path:
    return state_dir() / "history.jsonl"


def write_manifest(result) -> str:
    """Write a per-item audit manifest of a real clean run, so there is a record
    of exactly which paths/commands were removed. Returns the file path (or "").

    Skipped for dry-runs and when nothing was actually removed.
    """
    if getattr(result, "dry_run", False):
        return ""
    removed = [o for o in result.outcomes if getattr(o, "removed", False)]
    if not removed:
        return ""
    runs = state_dir() / "runs"
    stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime())
    path = runs / f"{stamp}.jsonl"
    try:
        runs.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            for o in removed:
                fh.write(json.dumps({
                    "time": time.time(),
                    "cleaner_id": o.item.cleaner_id,
                    "description": o.item.description,
                    "path": o.item.path,
                    # Registry runs: the target's display only, never values.
                    "registry": (o.item.reg.display
                                 if getattr(o.item, "reg", None) is not None
                                 else None),
                    "command": list(o.item.command) if o.item.command else None,
                    "bytes": o.freed,
                }) + "\n")
        return str(path)
    except OSError:
        return ""


def record(freed: int, items: int, *, mode: str, registry: int = 0) -> None:
    """Append a completed clean run to the history log. ``mode`` is one of
    'delete', 'quarantine', 'mixed' (an act batch that quarantined some
    items and deleted others, e.g. paths plus launch-job files) or
    'administrator' (removed by the elevated helper; see the CLI).
    ``registry`` counts removed registry entries."""
    path = _history_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        entry = {"time": time.time(), "freed": freed, "items": items, "mode": mode}
        if registry:
            entry["registry"] = int(registry)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # history is best-effort; never fail a clean over it


def load() -> List[Dict]:
    path = _history_file()
    if not path.exists():
        return []
    entries: List[Dict] = []
    try:
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    except (OSError, ValueError):
        return entries
    return entries


def stats() -> Dict:
    entries = load()
    return {
        "runs": len(entries),
        "total_freed": sum(e.get("freed", 0) for e in entries),
        "total_items": sum(e.get("items", 0) for e in entries),
        "last_time": entries[-1]["time"] if entries else 0,
        "entries": entries,
    }
