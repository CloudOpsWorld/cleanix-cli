"""Reversible cleaning: move junk to a quarantine instead of deleting it.

``cleanix clean --quarantine`` moves items into a per-run quarantine directory
and writes a manifest. ``cleanix restore`` moves them back; ``cleanix quarantine
empty`` reclaims the space for good. This makes cleaning undoable — a safety net
most cleaners don't offer.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path
from typing import Dict, List, Optional

from cleanix.core.context import invoking_user
from cleanix.core.utils import path_size


def quarantine_root() -> Path:
    from cleanix.core import platform as plat
    from cleanix.core import winenv

    if plat.is_windows():
        return winenv.local_appdata() / "cleanix" / "quarantine"
    return invoking_user().home / ".local" / "state" / "cleanix" / "quarantine"


class Quarantine:
    """A single quarantine run (a batch of moved items)."""

    def __init__(self, run_id: str):
        self.run_id = run_id
        self.dir = quarantine_root() / run_id
        self.files_dir = self.dir / "files"
        self.items: List[Dict] = []

    def store(self, path: os.PathLike | str) -> None:
        """Move ``path`` into this quarantine run, recording its origin."""
        src = Path(os.path.abspath(str(path)))
        size = path_size(src)
        self.files_dir.mkdir(parents=True, exist_ok=True)
        idx = len(self.items)
        dest = self.files_dir / f"{idx}__{src.name}"
        shutil.move(str(src), str(dest))
        self.items.append(
            {"original": str(src), "stored": str(dest), "size": size}
        )

    def save(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "manifest.json").write_text(
            json.dumps(
                {"run_id": self.run_id, "created": time.time(), "items": self.items},
                indent=2,
            ),
            encoding="utf-8",
        )

    @property
    def size(self) -> int:
        return sum(i["size"] for i in self.items)


def new_run() -> Quarantine:
    run_id = f"{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}"
    return Quarantine(run_id)


def _read_manifest(run_dir: Path) -> Optional[Dict]:
    mf = run_dir / "manifest.json"
    if not mf.exists():
        return None
    try:
        return json.loads(mf.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None


def list_runs() -> List[Dict]:
    root = quarantine_root()
    runs: List[Dict] = []
    if not root.is_dir():
        return runs
    for run_dir in sorted(root.iterdir()):
        data = _read_manifest(run_dir)
        if not data:
            continue
        runs.append(
            {
                "run_id": data.get("run_id", run_dir.name),
                "created": data.get("created", 0),
                "count": len(data.get("items", [])),
                "size": sum(i.get("size", 0) for i in data.get("items", [])),
            }
        )
    return runs


def latest_run() -> Optional[str]:
    runs = list_runs()
    return runs[-1]["run_id"] if runs else None


def restore(run_id: str) -> Dict:
    """Move a run's items back to their original locations."""
    run_dir = quarantine_root() / run_id
    data = _read_manifest(run_dir)
    if not data:
        raise FileNotFoundError(f"no quarantine run '{run_id}'")

    restored, failed = [], []
    for item in data.get("items", []):
        original = Path(item["original"])
        stored = Path(item["stored"])
        if not stored.exists():
            failed.append((item["original"], "missing from quarantine"))
            continue
        if original.exists():
            failed.append((item["original"], "destination already exists"))
            continue
        try:
            original.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(stored), str(original))
            restored.append(item["original"])
        except OSError as exc:
            failed.append((item["original"], str(exc)))

    # If everything came back, drop the (now empty) run.
    if not failed:
        shutil.rmtree(run_dir, ignore_errors=True)
    return {"restored": restored, "failed": failed}


def purge(run_id: str) -> int:
    run_dir = quarantine_root() / run_id
    data = _read_manifest(run_dir)
    size = sum(i.get("size", 0) for i in data.get("items", [])) if data else 0
    shutil.rmtree(run_dir, ignore_errors=True)
    return size


def purge_all() -> int:
    total = 0
    for run in list_runs():
        total += purge(run["run_id"])
    return total


def total_size() -> int:
    return sum(r["size"] for r in list_runs())
