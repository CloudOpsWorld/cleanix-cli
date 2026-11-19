"""Reversible cleaning: move junk to a quarantine instead of deleting it.

``cleanix clean --quarantine`` moves items into a per-run quarantine directory
and writes a manifest. ``cleanix restore`` moves them back; ``cleanix quarantine
empty`` reclaims the space for good. This makes cleaning undoable — a safety net
most cleaners don't offer.

Registry entries (``ItemKind.REGISTRY``) are never moved: before each delete
:meth:`Quarantine.store_registry` writes and verifies a ``.reg`` + JSON
backup under ``<run>/registry`` and saves the manifest, so the entry is
recorded before anything is deleted. Manifest entries carry
``"type": "registry"``; entries without ``"type"`` are files, as before.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cleanix.core.context import invoking_user
from cleanix.core.utils import path_size

_ERROR_NOT_SAME_DEVICE = 17  # Windows winerror for a cross-volume rename
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _rename(src: str, dst: str) -> None:
    """os.rename indirection (tests force the cross-volume fallback)."""
    os.rename(src, dst)


def _is_cross_volume(exc: OSError) -> bool:
    import errno

    return (
        getattr(exc, "winerror", None) == _ERROR_NOT_SAME_DEVICE
        or exc.errno == errno.EXDEV
    )


def _win_attrs(entry_or_path) -> int:
    if isinstance(entry_or_path, os.DirEntry):
        st = entry_or_path.stat(follow_symlinks=False)
    else:
        st = os.lstat(entry_or_path)
    return st.st_file_attributes  # fail closed: AttributeError/OSError propagate


def _win_find_reparse(path: str) -> Optional[str]:
    """First reparse point at or below ``path`` (never followed), else None."""
    if _win_attrs(path) & _FILE_ATTRIBUTE_REPARSE_POINT:
        return path
    if not os.path.isdir(path):
        return None
    with os.scandir(path) as it:
        entries = list(it)
    for entry in entries:
        attrs = _win_attrs(entry)
        if attrs & _FILE_ATTRIBUTE_REPARSE_POINT:
            return entry.path
        if entry.is_dir(follow_symlinks=False):
            found = _win_find_reparse(entry.path)
            if found:
                return found
    return None


def _win_copy_no_reparse(src: str, dst: str) -> None:
    """Copy a file or tree, refusing (OSError) on any reparse point met."""
    if _win_attrs(src) & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise OSError(f"refusing to copy reparse point {src}")
    if not os.path.isdir(src):
        shutil.copy2(src, dst)
        return
    os.mkdir(dst)
    with os.scandir(src) as it:
        entries = list(it)
    for entry in entries:
        target = os.path.join(dst, entry.name)
        if _win_attrs(entry) & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise OSError(f"refusing to copy reparse point {entry.path}")
        if entry.is_dir(follow_symlinks=False):
            _win_copy_no_reparse(entry.path, target)
        else:
            shutil.copy2(entry.path, target)
    shutil.copystat(src, dst)


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
        # item_key -> index of its registry entry in ``items`` (this process only)
        self._reg_index: Dict[str, int] = {}

    def store(self, path: os.PathLike | str) -> None:
        """Move ``path`` into this quarantine run, recording its origin."""
        if os.name == "nt":
            self._store_windows(path)
            return
        src = Path(os.path.abspath(str(path)))
        size = path_size(src)
        self.files_dir.mkdir(parents=True, exist_ok=True)
        idx = len(self.items)
        dest = self.files_dir / f"{idx}__{src.name}"
        shutil.move(str(src), str(dest))
        self.items.append(
            {"original": str(src), "stored": str(dest), "size": size}
        )

    def _store_windows(self, path: os.PathLike | str) -> None:
        """Windows store: check and act on the same canonical path.

        * Same volume: a plain ``os.rename`` (moves a junction as the link
          itself; a locked file makes it fail with nothing copied).
        * Cross volume: refuse if any junction/symlink is inside (never copy a
          link target); otherwise copy without following reparse points, then
          remove the source with the guarded remover. A failed copy is removed;
          if the source cannot be fully removed after a good copy, the copy
          (possibly the only surviving bytes) is kept and recorded as
          ``partial`` in the manifest straight away, never left silently.
        """
        from cleanix.core import safety

        src = safety.assert_safe_to_delete(path)
        src_s = str(src)
        if not os.path.lexists(src_s):
            raise FileNotFoundError(src_s)
        size = path_size(src)
        self.files_dir.mkdir(parents=True, exist_ok=True)
        idx = len(self.items)
        dest = self.files_dir / f"{idx}__{src.name}"
        dest_s = str(dest)
        try:
            _rename(src_s, dest_s)
        except OSError as exc:
            if not _is_cross_volume(exc):
                raise
        else:
            self.items.append({"original": src_s, "stored": dest_s, "size": size})
            return

        link = _win_find_reparse(src_s)
        if link:
            raise OSError(
                f"cannot quarantine across volumes: {link} is a junction/symlink"
            )
        try:
            _win_copy_no_reparse(src_s, dest_s)
        except BaseException:
            if os.path.lexists(dest_s):
                try:
                    safety.safe_rmtree(dest_s)
                except OSError as cleanup_exc:
                    self.items.append({
                        "original": src_s, "stored": dest_s, "size": path_size(dest),
                        "partial": True,
                        "note": f"incomplete copy could not be removed: {cleanup_exc}",
                    })
                    self.save()
            raise
        try:
            safety.safe_rmtree(src_s)
        except OSError as exc:
            self.items.append({
                "original": src_s, "stored": dest_s, "size": size, "partial": True,
                "note": f"copied, but the source could not be fully removed: {exc}",
            })
            self.save()
            raise
        self.items.append({"original": src_s, "stored": dest_s, "size": size})

    # -- registry backups (RegistryBackupSink) -------------------------------
    def store_registry(self, item, backend) -> None:
        """Back up one registry entry before its delete.

        Raises ``regclean.RegistryChanged`` when the entry no longer matches
        the scan, ``regbackup.BackupError`` (or ``OSError``) when the backup
        cannot be written, verified and recorded. All or nothing: on any
        failure no manifest entry and no backup file is left behind."""
        from cleanix.core import regbackup, regsnap
        from cleanix.core.models import ItemKind, item_key
        from cleanix.core.regclean import RegistryChanged

        reg = item.reg
        if item.kind is not ItemKind.REGISTRY or reg is None:
            raise ValueError("not a registry item")
        try:
            snap = regsnap.snapshot(backend, reg)
        except regsnap.SnapshotError as exc:
            raise RegistryChanged(str(exc)) from exc
        if regsnap.fingerprint(reg, snap) != reg.fingerprint:
            raise RegistryChanged("the entry differs from the scan")
        idx = len(self.items)
        files = regbackup.write_backup(
            self.dir / "registry", idx, item.cleaner_id, reg, snap
        )
        self.items.append({
            "type": "registry",
            "original": reg.display,
            "cleaner_id": item.cleaner_id,
            "hive": reg.hive,
            "key": reg.key,
            "value": reg.value,
            "json": str(files.json_path),
            "reg": str(files.reg_path),
            "size": 0,
            "deleted": None,
        })
        try:
            self.save()  # durable before the delete
        except BaseException:
            self.items.pop()
            for p in (files.json_path, files.reg_path):
                try:
                    os.unlink(str(p))
                except OSError:
                    pass
            raise
        self._reg_index[item_key(item)] = idx

    def mark_registry(self, item, deleted: bool) -> None:
        """Record whether the entry was deleted (False: certainly not)."""
        from cleanix.core.models import item_key

        idx = self._reg_index.get(item_key(item))
        if idx is None:
            return
        self.items[idx]["deleted"] = bool(deleted)
        self.save()

    before_delete = store_registry
    after_delete = mark_registry

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
        items = data.get("items", [])
        reg = [i for i in items if isinstance(i, dict) and i.get("type") == "registry"]
        runs.append(
            {
                "run_id": data.get("run_id", run_dir.name),
                "created": data.get("created", 0),
                "count": len(items),
                "size": sum(i.get("size", 0) for i in items),
                "registry": len(reg),
                "registry_admin": sum(1 for i in reg if i.get("hive") == "HKLM"),
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
        kind = item.get("type")
        if kind == "registry":
            if item.get("deleted") is False:
                continue  # never deleted: nothing to restore
            ok, text = _restore_registry(run_dir, run_id, item)
            if ok:
                restored.append(text)
            else:
                failed.append((item.get("original", "?"), text))
            continue
        if kind is not None:
            failed.append((item.get("original", "?"), "unknown entry type"))
            continue
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


def _restore_registry(run_dir: Path, run_id: str, item: Dict) -> Tuple[bool, str]:
    """``(True, display)`` or ``(False, reason)``. The backup is always read
    from this run's own ``registry`` directory (only the recorded file name
    is used), so a manifest cannot point restore at a file elsewhere. HKCU
    entries are restored in-process; HKLM ones only when elevated, else the
    refusal names the run and the ``reg import`` fallback (ruling R6)."""
    from cleanix.core import regbackup, winenv, winregistry

    name = Path(str(item.get("json") or "")).name
    json_path = run_dir / "registry" / name
    try:
        shown = regbackup.restore_entry(
            json_path, winregistry.get_backend(),
            is_admin=winenv.is_admin(), require_owner=True,
        )
    except regbackup.RestoreRefused as exc:
        return False, exc.message_for(run_id)
    except Exception as exc:  # noqa: BLE001 - one entry never aborts the rest
        return False, str(exc) or type(exc).__name__
    return True, shown


def purge_detailed(run_id: str) -> Tuple[int, List[str]]:
    """``(bytes actually reclaimed, errors)`` for removing one run.

    On Windows the run is removed with the guarded, read-only-clearing,
    junction-safe remover; whatever cannot be removed is reported and not
    counted as reclaimed. Elsewhere this is :func:`purge` with no errors.
    """
    if os.name != "nt":
        return purge(run_id), []
    from cleanix.core import safety

    run_dir = quarantine_root() / run_id
    data = _read_manifest(run_dir)
    recorded = sum(i.get("size", 0) for i in data.get("items", [])) if data else 0
    if not os.path.lexists(str(run_dir)):
        return 0, []
    before = path_size(run_dir)
    errors: List[str] = []
    try:
        safety.safe_rmtree(run_dir)
    except (OSError, safety.UnsafePathError) as exc:
        errors.append(str(exc))
    if not os.path.lexists(str(run_dir)):
        return recorded, errors
    if not errors:
        errors.append(f"{run_dir} could not be fully removed")
    mf = run_dir / "manifest.json"
    if data and not mf.exists():
        # Keep what is left visible to `quarantine list/empty`.
        try:
            mf.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except OSError:
            pass
    remaining = path_size(run_dir)
    return max(0, min(recorded, before - remaining)), errors


def purge_all_detailed() -> Tuple[int, List[str]]:
    total, errors = 0, []
    for run in list_runs():
        freed, errs = purge_detailed(run["run_id"])
        total += freed
        errors += errs
    return total, errors


def purge(run_id: str) -> int:
    if os.name == "nt":
        return purge_detailed(run_id)[0]
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
