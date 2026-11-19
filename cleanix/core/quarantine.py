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

import hashlib
import json
import os
import secrets
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


def _replace(src: str, dst: str) -> None:
    """os.replace indirection (tests simulate a failing manifest save)."""
    os.replace(src, dst)


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


class ManifestConflict(OSError):
    """The run's manifest on disk was not written by this run object."""


def _make_run_id() -> str:
    """Creation time first (runs sort chronologically), then the pid and a
    random suffix so two runs created in the same second never collide."""
    return f"{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}-{secrets.token_hex(2)}"


class Quarantine:
    """A single quarantine run (a batch of moved items).

    The run directory is claimed (created with ``exist_ok=False``) before
    the first write; if it already exists the run takes a fresh id, so two
    runs can never share a directory. ``run_id``/``dir`` are final once
    anything was written. :meth:`save` refuses to replace a manifest this
    object did not write."""

    def __init__(self, run_id: str):
        self._set_id(run_id)
        self.items: List[Dict] = []
        # item_key -> index of its registry entry in ``items`` (this process only)
        self._reg_index: Dict[str, int] = {}
        self._claimed = False
        self._written: Optional[str] = None  # sha256 of the manifest we last wrote

    def _set_id(self, run_id: str) -> None:
        self.run_id = run_id
        self.dir = quarantine_root() / run_id
        self.files_dir = self.dir / "files"

    def _claim(self) -> None:
        """Create this run's directory exclusively (retrying with a fresh id)."""
        if self._claimed:
            return
        quarantine_root().mkdir(parents=True, exist_ok=True)
        for _ in range(32):
            try:
                self.dir.mkdir(exist_ok=False)
            except FileExistsError:
                self._set_id(_make_run_id())
                continue
            self._claimed = True
            return
        raise FileExistsError(f"could not create a unique quarantine run under {quarantine_root()}")

    def store(self, path: os.PathLike | str) -> None:
        """Move ``path`` into this quarantine run, recording its origin."""
        self._claim()
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

    def store_copy(self, path: os.PathLike | str) -> str:
        """Copy one regular file into this run (metadata kept) and save the
        manifest before returning the stored path.

        The entry has ``"type": "copy"``: it is a backup for manual recovery
        of something removed permanently, never an Undo, so :func:`restore`
        does not act on it. A link, reparse point or non-regular file is
        refused (OSError). All or nothing: on failure no entry and no copy is
        left behind."""
        import stat as _stat

        src = os.path.abspath(str(path))
        st = os.lstat(src)
        if (not _stat.S_ISREG(st.st_mode)
                or getattr(st, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT):
            raise OSError(f"refusing to copy {src}: not a regular file")
        self._claim()
        self.files_dir.mkdir(parents=True, exist_ok=True)
        idx = len(self.items)
        dest = self.files_dir / f"{idx}__{os.path.basename(src)}"
        try:
            shutil.copy2(src, str(dest), follow_symlinks=False)
            self.items.append({"type": "copy", "original": src, "stored": str(dest),
                               "size": st.st_size})
            try:
                self.save()
            except BaseException:
                self.items.pop()
                raise
        except BaseException:
            try:
                os.unlink(str(dest))
            except OSError:
                pass
            raise
        return str(dest)

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
        self._claim()
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
        """Record whether the entry was deleted (False: certainly not).

        The save is tried twice. If it still fails, the in-memory flag is
        put back to what is on disk (``None``, which restore treats as
        restorable) and the error is raised for the caller to report."""
        from cleanix.core.models import item_key

        idx = self._reg_index.get(item_key(item))
        if idx is None:
            return
        previous = self.items[idx]["deleted"]
        self.items[idx]["deleted"] = bool(deleted)
        last: Optional[BaseException] = None
        for _ in range(2):
            try:
                self.save()
                return
            except Exception as exc:  # noqa: BLE001
                last = exc
                time.sleep(0.05)  # a short back-off before the second attempt
        self.items[idx]["deleted"] = previous
        assert last is not None
        raise last

    before_delete = store_registry
    after_delete = mark_registry

    def save(self) -> None:
        """Write the manifest atomically (temp file, fsync, replace): a
        failed save leaves the previous manifest intact, so entries already
        recorded (e.g. deleted registry entries) stay restorable.

        Raises :class:`ManifestConflict` instead of replacing a manifest
        that this object did not write (another run with the same id)."""
        self._claim()
        data = json.dumps(
            {"run_id": self.run_id, "created": time.time(), "items": self.items},
            indent=2,
        ).encode("utf-8")
        target = self.dir / "manifest.json"
        if os.path.lexists(str(target)):
            current = target.read_bytes()
            if self._written is None or hashlib.sha256(current).hexdigest() != self._written:
                raise ManifestConflict(
                    f"refusing to overwrite the manifest of quarantine run "
                    f"'{self.run_id}': it was not written by this run"
                )
        tmp = self.dir / f".manifest.{os.getpid()}.{secrets.token_hex(6)}.tmp"
        try:
            with open(tmp, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            for attempt in range(4):
                try:
                    _replace(str(tmp), str(target))
                    break
                except PermissionError:
                    # Windows: a reader (AV, indexer, GUI) briefly holds it.
                    if attempt == 3:
                        raise
                    time.sleep(0.05 * (2 ** attempt))
        except BaseException:
            try:
                os.unlink(str(tmp))
            except OSError:
                pass
            raise
        self._written = hashlib.sha256(data).hexdigest()

    @property
    def size(self) -> int:
        return sum(i["size"] for i in self.items)

    def discard_if_empty(self) -> None:
        """Remove this run's directory when nothing was recorded in it
        (only empty directories are removed; nothing else is touched)."""
        if not self._claimed or self.items:
            return
        for d in (self.dir / "registry", self.files_dir, self.dir):
            try:
                os.rmdir(str(d))
            except OSError:
                pass

    @staticmethod
    def describe_registry_entries(run_id: str) -> List[str]:
        return describe_registry_entries(run_id)


def new_run() -> Quarantine:
    """A new run. Nothing is created on disk until the first write."""
    return Quarantine(_make_run_id())


MAX_MANIFEST_BYTES = 8 * 1024 * 1024


def _read_manifest(run_dir: Path) -> Optional[Dict]:
    """The run's manifest, or None. Only a regular file that is not a link
    (symlink, junction or other reparse point) and at most
    ``MAX_MANIFEST_BYTES`` is read (the elevated helper reads manifests in a
    user-writable folder)."""
    import stat as _stat

    mf = Path(run_dir) / "manifest.json"
    try:
        st = os.lstat(str(mf))
    except OSError:
        return None
    if (
        not _stat.S_ISREG(st.st_mode)  # lstat: a symlink is never S_ISREG
        or getattr(st, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
    ):
        return None
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(mf), flags)
        chunks, total = [], 0
        try:
            while total <= MAX_MANIFEST_BYTES:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
        finally:
            os.close(fd)
        raw = b"".join(chunks)
        if len(raw) > MAX_MANIFEST_BYTES:
            return None
        data = json.loads(raw.decode("utf-8-sig"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def list_runs() -> List[Dict]:
    root = quarantine_root()
    runs: List[Dict] = []
    if not root.is_dir():
        return runs
    for run_dir in sorted(root.iterdir()):
        data = _read_manifest(run_dir)
        if not data:
            continue
        items = _items_of(data)
        good = [i for i in items if isinstance(i, dict)]
        reg = [i for i in good if i.get("type") == "registry"]
        runs.append(
            {
                "run_id": data.get("run_id", run_dir.name),
                "created": data.get("created", 0),
                "count": len(items),
                "size": sum(_size_of(i) for i in good),
                "registry": len(reg),
                "registry_admin": sum(1 for i in reg if i.get("hive") == "HKLM"),
                # Entries restore would act on: files, and registry entries
                # not known to be untouched (deleted True, or None = unknown).
                "removed_count": sum(
                    1 for i in good
                    if i.get("type") is None
                    or (i.get("type") == "registry" and i.get("deleted") is not False)
                ),
            }
        )
    return runs


def _items_of(data: Dict) -> List:
    items = data.get("items", []) if isinstance(data, dict) else []
    return items if isinstance(items, list) else []


def _size_of(item: Dict) -> int:
    size = item.get("size", 0)
    return size if isinstance(size, int) and not isinstance(size, bool) else 0


def latest_run() -> Optional[str]:
    """The most recently created run (by the manifest's ``created`` time,
    then the id), never by the lexical order of pid digits."""
    runs = list_runs()
    if not runs:
        return None

    def key(r: Dict):
        c = r.get("created", 0)
        ok = isinstance(c, (int, float)) and not isinstance(c, bool)
        return (c if ok else 0, str(r.get("run_id", "")))

    return max(runs, key=key)["run_id"]


def restore(run_id: str, *, allow_machine_restore: bool = False) -> Dict:
    """Move a run's items back to their original locations.

    Registry entries are re-created from their validated backups. HKCU
    entries are restored in-process. HKLM entries are restored only when the
    process is elevated AND ``allow_machine_restore`` is True, which a caller
    passes only after showing the user :func:`describe_registry_entries` and
    getting confirmation; otherwise they fail with the Administrator-terminal
    advice (ruling R6) and the run is kept."""
    run_dir = quarantine_root() / run_id
    data = _read_manifest(run_dir)
    if not data:
        raise FileNotFoundError(f"no quarantine run '{run_id}'")

    from cleanix.core import regpromises

    restored, failed = [], []
    not_restored = []
    skipped = 0
    for item in _items_of(data):
        if not isinstance(item, dict):
            failed.append(("?", "invalid manifest entry"))
            continue
        kind = item.get("type")
        if kind == "registry":
            if item.get("deleted") is False:
                skipped += 1  # never deleted: nothing to restore, keep its backup
                continue
            if not regpromises.registry_undo_shipped():
                # The registry write path is unverified on real Windows: never
                # run it. Not a failure; file entries restore as before and
                # the run (with its backup files) is kept.
                skipped += 1
                not_restored.append((
                    item.get("original", "?"),
                    regpromises.restore_disabled_text(run_dir / "registry"),
                ))
                continue
            ok, text = _restore_registry(run_dir, run_id, item, allow_machine_restore)
            if ok:
                restored.append(text)
            else:
                failed.append((item.get("original", "?"), text))
            continue
        if kind == "copy":
            # A copy of something removed permanently (Quarantine.store_copy):
            # kept for manual recovery, never restored by Undo.
            skipped += 1
            not_restored.append((
                item.get("original", "?"),
                "removed permanently; not restored automatically. A copy is "
                f"kept in {run_dir / 'files'}",
            ))
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

    # Drop the run only when it is fully consumed: something came back,
    # nothing failed, and no entry with a kept backup was skipped.
    if restored and not failed and not skipped:
        shutil.rmtree(run_dir, ignore_errors=True)
    out = {"restored": restored, "failed": failed}
    if not_restored:  # registry gate closed, or copies of permanent removals
        out["not_restored"] = not_restored
    return out


def _backup_json(run_dir: Path, item: Dict) -> Path:
    """The entry's JSON, always inside this run's ``registry`` directory
    (only the recorded file name is used)."""
    return run_dir / "registry" / Path(str(item.get("json") or "")).name


def _restore_registry(
    run_dir: Path, run_id: str, item: Dict, allow_machine_restore: bool = False
) -> Tuple[bool, str]:
    """``(True, display)`` or ``(False, reason)``. The backup is always read
    from this run's own ``registry`` directory, so a manifest cannot point
    restore at a file elsewhere, and a backup known to belong to another
    account is refused (``require_owner``; for HKLM also unknown ownership).
    HKCU entries are restored in-process; HKLM ones only when elevated and
    confirmed, else the refusal names the run and the ``reg import``
    fallback (ruling R6)."""
    from cleanix.core import regbackup, winenv, winregistry

    json_path = _backup_json(run_dir, item)
    try:
        shown = regbackup.restore_entry(
            json_path, winregistry.get_backend(),
            is_admin=bool(allow_machine_restore) and winenv.is_admin(),
            require_owner=True,
        )
    except regbackup.RestoreRefused as exc:
        if winenv.is_admin() and not allow_machine_restore:
            return False, (
                "not restored: machine-wide (HKLM) entries need explicit "
                "confirmation; review exactly what will be written and confirm "
                f"the restore of run {run_id}"
            )
        return False, exc.message_for(run_id)
    except Exception as exc:  # noqa: BLE001 - one entry never aborts the rest
        return False, str(exc) or type(exc).__name__
    return True, shown


MACHINE_WARNING = (
    "These values will be WRITTEN machine-wide. The backup files may have been "
    "written by any program running as your user."
)
USER_WARNING = (
    "These values will be WRITTEN for your account. The backup files may have "
    "been written by any program running as your user."
)


def describe_registry_entries(run_id: str) -> List[str]:
    """Human-readable lines naming exactly what restoring ``run_id`` would
    write to the registry: a warning line first, then for each entry restore
    would touch every key and every value with its type and data (names and
    data escaped, long data truncated; see ``regbackup.describe_backup``),
    read from the validated backup, never from the manifest. An entry whose
    backup does not validate is listed as such (restore would refuse it).
    Callers show this before passing ``allow_machine_restore=True`` to
    :func:`restore`."""
    from cleanix.core import regbackup

    from cleanix.core.models import _visible

    data = _read_manifest(quarantine_root() / run_id)
    if not data:
        raise FileNotFoundError(f"no quarantine run '{run_id}'")
    lines: List[str] = []
    machine = False
    for item in _items_of(data):
        if not isinstance(item, dict) or item.get("type") != "registry":
            continue
        if item.get("deleted") is False:
            continue  # restore never touches it
        machine = machine or item.get("hive") == "HKLM"
        try:
            lines.extend(regbackup.describe_backup(_backup_json(quarantine_root() / run_id, item)))
        except regbackup.RestoreError as exc:
            lines.append(f"{_visible(str(item.get('original', '?')))}: {_visible(str(exc))}")
    if lines:
        lines.insert(0, MACHINE_WARNING if machine else USER_WARNING)
    return lines


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
