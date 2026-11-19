"""Deleting one registry target, after its backup, with every check re-run.

Data safety dominates. :func:`delete_target` is the only code that deletes
registry keys or values, and it is called only after a backup sink has
written and verified the entry's backup (or, in the elevated helper, after
the GUI did so as the user: :class:`VerifyOnlySink`).

Order of :func:`delete_target`:

1. HKLM needs an elevated process (:class:`AdminRequired`), never a silent
   skip. HKCU is the hive of the running account (ruling R15).
2. ``regsafety.check_target`` with the backend (allowlist, deny rules and no
   registry link on the path) - :class:`RegistryBlocked`.
3. Re-snapshot; the fingerprint must equal the scanned one, otherwise
   :class:`RegistryChanged`.
4. Preflight ``can_delete`` on every key of the tree (or on the value); a
   refusal raises :class:`~cleanix.core.winregistry.AccessDenied` before
   anything is written.
5. Delete bottom-up, leaf keys only, by the exact names of the snapshot;
   a value by its exact name. Immediately before EACH delete call the path
   is re-checked (``check_target`` and no link between the target and the
   leaf) and the leaf is re-snapshotted and compared with its part of the
   scanned snapshot (ruling R17: this is as close to the delete as a caller
   can get).
6. Verify the target is gone.

Exceptions tell the caller whether anything may have been deleted:

* nothing was deleted: :class:`RegistryChanged`, :class:`RegistryBlocked`,
  :class:`AccessDenied` (incl. :class:`AdminRequired`), :class:`NotRemoved`;
* something may have been deleted, or the state is unknown:
  :class:`PartialDelete` ("partially deleted: ..."), whose message advises
  to scan again. Restore is an additive merge, so the backup completes it.

Residual (R17, documented and accepted): ``WinRegBackend.delete_key`` checks
link-ness and leaf-ness on a handle and then ``DeleteKeyEx`` resolves the
path again. A link swapped in inside that window cannot be seen by any
caller; if ``RegDeleteKeyEx`` follows a final-component link, the link
TARGET leaf is deleted. The post-delete check (step 6) then still finds the
entry, so the outcome is a :class:`PartialDelete` error, never a success.
Values are not affected: ``delete_value`` checks and deletes through one
handle.

Other residuals of having no transactional API (R17, accepted):

* Values or subkeys written to a leaf key AFTER its pre-delete re-snapshot
  and before ``delete_key`` are deleted with it (a subkey makes the backend
  refuse the non-leaf key instead). They are not in the backup, and the
  outcome is a success.
* An ancestor key replaced by a registry link needs write access to that
  container's parent (the same user for HKCU, an administrator for HKLM).
  That is the accepted threat model: such a writer can already change the
  entry directly.

What is detected, immediately before every delete call: the entry changed
(any name, type or data in the remaining part of the tree), a key turned
into a link anywhere from ``SOFTWARE\\<next>`` down to the leaf, the entry
or an ancestor gone, and every safety rule. What is not: changes inside the
few instructions between that check and the backend call, and inside the
backend between its own handle check and ``DeleteKeyEx``.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from typing import List, Mapping, Optional, Protocol, Tuple

from cleanix.core import regsafety, regsnap, winenv
from cleanix.core.models import CleanableItem, RegTarget
from cleanix.core.regsnap import KeySnap, SnapshotError
from cleanix.core.winregistry import (
    AccessDenied,
    RegistryBackend,
    RegistryError,
    RegValue,
)

ADMIN_REQUIRED = (
    "needs administrator: machine-wide (HKLM) registry entries are removed "
    "only from an elevated (Administrator) process; nothing was deleted"
)
CHANGED = "changed since the scan; scan again"


class RegistryChanged(Exception):
    """The entry differs from the scanned one (or is gone, or became a
    link). Nothing was deleted by the call that raised it."""


class RegistryBlocked(RegistryError):
    """The registry safety rules refuse the target. Nothing was deleted."""


class AdminRequired(AccessDenied):
    """An HKLM target in a process that is not elevated. Nothing was deleted."""


class NotRemoved(RegistryError):
    """The delete failed and the entry is verifiably intact."""


class PartialDelete(RegistryError):
    """Something may have been deleted, or the state is unknown."""


class RegistryBackupSink(Protocol):
    """Writes (and verifies) the backup before a registry delete."""

    def before_delete(self, item: CleanableItem, backend) -> None:
        """Back up ``item``; raise to veto the delete."""

    def after_delete(self, item: CleanableItem, deleted: bool) -> None:
        """Record the result. ``deleted`` is False only when nothing was
        deleted; True when something was (or may have been)."""


BACKUP_REQUIRED = "backup is required for this entry"


@dataclass(frozen=True)
class VerifiedBackup:
    """A registry backup already read and fully verified (format, safety
    rules, digest): who it is for, exactly which target, and the
    fingerprint of the backed-up snapshot."""

    cleaner_id: str
    target: RegTarget
    fingerprint: str
MAX_BACKUP_FILES = 10_000
_RUN_ID = re.compile(r"\A[0-9A-Za-z][0-9A-Za-z._-]{0,127}\Z")
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class VerifyOnlySink:
    """Sink for the elevated helper: the GUI already wrote the backup as the
    user into a quarantine run (ruling R6), and the helper writes nothing.

    It is bound to ONE quarantine run of the invoking account, named by its
    run id (``VerifyOnlySink("20261119-...")``); a path is accepted only when
    it is exactly a run directory directly under ``quarantine_root()``.
    ``before_delete`` vetoes (raises ``regbackup.BackupError``) unless

    * the item is an HKLM entry (HKCU entries are never cleaned by the
      helper, and never without a backup the user can restore);
    * the run id is a plain name (no separators, traversal, drive or NUL)
      and the run directory is a real directory (not a link or junction)
      directly under the quarantine root;
    * the run's manifest has a registry entry for exactly this cleaner,
      hive, key and value that Undo would restore (``deleted`` is not
      False), and
    * that entry's backup JSON (read from the run's own ``registry``
      directory) passes the full restore validation and is for exactly
      this cleaner, target and fingerprint.

    So whatever the helper deletes is restorable by ``cleanix restore
    <run>``; a loose or orphaned backup file never counts.
    """

    def __init__(self, run, root=None) -> None:
        self._run = run
        self._root = root
        self._preloaded: Optional[Mapping[str, "VerifiedBackup"]] = None
        self.run_id: Optional[str] = None
        if isinstance(run, str) and _RUN_ID.match(run):
            self.run_id = run
        elif isinstance(run, os.PathLike):
            name = os.fspath(run)
            base = os.path.basename(os.path.normpath(name)) if name else ""
            self.run_id = base if _RUN_ID.match(base or "-") else None

    def _root_dir(self) -> str:
        from cleanix.core import quarantine

        return os.fspath(self._root if self._root is not None else quarantine.quarantine_root())

    def _run_dir(self):
        """The validated run directory, or raise ``BackupError``."""
        from pathlib import Path

        from cleanix.core import regbackup

        def refuse(why: str):
            return regbackup.BackupError(f"{BACKUP_REQUIRED}: {why}")

        if self._run is None:
            raise refuse("no backup run was given")
        if self.run_id is None or self.run_id in (".", ".."):
            raise refuse("not a valid quarantine run id")
        root = self._root_dir()
        real_root = os.path.realpath(root)
        if isinstance(self._run, os.PathLike):
            # A path must resolve to a run directly under the root.
            if os.path.dirname(os.path.realpath(os.fspath(self._run))) != real_root:
                raise refuse("the backup is not a run of this account's quarantine")
        run_dir = os.path.join(root, self.run_id)
        try:
            st = os.lstat(run_dir)
        except OSError as exc:
            raise refuse(f"no quarantine run '{self.run_id}'") from exc
        if (
            stat.S_ISLNK(st.st_mode)
            or not stat.S_ISDIR(st.st_mode)
            or getattr(st, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise refuse("the quarantine run is a link or not a directory")
        if os.path.dirname(os.path.realpath(run_dir)) != real_root:
            raise refuse("the backup is not a run of this account's quarantine")
        return Path(run_dir)

    @classmethod
    def from_preloaded(
        cls, run_id: str, entries: Mapping[str, "VerifiedBackup"]
    ) -> "VerifyOnlySink":
        """A sink that never touches the filesystem: ``entries`` maps an
        item key (``models.item_key``) to the backup the caller already
        read and fully verified (the elevated helper does every read of
        the run once, at validation time). An item without an entry, or
        whose entry does not match exactly, is refused."""
        sink = cls(run_id)
        sink._preloaded = dict(entries)
        return sink

    @property
    def backup_dir(self):
        if self._preloaded is not None:
            return None  # never resolved again by path
        try:
            return self._run_dir()
        except Exception:  # noqa: BLE001
            return None

    def before_delete(self, item: CleanableItem, backend) -> None:
        from cleanix.core import quarantine, regbackup
        from cleanix.core.models import item_key

        reg = item.reg
        if reg is None or reg.hive != "HKLM":
            raise regbackup.BackupError(BACKUP_REQUIRED)
        if self._preloaded is not None:
            if self.run_id is None:
                raise regbackup.BackupError(f"{BACKUP_REQUIRED}: not a valid quarantine run id")
            b = self._preloaded.get(item_key(item))
            if (
                b is not None
                and b.cleaner_id == item.cleaner_id
                and b.target == reg
                and b.fingerprint == reg.fingerprint
            ):
                return None
            raise regbackup.BackupError(
                f"{BACKUP_REQUIRED}: quarantine run '{self.run_id}' holds no restorable, "
                "verified backup of it"
            )
        run_dir = self._run_dir()
        data = quarantine._read_manifest(run_dir)
        if not data:
            raise regbackup.BackupError(
                f"{BACKUP_REQUIRED}: quarantine run '{self.run_id}' has no readable manifest"
            )
        for entry in quarantine._items_of(data)[:MAX_BACKUP_FILES]:
            if not (
                isinstance(entry, dict)
                and entry.get("type") == "registry"
                and entry.get("deleted") is not False
                and entry.get("cleaner_id") == item.cleaner_id
                and entry.get("hive") == reg.hive
                and entry.get("key") == reg.key
                and entry.get("value") == reg.value
            ):
                continue
            try:
                cid, target, snap = regbackup.load_verified(
                    quarantine._backup_json(run_dir, entry)
                )
            except regbackup.RestoreError:
                continue
            if (
                cid == item.cleaner_id
                and target == reg
                and regsnap.fingerprint(target, snap) == reg.fingerprint
            ):
                return None
        raise regbackup.BackupError(
            f"{BACKUP_REQUIRED}: quarantine run '{self.run_id}' holds no restorable, "
            "verified backup of it"
        )

    def after_delete(self, item: CleanableItem, deleted: bool) -> None:
        return None


def check_live(backend: RegistryBackend, cleaner_id: str, target: RegTarget) -> None:
    """``check_target`` with the backend. A refusal because the entry (or a
    key above it) is gone is :class:`RegistryChanged`; any other refusal is
    :class:`RegistryBlocked`."""
    reason = regsafety.check_target(cleaner_id, target, backend)
    if reason is None:
        return
    try:
        exists = backend.key_exists(target.hive, target.key)
    except RegistryError as exc:
        raise RegistryChanged(f"could not verify the entry: {exc}") from exc
    if not exists:
        raise RegistryChanged("the entry is gone")
    raise RegistryBlocked(f"blocked by registry safety rules: {reason}")


# -- helpers ---------------------------------------------------------------------
def _key_ops(path: str, snap: KeySnap, out: List[Tuple[str, KeySnap]]) -> None:
    """Post-order (bottom-up) list of ``(path, keysnap)`` using the exact
    names from the snapshot."""
    for sub in snap.subkeys:
        _key_ops(path + "\\" + sub.name, sub, out)
    out.append((path, snap))


def _check_path(
    backend: RegistryBackend, cleaner_id: str, target: RegTarget, path: str
) -> None:
    """Re-run the safety rules and refuse a link on any key from the target
    down to (but excluding) ``path``; the snapshot of ``path`` refuses a
    link at ``path`` itself."""
    reason = regsafety.check_target(cleaner_id, target, backend)
    if reason is not None:
        raise RegistryChanged(reason)
    base = target.key.split("\\")
    parts = path.split("\\")
    try:
        for depth in range(len(base) + 1, len(parts)):
            if backend.is_link(target.hive, "\\".join(parts[:depth])):
                raise RegistryChanged("registry link (symbolic link) in the tree")
    except RegistryError as exc:
        raise RegistryChanged(f"could not verify the entry: {exc}") from exc


def _verify_leaf(
    backend: RegistryBackend, cleaner_id: str, target: RegTarget, path: str, snap: KeySnap
) -> None:
    """Immediately before deleting ``path``: it is still exactly the scanned
    key, minus the subkeys already deleted (so it must have none)."""
    _check_path(backend, cleaner_id, target, path)
    probe = RegTarget(target.hive, path)
    try:
        now = regsnap.snapshot(backend, probe)
    except SnapshotError as exc:
        raise RegistryChanged(str(exc)) from exc
    expected = KeySnap(name=snap.name, values=snap.values, subkeys=())
    if regsnap.fingerprint(probe, now) != regsnap.fingerprint(probe, expected):
        raise RegistryChanged(f"{target.hive}\\{path} differs from the scan")


def _verify_value(
    backend: RegistryBackend, cleaner_id: str, target: RegTarget
) -> RegValue:
    _check_path(backend, cleaner_id, target, target.key)
    try:
        now = regsnap.snapshot(backend, target)
    except SnapshotError as exc:
        raise RegistryChanged(str(exc)) from exc
    if not isinstance(now, RegValue) or regsnap.fingerprint(target, now) != target.fingerprint:
        raise RegistryChanged("the value differs from the scan")
    return now


def _intact(backend: RegistryBackend, target: RegTarget) -> bool:
    try:
        now = regsnap.snapshot(backend, target)
    except (SnapshotError, RegistryError):
        return False
    return regsnap.fingerprint(target, now) == target.fingerprint


def _still_present(backend: RegistryBackend, target: RegTarget, name: Optional[str]) -> bool:
    if not backend.key_exists(target.hive, target.key):
        return False
    if name is None:
        return True
    return name.casefold() in regsnap.read_values(backend, target.hive, target.key)


# -- the delete --------------------------------------------------------------------
def delete_target(
    backend: RegistryBackend,
    cleaner_id: str,
    target: RegTarget,
    *,
    is_admin: Optional[bool] = None,
) -> None:
    """Delete exactly the scanned ``target`` or raise (see the module doc).

    ``is_admin`` defaults to :func:`winenv.is_admin` (tests pass it)."""
    hive = target.hive
    if hive == "HKLM":
        admin = winenv.is_admin() if is_admin is None else is_admin
        if not admin:
            raise AdminRequired(ADMIN_REQUIRED)

    # 1. the safety rules, with the backend (links on the path)
    check_live(backend, cleaner_id, target)

    # 2. the entry is still exactly the scanned one
    try:
        snap = regsnap.snapshot(backend, target)
    except SnapshotError as exc:
        raise RegistryChanged(str(exc)) from exc
    if regsnap.fingerprint(target, snap) != target.fingerprint:
        raise RegistryChanged("the entry differs from the scan")

    # 3. preflight: every delete is permitted before anything is written
    ops: List[Tuple[str, KeySnap]] = []
    value_name: Optional[str] = None
    try:
        if isinstance(snap, RegValue):
            value_name = snap.name
            if not backend.can_delete(hive, target.key, value_name):
                raise AccessDenied(
                    f"access denied: {target.display}; nothing was deleted"
                )
        else:
            _key_ops(target.key, snap, ops)
            for path, _ks in ops:
                if not backend.can_delete(hive, path, None):
                    raise AccessDenied(
                        f"access denied: {hive}\\{path}; nothing was deleted"
                    )
    except AccessDenied:
        raise
    except RegistryError as exc:
        raise NotRemoved(f"not removed: {exc}; nothing was deleted") from exc

    # 4. delete bottom-up, re-verifying immediately before each call
    attempted = False
    try:
        if value_name is not None:
            exact = _verify_value(backend, cleaner_id, target)
            attempted = True
            backend.delete_value(hive, target.key, exact.name)
        else:
            for path, ks in ops:
                _verify_leaf(backend, cleaner_id, target, path, ks)
                attempted = True
                backend.delete_key(hive, path)
    except Exception as exc:  # noqa: BLE001 - classified below, never swallowed
        if not attempted:
            raise  # RegistryChanged before the first write: nothing deleted
        if _intact(backend, target):
            raise NotRemoved(
                f"not removed: {str(exc) or type(exc).__name__}; nothing was deleted"
            ) from exc
        raise PartialDelete(
            f"partially deleted: {str(exc) or type(exc).__name__}; scan again"
        ) from exc

    # 5. verify it is gone
    try:
        present = _still_present(backend, target, value_name)
    except Exception as exc:  # noqa: BLE001
        raise PartialDelete(
            f"partially deleted or state unknown: could not verify the removal "
            f"({str(exc) or type(exc).__name__}); scan again"
        ) from exc
    if present:
        raise PartialDelete(
            "partially deleted: the entry is still present after removal "
            "(state unknown); scan again"
        )
