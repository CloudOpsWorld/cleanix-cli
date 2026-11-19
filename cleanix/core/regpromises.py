"""Single switch for registry backup/undo wording and behaviour.

Registry entries are only described as "restorable" (and the registry restore
write path only runs) once the backup, restore and delete paths have been
verified on real Windows (docs/registry-cleanup-verification.md). Until then
``UNDO_SHIPPED`` stays False: the backups are still written, but every UI says
restoring registry entries is not supported yet and ``quarantine.restore``
refuses to run the registry write path.
"""

from __future__ import annotations

from typing import Optional

UNDO_SHIPPED = False

PERMANENT_LINE = (
    "A backup of each removed registry entry is written to the quarantine "
    "folder, but restoring registry entries is not supported in this version "
    "yet; to restore one manually, inspect the .reg file and import it with "
    'reg import "<file>" /reg:64.'
)


def registry_undo_shipped() -> bool:
    return UNDO_SHIPPED


def restore_disabled_text(where) -> str:
    """Why a registry entry was not restored while the switch is off."""
    return ("not restored: registry restore is not enabled in this version "
            f"(backup files are in {where})")


def backup_files_note(where) -> str:
    return f"the backup files are in {where}"


def restore_hint(run: Optional[str], hive: str = "HKCU", where=None) -> str:
    """The restore instruction that may truthfully follow a registry message,
    or ``""`` while the switch is off. HKCU: ``cleanix restore <run>``. HKLM
    (and any helper run): only an Administrator terminal running as the SAME
    account, after inspecting every .reg file, with ``reg import ... /reg:64``;
    never ``cleanix restore <run>`` from this process."""
    if not registry_undo_shipped() or not run:
        return ""
    if hive == "HKLM":
        folder = f"{where}\registry" if where else "<run folder>\registry"
        return (
            "restoring machine-wide entries needs an Administrator terminal "
            "(the same account that made the backup): inspect every .reg file, "
            'then reg import "' + folder + '\\<file>.reg" /reg:64'
        )
    return f"restore with cleanix restore {run}"
