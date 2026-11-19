"""Single switch for registry backup/undo wording in the UIs.

Registry entries are only described as "backed up" and "restorable" once the
backup, restore and delete paths ship and have been verified. The integration
task flips ``UNDO_SHIPPED`` after that check; until then the UIs say that
registry removal is permanent.
"""

UNDO_SHIPPED = False

PERMANENT_LINE = ("Registry entries are removed permanently: no backup or "
                  "restore is available in this version.")


def registry_undo_shipped() -> bool:
    return UNDO_SHIPPED
