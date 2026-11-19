"""Registry: dead uninstall entries.

An Apps & Features entry is reported only when it is provably dead: no
subkeys, none of the R12 exclusions, an ``InstallLocation`` and an
``UninstallString`` that are both present and MISSING on disk, and every
other command or icon it names is absent or MISSING. Unknown is not dead.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Iterable, List, Optional, Tuple

from cleanix.cleaners.winreg_base import Finding, RegistryDetector
from cleanix.core import regbackup, regsnap
from cleanix.core.models import RegTarget
from cleanix.core.regsafety import Container
from cleanix.core.regtargets import (
    DetectorContext,
    Existence,
    strip_icon_index,
    target_state,
)
from cleanix.core.winregistry import (
    REG_DWORD,
    REG_EXPAND_SZ,
    REG_SZ,
    RegistryBackend,
    RegistryError,
    RegValue,
)

_KB = re.compile(r"\bKB\d+", re.IGNORECASE)
_STRING_TYPES = (REG_SZ, REG_EXPAND_SZ)


def _scan_owner_matches() -> bool:
    """Whether HKCU belongs to the user whose environment variables we expand.

    Conservative: an elevated process (the helper, or a CLI run as another
    administrator account) may read a different account's HKCU than the one
    the environment describes, so per-user variables are then UNKNOWN."""
    from cleanix.core import context

    try:
        return not context.is_effective_root()
    except Exception:
        return False


def _text(values, name: str) -> Tuple[bool, Optional[str]]:
    """(present, string) where string is None when present but not a
    REG_SZ/REG_EXPAND_SZ value."""
    v: Optional[RegValue] = values.get(name.casefold())
    if v is None:
        return False, None
    if v.type in _STRING_TYPES and isinstance(v.data, str):
        return True, v.data
    return True, None


class WinRegUninstall(RegistryDetector):
    id = "win_reg_uninstall"
    name = "Registry: dead uninstall entries"
    description = "Apps & Features entries whose program folder and uninstaller are gone (opt-in)"

    def entries(
        self, container: Container, backend: RegistryBackend, ctx: DetectorContext
    ) -> Iterable[Finding]:
        ctx = dataclasses.replace(
            ctx, owner_matches=ctx.owner_matches and _scan_owner_matches()
        )
        try:
            names = backend.subkeys(container.hive, container.key)
        except RegistryError:
            return
        for name in names:
            finding = self._entry(container, backend, ctx, name)
            if finding is not None:
                yield finding

    def _entry(
        self,
        container: Container,
        backend: RegistryBackend,
        ctx: DetectorContext,
        name: str,
    ) -> Optional[Finding]:
        hive = container.hive
        machine = hive == "HKLM"
        key = f"{container.key}\\{name}"
        try:
            if backend.subkeys(hive, key):
                return None
            values = regsnap.read_values(backend, hive, key)
        except RegistryError:
            return None
        if _KB.search(name):
            return None
        # R12 exclusions.
        for flag in ("WindowsInstaller", "SystemComponent"):
            v = values.get(flag.casefold())
            if v is not None and not (v.type == REG_DWORD and v.data == 0):
                return None
        if "parentkeyname" in values or "releasetype" in values:
            return None
        _, display = _text(values, "DisplayName")
        if display is None or not display.strip() or _KB.search(display):
            return None
        present, publisher = _text(values, "Publisher")
        if present and (publisher is None or "microsoft" in publisher.casefold()):
            return None

        checks: List[str] = []

        def check(value_name: str, *, command: bool, icon: bool, required: bool) -> bool:
            present, raw = _text(values, value_name)
            if not present:
                return not required
            if raw is None or not raw.strip():
                return False
            subject = strip_icon_index(raw) if icon else raw
            state = target_state(subject, command=command, ctx=ctx, machine=machine)
            checks.append(f"{value_name} {subject}: {state.value}")
            return state is Existence.MISSING

        for value_name, command, icon, required in (
            ("InstallLocation", False, False, True),
            ("UninstallString", True, False, True),
            ("QuietUninstallString", True, False, False),
            ("ModifyPath", True, False, False),
            ("DisplayIcon", False, True, False),
        ):
            if not check(value_name, command=command, icon=icon, required=required):
                return None

        target = RegTarget(hive, key)
        try:
            snap = regsnap.snapshot(backend, target)
        except (regsnap.SnapshotError, RegistryError):
            return None
        if regbackup.backup_problem(self.id, target, snap) is not None:
            return None

        description = f"Uninstall entry: {display}"
        if publisher and publisher.strip():
            description += f" ({publisher})"
        return Finding(target, description, "; ".join(checks))
