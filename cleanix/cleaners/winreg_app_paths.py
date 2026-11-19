"""Registry: dead App Paths.

An entry ``...\\App Paths\\<name>.exe`` is listed only when its default value
(a REG_SZ or REG_EXPAND_SZ path or command) points at a file that is provably
missing (:func:`cleanix.core.regtargets.target_state`). The ``Path`` value is
a list of directories added to PATH and is deliberately not evidence. Unknown
is never dead: any other value type, a variable we cannot expand, a host
executable, a network or removable drive, a Microsoft-owned or App Execution
Alias location, or any read error leaves the entry alone.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Iterable

from cleanix.cleaners.winreg_base import Finding, RegistryDetector
from cleanix.core import regsnap
from cleanix.core.models import RegTarget
from cleanix.core.regbackup import backup_problem
from cleanix.core.regsafety import Container
from cleanix.core.regtargets import (
    DetectorContext,
    Existence,
    describe_target,
    target_state,
)
from cleanix.core.winregistry import REG_EXPAND_SZ, REG_SZ, RegistryBackend, RegistryError

_log = logging.getLogger(__name__)

# Values that mean the entry is not a plain "run this file" mapping.
_INDIRECT_VALUES = frozenset({"delegateexecute"})


def _scan_is_for_hive_owner() -> bool:
    """True when HKCU (and the environment used to expand variables) belong to
    the user being scanned. An elevated process may run as another account
    than the invoking user, and ``--all-users`` scans bind another user, so
    per-user variables are not trusted in those cases."""
    try:
        from cleanix.core import context

        if context.is_effective_root():
            return False
        user = context.current_user()
        return bool(user.is_invoker) and user == context.invoking_user()
    except Exception:
        return False


class WinRegAppPaths(RegistryDetector):
    id = "win_reg_app_paths"
    name = "Registry: dead App Paths"
    description = "App Paths entries that point at programs that no longer exist (opt-in)"

    def entries(
        self, container: Container, backend: RegistryBackend, ctx: DetectorContext
    ) -> Iterable[Finding]:
        try:
            names = backend.subkeys(container.hive, container.key)
        except RegistryError:
            return
        machine = container.hive == "HKLM"
        if not machine and ctx.owner_matches and not _scan_is_for_hive_owner():
            ctx = dataclasses.replace(ctx, owner_matches=False)
        for name in names:
            if not name.casefold().endswith(".exe"):
                continue
            key = container.key + "\\" + name
            try:
                if backend.subkeys(container.hive, key):
                    continue
                values = regsnap.read_values(backend, container.hive, key)
            except RegistryError:
                continue
            if _INDIRECT_VALUES & set(values):
                continue
            default = values.get("")
            if default is None or default.type not in (REG_SZ, REG_EXPAND_SZ):
                continue
            raw = default.data
            if not isinstance(raw, str) or not raw.strip():
                continue
            # The default value may carry arguments or quotes: judge it as a
            # command so that any candidate that exists keeps the entry.
            state = target_state(raw, command=True, ctx=ctx, machine=machine)
            if state is not Existence.MISSING:
                continue
            target = RegTarget(container.hive, key)
            try:
                snap = regsnap.snapshot(backend, target)
            except (regsnap.SnapshotError, RegistryError):
                continue
            if backup_problem(self.id, target, snap) is not None:
                continue
            yield Finding(
                target=target,
                description=f"App Paths: {name}",
                evidence="(Default) "
                + describe_target(raw, command=True, ctx=ctx, machine=machine),
            )
