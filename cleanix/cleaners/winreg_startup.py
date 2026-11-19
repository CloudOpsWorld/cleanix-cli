"""Registry: dead startup entries.

Each value directly inside a Run or RunOnce container is a command line. It
is reported only when the program it starts is provably MISSING. Everything
uncertain (host executables, unexpanded variables, network or Microsoft
locations, non-string values) is kept. Only reads; the item is the VALUE,
never the key. ``StartupApproved`` (the disabled-entry store) is a separate
key and is never read.
"""

from __future__ import annotations

from typing import Iterable

from cleanix.cleaners.winreg_base import Finding, RegistryDetector
from cleanix.core import regbackup, regsnap
from cleanix.core.models import RegTarget
from cleanix.core.regsafety import Container
from cleanix.core.regtargets import DetectorContext, Existence, target_state
from cleanix.core.winregistry import (
    REG_EXPAND_SZ,
    REG_SZ,
    RegistryBackend,
    RegistryError,
)

_MAX_COMMAND = 1024  # longer command lines are not judged
_MAX_SHOWN = 200


def _shown(text: str) -> str:
    text = text.replace("\r", " ").replace("\n", " ")
    return text if len(text) <= _MAX_SHOWN else text[: _MAX_SHOWN - 3] + "..."


class WinRegStartup(RegistryDetector):
    id = "win_reg_startup"
    name = "Registry: dead startup entries"
    description = "Run and RunOnce entries for programs that no longer exist (opt-in)"

    def entries(
        self, container: Container, backend: RegistryBackend, ctx: DetectorContext
    ) -> Iterable[Finding]:
        try:
            values = regsnap.read_values(backend, container.hive, container.key)
        except RegistryError:
            return
        machine = container.hive == "HKLM"
        for value in values.values():
            if not value.name or value.type not in (REG_SZ, REG_EXPAND_SZ):
                continue
            command = value.data
            if not isinstance(command, str) or not command.strip():
                continue
            if len(command) > _MAX_COMMAND or "\x00" in command:
                continue
            state = target_state(command, command=True, ctx=ctx, machine=machine)
            if state is not Existence.MISSING:
                continue
            target = RegTarget(container.hive, container.key, value.name)
            try:
                snap = regsnap.snapshot(backend, target)
            except (regsnap.SnapshotError, RegistryError):
                continue
            if regbackup.backup_problem(self.id, target, snap) is not None:
                continue
            yield Finding(
                target,
                f"Startup entry: {value.name}",
                f"Command {_shown(command)}: missing",
            )
