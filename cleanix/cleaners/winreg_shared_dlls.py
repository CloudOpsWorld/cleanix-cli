"""Registry: SharedDLLs counts for files that no longer exist.

Each value under ``SharedDLLs`` is named after a file (a plain drive-absolute
path, not a command) and holds a REG_DWORD install count. A counter is dead
only when the file is provably MISSING; any ambiguity is unknown, and unknown
is not dead. The item is the value, never the key. Read-only: the container
is read once through ``read_values`` (never snapshotted as one tree).
"""

from __future__ import annotations

import re
import time
from typing import Iterable

from cleanix.cleaners.winreg_base import Finding, RegistryDetector
from cleanix.core import regbackup, regsnap
from cleanix.core.models import RegTarget
from cleanix.core.regsafety import Container
from cleanix.core.regtargets import DetectorContext, Existence, _under, target_state
from cleanix.core.winregistry import REG_DWORD, RegistryBackend, RegistryError, RegValue

# Work bounds for a huge container. The base re-reads the container once per
# finding when it snapshots a value, so findings are capped much lower.
MAX_CHECKED = 5000
MAX_FINDINGS = 500
MAX_SECONDS = 30.0

_DRIVE_ABS = re.compile(r"^[A-Za-z]:\\")
_REFUSED = re.compile(r'["%/\x00-\x1f]')


class WinRegSharedDlls(RegistryDetector):
    id = "win_reg_shared_dlls"
    name = "Registry: SharedDLLs counts for missing files"
    description = "SharedDLLs counters for files that no longer exist (opt-in)"

    def entries(
        self, container: Container, backend: RegistryBackend, ctx: DetectorContext
    ) -> Iterable[Finding]:
        try:
            if not backend.key_exists(container.hive, container.key):
                return
            values = regsnap.read_values(backend, container.hive, container.key)
        except RegistryError:
            return
        deadline = time.monotonic() + MAX_SECONDS
        checked = found = 0
        for _fold, v in sorted(values.items()):
            if checked >= MAX_CHECKED or found >= MAX_FINDINGS:
                return
            if time.monotonic() > deadline:
                return
            name = v.name
            if not self._candidate(v, ctx):
                continue
            checked += 1
            try:
                # machine=True: SharedDLLs is HKLM only, so per-user variables
                # and profile paths are never judged. owner_matches is carried
                # by ctx and only ever makes this stricter.
                state = target_state(name, command=False, ctx=ctx, machine=True)
            except Exception:
                continue
            if state is not Existence.MISSING:
                continue
            target = RegTarget(container.hive, container.key, name)
            if regbackup.backup_problem(self.id, target, RegValue(name, v.type, v.data)):
                continue
            found += 1
            yield Finding(
                target=target,
                description=f"Shared file counter: {name}",
                evidence=f"{name}: missing (count {v.data})",
            )

    @staticmethod
    def _candidate(v: RegValue, ctx: DetectorContext) -> bool:
        if v.type != REG_DWORD or isinstance(v.data, bool) or not isinstance(v.data, int):
            return False
        name = v.name
        if not _DRIVE_ABS.match(name) or _REFUSED.search(name):
            return False
        # Windows-owned files (System32, SysWOW64, ...) are never judged.
        if ctx.system_root and _under(name, ctx.system_root):
            return False
        return True
