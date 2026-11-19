"""Registry: SharedDLLs counts for files that no longer exist.

Each value under ``SharedDLLs`` is named after a file (a plain drive-absolute
path, not a command) and holds a REG_DWORD install count. A counter is dead
only when the file is provably MISSING; any ambiguity is unknown, and unknown
is not dead. The item is the value, never the key. Read-only: the container
is read once through ``read_values`` (never snapshotted as one tree) and each
finding carries its already-read value, so no finding re-reads the container.

Work is bounded (MAX_CHECKED, MAX_FINDINGS, MAX_SECONDS of the detector's own
time, not time spent suspended at a yield). Hitting a bound is never silent:
the detector calls ``note_incomplete`` and the base reports it as
``CleanerReport.incomplete`` next to the findings already produced. It is a
report note, never an item, so nothing deletable comes from it.
"""

from __future__ import annotations

import re
import time
from typing import Iterable

from cleanix.cleaners.winreg_base import Finding, RegistryDetector
from cleanix.core import regbackup, regsnap
from cleanix.core.models import RegTarget
from cleanix.core.regsafety import Container
from cleanix.core.regtargets import DetectorContext, Existence, target_state, under
from cleanix.core.winregistry import REG_DWORD, RegistryBackend, RegistryError, RegValue

MAX_CHECKED = 20000
MAX_FINDINGS = 2000
MAX_SECONDS = 30.0
_clock = time.monotonic

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
        spent = 0.0  # own work only: time suspended at a yield is not counted
        mark = _clock()
        checked = found = 0
        for _fold, v in sorted(values.items()):
            if not self._candidate(v, ctx):
                continue
            spent += _clock() - mark
            mark = _clock()
            if checked >= MAX_CHECKED:
                self.note_incomplete(f"more than {MAX_CHECKED} counters; the rest were not checked")
                return
            if found >= MAX_FINDINGS:
                self.note_incomplete(f"more than {MAX_FINDINGS} dead counters; the rest were not listed")
                return
            if spent > MAX_SECONDS:
                self.note_incomplete("time limit reached; the rest were not checked")
                return
            name = v.name
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
            value = RegValue(name, v.type, v.data)
            target = RegTarget(container.hive, container.key, name)
            if regbackup.backup_problem(self.id, target, value):
                continue
            found += 1
            finding = Finding(
                target=target,
                description=f"Shared file counter: {name}",
                evidence=f"{name}: missing (count {v.data})",
                value=value,
            )
            spent += _clock() - mark
            yield finding
            mark = _clock()

    @staticmethod
    def _candidate(v: RegValue, ctx: DetectorContext) -> bool:
        if v.type != REG_DWORD or not isinstance(v.data, int):
            return False
        name = v.name
        if not _DRIVE_ABS.match(name) or _REFUSED.search(name):
            return False
        # Windows-owned files (System32, SysWOW64, ...) are never judged.
        if ctx.system_root and under(name, ctx.system_root):
            return False
        return True
