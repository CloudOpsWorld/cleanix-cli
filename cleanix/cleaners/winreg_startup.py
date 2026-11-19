"""Registry: dead startup entries (detector stub; the evidence rules arrive in a later task)."""

from __future__ import annotations

from typing import Iterable

from cleanix.cleaners.winreg_base import Finding, RegistryDetector
from cleanix.core.regsafety import Container
from cleanix.core.regtargets import DetectorContext
from cleanix.core.winregistry import RegistryBackend


class WinRegStartup(RegistryDetector):
    id = "win_reg_startup"
    name = "Registry: dead startup entries"
    description = "Run and RunOnce entries for programs that no longer exist (opt-in)"

    def context(self):  # stub: no evidence context is needed yet
        return None

    def entries(
        self, container: Container, backend: RegistryBackend, ctx: DetectorContext
    ) -> Iterable[Finding]:
        return ()
