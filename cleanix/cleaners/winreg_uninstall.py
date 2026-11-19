"""Registry: dead uninstall entries (detector stub; the evidence rules arrive in a later task)."""

from __future__ import annotations

from typing import Iterable

from cleanix.cleaners.winreg_base import Finding, RegistryDetector
from cleanix.core.regsafety import Container
from cleanix.core.regtargets import DetectorContext
from cleanix.core.winregistry import RegistryBackend


class WinRegUninstall(RegistryDetector):
    id = "win_reg_uninstall"
    name = "Registry: dead uninstall entries"
    description = "Apps & Features entries whose program folder and uninstaller are gone (opt-in)"

    def context(self):  # stub: no evidence context is needed yet
        return None

    def entries(
        self, container: Container, backend: RegistryBackend, ctx: DetectorContext
    ) -> Iterable[Finding]:
        return ()
