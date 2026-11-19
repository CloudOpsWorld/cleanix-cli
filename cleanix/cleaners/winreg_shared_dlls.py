"""Registry: SharedDLLs counts for missing files (detector stub; the evidence rules arrive in a later task)."""

from __future__ import annotations

from typing import Iterable

from cleanix.cleaners.winreg_base import Finding, RegistryDetector
from cleanix.core.regsafety import Container
from cleanix.core.regtargets import DetectorContext
from cleanix.core.winregistry import RegistryBackend


class WinRegSharedDlls(RegistryDetector):
    id = "win_reg_shared_dlls"
    name = "Registry: SharedDLLs counts for missing files"
    description = "SharedDLLs counters for files that no longer exist (opt-in)"

    def entries(
        self, container: Container, backend: RegistryBackend, ctx: DetectorContext
    ) -> Iterable[Finding]:
        return ()
