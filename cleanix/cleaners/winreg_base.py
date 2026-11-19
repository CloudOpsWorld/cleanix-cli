"""Base class for the Windows registry detectors.

A detector yields :class:`Finding` objects for entries it can prove dead.
This base re-checks every finding against the safety rules, captures a
snapshot and fingerprint, and turns it into a REGISTRY item. Nothing here
deletes anything.
"""

from __future__ import annotations

import abc
import dataclasses
import sys
from dataclasses import dataclass
from typing import Iterable, Iterator, Optional

from cleanix.cleaners.base import SCOPE_SYSTEM, Cleaner
from cleanix.core import regsnap, winregistry
from cleanix.core.models import CleanableItem, ItemKind, RegTarget
from cleanix.core.platform import WINDOWS
from cleanix.core.regsafety import Container, check_target, containers_for
from cleanix.core.regtargets import DetectorContext, default_context
from cleanix.core.winregistry import RegistryBackend, RegistryError


@dataclass(frozen=True)
class Finding:
    target: RegTarget
    description: str
    evidence: str


class RegistryDetector(Cleaner):
    platforms = (WINDOWS,)
    scope = SCOPE_SYSTEM
    default_enabled = False
    safe_default = False
    requires_root = False

    def available(self) -> Optional[str]:
        if sys.platform != "win32" and winregistry.backend_override() is None:
            return "only available on Windows"
        return None

    def context(self) -> DetectorContext:
        return default_context()

    @abc.abstractmethod
    def entries(
        self, container: Container, backend: RegistryBackend, ctx: DetectorContext
    ) -> Iterable[Finding]:
        """Yield the provably dead entries found in ``container``."""

    def registry_item(self, finding: Finding, fingerprint: str) -> CleanableItem:
        t = finding.target
        return CleanableItem(
            cleaner_id=self.id,
            description=finding.description,
            size=0,
            kind=ItemKind.REGISTRY,
            requires_root=t.hive == "HKLM",
            hint=finding.evidence,
            reg=dataclasses.replace(t, fingerprint=fingerprint),
        )

    def find_items(self) -> Iterator[CleanableItem]:
        backend = winregistry.get_backend()
        ctx = self.context()
        for container in containers_for(self.id):
            for finding in self.entries(container, backend, ctx):
                if check_target(self.id, finding.target, backend) is not None:
                    continue
                try:
                    snap = regsnap.snapshot(backend, finding.target)
                except (regsnap.SnapshotError, RegistryError):
                    continue
                yield self.registry_item(
                    finding, regsnap.fingerprint(finding.target, snap)
                )
