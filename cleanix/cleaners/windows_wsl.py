"""WSL / Docker Desktop virtual-disk reporter (report only).

WSL2 distros keep their filesystem in an ``ext4.vhdx`` file that grows but
never shrinks on its own. We only *report* these files; compacting them is a
deliberate manual step and the disk is never deleted.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from cleanix.cleaners.base import Cleaner, SCOPE_USER
from cleanix.core import winenv
from cleanix.core.models import CleanableItem
from cleanix.core.platform import WINDOWS
from cleanix.core.utils import human_size, iter_children, path_size, walk_no_reparse

_HINT = (
    "WSL virtual disk: it grows but never shrinks by itself. Shut WSL down "
    "(wsl --shutdown) then reclaim space with "
    "`wsl --manage <distro> --set-sparse true`  (or Optimize-VHD). "
    "Never delete this file: it IS the distro's filesystem."
)


class WslDiskReporter(Cleaner):
    id = "wsl_disk"
    name = "WSL virtual disks"
    description = "ext4.vhdx disks of WSL distros and Docker Desktop (report only)"
    platforms = (WINDOWS,)
    scope = SCOPE_USER
    requires_root = False

    def _vhdx_files(self):
        local = winenv.local_appdata()
        for pkg in iter_children(local / "Packages"):
            state = pkg / "LocalState"
            if state.is_dir():
                yield state / "ext4.vhdx", pkg.name
        docker = local / "Docker" / "wsl"
        if docker.is_dir():
            for dirpath, _dirs, files in walk_no_reparse(docker):
                if "ext4.vhdx" in files:
                    yield Path(dirpath) / "ext4.vhdx", "Docker Desktop"

    def find_items(self) -> Iterable[CleanableItem]:
        for vhdx, owner in self._vhdx_files():
            if not vhdx.is_file():
                continue
            size = path_size(vhdx)
            if size <= 0:
                continue
            item = self.report_item(
                vhdx, f"WSL disk ({owner}): {human_size(size)}", hint=_HINT
            )
            if item:
                yield item
