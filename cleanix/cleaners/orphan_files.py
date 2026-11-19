"""Report files and folders that no installed package owns (Linux, read-only).

Scans only ``/opt``, ``/usr/local``, ``/var/lib`` and ``/var/cache`` at fixed,
shallow depths. Nothing is ever deleted: every result is a report-only item
whose hint names the exact path and the package-manager command to confirm
ownership first.
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Iterable, Optional

from cleanix.cleaners import orphan_common as oc
from cleanix.cleaners.base import SCOPE_SYSTEM
from cleanix.cleaners.linux_extras import _LEFTOVER_SUFFIXES
from cleanix.cleaners.orphan_common import Finding, OrphanReporter
from cleanix.core.platform import LINUX

_USR_LOCAL_STD = frozenset(
    "bin sbin lib lib64 libexec include etc games src share man".split()
)
_SHARE_SKELETON = frozenset(
    "man info doc applications icons fonts ca-certificates pixmaps mime "
    "locale xml sgml emacs texmf".split()
)
_SKIP = {
    "/var/lib": frozenset(
        "dpkg apt rpm dnf yum pacman apk systemd private flatpak snapd docker "
        "containerd containers lxd lxc libvirt machines portables ucf polkit-1 "
        "sudo dbus misc pam initramfs-tools os-prober update-rc.d alternatives "
        "dhcp NetworkManager AccountsService PackageKit logrotate man-db "
        "plymouth sss nfs ubuntu-advantage cloud".split()
    ),
    "/var/cache": frozenset(
        "apt dnf yum pacman man fontconfig ldconfig debconf PackageKit cups "
        "fwupd app-info abrt-di private snapd flatpak cracklib apparmor "
        "swcatalog".split()
    ),
}
# Roots whose entries need a second signal (no package/account/unit name match).
_NEEDS_NAMES = ("/var/lib", "/var/cache")
_ROOTS = ("/opt", "/usr/local", "/var/lib", "/var/cache")
_UNIT_DIRS = ("/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system")


class UnownedSystemFilesReporter(OrphanReporter):
    id = "orphan_files"
    name = "Files not from any package"
    description = (
        "Items under /opt, /usr/local, /var/lib and /var/cache that no "
        "installed package owns (report only)"
    )
    platforms = (LINUX,)
    scope = SCOPE_SYSTEM
    default_enabled = False

    def available(self) -> Optional[str]:
        if self.pkg_backend() is None:
            return "package ownership lookup is not supported on this distribution"
        return None

    # ----------------------------------------------------------- helpers
    def _unit_names(self) -> set:
        names: set = set()
        for d in _UNIT_DIRS:
            for p in oc.list_dir(oc.in_root(self.sysroot, d)) or []:
                names.add(p.name.rsplit(".", 1)[0])
        return names

    def _hint(self, backend: str, logical: str) -> str:
        check = oc.owner_check_command(backend, logical)
        text = (
            f"Nothing installed this through {backend}. Check first: {check}. "
        )
        if logical.startswith("/usr/local"):
            text += (
                "It was probably installed manually (make install, a script "
                "or pip). "
            )
        return text + (
            f"If you no longer need it, remove {shlex.quote(logical)} by hand "
            "(administrator rights needed)."
        )

    def _candidates(self, root: str, root_real: Path):
        """Yield (logical, real) candidates, or a Finding note if unreadable."""
        kids = oc.list_dir(root_real)
        if kids is None:
            yield self._unreadable(root, root_real)
            return
        if root != "/usr/local":
            for k in kids:
                yield from self._keep(root, root_real, k, _SKIP.get(root, ()))
            return
        for k in kids:
            if k.name not in _USR_LOCAL_STD:
                yield from self._keep(root, root_real, k, ())
                continue
            sub = oc.list_dir(k)
            if sub is None:
                yield self._unreadable(f"{root}/{k.name}", k)
                continue
            skip = _SHARE_SKELETON if k.name == "share" else ()
            for c in sub:
                yield from self._keep(root, root_real, c, skip)

    def _unreadable(self, logical: str, real: Path) -> Finding:
        return self.note(
            real,
            f"Not checked: {logical} needs administrator rights to list",
            "Run the scan as administrator to include it.",
        )

    def _keep(self, root, root_real, child: Path, skip):
        name = child.name
        if name in skip or oc.bad_name(name) or name.endswith(_LEFTOVER_SUFFIXES):
            return
        yield (oc.logical_path(self.sysroot, child), child, root, root_real)

    # ------------------------------------------------------------ scanning
    def system_findings(self) -> Iterable[Finding]:
        backend = self.pkg_backend()
        if backend is None:
            return
        loaded = False
        evidence: Optional[set] = None
        cands = []
        for root in _ROOTS:
            root_real = oc.in_root(self.sysroot, root)
            root_dev = oc.device_of(root_real)
            if root in _NEEDS_NAMES:
                if oc.list_dir(root_real) == []:
                    continue  # missing/empty root: nothing to check or to note
                if not loaded:
                    loaded = True
                    names = oc.installed_package_names(backend)
                    if names:
                        evidence = (
                            names
                            | oc.system_account_names(self.sysroot)
                            | self._unit_names()
                        )
                if evidence is None:
                    yield self.note(
                        root_real,
                        f"Not checked: {root} (the installed package list is unavailable)",
                        "Names under this folder can only be judged against the "
                        "installed packages, which could not be listed.",
                    )
                    continue
            for item in self._candidates(root, root_real):
                if isinstance(item, Finding):
                    yield item
                    continue
                logical, real, _r, _rr = item
                dev = oc.device_of(real)
                if dev is None or (root_dev is not None and dev != root_dev):
                    continue
                if root in _NEEDS_NAMES and oc.name_matches(real.name, evidence):
                    continue
                cands.append((logical, real))
        if not cands:
            return
        unowned = oc.query_unowned(
            backend, [lg for lg, _ in cands], self.budget
        )
        for logical, real in cands:
            if logical not in unowned:
                continue
            outside = logical.startswith("/usr/local/")
            label = (
                f"Installed outside the package manager: {logical}"
                if outside
                else f"Not from any package: {logical}"
            )
            is_link = os.path.islink(real)
            yield Finding(
                real, label, self._hint(backend, logical),
                requires_root=True, note=is_link,
            )
