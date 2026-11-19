"""Report files and folders that no installed package owns (Linux, read-only).

Scans only ``/opt``, ``/usr/local``, ``/var/lib`` and ``/var/cache`` at fixed,
shallow depths. Nothing is ever deleted: every result is a report-only item
whose hint names the exact path and the package-manager command to confirm
ownership first.
"""

from __future__ import annotations

import bisect
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
    "locale xml sgml emacs texmf zoneinfo".split()
)
# Debian/Ubuntu maintainer scripts create these under /usr/local/lib; dpkg
# does not own them, but they hold pip-installed system packages.
_PYTHON_DIR_NAMES = frozenset({"site_python", "dist-packages", "site-packages"})
_PYTHON_DIR_PREFIXES = ("python2", "python3")
_SKIP = {
    "/var/lib": frozenset(
        "dpkg apt rpm dnf yum pacman apk systemd private flatpak snapd docker "
        "containerd containers lxd lxc libvirt machines portables ucf polkit-1 "
        "sudo dbus misc pam initramfs-tools os-prober update-rc.d alternatives "
        "dhcp NetworkManager AccountsService PackageKit logrotate man-db "
        "plymouth sss nfs ubuntu-advantage cloud bluetooth boltd rpm-state "
        "shells.state swcatalog cups sddm gdm lightdm fwupd ModemManager "
        "upower geoclue power-profiles-daemon".split()
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
_PROBE_CHILDREN = 5
_GLOB = set("*?[]\\")
_CHECK_EVERY = 64


class NameEvidence:
    """Pre-normalised names: fast two-way prefix matching.

    ``matches(name)`` is true when the normalised name equals a known
    normalised name, or when the shorter of the two (at least 4 characters)
    is a prefix of the longer one.
    """

    def __init__(self, names: Iterable[str]):
        self._set = {n for n in (oc._norm(x) for x in names) if n}
        self._sorted = sorted(self._set)

    def matches(self, name: str) -> bool:
        n = oc._norm(name)
        if not n:
            return False
        if n in self._set:
            return True
        # a known name that is a proper prefix of ``n`` (>= 4 chars)
        for k in range(4, len(n)):
            if n[:k] in self._set:
                return True
        # ``n`` is a prefix of a known name
        if len(n) >= 4:
            i = bisect.bisect_left(self._sorted, n)
            if i < len(self._sorted) and self._sorted[i].startswith(n):
                return True
        return False


def _is_python_dir(name: str) -> bool:
    return name in _PYTHON_DIR_NAMES or name.startswith(_PYTHON_DIR_PREFIXES)


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
        text = f"Nothing installed this through {backend}. Check first: {check}. "
        if logical.startswith("/usr/local"):
            text += (
                "It was probably installed manually (for example make install "
                "or an installer script). "
            )
        return text + (
            f"If you no longer need it, remove {shlex.quote(logical)} by hand "
            "(administrator rights needed)."
        )

    def _unreadable(self, logical: str, real: Path) -> Finding:
        return self.note(
            real,
            f"Not checked: {logical} needs administrator rights to list",
            "Run the scan as administrator to include it.",
        )

    def _keep(self, child: Path, skip):
        name = child.name
        if name in skip or oc.bad_name(name) or name.endswith(_LEFTOVER_SUFFIXES):
            return
        yield (oc.logical_path(self.sysroot, child), child)

    def _candidates(self, root: str, kids: list):
        """Yield (logical, real) candidates, or Finding notes if unreadable."""
        if root != "/usr/local":
            for k in kids:
                yield from self._keep(k, _SKIP.get(root, ()))
            return
        for k in kids:
            if k.name not in _USR_LOCAL_STD:
                yield from self._keep(k, ())
                continue
            if os.path.islink(k):
                continue  # a symlinked standard dir is never followed
            sub = oc.list_dir(k)
            if sub is None:
                yield self._unreadable(f"{root}/{k.name}", k)
                continue
            for c in sub:
                if k.name == "share":
                    skip = _SHARE_SKELETON
                elif k.name in ("lib", "lib64") and _is_python_dir(c.name):
                    continue
                else:
                    skip = ()
                yield from self._keep(c, skip)

    def _probes(self, real: Path) -> list:
        """Up to a few immediate children, for the vendor-parent check."""
        if os.path.islink(real) or not real.is_dir():
            return []
        kids = oc.list_dir(real) or []
        out = []
        for k in sorted(kids, key=lambda p: p.name):
            if (
                oc.bad_name(k.name)
                or (_GLOB & set(k.name))
                or os.path.islink(k)
            ):
                continue
            out.append(oc.logical_path(self.sysroot, k))
            if len(out) >= _PROBE_CHILDREN:
                break
        return out

    # ------------------------------------------------------------ scanning
    def system_findings(self) -> Iterable[Finding]:
        backend = self.pkg_backend()
        if backend is None:
            return
        loaded = False
        evidence: Optional[NameEvidence] = None
        cands = []
        for root in _ROOTS:
            root_real = oc.in_root(self.sysroot, root)
            if os.path.islink(root_real):
                continue  # e.g. /usr/local -> ../var/usrlocal: never followed
            kids = oc.list_dir(root_real)  # each root is listed once
            if kids is None:
                yield self._unreadable(root, root_real)
                continue
            if not kids:
                continue
            if root in _NEEDS_NAMES:
                if not loaded:
                    loaded = True
                    names = oc.installed_package_names(backend)
                    if names:
                        evidence = NameEvidence(
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
            root_dev = oc.device_of(root_real)
            for n, item in enumerate(self._candidates(root, kids)):
                if n % _CHECK_EVERY == 0 and self.budget.expired():
                    yield self.note(
                        root_real,
                        f"Not checked: rest of {root} (time limit reached)",
                        "Raise orphan_max_seconds in the config to scan further.",
                    )
                    break
                if isinstance(item, Finding):
                    yield item
                    continue
                logical, real = item
                dev = oc.device_of(real)
                if dev is None or (root_dev is not None and dev != root_dev):
                    continue
                if root in _NEEDS_NAMES and evidence.matches(real.name):
                    continue
                cands.append((logical, real))
        if not cands:
            return
        probes = {}
        for logical, real in cands:
            if self.budget.expired():
                break
            probes[logical] = self._probes(real)
        queried = [lg for lg, _ in cands]
        queried += [c for ps in probes.values() for c in ps]
        unowned = oc.query_unowned(backend, queried, self.budget)
        for logical, real in cands:
            if logical not in unowned:
                continue
            # vendor parent (/opt/vendor/app): any owned child owns the parent
            if any(c not in unowned for c in probes.get(logical, ())):
                continue
            label = (
                f"Installed outside the package manager: {logical}"
                if logical.startswith("/usr/local/")
                else f"Not from any package: {logical}"
            )
            yield Finding(
                real, label, self._hint(backend, logical), requires_root=True
            )
