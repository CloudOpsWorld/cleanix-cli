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
import time
from pathlib import Path
from typing import Iterable, Optional

from cleanix.cleaners import orphan_common as oc
from cleanix.cleaners.base import SCOPE_SYSTEM
from cleanix.cleaners.linux_extras import LEFTOVER_SUFFIXES
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
_PYTHON_DIR_NAMES = frozenset({
    "site_python", "dist-packages", "site-packages",
    # language-runtime trees that installer scripts / package managers create
    "R", "site_ruby", "lua", "octave", "perl", "php",
})
_PYTHON_DIR_PREFIXES = ("python2", "python3")
# Long-running services keep live state here (k3s, kubelet, CNI, container
# runtimes, cloud agents); it is never "left over" from a removed package.
_RUNTIME_DIRS = frozenset(
    "rancher kubelet cni containerd waagent amazon lxd lxcfs microk8s k0s k3s "
    "snap docker containers podman libvirt flatpak".split()
)
_SKIP = {
    "/opt": _RUNTIME_DIRS,
    "/var/lib": _RUNTIME_DIRS | frozenset(
        "dpkg apt rpm dnf yum pacman apk systemd private flatpak snapd docker "
        "containerd containers lxd lxc libvirt machines portables ucf polkit-1 "
        "sudo dbus misc pam initramfs-tools os-prober update-rc.d alternatives "
        "dhcp NetworkManager AccountsService PackageKit logrotate man-db "
        "plymouth sss nfs ubuntu-advantage cloud bluetooth boltd rpm-state "
        "shells.state swcatalog cups sddm gdm lightdm fwupd ModemManager "
        "upower geoclue power-profiles-daemon app-info".split()
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
_FRESH_CHILDREN = 20
_EXEC_ROOTS = ("/opt/", "/var/lib/", "/var/cache/", "/usr/local/")
_CAVEAT = (
    "It may be created at runtime by a program or installer script; "
    "removing it can break that program. Check what uses it first. "
)
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

    def _unit_evidence(self) -> set:
        """Names a systemd unit stands for: unit stems, plus the program and
        data folder each ExecStart uses (``/opt/foo/bin/x`` -> foo, x)."""
        names = self._unit_names()
        seen = 0
        for d in _UNIT_DIRS:
            for p in oc.list_dir(oc.in_root(self.sysroot, d)) or []:
                if not p.name.endswith(".service") or oc.bad_name(p.name):
                    continue
                seen += 1
                if seen > 2000 or self.budget.expired():
                    return names
                try:
                    if os.path.islink(p):
                        continue
                    with open(p, "rb") as fh:
                        text = fh.read(65536).decode("utf-8", "replace")
                except OSError:
                    continue
                for line in text.splitlines():
                    line = line.strip()
                    if not line.startswith("ExecStart"):
                        continue
                    _k, _, val = line.partition("=")
                    prog = val.lstrip("-@+!: " + chr(9)).split(None, 1)
                    if not prog or not prog[0].startswith("/"):
                        continue
                    path = prog[0]
                    names.add(path.rsplit("/", 1)[-1])
                    for r in _EXEC_ROOTS:
                        if path.startswith(r):
                            first = path[len(r):].split("/", 1)[0]
                            if first:
                                names.add(first)
        return names

    def _is_fresh(self, real: Path, cutoff: Optional[float]) -> bool:
        """True when the entry or its newest immediate child changed since
        ``cutoff`` (live data is always fresh). lstat only; budget-aware."""
        if cutoff is None:
            return False
        try:
            st = real.lstat()
        except OSError:
            return True  # cannot tell: treat as in use
        newest = st.st_mtime
        if os.path.isdir(real) and not os.path.islink(real):
            try:
                with os.scandir(real) as it:
                    for n, entry in enumerate(it):
                        if n >= _FRESH_CHILDREN or self.budget.expired():
                            break
                        try:
                            newest = max(
                                newest, entry.stat(follow_symlinks=False).st_mtime
                            )
                        except OSError:
                            continue
            except OSError:
                return True
        return newest > cutoff

    def _hint(self, backend: str, logical: str, sampled: bool = False) -> str:
        check = oc.owner_check_command(backend, logical)
        text = f"Nothing installed this through {backend}. Check first: {check}. "
        text += _CAVEAT
        if logical.startswith("/usr/local"):
            text += (
                "It was probably installed manually (for example make install "
                "or an installer script). "
            )
        if sampled:
            text += "Only a sample of this folder was checked for ownership. "
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
        if name in skip or oc.bad_name(name) or name.endswith(LEFTOVER_SUFFIXES):
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

    def _probes(self, real: Path):
        """Vendor-parent check input: ``(status, probes, sampled)``.

        ``status`` is "ok" when the folder can be judged (a file, a symlink,
        an empty folder, or a folder with usable children to query) and
        "unknown" when its contents cannot be listed or none of its children
        can be queried. Unknown folders are never reported. Large folders are
        sampled (first 3 and last 2 by name).
        """
        if os.path.islink(real) or not real.is_dir():
            return "ok", [], False
        kids = oc.list_dir(real)
        if kids is None:
            return "unknown", [], False
        if not kids:
            return "ok", [], False
        eligible = [
            k for k in sorted(kids, key=lambda p: p.name)
            if not (oc.bad_name(k.name) or (_GLOB & set(k.name))
                    or os.path.islink(k))
        ]
        if not eligible:
            return "unknown", [], False
        sampled = len(eligible) > _PROBE_CHILDREN
        if sampled:
            eligible = eligible[:3] + eligible[-2:]
        return (
            "ok",
            [oc.logical_path(self.sysroot, k) for k in eligible],
            sampled,
        )

    # ------------------------------------------------------------ scanning
    def system_findings(self) -> Iterable[Finding]:
        backend = self.pkg_backend()
        if backend is None:
            return
        loaded = False
        evidence: Optional[NameEvidence] = None
        unit_evidence: Optional[NameEvidence] = None
        days = float(self.config.orphan_min_age_days)
        cutoff = time.time() - days * 86400 if days > 0 else None
        cands = []
        units = self._unit_evidence()
        unit_evidence = NameEvidence(units)
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
                            | units
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
                    return  # find_items adds the one "incomplete" note
                if isinstance(item, Finding):
                    yield item
                    continue
                logical, real = item
                dev = oc.device_of(real)
                if dev is None or (root_dev is not None and dev != root_dev):
                    continue
                if root in _NEEDS_NAMES and evidence.matches(real.name):
                    continue
                if root == "/opt" and oc._norm(real.name) in unit_evidence._set:
                    continue  # a service runs from / is named after it
                if self._is_fresh(real, cutoff):
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
        queried += [c for _st, ps, _sm in probes.values() for c in ps]
        unowned = oc.query_unowned(backend, queried, self.budget)
        report = []
        unknown = 0
        for logical, real in cands:
            if logical not in unowned or logical not in probes:
                continue
            status, ps, sampled = probes[logical]
            if status != "ok":
                unknown += 1
                continue
            # vendor parent (/opt/vendor/app): report only if every probed
            # child was queried and came back unowned
            if any(c not in unowned for c in ps):
                continue
            report.append((logical, real, sampled))
        if unknown:
            yield self.note(
                Path(self.sysroot),
                f"Not checked: {unknown} folders could not be listed or "
                "checked for owned contents (may need administrator rights)",
                "Run the scan as administrator to include them.",
            )
        for logical, real, sampled in report:
            label = (
                f"Installed outside the package manager: {logical}"
                if logical.startswith("/usr/local/")
                else f"Not from any package: {logical}"
            )
            yield Finding(
                real, label, self._hint(backend, logical, sampled),
                requires_root=True,
                remedy_kind=oc.RemedyKind.PATH,
            )

    # ------------------------------------------------- act-time re-check
    def still_unowned(self, real: Path) -> Optional[str]:
        """Why ``real`` (a finding of this detector) must not be removed
        now, or None when the scan's evidence still holds: the package
        manager still answers, positively, that no package owns it (nor,
        for a folder, its probed children -- the usr-merge alias rule of
        :func:`orphan_common.query_unowned` applies), no installed package,
        system account or service has its name (``/var/lib``,
        ``/var/cache``; ``/opt``: no service runs from it) and it did not
        change recently. Unknown, unreadable or timed-out answers are a
        reason (fail closed)."""
        backend = self.pkg_backend()
        if backend is None:
            return "package ownership cannot be checked now"
        logical = oc.logical_path(self.sysroot, real)
        root = next((r for r in _ROOTS if logical.startswith(r + "/")), None)
        if root is None:
            return "it is not in a folder this scenario checks"
        name = real.name
        if oc.bad_name(logical) or (_GLOB & set(logical)):
            return "its name cannot be checked for package ownership"
        units = self._unit_evidence()
        if root in _NEEDS_NAMES:
            names = oc.installed_package_names(backend)
            if not names:
                return "the installed packages could not be listed now"
            evidence = NameEvidence(names | oc.system_account_names(self.sysroot) | units)
            if evidence.matches(name):
                return "an installed package, account or service now has its name"
        if root == "/opt" and oc._norm(name) in NameEvidence(units)._set:
            return "a service now runs from it or is named after it"
        days = float(self.config.orphan_min_age_days)
        cutoff = time.time() - days * 86400 if days > 0 else None
        if self._is_fresh(real, cutoff):
            return "it changed recently (it may be in use)"
        status, probes, _sampled = self._probes(real)
        if status != "ok":
            return "its contents could not be checked for package ownership"
        queried = [logical] + list(probes)
        from cleanix.core import reverify

        unowned = reverify.prefetched(self.id)  # up front: one batched query
        if unowned is None:  # right before the removal: always a fresh query
            budget = oc.ScanBudget(len(queried) + 1, _REVERIFY_SECONDS)
            budget.start()
            unowned = oc.query_unowned(backend, queried, budget)
        if any(q not in unowned for q in queried):
            return "a package owns it now, or its ownership could not be confirmed"
        return None


_REVERIFY_SECONDS = 120.0


def prefetch_unowned(paths, config) -> Optional[set]:
    """The up-front (whole batch) ownership answer: ONE ``query_unowned``
    call (several paths per ``dpkg-query -S`` / ``rpm -qf`` / ``pacman -Qo``
    argv, as the read-only allowlist permits) over every path and its
    probed children; the set of positively unowned ones, or None (no
    backend). The removal-phase re-check never uses it."""
    reporter = UnownedSystemFilesReporter(config)
    reporter.budget.start()
    backend = reporter.pkg_backend()
    if backend is None:
        return None
    queried = []
    for path in paths:
        real = Path(path)
        queried.append(oc.logical_path(reporter.sysroot, real))
        status, probes, _sampled = reporter._probes(real)
        if status == "ok":
            queried.extend(probes)
    queried = list(dict.fromkeys(queried))
    budget = oc.ScanBudget(len(queried) + 1, _REVERIFY_SECONDS)
    budget.start()
    return set(oc.query_unowned(backend, queried, budget))


def reverify_system_item(path: str, config) -> Optional[str]:
    """Act-time re-check of one system-wide finding (``reverify`` table)."""
    reporter = UnownedSystemFilesReporter(config)
    reporter.budget.start()
    return reporter.still_unowned(Path(path))
