"""BSD package/ports leftovers (FreeBSD, and pkgin-based systems).

FreeBSD's ``pkg`` keeps a download cache and can autoremove orphaned
dependencies; the ports tree accumulates distfiles and build ``work`` dirs.
NetBSD/illumos ``pkgin`` keeps a similar cache.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from cleanix.cleaners.base import SCOPE_SYSTEM, Cleaner
from cleanix.core.models import CleanableItem
from cleanix.core.platform import DRAGONFLY, FREEBSD, NETBSD, SUNOS
from cleanix.core.utils import path_size, run_command, which


class FreeBsdPkgCleaner(Cleaner):
    id = "pkg"
    scope = SCOPE_SYSTEM
    name = "FreeBSD pkg cache & orphans"
    description = "Cached packages and orphaned dependencies (pkg)"
    requires_root = True
    # ``pkg`` is FreeBSD/DragonFly; OpenBSD (pkg_add) and NetBSD (pkgin) differ.
    platforms = (FREEBSD, DRAGONFLY)

    def available(self):
        if not which("pkg"):
            return "pkg not found"
        return None

    def find_items(self) -> Iterable[CleanableItem]:
        cache = Path("/var/cache/pkg")
        size = path_size(cache) if cache.exists() else 0
        if size > 0:
            yield self.command_item(
                ["pkg", "clean", "-ay"],
                "Remove cached package files",
                size=size,
            )
        # Orphaned automatic dependencies. ``-nq`` (dry-run + quiet) prints one
        # package name per line when there are orphans and nothing when clean —
        # far more robust than string-matching pkg's prose, which varies by
        # version and locale.
        code, out, _err = run_command(["pkg", "autoremove", "-nq"], timeout=60)
        if code == 0 and any(ln.strip() for ln in out.splitlines()):
            yield self.command_item(
                ["pkg", "autoremove", "-y"],
                "Autoremove orphaned dependencies",
            )


class BsdDistfilesCleaner(Cleaner):
    id = "bsd_distfiles"
    scope = SCOPE_SYSTEM
    name = "BSD ports distfiles & work dirs"
    description = "Downloaded source tarballs and stale build work/ directories"
    requires_root = True
    platforms = (FREEBSD,)

    def find_items(self) -> Iterable[CleanableItem]:
        distfiles = Path("/usr/ports/distfiles")
        if distfiles.exists() and path_size(distfiles) > 0:
            item = self.path_item(distfiles, "Ports distfiles cache")
            # Delete the *contents*, not the distfiles dir itself.
            if item:
                for child in distfiles.iterdir():
                    ci = self.path_item(child, f"Distfile: {child.name}")
                    if ci:
                        yield ci

        # Leftover build work/ directories under the ports tree.
        ports = Path("/usr/ports")
        if ports.exists():
            # -maxdepth must precede the tests: GNU find warns but FreeBSD find
            # is strict about primary ordering.
            code, out, _err = run_command(
                ["find", "/usr/ports", "-maxdepth", "3",
                 "-type", "d", "-name", "work"],
                timeout=60,
            )
            if code == 0:
                for line in out.splitlines():
                    line = line.strip()
                    if line:
                        item = self.path_item(line, f"Ports work dir: {line}")
                        if item:
                            yield item


class PkginCleaner(Cleaner):
    id = "pkgin"
    scope = SCOPE_SYSTEM
    name = "pkgin cache (NetBSD/pkgsrc)"
    description = "Cached binary packages downloaded by pkgin"
    requires_root = True
    # pkgin (pkgsrc) also ships on illumos/SmartOS and DragonFly, not just NetBSD.
    platforms = (NETBSD, SUNOS, DRAGONFLY)

    def available(self):
        if not which("pkgin"):
            return "pkgin not found"
        return None

    def find_items(self) -> Iterable[CleanableItem]:
        cache = Path("/var/db/pkgin/cache")
        size = path_size(cache) if cache.exists() else 0
        if size > 0:
            yield self.command_item(
                ["pkgin", "-y", "clean"],
                "Remove cached binary packages",
                size=size,
            )
