"""Operating-system / distribution detection.

Cleanix targets every *nix flavour, so cleaners declare which platforms they
apply to and the engine only runs the relevant ones. Detection is cheap and
cached. Distro detection parses ``/etc/os-release`` (freedesktop standard,
present on virtually all modern Linux distros).
"""

from __future__ import annotations

import platform as _platform
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, Set

# Canonical platform tokens used by cleaners.
LINUX = "linux"
MACOS = "macos"
FREEBSD = "freebsd"
OPENBSD = "openbsd"
NETBSD = "netbsd"
DRAGONFLY = "dragonfly"
SUNOS = "sunos"      # Solaris / illumos
WINDOWS = "windows"
UNKNOWN = "unknown"

ALL = "*"            # every POSIX platform; Windows must opt in

BSD: Set[str] = {FREEBSD, OPENBSD, NETBSD, DRAGONFLY}

# Platforms that follow the freedesktop/XDG layout (~/.cache, ~/.local/share,
# freedesktop Trash, etc.). macOS uses ~/Library instead and is excluded.
XDG_PLATFORMS = (LINUX, FREEBSD, OPENBSD, NETBSD, DRAGONFLY)


@lru_cache(maxsize=1)
def current_os() -> str:
    system = _platform.system().lower()
    if system == "linux":
        return LINUX
    if system == "darwin":
        return MACOS
    if "freebsd" in system:
        return FREEBSD
    if "openbsd" in system:
        return OPENBSD
    if "netbsd" in system:
        return NETBSD
    if "dragonfly" in system:
        return DRAGONFLY
    if system == "sunos":
        return SUNOS
    if system == "windows":
        return WINDOWS
    return UNKNOWN


@lru_cache(maxsize=1)
def os_release() -> Dict[str, str]:
    """Parse /etc/os-release into a dict (empty on non-Linux or if absent)."""
    data: Dict[str, str] = {}
    for candidate in ("/etc/os-release", "/usr/lib/os-release"):
        p = Path(candidate)
        if not p.exists():
            continue
        try:
            for line in p.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                data[key.strip()] = value.strip().strip('"').strip("'")
        except OSError:
            continue
        break
    return data


def current_distro() -> str:
    """Distro id, e.g. ``fedora``, ``debian``, ``ubuntu``, ``arch`` (or "")."""
    return os_release().get("ID", "").lower()


def distro_like() -> Set[str]:
    """The ``ID_LIKE`` family set, e.g. {'debian'} for Ubuntu."""
    return set(os_release().get("ID_LIKE", "").lower().split())


def distro_family() -> Set[str]:
    """Distro id plus its ID_LIKE ancestry, for family checks."""
    fam = {current_distro()} | distro_like()
    fam.discard("")
    return fam


def is_bsd() -> bool:
    return current_os() in BSD


def is_linux() -> bool:
    return current_os() == LINUX


def is_macos() -> bool:
    return current_os() == MACOS


def is_windows() -> bool:
    return current_os() == WINDOWS


def supports(platforms: Iterable[str]) -> bool:
    """True if a cleaner declaring ``platforms`` applies to this machine."""
    plats = set(platforms)
    if current_os() == WINDOWS:
        return WINDOWS in plats
    return ALL in plats or current_os() in plats


def os_label() -> str:
    """Human label, e.g. ``fedora (linux)`` or ``macos``."""
    distro = current_distro()
    if distro:
        pretty = os_release().get("PRETTY_NAME") or distro
        return f"{pretty}"
    return current_os()
