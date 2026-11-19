"""Report-only detectors for stale menu entries and broken alternatives links.

* ``stale_launchers`` - ``.desktop`` entries (application menu, autostart)
  whose program no longer exists.
* ``stale_alternatives`` - symlinks in ``/etc/alternatives`` whose target is gone.

Nothing is ever deleted. Every finding carries a hint naming the exact path and
how to confirm it; unknown or unverifiable situations (unreadable files,
removable locations, unparsable Exec lines, entries a package owns) are skipped.
Commands are only called through ``orphan_common`` (``run``/``tool``).
AppImage launchers (``appimagekit_*.desktop``) belong to the ``appimage``
cleaner and are skipped here.
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Iterable, Optional

from cleanix.cleaners import orphan_common as oc
from cleanix.cleaners.base import SCOPE_SYSTEM, SCOPE_USER
from cleanix.core.platform import LINUX
from cleanix.core.utils import home

_MAX_DESKTOP_BYTES = 64 * 1024

_WRAPPERS = frozenset(
    {
        "sh", "bash", "dash", "zsh", "flatpak", "snap", "gtk-launch",
        "xdg-open", "gio", "kioclient", "kioclient5", "kde-open", "kde-open5",
        "pkexec", "sudo",
    }
)

# Fixed lookup list for relative programs; $PATH is never consulted.
_PATH_DIRS = (
    "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin",
    "/bin", "/usr/games", "/usr/local/games", "/snap/bin",
    "/var/lib/flatpak/exports/bin",
)
_HOME_PATH_DIRS = (".local/bin", "bin", ".local/share/flatpak/exports/bin")

# Package-owned system directories: reported only when query_unowned agrees.
_OWNED_DIRS = ("/usr/share/applications", "/etc/xdg/autostart")
_LOCAL_DIR = "/usr/local/share/applications"


# ------------------------------------------------------------ desktop parse
def _read_entry(path: Path) -> Optional[dict]:
    """Keys of the [Desktop Entry] group, or None if unreadable/absent."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(_MAX_DESKTOP_BYTES)
    except OSError:
        return None
    keys: dict = {}
    in_group = found = False
    for line in raw.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            if in_group:
                break
            in_group = line == "[Desktop Entry]"
            found = found or in_group
            continue
        if in_group and "=" in line:
            k, v = line.split("=", 1)
            keys.setdefault(k.strip(), v.strip())
    return keys if found else None


def _exec_binary(exec_line: str) -> Optional[str]:
    """First real program token of an Exec line, or None if not checkable."""
    try:
        toks = shlex.split(exec_line)
    except ValueError:
        return None
    if not toks:
        return None
    i = 0
    if os.path.basename(toks[0]) == "env":
        i = 1
        if i < len(toks) and toks[i].startswith("-"):
            return None  # env options: too exotic to judge
    while (
        i < len(toks)
        and not toks[i].startswith("/")
        and "=" in toks[i]
        and toks[i].split("=", 1)[0].replace("_", "").isalnum()
    ):
        i += 1
    return toks[i] if i < len(toks) else None


def _exists(path: str) -> Optional[bool]:
    try:
        os.stat(path)
        return True
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        return None  # permission etc.: unknown


class StaleDesktopEntryReporter(oc.OrphanReporter):
    id = "stale_launchers"
    name = "Menu entries for removed programs"
    description = (
        "Application menu and autostart entries whose program is missing "
        "(report only)"
    )
    platforms = (LINUX,)
    scope = SCOPE_USER

    # ---- program lookup
    def _is_missing(self, token: str) -> bool:
        """True only on positive evidence that ``token`` does not exist."""
        if (
            not token
            or os.path.basename(token) in _WRAPPERS
            or "%" in token
            or "$" in token
            or token.startswith("~")
            or oc.bad_name(token)
        ):
            return False
        if token.startswith("/"):
            if oc.is_removable_location(token):
                return False
            reals = [str(oc.in_root(self.sysroot, token))]
        else:
            if "/" in token:
                return False
            reals = [
                str(oc.in_root(self.sysroot, f"{d}/{token}")) for d in _PATH_DIRS
            ]
            reals += [str(home() / d / token) for d in _HOME_PATH_DIRS]
        for real in reals:
            ex = _exists(real)
            if ex is None or ex:
                return False
            # dangling symlink into a removable location: unknown, not stale
            if os.path.islink(real):
                try:
                    tgt = os.readlink(real)
                except OSError:
                    return False
                if oc.is_removable_location(tgt):
                    return False
        return True

    @staticmethod
    def _binary_of(keys: dict) -> Optional[str]:
        if keys.get("Hidden", "").lower() == "true":
            return None
        if keys.get("Type", "") != "Application":
            return None
        try_exec = keys.get("TryExec", "").strip()
        if try_exec:
            return try_exec
        if "Exec" not in keys:
            return None
        return _exec_binary(keys["Exec"])

    # ---- directory walk
    def _desktop_files(self, directory: Path, depth: int, max_depth: int):
        children = oc.list_dir(directory)
        if not children:
            return
        for child in sorted(children):
            if self.budget.expired():
                return
            name = child.name
            if oc.bad_name(name):
                continue
            try:
                if child.is_symlink():
                    continue
                is_dir = child.is_dir()
            except OSError:
                continue
            if is_dir:
                if depth < max_depth:
                    yield from self._desktop_files(child, depth + 1, max_depth)
            elif name.endswith(".desktop") and not name.startswith("appimagekit_"):
                yield child

    def _candidates(self, directory: Path, max_depth: int = 0):
        for path in self._desktop_files(directory, 0, max_depth):
            keys = _read_entry(path)
            if not keys:
                continue
            token = self._binary_of(keys)
            if token is None or not self._is_missing(token):
                continue
            yield path, keys, token

    def _finding(self, path, keys, token, system, backend) -> oc.Finding:
        logical = oc.logical_path(self.sysroot, path) if system else path.as_posix()
        name = oc.safe_label(keys.get("Name", "") or path.name)
        hint = (
            f"It points at {oc.safe_label(token)}, which is missing. If you no "
            f"longer use it, remove {shlex.quote(logical)}; it is only a menu "
            "shortcut."
        )
        if system:
            chk = oc.owner_check_command(backend, logical)
            if chk:
                hint += f" Check first: {chk}."
            hint += " Administrator rights are needed."
        return oc.Finding(
            path,
            f"Menu entry for a missing program: {name} ({logical})",
            hint,
            requires_root=system,
        )

    # ---- parts
    def system_findings(self) -> Iterable[oc.Finding]:
        backend = self.pkg_backend()
        for path, keys, token in self._candidates(
            oc.in_root(self.sysroot, _LOCAL_DIR)
        ):
            yield self._finding(path, keys, token, True, backend)
        if backend is None:
            return  # cannot tell who owns package entries: skip those dirs
        for logical in _OWNED_DIRS:
            found = {
                oc.logical_path(self.sysroot, p): (p, k, t)
                for p, k, t in self._candidates(oc.in_root(self.sysroot, logical))
            }
            if not found:
                continue
            unowned = oc.query_unowned(backend, list(found), self.budget)
            for key in sorted(unowned):
                path, keys, token = found[key]
                yield self._finding(path, keys, token, True, backend)

    def user_findings(self) -> Iterable[oc.Finding]:
        h = home()
        for sub, depth in ((".local/share/applications", 3), (".config/autostart", 0)):
            for path, keys, token in self._candidates(h / sub, depth):
                yield self._finding(path, keys, token, False, None)


class BrokenAlternativesReporter(oc.OrphanReporter):
    id = "stale_alternatives"
    name = "Broken default-program links"
    description = (
        "Links in /etc/alternatives that point at removed programs "
        "(report only)"
    )
    platforms = (LINUX,)
    scope = SCOPE_SYSTEM

    def _dir(self) -> Path:
        return oc.in_root(self.sysroot, "/etc/alternatives")

    def available(self) -> Optional[str]:
        if not self._dir().is_dir():
            return "no alternatives system"
        return None

    def system_findings(self) -> Iterable[oc.Finding]:
        children = oc.list_dir(self._dir())
        if children is None:
            yield self.note(
                self._dir(),
                "Could not read /etc/alternatives",
                "Run the scan with administrator rights to check it.",
            )
            return
        cmd = (
            "update-alternatives" if oc.tool("update-alternatives") else "alternatives"
        )
        for link in sorted(children):
            if self.budget.expired():
                return
            if oc.bad_name(link.name) or not link.is_symlink():
                continue
            if oc.link_target_exists(link, self.sysroot) is not False:
                continue
            try:
                target = os.readlink(link)
            except OSError:
                continue
            if oc.is_removable_location(target) or oc.bad_name(target):
                continue
            q = shlex.quote(link.name)
            yield oc.Finding(
                link,
                f"Broken default-program link: {link.name} -> {target}",
                f"See the choices: {cmd} --display {q}. "
                f"Pick a working one with: sudo {cmd} --config {q}.",
                requires_root=True,
            )
