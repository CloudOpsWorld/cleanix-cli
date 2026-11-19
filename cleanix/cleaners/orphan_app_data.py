"""Report-only: macOS data folders left behind by apps that were removed.

Looks at ``Application Support`` and ``Containers`` folders and ``Preferences``
property lists whose name is a reverse-DNS bundle id (``com.vendor.App``), in
the user's Library (per user) and in ``/Library`` (once per scan). Nothing is
ever removed; every finding carries a hint with the one path and a command
that confirms the app really is gone, then suggests moving it to the Trash.

Unknown is not orphan. A name is reported only when it is reverse-DNS, is at
least ``orphan_min_age_days`` old, is not Apple's, and nothing installed
shares its id, an id prefix or its vendor. Human-named folders ("Slack",
"Google") are never reported. If the list of installed apps cannot be built
nothing is reported and one "Not checked" note is shown instead.
"""

from __future__ import annotations

import os
import plistlib
import re
import shlex
import time
from pathlib import Path
from typing import Iterable, Optional, Union

from cleanix.cleaners import orphan_common as oc
from cleanix.cleaners.base import SCOPE_USER
from cleanix.core.platform import MACOS
from cleanix.core.utils import home

MAX_PLIST_BYTES = 1024 * 1024
MAX_MDFIND_PATHS = 50000

_ID_RE = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9_-]+){2,}$")
_TEAM_RE = re.compile(r"^[A-Z0-9]{10}\.")
_LOWER_FIRST = re.compile(r"^[a-z][a-z0-9-]*$")
_SHARED_HOSTS = {
    "com.github", "io.github", "com.gitlab", "io.gitlab",
    "org.sourceforge", "net.sourceforge",
}
_APPLE_EXACT = {".globalpreferences", "loginwindow", "pbs", "com.apple"}
_BUNDLE_SUFFIXES = (".app", ".appex", ".xpc")
_NESTED_DIRS = (
    "Library/LoginItems", "Helpers", "Frameworks", "PlugIns",
    "XPCServices", "Library/LaunchServices",
)
_APP_ROOTS = (  # (logical folder, max depth below it for *.app)
    ("/Applications", 3),
    ("/System/Applications", 2),
    ("/opt/homebrew/Caskroom", 3),
    ("/usr/local/Caskroom", 3),
)
_LAUNCH_DIRS = ("/Library/LaunchAgents", "/Library/LaunchDaemons")


# --------------------------------------------------------------- id helpers
def candidate_id(name: str) -> Optional[str]:
    """The bundle id a folder/plist name stands for, else None.

    Strips ``.plist``, a ``TEAMID.`` prefix and a ``group.`` prefix. Only
    reverse-DNS names with a lowercase first label qualify (so "Slack" and
    "Adobe.Photoshop.2020" never do).
    """
    n = name[: -len(".plist")] if name.endswith(".plist") else name
    n = _TEAM_RE.sub("", n, count=1)
    if n.startswith("group."):
        n = n[len("group."):]
    if not _ID_RE.match(n):
        return None
    if not _LOWER_FIRST.match(n.split(".", 1)[0]):
        return None
    return n


def vendor_key(bundle_id: str) -> str:
    parts = bundle_id.lower().split(".")
    two = ".".join(parts[:2])
    return ".".join(parts[:3]) if two in _SHARED_HOSTS else two


class _Index:
    """Normalised lookup sets, built once per scan."""

    def __init__(self, installed: Iterable[str]):
        self.ids: set = set()
        self.vendors: set = set()
        self.prefixes: set = set()  # proper dotted prefixes of installed ids
        for raw in installed:
            i = raw.strip().lower()
            if not i:
                continue
            self.ids.add(i)
            self.vendors.add(vendor_key(i))
            parts = i.split(".")
            for k in range(1, len(parts)):
                self.prefixes.add(".".join(parts[:k]))


def is_excluded(bid: str, installed: Union[set, _Index]) -> bool:
    """True when ``bid`` must not be reported as an orphan."""
    b = bid.lower()
    if b.startswith("com.apple.") or b in _APPLE_EXACT:
        return True
    idx = installed if isinstance(installed, _Index) else _Index(installed)
    if b in idx.ids:
        return True
    if b in idx.prefixes:  # an installed id starts with bid + "."
        return True
    parts = b.split(".")
    for k in range(1, len(parts)):  # bid starts with an installed id + "."
        if ".".join(parts[:k]) in idx.ids:
            return True
    return vendor_key(b) in idx.vendors


# ------------------------------------------------------ installed-app index
def _is_real_dir(path: Path) -> bool:
    return os.path.isdir(path) and not os.path.islink(path)


def _bundle_id(bundle: Path) -> Optional[str]:
    plist = bundle / "Contents" / "Info.plist"
    try:
        if plist.stat().st_size > MAX_PLIST_BYTES:
            return None
        with open(plist, "rb") as fh:
            data = plistlib.load(fh)
    except Exception:  # noqa: BLE001 - unreadable/hostile plist: just no id
        return None
    bid = data.get("CFBundleIdentifier") if isinstance(data, dict) else None
    return bid if isinstance(bid, str) and bid else None


def _collect_bundle(bundle: Path, ids: set, level: int = 0) -> None:
    bid = _bundle_id(bundle)
    if bid:
        ids.add(bid)
    if level >= 4:
        return
    for sub in _NESTED_DIRS:
        _collect_nested(bundle / "Contents" / sub, ids, 1, level)


def _collect_nested(directory: Path, ids: set, depth: int, level: int) -> None:
    children = oc.list_dir(directory)
    if not children:
        return
    for child in children:
        if oc.bad_name(child.name):
            continue
        if child.name.endswith(_BUNDLE_SUFFIXES):
            if _is_real_dir(child):
                _collect_bundle(child, ids, level + 1)
        elif depth < 4 and _is_real_dir(child):
            _collect_nested(child, ids, depth + 1, level)


def _walk_apps(directory: Path, ids: set, depth: int, max_depth: int) -> bool:
    """Collect ids of every ``*.app`` under ``directory``; False if unreadable."""
    children = oc.list_dir(directory)
    if children is None:
        return False
    for child in children:
        if oc.bad_name(child.name):
            continue
        if child.name.endswith(".app"):
            if os.path.isdir(child):  # a symlinked (cask) app is still an app
                _collect_bundle(child, ids)
        elif depth < max_depth and _is_real_dir(child):
            _walk_apps(child, ids, depth + 1, max_depth)
    return True


def _launch_stems(directory: Path, ids: set) -> None:
    for child in oc.list_dir(directory) or ():
        if child.suffix == ".plist" and not oc.bad_name(child.name):
            ids.add(child.stem)


def installed_ids(root, home_dir: Path) -> Optional[set]:
    """Bundle ids of everything that looks installed, or None if unknown.

    None when ``/Applications`` is missing or unreadable, or when nothing at
    all was found (an empty inventory would make every name look orphaned).
    """
    apps = oc.in_root(root, "/Applications")
    if not _is_real_dir(apps) and not os.path.isdir(apps):
        return None
    ids: set = set()
    if not _walk_apps(apps, ids, 1, 3):
        return None
    for logical, depth in _APP_ROOTS[1:]:
        _walk_apps(oc.in_root(root, logical), ids, 1, depth)
    _walk_apps(Path(home_dir) / "Applications", ids, 1, 3)

    rc, out, _ = oc.run(
        ["mdfind", "kMDItemContentType == 'com.apple.application-bundle'"]
    )
    if rc == 0:
        for n, line in enumerate(out.splitlines()):
            if n >= MAX_MDFIND_PATHS:
                break
            line = line.strip()
            if not line.endswith(".app") or oc.bad_name(line):
                continue
            for cand in (oc.in_root(root, line), Path(line)):
                if os.path.isdir(cand):
                    _collect_bundle(cand, ids)
                    break

    _launch_stems(Path(home_dir) / "Library" / "LaunchAgents", ids)
    for logical in _LAUNCH_DIRS:
        _launch_stems(oc.in_root(root, logical), ids)

    rc, out, _ = oc.run(["pkgutil", "--pkgs"])
    if rc == 0:
        ids.update(ln.strip() for ln in out.splitlines() if ln.strip())
    return ids or None


# ----------------------------------------------------------------- reporter
class OrphanAppDataReporter(oc.OrphanReporter):
    id = "orphan_app_data"
    name = "Data of removed apps"
    description = (
        "Application Support, Preferences and Containers entries of apps "
        "that are no longer installed (report only)"
    )
    platforms = (MACOS,)
    scope = SCOPE_USER

    def _reset(self) -> None:
        super()._reset()
        self._index: Optional[_Index] = None
        self._index_built = False

    def _installed(self) -> Optional[_Index]:
        if not self._index_built:
            self._index_built = True
            ids = installed_ids(self.sysroot, home())
            self._index = _Index(ids) if ids is not None else None
        return self._index

    # ------------------------------------------------------------ discovery
    def system_findings(self) -> Iterable[oc.Finding]:
        if self._installed() is None:
            apps = oc.in_root(self.sysroot, "/Applications")
            yield self.note(
                apps,
                "Not checked: could not list the installed apps "
                f"({oc.logical_path(self.sysroot, apps)})",
                "No app data is reported until the installed apps can be read. "
                "Grant Full Disk Access or run with admin rights and scan again.",
                requires_root=False,
            )
            return
        lib = oc.in_root(self.sysroot, "/Library")
        yield from self._scan_dir(lib / "Application Support", dirs=True, system=True)
        yield from self._scan_dir(lib / "Preferences", dirs=False, system=True)

    def user_findings(self) -> Iterable[oc.Finding]:
        if self._installed() is None:
            return
        lib = home() / "Library"
        yield from self._scan_dir(lib / "Application Support", dirs=True, system=False)
        yield from self._scan_dir(lib / "Containers", dirs=True, system=False, fda=True)
        yield from self._scan_dir(lib / "Preferences", dirs=False, system=False)

    def _scan_dir(
        self, directory: Path, dirs: bool, system: bool, fda: bool = False
    ) -> Iterable[oc.Finding]:
        logical = oc.logical_path(self.sysroot, directory)
        children = oc.list_dir(directory)
        if children is None:
            reason = (
                f"macOS needs Full Disk Access to list {logical}"
                if fda
                else f"could not read {logical}"
            )
            yield self.note(
                directory,
                f"Not checked: {reason}",
                "Grant Full Disk Access to your terminal or Cleanix and scan again."
                if fda
                else "Check the folder's permissions and scan again.",
                requires_root=system,
            )
            return
        cutoff = time.time() - float(self.config.orphan_min_age_days) * 86400
        index = self._index
        for child in sorted(children):
            if self.budget.expired():
                return
            name = child.name
            if oc.bad_name(name):
                continue
            if not dirs and not name.endswith(".plist"):
                continue
            bid = candidate_id(name)
            if bid is None or is_excluded(bid, index):
                continue
            try:
                st = child.lstat()
            except OSError:
                continue
            import stat as _stat

            if _stat.S_ISLNK(st.st_mode):
                continue
            if _stat.S_ISDIR(st.st_mode) != dirs:
                continue  # Support/Containers: folders only; Preferences: files
            if st.st_mtime > cutoff:
                continue
            real_logical = oc.logical_path(self.sysroot, child)
            yield oc.Finding(
                child,
                f"Left by a removed app: {bid} ({real_logical})",
                self._hint(bid, real_logical),
                requires_root=system,
            )

    @staticmethod
    def _hint(bid: str, logical: str) -> str:
        return (
            f"No installed app uses the id {bid}. Check with: "
            f"mdfind \"kMDItemCFBundleIdentifier == '{bid}'\" "
            "(no result means it is not installed). "
            f"If you no longer need it, move {shlex.quote(logical)} "
            "to the Trash in Finder."
        )
