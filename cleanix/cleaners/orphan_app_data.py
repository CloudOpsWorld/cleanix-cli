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
import stat as _stat
import time
from pathlib import Path
from typing import Iterable, Optional, Union

from cleanix.cleaners import orphan_common as oc
from cleanix.cleaners.base import SCOPE_USER
from cleanix.core import context
from cleanix.core.platform import MACOS
from cleanix.core.utils import home

MAX_PLIST_BYTES = 1024 * 1024
MAX_MDFIND_PATHS = 50000
MIN_APPS = 5  # distinct app ids an inventory needs before it is believed

_ID_RE = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9_-]+){2,}$")
_TEAM_RE = re.compile(r"^[A-Z0-9]{10}\.")
_LOWER_FIRST = re.compile(r"^[a-z][a-z0-9-]*$")
_SHARED_HOSTS = {
    "com.github", "io.github", "com.gitlab", "io.gitlab",
    "org.sourceforge", "net.sourceforge",
}
_APPLE_EXACT = {".globalpreferences", "loginwindow", "pbs", "com.apple"}
# OS / command-line components that use non-Apple ids but have no app bundle.
# "unity." is the Unity engine's default bundle-id prefix for games (their
# data lives beside Steam/itch installs that have no app bundle to inspect).
_OS_DENY_PREFIXES = (
    "org.cups.", "edu.mit.", "org.gnu.", "org.freedesktop.", "org.x.", "unity.",
)
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
# Folders whose entry names are programs (no app bundle, no bundle id):
# Homebrew / MacPorts formulae and cargo / nix binaries. Rust CLI tools using the
# ``directories`` crate keep config in reverse-DNS folders named after them.
_TOOL_DIRS = (
    "/opt/homebrew/Cellar", "/opt/homebrew/opt", "/opt/homebrew/bin",
    "/usr/local/Cellar", "/usr/local/opt",
    "/opt/local/var/macports/software",
    "/nix/var/nix/profiles/default/bin",
)
_HOME_TOOL_DIRS = (".cargo/bin", ".nix-profile/bin", ".local/bin")
_STEAM_DIRS = (
    "Library/Application Support/Steam/steamapps/common",
)
_STEAM_APPS = "Library/Application Support/Steam/steamapps"
_ACF_NAME = re.compile(r'^\s*"name"\s+"([^"]{1,200})"', re.M)
_LAUNCH_DIRS = ("/Library/LaunchAgents", "/Library/LaunchDaemons")
# The system-wide folders scanned (folders in the first, .plist files in the
# second). Also the elevated helper's allowed roots for this scenario.
SYSTEM_DIRS = ("/Library/Application Support", "/Library/Preferences")


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


def _norm_name(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


class _Index:
    """Normalised lookup sets, built once per scan."""

    def __init__(self, installed: Iterable[str], noid_names: Iterable[str] = ()):
        self.ids: set = set()
        self.vendors: set = set()
        self.prefixes: set = set()  # proper dotted prefixes of installed ids
        self.names: set = {n for n in map(_norm_name, noid_names) if n}
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
    if any(b.startswith(p) for p in _OS_DENY_PREFIXES):
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
    if idx.names and any(_norm_name(label) in idx.names for label in parts[1:]):
        return True  # an app whose id we could not read has this name
    return vendor_key(b) in idx.vendors


# ------------------------------------------------------ installed-app index
class _Unknown(Exception):
    """The inventory cannot be trusted (budget spent, too many gaps)."""


class _Ctx:
    def __init__(self, budget):
        self.budget = budget
        self.ids: set = set()
        self.top_ids: set = set()  # ids of top-level apps from the app folders
        self.noid: list = []       # folder names of apps without a readable id
        self.apps = 0

    def check(self) -> None:
        if self.budget is not None and self.budget.expired():
            raise _Unknown


def _is_real_dir(path: Path) -> bool:
    return os.path.isdir(path) and not os.path.islink(path)


def _read_id(plist: Path) -> Optional[str]:
    try:
        if plist.stat().st_size > MAX_PLIST_BYTES:
            return None
        with open(plist, "rb") as fh:
            data = plistlib.load(fh)
    except Exception:  # noqa: BLE001 - unreadable/hostile plist: just no id
        return None
    bid = data.get("CFBundleIdentifier") if isinstance(data, dict) else None
    return bid if isinstance(bid, str) and bid else None


def _bundle_ids(bundle: Path) -> list:
    """Ids of a bundle: Contents/Info.plist, a flat Info.plist, and the
    ``Wrapper/*.app`` of iOS apps running on the Mac."""
    out = []
    for rel in ("Contents/Info.plist", "Info.plist"):
        bid = _read_id(bundle / rel)
        if bid:
            out.append(bid)
            break
    for child in oc.list_dir(bundle / "Wrapper") or ():
        if child.name.endswith(".app") and _is_real_dir(child):
            for rel in ("Info.plist", "Contents/Info.plist"):
                bid = _read_id(child / rel)
                if bid:
                    out.append(bid)
                    break
    return out


def _collect_bundle(bundle: Path, ctx: _Ctx, level: int = 0, top: bool = False) -> None:
    ctx.check()
    found = _bundle_ids(bundle)
    ctx.ids.update(found)
    if top:
        ctx.apps += 1
        if found:
            ctx.top_ids.update(found)
        else:
            ctx.noid.append(bundle.name[: -len(".app")])
    if level >= 4:
        return
    for sub in _NESTED_DIRS:
        _collect_nested(bundle / "Contents" / sub, ctx, 1, level)


def _collect_nested(directory: Path, ctx: _Ctx, depth: int, level: int) -> None:
    children = oc.list_dir(directory)
    if not children:
        return
    for child in children:
        ctx.check()
        if oc.bad_name(child.name):
            continue
        if child.name.endswith(_BUNDLE_SUFFIXES):
            if _is_real_dir(child):
                _collect_bundle(child, ctx, level + 1)
        elif depth < 4 and _is_real_dir(child):
            _collect_nested(child, ctx, depth + 1, level)


def _walk_apps(directory: Path, ctx: _Ctx, depth: int, max_depth: int) -> bool:
    """Collect every ``*.app`` under ``directory``; False if unreadable."""
    children = oc.list_dir(directory)
    if children is None:
        return False
    for child in children:
        ctx.check()
        if oc.bad_name(child.name):
            continue
        if child.name.endswith(".app"):
            if os.path.isdir(child):  # a symlinked (cask) app is still an app
                _collect_bundle(child, ctx, top=True)
        elif depth < max_depth and _is_real_dir(child):
            _walk_apps(child, ctx, depth + 1, max_depth)
    return True


def _launch_stems(directory: Path, ids: set) -> None:
    for child in oc.list_dir(directory) or ():
        if child.suffix == ".plist" and not oc.bad_name(child.name):
            ids.add(child.stem)


def _tool_names(root, homes, ctx: "_Ctx") -> list:
    """Names of command-line tools and Steam games (no bundle id to read)."""
    names: list = []
    dirs = [oc.in_root(root, d) for d in _TOOL_DIRS]
    for h in homes:
        dirs += [h / d for d in _HOME_TOOL_DIRS]
        dirs += [h / d for d in _STEAM_DIRS]
    for d in dirs:
        ctx.check()
        for child in oc.list_dir(d) or ():
            if not oc.bad_name(child.name):
                names.append(child.name)
    for h in homes:
        steam = h / _STEAM_APPS
        for child in oc.list_dir(steam) or ():
            ctx.check()
            if not (child.name.startswith("appmanifest_") and child.suffix == ".acf"):
                continue
            try:
                with open(child, "rb") as fh:
                    text = fh.read(65536).decode("utf-8", "replace")
            except OSError:
                continue
            m = _ACF_NAME.search(text)
            if m:
                names.append(m.group(1))
    return names


def _inventory(root, homes: Iterable[Path], budget=None, *,
               require_mdfind: bool = False) -> Optional[tuple]:
    """``(ids, names_of_apps_without_id)`` or None when the inventory cannot
    be trusted: ``/Applications`` unreadable, fewer than MIN_APPS distinct app
    ids, too many apps with no readable id, or the budget ran out.
    ``require_mdfind`` (the act-time re-check): Spotlight's list of app
    bundles must be available too, else None."""
    homes = [Path(h) for h in homes]
    ctx = _Ctx(budget)
    try:
        apps = oc.in_root(root, "/Applications")
        if not os.path.isdir(apps) or not _walk_apps(apps, ctx, 1, 3):
            return None
        for logical, depth in _APP_ROOTS[1:]:
            _walk_apps(oc.in_root(root, logical), ctx, 1, depth)
        for h in homes:
            _walk_apps(h / "Applications", ctx, 1, 3)
        if len(ctx.top_ids) < MIN_APPS:
            return None
        if len(ctx.noid) > 3 or len(ctx.noid) * 10 > ctx.apps:
            return None

        rc, out, _ = oc.run(
            ["mdfind", "kMDItemContentType == 'com.apple.application-bundle'"]
        )
        if rc != 0 and require_mdfind:
            return None
        if rc == 0:
            for n, line in enumerate(out.splitlines()):
                if n >= MAX_MDFIND_PATHS:
                    break
                ctx.check()
                line = line.strip()
                if not line.endswith(".app") or oc.bad_name(line):
                    continue
                for cand in (oc.in_root(root, line), Path(line)):
                    if os.path.isdir(cand):
                        _collect_bundle(cand, ctx)  # ids only, not counted
                        break

        for h in homes:
            _launch_stems(h / "Library" / "LaunchAgents", ctx.ids)
        for logical in _LAUNCH_DIRS:
            _launch_stems(oc.in_root(root, logical), ctx.ids)

        rc, out, _ = oc.run(["pkgutil", "--pkgs"])
        if rc == 0:
            ctx.ids.update(ln.strip() for ln in out.splitlines() if ln.strip())
        names = _tool_names(root, homes, ctx)
        ctx.check()
    except _Unknown:
        return None
    return ctx.ids, list(ctx.noid) + names


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

    @staticmethod
    def _homes() -> list:
        homes = [home()]
        try:
            homes += [u.home for u in context.get_target_users()]
        except Exception:  # noqa: BLE001 - fall back to the current user
            pass
        return homes

    def _installed(self) -> Optional[_Index]:
        if not self._index_built:
            self._index_built = True
            inv = _inventory(self.sysroot, self._homes(), self.budget)
            self._index = _Index(*inv) if inv is not None else None
        return self._index

    # ------------------------------------------------- act-time re-check
    def still_orphaned(self, real: Path) -> Optional[str]:
        """Why ``real`` (a system-wide finding: an entry directly in one of
        :data:`SYSTEM_DIRS`) must not be removed now, or None when no
        installed app uses its id: the installed-apps inventory is rebuilt
        (Spotlight's list of app bundles required) and the id checked
        exactly as the scan did. An inventory that cannot be built is a
        reason (fail closed)."""
        logical = oc.logical_path(self.sysroot, real)
        parent = logical.rsplit("/", 1)[0]
        if parent not in SYSTEM_DIRS:
            return "it is not in a folder this scenario checks"
        dirs = parent == SYSTEM_DIRS[0]
        name = real.name
        if oc.bad_name(name) or (not dirs and not name.endswith(".plist")):
            return "its name is not a bundle id"
        bid = candidate_id(name)
        if bid is None:
            return "its name is not a bundle id"
        cutoff = time.time() - float(self.config.orphan_min_age_days) * 86400
        try:
            newest = real.lstat().st_mtime
        except OSError:
            return "it cannot be inspected"
        if dirs:
            newest = max(newest, self._newest_child_mtime(real))
        if newest > cutoff:
            return "it changed recently (it may be in use)"
        inv = _inventory(self.sysroot, self._homes(), self.budget, require_mdfind=True)
        if inv is None:
            return "the installed apps could not be listed now"
        if is_excluded(bid, _Index(*inv)):
            return f"an installed app now uses the id {bid}"
        return None

    # ------------------------------------------------------------ discovery
    def system_findings(self) -> Iterable[oc.Finding]:
        if self._installed() is None:
            if self.budget.stop_reason:
                return  # ran out of time listing apps: the stop note says so
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
        for logical, dirs in zip(SYSTEM_DIRS, (True, False)):
            yield from self._scan_dir(oc.in_root(self.sysroot, logical), dirs=dirs, system=True)

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
            if _stat.S_ISLNK(st.st_mode):
                continue
            if _stat.S_ISDIR(st.st_mode) != dirs:
                continue  # Support/Containers: folders only; Preferences: files
            newest = st.st_mtime
            if dirs:
                newest = max(newest, self._newest_child_mtime(child))
            if newest > cutoff:
                continue
            real_logical = oc.logical_path(self.sysroot, child)
            yield oc.Finding(
                child,
                f"Left by a removed app: {bid} ({real_logical})",
                self._hint(bid, real_logical),
                requires_root=system,
                remedy_kind=oc.RemedyKind.PATH,
            )

    def _newest_child_mtime(self, directory: Path) -> float:
        """Newest lstat mtime among up to 20 immediate children."""
        newest = 0.0
        try:
            with os.scandir(directory) as it:
                for n, entry in enumerate(it):
                    if n >= 20 or self.budget.expired():
                        break
                    try:
                        newest = max(newest, entry.stat(follow_symlinks=False).st_mtime)
                    except OSError:
                        continue
        except OSError:
            pass
        return newest

    @staticmethod
    def _hint(bid: str, logical: str) -> str:
        return (
            f"No installed app uses the id {bid}. Check with: "
            f"mdfind \"kMDItemCFBundleIdentifier == '{bid}'\" "
            "(no result means it is not installed). Command-line tools have no "
            "bundle id and are not found by mdfind; do not remove it if you "
            "installed such a tool. "
            f"If you no longer need it, move {shlex.quote(logical)} "
            "to the Trash in Finder."
        )


def reverify_system_item(path: str, config) -> Optional[str]:
    """Act-time re-check of one system-wide finding (``reverify`` table)."""
    reporter = OrphanAppDataReporter(config)
    reporter.budget.start()
    return reporter.still_orphaned(Path(path))
