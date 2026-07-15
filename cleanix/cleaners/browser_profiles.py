"""Orphaned / secondary browser profiles and heavy rebuildable profile subdirs.

This cleaner is **report-only** by design: it never yields a deletable item.
Deleting the wrong browser profile is data loss — a profile holds the user's
bookmarks, saved passwords, history and open tabs — so cleanix only *surfaces*
candidates (with sizes and removal guidance) and leaves the decision to the
user.

It deliberately covers what the browser *cache* cleaner
(:mod:`cleanix.cleaners.browsers`) does not:

* whole **non-default profiles** that look abandoned (no activity for
  ``browser_profile_stale_days`` days);
* a handful of heavy, rebuildable per-profile subdirs the cache cleaner leaves
  alone — ``Crash Reports``, ``GrShaderCache``, ``Service Worker/CacheStorage``,
  session-restore backups and ``Old Data`` — surfaced report-only.

Both Linux/XDG and macOS layouts are handled; paths are resolved per-OS.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Iterable, Optional, Tuple

from cleanix.cleaners.base import Cleaner
from cleanix.core.models import CleanableItem
from cleanix.core.platform import ALL, is_macos
from cleanix.core.utils import home, human_size, iter_children, path_size

# Upper bound on how many items we surface, so a machine with dozens of profiles
# cannot flood the report.
_MAX_ITEMS = 200

# Heavy, rebuildable per-profile subdirs the cache cleaner does NOT cover.
# Reported (never deleted) so the user can reclaim space knowingly. Each entry
# is (relative path components, human label).
_CHROMIUM_HEAVY_SUBDIRS: Tuple[Tuple[Tuple[str, ...], str], ...] = (
    (("Crash Reports",), "crash reports"),
    (("GrShaderCache",), "GPU shader cache"),
    (("Service Worker", "CacheStorage"), "service-worker CacheStorage"),
    (("Sessions",), "session-restore backups"),
    (("Old Data",), "old profile data"),
)


def _dir_is_symlink(p: Path) -> bool:
    try:
        return p.is_symlink()
    except OSError:
        return True


def _mtime(p: Path) -> float:
    """lstat mtime of ``p`` (0.0 if it cannot be read)."""
    try:
        return os.lstat(p).st_mtime
    except OSError:
        return 0.0


def _last_activity(profile: Path) -> float:
    """Best-effort "last used" timestamp for a chromium/firefox profile.

    Uses the newest of the profile directory's own mtime and the mtime of the
    file that the browser touches on virtually every navigation (Chromium's
    ``History`` SQLite db, or Firefox's ``places.sqlite``). This is a far better
    activity signal than the directory mtime alone.
    """
    newest = _mtime(profile)
    for marker in ("History", "places.sqlite"):
        m = _mtime(profile / marker)
        if m > newest:
            newest = m
    return newest


def _idle_days(profile: Path) -> Optional[float]:
    """Days since the profile was last active, or ``None`` if unknown."""
    ts = _last_activity(profile)
    if ts <= 0:
        return None
    return max(0.0, (time.time() - ts) / 86400.0)


class BrowserProfileReporter(Cleaner):
    id = "browser_profiles"
    name = "Orphaned browser profiles"
    description = (
        "Stale/secondary browser profiles & heavy profile subdirs (report only)"
    )
    requires_root = False
    # Applies everywhere; per-OS paths are resolved inside find_items().
    platforms = (ALL,)

    # -- support-dir discovery ----------------------------------------------
    def _chromium_roots(self) -> Iterable[Tuple[str, Path]]:
        """Yield (browser label, support dir) for installed chromium browsers."""
        h = home()
        if is_macos():
            appsup = h / "Library" / "Application Support"
            candidates = [
                ("Chrome", appsup / "Google" / "Chrome"),
                ("Chromium", appsup / "Chromium"),
                ("Edge", appsup / "Microsoft Edge"),
                ("Brave", appsup / "BraveSoftware" / "Brave-Browser"),
            ]
        else:
            cfg = h / ".config"
            candidates = [
                ("Chrome", cfg / "google-chrome"),
                ("Chromium", cfg / "chromium"),
                ("Edge", cfg / "microsoft-edge"),
                ("Brave", cfg / "BraveSoftware" / "Brave-Browser"),
            ]
        for label, root in candidates:
            try:
                if root.is_dir() and not _dir_is_symlink(root):
                    yield label, root
            except OSError:
                continue

    def _firefox_roots(self) -> Iterable[Path]:
        h = home()
        if is_macos():
            root = h / "Library" / "Application Support" / "Firefox"
        else:
            root = h / ".mozilla" / "firefox"
        try:
            if root.is_dir() and not _dir_is_symlink(root):
                yield root
        except OSError:
            return

    # -- chromium ------------------------------------------------------------
    def _is_profile_dir(self, child: Path) -> bool:
        name = child.name
        return name == "Default" or name.startswith("Profile ")

    def _chromium_items(self) -> Iterable[CleanableItem]:
        stale_days = float(getattr(self.config, "browser_profile_stale_days", 90.0))
        for label, root in self._chromium_roots():
            for child in iter_children(root):
                try:
                    if not child.is_dir() or _dir_is_symlink(child):
                        continue
                except OSError:
                    continue
                if not self._is_profile_dir(child):
                    continue

                idle = _idle_days(child)
                # Only surface a profile that looks abandoned. The Default /
                # active profile is only surfaced if it, too, is stale.
                if idle is not None and idle >= stale_days:
                    size = path_size(child)
                    if size > 0:
                        item = self.report_item(
                            child,
                            f"Possibly-orphaned {label} profile '{child.name}' "
                            f"({human_size(size)}, {int(idle)}d idle)",
                            hint=(
                                "CONTAINS BOOKMARKS, SAVED PASSWORDS & HISTORY — "
                                "do not delete blindly. If you no longer use it, "
                                f"remove it from {label}'s profile manager "
                                "(Settings -> profiles / the people icon), which "
                                "safely detaches and deletes the profile."
                            ),
                        )
                        if item:
                            yield item

                # Heavy rebuildable subdirs the cache cleaner does not touch.
                for parts, sublabel in _CHROMIUM_HEAVY_SUBDIRS:
                    target = child.joinpath(*parts)
                    try:
                        if not target.is_dir() or _dir_is_symlink(target):
                            continue
                    except OSError:
                        continue
                    if path_size(target) <= 0:
                        continue
                    item = self.report_item(
                        target,
                        f"{label} {child.name}: {sublabel} "
                        f"({human_size(path_size(target))})",
                        hint=(
                            "Rebuildable by the browser, but not cleared by the "
                            "cache cleaner. Safe to remove while the browser is "
                            "closed; it will be regenerated on next launch."
                        ),
                    )
                    if item:
                        yield item

    # -- firefox -------------------------------------------------------------
    def _firefox_default_names(self, root: Path) -> set:
        """Profile dir names that profiles.ini marks as default/active.

        Parsed leniently: any ``Path=`` under a section whose ``Default=1`` (or
        any ``[Install...]`` default) is treated as an active profile to skip.
        Returns the set of directory *names* (basename of the Path=value).
        """
        ini = root / "profiles.ini"
        names: set = set()
        try:
            if not ini.is_file():
                return names
            text = ini.read_text(errors="replace")
        except OSError:
            return names

        section_path: Optional[str] = None
        section_is_default = False

        def _flush():
            if section_path and section_is_default:
                names.add(Path(section_path).name)

        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith("[") and line.endswith("]"):
                _flush()
                header = line[1:-1]
                # [Install...] sections point at the active profile via Default=.
                section_path = None
                section_is_default = header.startswith("Install")
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key == "Path":
                section_path = value
            elif key == "Default":
                if section_path is None:
                    # [InstallXXX] Default=<path to active profile>
                    if value:
                        names.add(Path(value).name)
                elif value == "1":
                    section_is_default = True
        _flush()
        return names

    def _firefox_items(self) -> Iterable[CleanableItem]:
        stale_days = float(getattr(self.config, "browser_profile_stale_days", 90.0))
        for root in self._firefox_roots():
            defaults = self._firefox_default_names(root)
            for child in iter_children(root):
                try:
                    if not child.is_dir() or _dir_is_symlink(child):
                        continue
                except OSError:
                    continue
                name = child.name
                # Firefox profiles are "<random>.<name>"; skip infra dirs.
                if "." not in name or name in ("Crash Reports", "Pending Pings"):
                    continue
                if name in defaults:
                    continue  # never surface the active/default profile

                idle = _idle_days(child)
                if idle is None or idle < stale_days:
                    continue
                size = path_size(child)
                if size <= 0:
                    continue
                item = self.report_item(
                    child,
                    f"Possibly-orphaned Firefox profile '{name}' "
                    f"({human_size(size)}, {int(idle)}d idle)",
                    hint=(
                        "CONTAINS BOOKMARKS, SAVED PASSWORDS & HISTORY — do not "
                        "delete blindly. If unused, remove it via "
                        "about:profiles or the Profile Manager "
                        "(firefox -P) which deletes it safely."
                    ),
                )
                if item:
                    yield item

                # Session-restore backups: heavy, rebuildable, not a cache dir.
                sessions = child / "sessionstore-backups"
                try:
                    heavy = sessions.is_dir() and not _dir_is_symlink(sessions)
                except OSError:
                    heavy = False
                if heavy and path_size(sessions) > 0:
                    sitem = self.report_item(
                        sessions,
                        f"Firefox {name}: session-restore backups "
                        f"({human_size(path_size(sessions))})",
                        hint=(
                            "Recovery copies of previous tab sessions. Removing "
                            "them (browser closed) only drops the ability to "
                            "restore old windows; not covered by the cache cleaner."
                        ),
                    )
                    if sitem:
                        yield sitem

    # -- entry point ---------------------------------------------------------
    def find_items(self) -> Iterable[CleanableItem]:
        count = 0
        try:
            producers = (self._chromium_items(), self._firefox_items())
        except Exception:  # noqa: BLE001 - defensive
            return
        for producer in producers:
            for item in producer:
                if item is None:
                    continue
                yield item
                count += 1
                if count >= _MAX_ITEMS:
                    return
