"""Curation layer: plain-language copy, safety levels and result grouping.

Pure logic (no Qt, no I/O). Front-ends use it to present scan results as a
short list of understandable groups instead of thousands of raw paths.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Mapping, Optional

from cleanix.core.catalog import CleanerInfo, category_of
from cleanix.core.models import CleanableItem, ItemKind, ScanResult


class Safety(str, Enum):
    SAFE = "Safe"
    REVIEW = "Review"
    ADMIN = "Needs admin"
    PERMANENT = "Permanent"


# Higher rank = more restrictive.
_RANK = {Safety.SAFE: 0, Safety.REVIEW: 1, Safety.ADMIN: 2, Safety.PERMANENT: 3}


@dataclass(frozen=True)
class Copy:
    title: str
    blurb: str


_REVIEW_TAIL = "You decide; Cleanix will not delete it."

_RAW = {
    # --- temporary files / litter
    "temp": ("Temporary files", "Stale scratch files apps left behind. Removed safely; apps recreate what they need."),
    "win_temp": ("Temporary files", "Stale scratch files in your user temp folder. Removed safely; apps recreate what they need."),
    "broken_symlinks": ("Broken shortcuts", "Links pointing at files that no longer exist. Removing them has no effect on working software."),
    "apple_litter": ("macOS metadata litter", "Hidden .DS_Store and ._ files from macOS. Removed safely; Finder recreates them."),
    "home_coredumps": ("Crash dump files", "Core files from crashed programs in your home folder. Only useful for debugging; removing them is safe."),
    "build_litter": ("Build and test leftovers", "Python and tool cache folders in your projects. Rebuilt automatically on the next run."),
    "macos_diagnostics": ("Mac logs and crash reports", "Diagnostic logs from apps. Removing them loses only troubleshooting history."),
    # --- browsers
    "browsers": ("Browser caches", "Saved web pages and images that speed up browsing. Rebuilt as you browse; sites may load slower once."),
    "win_browser_cache": ("Browser caches", "Cached web content for Chrome, Edge, Brave and Firefox. Rebuilt as you browse; sites may load slower once."),
    # --- developer
    "dev_caches": ("Developer tool caches", "Downloads cached by cargo, go, gradle and similar tools. Fetched again when a build needs them."),
    "pip_cache": ("Python package cache", "Downloaded Python packages kept for reuse. Downloaded again when needed."),
    "npm_cache": ("JavaScript package caches", "Packages cached by npm and yarn. Downloaded again when needed."),
    "lang_caches": ("Language package caches", "Re-downloadable modules for Go, Rust, .NET and others. Fetched again when a build needs them."),
    "win_pkg_caches": ("Package manager downloads", "Installers cached by WinGet, Chocolatey, Scoop and NuGet. Downloaded again when needed."),
    "win_visualstudio": ("Visual Studio caches", "Component cache for Visual Studio. Rebuilt on the next launch, which may start slower."),
    "jetbrains": ("JetBrains IDE caches", "Caches and indexes for IntelliJ, PyCharm and friends. Rebuilt on next launch; the first start is slower."),
    "toolchains": ("Old toolchain versions", "Superseded rustup, nvm, pyenv and similar versions. Removed permanently; projects pinned to an old version must reinstall it."),
    "guix": ("Guix unused packages", "Unreferenced Guix store items and old generations. Removed permanently; rollbacks to them are lost."),
    "conda": ("Conda package caches", "Unused conda packages and downloads. Downloaded again when needed."),
    "opam": ("OCaml package cache", "Downloads and build logs from OPAM. Fetched again when needed."),
    "sdkman": ("SDKMAN downloads", "Archives of SDKs you already installed. Downloaded again if you reinstall one."),
    "gem": ("Old Ruby gem versions", "Superseded versions of installed gems. Removed permanently; projects pinned to them must reinstall."),
    "cpanm": ("Perl build leftovers", "Work folders from cpanm builds. Recreated on the next install."),
    "ollama": ("Ollama leftover model data", "Incomplete model downloads and logs. Your installed models are kept."),
    "huggingface": ("Hugging Face download junk", "Unfinished downloads and stale locks. Your downloaded models are kept."),
    "ai_compile_cache": ("AI compiled kernel caches", "Compiled GPU kernels from Triton, torch and vLLM. Rebuilt on next use; the first run is slower."),
    "vm_tooling": ("VM and cloud tool caches", "Logs and caches from VirtualBox, Vagrant, Kubernetes and cloud CLIs. Rebuilt or downloaded again when used."),
    "ide_caches": ("Editor caches and logs", "Logs and caches from VS Code, Sublime, Zed and similar editors. Rebuilt automatically."),
    "xcode": ("Xcode build caches", "DerivedData, archives and simulator caches. Rebuilt on the next build; old archives are lost."),
    # --- apps
    "user_cache": ("App caches", "Temporary data apps keep under ~/.cache. Rebuilt as apps run; they may start slower once."),
    "thumbnails": ("Image thumbnails", "Small previews of pictures and videos. Regenerated when you open the folder again."),
    "win_thumbnails": ("Thumbnail and icon caches", "Explorer previews and icon cache. Rebuilt automatically; folders may draw slower once."),
    "win_error_reports": ("Error reports", "Windows crash reports and dumps from your apps. Removing them loses only troubleshooting data."),
    "electron_cache": ("Desktop app caches", "Rebuildable caches from Electron apps such as chat and editor apps. Recreated automatically."),
    "gpu_shader_cache": ("Graphics shader caches", "Compiled graphics shaders. Rebuilt automatically; the first game launch may be slower."),
    "win_shader_cache": ("Graphics shader caches", "Compiled DirectX, NVIDIA and AMD shaders. Rebuilt automatically; the first game launch may be slower."),
    "font_cache": ("Font cache", "Fontconfig lookup data. Rebuilt automatically the next time a program needs fonts."),
    "flatpak_cache": ("Flatpak app caches", "Per-app cache folders of Flatpak apps. Recreated as the apps run."),
    "steam": ("Steam caches", "Shader, partial-download and web caches. Rebuilt or downloaded again; games are kept."),
    "search_index": ("Desktop search indexes", "Baloo, Tracker and similar search data. Rebuilt in the background; search is incomplete meanwhile."),
    "snap_app_cache": ("Snap app caches", "Cache folders inside your snap app data. Recreated as the apps run."),
    "appimage": ("AppImage menu leftovers", "Menu entries and icons of AppImages you removed. Only dead launchers disappear."),
    "macos_extra": ("Mac saved states and caches", "Saved app state (apps reopen without their windows), CocoaPods, Carthage and QuickLook caches. The caches are rebuilt automatically."),
    "macos_containers": ("Mac sandboxed app caches", "Caches inside app containers. Recreated as apps run."),
    "macos_font_cache": ("Mac font caches", "Font registration caches. Rebuilt automatically after a restart."),
    "macos_caches": ("Mac app caches", "Application caches in ~/Library/Caches. Rebuilt as apps run; they may start slower once."),
    # --- trash
    "trash": ("Trash", "Files you already deleted and not yet emptied. Removed permanently; you cannot restore them afterwards."),
    "macos_trash": ("Trash", "Files you already deleted and not yet emptied. Removed permanently; you cannot restore them afterwards."),
    "win_recycle_bin": ("Recycle Bin", "Files you already deleted on all drives. Removed permanently; you cannot restore them afterwards."),
    # --- backups and tool leftovers
    "claude_code": ("Claude Code leftovers", "Old backups, transcripts and debug logs. Past session history is lost; settings are kept."),
    "codex": ("Codex CLI leftovers", "Old session rollouts and logs. Past session history is lost; settings are kept."),
    "gemini_cli": ("Gemini CLI leftovers", "Old per-project session and log data. Past session history is lost; settings are kept."),
    "opencode": ("OpenCode leftovers", "Logs, snapshots and tool output. Your database and sign-in are kept."),
    "ai_clients": ("AI app leftovers", "Logs and rebuildable indexes of LM Studio, Jan, Continue and Claude apps. Indexes are rebuilt on demand; old logs are lost."),
    "aider": ("Aider leftovers", "Stray .aider history and cache files in projects. Chat history in them is lost."),
    "app_leftovers": ("App logs and leftovers", "Logs, crash reports and temp data from desktop apps. Removing them loses only history."),
    "backup_files": ("Editor backup files", "Files ending in ~, .orig, .bak or .rej. These may be your only old copy of something; opt-in."),
    "backup_caches": ("Backup tool caches", "Caches of borg, restic and rclone, not your backups. Rebuilt on the next backup run."),
    "editor_state": ("Editor swap and undo files", "Vim and Neovim swap, undo and backup state. Unsaved recovery data and persistent undo history are lost."),
    # --- system (admin) and package managers
    "docker": ("Docker leftovers", "Dangling images, stopped containers and build cache. Removed permanently; data inside stopped containers is lost, and other settings may also remove unused volumes."),
    "podman": ("Podman leftovers", "Dangling images, stopped containers and build cache. Removed permanently; data inside stopped containers is lost, and other settings may also remove unused volumes."),
    "nerdctl": ("containerd leftovers", "Dangling images, stopped containers and build cache. Removed permanently; data inside stopped containers is lost, and other settings may also remove unused volumes."),
    "crictl": ("Unused container images", "Images no pod references. Removed permanently; they are pulled again when needed."),
    "logs": ("Old system logs", "Rotated and compressed logs in /var/log. Only older troubleshooting history is lost."),
    "journal": ("System journal history", "Old systemd journal entries above the size cap. Older history is lost."),
    "coredumps": ("System crash dumps", "Crash dumps kept by systemd-coredump. Only useful for debugging."),
    "crash_reports": ("System crash reports", "Application crash dumps in /var/crash. Only useful for debugging."),
    "config_leftovers": ("Package update leftovers", "Old .rpmnew, .pacnew and .dpkg-old files. Review any you edited before removal."),
    "apt": ("APT cache and unused packages", "Downloaded .deb files and orphaned dependencies. Downloaded again when needed."),
    "dnf": ("DNF cache and unused packages", "Cached metadata and orphaned dependencies. Downloaded again when needed."),
    "pacman": ("Pacman cache and orphans", "Cached package files and orphaned packages. Downloaded again when needed; old versions lose rollback."),
    "zypper": ("Zypper package cache", "Cached RPMs and metadata. Downloaded again when needed."),
    "apk": ("apk package cache", "Cached Alpine packages. Downloaded again when needed."),
    "xbps": ("XBPS cache and orphans", "Cached packages and orphaned dependencies on Void. Downloaded again when needed."),
    "portage": ("Portage source archives", "Stale source tarballs and binary packages. Downloaded again when needed."),
    "eopkg": ("Solus package cache", "Cached packages and orphaned dependencies. Downloaded again when needed."),
    "swupd": ("Clear Linux update cache", "Cached update bundles. Downloaded again when needed."),
    "flatpak": ("Unused Flatpak runtimes", "Runtimes no app needs any more. Removed permanently; reinstalled automatically if an app needs one."),
    "snap": ("Old Snap versions", "Disabled older revisions of snap apps. Removed permanently; you lose rollback to them."),
    "nix_gc": ("Nix unused packages", "Old generations and unreferenced Nix store paths. Removed permanently; rollbacks to them are lost."),
    "homebrew": ("Homebrew old versions", "Old formula versions and downloads. Removed permanently; downloaded again if needed."),
    "macports": ("MacPorts leftovers", "Inactive ports and build leftovers. Removed permanently; rebuilt if needed."),
    "pkg": ("FreeBSD package cache", "Cached packages and orphaned dependencies. Downloaded again when needed."),
    "bsd_distfiles": ("BSD ports downloads", "Source tarballs and stale build folders. Downloaded again when needed."),
    "pkgin": ("pkgin package cache", "Cached NetBSD binary packages. Downloaded again when needed."),
    "memory": ("Reclaim memory cache", "Frees reclaimable RAM cache. Nothing is deleted; apps may re-read files slightly slower."),
    "swap": ("Empty swap space", "Moves swapped data back into RAM. Nothing is deleted; the system may pause briefly."),
    "memory_macos": ("Free inactive memory", "Runs the Apple purge tool on inactive memory. Nothing is deleted; apps may reload slightly slower."),
    "system_cache": ("System caches", "Regenerable PackageKit, man page and printer caches. Rebuilt automatically; removed with administrator permission, so it cannot be undone."),
    "var_backups": ("Debian package status backups", "Rotated dpkg and apt status backups. Only older recovery copies are lost."),
    "crash_spool": ("Queued crash reports", "Reports waiting in the ABRT or apport spool. Only useful for debugging."),
    "offline_updates": ("Downloaded offline updates", "Packages staged for an offline upgrade. Downloaded again when you upgrade."),
    "old_kernels": ("Old kernels", "Superseded kernel packages; the running and newest ones are kept. Removed permanently; you lose fallback to them."),
    "localepurge": ("Unused languages", "Translations for languages you do not use. Removed permanently; reinstall a package to restore them."),
    "macos_system_cache": ("Mac system caches", "Regenerable caches in /Library/Caches. Rebuilt automatically; removed with administrator permission, so it cannot be undone."),
    "win_system_temp": ("System temporary files", "Stale files in the Windows temp folder. Removed with administrator permission and cannot be undone; Windows recreates what it needs."),
    "win_update_cache": ("Windows Update downloads", "Downloaded update files and delivery cache. Downloaded again if needed."),
    "win_system_dumps": ("System crash dumps", "Memory dumps and queued error reports. Only useful for debugging."),
    "win_component_store": ("Old Windows components", "Superseded Windows components removed with DISM. Permanent; you lose uninstall of older updates."),
    # --- review only (never deleted by Cleanix)
    "big_files": ("Largest files", "The biggest files in your home folder. " + _REVIEW_TAIL),
    "downloads": ("Old downloads", "Large old files in Downloads. " + _REVIEW_TAIL),
    "duplicates": ("Duplicate files", "Identical large files in your home folder. " + _REVIEW_TAIL),
    "project_cruft": ("Stale project folders", "Build or dependency folders in untouched projects. " + _REVIEW_TAIL),
    "browser_profiles": ("Unused browser profiles", "Old or secondary browser profiles. " + _REVIEW_TAIL),
    "win_prefetch": ("Prefetch data", "Windows startup-speed hints. " + _REVIEW_TAIL),
    "win_windows_old": ("Previous Windows installation", "Windows.old left after an upgrade. " + _REVIEW_TAIL),
    "wsl_disk": ("WSL virtual disks", "Disk images of WSL and Docker Desktop. " + _REVIEW_TAIL),
    "snapshots": ("System snapshots", "Timeshift, Snapper and btrfs snapshots. " + _REVIEW_TAIL),
    "time_machine": ("Time Machine local snapshots", "Local Time Machine snapshots. " + _REVIEW_TAIL),
    "device_backups": ("Phone and tablet backups", "iOS and Android device backups, often irreplaceable. " + _REVIEW_TAIL),
    "libvirt_saves": ("Saved virtual machine states", "Suspended VM memory images with real state. " + _REVIEW_TAIL),
    "macos_sleepimage": ("Mac sleep image", "Hibernation file recreated by macOS. " + _REVIEW_TAIL),
    "orphan_files": ("Files not from any package", "Folders in /opt, /usr/local, /var/lib and /var/cache that no installed package owns (may be a false positive; confirm with your package manager before removing). " + _REVIEW_TAIL),
    "stale_services": ("Services for removed programs", "Startup services whose program or unit file is gone (may be a false positive; confirm with your package manager before removing). " + _REVIEW_TAIL),
    "stale_launchers": ("Menu entries for removed programs", "App menu and autostart entries whose program is missing (may be a false positive; confirm with your package manager before removing). " + _REVIEW_TAIL),
    "stale_alternatives": ("Broken default-program links", "System default-program links that point at removed programs (may be a false positive; confirm with your package manager before removing). " + _REVIEW_TAIL),
    "orphan_launch_jobs": ("Background jobs of removed apps", "Mac launch agents and daemons whose program is gone (may be a false positive; confirm with your package manager before removing). " + _REVIEW_TAIL),
    "orphan_app_data": ("Data of removed apps", "Settings and data left by Mac apps that are no longer installed (may be a false positive; confirm with your package manager before removing). " + _REVIEW_TAIL),
    "stale_receipts": ("Install records of removed packages", "Mac installer receipts whose files are all gone (may be a false positive; confirm with your package manager before removing). " + _REVIEW_TAIL),
}

COPY: Dict[str, Copy] = {k: Copy(*v) for k, v in _RAW.items()}


def copy_for(cleaner_id: str, name: str, description: str) -> Copy:
    """Curated copy for a cleaner id, or its own name/description."""
    return COPY.get(cleaner_id) or Copy(name, description)


def safety_of(item: CleanableItem, info: Optional[CleanerInfo]) -> Safety:
    if info is None:
        return Safety.REVIEW
    if item.report_only:
        return Safety.REVIEW
    if item.requires_root:
        return Safety.ADMIN
    if item.kind is ItemKind.COMMAND:
        return Safety.PERMANENT
    return Safety.SAFE if info.safe_default else Safety.REVIEW


def _is_windowsy(*paths: str) -> bool:
    return any("\\" in p or re.match(r"^[A-Za-z]:", p) for p in paths)


def shorten_path(path: str, home: Optional[str]) -> str:
    """Replace a leading ``home`` on a path-component boundary with ``~``."""
    if not home:
        return path
    win = _is_windowsy(path, home)
    seps = "\\/" if win else "/"
    h = home.rstrip(seps) or home
    if not h or len(path) < len(h):
        return path
    head, rest = path[: len(h)], path[len(h):]
    same = head.lower() == h.lower() if win else head == h
    if not same or (rest and rest[0] not in seps):
        return path
    return "~" + rest


_PREFIX = re.compile(r"^[^:\n]{1,40}:\s+")


def display_label(item: CleanableItem, home: Optional[str]) -> str:
    """Short row label: description minus a redundant ``Name: `` prefix."""
    if item.kind is ItemKind.COMMAND:
        return " ".join(item.command or [])
    desc = item.description or ""
    m = _PREFIX.match(desc)
    cleaned = desc[m.end():].strip() if m else desc.strip()
    if cleaned:
        return cleaned
    if item.path:
        return shorten_path(item.path, home)
    return desc


@dataclass
class Group:
    cleaner_id: str
    title: str
    blurb: str
    category: str
    safety: Safety
    items: List[CleanableItem] = field(default_factory=list)
    shown: List[CleanableItem] = field(default_factory=list)
    rest: List[CleanableItem] = field(default_factory=list)
    zero: List[CleanableItem] = field(default_factory=list)
    total_size: int = 0

    @property
    def rest_size(self) -> int:
        return sum(i.size for i in self.rest)

    @property
    def item_count(self) -> int:
        return len(self.items)


def is_empty(item: CleanableItem) -> bool:
    """True for items with nothing to show. A COMMAND item's size is unknown
    (best effort, often 0), so it is never treated as empty. A report-only
    finding or "not checked" note legitimately has size 0 and must stay
    visible (it can never be selected for deletion anyway)."""
    return (item.size <= 0 and item.kind is not ItemKind.COMMAND
            and not item.report_only)


def build_groups(
    result: ScanResult,
    infos: Mapping[str, CleanerInfo],
    *,
    top_n: int = 15,
    show_empty: bool = False,
) -> List[Group]:
    """One group per cleaner report with items, biggest first."""
    groups: List[Group] = []
    for rep in result.reports:
        if not rep.items:
            continue
        items = sorted(rep.items, key=lambda i: -i.size)
        nonzero = [i for i in items if not is_empty(i)]
        zero = [i for i in items if is_empty(i)]
        if not nonzero and not show_empty:
            continue
        info = infos.get(rep.cleaner_id)
        cp = copy_for(rep.cleaner_id, rep.name, rep.description)
        safety = max((safety_of(i, info) for i in items), key=_RANK.__getitem__)
        groups.append(
            Group(
                cleaner_id=rep.cleaner_id,
                title=cp.title,
                blurb=cp.blurb,
                category=info.category if info else category_of(rep.cleaner_id),
                safety=safety,
                items=items,
                shown=nonzero[:top_n],
                rest=nonzero[top_n:],
                zero=zero,
                total_size=sum(i.size for i in items),
            )
        )
    groups.sort(key=lambda g: -g.total_size)
    return groups
