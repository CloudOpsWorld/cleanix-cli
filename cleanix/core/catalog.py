"""Cleaner catalog for front-ends: categories and the pre-selection rule.

Pure data and policy; performs no I/O. The GUI uses it to group cleaners and
to decide which items Simple mode may pre-select.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from cleanix.cleaners.base import Cleaner
from cleanix.config import Config
from cleanix.core import registry
from cleanix.core.models import CleanableItem, ItemKind

CATEGORIES: Dict[str, str] = {
    "temp": "Temporary files",
    "browser": "Browser caches",
    "dev": "Developer caches",
    "apps": "App caches",
    "trash": "Trash / Recycle Bin",
    "system": "System files (administrator)",
    "review": "Needs your review",
    "backups": "Backups & leftovers",
    "registry": "Registry leftovers",
    "other": "Other",
}

# Cleaners excluded from the default (fast) scan; Simple's "Deep scan" opts in.
SLOW_SCAN_IDS = ("duplicates", "big_files", "downloads")

# Categories whose items are never pre-selected, whatever the cleaner says.
_NEVER_PRESELECT = frozenset(
    {"trash", "system", "review", "backups", "registry", "other"}
)

# Windows registry detectors: the single definition used by the CLI and helper.
REGISTRY_IDS: Tuple[str, ...] = (
    "win_reg_uninstall",
    "win_reg_app_paths",
    "win_reg_file_assoc",
    "win_reg_startup",
    "win_reg_shared_dlls",
)

_CATEGORY_BY_ID: Dict[str, str] = {}


def _assign(category: str, ids: str) -> None:
    for cid in ids.split():
        _CATEGORY_BY_ID[cid] = category


_assign("temp", "temp win_temp")
_assign("browser", "browsers win_browser_cache")
_assign(
    "dev",
    "dev_caches pip_cache npm_cache lang_caches win_pkg_caches "
    "win_visualstudio jetbrains",
)
_assign(
    "apps",
    "user_cache thumbnails win_thumbnails win_error_reports electron_cache "
    "gpu_shader_cache win_shader_cache",
)
_assign(
    "temp",
    "broken_symlinks apple_litter home_coredumps build_litter macos_diagnostics",
)
_assign(
    "dev",
    "toolchains guix conda opam sdkman gem cpanm ollama huggingface "
    "ai_compile_cache vm_tooling ide_caches xcode",
)
_assign(
    "apps",
    "font_cache flatpak_cache steam search_index snap_app_cache appimage "
    "macos_extra macos_containers macos_font_cache macos_caches",
)
# Tool leftovers, session/history data and backup-style litter.
_assign(
    "backups",
    "claude_code codex gemini_cli opencode ai_clients aider app_leftovers "
    "backup_files backup_caches editor_state",
)
_assign("trash", "trash macos_trash win_recycle_bin")
# Report-only cleaners (never deletes; user reviews manually). These win over
# "system" even when they need root to read.
_assign(
    "review",
    "big_files downloads duplicates project_cruft browser_profiles "
    "win_prefetch win_windows_old wsl_disk snapshots time_machine "
    "device_backups libvirt_saves macos_sleepimage",
)
# Administrator / system-wide cleaners and package managers.
_assign(
    "system",
    "docker podman nerdctl crictl logs journal coredumps crash_reports "
    "config_leftovers apt dnf pacman zypper apk xbps portage eopkg swupd "
    "flatpak snap nix_gc homebrew macports pkg pkgin bsd_distfiles "
    "memory swap memory_macos system_cache var_backups crash_spool "
    "offline_updates old_kernels localepurge macos_system_cache "
    "win_system_temp win_update_cache win_system_dumps win_component_store",
)
_assign("registry", " ".join(REGISTRY_IDS))


def category_of(cleaner_id: str) -> str:
    """Category id for a cleaner id; unknown ids are ``"other"``."""
    return _CATEGORY_BY_ID.get(cleaner_id, "other")


@dataclass(frozen=True)
class CleanerInfo:
    id: str
    name: str
    description: str
    requires_root: bool
    platforms: tuple
    supported: bool
    default_enabled: bool
    safe_default: bool
    category: str


def _info_for(cleaner: Cleaner) -> CleanerInfo:
    return CleanerInfo(
        id=cleaner.id,
        name=cleaner.name,
        description=cleaner.description,
        requires_root=cleaner.requires_root,
        platforms=tuple(cleaner.platforms),
        supported=cleaner.supported(),
        default_enabled=cleaner.default_enabled,
        safe_default=cleaner.safe_default,
        category=category_of(cleaner.id),
    )


def list_cleaners(
    config: Config, *, include_unsupported: bool = False
) -> List[CleanerInfo]:
    """Describe every registered cleaner, in registry order."""
    infos = [_info_for(c) for c in registry.describe_all(config).values()]
    if not include_unsupported:
        infos = [i for i in infos if i.supported]
    return infos


def preselect(item: CleanableItem, info: CleanerInfo) -> bool:
    """True if Simple mode may pre-select ``item``.

    Only reviewed-safe cleaners, plain deletable user-owned PATH items, and
    never Trash/system/review/other categories.
    """
    return (
        info.safe_default
        and not item.report_only
        and not item.requires_root
        and item.kind is ItemKind.PATH
        and info.category not in _NEVER_PRESELECT
    )
