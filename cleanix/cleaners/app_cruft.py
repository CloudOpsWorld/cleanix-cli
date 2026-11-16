"""Bloat that miscellaneous desktop apps scatter across the home directory.

Electron apps in particular drop rebuildable HTTP/GPU/code caches into their
config dirs; GPU drivers, Steam, and JetBrains IDEs keep large regenerable
caches. We only ever touch caches that the app recreates on demand — never
session/login stores (Local Storage, IndexedDB, Service Worker, cookies).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from cleanix.cleaners.base import Cleaner
from cleanix.core.models import CleanableItem
from cleanix.core import platform, winenv
from cleanix.core.platform import LINUX, MACOS, WINDOWS, XDG_PLATFORMS
from cleanix.core.utils import config_dir
from cleanix.core.utils import home, iter_children, path_size

# Electron/Chromium cache subdirs that are always safe to delete — the runtime
# rebuilds them. Deliberately EXCLUDES Service Worker, IndexedDB, Local/Session
# Storage, Cookies and other persistent site/session data.
_SAFE_ELECTRON_CACHES = (
    "Cache",
    "Code Cache",
    "GPUCache",
    "CachedData",
    "DawnCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "GrShaderCache",
    "ShaderCache",
    "component_crx_cache",
    "Crashpad",
    "blob_storage",
)

# Browser config dirs are owned by the dedicated browser cleaner; skip them here
# to avoid offering the same cache twice.
_SKIP_APPS = {
    "google-chrome", "chromium", "BraveSoftware", "vivaldi",
    "microsoft-edge", "opera", "google-chrome-beta", "chromium-dev",
}

# Windows Roaming dirs owned by browsers (compared case-insensitively).
_WIN_SKIP_APPS = {"bravesoftware", "opera software", "mozilla", "microsoft"}


class ElectronCacheCleaner(Cleaner):
    id = "electron_cache"
    name = "Electron/Chromium app caches"
    description = "Rebuildable Cache/GPUCache/Code Cache from Electron apps"
    requires_root = False
    platforms = (*XDG_PLATFORMS, WINDOWS)

    def _config_roots(self) -> Iterable[Path]:
        if platform.is_windows():
            roaming = winenv.roaming_appdata()
            if roaming.is_dir():
                for app in iter_children(roaming):
                    low = app.name.lower()
                    if low == "microsoft":
                        # Roaming\Microsoft holds Office/Windows state (and
                        # Edge); only classic Teams is an Electron app here.
                        for sub in iter_children(app):
                            if sub.name.lower() == "teams" and sub.is_dir():
                                yield sub
                        continue
                    if (
                        app.is_dir()
                        and low not in _WIN_SKIP_APPS
                        and low not in {n.lower() for n in _SKIP_APPS}
                    ):
                        yield app
            return
        cfg = config_dir()
        if cfg.is_dir():
            for app in iter_children(cfg):
                if app.is_dir() and app.name not in _SKIP_APPS:
                    yield app
        # Flatpak-packaged Electron apps keep config under ~/.var/app/<id>/config.
        var = home() / ".var" / "app"
        if var.is_dir():
            for app in iter_children(var):
                conf = app / "config"
                if conf.is_dir():
                    for sub in iter_children(conf):
                        if sub.is_dir():
                            yield sub

    def find_items(self) -> Iterable[CleanableItem]:
        for app_dir in self._config_roots():
            for cache_name in _SAFE_ELECTRON_CACHES:
                target = app_dir / cache_name
                if target.is_dir() and path_size(target) > 0:
                    item = self.path_item(
                        target, f"{app_dir.name}: {cache_name}"
                    )
                    if item:
                        yield item


class FlatpakAppCacheCleaner(Cleaner):
    id = "flatpak_cache"
    name = "Flatpak app caches"
    description = "Per-app cache dirs under ~/.var/app/*/cache"
    requires_root = False
    platforms = (LINUX,)

    def find_items(self) -> Iterable[CleanableItem]:
        var = home() / ".var" / "app"
        if not var.is_dir():
            return
        for app in iter_children(var):
            cache = app / "cache"
            if not cache.is_dir():
                continue
            for child in iter_children(cache):
                # A flatpak's own fontconfig cache etc. — all safe.
                item = self.path_item(child, f"{app.name} cache: {child.name}")
                if item:
                    yield item


class GpuShaderCacheCleaner(Cleaner):
    id = "gpu_shader_cache"
    name = "GPU shader caches"
    description = "Mesa/NVIDIA/RADV shader caches (rebuilt after driver changes)"
    requires_root = False
    platforms = (LINUX,)

    def _candidates(self):
        h = home()
        cache = h / ".cache"
        yield cache / "mesa_shader_cache", "Mesa shader cache"
        yield cache / "mesa_shader_cache_db", "Mesa shader cache (db)"
        yield h / ".nv" / "GLCache", "NVIDIA GL shader cache"
        yield cache / "nvidia" / "GLCache", "NVIDIA GL shader cache"
        yield cache / "radv_builtin_shaders64", "RADV builtin shaders"
        yield cache / "AMD" / "VkCache", "AMD Vulkan pipeline cache"

    def find_items(self) -> Iterable[CleanableItem]:
        seen = set()
        for path, label in self._candidates():
            if path in seen or not path.exists() or path_size(path) <= 0:
                continue
            seen.add(path)
            item = self.path_item(path, label)
            if item:
                yield item


class SteamCleaner(Cleaner):
    id = "steam"
    name = "Steam caches"
    description = "Shader cache, partial downloads, and HTTP cache"
    requires_root = False
    platforms = (LINUX,)

    def _steam_root(self) -> Path:
        for candidate in (
            home() / ".local" / "share" / "Steam",
            home() / ".steam" / "steam",
        ):
            if candidate.is_dir():
                return candidate
        return home() / ".local" / "share" / "Steam"

    def find_items(self) -> Iterable[CleanableItem]:
        root = self._steam_root()
        if not root.is_dir():
            return
        apps = root / "steamapps"
        # Per-game shader caches.
        for child in iter_children(apps / "shadercache"):
            item = self.path_item(child, f"Steam shader cache: {child.name}")
            if item:
                yield item
        # Interrupted downloads and temp staging.
        for rel in ("downloading", "temp"):
            target = apps / rel
            if target.is_dir() and path_size(target) > 0:
                item = self.path_item(target, f"Steam {rel}")
                if item:
                    yield item
        # HTTP cache.
        httpcache = root / "appcache" / "httpcache"
        if httpcache.is_dir() and path_size(httpcache) > 0:
            item = self.path_item(httpcache, "Steam HTTP cache")
            if item:
                yield item


class JetBrainsCleaner(Cleaner):
    id = "jetbrains"
    name = "JetBrains IDE caches"
    description = "Caches, logs, and indexes for IntelliJ/PyCharm/etc."
    requires_root = False
    platforms = (LINUX, MACOS, *XDG_PLATFORMS, WINDOWS)

    def _roots(self) -> Iterable[Path]:
        if platform.is_windows():
            yield winenv.local_appdata() / "JetBrains"
            return
        # Linux/BSD: ~/.cache/JetBrains/<Product>/{caches,log,index,...}
        yield home() / ".cache" / "JetBrains"
        # macOS: ~/Library/Caches/JetBrains and ~/Library/Logs/JetBrains
        yield home() / "Library" / "Caches" / "JetBrains"
        yield home() / "Library" / "Logs" / "JetBrains"

    def find_items(self) -> Iterable[CleanableItem]:
        for root in self._roots():
            if not root.is_dir():
                continue
            for product in iter_children(root):
                if not product.is_dir():
                    continue
                for sub in ("caches", "log", "logs", "index", "tmp"):
                    target = product / sub
                    if target.is_dir() and path_size(target) > 0:
                        item = self.path_item(
                            target, f"JetBrains {product.name}: {sub}"
                        )
                        if item:
                            yield item
