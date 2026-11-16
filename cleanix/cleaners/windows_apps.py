"""Windows application cleaners: browser caches, GPU shader caches,
package-manager caches and Visual Studio caches.

Cleaners yield cache *subdirectories* only, never profile roots or session
data (Cookies, Login Data, Local Storage, IndexedDB, History).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from cleanix.cleaners.base import Cleaner, SCOPE_USER
from cleanix.core import winenv
from cleanix.core.models import CleanableItem
from cleanix.core.platform import WINDOWS
from cleanix.core.utils import home, iter_children, path_size

_CHROMIUM_CACHES = ("Cache", "Code Cache", "GPUCache")


def _is_profile(name: str) -> bool:
    return name == "Default" or name.startswith("Profile ")


class WinBrowserCacheCleaner(Cleaner):
    id = "win_browser_cache"
    name = "Browser caches"
    description = "Cache, Code Cache and GPUCache of Chrome, Edge, Brave and Firefox"
    platforms = (WINDOWS,)
    scope = SCOPE_USER

    # (label, relative User Data dir, config keys; None = always processed)
    _CHROMIUM = (
        ("Chrome", ("Google", "Chrome", "User Data"), ("chrome", "chromium")),
        ("Edge", ("Microsoft", "Edge", "User Data"), None),
        ("Brave", ("BraveSoftware", "Brave-Browser", "User Data"), None),
    )

    def find_items(self) -> Iterable[CleanableItem]:
        local = winenv.local_appdata()
        wanted = {b.lower() for b in self.config.browsers}
        for label, rel, keys in self._CHROMIUM:
            if keys is not None and not wanted.intersection(keys):
                continue
            for prof in iter_children(local.joinpath(*rel)):
                if not prof.is_dir() or not _is_profile(prof.name):
                    continue
                for cache in _CHROMIUM_CACHES:
                    target = prof / cache
                    if target.is_dir() and path_size(target) > 0:
                        item = self.path_item(
                            target, f"{label} {prof.name}: {cache}"
                        )
                        if item:
                            yield item
        if "firefox" in wanted:
            profiles = local / "Mozilla" / "Firefox" / "Profiles"
            for prof in iter_children(profiles):
                target = prof / "cache2"
                if target.is_dir() and path_size(target) > 0:
                    item = self.path_item(target, f"Firefox {prof.name}: cache2")
                    if item:
                        yield item


class WinShaderCacheCleaner(Cleaner):
    id = "win_shader_cache"
    name = "GPU shader caches"
    description = "DirectX, NVIDIA and AMD shader caches (rebuilt on demand)"
    platforms = (WINDOWS,)
    scope = SCOPE_USER

    _CANDIDATES = (
        (("D3DSCache",), "DirectX shader cache"),
        (("NVIDIA", "DXCache"), "NVIDIA DX shader cache"),
        (("NVIDIA", "GLCache"), "NVIDIA GL shader cache"),
        (("AMD", "DxCache"), "AMD DX shader cache"),
        (("AMD", "GLCache"), "AMD GL shader cache"),
    )

    def find_items(self) -> Iterable[CleanableItem]:
        local = winenv.local_appdata()
        for rel, label in self._CANDIDATES:
            path = local.joinpath(*rel)
            if path.is_dir() and path_size(path) > 0:
                item = self.path_item(path, label)
                if item:
                    yield item


class WinPackageCacheCleaner(Cleaner):
    id = "win_pkg_caches"
    name = "Package manager caches"
    description = "WinGet, Chocolatey, Scoop and NuGet download caches"
    platforms = (WINDOWS,)
    scope = SCOPE_USER

    def _candidates(self):
        temp = winenv.user_temp()
        yield temp / "WinGet", "WinGet temp"
        yield temp / "chocolatey", "Chocolatey temp"
        choco = os.environ.get("ChocolateyInstall")
        if choco:
            yield Path(choco) / "lib-bad", "Chocolatey failed installs"
        scoop = os.environ.get("SCOOP")
        scoop_root = Path(scoop) if scoop else home() / "scoop"
        yield scoop_root / "cache", "Scoop cache"
        yield winenv.local_appdata() / "NuGet" / "v3-cache", "NuGet cache"

    def find_items(self) -> Iterable[CleanableItem]:
        seen = set()
        for path, label in self._candidates():
            if path in seen or not path.is_dir() or path_size(path) <= 0:
                continue
            seen.add(path)
            item = self.path_item(path, label)
            if item:
                yield item


class WinVisualStudioCleaner(Cleaner):
    id = "win_visualstudio"
    name = "Visual Studio caches"
    description = "Visual Studio ComponentModelCache (rebuilt on next launch)"
    platforms = (WINDOWS,)
    scope = SCOPE_USER

    def find_items(self) -> Iterable[CleanableItem]:
        vs = winenv.local_appdata() / "Microsoft" / "VisualStudio"
        for inst in iter_children(vs):
            target = inst / "ComponentModelCache"
            if target.is_dir() and path_size(target) > 0:
                item = self.path_item(
                    target, f"Visual Studio {inst.name}: ComponentModelCache"
                )
                if item:
                    yield item
