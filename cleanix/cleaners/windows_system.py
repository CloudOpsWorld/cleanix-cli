"""Windows system cleaners (administrator level): system temp, Windows Update
and Delivery Optimization caches, crash dumps, plus report-only items and the
opt-in component store cleanup.

Cleaners yield *children* of directories, never the directories themselves
(except the file ``MEMORY.DMP`` and the report-only single items).
"""

from __future__ import annotations

from typing import Iterable

from cleanix.cleaners.base import Cleaner, SCOPE_SYSTEM
from cleanix.core import winenv
from cleanix.core.models import CleanableItem
from cleanix.core.platform import WINDOWS
from cleanix.core.utils import iter_children, modified_within, older_than, which

DISM_TIMEOUT = 3600  # seconds


class WinSystemTempCleaner(Cleaner):
    id = "win_system_temp"
    name = "System temp files (Windows/Temp)"
    description = "Stale files in the system temp folder older than the configured age"
    platforms = (WINDOWS,)
    scope = SCOPE_SYSTEM
    requires_root = True

    def find_items(self) -> Iterable[CleanableItem]:
        # Windows\Temp is writable by standard users while this cleaner runs
        # elevated. The remover re-checks every directory for a junction swap
        # right before descending (safety._win_rmtree), but entries are NOT
        # filtered by owner: doing that reliably needs security-descriptor
        # APIs beyond what we use without new dependencies. Residual limit,
        # documented in the README Windows notes.
        for child in iter_children(winenv.system_root() / "Temp"):
            if not older_than(child, self.config.temp_min_age_days):
                continue
            if modified_within(child, self.config.cache_min_age_minutes):
                continue
            item = self.path_item(child, f"System temp: {child.name}")
            if item:
                yield item


class WinUpdateCacheCleaner(Cleaner):
    id = "win_update_cache"
    name = "Windows Update and Delivery Optimization cache"
    description = "Downloaded update payloads and delivery optimization cache"
    platforms = (WINDOWS,)
    scope = SCOPE_SYSTEM
    requires_root = True

    def find_items(self) -> Iterable[CleanableItem]:
        root = winenv.system_root()
        for base, label in (
            (root / "SoftwareDistribution" / "Download", "Update download"),
            (
                root / "ServiceProfiles" / "NetworkService" / "AppData" / "Local"
                / "Microsoft" / "Windows" / "DeliveryOptimization" / "Cache",
                "Delivery Optimization",
            ),
        ):
            for child in iter_children(base):
                item = self.path_item(child, f"{label}: {child.name}")
                if item:
                    yield item


class WinSystemDumpsCleaner(Cleaner):
    id = "win_system_dumps"
    name = "System crash dumps and error reports"
    description = "MEMORY.DMP, minidumps, live kernel reports and queued WER reports"
    platforms = (WINDOWS,)
    scope = SCOPE_SYSTEM
    requires_root = True

    def find_items(self) -> Iterable[CleanableItem]:
        root = winenv.system_root()
        item = self.path_item(root / "MEMORY.DMP", "Kernel memory dump: MEMORY.DMP")
        if item:
            yield item
        wer = winenv.programdata() / "Microsoft" / "Windows" / "WER"
        for base, label in (
            (root / "Minidump", "Minidump"),
            (root / "LiveKernelReports", "Live kernel report"),
            (wer / "ReportArchive", "Error report archive"),
            (wer / "ReportQueue", "Error report queue"),
        ):
            for child in iter_children(base):
                item = self.path_item(child, f"{label}: {child.name}")
                if item:
                    yield item


class WinPrefetchReporter(Cleaner):
    id = "win_prefetch"
    name = "Prefetch folder (report only)"
    description = "Windows Prefetch data; reported but never deleted"
    platforms = (WINDOWS,)
    scope = SCOPE_SYSTEM
    requires_root = True

    def find_items(self) -> Iterable[CleanableItem]:
        item = self.report_item(
            winenv.system_root() / "Prefetch",
            "Prefetch folder",
            hint="Windows rebuilds Prefetch automatically; deleting it rarely helps.",
        )
        if item:
            yield item


class WindowsOldReporter(Cleaner):
    id = "win_windows_old"
    name = "Windows.old (report only)"
    description = "Previous Windows installation left after an upgrade"
    platforms = (WINDOWS,)
    scope = SCOPE_SYSTEM
    requires_root = True

    def find_items(self) -> Iterable[CleanableItem]:
        item = self.report_item(
            winenv.system_drive() + "\\Windows.old",
            "Previous Windows installation (Windows.old)",
            hint="Remove it via Settings > System > Storage > Temporary files, or run cleanmgr.",
        )
        if item:
            yield item


class WinComponentStoreCleaner(Cleaner):
    id = "win_component_store"
    name = "Component store cleanup (DISM)"
    description = "Remove superseded Windows components with DISM StartComponentCleanup"
    platforms = (WINDOWS,)
    scope = SCOPE_SYSTEM
    requires_root = True
    default_enabled = False

    def available(self) -> str | None:
        if which("Dism.exe") is None:
            return "Dism.exe not found"
        return None

    def find_items(self) -> Iterable[CleanableItem]:
        yield self.command_item(
            ["Dism.exe", "/Online", "/Cleanup-Image", "/StartComponentCleanup"],
            "Clean up the Windows component store (DISM)",
            size=0,
            # StartComponentCleanup routinely takes 5-30 minutes.
            timeout=DISM_TIMEOUT,
        )
