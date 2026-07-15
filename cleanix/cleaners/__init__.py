"""Built-in cleaners.

Each module defines one or more :class:`~cleanix.cleaners.base.Cleaner`
subclasses. :data:`ALL_CLEANERS` is the ordered registry consumed by the
engine. Cleaners declare which platforms they apply to; the engine only runs
the ones relevant to the current operating system.
"""

from __future__ import annotations

from typing import List, Type

from cleanix.cleaners.base import Cleaner

# Cross-platform / freedesktop
from cleanix.cleaners.trash import TrashCleaner
from cleanix.cleaners.thumbnails import ThumbnailCleaner
from cleanix.cleaners.user_cache import UserCacheCleaner
from cleanix.cleaners.temp_files import TempFilesCleaner
from cleanix.cleaners.font_cache import FontCacheCleaner
from cleanix.cleaners.browsers import BrowserCacheCleaner
from cleanix.cleaners.broken_symlinks import BrokenSymlinkCleaner
from cleanix.cleaners.apple_litter import AppleLitterCleaner
from cleanix.cleaners.dev_caches import DevCacheCleaner
from cleanix.cleaners.pip_cache import PipCacheCleaner
from cleanix.cleaners.npm_cache import NpmCacheCleaner
from cleanix.cleaners.containers import DockerCleaner, PodmanCleaner
from cleanix.cleaners.containerd import CrictlCleaner, NerdctlCleaner
from cleanix.cleaners.toolchains import ToolchainVersionCleaner
from cleanix.cleaners.project_cruft import ProjectCruftCleaner
from cleanix.cleaners.big_files import BigFileReporter
from cleanix.cleaners.downloads import DownloadsReporter

# Logs / crashes
from cleanix.cleaners.logs import JournalCleaner, RotatedLogCleaner
from cleanix.cleaners.coredumps import CoredumpCleaner
from cleanix.cleaners.linux_extras import ConfigLeftoverCleaner, CrashReportCleaner

# Linux package managers
from cleanix.cleaners.apt import AptCleaner
from cleanix.cleaners.dnf import DnfCleaner
from cleanix.cleaners.pacman import PacmanCleaner
from cleanix.cleaners.distro_pkg import (
    ApkCleaner,
    PortageCleaner,
    XbpsCleaner,
    ZypperCleaner,
)
from cleanix.cleaners.packaging_extras import (
    AppImageCruftCleaner,
    FlatpakCleaner,
    NixGcCleaner,
    SnapCleaner,
)

# macOS
from cleanix.cleaners.macos import (
    HomebrewCleaner,
    MacDiagnosticsCleaner,
    MacPortsCleaner,
    MacTrashCleaner,
    MacUserCacheCleaner,
    XcodeCleaner,
)

# AI / LLM tools
from cleanix.cleaners.ai_tools import (
    AIClientCleaner,
    AICompileCacheCleaner,
    AiderLitterCleaner,
    HuggingFaceCleaner,
    OllamaCleaner,
)

# AI coding-agent CLIs (Claude Code, Codex, Gemini CLI, OpenCode)
from cleanix.cleaners.ai_cli import (
    ClaudeCodeCleaner,
    CodexCleaner,
    GeminiCliCleaner,
    OpenCodeCleaner,
)

# General desktop-app cruft
from cleanix.cleaners.app_cruft import (
    ElectronCacheCleaner,
    FlatpakAppCacheCleaner,
    GpuShaderCacheCleaner,
    JetBrainsCleaner,
    SteamCleaner,
)

# Additional system leftovers
from cleanix.cleaners.sys_extras import (
    CrashSpoolCleaner,
    OfflineUpdateCleaner,
    SystemCacheCleaner,
    VarBackupsCleaner,
)
from cleanix.cleaners.kernels import OldKernelCleaner
from cleanix.cleaners.localizations import LocalePurgeCleaner

# Language / toolchain caches
from cleanix.cleaners.lang_caches import LangPackageCacheCleaner

# Desktop search indexes
from cleanix.cleaners.desktop_extras import SearchIndexCleaner

# Virtualization / cloud
from cleanix.cleaners.virtualization import LibvirtSaveReporter, VmToolingCleaner

# Editor / build litter
from cleanix.cleaners.editor_litter import (
    BackupFileCleaner,
    BuildLitterCleaner,
    EditorStateCleaner,
    HomeCoreDumpCleaner,
)

# Backups & snapshots (mostly report-only)
from cleanix.cleaners.snapshots import (
    BackupCacheCleaner,
    DeviceBackupReporter,
    SnapshotReporter,
    TimeMachineReporter,
)

# IDEs, apps, memory
from cleanix.cleaners.ide import IdeCleaner
from cleanix.cleaners.apps import AppLeftoverCleaner, SnapAppCacheCleaner
from cleanix.cleaners.memory import (
    DropCachesCleaner,
    MacMemoryPurgeCleaner,
    SwapReclaimCleaner,
)

# More package managers
from cleanix.cleaners.more_pkg import (
    CondaCleaner,
    CpanmCleaner,
    EopkgCleaner,
    GemCleanupCleaner,
    GuixCleaner,
    OpamCleaner,
    SdkmanCleaner,
    SwupdCleaner,
)

# macOS extras
from cleanix.cleaners.macos_extra import (
    MacContainerCacheCleaner,
    MacExtraCachesCleaner,
    MacFontCacheCleaner,
    MacSleepImageReporter,
    MacSystemCacheCleaner,
)

# BSD
from cleanix.cleaners.bsd import (
    BsdDistfilesCleaner,
    FreeBsdPkgCleaner,
    PkginCleaner,
)

ALL_CLEANERS: List[Type[Cleaner]] = [
    # Cross-platform user junk
    TrashCleaner,
    ThumbnailCleaner,
    UserCacheCleaner,
    TempFilesCleaner,
    FontCacheCleaner,
    BrowserCacheCleaner,
    BrokenSymlinkCleaner,
    AppleLitterCleaner,
    DevCacheCleaner,
    PipCacheCleaner,
    NpmCacheCleaner,
    DockerCleaner,
    PodmanCleaner,
    NerdctlCleaner,
    CrictlCleaner,
    # Language / toolchain versions
    ToolchainVersionCleaner,
    # Logs & crashes
    RotatedLogCleaner,
    JournalCleaner,
    CoredumpCleaner,
    CrashReportCleaner,
    ConfigLeftoverCleaner,
    # Linux package managers
    AptCleaner,
    DnfCleaner,
    PacmanCleaner,
    ZypperCleaner,
    ApkCleaner,
    XbpsCleaner,
    PortageCleaner,
    EopkgCleaner,
    SwupdCleaner,
    GuixCleaner,
    CondaCleaner,
    OpamCleaner,
    SdkmanCleaner,
    GemCleanupCleaner,
    CpanmCleaner,
    # Universal/sandbox package formats
    FlatpakCleaner,
    SnapCleaner,
    NixGcCleaner,
    AppImageCruftCleaner,
    # AI / LLM engines and clients
    OllamaCleaner,
    HuggingFaceCleaner,
    AICompileCacheCleaner,
    AIClientCleaner,
    AiderLitterCleaner,
    # AI coding-agent CLIs
    ClaudeCodeCleaner,
    CodexCleaner,
    GeminiCliCleaner,
    OpenCodeCleaner,
    # Desktop-app cruft
    ElectronCacheCleaner,
    FlatpakAppCacheCleaner,
    GpuShaderCacheCleaner,
    SteamCleaner,
    JetBrainsCleaner,
    # Language / toolchain caches
    LangPackageCacheCleaner,
    # Desktop search indexes & activity
    SearchIndexCleaner,
    # IDEs & applications
    IdeCleaner,
    AppLeftoverCleaner,
    SnapAppCacheCleaner,
    # Memory (opt-in via --only)
    DropCachesCleaner,
    SwapReclaimCleaner,
    MacMemoryPurgeCleaner,
    # Editor / build litter
    EditorStateCleaner,
    BuildLitterCleaner,
    HomeCoreDumpCleaner,
    BackupFileCleaner,
    # Virtualization / cloud
    VmToolingCleaner,
    LibvirtSaveReporter,
    # Additional system leftovers
    SystemCacheCleaner,
    VarBackupsCleaner,
    CrashSpoolCleaner,
    OfflineUpdateCleaner,
    OldKernelCleaner,
    LocalePurgeCleaner,
    # Backups & snapshots (report-only tier)
    BackupCacheCleaner,
    SnapshotReporter,
    TimeMachineReporter,
    DeviceBackupReporter,
    ProjectCruftCleaner,
    BigFileReporter,
    DownloadsReporter,
    # macOS extras
    MacExtraCachesCleaner,
    MacContainerCacheCleaner,
    MacSystemCacheCleaner,
    MacFontCacheCleaner,
    MacSleepImageReporter,
    # macOS
    MacUserCacheCleaner,
    MacTrashCleaner,
    MacDiagnosticsCleaner,
    HomebrewCleaner,
    MacPortsCleaner,
    XcodeCleaner,
    # BSD
    FreeBsdPkgCleaner,
    BsdDistfilesCleaner,
    PkginCleaner,
]

__all__ = ["ALL_CLEANERS", "Cleaner"]
