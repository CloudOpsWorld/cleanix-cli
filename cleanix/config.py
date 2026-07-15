"""Configuration: sane defaults plus optional YAML overrides.

Defaults are defined in code so cleanix works with zero configuration. Users
may drop a YAML file at ``~/.config/cleanix/config.yaml`` to override any field;
see ``config/default.yaml`` for the shape.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import List


def _config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / "cleanix" / "config.yaml"


@dataclass
class Config:
    """Tunable behavior shared by every cleaner."""

    # Cleaners the user has explicitly disabled (by id).
    disabled_cleaners: List[str] = field(default_factory=list)

    # Only remove temp files older than this many days.
    temp_min_age_days: float = 3.0

    # Only remove rotated logs older than this many days.
    log_min_age_days: float = 7.0

    # Keep at most this much journald history (systemd `--vacuum-size`).
    journal_max_size_mb: int = 200

    # Only remove coredumps older than this many days.
    coredump_min_age_days: float = 3.0

    # Leave loose cache files alone if modified within this many minutes
    # (an "in use" guard against actively-written scratch files).
    cache_min_age_minutes: float = 10.0

    # Extra directories to treat as user caches to clear.
    extra_cache_dirs: List[str] = field(default_factory=list)

    # Browsers to include when clearing browser caches.
    browsers: List[str] = field(
        default_factory=lambda: ["firefox", "chrome", "chromium"]
    )

    # Directories scanned for dangling (broken) symlinks — a classic sign of
    # software that was removed without cleaning up after itself.
    symlink_scan_dirs: List[str] = field(
        default_factory=lambda: [
            "~/.local/bin", "~/bin", "~/.local/share/applications",
            "/usr/local/bin", "/usr/local/sbin", "/usr/local/share/applications",
        ]
    )

    # When pruning container systems, also remove unused *volumes*. Off by
    # default because volumes can hold real data.
    docker_prune_volumes: bool = False

    # By default only *dangling* (untagged) images are pruned — a truly safe
    # leftover. Enable this to also remove tagged images not used by any
    # container ("docker image prune -a"); it frees more but forces re-pulls.
    docker_prune_all_images: bool = False

    # Offer removal of package-update leftovers (.rpmnew/.pacnew/.dpkg-old ...).
    remove_config_leftovers: bool = True

    # Remove ``.DS_Store`` / AppleDouble (``._*``) litter from the home tree.
    remove_apple_litter: bool = True

    # AI CLI tools keep rolling config/file backups; keep this many newest and
    # offer the older surplus for removal ("keep max N backups").
    keep_backups: int = 2

    # AI CLI session transcripts / file-history / logs older than this many days
    # are considered stale and offered for removal (chat history is user data,
    # so this is age-gated and conservative).
    ai_history_max_age_days: float = 30.0

    # Old-kernel removal: keep the newest N installed kernels (plus the running
    # one is always kept by the package manager). Set remove_old_kernels=false
    # to skip entirely.
    remove_old_kernels: bool = True
    keep_kernels: int = 2

    # Include language "offline repository" caches whose removal forces large
    # re-downloads and can break offline builds (Maven ~/.m2, Ivy, sbt,
    # Coursier, NuGet, RubyGems). Off by default.
    include_offline_repos: bool = False

    # Remove editor backup/tilde litter (``*~``, ``*.orig``, ``*.bak``,
    # ``*.rej``). Off by default — these can be intentional.
    remove_backup_files: bool = False

    # Purge locale/man-page translations for languages you don't use
    # (localepurge-style). Off by default — frees space but affects i18n.
    purge_unused_locales: bool = False

    # Extra paths/globs that must NEVER be deleted, on top of the built-in
    # protected paths (e.g. "~/Projects/**", "/data").
    protected_globs: List[str] = field(default_factory=list)

    # Old language-toolchain *versions* (rustup/nvm/pyenv/rbenv/asdf/sdkman):
    # keep the active + newest N, offer the older surplus for removal.
    prune_old_toolchains: bool = True
    keep_toolchain_versions: int = 2

    # Report-only: stale, regenerable project build/dependency dirs
    # (node_modules, .venv, target, …) in projects untouched for N+ days.
    project_scan_dirs: List[str] = field(
        default_factory=lambda: ["~/Projects", "~/src", "~/dev", "~/code", "~/git"]
    )
    project_stale_days: float = 120.0

    # Report-only large-file finder: surface the N largest files >= M MiB.
    big_file_min_size_mb: float = 500.0
    big_files_top_n: int = 20

    # Report-only ~/Downloads triage: flag items older than N days and >= M MiB.
    downloads_stale_days: float = 60.0
    downloads_min_size_mb: float = 50.0

    # Report-only: non-default browser profiles idle for N+ days (may be orphaned).
    browser_profile_stale_days: float = 90.0

    # Report-only duplicate finder: compare files >= M MiB, report top N groups.
    dup_min_size_mb: float = 10.0
    dup_top_n: int = 50

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "Config":
        """Load config, layering a YAML file over the defaults if present."""
        cfg = cls()
        cfg_path = Path(path) if path else _config_path()
        if not cfg_path.exists():
            return cfg

        try:
            import yaml  # imported lazily so the dep is optional at runtime
        except ImportError:
            return cfg

        try:
            data = yaml.safe_load(cfg_path.read_text()) or {}
        except (OSError, yaml.YAMLError):
            return cfg

        known = {f.name for f in fields(cls)}
        for key, value in data.items():
            if key in known and value is not None:
                setattr(cfg, key, value)
        return cfg


# One-line help shown by ``cleanix config list``.
FIELD_HELP = {
    "disabled_cleaners": "Cleaner ids to disable entirely",
    "temp_min_age_days": "Only remove temp files older than N days",
    "log_min_age_days": "Only remove rotated logs older than N days",
    "journal_max_size_mb": "Cap journald history to N MiB when vacuuming",
    "coredump_min_age_days": "Only remove coredumps older than N days",
    "cache_min_age_minutes": "Leave loose cache files touched within N minutes",
    "extra_cache_dirs": "Additional cache directories to clear",
    "browsers": "Browsers whose caches to clear",
    "symlink_scan_dirs": "Directories scanned for broken symlinks",
    "docker_prune_volumes": "Also prune unused Docker/Podman volumes",
    "docker_prune_all_images": "Prune all unused images, not just dangling ones",
    "remove_config_leftovers": "Offer .rpmnew/.pacnew/.dpkg-old residue",
    "remove_apple_litter": "Remove .DS_Store / AppleDouble litter",
    "keep_backups": "AI CLI rolling backups to keep (newest N)",
    "ai_history_max_age_days": "AI transcripts/history older than N days are stale",
    "remove_old_kernels": "Offer removal of superseded kernels",
    "keep_kernels": "Number of newest kernels to keep",
    "include_offline_repos": "Include Maven/Ivy/NuGet/etc. offline caches",
    "remove_backup_files": "Remove *~/*.bak/*.orig/*.rej editor backups",
    "purge_unused_locales": "Remove locale/man-page translations you don't use",
    "prune_old_toolchains": "Offer removal of superseded language toolchains",
    "keep_toolchain_versions": "Toolchain versions to keep per manager (newest N)",
    "project_scan_dirs": "Project roots scanned for stale build/dependency dirs",
    "project_stale_days": "Report build/dep dirs in projects untouched N+ days",
    "big_file_min_size_mb": "Report files in $HOME at least this large (MiB)",
    "big_files_top_n": "Report at most the N largest files (largest first)",
    "downloads_stale_days": "Flag ~/Downloads items older than N days (report only)",
    "downloads_min_size_mb": "Only flag ~/Downloads items at least N MiB",
    "browser_profile_stale_days": "Report browser profiles idle N+ days (report only)",
    "dup_min_size_mb": "Only compare files in $HOME at least this large (MiB)",
    "dup_top_n": "Report at most the N largest duplicate groups",
}


def _field_types() -> dict:
    """Map each config key to the Python type of its default value."""
    defaults = Config()
    return {f.name: type(getattr(defaults, f.name)) for f in fields(Config)}


def field_names() -> List[str]:
    return [f.name for f in fields(Config)]


def coerce_value(key: str, raw: str):
    """Convert a CLI string into the correct type for config key ``key``."""
    types = _field_types()
    if key not in types:
        raise KeyError(key)
    t = types[key]
    if t is bool:
        low = raw.strip().lower()
        if low in ("1", "true", "yes", "on", "y", "t"):
            return True
        if low in ("0", "false", "no", "off", "n", "f"):
            return False
        raise ValueError(f"expected a boolean for {key}, got {raw!r}")
    if t is int:
        try:
            return int(raw)
        except ValueError:
            raise ValueError(f"expected an integer for {key}, got {raw!r}")
    if t is float:
        try:
            return float(raw)
        except ValueError:
            raise ValueError(f"expected a number for {key}, got {raw!r}")
    if t is list:
        return [p.strip() for p in raw.split(",") if p.strip()]
    return raw


def read_user_overrides(path: str | os.PathLike | None = None) -> dict:
    """Return the raw override dict from the user's YAML (or {} if none)."""
    cfg_path = Path(path) if path else _config_path()
    if not cfg_path.exists():
        return {}
    try:
        import yaml

        return yaml.safe_load(cfg_path.read_text()) or {}
    except Exception:  # noqa: BLE001
        return {}


def write_user_override(key: str, value, path: str | os.PathLike | None = None) -> Path:
    """Set ``key`` in the user's YAML config, creating it if needed."""
    import yaml

    if key not in _field_types():
        raise KeyError(key)
    cfg_path = Path(path) if path else _config_path()
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    data = read_user_overrides(cfg_path)
    data[key] = value
    cfg_path.write_text(yaml.safe_dump(data, default_flow_style=False, sort_keys=True))
    return cfg_path


def remove_user_override(key: str, path: str | os.PathLike | None = None) -> bool:
    """Remove ``key`` from the user's YAML (revert to default). True if removed."""
    import yaml

    cfg_path = Path(path) if path else _config_path()
    data = read_user_overrides(cfg_path)
    if key not in data:
        return False
    del data[key]
    cfg_path.write_text(yaml.safe_dump(data, default_flow_style=False, sort_keys=True))
    return True


def config_file_path() -> Path:
    return _config_path()
