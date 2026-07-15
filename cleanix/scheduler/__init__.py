"""Scheduling support.

Picks the right OS-native backend: a **systemd user timer** on Linux, a
**launchd LaunchAgent** on macOS, and a **cron job** on the BSDs (and any
system with ``crontab`` but no systemd). All three expose the same
``install/uninstall/status`` surface, so callers use :func:`backend` and stay
platform-agnostic.
"""

from __future__ import annotations

import shutil

from cleanix.core.platform import is_bsd, is_macos


def backend():
    """Return the scheduling backend module for the current OS."""
    if is_macos():
        from cleanix.scheduler import launchd

        return launchd
    if is_bsd():
        from cleanix.scheduler import cron

        return cron
    if not shutil.which("systemctl") and shutil.which("crontab"):
        # A Linux without systemd (rc/init-based, containers) but with cron.
        from cleanix.scheduler import cron

        return cron
    from cleanix.scheduler import systemd

    return systemd
