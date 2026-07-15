"""Scheduling support.

Picks the right OS-native backend: a **systemd user timer** on Linux/BSD and a
**launchd LaunchAgent** on macOS. Both expose the same
``install/uninstall/status`` surface, so callers use :func:`backend` and stay
platform-agnostic.
"""

from __future__ import annotations

from cleanix.core.platform import is_macos


def backend():
    """Return the scheduling backend module for the current OS."""
    if is_macos():
        from cleanix.scheduler import launchd

        return launchd
    from cleanix.scheduler import systemd

    return systemd
