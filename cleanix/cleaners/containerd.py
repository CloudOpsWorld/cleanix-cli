"""containerd-native container leftovers (nerdctl / crictl).

These engines run on top of ``containerd`` rather than the Docker daemon, yet
accumulate the same regenerable junk: dangling (untagged) images, stopped
containers, build cache and unused networks.

``nerdctl`` is a near-drop-in Docker CLI: ``nerdctl system df``,
``nerdctl images --filter dangling=true``, ``nerdctl ps -a --size``,
``nerdctl builder prune`` and the ``image/container/volume/network prune``
family all share Docker's argument and output formats. That lets us reuse the
whole :class:`~cleanix.cleaners.containers._ContainerCleaner` machinery — the
liveness probe, the per-category size estimation and the item assembly — by
subclassing it, so any fix landing in the base cleaner is inherited for free.

``crictl`` is the Kubernetes/CRI debug client (k3s, containerd-CRI). Its
command surface is *not* Docker-compatible — there is no ``system df``, no
build-cache concept and image sizes aren't reported in Docker's format — so it
does **not** subclass ``_ContainerCleaner``. Instead it offers a single
conservative ``crictl rmi --prune`` command (remove images unused by any pod)
as its own lightweight cleaner.
"""

from __future__ import annotations

from typing import Iterable, Optional

from cleanix.cleaners.base import Cleaner, SCOPE_SYSTEM
from cleanix.cleaners.containers import _ContainerCleaner
from cleanix.core.models import CleanableItem
from cleanix.core.platform import LINUX
from cleanix.core.utils import run_command, which


class NerdctlCleaner(_ContainerCleaner):
    """containerd leftovers via the Docker-compatible ``nerdctl`` CLI."""

    id = "nerdctl"
    scope = SCOPE_SYSTEM
    name = "containerd (nerdctl) leftovers"
    description = "Dangling images, stopped containers, build cache, networks"
    binary = "nerdctl"
    # containerd/nerdctl are Linux-only.
    platforms = (LINUX,)


class CrictlCleaner(Cleaner):
    """Unused CRI images via ``crictl rmi --prune`` (k3s / containerd-CRI).

    CRI's client speaks a different dialect from Docker (no ``system df``, no
    build cache, non-Docker size formats), so we can't reuse the ``system df``
    itemisation. We offer only the one operation ``crictl`` supports cleanly:
    pruning images not referenced by any pod. Its reclaimed size can't be
    estimated up front the way ``docker system df`` allows, so it is surfaced
    without a size claim rather than a fabricated one.
    """

    id = "crictl"
    scope = SCOPE_SYSTEM
    name = "CRI (crictl) unused images"
    description = "Images not referenced by any pod (k3s / containerd-CRI)"
    platforms = (LINUX,)
    # The CRI socket is typically root-owned (e.g. k3s), so pruning needs root.
    requires_root = True

    def available(self) -> Optional[str]:
        if not which("crictl"):
            return "crictl not found"
        # crictl can be installed without a reachable CRI runtime endpoint
        # (socket down, k3s not started). ``version`` talks to the runtime and
        # is the cheap liveness probe; skip clearly rather than emitting a
        # prune that only fails at execute time.
        code, _out, _err = run_command(["crictl", "version"], timeout=20)
        if code != 0:
            return "crictl installed but CRI runtime unreachable"
        return None

    def find_items(self) -> Iterable[CleanableItem]:
        yield self.command_item(
            ["crictl", "rmi", "--prune"],
            "Unused images (not referenced by any pod)",
            size=0,
        )
