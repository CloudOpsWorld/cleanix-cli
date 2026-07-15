"""Container-engine leftovers (Docker / Podman).

A "leftover" here is anything the engine keeps around that is **not referenced
by an existing container** and can be regenerated: dangling (untagged) images,
stopped containers, unused networks and build cache. Rather than lumping these
into one opaque ``system prune`` with a bogus size, we surface each category as
its own item whose estimated size matches *exactly* what pruning that category
reclaims — so the number you see is the number you get.

Two categories stay opt-in because they can destroy real work:
  * unused **volumes** (``docker_prune_volumes``) — may hold databases, etc.
  * all unused **images** (``docker_prune_all_images``) — tagged images with no
    container are removed too, forcing a re-pull on next use.
"""

from __future__ import annotations

import json
import re
from typing import Iterable, Optional

from cleanix.cleaners.base import Cleaner, SCOPE_SYSTEM
from cleanix.core.models import CleanableItem
from cleanix.core.utils import run_command, which

_SIZE_RE = re.compile(r"([\d.]+)\s*([KMGT]?B)", re.IGNORECASE)
_UNIT = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}


def _parse_size(text: str) -> int:
    """Parse the first size token in ``text`` (e.g. "1.2GB") into bytes."""
    m = _SIZE_RE.search(text or "")
    if not m:
        return 0
    value = float(m.group(1))
    unit = m.group(2).upper()
    return int(value * _UNIT.get(unit, 1))


class _ContainerCleaner(Cleaner):
    binary = ""
    requires_root = False

    def available(self) -> Optional[str]:
        if not which(self.binary):
            return f"{self.binary} not found"
        # The binary can be installed while the engine is unreachable — a
        # stopped Docker daemon, or a Podman machine that was never started
        # (macOS runs Podman inside a Linux VM). ``info`` is the cheap standard
        # liveness probe; skip with a clear reason rather than emitting prunes
        # that only fail at execute time.
        code, _out, _err = run_command([self.binary, "info"], timeout=20)
        if code != 0:
            return f"{self.binary} installed but not running"
        return None

    # -- low-level probes ----------------------------------------------------
    def _df_reclaimable(self) -> dict:
        """Reclaimable bytes per ``system df`` row, keyed by ``Type``.

        Keys seen in practice: ``Images``, ``Containers``, ``Local Volumes``,
        ``Build Cache``. Missing/failed probes yield an empty mapping.
        """
        code, out, _err = run_command(
            [self.binary, "system", "df", "--format", "{{json .}}"], timeout=30
        )
        result: dict = {}
        if code != 0 or not out.strip():
            return result
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            row_type = row.get("Type")
            if row_type:
                result[row_type] = _parse_size(row.get("Reclaimable", ""))
        return result

    def _dangling_images_size(self) -> int:
        """Total size of untagged (dangling) images — what ``image prune``
        removes without ``-a``."""
        code, out, _err = run_command(
            [self.binary, "images", "--filter", "dangling=true",
             "--format", "{{.Size}}"],
            timeout=30,
        )
        if code != 0:
            return 0
        return sum(_parse_size(line) for line in out.splitlines() if line.strip())

    def _stopped_containers(self) -> tuple:
        """``(count, reclaimable_bytes)`` for stopped containers.

        ``ps --size`` reports ``"<writable> (virtual <total>)"``; the writable
        layer is what ``container prune`` actually reclaims, so we take the
        first size token on each line.
        """
        code, out, _err = run_command(
            [self.binary, "ps", "-a", "--size",
             "--filter", "status=exited",
             "--filter", "status=created",
             "--filter", "status=dead",
             "--format", "{{.Size}}"],
            timeout=30,
        )
        if code != 0:
            return 0, 0
        lines = [ln for ln in out.splitlines() if ln.strip()]
        return len(lines), sum(_parse_size(ln) for ln in lines)

    def _unused_networks(self) -> int:
        """Count of user-defined networks not used by any container.

        The ``dangling=true`` network filter (Docker 20.10+, Podman 4+) means
        "unreferenced"; on engines that don't support it the probe fails and we
        report zero rather than guessing.
        """
        code, out, _err = run_command(
            [self.binary, "network", "ls", "--filter", "dangling=true",
             "--format", "{{.ID}}"],
            timeout=30,
        )
        if code != 0:
            return 0
        return sum(1 for ln in out.splitlines() if ln.strip())

    # -- item assembly -------------------------------------------------------
    def find_items(self) -> Iterable[CleanableItem]:
        df = self._df_reclaimable()

        # 1) Images — dangling only by default, all-unused when opted in.
        if self.config.docker_prune_all_images:
            size = df.get("Images", 0)
            if size > 0:
                yield self.command_item(
                    [self.binary, "image", "prune", "-a", "-f"],
                    "Unused images (not referenced by any container)",
                    size=size,
                )
        else:
            size = self._dangling_images_size()
            if size > 0:
                yield self.command_item(
                    [self.binary, "image", "prune", "-f"],
                    "Dangling (untagged) images",
                    size=size,
                )

        # 2) Stopped containers (writable layers).
        count, size = self._stopped_containers()
        if count > 0:
            noun = "container" if count == 1 else "containers"
            yield self.command_item(
                [self.binary, "container", "prune", "-f"],
                f"{count} stopped {noun}",
                size=size,
            )

        # 3) Build cache.
        size = df.get("Build Cache", 0)
        if size > 0:
            yield self.command_item(
                [self.binary, "builder", "prune", "-f"],
                "Build cache",
                size=size,
            )

        # 4) Unused networks (no reclaimable disk, but real leftovers).
        count = self._unused_networks()
        if count > 0:
            noun = "network" if count == 1 else "networks"
            yield self.command_item(
                [self.binary, "network", "prune", "-f"],
                f"{count} unused {noun}",
                size=0,
            )

        # 5) Unused volumes — opt-in, may hold real data.
        if self.config.docker_prune_volumes:
            size = df.get("Local Volumes", 0)
            if size > 0:
                yield self.command_item(
                    [self.binary, "volume", "prune", "-f"],
                    "Unused (anonymous) volumes",
                    size=size,
                )


class DockerCleaner(_ContainerCleaner):
    id = "docker"
    scope = SCOPE_SYSTEM
    name = "Docker leftovers"
    description = "Dangling images, stopped containers, build cache, networks"
    binary = "docker"


class PodmanCleaner(_ContainerCleaner):
    id = "podman"
    scope = SCOPE_SYSTEM
    name = "Podman leftovers"
    description = "Dangling images, stopped containers, build cache, networks"
    binary = "podman"
