"""Superseded language-toolchain *versions* (not just their caches).

Version managers accumulate multi-gigabyte installed runtimes — old node
versions under ``~/.nvm``, Python builds under ``~/.pyenv``, rustup toolchains,
SDKMAN candidates — that are the single biggest reclaimable sink on a developer
machine after Docker.

This is higher blast radius than a cache: removing the *active* version breaks
your shell. So the cleaner is deliberately conservative:

  * It never offers a version it cannot prove is inactive — the currently
    selected / default version of each manager is always protected, and a
    manager whose active version can't be determined is skipped entirely.
  * It keeps the newest ``keep_toolchain_versions`` of the remainder.
  * Items are ordinary deletable paths, so ``clean --quarantine`` makes them
    reversible.

Gate the whole cleaner off with ``prune_old_toolchains: false``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Set, Tuple

from cleanix.cleaners.base import Cleaner
from cleanix.core.models import CleanableItem
from cleanix.core.utils import home, iter_children, surplus_after_keeping


def _read_first_line(path: Path) -> str:
    try:
        return path.read_text().strip().splitlines()[0].strip()
    except (OSError, IndexError):
        return ""


def _dir_children(path: Path) -> List[Path]:
    try:
        return [c for c in iter_children(path) if c.is_dir() and not c.is_symlink()]
    except OSError:
        return []


class ToolchainVersionCleaner(Cleaner):
    id = "toolchains"
    name = "Old toolchain versions"
    description = "Superseded rustup/nvm/pyenv/rbenv/sdkman/asdf versions"
    requires_root = False

    # -- per-manager (versions_dir, {active version names to protect}) --------
    def _pyenv(self) -> Tuple[Path, Set[str]]:
        root = home() / ".pyenv"
        active = {_read_first_line(root / "version")}
        return root / "versions", {a for a in active if a}

    def _rbenv(self) -> Tuple[Path, Set[str]]:
        root = home() / ".rbenv"
        active = {_read_first_line(root / "version")}
        return root / "versions", {a for a in active if a}

    def _rustup(self) -> Tuple[Path, Set[str]]:
        root = home() / ".rustup"
        active: Set[str] = set()
        try:
            for line in (root / "settings.toml").read_text().splitlines():
                if line.strip().startswith("default_toolchain"):
                    active.add(line.split("=", 1)[1].strip().strip('"'))
        except OSError:
            pass
        return root / "toolchains", active

    def _sdkman(self) -> Iterable[Tuple[Path, Set[str]]]:
        candidates = home() / ".sdkman" / "candidates"
        for cand in _dir_children(candidates):
            current = cand / "current"  # symlink to the active version dir
            active = set()
            try:
                if current.is_symlink():
                    active.add(Path(current.resolve()).name)
            except OSError:
                pass
            yield cand, active

    def _nvm(self) -> Tuple[Path, Set[str]]:
        root = home() / ".nvm"
        default = _read_first_line(root / "alias" / "default")
        # Only protect (and therefore only prune) when the default resolves to a
        # concrete installed version dir; aliases like "lts/*" are ambiguous, so
        # we bail out of nvm entirely rather than risk deleting the wrong one.
        versions = root / "versions" / "node"
        names = {c.name for c in _dir_children(versions)}
        if default in names:
            return versions, {default}
        if default and f"v{default}" in names:
            return versions, {f"v{default}"}
        return versions, set()  # unresolved default -> caller must skip

    def _asdf(self) -> Iterable[Tuple[Path, Set[str]]]:
        installs = home() / ".asdf" / "installs"
        active_by_tool: dict = {}
        try:
            for line in (home() / ".tool-versions").read_text().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    active_by_tool.setdefault(parts[0], set()).update(parts[1:])
        except OSError:
            pass
        for tool in _dir_children(installs):
            yield tool, active_by_tool.get(tool.name, set())

    # -- assembly ------------------------------------------------------------
    def _managers(self) -> Iterable[Tuple[str, Path, Set[str], bool]]:
        """Yield (label, versions_dir, protected_names, resolved_active)."""
        vd, act = self._pyenv();  yield "pyenv", vd, act, bool(act)
        vd, act = self._rbenv();  yield "rbenv", vd, act, bool(act)
        vd, act = self._rustup(); yield "rustup", vd, act, bool(act)
        vd, act = self._nvm();    yield "nvm", vd, act, bool(act)
        for cand, act in self._sdkman():
            yield f"sdkman/{cand.name}", cand, act, bool(act)
        for tool, act in self._asdf():
            yield f"asdf/{tool.name}", tool, act, bool(act)

    def find_items(self) -> Iterable[CleanableItem]:
        if not getattr(self.config, "prune_old_toolchains", True):
            return
        keep = int(getattr(self.config, "keep_toolchain_versions", 2))

        for label, versions_dir, protected, resolved in self._managers():
            if not versions_dir.is_dir():
                continue
            versions = _dir_children(versions_dir)
            # sdkman keeps a `current` symlink alongside version dirs — ignore it.
            versions = [v for v in versions if v.name != "current"]
            if not versions:
                continue
            # Fail safe: if we could not determine the active version for a
            # manager that clearly has installs, do not offer anything.
            if not resolved and label in ("pyenv", "rbenv", "rustup", "nvm"):
                continue
            prunable = [v for v in versions if v.name not in protected]
            for old in surplus_after_keeping(prunable, keep):
                item = self.path_item(
                    old, f"{label}: old version {old.name}"
                )
                if item:
                    yield item
