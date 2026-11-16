"""Leftovers from AI coding-agent CLIs.

These tools quietly accumulate a lot on disk: rolling config backups, per-session
file-edit history/checkpoints, conversation transcripts, per-session todo lists,
debug logs, and telemetry. This module *triages* them:

- **Rolling backups** → keep the newest ``keep_backups`` (default 2), remove the
  older surplus. This is the "keep max N backups" the user asked for.
- **Transcripts / file-history / logs** → offered only once older than
  ``ai_history_max_age_days`` (default 30d), since they are conversation data.
- **Ephemeral scratch** (debug, todos, shell snapshots, telemetry, caches) →
  offered outright, skipping anything modified very recently (in-use guard).

Config/auth/plugins are never touched. Covers Claude Code, OpenAI Codex,
Gemini CLI, and OpenCode.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, List

from cleanix.cleaners.base import Cleaner
from cleanix.core.models import CleanableItem
from cleanix.core.platform import ALL, WINDOWS
from cleanix.core.utils import data_dir
from cleanix.core.utils import (
    home,
    iter_children,
    modified_within,
    older_than,
    surplus_after_keeping,
)


class _AgentCleaner(Cleaner):
    """Shared helpers for AI-CLI cleaners."""

    requires_root = False
    # Home-relative state dirs (~/.claude, ~/.codex, ...) work on Windows too.
    platforms = (ALL, WINDOWS)

    def _ephemeral_children(
        self, directory: Path, label: str, guard_minutes: float | None = None
    ) -> Iterable[CleanableItem]:
        """Offer each child of a scratch dir, skipping freshly-written ones.

        ``guard_minutes`` sets how recently-modified an entry must be to be
        left alone. Use a large value (e.g. a day) for per-session state that
        might belong to a currently-running session.
        """
        if not directory.is_dir():
            return
        guard = (
            self.config.cache_min_age_minutes
            if guard_minutes is None
            else guard_minutes
        )
        for child in iter_children(directory):
            if modified_within(child, guard):
                continue
            item = self.path_item(child, f"{label}: {child.name}")
            if item:
                yield item

    def _stale_children(self, directory: Path, label: str) -> Iterable[CleanableItem]:
        """Offer children older than the history-retention age."""
        if not directory.is_dir():
            return
        age = self.config.ai_history_max_age_days
        for child in iter_children(directory):
            if not older_than(child, age):
                continue
            item = self.path_item(child, f"{label}: {child.name}")
            if item:
                yield item


class ClaudeCodeCleaner(_AgentCleaner):
    id = "claude_code"
    name = "Claude Code leftovers"
    description = "Old backups, file-history, transcripts, debug logs & scratch"

    def _root(self) -> Path:
        return home() / ".claude"

    def find_items(self) -> Iterable[CleanableItem]:
        root = self._root()
        if not root.is_dir():
            return

        # 1) Rolling config backups: keep newest N, offer the surplus.
        backups = root / "backups"
        if backups.is_dir():
            files = [c for c in iter_children(backups) if c.is_file()]
            for old in surplus_after_keeping(files, self.config.keep_backups):
                item = self.path_item(
                    old, f"Old Claude backup: {old.name}"
                )
                if item:
                    yield item

        # 2a) Always-safe scratch — short in-use guard is enough.
        for sub, label in (
            ("debug", "Claude debug log"),
            ("statsig", "Claude telemetry cache"),
            ("paste-cache", "Claude paste cache"),
            ("downloads", "Claude download"),
            ("cache", "Claude cache"),
        ):
            yield from self._ephemeral_children(root / sub, label)

        # 2b) Per-session scratch that may belong to a *running* session — keep
        # anything touched in the last day so we never disturb an active run.
        _DAY = 24 * 60
        for sub, label in (
            ("todos", "Claude session todos"),
            ("shell-snapshots", "Claude shell snapshot"),
            ("session-env", "Claude session env"),
        ):
            yield from self._ephemeral_children(root / sub, label, guard_minutes=_DAY)

        # 3) Per-session file-edit history — offer sessions older than retention.
        yield from self._stale_children(root / "file-history", "Claude file-history")

        # 4) Conversation transcripts — age-gated (this is your history).
        projects = root / "projects"
        if projects.is_dir():
            for proj in iter_children(projects):
                yield from self._stale_children(proj, f"Claude transcript ({proj.name})")


class CodexCleaner(_AgentCleaner):
    id = "codex"
    name = "OpenAI Codex CLI leftovers"
    description = "Old session rollouts and TUI logs under ~/.codex"

    def _root(self) -> Path:
        override = os.environ.get("CODEX_HOME")
        return Path(override) if override else home() / ".codex"

    def find_items(self) -> Iterable[CleanableItem]:
        root = self._root()
        if not root.is_dir():
            return
        # sessions/YYYY/MM/DD/rollout-*.jsonl — offer files older than retention.
        sessions = root / "sessions"
        if sessions.is_dir():
            age = self.config.ai_history_max_age_days
            for dirpath, _dirs, files in os.walk(sessions, onerror=lambda e: None):
                for name in files:
                    p = Path(dirpath, name)
                    if older_than(p, age):
                        item = self.path_item(p, f"Codex session: {name}")
                        if item:
                            yield item
        # logs.
        yield from self._ephemeral_children(root / "logs", "Codex log")


class GeminiCliCleaner(_AgentCleaner):
    id = "gemini_cli"
    name = "Gemini CLI leftovers"
    description = "Old per-project session/log data under ~/.gemini/tmp"

    def _root(self) -> Path:
        return home() / ".gemini"

    def find_items(self) -> Iterable[CleanableItem]:
        tmp = self._root() / "tmp"
        if not tmp.is_dir():
            return
        # Each project hash dir holds chats/ and logs.json; age-gate them.
        yield from self._stale_children(tmp, "Gemini session data")


class OpenCodeCleaner(_AgentCleaner):
    id = "opencode"
    name = "OpenCode leftovers"
    description = "Logs, snapshots, and tool output (keeps DB/auth/storage)"

    def _root(self) -> Path:
        base = str(data_dir())
        return Path(base) / "opencode"

    def find_items(self) -> Iterable[CleanableItem]:
        root = self._root()
        if not root.is_dir():
            return
        for sub, label in (
            ("log", "OpenCode log"),
            ("tool-output", "OpenCode tool output"),
            ("snapshot", "OpenCode snapshot"),
        ):
            yield from self._ephemeral_children(root / sub, label)
