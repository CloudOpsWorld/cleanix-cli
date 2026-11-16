"""Leftovers from locally-installed AI / LLM engines and clients.

The guiding principle is *triage*: remove genuinely disposable junk — dangling
model blobs from interrupted pulls, ``*.incomplete`` downloads, compile/JIT
kernel caches, embeddings indexes, and logs — while never wholesale-deleting the
models you deliberately downloaded or your chat history.

Covered: Ollama, Hugging Face Hub, PyTorch/Triton/vLLM/CUDA compile caches,
LM Studio, Jan, Continue.dev, Claude, and Aider project litter.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable, Set

from cleanix.cleaners.base import Cleaner
from cleanix.core.context import current_user
from cleanix.core.models import CleanableItem
from cleanix.core.platform import ALL, WINDOWS
from cleanix.core.utils import (
    home,
    iter_children,
    modified_within,
    path_size,
    walk_pruned,
    which,
)


class OllamaCleaner(Cleaner):
    id = "ollama"
    name = "Ollama dangling blobs"
    description = "Orphaned model blobs from interrupted pulls, plus logs"
    requires_root = False
    platforms = (ALL, WINDOWS)

    def _models_dir(self) -> Path:
        # Honor the env override only for the user who launched cleanix; when
        # sweeping other users' homes we must not project their env onto ours.
        override = os.environ.get("OLLAMA_MODELS")
        if override and current_user().is_invoker:
            return Path(override)
        return home() / ".ollama" / "models"

    def _referenced_digests(self, manifests: Path) -> Set[str]:
        """Collect every blob digest referenced by a manifest."""
        referenced: Set[str] = set()
        if not manifests.is_dir():
            return referenced
        for dirpath, _dirs, files in walk_pruned(manifests, prune=set()):
            for name in files:
                try:
                    data = json.loads(Path(dirpath, name).read_text())
                except (OSError, ValueError):
                    continue
                digests = []
                cfg = data.get("config", {})
                if isinstance(cfg, dict) and cfg.get("digest"):
                    digests.append(cfg["digest"])
                for layer in data.get("layers", []) or []:
                    if isinstance(layer, dict) and layer.get("digest"):
                        digests.append(layer["digest"])
                # Manifest stores "sha256:abc"; blob files are "sha256-abc".
                for d in digests:
                    referenced.add(d.replace(":", "-"))
        return referenced

    def find_items(self) -> Iterable[CleanableItem]:
        models = self._models_dir()
        blobs = models / "blobs"
        manifests = models / "manifests"

        # Only act if we can see a populated manifest set (i.e. the store is
        # really here and we can tell what's referenced).
        referenced = self._referenced_digests(manifests)
        if blobs.is_dir() and referenced:
            for blob in iter_children(blobs):
                if blob.name in referenced:
                    continue
                # Skip blobs that might be part of an in-progress pull.
                if modified_within(blob, 60):
                    continue
                item = self.path_item(blob, f"Dangling Ollama blob: {blob.name}")
                if item:
                    yield item

        # Ollama server logs.
        logs = home() / ".ollama" / "logs"
        if logs.is_dir():
            for log in iter_children(logs):
                item = self.path_item(log, f"Ollama log: {log.name}")
                if item:
                    yield item


class HuggingFaceCleaner(Cleaner):
    id = "huggingface"
    name = "Hugging Face cache junk"
    description = "Incomplete downloads and stale lock files (keeps models)"
    requires_root = False
    platforms = (ALL, WINDOWS)

    def _roots(self) -> Iterable[Path]:
        base = os.environ.get("HF_HOME")
        roots = [Path(base)] if base and current_user().is_invoker else []
        roots.append(home() / ".cache" / "huggingface")
        for r in roots:
            if r.is_dir():
                yield r

    def find_items(self) -> Iterable[CleanableItem]:
        seen: Set[str] = set()
        for root in self._roots():
            # Interrupted downloads: blobs/<etag>.incomplete
            for dirpath, _dirs, files in walk_pruned(root, prune={".no_exist"}):
                for name in files:
                    if name.endswith(".incomplete"):
                        p = os.path.join(dirpath, name)
                        if p in seen:
                            continue
                        seen.add(p)
                        item = self.path_item(p, f"HF incomplete download: {name}")
                        if item:
                            yield item
            # Lock files and negative-lookup cache — always safe to drop.
            for rel in ("hub/.locks", ".locks", "hub/.no_exist"):
                target = root / rel
                if target.exists():
                    item = self.path_item(target, f"HF {rel}")
                    if item:
                        yield item


class AICompileCacheCleaner(Cleaner):
    id = "ai_compile_cache"
    name = "AI compile/kernel caches"
    description = "Triton, torch.compile/inductor, vLLM, CUDA JIT kernel caches"
    requires_root = False
    platforms = (ALL, WINDOWS)

    def _candidates(self):
        h = home()
        cache = h / ".cache"
        user = current_user().name or ""
        yield h / ".triton" / "cache", "Triton kernel cache"
        yield cache / "torch_extensions", "PyTorch JIT extensions cache"
        yield cache / "vllm", "vLLM torch.compile cache"
        yield h / ".nv" / "ComputeCache", "CUDA compute (PTX JIT) cache"
        yield cache / "flashinfer", "FlashInfer JIT cache"
        yield cache / "tfhub_modules", "TensorFlow Hub module cache"
        if user:
            yield Path("/tmp") / f"torchinductor_{user}", "TorchInductor cache (/tmp)"
            yield Path("/tmp") / f"triton_{user}", "Triton cache (/tmp)"

    def find_items(self) -> Iterable[CleanableItem]:
        seen = set()
        for path, label in self._candidates():
            if path in seen or not path.exists() or path_size(path) <= 0:
                continue
            seen.add(path)
            item = self.path_item(path, label)
            if item:
                yield item


class AIClientCleaner(Cleaner):
    id = "ai_clients"
    name = "AI client leftovers"
    description = "Logs & rebuildable indexes for LM Studio, Jan, Continue, Claude"
    requires_root = False
    platforms = (ALL, WINDOWS)

    def _candidates(self):
        h = home()
        # LM Studio — logs only (never the models/config store).
        yield h / ".cache" / "lm-studio" / "server-logs", "LM Studio server logs"
        yield h / ".lmstudio" / "server-logs", "LM Studio server logs"
        yield h / ".lmstudio" / "logs", "LM Studio logs"
        # Jan — logs.
        yield h / ".config" / "Jan" / "logs", "Jan logs"
        yield h / "jan" / "logs", "Jan logs"
        # Continue.dev — rebuildable embeddings index, logs, telemetry.
        yield h / ".continue" / "index", "Continue.dev index (rebuildable)"
        yield h / ".continue" / "logs", "Continue.dev logs"
        yield h / ".continue" / "dev_data", "Continue.dev telemetry data"
        # (Claude Code is handled by the dedicated claude_code cleaner.)
        # Open WebUI / text-generation-webui logs.
        yield h / ".cache" / "chroma", "Chroma vector DB cache"

    def find_items(self) -> Iterable[CleanableItem]:
        for path, label in self._candidates():
            if path.exists() and path_size(path) > 0:
                item = self.path_item(path, label)
                if item:
                    yield item


class AiderLitterCleaner(Cleaner):
    id = "aider"
    name = "Aider project litter"
    description = "Stray .aider.* history/cache files left in project folders"
    requires_root = False
    platforms = (ALL, WINDOWS)

    _NAMES = (
        ".aider.chat.history.md",
        ".aider.input.history",
        ".aider.llm.history",
    )
    _PREFIXES = (".aider.tags.cache",)

    def find_items(self) -> Iterable[CleanableItem]:
        root = home()
        for dirpath, dirs, files in walk_pruned(root):
            # .aider.tags.cache.v3 is a directory; catch it as we descend.
            for d in list(dirs):
                if d.startswith(self._PREFIXES):
                    p = os.path.join(dirpath, d)
                    item = self.path_item(p, f"Aider cache: {p}")
                    if item:
                        yield item
            for name in files:
                if name in self._NAMES or name.startswith(self._PREFIXES):
                    p = os.path.join(dirpath, name)
                    item = self.path_item(p, f"Aider leftover: {p}")
                    if item:
                        yield item
