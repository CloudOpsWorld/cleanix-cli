"""Duplicate-file finder (report-only).

When a disk fills up, a very common culprit is the *same* large file living in
two or three places — an ISO downloaded twice, a video copied into a backup
folder, a dataset duplicated across projects. Deleting the redundant copies is a
judgement call only the human can make (which copy is the "real" one?), so this
cleaner never removes anything: it surfaces each duplicate *group* with the
space that could be reclaimed by keeping a single copy, and a manual hint.

Hashing every file on disk would be far too slow, so the search is staged to do
the least work possible:

1. Walk ``home()`` (same pruning as the large-file finder) and collect only
   regular files at least ``dup_min_size_mb`` in size. Symlinks and
   actively-written files are skipped.
2. Bucket candidates by exact byte size. A size seen only once cannot have a
   duplicate, so those buckets are dropped without ever being read.
3. Within each surviving size bucket, read a cheap *partial* hash (first 64 KiB)
   to sub-group, then a full streamed SHA-256 only inside a matching partial
   group. Files with a unique size — the vast majority — are never hashed.
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections import defaultdict
from typing import Dict, Iterable, List

from cleanix.cleaners.base import Cleaner
from cleanix.core.models import CleanableItem
from cleanix.core.platform import ALL
from cleanix.core.utils import home, human_size, modified_within, walk_pruned

# A file touched within the last few minutes may still be growing (a download in
# progress); its size/content is not yet stable, so leave it out of comparison.
_IN_USE_MINUTES = 5.0

# Bytes read for the cheap first-pass ("partial") hash. Big enough to separate
# most unrelated files, small enough to stay near-free.
_PARTIAL_BYTES = 64 * 1024

# Streaming chunk for the full hash — never load a whole (possibly multi-GiB)
# file into memory.
_CHUNK_BYTES = 1024 * 1024

# A single size bucket with more files than this is skipped: it is almost always
# a pathological case (thousands of same-sized generated files) whose full
# hashing would dominate the scan for little benefit.
_MAX_BUCKET = 500

# Cap how many peer paths are spelled out in a group's hint.
_HINT_PATHS = 8


def _partial_hash(path: str) -> str | None:
    """SHA-256 of the first ``_PARTIAL_BYTES`` of ``path`` (None on any error)."""
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read(_PARTIAL_BYTES)).hexdigest()
    except OSError:
        return None


def _full_hash(path: str) -> str | None:
    """Streamed SHA-256 of the whole file (None on any error)."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(_CHUNK_BYTES), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


class DuplicateFileReporter(Cleaner):
    id = "duplicates"
    name = "Duplicate files"
    description = "Identical large files in your home directory (report only)"
    requires_root = False
    platforms = (ALL,)

    def find_items(self) -> Iterable[CleanableItem]:
        min_bytes = int(
            getattr(self.config, "dup_min_size_mb", 10.0) * 1024 * 1024
        )
        top_n = int(getattr(self.config, "dup_top_n", 50))
        if top_n <= 0 or min_bytes <= 0:
            return

        # -- 1. collect candidates, bucketed by exact size ------------------
        by_size: Dict[int, List[str]] = defaultdict(list)
        for dirpath, _dirnames, filenames in walk_pruned(home()):
            for name in filenames:
                fpath = os.path.join(dirpath, name)
                try:
                    st = os.lstat(fpath)
                except OSError:
                    continue
                # Regular files only — never symlinks (walk_pruned already
                # avoids descending through symlinked directories).
                if not stat.S_ISREG(st.st_mode):
                    continue
                size = st.st_size
                if size < min_bytes:
                    continue
                if modified_within(fpath, _IN_USE_MINUTES):
                    continue
                by_size[size].append(fpath)

        # -- 2/3. hash only within multi-file size buckets ------------------
        # Each emitted group is (reclaimable, size, [paths]).
        groups: List[tuple[int, int, List[str]]] = []
        for size, paths in by_size.items():
            if len(paths) < 2 or len(paths) > _MAX_BUCKET:
                continue

            # Cheap first pass: sub-group by a partial hash so we full-hash
            # only files that already agree on their first 64 KiB.
            by_partial: Dict[str, List[str]] = defaultdict(list)
            for p in paths:
                ph = _partial_hash(p)
                if ph is not None:
                    by_partial[ph].append(p)

            for candidates in by_partial.values():
                if len(candidates) < 2:
                    continue
                by_full: Dict[str, List[str]] = defaultdict(list)
                for p in candidates:
                    fh = _full_hash(p)
                    if fh is not None:
                        by_full[fh].append(p)
                for matches in by_full.values():
                    if len(matches) < 2:
                        continue
                    n = len(matches)
                    reclaimable = size * (n - 1)
                    groups.append((reclaimable, size, sorted(matches)))

        # -- 4/5. rank by reclaimable space, cap, and emit ------------------
        groups.sort(key=lambda g: g[0], reverse=True)
        for reclaimable, size, matches in groups[:top_n]:
            n = len(matches)
            representative = matches[0]
            others = matches[1:]
            shown = others[:_HINT_PATHS]
            more = len(others) - len(shown)
            peers = "; ".join(shown)
            if more > 0:
                peers += f"; (+{more} more)"
            item = self.report_item(
                representative,
                f"{n} copies of a {human_size(size)} file — "
                f"{human_size(reclaimable)} reclaimable",
                hint=(
                    f"identical copies: {peers} — remove all but one "
                    f"if these are redundant"
                ),
            )
            if item:
                yield item
