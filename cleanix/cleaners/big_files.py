"""Large-file finder (report-only).

A user who has filled their disk usually wants to *see* what is eating the
space, not have cleanix guess which giant files are junk — a 40 GiB video or VM
image may be exactly what they wanted to keep. So this cleaner never deletes
anything: it walks the home tree, surfaces the biggest files (with sizes and a
manual removal hint), and leaves the decision to the human.
"""

from __future__ import annotations

import heapq
import os
import stat
from typing import Iterable, List, Tuple

from cleanix.cleaners.base import Cleaner
from cleanix.core.models import CleanableItem
from cleanix.core.platform import ALL
from cleanix.core.utils import (
    _allocated_bytes,
    home,
    human_size,
    modified_within,
    walk_pruned,
)

# Leave anything touched within the last few minutes alone: a very recent mtime
# suggests the file is being actively written (a download in progress, a render
# still spooling), and its size is not yet meaningful.
_IN_USE_MINUTES = 5.0


class BigFileReporter(Cleaner):
    id = "big_files"
    name = "Large files"
    description = "Biggest files in your home directory (report only)"
    requires_root = False
    platforms = (ALL,)

    def find_items(self) -> Iterable[CleanableItem]:
        min_bytes = int(
            getattr(self.config, "big_file_min_size_mb", 500.0) * 1024 * 1024
        )
        top_n = int(getattr(self.config, "big_files_top_n", 20))
        if top_n <= 0:
            return

        # Keep a running min-heap of the top-N largest files seen so far. Each
        # entry is (size, path); the smallest sits at heap[0] and is evicted
        # once the heap is full and a bigger file arrives.
        heap: List[Tuple[int, str]] = []

        for dirpath, _dirnames, filenames in walk_pruned(home()):
            for name in filenames:
                fpath = os.path.join(dirpath, name)
                try:
                    st = os.lstat(fpath)
                except OSError:
                    continue
                # Files only, never symlinks (walk_pruned already avoids
                # descending through symlinked dirs).
                if not stat.S_ISREG(st.st_mode):
                    continue
                size = _allocated_bytes(st)
                if size < min_bytes:
                    continue
                if modified_within(fpath, _IN_USE_MINUTES):
                    continue
                if len(heap) < top_n:
                    heapq.heappush(heap, (size, fpath))
                elif size > heap[0][0]:
                    heapq.heapreplace(heap, (size, fpath))

        # Emit largest-first.
        for size, fpath in sorted(heap, key=lambda t: t[0], reverse=True):
            item = self.report_item(
                fpath,
                f"Large file: {os.path.basename(fpath)} ({human_size(size)})",
                hint="review and remove manually if no longer needed: rm <path>",
            )
            if item:
                yield item
