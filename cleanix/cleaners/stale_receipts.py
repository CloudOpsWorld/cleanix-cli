"""Report-only: macOS installer receipts of packages whose files are all gone.

Receipts live in ``/private/var/db/receipts``; ``pkgutil`` lists them and the
files each one installed. A receipt is reported only on positive evidence: its
file list is non-empty, none of a stratified sample of its files (first 25,
last 25 and 100 pseudo-random ones seeded from the receipt id) exists any
more, and none of the bundles it installed (``Foo.app`` ...) turns up in the
install location or in the usual application folders (a moved or renamed app
is not a removed one).

Unknown is not stale: ``com.apple.*`` receipts, volumes other than ``/``,
staging or relocated install locations, locations that are not a stable
parent, failing or unparsable ``pkgutil`` answers, anything whose existence
cannot be determined, symlinked receipts and receipts without a file on disk
are never reported. Nothing is ever forgotten or removed; each hint names the
one receipt only.
"""

from __future__ import annotations

import hashlib
import os
import plistlib
import posixpath
import random
import re
import shlex
from pathlib import Path
from typing import Iterable, Optional

from cleanix.cleaners import orphan_common as oc
from cleanix.cleaners.base import SCOPE_SYSTEM
from cleanix.core.platform import MACOS

RECEIPTS_DIR = "/private/var/db/receipts"
SAMPLE_HEAD = 25
SAMPLE_TAIL = 25
SAMPLE_RANDOM = 100
MAX_RECEIPTS = 1000  # receipts examined per scan; only findings use the budget
MAX_BUNDLES = 50
MAX_OUTPUT_CHARS = 4 * 1024 * 1024
MAX_CALL_TIMEOUT = 60
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
# Stable parents: install locations that always exist for many packages. Any
# other location (a package's own folder, a relocated or missing one) is
# "unknown", never stale.
STABLE_PARENTS = frozenset(
    {
        "/", "/Applications", "/Library", "/Library/Application Support",
        "/usr", "/usr/local", "/usr/local/bin", "/usr/local/lib",
        "/usr/local/share", "/opt", "/private", "/Users",
    }
)
STAGING_PREFIXES = ("/tmp", "/private/tmp", "/private/var/folders", "/var/folders")
APP_DIRS = (
    "/Applications", "/Applications/Utilities", "/Library", "/System/Applications",
)


def _under(logical: str, prefix: str) -> bool:
    return logical == prefix or logical.startswith(prefix + "/")


def _exists(path: Path) -> Optional[bool]:
    """True/False for a definite answer, None when it cannot be told."""
    try:
        os.lstat(path)  # a dangling symlink still counts as present
        return True
    except (FileNotFoundError, NotADirectoryError):
        return False
    except (OSError, ValueError):
        return None


def _location(plist: dict) -> Optional[str]:
    """Normalised absolute install location, or None when not trustworthy."""
    if plist.get("volume") != "/":
        return None
    loc = plist.get("install-location")
    if not isinstance(loc, str) or oc.bad_name(loc):
        return None
    if ".." in loc.split("/"):
        return None
    norm = posixpath.normpath("/" + loc.strip("/"))
    if norm.startswith("//"):
        norm = norm[1:]
    if oc.is_removable_location(norm):
        return None
    if any(_under(norm, p) for p in STAGING_PREFIXES):
        return None
    if norm not in STABLE_PARENTS:
        return None
    return norm


def sample_files(pkg_id: str, files: list) -> list:
    """Deterministic stratified sample of a sorted file list."""
    n = len(files)
    if n <= SAMPLE_HEAD + SAMPLE_TAIL + SAMPLE_RANDOM:
        return list(files)
    seed = int.from_bytes(hashlib.sha256(pkg_id.encode("utf-8")).digest()[:8], "big")
    rng = random.Random(seed)
    mid = range(SAMPLE_HEAD, n - SAMPLE_TAIL)
    picks = sorted(rng.sample(mid, min(SAMPLE_RANDOM, len(mid))))
    return files[:SAMPLE_HEAD] + [files[i] for i in picks] + files[n - SAMPLE_TAIL:]


class StaleReceiptReporter(oc.OrphanReporter):
    """Receipts are examined in sorted id order, so when a scan is cut short
    the unexamined ones are the alphabetically last; the stop note says so."""

    id = "stale_receipts"
    name = "Install records of removed packages"
    description = "Installer receipts whose installed files are all gone (report only)"
    platforms = (MACOS,)
    scope = SCOPE_SYSTEM

    def available(self) -> Optional[str]:
        if oc.tool("pkgutil") is None:
            return "pkgutil not found"
        return None

    def _timeout(self) -> int:
        """Per-call timeout: never more than the time left in the budget."""
        b = self.budget
        if b._start is None:
            b.start()
        remaining = b.max_seconds - (b._clock() - b._start)
        return max(1, min(MAX_CALL_TIMEOUT, int(remaining)))

    def _run(self, argv):
        return oc.run(argv, self._timeout())

    # ------------------------------------------------------------ discovery
    def system_findings(self) -> Iterable[oc.Finding]:
        receipts_dir = oc.in_root(self.sysroot, RECEIPTS_DIR)
        rc, out, _ = self._run(["pkgutil", "--pkgs"])
        if rc != 0 or len(out) > MAX_OUTPUT_CHARS:
            yield self.note(
                receipts_dir,
                "Not checked: could not list installer receipts",
                "Run pkgutil --pkgs yourself to see why it failed.",
            )
            return
        ids = sorted(
            {
                ln.strip()
                for ln in out.splitlines()
                if ln.strip()
                and not ln.strip().startswith("com.apple.")
                and _ID_RE.match(ln.strip())
            }
        )
        self._app_dirs = self._application_dirs()
        self._unchecked = 0
        for n, pkg_id in enumerate(ids):
            reason = None
            if self.budget.expired():
                reason = self.budget.stop_reason or "limit"
            elif n >= MAX_RECEIPTS:
                reason = "receipt limit"
            if reason:
                if not self._stop_noted:
                    self._stop_noted = True
                    yield self.note(
                        Path(self.sysroot),
                        f"Scan stopped early ({reason}); results are incomplete",
                        "Receipts are checked in alphabetical order; later ones "
                        "were not examined. Raise orphan_max_seconds to scan further.",
                        requires_root=False,
                    )
                return
            finding = self._check(pkg_id)
            if finding is not None:
                yield finding
        if self._unchecked:
            yield self.note(
                receipts_dir,
                f"{self._unchecked} receipts could not be checked",
                "pkgutil gave no usable answer for them; they are not reported.",
            )

    def _application_dirs(self) -> list:
        dirs = [oc.in_root(self.sysroot, d) for d in APP_DIRS]
        users = oc.list_dir(oc.in_root(self.sysroot, "/Users")) or []
        for u in sorted(users)[:200]:
            dirs.append(u / "Applications")
        return dirs

    # -------------------------------------------------------------- checking
    def _check(self, pkg_id: str) -> Optional[oc.Finding]:
        receipt = self._receipt_path(pkg_id)
        if receipt is None:
            return None
        rc, out, _ = self._run(["pkgutil", "--pkg-info-plist", pkg_id])
        if rc != 0 or len(out) > MAX_OUTPUT_CHARS:
            self._unchecked += 1
            return None
        try:
            plist = plistlib.loads(out.encode("utf-8"))
        except Exception:  # noqa: BLE001 - expat and friends on odd output
            self._unchecked += 1
            return None
        if not isinstance(plist, dict):
            self._unchecked += 1
            return None
        location = _location(plist)
        if location is None or self.budget.expired():
            return None

        rc, out, _ = self._run(["pkgutil", "--only-files", "--files", pkg_id])
        if rc != 0 or len(out) > MAX_OUTPUT_CHARS:
            self._unchecked += 1
            return None
        # --only-files ordering is not stable: sort before sampling.
        files = sorted({ln for ln in out.splitlines() if ln.strip()})
        if not files:
            return None
        for rel in files:
            if oc.bad_name(rel) or ".." in rel.split("/"):
                return None  # cannot be judged safely
        for rel in sample_files(pkg_id, files):
            logical = posixpath.normpath(location.rstrip("/") + "/" + rel.lstrip("/"))
            if _exists(oc.in_root(self.sysroot, logical)) is not False:
                return None  # present, or unknown (early exit)
        if self._bundle_survives(location, files):
            return None
        q = shlex.quote(pkg_id)
        return oc.Finding(
            receipt,
            f"Install record for a removed package: {pkg_id}",
            "This package may no longer be installed. After confirming with "
            f"`pkgutil --pkg-info {q}` and `pkgutil --files {q}`, you can drop "
            f"only that record: sudo pkgutil --forget {q}",
            requires_root=True,
        )

    def _bundle_survives(self, location: str, files: list) -> bool:
        """A top-level bundle (``Foo.app``, ``*.framework`` ...) still exists in
        the install location or an application folder (moved/renamed app).
        Plain top-level folders (``usr``) are shared and prove nothing."""
        bundles = set()
        for rel in files:
            first, sep, _ = rel.lstrip("/").partition("/")
            if sep and "." in first.strip("."):
                bundles.add(first)
        if len(bundles) > MAX_BUNDLES:
            return True  # too many to judge: unknown
        for b in sorted(bundles):
            at = oc.in_root(self.sysroot, location.rstrip("/") + "/" + b)
            if _exists(at) is not False:
                return True
            for d in self._app_dirs:
                if _exists(d / b) is not False:
                    return True
        return False

    def _receipt_path(self, pkg_id: str) -> Optional[Path]:
        for ext in ("plist", "bom"):
            p = oc.in_root(self.sysroot, f"{RECEIPTS_DIR}/{pkg_id}.{ext}")
            if os.path.islink(p):
                return None  # never judge or report through a link
            if _exists(p) is True:
                return p
        return None
