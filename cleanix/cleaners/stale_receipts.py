"""Report-only: macOS installer receipts of packages whose files are all gone.

Receipts live in ``/private/var/db/receipts``; ``pkgutil`` lists them and the
files each one installed. A receipt is reported only on positive evidence:
its file list is non-empty and none of the first 50 files exists any more.

Unknown is not stale: ``com.apple.*`` receipts, volumes other than ``/``,
failing or unparsable ``pkgutil`` answers, an install location that still
exists, anything whose existence cannot be determined, and receipts without a
file on disk are never reported. Nothing is ever forgotten or removed; each
hint names the one receipt only.
"""

from __future__ import annotations

import os
import plistlib
import posixpath
import re
import shlex
from pathlib import Path
from typing import Iterable, Optional

from cleanix.cleaners import orphan_common as oc
from cleanix.cleaners.base import SCOPE_SYSTEM
from cleanix.core.platform import MACOS

RECEIPTS_DIR = "/private/var/db/receipts"
SAMPLE_FILES = 50
MAX_OUTPUT_CHARS = 4 * 1024 * 1024
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
# Install locations shared by many packages: they always exist, so their
# existence says nothing about one package.
_SHARED_LOCATIONS = frozenset(
    {
        "/", "/Applications", "/Library", "/Library/Application Support",
        "/usr", "/usr/local", "/usr/local/bin", "/usr/local/lib",
        "/usr/local/share", "/opt", "/private", "/Users",
    }
)


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
    """Normalised absolute install location, or None when not usable."""
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
    return norm


class StaleReceiptReporter(oc.OrphanReporter):
    id = "stale_receipts"
    name = "Install records of removed packages"
    description = "Installer receipts whose installed files are all gone (report only)"
    platforms = (MACOS,)
    scope = SCOPE_SYSTEM

    def available(self) -> Optional[str]:
        if oc.tool("pkgutil") is None:
            return "pkgutil not found"
        return None

    # ------------------------------------------------------------ discovery
    def system_findings(self) -> Iterable[oc.Finding]:
        rc, out, _ = oc.run(["pkgutil", "--pkgs"])
        if rc != 0 or len(out) > MAX_OUTPUT_CHARS:
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
        for pkg_id in ids:
            if not self.budget.take():
                if not self._stop_noted:
                    self._stop_noted = True
                    yield self.note(
                        Path(self.sysroot),
                        "Scan stopped early "
                        f"({self.budget.stop_reason or 'limit'}); results are incomplete",
                        "Raise orphan_max_items / orphan_max_seconds in the "
                        "config to scan further.",
                        requires_root=False,
                    )
                return
            finding = self._check(pkg_id)
            if finding is not None:
                yield finding

    # -------------------------------------------------------------- checking
    def _check(self, pkg_id: str) -> Optional[oc.Finding]:
        receipt = self._receipt_path(pkg_id)
        if receipt is None:
            return None
        rc, out, _ = oc.run(["pkgutil", "--pkg-info-plist", pkg_id])
        if rc != 0 or len(out) > MAX_OUTPUT_CHARS:
            return None
        try:
            plist = plistlib.loads(out.encode("utf-8"))
        except Exception:  # noqa: BLE001 - expat and friends on odd output
            return None
        if not isinstance(plist, dict):
            return None
        location = _location(plist)
        if location is None:
            return None
        if location not in _SHARED_LOCATIONS and (
            _exists(oc.in_root(self.sysroot, location)) is not False
        ):
            return None  # the package's own folder is still there (or unknown)

        rc, out, _ = oc.run(["pkgutil", "--only-files", "--files", pkg_id])
        if rc != 0 or len(out) > MAX_OUTPUT_CHARS:
            return None
        files = [ln for ln in out.splitlines() if ln.strip()][:SAMPLE_FILES]
        if not files:
            return None
        for rel in files:
            if oc.bad_name(rel) or ".." in rel.split("/"):
                return None  # cannot be judged safely
            logical = posixpath.normpath(location.rstrip("/") + "/" + rel.lstrip("/"))
            if _exists(oc.in_root(self.sysroot, logical)) is not False:
                return None  # present, or unknown
        q = shlex.quote(pkg_id)
        return oc.Finding(
            receipt,
            f"Install record for a removed package: {pkg_id}",
            f"See what it installed: pkgutil --files {q}. "
            f"To drop only the record: sudo pkgutil --forget {q}.",
            requires_root=True,
        )

    def _receipt_path(self, pkg_id: str) -> Optional[Path]:
        for ext in ("plist", "bom"):
            p = oc.in_root(self.sysroot, f"{RECEIPTS_DIR}/{pkg_id}.{ext}")
            if _exists(p) is True:
                return p
        return None
