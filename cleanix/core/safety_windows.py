"""Pure Windows path-protection model.

Only string logic via ``ntpath``: no filesystem access and no dependence on the
host OS, so it is testable everywhere. Paths are compared component by
component (never by string prefix), so ``C:\\Windows2`` is not inside
``C:\\Windows``.
"""
from __future__ import annotations

import ntpath
from typing import List, Mapping, Optional, Sequence, Tuple

# The only subpaths of %SystemRoot% that may be deleted (relative, casefolded).
SYSTEMROOT_ALLOWED: Tuple[str, ...] = (
    "temp",
    "softwaredistribution\\download",
    "prefetch",
    "minidump",
    "livekernelreports",
    "logs\\cbs",
    "memory.dmp",
    "serviceprofiles\\networkservice\\appdata\\local\\microsoft\\windows\\deliveryoptimization\\cache",
)

# Allowed when equal; every other entry is allowed only strictly below it.
_ALLOWED_FILES = ("memory.dmp",)

_USER_PROTECTED = (
    "Documents", "Desktop", "Downloads", "Pictures", "Music", "Videos",
    "OneDrive", "AppData", "AppData\\Roaming", "AppData\\Local",
    "AppData\\LocalLow", ".ssh", ".gnupg",
)

_ENV_DEFAULTS = {
    "systemroot": "C:\\Windows",
    "systemdrive": "C:",
    "programfiles": "C:\\Program Files",
    "programfiles(x86)": "C:\\Program Files (x86)",
    "programdata": "C:\\ProgramData",
}


def normalize(path: str) -> str:
    """Canonical comparison form: no ``\\\\?\\`` prefix, backslashes, normpath,
    casefolded, no trailing separator except on a drive root."""
    # Convert "/" first so mixed-separator prefixes (//?\C:\x) are recognised.
    p = str(path).replace("/", "\\")
    if p[:4] in ("\\\\?\\", "\\\\.\\"):
        p = p[4:]
        if p[:4].upper() == "UNC\\":
            p = "\\\\" + p[4:]
    drive, tail = ntpath.splitdrive(p)
    comps = []
    for c in tail.split("\\"):
        if c not in (".", ".."):
            # NTFS stream suffix (name:stream:$TYPE) and trailing dots/spaces
            # are ignored by Windows; strip them so they cannot dodge the check.
            c = c.split(":", 1)[0].rstrip(". ")
        comps.append(c)
    p = ntpath.normpath(drive + "\\".join(comps)).casefold()
    drive, tail = ntpath.splitdrive(p)
    if tail not in ("", "\\"):
        p = drive + tail.rstrip("\\")
    return p


def _parts(norm: str) -> List[str]:
    drive, tail = ntpath.splitdrive(norm)
    return [drive] + [c for c in tail.split("\\") if c]


def _is_under(parts: List[str], root: List[str]) -> bool:
    """True if ``parts`` equals ``root`` or is inside it (component-wise)."""
    return len(parts) >= len(root) and parts[: len(root)] == root


def _is_absolute(norm: str) -> bool:
    drive, tail = ntpath.splitdrive(norm)
    return bool(drive) and tail.startswith("\\")


def _is_root(norm: str) -> bool:
    drive, tail = ntpath.splitdrive(norm)
    return bool(drive) and tail in ("", "\\")


def _env(env: Mapping[str, str], key: str) -> str:
    """Env value, or the documented default if missing/malformed (fail closed)."""
    lk = key.lower()
    default = _ENV_DEFAULTS[lk]
    for k, val in env.items():
        if str(k).lower() == lk and val:
            n = normalize(str(val))
            if lk == "systemdrive":
                if len(n) == 2 and n[1] == ":" and n[0].isalpha():
                    return str(val)
            elif _is_absolute(n) and not _is_root(n) and not n.startswith("\\\\"):
                return str(val)
    return default


def _both(env: Mapping[str, str], key: str) -> List[str]:
    """Normalised env-derived value plus the default (deduplicated)."""
    out = [normalize(_env(env, key))]
    d = normalize(_ENV_DEFAULTS[key.lower()])
    if d not in out:
        out.append(d)
    return out


def violation(target: str, env: Mapping[str, str], homes: Sequence[str]) -> Optional[str]:
    """Return a refusal reason, or ``None`` if ``target`` may be deleted."""
    if not target or not str(target).strip():
        return "empty path"
    t = normalize(target)
    if t.startswith("\\\\"):
        return f"UNC paths are never deleted: {target}"
    if not _is_absolute(t):
        return f"not an absolute Windows path: {target}"
    if _is_root(t):
        return f"refusing drive root: {target}"
    tp = _parts(t)

    sysroots = _both(env, "SystemRoot")
    sysdrives = _both(env, "SystemDrive")
    pfs = _both(env, "ProgramFiles") + _both(env, "ProgramFiles(x86)")
    pdatas = _both(env, "ProgramData")

    protected = sysroots + pfs + pdatas
    for sd in sysdrives:
        protected += [sd + "\\" + n for n in
                      ("users", "system volume information", "$recycle.bin", "recovery", "boot")]
    for home in homes:
        h = normalize(home)
        protected.append(h)
        protected += [normalize(h + "\\" + s) for s in _USER_PROTECTED]

    for root in protected:
        if _is_absolute(root) and _is_under(_parts(root), tp):
            return f"protected location (or contains one): {target}"

    for sysroot in sysroots:
        sp = _parts(sysroot)
        if _is_under(tp, sp):
            for allowed in SYSTEMROOT_ALLOWED:
                ap = sp + _parts("x:\\" + allowed)[1:]
                if allowed in _ALLOWED_FILES:
                    if _is_under(tp, ap):
                        return None
                elif len(tp) > len(ap) and _is_under(tp, ap):
                    return None  # strictly below an allowed directory
            return f"inside the Windows directory and not an allowed cleanup path: {target}"

    for pfroot in pfs:
        if _is_under(tp, _parts(pfroot)):
            return f"inside Program Files: {target}"
    return None
