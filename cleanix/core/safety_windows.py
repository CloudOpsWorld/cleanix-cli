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
    p = str(path)
    if p[:4] in ("\\\\?\\", "//?/", "\\\\.\\", "//./"):
        p = p[4:]
        if p[:4].upper() == "UNC\\" or p[:4].upper() == "UNC/":
            p = "\\\\" + p[4:]
    p = p.replace("/", "\\")
    p = ntpath.normpath(p).casefold()
    drive, tail = ntpath.splitdrive(p)
    if tail not in ("", "\\"):
        tail = tail.rstrip("\\")
        p = drive + tail
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
    lk = key.lower()
    for k, val in env.items():
        if str(k).lower() == lk and val:
            return str(val)
    return _ENV_DEFAULTS[lk]


def violation(target: str, env: Mapping[str, str], homes: Sequence[str]) -> Optional[str]:
    """Return a refusal reason, or ``None`` if ``target`` may be deleted."""
    if not target or not str(target).strip():
        return "empty path"
    t = normalize(target)
    if not _is_absolute(t):
        return f"not an absolute Windows path: {target}"
    if _is_root(t):
        return f"refusing drive or share root: {target}"
    tp = _parts(t)

    sysroot = normalize(_env(env, "SystemRoot"))
    sysdrive = normalize(_env(env, "SystemDrive")).rstrip("\\")
    pf = normalize(_env(env, "ProgramFiles"))
    pf86 = normalize(_env(env, "ProgramFiles(x86)"))
    pdata = normalize(_env(env, "ProgramData"))

    protected = [sysroot, pf, pf86, pdata]
    protected += [sysdrive + "\\" + n for n in
                  ("users", "system volume information", "$recycle.bin", "recovery", "boot")]
    for home in homes:
        h = normalize(home)
        protected.append(h)
        protected += [normalize(h + "\\" + s) for s in _USER_PROTECTED]

    for root in protected:
        if _is_absolute(root) and _is_under(_parts(root), tp):
            return f"protected location (or contains one): {target}"

    sp = _parts(sysroot)
    if _is_under(tp, sp):
        for allowed in SYSTEMROOT_ALLOWED:
            if _is_under(tp, sp + _parts("x:\\" + allowed)[1:]):
                return None
        return f"inside the Windows directory and not an allowed cleanup path: {target}"

    for pfroot in (pf, pf86):
        if _is_under(tp, _parts(pfroot)):
            return f"inside Program Files: {target}"
    return None
