"""Registry: dead file-type handlers (ProgId / Applications entries).

Reads only below the detector's own containers and never writes. An entry is
reported only when its whole subtree has the plain "shell\\<verb>\\command"
shape (plus an optional DefaultIcon), every command and icon target is
provably MISSING, and nothing else (CLSID, shellex, CurVer, URL Protocol,
DelegateExecute, AppX identity, unknown values) is present. Unknown is not
dead: any doubt keeps the entry. File extension keys are never reported.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple

from cleanix.cleaners.winreg_base import Finding, RegistryDetector
from cleanix.core import regsnap
from cleanix.core.models import RegTarget
from cleanix.core.regbackup import backup_problem
from cleanix.core.regsafety import Container, check_target
from cleanix.core.regtargets import DetectorContext, Existence, strip_icon_index, target_state
from cleanix.core.winregistry import (
    REG_EXPAND_SZ,
    REG_SZ,
    RegistryBackend,
    RegistryError,
    RegValue,
)

# Values tolerated beside the structure (all casefolded). Anything else on an
# entry, verb or command key means we do not understand it: keep it.
_ENTRY_VALUES = frozenset(
    {"", "friendlyappname", "friendlytypename", "editflags", "noopenwith",
     "nostaticdefaultverb", "alwaysshowext", "nevershowext"}
)
_VERB_VALUES = frozenset(
    {"", "muiverb", "extended", "icon", "noworkingdirectory", "friendlyappname",
     "position"}
)
# Well-known Windows Applications\ entries, never reported whatever they say.
_WINDOWS_APPS = frozenset(
    {"notepad.exe", "wordpad.exe", "mspaint.exe", "explorer.exe", "iexplore.exe",
     "write.exe", "calc.exe", "cmd.exe", "powershell.exe", "regedit.exe",
     "mmc.exe", "control.exe", "msedge.exe", "wmplayer.exe", "snippingtool.exe",
     "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"}
)
# Well-known Windows ProgIds and categories the guard's deny list does not
# cover; never reported (conservative, casefolded).
_WINDOWS_PROGIDS = frozenset(
    {"txtfile", "http", "https", "ftp", "file", "mailto", "regfile", "inffile",
     "inifile", "htmlfile", "jpegfile", "pngfile", "giffile", "bmpfile",
     "cplfile", "dllfile", "sysfile", "vbsfile", "vbefile", "jsfile", "jsefile",
     "wsffile", "wshfile", "chm.file", "helpfile", "cabfile", "cdafile",
     "mscfile", "themefile", "icofile", "curfile", "anifile",
     "component categories", "shell", "search", "search-ms", "telnet", "news",
     "nntp", "snews", "gopher", "tn3270", "ie.http", "ie.ftp", "ie.file",
     "mhtmlfile", "xmlfile", "urlfile", "internetshortcut", "shortcut",
     "scrfile", "ocxfile", "pffile", "fonfile", "ttffile", "otffile",
     "cabfolder", "sendto", "droptarget", "desktop", "network", "printers",
     "recyclebin"}
)
_STRING_TYPES = (REG_SZ, REG_EXPAND_SZ)


def _fold(items: Iterable[str]) -> Dict[str, str]:
    return {i.casefold(): i for i in items}


class WinRegFileAssoc(RegistryDetector):
    id = "win_reg_file_assoc"
    name = "Registry: dead file-type handlers"
    description = "Open-with handlers pointing at deleted programs (opt-in)"

    def entries(
        self, container: Container, backend: RegistryBackend, ctx: DetectorContext
    ) -> Iterable[Finding]:
        if container.hive == "HKCU" and not ctx.owner_matches:
            return  # another user's (or the helper's) HKCU is never judged
        try:
            names = backend.subkeys(container.hive, container.key)
        except RegistryError:
            return
        machine = container.hive == "HKLM"
        for name in sorted(names):
            if name.casefold() in _WINDOWS_APPS | _WINDOWS_PROGIDS:
                continue
            key = container.key + "\\" + name
            target = RegTarget(container.hive, key, None, "")
            if check_target(self.id, target) is not None:
                continue
            try:
                evidence = self._evidence(backend, ctx, container.hive, key, machine)
                if evidence is None:
                    continue
                snap = regsnap.snapshot(backend, target)
                if backup_problem(self.id, target, snap) is not None:
                    continue
            except (RegistryError, regsnap.SnapshotError):
                continue
            yield Finding(target, f"File-type handler: {name}", "; ".join(evidence))

    # -- structure and evidence -------------------------------------------
    def _read(
        self, backend: RegistryBackend, hive: str, key: str
    ) -> Optional[Tuple[Dict[str, str], Dict[str, RegValue]]]:
        """Subkeys (folded) and values (folded) of a non-link key, or None."""
        if backend.is_link(hive, key):
            return None
        subs = _fold(backend.subkeys(hive, key))
        vals = {v.name.casefold(): v for v in backend.values(hive, key)}
        return subs, vals

    def _evidence(
        self,
        backend: RegistryBackend,
        ctx: DetectorContext,
        hive: str,
        key: str,
        machine: bool,
    ) -> Optional[List[str]]:
        top = self._read(backend, hive, key)
        if top is None:
            return None
        subs, vals = top
        if not set(vals) <= _ENTRY_VALUES:
            return None
        if not set(subs) <= {"shell", "defaulticon"} or "shell" not in subs:
            return None
        evidence: List[str] = []

        shell = self._read(backend, hive, key + "\\" + subs["shell"])
        if shell is None:
            return None
        verbs, shell_vals = shell
        if not verbs or not set(shell_vals) <= {""}:
            return None
        for verb_fold in sorted(verbs):
            vkey = f"{key}\\{subs['shell']}\\{verbs[verb_fold]}"
            verb = self._read(backend, hive, vkey)
            if verb is None:
                return None
            vsubs, vvals = verb
            if set(vsubs) != {"command"} or not set(vvals) <= _VERB_VALUES:
                return None
            icon = vvals.get("icon")
            if icon is not None:
                if icon.type not in _STRING_TYPES or not isinstance(icon.data, str):
                    return None
                raw = strip_icon_index(icon.data)
                state = target_state(raw, command=False, ctx=ctx, machine=machine)
                evidence.append(f"{verbs[verb_fold]} Icon {icon.data}: {state.value}")
                if state is not Existence.MISSING:
                    return None
            ckey = f"{vkey}\\{vsubs['command']}"
            cmd = self._read(backend, hive, ckey)
            if cmd is None:
                return None
            csubs, cvals = cmd
            if csubs or set(cvals) != {""}:
                return None
            default = cvals[""]
            if default.type not in _STRING_TYPES or not isinstance(default.data, str):
                return None
            state = target_state(default.data, command=True, ctx=ctx, machine=machine)
            evidence.append(
                f"shell\\{verbs[verb_fold]}\\command {default.data}: {state.value}"
            )
            if state is not Existence.MISSING:
                return None

        if "defaulticon" in subs:
            ikey = key + "\\" + subs["defaulticon"]
            icon_node = self._read(backend, hive, ikey)
            if icon_node is None:
                return None
            isubs, ivals = icon_node
            if isubs or set(ivals) != {""}:
                return None
            default = ivals[""]
            if default.type not in _STRING_TYPES or not isinstance(default.data, str):
                return None
            raw = strip_icon_index(default.data)
            state = target_state(raw, command=False, ctx=ctx, machine=machine)
            evidence.append(f"DefaultIcon {default.data}: {state.value}")
            if state is not Existence.MISSING:
                return None
        return evidence
