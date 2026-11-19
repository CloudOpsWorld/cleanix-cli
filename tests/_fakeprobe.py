"""Shared fakes for target-evidence tests (filesystem, WinProber context)."""

from __future__ import annotations

from types import SimpleNamespace

from cleanix.core.regtargets import DetectorContext, WinProber, microsoft_roots


ENV = {
    "ProgramFiles": r"C:\Program Files",
    "ProgramW6432": r"C:\Program Files",
    "ProgramFiles(x86)": r"C:\Program Files (x86)",
    "ProgramData": r"C:\ProgramData",
    "LOCALAPPDATA": r"C:\Users\me\AppData\Local",
    "SystemRoot": r"C:\Windows",
    "SystemDrive": "C:",
}


class WinErr(OSError):
    def __init__(self, code: int) -> None:
        super().__init__(f"winerror {code}")
        self._code = code

    @property
    def winerror(self):  # type: ignore[override]
        return self._code


class FakeFS:
    """Casefolded present set; everything else raises winerror 3 unless listed."""

    def __init__(self, present=(), errors=None, drives=None, bad_roots=(), reparse=()):
        self.present = {p.casefold() for p in present}
        self.reparse = {p.casefold() for p in reparse}
        self.errors = {k.casefold(): v for k, v in (errors or {}).items()}
        self.drives = {"C:": 3}
        self.drives.update(drives or {})
        self.bad_roots = {r.casefold() for r in bad_roots}
        self.roots = {d.casefold() + "\\" for d in self.drives}

    def drive_type(self, root: str) -> int:
        return self.drives.get(root[:2].upper(), 1)  # 1 = no root dir

    def lstat(self, path: str):
        key = path.casefold()
        if key in self.bad_roots:
            raise WinErr(5)
        if key in self.errors:
            raise WinErr(self.errors[key])
        if key in self.present or key in self.roots:
            attrs = 0x400 if key in self.reparse else 0x10
            return SimpleNamespace(st_file_attributes=attrs)
        raise WinErr(3)


def make_ctx(fs: FakeFS, env=ENV) -> DetectorContext:
    prober = WinProber(
        system_root=r"C:\Windows",
        program_files=microsoft_roots(env, "C:"),
        program_data=r"C:\ProgramData",
        local_appdata=r"C:\Users\me\AppData\Local",
        drive_type=fs.drive_type,
        lstat=fs.lstat,
    )
    return DetectorContext(
        env=env, prober=prober, profiles_root=r"C:\Users", system_root=r"C:\Windows"
    )
