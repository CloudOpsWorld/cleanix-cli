# Windows Registry Cleanup (Sub-project B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let Windows users find and remove provably dead registry entries (Uninstall, App Paths, file-association handlers, Run/RunOnce, SharedDLLs) from HKCU/HKLM `SOFTWARE`. Every delete is preceded by a mandatory backup and can be undone. Every registry cleaner is opt-in.

**Architecture:** A new `ItemKind.REGISTRY` carries a `RegTarget` (hive, physical key path, optional value name, content fingerprint). All registry I/O goes through a `RegistryBackend` Protocol (`cleanix/core/winregistry.py`). The `winreg` implementation lives in one Windows-only module, and tests inject an in-memory fake. Pure modules decide everything else:
- `regsafety` (allowlist and denylist),
- `regsnap` (snapshot and fingerprint),
- `regtargets` ("is this target provably missing?": tri-state),
- `regbackup` (`.reg` and JSON backup, restore).

Five detector cleaners yield only provably dead entries. The engine deletes a registry item only after a backup sink has written and verified its backup. HKCU items are cleaned in-process. HKLM items go through the existing elevated helper, using the existing re-scan and key-match pattern: the fingerprint is part of the item key, so a changed entry no longer matches. The GUI writes the HKLM backup as the user before it launches the helper.

**Tech Stack:** Python 3.10+, stdlib `winreg` (Windows only, imported lazily in one module), `hashlib`/`json`/`base64`, existing engine, quarantine, elevated helper and PySide6 GUI (optional extra), pytest/pytest-qt.

**Spec:** `docs/superpowers/specs/2026-11-19-curated-listings-and-orphans-design.md` section B (binding). Parent design: `docs/superpowers/specs/2026-11-16-windows-and-gui-design.md`. Its "registry cleaning" non-goal is superseded only as recorded in Ruling R1.

**Dependency waves** (tasks within a wave touch disjoint files and can run in parallel worktrees):
- **W0:** T1
- **W1:** T2, T3, T4, T5
- **W2:** T6, T7, T8, T9, T10, T11
- **W3:** T12, T13
- **W4:** T14

Merge order inside a wave is free. Merge each wave before starting the next.

## Global Constraints

- Python 3.10+; no new dependencies. `import winreg` appears **only** in `cleanix/core/winregistry_win.py`, which is imported lazily and only when `sys.platform == "win32"`. Every `cleanix.core.*` module must import on Linux and macOS. The new abstraction is `winregistry`, never `registry`: `cleanix/core/registry.py` is the cleaner registry and keeps its name.
- Hives: `HKCU` and `HKLM` only, and the first key component must be `SOFTWARE`. `HKEY_CLASSES_ROOT`, `HKEY_USERS` and `HKEY_CURRENT_CONFIG` are never opened. Keys are always addressed by their **physical** path (with a literal `WOW6432Node` where it applies), opened with `KEY_WOW64_64KEY`.
- Registry cleaner ids:
  - `win_reg_uninstall`
  - `win_reg_app_paths`
  - `win_reg_file_assoc`
  - `win_reg_startup`
  - `win_reg_shared_dlls`

  All of them use `platforms=(WINDOWS,)`, `scope=SCOPE_SYSTEM`, `default_enabled=False`, `safe_default=False` and class-level `requires_root=False`. Each item sets `requires_root = (hive == "HKLM")`. Category `"registry"`, label `"Registry leftovers"`, is in `_NEVER_PRESELECT`. Safety badge: `Review` for every REGISTRY item.
- "Unknown is not dead." An entry is listed only when every piece of evidence the detector requires is `Existence.MISSING`. Any `UNKNOWN` drops the entry.
- No REGISTRY item is deleted without a backup sink. Rules for the backup:
  - It is written and read back before the delete. If the backup fails, nothing is deleted.
  - It is independent of "keep a copy" and `--quarantine`.
  - The delete re-reads the entry and proceeds only if the fingerprint still equals the scanned one.
- The file deletion guard `cleanix/core/safety.py` is unchanged. Registry rules live in `cleanix/core/regsafety.py`.
- Tests never touch the real registry. An autouse fixture installs a backend that raises on any call. Tests still never create `HKCU\Software\Cleanix` (QSettings isolation stands). The manual verification script uses only `HKCU\Software\CleanixTest` and removes it.
- Undo is promised only where it is true:
  - HKCU registry entries: restorable from the Power Quarantine tab or `cleanix restore`. Simple mode never cleans registry items (R13).
  - HKLM entries: backed up, but restorable only from an Administrator terminal, either `cleanix restore <run>` or `reg import "<absolute .reg path>"`. See R6.
- The five ids are defined once, as `catalog.REGISTRY_IDS`. The CLI and the helper import that tuple and never repeat the list.
- Commit trailer: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Do not push or merge to main.
- Test command (repo root): `QT_QPA_PLATFORM=offscreen PYTHONPATH=. PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider <paths>`. GUI tests skip cleanly without PySide6.

## Review Focus

1. **The entry changes between scan and clean** (the app was reinstalled, or a value was edited). Expected: nothing is deleted, the outcome says "changed since the scan; scan again", and no orphan backup entry is marked deleted. Test owner: T11.
2. **A delete fails half-way** (ACL on one subkey, a key locked by another process). Expected: the preflight catches it before anything is deleted. If the delete still fails mid-tree, the outcome names the backup run, and restore recreates exactly the missing parts. Test owners: T11 and T4.
3. **The backup location is unwritable or the disk is full.** Expected: zero registry writes, an error outcome per item, and file items in the same clean are unaffected. Test owner: T11.
4. **A tampered or foreign backup in the quarantine dir** (a JSON entry pointing at `HKLM\SYSTEM`, or at a key outside its detector container). Expected: restore refuses that entry and writes nothing. Test owner: T4.
5. **Odd names and data**: Unicode, `"` and `\` in names, SharedDLLs value names that are full paths, REG_SZ with embedded CR/LF, REG_MULTI_SZ with empty strings, unknown value types (e.g. 0x20). Expected: an exact round-trip through the `.reg` text, the JSON and restore. Test owner: T4.

## Rulings (decisions where the spec is silent; cost if wrong)

- **R1** The parent spec's "registry cleaning / startup-item disabling" non-goal is superseded **only** for provably dead entries. Live entries are never touched, and nothing is "disabled" (no `StartupApproved` edits). *Cost if wrong:* a reviewer reads startup cleanup as the forbidden "disabling". Mitigation: the copy says "points at a program that no longer exists".
- **R2** One cleaner id per detector, covering both hives, with per-item `requires_root`. The alternative was 9 hive-split ids. *Cost:* a user cannot opt into HKCU-only for one detector except by not elevating. The helper never deletes HKCU items: they are not `requires_root`, and T13 adds an explicit hive check.
- **R3** The badge for REGISTRY items is `Review` even when they need admin (spec: safety Review). The administrator need is still shown in the row, tooltip and detail pane, and still gates selection. *Cost:* the badge under-signals elevation.
- **R4** The backup is two files from the same snapshot:
  - `N__registry.reg`: UTF-16LE with BOM, CRLF, `Windows Registry Editor Version 5.00`, no line wrapping. It is for humans, regedit and manual `reg import`.
  - `N__registry.json`: typed values with base64 binary data. It is the machine source for Undo.

  Undo re-creates entries with `winreg` from the JSON and never runs `reg import`. Reasons: `reg import` silently overwrites, reports only an exit code, and would import whatever a user-writable file says. Re-creation re-validates every path. *Cost:* two formats that must agree. A test serializes both from one snapshot and checks they decode to the same values.
- **R5** The backup is mandatory and independent of keep-copy. A quarantine run is created for registry items alone (CLI without `--quarantine`, GUI with "keep a copy" off). *Cost:* small `.reg`/`.json` files remain until the user empties quarantine.
- **R6** For HKLM, the GUI (as the user) writes the backup into a quarantine run, then launches the helper.
  - The helper writes nothing: the existing rule 8 stands.
  - The helper deletes only items whose key, which embeds the fingerprint, matches its own fresh scan, and re-checks the fingerprint immediately before the delete.
  - HKLM Undo is refused in a non-elevated process. The refusal names the run and the absolute `.reg` path, with both `cleanix restore <run>` and `reg import "<path>"` to be run from an Administrator terminal. `reg import` is the only route that works under over-the-shoulder UAC, where the administrator is a different account whose `%LOCALAPPDATA%` does not contain the run. The GUI never offers an elevated restore. An elevated import of a user-writable file would let a standard user plant HKLM entries, for example a Run entry.
  - *Cost:* no one-click Undo for machine entries (Open question 1).
- **R7** Restore is an additive merge. It recreates missing keys and values. A value that exists with identical type and data counts as restored. Any differing value fails the whole entry **before** anything is written. Security descriptors are neither backed up nor restored, so recreated keys inherit the parent ACL. *Cost:* a restored key loses a custom ACL. Dead entries rarely have one.
- **R8** The fingerprint is part of `item_key`, so a changed entry is "unmatched" in the helper. The request schema is unchanged. *Cost:* GUI selection does not survive a fingerprint change across rescans, which is correct behaviour.
- **R9** Registry items have size 0. They are never hidden as "empty", and `freed` stays 0 bytes: no space or speed claims.
- **R10** Detector containers are exact allowlisted keys.
  - A deletable target is either an entry key exactly one level below a key-container, or a value directly inside a value-container.
  - A container itself is never a target, and neither is a key that is another detector's container.
  - Microsoft or Windows ownership is judged per entry (values and target location), not by the `SOFTWARE\Microsoft\...` prefix, which every container shares.
- **R11** Existence is tri-state. MISSING requires an `lstat` failure with winerror 2 or 3 on a mounted fixed (`DRIVE_FIXED`) local drive whose root is readable. Everything else is UNKNOWN, including:
  - UNC paths, `\\.\`, unknown or removable drive letters, access denied;
  - unexpanded `%VAR%`;
  - relative paths and bare names;
  - host executables (`msiexec`, `rundll32`, `cmd`, `powershell`, `pwsh`, `wscript`, `cscript`, `regsvr32`, `mshta`, `explorer`, `conhost`, `dllhost`, `wsl`);
  - a `~N` short-name component that does not resolve;
  - any path under `%SystemRoot%`, which also sidesteps System32/SysWOW64 redirection;
  - `<PF>\WindowsApps`, `<PF>\Windows*`, `<PF>\Microsoft*`, `<PF>\Internet Explorer`, `%ProgramData%\Microsoft`, `%LOCALAPPDATA%\Microsoft` (Microsoft-owned, Features on Demand, App Execution Aliases). `<PF>` covers each of `%ProgramW6432%`, `%ProgramFiles%` and `%ProgramFiles(x86)%`, plus the literals `<SystemDrive>\Program Files` and `<SystemDrive>\Program Files (x86)`. The literals matter because a 32-bit Python sees `%ProgramFiles%` as the x86 folder, and the helper's sanitized environment drops `ProgramW6432` and `PUBLIC`;
  - for HKLM entries, anything under the profiles root (`C:\Users`), because it is another user's per-user install.

  *Cost:* some real dead entries are missed. That is accepted.
- **R12** Uninstall entries are skipped (as unknown or owned) when any of these holds:
  - `InstallLocation` is empty or absent (the spec needs both the location and the uninstaller to be gone);
  - `WindowsInstaller=1` (MSI-managed: deleting the ARP key desynchronises Installer);
  - `SystemComponent=1`;
  - `ParentKeyName` or `ReleaseType` is present;
  - the name matches `KB\d+`;
  - `Publisher` contains "microsoft" (casefold);
  - `DisplayName` is absent;
  - the entry has subkeys.
- **R13** Simple mode never scans the registry detectors (they are opt-in and Deep scan does not add them). On Windows it shows one static line: "Registry leftovers are checked only in Power mode." If registry items ever reach Simple (a shared scan result), they are read-only with the existing `NOT_FROM_SIMPLE` text. *Cost:* Simple users never see registry findings (Open question 2).
- **R14** CLI: `--registry` on `scan` and `clean` adds the five ids to `--only`. If `--only` was not given, it means "only the registry detectors". No default changes, and scheduled scans never include them. On non-Windows, `--registry` prints "Registry cleanup is only available on Windows." and exits 2.
- **R15** The scope is `SCOPE_SYSTEM`. HKCU is the hive of the running process: in an elevated CLI that is the administrator account's hive, and `--all-users` does not iterate other users' hives (NTUSER.DAT loading is out of scope).
- **R16** Snapshot limits: at most 256 keys, 4096 values and 1 MiB of data per target, and no registry link anywhere in the target tree. Above that, the target is skipped as ambiguous.
- **R17** No transactional registry API is used (that would need ctypes `RegCreateKeyTransacted`). The window between the final fingerprint check and the delete is accepted and documented.
  - The real consequence is worse than deleting a stale entry. `WinRegBackend.delete_key` checks link-ness and leaf-ness on a `REG_OPTION_OPEN_LINK` handle, then `DeleteKeyEx` resolves the path again. `RegDeleteKeyEx` very likely follows a registry link in the last path component. So if the leaf is replaced by a link inside that window, the link's **target** key may be deleted when it is a leaf.
  - Mitigations:
    - the window is minimal: the handle check runs immediately before `DeleteKeyEx`, with no other work in between;
    - Task 11 must re-verify the fingerprint of the target path immediately before each `delete_key`/`delete_value` call;
    - Task 14 measures what a raw `DeleteKeyEx` on a link path deletes.
  - The T3 tests model this pessimistically: `FakeWinreg(delete_follows_final_link=True)` and `test_r17_link_swapped_in_after_check_deletes_target`.

## Risks

- **False positives despite the rules.** Mitigated by the tri-state evidence, the per-detector structure checks, the false-positive matrix (T2), Review-only presentation, the mandatory backup and opt-in ids.
- **Undocumented `winreg` behaviour.** `REG_OPTION_OPEN_LINK` via `OpenKeyEx`'s `reserved` argument, `SymbolicLinkValue` detection, and `DeleteKeyEx` on 32-bit Python are verified only by T3's fake-module tests and by the T14 manual run on real Windows. Until T14 step 4 passes, the branch is not releasable.
- **HKLM undo friction** (R6). Users may expect one-click undo. The confirm text and README say exactly what is true.
- **Partially deleted trees.** Mitigated by the preflight `can_delete` on every key, bottom-up deletion and additive-merge restore.
- **Copy drift.** The existing every-cleaner-has-copy test covers the five new ids.
- **Helper allowlist growth.** Five new Windows ids. Their eligibility is narrowed to `REGISTRY` kind plus `HKLM` plus a regsafety pass, mirrored in `static_admin_problem` (parity test).

---

### Task 1: Foundation — item model, registry Protocol, safety rules, snapshot, catalog/copy, stub detectors

**Files:**
- Modify:
  - `cleanix/core/models.py`: `ItemKind.REGISTRY`, `RegTarget`, `CleanableItem.reg`, `item_key`, `item_target`.
  - `cleanix/core/engine.py`: fail-closed REGISTRY and unknown-kind branches only.
  - `cleanix/core/catalog.py`: category, ids, `_NEVER_PRESELECT`.
  - `cleanix/core/curation.py`: `is_empty`, `safety_of`, `display_label`, COPY entries.
  - `cleanix/cleaners/__init__.py`: register five detectors after `WslDiskReporter`.
  - `tests/conftest.py`: autouse no-real-registry fixture, `fake_registry` fixture.
- Create:
  - `cleanix/core/winregistry.py`
  - `cleanix/core/regsafety.py`
  - `cleanix/core/regsnap.py`
  - `cleanix/core/regtargets.py` (types only)
  - `cleanix/cleaners/winreg_base.py`
  - stubs `cleanix/cleaners/winreg_uninstall.py`, `winreg_app_paths.py`, `winreg_file_assoc.py`, `winreg_startup.py`, `winreg_shared_dlls.py`
  - `tests/_fakereg.py`
- Test: `tests/test_registry_foundation.py`

**Interfaces:**
- Consumes: `Cleaner`, `SCOPE_SYSTEM`, `WINDOWS`, `catalog._assign`, `curation._RAW`.
- Produces (exact):
  - `models.ItemKind.REGISTRY = "registry"`.
  - `@dataclass(frozen=True) models.RegTarget: hive: str; key: str; value: Optional[str] = None; fingerprint: str = ""`, plus property `display -> str`. It returns `f"{hive}\\{key}"`, followed by `f" [{value}]"` when `value` is not None.
  - `CleanableItem.reg: Optional[RegTarget] = None`. `__post_init__` requires the following for REGISTRY: `reg` set, `hive in {"HKCU","HKLM"}`, non-empty `key` and `fingerprint`, `path is None and command is None`. A non-REGISTRY item with `reg` set raises `ValueError`.
  - `item_key(item)` for REGISTRY: `f"{cid}|reg|" + json.dumps([hive, key, value, fingerprint], ensure_ascii=True)`.
  - `models.item_target(item) -> str`: path, command joined with spaces, or `reg.display`.
  - `winregistry`:
    - constants `REG_NONE=0, REG_SZ=1, REG_EXPAND_SZ=2, REG_BINARY=3, REG_DWORD=4, REG_DWORD_BIG_ENDIAN=5, REG_LINK=6, REG_MULTI_SZ=7, REG_QWORD=11`;
    - `@dataclass(frozen=True) RegValue: name: str; type: int; data: Union[str, int, bytes, Tuple[str, ...]]`;
    - exceptions `RegistryError(Exception)`, `KeyMissing(RegistryError)`, `AccessDenied(RegistryError)`, `RegistryUnavailable(RegistryError)`;
    - `class RegistryBackend(Protocol)`, where `hive` is `"HKCU"|"HKLM"` and `key` is the physical path:
      - `subkeys(hive, key) -> List[str]`
      - `values(hive, key) -> List[RegValue]`
      - `key_exists(hive, key) -> bool`
      - `is_link(hive, key) -> bool`
      - `can_delete(hive, key, value: Optional[str]) -> bool`
      - `delete_key(hive, key) -> None` (leaf only)
      - `delete_value(hive, key, name) -> None`
      - `create_key(hive, key) -> None` (creates intermediate keys, idempotent)
      - `set_value(hive, key, value: RegValue) -> None`
    - `get_backend() -> RegistryBackend`: returns the override if one is set, else the `winregistry_win.WinRegBackend()` lazily on win32, else a backend whose every method raises `RegistryUnavailable`;
    - `set_backend(b: Optional[RegistryBackend]) -> None`;
    - context manager `using_backend(b)`.
  - `regsafety`:
    - `@dataclass(frozen=True) Container: hive: str; key: str; level: str` where `level in {"key","value"}`;
    - `CONTAINERS: Mapping[str, Tuple[Container, ...]]`, exactly as follows (`CV = SOFTWARE\Microsoft\Windows\CurrentVersion`, `CVW = SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion`):

      | Cleaner id | Containers | Level |
      |---|---|---|
      | `win_reg_uninstall` | HKCU `CV\Uninstall`, HKLM `CV\Uninstall`, HKLM `CVW\Uninstall` | key |
      | `win_reg_app_paths` | HKCU `CV\App Paths`, HKLM `CV\App Paths`, HKLM `CVW\App Paths` | key |
      | `win_reg_file_assoc` | HKCU and HKLM `SOFTWARE\Classes`, HKCU and HKLM `SOFTWARE\Classes\Applications` | key |
      | `win_reg_startup` | HKCU `CV\Run`, HKCU `CV\RunOnce`, HKLM `CV\Run`, HKLM `CV\RunOnce`, HKLM `CVW\Run`, HKLM `CVW\RunOnce` | value |
      | `win_reg_shared_dlls` | HKLM `CV\SharedDLLs`, HKLM `CVW\SharedDLLs` | value |

    - `normalize(hive: str, key: str) -> Tuple[str, Tuple[str, ...]]`:
      - maps `HKEY_CURRENT_USER` to `HKCU` and `HKEY_LOCAL_MACHINE` to `HKLM`, and raises `ValueError` for any other hive;
      - splits on `\` and raises on empty, `.`, or `..` components, control characters, or leading/trailing whitespace;
      - casefolds every component;
      - requires the first component to be `software`.
    - `match_form(hive, key) -> Tuple[str, ...]`: `normalize` with a `wow6432node` component removed when it directly follows `software` or `software\classes`.
    - `DENY_PREFIXES` (match-form, prefix test):
      - `software\microsoft\windows nt`
      - `software\microsoft\windows\currentversion\installer`
      - `software\microsoft\windows\currentversion\explorer`
      - `software\classes\installer`, `\clsid`, `\interface`, `\typelib`, `\appid`, `\local settings`, `\mime`, `\protocols`
    - `DENY_COMPONENTS = {"policies"}` (anywhere).
    - Classes names that are denied:
      - names starting with `.`;
      - exact names `*`, `directory`, `drive`, `folder`, `allfilesystemobjects`, `systemfileassociations`, `unknown`, `exefile`, `lnkfile`, `batfile`, `cmdfile`, `comfile`, `msi.package`, `applications`;
      - prefixes `appx`, `microsoft.`, `windows.`, `msedge`, `ms-`, `word.`, `excel.`, `powerpoint.`, `outlook.`, `access.`, `onenote.`, `visio.`.
    - `check_target(cleaner_id: str, target: RegTarget, backend: Optional[RegistryBackend] = None) -> Optional[str]`: returns None when acceptable, else a plain-language reason. With `backend`, it also refuses when `is_link` is true on any key from `SOFTWARE\<next>` down to the target, except the trusted anchor `HKCU\SOFTWARE\Classes`.
    - `containers_for(cleaner_id) -> Tuple[Container, ...]`.
  - `regsnap`:
    - `@dataclass(frozen=True) KeySnap: name: str; values: Tuple[RegValue, ...]; subkeys: Tuple["KeySnap", ...]`;
    - `Snapshot = Union[KeySnap, RegValue]`;
    - `class SnapshotError(Exception)`;
    - `MAX_KEYS=256, MAX_VALUES=4096, MAX_BYTES=1_048_576`;
    - `snapshot(backend, target: RegTarget) -> Snapshot`: raises `SnapshotError` on a link in the tree, on exceeding a limit, on missing data, or on access denied;
    - `fingerprint(target: RegTarget, snap: Snapshot) -> str`: sha256 hex over canonical JSON of the hive, the key casefolded, the value name and the snapshot, with names sorted casefolded and exact-case names included;
    - `to_jsonable(snap) -> dict` and `from_jsonable(obj) -> Snapshot`, with bytes stored as base64;
    - `read_values(backend, hive, key) -> Dict[str, RegValue]`, keyed by casefolded name.
  - `regtargets` (types only, filled in by T2):
    - `class Existence(Enum): PRESENT, MISSING, UNKNOWN`;
    - `class Prober(Protocol): probe(path: str) -> Existence`;
    - `@dataclass(frozen=True) DetectorContext: env: Mapping[str, str]; prober: Prober; profiles_root: str; system_root: str`;
    - `default_context() -> DetectorContext`, which raises `NotImplementedError` until T2.
  - `winreg_base`:
    - `@dataclass(frozen=True) Finding: target: RegTarget; description: str; evidence: str`;
    - `class RegistryDetector(Cleaner)` with the Global Constraints attributes. `find_items()` does the following for each container in `containers_for(self.id)`:
      - it calls `self.entries(container, backend, ctx)`;
      - for each finding, it requires `check_target(..., backend) is None` and takes a snapshot, skipping the finding on `SnapshotError`, `RegistryError` or a non-None reason;
      - it yields `registry_item(finding, fingerprint)`, where `requires_root = hive == "HKLM"`, `size=0` and `hint=evidence`.
    - It also defines `entries(self, container, backend, ctx) -> Iterable[Finding]` (abstract; stubs yield nothing) and `context(self) -> DetectorContext` (returns `regtargets.default_context()`, overridable by tests).
    - `available()` returns `"only available on Windows"` when `sys.platform != "win32"` and no backend override is set. This matters because `build_cleaners(only=...)` runs unsupported cleaners off Windows.
  - `catalog.REGISTRY_IDS: Tuple[str, ...]`: the five ids, in Global Constraints order.
  - Stub classes: `WinRegUninstall`, `WinRegAppPaths`, `WinRegFileAssoc`, `WinRegStartup`, `WinRegSharedDlls`, with ids as in Global Constraints and names "Registry: dead uninstall entries", "Registry: dead App Paths", "Registry: dead file-type handlers", "Registry: dead startup entries", "Registry: SharedDLLs counts for missing files".
  - `catalog.CATEGORIES["registry"] = "Registry leftovers"`; `_assign("registry", <five ids>)`; `"registry"` added to `_NEVER_PRESELECT`.
  - `curation` changes:
    - `is_empty`: False for REGISTRY.
    - `safety_of`: REGISTRY returns `REVIEW`, checked right after `info is None`.
    - `display_label`: for REGISTRY with an empty cleaned description, use `reg.display`.
    - COPY entries:
      - `win_reg_uninstall` ("Dead uninstall entries", "Apps & Features entries whose program folder and uninstaller are gone. Removing them only tidies the list; a backup is kept.")
      - `win_reg_app_paths` ("Dead program shortcuts (App Paths)", "Run-dialog shortcuts to programs that no longer exist. Removing them has no effect on working software; a backup is kept.")
      - `win_reg_file_assoc` ("Dead file-type handlers", "Open-with handlers pointing at deleted programs. Affected files fall back to 'choose an app'; a backup is kept.")
      - `win_reg_startup` ("Dead startup entries", "Startup entries for programs that no longer exist. Nothing starts from them today; a backup is kept.")
      - `win_reg_shared_dlls` ("Stale shared-file counters", "Install counters for shared files that no longer exist. Uninstallers no longer need them; a backup is kept.")
  - Engine (fail-closed only): `_clean_one` dispatches PATH, then COMMAND, then REGISTRY. The REGISTRY branch returns `CleanOutcome(removed=False, error="registry cleaning is not available")` until T11. Any other kind returns `error="unknown item kind"`. Nothing ever runs `run_command([])`.
  - `tests/_fakereg.py`:
    - `FakeRegistry`, implementing the Protocol in memory with case-insensitive names. It provides `add_key(hive, key, values: Mapping[str, Tuple[int, object]] = {}, *, link=False, deny_delete=False, deny_read=False)`, `fail_next(op: str, exc: Exception)`, `calls: List[Tuple]`, and `tree(hive, key) -> dict` for assertions.
    - `ForbiddenBackend`: every method appends to `self.calls` and raises `AssertionError("tests must never touch the real registry")`. The append matters because `Cleaner.scan` catches `Exception`, which would otherwise swallow the error.
    - `FakeProber(states: Mapping[str, Existence], default=Existence.UNKNOWN)`, with paths casefolded.
  - `tests/conftest.py`:
    - autouse `_no_real_registry` sets `winregistry.set_backend(ForbiddenBackend())`. At teardown it fails the test when `calls` is non-empty, then resets the backend;
    - fixture `fake_registry` installs and returns a `FakeRegistry`.

- [ ] **Step 1: Write the failing tests** in `tests/test_registry_foundation.py`:
  - `test_registry_item_validation`: REGISTRY without `reg`, with hive `HKCR`, without a fingerprint, or with `path` set raises `ValueError`.
  - `test_item_key_registry_unique`: `("HKLM", r"SOFTWARE\a|b", "c")` and `("HKLM", r"SOFTWARE\a", "b|c")` give different keys, and keys differ by fingerprint.
  - `test_item_target_and_display`: `HKLM\SOFTWARE\X [v]`.
  - `test_normalize_and_match_form`:
    - `HKEY_LOCAL_MACHINE` and `SOFTWARE\WOW6432Node\Microsoft` match-form equals that of `SOFTWARE\Microsoft`;
    - `HKEY_CLASSES_ROOT`, `HKU`, `SYSTEM\CurrentControlSet`, `SOFTWARE\\a`, `SOFTWARE\..\SYSTEM` and `SOFTWARE\a ` raise.
  - `test_check_target_allowlist`:
    - accepts `HKCU CV\Uninstall\Foo` for `win_reg_uninstall`;
    - refuses the container itself, `CV\Uninstall\Foo\Sub`, the same key for `win_reg_startup`, a value target in a key-container, `HKLM SOFTWARE\Classes\CLSID`, `SOFTWARE\Classes\.txt`, `SOFTWARE\Classes\Applications` (a container), `SOFTWARE\Classes\Microsoft.Foo`, `...\Policies\...\Run`, and `HKLM SYSTEM\...`;
    - all of these hold case-insensitively and under the WOW6432Node alias.
  - `test_check_target_links` (FakeRegistry): a link below the container is refused; the `HKCU\SOFTWARE\Classes` anchor is not.
  - `test_snapshot_fingerprint_stable_and_sensitive`: the same tree gives the same fingerprint; changing one byte, one type, or a name's case changes it; reordering does not.
  - `test_snapshot_limits_and_links`: 257 keys, a link subkey, or `deny_read` raises `SnapshotError`.
  - `test_jsonable_roundtrip_all_types`: types 0, 1, 2, 3, 4, 5, 7, 11 and 0x20.
  - `test_registry_ids_catalog_and_copy`: each id has category `registry`, is never preselected, has a COPY entry, `safety_of` is `REVIEW` for HKLM and HKCU items, and `is_empty` is False.
  - `test_build_groups_keeps_zero_size_registry`
  - `test_engine_never_runs_registry_as_command`: a monkeypatched `run_command` is never called, and the error text matches.
  - `test_stub_detectors_registered_opt_in`: all five are in `ALL_CLEANERS`, `default_enabled` is False, scope is SYSTEM, platforms is `(WINDOWS,)`, and a default `build_cleaners(Config())` on any OS contains none of them.
  - `test_detector_base_builds_items`: a test subclass yields two findings and one denied finding; the items carry the fingerprint, `requires_root` follows the hive, and the denied finding is dropped.
  - `test_forbidden_backend_active`: `winregistry.get_backend().subkeys("HKCU","SOFTWARE")` raises `AssertionError` and is recorded in `calls`. Clear `calls` at the end of the test so teardown passes.
  - `test_detectors_unavailable_off_windows` (with `sys.platform` monkeypatched to `linux` and no override): `scan()` returns `skipped_reason == "only available on Windows"` and makes zero backend calls.
  - `test_core_imports_without_winreg`: in a subprocess with `sys.modules["winreg"] = None`, import `cleanix.core.winregistry`, `regsafety`, `regsnap`, `regtargets`, `cleanix.cleaners`.
  - `test_winreg_imported_only_in_backend_module`: grep `cleanix/` for `import winreg` and `from winreg`; the only hit is `winregistry_win.py`, and zero hits is allowed until T3.
- [ ] **Step 2: Run** `tests/test_registry_foundation.py`. Expect FAIL (modules missing).
- [ ] **Step 3: Implement** the Produces list. `regsafety` reasons are short plain sentences, for example "not inside an allowed registry location" or "Windows-owned key".
- [ ] **Step 4: Run** `tests/test_registry_foundation.py tests/test_curation.py tests/test_catalog.py tests/test_cleanix.py`. Expect PASS. `test_no_cleaner_in_other_category` and the copy test cover the new ids.
- [ ] **Step 4b: Audit and run the full suite.** Grep `tests/` for `ALL_CLEANERS`, `describe_all` and `include_unsupported`. Known users today: `test_catalog.py`, `test_curation.py`, `test_elevate.py`, `test_admin_eligibility.py`. Make sure any test that *scans* every cleaner on win32 either installs `fake_registry` or excludes `catalog.REGISTRY_IDS`. Then run the full suite on Windows: zero failures, and no `_no_real_registry` teardown failures.
- [ ] **Step 5: Commit** `feat(core): registry item model, backend protocol, safety rules and opt-in detector stubs`.

---

### Task 2: Target evidence — command parsing, env expansion, tri-state existence (W1)

**Files:**
- Modify: `cleanix/core/regtargets.py`
- Test: `tests/test_regtargets.py`

**Interfaces:**
- Consumes: `Existence`, `Prober`, `DetectorContext` (T1).
- Produces:
  - `expand_env(text: str, env: Mapping[str, str]) -> Optional[str]`: names are case-insensitive; returns None when any `%NAME%` stays unresolved.
  - `strip_icon_index(text: str) -> str`: removes a trailing `,<-?digits>`.
  - `@dataclass(frozen=True) CommandParse: candidates: Tuple[str, ...]; host: bool; relative: bool`.
  - `parse_command(cmd: str) -> CommandParse`:
    - a leading quoted token is the only candidate;
    - for unquoted commands, the candidates are every prefix ending before a space, plus the whole string, in CreateProcess order, each also with `.exe` appended when it has no extension;
    - `host` is true when the first candidate's basename without `.exe` (casefold) is in `HOST_EXES`;
    - `relative` is true when no candidate is a drive-absolute path.
  - `HOST_EXES = frozenset({"msiexec","rundll32","cmd","powershell","pwsh","wscript","cscript","regsvr32","mshta","explorer","conhost","dllhost","wsl"})`.
  - `class WinProber`:
    - `__init__(self, *, system_root: str, program_files: Sequence[str], program_data: str, local_appdata: str, drive_type: Callable[[str], int], lstat: Callable[[str], object] = os.lstat)`;
    - `probe(path) -> Existence`, with the R11 rules in this order: UNC or device path → strip `\\?\` → not drive-absolute → drive type is not `DRIVE_FIXED (3)` → Microsoft location (PRESENT if `lstat` succeeds, else UNKNOWN) → `~\d` component (PRESENT or UNKNOWN) → `lstat` (PRESENT / MISSING on winerror 2 or 3 if the drive root `lstat`s fine / UNKNOWN).
  - `target_state(raw: str, *, command: bool, ctx: DetectorContext, machine: bool) -> Existence`:
    - expand; if expansion fails, UNKNOWN;
    - for a command: parse, and return UNKNOWN when `host` or `relative`;
    - for a machine entry: any candidate under `ctx.profiles_root` gives UNKNOWN;
    - then any candidate PRESENT gives PRESENT, all candidates MISSING give MISSING, otherwise UNKNOWN.
  - `microsoft_roots(env: Mapping[str, str], system_drive: str) -> Tuple[str, ...]`: the `<PF>` set from R11, built from `ProgramW6432`, `ProgramFiles` and `ProgramFiles(x86)` when present, plus the two `<SystemDrive>` literals. Duplicates are removed case-insensitively. `WinProber.program_files` receives this set.
  - `default_context() -> DetectorContext`:
    - env is `os.environ` (the Windows API values come from `winenv`);
    - the prober is `WinProber` with `GetDriveTypeW` via ctypes, imported lazily;
    - `profiles_root` is the parent of `%PUBLIC%`, falling back to `<SystemDrive>\Users`;
    - on non-Windows it raises `RegistryUnavailable`.

- [ ] **Step 1: Write the failing tests**:
  - `test_expand_env` (`%ProgramFiles%\a` is expanded; `%NOPE%\a` gives None; case-insensitive).
  - `test_parse_command_quoted_and_args`: `"C:\P F\u.exe" /S` has candidates `(C:\P F\u.exe,)`.
  - `test_parse_command_unquoted_spaces`: `C:\Program Files\Foo\unins.exe /x` includes `C:\Program`, `C:\Program.exe`, `C:\Program Files\Foo\unins.exe`, in order.
  - `test_parse_command_hosts`: `MsiExec.exe /X{GUID}`, `rundll32.exe C:\x.dll,Run` and `cmd /c x` give `host`.
  - `test_strip_icon_index`
  - The false-positive matrix `test_target_state_matrix`, parametrized with `FakeProber` and fake `drive_type`/`lstat` (expected result in brackets):
    1. quoted missing exe on a fixed drive [MISSING]
    2. present exe [PRESENT]
    3. `\\server\share\a.exe` [UNKNOWN]
    4. `\\?\UNC\server\a.exe` [UNKNOWN]
    5. `\\?\C:\gone\a.exe` [MISSING]
    6. drive `E:` removable [UNKNOWN]
    7. drive `Q:` not present [UNKNOWN]
    8. drive root unreadable [UNKNOWN]
    9. `lstat` access denied (winerror 5) [UNKNOWN]
    10. `%UNDEFINED%\a.exe` [UNKNOWN]
    11. `notepad.exe` (relative) [UNKNOWN]
    12. `C:\Windows\System32\gone.exe` [UNKNOWN]
    13. `C:\Windows\Sysnative\x.exe` [UNKNOWN]
    14. `%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe` (lstat raises) [UNKNOWN]
    15. `C:\Program Files\WindowsApps\x\a.exe` [UNKNOWN]
    16. `C:\Program Files\Microsoft Office\x.exe` missing [UNKNOWN]
    17. `C:\PROGRA~1\Gone\a.exe` missing [UNKNOWN]
    18. `C:\PROGRA~1\Here\a.exe` present [PRESENT]
    19. HKLM entry `C:\Users\bob\AppData\Local\x.exe` missing [UNKNOWN]
    20. HKCU entry, same path, missing [MISSING]
    21. unquoted `C:\Program Files\Foo\u.exe /S` where `C:\Program.exe` exists [PRESENT]
    22. same, where everything is missing [MISSING]
    23. `MsiExec.exe /X{..}` [UNKNOWN]
    24. `rundll32 C:\gone.dll,X` [UNKNOWN]
    25. empty string [UNKNOWN]
    26. `"C:\a.exe` with an unterminated quote [UNKNOWN]
    27. 32-bit process (env `ProgramFiles=C:\Program Files (x86)`, no `ProgramW6432`), `C:\Program Files\Microsoft Office\root\x.exe` missing [UNKNOWN]
    28. helper-style env without `PUBLIC` and `ProgramW6432`: `C:\Program Files\WindowsApps\a.exe` [UNKNOWN], and `profiles_root` falls back to `C:\Users`
  - `test_default_context_unavailable_off_windows` (skipif win32).
- [ ] **Step 2: Run** `tests/test_regtargets.py`. Expect FAIL.
- [ ] **Step 3: Implement.** Use `ntpath` for every path operation, so the tests run identically on POSIX.
- [ ] **Step 4: Run** `tests/test_regtargets.py tests/test_registry_foundation.py`. Expect PASS.
- [ ] **Step 5: Commit** `feat(core): tri-state evidence for registry targets`.

---

### Task 3: winreg-backed backend (W1)

**Files:**
- Create: `cleanix/core/winregistry_win.py`
- Test: `tests/test_winreg_backend.py`

**Interfaces:**
- Consumes: `RegistryBackend`, `RegValue`, the errors and constants (T1).
- Produces:
  - `class WinRegBackend` implementing the Protocol: `__init__(self, winreg_module=None)`, where None means `import winreg` here.
  - Every open uses `KEY_WOW64_64KEY | <access>`.
  - Hive map: `{"HKCU": HKEY_CURRENT_USER, "HKLM": HKEY_LOCAL_MACHINE}`. Anything else raises `ValueError`.
  - `is_link` opens with `OpenKeyEx(root, key, REG_OPTION_OPEN_LINK, KEY_QUERY_VALUE | KEY_WOW64_64KEY)` and returns True iff `QueryValueEx(h, "SymbolicLinkValue")` returns type `REG_LINK`.
  - `can_delete` opens with `DELETE (0x00010000) | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE` for a key, or with `KEY_SET_VALUE` on the parent for a value. It returns False on `PermissionError`.
  - `delete_key` uses `DeleteKeyEx(root, key, KEY_WOW64_64KEY, 0)`.
  - `create_key` uses `CreateKeyEx(..., KEY_WRITE | KEY_WOW64_64KEY)`.
  - Error mapping: `FileNotFoundError` or winerror 2 raises `KeyMissing`; `PermissionError` or winerror 5 raises `AccessDenied`; any other `OSError` raises `RegistryError`.
  - Data normalisation: REG_MULTI_SZ becomes a tuple, and None data becomes `b""`.
  - Handles are always closed (`with` or `CloseKey`).

- [ ] **Step 1: Write the failing tests** against a fake `winreg` module object (`types.SimpleNamespace` with recording functions; it runs on every OS):
  - `test_opens_use_64bit_view`
  - `test_is_link_uses_open_link_option`
  - `test_error_mapping`
  - `test_values_normalised`
  - `test_delete_key_uses_delete_key_ex_with_view`
  - `test_set_value_types_passed_through`
  - `test_unknown_hive_rejected`
  - `test_handles_closed_on_error`
  - `test_get_backend_selects_win_backend_only_on_win32`: monkeypatch `sys.platform` and `winregistry.set_backend(None)` inside the test, then restore the Forbidden backend.
- [ ] **Step 2: Run** the file. Expect FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests/test_winreg_backend.py tests/test_registry_foundation.py`. Expect PASS. The import-location test now finds exactly one module.
- [ ] **Step 5: Commit** `feat(core): winreg backend for the registry protocol`.

---

### Task 4: Backup files and restore (W1)

**Files:**
- Create: `cleanix/core/regbackup.py`
- Test: `tests/test_regbackup.py`

**Interfaces:**
- Consumes:
  - from `regsnap` (T1): `snapshot`, `fingerprint`, `to_jsonable`, `from_jsonable`, `KeySnap`;
  - from `regsafety` (T1): `check_target`;
  - from `winregistry` (T1): `RegistryBackend`, `RegValue`.
- Produces:
  - `REG_HEADER = "Windows Registry Editor Version 5.00"`; `HIVE_NAMES = {"HKCU": "HKEY_CURRENT_USER", "HKLM": "HKEY_LOCAL_MACHINE"}`.
  - `to_reg_text(target: RegTarget, snap: Snapshot) -> str`:
    - header, blank line, `[HIVE\key]` sections parent-first;
    - REG_SZ as `"..."` with `\` and `"` escaped; a REG_SZ containing CR or LF becomes `hex(1):`;
    - REG_DWORD as `dword:%08x`, REG_QWORD as `hex(b):` (little-endian), REG_BINARY as `hex:`;
    - REG_EXPAND_SZ as `hex(2):` (UTF-16LE plus NUL), REG_MULTI_SZ as `hex(7):` (each string plus NUL, then a final NUL);
    - other types as `hex(N):` raw; the default value as `@`;
    - a value target writes only its key header and that one value;
    - CRLF line endings, no wrapping.
  - `@dataclass(frozen=True) BackupFiles: reg_path: Path; json_path: Path`.
  - `write_backup(directory: Path, index: int, cleaner_id: str, target: RegTarget, snap: Snapshot) -> BackupFiles`:
    - writes `"{index}__registry.reg"` (UTF-16 with BOM) and `"{index}__registry.json"` as `{"format": 1, "cleaner_id", "hive", "key", "value", "fingerprint", "snapshot"}`;
    - fsyncs both;
    - re-reads the JSON and raises `BackupError` unless the fingerprint of the decoded snapshot equals `target.fingerprint`.
  - `class BackupError(Exception)`; `class RestoreError(Exception)`.
  - `restore_entry(json_path: Path, backend: RegistryBackend, *, is_admin: bool) -> str`. It returns the display string. In order, it:
    1. parses and validates the JSON (format 1, known types, sizes within the regsnap limits);
    2. checks that `check_target(cleaner_id, target)` is None and that every key in the snapshot lies at or under the target key;
    3. refuses HKLM when `not is_admin`. The message is `f'needs administrator: from an Administrator terminal run cleanix restore {{run}} or reg import "{reg_path}"'`, where `reg_path` is the absolute path of the sibling `.reg` file and the caller fills in `{run}`;
    4. runs a pre-check pass that fails the whole entry when any existing value differs (R7);
    5. runs a write pass that creates the missing keys and values;
    6. re-snapshots and returns only if the fingerprint equals the backup's, else raises `RestoreError("restored, but the result differs from the backup")`.

- [ ] **Step 1: Write the failing tests**:
  - `test_reg_text_golden`: one key with every type, exact expected text including `@`, escapes, `hex(2)`, `hex(7)` and `hex(b)`.
  - `test_reg_text_value_target_only_one_value`
  - `test_reg_file_is_utf16_bom_crlf`
  - `test_reg_and_json_agree`: a tiny `.reg` parser in the test (the test's own helper, not product code) decodes `to_reg_text`, and the result equals `from_jsonable` of the JSON for the odd-data fixture from Review Focus 5.
  - `test_write_backup_verifies_readback`: monkeypatch the JSON writer to corrupt one byte; expect `BackupError`.
  - `test_restore_recreates_tree_exactly`: delete it in FakeRegistry, restore, and the fingerprint is equal.
  - `test_restore_merges_after_partial_delete`: one subkey still exists and is identical; it succeeds.
  - `test_restore_conflict_writes_nothing`: one existing value differs; `RestoreError` is raised and `calls` contains no `set_value` or `create_key`.
  - `test_restore_refuses_tampered_paths`: the key is rewritten to `SYSTEM\x`, a snapshot subkey escapes the target, or the cleaner id does not own the container. Each raises with zero writes.
  - `test_restore_hklm_needs_admin`: zero writes, and the message contains the absolute `.reg` path and `reg import`.
  - `test_restore_rejects_unknown_format`
- [ ] **Step 2: Run** `tests/test_regbackup.py`. Expect FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests/test_regbackup.py`. Expect PASS.
- [ ] **Step 5: Commit** `feat(core): .reg/JSON registry backups with validated restore`.

---

### Task 5: GUI presentation of registry items (W1)

**Files:**
- Modify:
  - `cleanix/gui/models.py`: `_type_label` returns `"Registry"`; `_target_text` uses `item_target`.
  - `cleanix/gui/grouped_results.py`: tooltip and Copy path use `item_target`; Open location is hidden for REGISTRY.
  - `cleanix/gui/power_view.py`: `detail_text`, `confirm_text`.
  - `cleanix/gui/simple_view.py`: the irreversible count uses `kind is COMMAND`; static Windows registry note.
  - `cleanix/gui/panels_data.py`: Quarantine "Items" cell and restore failure text.
- Test: `tests/gui/test_registry_gui.py`

**Interfaces:**
- Consumes: `ItemKind.REGISTRY`, `RegTarget`, `item_target`, `curation` changes (T1); the `quarantine.list_runs()` row keys `"registry"` and `"registry_admin"` (ints; produced by T11; tests monkeypatch `list_runs`).
- Produces:
  - `PowerView.detail_text` for REGISTRY shows:
    - `Registry: <display>`;
    - `Evidence: <hint>`;
    - `Backed up before removal (.reg in quarantine).`;
    - `Requires administrator` when HKLM.
  - `PowerView.confirm_text(items, hidden, keep_copy)` adds, with `u` the HKCU registry count and `a` the HKLM registry count:
    - if `u`: `f"{u} registry entr{'y' if u == 1 else 'ies'} will be backed up first and can be restored from the Quarantine tab."`
    - if `a`: `f"{a} administrator registry entr{'y' if a == 1 else 'ies'} will be backed up first; restoring them needs an Administrator terminal (cleanix restore)."`
    - The existing admin "removed permanently" line counts only non-REGISTRY admin items.
    - With `keep_copy` False and some non-registry items, the "permanently removed" line becomes "Files and commands will be permanently removed; registry entries are still backed up." When every item is registry, that line is omitted.
  - `SimpleView.registry_note: QLabel`: visible only when `current_os() == WINDOWS`, with text "Registry leftovers are checked only in Power mode."
  - QuarantinePanel "Items" cell: `"{count} ({registry} registry)"` when registry > 0. The restore status lists up to 3 failure reasons verbatim.

- [ ] **Step 1: Write the failing tests** (pytest-qt, offscreen, using the `fake_registry` fixture where needed):
  - `test_simple_registry_items_read_only_with_power_hint`: `set_scan_result` with HKCU and HKLM registry items puts them in the review tree, nothing is ticked, they cannot be ticked, and the reason is `SimpleView.NOT_FROM_SIMPLE`.
  - `test_simple_registry_note_only_on_windows`
  - `test_power_registry_group_review_badge_and_opt_in`
  - `test_power_confirm_text_registry_lines`: HKCU only; HKLM only; mixed with files and keep_copy False. Exact strings.
  - `test_power_detail_text_registry`
  - `test_grouped_results_copy_path_and_no_open_location_for_registry`: the context-menu action is absent, and `reveal` is never called (monkeypatched to raise).
  - `test_table_type_and_target_columns_registry`
  - `test_quarantine_panel_shows_registry_count_and_reasons`
  - `test_registry_items_never_selected_by_safe_only`
- [ ] **Step 2: Run** the file. Expect FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests/gui`. Expect PASS. The existing confirm and undo wording tests are unchanged.
- [ ] **Step 5: Commit** `feat(gui): present registry findings as Review items with backup wording`.

---

### Tasks 6–10: Detectors (W2, five parallel tasks)

Every detector task follows the same structure. **The common block below (Files, Interfaces, fixture, steps) is part of each detector task's brief. Hand it to the implementer together with that task's own subsection.**

**Files:** Modify the detector's own module only. Test: its own file.

**Interfaces:**
- Consumes:
  - `RegistryDetector`, `Finding` (T1);
  - `regsnap.read_values` (T1);
  - `regtargets.target_state`, `strip_icon_index`, `Existence` (T2);
  - `DetectorContext`, plus the `fake_registry` fixture and `FakeProber` (T1).
- Produces: the detector's `entries(container, backend, ctx) -> Iterable[Finding]` (the class name is unchanged from T1). The evidence string lists every checked target and its state, for example `"InstallLocation C:\Foo: missing; UninstallString C:\Foo\unins000.exe: missing"`.

Common test fixture: a `DetectorContext` with `FakeProber` states and `env={"ProgramFiles": r"C:\Program Files", ...}`. The detector's `context()` is overridden to return it. Assertions are on `find_items()`, so the T1 base filters (allowlist, links, snapshot) apply. Every task includes `test_<id>_never_touches_unlisted_containers`: FakeRegistry `calls` show reads only under that detector's containers, and no write calls at all.

Each task has these steps:
- [ ] **Step 1:** Write the failing tests listed below.
- [ ] **Step 2:** Run the test file. Expect FAIL.
- [ ] **Step 3:** Implement `entries`.
- [ ] **Step 4:** Run the test file and `tests/test_registry_foundation.py`. Expect PASS.
- [ ] **Step 5:** Commit `feat(cleaners): <id> detector`.

#### Task 6: `win_reg_uninstall` — `cleanix/cleaners/winreg_uninstall.py`, `tests/test_winreg_uninstall.py`

The rule: an entry key is dead iff it has no subkeys, the R12 exclusions do not apply, `InstallLocation` is MISSING (path), `UninstallString` is MISSING (command), and each of `QuietUninstallString`, `ModifyPath` (command) and `DisplayIcon` (path after `strip_icon_index`) is absent or MISSING. Values must be REG_SZ or REG_EXPAND_SZ; any other type is unknown.

The description is `f"Uninstall entry: {DisplayName}"`, with `f" ({Publisher})"` added when a publisher is present.

Tests:
- `test_dead_entry_listed`, including the HKLM WOW6432Node variant, which gets `requires_root=True`.
- Each of these keeps the entry (parametrized):
  - empty `InstallLocation`;
  - the location PRESENT;
  - the uninstaller UNKNOWN (UNC);
  - `MsiExec` UninstallString;
  - `WindowsInstaller=1`;
  - `SystemComponent=1`;
  - `ParentKeyName`;
  - `ReleaseType`;
  - name `KB5034441`;
  - Publisher "Microsoft Corporation";
  - no DisplayName;
  - has a subkey;
  - DisplayIcon PRESENT;
  - `QuietUninstallString` UNKNOWN;
  - `%UNDEFINED%` in a value;
  - InstallLocation under `C:\Users\x` for an HKLM entry;
  - a REG_BINARY UninstallString.
- `test_unreadable_entry_skipped` (`deny_read`).

#### Task 7: `win_reg_app_paths` — `cleanix/cleaners/winreg_app_paths.py`, `tests/test_winreg_app_paths.py`

The rule: the entry key name ends in `.exe` (casefold), the default value (`""`) is REG_SZ or REG_EXPAND_SZ, and the target (path, quotes stripped) is MISSING. The `Path` value is ignored as evidence. The description is `f"App Paths: {name}"`.

Tests:
- `test_dead_app_path_listed`
- Kept:
  - target PRESENT;
  - a target under `C:\Program Files\Windows NT` (e.g. `wordpad.exe`);
  - `msedge.exe` under `Program Files (x86)\Microsoft`;
  - no default value;
  - a non-`.exe` name;
  - a relative target;
  - an App Execution Alias path;
  - a removable drive.

#### Task 8: `win_reg_file_assoc` — `cleanix/cleaners/winreg_file_assoc.py`, `tests/test_winreg_file_assoc.py`

The rule, for an entry under `SOFTWARE\Classes` or `SOFTWARE\Classes\Applications`:
- the regsafety Classes name rules pass;
- the subkeys are a subset of `{"shell", "DefaultIcon"}`;
- `shell` has at least one verb, each verb's subkeys are exactly `{"command"}`, and each `command` has only a default value (REG_SZ/EXPAND_SZ) and no `DelegateExecute`;
- every verb command is MISSING;
- `DefaultIcon`, if present, is MISSING;
- no `URL Protocol`, `CLSID` or `shellex` anywhere.

The description is `f"File-type handler: {name}"`.

Tests:
- `test_dead_progid_listed`
- `test_dead_applications_entry_listed`
- Kept:
  - one verb PRESENT;
  - a `DelegateExecute` verb;
  - a `shellex` subkey;
  - a `CLSID` subkey;
  - a `URL Protocol` value;
  - a `.txt` key;
  - `AppX123`;
  - `Word.Document.12`;
  - `Applications` itself;
  - a `CurVer` subkey;
  - a verb with an `rundll32` command;
  - a link subkey;
  - `HKLM\SOFTWARE\Classes\CLSID\{...}`, which is never enumerated as an entry candidate because of the deny rule.

#### Task 9: `win_reg_startup` — `cleanix/cleaners/winreg_startup.py`, `tests/test_winreg_startup.py`

The rule: each value in a Run or RunOnce container, of type REG_SZ or REG_EXPAND_SZ, with a non-empty name, whose command is MISSING. The description is `f"Startup entry: {name}"`, and the evidence names the command.

Tests:
- `test_dead_run_value_listed`, covering HKCU, HKLM and WOW6432Node, with `RegTarget.value` set.
- Kept:
  - command PRESENT;
  - `rundll32` command;
  - `cmd /c` command;
  - unquoted path with spaces where a prefix exists;
  - UNC;
  - `%UNDEFINED%`;
  - an HKLM value pointing under `C:\Users`;
  - a REG_BINARY value;
  - the default value `""`;
  - a value under `...\Policies\Explorer\Run` (never read).
- `test_runonce_prefixed_names_ok`: `!Foo` is listed when dead.

#### Task 10: `win_reg_shared_dlls` — `cleanix/cleaners/winreg_shared_dlls.py`, `tests/test_winreg_shared_dlls.py`

The rule: each value in a SharedDLLs container whose type is REG_DWORD, whose name is a drive-absolute path, and whose path is MISSING. The description is `f"Shared file counter: {name}"`. Items are `requires_root=True`, because the containers are HKLM only.

Tests:
- `test_dead_counter_listed`
- Kept:
  - file PRESENT;
  - under `C:\Windows\System32`;
  - a REG_SZ type;
  - a relative name;
  - a UNC name;
  - an `E:` removable drive.
- `test_value_names_with_backslashes_roundtrip_key`: `item_key` and `RegTarget.value` keep the full path name.

---

### Task 11: Delete path — engine, service, quarantine (W2)

**Files:**
- Create: `cleanix/core/regclean.py`
- Modify:
  - `cleanix/core/engine.py`: REGISTRY branch and `registry_backup` parameter.
  - `cleanix/core/service.py`
  - `cleanix/core/quarantine.py`: `store_registry`, `mark_registry`, restore dispatch, `list_runs` fields.
- Test: `tests/test_regclean.py`

**Interfaces:**
- Consumes:
  - from T1: `regsnap.snapshot`, `fingerprint`; `regsafety.check_target`; `winregistry.get_backend`;
  - from T4: `regbackup.write_backup`, `restore_entry`, `BackupError`, `RestoreError`.
- Produces:
  - `class RegistryChanged(Exception)`.
  - `class RegistryBackupSink(Protocol)`: `before_delete(item: CleanableItem, backend) -> None` (raises to veto) and `after_delete(item: CleanableItem, deleted: bool) -> None`.
  - `regclean.delete_target(backend, cleaner_id: str, target: RegTarget) -> None`:
    1. `check_target(cleaner_id, target, backend)`;
    2. re-snapshot, raising `RegistryChanged` when the fingerprint differs;
    3. preflight `can_delete` on every key in the tree (or on the value), raising `AccessDenied` before any write;
    4. delete bottom-up;
    5. a failure after the first write raises `RegistryError("partially deleted: ...")`.
  - `regclean.VerifyOnlySink`: `before_delete` is a no-op, because `delete_target` verifies anyway. It documents that the backup was written by the GUI. Used only by the helper.
  - `Quarantine` satisfies `RegistryBackupSink`: `before_delete = store_registry`, `after_delete = mark_registry` (class-level aliases).
  - `Quarantine.store_registry(item, backend) -> None`:
    - snapshot; `RegistryChanged` if the fingerprint differs from `item.reg.fingerprint`;
    - `regbackup.write_backup(self.dir / "registry", len(self.items), ...)`;
    - append the manifest entry `{"type": "registry", "original": reg.display, "cleaner_id", "hive", "key", "value", "json": str, "reg": str, "size": 0, "deleted": None}`;
    - `self.save()` immediately, so the manifest is durable before the delete.
  - `Quarantine.mark_registry(item, deleted: bool)`, as `after_delete`: sets `"deleted"` and saves.
  - `restore()`:
    - entries with `"type": "registry"` and `deleted is not False` go through `regbackup.restore_entry(..., is_admin=winenv.is_admin())`, with `<run>` substituted into the admin message;
    - `deleted is False` entries are skipped silently;
    - entries without `"type"` are files, as before;
    - reasons go into `failed`.
  - `list_runs()` rows gain `"registry": int` and `"registry_admin": int`. `purge*` is unchanged.
  - `Engine.clean(..., registry_backup: Optional[RegistryBackupSink] = None)`. `_clean_registry`:
    - `check_target` failing gives "blocked by registry safety rules";
    - a dry run gives `freed=0`;
    - a None sink gives "registry entries are removed only with a backup";
    - `before_delete` raising gives `f"backup failed, nothing deleted: {exc}"`, or "changed since the scan; scan again" for `RegistryChanged`;
    - otherwise it calls `delete_target`, then `after_delete`;
    - a successful outcome has `removed=True`, `freed=0`.
  - `service.clean(..., registry_backup_elsewhere: bool = False)`:
    - for a real clean with REGISTRY items, it creates a quarantine run even when `use_quarantine` is False; it passes `quarantine=run if use_quarantine else None` and `registry_backup=run`;
    - `registry_backup_elsewhere=True` passes `VerifyOnlySink()` and creates no run;
    - `record_history=False` with REGISTRY items and not elsewhere raises `ValueError`;
    - the run is saved and `quarantine_run` is set whenever it holds any item.

- [ ] **Step 1: Write the failing tests** (FakeRegistry, `quarantine_root` monkeypatched to `tmp_path`):
  - `test_clean_hkcu_entry_backs_up_then_deletes`: the `.reg` and `.json` exist, the manifest is saved before `delete_key` (assert the manifest file's existence inside a FakeRegistry `delete_key` hook), and the key is gone.
  - `test_changed_since_scan_nothing_deleted` (Review Focus 1)
  - `test_backup_dir_unwritable_nothing_deleted` (Review Focus 3): mixed with one PATH item, which is still cleaned.
  - `test_preflight_denied_nothing_deleted`
  - `test_partial_delete_reports_run_and_restore_completes` (Review Focus 2)
  - `test_no_sink_refuses`
  - `test_dry_run_touches_nothing`: `calls` contains reads only.
  - `test_service_creates_run_without_keep_copy`
  - `test_service_helper_mode_writes_nothing`: no quarantine dir is created.
  - `test_restore_hkcu_roundtrip_via_quarantine_restore`
  - `test_restore_hklm_not_admin_reports_instruction`: `winenv.is_admin` is monkeypatched False; the failure reason contains `cleanix restore <run_id>`, and the run is kept.
  - `test_old_file_manifests_still_restore`
  - `test_list_runs_registry_counts`
- [ ] **Step 2: Run** `tests/test_regclean.py`. Expect FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests/test_regclean.py tests/test_windows_quarantine.py tests/test_service.py tests/test_cleanix.py tests/test_registry_foundation.py`. Expect PASS. Replace T1's "registry cleaning is not available" test expectation with the no-sink one.
- [ ] **Step 5: Commit** `feat(core): backed-up registry deletion with undo through quarantine`.

---

### Task 12: CLI exposure, JSON, history, completion, man page (W3)

**Files:**
- Modify:
  - `cleanix/cli.py`: `--registry`, `cmd_clean` registry run, `_write_simulation`/`cmd_explain`/`_interactive_select` via `item_target`.
  - `cleanix/core/report.py`: additive per-item `"kind"` and `"registry": {"hive","key","value"} | None`.
  - `cleanix/core/history.py`: additive `"registry": display | None` in `write_manifest`.
  - `cleanix/completion.py`: `--registry` in `SCAN_CLEAN_OPTS`.
  - `cleanix.1`: regenerated.
- Test: `tests/test_registry_cli.py`

**Interfaces:**
- Consumes: `Engine.clean(registry_backup=...)`, `quarantine.new_run/store_registry/save` (T11); `item_target` (T1); `catalog` ids.
- Produces:
  - The CLI uses `catalog.REGISTRY_IDS`.
  - `--registry` (`store_true`) on `scan` and `clean`, implementing R14.
  - `cmd_clean` real-clean behaviour when REGISTRY items are present:
    - `reg_run = quarantine if args.quarantine else qmod.new_run()`, passed as `registry_backup`;
    - after the clean, save `reg_run` if it has items, then print `f"Registry backup saved in quarantine run '{run_id}'; undo with cleanix restore {run_id}."`;
    - the confirm prompt adds `f"{n} registry entr(y/ies) are backed up first."`.
  - `cleanix restore` prints the registry failure reasons; the existing loop already does this.
  - JSON `schema_version` stays 1 because the fields are additive.

- [ ] **Step 1: Write the failing tests**:
  - `test_registry_flag_selects_only_registry_ids`: with `build_cleaners` monkeypatched to capture `only`, test `--registry` alone and `--registry --only temp`.
  - `test_registry_flag_non_windows_exits_2` (`plat.is_windows` monkeypatched False).
  - `test_default_scan_has_no_registry_cleaners`
  - `test_clean_execute_registry_without_quarantine_flag_creates_backup_run` (FakeRegistry plus a fake detector result, `--execute --yes`).
  - `test_simulate_and_explain_show_registry_target`
  - `test_json_report_registry_fields_additive`: old keys are unchanged.
  - `test_history_manifest_registry_field`
  - `test_completion_offers_registry_flag` (bash, zsh, fish).
  - `test_manpage_in_sync`: output of `python scripts/gen_manpage.py` (with a fixed date) contains `\-\-registry`.
- [ ] **Step 2: Run** `tests/test_registry_cli.py`. Expect FAIL.
- [ ] **Step 3: Implement**, then regenerate with `python scripts/gen_manpage.py > cleanix.1`.
- [ ] **Step 4: Run** `tests/test_registry_cli.py tests/test_cleanix.py tests/test_windows_cli.py`. Expect PASS.
- [ ] **Step 5: Commit** `feat(cli): opt-in --registry for scan/clean with backup notice`.

---

### Task 13: Elevated helper — HKLM registry deletions (W3)

**Files:**
- Modify:
  - `cleanix/elevated.py`: `REGISTRY_ADMIN_IDS`, `admin_cleaner_ids`, `_eligible`, `static_admin_problem`, the `_execute` REGISTRY branch, and docstring points 5, 7 and 8.
  - `cleanix/gui/elevation.py`: pre-launch backups, `ElevatedOutcome` fields, outcome and preview lines.
  - `cleanix/gui/workers.py`: only the `admin_preview_registry` count in `_run_dry`.
  - `tests/test_elevate.py`: update `test_allowlist_rules_hold_for_this_platform` and `test_allowlist_on_windows`.
  - `tests/test_admin_eligibility.py`: registry parity.
  - `tests/gui/test_admin_eligibility.py`: its parity helpers build REGISTRY HKLM items for registry ids when on Windows.
  - `tests/gui/test_elevated_flow.py`, but only if it asserts the allowlist or the "cannot be undone" wording.
- Test: `tests/test_registry_helper.py`

**Interfaces:**
- Consumes: `service.clean(registry_backup_elsewhere=True)`, `quarantine.new_run/store_registry/save/purge` (T11); `regsafety.check_target` (T1).
- Produces:
  - `elevated.REGISTRY_ADMIN_IDS = frozenset(catalog.REGISTRY_IDS)`. `admin_cleaner_ids()` adds them on Windows when `supported()`, bypassing the system-category, class-`requires_root` and `default_enabled` rules, and only for these ids.
  - `_eligible(item, allowed)`: for an id in `REGISTRY_ADMIN_IDS`, it additionally requires `item.kind is REGISTRY`, `item.reg.hive == "HKLM"` and `check_target(...) is None`. Any REGISTRY item from another id is refused.
  - `static_admin_problem` mirrors this. The plain reasons are "Only machine-wide (HKLM) registry entries are cleaned with administrator permission" and "Blocked by registry safety rules".
  - `_execute`: REGISTRY items skip `_path_chain_problem`, are refused unless HKLM, and are cleaned with `service.clean([item], config, dry_run=False, use_quarantine=False, record_history=False, registry_backup_elsewhere=True, cancel=cancel)`. The helper writes nothing.
  - `elevation.ElevatedOutcome` gains `registry_backup_run: Optional[str] = None` and `registry_backup_failed: int = 0`.
  - `run_elevated_part`:
    - before writing the request, it creates one quarantine run for the REGISTRY admin items, calls `store_registry` for each, and drops any item whose backup fails from the selection (counted in `registry_backup_failed`; if nothing remains, the outcome is FAILED with "Registry backup failed; nothing was removed.");
    - after the launch, it purges the run when the status is DECLINED or UNAVAILABLE, or when cancel stopped it before launch, and otherwise keeps it with `deleted: None` entries.
  - `admin_outcome_lines` adds:
    - when a run is kept: `f"Registry entries were backed up to quarantine run {run} ({run_dir}); to restore, from an Administrator terminal run cleanix restore {run} or reg import each .reg file there"`. `run_dir` is the absolute run directory;
    - the existing "Administrator items are removed permanently" line becomes "Administrator files and commands are removed permanently; they cannot be undone." when any registry admin item was sent.
  - `admin_preview_line(count, size, registry: int = 0)`, the dry run: when `registry` is greater than 0, it says `f"... would be removed after one administrator prompt; files and commands cannot be undone, {registry} registry entr(y/ies) are backed up first"`. `CombinedSummary` gains `admin_preview_registry: int = 0`, set by `ElevatedCleanWorker._run_dry`. This edits `cleanix/gui/workers.py`, so add that file to this task.

- [ ] **Step 1: Write the failing tests**:
  - `test_registry_ids_allowlisted_on_windows_only` (monkeypatch `plat.is_windows` both ways).
  - `test_hkcu_registry_item_never_eligible`
  - `test_registry_item_from_non_registry_cleaner_refused`
  - `test_static_problem_parity_registry`: for every id, REGISTRY HKLM, REGISTRY HKCU and COMMAND variants agree between `static_admin_problem` and `_eligible`.
  - `test_execute_registry_branch_uses_verify_only_and_writes_nothing`: patch `service.scan` to return a FakeRegistry-backed item and record `service.clean` kwargs.
  - `test_changed_key_is_unmatched_in_helper`: the request key has the old fingerprint and the scan has the new one, giving `unmatched == 1` and no delete.
  - `test_gui_writes_backup_before_launch`: the launcher stub asserts that the backup files exist when it is called.
  - `test_backup_failure_drops_item_from_request`
  - `test_declined_purges_backup_run`
  - `test_outcome_lines_registry_wording`: the line contains the absolute run dir and `reg import`.
  - `test_dry_run_preview_registry_not_called_permanent`
  - Updated `test_allowlist_rules_hold_for_this_platform`: `category == "system" or cid == "temp" or cid in REGISTRY_ADMIN_IDS`, with the registry ids required to be `win_*` and supported.
  - Updated `test_static_problem_matches_helper_for_every_cleaner`: a REGISTRY HKLM item is used for registry ids.
- [ ] **Step 2: Run** `tests/test_registry_helper.py tests/test_elevate.py tests/test_admin_eligibility.py`. Expect FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the same files plus `tests/gui/test_elevated_flow.py tests/gui/test_admin_eligibility.py`. Expect PASS.
- [ ] **Step 5: Commit** `feat(elevated): allowlisted HKLM registry deletions with user-side backup`.

---

### Task 14: Docs, verification script, integration (W4)

**Files:**
- Modify:
  - `README.md`, with these edits:
    - Windows notes line 41 becomes "touches the registry only through the opt-in registry cleaners";
    - "Quarantine covers path-based items only" now mentions registry backups;
    - new section "Registry cleanup (Windows, opt-in)": detectors, evidence rules, backup files, `--registry`, HKLM restore from an Administrator terminal, manual `reg import` fallback;
    - "What Undo covers": HKCU registry entries yes, HKLM only via an Administrator terminal;
    - helper list "On Windows it is 4 cleaners" becomes 4 plus the five registry ids, which delete HKLM entries only;
    - Security notes gain a bullet: HKLM registry backups are written by the user before elevation, the helper deletes only fingerprint-matched entries and writes nothing, and the fingerprint-to-delete window is not transactional (R17).
  - `docs/superpowers/specs/2026-11-19-curated-listings-and-orphans-design.md`: status line, B implemented.
- Create:
  - `scripts/verify_registry_cleanup.py`
  - `tests/test_verify_registry_script.py`

**Interfaces:**
- Consumes: everything above.
- Produces: `scripts/verify_registry_cleanup.py` with:
  - `class ReRootedBackend`, `__init__(self, inner, root_hive="HKCU", root_key=r"SOFTWARE\CleanixTest")`. It maps each logical `(hive, key)` to `(root_hive, f"{root_key}\\{hive}\\{key}")`. `is_link` answers for the mapped key. It raises `ValueError` for any mapped key not under the root.
  - `main() -> int`, which:
    1. refuses unless `sys.platform == "win32"`, and refuses if `HKCU\SOFTWARE\CleanixTest` already exists (exit 2);
    2. creates fixtures under the root: one dead and one live entry per detector, plus controls (UNC, `%UNDEFINED%`, a target under `C:\Windows`, an existing exe). Dead targets point into `<SystemDrive>\CleanixVerify-<uuid4>\`, which the script creates and then deletes to make them dead. This folder must be outside the profiles root: under R11, HKLM-logical targets in `C:\Users` are UNKNOWN. The script removes the folder on exit, including on failure;
    3. runs each detector with `using_backend(ReRootedBackend(WinRegBackend()))`, and with `quarantine_root` redirected to a temp dir;
    4. asserts exactly the dead entries are found;
    5. runs `service.clean` (HKLM-logical items with `allow_root_items` via `Engine` directly, since they are physically in HKCU);
    6. asserts dead removed, live kept, and both backup files exist with the UTF-16 BOM and header;
    7. runs `quarantine.restore`:
       - HKCU-logical entries are restored and their fingerprints are equal;
       - in a non-admin run, HKLM-logical entries fail with the `reg import` instruction text;
       - the script then restores those entries with `regbackup.restore_entry(..., is_admin=True)`, which is safe because they are physically under the HKCU test root, and asserts the fingerprints are equal;
    8. finally deletes the whole `HKCU\SOFTWARE\CleanixTest` tree;
    9. asserts the root is gone and that the exact key `HKCU\SOFTWARE\Cleanix` does not exist (not a prefix match);
    10. prints PASS or FAIL per step and exits 0 only if all pass.

- [ ] **Step 1: Write the failing test** `tests/test_verify_registry_script.py`, which imports the script by path and never calls `main()`:
  - `test_rerooted_maps_into_test_root` (FakeRegistry inner);
  - `test_rerooted_refuses_escape` (a key containing `..` is rejected by normalize; a mapped key outside the root raises).
- [ ] **Step 2: Run** it. Expect FAIL. **Step 3: Implement** the script and the README/spec edits. **Step 4: Run** it. Expect PASS.
- [ ] **Step 5: Full suite** with PySide6: `QT_QPA_PLATFORM=offscreen PYTHONPATH=. PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider`. Expect 0 failures. Repeat in a venv without PySide6: expect 0 failures, with GUI tests skipped. Run both on Windows and on Linux.
- [ ] **Step 6: Manual Windows verification checklist.** Use a normal (non-admin) account first, then an Administrator terminal.
  - [ ] `python scripts/verify_registry_cleanup.py` prints all PASS. `reg query HKCU\Software\CleanixTest` reports that the key cannot be found. `reg query HKCU\Software\Cleanix` reports that the key cannot be found.
  - [ ] `cleanix scan` lists no registry cleaners. `cleanix scan --registry` lists findings and makes no writes: compare `reg export` of the five containers before and after, using `fc /b`.
  - [ ] `cleanix gui`, Power mode: tick a registry cleaner in "Choose what to scan" and scan. The groups show the Review badge, the Evidence text, no Open location, and the confirm wording from T5 (do NOT clean real entries). Simple mode shows the registry note.
  - [ ] The `.reg` written by the script opens in Notepad as readable UTF-16 text, with the header and the expected values.
  - [ ] Elevated helper path: covered by the unit tests only. Do not clean real HKLM entries on the verification machine.
  - [ ] **Real-`winreg` backend checks (from the T3 review).** `scripts/verify_registry_cleanup.py` implements these as extra PASS/FAIL steps under `HKCU\Software\CleanixTest` only.
    - **Link fixtures.** `winreg` cannot create links. Use ctypes `RegCreateKeyExW` with `REG_OPTION_CREATE_LINK` (0x2), then set `SymbolicLinkValue` as `REG_LINK` holding `\REGISTRY\USER\<SID>\Software\CleanixTest\Target`. Clean up by deleting the link through an `REG_OPTION_OPEN_LINK` handle (ctypes `NtDeleteKey`, or an equivalent verified on the machine), never by its path.
    1. `OpenKeyEx` with `REG_OPTION_OPEN_LINK` passed as `reserved` opens the link itself. `QueryValueEx(h, "SymbolicLinkValue")` returns type 6. `is_link` is True for the link and False for the target and for a plain key.
    2. `delete_key` and `delete_value` refuse the link, and the target is untouched.
    3. MEASURE what a raw `DeleteKeyEx` on the link path deletes: the link or the target. Record the result in R17.
    4. `DeleteKeyEx` on a non-leaf key fails with winerror 5 and deletes nothing.
    5. The end of enumeration is winerror 259. A missing key is winerror 2.
    6. REG_MULTI_SZ round-trips `['a','','b']`, `['a','']`, `['']` and `[]` through `set_value`/`values`.
    7. Lossy reads:
       - REG_SZ/REG_EXPAND_SZ with an embedded NUL is cut at the NUL;
       - DWORD/QWORD with wrong-size data is read through a pointer cast;
       - a zero-length MULTI_SZ reads as `[]`.

       Expected: the backup and the fingerprint agree with each other but not with the raw bytes. Either document this, or make the detectors skip such values.
    8. REG_NONE, type 0x20 and REG_BINARY round-trip as bytes. Writing REG_DWORD 2^32 raises `OverflowError`.
    9. `CreateKeyEx` creates missing intermediate keys. Run once under 32-bit Python on 64-bit Windows, with explicit `Wow6432Node` paths.
    10. The script removes `CleanixTest` completely, including the link key.
    11. Under the elevated helper, HKCU is the elevated account's hive (T13 note).
- [ ] **Step 7: Commit** `docs: registry cleanup (Windows, opt-in) and verification script`.

## Open questions for the user

1. **One-click Undo for machine-wide (HKLM) entries?** The plan's default (R6): backups are kept, but restoring them needs `cleanix restore <run>`, or `reg import "<file>"`, in an Administrator terminal. With over-the-shoulder UAC (a separate administrator account), only `reg import` with the absolute path works, because the run lives in the standard user's profile. One-click Undo would need a new elevated "restore" helper action, plus an administrator-only integrity record of each backup, for example a digest stored under `HKLM\Software\Cleanix`. Without that record, a standard user could get the helper to write arbitrary HKLM entries.
2. **Should Simple mode ever scan the registry?** The plan's default (R13): no. Simple shows "Registry leftovers are checked only in Power mode." The alternative is that Simple's Deep scan includes the registry detectors and lists them read-only, which makes Deep scan slower and adds registry reads.
