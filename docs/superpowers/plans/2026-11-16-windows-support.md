# Cleanix Windows Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make cleanix scan and clean safely on Windows 10/11, with Windows cleaners, a Windows-aware deletion guard, Task Scheduler support and Windows CI (spec Part 1; the GUI is a separate later plan).

**Architecture:** Windows is opt-in per cleaner: `(ALL,)` keeps meaning "every POSIX platform", and a cleaner runs on Windows only if its `platforms` contains `WINDOWS`. The deletion guard gets a pure, string-based Windows path model (`safety_windows.py`, testable on any OS) wired into the existing `safety.py`. New Windows cleaners read locations through one helper module (`winenv.py`) so tests can redirect them to a temp tree on any OS.

**Tech Stack:** Python >= 3.10, `rich`, `PyYAML`, `pytest`, stdlib `ctypes`/`ntpath`/`subprocess` (no new dependencies).

**Spec:** `docs/superpowers/specs/2026-11-16-windows-and-gui-design.md` (Part 1, plus its "Clarifications from the builder check").

## Global Constraints

- Python >= 3.10; base dependencies stay `rich` and `PyYAML`. No new runtime dependency.
- All deletion goes through `safe_rmtree` / `safe_unlink` in `cleanix/core/safety.py`; no cleaner deletes directly.
- Report-only when unsure: Prefetch and `Windows.old` are report-only; the component-store cleanup (DISM) is opt-in (`default_enabled = False`).
- Non-goals: no registry cleaning, no startup-item changes, no driver or "optimizer" features, no file deletion inside WinSxS (DISM only).
- Never touch: Documents, Desktop, Downloads, Pictures, Music, Videos, OneDrive, `AppData\Roaming` as a whole, browser profiles, passwords or logins.
- Windows targets: Windows 10/11 x64. The existing suite must keep passing on Linux and macOS.
- Existing CLI commands, flags and JSON output stay compatible.
- Cleaners that read Windows locations call them as `winenv.local_appdata()` (module attribute access, never `from ... import`), so tests can monkeypatch them.
- Work on branch `feat/windows-support`. Commit messages end with the line `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.
- Dev setup: `pip install -e . pytest`; run tests with `python -m pytest -q`.

## Baseline findings (checked on Windows 11 before planning)

- `safety.is_safe_to_delete("/")` returns **True** on Windows (the path resolves to `C:\`, which the POSIX protected list doesn't contain). Task 2-3 close this before any Windows cleaner can delete.
- About 30 cleaners inherit `platforms = (ALL,)`, so they currently run on Windows with POSIX assumptions. Task 1 stops that.
- The existing suite fails its first test on Windows and then runs for over 5 minutes (real cleaners scan the home directory). Task 1 should remove the hang; Task 11 makes the suite green.

## Review Focus

1. A delete target spelled with a `\\?\` prefix, forward slashes, odd case or a trailing separator must not slip past the protected list.
2. A junction or symlink inside a cache directory that points at real user data must be removed as the link only, never followed.
3. Locked or in-use files (Explorer thumbnail DBs, a running browser's cache) must produce a reported error for that item, never a crash, a forced delete or an aborted run.
4. Unreadable admin-only directories (`C:\Windows\Temp`, `SoftwareDistribution`) scanned as a normal user must yield "requires admin" items or a skipped cleaner, never an exception.
5. Spaces and non-ASCII characters in the home directory name and in the `cleanix.exe` path (`C:\Program Files\...`) must survive the scheduled-task command line.

---

### Task 1: Platform token and Windows opt-in semantics

**Files:**
- Modify: `cleanix/core/platform.py`
- Test: `tests/test_windows_platform.py`

**Interfaces:**
- Produces: `WINDOWS = "windows"`; `is_windows() -> bool`; `current_os()` returns `WINDOWS` when `platform.system()` is `"Windows"`; `supports(platforms)` returns, on Windows, `WINDOWS in platforms`, and on every other OS the existing `ALL in platforms or current_os() in platforms`. `XDG_PLATFORMS` is unchanged (excludes Windows).

- [ ] **Step 1: Create branch `feat/windows-support`** (`git switch -c feat/windows-support`).
- [ ] **Step 2: Write failing tests** in `tests/test_windows_platform.py`, monkeypatching `cleanix.core.platform.current_os` (the module global that `supports` calls):
  - `test_all_does_not_include_windows`: with os `"windows"`, `supports((ALL,)) is False`; `supports((XDG_PLATFORMS))` is False.
  - `test_windows_requires_explicit_optin`: `supports((WINDOWS,)) is True`; `supports((ALL, WINDOWS)) is True`.
  - `test_posix_unchanged`: with os `"linux"`, `supports((ALL,)) is True`, `supports((WINDOWS,)) is False`.
  - `test_current_os_detects_windows`: monkeypatch `platform.system` to return `"Windows"`, call `current_os.cache_clear()` then `current_os() == WINDOWS`, and clear the cache again afterwards.
- [ ] **Step 3: Run** `python -m pytest tests/test_windows_platform.py -v`; expect FAIL (`WINDOWS` undefined).
- [ ] **Step 4: Implement** the token, `is_windows()` and the new `supports` branch; update the `ALL` comment to "every POSIX platform; Windows must opt in".
- [ ] **Step 5: Run** the new tests (PASS), then `python -m pytest -q -x` on this Windows machine; note which tests still fail (they are fixed in Tasks 3 and 11) and that the run no longer hangs.
- [ ] **Step 6: Commit** `feat(platform): add Windows platform token with opt-in semantics`.

### Task 2: Windows path-safety model (pure, testable on any OS)

**Files:**
- Create: `cleanix/core/safety_windows.py`
- Test: `tests/test_windows_safety_model.py`

**Interfaces:**
- Produces:
  - `normalize(path: str) -> str`: strips `\\?\` (and maps `\\?\UNC\` to `\\`), converts `/` to `\`, applies `ntpath.normpath`, casefolds, removes a trailing separator except on a drive root.
  - `violation(target: str, env: Mapping[str, str], homes: Sequence[str]) -> Optional[str]`: a human-readable refusal reason, or `None` if the target may be deleted. Pure string logic via `ntpath`; no filesystem access.
  - `SYSTEMROOT_ALLOWED: tuple[str, ...]`, the only subpaths of `%SystemRoot%` that may be deleted, relative and casefolded: `temp`, `softwaredistribution\download`, `prefetch`, `minidump`, `livekernelreports`, `logs\cbs`, `memory.dmp`, `serviceprofiles\networkservice\appdata\local\microsoft\windows\deliveryoptimization\cache`.
- Rules for `violation` (env keys `SystemRoot`, `SystemDrive`, `ProgramFiles`, `ProgramFiles(x86)`, `ProgramData`, defaulting to `C:\Windows`, `C:`, `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData`):
  1. Refuse any drive root (`X:\`) and any UNC share root (`\\server\share`).
  2. Refuse a target that equals, or is an ancestor of, a protected root: `%SystemRoot%`, `%ProgramFiles%`, `%ProgramFiles(x86)%`, `%ProgramData%`, `%SystemDrive%\Users`, `\System Volume Information`, `\$Recycle.Bin`, `\Recovery`, `\Boot`, and, for each home, the home itself plus `Documents`, `Desktop`, `Downloads`, `Pictures`, `Music`, `Videos`, `OneDrive`, `AppData`, `AppData\Roaming`, `AppData\Local`, `AppData\LocalLow`, `.ssh`, `.gnupg`.
  3. Refuse anything *under* `%SystemRoot%` unless it falls under a `SYSTEMROOT_ALLOWED` prefix.
  4. Refuse anything under `%ProgramFiles%` or `%ProgramFiles(x86)%`.
  5. Everything else is allowed (protection of a folder does not protect its subpaths, as on POSIX).

- [ ] **Step 1: Write failing tests** (`homes=[r"C:\Users\bob"]`, default env). Each asserts `violation(...)` is not `None` unless stated:
  - `test_drive_and_unc_roots_refused`: `"C:\\"`, `"c:/"`, `"D:\\"`, `r"\\srv\share"`.
  - `test_prefix_case_and_slashes_normalised`: `r"\\?\C:\Windows"`, `r"c:\WINDOWS"`, `"C:/Windows/"`, `r"C:\Users\bob\.\Documents"`.
  - `test_ancestors_refused`: `r"C:\Users"`, `"C:\\"`, `r"C:\Users\bob"`.
  - `test_protected_user_folders`: `Documents`, `Desktop`, `AppData`, `AppData\Roaming`, `AppData\Local` under bob.
  - `test_cache_subpaths_allowed` (returns `None`): `r"C:\Users\bob\AppData\Local\Temp\x.tmp"`, `r"C:\Users\bob\AppData\Roaming\Slack\Cache"`, `r"C:\ProgramData\Microsoft\Windows\WER\ReportArchive"`.
  - `test_systemroot_allowlist`: `r"C:\Windows\Temp\a.tmp"`, `r"C:\Windows\SoftwareDistribution\Download\x"`, `r"C:\Windows\MEMORY.DMP"` allowed; `r"C:\Windows\System32\drivers\x.sys"` and `r"C:\Windows\WinSxS\x"` refused.
  - `test_program_files_subtrees_refused`: `r"C:\Program Files\App\cache"` and `r"C:\Program Files (x86)\App"`.
  - `test_custom_env_respected`: env `{"SystemRoot": r"D:\WinNT"}` makes `r"D:\WinNT\System32"` refused.
  - `test_non_ascii_and_spaces_home`: home `r"C:\Users\Zoë Müller"` is protected and its `AppData\Local\Temp\x` is allowed.
- [ ] **Step 2: Run** `python -m pytest tests/test_windows_safety_model.py -v`; expect FAIL (module missing).
- [ ] **Step 3: Implement** `normalize`, `SYSTEMROOT_ALLOWED` and `violation` per the rules above, using only `ntpath` string operations (compare normalised, casefolded strings component by component so `C:\Windows2` is not treated as inside `C:\Windows`).
- [ ] **Step 4: Run** the tests; expect PASS.
- [ ] **Step 5: Commit** `feat(safety): add pure Windows path-protection model`.

### Task 3: Wire the Windows guard into deletion

**Files:**
- Modify: `cleanix/core/safety.py` (`assert_safe_to_delete`, `safe_unlink`, `safe_rmtree`)
- Modify: `tests/test_cleanix.py` (mark POSIX-only tests)
- Test: `tests/test_windows_safety_integration.py` (every test `skipif(sys.platform != "win32")`)

**Interfaces:**
- Consumes: `safety_windows.violation`, `platform.is_windows`.
- Produces: `is_reparse_point(path: str | os.PathLike) -> bool`, true for a symlink or junction (`st_file_attributes & 0x400` on Windows, `os.path.islink` elsewhere); `assert_safe_to_delete` on Windows calls `violation(str(resolved), os.environ, [str(h) for h in _home_dirs()])` and raises `UnsafePathError(reason)`; the root check uses "path equals its own parent" instead of `"/"`.

- [ ] **Step 1: Write failing Windows-only tests**:
  - `test_drive_root_refused`: `safety.is_safe_to_delete("/")` and `"C:\\"` are False (the baseline bug).
  - `test_short_name_cannot_bypass`: `os.path.expandvars(r"%SystemRoot%")` spelled via its 8.3 or differently cased form is refused.
  - `test_junction_removed_as_link_only`: create a directory with a file, create a junction to it with `subprocess.run(["cmd","/c","mklink","/J",link,target])`, call `safe_rmtree(link)`; assert the junction is gone, the target directory and its file still exist.
  - `test_dir_symlink_removed_as_link_only`: same with `os.symlink(target, link, target_is_directory=True)` (skip if privilege is missing).
  - `test_readonly_file_removed`: a read-only file inside a tree is deleted by `safe_rmtree`.
  - `test_locked_file_reports_error_not_crash`: hold a file open with `open(path, "rb")` inside a tree and assert `safe_rmtree` raises `OSError`, while `Engine([]).clean([item], dry_run=False)` returns an outcome with `error` set and no exception.
- [ ] **Step 2: Run** `python -m pytest tests/test_windows_safety_integration.py -v` on Windows; expect FAIL.
- [ ] **Step 3: Implement** the guard dispatch, `is_reparse_point`, and link-only removal in `safe_unlink`/`safe_rmtree` (directory symlink or junction: `os.rmdir`; file symlink: `os.unlink`). In `safe_rmtree`, retry a failed removal after clearing the read-only bit (`os.chmod(path, stat.S_IWRITE)`); do not force locked files.
- [ ] **Step 4: Mark POSIX-only tests.** Add `posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX paths")` and apply it to `test_protected_system_paths_refused` (keep its Windows equivalent in the new file), `test_home_and_config_protected`, and any other test in `tests/test_cleanix.py` that fails on Windows for POSIX-path reasons; each skip gets a short reason. Do not delete or weaken any test.
- [ ] **Step 5: Run** the integration tests and the full suite on Windows; expect PASS or only skips for POSIX-only tests.
- [ ] **Step 6: Commit** `feat(safety): enforce Windows path guard and link-safe removal`.

### Task 4: Windows environment helpers, admin detection and test fixture

**Files:**
- Create: `cleanix/core/winenv.py`
- Modify: `cleanix/core/context.py`, `cleanix/core/utils.py`
- Create: `tests/conftest.py`
- Test: `tests/test_windows_env.py`

**Interfaces:**
- Produces in `winenv` (importable on every OS; Windows-only imports happen inside functions):
  - `is_admin() -> bool` (False off Windows; `ctypes.windll.shell32.IsUserAnAdmin()` on Windows).
  - `local_appdata() -> Path`, `roaming_appdata() -> Path`: for the invoking user honor `LOCALAPPDATA` / `APPDATA` when set, otherwise `current_user().home / "AppData" / "Local"` (or `Roaming`); for any other user always the home-derived path.
  - `user_temp() -> Path` (`local_appdata() / "Temp"`); `programdata() -> Path` (`ProgramData` env or `C:\ProgramData`); `system_root() -> Path` (`SystemRoot` or `C:\Windows`); `system_drive() -> str` (`SystemDrive` or `"C:"`).
  - `recycle_bin_size() -> int`: bytes via `SHQueryRecycleBinW` on Windows, `0` on failure or elsewhere.
  - `relaunch_elevated(argv: Sequence[str]) -> bool`: `ShellExecuteW(None, "runas", ...)`; False off Windows.
- `context.is_effective_root()` and `utils.is_root()` return `winenv.is_admin()` on Windows; `invoking_user()` falls back to `USERNAME` when `USER` is unset.
- Fixture `fake_win` in `tests/conftest.py`: takes `tmp_path`, creates `Users/u/AppData/{Local,Roaming}`, `ProgramData`, `Windows`, and monkeypatches `winenv.local_appdata`, `roaming_appdata`, `programdata`, `system_root`, `system_drive`, `user_temp`, plus `context.invoking_user` and `context._cached_targets` so `utils.home()` is `tmp_path/Users/u`. Returns a namespace with `.home`, `.local`, `.roaming`, `.programdata`, `.system_root`.

- [ ] **Step 1: Write failing tests**:
  - `test_local_appdata_for_other_user_ignores_env`: with `use_user(TargetUser("x", home, 0, 0, False))` and `LOCALAPPDATA` set elsewhere, `local_appdata() == home / "AppData" / "Local"`.
  - `test_local_appdata_honors_env_for_invoker`: invoker user plus `LOCALAPPDATA=tmp/L` returns `tmp/L`.
  - `test_helpers_are_safe_off_windows` (skipif on win32): `is_admin() is False`, `recycle_bin_size() == 0`, `relaunch_elevated(["x"]) is False`.
  - `test_is_admin_returns_bool_on_windows` (win32 only).
  - `test_fake_win_fixture_redirects_home`: `utils.home() == fake_win.home`.
- [ ] **Step 2: Run** `python -m pytest tests/test_windows_env.py -v`; expect FAIL.
- [ ] **Step 3: Implement** `winenv`, the fixture, and the `context`/`utils` changes (Windows multi-user sweeping stays out of scope: on Windows only the invoking user's home is scanned, which the existing `pwd is None` fallback already gives).
- [ ] **Step 4: Run** the new tests and the full suite; expect PASS.
- [ ] **Step 5: Commit** `feat(core): add Windows environment helpers and admin detection`.

### Task 5: Windows data locations and CLI behaviour

**Files:**
- Modify: `cleanix/config.py` (`_config_path`), `cleanix/core/history.py` (`state_dir`), `cleanix/core/quarantine.py` (`quarantine_root`), `cleanix/scheduler/cron.py` untouched
- Modify: `cleanix/cli.py` (`_disk_free`, sudo hint strings at the lines that say "re-run with sudo" and "Hint that more is available with sudo"), `cleanix/core/engine.py` (the "requires root" message), `cleanix/reset.py` / `cmd_factory_reset`
- Test: `tests/test_windows_cli.py`

**Interfaces:**
- Consumes: `platform.is_windows`, `winenv.roaming_appdata`, `winenv.local_appdata`.
- Produces: config file at `%APPDATA%\cleanix\config.yaml`; history and scan state at `%LOCALAPPDATA%\cleanix`; quarantine at `%LOCALAPPDATA%\cleanix\quarantine`; `_disk_free` default path becomes the system drive root on Windows; elevation messages say "run from an elevated (Administrator) terminal" on Windows and keep the `sudo` wording elsewhere; `factory-reset` on Windows prints that it is not supported on Windows and exits non-zero without running anything.

- [ ] **Step 1: Write failing tests** (monkeypatch `platform.is_windows`/`current_os` plus `fake_win` so they run on any OS):
  - `test_config_path_on_windows`, `test_state_dir_on_windows`, `test_quarantine_root_on_windows`: each equals the path above under `fake_win`.
  - `test_requires_root_message_mentions_administrator_on_windows`: an `Engine([]).clean([root_item], dry_run=False, allow_root_items=False)` outcome error contains `"Administrator"`.
  - `test_factory_reset_unsupported_on_windows`: `cli.main(["factory-reset", ...])` returns non-zero and prints a "not supported on Windows" message (use whichever required flags the command has; read `cmd_factory_reset`).
- [ ] **Step 2: Run** the tests; expect FAIL.
- [ ] **Step 3: Implement** the path branches, messages and the Windows guard in `cmd_factory_reset`.
- [ ] **Step 4: Run** the new tests and the full suite; expect PASS.
- [ ] **Step 5: Commit** `feat(cli): Windows data locations, messages and factory-reset guard`.

### Task 6: Windows core cleaners (temp, thumbnails, error reports, Recycle Bin)

**Files:**
- Create: `cleanix/cleaners/windows_core.py`
- Modify: `cleanix/cleaners/__init__.py` (import and append to `ALL_CLEANERS`)
- Test: `tests/test_windows_cleaners_core.py`

**Interfaces:**
- Consumes: `winenv.*`, `Cleaner.path_item`, `Cleaner.command_item`, `utils.iter_children`, `utils.older_than`, `utils.modified_within`, `Config.temp_min_age_days`, `Config.cache_min_age_minutes`.
- Produces (all `platforms = (WINDOWS,)`):
  - `WinTempCleaner` id `win_temp`, scope user: children of `winenv.user_temp()` older than `temp_min_age_days` and not modified within `cache_min_age_minutes`; skips children named `WinGet` or `chocolatey` (case-insensitive; owned by the package-cache cleaner in Task 8).
  - `WinThumbnailCleaner` id `win_thumbnails`, scope user: `thumbcache_*.db` and `iconcache_*.db` in `local_appdata()/Microsoft/Windows/Explorer`, plus `local_appdata()/IconCache.db`.
  - `WinErrorReportingCleaner` id `win_error_reports`, scope user: `local_appdata()/Microsoft/Windows/WER` children and `local_appdata()/CrashDumps` children.
  - `WinRecycleBinCleaner` id `win_recycle_bin`, scope system: when `winenv.recycle_bin_size() > 0`, one COMMAND item `["powershell", "-NoProfile", "-Command", "Clear-RecycleBin -Force -ErrorAction SilentlyContinue"]` with that size, `requires_root=False`. Not quarantinable (command item).

- [ ] **Step 1: Write failing tests** using `fake_win`; call `cleaner.find_items()` directly:
  - `test_win_temp_offers_old_files_only`: an old file (mtime set 10 days back) and a fresh file in `user_temp()`; only the old one is offered with the correct `size`.
  - `test_win_temp_skips_package_dirs`: `Temp/WinGet` is not offered.
  - `test_win_temp_never_offers_temp_itself`: no item's path equals `user_temp()`.
  - `test_thumbnails_match_only_cache_dbs`: `thumbcache_256.db` offered, `other.db` not.
  - `test_error_reports_and_crashdumps_offered`.
  - `test_recycle_bin_command_item`: patch `winenv.recycle_bin_size` to 1234 gives one item, `kind is ItemKind.COMMAND`, `size == 1234`, `command[0] == "powershell"`; patched to 0 gives none.
  - `test_cleaners_declare_windows_only`: each class's `platforms == (WINDOWS,)` and `supports(...)` is False on a patched `"linux"` OS.
  - `test_unreadable_dir_does_not_raise`: monkeypatch `iter_children` (in the cleaner module) to raise `PermissionError`; `cleaner.scan()` returns a report with `skipped_reason` set or zero items, no exception (`Cleaner.scan` already wraps errors; pin it).
- [ ] **Step 2: Run** `python -m pytest tests/test_windows_cleaners_core.py -v`; expect FAIL.
- [ ] **Step 3: Implement** the four cleaners and register them.
- [ ] **Step 4: Run** the new tests and the full suite; expect PASS.
- [ ] **Step 5: Commit** `feat(cleaners): Windows temp, thumbnail, error-report and Recycle Bin cleaners`.

### Task 7: Windows system cleaners (admin-level)

**Files:**
- Create: `cleanix/cleaners/windows_system.py`
- Modify: `cleanix/cleaners/__init__.py`
- Test: `tests/test_windows_cleaners_system.py`

**Interfaces:**
- Consumes: as Task 6, plus `Cleaner.report_item`, `Cleaner.available`, `utils.which`.
- Produces (all `platforms = (WINDOWS,)`, scope system, `requires_root = True` unless noted):
  - `WinSystemTempCleaner` id `win_system_temp`: children of `system_root()/Temp` older than `temp_min_age_days`.
  - `WinUpdateCacheCleaner` id `win_update_cache`: children of `system_root()/SoftwareDistribution/Download` and of `system_root()/ServiceProfiles/NetworkService/AppData/Local/Microsoft/Windows/DeliveryOptimization/Cache`.
  - `WinSystemDumpsCleaner` id `win_system_dumps`: `system_root()/MEMORY.DMP`, children of `system_root()/Minidump`, `system_root()/LiveKernelReports`, and children of `programdata()/Microsoft/Windows/WER/ReportArchive` and `ReportQueue`.
  - `WinPrefetchReporter` id `win_prefetch`: one **report-only** item for `system_root()/Prefetch` with a hint that Windows rebuilds it and deleting rarely helps.
  - `WindowsOldReporter` id `win_windows_old`: one **report-only** item for `system_drive() + "\\Windows.old"` with a hint to use Settings > System > Storage > Temporary files or `cleanmgr`.
  - `WinComponentStoreCleaner` id `win_component_store`, `default_enabled = False`: COMMAND item `["Dism.exe", "/Online", "/Cleanup-Image", "/StartComponentCleanup"]`, size 0; `available()` returns a reason when `which("Dism.exe")` is None.

- [ ] **Step 1: Write failing tests** with `fake_win`:
  - `test_update_cache_offers_download_children`, `test_system_dumps_cover_memory_dmp_and_minidump`.
  - `test_every_path_item_passes_windows_guard`: for each deletable item these cleaners yield, `safety_windows.violation(item.path, env, [str(fake_win.home)])` with env pointing at `fake_win` is `None` (pins the allowlist and the cleaners together).
  - `test_prefetch_and_windows_old_are_report_only`: `item.report_only is True` and `hint` is non-empty.
  - `test_component_store_is_opt_in`: `default_enabled is False`; with `which` patched to None, `available()` is a non-empty string.
  - `test_admin_cleaners_marked_requires_root`: items from the update, system-temp and dumps cleaners have `requires_root is True`.
- [ ] **Step 2: Run** the tests; expect FAIL.
- [ ] **Step 3: Implement** and register the six cleaners (order: after Task 6's).
- [ ] **Step 4: Run** the new tests and the full suite; expect PASS.
- [ ] **Step 5: Commit** `feat(cleaners): Windows update cache, dumps, prefetch, Windows.old and DISM cleaners`.

### Task 8: Windows application cleaners

**Files:**
- Create: `cleanix/cleaners/windows_apps.py`
- Modify: `cleanix/cleaners/__init__.py`
- Test: `tests/test_windows_cleaners_apps.py`

**Interfaces:**
- Consumes: as Task 6; `Config.browsers`.
- Produces (all `platforms = (WINDOWS,)`, scope user):
  - `WinBrowserCacheCleaner` id `win_browser_cache`. Under `local_appdata()`: Chrome `Google/Chrome/User Data`, Edge `Microsoft/Edge/User Data`, Brave `BraveSoftware/Brave-Browser/User Data`; in each profile dir (`Default` and `Profile *`) offer only `Cache`, `Code Cache`, `GPUCache`. Firefox: `Mozilla/Firefox/Profiles/*/cache2`. Chrome and Firefox are processed only when their key (`chrome` or `chromium`; `firefox`) is in `config.browsers`; Edge and Brave are always processed. Never touch `Cookies`, `Login Data`, `Local Storage`, `IndexedDB`, `History`.
  - `WinShaderCacheCleaner` id `win_shader_cache`: `local_appdata()/D3DSCache`, `NVIDIA/DXCache`, `NVIDIA/GLCache`, `AMD/DxCache`, `AMD/GLCache`.
  - `WinPackageCacheCleaner` id `win_pkg_caches`: `user_temp()/WinGet`, `user_temp()/chocolatey`, `%ChocolateyInstall%/lib-bad` (env var; skipped when unset), Scoop `cache` directory (`SCOOP` env var, else `home()/scoop`), NuGet `local_appdata()/NuGet/v3-cache`.
  - `WinVisualStudioCleaner` id `win_visualstudio`: `local_appdata()/Microsoft/VisualStudio/*/ComponentModelCache`.
- Modify existing: `ElectronCacheCleaner` (`app_cruft.py`) adds `WINDOWS` to `platforms` and, on Windows, scans `winenv.roaming_appdata()` children instead of the XDG config dir (same safe subdir list); `JetBrainsCleaner` adds `WINDOWS` and scans `local_appdata()/JetBrains/*` caches and logs.

- [ ] **Step 1: Write failing tests** with `fake_win`:
  - `test_browser_offers_cache_dirs_only`: build a Chrome profile with `Cache`, `Code Cache`, `Cookies`, `Login Data`; only the two cache dirs are offered.
  - `test_browser_respects_config_for_chrome_and_firefox`: with `config.browsers = []` Chrome and Firefox are not offered but Edge still is.
  - `test_shader_cache_paths`, `test_package_caches_and_env_override` (`SCOOP` set to a tmp dir).
  - `test_electron_on_windows_keeps_session_data`: `Roaming/Slack/Cache` offered; `Roaming/Slack/Local Storage` and `Cookies` not.
  - `test_electron_declares_windows`, `test_jetbrains_windows_caches_offered`.
  - `test_no_duplicate_paths_across_cleaners`: run `WinTempCleaner`, `WinPackageCacheCleaner` and `WinBrowserCacheCleaner` against a tree containing `Temp/WinGet`; no path appears in two cleaners' results.
- [ ] **Step 2: Run** the tests; expect FAIL.
- [ ] **Step 3: Implement** the cleaners, register them, and extend `ElectronCacheCleaner` and `JetBrainsCleaner`.
- [ ] **Step 4: Run** the new tests and the full suite; expect PASS.
- [ ] **Step 5: Commit** `feat(cleaners): Windows browser, shader, package-manager and IDE caches`.

### Task 9: Existing cross-platform cleaners opt in to Windows

**Files:**
- Modify: `cleanix/cleaners/dev_caches.py`, `pip_cache.py`, `npm_cache.py`, `containers.py` (Docker), `ai_tools.py`, `ai_cli.py`, `big_files.py`, `downloads.py`, `duplicates.py`, `project_cruft.py`, `browser_profiles.py`
- Create: `cleanix/cleaners/windows_wsl.py`
- Modify: `cleanix/cleaners/__init__.py`
- Test: `tests/test_windows_crossplatform.py`

**Interfaces:**
- Produces: each listed cleaner's `platforms` becomes `(ALL, WINDOWS)` (explicit `(ALL,)` ones) or gains `platforms = (ALL, WINDOWS)` (those that inherited the default), after its paths are made Windows-correct:
  - `DevCacheCleaner`: on Windows add `local_appdata()/go-build`, `local_appdata()/uv/cache`, `local_appdata()/pip/Cache`, `local_appdata()/npm-cache`, `home()/.cargo/registry/cache`, `home()/.gradle/caches`, `home()/.cache/pre-commit`; skip the POSIX-only `~/.cache/*` entries.
  - `PipCacheCleaner` / `NpmCacheCleaner`: use the Windows locations above (do not double-offer what `DevCacheCleaner` owns; keep the existing dedupe approach).
  - Docker cleaner: runs on Windows unchanged (docker CLI).
  - AI cleaners (`ai_tools.py`, `ai_cli.py`): home-relative paths already work; add `WINDOWS` and verify with tests; Claude Code and Codex use `home()/.claude`, `home()/.codex`.
  - Reporters (`BigFileReporter`, `DownloadsReporter`, `DuplicateFileReporter`, `ProjectCruftCleaner`, `BrowserProfileReporter`): add `WINDOWS`; `walk_pruned` prune set gains `AppData` so scans skip it; `BrowserProfileReporter` Windows profile roots are the Task 8 browser `User Data` dirs.
  - Cleaners that stay POSIX-only (toolchains, editor litter, logs, apple litter, VM tooling, conda/opam/sdkman/gem/cpan, backup cache) are **not** opted in by this plan.
  - New `WslDiskReporter` id `wsl_disk` (`platforms = (WINDOWS,)`): report-only items for `ext4.vhdx` files under `local_appdata()/Packages/*/LocalState` and `local_appdata()/Docker/wsl`, hint `wsl --manage <distro> --set-sparse true  (or Optimize-VHD)`.

- [ ] **Step 1: Write failing tests** with `fake_win`:
  - `test_dev_caches_windows_locations`: create `Local/go-build`, `Local/npm-cache`, `~/.cargo/registry/cache` with files; all offered with correct sizes.
  - `test_opted_in_cleaners_run_on_windows`: with `current_os` patched to `"windows"`, each opted-in class has `supports(cls.platforms) is True`; each not-opted-in class from the "stay POSIX-only" list has `supports(...) is False`.
  - `test_walk_pruned_skips_appdata`: a file under `home/AppData` is never yielded.
  - `test_wsl_reports_vhdx_report_only`: a fake `Packages/X/LocalState/ext4.vhdx` yields a report-only item with hint containing `wsl --manage`.
  - `test_no_cleaner_scans_run_on_windows_without_optin`: `build_cleaners(Config())` with `current_os` patched to `"windows"` returns only cleaners whose `platforms` contains `WINDOWS`.
- [ ] **Step 2: Run** the tests; expect FAIL.
- [ ] **Step 3: Implement** the changes and register `WslDiskReporter`.
- [ ] **Step 4: Run** the new tests and the full suite; expect PASS.
- [ ] **Step 5: Commit** `feat(cleaners): opt cross-platform cleaners in to Windows, add WSL disk reporter`.

### Task 10: Windows Task Scheduler backend

**Files:**
- Create: `cleanix/scheduler/schtasks.py`
- Modify: `cleanix/scheduler/__init__.py` (`backend()` returns it when `is_windows()`)
- Test: `tests/test_windows_scheduler.py`

**Interfaces:**
- Produces in `schtasks` (same surface as `cron.py`): `FREQUENCIES = {"hourly": ..., "daily": ..., "weekly": ..., "monthly": ...}`; `build_create_args(frequency: str, exe: str, report_file: str) -> list[str]`, an argv for `schtasks`: `["schtasks", "/Create", "/TN", "Cleanix Scan", "/TR", <quoted command>, "/SC", <HOURLY|DAILY|WEEKLY|MONTHLY>, "/ST", "03:00", "/RL", "LIMITED", "/F"]` (no `/ST` for hourly); the task command is `"<exe>" scan --json --output "<report_file>"` (paths quoted so spaces survive); `install(frequency="weekly") -> str`, `uninstall() -> str`, `status() -> str`, with `uninstall` using `schtasks /Delete /TN "Cleanix Scan" /F` and `status` using `schtasks /Query /TN "Cleanix Scan"`. The task runs as the current user, never as SYSTEM, and only scans (never deletes). Report file: `history.state_dir() / "last-scan.json"`.

- [ ] **Step 1: Write failing tests** (any OS):
  - `test_backend_selects_schtasks_on_windows`: monkeypatch `scheduler.is_windows` True, `backend().__name__.endswith("schtasks")`.
  - `test_create_args_quote_paths_with_spaces_and_unicode`: `exe=r"C:\Program Files\Cleanix\cleanix.exe"`, `report_file=r"C:\Users\Zoë Müller\AppData\Local\cleanix\last-scan.json"`; the `/TR` argument contains both paths wrapped in double quotes and ends with `scan --json --output "<report>"`-style quoting.
  - `test_create_args_never_use_system_account`: `"/RU"` is absent from the args and `"/RL"` is followed by `"LIMITED"`.
  - `test_unknown_frequency_raises_value_error`.
  - `test_install_calls_schtasks` (monkeypatch `subprocess.run` to record argv, return exit 0): `install("daily")` runs the create args; a non-zero exit raises `RuntimeError` containing stderr.
  - `test_uninstall_and_status_when_absent`: exit code 1 from `/Query` gives "not installed"; from `/Delete` gives "Nothing to remove".
- [ ] **Step 2: Run** the tests; expect FAIL.
- [ ] **Step 3: Implement** the backend and the dispatch branch (check Windows first in `backend()`). Note in the module docstring that notification toasts are not part of this backend (systemd's `notify-send` has no equivalent here; the report file is the output).
- [ ] **Step 4: Run** the new tests and the full suite; expect PASS.
- [ ] **Step 5: Commit** `feat(scheduler): Windows Task Scheduler backend`.

### Task 11: CI, packaging, docs and a green Windows suite

**Files:**
- Modify: `.github/workflows/ci.yml`, `pyproject.toml`, `README.md`, `cleanix.1` generation inputs if they list platforms (`scripts/gen_manpage.py`), `RELEASING.md` only if it names platforms
- Test: existing suite on this Windows machine plus `windows-latest` in CI

**Interfaces:**
- Produces: CI matrix `os: [ubuntu-latest, macos-latest, windows-latest]` (comment updated); classifier `Operating System :: Microsoft :: Windows` and keyword `windows`; description "...every *nix (Linux, macOS, BSD) and Windows."; version `1.3.0`; README platform table gains a Windows row (cleaners from Tasks 6-9, Task Scheduler) and a short "Windows notes" section (run an elevated terminal for admin items; Prefetch, `Windows.old` and WSL are report-only; DISM cleanup is opt-in via `--only win_component_store`; quarantine does not cover command items such as the Recycle Bin).

- [ ] **Step 1: Run** the full suite on this Windows machine: `python -m pytest -q`. Fix any remaining failures by marking genuinely POSIX-only tests with a reason (as in Task 3) or fixing real Windows bugs; never delete or weaken a test. Expected: all pass or skip, finishing in well under 2 minutes.
- [ ] **Step 2: Run** `cleanix list` and `cleanix scan` (read-only) in this Windows environment; confirm only Windows and opted-in cross-platform cleaners are listed, and the scan completes without a traceback.
- [ ] **Step 3: Update** `ci.yml`, `pyproject.toml` and the docs as above.
- [ ] **Step 4: Run** `python -m pytest -q` again and `ruff check cleanix tests` (advisory); expect no new failures.
- [ ] **Step 5: Commit** `feat: Windows support (v1.3.0): CI, docs and packaging metadata`.

---

## Self-review notes

- **Spec coverage (Part 1):** platform token (T1); safety layer incl. case-insensitivity, `\\?\`, junctions, locked files (T2-3); context/elevation (T4; the UAC re-launch primitive `winenv.relaunch_elevated` ships here, but the end-to-end elevated clean flow belongs to Part 2's helper, so the CLI only prints an "elevated terminal" hint in T5); Windows cleaners incl. every item in the spec list (T6-8: temp, Windows Update, Delivery Optimization, Recycle Bin, thumbnails/icon cache, WER/dumps, Prefetch report-only, `Windows.old` report-only, DISM, winget/choco/scoop, Edge/Chrome/Firefox, shader caches, Visual Studio/JetBrains, Electron); cross-platform cleaners made Windows-aware incl. Docker/WSL reporting (T9); Task Scheduler (T10); CI/classifier/README/version (T11). Microsoft Store caches are not included (no safe, stable location found); noted as a gap for the owner.
- **Not in this plan (by design):** `safe_default` on `Cleaner`, the GUI, installers, signing (Part 2); multi-user sweeping on Windows (invoking user only).
- **Type consistency:** `violation(target, env, homes)`, `winenv.*` names, `fake_win` fields and cleaner ids are used identically across tasks.
