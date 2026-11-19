# System-wide Orphan Reports (Sub-project C) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Linux and macOS users read-only reports of system-wide orphans and leftovers: files no package owns, services, menu entries and alternatives that point at removed programs, and Mac launch jobs, app data and installer receipts left by removed apps. Each finding comes with a safe manual-removal hint. Nothing is deleted.

**Architecture:** One foundation module `cleanix/cleaners/orphan_common.py` provides:
- an `OrphanReporter` base class, which turns `Finding`s into report-only items with budgeted sizing
- a scan budget
- a lister and size walker that stays on one filesystem and never follows symlinks
- package-ownership queries for dpkg, rpm and pacman behind an allowlist of read-only commands
- shared hint helpers

Each detector family is its own module and test file, built in parallel in separate worktrees and not registered. A single wire-up task then registers all of them and adds their copy text, category and docs.

**Tech Stack:** Python 3.10+ stdlib only (`plistlib`, `shlex`, `os.scandir`), existing `cleanix.core.utils.run_command`/`which`, pytest.

**Spec:** `docs/superpowers/specs/2026-11-19-curated-listings-and-orphans-design.md`, section C (binding). Parent design: `docs/superpowers/specs/2026-11-16-windows-and-gui-design.md`.

**Dependency waves:**
- **W1:** Task 1
- **W2:** Tasks 2–7 in parallel. Each owns exactly one new module and one new test file.
- **W3:** Task 8 (wire-up)
- **W4:** Task 9 (integration and verification)

## Global Constraints

- Report-only, with no deletion path. Every item has `report_only=True`, a non-empty `hint` and a PATH kind; there are no COMMAND items. Category is `"review"`. Never in `elevated.admin_cleaner_ids()`. The `safety.py` deletion guard is unchanged.
- **Works without root.** Class `requires_root = False`. Item `requires_root=True` for system paths (removal needs admin) and `False` under the home folder. When something can't be read, the report carries a size-0 note item and the scan does not crash.
- **Symlinks are never followed out of the scanned tree.** Listing and sizing use `lstat` only, never descend into a symlinked directory, and never cross to another `st_dev`. Checking whether a link's target exists is allowed. That is a single existence check and never a walk.
- **Unknown is not orphan.** None of these produce a finding:
  - a command that fails, times out (rc 124) or is missing (rc 127)
  - output that doesn't parse
  - an unreadable file
  - a path on another device
  - a path under `/mnt/`, `/media/`, `/run/media/`, `/Volumes/`, `/net/` or `/afs/`
- **Commands.** Only `orphan_common.run()` may run commands. It prefixes `env LC_ALL=C`, never uses `shell=True`, and refuses (rc 126) any argv whose first two tokens are not in `READ_ONLY_COMMANDS`.
- **Hints:**
  - name the exact path, quoted with `shlex.quote`, plus the command that confirms ownership first (`dpkg -S`, `rpm -qf`, `pacman -Qo`, `pkgutil --file-info`, `pkgutil --files`)
  - never contain `*`, `xargs`, `-rf`, `rm -r` or any multi-path command
  - prefer "move to the Trash" on macOS
- Labels pass through `safe_label()`, which replaces control characters with `?` and caps the length at 200. Entries whose names contain `\n`, `\r` or NUL are skipped.
- **Budget.** Each cleaner gets `Config.orphan_max_items` (default 200) and `orphan_max_seconds` (default 60.0), and the budget covers sizing. When the budget runs out the scan stops, and one note item says the results are incomplete.
- **Existing coverage is reused, not duplicated:**

  | Finding | Already handled by |
  |---|---|
  | dpkg `rc` packages | `apt` |
  | `.dpkg-old`/`.rpmsave`/`.pacnew` files | `config_leftovers` |
  | `appimagekit_*.desktop` | `appimage` |
  | broken symlinks in `symlink_scan_dirs` | `broken_symlinks` |
  | `~/Library/Caches` | `macos_caches` |
  | `Saved Application State` | `macos_extra` |
  | old Homebrew versions | `homebrew` |
- Python 3.10+, no new dependencies. Tests are hermetic: a fake sysroot under `tmp_path`, faked commands, no real `/etc` reads, no real command runs. Symlink tests use a `posix_only` skip marker, because the suite also runs on Windows.
- Commit trailer: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Do not push.
- Test command (run from the repo root): `QT_QPA_PLATFORM=offscreen PYTHONPATH=. PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider <paths>`.

## Review Focus

1. **The package tool fails, times out or prints localized or unexpected text.** Expect zero findings from that batch, never "everything is unowned". Tests: Task 1 `test_parse_*_needs_positive_evidence`, Task 2 `test_unknown_ownership_reports_nothing`.
2. **Huge or remote trees** (a 100 GB `/var/lib/mysql`, an NFS-mounted `/srv/x`). The scan must stay within `orphan_max_seconds`, never size across a device boundary, and mark a partial size as a lower bound. Tests: Task 1 `test_bounded_size_*`, Task 2 `test_other_device_entry_skipped`.
3. **Paths with spaces, quotes or odd characters.** Hints must be pasteable and target exactly that one path. Each family has `test_hint_quotes_path_with_space`.
4. **Scanning without root or without macOS Full Disk Access.** Expect a note saying what was not checked, other roots still reported, and no exception. Tests: Task 2 `test_unreadable_root_yields_note`, Task 6 `test_containers_without_fda_yields_note`.
5. **Mac false positives** must not be reported:
   - Apple ids
   - helper, login-item and agent bundles
   - a vendor's other apps
   - team-id and `group.` prefixes
   - apps on external volumes
   - CLI tools that write preferences

   Tests: the Task 5 and Task 6 false-positive matrices.

---

### Task 1: Foundation (`orphan_common`, config keys, fixtures)

**Files:**
- Create: `cleanix/cleaners/orphan_common.py`
- Create: `tests/test_orphan_common.py`
- Modify: `cleanix/config.py`
  - add `orphan_max_items: int = 200`, `orphan_max_seconds: float = 60.0` and `orphan_min_age_days: float = 30.0`
  - add `FIELD_HELP` entries: "Report at most N orphan findings per cleaner", "Stop an orphan scan after N seconds", "Mac app data must be untouched N days to be reported"
- Modify: `config/default.yaml` (the three keys, commented, in the existing style)
- Modify: `tests/conftest.py` (add the `orphan_env` fixture)

**Interfaces:**
- Consumes: `Cleaner`, `SCOPE_USER`/`SCOPE_SYSTEM`, `CleanableItem`, `CleanerReport`, `utils.run_command`, `utils.which`, `utils._allocated_bytes`, `platform.distro_family`, `context.current_user`.
- Produces (exact):
  - `READ_ONLY_COMMANDS: frozenset[tuple[str, str]]` containing:
    - `("dpkg-query","-S")`, `("dpkg-query","-W")`
    - `("rpm","-qf")`, `("rpm","-qa")`
    - `("pacman","-Qo")`, `("pacman","-Qq")`
    - `("mdfind","kMDItemContentType == 'com.apple.application-bundle'")`
    - `("pkgutil","--pkgs")`, `("pkgutil","--pkg-info-plist")`, `("pkgutil","--only-files")`
  - `run(argv: Sequence[str], timeout: int = 60) -> tuple[int, str, str]`. Allowlist check, then `run_command(["env", "LC_ALL=C", *argv], timeout)`. Returns `(126, "", "refused")` when the argv is not allowlisted.
  - `tool(name: str) -> Optional[str]` (wraps `which`; the single patch point for tests).
  - `@dataclass(frozen=True) class Finding`:
    - `path: Path` is the real on-disk path.
    - `label: str`
    - `hint: str`
    - `requires_root: bool = True`
    - `note: bool = False`. A note is never sized and has size 0.
  - `class ScanBudget`:
    - `__init__(self, max_items: int, max_seconds: float, clock: Callable[[], float] = time.monotonic)`
    - `take() -> bool` returns False once the item cap is reached or time has expired.
    - `expired() -> bool`
    - `stop_reason: Optional[str]` is `"item limit"` or `"time limit"`.
  - `device_of(path: Path) -> Optional[int]` (`lstat().st_dev`; patchable).
  - `list_dir(path: Path) -> Optional[list[Path]]`. Returns `None` on PermissionError or other OSError except "missing", and `[]` when the path is missing.
  - `bounded_size(path: Path, budget: ScanBudget) -> tuple[int, bool]`. lstat-only walk in allocated bytes. Skips symlinks and entries whose `device_of` differs from `path`'s, and stops as soon as `budget.expired()`. `complete` is False if it stopped early or hit an unreadable directory.
  - Path helpers:
    - `in_root(root: str | Path, logical: str) -> Path`
    - `logical_path(root: str | Path, real: Path) -> str` (always POSIX)
    - `link_target_exists(link: Path, root: str | Path) -> Optional[bool]`. An absolute target is resolved under `root` and a relative one against the link's directory. `"/dev/null"` returns True. An unreadable link returns None.
  - Text helpers:
    - `is_removable_location(logical: str) -> bool`
    - `safe_label(text: str) -> str`
    - `bad_name(name: str) -> bool` is True when the name contains `\n`, `\r` or `\0`.
  - Ownership helpers:
    - `detect_pkg_backend(family: Optional[set[str]] = None) -> Optional[str]` returns `"dpkg"`, `"rpm"`, `"pacman"` or None. Matching is by family and also requires the tool:

      | Backend | Family (any of) | Tool required |
      |---|---|---|
      | dpkg | `debian`, `ubuntu` | `dpkg-query` |
      | rpm | `fedora`, `rhel`, `centos`, `suse`, `opensuse`, `sles`, `mageia` | `rpm` |
      | pacman | `arch`, `manjaro` | `pacman` |
    - `owner_check_command(backend: Optional[str], logical: str) -> Optional[str]` returns `dpkg -S <q>`, `rpm -qf <q>`, `pacman -Qo <q>` or `pkgutil --file-info <q>` (backend `"pkgutil"`), or None.
    - `parse_dpkg(paths, rc, out, err) -> Optional[set[str]]`, `parse_rpm(...)` and `parse_pacman(...)` return the unowned subset, or None when the result is unknown. A path counts as unowned only with positive evidence:
      - dpkg: `no path found matching pattern <p>` in `err`
      - rpm: `file <p> is not owned by any package`
      - pacman: `error: No package owns <p>`

      If rc is not 0 or 1, the result is None.
    - `query_unowned(backend: str, logical_paths: Sequence[str], budget: ScanBudget, *, batch: int = 100, timeout: int = 60) -> set[str]`.
      - Paths containing `*?[]\` are never queried and count as owned.
      - A batch with an unknown result contributes nothing.
      - argv by backend:

        | Backend | argv |
        |---|---|
        | dpkg | `["dpkg-query","-S",...]` |
        | rpm | `["rpm","-qf",...]` |
        | pacman | `["pacman","-Qo",...]` |
    - `installed_package_names(backend: str) -> Optional[set[str]]`. Runs one of the following and returns None on failure:
      - `dpkg-query -W -f=${Package}\n`
      - `rpm -qa --qf %{NAME}\n`
      - `pacman -Qq`
    - `system_account_names(root) -> set[str]` (first fields of `<root>/etc/passwd`).
    - `name_matches(name: str, names: set[str]) -> bool`. Both sides are normalised: lowercase, keep only `[a-z0-9]`, and remove a trailing version (digits). The result is True if the normalised values are equal, or if the normalised name has at least 4 characters and is a prefix of a normalised candidate.
  - `class OrphanReporter(Cleaner)`:
    - `requires_root = False`, `sysroot: str = "/"`
    - `budget: ScanBudget` is created in `__init__` from config, so a direct `find_items()` call (tests, `cleanix explain`) works.
    - `scan()` replaces it with a fresh budget, resets the once-flags, then calls `super().scan()`.
    - `pkg_backend(self) -> Optional[str]` returns `detect_pkg_backend()`. It is the only way detectors pick a backend, so tests can patch it on the class.
    - Detector modules must call commands only as `orphan_common.run(...)` / `orphan_common.tool(...)` (module attribute access, never `from ... import run`).
    - `system_findings(self) -> Iterable[Finding]` and `user_findings(self) -> Iterable[Finding]` both default to `()`.
    - `find_items()` yields system findings once per scan and user findings on every call (so once per target user). Each finding becomes a `CleanableItem(report_only=True, hint=..., size=bounded_size or 0 for notes)`. A partial size appends `" (size is a lower bound)"` to the description. When `budget.take()` fails it yields one note, `"Scan stopped early (<stop_reason>); results are incomplete"`, and stops.
    - `note(path: Path, label: str, hint: str, requires_root: bool = True) -> Finding`
  - conftest `orphan_env(tmp_path, monkeypatch)` returns a `SimpleNamespace` with these fields:
    - `root = tmp_path/"root"` is patched as `OrphanReporter.sysroot`.
    - `home = tmp_path/"home"/"u"` is installed as the single target user, the same way `fake_win` does it.
    - `cmds` is a `FakeCommands` patched over `orphan_common.run_command` and `orphan_common.which`, the module globals that `run()` and `tool()` call. This keeps the allowlist and the `env LC_ALL=C` prefix under test in every detector test and holds whatever the import style. It supports:
      - `on(prefix: tuple, rc=0, out="", err="")`. The prefix is matched against argv without the `env LC_ALL=C` prefix. An unmatched argv returns `(127, "", "not found")`.
      - `tools: set[str]`
      - `calls: list[list[str]]`

- [ ] **Step 1: Write failing tests** in `tests/test_orphan_common.py`:
  - `test_run_refuses_non_allowlisted_commands`: `run(["rm","-rf","/x"])` returns rc 126, and `run_command` is never called.
  - `test_run_prefixes_c_locale` (patch `run_command`; assert its argv starts `["env","LC_ALL=C","dpkg-query","-S"]`).
  - `test_budget_item_and_time_limits`, using a fake clock: `take()` is True twice with `max_items=2`, then False with `stop_reason=="item limit"`. With the clock moved past `max_seconds`, `expired()` is True.
  - `test_bounded_size_skips_symlinks_and_other_devices` (`posix_only` for the symlink part; patch `device_of` so one subdirectory reports another device; assert its bytes are excluded).
  - `test_bounded_size_stops_when_expired` returns `complete is False`.
  - `test_list_dir_permission_error_returns_none` (patch `os.scandir` to raise `PermissionError`).
  - `test_parse_dpkg_needs_positive_evidence`, with paths `/opt/a,/opt/b,/opt/c`:
    - out `"foo: /opt/a\n"` and err `"dpkg-query: no path found matching pattern /opt/b\n"` → `{"/opt/b"}`
    - rc 2 → `None`
  - `test_parse_rpm_needs_positive_evidence`.
  - `test_parse_pacman_needs_positive_evidence`.
  - `test_query_unowned_batches`: 250 paths → 3 `dpkg-query` calls. A path containing `*` is never in any argv.
  - `test_query_unowned_unknown_batch_reports_nothing`: rc 124 → `set()`.
  - `test_detect_backend_by_family`:

    | Family | Tool present | Expected |
    |---|---|---|
    | ubuntu | `dpkg-query` | dpkg |
    | fedora | `rpm` | rpm |
    | arch | `pacman` | pacman |
    | alpine | any | None |
    | debian | no `dpkg-query` | None |
  - `test_name_matches`:

    | Name | Names | Expected |
    |---|---|---|
    | `"postgresql"` | `{"postgresql-16"}` | True |
    | `"NetworkManager"` | `{"network-manager"}` | True |
    | `"mysql"` | `{"mysql-server-8.0"}` | True |
    | `"ucf"` | `{"ucfx"}` | False |
    | `"myapp"` | `{"mya"}` | False |
  - `test_owner_check_command_quotes`: `"/opt/My App"` → `"dpkg -S '/opt/My App'"`; `None` → `None`.
  - `test_safe_label_and_bad_name`.
  - `test_is_removable_location`: `/media/u/x` and `/Volumes/Ext/a` → True; `/opt/x` → False.
  - `test_reporter_system_part_once_user_part_per_user`: a dummy subclass with `scope=SCOPE_USER`, two target users (patch `base.get_target_users`/`use_user` as in `tests/test_cleanix.py::test_scan_all_users_dedupes_identical_commands`). Expect 1 system item plus 2 user items, all `report_only` with `hint`.
  - `test_reporter_truncation_note`: `orphan_max_items=1` and 3 findings → 1 sized item plus 1 note with size 0 containing `"stopped early"`.
  - `test_note_is_never_sized` (patch `bounded_size` to raise if called with a note path).
- [ ] **Step 2: Run** `pytest tests/test_orphan_common.py` and expect FAIL (module missing).
- [ ] **Step 3: Implement** `orphan_common.py`, the config keys, `default.yaml` and the conftest fixture as specified above.
- [ ] **Step 4: Run** `pytest tests/test_orphan_common.py tests/test_cleanix.py tests/test_curation.py` and expect PASS. Nothing is registered yet, so the existing tests are untouched.
- [ ] **Step 5: Commit** `feat(cleaners): orphan-report foundation (budget, ownership queries, safe walker)`.

---

### Task 2: Linux files owned by no package (`orphan_files`)

**Files:** Create `cleanix/cleaners/linux_orphan_files.py` and `tests/test_orphans_linux_files.py`.

**Interfaces:**
- Consumes: Task 1 (`OrphanReporter`, `Finding`, `list_dir`, `device_of`, `query_unowned`, `installed_package_names`, `system_account_names`, `name_matches`, `owner_check_command`, `OrphanReporter.pkg_backend`, `bad_name`), `linux_extras._LEFTOVER_SUFFIXES`.
- Produces: `class UnownedSystemFilesReporter(OrphanReporter)` with these attributes:
  - `id="orphan_files"`
  - `name="Files not from any package"`
  - `description="Items under /opt, /usr/local, /var/lib, /var/cache, /etc and /srv that no installed package owns (report only)"`
  - `platforms=(LINUX,)`, `scope=SCOPE_SYSTEM`, `default_enabled=False`

  `available()` returns `"package ownership lookup is not supported on this distribution"` when `self.pkg_backend()` is None.
- Rules (pinned):
  - **Candidates and depth:**
    - **Depth 1:** children of `/opt`, `/srv`, `/var/lib`, `/var/cache` and `/etc`.
    - **`/usr/local`:** depth-1 children other than the standard set `{bin, sbin, lib, lib64, libexec, include, etc, games, src, share, man}`, plus the depth-2 children of those standard directories. Under `share` the skeleton directories `{man, info, doc, applications, icons, fonts, ca-certificates, pixmaps, mime, locale, xml, sgml, emacs, texmf}` are skipped.
  - **Skip lists:**

    | Root | Skipped entries |
    |---|---|
    | `/var/lib` | `dpkg apt rpm dnf yum pacman apk systemd private flatpak snapd docker containerd containers lxd lxc libvirt machines portables ucf polkit-1 sudo dbus misc pam initramfs-tools os-prober update-rc.d alternatives dhcp NetworkManager AccountsService PackageKit logrotate man-db plymouth sss nfs ubuntu-advantage cloud` |
    | `/var/cache` | `apt dnf yum pacman man fontconfig ldconfig debconf PackageKit cups fwupd app-info abrt-di private snapd flatpak cracklib apparmor swcatalog` |
    | `/etc` | `passwd shadow group gshadow subuid subgid` (each with and without a trailing `-`), plus `hostname hosts machine-id machine-info resolv.conf fstab crypttab mtab localtime timezone adjtime ld.so.cache ssl ssh pki alternatives systemd netplan NetworkManager cloud locale.conf vconsole.conf environment motd issue issue.net` and every name starting with `.` |
    | Every root | names ending in `_LEFTOVER_SUFFIXES`, `bad_name` entries, entries whose `device_of` differs from their root's |
  - **Second signal** for `/var/lib`, `/var/cache` and `/etc`: an entry must not `name_matches` any of:
    - the installed package names
    - `system_account_names`
    - the unit basenames found in `/etc/systemd/system`, `/usr/lib/systemd/system` and `/lib/systemd/system`

    If the installed package names are unknown, those three roots are not reported and a note is yielded for each.
  - **Ownership:** one batched `query_unowned` call over all remaining candidates. Only unowned paths are reported.
  - **Symlink entries:** the link itself is reported as a note-sized finding (size 0, never followed).
  - **Unreadable root:** `note(root, "Not checked: <root> needs administrator rights to list", "Run the scan as administrator to include it.")`.
  - **Label:**
    - `"Not from any package: <logical>"`
    - for `/usr/local`: `"Installed outside the package manager: <logical>"`
  - **Hint:** `"Nothing installed this through <backend>. Check first: <owner_check_command>. If you no longer need it, remove <quoted path> by hand (administrator rights needed)."` For `/usr/local`, the hint also says it was probably installed manually (make install, a script or pip).

- [ ] **Step 1: Write failing tests** in `tests/test_orphans_linux_files.py` (all use `orphan_env`; `cmds.tools={"dpkg-query"}`; `OrphanReporter.pkg_backend` patched on the class to return `"dpkg"`):
  - `test_reports_unowned_opt_dir`: `/opt/oldapp` is unowned and `/opt/google` is owned → exactly one item, `report_only`, `requires_root`, hint contains `dpkg -S /opt/oldapp`.
  - `test_false_positives_not_reported`. None of these may be reported:
    - every skip-list sample: `/var/lib/dpkg`, `/var/lib/docker`, `/var/lib/flatpak`, `/var/lib/snapd`, `/var/lib/systemd`, `/etc/hostname`, `/etc/machine-id`, `/etc/.pwd.lock`
    - `/etc/foo.conf.dpkg-old`
    - `/var/lib/postgresql` with package `postgresql-16` installed, even though dpkg says it is unowned
    - `/var/lib/colord` with `colord` in passwd
    - `/var/lib/foo` when `foo.service` exists
    - `/usr/local/share/man`
    - `/usr/local/bin` itself
    - an entry on another device
    - a name containing `\n`
    - `/opt/a*b`
  - `test_usr_local_depth_two`: `/usr/local/bin/mytool` is reported with the "Installed outside" label. `/usr/local/go` is reported as one item.
  - `test_unknown_ownership_reports_nothing`: the dpkg query returns rc 124 → `[]`.
  - `test_installed_names_unknown_skips_name_evidence_roots`: `dpkg-query -W` fails. Nothing is reported under `/var/lib`, `/var/cache` or `/etc` beyond notes, and `/opt/oldapp` is still reported.
  - `test_unreadable_root_yields_note` (patch `list_dir` to return None for `/var/lib`): a size-0 item containing `"needs administrator"`.
  - `test_symlink_entry_not_followed` (`posix_only`): `/opt/link -> /elsewhere/big` gives size 0 and the target is never listed.
  - `test_other_device_entry_skipped`.
  - `test_hint_quotes_path_with_space`: `/opt/My App` → hint contains `'/opt/My App'`, and has no `*`, no `-rf` and no `xargs`.
  - `test_budget_caps_items`: `orphan_max_items=2` with 5 unowned → 2 items plus 1 note.
  - `test_available_without_backend`.
- [ ] **Step 2: Run** `pytest tests/test_orphans_linux_files.py` and expect FAIL.
- [ ] **Step 3: Implement** `UnownedSystemFilesReporter.system_findings()` per the rules above.
- [ ] **Step 4: Run** the same tests and expect PASS.
- [ ] **Step 5: Commit** `feat(cleaners): report Linux files owned by no package`.

---

### Task 3: Stale systemd units (`stale_services`)

**Files:** Create `cleanix/cleaners/systemd_stale.py` and `tests/test_orphans_systemd.py`.

**Interfaces:**
- Consumes: Task 1 (`OrphanReporter`, `Finding`, `in_root`, `logical_path`, `list_dir`, `link_target_exists`, `is_removable_location`, `owner_check_command`, `OrphanReporter.pkg_backend`), `utils.home`.
- Produces: `class StaleSystemdUnitReporter(OrphanReporter)` with these attributes:
  - `id="stale_services"`
  - `name="Services for removed programs"`
  - `description="systemd units, drop-ins and enablement links whose program or unit is gone (report only)"`
  - `platforms=(LINUX,)`, `scope=SCOPE_USER` (the system part runs once)

  `available()` returns `"systemd unit directories not found"` when neither `/etc/systemd/system` nor `/usr/lib/systemd/system` exists under the sysroot.
- Rules (pinned):
  - **Scanned admin directories.** These are the only ones checked; vendor directories are never reported.

    | Part | Directories |
    |---|---|
    | system | `/etc/systemd/system`, `/usr/local/lib/systemd/system`, `/etc/systemd/user` |
    | user | `~/.config/systemd/user` |
  - **Lookup directories,** used to decide whether a unit exists:

    | Part | Directories |
    |---|---|
    | system | `/etc/systemd/system`, `/run/systemd/system`, `/run/systemd/generator`, `/run/systemd/generator.early`, `/run/systemd/generator.late`, `/usr/local/lib/systemd/system`, `/usr/lib/systemd/system`, `/lib/systemd/system` |
    | user | `~/.config/systemd/user`, `~/.local/share/systemd/user`, `/etc/systemd/user`, `/usr/local/lib/systemd/user`, `/usr/lib/systemd/user`, `/lib/systemd/user` |
  - **(a) Unit file** (a regular `*.service` file):
    - Collect the non-empty `ExecStart=` values. Strip leading characters from `@-:+!`, then take the first token with `shlex.split`.
    - Skip the unit if any token contains `%` or `$`, or is under a removable location.
    - A relative name is looked up in `/usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin`.
    - The unit is stale only if every ExecStart binary is missing and no `Condition*=`/`Assert*=` line mentions that binary.
    - Label: `"Service for a missing program: <unit> (runs <binary>)"`.
  - **(b) Broken unit link.** A symlink directly in a scanned directory, or in its `*.wants/`, `*.requires/` or `*.upholds/`, whose `link_target_exists` is False. A `/dev/null` target (masked) is never reported, and None is skipped.
    - Label: `"Broken unit link: <logical> -> <target>"`.
  - **(c) Orphaned drop-in.** A `<unit>.d` directory whose suffix is `.service`, `.socket`, `.timer` or `.path`, and whose unit is absent from every lookup directory.
    - Skipped: bare type drop-ins (`service.d`), prefix drop-ins (stem ends with `-`), and an instance `foo@bar.service` whose `foo@.service` exists.
    - Label: `"Settings for a removed service: <logical>"`.
  - **Hint, system part:** `"Confirm it is unused: systemctl status <unit>[; <owner_check_command>]. If so: sudo systemctl disable <unit>, remove <quoted path> by hand, then sudo systemctl daemon-reload."`
  - **Hint, user part:** the same text with `systemctl --user` and no `sudo`.

- [ ] **Step 1: Write failing tests:**
  - `test_service_with_missing_binary_reported`
  - `test_false_positives_not_reported`. None of these may be reported:
    - the binary exists
    - a relative `ExecStart=foo` with `/usr/bin/foo` present
    - `ExecStart=%h/bin/x`
    - `ExecStart=${X}/y`
    - `ConditionPathExists=/opt/x/bin/x`
    - `ExecStart=/mnt/usb/x`
    - two ExecStart lines, one of them present
    - a missing-binary unit in `/usr/lib/systemd/system` (vendor directory, not scanned)
    - `service.d`
    - `foo-.service.d`
    - `getty@tty1.service.d` with `/lib/systemd/system/getty@.service` present
    - `foo.mount.d`
    - a masked unit linked to `/dev/null` (`posix_only`)
  - `test_broken_wants_link_reported` (`posix_only`)
  - `test_orphan_dropin_reported`
  - `test_user_unit_hint_has_no_sudo`
  - `test_hint_quotes_path_with_space`
  - `test_system_part_once_across_users`
- [ ] **Step 2: Run** `pytest tests/test_orphans_systemd.py` and expect FAIL.
- [ ] **Step 3: Implement** `system_findings()` and `user_findings()` per the rules above.
- [ ] **Step 4: Run** the same tests and expect PASS.
- [ ] **Step 5: Commit** `feat(cleaners): report stale systemd units, drop-ins and links`.

---

### Task 4: Stale menu entries and alternatives (`stale_launchers`, `stale_alternatives`)

**Files:** Create `cleanix/cleaners/linux_stale_entries.py` and `tests/test_orphans_linux_entries.py`.

**Interfaces:**
- Consumes: Task 1 (as in Task 3, plus `query_unowned`), `utils.home`.
- Produces:
  - `class StaleDesktopEntryReporter(OrphanReporter)`:
    - `id="stale_launchers"`
    - `name="Menu entries for removed programs"`
    - `description="Application menu and autostart entries whose program is missing (report only)"`
    - `platforms=(LINUX,)`, `scope=SCOPE_USER`
  - `class BrokenAlternativesReporter(OrphanReporter)`:
    - `id="stale_alternatives"`
    - `name="Broken default-program links"`
    - `description="Links in /etc/alternatives that point at removed programs (report only)"`
    - `platforms=(LINUX,)`, `scope=SCOPE_SYSTEM`
    - `available()` returns `"no alternatives system"` when `/etc/alternatives` is absent.
- Desktop rules (pinned):
  - **Scanned directories:**

    | Part | Directories |
    |---|---|
    | user | `~/.local/share/applications` (recursive, depth ≤ 3), `~/.config/autostart` |
    | system | `/usr/local/share/applications`, `/usr/share/applications`, `/etc/xdg/autostart` |

    `/usr/share/applications` and `/etc/xdg/autostart` are reported only if `query_unowned` says the entry is unowned. With no backend, those two directories are skipped.
  - **Skipped entries:**
    - symlinked `.desktop` files
    - `appimagekit_*.desktop`
    - `Hidden=true`
    - `Type` other than `Application`
    - entries with neither `TryExec` nor `Exec`
    - an Exec that fails to parse with `shlex`
  - **Which binary is checked:**
    - `TryExec` if present.
    - Otherwise the first `Exec` token, after a leading `env` and any `VAR=value` tokens.
    - Skip if that token is one of `{sh, bash, dash, zsh, flatpak, snap, gtk-launch, xdg-open, gio, kioclient, kioclient5, kde-open, kde-open5, pkexec, sudo}`.
    - Skip if the token contains `%` or `$`, or is under a removable location.
    - A relative token is searched in `/usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin /usr/games /usr/local/games /snap/bin /var/lib/flatpak/exports/bin ~/.local/bin ~/bin ~/.local/share/flatpak/exports/bin`. The fixed list is used, never `$PATH`.
  - **Label:** `"Menu entry for a missing program: <Name> (<logical>)"`.
  - **Hint:** `"It points at <binary>, which is missing. If you no longer use it, remove <quoted path>; it is only a menu shortcut."` System entries also say `Check first: <owner_check_command>` and that administrator rights are needed.
- Alternatives rules:
  - Each symlink in `/etc/alternatives` whose `link_target_exists` is False is reported. Unknown results and removable-location targets are skipped.
  - Label: `"Broken default-program link: <name> -> <target>"`.
  - Hint: `"See the choices: <cmd> --display <name>. Pick a working one with: sudo <cmd> --config <name>."`, where `<cmd>` is `update-alternatives` if `tool()` finds it, else `alternatives`.

- [ ] **Step 1: Write failing tests:**
  - `test_desktop_missing_exec_reported` (user and `/usr/local`)
  - `test_desktop_false_positives`. None of these may be reported:
    - absolute Exec present
    - relative Exec found in `/usr/bin`
    - `env FOO=1 bar %U` with `bar` present
    - `TryExec` present while Exec is odd
    - `Hidden=true`
    - `appimagekit_x.desktop`
    - `flatpak run org.x`
    - `sh -c "..."`
    - `Type=Link`
    - Exec under `/media/u/x`
    - a symlinked `.desktop` (`posix_only`)
  - `test_usr_share_entry_needs_unowned`: dpkg owns `a.desktop`, so it is not reported. `b.desktop` is unowned and is reported. With no backend, neither is reported.
  - `test_alternative_broken_link_reported` (`posix_only`)
  - `test_alternative_working_link_not_reported` (`posix_only`)
  - `test_hint_quotes_path_with_space`, for both classes
- [ ] **Step 2: Run** `pytest tests/test_orphans_linux_entries.py` and expect FAIL.
- [ ] **Step 3: Implement** both classes per the rules above.
- [ ] **Step 4: Run** the same tests and expect PASS.
- [ ] **Step 5: Commit** `feat(cleaners): report stale menu entries and broken alternatives`.

---

### Task 5: Orphaned macOS launch jobs (`orphan_launch_jobs`)

**Files:** Create `cleanix/cleaners/mac_launchd_orphans.py` and `tests/test_orphans_mac_launchd.py`.

**Interfaces:**
- Consumes: Task 1, `plistlib`, `utils.home`, `utils.current_uid`.
- Produces: `class OrphanLaunchJobReporter(OrphanReporter)` with these attributes:
  - `id="orphan_launch_jobs"`
  - `name="Background jobs of removed apps"`
  - `description="LaunchAgents and LaunchDaemons whose program is missing (report only)"`
  - `platforms=(MACOS,)`, `scope=SCOPE_USER`

  It also provides `job_program(plist: dict) -> Optional[str]` (module function), which returns `Program`, else `ProgramArguments[0]`, else None, and returns None whenever `BundleProgram` is present.
- Rules:
  - **Scanned directories.** `/System/Library` is never scanned.
    - user: `~/Library/LaunchAgents`
    - system: `/Library/LaunchAgents`, `/Library/LaunchDaemons`
  - **Plist parsing:** `plistlib.load` reads both XML and binary plists. A parse error means skip.
  - **Skipped:**
    - a label or filename starting with `com.apple.`
    - no program
    - a program that is not absolute, or contains `~` or `$`
    - a removable location
    - a program that exists under the sysroot
  - **Plist symlinks:**
    - A symlinked plist with a missing target is reported as `"Broken job link: <logical>"`.
    - Otherwise its content is read normally. Reading a file is not a walk.
  - `Disabled=true` jobs are still reported.
  - **Label:** `"Background job for a missing program: <label> (runs <program>)"`.
  - **Hint:** `"Confirm with: pkgutil --file-info <q>. If unused: launchctl bootout gui/<uid> <q>, then move <q> to the Trash."`
    - For a system job, replace the `launchctl bootout` part with `sudo launchctl bootout system <q>`.
    - For `homebrew.mxcl.*` labels, append `"For Homebrew services, check brew services list first."`.

- [ ] **Step 1: Write failing tests:**
  - `test_missing_program_reported`, for both an XML plist and a binary plist (`plistlib.dump(..., fmt=FMT_BINARY)`)
  - `test_false_positives`. None of these may be reported:
    - `com.apple.foo.plist`
    - an existing program
    - `BundleProgram`
    - a relative program
    - `/Volumes/Ext/app/bin`
    - an unparsable plist
    - a `ProgramArguments[0]` that exists
    - a plist under `<root>/System/Library/LaunchDaemons`
  - `test_disabled_job_still_reported`
  - `test_homebrew_hint`
  - `test_user_hint_uses_uid_and_quotes_path_with_space`
  - `test_broken_plist_link_reported` (`posix_only`)
  - `test_system_part_once_across_users`
- [ ] **Step 2: Run** `pytest tests/test_orphans_mac_launchd.py` and expect FAIL.
- [ ] **Step 3: Implement** `OrphanLaunchJobReporter` per the rules above.
- [ ] **Step 4: Run** the same tests and expect PASS.
- [ ] **Step 5: Commit** `feat(cleaners): report macOS launch jobs of removed apps`.

---

### Task 6: macOS data of removed apps (`orphan_app_data`)

**Files:** Create `cleanix/cleaners/mac_app_orphans.py` and `tests/test_orphans_mac_apps.py`.

**Interfaces:**
- Consumes: Task 1, `plistlib`, `utils.home`, `Config.orphan_min_age_days`.
- Produces:
  - `class OrphanAppDataReporter(OrphanReporter)`:
    - `id="orphan_app_data"`
    - `name="Data of removed apps"`
    - `description="Application Support, Preferences and Containers entries of apps that are no longer installed (report only)"`
    - `platforms=(MACOS,)`, `scope=SCOPE_USER`
  - Module functions:
    - `installed_ids(root: Path, home: Path) -> Optional[set[str]]`
    - `candidate_id(name: str) -> Optional[str]`. Strips `.plist`, a leading `group.`, and a leading `^[A-Z0-9]{10}\.` team prefix. Returns the id only if it matches `^[A-Za-z0-9-]+(\.[A-Za-z0-9_-]+){2,}$`.
    - `vendor_key(bundle_id: str) -> str`. Returns the first two labels, lowercased, or the first three when the first two are one of `{com.github, io.github, com.gitlab, io.gitlab, org.sourceforge, net.sourceforge}`.
    - `is_excluded(bid: str, installed: set[str]) -> bool`
- Rules (pinned):
  - **Installed-id index** (`installed_ids`):
    - **Apps scanned:**
      - `*.app` in `/Applications` and `~/Applications` (depth ≤ 3) and `/System/Applications` (depth ≤ 2).
      - Inside each app, nested `.app`, `.appex` and `.xpc` bundles under `Contents/{Library/LoginItems, Helpers, Frameworks, PlugIns, XPCServices, Library/LaunchServices}` (depth ≤ 4).
      - Paths from `mdfind kMDItemContentType == 'com.apple.application-bundle'`. If mdfind fails, its contribution is simply empty.
    - **Ids collected:**
      - `CFBundleIdentifier` from each found bundle's `Contents/Info.plist`
      - launch job filename stems from `~/Library/LaunchAgents`, `/Library/LaunchAgents` and `/Library/LaunchDaemons`. This module lists those directories itself and imports nothing from Task 5.
      - ids from `pkgutil --pkgs` (ignored on failure)
    - If `/Applications` is unreadable, `installed_ids` returns None. Then nothing is reported and a note is yielded.
  - **Candidates:**
    - `~/Library/Application Support/*`, `~/Library/Containers/*` and `~/Library/Preferences/*.plist` (depth 1, files only)
    - `/Library/Application Support/*` and `/Library/Preferences/*.plist`
    - Only names for which `candidate_id` returns an id. Human-named folders are never reported.
    - Never scanned: `Caches`, `Saved Application State`, `Group Containers`.
    - Symlinked entries are skipped.
  - **`is_excluded`** is True when any of these holds:
    - The id starts with `com.apple.`, or is `.GlobalPreferences`, `loginwindow` or `pbs`.
    - The id equals an installed id.
    - An installed id starts with `bid + "."`, or `bid` starts with an installed id plus `"."`.
    - `vendor_key(bid)` equals `vendor_key` of any installed id.
  - Entries whose own lstat mtime is within `orphan_min_age_days` are skipped.
  - **Unreadable `~/Library/Containers`** gives the note `"Not checked: macOS needs Full Disk Access to list <logical>"`.
  - **Label:** `"Left by a removed app: <id> (<logical>)"`.
  - **Hint:** `"No installed app uses the id <id>. Check with: mdfind \"kMDItemCFBundleIdentifier == '<id>'\" (no result means it is not installed). If you no longer need it, move <q> to the Trash in Finder."`

- [ ] **Step 1: Write failing tests.** The fake `/Applications/Acme Editor.app` has `com.acme.Editor` in a binary `Info.plist` and a nested `Contents/Library/LoginItems/Helper.app` with `com.helperco.agent`.
  - `test_reports_old_app_data`: these are reported:
    - `~/Library/Application Support/com.oldvendor.OldApp`, aged 40 days
    - `~/Library/Preferences/com.oldvendor.OldApp.plist`
  - `test_false_positives`. None of these may be reported:
    - `com.apple.Safari.plist`
    - `com.acme.Editor.helper`
    - `com.acme.Updater` (same vendor)
    - `ABCDE12345.com.acme.shared`
    - `group.com.acme.x`
    - `com.helperco.agent.data` (nested helper)
    - a `Google` folder (human name)
    - `com.old.thing` modified 2 days ago
    - an id that only appears as a launchd label
    - an id that only appears in `pkgutil --pkgs`
    - an app found only via mdfind in `<root>/opt/Apps/X.app`
    - an entry under `Caches` or `Saved Application State`
  - `test_shared_host_vendor_rule`: an installed `com.github.alice.ToolA` does not hide `com.github.bob.ToolB`, which is reported.
  - `test_applications_unreadable_reports_only_note`
  - `test_containers_without_fda_yields_note`
  - `test_hint_quotes_path_with_space`
- [ ] **Step 2: Run** `pytest tests/test_orphans_mac_apps.py` and expect FAIL.
- [ ] **Step 3: Implement** the module per the rules above.
- [ ] **Step 4: Run** the same tests and expect PASS.
- [ ] **Step 5: Commit** `feat(cleaners): report macOS data of removed apps`.

---

### Task 7: Stale macOS installer receipts (`stale_receipts`)

**Files:** Create `cleanix/cleaners/mac_receipts.py` and `tests/test_orphans_mac_receipts.py`.

**Interfaces:**
- Consumes: Task 1 (`run`, `tool`, `in_root`, `is_removable_location`, `OrphanReporter`), `plistlib`.
- Produces: `class StaleReceiptReporter(OrphanReporter)` with these attributes:
  - `id="stale_receipts"`
  - `name="Install records of removed packages"`
  - `description="Installer receipts whose installed files are all gone (report only)"`
  - `platforms=(MACOS,)`, `scope=SCOPE_SYSTEM`

  `available()` returns `"pkgutil not found"` when `tool("pkgutil")` is None.
- Rules:
  - Get the ids from `pkgutil --pkgs` and skip `com.apple.*`.
  - For each id, while `budget.take()` allows:
    - Run `pkgutil --pkg-info-plist <id>` and read `volume` and `install-location`.
    - Run `pkgutil --only-files --files <id>` and sample the first 50 files.
  - A receipt is stale only if the file list is non-empty and no sampled file exists under `in_root(root, volume/install-location/file)`.
  - **Skipped:**
    - a volume other than `/`
    - any non-zero rc
    - a plist parse error
  - **Reported path:** `/private/var/db/receipts/<id>.plist`, or `<id>.bom` if the plist is absent. If neither exists, the receipt is skipped.
  - **Label:** `"Install record for a removed package: <id>"`.
  - **Hint:** `"See what it installed: pkgutil --files <q-id>. To drop only the record: sudo pkgutil --forget <q-id>."`

- [ ] **Step 1: Write failing tests:**
  - `test_stale_receipt_reported`
  - `test_false_positives`. None of these may be reported:
    - one file still present
    - `com.apple.pkg.X`
    - volume `/Volumes/Ext`
    - an empty file list
    - `--pkg-info-plist` rc 1
    - an unparsable plist
    - no receipt file on disk
  - `test_only_allowlisted_commands_called`: every `cmds.calls` argv is in `READ_ONLY_COMMANDS`.
  - `test_budget_limits_pkgutil_calls`
- [ ] **Step 2: Run** `pytest tests/test_orphans_mac_receipts.py` and expect FAIL.
- [ ] **Step 3: Implement** `StaleReceiptReporter` per the rules above.
- [ ] **Step 4: Run** the same tests and expect PASS.
- [ ] **Step 5: Commit** `feat(cleaners): report stale macOS installer receipts`.

---

### Task 8: Wire-up — registry, copy, category, CLI, docs

**Files:**
- Modify: `cleanix/cleaners/__init__.py`. Import the 7 classes and append them to `ALL_CLEANERS` after `DuplicateFileReporter` under the comment `# System-wide orphan reports (report-only)`.
- Modify: `cleanix/core/catalog.py`. Add `_assign("review", "orphan_files stale_services stale_launchers stale_alternatives orphan_launch_jobs orphan_app_data stale_receipts")`. `SLOW_SCAN_IDS` is unchanged.
- Modify: `cleanix/core/curation.py`. Add `_RAW` entries, each blurb ending with `" " + _REVIEW_TAIL`:

  | id | Title | Blurb (before the tail) |
  |---|---|---|
  | `orphan_files` | Files not from any package | Folders in /opt, /usr/local, /var and /etc that no installed package owns. |
  | `stale_services` | Services for removed programs | Startup services whose program or unit file is gone. |
  | `stale_launchers` | Menu entries for removed programs | App menu and autostart entries whose program is missing. |
  | `stale_alternatives` | Broken default-program links | System default-program links that point at removed programs. |
  | `orphan_launch_jobs` | Background jobs of removed apps | Mac launch agents and daemons whose program is gone. |
  | `orphan_app_data` | Data of removed apps | Settings and data left by Mac apps that are no longer installed. |
  | `stale_receipts` | Install records of removed packages | Mac installer receipts whose files are all gone. |
- Modify: `tests/test_curation.py`. In `test_will_not_delete_copy_only_on_report_only_cleaners`, check the source of every class in `type(c).__mro__` except `Cleaner`, `abc.ABC` and `object`. `OrphanReporter` carries `report_only=True`.
- Modify: `tests/test_catalog.py` (add the 7 class names to `REVIEW_CLASSES`).
- Modify: `cleanix/cli.py`. In `cmd_list`, append ` (opt-in)` to the name of cleaners with `default_enabled=False`.
- Modify: `README.md`.
  - Add a new section, "System-wide leftovers (report-only, Linux/macOS)":
    - what each id checks
    - that nothing is deleted
    - that `orphan_files` is opt-in (`cleanix scan --only orphan_files`)
    - that the scans work without root and say what they could not read
    - the reuse list from Global Constraints
    - the three config keys
  - Extend the "Covered report-only" line.
- Create: `tests/test_orphans_wiring.py`.

**Interfaces:**
- Consumes: the classes from Tasks 2–7; `elevated.admin_cleaner_ids`; `registry.build_cleaners`; `cli.main`.
- Produces: the 7 ids, registered, in category `review` and with COPY entries.

- [ ] **Step 1: Write failing tests** in `tests/test_orphans_wiring.py`:
  - `test_orphan_cleaners_are_review_report_only`. For each id:
    - registered
    - `category_of(id) == "review"`
    - not in `elevated.admin_cleaner_ids()`
    - class `requires_root is False` and `safe_default is False`
    - `"windows"` not in `platforms`
    - the COPY blurb ends with `_REVIEW_TAIL`
  - `test_orphan_files_is_opt_in`. With `current_os` patched to `linux`, `build_cleaners(Config())` excludes it and `build_cleaners(Config(), only=["orphan_files"])` includes it.
  - `test_list_marks_opt_in`: `cli.main(["list","--all"])` output contains `opt-in` (do not assert on a single row; Rich may wrap columns).
  - `test_scan_yields_only_report_only_items`. Each registered orphan class runs on an empty `orphan_env` sysroot without raising, and every item is `report_only` with a hint.
- [ ] **Step 2: Run** `pytest tests/test_orphans_wiring.py tests/test_curation.py tests/test_catalog.py` and expect FAIL.
- [ ] **Step 3: Implement** the registry, catalog, COPY, test edits, CLI marker and README changes listed above.
- [ ] **Step 4: Run** `pytest tests/test_orphans_wiring.py tests/test_curation.py tests/test_catalog.py tests/test_elevate.py` and expect PASS.
- [ ] **Step 5: Commit** `feat: register Linux/macOS orphan reports (review, report-only)`.

---

### Task 9: Integration and verification

**Files:** Modify `docs/superpowers/specs/2026-11-19-curated-listings-and-orphans-design.md` (status line: C implemented) and the tests as needed.

- [ ] **Step 1: Merge** the task branches in order 1, 2–7 and 8. Run `pytest tests/test_orphan*.py`; expect PASS.
- [ ] **Step 2: Full suite** with PySide6, and again in a venv without PySide6. Expect 0 failures; only GUI tests may skip without Qt.
- [ ] **Step 3: WSL Ubuntu read-only run.** Confirm the distro name with `wsl -l -q`. Copy the repo to native ext4: `wsl -d Ubuntu -- bash -lc 'rm -rf ~/cleanix-c && mkdir -p ~/cleanix-c && cp -a /mnt/d/Vaulted/workspace/cleanix-cli/. ~/cleanix-c/'`. Use the same Python setup as earlier review runs (a venv in the copy); ask the controller if unclear. Then:
  1. Run `pytest -q tests/test_orphan*.py` there.
  2. Run `python -m cleanix scan --only orphan_files,stale_services,stale_launchers,stale_alternatives --json > ~/orphans.json` as the normal user.
  3. Run `scan` only: never `clean`, never `sudo`.
  4. Record, per id, the item count, the note count and the elapsed time. `orphan_files` must finish within `orphan_max_seconds` plus a small margin.
  5. Inspect every reported path by hand. A false positive gets a skip-list entry or rule plus a test in the owning module, and the run is repeated.
- [ ] **Step 4: macOS.** It cannot be run on this machine. Confirm the Task 5–7 tests cover every pinned rule. Record in the PR notes that the first real-Mac run is outstanding.
- [ ] **Step 5: Commit** `docs: orphan reports verified (sub-project C)`.

---

## Rulings (the spec was silent; cost if wrong)

1. **Reuse instead of new detectors.** These are not re-detected; see the table in Global Constraints:
   - dpkg `rc` (`apt`)
   - config residue (`config_leftovers`; `orphan_files` also skips those suffixes)
   - AppImage launchers
   - broken symlinks in `symlink_scan_dirs`
   - `~/Library/Caches`
   - Saved Application State
   - Homebrew old versions

   Orphaned `brew services` plists still surface through `orphan_launch_jobs`. Formulae that only exist as leftover dependencies (`brew autoremove`) are out of scope for v1.
   *Cost:* users miss Homebrew dependency leftovers. A small report-only follow-up can add them.
2. **Unknown is not orphan,** mirroring B. A path is unowned only with positive evidence from the tool's output.
   *Cost:* some real orphans are missed on odd systems. That is preferable to a wrong report.
3. **Ownership backends are dpkg, rpm and pacman only.** On apk, xbps, portage, nix, eopkg and swupd, `orphan_files` is skipped with a reason.
   *Cost:* nothing is reported on those distros.
4. **`/var/lib`, `/var/cache` and `/etc` need a second signal:** no package name, account or unit name may match. Fixed depths per root (Task 2), plus skip lists.
   *Cost:* leftovers whose name matches an installed package are missed.
5. **`orphan_files` is opt-in** (`default_enabled=False`) and not in `SLOW_SCAN_IDS`, so Simple mode never runs it; Power (tick) and CLI `--only` do. The other six are fast and on by default (category review, never pre-selected).
   *Cost:* Simple-mode users never see unowned files.
6. **systemd:**
   - Only admin directories are scanned; vendor units are the package's business.
   - A unit is stale only when every ExecStart binary is missing.
   - Only `.service`/`.socket`/`.timer`/`.path` drop-ins are checked.

   *Cost:* broken vendor units are not reported.
7. **Desktop entries** in `/usr/share/applications` and `/etc/xdg/autostart` are reported only when no package owns them.
   **Alternatives:** only broken `/etc/alternatives` links are reported; the alternatives admin database is not parsed.
   *Cost:* missing registered choices that are not currently selected are not reported.
8. **macOS app data uses reverse-DNS names only, plus vendor-prefix exclusion and a 30-day minimum age.** Human-named folders such as `Slack` are never reported.
   *Cost:* lower recall. Most `Application Support` leftovers with plain names are missed, in exchange for near-zero false positives.
9. **Notes and links are size-0 report-only items.** This covers unreadable roots, truncation and broken links. They show in the CLI, the Findings tab and the raw list, but spec A hides zero-size-only groups in the curated view unless "show empty" is on.
   *Cost:* `stale_alternatives` and broken-link findings are invisible in the default curated view (see Open questions).
10. **Sizing uses `bounded_size`, not `report_item`/`path_size`,** so the time budget covers it. The report-only source check in `test_curation.py` becomes MRO-aware.
    *Cost:* none functional. One test is generalised.
11. **`LC_ALL=C` via an `env` argv prefix** inside `orphan_common.run`, with a hard allowlist of read-only commands. `utils.run_command` is unchanged.
    *Cost:* if `env` were absent the query would fail and be treated as unknown, so nothing is reported.
12. **Mixed system/user detectors** use `SCOPE_USER`, with the system part run once per scan.
    **No `reveal.py` change:** item paths are absolute, control-character names are skipped, and reveal already uses argv only.
    *Cost:* none expected.

## Risks

- **macOS cannot be run on this machine.** Tasks 5–7 are verified only against fake trees, fake plists and fake `pkgutil`/`mdfind` output. The first real-Mac run may reveal:
  - TCC errors on paths other than `Containers`
  - non-`com.apple` Apple ids
  - bundle layouts the index misses

  Mitigations: report-only, conservative exclusions, and notes when the scan is unsure.
- **dpkg and runtime-created directories.** dpkg does not list directories that postinst scripts create, so `/var/lib/<service>` can look unowned. Mitigations: the second signal, the skip lists, and the WSL manual review in Task 9.
- **Blocking syscalls.** A hung NFS or FUSE mount can block a single `lstat`/`scandir` beyond the time budget, because the budget is checked between calls and cannot interrupt them. Mitigations: depth-1 listing only and the device check. Accepted.
- **WSL is not a typical install.** It may lack systemd units or desktop entries, so its counts are not representative of a desktop distro.
- **Users acting on hints.** Hints name one path and require an ownership check first. A user can still remove something needed; that is inherent to report-only with manual removal.

## Open questions for the controller

1. **Should `/etc` and `/srv` stay in the `orphan_files` scan?** The spec names only `/var/lib`, `/opt` and `/usr/local`; the brief added `/etc`, `/var/cache` and `/srv`. Unowned is the normal state for many `/etc` and `/srv` entries. They are included with the strict rules above; dropping them is a one-line change in Task 2.
2. **Should zero-byte report-only findings appear in curated groups?** These are broken links and "not checked" notes. Spec A currently hides groups that contain only zero-size items unless "show empty" is on (Ruling 9).
