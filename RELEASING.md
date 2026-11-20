# Releasing cleanix-cli

Publishing is fully automated via GitHub Actions, modeled on a
push-to-`main`-triggers-release flow.

## Workflows

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| `.github/workflows/ci.yml` | push / PR to `main`/`master` | Test matrix (Ubuntu + macOS + Windows × Python 3.8–3.13, without PySide6 so GUI tests skip), a `gui-test` job (Ubuntu + macOS + Windows, Python 3.12, `.[gui-test]`, headless Qt), advisory ruff lint & mypy |
| `.github/workflows/build.yml` | `workflow_call` / manual | Runs tests, builds standalone binaries (Linux + macOS via PyInstaller) and the wheel/sdist (`python -m build` + `twine check`) |
| `.github/workflows/release.yml` | push to `main`/`master` | Detects a new version, tags it, builds artifacts, creates a GitHub Release, and publishes to PyPI |

## How a release happens

1. Bump the version in **both** `pyproject.toml` and `cleanix/__init__.py`
   (the release workflow fails if they disagree).
2. Commit and push to `main`.
3. `release.yml` will:
   - see the version has no matching `vX.Y.Z` git tag,
   - create and push that tag,
   - build binaries + wheel/sdist,
   - create a GitHub Release with the binaries and package attached,
   - publish the wheel/sdist to PyPI.

If the tag already exists, the release is skipped — so pushing unrelated commits
never re-releases.

## Beta / pre-release procedure

Used for the 1.4.0 betas and for 1.5.0b1:

1. Give the version a PEP 440 pre-release suffix in **both** files, for example
   `1.5.0b1` (`pyproject.toml` `version` and `cleanix/__init__.py`
   `__version__`). The workflow tags it `v1.5.0b1` as usual.
2. PyPI treats it as a pre-release, so users only get it with `--pre`:
   `pip install --pre cleanix-cli` (GUI: `pip install --pre "cleanix-cli[gui]"`).
   A plain `pip install cleanix-cli` keeps installing the last final release.
3. After `release.yml` has created the GitHub Release, edit it by hand and mark
   it as a **pre-release** (the workflow does not do this).
4. The standalone binaries do not include the GUI; `cleanix gui` in a binary
   says to install it with pip (with `--pre` while the version is a beta).

Version 1.5.0b1 (acting on findings) must not become a non-beta release until
the checklist in [docs/findings-verification.md](docs/findings-verification.md)
has been run on real Linux and macOS machines (and Windows, where it says so)
and every box is ticked. Then change the version to `1.5.0` in both files.

## The GUI

The desktop GUI ships inside the same wheel: `pip install "cleanix-cli[gui]"`
adds PySide6, and the `cleanix-gui` entry point (a `gui-scripts` entry, no
console window on Windows) is declared in `pyproject.toml`. The standalone CLI
binaries built by `build.yml` do not include the GUI.

Standalone GUI installers (PyInstaller bundles, a Windows installer, macOS
`.dmg`, Linux AppImage), code signing/notarisation and a root-owned helper
location are **Plan 2B** and not part of this pipeline yet.

## One-time PyPI setup (Trusted Publishing — recommended)

No API token required. On PyPI:

1. Create the project owner/account, then go to **PyPI → Your projects →
   Publishing → Add a new pending publisher** with:
   - Owner: your GitHub org/user
   - Repository: `cleanix-cli`
   - Workflow name: `release.yml`
   - Environment: `pypi`
2. In the GitHub repo, create an **Environment** named `pypi`
   (Settings → Environments) — optionally add required reviewers for a manual
   approval gate before publish.

That's it: `release.yml` requests an OIDC token (`id-token: write`) and PyPI
trusts it.

### Alternative: API token

If you prefer a token, add a repository secret `PYPI_API_TOKEN` and uncomment the
`password:` line in the `publish-pypi` job of `release.yml`.

## Testing the pipeline first

- Run **Build** manually (Actions → Build → Run workflow) to confirm binaries and
  the package build without cutting a release.
- Optionally point at **TestPyPI** first by adding `repository-url:
  https://test.pypi.org/legacy/` to the publish step.

## Local dry run

```bash
pip install build twine
python -m build
twine check dist/*
```
