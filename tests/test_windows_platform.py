from cleanix.core import platform as plat
from cleanix.core.platform import ALL, WINDOWS, XDG_PLATFORMS, supports


def test_all_does_not_include_windows(monkeypatch):
    monkeypatch.setattr(plat, "current_os", lambda: "windows")
    assert supports((ALL,)) is False
    assert supports(XDG_PLATFORMS) is False


def test_windows_requires_explicit_optin(monkeypatch):
    monkeypatch.setattr(plat, "current_os", lambda: "windows")
    assert supports((WINDOWS,)) is True
    assert supports((ALL, WINDOWS)) is True


def test_posix_unchanged(monkeypatch):
    monkeypatch.setattr(plat, "current_os", lambda: "linux")
    assert supports((ALL,)) is True
    assert supports((WINDOWS,)) is False


def test_current_os_detects_windows(monkeypatch):
    monkeypatch.setattr(plat._platform, "system", lambda: "Windows")
    plat.current_os.cache_clear()
    try:
        assert plat.current_os() == WINDOWS
        assert plat.is_windows() is True
    finally:
        monkeypatch.undo()
        plat.current_os.cache_clear()
