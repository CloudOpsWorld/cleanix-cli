"""Pure-string tests of the Windows path-protection model (run on any OS)."""
import pytest

from cleanix.core.safety_windows import SYSTEMROOT_ALLOWED, normalize, violation

HOMES = [r"C:\Users\bob"]
ENV = {}


def v(target, env=ENV, homes=HOMES):
    return violation(target, env, homes)


@pytest.mark.parametrize("p", ["C:\\", "c:/", "D:\\", r"\\srv\share", "\\\\srv\\share\\",
                               "\\\\?\\UNC\\srv\\share"])
def test_drive_and_unc_roots_refused(p):
    assert v(p) is not None


@pytest.mark.parametrize("p", ["\\\\?\\C:\\Windows", r"c:\WINDOWS", "C:/Windows/",
                               r"C:\Users\bob\.\Documents", r"C:\Users\bob\x\..\Documents"])
def test_prefix_case_and_slashes_normalised(p):
    assert v(p) is not None


@pytest.mark.parametrize("p", [r"C:\Users", "C:\\", r"C:\Users\bob"])
def test_ancestors_refused(p):
    assert v(p) is not None


@pytest.mark.parametrize("sub", ["Documents", "Desktop", "AppData", "AppData\\Roaming",
                                 "AppData\\Local", "Downloads", ".ssh", "OneDrive"])
def test_protected_user_folders(sub):
    assert v("C:\\Users\\bob\\" + sub) is not None


@pytest.mark.parametrize("p", [r"C:\Users\bob\AppData\Local\Temp\x.tmp",
                               r"C:\Users\bob\AppData\Roaming\Slack\Cache",
                               r"C:\ProgramData\Microsoft\Windows\WER\ReportArchive"])
def test_cache_subpaths_allowed(p):
    assert v(p) is None


@pytest.mark.parametrize("p", [r"C:\Windows\Temp\a.tmp", r"C:\Windows\SoftwareDistribution\Download\x",
                               r"C:\Windows\MEMORY.DMP", r"C:\Windows\Logs\CBS\CBS.log"])
def test_systemroot_allowlist_allowed(p):
    assert v(p) is None


@pytest.mark.parametrize("p", [r"C:\Windows\System32\drivers\x.sys", r"C:\Windows\WinSxS\x",
                               r"C:\Windows\SoftwareDistribution", r"C:\Windows\Logs",
                               r"C:\Windows\Temp\..\System32"])
def test_systemroot_other_refused(p):
    assert v(p) is not None


def test_sibling_prefix_not_confused():
    assert v(r"C:\Windows2\foo") is None
    assert v(r"C:\Program Files2\foo") is None


@pytest.mark.parametrize("p", [r"C:\Program Files\App\cache", r"C:\Program Files (x86)\App"])
def test_program_files_subtrees_refused(p):
    assert v(p) is not None


def test_custom_env_respected():
    assert v(r"D:\WinNT\System32", {"SystemRoot": r"D:\WinNT"}) is not None
    assert v(r"D:\WinNT\Temp\x", {"SystemRoot": r"D:\WinNT"}) is None
    assert v(r"d:\winnt\system32", {"SYSTEMROOT": r"D:\WinNT"}) is not None
    # the documented default stays protected too
    assert v(r"C:\Windows\System32", {"SystemRoot": r"D:\WinNT"}) is not None
    assert v(r"D:\WinNT", {"SystemRoot": r"D:\WinNT"}) is not None


@pytest.mark.parametrize("p", ["//?\\C:\\Windows", "\\\\?/C:\\Windows", "\\/?\\C:\\Windows\\System32",
                               "//?/C:/Windows", "\\\\.\\C:\\Windows"])
def test_mixed_separator_prefix_refused(p):
    assert v(p) is not None


@pytest.mark.parametrize("p", ["\\\\?\\unc\\srv\\share", "\\\\localhost\\C$\\Windows",
                               "\\\\127.0.0.1\\c$\\Users\\bob\\Documents",
                               "\\\\?\\UNC\\localhost\\C$\\Windows\\System32",
                               "//srv/share/x", "\\\\srv\\share\\cache\\x"])
def test_every_unc_path_refused(p):
    assert "UNC" in v(p)


@pytest.mark.parametrize("p", ["C:\\Windows.", "C:\\Windows ", "C:\\Users\\bob\\Documents.",
                               "C:\\Program Files.", "C:\\Windows::$INDEX_ALLOCATION",
                               "C:\\Windows:$I30:$INDEX_ALLOCATION",
                               "C:\\Users\\bob\\Documents::$INDEX_ALLOCATION",
                               "C:\\Windows\\System32. \\x", "C:\\Windows\\Temp\\..."])
def test_trailing_dots_spaces_and_streams_refused(p):
    assert v(p) is not None


def test_stream_under_allowed_prefix_still_allowed():
    assert v("C:\\Windows\\Temp\\x:stream") is None
    assert v("C:\\Windows\\Temp\\x.tmp. ") is None


@pytest.mark.parametrize("bad", ["Windows", "%SystemDrive%\\Windows", " ", "x", "\\\\srv\\share", "C:\\"])
def test_malformed_env_fails_closed(bad):
    env = {"SystemRoot": bad, "ProgramFiles": bad, "ProgramFiles(x86)": bad,
           "ProgramData": bad, "SystemDrive": bad}
    assert v("C:\\Windows\\System32", env) is not None
    assert v("C:\\Program Files\\App", env) is not None
    assert v("C:\\ProgramData", env) is not None
    assert v("C:\\Users", env) is not None


def test_allowed_directories_themselves_refused():
    for d in ["Temp", "SoftwareDistribution\\Download", "Prefetch", "Minidump",
              "LiveKernelReports", "Logs\\CBS",
              "ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache"]:
        assert v("C:\\Windows\\" + d) is not None
        assert v("C:\\Windows\\" + d + "\\x") is None
    assert v("C:\\Windows\\MEMORY.DMP") is None


def test_non_ascii_and_spaces_home():
    homes = [r"C:\Users\Zoë Müller"]
    assert v(r"C:\Users\Zoë Müller", homes=homes) is not None
    assert v(r"C:\Users\Zoë Müller\Documents", homes=homes) is not None
    assert v(r"C:\Users\Zoë Müller\AppData\Local\Temp\x", homes=homes) is None


def test_relative_and_empty_refused():
    for p in ["", "foo", "..\\x", "C:foo", "\\Windows"]:
        assert v(p) is not None


def test_other_protected_roots():
    for p in [r"C:\$Recycle.Bin", r"C:\System Volume Information",
              r"C:\Recovery", r"C:\Boot", r"C:\ProgramData", r"C:\Program Files"]:
        assert v(p) is not None


def test_normalize():
    assert normalize("\\\\?\\C:\\Windows\\\\") == "c:\\windows"
    assert normalize("\\\\?\\UNC\\Srv\\Share\\X") == "\\\\srv\\share\\x"
    assert normalize("C:/A/./B/") == "c:\\a\\b"
    assert normalize("C:/") == "c:\\"


def test_allowlist_values():
    assert "memory.dmp" in SYSTEMROOT_ALLOWED and len(SYSTEMROOT_ALLOWED) == 8
