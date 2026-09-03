"""Path resolution safety.

SARIF URIs are attacker-controlled. Every one of these is an attempt to read a
file the user never pointed us at.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sift.paths import UnsafePathError, normalize_uri, read_text_head, resolve


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("password\n", encoding="utf-8")
    return root


@pytest.mark.parametrize(
    "uri",
    [
        "../secret.txt",
        "../../etc/passwd",
        "src/../../secret.txt",
        "src/../../../../../../etc/passwd",
        "./../secret.txt",
        "..%2Fsecret.txt",
        "%2e%2e/secret.txt",
        "..\\secret.txt",
        "src\\..\\..\\secret.txt",
    ],
    ids=[
        "parent",
        "deep-parent",
        "parent-after-descent",
        "many-parents",
        "dot-slash-parent",
        "encoded-slash",
        "encoded-dots",
        "windows-parent",
        "windows-mixed",
    ],
)
def test_traversal_is_refused(repo: Path, uri: str) -> None:
    with pytest.raises(UnsafePathError):
        resolve(repo, uri)


@pytest.mark.parametrize(
    "uri",
    [
        "/etc/passwd",
        "C:/Windows/win.ini",
        "C:\\Windows\\win.ini",
        "//server/share/x",
        "\\\\server\\share\\x",
    ],
    ids=["posix-absolute", "drive-forward", "drive-back", "unc-forward", "unc-back"],
)
def test_absolute_and_unc_are_refused(repo: Path, uri: str) -> None:
    with pytest.raises(UnsafePathError):
        resolve(repo, uri)


@pytest.mark.parametrize("uri", ["", "   ", ".", ".."], ids=["empty", "spaces", "dot", "dotdot"])
def test_meaningless_paths_are_refused(repo: Path, uri: str) -> None:
    with pytest.raises(UnsafePathError):
        resolve(repo, uri)


def test_symlink_escaping_the_root_is_refused(repo: Path, tmp_path: Path) -> None:
    """The case a string-prefix check misses.

    The link lives inside the repo, so `str(path).startswith(str(root))` is true
    before resolution. Only following the link first catches it.
    """
    link = repo / "src" / "escape.py"
    try:
        link.symlink_to(tmp_path / "secret.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted in this environment")
    with pytest.raises(UnsafePathError):
        resolve(repo, "src/escape.py")


@pytest.mark.parametrize(
    "uri",
    ["src/app.py", "./src/app.py", "src\\app.py", "src/%61pp.py"],
    ids=["plain", "dot-slash", "backslash", "encoded"],
)
def test_legitimate_paths_resolve(repo: Path, uri: str) -> None:
    resolved = resolve(repo, uri)
    assert resolved.name in {"app.py"}
    assert repo in resolved.parents


@pytest.mark.parametrize(
    "uri",
    ["file:///src/app.py", "file:///home/runner/work/repo/src/app.py", ".//src/a.py"],
    ids=["file-uri-root", "file-uri-scan-machine", "double-slash"],
)
def test_absolute_file_uris_are_refused(repo: Path, uri: str) -> None:
    """An absolute URI cannot be mapped into this repo without guessing.

    Scanners do emit `file:` URIs naming the scan machine's checkout. There is no
    sound way to rebase one onto a different root, and guessing means opening a
    file the finding was not about. Refused; the classifier falls back to
    path-string heuristics, which still work without reading anything.
    """
    with pytest.raises(UnsafePathError):
        resolve(repo, uri)


def test_resolved_path_need_not_exist(repo: Path) -> None:
    """Classification happens before we know the file is there."""
    assert resolve(repo, "src/missing.py").name == "missing.py"


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("src\\pkg\\a.py", "src/pkg/a.py"),
        ("./src/a.py", "src/a.py"),
        (".//src/a.py", "/src/a.py"),
        ("src/my%20folder/a.py", "src/my folder/a.py"),
        ("file:///home/x/src/a.py", "/home/x/src/a.py"),
    ],
    ids=["backslash", "dot-slash", "double-slash-stays-absolute", "percent", "file-uri"],
)
def test_normalize_uri(uri: str, expected: str) -> None:
    assert normalize_uri(uri) == expected


def test_read_text_head_is_bounded(tmp_path: Path) -> None:
    target = tmp_path / "big.py"
    target.write_text("\n".join(f"line {i}" for i in range(1000)), encoding="utf-8")
    head = read_text_head(target, max_lines=3)
    assert head.count("\n") <= 3
    assert "line 900" not in head


def test_read_text_head_tolerates_missing_and_binary(tmp_path: Path) -> None:
    """A classifier must degrade, not crash, on whatever is on disk."""
    assert read_text_head(tmp_path / "nope.py") == ""
    binary = tmp_path / "blob.bin"
    binary.write_bytes(b"\x00\xff\xfe" * 100)
    read_text_head(binary)  # must not raise


def test_read_text_head_respects_byte_cap(tmp_path: Path) -> None:
    target = tmp_path / "one_long_line.py"
    target.write_text("x" * 100_000, encoding="utf-8")
    assert len(read_text_head(target, max_bytes=1024)) <= 1024


@pytest.mark.parametrize(
    "uri",
    [
        "C:/Windows/win.ini",
        r"C:\Windows\win.ini",
        "c:/windows/win.ini",
        "D:/data/x",
        "c:",
        "C:relative",
    ],
    ids=["upper", "backslash", "lower", "other-drive", "bare", "drive-relative"],
)
def test_windows_drive_paths_are_refused_on_every_host(repo: Path, uri: str) -> None:
    """Refusal must not depend on which OS is running.

    On Linux, `Path("C:/Windows/win.ini")` is neither absolute nor
    drive-qualified — it is a relative path with a directory named `C:` — so a
    check that asks pathlib silently accepts it there while refusing it on
    Windows. CI caught exactly that. SIFT routinely runs on a Linux runner
    against SARIF produced on a Windows developer machine, so the check is done
    on the normalized string instead.
    """
    with pytest.raises(UnsafePathError):
        resolve(repo, uri)
