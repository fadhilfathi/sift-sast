"""Safe resolution of paths that came out of a SARIF file.

A SARIF file is untrusted input. Its `artifactLocation.uri` values are
attacker-controlled in exactly the same way the analyzed source is, and the
obvious implementation — `repo_root / uri` — happily reads
`../../../../etc/passwd` or `C:\\Windows\\win.ini`.

Everything that opens a file named by a finding goes through :func:`resolve`.
"""

from __future__ import annotations

import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlparse


class UnsafePathError(ValueError):
    """A SARIF URI resolved outside the repository root, or could not be resolved.

    Never recovered from by substituting a different path. The caller records a
    warning and proceeds without the file.
    """


def normalize_uri(uri: str) -> str:
    """Turn a SARIF artifact URI into a repo-relative POSIX path string.

    Handles the shapes real scanners emit: percent-encoding, `file:` URIs,
    Windows backslashes (Semgrep on Windows), leading `./`, and Unicode paths in
    either composed or decomposed form.
    """
    text = uri.strip()
    if text.lower().startswith("file:"):
        parsed = urlparse(text)
        text = unquote(parsed.path)
        # file:///C:/x -> /C:/x on parse; strip the leading slash before a drive.
        if len(text) > 2 and text[0] == "/" and text[2] == ":":
            text = text[1:]
    else:
        text = unquote(text)

    text = text.replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return unicodedata.normalize("NFC", text)


def resolve(repo_root: Path, uri: str) -> Path:
    """Resolve a SARIF URI to a real path inside ``repo_root``.

    Raises :class:`UnsafePathError` if the result escapes the root. Symlinks are
    followed *before* the containment check, so a symlink inside the repo that
    points outside it is rejected rather than followed — that is the trick a
    plain string-prefix check misses.
    """
    root = repo_root.resolve(strict=False)
    relative = normalize_uri(uri)

    if not relative or relative in {".", ".."}:
        raise UnsafePathError(f"empty or meaningless path: {uri!r}")

    candidate = Path(relative)
    if candidate.is_absolute() or candidate.drive or relative.startswith("//"):
        # Absolute paths, drive letters, and UNC shares never name something
        # inside a repo-relative checkout.
        raise UnsafePathError(f"absolute or UNC path refused: {uri!r}")

    target = (root / candidate).resolve(strict=False)
    if target != root and root not in target.parents:
        raise UnsafePathError(f"path escapes the repository root: {uri!r}")
    return target


def read_text_head(path: Path, *, max_lines: int = 5, max_bytes: int = 8192) -> str:
    """Read the first few lines of a file, tolerating anything on disk.

    Bounded on purpose: the only reason to read a file during pre-filtering is to
    look for a generated-code marker, which lives in the first handful of lines.
    Reading whole files here would make the no-LLM stage the slow one.

    Returns an empty string rather than raising for a file that is missing,
    unreadable, or binary. A classifier that cannot read a file must fall back to
    path heuristics, not crash the run.
    """
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = []
            consumed = 0
            for _ in range(max_lines):
                line = handle.readline(max_bytes - consumed)
                if not line:
                    break
                consumed += len(line)
                lines.append(line)
                if consumed >= max_bytes:
                    break
            return "".join(lines)
    except (OSError, ValueError):
        return ""
