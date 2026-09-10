"""Verify every cited `FileLineRef` actually exists before a verdict built on
it is accepted.

docs/ARCHITECTURE.md, Trust boundary: "a hallucinated citation invalidates
the argument that made it." This cannot live in the Pydantic schema - schema
validators have no filesystem access - so it runs here, in the orchestrator,
against the same traversal-safe resolver every other file read in this
project uses (`sift.paths`, P2).
"""

from __future__ import annotations

from pathlib import Path

from sift.models.verdict import FileLineRef
from sift.paths import UnsafePathError, resolve


def citation_exists(repo_root: Path, ref: FileLineRef) -> bool:
    """Does this citation point at a real line in a real file under the repo?"""
    try:
        real_path = resolve(repo_root, ref.path)
    except UnsafePathError:
        return False
    if not real_path.is_file():
        return False
    try:
        line_count = sum(1 for _ in real_path.open(encoding="utf-8", errors="replace"))
    except OSError:
        return False
    last_line = ref.end_line or ref.line
    return 1 <= ref.line <= line_count and last_line <= line_count


def all_citations_exist(repo_root: Path, refs: list[FileLineRef]) -> bool:
    """Every citation must exist; one hallucination invalidates the batch."""
    return all(citation_exists(repo_root, ref) for ref in refs)
