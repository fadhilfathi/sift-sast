"""A hallucinated citation must be detectable against the real repo.

docs/ARCHITECTURE.md, Trust boundary: "a hallucinated citation invalidates
the argument that made it." tests/fixtures/python_project/src/app.py has 41
lines - used as ground truth here.
"""

from __future__ import annotations

from pathlib import Path

from sift.models.verdict import FileLineRef
from sift.orchestrator.evidence import all_citations_exist, citation_exists

PROJECT = Path(__file__).resolve().parent / "fixtures" / "python_project"


def test_a_real_line_in_a_real_file_exists() -> None:
    assert citation_exists(PROJECT, FileLineRef(path="src/app.py", line=1))


def test_a_line_past_the_end_of_the_file_does_not_exist() -> None:
    assert not citation_exists(PROJECT, FileLineRef(path="src/app.py", line=9999))


def test_a_nonexistent_file_does_not_exist() -> None:
    assert not citation_exists(PROJECT, FileLineRef(path="src/nope_not_real.py", line=1))


def test_a_path_escaping_the_repo_root_does_not_exist() -> None:
    """Routed through sift.paths.resolve - the same traversal-safe check
    every other file read in this project uses."""
    assert not citation_exists(PROJECT, FileLineRef(path="../../etc/passwd", line=1))


def test_end_line_past_the_file_does_not_exist() -> None:
    assert not citation_exists(PROJECT, FileLineRef(path="src/app.py", line=1, end_line=9999))


def test_all_citations_exist_requires_every_one() -> None:
    real = FileLineRef(path="src/app.py", line=1)
    fake = FileLineRef(path="src/app.py", line=9999)
    assert all_citations_exist(PROJECT, [real])
    assert not all_citations_exist(PROJECT, [real, fake])


def test_empty_citation_list_trivially_passes() -> None:
    assert all_citations_exist(PROJECT, [])
