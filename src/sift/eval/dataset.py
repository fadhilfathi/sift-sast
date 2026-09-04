"""The labeled dataset schema — decision D10 in `docs/ARCHITECTURE.md`.

Schema only. Population is P4 step 4, deliberately after this file: the
criteria are committed before any label is assigned, so no entry can be
admitted later because it happens to help the numbers.
"""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class Provenance(StrEnum):
    """Where a finding came from. Sets the evidentiary bar — see D10."""

    OWASP_BENCHMARK = "OWASP_BENCHMARK"
    JULIET = "JULIET"
    CVE_FIX = "CVE_FIX"
    HAND_LABELED = "HAND_LABELED"
    #: Drawn from genuine Semgrep/CodeQL output against real pinned-commit
    #: source (the 19 adjudicable findings measured in P4 step 2), not from a
    #: curated benchmark or a hand-picked CVE. Reported as its own subset,
    #: never pooled into the public-benchmark or private-holdout counts.
    REAL_WORLD = "REAL_WORLD"


class GroundTruth(StrEnum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"


#: D13: reported separately, never pooled into one blended number.
#: cve_fix and hand_labeled together are "the private holdout" — the number
#: that counts. public_benchmark carries volume under assumed contamination.
#: real_world is a distinct sanity check, capped near 19 by construction.
PRIVATE_HOLDOUT_PROVENANCE = frozenset({Provenance.CVE_FIX, Provenance.HAND_LABELED})
PUBLIC_BENCHMARK_PROVENANCE = frozenset({Provenance.OWASP_BENCHMARK, Provenance.JULIET})

#: D13: below this many findings, the private holdout must be reported as
#: thin, with an explicit statement of what claims that size does and does
#: not support — never presented as robust.
THIN_HOLDOUT_THRESHOLD = 50


class DatasetEntry(BaseModel):
    """One labeled finding. Every field here is required by D10 — a
    dataset entry is not admissible with any of them missing."""

    model_config = ConfigDict(frozen=True)

    id: str
    rule_id: str
    #: Repo-relative path within `repo_sha`.
    path: str
    line: int = Field(ge=1)
    #: The pinned commit SHA the finding was found at — never a branch,
    #: never "latest".
    repo: str
    repo_sha: str
    ground_truth: GroundTruth
    rationale: str = Field(
        min_length=1, description="Cites specific code — never 'obviously a TP'."
    )
    provenance: Provenance
    labeled_by: str = Field(
        description="A person's name, or the CVE/commit that decided it for us."
    )


class RejectedCandidate(BaseModel):
    """A finding that was considered and did not make the dataset.

    D10: 'the rejection rate is a headline number about how much of a real
    repository's findings this tool can currently reason about' — counted,
    not discarded silently.
    """

    model_config = ConfigDict(frozen=True)

    rule_id: str
    path: str
    line: int = Field(ge=1)
    reason: str


def load_dataset(path: Path) -> list[DatasetEntry]:
    """Every labeled entry in `path`, one JSON object per line (JSONL).

    Returns an empty list if the file does not exist — true today, since
    P4 step 4 has not run yet. A harness that crashes on a not-yet-built
    dataset would make `--dry-run` unusable before there is anything to
    estimate against.
    """
    if not path.is_file():
        return []
    entries = []
    for line_text in path.read_text(encoding="utf-8").splitlines():
        line_text = line_text.strip()
        if not line_text:
            continue
        entries.append(DatasetEntry.model_validate(json.loads(line_text)))
    return entries


def load_rejected(path: Path) -> list[RejectedCandidate]:
    """Same JSONL convention as `load_dataset`, for the rejection log."""
    if not path.is_file():
        return []
    rejected = []
    for line_text in path.read_text(encoding="utf-8").splitlines():
        line_text = line_text.strip()
        if not line_text:
            continue
        rejected.append(RejectedCandidate.model_validate(json.loads(line_text)))
    return rejected


def stratify_by_provenance(
    entries: list[DatasetEntry],
) -> dict[Provenance, list[DatasetEntry]]:
    """D11/D13: every consumer of the dataset groups by provenance before
    computing anything, so no caller can accidentally blend the subsets."""
    by_provenance: dict[Provenance, list[DatasetEntry]] = {p: [] for p in Provenance}
    for entry in entries:
        by_provenance[entry.provenance].append(entry)
    return by_provenance


def private_holdout_size(entries: list[DatasetEntry]) -> int:
    """CVE_FIX + HAND_LABELED combined — 'the number that counts' per D13."""
    return sum(1 for e in entries if e.provenance in PRIVATE_HOLDOUT_PROVENANCE)


def is_holdout_thin(entries: list[DatasetEntry]) -> bool:
    return private_holdout_size(entries) < THIN_HOLDOUT_THRESHOLD
