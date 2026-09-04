"""The D10 dataset schema and loader. Schema only - population is P4 step 4."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from sift.eval.dataset import (
    THIN_HOLDOUT_THRESHOLD,
    DatasetEntry,
    GroundTruth,
    Provenance,
    RejectedCandidate,
    is_holdout_thin,
    load_dataset,
    load_rejected,
    private_holdout_size,
    stratify_by_provenance,
)


def make_entry(**overrides: object) -> DatasetEntry:
    base: dict[str, object] = {
        "id": "e1",
        "rule_id": "r",
        "path": "src/a.py",
        "line": 10,
        "repo": "org/repo",
        "repo_sha": "a" * 40,
        "ground_truth": GroundTruth.TRUE_POSITIVE,
        "rationale": "the sink is reached with unsanitized input",
        "provenance": Provenance.CVE_FIX,
        "labeled_by": "CVE-2024-0000",
    }
    return DatasetEntry.model_validate(base | overrides)


def test_real_world_is_a_valid_provenance() -> None:
    """Added by the P4 kickoff decision - the harvested real-scanner findings."""
    entry = make_entry(provenance=Provenance.REAL_WORLD, labeled_by="a person")
    assert entry.provenance is Provenance.REAL_WORLD


def test_entry_requires_a_nonempty_rationale() -> None:
    with pytest.raises(ValidationError):
        make_entry(rationale="")


def test_entry_is_frozen() -> None:
    entry = make_entry()
    with pytest.raises(ValidationError):
        entry.ground_truth = GroundTruth.FALSE_POSITIVE  # type: ignore[misc]


def test_load_dataset_returns_empty_list_when_file_missing(tmp_path: Path) -> None:
    """A harness that crashes on a not-yet-built dataset makes --dry-run
    unusable before there is anything to estimate against."""
    assert load_dataset(tmp_path / "nope.jsonl") == []


def test_load_dataset_round_trips_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "dataset.jsonl"
    entry = make_entry()
    path.write_text(entry.model_dump_json() + "\n", encoding="utf-8")
    loaded = load_dataset(path)
    assert len(loaded) == 1
    assert loaded[0] == entry


def test_load_dataset_skips_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "dataset.jsonl"
    entry = make_entry()
    path.write_text(f"\n{entry.model_dump_json()}\n\n", encoding="utf-8")
    assert len(load_dataset(path)) == 1


def test_load_rejected_returns_empty_list_when_file_missing(tmp_path: Path) -> None:
    assert load_rejected(tmp_path / "nope.jsonl") == []


def test_load_rejected_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "rejected.jsonl"
    candidate = RejectedCandidate(rule_id="r", path="a.py", line=1, reason="INSUFFICIENT")
    path.write_text(json.dumps(candidate.model_dump()) + "\n", encoding="utf-8")
    loaded = load_rejected(path)
    assert loaded == [candidate]


def test_stratify_groups_by_provenance() -> None:
    entries = [
        make_entry(id="a", provenance=Provenance.CVE_FIX),
        make_entry(id="b", provenance=Provenance.HAND_LABELED),
        make_entry(id="c", provenance=Provenance.CVE_FIX),
    ]
    by_provenance = stratify_by_provenance(entries)
    assert len(by_provenance[Provenance.CVE_FIX]) == 2
    assert len(by_provenance[Provenance.HAND_LABELED]) == 1
    assert by_provenance[Provenance.REAL_WORLD] == []


def test_stratify_never_pools_across_provenance() -> None:
    """D13: the caller must be able to see each subset in isolation."""
    entries = [make_entry(provenance=p) for p in Provenance]
    by_provenance = stratify_by_provenance(entries)
    assert all(len(group) == 1 for group in by_provenance.values())


def test_private_holdout_is_cve_fix_plus_hand_labeled_only() -> None:
    entries = [
        make_entry(id="a", provenance=Provenance.CVE_FIX),
        make_entry(id="b", provenance=Provenance.HAND_LABELED),
        make_entry(id="c", provenance=Provenance.OWASP_BENCHMARK),
        make_entry(id="d", provenance=Provenance.JULIET),
        make_entry(id="e", provenance=Provenance.REAL_WORLD),
    ]
    assert private_holdout_size(entries) == 2


def test_holdout_thin_below_threshold() -> None:
    entries = [make_entry(id=str(i), provenance=Provenance.CVE_FIX) for i in range(10)]
    assert is_holdout_thin(entries) is True


def test_holdout_not_thin_at_or_above_threshold() -> None:
    entries = [
        make_entry(id=str(i), provenance=Provenance.CVE_FIX) for i in range(THIN_HOLDOUT_THRESHOLD)
    ]
    assert is_holdout_thin(entries) is False
