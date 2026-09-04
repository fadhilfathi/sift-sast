"""`sift eval` and `sift cost` — the P4 step 3 harness surface."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from sift.cli import app
from sift.eval.dataset import DatasetEntry, GroundTruth, Provenance

runner = CliRunner()


def write_dataset(path: Path, count: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for i in range(count):
            entry = DatasetEntry(
                id=str(i),
                rule_id="r",
                path="a.py",
                line=1,
                repo="org/repo",
                repo_sha="a" * 40,
                ground_truth=GroundTruth.TRUE_POSITIVE,
                rationale="because",
                provenance=Provenance.CVE_FIX,
                labeled_by="test",
            )
            handle.write(entry.model_dump_json() + "\n")


def test_dry_run_with_no_dataset_costs_nothing(tmp_path: Path) -> None:
    result = runner.invoke(app, ["eval", "--dry-run", "--dataset", str(tmp_path / "nope.jsonl")])
    assert result.exit_code == 0, result.output
    assert "calls:      0" in result.output
    assert "$0.0000" in result.output


def test_dry_run_reports_call_count_from_a_real_dataset(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset.jsonl"
    write_dataset(dataset, 10)
    result = runner.invoke(app, ["eval", "--dry-run", "--dataset", str(dataset)])
    assert result.exit_code == 0, result.output
    assert "calls:      10" in result.output


def test_dry_run_exits_nonzero_when_estimate_exceeds_budget(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset.jsonl"
    write_dataset(dataset, 500)  # comfortably over $5 at the default per-finding estimate
    result = runner.invoke(
        app, ["eval", "--dry-run", "--dataset", str(dataset), "--budget", "1.00"]
    )
    assert result.exit_code == 1
    assert "EXCEEDS BUDGET" in result.output


def test_dry_run_never_requires_an_api_key(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("SIFT_API_KEY", raising=False)
    dataset = tmp_path / "dataset.jsonl"
    write_dataset(dataset, 3)
    result = runner.invoke(app, ["eval", "--dry-run", "--dataset", str(dataset)])
    assert result.exit_code == 0


def test_real_run_exits_two_naming_what_is_missing(tmp_path: Path) -> None:
    """Without --dry-run: P4 step 5 doesn't exist yet. Returning 0 from a run
    that never scored anything would be an unmeasured metric wearing a
    success exit code."""
    result = runner.invoke(app, ["eval", "--dataset", str(tmp_path / "nope.jsonl")])
    assert result.exit_code == 2
    assert "P4 step 5" in result.output


def test_config_is_stamped_with_prompt_hashes(tmp_path: Path) -> None:
    prompts = tmp_path / "prompts"
    prompts.mkdir()
    (prompts / "baseline.txt").write_text("be careful", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "eval",
            "--dry-run",
            "--dataset",
            str(tmp_path / "nope.jsonl"),
            "--prompts",
            str(prompts),
        ],
    )
    assert "baseline.txt" in result.output
    assert "none yet" not in result.output


def test_cost_with_no_report_yet_exits_one(tmp_path: Path) -> None:
    result = runner.invoke(app, ["cost", "--report", str(tmp_path / "nope.md")])
    assert result.exit_code == 1
    assert "run `sift eval` first" in result.output


def test_cost_prints_an_existing_report(tmp_path: Path) -> None:
    report = tmp_path / "REPORT.md"
    report.write_text("# a report\n\nhello\n", encoding="utf-8")
    result = runner.invoke(app, ["cost", "--report", str(report)])
    assert result.exit_code == 0
    assert "hello" in result.output


def test_rejected_candidates_are_counted_separately_from_the_dataset(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset.jsonl"
    rejected = tmp_path / "rejected.jsonl"
    write_dataset(dataset, 2)
    rejected.write_text(
        json.dumps({"rule_id": "r", "path": "b.py", "line": 5, "reason": "non_python"}) + "\n",
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        ["eval", "--dry-run", "--dataset", str(dataset), "--rejected", str(rejected)],
    )
    assert "labeled:  2" in result.output
    assert "rejected: 1" in result.output
