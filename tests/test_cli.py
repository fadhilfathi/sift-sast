"""CLI behavior.

The load-bearing assertion here is the exit code. A security tool that returns 0
having done nothing is worse than one that is honestly absent, because a CI
pipeline reads 0 as "clean".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sift import __version__
from sift.cli import app

runner = CliRunner()

FIXTURES = Path(__file__).resolve().parents[1] / "evals" / "fixtures"
FLASK = FIXTURES / "generated" / "semgrep-pallets-flask-p-default.sarif"
MINIMAL = FIXTURES / "handcrafted" / "minimal-regions.sarif"
MULTI = FIXTURES / "handcrafted" / "multiple-runs.sarif"


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def test_triage_without_dry_run_and_no_api_key_exits_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real run needs SIFT_API_KEY. Reporting success while never having been
    able to call a model would claim an adjudication that never happened."""
    monkeypatch.delenv("SIFT_API_KEY", raising=False)
    result = runner.invoke(app, ["triage", str(MULTI), "--out", str(tmp_path / "o.sarif")])
    assert result.exit_code == 1
    assert "SIFT_API_KEY" in result.output


def test_triage_dry_run_emits_and_reports(tmp_path: Path) -> None:
    out = tmp_path / "triaged.sarif"
    result = runner.invoke(
        app,
        [
            "triage",
            str(FLASK),
            "--out",
            str(out),
            "--dry-run",
            "--report-out",
            str(tmp_path / "report.json"),
            "--comment-out",
            str(tmp_path / "comment.md"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out.is_file()
    assert "findings: 16" in result.output
    assert "no model called; nothing adjudicated" in result.output
    assert (tmp_path / "report.json").is_file()
    assert (tmp_path / "comment.md").is_file()


def test_dry_run_labels_every_finding_without_dropping_any(tmp_path: Path) -> None:
    """Every finding that entered leaves labeled - Stage 1's decision, at
    minimum, even when Stage 3 never ran. Never the P1 passthrough anymore:
    a dry run still annotates, it just never calls a model to do it."""
    out = tmp_path / "triaged.sarif"
    runner.invoke(
        app,
        [
            "triage",
            str(MULTI),
            "--out",
            str(out),
            "--dry-run",
            "--report-out",
            str(tmp_path / "report.json"),
            "--comment-out",
            str(tmp_path / "comment.md"),
        ],
    )
    before = json.loads(MULTI.read_text(encoding="utf-8"))
    after = json.loads(out.read_text(encoding="utf-8"))
    before_count = sum(len(run.get("results", [])) for run in before["runs"])
    after_count = sum(len(run.get("results", [])) for run in after["runs"])
    assert after_count == before_count
    for run in after["runs"]:
        for result in run.get("results", []):
            assert "sift/v1" in result.get("properties", {})


def _dry_run_args(sarif: Path, out: Path, tmp_path: Path) -> list[str]:
    """Every triage invocation now writes a run report and a PR comment -
    default paths are cwd-relative, so tests must redirect them into
    tmp_path or they would litter the repo working directory on every run."""
    return [
        "triage",
        str(sarif),
        "--out",
        str(out),
        "--dry-run",
        "--report-out",
        str(tmp_path / "report.json"),
        "--comment-out",
        str(tmp_path / "comment.md"),
    ]


def test_model_tier_options_accept_friendly_names(tmp_path: Path) -> None:
    """--analyst-model/--adjudicator-model take HAIKU/OPUS, not the gateway's
    raw model slug - the Action's inputs use these same friendly names."""
    out = tmp_path / "triaged.sarif"
    result = runner.invoke(
        app,
        [
            *_dry_run_args(MINIMAL, out, tmp_path),
            "--analyst-model",
            "HAIKU",
            "--adjudicator-model",
            "OPUS",
        ],
    )
    assert result.exit_code == 0, result.output


def test_dry_run_warns_about_positional_identity(tmp_path: Path) -> None:
    """These findings detach on any line shift, and the user is told so."""
    out = tmp_path / "triaged.sarif"
    result = runner.invoke(app, _dry_run_args(MINIMAL, out, tmp_path))
    assert result.exit_code == 0
    assert "positional" in result.output
    assert "detach" in result.output


def test_no_positional_warning_when_identity_is_stable(tmp_path: Path) -> None:
    out = tmp_path / "triaged.sarif"
    result = runner.invoke(app, _dry_run_args(FLASK, out, tmp_path))
    assert "detach" not in result.output


def test_malformed_input_exits_nonzero(tmp_path: Path) -> None:
    bad = tmp_path / "bad.sarif"
    bad.write_text('{"version": "2.1.0"}', encoding="utf-8")
    result = runner.invoke(
        app, ["triage", str(bad), "--out", str(tmp_path / "o.sarif"), "--dry-run"]
    )
    assert result.exit_code == 1
    assert not (tmp_path / "o.sarif").exists()


def test_missing_input_exits_nonzero(tmp_path: Path) -> None:
    result = runner.invoke(app, ["triage", str(tmp_path / "nope.sarif"), "--dry-run"])
    assert result.exit_code != 0


def test_eval_without_dry_run_exits_two() -> None:
    """P4 step 5 (baseline scoring) isn't built yet. `sift cost` is implemented
    as of P4 step 3 - its own exit-code behavior is tested in test_cli_eval.py."""
    result = runner.invoke(app, ["eval"])
    assert result.exit_code == 2
    assert "not implemented" in result.output


def test_output_is_ascii_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    """The Windows console defaults to cp1252 and mangles non-ASCII into '?'."""
    monkeypatch.delenv("SIFT_API_KEY", raising=False)
    result = runner.invoke(app, ["triage", str(MULTI)])
    result.output.encode("cp1252")
