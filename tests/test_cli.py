"""CLI behavior.

The load-bearing assertion here is the exit code. A security tool that returns 0
having done nothing is worse than one that is honestly absent, because a CI
pipeline reads 0 as "clean".
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from sift import __version__
from sift.canonical import canonical_equal
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


def test_triage_without_dry_run_refuses() -> None:
    """P5 is not built. Reporting success would claim a triage that never happened."""
    result = runner.invoke(app, ["triage", str(MULTI)])
    assert result.exit_code == 2
    assert "P5" in result.output


def test_triage_dry_run_emits_and_reports(tmp_path: Path) -> None:
    out = tmp_path / "triaged.sarif"
    result = runner.invoke(app, ["triage", str(FLASK), "--out", str(out), "--dry-run"])
    assert result.exit_code == 0, result.output
    assert out.is_file()
    assert "findings: 16" in result.output
    assert "no verdicts written" in result.output


def test_dry_run_output_is_a_faithful_copy(tmp_path: Path) -> None:
    """P1 emit adds nothing at all. The first thing SIFT writes lands in P5."""
    out = tmp_path / "triaged.sarif"
    runner.invoke(app, ["triage", str(MULTI), "--out", str(out), "--dry-run"])
    assert canonical_equal(
        json.loads(MULTI.read_text(encoding="utf-8")),
        json.loads(out.read_text(encoding="utf-8")),
    )


def test_dry_run_warns_about_positional_identity(tmp_path: Path) -> None:
    """These findings detach on any line shift, and the user is told so."""
    out = tmp_path / "triaged.sarif"
    result = runner.invoke(app, ["triage", str(MINIMAL), "--out", str(out), "--dry-run"])
    assert result.exit_code == 0
    assert "positional" in result.output
    assert "detach" in result.output


def test_no_positional_warning_when_identity_is_stable(tmp_path: Path) -> None:
    out = tmp_path / "triaged.sarif"
    result = runner.invoke(app, ["triage", str(FLASK), "--out", str(out), "--dry-run"])
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


def test_output_is_ascii_safe() -> None:
    """The Windows console defaults to cp1252 and mangles non-ASCII into '?'."""
    result = runner.invoke(app, ["triage", str(MULTI)])
    result.output.encode("cp1252")
