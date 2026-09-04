"""The harness: dry-run estimation and the D11/D13-shaped report."""

from __future__ import annotations

from sift.eval.config import EvalConfig
from sift.eval.cost import ModelId
from sift.eval.dataset import DatasetEntry, GroundTruth, Provenance, RejectedCandidate
from sift.eval.harness import (
    EvalReport,
    dry_run_estimate,
    estimate_from_text,
    render_report_markdown,
)


def make_config(**overrides: object) -> EvalConfig:
    base: dict[str, object] = {
        "temperature": 0.0,
        "dataset_path": "evals/dataset/dataset.jsonl",
        "budget_usd": 5.00,
    }
    return EvalConfig.model_validate(base | overrides)


def make_entry(**overrides: object) -> DatasetEntry:
    base: dict[str, object] = {
        "id": "e1",
        "rule_id": "r",
        "path": "a.py",
        "line": 1,
        "repo": "org/repo",
        "repo_sha": "a" * 40,
        "ground_truth": GroundTruth.TRUE_POSITIVE,
        "rationale": "because",
        "provenance": Provenance.CVE_FIX,
        "labeled_by": "test",
    }
    return DatasetEntry.model_validate(base | overrides)


# ------------------------------------------------------------- dry_run_estimate


def test_dry_run_estimate_is_one_call_per_finding() -> None:
    """The P4 single-prompt baseline's shape, not the P5 four-agent pipeline's."""
    entries = [make_entry(id=str(i)) for i in range(7)]
    estimate = dry_run_estimate(entries, make_config())
    assert estimate.call_count == 7


def test_dry_run_estimate_on_empty_dataset_costs_nothing() -> None:
    estimate = dry_run_estimate([], make_config())
    assert estimate.call_count == 0
    assert estimate.usd == 0.0


def test_dry_run_estimate_uses_the_configured_baseline_model() -> None:
    config = make_config(baseline_model=ModelId.HAIKU)
    estimate = dry_run_estimate([make_entry()], config)
    assert estimate.calls[0].model is ModelId.HAIKU


def test_dry_run_estimate_never_touches_the_network() -> None:
    """Purely arithmetic - no import of a provider SDK, no API key needed.

    Proven by running it here, in a test suite with no credentials
    configured at all, and getting a real number back rather than an error.
    """
    estimate = dry_run_estimate([make_entry(id=str(i)) for i in range(50)], make_config())
    assert estimate.call_count == 50


def test_estimate_from_text_scales_with_content_length() -> None:
    short = estimate_from_text(["x" * 40], make_config())
    long = estimate_from_text(["x" * 4000], make_config())
    assert long.usd > short.usd


# ------------------------------------------------------------------ EvalReport


def test_report_build_counts_by_provenance() -> None:
    entries = [
        make_entry(id="a", provenance=Provenance.CVE_FIX),
        make_entry(id="b", provenance=Provenance.CVE_FIX),
        make_entry(id="c", provenance=Provenance.HAND_LABELED),
    ]
    report = EvalReport.build(entries, [], make_config())
    assert report.by_provenance["CVE_FIX"].count == 2
    assert report.by_provenance["HAND_LABELED"].count == 1
    assert report.by_provenance["REAL_WORLD"].count == 0


def test_report_build_counts_rejections_by_reason() -> None:
    rejected = [
        RejectedCandidate(rule_id="r", path="a.py", line=1, reason="INSUFFICIENT"),
        RejectedCandidate(rule_id="r", path="b.py", line=2, reason="INSUFFICIENT"),
        RejectedCandidate(rule_id="r", path="c.py", line=3, reason="non_python"),
    ]
    report = EvalReport.build([], rejected, make_config())
    assert report.rejected_by_reason == {"INSUFFICIENT": 2, "non_python": 1}


def test_report_flags_a_thin_holdout() -> None:
    entries = [make_entry(id=str(i), provenance=Provenance.CVE_FIX) for i in range(10)]
    report = EvalReport.build(entries, [], make_config())
    assert report.holdout_is_thin is True
    assert report.private_holdout_size == 10


# --------------------------------------------------------------- markdown output


def test_markdown_states_false_suppression_rate_is_not_yet_measured() -> None:
    """CONTRIBUTING.md: never publish an unmeasured metric. With no P4 step 5
    scoring run, the report must say so rather than print a blank that reads
    as zero."""
    report = EvalReport.build([], [], make_config())
    markdown = render_report_markdown(report)
    assert "not yet measured" in markdown or "Not yet measured" in markdown


def test_markdown_flags_a_thin_holdout_explicitly() -> None:
    entries = [make_entry(id=str(i), provenance=Provenance.HAND_LABELED) for i in range(5)]
    report = EvalReport.build(entries, [], make_config())
    markdown = render_report_markdown(report)
    assert "Thin holdout" in markdown
    assert "does not" in markdown or "not a precise point estimate" in markdown


def test_markdown_does_not_flag_a_holdout_that_meets_the_threshold() -> None:
    from sift.eval.dataset import THIN_HOLDOUT_THRESHOLD

    entries = [
        make_entry(id=str(i), provenance=Provenance.CVE_FIX) for i in range(THIN_HOLDOUT_THRESHOLD)
    ]
    report = EvalReport.build(entries, [], make_config())
    markdown = render_report_markdown(report)
    assert "Thin holdout" not in markdown


def test_markdown_shows_prompt_hashes_as_none_when_absent() -> None:
    report = EvalReport.build([], [], make_config())
    markdown = render_report_markdown(report)
    assert "none yet" in markdown


def test_markdown_reports_every_provenance_never_pooled() -> None:
    entries = [make_entry(id=str(p), provenance=p) for p in Provenance]
    report = EvalReport.build(entries, [], make_config())
    markdown = render_report_markdown(report)
    for provenance in Provenance:
        assert provenance.value in markdown


def test_markdown_includes_cost_when_provided() -> None:
    report = EvalReport.build([], [], make_config(), cost_usd=1.2345)
    markdown = render_report_markdown(report)
    assert "$1.2345" in markdown


def test_markdown_is_ascii() -> None:
    """The CLI already hit a Windows cp1252 failure on non-ASCII output.

    This test previously passed while the report contained three separate
    em dashes - `_fmt`'s missing-value placeholder and two hardcoded
    sentences - because the dataset it built had a value for every metric,
    so `_fmt` was never exercised, and none of the covering strings happened
    to run through this particular path. Fixed for real by removing every
    em dash from every string the renderer can emit, not by adjusting the
    fixture to dodge the ones that were left.
    """
    entries = [make_entry(id=str(i), provenance=Provenance.CVE_FIX) for i in range(3)]
    report = EvalReport.build(entries, [], make_config())
    render_report_markdown(report).encode("ascii")


def test_markdown_is_ascii_with_no_metrics_and_a_thin_holdout() -> None:
    """Exercises _fmt's None branch and the thin-holdout sentence together -
    the two paths the first ASCII test above did not reach."""
    entries = [make_entry(id=str(i), provenance=Provenance.HAND_LABELED) for i in range(3)]
    report = EvalReport.build(entries, [], make_config())
    render_report_markdown(report).encode("ascii")
