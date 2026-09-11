"""P5 step 6: --dry-run end to end on the four-agent path.

Zero network, zero API key - see tests/conftest.py's autouse network block,
which applies here exactly as everywhere else in the suite.
"""

from __future__ import annotations

from sift.eval.cost import ModelId
from sift.orchestrator.dry_run import pipeline_dry_run_estimate
from tests._orchestrator_helpers import bundle, realistic_pipeline_config


def test_four_calls_per_finding() -> None:
    config = realistic_pipeline_config()
    estimate = pipeline_dry_run_estimate([bundle()], config)
    assert estimate.call_count == 4


def test_four_calls_per_finding_scales_with_dataset_size() -> None:
    config = realistic_pipeline_config()
    estimate = pipeline_dry_run_estimate([bundle(), bundle(), bundle()], config)
    assert estimate.call_count == 12


def test_role_model_tiers_are_correct() -> None:
    """Three Haiku calls and exactly one Opus call per finding - the
    Adjudicator, and only the Adjudicator, on the strongest tier."""
    config = realistic_pipeline_config()
    estimate = pipeline_dry_run_estimate([bundle()], config)
    models = [call.model for call in estimate.calls]
    assert models.count(ModelId.HAIKU) == 3
    assert models.count(ModelId.OPUS) == 1


def test_adjudicator_is_never_the_cheap_model() -> None:
    """Even if every AgentCall happened to be constructed with the same
    model (a config bug), the Adjudicator's slot in the estimate must trace
    back to config.adjudicator.model specifically - not silently to
    whichever tier the analysts got. Proven by using two genuinely different
    models and checking the last of the four calls matches adjudicator's."""
    config = realistic_pipeline_config()
    estimate = pipeline_dry_run_estimate([bundle()], config)
    assert estimate.calls[3].model is config.adjudicator.model
    assert estimate.calls[3].model is ModelId.OPUS


def test_cost_estimate_is_positive_and_finite() -> None:
    config = realistic_pipeline_config()
    estimate = pipeline_dry_run_estimate([bundle()], config)
    assert estimate.usd > 0.0
    assert estimate.usd < 1.0  # one finding, four short calls - sanity ceiling


def test_cost_matches_hand_computed_pricing_table_arithmetic() -> None:
    """Sane against the gateway's published pricing table: reconstruct the dollar figure
    from PRICING directly and confirm the estimator agrees, rather than only
    checking the estimator agrees with itself."""
    from sift.eval.cost import PRICING

    config = realistic_pipeline_config()
    estimate = pipeline_dry_run_estimate([bundle()], config)
    expected = 0.0
    for call in estimate.calls:
        pricing = PRICING[call.model]
        fresh = call.input_tokens - call.cached_input_tokens - call.cache_write_tokens
        expected += (
            fresh * pricing.input_per_mtok
            + call.cached_input_tokens * pricing.input_per_mtok * pricing.cache_read_multiplier
            + call.cache_write_tokens * pricing.input_per_mtok * pricing.cache_write_multiplier
            + call.output_tokens * pricing.output_per_mtok
        ) / 1_000_000
    assert estimate.usd == expected


def test_shared_context_is_cache_written_once_and_read_three_times() -> None:
    """Mirrors ChatMessage.cacheable in sift.llm.provider - the estimate
    should not charge full price for the shared prefix on all four calls."""
    config = realistic_pipeline_config()
    estimate = pipeline_dry_run_estimate([bundle()], config)
    write_calls = [c for c in estimate.calls if c.cache_write_tokens > 0]
    read_calls = [c for c in estimate.calls if c.cached_input_tokens > 0]
    assert len(write_calls) == 1
    assert len(read_calls) == 3


def test_empty_dataset_costs_nothing() -> None:
    estimate = pipeline_dry_run_estimate([], realistic_pipeline_config())
    assert estimate.call_count == 0
    assert estimate.usd == 0.0
