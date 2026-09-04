"""Cost estimation — cheap, deterministic, offline. No model call needed."""

from __future__ import annotations

import pytest

from sift.eval.cost import PRICING, CallEstimate, ModelId, RunEstimate, estimate_tokens


def test_pricing_table_has_both_configured_models() -> None:
    assert ModelId.HAIKU in PRICING
    assert ModelId.OPUS in PRICING


def test_opus_costs_more_than_haiku_per_token() -> None:
    assert PRICING[ModelId.OPUS].input_per_mtok > PRICING[ModelId.HAIKU].input_per_mtok
    assert PRICING[ModelId.OPUS].output_per_mtok > PRICING[ModelId.HAIKU].output_per_mtok


def test_estimate_tokens_is_never_zero_for_nonempty_text() -> None:
    assert estimate_tokens("x") >= 1


def test_estimate_tokens_scales_with_length() -> None:
    assert estimate_tokens("x" * 4000) > estimate_tokens("x" * 40)


@pytest.mark.parametrize(
    ("model", "input_tokens", "output_tokens", "expected"),
    [
        (ModelId.HAIKU, 1_000_000, 0, 1.00),
        (ModelId.HAIKU, 0, 1_000_000, 5.00),
        (ModelId.OPUS, 1_000_000, 0, 5.00),
        (ModelId.OPUS, 0, 1_000_000, 25.00),
    ],
    ids=["haiku-input", "haiku-output", "opus-input", "opus-output"],
)
def test_call_cost_matches_the_published_rate(
    model: ModelId, input_tokens: int, output_tokens: int, expected: float
) -> None:
    call = CallEstimate(model=model, input_tokens=input_tokens, output_tokens=output_tokens)
    assert call.usd == pytest.approx(expected)


def test_cached_input_is_cheaper_than_fresh_input() -> None:
    fresh = CallEstimate(model=ModelId.OPUS, input_tokens=1000, output_tokens=0)
    cached = CallEstimate(
        model=ModelId.OPUS, input_tokens=1000, output_tokens=0, cached_input_tokens=1000
    )
    assert cached.usd < fresh.usd
    # ~0.1x the fresh rate, per the cache_read_multiplier.
    assert cached.usd == pytest.approx(fresh.usd * 0.10)


def test_run_estimate_sums_every_call() -> None:
    calls = [
        CallEstimate(model=ModelId.OPUS, input_tokens=1_000_000, output_tokens=0),
        CallEstimate(model=ModelId.HAIKU, input_tokens=1_000_000, output_tokens=0),
    ]
    run = RunEstimate(calls=calls)
    assert run.call_count == 2
    assert run.usd == pytest.approx(5.00 + 1.00)


def test_run_estimate_breaks_down_by_model() -> None:
    calls = [
        CallEstimate(model=ModelId.OPUS, input_tokens=1_000_000, output_tokens=0),
        CallEstimate(model=ModelId.OPUS, input_tokens=1_000_000, output_tokens=0),
        CallEstimate(model=ModelId.HAIKU, input_tokens=1_000_000, output_tokens=0),
    ]
    run = RunEstimate(calls=calls)
    assert run.by_model[ModelId.OPUS] == pytest.approx(10.00)
    assert run.by_model[ModelId.HAIKU] == pytest.approx(1.00)


def test_empty_run_costs_nothing() -> None:
    assert RunEstimate(calls=[]).usd == 0.0
    assert RunEstimate(calls=[]).call_count == 0
