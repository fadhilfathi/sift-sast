"""The pre-call budget guard. CONTRIBUTING.md: checked before each call, not after."""

from __future__ import annotations

import pytest

from sift.eval.budget import DEFAULT_BUDGET_USD, BudgetExceededError, BudgetGuard


def test_default_budget_is_five_dollars() -> None:
    assert DEFAULT_BUDGET_USD == 5.00


def test_a_call_within_budget_is_allowed() -> None:
    guard = BudgetGuard(limit_usd=5.00)
    guard.check_before_call(4.99)  # must not raise


def test_a_call_at_exactly_the_limit_is_allowed() -> None:
    guard = BudgetGuard(limit_usd=5.00)
    guard.check_before_call(5.00)  # must not raise


def test_a_call_that_would_exceed_the_limit_is_refused() -> None:
    guard = BudgetGuard(limit_usd=5.00)
    with pytest.raises(BudgetExceededError):
        guard.check_before_call(5.01)


def test_the_refusal_happens_before_any_spend_is_recorded() -> None:
    """The exception fires from check_before_call, which never touches spent_usd -
    the call it blocks genuinely never happened."""
    guard = BudgetGuard(limit_usd=5.00)
    with pytest.raises(BudgetExceededError):
        guard.check_before_call(5.01)
    assert guard.spent_usd == 0.0
    assert guard.calls_made == 0


def test_spend_accumulates_across_calls() -> None:
    guard = BudgetGuard(limit_usd=5.00)
    guard.check_before_call(2.00)
    guard.record_actual(2.00)
    guard.check_before_call(2.00)
    guard.record_actual(2.00)
    assert guard.spent_usd == pytest.approx(4.00)
    assert guard.calls_made == 2


def test_accumulated_spend_eventually_refuses_a_call_that_alone_would_fit() -> None:
    guard = BudgetGuard(limit_usd=5.00)
    guard.check_before_call(4.00)
    guard.record_actual(4.00)
    # 2.00 alone is under the 5.00 limit, but 4.00 already spent + 2.00 > 5.00.
    with pytest.raises(BudgetExceededError):
        guard.check_before_call(2.00)


def test_remaining_usd_reflects_spend() -> None:
    guard = BudgetGuard(limit_usd=5.00)
    guard.record_actual(3.00)
    assert guard.remaining_usd == pytest.approx(2.00)


def test_remaining_usd_never_goes_negative() -> None:
    guard = BudgetGuard(limit_usd=5.00)
    guard.record_actual(9.00)  # a real call can still overshoot slightly
    assert guard.remaining_usd == 0.0


def test_exception_carries_the_numbers_for_a_useful_error_message() -> None:
    guard = BudgetGuard(limit_usd=5.00)
    guard.record_actual(3.00)
    with pytest.raises(BudgetExceededError) as caught:
        guard.check_before_call(3.00)
    assert caught.value.spent == pytest.approx(3.00)
    assert caught.value.limit == pytest.approx(5.00)
    assert caught.value.next_call_usd == pytest.approx(3.00)
