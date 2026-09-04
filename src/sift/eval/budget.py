"""The $5.00/run hard abort — checked before each call, not after.

CONTRIBUTING.md: "Hard abort at $5.00 per eval run, checked before each call,
not after." The distinction matters: checking after a call means the call
that busts the budget still happened and still cost money. This guard refuses
the call itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class BudgetExceededError(RuntimeError):
    """Raised before a call would be made, never after. No partial spend
    caused this — the call this exception blocks has not happened yet."""

    def __init__(self, *, spent: float, limit: float, next_call_usd: float) -> None:
        self.spent = spent
        self.limit = limit
        self.next_call_usd = next_call_usd
        super().__init__(
            f"budget exceeded: ${spent:.4f} spent + ${next_call_usd:.4f} estimated "
            f"next call > ${limit:.2f} limit"
        )


#: CONTRIBUTING.md: "Hard abort at $5.00 per eval run."
DEFAULT_BUDGET_USD = 5.00


@dataclass
class BudgetGuard:
    """Tracks spend across a run and refuses a call that would exceed the limit.

    `check_before_call` must be called with the call's own cost *estimate*
    before the call is made. `record_actual` is called after, with the real
    cost — the two can differ (an estimate is not a measurement), and only
    the recorded actual accumulates toward the limit.
    """

    limit_usd: float = DEFAULT_BUDGET_USD
    spent_usd: float = field(default=0.0, init=False)
    calls_made: int = field(default=0, init=False)

    def check_before_call(self, estimated_call_usd: float) -> None:
        if self.spent_usd + estimated_call_usd > self.limit_usd:
            raise BudgetExceededError(
                spent=self.spent_usd, limit=self.limit_usd, next_call_usd=estimated_call_usd
            )

    def record_actual(self, actual_call_usd: float) -> None:
        self.spent_usd += actual_call_usd
        self.calls_made += 1

    @property
    def remaining_usd(self) -> float:
        return max(0.0, self.limit_usd - self.spent_usd)
