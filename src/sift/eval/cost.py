"""Cost estimation. Cheap and deterministic — no model call needed to run it.

CONTRIBUTING.md: "cost and latency are product features... deterministic
filters run before any model call." This module is that filter's arithmetic.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ModelId(StrEnum):
    """Model policy per CONTRIBUTING.md. Haiku for the analysts, Opus for the
    Adjudicator — the Adjudicator is never downgraded to save money, and
    nothing in this module is capable of picking a cheaper model for it.

    Values are gateway model slugs (`vendor/model`); the gateway itself is
    named only in `sift.llm.provider`, never here."""

    HAIKU = "anthropic/claude-haiku-4-5"
    OPUS = "anthropic/claude-opus-5"


@dataclass(frozen=True)
class Pricing:
    """USD per million tokens. Cache read/write are multipliers on the input
    rate, matching the gateway's published cache price list."""

    input_per_mtok: float
    output_per_mtok: float
    #: A cache write costs ~1.25x the base input rate; a cache read costs ~0.1x.
    cache_write_multiplier: float = 1.25
    cache_read_multiplier: float = 0.10


#: The gateway's published per-provider rates for the pinned upstream
#: ("anthropic"), read off the gateway's model pages on 2026-09-05:
#: anthropic/claude-haiku-4-5 at $1.00/$5.00, anthropic/claude-opus-5 at
#: $5.00/$25.00 per M input/output; cache read 0.1x and cache write 1.25x on
#: both, which is what the multipliers below encode. Verify against the
#: gateway before trusting this for a real spend decision — prices change,
#: and this table does not self-update.
PRICING: dict[ModelId, Pricing] = {
    ModelId.HAIKU: Pricing(input_per_mtok=1.00, output_per_mtok=5.00),
    ModelId.OPUS: Pricing(input_per_mtok=5.00, output_per_mtok=25.00),
}


def estimate_tokens(text: str) -> int:
    """A cheap, offline token estimate: ~4 characters per token for English
    prose and code. This is a heuristic, not a measurement.

    The real count comes from the gateway response's `usage` block (see
    `sift.llm.provider.ProviderResponse`) — but that needs a live API key and
    network access, which `--dry-run` must not require. This
    heuristic is the offline fallback that keeps `--dry-run` truly free; once
    `SIFT_API_KEY` is set (P4 step 5), the real run records `usage` totals
    for its own bookkeeping without contradicting this function's purpose.
    """
    return max(1, len(text) // 4)


@dataclass(frozen=True)
class CallEstimate:
    """One model call's estimated cost, before it is made.

    `cached_input_tokens` is the portion read from a prior cache write
    (discounted at `cache_read_multiplier`). `cache_write_tokens` is the
    portion of *this* call that primes the cache for later calls to read -
    priced at the premium `cache_write_multiplier`, not the base rate. Both
    default to 0, so a caller estimating a single uncached call (P4's shape)
    is unaffected.
    """

    model: ModelId
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int = 0
    cache_write_tokens: int = 0

    @property
    def usd(self) -> float:
        pricing = PRICING[self.model]
        fresh_input = max(0, self.input_tokens - self.cached_input_tokens - self.cache_write_tokens)
        cost = (
            fresh_input * pricing.input_per_mtok
            + self.cached_input_tokens * pricing.input_per_mtok * pricing.cache_read_multiplier
            + self.cache_write_tokens * pricing.input_per_mtok * pricing.cache_write_multiplier
            + self.output_tokens * pricing.output_per_mtok
        ) / 1_000_000
        return cost


@dataclass(frozen=True)
class RunEstimate:
    """The whole run's estimated cost and call count, before anything spends."""

    calls: list[CallEstimate]

    @property
    def call_count(self) -> int:
        return len(self.calls)

    @property
    def usd(self) -> float:
        return sum(call.usd for call in self.calls)

    @property
    def by_model(self) -> dict[ModelId, float]:
        totals: dict[ModelId, float] = {}
        for call in self.calls:
            totals[call.model] = totals.get(call.model, 0.0) + call.usd
        return totals
