"""The safety rule is the load-bearing invariant. If this file goes quiet, the tool is unsafe."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sift.models import Adjudication, ContextCompleteness, FileLineRef, Objection, Verdict


def make(**kw: object) -> Adjudication:
    """Every blocking condition satisfied by default - so each test below can
    break exactly one and prove it, alone, forces the downgrade. A test that
    starts from two broken conditions proves nothing about either."""
    base: dict[str, object] = {
        "correlation_id": "abc123",
        "verdict": Verdict.FALSE_POSITIVE,
        "confidence": 0.99,
        "justification": "input is a compile-time constant at config.py:12",
        "adversary_objection_count": 1,
        # The one objection the Adversary filed, carried into open_objections
        # and rebutted - matches adversary_objection_count=1 exactly, so
        # neither "unrebutted" nor "dropped" fires by default.
        "open_objections": [
            Objection(claim="default objection", rebutted=True, rebuttal="answered by default")
        ],
        "context_completeness": ContextCompleteness.COMPLETE,
    }
    return Adjudication.model_validate(base | kw)


def test_confident_dismissal_stands() -> None:
    assert make().verdict is Verdict.FALSE_POSITIVE


# --------------------------------------------------------------------------
# B1-B4: each blocking condition proven in isolation. Every other condition
# in `make()` is satisfied, so a failing assertion here can only mean the one
# condition under test - not some other blocker firing alongside it.
# --------------------------------------------------------------------------


def test_b1_low_confidence_alone_blocks() -> None:
    adj = make(confidence=0.5)
    assert adj.verdict is Verdict.NEEDS_HUMAN_REVIEW
    assert adj.downgrade_reason is not None
    assert "confidence" in adj.downgrade_reason
    assert "unrebutted" not in adj.downgrade_reason
    assert "zero objections" not in adj.downgrade_reason
    assert "completeness" not in adj.downgrade_reason


def test_b2_unrebutted_objection_alone_blocks() -> None:
    adj = make(open_objections=[Objection(claim="the validator is bypassed on the retry path")])
    assert adj.verdict is Verdict.NEEDS_HUMAN_REVIEW
    assert adj.downgrade_reason is not None
    assert "unrebutted" in adj.downgrade_reason
    assert "confidence" not in adj.downgrade_reason
    assert "zero objections" not in adj.downgrade_reason
    assert "completeness" not in adj.downgrade_reason


def test_b3_insufficient_completeness_alone_blocks() -> None:
    adj = make(context_completeness=ContextCompleteness.INSUFFICIENT)
    assert adj.verdict is Verdict.NEEDS_HUMAN_REVIEW
    assert adj.downgrade_reason is not None
    assert "completeness" in adj.downgrade_reason
    assert "confidence" not in adj.downgrade_reason
    assert "unrebutted" not in adj.downgrade_reason
    assert "zero objections" not in adj.downgrade_reason


def test_b4_zero_adversary_objections_alone_blocks() -> None:
    adj = make(adversary_objection_count=0)
    assert adj.verdict is Verdict.NEEDS_HUMAN_REVIEW
    assert adj.downgrade_reason is not None
    assert "zero objections" in adj.downgrade_reason
    assert "confidence" not in adj.downgrade_reason
    assert "unrebutted" not in adj.downgrade_reason
    assert "completeness" not in adj.downgrade_reason


def test_dropped_adversary_objection_alone_blocks() -> None:
    """The Adversary filed one objection (adversary_objection_count=1), but
    the Adjudicator's own open_objections is empty - the objection was
    dropped, not resolved. Caught by count comparison, not by an unrebutted
    entry (there is no entry to be unrebutted)."""
    adj = make(adversary_objection_count=1, open_objections=[])
    assert adj.verdict is Verdict.NEEDS_HUMAN_REVIEW
    assert adj.downgrade_reason is not None
    assert "dropped" in adj.downgrade_reason
    assert "confidence" not in adj.downgrade_reason
    assert "unrebutted" not in adj.downgrade_reason
    assert "completeness" not in adj.downgrade_reason


def test_partial_completeness_does_not_block() -> None:
    """PARTIAL is evidence the model weighs, not a structural blocker - only
    INSUFFICIENT (and the missing/None case below) is."""
    assert make(context_completeness=ContextCompleteness.PARTIAL).verdict is Verdict.FALSE_POSITIVE


def test_missing_completeness_is_treated_as_insufficient() -> None:
    """A caller that forgot to report completeness gets the safe outcome."""
    kw = {k: v for k, v in make().model_dump().items() if k != "context_completeness"}
    adj = Adjudication.model_validate(kw | {"verdict": Verdict.FALSE_POSITIVE})
    assert adj.context_completeness is None
    assert adj.verdict is Verdict.NEEDS_HUMAN_REVIEW
    assert "completeness" in (adj.downgrade_reason or "")


def test_headline_adversarial_case() -> None:
    """High confidence, filed but unrebutted objection: must still downgrade.
    This is the case the whole safety rule exists to catch - a model that is
    very sure, with a prosecution that was never actually answered."""
    adj = make(
        confidence=0.99,
        open_objections=[Objection(claim="the allowlist only checks the prefix")],
    )
    assert adj.verdict is Verdict.NEEDS_HUMAN_REVIEW
    assert adj.downgraded_from is Verdict.FALSE_POSITIVE


@pytest.mark.parametrize("conf", [0.0, 0.5, 0.84, 0.8499])
def test_low_confidence_dismissal_is_downgraded(conf: float) -> None:
    adj = make(confidence=conf)
    assert adj.verdict is Verdict.NEEDS_HUMAN_REVIEW
    assert adj.downgraded_from is Verdict.FALSE_POSITIVE
    assert "confidence" in (adj.downgrade_reason or "")


def test_floor_is_inclusive() -> None:
    assert make(confidence=0.85).verdict is Verdict.FALSE_POSITIVE


def test_unrebutted_objection_blocks_dismissal() -> None:
    adj = make(open_objections=[Objection(claim="the validator is bypassed on the retry path")])
    assert adj.verdict is Verdict.NEEDS_HUMAN_REVIEW
    assert "unrebutted" in (adj.downgrade_reason or "")


def test_rebutted_objection_does_not_block() -> None:
    adj = make(
        open_objections=[
            Objection(claim="validator bypassed", rebutted=True, rebuttal="retry path re-validates")
        ]
    )
    assert adj.verdict is Verdict.FALSE_POSITIVE


def test_zero_adversary_objections_blocks_dismissal_at_any_confidence() -> None:
    """An Adversary that filed nothing is not the same as one that looked and
    found nothing to rebut. Confidence alone must never be enough."""
    adj = make(confidence=1.0, adversary_objection_count=0)
    assert adj.verdict is Verdict.NEEDS_HUMAN_REVIEW
    assert adj.downgraded_from is Verdict.FALSE_POSITIVE
    assert "zero objections" in (adj.downgrade_reason or "")


def test_adversary_objection_count_defaults_to_the_safe_zero() -> None:
    """A caller that forgets to report the count gets blocked, not a free pass."""
    adj = make()
    del_kw = {k: v for k, v in adj.model_dump().items() if k != "adversary_objection_count"}
    adj2 = Adjudication.model_validate(del_kw | {"verdict": Verdict.FALSE_POSITIVE})
    assert adj2.adversary_objection_count == 0
    assert adj2.verdict is Verdict.NEEDS_HUMAN_REVIEW


def test_true_positive_never_downgraded() -> None:
    adj = make(verdict=Verdict.TRUE_POSITIVE, confidence=0.1)
    assert adj.verdict is Verdict.TRUE_POSITIVE
    assert adj.downgraded_from is None


def test_rule_reapplies_on_assignment() -> None:
    """A later mutation must not sneak a weak dismissal past the constructor."""
    adj = make(verdict=Verdict.TRUE_POSITIVE, confidence=0.4)
    adj.verdict = Verdict.FALSE_POSITIVE
    assert adj.verdict is Verdict.NEEDS_HUMAN_REVIEW


def test_rebutted_objection_requires_text() -> None:
    with pytest.raises(ValidationError):
        Objection(claim="x", rebutted=True)


def test_justification_is_capped() -> None:
    with pytest.raises(ValidationError):
        make(justification="x" * 501)


def test_evidence_span_must_be_ordered() -> None:
    with pytest.raises(ValidationError):
        FileLineRef(path="a.py", line=10, end_line=9)
