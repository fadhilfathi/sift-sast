"""The safety rule is the load-bearing invariant. If this file goes quiet, the tool is unsafe."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sift.models import Adjudication, FileLineRef, Objection, Verdict


def make(**kw: object) -> Adjudication:
    base: dict[str, object] = {
        "finding_fingerprint": "abc123",
        "verdict": Verdict.FALSE_POSITIVE,
        "confidence": 0.99,
        "justification": "input is a compile-time constant at config.py:12",
    }
    return Adjudication.model_validate(base | kw)


def test_confident_dismissal_stands() -> None:
    assert make().verdict is Verdict.FALSE_POSITIVE


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
