"""Schema-level closure on the analyst/Adversary output contracts.

These are not prompt conventions — a model that tries to emit the wrong
shape must fail validation, not merely be asked nicely not to.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sift.models.verdict import (
    AdversaryOutput,
    AdversaryPosition,
    AnalystOutput,
    FiledObjection,
    Verdict,
)


def test_analyst_output_has_no_objections_field() -> None:
    """The field does not exist on the type at all."""
    assert "objections" not in AnalystOutput.model_fields


def test_analyst_output_rejects_an_objections_key() -> None:
    """extra='forbid' — a model that tries to sneak one in fails validation,
    not silently drops it."""
    with pytest.raises(ValidationError):
        AnalystOutput.model_validate(
            {
                "position": Verdict.TRUE_POSITIVE,
                "confidence": 0.9,
                "reasoning": "x",
                "objections": [{"claim": "should not be accepted"}],
            }
        )


def test_analyst_output_accepts_its_real_shape() -> None:
    out = AnalystOutput.model_validate(
        {"position": Verdict.TRUE_POSITIVE, "confidence": 0.9, "reasoning": "reaches the sink"}
    )
    assert out.position is Verdict.TRUE_POSITIVE


def test_adversary_position_excludes_false_positive() -> None:
    with pytest.raises(ValueError, match="FALSE_POSITIVE"):
        AdversaryPosition("FALSE_POSITIVE")


def test_adversary_output_accepts_true_positive_or_needs_review() -> None:
    for position in (AdversaryPosition.TRUE_POSITIVE, AdversaryPosition.NEEDS_HUMAN_REVIEW):
        out = AdversaryOutput.model_validate(
            {"position": position, "confidence": 0.5, "reasoning": "x"}
        )
        assert out.position is position


def test_filed_objection_has_no_rebutted_field() -> None:
    assert "rebutted" not in FiledObjection.model_fields
    assert "rebuttal" not in FiledObjection.model_fields


def test_adversary_cannot_pre_mark_its_own_objection_rebutted() -> None:
    """extra='forbid' on FiledObjection - a smuggled rebutted=True is rejected,
    not accepted and ignored."""
    with pytest.raises(ValidationError):
        AdversaryOutput.model_validate(
            {
                "position": AdversaryPosition.TRUE_POSITIVE,
                "confidence": 0.6,
                "reasoning": "x",
                "objections": [
                    {"claim": "the sanitizer is unconfirmed", "rebutted": True, "rebuttal": "n/a"}
                ],
            }
        )
