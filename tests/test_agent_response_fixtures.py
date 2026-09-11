"""P5 step 4: recorded-response fixtures + adversarial safety-rule tests.

Zero live model calls - every fixture here is a hand-written string standing
in for what a model might actually reply, exercised through the real parse
and validation path (`sift.orchestrator.pipeline._parse_json`,
`AnalystOutput`/`AdversaryOutput`/`Adjudication.model_validate`, and for the
three end-to-end cases, `run_pipeline` itself against a fake `complete_fn`).
"""

from __future__ import annotations

import asyncio
import json

import pytest
from pydantic import ValidationError

from sift.models.verdict import AdversaryOutput, AnalystOutput, Verdict
from sift.orchestrator.pipeline import _parse_json, run_pipeline
from tests._orchestrator_helpers import (
    bundle,
    load_fixture,
    pipeline_config,
    provider_response,
    valid_response_payload,
)

# --------------------------------------------------------------------- valid


@pytest.mark.parametrize("role", ["reachability", "exploitability"])
def test_valid_analyst_fixture_parses(role: str) -> None:
    output = AnalystOutput.model_validate(valid_response_payload(role))
    assert output.position is Verdict.TRUE_POSITIVE


def test_valid_adversary_fixture_parses() -> None:
    output = AdversaryOutput.model_validate(valid_response_payload("adversary"))
    assert len(output.objections) == 1


def test_valid_adjudicator_fixture_parses_as_json() -> None:
    payload = valid_response_payload("adjudicator")
    assert payload["verdict"] == "TRUE_POSITIVE"


# -------------------------------------------------------------- malformed JSON

MALFORMED = ["truncated", "trailing_prose", "markdown_fenced", "double_encoded"]


@pytest.mark.parametrize("name", MALFORMED)
def test_malformed_json_fixture_fails_to_parse(name: str) -> None:
    text = load_fixture("malformed_json", f"{name}.txt")
    with pytest.raises(ValueError):
        _parse_json(text)


# ----------------------------------------------------------- schema-violating

SCHEMA_VIOLATING = [
    "confidence_out_of_range",
    "unknown_verdict_enum",
    "missing_required_field",
    "wrong_type",
]


@pytest.mark.parametrize("name", SCHEMA_VIOLATING)
def test_schema_violating_fixture_fails_validation(name: str) -> None:
    text = load_fixture("schema_violating", f"{name}.txt")
    payload = json.loads(text)
    with pytest.raises(ValidationError):
        AnalystOutput.model_validate(payload)


# ---------------------------------------------------- Adversary-specific cases


def test_adversary_false_positive_position_fails_validation() -> None:
    """The contract forbids this outright - AdversaryPosition has no
    FALSE_POSITIVE member, so this cannot even construct."""
    text = load_fixture("adversary_forbidden", "false_positive_position.txt")
    with pytest.raises(ValidationError):
        AdversaryOutput.model_validate(json.loads(text))


def test_adversary_empty_objections_fixture_parses() -> None:
    """The shape itself is valid - an Adversary that genuinely found nothing
    is allowed to say so. What blocks a dismissal built on it is
    adversary_objection_count == 0 in the safety rule (test_verdict_safety.py
    ::test_b4_zero_adversary_objections_alone_blocks), not a parse failure
    here."""
    text = load_fixture("adversary_empty_objections", "no_objections.txt")
    output = AdversaryOutput.model_validate(json.loads(text))
    assert output.objections == []


# ------------------------------------------------------- end-to-end, via the
# ------------------------------------------------------- real orchestrator


def _fake_complete_with_adjudicator_fixture(adjudicator_fixture_text: str):  # type: ignore[no-untyped-def]
    reachability = valid_response_payload("reachability")
    exploitability = valid_response_payload("exploitability")
    adversary = valid_response_payload("adversary")

    def fake_complete(config, messages, *, model=None):  # type: ignore[no-untyped-def]
        instructions = messages[-1].content
        if instructions.startswith("You are the REACHABILITY"):
            return provider_response(json.dumps(reachability))
        if instructions.startswith("You are the EXPLOITABILITY"):
            return provider_response(json.dumps(exploitability))
        if instructions.startswith("You are the ADVERSARY"):
            return provider_response(json.dumps(adversary))
        return provider_response(adjudicator_fixture_text)

    return fake_complete


def test_hallucinated_evidence_line_fixture_downgrades_through_the_real_pipeline() -> None:
    fixture = load_fixture("hallucinated_evidence", "evidence_line_not_in_bundle.txt")
    fake = _fake_complete_with_adjudicator_fixture(fixture)
    result = asyncio.run(
        run_pipeline(
            correlation_id="c1", bundle=bundle(), config=pipeline_config(), complete_fn=fake
        )
    )
    assert result.adjudication.verdict is Verdict.NEEDS_HUMAN_REVIEW
    assert "hallucinated citation" in (result.adjudication.downgrade_reason or "")


def test_hallucinated_rebuttal_citation_fails_through_the_real_pipeline() -> None:
    """Rebuttal citations go through the same existence check as top-level
    evidence_lines, not a looser one - a fabricated line inside a rebutted
    objection's `evidence` is caught exactly the same way."""
    fixture = load_fixture("hallucinated_evidence", "rebuttal_citation_not_in_bundle.txt")
    fake = _fake_complete_with_adjudicator_fixture(fixture)
    result = asyncio.run(
        run_pipeline(
            correlation_id="c1", bundle=bundle(), config=pipeline_config(), complete_fn=fake
        )
    )
    assert result.adjudication.verdict is Verdict.NEEDS_HUMAN_REVIEW
    assert "hallucinated citation" in (result.adjudication.downgrade_reason or "")


def test_injection_compliant_fixture_still_downgrades() -> None:
    """A fully-compromised Adjudicator - one that obeys an injected comment
    and drops the Adversary's real objection rather than rebutting it - is
    still caught. Not by the injection itself being detected (nothing here
    reads the comment's text), but by the objection-count gate: the
    Adversary filed one, the Adjudicator's own output carries zero."""
    fixture = load_fixture("injection_compliant", "obeys_comment_instruction.txt")
    fake = _fake_complete_with_adjudicator_fixture(fixture)
    result = asyncio.run(
        run_pipeline(
            correlation_id="c1", bundle=bundle(), config=pipeline_config(), complete_fn=fake
        )
    )
    assert result.adjudication.verdict is Verdict.NEEDS_HUMAN_REVIEW
    assert "dropped" in (result.adjudication.downgrade_reason or "")
