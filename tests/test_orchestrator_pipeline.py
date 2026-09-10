"""Orchestrator wiring, end to end, against a fake `complete_fn`.

Zero live model calls - see docs/ARCHITECTURE.md's P5 zero-spend decision.
This is a wiring smoke test (concurrency, cost/latency aggregation, the
structural adversary_objection_count rule, citation verification); the full
adversarial recorded-response fixture corpus is the dedicated next step.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from sift.context.builder import build_context_bundle
from sift.eval.cost import ModelId
from sift.ingest.fingerprint import FindingRef, IdentitySource
from sift.llm.provider import ChatMessage, ProviderConfig, ProviderResponse
from sift.models.context import ContextBundle
from sift.models.verdict import Verdict
from sift.orchestrator.pipeline import AgentCall, CompleteFn, PipelineConfig, run_pipeline

ROOT = Path(__file__).resolve().parents[1]
PROMPTS = ROOT / "src" / "sift" / "agents" / "prompts"
PROJECT = Path(__file__).resolve().parent / "fixtures" / "python_project"


def _bundle() -> ContextBundle:
    finding = FindingRef(
        correlation_id="pipeline-test",
        identity_source=IdentitySource.CONTENT,
        run_index=0,
        result_index=0,
        rule_id="sift-test/command-injection",
        uri="src/app.py",
        start_line=27,
    )
    return build_context_bundle(finding, PROJECT)


def _config() -> PipelineConfig:
    call = AgentCall(
        model=ModelId.HAIKU, provider_config=ProviderConfig(model="x/y", api_key="test-key")
    )
    return PipelineConfig(
        reachability=call,
        exploitability=call,
        adversary=call,
        adjudicator=call,
        prompt_hashes={"reachability.txt": "abc"},
        repo_root=PROJECT,
        shared_context_template=(PROMPTS / "shared_context.txt").read_text(encoding="utf-8"),
        reachability_template=(PROMPTS / "reachability.txt").read_text(encoding="utf-8"),
        exploitability_template=(PROMPTS / "exploitability.txt").read_text(encoding="utf-8"),
        adversary_template=(PROMPTS / "adversary.txt").read_text(encoding="utf-8"),
        adjudicator_template=(PROMPTS / "adjudicator.txt").read_text(encoding="utf-8"),
    )


def _response(payload: dict[str, object]) -> ProviderResponse:
    return ProviderResponse(
        content=json.dumps(payload),
        model="x/y",
        prompt_tokens=100,
        completion_tokens=50,
        cost_usd=0.001,
    )


def _dispatch_by_role(
    reachability: dict[str, object],
    exploitability: dict[str, object],
    adversary: dict[str, object],
    adjudicator: dict[str, object],
) -> CompleteFn:
    def fake_complete(
        config: ProviderConfig, messages: list[ChatMessage], *, model: ModelId | None = None
    ) -> ProviderResponse:
        instructions = messages[-1].content
        if instructions.startswith("You are the REACHABILITY"):
            return _response(reachability)
        if instructions.startswith("You are the EXPLOITABILITY"):
            return _response(exploitability)
        if instructions.startswith("You are the ADVERSARY"):
            return _response(adversary)
        if instructions.startswith("You are the ADJUDICATOR"):
            return _response(adjudicator)
        raise AssertionError(f"unrecognized instructions: {instructions[:60]!r}")

    return fake_complete


_REACHABILITY_TP = {
    "position": "TRUE_POSITIVE",
    "confidence": 0.9,
    "reasoning": "reaches the sink",
    "evidence_lines": [{"path": "src/app.py", "line": 1}],
    "unresolved_questions": [],
}
_EXPLOITABILITY_TP = {
    "position": "TRUE_POSITIVE",
    "confidence": 0.9,
    "reasoning": "no mitigation confirmed",
    "evidence_lines": [{"path": "src/app.py", "line": 1}],
    "unresolved_questions": [],
}
_ADVERSARY_WITH_OBJECTION = {
    "position": "TRUE_POSITIVE",
    "confidence": 0.8,
    "reasoning": "the sanitizer is unconfirmed",
    "evidence_lines": [{"path": "src/app.py", "line": 1}],
    "objections": [
        {"claim": "unconfirmed sanitizer", "evidence": [{"path": "src/app.py", "line": 1}]}
    ],
    "unresolved_questions": [],
}
_ADVERSARY_NO_OBJECTION = {**_ADVERSARY_WITH_OBJECTION, "objections": []}


def test_true_positive_round_trip() -> None:
    adjudicator_payload = {
        "verdict": "TRUE_POSITIVE",
        "confidence": 0.9,
        "justification": "input reaches the sink, no mitigation",
        "evidence_lines": [{"path": "src/app.py", "line": 1}],
        "unresolved_questions": [],
        "open_objections": [],
    }
    fake = _dispatch_by_role(
        _REACHABILITY_TP, _EXPLOITABILITY_TP, _ADVERSARY_WITH_OBJECTION, adjudicator_payload
    )
    result = asyncio.run(
        run_pipeline(correlation_id="c1", bundle=_bundle(), config=_config(), complete_fn=fake)
    )
    assert result.adjudication.verdict is Verdict.TRUE_POSITIVE
    assert result.adjudication.adversary_objection_count == 1
    assert len(result.arguments) == 3
    assert result.cost_usd == pytest.approx(0.004)
    assert result.latency_ms >= 0


def test_zero_adversary_objections_forces_needs_human_review() -> None:
    """The structural rule from docs/ARCHITECTURE.md, exercised through the
    real orchestrator path, not just the schema directly - even when the
    model itself claims FALSE_POSITIVE at high confidence."""
    adjudicator_payload = {
        "verdict": "FALSE_POSITIVE",
        "confidence": 0.99,
        "justification": "compile-time constant",
        "evidence_lines": [{"path": "src/app.py", "line": 1}],
        "unresolved_questions": [],
        "open_objections": [],
    }
    fake = _dispatch_by_role(
        _REACHABILITY_TP, _EXPLOITABILITY_TP, _ADVERSARY_NO_OBJECTION, adjudicator_payload
    )
    result = asyncio.run(
        run_pipeline(correlation_id="c1", bundle=_bundle(), config=_config(), complete_fn=fake)
    )
    assert result.adjudication.verdict is Verdict.NEEDS_HUMAN_REVIEW
    assert result.adjudication.downgraded_from is Verdict.FALSE_POSITIVE
    assert "zero objections" in (result.adjudication.downgrade_reason or "")


def test_hallucinated_citation_forces_needs_human_review() -> None:
    adjudicator_payload = {
        "verdict": "TRUE_POSITIVE",
        "confidence": 0.9,
        "justification": "cites a line that does not exist",
        "evidence_lines": [{"path": "src/app.py", "line": 999999}],
        "unresolved_questions": [],
        "open_objections": [],
    }
    fake = _dispatch_by_role(
        _REACHABILITY_TP, _EXPLOITABILITY_TP, _ADVERSARY_WITH_OBJECTION, adjudicator_payload
    )
    result = asyncio.run(
        run_pipeline(correlation_id="c1", bundle=_bundle(), config=_config(), complete_fn=fake)
    )
    assert result.adjudication.verdict is Verdict.NEEDS_HUMAN_REVIEW
    assert "hallucinated citation" in (result.adjudication.downgrade_reason or "")


def test_shared_context_message_is_cacheable_and_identical_across_calls() -> None:
    seen_shared: list[str] = []
    seen_cacheable: list[bool] = []

    def fake_complete(
        config: ProviderConfig, messages: list[ChatMessage], *, model: ModelId | None = None
    ) -> ProviderResponse:
        seen_shared.append(messages[0].content)
        seen_cacheable.append(messages[0].cacheable)
        instructions = messages[-1].content
        if instructions.startswith("You are the REACHABILITY"):
            return _response(_REACHABILITY_TP)
        if instructions.startswith("You are the EXPLOITABILITY"):
            return _response(_EXPLOITABILITY_TP)
        if instructions.startswith("You are the ADVERSARY"):
            return _response(_ADVERSARY_WITH_OBJECTION)
        return _response(
            {
                "verdict": "TRUE_POSITIVE",
                "confidence": 0.9,
                "justification": "x",
                "evidence_lines": [],
                "unresolved_questions": [],
                "open_objections": [],
            }
        )

    asyncio.run(
        run_pipeline(
            correlation_id="c1", bundle=_bundle(), config=_config(), complete_fn=fake_complete
        )
    )
    assert len(seen_shared) == 4
    assert len(set(seen_shared)) == 1, "shared context must be byte-identical across all 4 calls"
    assert all(seen_cacheable), "shared context must be marked cacheable on every call"
