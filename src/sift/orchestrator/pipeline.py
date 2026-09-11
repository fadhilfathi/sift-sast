"""P5 async orchestration.

The three analysts run concurrently against a shared, prompt-cached context
prefix; the Adjudicator runs after, seeing their raw parsed output with no
role attached at all (see sift.agents.adjudicator). Every citation an
accepted verdict rests on is verified against the real repo before the
verdict is returned. The D1 cache key is computed so a caller can decide
whether to skip the call entirely - this module never reads or writes a
cache itself, that is the caller's concern.

Zero live model calls happen in this project's test suite. `complete_fn` is
injected so every path here is exercised by recorded-response fixtures
instead - see docs/ARCHITECTURE.md's P5 zero-spend decision.
"""

from __future__ import annotations

import asyncio
import json
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

import sift
from sift.agents.adjudicator import render_adjudicator_prompt
from sift.agents.adversary import render_adversary_prompt
from sift.agents.exploitability import render_exploitability_prompt
from sift.agents.reachability import render_reachability_prompt
from sift.agents.shared_context import render_shared_context_prompt
from sift.eval.cost import ModelId
from sift.llm.provider import ChatMessage, ProviderConfig, ProviderResponse
from sift.models.context import ContextBundle
from sift.models.verdict import (
    Adjudication,
    AdversaryOutput,
    AgentArgument,
    AgentRole,
    AnalystOutput,
    FileLineRef,
    Objection,
    TriageResult,
    Verdict,
)
from sift.orchestrator.cache_key import compute_cache_key
from sift.orchestrator.evidence import all_citations_exist

AgentOutput = AnalystOutput | AdversaryOutput


class CompleteFn(Protocol):
    """The shape of one completion call - matches `sift.llm.provider.complete`
    so production code and recorded-response test fixtures are interchangeable
    at this one seam."""

    def __call__(
        self, config: ProviderConfig, messages: list[ChatMessage], *, model: ModelId | None = None
    ) -> ProviderResponse: ...


class AgentOutputParseError(RuntimeError):
    """A model's response could not be parsed into its validated schema."""

    def __init__(self, role: str, raw_content: str, cause: Exception) -> None:
        self.role = role
        self.raw_content = raw_content
        super().__init__(f"{role}: could not parse response as its output schema: {cause}")


@dataclass(frozen=True)
class AgentCall:
    """Which model an agent runs on, and the config to call it with."""

    model: ModelId
    provider_config: ProviderConfig


@dataclass(frozen=True)
class PipelineConfig:
    """Everything the orchestrator needs to adjudicate one finding."""

    reachability: AgentCall
    exploitability: AgentCall
    adversary: AgentCall
    adjudicator: AgentCall
    prompt_hashes: dict[str, str]
    repo_root: Path
    shared_context_template: str
    reachability_template: str
    exploitability_template: str
    adversary_template: str
    adjudicator_template: str

    def __post_init__(self) -> None:
        temps = {
            self.reachability.provider_config.temperature,
            self.exploitability.provider_config.temperature,
            self.adversary.provider_config.temperature,
            self.adjudicator.provider_config.temperature,
        }
        if len(temps) != 1:
            raise ValueError(
                f"all four agents must share one temperature for a well-defined D1 "
                f"cache key, got {sorted(temps)}"
            )

    @property
    def temperature(self) -> float:
        return self.reachability.provider_config.temperature

    @property
    def model_ids(self) -> tuple[str, ...]:
        return (
            self.reachability.model.value,
            self.exploitability.model.value,
            self.adversary.model.value,
            self.adjudicator.model.value,
        )


def cache_key_for(correlation_id: str, bundle: ContextBundle, config: PipelineConfig) -> str:
    """The D1 cache key for this finding under this exact configuration."""
    return compute_cache_key(
        correlation_id=correlation_id,
        bundle=bundle,
        model_ids=config.model_ids,
        temperature=config.temperature,
        prompt_hashes=config.prompt_hashes,
        sift_version=sift.__version__,
    )


def _parse_json(content: str) -> dict[str, object]:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"response is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"response JSON is a {type(payload).__name__}, expected an object")
    return payload


def _call_analyst(
    complete_fn: CompleteFn,
    call: AgentCall,
    role: str,
    shared_message: ChatMessage,
    instructions: str,
) -> tuple[AnalystOutput, ProviderResponse]:
    response = complete_fn(
        call.provider_config,
        [shared_message, ChatMessage(role="user", content=instructions)],
        model=call.model,
    )
    try:
        output = AnalystOutput.model_validate(_parse_json(response.content))
    except (ValueError, ValidationError) as exc:
        raise AgentOutputParseError(role, response.content, exc) from exc
    return output, response


def _call_adversary(
    complete_fn: CompleteFn,
    call: AgentCall,
    shared_message: ChatMessage,
    instructions: str,
) -> tuple[AdversaryOutput, ProviderResponse]:
    response = complete_fn(
        call.provider_config,
        [shared_message, ChatMessage(role="user", content=instructions)],
        model=call.model,
    )
    try:
        output = AdversaryOutput.model_validate(_parse_json(response.content))
    except (ValueError, ValidationError) as exc:
        raise AgentOutputParseError("ADVERSARY", response.content, exc) from exc
    return output, response


def _to_agent_argument(role: AgentRole, output: AgentOutput) -> AgentArgument:
    """The stored audit-trail record. Not what the Adjudicator sees - that is
    the raw `output`, rendered by sift.agents.adjudicator with no role field
    at all. This is for TriageResult, read by humans and SARIF properties."""
    if isinstance(output, AdversaryOutput):
        position = Verdict(output.position.value)
        objections = [
            Objection(claim=o.claim, evidence=o.evidence, rebutted=False, rebuttal=None)
            for o in output.objections
        ]
    else:
        position = output.position
        objections = []
    return AgentArgument(
        role=role,
        position=position,
        confidence=output.confidence,
        reasoning=output.reasoning,
        evidence_lines=output.evidence_lines,
        objections=objections,
        unresolved_questions=output.unresolved_questions,
    )


def _all_evidence_refs(adjudication: Adjudication) -> list[FileLineRef]:
    refs = list(adjudication.evidence_lines)
    for objection in adjudication.open_objections:
        refs.extend(objection.evidence)
    return refs


async def run_pipeline(
    *,
    correlation_id: str,
    bundle: ContextBundle,
    config: PipelineConfig,
    complete_fn: CompleteFn,
    shuffle_seed: str | None = None,
) -> TriageResult:
    """Adjudicate one finding end to end.

    The three analysts run concurrently (`asyncio.gather` over
    `asyncio.to_thread`, since `complete_fn` is a synchronous call - see
    `sift.llm.provider.complete`). The Adjudicator then sees their raw output
    in an order seeded from `shuffle_seed` (defaults to `correlation_id`), so
    the labeling is reproducible per finding but not fixed across findings -
    a model should not be able to learn "argument C is always the Adversary"
    from a constant slot.
    """
    start = time.monotonic()

    shared_text = render_shared_context_prompt(config.shared_context_template, bundle)
    shared_message = ChatMessage(role="user", content=shared_text, cacheable=True)

    reachability_instructions = render_reachability_prompt(config.reachability_template, bundle)
    exploitability_instructions = render_exploitability_prompt(
        config.exploitability_template, bundle
    )
    adversary_instructions = render_adversary_prompt(config.adversary_template, bundle)

    (
        (reachability_output, reachability_response),
        (
            exploitability_output,
            exploitability_response,
        ),
        (adversary_output, adversary_response),
    ) = await asyncio.gather(
        asyncio.to_thread(
            _call_analyst,
            complete_fn,
            config.reachability,
            "REACHABILITY",
            shared_message,
            reachability_instructions,
        ),
        asyncio.to_thread(
            _call_analyst,
            complete_fn,
            config.exploitability,
            "EXPLOITABILITY",
            shared_message,
            exploitability_instructions,
        ),
        asyncio.to_thread(
            _call_adversary,
            complete_fn,
            config.adversary,
            shared_message,
            adversary_instructions,
        ),
    )

    labeled: list[tuple[AgentRole, AgentOutput]] = [
        (AgentRole.REACHABILITY, reachability_output),
        (AgentRole.EXPLOITABILITY, exploitability_output),
        (AgentRole.ADVERSARY, adversary_output),
    ]
    # Not a security control - identity-stripping is structural (the model
    # never receives a role field at all, see sift.agents.adjudicator). This
    # only stops a fixed A/B/C slot from becoming a learnable pattern.
    rng = random.Random(shuffle_seed or correlation_id)  # noqa: S311
    shuffled = labeled.copy()
    rng.shuffle(shuffled)
    ordered_outputs = [output for _role, output in shuffled]

    adjudicator_instructions = render_adjudicator_prompt(
        config.adjudicator_template, bundle, ordered_outputs
    )
    adjudicator_response = complete_fn(
        config.adjudicator.provider_config,
        [shared_message, ChatMessage(role="user", content=adjudicator_instructions)],
        model=config.adjudicator.model,
    )
    try:
        adjudicator_payload = _parse_json(adjudicator_response.content)
    except ValueError as exc:
        raise AgentOutputParseError("ADJUDICATOR", adjudicator_response.content, exc) from exc

    adjudicator_payload["correlation_id"] = correlation_id
    # Never trust the model's own claim about this - see docs/ARCHITECTURE.md,
    # "The Adversary's position is not its signal". Computed from what the
    # Adversary actually filed, not anything the Adjudicator reports.
    adjudicator_payload["adversary_objection_count"] = len(adversary_output.objections)
    # Same rule: copied from the bundle the tool actually built, never taken
    # on the Adjudicator's own word - see docs/ARCHITECTURE.md decision D6.
    adjudicator_payload["context_completeness"] = bundle.completeness.value
    try:
        adjudication = Adjudication.model_validate(adjudicator_payload)
    except ValidationError as exc:
        raise AgentOutputParseError("ADJUDICATOR", adjudicator_response.content, exc) from exc

    if not all_citations_exist(config.repo_root, _all_evidence_refs(adjudication)):
        if adjudication.downgraded_from is None:
            adjudication.downgraded_from = adjudication.verdict
        reason = "hallucinated citation: a cited evidence line does not exist in the repo"
        adjudication.downgrade_reason = (
            f"{adjudication.downgrade_reason}; {reason}"
            if adjudication.downgrade_reason
            else reason
        )
        adjudication.verdict = Verdict.NEEDS_HUMAN_REVIEW

    arguments = [_to_agent_argument(role, output) for role, output in labeled]
    responses = [
        reachability_response,
        exploitability_response,
        adversary_response,
        adjudicator_response,
    ]
    cost_usd = sum(r.cost_usd for r in responses)
    latency_ms = int((time.monotonic() - start) * 1000)

    return TriageResult(
        adjudication=adjudication,
        arguments=arguments,
        resolved_by="agents",
        cost_usd=cost_usd,
        latency_ms=latency_ms,
    )
