"""Shared setup for P5 orchestrator-level tests (steps 4-6).

Not a test file itself - pytest only collects `test_*.py`. Kept separate
from `test_orchestrator_pipeline.py`'s own local helpers (step 3, already
reviewed and committed) rather than refactoring that file's proven state for
this later work's convenience.
"""

from __future__ import annotations

import json
from pathlib import Path

from sift.context.builder import build_context_bundle
from sift.eval.cost import ModelId
from sift.ingest.fingerprint import FindingRef, IdentitySource
from sift.llm.provider import ProviderConfig, ProviderResponse
from sift.models.context import ContextBundle
from sift.orchestrator.pipeline import AgentCall, PipelineConfig

ROOT = Path(__file__).resolve().parents[1]
PROMPTS = ROOT / "src" / "sift" / "agents" / "prompts"
PROJECT = Path(__file__).resolve().parent / "fixtures" / "python_project"
RESPONSES = Path(__file__).resolve().parent / "fixtures" / "agent_responses"


def bundle(start_line: int = 27) -> ContextBundle:
    finding = FindingRef(
        correlation_id="fixture-test",
        identity_source=IdentitySource.CONTENT,
        run_index=0,
        result_index=0,
        rule_id="sift-test/command-injection",
        uri="src/app.py",
        start_line=start_line,
    )
    return build_context_bundle(finding, PROJECT)


def pipeline_config() -> PipelineConfig:
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


def realistic_pipeline_config() -> PipelineConfig:
    """Real per-role model tiers - Haiku for the three analysts, Opus for the
    Adjudicator (CONTRIBUTING.md: never downgraded to save cost) - unlike
    `pipeline_config()` above, which deliberately uses one model everywhere
    for wiring tests that do not care about tier correctness."""
    haiku = AgentCall(
        model=ModelId.HAIKU, provider_config=ProviderConfig(model="x/haiku", api_key="test-key")
    )
    opus = AgentCall(
        model=ModelId.OPUS, provider_config=ProviderConfig(model="x/opus", api_key="test-key")
    )
    return PipelineConfig(
        reachability=haiku,
        exploitability=haiku,
        adversary=haiku,
        adjudicator=opus,
        prompt_hashes={"reachability.txt": "abc"},
        repo_root=PROJECT,
        shared_context_template=(PROMPTS / "shared_context.txt").read_text(encoding="utf-8"),
        reachability_template=(PROMPTS / "reachability.txt").read_text(encoding="utf-8"),
        exploitability_template=(PROMPTS / "exploitability.txt").read_text(encoding="utf-8"),
        adversary_template=(PROMPTS / "adversary.txt").read_text(encoding="utf-8"),
        adjudicator_template=(PROMPTS / "adjudicator.txt").read_text(encoding="utf-8"),
    )


def provider_response(content: str) -> ProviderResponse:
    return ProviderResponse(
        content=content, model="x/y", prompt_tokens=100, completion_tokens=50, cost_usd=0.001
    )


def load_fixture(*parts: str) -> str:
    """Read a recorded-response fixture's raw text, trailing newline stripped."""
    return (RESPONSES.joinpath(*parts)).read_text(encoding="utf-8").rstrip("\n")


def valid_response_payload(role: str) -> dict[str, object]:
    text = load_fixture("valid", f"{role}.txt")
    payload: dict[str, object] = json.loads(text)
    return payload
