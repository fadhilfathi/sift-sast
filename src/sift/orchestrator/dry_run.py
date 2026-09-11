"""P5 --dry-run: estimated cost and call count for the four-agent pipeline,
before anything spends. Zero network, zero API key required - the context
bundle is already built deterministically (tree-sitter, no LLM), so the only
thing this module adds is arithmetic over the real rendered prompt text.
"""

from __future__ import annotations

from sift.agents.adversary import render_adversary_prompt
from sift.agents.exploitability import render_exploitability_prompt
from sift.agents.reachability import render_reachability_prompt
from sift.agents.shared_context import render_shared_context_prompt
from sift.eval.cost import CallEstimate, RunEstimate, estimate_tokens
from sift.models.context import ContextBundle
from sift.orchestrator.pipeline import PipelineConfig

#: Provisional, like P4's per-finding estimate - the real count comes from a
#: live call's `usage` block once SIFT_API_KEY is set. Kept separate from
#: P4's baseline constants (sift.eval.harness) since a single-role reply is
#: shorter than nothing at all is a bad default; each role here has a
#: different expected reply shape (see the four prompts' OUTPUT sections).
ESTIMATED_ANALYST_OUTPUT_TOKENS = 400
ESTIMATED_ADVERSARY_OUTPUT_TOKENS = 600  # objections make its replies longer
ESTIMATED_ADJUDICATOR_OUTPUT_TOKENS = 500


def pipeline_dry_run_estimate(bundles: list[ContextBundle], config: PipelineConfig) -> RunEstimate:
    """Four calls per bundle: Reachability, Exploitability, Adversary, then
    the Adjudicator - matching `orchestrator.pipeline.run_pipeline`'s real
    call shape exactly, not an approximation of it.

    The shared context block is rendered once per bundle and its token count
    charged as a cache write on the first of the four calls and a cache read
    on the other three - mirroring `ChatMessage.cacheable` in
    `sift.llm.provider`, so the estimate reflects what caching actually
    saves rather than pretending every call pays full price.
    """
    calls: list[CallEstimate] = []
    for bundle in bundles:
        shared_text = render_shared_context_prompt(config.shared_context_template, bundle)
        shared_tokens = estimate_tokens(shared_text)

        reachability_text = render_reachability_prompt(config.reachability_template, bundle)
        exploitability_text = render_exploitability_prompt(config.exploitability_template, bundle)
        adversary_text = render_adversary_prompt(config.adversary_template, bundle)
        # The Adjudicator's own instructions vary with the other three
        # agents' real output, which does not exist at dry-run time - the
        # rendered length of its own prompt template stands in, the same
        # kind of stand-in P4's dry-run already uses for the whole prompt.
        adjudicator_text = config.adjudicator_template

        calls.append(
            CallEstimate(
                model=config.reachability.model,
                input_tokens=shared_tokens + estimate_tokens(reachability_text),
                output_tokens=ESTIMATED_ANALYST_OUTPUT_TOKENS,
                cache_write_tokens=shared_tokens,
            )
        )
        calls.append(
            CallEstimate(
                model=config.exploitability.model,
                input_tokens=shared_tokens + estimate_tokens(exploitability_text),
                output_tokens=ESTIMATED_ANALYST_OUTPUT_TOKENS,
                cached_input_tokens=shared_tokens,
            )
        )
        calls.append(
            CallEstimate(
                model=config.adversary.model,
                input_tokens=shared_tokens + estimate_tokens(adversary_text),
                output_tokens=ESTIMATED_ADVERSARY_OUTPUT_TOKENS,
                cached_input_tokens=shared_tokens,
            )
        )
        calls.append(
            CallEstimate(
                model=config.adjudicator.model,
                input_tokens=shared_tokens + estimate_tokens(adjudicator_text),
                output_tokens=ESTIMATED_ADJUDICATOR_OUTPUT_TOKENS,
                cached_input_tokens=shared_tokens,
            )
        )
    return RunEstimate(calls=calls)
