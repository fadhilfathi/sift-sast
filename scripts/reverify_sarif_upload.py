"""Regenerate fadhilfathi/sarif-upload-check's emitted SARIF using the real
four-agent pipeline, at zero spend, so its `Verify SARIF upload` workflow
re-checks the current emitter against real GitHub Code Scanning behavior.

Not part of the `sift` package - a maintainer-run script, invoked against a
local checkout of the companion repo. See docs/OPERATIONS.md, "Verifying the
SARIF emitter against Code Scanning."

Usage:
    python scripts/reverify_sarif_upload.py /path/to/sarif-upload-check

Then, in that checkout: commit sarif/emitted.sarif, push, and
`gh run watch` the `Verify SARIF upload` workflow it triggers.

Uses a deterministic fake `complete_fn`, keyed on each finding's rule_id, so
this never spends money and never touches the network - see
tests/conftest.py's autouse network block, which this script deliberately
mirrors by never importing anything that could bypass it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sift import ingest, prefilter
from sift.context.builder import build_context_bundle
from sift.emit import sarif as emit_sarif
from sift.emit.annotate import annotate_adjudicated, annotate_prefiltered
from sift.eval.cost import ModelId
from sift.llm.provider import ChatMessage, ProviderConfig, ProviderResponse
from sift.orchestrator.pipeline import AgentCall, PipelineConfig, run_pipeline

PROMPTS = Path(__file__).resolve().parents[1] / "src" / "sift" / "agents" / "prompts"

#: Which of sarif-upload-check's five rules should come back TRUE_POSITIVE.
#: The other two (suppressed-subprocess, suppressed-insource) come back
#: FALSE_POSITIVE, so the regenerated SARIF carries a real Suppression from
#: SIFT's own emitter - the thing being re-verified, not a hand-crafted one.
TRUE_POSITIVE_RULES = {
    "sift.verify.command-injection",
    "sift.verify.sql-injection",
    "sift.verify.path-traversal",
}


def _fake_complete(
    config: ProviderConfig, messages: list[ChatMessage], *, model: ModelId | None = None
) -> ProviderResponse:
    shared = messages[0].content
    rule_line = next((line for line in shared.splitlines() if line.startswith("rule_id:")), "")
    rule_id = rule_line.split(":", 1)[1].strip()
    is_tp = rule_id in TRUE_POSITIVE_RULES
    instructions = messages[-1].content

    if instructions.startswith(("You are the REACHABILITY", "You are the EXPLOITABILITY")):
        payload: dict[str, object] = {
            "position": "TRUE_POSITIVE" if is_tp else "FALSE_POSITIVE",
            "confidence": 0.9,
            "reasoning": f"deterministic re-verification stub for {rule_id}",
            "evidence_lines": [],
            "unresolved_questions": [],
        }
    elif instructions.startswith("You are the ADVERSARY"):
        payload = {
            "position": "TRUE_POSITIVE",
            "confidence": 0.6 if is_tp else 0.3,
            "reasoning": "stub prosecution",
            "evidence_lines": [],
            "objections": (
                []
                if is_tp
                else [{"claim": "constant argument list, no taint reaches it", "evidence": []}]
            ),
            "unresolved_questions": [],
        }
    else:
        payload = {
            "verdict": "TRUE_POSITIVE" if is_tp else "FALSE_POSITIVE",
            "confidence": 0.95 if is_tp else 0.9,
            "justification": (
                f"untrusted input reaches the sink for {rule_id}"
                if is_tp
                else "constant argument list confirmed by reading the call site directly"
            ),
            "evidence_lines": [],
            "unresolved_questions": [],
            "open_objections": (
                []
                if is_tp
                else [
                    {
                        "claim": "constant argument list, no taint reaches it",
                        "evidence": [],
                        "rebutted": True,
                        "rebuttal": "the call site passes a literal list, read directly",
                    }
                ]
            ),
        }
    return ProviderResponse(
        content=json.dumps(payload),
        model="x/y",
        prompt_tokens=500,
        completion_tokens=200,
        cost_usd=0.0,
    )


def _build_config(repo_root: Path) -> PipelineConfig:
    analyst = AgentCall(
        model=ModelId.HAIKU, provider_config=ProviderConfig(model="x/y", api_key="k")
    )
    adjudicator = AgentCall(
        model=ModelId.OPUS, provider_config=ProviderConfig(model="x/y", api_key="k")
    )
    return PipelineConfig(
        reachability=analyst,
        exploitability=analyst,
        adversary=analyst,
        adjudicator=adjudicator,
        prompt_hashes={},
        repo_root=repo_root,
        shared_context_template=(PROMPTS / "shared_context.txt").read_text(encoding="utf-8"),
        reachability_template=(PROMPTS / "reachability.txt").read_text(encoding="utf-8"),
        exploitability_template=(PROMPTS / "exploitability.txt").read_text(encoding="utf-8"),
        adversary_template=(PROMPTS / "adversary.txt").read_text(encoding="utf-8"),
        adjudicator_template=(PROMPTS / "adjudicator.txt").read_text(encoding="utf-8"),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", type=Path, help="Local checkout of sarif-upload-check.")
    args = parser.parse_args()
    repo: Path = args.repo
    input_sarif = repo / "sarif" / "input.sarif"
    output_sarif = repo / "sarif" / "emitted.sarif"

    log, source = ingest.load(input_sarif)
    findings = ingest.results_of(log)
    report = prefilter.run(findings, repo_root=repo)
    print(f"findings: {len(findings)}  adjudicate: {report.adjudicate_count}")

    config = _build_config(repo)
    for decision in report.decisions:
        ref = decision.ref
        run = log.runs[ref.run_index]
        result = run.results[ref.result_index]
        if decision.disposition.value != "ADJUDICATE":
            run.results[ref.result_index] = annotate_prefiltered(result, ref, decision)
            continue
        bundle = build_context_bundle(ref, repo)
        triage_result = asyncio.run(
            run_pipeline(
                correlation_id=ref.correlation_id,
                bundle=bundle,
                config=config,
                complete_fn=_fake_complete,
            )
        )
        print(f"  {ref.rule_id}: {triage_result.adjudication.verdict.value}")
        run.results[ref.result_index] = annotate_adjudicated(result, ref, decision, triage_result)

    written = emit_sarif.write(log, output_sarif, source=source)
    print(f"wrote {written} bytes to {output_sarif}")


if __name__ == "__main__":
    main()
