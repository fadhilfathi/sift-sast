"""The four P5 role prompts and the shared context block render cleanly
against a real bundle. Same regression class as test_prompt_render.py's
baseline check: `str.format` consumes one level of `{{ }}` escaping, so a
missed placeholder or an unescaped literal brace reaches the model as either
a KeyError or invalid-looking JSON in the example.
"""

from __future__ import annotations

from pathlib import Path

from sift.agents.adjudicator import render_adjudicator_prompt
from sift.agents.adversary import render_adversary_prompt
from sift.agents.exploitability import render_exploitability_prompt
from sift.agents.reachability import render_reachability_prompt
from sift.agents.shared_context import render_shared_context_prompt
from sift.context.builder import build_context_bundle
from sift.ingest.fingerprint import FindingRef, IdentitySource
from sift.models.context import ContextBundle
from sift.models.verdict import AdversaryOutput, AnalystOutput, Verdict

ROOT = Path(__file__).resolve().parents[1]
PROMPTS = ROOT / "src" / "sift" / "agents" / "prompts"
PROJECT = Path(__file__).resolve().parent / "fixtures" / "python_project"


def _bundle() -> ContextBundle:
    finding = FindingRef(
        correlation_id="render-test",
        identity_source=IdentitySource.CONTENT,
        run_index=0,
        result_index=0,
        rule_id="sift-test/command-injection",
        uri="src/app.py",
        start_line=27,
    )
    return build_context_bundle(finding, PROJECT)


def _assert_clean(rendered: str) -> None:
    assert "{{" not in rendered
    assert "}}" not in rendered
    assert "{rule_id}" not in rendered
    assert "{context_block}" not in rendered


def test_shared_context_renders_cleanly() -> None:
    template = (PROMPTS / "shared_context.txt").read_text(encoding="utf-8")
    _assert_clean(render_shared_context_prompt(template, _bundle()))


def test_reachability_renders_cleanly() -> None:
    template = (PROMPTS / "reachability.txt").read_text(encoding="utf-8")
    _assert_clean(render_reachability_prompt(template, _bundle()))


def test_exploitability_renders_cleanly() -> None:
    template = (PROMPTS / "exploitability.txt").read_text(encoding="utf-8")
    _assert_clean(render_exploitability_prompt(template, _bundle()))


def test_adversary_renders_cleanly() -> None:
    template = (PROMPTS / "adversary.txt").read_text(encoding="utf-8")
    rendered = render_adversary_prompt(template, _bundle())
    _assert_clean(rendered)
    assert '"position": "FALSE_POSITIVE"' not in rendered.split("OUTPUT")[0]


def test_adjudicator_renders_cleanly_with_three_arguments() -> None:
    template = (PROMPTS / "adjudicator.txt").read_text(encoding="utf-8")
    arguments: list[AnalystOutput | AdversaryOutput] = [
        AnalystOutput(position=Verdict.TRUE_POSITIVE, confidence=0.6, reasoning="a"),
        AnalystOutput(position=Verdict.NEEDS_HUMAN_REVIEW, confidence=0.5, reasoning="b"),
        AnalystOutput(position=Verdict.TRUE_POSITIVE, confidence=0.7, reasoning="c"),
    ]
    rendered = render_adjudicator_prompt(template, _bundle(), arguments)
    _assert_clean(rendered)
    assert "{argument_a}" not in rendered
    assert "reasoning: a" in rendered
