"""The baseline prompt renders cleanly against a real bundle.

Regression test for the doubled-brace bug: `str.format` consumes one level
of `{{ }}` escaping, so an example written `{{{{ }}}}` reaches the model
with literal double braces and any literal-following model echoes invalid
JSON back. Nothing tested rendering before; now something does.
"""

from __future__ import annotations

from pathlib import Path

from sift.agents.baseline import render_baseline_prompt
from sift.context.builder import build_context_bundle
from sift.ingest.fingerprint import FindingRef, IdentitySource

ROOT = Path(__file__).resolve().parents[1]
PROMPT = ROOT / "src" / "sift" / "agents" / "prompts" / "baseline.txt"
PROJECT = Path(__file__).resolve().parent / "fixtures" / "python_project"


def _bundle() -> object:
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


def test_rendered_prompt_contains_no_format_leftovers() -> None:
    """No `{{` survives (would show the model literal double braces), and no
    `{placeholder}` goes unfilled."""
    from sift.models.context import ContextBundle

    bundle = _bundle()
    assert isinstance(bundle, ContextBundle)
    rendered = render_baseline_prompt(PROMPT.read_text(encoding="utf-8"), bundle)
    assert "{{" not in rendered
    assert "}}" not in rendered
    for placeholder in (
        "{rule_id}",
        "{message}",
        "{file_class}",
        "{completeness}",
        "{context_block}",
        "{data_flow}",
        "{sanitizers}",
        "{imports}",
    ):
        assert placeholder not in rendered


def test_rendered_prompt_shows_the_model_single_brace_json() -> None:
    """The OUTPUT example the model sees must be single-brace JSON shape, and
    the retrieved code must arrive inside the untrusted delimiters."""
    from sift.models.context import ContextBundle

    bundle = _bundle()
    assert isinstance(bundle, ContextBundle)
    rendered = render_baseline_prompt(PROMPT.read_text(encoding="utf-8"), bundle)
    assert '"verdict": "TRUE_POSITIVE" | "FALSE_POSITIVE" | "NEEDS_HUMAN_REVIEW"' in rendered
    assert '{"path": "repo/relative/path.py", "line": 123}' in rendered
    assert "<<<UNTRUSTED SOURCE" in rendered
    assert "subprocess.check_output" in rendered
