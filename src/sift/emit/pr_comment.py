"""Stage 4 — the Markdown PR comment.

Grouped by verdict: TRUE_POSITIVE first, NEEDS_HUMAN_REVIEW second,
FALSE_POSITIVE last and collapsed. A dismissal with no visible reasoning is
the thing this project exists to prevent, so every FALSE_POSITIVE shows its
justification and confirms all five structural blockers (docs/ARCHITECTURE.md
"The safety rule") cleared. Language is "adjudicated", "escalated", or
"dismissed with justification" - never "resolved" or "safe", which imply a
guarantee this tool does not make.

ASCII only - the CLI already hit a Windows cp1252 crash on non-ASCII output
twice; this text goes through the same kind of pipe (a GitHub Actions log,
then a PR comment API call).
"""

from __future__ import annotations

from sift.ingest.fingerprint import FindingRef
from sift.models.verdict import TriageResult, Verdict

#: Rendered inside an HTML comment so the Action can find and update its own
#: comment instead of stacking a new one on every run.
COMMENT_MARKER = "<!-- sift-sast:report -->"

_VERDICT_HEADING = {
    Verdict.TRUE_POSITIVE: "## Adjudicated TRUE_POSITIVE",
    Verdict.NEEDS_HUMAN_REVIEW: "## Escalated to a human",
    Verdict.FALSE_POSITIVE: "## Dismissed with justification",
}


def _finding_line(ref: FindingRef, triage: TriageResult) -> str:
    adjudication = triage.adjudication
    location = f"{ref.uri or '(unknown file)'}:{ref.start_line or '?'}"
    return (
        f"- `{ref.rule_id or 'unknown-rule'}` at `{location}` "
        f"(confidence {adjudication.confidence:.2f}) - {adjudication.justification}"
    )


def _false_positive_block(ref: FindingRef, triage: TriageResult) -> str:
    adjudication = triage.adjudication
    completeness = (
        adjudication.context_completeness.value
        if adjudication.context_completeness is not None
        else "MISSING"
    )
    cleared = (
        f"confidence {adjudication.confidence:.2f} >= 0.85; "
        f"completeness {completeness} (not INSUFFICIENT); "
        f"{adjudication.adversary_objection_count} adversary objection(s) filed, "
        f"{len(adjudication.open_objections)} carried into review, all rebutted"
    )
    return (
        f"<details>\n<summary><code>{ref.rule_id or 'unknown-rule'}</code> at "
        f"<code>{ref.uri or '(unknown file)'}:{ref.start_line or '?'}</code></summary>\n\n"
        f"{adjudication.justification}\n\n"
        f"Cleared: {cleared}\n"
        f"</details>\n"
    )


def render_pr_comment(
    findings: list[tuple[FindingRef, TriageResult]],
    *,
    total_cost_usd: float,
    dry_run: bool,
) -> str:
    """One Markdown document, grouped by verdict, ready to post or update."""
    lines = [COMMENT_MARKER, "# SIFT triage report", ""]

    if dry_run:
        lines.append("**Dry run** - no model was called, nothing below was adjudicated.")
        lines.append("")

    lines.append(
        "This tool's accuracy has not been measured against a labeled dataset "
        "outside offline fixtures. See the README's Evaluation section."
    )
    lines.append("")

    by_verdict: dict[Verdict, list[tuple[FindingRef, TriageResult]]] = {
        Verdict.TRUE_POSITIVE: [],
        Verdict.NEEDS_HUMAN_REVIEW: [],
        Verdict.FALSE_POSITIVE: [],
    }
    for ref, triage in findings:
        by_verdict[triage.adjudication.verdict].append((ref, triage))

    for verdict in (Verdict.TRUE_POSITIVE, Verdict.NEEDS_HUMAN_REVIEW):
        group = by_verdict[verdict]
        lines.append(_VERDICT_HEADING[verdict] + f" ({len(group)})")
        lines.append("")
        if not group:
            lines.append("_None._")
        else:
            for ref, triage in group:
                lines.append(_finding_line(ref, triage))
        lines.append("")

    fp_group = by_verdict[Verdict.FALSE_POSITIVE]
    lines.append(_VERDICT_HEADING[Verdict.FALSE_POSITIVE] + f" ({len(fp_group)})")
    lines.append("")
    if not fp_group:
        lines.append("_None._")
    else:
        for ref, triage in fp_group:
            lines.append(_false_positive_block(ref, triage))
    lines.append("")

    lines.append(f"Total cost: ${total_cost_usd:.4f}")
    return "\n".join(lines) + "\n"
