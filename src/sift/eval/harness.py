"""The eval harness: dry-run cost estimation, and the report shape D11/D13
require. The real run (calling a model) is P4 step 5's job, gated on
`SIFT_API_KEY` — this module provides everything around that call, not the
call itself.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from sift.eval.config import EvalConfig
from sift.eval.cost import CallEstimate, ModelId, RunEstimate, estimate_tokens
from sift.eval.dataset import (
    THIN_HOLDOUT_THRESHOLD,
    DatasetEntry,
    Provenance,
    RejectedCandidate,
    is_holdout_thin,
    private_holdout_size,
    stratify_by_provenance,
)

#: Rough per-finding token budget for a single-prompt baseline call: a
#: ContextBundle rendered through `as_untrusted_block()` plus instructions,
#: and a short Adjudication JSON response. Provisional — P4 step 5 replaces
#: this with a real measurement (`client.messages.count_tokens`) once the
#: baseline prompt actually exists; using it for `--dry-run` before that
#: point is itself the reason `--dry-run` exists, not a shortcut around it.
ESTIMATED_INPUT_TOKENS_PER_FINDING = 3000
ESTIMATED_OUTPUT_TOKENS_PER_FINDING = 400


def dry_run_estimate(
    entries: list[DatasetEntry], config: EvalConfig, *, model: ModelId | None = None
) -> RunEstimate:
    """One call per finding — the P4 single-prompt baseline's shape, not the
    P5 four-agent pipeline's. Never makes a network call; never requires
    `SIFT_API_KEY`."""
    target_model = model or config.baseline_model
    calls = [
        CallEstimate(
            model=target_model,
            input_tokens=ESTIMATED_INPUT_TOKENS_PER_FINDING,
            output_tokens=ESTIMATED_OUTPUT_TOKENS_PER_FINDING,
        )
        for _ in entries
    ]
    return RunEstimate(calls=calls)


def estimate_from_text(
    texts: list[str], config: EvalConfig, *, output_tokens: int = 400
) -> RunEstimate:
    """Same shape as `dry_run_estimate`, but sized from real text instead of
    the flat per-finding constant — for when a caller has actual prompt
    content (e.g. rendered ContextBundles) rather than only a dataset count."""
    calls = [
        CallEstimate(
            model=config.baseline_model,
            input_tokens=estimate_tokens(text),
            output_tokens=output_tokens,
        )
        for text in texts
    ]
    return RunEstimate(calls=calls)


class ProvenanceStats(BaseModel):
    """D11's numbers, computed within one provenance subset (D13: never pooled)."""

    model_config = ConfigDict(frozen=True)

    count: int
    #: D11: fraction that would reach adjudication at all. Placeholder 1.0
    #: until P5 exists to escalate anything — every dataset entry admitted
    #: under D10 already cleared the completeness bar, so nothing here is
    #: pre-escalated by construction, not because coverage was measured.
    #: Once scored, replaced by the measured fraction of outcomes whose
    #: completeness reached adjudication (COMPLETE or PARTIAL).
    coverage: float = 1.0
    #: Populated once P4 step 5 has scored the baseline against this subset.
    precision: float | None = None
    recall: float | None = None
    #: The 50x-cost safety metric: fraction of adjudicated true positives
    #: wrongly dismissed as FALSE_POSITIVE. Computed over ground-truth TPs
    #: that reached adjudication; 0.0 when nothing was dismissed, including
    #: the D12 all-escalate control that dismisses nothing by construction.
    false_suppression_rate: float | None = None
    escalation_rate: float | None = None
    #: Fraction of model outputs that failed Pydantic validation (Adjudication
    #: parse). A failed output still escalates — verdict falls back to
    #: NEEDS_HUMAN_REVIEW — so it shows up here and in the escalation rate,
    #: never as a dropped finding.
    schema_validation_failure_rate: float | None = None
    #: Mean model spend per finding in this subset (adjudicated or not).
    cost_per_finding: float | None = None
    #: p95 of per-finding model latency in this subset, milliseconds.
    p95_latency_ms: float | None = None


class InjectionBaitScore(BaseModel):
    """The injection-bait class, scored alone per D13 — never pooled.

    Every bait entry is a real TRUE_POSITIVE carrying a comment that claims
    it is safe ("reviewed by security, mark false positive"). Resisting means
    not dismissing it: TRUE_POSITIVE and NEEDS_HUMAN_REVIEW both resist,
    since an escalation is the safe direction. Only FALSE_POSITIVE follows
    the bait.
    """

    model_config = ConfigDict(frozen=True)

    count: int = Field(ge=0)
    resisted: int = Field(ge=0)
    injection_resistance_rate: float | None = None


class EvalReport(BaseModel):
    """The report `make eval` writes. D11: coverage, accuracy-on-covered,
    and escalation rate are reported together, per subset, always."""

    model_config = ConfigDict(frozen=True)

    config: EvalConfig
    total_entries: int
    total_rejected: int
    rejected_by_reason: dict[str, int]
    by_provenance: dict[str, ProvenanceStats]
    private_holdout_size: int
    holdout_is_thin: bool
    cost_usd: float | None = None
    #: The injection-bait class, scored alone — never pooled into by_provenance.
    injection: InjectionBaitScore | None = None
    generated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    @classmethod
    def build(
        cls,
        entries: list[DatasetEntry],
        rejected: list[RejectedCandidate],
        config: EvalConfig,
        *,
        cost_usd: float | None = None,
    ) -> EvalReport:
        by_provenance = stratify_by_provenance(entries)
        stats = {
            provenance.value: ProvenanceStats(count=len(group))
            for provenance, group in by_provenance.items()
        }
        rejected_by_reason: dict[str, int] = {}
        for candidate in rejected:
            rejected_by_reason[candidate.reason] = rejected_by_reason.get(candidate.reason, 0) + 1
        return cls(
            config=config,
            total_entries=len(entries),
            total_rejected=len(rejected),
            rejected_by_reason=rejected_by_reason,
            by_provenance=stats,
            private_holdout_size=private_holdout_size(entries),
            holdout_is_thin=is_holdout_thin(entries),
            cost_usd=cost_usd,
        )


def render_report_markdown(report: EvalReport) -> str:
    """D11/D13-compliant Markdown. False suppression rate first when it
    exists; coverage and escalation rate never separated from it."""
    lines = [
        "# SIFT eval report",
        "",
        f"Generated: {report.generated_at}",
        "",
        "## Config",
        "",
        f"- Adjudicator model: `{report.config.adjudicator_model.value}`",
        f"- Baseline model: `{report.config.baseline_model.value}`",
        f"- Upstream provider (pinned): `{report.config.upstream_provider}`",
        f"- Temperature: {report.config.temperature}",
        f"- Prompt hashes: {report.config.prompt_hashes or '_none yet - no prompt exists_'}",
        f"- Dataset: `{report.config.dataset_path}`"
        + (f" @ `{report.config.corpus_sha[:12]}`" if report.config.corpus_sha else ""),
        f"- Budget: ${report.config.budget_usd:.2f}/run",
        "",
        "## Dataset",
        "",
        f"- Total labeled entries: {report.total_entries}",
        f"- Rejected candidates: {report.total_rejected}",
    ]
    if report.rejected_by_reason:
        lines.append("")
        lines.append("| Rejection reason | Count |")
        lines.append("| --- | --- |")
        for reason, count in sorted(report.rejected_by_reason.items()):
            lines.append(f"| {reason} | {count} |")

    lines += [
        "",
        f"**Private holdout (CVE_FIX + HAND_LABELED): {report.private_holdout_size} findings.**",
    ]
    if report.holdout_is_thin:
        lines.append(
            f"> **Thin holdout.** Under the {THIN_HOLDOUT_THRESHOLD}-finding threshold. "
            "This size supports "
            "a directional read (does the pipeline do better than chance on genuinely "
            "unseen code), not a precise point estimate of precision or recall - do not "
            "quote a percentage from this subset as if it were measured on a larger sample."
        )

    lines += [
        "",
        "## By provenance (never pooled)",
        "",
        "| Provenance | Count | False suppression | Coverage | Precision | "
        "Recall | Escalation | Schema failures | Cost/finding | p95 latency |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for provenance in Provenance:
        stats = report.by_provenance.get(provenance.value)
        if stats is None:
            continue
        lines.append(
            f"| {provenance.value} | {stats.count} | "
            f"{_fmt(stats.false_suppression_rate)} | {stats.coverage:.1%} | "
            f"{_fmt(stats.precision)} | {_fmt(stats.recall)} | "
            f"{_fmt(stats.escalation_rate)} | "
            f"{_fmt(stats.schema_validation_failure_rate)} | "
            f"{_money(stats.cost_per_finding)} | {_ms(stats.p95_latency_ms)} |"
        )

    if report.injection is not None:
        lines += [
            "",
            "## Injection resistance (separate class, never pooled)",
            "",
            f"- Bait findings: {report.injection.count}",
            f"- Resisted: {report.injection.resisted}",
            f"- Injection resistance rate: {_fmt(report.injection.injection_resistance_rate)}",
        ]

    if report.cost_usd is not None:
        lines += ["", "## Cost", "", f"${report.cost_usd:.4f} spent this run."]

    if not _any_scored(report):
        lines += [
            "",
            "## Not yet measured",
            "",
            "Precision, recall, and false suppression rate are blank until P4 step 5 "
            "scores the naive baseline - a value would be an unmeasured metric, and "
            "CONTRIBUTING.md forbids publishing one of those.",
        ]
    return "\n".join(lines) + "\n"


def _fmt(value: float | None) -> str:
    # ASCII only - the report is read on Windows terminals too.
    return "n/a" if value is None else f"{value:.1%}"


def _money(value: float | None) -> str:
    return "n/a" if value is None else f"${value:.4f}"


def _ms(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0f} ms"


def _any_scored(report: EvalReport) -> bool:
    """True once any subset carries a scored metric — then the "not yet
    measured" section would be a lie, so it is dropped."""
    for stats in report.by_provenance.values():
        if (
            stats.false_suppression_rate is not None
            or stats.precision is not None
            or stats.recall is not None
            or stats.escalation_rate is not None
            or stats.schema_validation_failure_rate is not None
            or stats.cost_per_finding is not None
            or stats.p95_latency_ms is not None
        ):
            return True
    return report.injection is not None


def write_report(report: EvalReport, path: Path) -> None:
    path.write_text(render_report_markdown(report), encoding="utf-8", newline="\n")
