"""Stage 4 — the JSON run report: cost, latency, verdict distribution, model
IDs, prompt hashes. CONTRIBUTING.md: "a metric without its configuration is
meaningless and must not reach the README" — this is that configuration,
attached to every real run, not just an eval report.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from pydantic import BaseModel, Field

from sift.models.verdict import TriageResult, Verdict
from sift.orchestrator.pipeline import PipelineConfig


class RunReport(BaseModel):
    """Everything a caller needs to trust or audit one `sift triage` run."""

    total_findings: int
    resolved_by_prefilter: int
    adjudicated: int
    verdict_counts: dict[str, int] = Field(default_factory=dict)
    total_cost_usd: float = 0.0
    total_latency_ms: int = 0
    model_ids: dict[str, str] = Field(default_factory=dict)
    prompt_hashes: dict[str, str] = Field(default_factory=dict)
    temperature: float = 0.0


def build_run_report(
    *,
    total_findings: int,
    resolved_by_prefilter: int,
    results: list[TriageResult],
    config: PipelineConfig,
) -> RunReport:
    verdicts = Counter(r.adjudication.verdict.value for r in results)
    for verdict in Verdict:
        verdicts.setdefault(verdict.value, 0)
    return RunReport(
        total_findings=total_findings,
        resolved_by_prefilter=resolved_by_prefilter,
        adjudicated=len(results),
        verdict_counts=dict(verdicts),
        total_cost_usd=sum(r.cost_usd for r in results),
        total_latency_ms=sum(r.latency_ms for r in results),
        model_ids={
            "reachability": config.reachability.model.value,
            "exploitability": config.exploitability.model.value,
            "adversary": config.adversary.model.value,
            "adjudicator": config.adjudicator.model.value,
        },
        prompt_hashes=config.prompt_hashes,
        temperature=config.temperature,
    )


def write_run_report(report: RunReport, path: Path) -> None:
    path.write_text(json.dumps(report.model_dump(), indent=2, ensure_ascii=True) + "\n", "utf-8")
