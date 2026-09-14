"""Stage 4 — attach SIFT's decision to a SARIF result, never delete one.

Every finding that entered `sift triage` carries a `properties["sift/v1"]`
bag when it leaves, whether Stage 1 short-circuited it or Stage 3 actually
adjudicated it. A `Suppression` is attached for a `FALSE_POSITIVE` verdict
for interop correctness, but GitHub Code Scanning ignores SARIF
`suppressions` entirely (measured, P1 - see docs/ARCHITECTURE.md) - it is
never the mechanism a caller should rely on to dismiss an alert.
"""

from __future__ import annotations

from sift.ingest.fingerprint import CORRELATION_VERSION, FindingRef
from sift.models.sarif import Result, Suppression, SuppressionKind, SuppressionStatus
from sift.models.verdict import Adjudication, TriageResult, Verdict
from sift.prefilter import PrefilterDecision


def annotate_prefiltered(result: Result, ref: FindingRef, decision: PrefilterDecision) -> Result:
    """A finding Stage 1 decided about without a model. Still labeled, never dropped."""
    properties = dict(result.properties)
    properties[CORRELATION_VERSION] = {
        "correlation_id": ref.correlation_id,
        "identity_source": ref.identity_source.value,
        "disposition": decision.disposition.value,
        "resolved_by": decision.resolved_by,
        "justification": decision.justification,
    }
    return result.model_copy(update={"properties": properties})


def annotate_adjudicated(
    result: Result, ref: FindingRef, decision: PrefilterDecision, triage: TriageResult
) -> Result:
    """A finding Stage 3 actually adjudicated. Carries the verdict, the
    confidence, the justification, and a summary of every agent's argument -
    never just the final answer with no visible reasoning."""
    adjudication: Adjudication = triage.adjudication
    properties = dict(result.properties)
    properties[CORRELATION_VERSION] = {
        "correlation_id": ref.correlation_id,
        "identity_source": ref.identity_source.value,
        "disposition": decision.disposition.value,
        "resolved_by": triage.resolved_by,
        "verdict": adjudication.verdict.value,
        "confidence": adjudication.confidence,
        "justification": adjudication.justification,
        "context_completeness": (
            adjudication.context_completeness.value
            if adjudication.context_completeness is not None
            else None
        ),
        "adversary_objection_count": adjudication.adversary_objection_count,
        "downgraded_from": (
            adjudication.downgraded_from.value if adjudication.downgraded_from else None
        ),
        "downgrade_reason": adjudication.downgrade_reason,
        "cost_usd": triage.cost_usd,
        "latency_ms": triage.latency_ms,
        "arguments": [
            {"role": a.role.value, "position": a.position.value, "confidence": a.confidence}
            for a in triage.arguments
        ],
    }

    suppressions = list(result.suppressions)
    if adjudication.verdict is Verdict.FALSE_POSITIVE:
        suppressions.append(
            Suppression(
                kind=SuppressionKind.EXTERNAL,
                status=SuppressionStatus.ACCEPTED,
                justification=adjudication.justification,
            )
        )

    return result.model_copy(update={"properties": properties, "suppressions": suppressions})
