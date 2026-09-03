"""Stage 1 — deterministic pre-filter. No LLM calls.

Two jobs: collapse exact duplicates, and classify each finding's file. Both are
cheap, both are reproducible, and neither needs a model.

What this stage deliberately does *not* do is dismiss findings by file class.
See :data:`SAFE_TO_RESOLVE` and the note on it — that policy is off by default,
and the reason is the whole point of this module.

Nothing is ever removed. Every finding that enters leaves, carrying a
disposition, a `resolved_by` label, and a justification.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from sift.ingest.fingerprint import FindingRef
from sift.models.context import FileClass
from sift.prefilter.classify import Classification, classify


class Disposition(StrEnum):
    """What Stage 1 decided to do with a finding."""

    #: Byte-for-byte the same finding as one already kept. The survivor is named.
    DEDUPLICATED = "DEDUPLICATED"
    #: Dismissed without a model. Policy-gated and off by default.
    RESOLVED = "RESOLVED"
    #: Passed on to context building and adjudication.
    ADJUDICATE = "ADJUDICATE"


#: File classes the pre-filter may dismiss outright, when the caller opts in.
#:
#: Empty by default, and that is a considered position rather than an oversight.
#: The brief anticipated test, vendored, generated, and fixture files being
#: "resolvable without a model". Examined one at a time, none of them is:
#:
#: - **vendored** — Log4Shell was vendored. A vulnerable dependency is a real
#:   vulnerability; the fix is an upgrade, not a dismissal.
#: - **generated** — the code still ships and still runs. The fix belongs in the
#:   generator, which makes it harder to action, not less real.
#: - **test** — hardcoded credentials in tests are real credentials, and test
#:   helpers get imported by production code more often than anyone admits.
#: - **fixture** — the classic home of a committed private key.
#:
#: Each would be a silent dismissal with no model and no human in the loop, which
#: is the exact failure mode carrying the ~50x cost. So the classification is
#: attached as evidence and the agents weigh it, rather than the pre-filter
#: deciding alone. A caller who accepts the risk for their own repo can pass
#: `resolve_classes` explicitly; `sift.prefilter` will not choose it for them.
SAFE_TO_RESOLVE: frozenset[FileClass] = frozenset()


class PrefilterDecision(BaseModel):
    """Stage 1's decision about one finding. Never a deletion."""

    model_config = ConfigDict(frozen=True)

    ref: FindingRef
    disposition: Disposition
    file_class: FileClass = FileClass.UNKNOWN
    resolved_by: str = Field(description="Which rule decided, e.g. 'prefilter:dedupe'.")
    justification: str
    #: For DEDUPLICATED, the correlation ID of the finding that was kept.
    duplicate_of: str | None = None
    used_content: bool = False


class PrefilterReport(BaseModel):
    """What Stage 1 did, and what it would have done under other policies."""

    total: int
    decisions: list[PrefilterDecision]
    by_disposition: dict[str, int]
    by_class: dict[str, int]
    #: How many findings each class *would* remove if it were opted into. This is
    #: the number that makes the policy choice an informed one instead of a guess.
    resolvable_by_class: dict[str, int]
    #: Findings that reached Stage 2. The denominator for every later claim.
    adjudicate_count: int
    duplicates_removed: int
    #: Distinct correlation IDs seen in more than one run, reported but never
    #: merged: two tools agreeing is not the same finding twice.
    cross_run_overlap: int

    @property
    def resolved_without_a_model(self) -> float:
        """Fraction of findings Stage 1 settled alone. The baseline to beat."""
        if self.total == 0:
            return 0.0
        settled = self.total - self.adjudicate_count
        return settled / self.total


def run(
    refs: Sequence[FindingRef],
    *,
    repo_root: Path | None = None,
    resolve_classes: frozenset[FileClass] = SAFE_TO_RESOLVE,
) -> PrefilterReport:
    """Deduplicate and classify. Returns one decision per input finding.

    ``len(report.decisions) == len(refs)`` always. That is asserted, because a
    pre-filter that can shrink its input is one refactor away from losing a
    vulnerability.
    """
    decisions: list[PrefilterDecision] = []
    seen: dict[str, FindingRef] = {}
    runs_per_id: defaultdict[str, set[int]] = defaultdict(set)
    classifications: dict[str, Classification] = {}
    resolvable = Counter[str]()

    for ref in refs:
        runs_per_id[ref.correlation_id].add(ref.run_index)

        if (kept := seen.get(ref.correlation_id)) is not None:
            decisions.append(
                PrefilterDecision(
                    ref=ref,
                    disposition=Disposition.DEDUPLICATED,
                    file_class=classifications.get(
                        ref.uri or "", Classification(FileClass.UNKNOWN)
                    ).file_class,
                    resolved_by="prefilter:dedupe",
                    justification=(
                        f"Identical correlation ID to the finding at run {kept.run_index}, "
                        f"result {kept.result_index}. Same rule, same location, same content."
                    ),
                    duplicate_of=kept.correlation_id,
                )
            )
            continue

        seen[ref.correlation_id] = ref

        uri = ref.uri or ""
        if uri not in classifications:
            classifications[uri] = (
                classify(uri, repo_root)
                if uri
                else Classification(FileClass.UNKNOWN, "finding has no location")
            )
        found = classifications[uri]

        if found.file_class not in (FileClass.SOURCE, FileClass.UNKNOWN):
            resolvable[found.file_class.value] += 1

        if found.file_class in resolve_classes:
            decisions.append(
                PrefilterDecision(
                    ref=ref,
                    disposition=Disposition.RESOLVED,
                    file_class=found.file_class,
                    resolved_by=f"prefilter:{found.file_class.value.lower()}",
                    justification=(
                        f"Classified {found.file_class.value} ({found.reason}), and the caller "
                        f"opted to resolve this class without a model."
                    ),
                    used_content=found.used_content,
                )
            )
            continue

        decisions.append(
            PrefilterDecision(
                ref=ref,
                disposition=Disposition.ADJUDICATE,
                file_class=found.file_class,
                resolved_by="prefilter:pass",
                justification=(
                    f"Classified {found.file_class.value}"
                    + (f" ({found.reason})" if found.reason else "")
                    + ". Not resolvable without judgment; passed to adjudication."
                ),
                used_content=found.used_content,
            )
        )

    if len(decisions) != len(refs):  # pragma: no cover - guarded invariant
        raise AssertionError(
            f"pre-filter changed the finding count: {len(refs)} -> {len(decisions)}"
        )

    by_disposition = Counter(d.disposition.value for d in decisions)
    return PrefilterReport(
        total=len(refs),
        decisions=decisions,
        by_disposition=dict(by_disposition),
        by_class=dict(Counter(d.file_class.value for d in decisions)),
        resolvable_by_class=dict(resolvable),
        adjudicate_count=by_disposition[Disposition.ADJUDICATE.value],
        duplicates_removed=by_disposition[Disposition.DEDUPLICATED.value],
        cross_run_overlap=sum(1 for ids in runs_per_id.values() if len(ids) > 1),
    )
