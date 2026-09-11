"""Adjudication schemas.

These types encode the safety contract. A missed true positive is roughly 50x
worse than a retained false positive, so every ambiguity here resolves toward
``NEEDS_HUMAN_REVIEW``. The downgrade in :meth:`Adjudication.enforce_safety_rule`
is the single most important rule in the codebase; do not relax it.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

#: A ``FALSE_POSITIVE`` verdict below this confidence is downgraded.
FALSE_POSITIVE_CONFIDENCE_FLOOR = 0.85


class Verdict(StrEnum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEEDS_HUMAN_REVIEW = "NEEDS_HUMAN_REVIEW"


class AgentRole(StrEnum):
    REACHABILITY = "REACHABILITY"
    EXPLOITABILITY = "EXPLOITABILITY"
    ADVERSARY = "ADVERSARY"
    ADJUDICATOR = "ADJUDICATOR"


class ContextCompleteness(StrEnum):
    """How much of the intended context was actually retrieved.

    Defined here rather than in `sift.models.context` (where the rest of the
    completeness machinery - `CompletenessReason`, `completeness_from` -
    lives) because `Adjudication` below needs it too, and `context.py`
    already imports `FileLineRef` from this module; putting it there would
    make a cycle. `sift.models.context` re-exports this name so
    `from sift.models.context import ContextCompleteness` still works.

    Not an absence signal buried in a warning list. Decision D6 specifies
    that `Adjudication` carries this value and that `INSUFFICIENT` blocks a
    FALSE_POSITIVE verdict on the same footing as the confidence floor.
    """

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    INSUFFICIENT = "INSUFFICIENT"


class FileLineRef(BaseModel):
    """A citation into analyzed source. Validated against the real file before use."""

    model_config = ConfigDict(frozen=True)

    path: str = Field(description="Repo-relative POSIX path.")
    line: int = Field(ge=1, description="1-indexed line number.")
    end_line: int | None = Field(default=None, ge=1)
    snippet: str | None = Field(
        default=None, max_length=2000, description="Verbatim source, never paraphrased."
    )

    @model_validator(mode="after")
    def check_span(self) -> Self:
        if self.end_line is not None and self.end_line < self.line:
            raise ValueError("end_line must be >= line")
        return self


class Objection(BaseModel):
    """An Adversary challenge to a dismissal, and whether anyone answered it."""

    claim: str = Field(max_length=500)
    evidence: list[FileLineRef] = Field(default_factory=list)
    rebutted: bool = Field(
        default=False,
        description="True only if another agent addressed this claim with code evidence.",
    )
    rebuttal: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def rebuttal_requires_text(self) -> Self:
        if self.rebutted and not self.rebuttal:
            raise ValueError("a rebutted objection must carry its rebuttal text")
        return self


class AnalystOutput(BaseModel):
    """The parsed response schema for Reachability and Exploitability.

    No `objections` field. Filing an objection against a dismissal is the
    Adversary's job — closing the field here at the schema level means an
    analyst cannot emit one for the Adjudicator to find and mistake for the
    real thing; the shape itself forbids it rather than a prompt asking
    nicely.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    position: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(max_length=3000)
    evidence_lines: list[FileLineRef] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)


class AdversaryPosition(StrEnum):
    """The Adversary's own position space. `FALSE_POSITIVE` is structurally
    absent — the prosecution does not get to conclude the defense's case."""

    TRUE_POSITIVE = "TRUE_POSITIVE"
    NEEDS_HUMAN_REVIEW = "NEEDS_HUMAN_REVIEW"


class FiledObjection(BaseModel):
    """An objection as the Adversary files it.

    No `rebutted` or `rebuttal` field. Those are the Adjudicator's fields to
    set, not the prosecution's — letting the Adversary pre-populate its own
    objection as resolved would let a model quietly mark its own case closed.
    The orchestrator attaches `rebutted=False, rebuttal=None` at handoff; the
    Adjudicator's output is what actually decides them.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    claim: str = Field(max_length=500)
    evidence: list[FileLineRef] = Field(default_factory=list)


class AdversaryOutput(BaseModel):
    """The parsed response schema for the Adversary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    position: AdversaryPosition
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(max_length=3000)
    evidence_lines: list[FileLineRef] = Field(default_factory=list)
    objections: list[FiledObjection] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)


class AgentArgument(BaseModel):
    """One analyst's position, as stored for the audit trail. The Adjudicator
    sees the raw `AnalystOutput`/`AdversaryOutput` forms with `role` never
    present at all, not this stored shape with `role` stripped after the
    fact."""

    role: AgentRole
    position: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(max_length=3000)
    evidence_lines: list[FileLineRef] = Field(default_factory=list)
    objections: list[Objection] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)


class Adjudication(BaseModel):
    """Final per-finding verdict. Emitted into SARIF."""

    model_config = ConfigDict(validate_assignment=True)

    correlation_id: str
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    justification: str = Field(
        max_length=500, description="Must cite specific code, not restate the rule."
    )
    evidence_lines: list[FileLineRef] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
    open_objections: list[Objection] = Field(
        default_factory=list, description="Adversary claims left unrebutted."
    )
    downgraded_from: Verdict | None = Field(
        default=None, description="Set when the safety rule overrode the model's verdict."
    )
    downgrade_reason: str | None = None
    adversary_objection_count: int = Field(
        default=0,
        ge=0,
        description=(
            "How many objections the Adversary filed, before any rebuttal. Zero blocks "
            "FALSE_POSITIVE regardless of confidence — see enforce_safety_rule. The safe "
            "default is zero: a caller must affirmatively report that the Adversary looked."
        ),
    )
    context_completeness: ContextCompleteness | None = Field(
        default=None,
        description=(
            "Copied from ContextBundle.completeness (decision D6). INSUFFICIENT blocks "
            "FALSE_POSITIVE on the same footing as the confidence floor — the tool cannot "
            "rule out the dangerous interpretation regardless of how confident the model is. "
            "None is treated the same as INSUFFICIENT: a caller that forgot to report "
            "completeness gets the safe outcome, not a free pass."
        ),
    )

    @model_validator(mode="after")
    def enforce_safety_rule(self) -> Self:
        """A dismissal must clear the confidence floor, answer every objection, have
        had a real prosecution run against it, and rest on context the tool actually
        finished retrieving.

        Runs on assignment too, so a later edit cannot sneak a weak dismissal through.
        """
        if self.verdict is not Verdict.FALSE_POSITIVE:
            return self

        reasons = []
        if self.confidence < FALSE_POSITIVE_CONFIDENCE_FLOOR:
            reasons.append(f"confidence {self.confidence:.2f} < {FALSE_POSITIVE_CONFIDENCE_FLOOR}")
        if unrebutted := [o for o in self.open_objections if not o.rebutted]:
            reasons.append(f"{len(unrebutted)} unrebutted adversary objection(s)")
        if self.adversary_objection_count == 0:
            reasons.append("adversary filed zero objections")
        elif len(self.open_objections) < self.adversary_objection_count:
            # The Adversary filed N objections, but fewer than N made it into
            # open_objections. Counting alone (the check above) cannot catch
            # this: a compromised or merely careless Adjudicator can report a
            # nonzero adversary_objection_count while quietly omitting the
            # objections themselves from its own output, rather than
            # rebutting them - dropping is not resolving.
            dropped = self.adversary_objection_count - len(self.open_objections)
            reasons.append(f"{dropped} adversary objection(s) dropped before adjudication")
        if self.context_completeness is None or self.context_completeness is (
            ContextCompleteness.INSUFFICIENT
        ):
            reasons.append(f"context completeness is {self.context_completeness}")
        if not reasons:
            return self

        # Bypass validate_assignment: we are inside the validator that it re-triggers.
        object.__setattr__(self, "downgraded_from", Verdict.FALSE_POSITIVE)
        object.__setattr__(self, "downgrade_reason", "; ".join(reasons))
        object.__setattr__(self, "verdict", Verdict.NEEDS_HUMAN_REVIEW)
        return self


class TriageResult(BaseModel):
    """Everything produced for one finding. Nothing is ever dropped, only labeled."""

    adjudication: Adjudication
    arguments: list[AgentArgument] = Field(default_factory=list)
    resolved_by: str = Field(
        description="Which stage decided: 'prefilter:test-file', 'agents', 'cache', ..."
    )
    cost_usd: float = Field(default=0.0, ge=0.0)
    latency_ms: int = Field(default=0, ge=0)
