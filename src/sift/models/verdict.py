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


class AgentArgument(BaseModel):
    """One analyst's position. The Adjudicator sees these with `role` stripped."""

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

    @model_validator(mode="after")
    def enforce_safety_rule(self) -> Self:
        """A dismissal must clear the confidence floor and answer every objection.

        Runs on assignment too, so a later edit cannot sneak a weak dismissal through.
        """
        if self.verdict is not Verdict.FALSE_POSITIVE:
            return self

        reasons = []
        if self.confidence < FALSE_POSITIVE_CONFIDENCE_FLOOR:
            reasons.append(f"confidence {self.confidence:.2f} < {FALSE_POSITIVE_CONFIDENCE_FLOOR}")
        if unrebutted := [o for o in self.open_objections if not o.rebutted]:
            reasons.append(f"{len(unrebutted)} unrebutted adversary objection(s)")
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
