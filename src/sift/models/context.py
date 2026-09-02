"""ContextBundle — the deterministic evidence package handed to the agents.

Everything here is assembled by tree-sitter and SARIF parsing. No model writes
into this structure. If a fact is not in here, the agents must not assert it.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from sift.models.verdict import FileLineRef


class FileClass(StrEnum):
    """Deterministic file classification. Drives the Stage 1 pre-filter."""

    SOURCE = "SOURCE"
    TEST = "TEST"
    GENERATED = "GENERATED"
    VENDORED = "VENDORED"
    FIXTURE = "FIXTURE"
    UNKNOWN = "UNKNOWN"


class EntrypointKind(StrEnum):
    """How untrusted input could reach the enclosing function."""

    HTTP_HANDLER = "HTTP_HANDLER"
    CLI_ARGUMENT = "CLI_ARGUMENT"
    QUEUE_CONSUMER = "QUEUE_CONSUMER"
    SCHEDULED_JOB = "SCHEDULED_JOB"
    RPC_HANDLER = "RPC_HANDLER"
    LIBRARY_EXPORT = "LIBRARY_EXPORT"
    INTERNAL_ONLY = "INTERNAL_ONLY"
    UNKNOWN = "UNKNOWN"


class CodeSpan(BaseModel):
    """A verbatim slice of analyzed source. Untrusted data, never instructions."""

    model_config = ConfigDict(frozen=True)

    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    source: str
    symbol: str | None = Field(default=None, description="Enclosing function or method name.")
    language: str | None = None


class CallSite(BaseModel):
    """A caller of the enclosing function, discovered by AST search."""

    caller: CodeSpan
    call_line: int = Field(ge=1)
    hops_from_finding: int = Field(ge=1, le=3)


class FlowStep(BaseModel):
    """One node of a SARIF codeFlow, resolved to real source."""

    order: int = Field(ge=0)
    location: FileLineRef
    source_line: str
    message: str | None = None


class SanitizerCall(BaseModel):
    """A call on the taint path that may neutralize the input.

    ``confirmed`` stays False unless the callee definition was actually read.
    A name that merely looks like a sanitizer is not evidence.
    """

    name: str
    location: FileLineRef
    definition: CodeSpan | None = None
    confirmed: bool = False


class Reachability(BaseModel):
    """External reachability of the entrypoint, from the call graph only."""

    entrypoint_kind: EntrypointKind = EntrypointKind.UNKNOWN
    entrypoint: CodeSpan | None = None
    path_from_entrypoint: list[CallSite] = Field(default_factory=list)
    externally_reachable: bool | None = Field(
        default=None, description="None means the analysis could not decide. Never guess."
    )
    notes: list[str] = Field(default_factory=list)


class ContextBundle(BaseModel):
    """Complete deterministic context for one finding."""

    model_config = ConfigDict(extra="forbid")

    finding_fingerprint: str
    rule_id: str
    rule_description: str | None = None
    message: str

    flagged: FileLineRef
    enclosing_function: CodeSpan | None = None
    callers: list[CallSite] = Field(default_factory=list)
    called_definitions: list[CodeSpan] = Field(default_factory=list)
    data_flow: list[FlowStep] = Field(
        default_factory=list, description="From SARIF codeFlows when the scanner provided one."
    )

    file_class: FileClass = FileClass.UNKNOWN
    imports: list[str] = Field(default_factory=list)
    sanitizers: list[SanitizerCall] = Field(default_factory=list)
    reachability: Reachability = Field(default_factory=Reachability)

    truncated: bool = Field(
        default=False, description="True if any span was clipped to fit the context budget."
    )
    build_warnings: list[str] = Field(
        default_factory=list, description="Parse failures etc. Agents must treat these as doubt."
    )

    def all_spans(self) -> list[CodeSpan]:
        """Every verbatim source span, for uniform untrusted-data wrapping and redaction."""
        spans = [*self.called_definitions, *(c.caller for c in self.callers)]
        if self.enclosing_function:
            spans.append(self.enclosing_function)
        if self.reachability.entrypoint:
            spans.append(self.reachability.entrypoint)
        spans.extend(c.caller for c in self.reachability.path_from_entrypoint)
        spans.extend(s.definition for s in self.sanitizers if s.definition)
        return spans
