"""ContextBundle — the deterministic evidence package handed to the agents.

Everything here is assembled by tree-sitter and SARIF parsing. No model writes
into this structure. If a fact is not in here, the agents must not assert it.
"""

from __future__ import annotations

import math
from collections import Counter
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

# ContextCompleteness lives in verdict.py, re-exported here: Adjudication
# (verdict.py) needs it too, and verdict.py cannot import context.py without
# a cycle, since context.py already imports FileLineRef from verdict.py.
# The `as ContextCompleteness` is mypy's explicit-reexport idiom, required
# under strict mode - a plain import here is otherwise invisible to a caller
# importing this name from this module.
from sift.models.verdict import ContextCompleteness as ContextCompleteness
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


#: Delimiters wrapped around a `CodeSpan` before it may reach a model. ASCII
#: only — the CLI already hit a Windows-terminal encoding failure on an em
#: dash, and this text is destined for the same kind of pipe.
_UNTRUSTED_BEGIN = "<<<UNTRUSTED SOURCE path={path} lines={start}-{end}>>>"
_UNTRUSTED_END = "<<<END UNTRUSTED SOURCE>>>"


class CodeSpan(BaseModel):
    """A verbatim slice of analyzed source. Untrusted data, never instructions."""

    model_config = ConfigDict(frozen=True)

    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    source: str
    symbol: str | None = Field(default=None, description="Enclosing function or method name.")
    language: str | None = None

    def as_untrusted_block(self) -> str:
        """The only form of this span P5 prompt assembly may read.

        `source` stays plain for diffing, for `sift context dump`, and because
        redaction operates on it directly. Delimiting lives here, on the data
        structure, rather than in a prompt template a future span type could
        bypass by omission.
        """
        header = _UNTRUSTED_BEGIN.format(path=self.path, start=self.start_line, end=self.end_line)
        return f"{header}\n{self.source}\n{_UNTRUSTED_END}"


class CallSite(BaseModel):
    """A caller of the enclosing function, discovered by AST search."""

    caller: CodeSpan
    call_line: int = Field(ge=1)
    #: Capped at 2 — see decision D7 in docs/ARCHITECTURE.md. Deeper reachability
    #: reasoning is Reachability's targeted entrypoint search, not a wider
    #: breadth-first walk of this list.
    hops_from_finding: int = Field(ge=1, le=2)


class TruncatedCaller(BaseModel):
    """One node where the walk stopped expanding further, with the true count."""

    symbol: str
    path: str
    callers_found: int = Field(ge=0)
    callers_kept: int = Field(ge=0)


class CallerSearch(BaseModel):
    """What the caller-graph traversal did, and exactly where it stopped.

    Decision D7: an empty ``callers`` list must never be producible by giving
    up. Every field here exists so that "zero callers exist" and "zero callers
    enumerated" cannot be confused by anything reading the bundle.
    """

    hop_limit: int = Field(ge=1)
    span_budget: int = Field(ge=1, description="Total CodeSpans allowed across the whole walk.")
    spans_used: int = Field(default=0, ge=0)
    refused: bool = Field(
        default=False,
        description="True if direct-caller count alone exceeded the refuse threshold.",
    )
    direct_caller_count: int | None = Field(
        default=None, description="Set when refused: how many direct callers exist, none walked."
    )
    truncated: bool = Field(
        default=False, description="True if the span budget ran out before the walk finished."
    )
    truncated_at: list[TruncatedCaller] = Field(default_factory=list)


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


class CompletenessReason(StrEnum):
    """Why a bundle is not COMPLETE. Tagged so code can match on it, not prose.

    See the trigger -> level table in docs/ARCHITECTURE.md (decision D6).
    """

    ENCLOSING_FUNCTION_UNRESOLVED = "enclosing-function-unresolved"
    DYNAMIC_DISPATCH = "dynamic-dispatch"
    C_EXTENSION_BOUNDARY = "c-extension-boundary"
    CALLER_SEARCH_REFUSED = "caller-search-refused"
    CALLER_SEARCH_TRUNCATED = "caller-search-truncated"
    UNRESOLVED_IMPORT = "unresolved-import"
    PATH_TRAVERSAL_REFUSED = "path-traversal-refused"
    FILE_UNREADABLE = "file-unreadable"


#: Reasons that, alone, mean the tool cannot rule out the dangerous
#: interpretation — not merely that it found less evidence than usual.
_INSUFFICIENT_REASONS = frozenset(
    {
        CompletenessReason.ENCLOSING_FUNCTION_UNRESOLVED,
        CompletenessReason.DYNAMIC_DISPATCH,
        CompletenessReason.C_EXTENSION_BOUNDARY,
    }
)


def completeness_from(
    reasons: set[CompletenessReason] | frozenset[CompletenessReason],
    *,
    externally_reachable: bool | None,
) -> ContextCompleteness:
    """The trigger -> level mapping from decision D6, as a pure function.

    Independently testable without a parser: given the reasons a build run
    collected and whether reachability was separately decided, this is the
    whole policy. ``CALLER_SEARCH_REFUSED`` is the one context-dependent case —
    it is only INSUFFICIENT while reachability is still undecided, because a
    resolved ``externally_reachable`` answers the question the caller graph
    would otherwise have been needed for.
    """
    if not reasons:
        return ContextCompleteness.COMPLETE
    if reasons & _INSUFFICIENT_REASONS:
        return ContextCompleteness.INSUFFICIENT
    if CompletenessReason.CALLER_SEARCH_REFUSED in reasons and externally_reachable is None:
        return ContextCompleteness.INSUFFICIENT
    return ContextCompleteness.PARTIAL


class SecretKind(StrEnum):
    """What a redacted value looked like. Never how it looked."""

    AWS_ACCESS_KEY = "AWS_ACCESS_KEY"
    PRIVATE_KEY_PEM = "PRIVATE_KEY_PEM"
    JWT = "JWT"
    CONNECTION_STRING = "CONNECTION_STRING"
    GENERIC_HIGH_ENTROPY = "GENERIC_HIGH_ENTROPY"


class EntropyClass(StrEnum):
    """Bucketed, not the raw float. Bucketing is what keeps this lossy."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


#: Shannon entropy in bits/char. Tuned against a real-shaped AWS key (HIGH)
#: and a common word (LOW); see tests/test_redact.py.
_ENTROPY_LOW_MAX = 3.0
_ENTROPY_MEDIUM_MAX = 4.0


def shannon_entropy(value: str) -> float:
    """Bits per character. Empty input has no information: 0.0."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def entropy_class(value: str) -> EntropyClass:
    bits = shannon_entropy(value)
    if bits < _ENTROPY_LOW_MAX:
        return EntropyClass.LOW
    if bits < _ENTROPY_MEDIUM_MAX:
        return EntropyClass.MEDIUM
    return EntropyClass.HIGH


def format_secret_placeholder(kind: SecretKind, length: int, entropy: EntropyClass) -> str:
    """The exact text substituted for a redacted value. ASCII only."""
    return f"<<REDACTED:kind={kind.value.lower()},len={length},entropy={entropy.value.lower()}>>"


class RedactedSecret(BaseModel):
    """A secret-shaped literal that was in the source and is not anymore.

    Decision D8: what survives is kind, length, and a bucketed entropy class —
    enough for an agent to reason "a 40-char high-entropy literal is passed
    here" without ever seeing the value. No hash, no prefix, no suffix: a hash
    of a short, guessable secret is brute-forceable offline and is not
    meaningfully one-way for this purpose.
    """

    model_config = ConfigDict(frozen=True)

    kind: SecretKind
    length: int = Field(ge=1)
    entropy_class: EntropyClass
    location: FileLineRef

    def placeholder(self) -> str:
        """The exact text substituted for the value in `CodeSpan.source`."""
        return format_secret_placeholder(self.kind, self.length, self.entropy_class)


class ContextBundle(BaseModel):
    """Complete deterministic context for one finding."""

    model_config = ConfigDict(extra="forbid")

    correlation_id: str
    rule_id: str
    rule_description: str | None = None
    message: str

    flagged: FileLineRef
    enclosing_function: CodeSpan | None = None
    callers: list[CallSite] = Field(default_factory=list)
    caller_search: CallerSearch
    called_definitions: list[CodeSpan] = Field(default_factory=list)
    data_flow: list[FlowStep] = Field(
        default_factory=list, description="From SARIF codeFlows when the scanner provided one."
    )

    file_class: FileClass = FileClass.UNKNOWN
    imports: list[str] = Field(default_factory=list)
    sanitizers: list[SanitizerCall] = Field(default_factory=list)
    reachability: Reachability = Field(default_factory=Reachability)
    redactions: list[RedactedSecret] = Field(default_factory=list)

    completeness: ContextCompleteness
    completeness_reasons: list[CompletenessReason] = Field(default_factory=list)

    truncated: bool = Field(
        default=False, description="True if any span was clipped to fit the context budget."
    )
    build_warnings: list[str] = Field(
        default_factory=list,
        description="Free-text detail behind the structured completeness_reasons above.",
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
