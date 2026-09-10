"""Pydantic schemas.

The interop contract between pipeline stages and across versions. Additive
optional fields are safe; removals, tightened constraints, and changed meanings
are breaking and need a CHANGELOG entry. See CONTRIBUTING.md.
"""

from sift.models.context import (
    CallerSearch,
    CallSite,
    CodeSpan,
    CompletenessReason,
    ContextBundle,
    ContextCompleteness,
    EntropyClass,
    EntrypointKind,
    FileClass,
    FlowStep,
    Reachability,
    RedactedSecret,
    SanitizerCall,
    SecretKind,
    TruncatedCaller,
    completeness_from,
    entropy_class,
    shannon_entropy,
)
from sift.models.sarif import Result, Run, SarifLog, Suppression
from sift.models.verdict import (
    Adjudication,
    AdversaryOutput,
    AdversaryPosition,
    AgentArgument,
    AgentRole,
    AnalystOutput,
    FiledObjection,
    FileLineRef,
    Objection,
    TriageResult,
    Verdict,
)

__all__ = [
    "Adjudication",
    "AdversaryOutput",
    "AdversaryPosition",
    "AgentArgument",
    "AgentRole",
    "AnalystOutput",
    "CallSite",
    "CallerSearch",
    "CodeSpan",
    "CompletenessReason",
    "ContextBundle",
    "ContextCompleteness",
    "EntropyClass",
    "EntrypointKind",
    "FileClass",
    "FileLineRef",
    "FiledObjection",
    "FlowStep",
    "Objection",
    "Reachability",
    "RedactedSecret",
    "Result",
    "Run",
    "SanitizerCall",
    "SarifLog",
    "SecretKind",
    "Suppression",
    "TriageResult",
    "TruncatedCaller",
    "Verdict",
    "completeness_from",
    "entropy_class",
    "shannon_entropy",
]
