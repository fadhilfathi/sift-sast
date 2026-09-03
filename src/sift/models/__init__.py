"""Pydantic schemas.

The interop contract between pipeline stages and across versions. Additive
optional fields are safe; removals, tightened constraints, and changed meanings
are breaking and need a CHANGELOG entry. See CONTRIBUTING.md.
"""

from sift.models.context import (
    CallSite,
    CodeSpan,
    ContextBundle,
    EntrypointKind,
    FileClass,
    FlowStep,
    Reachability,
    SanitizerCall,
)
from sift.models.sarif import Result, Run, SarifLog, Suppression
from sift.models.verdict import (
    Adjudication,
    AgentArgument,
    AgentRole,
    FileLineRef,
    Objection,
    TriageResult,
    Verdict,
)

__all__ = [
    "Adjudication",
    "AgentArgument",
    "AgentRole",
    "CallSite",
    "CodeSpan",
    "ContextBundle",
    "EntrypointKind",
    "FileClass",
    "FileLineRef",
    "FlowStep",
    "Objection",
    "Reachability",
    "Result",
    "Run",
    "SanitizerCall",
    "SarifLog",
    "Suppression",
    "TriageResult",
    "Verdict",
]
