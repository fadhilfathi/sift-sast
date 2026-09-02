"""SARIF 2.1.0 models.

Interop contract: SARIF in, SARIF out, lossless. Every model allows extra keys
and round-trips them, so fields SIFT does not understand survive untouched.
Dump with ``exclude_unset=True`` to avoid inventing keys the input never had.

Only the parts SIFT reads or writes are typed. Everything else rides along in
``model_extra``.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"


class _Sarif(BaseModel):
    """Base: preserve unknown fields verbatim."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)


class SuppressionKind(StrEnum):
    IN_SOURCE = "inSource"
    EXTERNAL = "external"


class SuppressionStatus(StrEnum):
    ACCEPTED = "accepted"
    UNDER_REVIEW = "underReview"
    REJECTED = "rejected"


class Message(_Sarif):
    text: str | None = None
    markdown: str | None = None


class ArtifactLocation(_Sarif):
    uri: str | None = None
    uri_base_id: str | None = Field(default=None, alias="uriBaseId")
    index: int | None = None


class Region(_Sarif):
    start_line: int | None = Field(default=None, alias="startLine")
    start_column: int | None = Field(default=None, alias="startColumn")
    end_line: int | None = Field(default=None, alias="endLine")
    end_column: int | None = Field(default=None, alias="endColumn")
    snippet: dict[str, Any] | None = None


class PhysicalLocation(_Sarif):
    artifact_location: ArtifactLocation | None = Field(default=None, alias="artifactLocation")
    region: Region | None = None


class Location(_Sarif):
    physical_location: PhysicalLocation | None = Field(default=None, alias="physicalLocation")
    message: Message | None = None


class ThreadFlowLocation(_Sarif):
    location: Location | None = None
    nesting_level: int | None = Field(default=None, alias="nestingLevel")


class ThreadFlow(_Sarif):
    locations: list[ThreadFlowLocation] = Field(default_factory=list)


class CodeFlow(_Sarif):
    thread_flows: list[ThreadFlow] = Field(default_factory=list, alias="threadFlows")
    message: Message | None = None


class Suppression(_Sarif):
    """How SIFT records a dismissal. Never a deletion."""

    kind: SuppressionKind = SuppressionKind.EXTERNAL
    status: SuppressionStatus = SuppressionStatus.ACCEPTED
    justification: str | None = None
    guid: str | None = None


class ReportingDescriptor(_Sarif):
    id: str
    name: str | None = None
    short_description: Message | None = Field(default=None, alias="shortDescription")
    full_description: Message | None = Field(default=None, alias="fullDescription")


class ToolComponent(_Sarif):
    name: str
    version: str | None = None
    rules: list[ReportingDescriptor] = Field(default_factory=list)


class Tool(_Sarif):
    driver: ToolComponent
    extensions: list[ToolComponent] = Field(default_factory=list)


class Result(_Sarif):
    rule_id: str | None = Field(default=None, alias="ruleId")
    rule_index: int | None = Field(default=None, alias="ruleIndex")
    level: str | None = None
    message: Message = Field(default_factory=Message)
    locations: list[Location] = Field(default_factory=list)
    code_flows: list[CodeFlow] = Field(default_factory=list, alias="codeFlows")
    suppressions: list[Suppression] = Field(default_factory=list)
    fingerprints: dict[str, str] = Field(default_factory=dict)
    partial_fingerprints: dict[str, str] = Field(default_factory=dict, alias="partialFingerprints")
    properties: dict[str, Any] = Field(default_factory=dict)


class Run(_Sarif):
    tool: Tool
    results: list[Result] = Field(default_factory=list)
    properties: dict[str, Any] = Field(default_factory=dict)


class SarifLog(_Sarif):
    version: str = SARIF_VERSION
    schema_uri: str | None = Field(default=SARIF_SCHEMA, alias="$schema")
    runs: list[Run] = Field(default_factory=list)
