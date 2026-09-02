"""Correlation IDs — decision D1 in `docs/ARCHITECTURE.md`.

The correlation ID answers one question: *is this the same finding a human
already reviewed?* It is **not** GitHub's alert identity, which we never write
to, and it is **not** the cache key, which is deliberately more sensitive and
arrives in P5.

Precedence, best first:

1. ``partialFingerprints["primaryLocationLineHash"]`` — preferred, because it
   makes our correlation agree with GitHub's alert identity for free.
2. A tool-supplied value from ``fingerprints``.
3. Computed here from rule, path, and the flagged line's *content*.

Tier 3 degrades to a positional identity when the line's content is unavailable.
That degradation is recorded rather than hidden: a positional ID detaches on any
line shift, and a caller is entitled to know that before trusting it.
"""

from __future__ import annotations

import hashlib
import unicodedata
from enum import StrEnum
from urllib.parse import unquote

from pydantic import BaseModel, ConfigDict, Field

from sift.models.sarif import Result, Run

#: Bump when the derivation changes, so old IDs are never mistaken for new ones.
CORRELATION_VERSION = "sift/v1"


class IdentitySource(StrEnum):
    """Which precedence tier produced the correlation ID."""

    PRIMARY_LOCATION_LINE_HASH = "primaryLocationLineHash"
    TOOL_FINGERPRINT = "toolFingerprint"
    CONTENT = "content"
    #: Degraded. No line content was available, so identity includes the line
    #: number and will detach when anything above the finding shifts.
    POSITIONAL = "positional"


class FindingRef(BaseModel):
    """One result, addressed within its file and identified across commits."""

    model_config = ConfigDict(frozen=True)

    correlation_id: str
    identity_source: IdentitySource
    run_index: int = Field(ge=0)
    result_index: int = Field(ge=0)
    rule_id: str | None = None
    uri: str | None = None
    start_line: int | None = None

    @property
    def stable(self) -> bool:
        """False when the ID will detach on an unrelated edit above the finding."""
        return self.identity_source is not IdentitySource.POSITIONAL


def normalize_path(uri: str) -> str:
    """Normalize an artifact URI for identity purposes.

    Percent-decoded, backslashes folded to forward slashes (Semgrep emits
    backslash URIs when run on Windows), leading ``./`` dropped, and Unicode
    normalized to NFC so that a composed and a decomposed ``é`` are one path.

    This is for *identity only*. It is not a safe path for reading files — that
    requires a repo-root containment check, which lands with the context builder.
    """
    decoded = unquote(uri).replace("\\", "/")
    while decoded.startswith("./"):
        decoded = decoded[2:]
    return unicodedata.normalize("NFC", decoded)


def normalize_line(source_line: str) -> str:
    """Normalize the flagged line's content.

    Trailing whitespace and line endings are stripped. **Leading whitespace is
    deliberately preserved.** Indentation is semantic in Python: a line dedented
    out of an ``if is_admin:`` guard is byte-identical after ``lstrip()`` while
    being a completely different security situation, and normalizing it away
    would let that edit inherit a stale dismissal.
    """
    return source_line.rstrip()


def _tool_scope(run: Run) -> str:
    """What distinguishes one run from another.

    Tool *name* but not version: including the version would detach every
    finding on a scanner upgrade. ``automationDetails.id`` separates multiple
    runs of the same tool over different languages or directories.

    Two runs that are genuinely indistinguishable produce the same scope, and so
    the same correlation ID. That is correct — they are the same finding
    reported twice, and deciding what to do about it is the pre-filter's job in
    P2, not ingest's.
    """
    details = getattr(run, "automationDetails", None) or (run.model_extra or {}).get(
        "automationDetails", {}
    )
    automation = details.get("id", "") if isinstance(details, dict) else ""
    return f"{run.tool.driver.name}\x00{automation}"


def _primary_location(result: Result) -> tuple[str | None, int | None, int | None]:
    """URI, start line, and start column of the result's first location."""
    if not result.locations:
        return None, None, None
    physical = result.locations[0].physical_location
    if physical is None:
        return None, None, None
    uri = physical.artifact_location.uri if physical.artifact_location else None
    region = physical.region
    return uri, (region.start_line if region else None), (region.start_column if region else None)


def _snippet_text(result: Result) -> str | None:
    """The flagged line's content, when the scanner included it."""
    if not result.locations:
        return None
    physical = result.locations[0].physical_location
    if physical is None or physical.region is None:
        return None
    snippet = physical.region.snippet
    text = snippet.get("text") if isinstance(snippet, dict) else None
    return text if isinstance(text, str) else None


def _digest(*parts: str) -> str:
    joined = "\x00".join(parts).encode("utf-8")
    return hashlib.sha256(joined).hexdigest()[:32]


def correlate(
    result: Result,
    *,
    run: Run,
    run_index: int,
    result_index: int,
    source_line: str | None = None,
) -> FindingRef:
    """Derive the correlation ID for one result.

    ``source_line`` is the verbatim content of the flagged line. Ingest does not
    read the repository, so it is normally ``None`` here and the snippet the
    scanner embedded is used instead. The context builder supplies the real line
    in P3, which upgrades a positional identity to a content one.
    """
    scope = _tool_scope(run)
    uri, start_line, start_column = _primary_location(result)
    rule_id = result.rule_id

    upstream = result.partial_fingerprints.get("primaryLocationLineHash")
    if upstream:
        return FindingRef(
            correlation_id=_digest(CORRELATION_VERSION, scope, upstream),
            identity_source=IdentitySource.PRIMARY_LOCATION_LINE_HASH,
            run_index=run_index,
            result_index=result_index,
            rule_id=rule_id,
            uri=uri,
            start_line=start_line,
        )

    if result.fingerprints:
        # Deterministic pick: sorted by key, so adding an unrelated fingerprint
        # later cannot silently change which one we keyed on.
        key, value = sorted(result.fingerprints.items())[0]
        return FindingRef(
            correlation_id=_digest(CORRELATION_VERSION, scope, key, value),
            identity_source=IdentitySource.TOOL_FINGERPRINT,
            run_index=run_index,
            result_index=result_index,
            rule_id=rule_id,
            uri=uri,
            start_line=start_line,
        )

    path = normalize_path(uri) if uri else ""
    column = str(start_column) if start_column is not None else ""
    line_text = source_line if source_line is not None else _snippet_text(result)

    if line_text is not None:
        # Content-based: survives insertions above the finding.
        return FindingRef(
            correlation_id=_digest(
                CORRELATION_VERSION, scope, rule_id or "", path, column, normalize_line(line_text)
            ),
            identity_source=IdentitySource.CONTENT,
            run_index=run_index,
            result_index=result_index,
            rule_id=rule_id,
            uri=uri,
            start_line=start_line,
        )

    # Degraded. Recorded, not hidden — this ID detaches on any line shift.
    return FindingRef(
        correlation_id=_digest(
            CORRELATION_VERSION, scope, rule_id or "", path, str(start_line or ""), column
        ),
        identity_source=IdentitySource.POSITIONAL,
        run_index=run_index,
        result_index=result_index,
        rule_id=rule_id,
        uri=uri,
        start_line=start_line,
    )
