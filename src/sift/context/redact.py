"""Secret detection and redaction — decision D8.

Preserve kind, length, and a bucketed entropy class. Destroy the value,
unconditionally and irreversibly. No hash, no prefix, no suffix — see the
rationale in `docs/ARCHITECTURE.md`.

A small set of hand-rolled patterns, not a new dependency: this is
defense-in-depth for the bundle, not a secrets-scanning product. False
negatives on exotic formats are accepted; false positives (redacting
something benign) are the safe failure direction and are also accepted.
"""

from __future__ import annotations

import re

from sift.models.context import (
    CodeSpan,
    EntropyClass,
    RedactedSecret,
    SecretKind,
    entropy_class,
    format_secret_placeholder,
)
from sift.models.verdict import FileLineRef

#: Ordered by specificity. A generic fallback runs last and only over quoted
#: string content that a specific pattern above did not already claim.
_SPECIFIC_PATTERNS: tuple[tuple[SecretKind, re.Pattern[str]], ...] = (
    (
        SecretKind.PRIVATE_KEY_PEM,
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
            r".*?"
            r"-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    (SecretKind.AWS_ACCESS_KEY, re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        SecretKind.JWT,
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ),
    (
        SecretKind.CONNECTION_STRING,
        re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:@'\"]+:[^\s@'\"]+@[^\s'\"]+"),
    ),
)

#: Quoted string literals long enough to plausibly be a secret. Only redacted
#: if their content is HIGH entropy (see `find_secrets`) — a long ordinary
#: sentence in a string is common and must not be destroyed on length alone.
_GENERIC_STRING = re.compile(r'"([^"\n]{16,200})"|\'([^\'\n]{16,200})\'')

#: (start byte offset, end byte offset, kind) for one detected secret.
Match = tuple[int, int, SecretKind]


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return not (a[1] <= b[0] or b[1] <= a[0])


def find_secrets(text: str) -> list[Match]:
    """Every secret-shaped span in `text`, as (start, end, kind) byte offsets.

    Specific patterns run first, in priority order; the generic high-entropy
    fallback only considers quoted-string content none of them already
    claimed, and only keeps it if the content itself buckets HIGH.
    """
    found: list[Match] = []
    for kind, pattern in _SPECIFIC_PATTERNS:
        for m in pattern.finditer(text):
            span = (m.start(), m.end())
            if not any(_overlaps(span, (s, e)) for s, e, _ in found):
                found.append((*span, kind))

    for m in _GENERIC_STRING.finditer(text):
        group = 1 if m.group(1) is not None else 2
        start, end = m.span(group)
        if any(_overlaps((start, end), (s, e)) for s, e, _ in found):
            continue
        content = m.group(group)
        if content and entropy_class(content) is EntropyClass.HIGH:
            found.append((start, end, SecretKind.GENERIC_HIGH_ENTROPY))

    return sorted(found, key=lambda t: t[0])


def redact_text(text: str) -> tuple[str, list[tuple[Match, str]]]:
    """Replace every detected secret with its placeholder.

    Returns the redacted text and, for each match, the matched value paired
    with its own span — the value is returned here only so the caller can
    compute length and entropy once; it must not be threaded any further.
    """
    matches = find_secrets(text)
    if not matches:
        return text, []

    pieces: list[str] = []
    cursor = 0
    resolved: list[tuple[Match, str]] = []
    for start, end, kind in matches:
        pieces.append(text[cursor:start])
        value = text[start:end]
        pieces.append(format_secret_placeholder(kind, len(value), entropy_class(value)))
        resolved.append(((start, end, kind), value))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces), resolved


def redact_span(span: CodeSpan) -> tuple[CodeSpan, list[RedactedSecret]]:
    """Redact every secret-shaped value out of a `CodeSpan`.

    Returns a new span (spans are frozen) and the `RedactedSecret` records for
    it, each carrying the real `FileLineRef` the match fell on within the span.
    """
    new_source, resolved = redact_text(span.source)
    if not resolved:
        return span, []

    secrets = []
    for (start, _end, kind), value in resolved:
        line = span.start_line + span.source.count("\n", 0, start)
        secrets.append(
            RedactedSecret(
                kind=kind,
                length=len(value),
                entropy_class=entropy_class(value),
                location=FileLineRef(path=span.path, line=line),
            )
        )
    return span.model_copy(update={"source": new_source}), secrets
