"""SARIF emitter.

In P1 this is pure passthrough: parse in, write out, nothing added. Verdicts,
suppressions, and the ``sift/v1`` properties bag arrive in P5.

The result-count invariant below is written now, while there is nothing to
suppress, precisely so the code that later *does* attach suppressions was never
shaped around being able to filter.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sift.canonical import dumps
from sift.models.sarif import SarifLog


class ResultCountError(AssertionError):
    """The emitter would have changed how many findings exist.

    Never recoverable. A finding is never deleted — suppression is a labeled
    annotation carrying a justification. If this fires, the bug is upstream of
    here and the run must stop rather than write a document that quietly lost
    someone's vulnerability.
    """


def to_document(log: SarifLog) -> dict[str, Any]:
    """Render the model back to a plain JSON document.

    ``exclude_unset`` is what preserves the absent / ``null`` / empty
    distinction. Without it Pydantic materializes defaults, and a result that
    never carried a ``suppressions`` key comes back carrying ``[]`` — a silent
    edit to someone else's document.

    ``by_alias`` restores SARIF's camelCase spelling.
    """
    document = log.model_dump(by_alias=True, exclude_unset=True, mode="json")
    if not isinstance(document, dict):  # pragma: no cover - model_dump on a model
        raise TypeError("SARIF log did not serialize to an object")
    return document


def check_lossless(source: dict[str, Any], emitted: dict[str, Any]) -> None:
    """Fail if the emitter changed how many findings exist.

    Checks per run rather than in total, so moving a result between runs cannot
    hide inside an unchanged grand total.
    """
    before = [len(run.get("results", [])) for run in source.get("runs", [])]
    after = [len(run.get("results", [])) for run in emitted.get("runs", [])]
    if before != after:
        raise ResultCountError(f"result counts changed per run: {before} -> {after}")


def dump(log: SarifLog, *, source: dict[str, Any] | None = None) -> str:
    """Serialize a SARIF log to text.

    Pass ``source`` — the raw parsed input — to assert the count invariant.
    """
    document = to_document(log)
    if source is not None:
        check_lossless(source, document)
    return dumps(document) + "\n"


def write(log: SarifLog, path: Path, *, source: dict[str, Any] | None = None) -> int:
    """Write SARIF to disk. Returns bytes written."""
    text = dump(log, source=source)
    path.write_text(text, encoding="utf-8", newline="\n")
    return len(text.encode("utf-8"))
