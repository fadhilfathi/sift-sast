"""SARIF ingest. Parse, and derive a correlation ID per finding.

No filtering happens here. Ingest returns every result the file contained; the
count that goes out equals the count that came in. Stage 1 labels, it does not
delete, and ingest does not get to pre-empt that.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from sift.ingest.fingerprint import FindingRef, correlate
from sift.models.sarif import SarifLog

__all__ = ["FindingRef", "SarifParseError", "load", "loads", "parse", "results_of"]


class SarifParseError(ValueError):
    """The input is not usable SARIF.

    Raised loudly and early. A SARIF file is untrusted input, and a tool that
    quietly recovers from a malformed one will quietly analyze the wrong thing.
    """


def load(path: Path) -> tuple[SarifLog, dict[str, Any]]:
    """Parse a SARIF file.

    Returns the typed log *and* the raw parsed document. The raw document is the
    reference for round-trip comparison — comparing a model against itself would
    prove nothing about whether the model lost a key.
    """
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise SarifParseError(f"cannot read {path}: {exc}") from exc
    return loads(raw_bytes, source=str(path))


def loads(data: bytes | str, *, source: str = "<bytes>") -> tuple[SarifLog, dict[str, Any]]:
    """Parse SARIF from bytes or text."""
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8-sig")  # tolerate a BOM; some tools emit one
        except UnicodeDecodeError as exc:
            raise SarifParseError(f"{source} is not valid UTF-8: {exc}") from exc
    try:
        document = json.loads(data)
    except json.JSONDecodeError as exc:
        raise SarifParseError(f"{source} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        kind = type(document).__name__
        raise SarifParseError(f"{source}: top level must be an object, got {kind}")
    return parse(document, source=source), document


def parse(document: dict[str, Any], *, source: str = "<dict>") -> SarifLog:
    """Validate a parsed JSON document into the SARIF model."""
    version = document.get("version")
    if version != "2.1.0":
        # Refuse rather than guess. Emitting SARIF we did not really understand
        # is how a finding silently changes shape on the way through.
        raise SarifParseError(f"{source}: expected SARIF version 2.1.0, got {version!r}")
    if "runs" not in document:
        # `runs` has a list default on the model, so without this check a
        # truncated or malformed file parses cleanly into an empty log and the
        # run reports zero findings. On a security tool that reads as "nothing
        # to see here", which is the worst possible way to fail.
        raise SarifParseError(f"{source}: no 'runs' key; refusing to treat it as zero findings")
    try:
        return SarifLog.model_validate(document)
    except ValidationError as exc:
        raise SarifParseError(f"{source}: does not match SARIF 2.1.0: {exc}") from exc


def results_of(log: SarifLog) -> list[FindingRef]:
    """Every result in the log, with its run index and correlation ID.

    Flattened across runs, because a result only means something together with
    the run that produced it — two runs may report the same rule at the same
    line and those are two findings, not one.
    """
    return [
        correlate(result, run=run, run_index=run_index, result_index=result_index)
        for run_index, run in enumerate(log.runs)
        for result_index, result in enumerate(run.results)
    ]
