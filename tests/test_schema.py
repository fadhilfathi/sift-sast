"""Validation against the official SARIF 2.1.0 JSON schema.

The schema is vendored at `tests/schema/` so this runs offline and a network
outage cannot quietly turn the check into a skip.

The property that matters is not "every fixture validates" — some deliberately
do not. It is **round-tripping a valid document must leave it valid, and must
never add a violation to an invalid one.**
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft4Validator

from sift.emit.sarif import to_document
from sift.ingest import loads, parse
from tests.test_roundtrip import CORPUS, GENERATED

SCHEMA_PATH = Path(__file__).resolve().parent / "schema" / "sarif-schema-2.1.0.json"

#: Fixtures that intentionally violate the schema, and why. Each is still
#: covered by the round-trip test — losslessness is our contract, and
#: schema-validity is the document author's.
KNOWN_INVALID = {
    "absent-null-empty.sarif": (
        "Explicit JSON nulls where the schema requires a string or integer. "
        "Deliberate: absent, null, and empty are three distinct states and the "
        "round-trip must preserve which one it was given."
    ),
    "vendor-extensions.sarif": (
        "Unknown keys outside the `properties` bag. The schema sets "
        "additionalProperties: false, but real tools emit vendor keys anyway, so "
        "we must round-trip them. This is why SIFT writes its own data into "
        "`properties` and nowhere else."
    ),
}


@pytest.fixture(scope="session")
def validator() -> Draft4Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft4Validator(schema)


def violations(validator: Draft4Validator, document: dict[str, Any]) -> list[str]:
    return [
        "/" + "/".join(str(p) for p in error.absolute_path) + ": " + error.message
        for error in sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))
    ]


def test_schema_is_vendored() -> None:
    """A missing schema must fail, not silently skip every check below."""
    assert SCHEMA_PATH.is_file(), f"vendored SARIF schema missing at {SCHEMA_PATH}"


@pytest.mark.parametrize("path", GENERATED, ids=lambda p: p.name)
def test_real_scanner_output_is_schema_valid(path: Path, validator: Draft4Validator) -> None:
    """Every fixture produced by a real scanner validates.

    If this ever fails it is a genuine upstream deviation: record it in
    evals/fixtures/SCHEMA_DEVIATIONS.md with the tool version and add it to
    KNOWN_INVALID. Do not edit the fixture to make it pass.
    """
    document = json.loads(path.read_text(encoding="utf-8"))
    assert violations(validator, document) == []


@pytest.mark.parametrize("path", CORPUS, ids=lambda p: p.name)
def test_roundtrip_introduces_no_new_violations(path: Path, validator: Draft4Validator) -> None:
    """The real property. A valid document stays valid; an invalid one gets no worse.

    Stated as a comparison rather than as "output is valid" so the deliberately
    invalid fixtures are still meaningfully tested instead of skipped.
    """
    _, document = loads(path.read_bytes(), source=str(path))
    before = violations(validator, document)
    after = violations(validator, to_document(parse(document)))
    assert after == before, (
        f"{path.name}: round trip changed schema violations\n"
        f"  before ({len(before)}): {before[:5]}\n"
        f"  after  ({len(after)}): {after[:5]}"
    )


@pytest.mark.parametrize("name", sorted(KNOWN_INVALID), ids=sorted(KNOWN_INVALID))
def test_known_invalid_fixtures_are_still_invalid(name: str, validator: Draft4Validator) -> None:
    """Keeps the exclusion list honest.

    If a fixture starts validating, the exclusion is stale and must be removed
    rather than left as a permanent unexplained carve-out.
    """
    path = next(p for p in CORPUS if p.name == name)
    document = json.loads(path.read_text(encoding="utf-8"))
    assert violations(validator, document), (
        f"{name} now validates; remove it from KNOWN_INVALID and from "
        f"evals/fixtures/SCHEMA_DEVIATIONS.md"
    )


def test_no_undeclared_invalid_fixtures(validator: Draft4Validator) -> None:
    """Nothing may fail the schema without being written down."""
    undeclared = [
        p.name
        for p in CORPUS
        if p.name not in KNOWN_INVALID
        and violations(validator, json.loads(p.read_text(encoding="utf-8")))
    ]
    assert undeclared == [], (
        f"undeclared schema violations in {undeclared}. Record each in "
        f"evals/fixtures/SCHEMA_DEVIATIONS.md with the tool version, then add it "
        f"to KNOWN_INVALID. Never edit a fixture to make it validate."
    )
