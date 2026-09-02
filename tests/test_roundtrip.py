"""The lossless round-trip contract — decision D2.

Two layers. The corpus tests prove we survive what scanners actually emit and
the adversarial shapes they emit rarely. The Hypothesis tests prove we survive
shapes nobody has thought of yet, which is the half a fixed corpus cannot cover.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sift.canonical import canonical, canonical_equal, diff
from sift.emit.sarif import ResultCountError, check_lossless, to_document
from sift.ingest import SarifParseError, loads, parse

FIXTURES = Path(__file__).resolve().parents[1] / "evals" / "fixtures"
HANDCRAFTED = sorted((FIXTURES / "handcrafted").glob("*.sarif"))
GENERATED = sorted((FIXTURES / "generated").glob("*.sarif"))
CORPUS = HANDCRAFTED + GENERATED


def roundtrip(document: dict[str, Any]) -> dict[str, Any]:
    return to_document(parse(document))


def assert_lossless(document: dict[str, Any], label: str) -> None:
    emitted = roundtrip(document)
    if not canonical_equal(document, emitted):
        divergences = diff(document, emitted)
        listed = "\n  ".join(divergences[:20])
        more = f"\n  ... and {len(divergences) - 20} more" if len(divergences) > 20 else ""
        pytest.fail(f"{label} lost data:\n  {listed}{more}")
    check_lossless(document, emitted)


# --------------------------------------------------------------------- corpus


def test_corpus_is_not_empty() -> None:
    """Guard against the corpus silently vanishing and every test below passing."""
    assert HANDCRAFTED, "handcrafted fixtures are missing"


@pytest.mark.parametrize("path", CORPUS, ids=lambda p: p.name)
def test_corpus_roundtrips(path: Path) -> None:
    _, document = loads(path.read_bytes(), source=str(path))
    assert_lossless(document, path.name)


@pytest.mark.parametrize("path", CORPUS, ids=lambda p: p.name)
def test_corpus_survives_two_roundtrips(path: Path) -> None:
    """A second pass must be a fixed point.

    A transformation that is lossy but *idempotently* lossy would pass a single
    round trip against its own output. Comparing pass two against the original
    is what catches that.
    """
    _, document = loads(path.read_bytes(), source=str(path))
    once = roundtrip(document)
    twice = roundtrip(once)
    assert canonical_equal(document, twice), diff(document, twice)


@pytest.mark.parametrize("path", CORPUS, ids=lambda p: p.name)
def test_corpus_result_count_preserved(path: Path) -> None:
    _, document = loads(path.read_bytes(), source=str(path))
    emitted = roundtrip(document)
    before = [len(r.get("results", [])) for r in document.get("runs", [])]
    after = [len(r.get("results", [])) for r in emitted.get("runs", [])]
    assert before == after


# ------------------------------------------------------- the invariant itself


def test_dropping_a_result_is_caught() -> None:
    """The count check must actually fire. An assertion nobody tested is decoration."""
    source = {"runs": [{"results": [{"ruleId": "a"}, {"ruleId": "b"}]}]}
    emitted = {"runs": [{"results": [{"ruleId": "a"}]}]}
    with pytest.raises(ResultCountError):
        check_lossless(source, emitted)


def test_moving_a_result_between_runs_is_caught() -> None:
    """Per-run counts, so a move cannot hide inside an unchanged total."""
    source = {"runs": [{"results": [{"ruleId": "a"}, {"ruleId": "b"}]}, {"results": []}]}
    emitted = {"runs": [{"results": [{"ruleId": "a"}]}, {"results": [{"ruleId": "b"}]}]}
    with pytest.raises(ResultCountError):
        check_lossless(source, emitted)


# ------------------------------------------------------------ canonicalization


@pytest.mark.parametrize(
    ("left", "right", "equal"),
    [
        (8.0, 8, True),
        (1e3, 1000, True),
        ({"a": [1.0, 2.0]}, {"a": [1, 2]}, True),
        ("é", "é", True),
        (None, {}, False),
        (None, [], False),
        ({}, [], False),
        (True, 1, False),
        (False, 0, False),
        (0.1, 0.2, False),
        (9007199254740993, 9007199254740992, False),
    ],
    ids=[
        "integral-float-is-int",
        "exponent-form",
        "nested-integral-floats",
        "unicode-escape-equals-literal",
        "null-is-not-empty-object",
        "null-is-not-empty-list",
        "empty-object-is-not-empty-list",
        "true-is-not-one",
        "false-is-not-zero",
        "distinct-floats-stay-distinct",
        "beyond-2-53-not-collapsed",
    ],
)
def test_canonical_equality(left: Any, right: Any, equal: bool) -> None:
    assert canonical_equal(left, right) is equal


def test_negative_zero_is_preserved() -> None:
    """-0.0 is distinguishable from 0, so collapsing it would lose information."""
    assert isinstance(canonical(-0.0), float)
    assert str(canonical(-0.0)) == "-0.0"


def test_absent_key_is_not_a_null_key() -> None:
    """The distinction that a defaulted Pydantic model would quietly destroy."""
    absent = {"runs": [{"tool": {"driver": {"name": "t"}}, "results": [{"ruleId": "r"}]}]}
    explicit = {
        "runs": [{"tool": {"driver": {"name": "t"}}, "results": [{"ruleId": "r", "level": None}]}]
    }
    assert not canonical_equal(absent, explicit)
    assert "level" not in roundtrip({"version": "2.1.0", **absent})["runs"][0]["results"][0]
    assert roundtrip({"version": "2.1.0", **explicit})["runs"][0]["results"][0]["level"] is None


def test_absent_suppressions_are_not_materialized() -> None:
    """A result that never had `suppressions` must not come back carrying `[]`.

    This is the specific silent edit the exclude_unset rule exists to prevent.
    """
    document = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "t"}}, "results": [{"ruleId": "r"}]}],
    }
    result = roundtrip(document)["runs"][0]["results"][0]
    assert "suppressions" not in result
    assert "properties" not in result
    assert "locations" not in result


# ------------------------------------------------------------------ hypothesis

json_atoms = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53), max_value=2**53),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    st.text(max_size=40),
)

json_values = st.recursive(
    json_atoms,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(min_size=1, max_size=12), children, max_size=4),
    ),
    max_leaves=12,
)


@st.composite
def sarif_results(draw: st.DrawFn) -> dict[str, Any]:
    """A result carrying arbitrary unknown keys and optional known ones."""
    result: dict[str, Any] = {"message": {"text": draw(st.text(max_size=60))}}
    if draw(st.booleans()):
        result["ruleId"] = draw(st.text(min_size=1, max_size=30))
    if draw(st.booleans()):
        result["level"] = draw(st.sampled_from(["none", "note", "warning", "error", None]))
    if draw(st.booleans()):
        region: dict[str, Any] = {}
        if draw(st.booleans()):
            region["startLine"] = draw(st.integers(min_value=1, max_value=10_000))
        if draw(st.booleans()):
            region["startColumn"] = draw(st.integers(min_value=1, max_value=500))
        if draw(st.booleans()):
            region["snippet"] = {"text": draw(st.text(max_size=60))}
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": draw(st.text(min_size=1, max_size=40))},
                    **({"region": region} if region else {}),
                }
            }
        ]
    elif draw(st.booleans()):
        result["locations"] = []
    if draw(st.booleans()):
        result["suppressions"] = []
    if draw(st.booleans()):
        result["properties"] = draw(
            st.dictionaries(st.text(min_size=1, max_size=10), json_values, max_size=3)
        )
    if draw(st.booleans()):
        result["partialFingerprints"] = {"primaryLocationLineHash": draw(st.text(max_size=20))}
    # Unknown keys, which must survive untouched.
    for key, value in draw(
        st.dictionaries(
            st.text(min_size=1, max_size=10).filter(lambda s: s not in {"message", "ruleId"}),
            json_values,
            max_size=3,
        )
    ).items():
        result.setdefault(key, value)
    return result


@st.composite
def sarif_logs(draw: st.DrawFn) -> dict[str, Any]:
    runs = draw(
        st.lists(
            st.builds(
                lambda name, results, extra: {
                    "tool": {"driver": {"name": name}},
                    "results": results,
                    **extra,
                },
                st.text(min_size=1, max_size=20),
                st.lists(sarif_results(), max_size=4),
                st.dictionaries(st.text(min_size=1, max_size=10), json_values, max_size=2),
            ),
            min_size=0,
            max_size=3,
        )
    )
    log: dict[str, Any] = {"version": "2.1.0", "runs": runs}
    # setdefault, not update: an arbitrary extra key named "runs" would otherwise
    # clobber the runs array. Hypothesis found exactly that, generating
    # {"version": "2.1.0", "runs": None} — which ingest correctly refuses, so the
    # strategy was wrong rather than the parser. Refusal is covered separately by
    # test_malformed_input_is_refused.
    for key, value in draw(
        st.dictionaries(
            st.text(min_size=1, max_size=10).filter(lambda s: s not in {"version", "runs"}),
            json_values,
            max_size=2,
        )
    ).items():
        log.setdefault(key, value)
    return log


@given(sarif_logs())
@settings(max_examples=250, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_arbitrary_sarif_roundtrips(document: dict[str, Any]) -> None:
    emitted = to_document(parse(document))
    assert canonical_equal(document, emitted), diff(document, emitted)
    check_lossless(document, emitted)


@given(sarif_logs())
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_arbitrary_sarif_survives_serialization(document: dict[str, Any]) -> None:
    """Through real bytes, not just Python objects.

    Object-level equality would not catch an encoder that mangles unicode or
    reformats a number on the way to disk.
    """
    emitted = to_document(parse(document))
    text = json.dumps(emitted, indent=2, ensure_ascii=False)
    assert canonical_equal(document, json.loads(text))


# -------------------------------------------------------- refusing bad input


@pytest.mark.parametrize(
    ("document", "reason"),
    [
        ({"version": "2.1.0", "runs": None}, "runs is null"),
        ({"version": "2.1.0"}, "runs is absent"),
        ({"runs": []}, "version is absent"),
        ({"version": "2.0.0", "runs": []}, "unsupported version"),
        ({"version": "3.0.0", "runs": []}, "future version"),
        ({"version": "2.1.0", "runs": [{}]}, "run has no tool"),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_malformed_input_is_refused(document: dict[str, Any], reason: str) -> None:
    """Refuse loudly rather than recover quietly.

    A SARIF file is untrusted input. A tool that silently repairs a malformed
    one goes on to analyze something the user never wrote, and reports on it
    with full confidence.
    """
    with pytest.raises(SarifParseError):
        parse(document)


@pytest.mark.parametrize(
    "payload",
    [b"", b"not json", b"[]", b'"a string"', b"null", b"\xff\xfe\x00bad utf-8"],
    ids=["empty", "not-json", "top-level-array", "top-level-string", "top-level-null", "bad-utf8"],
)
def test_unparseable_bytes_are_refused(payload: bytes) -> None:
    with pytest.raises(SarifParseError):
        loads(payload)


def test_utf8_bom_is_tolerated() -> None:
    """Some tools emit a BOM. That is not a reason to reject an otherwise good file."""
    document = {"version": "2.1.0", "runs": []}
    log, raw = loads(("﻿" + json.dumps(document)).encode("utf-8"))
    assert raw == document
    assert log.runs == []
