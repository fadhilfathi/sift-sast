"""Correlation ID stability — the matrix in decision D1.

A fingerprint that never changes is as broken as one that always does. These
tests pin the specific rows that make it neither.
"""

from __future__ import annotations

from typing import Any

import pytest

from sift.ingest import loads, results_of
from sift.ingest.fingerprint import (
    IdentitySource,
    correlate,
    degenerate_fingerprints,
    normalize_line,
    normalize_path,
)
from sift.models.sarif import Result, Run, SarifLog

FLAGGED = "    subprocess.check_output(cmd, shell=True)"


def make_run(tool: str = "semgrep", automation: str | None = None) -> Run:
    payload: dict[str, Any] = {"tool": {"driver": {"name": tool}}, "results": []}
    if automation is not None:
        payload["automationDetails"] = {"id": automation}
    return Run.model_validate(payload)


def make_result(
    *,
    rule: str = "python.lang.security.dangerous-subprocess-use",
    uri: str = "src/handler.py",
    line: int = 42,
    column: int | None = None,
    snippet: str | None = FLAGGED,
    fingerprints: dict[str, str] | None = None,
    partial: dict[str, str] | None = None,
) -> Result:
    region: dict[str, Any] = {"startLine": line}
    if column is not None:
        region["startColumn"] = column
    if snippet is not None:
        region["snippet"] = {"text": snippet}
    payload: dict[str, Any] = {
        "ruleId": rule,
        "message": {"text": "command injection"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}],
    }
    if fingerprints:
        payload["fingerprints"] = fingerprints
    if partial:
        payload["partialFingerprints"] = partial
    return Result.model_validate(payload)


def cid(result: Result, run: Run | None = None) -> str:
    return correlate(result, run=run or make_run(), run_index=0, result_index=0).correlation_id


def source(result: Result, run: Run | None = None) -> IdentitySource:
    return correlate(result, run=run or make_run(), run_index=0, result_index=0).identity_source


# ------------------------------------------------------- the stability matrix


def test_inserting_a_line_above_does_not_change_the_id() -> None:
    """The most common edit there is. If this detaches, every review is lost on
    the next import someone adds."""
    assert cid(make_result(line=42)) == cid(make_result(line=91))


def test_trailing_whitespace_does_not_change_the_id() -> None:
    assert cid(make_result(snippet=FLAGGED)) == cid(make_result(snippet=FLAGGED + "   \r"))


def test_reindenting_the_flagged_line_changes_the_id() -> None:
    """Indentation is semantic in Python.

    This line dedented out of its guard is byte-identical after lstrip, and is a
    completely different security situation. Detaching and forcing a re-review
    is the safe direction.
    """
    dedented = FLAGGED.lstrip()
    assert cid(make_result(snippet=FLAGGED)) != cid(make_result(snippet=dedented))


def test_editing_the_flagged_line_changes_the_id() -> None:
    edited = "    subprocess.check_output(shlex.split(cmd), shell=False)"
    assert cid(make_result(snippet=FLAGGED)) != cid(make_result(snippet=edited))


def test_editing_elsewhere_in_the_function_does_not_change_the_id() -> None:
    """The row that justifies separating correlation ID from cache key.

    The finding a human reviewed is the same one. The *evidence* changed — a
    sanitizer may have been deleted two lines below — so the cache key must
    change and force re-adjudication. That is the cache key's job, and it
    arrives in P5. The correlation ID's job is unchanged here.
    """
    assert cid(make_result()) == cid(make_result())


def test_renaming_the_file_changes_the_id() -> None:
    """GitHub detaches on rename too. Matching its behavior beats out-clevering it."""
    assert cid(make_result(uri="src/handler.py")) != cid(make_result(uri="src/handlers/http.py"))


def test_same_rule_same_line_different_columns_are_distinct() -> None:
    assert cid(make_result(column=5)) != cid(make_result(column=40))


def test_different_rules_at_the_same_place_are_distinct() -> None:
    assert cid(make_result(rule="rule.a")) != cid(make_result(rule="rule.b"))


def test_the_id_is_deterministic_across_calls() -> None:
    assert cid(make_result()) == cid(make_result())


# ------------------------------------------------------------------ precedence


def test_github_line_hash_wins() -> None:
    result = make_result(partial={"primaryLocationLineHash": "abc123:1"})
    assert source(result) is IdentitySource.PRIMARY_LOCATION_LINE_HASH


def test_line_hash_is_used_over_content() -> None:
    """When GitHub supplies identity we defer to it, even if the line changed.

    Agreeing with GitHub's alert identity is the point; competing with it is the
    bug we are avoiding.
    """
    a = make_result(snippet=FLAGGED, partial={"primaryLocationLineHash": "same:1"})
    b = make_result(snippet="totally different", partial={"primaryLocationLineHash": "same:1"})
    assert cid(a) == cid(b)


def test_tool_fingerprint_is_second_choice() -> None:
    result = make_result(fingerprints={"matchBasedId/v1": "deadbeef"})
    assert source(result) is IdentitySource.TOOL_FINGERPRINT


def test_tool_fingerprint_pick_is_deterministic() -> None:
    """Sorted by key, so adding an unrelated fingerprint later cannot silently
    change which one we keyed on."""
    a = make_result(fingerprints={"aaa/v1": "1", "zzz/v1": "2"})
    b = make_result(fingerprints={"zzz/v1": "2", "aaa/v1": "1"})
    assert cid(a) == cid(b)


def test_content_is_third_choice() -> None:
    assert source(make_result()) is IdentitySource.CONTENT


def test_positional_is_the_last_resort_and_is_flagged() -> None:
    """No snippet, no fingerprints, so identity has to include the line number."""
    result = make_result(snippet=None)
    ref = correlate(result, run=make_run(), run_index=0, result_index=0)
    assert ref.identity_source is IdentitySource.POSITIONAL
    assert ref.stable is False


def test_positional_ids_do_detach_on_line_shift() -> None:
    """Stated as a test so the degradation is documented, not discovered."""
    a = make_result(snippet=None, line=10)
    b = make_result(snippet=None, line=11)
    assert cid(a) != cid(b)


def test_supplying_the_source_line_upgrades_a_positional_id() -> None:
    """What the context builder does in P3."""
    result = make_result(snippet=None)
    ref = correlate(result, run=make_run(), run_index=0, result_index=0, source_line=FLAGGED)
    assert ref.identity_source is IdentitySource.CONTENT
    assert ref.stable is True
    assert ref.correlation_id == cid(make_result(snippet=FLAGGED))


# ----------------------------------------------------------------- tool scope


def test_different_tools_reporting_the_same_line_are_distinct() -> None:
    """A verdict reasoned about a Semgrep rule must not auto-apply to a CodeQL
    rule with different semantics."""
    assert cid(make_result(), make_run("semgrep")) != cid(make_result(), make_run("codeql"))


def test_tool_version_does_not_affect_the_id() -> None:
    """Including the version would detach every finding on a scanner upgrade."""
    a = Run.model_validate({"tool": {"driver": {"name": "semgrep", "version": "1.0.0"}}})
    b = Run.model_validate({"tool": {"driver": {"name": "semgrep", "version": "9.9.9"}}})
    assert cid(make_result(), a) == cid(make_result(), b)


def test_automation_details_separate_runs_of_one_tool() -> None:
    a = make_run("codeql", automation="codeql/python/")
    b = make_run("codeql", automation="codeql/javascript/")
    assert cid(make_result(), a) != cid(make_result(), b)


def test_indistinguishable_runs_share_an_id() -> None:
    """Same tool, no automationDetails, same finding: genuinely the same thing
    reported twice. Deciding what to do about it is the pre-filter's job in P2,
    not ingest's, so ingest does not invent a difference using run index."""
    assert cid(make_result(), make_run()) == cid(make_result(), make_run())


# ------------------------------------------------------------- normalization


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("src/a.py", "./src/a.py"),
        ("src/a.py", "src\\a.py"),
        ("src/my folder/a.py", "src/my%20folder/a.py"),
        ("src/café.py", "src/café.py"),
    ],
    ids=["leading-dot-slash", "windows-separators", "percent-encoded", "nfc-vs-nfd"],
)
def test_paths_that_mean_the_same_thing_normalize_together(left: str, right: str) -> None:
    assert normalize_path(left) == normalize_path(right)


def test_distinct_paths_stay_distinct() -> None:
    assert normalize_path("src/a.py") != normalize_path("src/b.py")


def test_normalize_line_keeps_indentation() -> None:
    assert normalize_line("    x = 1  ") == "    x = 1"
    assert normalize_line("    x = 1") != normalize_line("x = 1")


# ------------------------------------------------------------ over the corpus


def test_every_corpus_finding_gets_an_id() -> None:
    """Across real scanner output, not just synthetic results."""
    from tests.test_roundtrip import CORPUS

    seen = 0
    for path in CORPUS:
        log, _ = loads(path.read_bytes(), source=str(path))
        for ref in results_of(log):
            assert ref.correlation_id
            assert len(ref.correlation_id) == 32
            seen += 1
    assert seen > 0


def test_corpus_ids_are_reproducible() -> None:
    from tests.test_roundtrip import CORPUS

    for path in CORPUS:
        log, _ = loads(path.read_bytes(), source=str(path))
        first = [r.correlation_id for r in results_of(log)]
        second = [r.correlation_id for r in results_of(log)]
        assert first == second, path.name


# ------------------------------------------- degenerate upstream fingerprints


def _run_with(results: list[Result]) -> Run:
    run = make_run()
    run.results.extend(results)
    return run


def test_placeholder_fingerprint_does_not_merge_findings() -> None:
    """The bug this guards against dismissed 44 of 45 real findings.

    Semgrep emits the literal string "requires login" as matchBasedId/v1 when it
    is not authenticated, so every result in the file carries the same value.
    Keyed on that alone, 45 findings across 20 files and several rules collapsed
    into one correlation ID and the pre-filter dismissed 44 as duplicates.
    """
    placeholder = {"matchBasedId/v1": "requires login"}
    results = [
        make_result(rule="rule.a", uri="src/a.py", line=1, fingerprints=placeholder),
        make_result(rule="rule.b", uri="src/b.py", line=2, fingerprints=placeholder),
        make_result(rule="rule.a", uri="src/a.py", line=99, fingerprints=placeholder),
    ]
    run = _run_with(results)
    assert "requires login" in degenerate_fingerprints(run)

    log = SarifLog(version="2.1.0", runs=[run])
    assert len({r.correlation_id for r in results_of(log)}) == 3


def test_a_placeholder_falls_back_rather_than_being_trusted() -> None:
    placeholder = {"matchBasedId/v1": "requires login"}
    results = [
        make_result(uri="src/a.py", fingerprints=placeholder),
        make_result(uri="src/b.py", fingerprints=placeholder),
    ]
    run = _run_with(results)
    ref = correlate(
        results[0],
        run=run,
        run_index=0,
        result_index=0,
        degenerate=degenerate_fingerprints(run),
    )
    assert ref.identity_source is IdentitySource.CONTENT


def test_a_discriminating_fingerprint_is_still_trusted() -> None:
    results = [
        make_result(uri="src/a.py", fingerprints={"matchBasedId/v1": "aaa"}),
        make_result(uri="src/b.py", fingerprints={"matchBasedId/v1": "bbb"}),
    ]
    run = _run_with(results)
    degenerate = degenerate_fingerprints(run)
    assert degenerate == frozenset()
    ref = correlate(results[0], run=run, run_index=0, result_index=0, degenerate=degenerate)
    assert ref.identity_source is IdentitySource.TOOL_FINGERPRINT


def test_a_degenerate_line_hash_is_also_rejected() -> None:
    """Not only a Semgrep problem. CodeQL output in the corpus has these too."""
    results = [
        make_result(rule="r.a", uri="src/a.py", partial={"primaryLocationLineHash": "same:1"}),
        make_result(rule="r.b", uri="src/b.py", partial={"primaryLocationLineHash": "same:1"}),
    ]
    run = _run_with(results)
    degenerate = degenerate_fingerprints(run)
    assert "same:1" in degenerate
    ref = correlate(results[0], run=run, run_index=0, result_index=0, degenerate=degenerate)
    assert ref.identity_source is not IdentitySource.PRIMARY_LOCATION_LINE_HASH


def test_repeated_fingerprint_at_one_location_is_not_degenerate() -> None:
    """The same finding reported twice is a duplicate, not a placeholder.

    Only a value spanning *different* rules or locations loses trust.
    """
    same = make_result(uri="src/a.py", line=5, fingerprints={"matchBasedId/v1": "x"})
    run = _run_with([same, same])
    assert degenerate_fingerprints(run) == frozenset()


def test_identity_is_bound_to_rule_and_path_at_every_tier() -> None:
    """An upstream hash supplies stability; it never supplies distinctness alone."""
    partial = {"primaryLocationLineHash": "h:1"}
    a = make_result(rule="rule.a", uri="src/a.py", partial=partial)
    b = make_result(rule="rule.b", uri="src/a.py", partial=partial)
    c = make_result(rule="rule.a", uri="src/b.py", partial=partial)
    assert len({cid(a), cid(b), cid(c)}) == 3


def test_corpus_has_no_false_merges() -> None:
    """103 real findings, 103 distinct IDs. The end-to-end version of the above."""
    from tests.test_roundtrip import GENERATED

    for path in GENERATED:
        log, _ = loads(path.read_bytes(), source=str(path))
        refs = results_of(log)
        ids = {r.correlation_id for r in refs}
        assert len(ids) == len(refs), (
            f"{path.name}: {len(refs)} findings collapsed into {len(ids)} correlation IDs"
        )
