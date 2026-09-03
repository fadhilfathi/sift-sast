"""Stage 1 — dedupe, classification, and the disposition policy.

The load-bearing assertions are the ones about *not* acting: nothing is dropped,
and no file class dismisses a finding unless a caller explicitly asked for it.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from sift.ingest import loads, results_of
from sift.ingest.fingerprint import FindingRef, IdentitySource
from sift.models.context import FileClass
from sift.prefilter import SAFE_TO_RESOLVE, Disposition, run
from sift.prefilter.classify import classify
from tests.test_roundtrip import CORPUS, GENERATED


def ref(correlation_id: str, uri: str = "src/app.py", run_index: int = 0, i: int = 0) -> FindingRef:
    return FindingRef(
        correlation_id=correlation_id,
        identity_source=IdentitySource.CONTENT,
        run_index=run_index,
        result_index=i,
        rule_id="r",
        uri=uri,
        start_line=1,
    )


# ------------------------------------------------------------ never drop


def test_every_finding_that_enters_leaves() -> None:
    refs = [ref("a"), ref("a", i=1), ref("b", i=2), ref("a", i=3)]
    report = run(refs)
    assert report.total == 4
    assert len(report.decisions) == 4


@pytest.mark.parametrize("path", CORPUS, ids=lambda p: p.name)
def test_corpus_finding_count_is_preserved(path: Path) -> None:
    log, _ = loads(path.read_bytes(), source=str(path))
    refs = results_of(log)
    assert len(run(refs).decisions) == len(refs)


def test_every_decision_carries_a_label_and_a_justification() -> None:
    """A resolution with no stated reason is indistinguishable from a deletion."""
    for decision in run([ref("a"), ref("a", i=1), ref("b", "tests/test_x.py", i=2)]).decisions:
        assert decision.resolved_by
        assert decision.justification
        assert len(decision.justification) > 20


# ------------------------------------------------------------------ dedupe


def test_exact_duplicates_are_deduplicated() -> None:
    report = run([ref("a"), ref("a", i=1), ref("a", i=2)])
    dispositions = [d.disposition for d in report.decisions]
    assert dispositions == [
        Disposition.ADJUDICATE,
        Disposition.DEDUPLICATED,
        Disposition.DEDUPLICATED,
    ]
    assert report.duplicates_removed == 2


def test_the_first_occurrence_is_the_survivor() -> None:
    report = run([ref("a"), ref("a", i=1)])
    assert report.decisions[1].duplicate_of == "a"
    assert "run 0, result 0" in report.decisions[1].justification


def test_distinct_findings_are_not_merged() -> None:
    report = run([ref("a"), ref("b", i=1), ref("c", i=2)])
    assert report.duplicates_removed == 0
    assert report.adjudicate_count == 3


def test_cross_run_overlap_is_reported_not_merged() -> None:
    """Two tools agreeing is a signal, not a duplicate.

    Correlation IDs are tool-scoped, so this only happens for the same tool in
    two runs. It is counted so the number is visible, and left alone.
    """
    report = run([ref("a", run_index=0), ref("a", run_index=1, i=0)])
    assert report.cross_run_overlap == 1


# ------------------------------------------------- the policy that matters


def test_no_class_dismisses_a_finding_by_default() -> None:
    """The core safety property of this stage.

    Test, vendored, generated, and fixture files all reach adjudication unless a
    caller opts in. Each can hold a real vulnerability, and a dismissal here has
    no model and no human in the loop to catch it.
    """
    assert frozenset() == SAFE_TO_RESOLVE
    refs = [
        ref("a", "tests/test_login.py"),
        ref("b", "node_modules/lib/index.js", i=1),
        ref("c", "src/api_pb2.py", i=2),
        ref("d", "tests/fixtures/key.pem", i=3),
        ref("e", "src/app.py", i=4),
    ]
    report = run(refs)
    assert report.adjudicate_count == 5
    assert report.resolved_without_a_model == 0.0
    assert all(d.disposition is Disposition.ADJUDICATE for d in report.decisions)


def test_classification_is_still_attached_when_it_does_not_dismiss() -> None:
    report = run([ref("a", "tests/test_login.py"), ref("b", "node_modules/x.js", i=1)])
    assert report.decisions[0].file_class is FileClass.TEST
    assert report.decisions[1].file_class is FileClass.VENDORED


def test_opting_in_resolves_that_class_only() -> None:
    refs = [ref("a", "node_modules/x.js"), ref("b", "tests/test_y.py", i=1), ref("c", i=2)]
    report = run(refs, resolve_classes=frozenset({FileClass.VENDORED}))
    assert report.decisions[0].disposition is Disposition.RESOLVED
    assert report.decisions[0].resolved_by == "prefilter:vendored"
    assert report.decisions[1].disposition is Disposition.ADJUDICATE
    assert report.decisions[2].disposition is Disposition.ADJUDICATE


def test_resolvable_by_class_reports_without_acting() -> None:
    """The number that turns the policy choice into an informed one."""
    refs = [
        ref("a", "tests/test_x.py"),
        ref("b", "tests/test_y.py", i=1),
        ref("c", "node_modules/z.js", i=2),
        ref("d", "src/app.py", i=3),
    ]
    report = run(refs)
    assert report.resolvable_by_class == {"TEST": 2, "VENDORED": 1}
    assert report.adjudicate_count == 4  # reported, not acted on


# -------------------------------------------------------------- classifier


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("node_modules/lodash/index.js", FileClass.VENDORED),
        ("vendor/github.com/pkg/errors/errors.go", FileClass.VENDORED),
        ("third_party/zlib/zlib.c", FileClass.VENDORED),
        (".venv/lib/python3.12/site-packages/x.py", FileClass.VENDORED),
        ("tests/test_login.py", FileClass.TEST),
        ("src/handler_test.go", FileClass.TEST),
        ("web/components/Button.test.tsx", FileClass.TEST),
        ("web/components/Button.spec.ts", FileClass.TEST),
        ("src/java/com/x/FooTest.java", FileClass.TEST),
        ("conftest.py", FileClass.TEST),
        ("tests/fixtures/sample.json", FileClass.FIXTURE),
        ("testdata/input.txt", FileClass.FIXTURE),
        ("__snapshots__/App.snap", FileClass.FIXTURE),
        ("api/service_pb2.py", FileClass.GENERATED),
        ("api/service.pb.go", FileClass.GENERATED),
        ("static/app.min.js", FileClass.GENERATED),
        ("build/output.js", FileClass.GENERATED),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_classifier_positive_cases(uri: str, expected: FileClass) -> None:
    assert classify(uri).file_class is expected


@pytest.mark.parametrize(
    "uri",
    [
        "src/nodes/graph.py",
        "src/vendors/payment.py",
        "app/contest/views.py",
        "src/testing_utils_prod.py",
        "lib/attestation.py",
        "src/protest.py",
        "internal/generator/build.go",
        "src/latest/api.py",
        "src/specs_engine.py",
        "app/outbox/queue.py",
    ],
    ids=lambda v: v,
)
def test_classifier_does_not_misread_real_source(uri: str) -> None:
    """Target 0. Every one of these contains a keyword as a substring.

    `nodes` is not `node_modules`, `contest` is not `test`, `attestation` is not
    `test`, `latest` is not `test`. Matching substrings instead of whole path
    segments is how a real source file becomes a silent dismissal.
    """
    result = classify(uri)
    assert result.file_class in (FileClass.SOURCE, FileClass.UNKNOWN), (
        f"{uri} misclassified as {result.file_class} because {result.reason}"
    )


def test_vendored_beats_test() -> None:
    """Somebody else's test is more usefully described as vendored."""
    assert classify("node_modules/lib/test/x.js").file_class is FileClass.VENDORED


def test_generated_marker_needs_file_contents(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "wire.py").write_text(
        "# Code generated by protoc. DO NOT EDIT.\nx = 1\n", encoding="utf-8"
    )
    (src / "hand.py").write_text("import os\nx = 1\n", encoding="utf-8")

    assert classify("src/wire.py").file_class is FileClass.UNKNOWN  # path-only sees nothing
    marked = classify("src/wire.py", tmp_path)
    assert marked.file_class is FileClass.GENERATED
    assert marked.used_content is True
    assert classify("src/hand.py", tmp_path).file_class is FileClass.SOURCE


def test_unreadable_file_is_unknown_not_source(tmp_path: Path) -> None:
    """Absence of evidence is not evidence of source."""
    assert classify("src/missing.py", tmp_path).file_class is FileClass.UNKNOWN


def test_traversal_uri_is_unknown_not_crash(tmp_path: Path) -> None:
    result = classify("../../../../etc/passwd", tmp_path)
    assert result.file_class is FileClass.UNKNOWN
    assert "unsafe" in result.reason


# --------------------------------------------- measured on the real corpus


def test_classifier_precision_on_real_scanner_output() -> None:
    """Run the classifier over every path four real OSS repos produced.

    Not a pass/fail threshold — a printed distribution plus one hard assertion:
    nothing from a plainly-source path may be classified away. The distribution
    is what makes the P2 baseline number defensible instead of asserted.
    """
    counts: Counter[str] = Counter()
    misreads: list[str] = []
    for path in GENERATED:
        log, _ = loads(path.read_bytes(), source=str(path))
        for finding in results_of(log):
            if not finding.uri:
                continue
            result = classify(finding.uri)
            counts[result.file_class.value] += 1
            head = finding.uri.split("/")[0].lower()
            if head in {"src", "lib", "flask", "internal", "mux"} and result.file_class in (
                FileClass.VENDORED,
                FileClass.GENERATED,
            ):
                misreads.append(f"{finding.uri} -> {result.file_class} ({result.reason})")

    print(f"\nclassification over {sum(counts.values())} real findings: {dict(counts)}")
    assert misreads == [], "source paths classified away:\n  " + "\n  ".join(misreads)


@pytest.mark.parametrize(
    "uri",
    [
        "examples/auth/index.js",
        "examples/mvc/controllers/user.js",
        "sample/app.py",
        "samples/quickstart.go",
        "migrations/0007_add_token.py",
        "src/gen/parser.py",
        "out/handler.js",
        "obj/Service.cs",
    ],
    ids=lambda v: v,
)
def test_ambiguous_directories_are_not_classified_away(uri: str) -> None:
    """Deliberately excluded from the fixture and generated lists.

    Example code is code users copy into their own projects, so a vulnerability
    there propagates rather than staying inert. Migrations are routinely
    hand-edited and run against production. `gen`, `out`, and `obj` are
    three-letter names that mean something else in plenty of repos.

    Measured on the corpus: treating `examples/` as a fixture labelled 64 of 103
    real findings dismissible. That is the overreach this pins shut.
    """
    result = classify(uri)
    assert result.file_class in (FileClass.SOURCE, FileClass.UNKNOWN), (
        f"{uri} classified as {result.file_class} because {result.reason}"
    )
