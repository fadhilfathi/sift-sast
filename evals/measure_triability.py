"""One-off measurement: how much of the P1/P2 corpus is triable at all.

Not the eval harness (that is P4 step 3). This answers the question the P3
review raised: of the 103 real-scanner findings, how many could ever reach
adjudication, and which of five very different reasons explains the rest?
Aggregating that into one percentage would hide which of them is a corpus
artifact, a context-builder gap, or a documented language limitation - each
demands a different response, so they are kept apart end to end.

Requires the four pinned target repos checked out locally (see
evals/fixtures/generate.sh for the exact commits) - not committed to the repo,
so this script takes their paths as arguments rather than assuming a location.

    uv run python evals/measure_triability.py \\
        --flask   <path> \\
        --express <path> \\
        --gson    <path> \\
        --mux     <path>
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from sift.context.builder import build_context_bundle
from sift.ingest import loads, results_of
from sift.ingest.fingerprint import FindingRef, IdentitySource
from sift.models.context import CompletenessReason, ContextCompleteness
from sift.prefilter.classify import classify

#: Matched against each generated fixture's filename to pick the right checkout.
REPO_FOR_TOOL_TARGET = {
    "flask": "pallets-flask",
    "express": "expressjs-express",
    "gson": "google-gson",
    "mux": "gorilla-mux",
}

#: Only sift.context.builder is language-aware, and only implicitly: it always
#: parses with the Python grammar regardless of extension. This script checks
#: the extension itself so "non-Python source" is its own stratum rather than
#: being indistinguishable from a real Python parse failure.
PYTHON_EXTENSIONS = frozenset({".py", ".pyi"})


def _completeness_stratum(finding: FindingRef, repo_root: Path) -> str:
    bundle = build_context_bundle(finding, repo_root)
    if bundle.completeness in (ContextCompleteness.COMPLETE, ContextCompleteness.PARTIAL):
        return "triable"

    reasons = set(bundle.completeness_reasons)
    if CompletenessReason.ENCLOSING_FUNCTION_UNRESOLVED in reasons:
        return "python_enclosing_function_unresolved"
    if CompletenessReason.DYNAMIC_DISPATCH in reasons:
        return "python_dynamic_dispatch"
    if CompletenessReason.C_EXTENSION_BOUNDARY in reasons:
        return "python_c_extension_boundary"
    if CompletenessReason.CALLER_SEARCH_REFUSED in reasons:
        return "python_caller_search_refused"
    if CompletenessReason.PATH_TRAVERSAL_REFUSED in reasons:
        return "path_traversal_refused"
    if CompletenessReason.FILE_UNREADABLE in reasons:
        return "file_unreadable_at_pinned_sha"
    return f"insufficient_other:{sorted(r.value for r in reasons)}"


def stratum_for(uri: str | None, line: int | None, repo_root: Path | None) -> str:
    """One bucket per finding. Order matters: checked most-certain-exclusion first."""
    if not uri:
        return "no_location"

    if Path(uri).suffix.lower() not in PYTHON_EXTENSIONS:
        return "non_python_source"

    if repo_root is None:
        return "python_source_no_repo_checkout"

    file_class = classify(uri, repo_root).file_class
    if file_class.value in ("TEST", "VENDORED", "GENERATED", "FIXTURE"):
        return f"python_file_class_{file_class.value.lower()}"

    finding = FindingRef(
        correlation_id="measurement",
        identity_source=IdentitySource.CONTENT,
        run_index=0,
        result_index=0,
        rule_id="measurement",
        uri=uri,
        start_line=line or 1,
    )
    return _completeness_stratum(finding, repo_root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in REPO_FOR_TOOL_TARGET:
        parser.add_argument(f"--{name}", type=Path, default=None, help=f"checkout of {name}")
    args = parser.parse_args()

    repo_by_slug: dict[str, Path | None] = {}
    for tool_name, tool_slug in REPO_FOR_TOOL_TARGET.items():
        path = getattr(args, tool_name)
        if path is not None and not path.is_dir():
            print(f"error: --{tool_name} {path} is not a directory", file=sys.stderr)
            return 2
        repo_by_slug[tool_slug] = path

    counts: Counter[str] = Counter()
    per_repo: dict[str, Counter[str]] = {}
    total = 0

    for sarif_path in sorted(Path("evals/fixtures/generated").glob("*.sarif")):
        slug = next((s for s in repo_by_slug if s in sarif_path.name), None)
        repo_root = repo_by_slug.get(slug) if slug else None
        repo_key = slug or sarif_path.name
        repo_counts = per_repo.setdefault(repo_key, Counter())

        log, _ = loads(sarif_path.read_bytes(), source=str(sarif_path))
        for ref in results_of(log):
            total += 1
            bucket = stratum_for(ref.uri, ref.start_line, repo_root)
            counts[bucket] += 1
            repo_counts[bucket] += 1

    print(f"total findings measured: {total}\n")
    print("by repo:")
    for repo_label, repo_counts in sorted(per_repo.items()):
        print(f"  {repo_label}: {dict(sorted(repo_counts.items()))}")
    print("\naggregate, stratified:")
    for bucket, count in counts.most_common():
        print(f"  {bucket:42} {count:4}  ({count / total:5.1%})")

    triable = counts.get("triable", 0)
    print(f"\ntriable (COMPLETE or PARTIAL): {triable} / {total}  ({triable / total:.1%})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
