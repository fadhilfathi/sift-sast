# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-16

First public release. SARIF 2.1.0 in, annotated SARIF 2.1.0 out. The
pipeline is complete end to end and has never been measured against a
labeled dataset with a real model call — see "Known limitations" below
before trusting anything about its accuracy.

### Added

- **Ingest and emit** (`sift.ingest`, `sift.emit.sarif`): lossless SARIF
  2.1.0 round trip, defined as semantic equality under a documented
  canonicalization (`sift.canonical`) — absent, `null`, and empty stay
  three distinct states. Validated against the official SARIF 2.1.0 schema.
- **Finding identity** (`sift.ingest.fingerprint`): three separate
  identities — GitHub's own alert identity (passed through untouched),
  SIFT's correlation ID, and the D1 cache key — preferring
  `primaryLocationLineHash`, then a tool fingerprint, then line content,
  reporting when identity has degraded to positional.
- **Stage 1, deterministic pre-filter** (`sift.prefilter`): deduplication
  by correlation ID and `FileClass` classification (test/vendored/generated/
  fixture/source/unknown). Dismisses nothing by class by default —
  `SAFE_TO_RESOLVE` is empty on purpose; a caller opts in per class with
  `--resolve-class` against printed numbers. Every decision carries a
  `resolved_by` label and a justification; the finding count is asserted
  unchanged.
- **Stage 2, context builder** (`sift.context`, Python only): tree-sitter
  based retrieval of the enclosing function, direct callers up to a 2-hop
  budget, callee definitions on the taint path, SARIF `codeFlows`, import
  and sanitizer detection, and entrypoint reachability. Every bundle
  carries a `completeness` verdict (`COMPLETE`/`PARTIAL`/`INSUFFICIENT`)
  with tagged reasons — never a warning nobody is forced to read. Secrets
  are redacted before any span leaves the builder, preserving kind, length,
  and entropy class, never the value.
- **Stage 3, four-agent adjudication** (`sift.agents`, `sift.orchestrator`):
  Reachability, Exploitability, and Adversary run concurrently against a
  shared, prompt-cached context prefix; the Adjudicator sees their raw
  output with no role identity attached at all. A `FALSE_POSITIVE` verdict
  requires five independent conditions to hold at once, enforced in the
  schema rather than prompt text, each covered by an isolation test and
  verified by deliberate mutation:
  - confidence >= 0.85
  - no unrebutted Adversary objection
  - context completeness is not `INSUFFICIENT`
  - the Adversary filed at least one objection
  - every objection the Adversary filed reached the Adjudicator's own
    review (`len(open_objections) >= adversary_objection_count`)
  Every cited `FileLineRef` is verified against the real repo before a
  verdict is accepted; a hallucinated citation forces
  `NEEDS_HUMAN_REVIEW`. The D1 cache key is implemented. Zero live model
  calls occur anywhere in the test suite, enforced by an autouse fixture
  that patches the one network primitive the provider adapter uses.
- **Stage 4, emitters** (`sift.emit`): every finding, adjudicated or not,
  carries a `properties["sift/v1"]` bag; a `FALSE_POSITIVE` verdict also
  gets a `Suppression` for interop correctness (see Known limitations — it
  does not dismiss anything on GitHub). A JSON run report (cost, latency,
  verdict distribution, model IDs, prompt hashes) and a Markdown PR
  comment, grouped by verdict, TRUE_POSITIVE first and FALSE_POSITIVE last
  and collapsed — language restricted to "adjudicated" / "escalated" /
  "dismissed with justification", never "resolved" or "safe".
- **CLI** (`sift triage`): runs the full pipeline. `--dry-run` runs Stage 1
  and Stage 2 for real and estimates Stage 3's cost (four calls per
  finding, correct model tiers) without calling a model or needing an API
  key. Budget is checked per finding, before it runs, via a hard-abort
  guard.
- **GitHub Action** (`action.yml`): defaults to `dry-run: "true"` — spending
  requires an explicit opt-in, never an accidental one. Emits annotated
  SARIF and the JSON report as workflow artifacts; posts an idempotent PR
  comment (updates its own prior comment via a marker, never stacks).
- **Eval harness** (`sift.eval`, `evals/`): cost estimation against real
  gateway pricing, the budget guard, a 103-finding labeled dataset (45 true
  positive / 58 false positive, an 84-entry private holdout, D10 provenance
  classes), the D11 scoring module, and provenance-stratified reporting.
  `make eval-dry` / `make eval` / `make cost`.
- **Documentation**: `docs/ARCHITECTURE.md` (thirteen numbered design
  decisions with rationale and every measured finding), `docs/ROADMAP.md`
  (per-phase acceptance criteria), `docs/OPERATIONS.md` (repo settings,
  the SARIF-emitter verification procedure, the CodeQL self-scan triage).

### Fixed

- Correlation IDs no longer merge distinct findings when a scanner emits a
  placeholder fingerprint. Semgrep sends `matchBasedId/v1: "requires
  login"` when unauthenticated; keying on it collapsed 45 findings into one
  and dismissed 44 as duplicates. Identity is now bound to the finding's
  own rule and location at every tier, and non-discriminating fingerprint
  values are rejected.
- A count-based check could prove the Adversary had *filed* an objection
  without proving it *survived* into the Adjudicator's own review — a
  compromised or careless Adjudicator could report an honest count while
  silently dropping the objection itself, passing every check that existed
  until this was added.
- Analyzed source containing the literal untrusted-data delimiter text
  (`<<<END UNTRUSTED SOURCE>>>`, or a fake re-opening marker) reached the
  model unescaped — measured directly as 4 occurrences of the marker in a
  rendered block where exactly 2 were correct. Every `<<<`/`>>>` run inside
  analyzed source is now broken before wrapping.
- CLI and eval-report output is ASCII only; the Windows console mangled an
  em dash twice before every renderer was audited for it.
- Ingest refuses a document with no `runs` key rather than parsing it into
  an empty log and reporting zero findings.

### Security

- This repository's first real-world SAST run (CodeQL, triggered by the
  public flip) produced 8 alerts. All 8 triaged **FALSE_POSITIVE** by a
  human applying this project's own reachability-first standard — full
  reasoning in `docs/OPERATIONS.md` and the README. None touched the
  no-fallback code paths (`sift.paths`, `sift.ingest.fingerprint`,
  `sift.context.redact`, the safety rule); a real finding there would have
  been fixed, not triaged into a table row.
- `gitleaks` scans full git history on every push and on a weekly
  schedule, not just the diff.

### Known limitations

- **This tool's accuracy has not been measured.** Zero live LLM calls have
  ever run in this project, by deliberate zero-spend-construction decision
  — not because measuring was skipped, but because construction was
  decided not to gate on a spend decision. No precision, recall, false
  suppression rate, coverage, or injection-resistance rate exists yet.
- **D12 is unresolved.** The four-agent pipeline has never been compared
  against the single-prompt baseline that was built specifically to beat
  it. If it doesn't, the project's own honesty clause says cut it.
- **GitHub Code Scanning ignores SARIF `suppressions` entirely** — measured
  for `external` and `inSource` kinds, re-measured under this project's own
  emitter output. Real dismissal needs
  `PATCH /code-scanning/alerts/{number}`, which this project does not call
  automatically (see README, "Suppression behavior").
- Two dataset provenance classes (`OWASP_BENCHMARK`, `JULIET`) are empty —
  the labeled dataset is `HAND_LABELED` and `REAL_WORLD` only.
- Python only. Cross-file call-graph resolution is name-based, not
  type-resolved. The sanitizer allowlist is a fixed regex set. Entrypoint
  detection is decorator-substring matching.
- PyPI publishing is not set up for this release; `pip install sift-sast`
  does not work yet. Install from source or via the GitHub Action.

[Unreleased]: https://github.com/fadhilfathi/sift-sast/compare/v0.1.0...main
[0.1.0]: https://github.com/fadhilfathi/sift-sast/releases/tag/v0.1.0
