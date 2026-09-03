# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project scaffolding: `pyproject.toml`, pinned Python 3.12 dev environment, ruff,
  mypy strict, pytest, pre-commit, Makefile.
- Core schemas: `ContextBundle` (`sift.models.context`), `Adjudication` and
  supporting verdict types (`sift.models.verdict`), and lossless SARIF 2.1.0 models
  (`sift.models.sarif`).
- The safety rule, enforced in the schema: a `FALSE_POSITIVE` verdict requires
  `confidence >= 0.85` and no unrebutted Adversary objection, and is otherwise
  downgraded to `NEEDS_HUMAN_REVIEW` with the reason recorded.
- SARIF 2.1.0 ingest (`sift.ingest`) and emit (`sift.emit.sarif`) with a lossless
  round trip, defined as semantic equality under a documented canonicalization
  (`sift.canonical`). Absent, `null`, and empty stay three distinct states.
- Per-finding correlation IDs (`sift.ingest.fingerprint`), preferring GitHub's
  `primaryLocationLineHash`, then a tool fingerprint, then line content — and
  reporting when identity has degraded to positional.
- `sift triage --dry-run`: parse, fingerprint, and emit, printing a finding count
  and identity breakdown. No adjudication, and it says so.
- A 20-fixture SARIF corpus under `evals/fixtures/` with a pinned, reproducible
  generator, plus eight handcrafted adversarial documents.
- Schema validation against a vendored official SARIF 2.1.0 schema, asserting that
  a round trip never adds a violation.
- Documentation: `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, `docs/OPERATIONS.md`,
  `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, README skeleton.
- CI workflows: `ci`, `eval`, `release`, `security`, `fixtures`; Dependabot for pip
  and github-actions.

### Fixed

- Ingest refuses a document with no `runs` key rather than parsing it into an empty
  log and reporting zero findings.
- CLI output is ASCII only; the Windows console mangled an em dash.

### Known limitations

- GitHub Code Scanning ignores SARIF `suppressions` — measured for both `external`
  and `inSource` kinds. A dismissal will need
  `PATCH /code-scanning/alerts/{number}` in P6.
- Findings with neither a snippet nor a tool fingerprint fall back to a positional
  correlation ID that detaches when lines shift. P3 resolves this.
- No triage yet. `sift triage` without `--dry-run` exits 2 until P5.

[Unreleased]: https://github.com/fadhilfathi/sift/commits/main
