# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- SARIF 2.1.0 ingest (`sift.ingest`) and emit (`sift.emit.sarif`) with a lossless
  round trip, defined as semantic equality under a documented canonicalization
  (`sift.canonical`). Absent, `null`, and empty stay three distinct states.
- Per-finding correlation IDs (`sift.ingest.fingerprint`) that prefer GitHub's
  `primaryLocationLineHash`, then a tool fingerprint, then line content — and
  report when identity has degraded to positional.
- `sift triage --dry-run`: parse, fingerprint, and emit, with a finding count and
  identity breakdown. No adjudication, and it says so.
- A 20-fixture SARIF corpus under `evals/fixtures/` with a pinned, reproducible
  generator, plus 8 handcrafted adversarial documents.
- Schema validation against a vendored official SARIF 2.1.0 schema, asserting that
  a round trip never adds a violation.

### Fixed

- Ingest now refuses a document with no `runs` key instead of parsing it into an
  empty log and reporting zero findings.
- CLI output is ASCII only; the Windows console mangled an em dash.

### Known

- GitHub Code Scanning ignores SARIF `suppressions` — measured for both
  `external` and `inSource`. Dismissals will need
  `PATCH /code-scanning/alerts/{number}` in P6.

- Project scaffolding: `pyproject.toml`, pinned Python 3.12 dev environment, ruff,
  mypy strict, pytest, pre-commit, Makefile.
- Core schemas: `ContextBundle` (`sift.models.context`), `Adjudication` and
  supporting verdict types (`sift.models.verdict`), and lossless SARIF 2.1.0 models
  (`sift.models.sarif`).
- The safety rule, enforced in the schema: a `FALSE_POSITIVE` verdict requires
  `confidence >= 0.85` and no unrebutted Adversary objection, and is otherwise
  downgraded to `NEEDS_HUMAN_REVIEW` with the reason recorded.
- `sift` CLI skeleton — `version` works; `triage`, `eval`, and `cost` exit `2` with
  the phase they land in rather than pretending to run.
- Documentation: `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, `CLAUDE.md`,
  `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, README skeleton.
- CI workflows: `ci`, `eval`, `release`, `security`; Dependabot for pip and
  github-actions.

[Unreleased]: https://github.com/fadhilfathi/sift/commits/main
