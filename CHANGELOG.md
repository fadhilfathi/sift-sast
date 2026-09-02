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
- `sift` CLI skeleton — `version` works; `triage`, `eval`, and `cost` exit `2` with
  the phase they land in rather than pretending to run.
- Documentation: `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, `CLAUDE.md`,
  `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, README skeleton.
- CI workflows: `ci`, `eval`, `release`, `security`; Dependabot for pip and
  github-actions.

[Unreleased]: https://github.com/fadhilfathi/sift/commits/main
