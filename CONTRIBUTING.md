# Contributing to SIFT

## Setup

```bash
uv python install 3.12
uv venv --python 3.12
make install
uv run pre-commit install
```

Supported range is Python 3.11–3.13. Develop on 3.12; CI runs 3.11 and 3.12.

## The gate

```bash
make gate    # ruff check + ruff format --check + mypy strict + pytest
```

`make gate` must pass before you push. Do not disable a check to make it pass.

## What this project optimizes for

A missed true positive is roughly **50x worse** than a retained false positive.
Every tradeoff resolves toward caution. When a change makes SIFT dismiss more
findings, the burden of proof is on the change, and the proof is an eval report.

Concretely, a PR will be rejected if it:

- deletes a finding rather than labeling it
- relaxes the `FALSE_POSITIVE` confidence floor, or adds a way around the
  unrebutted-objection rule
- weakens or removes `tests/test_verdict_safety.py`
- changes prompts or application code in order to move an eval number
- publishes a metric that was not actually measured

## Areas and their rules

| Area | Rule |
| --- | --- |
| `src/sift/models/` | The schema is the interop contract. Additive optional fields are fine; removals, tightened constraints, and changed meanings are breaking and need a CHANGELOG entry. |
| `src/sift/context/` | tree-sitter only, no LLM code. Every query needs a fixture test. |
| `src/sift/agents/` | Prompt changes must report a `make eval` delta, before and after. Vibes are not justification. |
| `src/sift/llm/` | All provider calls go through `provider.py`. No direct SDK calls elsewhere. |
| `evals/` | The dataset is the source of truth. Never edit a label to fix a failure. Flag suspicious metric jumps as probable contamination. |

## Commits

Conventional Commits: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `perf`, `ci`.

- Imperative subject, under 72 characters
- The body explains **why**, not what
- Small and atomic
- No `Co-Authored-By` trailers, no generated-by footers

```
fix(prefilter): treat conftest.py as a test file

Semgrep flags fixtures defined in conftest.py, which were reaching the
adjudicator and burning tokens on findings no human would ever action.
```

## Pull requests

- Link the issue it closes
- State the eval delta if the change can affect verdicts, or say "no verdict impact"
- CI must be green. Never merge red.

## Adding a language

Use `/new-lang`, or follow it manually: tree-sitter grammar dependency, queries
under `src/sift/context/tree_sitter_queries/<lang>/`, a fixture per query, a
`FileClass` heuristic for that ecosystem, and eval dataset entries in that language.
A language is not "supported" until it has eval coverage.

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## Code of Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
