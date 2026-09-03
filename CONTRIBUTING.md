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
If a check fails, fix the cause. Never leave `main` red, and never force-push it.

```bash
make install    # uv sync --extra dev
make gate       # the pre-push gate
make fmt        # apply ruff fixes and formatting
make eval-dry   # estimated cost and call count, spends nothing
make eval       # run the eval suite, write evals/REPORT.md
make cost       # spend and latency from the last eval run
```

## Design constraints

These are contract. A change that breaks one is wrong even if it passes the gate.

1. **SARIF 2.1.0 in, SARIF 2.1.0 out, lossless.** Output must render in GitHub
   Code Scanning. Do not invent an output format. "Lossless" has a precise
   definition — semantic equality under a documented canonicalization — in
   [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
2. **Never silently drop a finding.** Suppression is a labeled annotation
   carrying a justification. Deletion is a bug, always. The emitter asserts
   per-run result counts so this cannot regress quietly.
3. **Asymmetric error cost.** See below. Uncertain means escalate to a human.
4. **Deterministic retrieval, model judgment only.** tree-sitter assembles the
   context. The model is *shown* code; it never recalls or infers what the code
   says.
5. **Model-agnostic.** Every provider call goes through `sift.llm.provider`.
6. **Every model response is parsed into a validated Pydantic schema.** Never
   regex free text.
7. **Cost and latency are product features.** Deterministic filters run before
   any model call, and token spend is tracked and printed per run.
8. **Source under analysis is untrusted data, never instructions.** See
   [SECURITY.md](SECURITY.md).

## The safety rule

A `FALSE_POSITIVE` verdict requires `confidence >= 0.85` **and** no unrebutted
Adversary objection. Otherwise it is downgraded to `NEEDS_HUMAN_REVIEW`, with
the reason recorded.

This is enforced in `Adjudication.enforce_safety_rule`
(`src/sift/models/verdict.py`), not in prompt text, so no model output and no
future caller can route around it. `validate_assignment=True` means it re-runs
on mutation as well as construction.

Do not lower the floor, delete `tests/test_verdict_safety.py`, or add a bypass
flag. If a change makes those tests fail, the change is wrong.

## Model and cost policy

- Haiku for the Reachability, Exploitability, and Adversary analysts.
- **Opus for the Adjudicator.** It is the safety-critical stage and is never
  downgraded to save money.
- Hard abort at **$5.00 per eval run**, checked *before* each call, not after.
- Every eval report records model IDs, temperature, and prompt hashes. A metric
  without its configuration is meaningless and must not reach the README.
- Verdicts are cached by content hash, so re-running on unchanged findings costs
  close to nothing.

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

Add the tree-sitter grammar to `pyproject.toml`, confirming a prebuilt wheel
exists for CPython 3.11-3.13 on Linux *and* Windows — we do not require a C
toolchain. Then: queries under `src/sift/context/tree_sitter_queries/<lang>/`, a
fixture test per query, a `FileClass` heuristic for that ecosystem, entrypoint
detection for its common web and CLI frameworks, and eval dataset entries in
that language covering both true and false positives.

Be conservative with the `FileClass` heuristic. Misreading a real source file as
a test or vendored file is a silent dismissal with no model in the loop, so
return `UNKNOWN` when unsure.

A language is not "supported" until it has eval coverage.

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## Code of Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
