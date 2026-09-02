# SIFT — SARIF Insight & Finding Triage

Triage SAST findings with AST-grounded code context and multi-agent LLM adjudication.
SARIF 2.1.0 in, annotated SARIF 2.1.0 out. Findings are never deleted, only labeled.

> **Status: pre-release (v0.0.0).** The pipeline is not yet end to end. Every metric
> below reads *not yet measured* and will stay that way until `make eval` produces it.
> No number reaches this table without a committed eval report behind it.

## Results

| Metric | Value | Target |
| --- | --- | --- |
| **False suppression rate** (true positives wrongly dismissed) | not yet measured | **< 2%** |
| False positives auto-dismissed | not yet measured | > 60% |
| Prompt-injection resistance | not yet measured | 100% |
| Cost per finding | not yet measured | — |
| p95 latency per finding | not yet measured | — |

False suppression rate is first on purpose. A missed true positive is roughly 50x
worse than a retained false positive, and every tradeoff in this codebase resolves
that way. See [Evaluation](#evaluation).

## Demo

Not yet recorded. Lands with the first end-to-end pipeline (P5).

## Quickstart

Not yet functional. `sift triage` exits `2` until P5. Once it works:

```bash
uv tool install sift-sast
sift triage results.sarif --repo . --out triaged.sarif
```

## GitHub Action

Not yet published. Lands in P6.

## How it works

```
SARIF ─▶ 1. Pre-filter ─▶ 2. Context Builder ─▶ 3. Adjudication ─▶ 4. Emitters
         (no LLM)          (tree-sitter,          (4 agents)         annotated SARIF
         dedupe,            no LLM)                                  Markdown comment
         test/vendored/     enclosing function,    Reachability ┐     JSON run report
         generated          call graph, data       Exploitability├▶ Adjudicator
                            flow, sanitizers       Adversary     ┘
```

Retrieval is deterministic; only judgment is delegated to a model. The Adjudicator
is shown code, never asked to recall it. The Adversary exists to argue every finding
*is* real — it counteracts the model's bias toward agreeable dismissal, which is this
tool's worst failure mode.

Full data flow and schemas: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Limitations

Honest, current, and specific:

- **Languages:** none shipped. Python lands in P3. JS, Java, Go are unscheduled.
- **No taint analysis of its own.** SIFT reasons over the data flow the scanner
  reported. If Semgrep or CodeQL got the flow wrong, SIFT inherits that error.
- **Cross-file reachability is 1–2 hops.** Deep indirection, dynamic dispatch,
  reflection, and framework magic will read as `UNKNOWN` and escalate to a human.
- **No runtime or config awareness.** It cannot see feature flags, WAF rules,
  deployment topology, or whether a route is actually exposed.
- **It will be wrong sometimes.** The design goal is that its errors are
  conservative — escalations, not silent dismissals — and that the rate is measured
  and published rather than asserted.
- **Cost:** unmeasured. Budget per run is enforced and printed; `--dry-run`
  estimates before spending.

## Evaluation

`evals/dataset/` holds labeled findings — the finding, a repo snapshot, a ground
truth label, and a rationale — seeded from OWASP Benchmark, the Juliet Test Suite,
and real CVE-fix commits.

```bash
make eval-dry   # estimated cost and call count, spends nothing
make eval       # writes evals/REPORT.md
```

Every report records model IDs, temperature, and prompt hashes. A metric without
its config is meaningless and must not be published.

## Development

```bash
make install    # uv sync --extra dev
make gate       # ruff + mypy strict + pytest — must pass before any push
```

Roadmap and per-phase acceptance criteria: [docs/ROADMAP.md](docs/ROADMAP.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
