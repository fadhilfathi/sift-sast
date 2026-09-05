# P4 pilot report: infrastructure, not a baseline score

**Status: infrastructure complete and validated offline. No live model run happened, by user choice. Every metric below is "not yet measured"  -  this document records what was built, what it costs to run, and what running it later requires. It is not a D11/D13 scored report, and nothing in it can inform D12's baseline question.**

## Why there are no scores

Step 5's live run (Run A: single-prompt baseline against the 103-finding dataset, Run B: all-escalate control) was never executed because the user chose not to spend money on live LLM calls in this phase. This was a spending decision, not a technical block: OpenRouter billing was resolved during the phase, and the runner proved itself correct in a `--limit 2` smoke test that reached a clean 402-before-billing (budget guard firing before any spend, exactly as designed) and was validated end-to-end. The infrastructure is merged on `main` and nothing further needs building before a run. When someone authorizes the spend, the procedure is: set `SIFT_API_KEY`, run `uv run python evals/pilot/run_baseline.py --flask <flask-checkout-at-d318b68>`, score the emitted rows with `sift.eval.scoring`, and render with `render_report_markdown`. Expected spend is under the $5.00 cap (see below).

Consequence, stated plainly: **step 5 has produced no numbers.** There is no baseline score, no false suppression rate, no precision or recall, no injection-resistance measurement. D12's question  -  does the four-agent thesis beat a genuine single-prompt baseline  -  is unanswered, and any claim about multi-agent performance remains inadmissible per the roadmap's own rule until this run exists.

## What was built (steps 4-5)

**Step 4  -  the dataset** (`evals/dataset/`, commit `3fc0d62`). `build.py` is deterministic, zero LLM calls: 103 labeled findings (`dataset.jsonl`), 9 rejection-log rows covering 84 rejected candidates (`rejected.jsonl`), and a 2-entry injection-bait class (`injection.jsonl`). Composition: 84 `HAND_LABELED` (42-file synthetic snapshot `snapshots/synth-v1/`, TP/FP twins per sink) plus 19 `REAL_WORLD` (Flask findings at pinned `pallets/flask@d318b68`). Class balance 45 TP / 58 FP. Every entry carries finding, pinned repo SHA, ground truth, written rationale citing code, provenance, and labeler. `PUBLIC_BENCHMARK` (OWASP/Juliet) and `CVE_FIX` are empty  -  see the shortfall note below.

**Step 5 infrastructure  -  three pieces, no live calls between them:**

1. **Provider adapter** (`src/sift/llm/provider.py`, commit `ce5ec20`). All LLM traffic goes through one OpenRouter gateway interface: pinned `("anthropic",)` routing with fallbacks off, `ProviderConfig.for_role` mapping tiers to `ModelId` (Haiku analysts, Opus adjudicator  -  never downgraded), per-call cost from real usage tokens, `EvalConfig.upstream_provider` stamping the pin into every report so routing drift is visible.
2. **Scoring module** (`src/sift/eval/scoring.py`, commit `f8040cb`). Pure math over runner rows: `ModelOutcome` (with `from_run_row` parsing the pilot runner's JSONL and raising loudly on malformed rows), `score_subset` / `score_all` (per-provenance, never pooled, strict 1:1 id join that raises on missing/extra/duplicate rows instead of dropping findings), `score_injection` (separate path, refuses non-TP bait). Metrics per subset: false suppression rate (suppressed / adjudicated ground-truth TPs; 0.0 when nothing was dismissed, including the all-escalate control), precision, recall, coverage, escalation rate, schema-validation-failure rate, mean cost per finding, p95 latency. 30 tests, including a deliberate mutation test (flip one TP to wrongly dismissed, assert the safety metric moves 0.0 -> 0.5).
3. **Pilot prompt and runner** (`src/sift/agents/prompts/baseline.txt`, `src/sift/agents/baseline.py`, `evals/pilot/run_baseline.py`, commit `32a011a`). The D12-genuine baseline: same `ContextBundle`, same `Adjudication` schema with the safety rule enforced in code, asymmetric-cost and untrusted-data instructions, four-step reasoning (reachability, exploitability, adversary steelman, completeness). Prompt rendering is centralized in `render_baseline_prompt`, shared by runner and test so the tested path and the run path cannot drift. The runner emits one JSONL row per finding (verdict, confidence, schema validity, citation verification, completeness escalation, cost, latency) plus Run B rows that escalate unconditionally at zero cost; raw run outputs are gitignored (`evals/pilot/runs/`) because they embed analyzed source.

Supporting guarantees: `tests/test_no_llm.py` proves the dataset builder imports no network/provider code, runs with sockets disabled, and leaks no label into model-visible text (asserted on every run); `tests/test_prompt_render.py` proves the rendered prompt shows the model single-brace JSON and the untrusted delimiters.

## The one measured number: dry-run cost

`uv run sift eval --dry-run` (confirmed on this tree): **103 findings, 103 calls, estimated $2.5750 against the $5.00 budget**  -  one Opus call per finding at the flat planning rate, spending nothing. This is a cost *estimate* for budgeting, not a measured spend; real per-call cost comes from gateway usage tokens at run time. The estimate fits the cap with roughly 2x headroom, and the `BudgetGuard` aborts before (never after) any call that would exceed it.

## Known shortfalls (carried, not hidden)

**Provenance gap.** `OWASP_BENCHMARK`/`JULIET` and `CVE_FIX` subsets are empty. The builder is Python-only (OWASP/Juliet offer no Python surface worth labeling blind) and no CVE-fix commit could be verified without network access. The eventual step-5 run therefore scores `HAND_LABELED` volume plus the 19-finding `REAL_WORLD` sanity check  -  a pilot baseline, not the D12 baseline in full. Filling the empty classes needs either a second-language builder (P7+ territory) or network-verified CVE-fix SHAs, and is explicitly future work.

**Single-repo real world.** The `REAL_WORLD` subset is Flask alone at one pinned SHA. It answers "does benchmark performance transfer to genuine scanner output" for exactly one codebase shape.

**No content-hash result cache yet.** The roadmap's "re-running on unchanged findings costs near zero" is specified (P1) but not implemented  -  it waits on P5's orchestrator and prompt cache. Today a re-run costs the full estimate again.

## P4 acceptance criteria, honestly marked

- `evals/dataset/` holds >= 100 labeled findings, class balanced: **met** (103, 45 TP / 58 FP), with the provenance-gap caveat above.
- Finding + snapshot + label + rationale per entry: **met**.
- Injection test class with its own metric: **met** (2 entries, separate `score_injection` path, never pooled)  -  **unmeasured**, like everything else scored.
- Precision, recall, false suppression rate (first), injection resistance, cost, p95 latency: **infrastructure met, measurement not done**. The metrics compute correctly over synthetic data in tests; no model output has ever passed through them.
- Config stamping (model IDs, temperature, prompt hashes): **met**  -  every report embeds `EvalConfig`; prompt hash `ac4f058c...` recorded.
- `--dry-run` cost/call estimate: **met** ($2.5750, confirmed twice).
- $5.00 hard abort before each call: **met** in `BudgetGuard`, proven by the 402-before-billing smoke test.
- Content-hash cache: **not met** (specified, deferred to P5 as designed).
- `make eval` reproducible, `evals/REPORT.md` committed: **not done**  -  there is no scored report to write; this file stands in its place until a live run exists.
- Naive single-prompt baseline, scored: **half met**  -  the baseline exists and is genuine; the scoring never ran. **D12's bar does not exist yet.**
