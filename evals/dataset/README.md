# P4 step 4 dataset (D10)

Built by `build.py` — deterministic, zero LLM calls. Re-run with
`uv run python evals/dataset/build.py` from the repo root.

- `dataset.jsonl` — 103 labeled findings: 84 `HAND_LABELED` (synthetic
  snapshot `snapshots/synth-v1/`, 42 files × TP/FP twin, each a distinct sink) + 19 `REAL_WORLD`
  (Flask findings at the pinned SHA below). Class balance 45 TP / 58 FP.
  Distinct (rule, path, line) sources: 94 — the 9 overlap are the 8 CodeQL
  locations reported by both suites plus sessions.py:281 by both rulesets.
- Label hygiene: build.py locates flagged lines from `# finding:` markers,
  then strips them; snapshot functions are named by file position (`alpha_`
  first, `beta_` second, order swapped by filename hash), so the name
  correlates with hash parity, never the label; both twins of a pair share
  the vuln-named rule_id, since a scanner rule fires on the sink, not the
  outcome. `tests/test_no_llm.py` asserts all three on every run.
- `rejected.jsonl` — 9 rows covering 84 rejected candidates: 80 non-Python
  corpus findings (language-scope mismatch, counted in bulk per stratum),
  4 dynamic-dispatch Flask findings (INSUFFICIENT, correctly escalated).
- `injection.jsonl` — 2-entry prompt-injection test class, ground truth
  TRUE_POSITIVE, scored separately in step 5, never pooled.

Provenance classes `CVE_FIX`, `OWASP_BENCHMARK`, `JULIET` are empty: the
builder is Python-only (OWASP/Juliet have no Python surface worth labeling
blind) and no CVE-fix commit could be verified without network access.
Per the step-4 brief this is a STOP-and-report condition, not a silent gap.

**SHA stamp (committer action required):** `HAND_LABELED` entries carry
`repo_sha = a24a2ce...` (HEAD at label time). The snapshot files are new in
the step-4 commit, so after commit, stamp the real step-4 commit SHA into
`build.py` (`SNAP_SHA`) and re-run before push. `REAL_WORLD` pins
`pallets/flask@d318b683471101618febed18996405ad26462110`.
