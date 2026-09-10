# Roadmap

Each phase ends with green CI on `main`. Between phases: stop and report. Phases
are not chained without explicit approval.

Legend: ☐ not started · ◐ in progress · ☑ done

---

## ☑ P0 — Scaffolding, repo, CI, docs, schemas

Tag nothing.

**Acceptance criteria**

- [x] Repo created, description, topics, issues + discussions + Dependabot enabled
- [x] `pyproject.toml`, Python 3.12 venv pinned via `.python-version`
- [x] ruff, mypy strict, pytest, pre-commit, Makefile all configured and passing
- [x] `ContextBundle` and `Adjudication` schemas defined and documented
- [x] The safety rule enforced in the schema and covered by tests
- [x] Four workflows: `ci`, `eval`, `release`, `security`; plus `dependabot.yml`
- [x] LICENSE, README skeleton, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, templates
- [x] Contributor workflow documented in `CONTRIBUTING.md`
- [x] `make gate` green locally, CI green on `main`
- [x] No attribution trailer in any commit (`git log --format=%B`)

---

## ☑ P1 — SARIF ingest and emit, lossless round-trip

No LLM. Nothing tagged.

**Acceptance criteria**

- [x] `sift.ingest` parses SARIF 2.1.0 into `SarifLog`; unknown keys survive
- [x] `sift.emit.sarif` writes it back
- [x] Property test over the corpus plus Hypothesis-generated documents:
      `parse(emit(parse(x))) == parse(x)` under the D2 canonicalization
- [x] Output validates against the official SARIF 2.1.0 JSON schema; deviations
      recorded in `evals/fixtures/SCHEMA_DEVIATIONS.md` rather than patched
- [x] **Accepted by GitHub Code Scanning** — uploaded for real, alerts read back
      and asserted
- [x] Stable per-finding correlation ID (D1) with the stability matrix tested
- [x] `sift triage --dry-run` runs parse, fingerprint, emit and prints counts
- [x] `make gate` green, CI green on `main`

**Corpus:** 20 fixtures — 12 generated from Semgrep 1.176.0 and CodeQL v2.26.4
against four pinned OSS repos, 8 handcrafted adversarial. 135 findings.

**Scope notes**

- *Byte-identity was dropped in favour of semantic equality* (D2). Measured: 0 of
  20 fixtures round-trip byte-identically, 20 of 20 do semantically. A
  byte-identical assertion would have been relaxed within a week.
- *All 12 real-scanner fixtures pass the official schema.* The deviation list was
  written expecting upstream violations and found none; the only two entries are
  handcrafted fixtures that are invalid on purpose. A test fails the build if a
  future scanner version changes that.
- *The schema sets `additionalProperties: false`*, which independently requires
  what D1 chose for other reasons — SIFT's own data goes in the `properties` bag
  and nowhere else.
- **GitHub ignores SARIF `suppressions`, both `external` and `inSource`.**
  Measured, not assumed. Dismissal in P6 must go through
  `PATCH /code-scanning/alerts/{number}`, which is a separate permission and must
  be opt-in. See `docs/ARCHITECTURE.md`.
- *The cache key is specified but not implemented.* It cannot be, until
  `ContextBundle` is populated (P3) and prompts exist (P5).
- *Positional identity is a live gap.* Findings with no snippet and no tool
  fingerprint fall back to a line-number identity that detaches on any shift. The
  CLI warns; P3's context builder resolves it by supplying the real source line.

---

## ☑ P2 — Deterministic pre-filter

Zero LLM calls. Nothing tagged.

**Acceptance criteria**

- [x] Dedupe by correlation ID
- [x] `FileClass` detection for test, vendored, generated, fixture files
- [x] Every resolution carries a `resolved_by` label and a justification. Nothing
      is deleted; `len(decisions) == len(refs)` is asserted.
- [x] Prints the fraction of findings resolved with no model
- [x] Precision of the pre-filter itself measured. 0 real-source misclassifications.

**Measured baseline: 0.0% settled without a model** (0 of 103 corpus findings).

**Scope notes**

- *The baseline is zero, and that is the finding.* Deduplication had nothing to
  collapse — each fixture is one scan of a distinct repo — and classification
  deliberately dismisses nothing. If every class were opted in it would be 15.5%.
- **`SAFE_TO_RESOLVE` is empty by default.** The design anticipated test,
  vendored, generated, and fixture files being resolvable without a model. None
  of them is: Log4Shell was vendored, generated code still ships, test
  credentials are real credentials, and fixtures are where private keys get
  committed. The classification is attached as evidence instead, and
  `--resolve-class` lets a caller opt in per class against printed numbers.
- *A serious bug was found and fixed by disbelieving a good number.* The first
  run reported 97.8% settled. Semgrep emits the placeholder `"requires login"` as
  `matchBasedId/v1` when unauthenticated, and keying on it collapsed 45 findings
  across 20 files and several rules into one correlation ID — 44 real findings
  dismissed as duplicates of each other. Every identity tier is now bound to the
  finding's own rule and location, and a fingerprint value that spans multiple
  rules or locations within a run is rejected as non-discriminating. Corpus-wide:
  103 findings, 103 distinct IDs. The same detector caught degenerate hashes in
  CodeQL output too.
- *Content identity needed an occurrence ordinal.* Excluding the line number
  keeps an ID stable when lines shift above it, but made the same rule on two
  byte-identical lines in one file collapse. Colliding findings at different
  lines now get an ordinal in line order; at the same line they stay merged,
  which is what dedupe is for.
- *`sift.paths` lands early.* The classifier reads file heads to find
  generated-code markers, so traversal-safe resolution was needed now rather than
  in P3. Symlinks are followed before the containment check, which is the case a
  string-prefix comparison misses. P3 reuses it.
- *Absolute `file:` URIs are refused.* Scanners emit them naming the scan
  machine's checkout, and there is no sound way to rebase one onto a different
  root. The classifier falls back to path-string heuristics.

---

## ☑ P3 — Context Builder, Python only

**Acceptance criteria**

- [x] tree-sitter queries for Python: function bounds, callers, callees, imports
- [x] Fixture test per query
- [x] Populates every `ContextBundle` field, or records a structured
      `CompletenessReason` (D6) — stronger than the original `build_warning`
      plan, since a warning nobody is forced to read is not a safety mechanism
- [x] Path reads are traversal-safe and scoped to the repo root
      (`sift.paths`, pulled forward from P2)
- [x] Secrets redacted from every materialized span before the bundle leaves
      the builder (D8)
- [x] `sift context dump <sarif>` writes `ContextBundle` JSON **for human
      review before any model sees it**, both the plain and untrusted-delimited
      form side by side (D9)
- [x] Reviewed and approved by the maintainer, against real bundles built
      from real Flask source at the pinned corpus commit, not only the
      synthetic fixture project

**Done means:** context quality is inspected and signed off. It caps triage quality.

**Scope notes**

- *The review surfaced the finding that defines P4 — corrected once, after
  the first framing conflated two different rules.* Of 16 real Semgrep Flask
  findings, 14 came back `INSUFFICIENT` — 12 because the finding landed in a
  `.html` template or `pyproject.toml` (correctly unparseable as Python, not a
  bug), 2 from a genuine `eval()`/`exec()` on the path. Of 8 CodeQL findings,
  all 8 were `COMPLETE`, and all 8 were inside Flask's own test files. The
  first write-up of this said C1 "forbids dismissing test-file findings" and
  implied that made them unusable for a dataset — wrong: **C1 forbids Stage 1
  auto-*resolving* a test-file finding without a model; it never forbade
  *adjudicating* one.** All 8 CodeQL findings and the 3 non-test Semgrep
  `COMPLETE` findings are equally dataset-eligible Python findings; only the
  4 `python_dynamic_dispatch` ones are genuinely unadjudicable. Measured
  precisely in `docs/ARCHITECTURE.md`: **3/103 (2.9%)** meet the full P1-P4
  dataset bar on this specific four-language corpus, while **19/23 (82.6%)**
  of the *Python* findings alone produced adjudicable context — 80/103 are
  excluded for language (JS/Java/Go), not capability. Both numbers are
  reported together everywhere from here on; neither is quoted alone. P4's
  dataset is built from OWASP/Juliet/CVE-fix/hand-labeled material, with
  those 19 real-world Python findings harvested in as a small, separately
  reported `REAL_WORLD` provenance class.
- *A caller-graph and dynamic-dispatch heuristic bug class, found by running
  against real code three separate times*, not by review: a span-budget
  counter shared across the whole bundle instead of scoped to the caller walk
  alone; a blind `str.replace()` while fixing that which silently turned an
  early return unconditional and made half a function permanently dead code;
  and a test fixture whose load-bearing line numbers were silently shifted by
  `ruff format` auto-fixing an import order. All three are fixed, and the
  practice — measure against real input, rerun rather than re-read a diff to
  verify a fix — is now standing practice for every later phase.
- *AC6 (closing the P1 positional-identity gap) was measured against real
  pinned-commit source, not simulated*: 8 of 103 corpus findings were
  positional, all 8 upgrade to stable `content` identity once the real source
  line is supplied.

---

## P4 - Eval harness and labeled dataset, then a naive baseline (in progress)

Built **before** the agents, on purpose.

**Status: infrastructure complete, live baseline UNRUN by user choice.**
Steps 1-4 (harness, dataset, provider adapter, scoring) are done, reviewed,
and merged; step 5's runner and prompt are built and validated offline, but
no model was ever called - see `evals/reports/p4-pilot.md`. Every scored
metric (precision, recall, false suppression rate, injection resistance,
cost, p95 latency) is **not yet measured**. D12's baseline bar does not
exist yet, and no architectural claim may lean on it.

**Acceptance criteria**

- [x] `evals/dataset/` holds **100+ labeled findings, class balanced**, seeded from
      OWASP Benchmark, the Juliet Test Suite, and real CVE-fix commits -
      **103 findings, 45 TP / 58 FP, but the seeding is narrower than
      specified:** 84 `HAND_LABELED` synthetic + 19 `REAL_WORLD` (Flask alone).
      `OWASP_BENCHMARK`/`JULIET` are empty (Python-only builder, no honest
      Python surface to label) and `CVE_FIX` is empty (no offline-verifiable
      fix SHA). Any eventual step-5 run is a **pilot baseline**, not the D12
      baseline in full, until those classes are filled.
- [x] Each entry: finding + repo snapshot + ground truth label + rationale
- [x] A dedicated **prompt-injection test class** with its own metric -
      built and separately scored in code, never pooled; unmeasured like the rest
- [x] Metrics: precision, recall, **false suppression rate** (first), injection
      resistance, cost per finding, p95 latency - **computed in
      `sift.eval.scoring`, covered by 30 tests, never run against model output**
- [x] Every report records model IDs, temperature, and prompt hashes
- [x] `--dry-run` prints estimated cost and call count and spends nothing -
      **$2.5750 for 103 findings, under the $5 cap, confirmed twice**
- [x] Hard abort at **$5.00 per run**, checked before each call -
      proven by a `--limit 2` smoke test reaching clean 402-before-billing
- [ ] Content-hash cache so re-running on unchanged findings costs near zero -
      specified in P1, deferred to P5's orchestrator as designed
- [ ] `make eval` is reproducible and writes `evals/REPORT.md`, committed -
      blocked on the live run; `evals/reports/p4-pilot.md` stands in its place
- [ ] A deliberately naive **single-prompt baseline**, scored. **That number is the
      bar the multi-agent design must clear.** - prompt and runner built and
      genuine; **scoring never ran, the bar does not exist yet**

**Done means:** we can measure. The measuring has not happened.

---

## P5 - Four-agent pipeline (in progress)

**Status: zero-spend construction; D12 comparison unresolved.** The pipeline is being built and tested via offline and recorded-response fixtures only - no live model calls, no spend during construction. The P4 comparison harness (baseline prompt, runner, scoring) stays wired and runnable; settling D12 takes a future spend decision plus a live run, the same pattern as P4's unrun step 5. Until then every scored metric on both sides is **not yet measured**.

**Acceptance criteria**

- [ ] Reachability, Exploitability, Adversary, Adjudicator implemented against the
      provider interface
- [ ] Async orchestration; the three analysts run concurrently
- [ ] Prompt caching on the shared context prefix
- [ ] The Adjudicator sees arguments with agent identities stripped
- [ ] Per-finding cost and latency tracked and reported
- [ ] Every cited `FileLineRef` is verified to exist before the verdict is accepted
- [ ] Injection resistance, structural: the P3 bait survives into the prompt as
      delimited data and is structurally incapable of reaching the verdict.
      Achievable offline; a real acceptance criterion for this phase.

**The following four require live model calls against the P4 dataset and cannot
be met on the zero-spend path. They are not deleted — they are P5's exit
criteria for whoever runs the eval later, built and wired now, unrun pending a
future spend decision:**

- [ ] Scored against the P4 baseline on the same dataset — harness built, wired,
      testable offline against recorded-response fixtures; **unrun pending live
      evaluation**
- [ ] **False suppression rate < 2%** and **> 60% of false positives dismissed** —
      scoring implemented and covered by tests against fixtures; **unrun pending
      live evaluation**
- [ ] Injection resistance, measured rate: the eval class scores structural
      survival against real model behavior, not just delimiter integrity — harness
      built; **unrun pending live evaluation**
- [ ] **Honesty clause** — if multi-agent does not meaningfully beat single-prompt,
      say so plainly and recommend cutting it. Cannot be applied with nothing run
      to compare; the clause stands as this phase's standard for whoever runs the
      eval, not as something this phase itself can satisfy. Do not tune the eval to
      agree with the architecture.

---

## ☐ P6 — Action, PR comments, release

**Acceptance criteria**

- [ ] `action.yml` works as `uses: fadhilfathi/sift-sast@v1` against a real repo
- [ ] Markdown PR comment, grouped by verdict, true positives first
- [ ] README carries **real measured numbers** and a recorded terminal demo
- [ ] README limitations/findings section includes, verbatim from
      `docs/ARCHITECTURE.md`: the GitHub-ignores-SARIF-suppressions finding (P1),
      the upstream-fingerprint-is-not-automatically-an-identity finding (P2),
      and the triability numbers from P4 stated as the paired pair they are —
      **3/103 (2.9%) on the four-language corpus** and **19/23 (82.6%) of
      Python findings alone**, with the 80/103 language exclusion named
      explicitly. Never one of the two numbers without the other.
- [ ] Adversarial review pass over the whole pipeline, findings triaged: every
      path where a real vulnerability could be silently dismissed, plus the
      threat model in `SECURITY.md`
- [ ] CHANGELOG complete, repo flipped public, **v0.1.0** tagged from a green `main`

---

## ☐ P7+ — Corpus/builder language parity (not scheduled)

Named here so it is not lost, not because it is next. Deliberately deferred
past P4-P6 per the P4 kickoff decision: attempting it mid-P4 risks shipping
neither a dataset nor a second language.

**The problem it addresses:** the fixture corpus is deliberately four
languages (Python, JavaScript, Java, Go) so the round-trip and pre-filter
tests in P1/P2 exercise more than one tool's SARIF shape. The context builder
is Python-only by P3's explicit scope. The gap between those two choices is
what produces the 77.7% `non_python_source` stratum measured in P4 — a
corpus/builder mismatch, not a capability finding, but one that will recur
for any future real-world dataset expansion until it is closed.

**Acceptance criteria, sketched, not committed:**

- [ ] Either the corpus gains a Python-only real-world source (a fifth
      pinned target repo), or the builder gains a second language
      (`CONTRIBUTING.md`'s "adding a language" section already specifies the
      per-language checklist: grammar, queries, fixture per query, `FileClass`
      heuristics, entrypoint detection, eval coverage)
- [ ] Whichever direction is chosen, re-run `evals/measure_triability.py`
      afterward and report the new stratification — the 2.9%/82.6% pair from
      P4 becomes the baseline this phase is measured against
- [ ] A language is not "supported" until it has eval coverage, per
      `CONTRIBUTING.md` — this phase does not close until that is true
