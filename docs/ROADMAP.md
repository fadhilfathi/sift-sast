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
- [x] Six subagents and six slash commands under `.claude/`
- [x] `make gate` green locally, CI green on `main`
- [x] No attribution trailer in any commit (`git log --format=%B`)

---

## ☐ P1 — SARIF ingest and emit, lossless round-trip

No LLM.

**Acceptance criteria**

- [ ] `sift.ingest` parses SARIF 2.1.0 into `SarifLog`; unknown keys survive
- [ ] `sift.emit.sarif` writes it back
- [ ] Property test (hypothesis) over **20 real SARIF fixtures** from Semgrep and
      CodeQL: `parse(emit(parse(x))) == parse(x)`, and unknown keys are byte-identical
- [ ] Output validates against the official SARIF 2.1.0 JSON schema
- [ ] Output **accepted by GitHub Code Scanning** — verified by an actual upload,
      not assumed
- [ ] Stable per-finding fingerprint; documented and tested for stability across
      line-number shifts

**Done means:** a SARIF file makes the full round trip with zero loss and the
result renders in Code Scanning.

---

## ☐ P2 — Deterministic pre-filter

Zero LLM calls.

**Acceptance criteria**

- [ ] Dedupe by fingerprint
- [ ] `FileClass` detection for test, vendored, generated, fixture files
- [ ] Every resolution carries a `resolved_by` label and a justification. Nothing
      is deleted.
- [ ] Prints the fraction of findings resolved with no model — **this number is the
      baseline every later stage must beat**, and it goes in the report
- [ ] Precision of the pre-filter itself measured: how often does it mislabel a
      real source file as a test or vendored file? Target 0.

**Done means:** the baseline is measured and committed.

---

## ☐ P3 — Context Builder, Python only

**Acceptance criteria**

- [ ] tree-sitter queries for Python: function bounds, callers, callees, imports
- [ ] Fixture test per query
- [ ] Populates every `ContextBundle` field, or records a `build_warning`
- [ ] Path reads are traversal-safe and scoped to the repo root, with a test that
      a `../../etc/passwd` style path is refused
- [ ] Secrets redacted from every span before the bundle leaves the builder
- [ ] `sift context dump <sarif>` writes `ContextBundle` JSON **for human review
      before any model sees it**
- [ ] Reviewed and approved by the maintainer

**Done means:** context quality is inspected and signed off. It caps triage quality.

---

## ☐ P4 — Eval harness and labeled dataset, then a naive baseline

Built **before** the agents, on purpose.

**Acceptance criteria**

- [ ] `evals/dataset/` holds **≥ 100 labeled findings, class balanced**, seeded from
      OWASP Benchmark, the Juliet Test Suite, and real CVE-fix commits
- [ ] Each entry: finding + repo snapshot + ground truth label + rationale
- [ ] A dedicated **prompt-injection test class** with its own metric
- [ ] Metrics: precision, recall, **false suppression rate** (first), injection
      resistance, cost per finding, p95 latency
- [ ] Every report records model IDs, temperature, and prompt hashes
- [ ] `--dry-run` prints estimated cost and call count and spends nothing
- [ ] Hard abort at **$5.00 per run**, checked before each call
- [ ] Content-hash cache so re-running on unchanged findings costs near zero
- [ ] `make eval` is reproducible and writes `evals/REPORT.md`, committed
- [ ] A deliberately naive **single-prompt baseline**, scored. **That number is the
      bar the multi-agent design must clear.**

**Done means:** we can measure. Until then no architectural claim is admissible.

---

## ☐ P5 — Four-agent pipeline

**Acceptance criteria**

- [ ] Reachability, Exploitability, Adversary, Adjudicator implemented against the
      provider interface
- [ ] Async orchestration; the three analysts run concurrently
- [ ] Prompt caching on the shared context prefix
- [ ] The Adjudicator sees arguments with agent identities stripped
- [ ] Per-finding cost and latency tracked and reported
- [ ] Every cited `FileLineRef` is verified to exist before the verdict is accepted
- [ ] Scored against the P4 baseline on the same dataset
- [ ] **False suppression rate < 2%** and **> 60% of false positives dismissed**
- [ ] Injection resistance measured and published

**Honesty clause:** if multi-agent does not meaningfully beat single-prompt, say so
plainly in the report and recommend cutting it. Do not tune the eval to agree with
the architecture.

---

## ☐ P6 — Action, PR comments, release

**Acceptance criteria**

- [ ] `action.yml` works as `uses: fadhilfathi/sift@v1` against a real repo
- [ ] Markdown PR comment, grouped by verdict, true positives first
- [ ] README carries **real measured numbers** and a recorded terminal demo
- [ ] `/redteam` pass by `adversarial-reviewer`, findings triaged
- [ ] CHANGELOG complete, repo flipped public, **v0.1.0** tagged from a green `main`
