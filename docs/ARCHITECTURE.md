# Architecture

## Data flow

```
                      ┌──────────────────────────────────────────┐
   results.sarif ────▶│ INGEST  sift.ingest                      │
   (Semgrep,          │ parse SARIF 2.1.0, preserve unknown keys │
    CodeQL, …)        │ compute a stable fingerprint per finding │
                      └───────────────────┬──────────────────────┘
                                          │ list[Result]
                      ┌───────────────────▼──────────────────────┐
                      │ STAGE 1  PRE-FILTER  (no LLM)            │
                      │ dedupe by fingerprint                    │
                      │ classify: test / vendored / generated /  │
                      │           fixture                        │
                      │ anything resolvable without a model      │
                      │ must never reach a model                 │
                      └──────┬────────────────────────┬──────────┘
                     resolved│                        │survivors
                             │                        │
                             │        ┌───────────────▼──────────┐
                             │        │ STAGE 2  CONTEXT BUILDER │
                             │        │ tree-sitter, no LLM      │
                             │        │ → ContextBundle          │
                             │        └───────────────┬──────────┘
                             │                        │
                             │        ┌───────────────▼──────────────────────┐
                             │        │ STAGE 3  ADJUDICATION (LLM)          │
                             │        │                                      │
                             │        │  Reachability ─┐                     │
                             │        │  Exploitability├─▶ Adjudicator ─▶ ✔  │
                             │        │  Adversary ────┘   (sees arguments,  │
                             │        │   (argues TP)       not identities)  │
                             │        └───────────────┬──────────────────────┘
                             │                        │
                      ┌──────▼────────────────────────▼──────────┐
                      │ STAGE 4  EMITTERS                        │
                      │ annotated SARIF · Markdown PR comment ·  │
                      │ JSON run report (cost, latency, verdicts)│
                      └──────────────────────────────────────────┘
```

Every finding that enters leaves. Stage 1 short-circuits to Stage 4 with a
`resolved_by` label; it never deletes.

## Stage 1 — deterministic pre-filter

No LLM calls. Deduplicates by fingerprint, then applies rule-based file
classification (`FileClass`). The fraction of findings resolved here is the
**baseline every later stage must beat** — measured in P2 and reported.

## Stage 2 — Context Builder

tree-sitter only. Produces one `ContextBundle` per surviving finding:

- the flagged line plus the full enclosing function body
- the full data flow path from SARIF `codeFlows` when the scanner provided one
- direct callers of the enclosing function, 1–2 hops up
- definitions of functions called on the taint path
- is-test / is-generated / is-vendored classification
- external reachability of the entrypoint (HTTP handler, CLI arg, queue, cron, …)
- imports, and any sanitizer or validator calls on the path

Context quality caps triage quality. If the builder cannot resolve something, it
records a `build_warning` rather than guessing; agents must read warnings as doubt.

## Stage 3 — adjudication

| Agent | Question | Constraint |
| --- | --- | --- |
| Reachability Analyst | Can untrusted input actually reach this sink? | Argues from the call graph only. |
| Exploitability Analyst | If reached, is there real impact? | Considers sanitizers, framework protections, type constraints. |
| Adversary | Argues the finding **is** a true positive and attacks the other two. | Exists to counteract the model's bias toward agreeable dismissal — our single worst failure mode. |
| Adjudicator | Emits the verdict. | Sees all three arguments plus raw context, but **not** agent identities. Opus; never downgraded to save cost. |

The first three run concurrently on a shared, prompt-cached context prefix.

### The safety rule

`FALSE_POSITIVE` requires `confidence >= 0.85` **and** no unrebutted Adversary
objection. Otherwise the verdict becomes `NEEDS_HUMAN_REVIEW`, with
`downgraded_from` and `downgrade_reason` recorded. Enforced in the schema, not in
prompt text, so no model output can bypass it.

## Stage 4 — emitters

- **Annotated SARIF** — a `Suppression` with `justification` for dismissals, plus a
  `properties` bag carrying confidence, reasoning, and the agent arguments.
- **Markdown PR comment** — grouped by verdict, true positives first.
- **JSON run report** — cost, latency, verdict distribution, model IDs, prompt hashes.

### Measured: GitHub ignores SARIF suppressions

Verified in P1 against a real repository, not inferred from documentation. Both
suppression kinds were uploaded together through the code-scanning API:

| Suppression | `status` | Result |
| --- | --- | --- |
| `kind: "external"` | `accepted` | alert came back **open** |
| `kind: "inSource"` | `accepted` | alert came back **open** |

Five findings uploaded, five alerts open, zero dismissed. Locations, line numbers,
and `security-severity` all survived intact; only the suppressions were dropped.
Reproduce with the `Verify SARIF upload` workflow in
[`fadhilfathi/sarif-upload-check`](https://github.com/fadhilfathi/sarif-upload-check).

Consequences for P5 and P6:

1. A `Suppression` in emitted SARIF is **inert on GitHub**. We still write it,
   because it is the interop-correct place for the justification and other
   consumers read it — but it will not dismiss an alert on its own.
2. Dismissing a Code Scanning alert requires a **separate authenticated call**:
   `PATCH /repos/{owner}/{repo}/code-scanning/alerts/{number}` with
   `state=dismissed` and a `dismissed_reason`. That is an additional, explicitly
   granted permission, and the Action must treat it as opt-in.
3. This is the safe direction to be wrong in. The failure mode is a dismissal that
   does not take effect and leaves an alert visible, not a real vulnerability
   silently disappearing from someone's dashboard.

Because the dismissal path runs through an alert-number API rather than through the
SARIF document, the correlation ID cannot be what addresses it. GitHub's alert
identity is — which is the second reason D1 refuses to compete with it.

## Trust boundary

```
  repo under analysis        SIFT                       LLM provider
  ───────────────────        ────                       ────────────
  source, comments,   ──▶  wrap in untrusted-data  ──▶  prompt
  strings, filenames       delimiters
       (UNTRUSTED)         redact secrets
                           path-traversal check
                           content-addressed cache

                      ◀──  validate into Pydantic  ◀──  response
                           verify every cited line
                           actually exists
```

Analyzed source is data. It is never allowed to act as an instruction. Cited
`FileLineRef`s are verified against the real file before a verdict is accepted —
a hallucinated citation invalidates the argument that made it.

## Finding identity

> **Decision D1**, settled before P1 implementation. This is load-bearing well past
> P1: it keys the LLM cache, it decides whether a suppression stays attached to an
> alert across commits, and it decides whether a triaged finding stays triaged when
> someone adds an import at the top of a file.

### There are three identities, not one

Collapsing them into one identifier is the mistake that produces suppressions
which appear to randomly detach from alerts. They answer different questions and
have opposite stability requirements.

| Identity | Question it answers | Owner |
| --- | --- | --- |
| **Alert identity** | Is this the same alert GitHub showed last commit? | **GitHub. Not us.** |
| **Correlation ID** | Is this the same finding a human already reviewed? | SIFT |
| **Cache key** | Have I already adjudicated this exact situation? | SIFT |

### 1. Alert identity — we do not own it, and we do not touch it

GitHub Code Scanning tracks alerts across commits using `partialFingerprints`,
principally `primaryLocationLineHash`. When a tool omits them the `codeql-action`
injects them at upload time — visible in our own CI log:

```
Adding fingerprints to SARIF file. See .../sarif-support-for-code-scanning
```

So an alert-tracking identity already exists in the pipeline before SIFT is
involved.

**Rule: `fingerprints` and `partialFingerprints` pass through untouched. SIFT never
adds a key, never modifies a value, never removes one.**

The consequence is the point: GitHub's alert matching behaves *exactly* as it would
if SIFT were not in the pipeline. A suppression we attach to a result stays attached
to the alert for precisely as long as GitHub says it is the same alert. We cannot
introduce a detachment bug in a mechanism we do not write to.

The tempting alternative — adding `sift/v1` into `partialFingerprints` — is
rejected. GitHub's matching behavior over multiple fingerprint keys is not something
we control or can pin, and getting it wrong silently detaches suppressions. SIFT's
own identifiers go in the `properties` bag, which has no matching semantics.

### 2. Correlation ID — "did a human already look at this?"

Derived, in this precedence order. The tier actually used is recorded in
`properties["sift/v1"].identity_source` so a human debugging a detachment can see
which one fired without re-deriving it.

1. `partialFingerprints["primaryLocationLineHash"]`, when present.
   Preferred because it makes our correlation agree with GitHub's alert identity for
   free. Disagreeing with GitHub is the failure mode we are avoiding; inheriting its
   answer is strictly better than inventing a competing one.
2. A value from `fingerprints`, when the tool supplied a versioned full fingerprint.
3. **Fallback, computed by SIFT:**
   `sha256(rule_id, normalized_path, normalized_flagged_line)`

Normalization for tier 3:

- **path** — POSIX separators, repo-relative, URI-decoded, Unicode NFC
- **flagged line** — trailing whitespace and line ending stripped. **Leading
  whitespace is preserved.**

That last point is deliberate and worth stating, because it looks like an
oversight. In Python indentation is semantic. A line dedented out of an `if
is_admin:` guard is byte-identical after an `lstrip()` but is a completely different
security situation. Normalizing leading whitespace away would let a genuinely
dangerous edit silently inherit a stale dismissal. The cost of keeping it is that a
reformatter detaches the finding and forces re-review — the safe direction.

### 3. Cache key — "can I reuse a verdict?"

```
sha256(correlation_id, canonical(ContextBundle), model_ids,
       temperature, prompt_version_hashes, sift_version)
```

This is a **different and deliberately more sensitive** hash than the correlation
ID, and the reason is the asymmetric error cost:

- A cache key that is **too stable** reuses a verdict computed from code that has
  since changed. Delete the sanitizer two lines below the flagged line and a stale
  `FALSE_POSITIVE` is reused. That is a missed true positive — the ~50x-cost error.
- A cache key that is **too sensitive** re-adjudicates unnecessarily. That costs
  money.

So the whole `ContextBundle` is in the key, not just the flagged line. A function
body edit that does not touch the flagged line **must** produce a new cache key,
because it can change the correct verdict.

**Rule: when in doubt, change the key.** Re-adjudication costs cents. Reusing a
stale dismissal costs a breach.

Including model IDs, temperature, and prompt hashes also satisfies the
content-addressing requirement in the threat model: a cached verdict can never be
served for a configuration that did not produce it.

### Stability matrix

Tested in P1. "Change" means the identifier must differ.

| Change to the code | Correlation ID | Cache key | Why |
| --- | --- | --- | --- |
| Insert a line above the finding | no change | no change | Line numbers move; identity is content-based, not positional. This is the single most common edit and must not detach a review. |
| Trailing whitespace / line-ending change on the flagged line | no change | no change | Not a semantic change. |
| Reformat that re-indents the flagged line | **change** | **change** | Indentation is semantic in Python. Detaching and re-reviewing is the safe direction. |
| Edit the flagged line | **change** | **change** | Different code, different finding. |
| Edit the enclosing function, not the flagged line | no change | **change** | Same finding a human reviewed, but the evidence changed — a sanitizer may have been removed. This row is the entire reason the two identities are separate. |
| Rename the file | **change** | **change** | Path is part of identity. GitHub detaches here too; matching its behavior beats being cleverer than it. |
| Same rule fires twice on one line at different columns | **change** | **change** | Column is included when the region supplies one. |
| Upgrade the model, or edit a prompt | no change | **change** | Same finding, new judgment required. |

A fingerprint that never changes is as broken as one that always does. These are
the specific rows that make it neither.

### Not in scope for P1

Correlation ID and cache key are *specified* here and the correlation ID is
*implemented and tested* in P1. The cache key cannot be implemented until
`ContextBundle` is populated in P3 and the prompts exist in P5. It is documented now
because the correlation ID's design only makes sense against it.

## Lossless round-trip

> **Decision D2**, settled before P1 implementation.

### The definition

**Lossless means semantic equality of the parsed documents under the
canonicalization below.** Formally, the P1 property test asserts:

```
canonical(parse(emit(parse(x)))) == canonical(parse(x))
```

### Byte-identical is explicitly rejected as the target

It is not achievable and pretending otherwise is worse than choosing a weaker
honest target:

- JSON object key order is not semantic, and no encoder preserves input order
  through a typed model
- encoders differ on unicode escaping (`é` vs `é`) and on number formatting
- real Semgrep and CodeQL output contains constructs the official schema rejects,
  so "byte-identical" and "schema-valid" can be in direct conflict

A byte-identical assertion would fail on the first real fixture and then get
quietly relaxed. Relaxing a check to make it pass is forbidden by CONTRIBUTING, so
we must not write a check that invites it. Semantic equality is enforceable and
holds.

### Canonicalization rules

| Aspect | Rule |
| --- | --- |
| Key order | Not significant. Compare parsed mappings, not text. |
| Whitespace and indentation in the JSON text | Not significant. |
| Numbers | Normalized: an integral float is equal to the same integer (`1.0 == 1`). SARIF line and column values are integers. |
| Strings | Compared decoded. `"é"` equals `"é"`. Output is UTF-8 with `ensure_ascii=False`. |
| **Absent vs. `null`** | **Significant. Not equal.** A key absent in the input must be absent in the output. |
| **Absent vs. `[]` / `{}`** | **Significant. Not equal.** An empty array we invent is a change to the document. |
| Unknown keys | Preserved, at every nesting depth, with their values compared by these same rules. |
| Array order | Significant everywhere. `results` order is meaningful to consumers. |

The absent/`null`/empty distinctions are why every SARIF model sets
`extra="allow"` and why emit uses `exclude_unset=True`. A Pydantic model with
defaults will happily materialize `"suppressions": []` onto a result that never had
the key. That is a silent mutation of someone else's document, and under this
definition it is a test failure rather than a shrug.

### Schema validation and upstream deviations

Emitted SARIF is validated against the official SARIF 2.1.0 JSON schema.

Real scanner output sometimes fails that schema. When a fixture does:

- **Never mutate the input to make it validate.** Rewriting a user's document to
  satisfy a validator is exactly the silent-modification failure this whole
  document is arguing against.
- Record it in `evals/fixtures/SCHEMA_DEVIATIONS.md`: fixture path, tool and exact
  version, JSON pointer to the offending node, and the validator's message.
- The round-trip property test still applies. Losslessness is our contract;
  schema-validity is upstream's.

### The emitter cannot drop a result

Structural, not conventional. The emitter asserts `len(results_out) ==
len(results_in)` per run, and that the multiset of correlation IDs is unchanged. In
P1 nothing is suppressed yet, but the invariant is written now so that the code
which later *does* attach suppressions was never shaped around being able to filter.

In P1 the emitter adds nothing at all — no properties, no suppressions. Pure
passthrough. The first thing it writes is in P5.

## Schemas

Full definitions live in `src/sift/models/`. Summary:

### ContextBundle — `models/context.py`

```python
class ContextBundle(BaseModel):
    finding_fingerprint: str
    rule_id: str
    rule_description: str | None
    message: str

    flagged: FileLineRef
    enclosing_function: CodeSpan | None
    callers: list[CallSite]            # 1-3 hops up
    called_definitions: list[CodeSpan] # callees on the taint path
    data_flow: list[FlowStep]          # from SARIF codeFlows

    file_class: FileClass              # SOURCE|TEST|GENERATED|VENDORED|FIXTURE|UNKNOWN
    imports: list[str]
    sanitizers: list[SanitizerCall]    # confirmed only if the definition was read
    reachability: Reachability         # entrypoint kind + path; externally_reachable
                                       # is None when undecidable — never guessed
    truncated: bool
    build_warnings: list[str]
```

Supporting types: `CodeSpan` (verbatim source slice), `CallSite`, `FlowStep`,
`SanitizerCall`, `Reachability`, `FileClass`, `EntrypointKind`.

### Verdict — `models/verdict.py`

```python
class Adjudication(BaseModel):
    finding_fingerprint: str
    verdict: Verdict                   # TRUE_POSITIVE|FALSE_POSITIVE|NEEDS_HUMAN_REVIEW
    confidence: float                  # 0.0-1.0
    justification: str                 # max 500 chars, must cite specific code
    evidence_lines: list[FileLineRef]  # validated to exist
    unresolved_questions: list[str]
    open_objections: list[Objection]
    downgraded_from: Verdict | None    # set when the safety rule overrode the model
    downgrade_reason: str | None
```

Supporting types: `AgentArgument` (one analyst's position; `role` is stripped
before the Adjudicator sees it), `Objection` (an Adversary claim plus whether it
was rebutted), `FileLineRef`, `TriageResult` (adjudication + arguments +
`resolved_by` + cost + latency).

`Adjudication` uses `validate_assignment=True`, so the safety rule re-runs on
mutation — a later edit cannot sneak a weak dismissal through.

## Backward compatibility

`ContextBundle` and `Adjudication` are the interop surface between stages and
across versions. Additive optional fields are fine. Removing a field, tightening a
constraint, or changing a field's meaning is a breaking change and needs a version
bump plus a CHANGELOG entry.
