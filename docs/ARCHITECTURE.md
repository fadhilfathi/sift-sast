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
