# SARIF fixture corpus

Input for the P1 lossless round-trip property test. Two halves, different jobs.

| Directory | What it is | Job |
| --- | --- | --- |
| `generated/` | Real Semgrep and CodeQL output against pinned OSS commits | Proves we handle what scanners actually emit |
| `handcrafted/` | Hand-written adversarial documents | Proves we handle the shapes scanners emit *rarely* |

Round-trip bugs live in the second set. A corpus of only real output tests one
tool's happy path repeatedly.

## Provenance

`generate.sh` is the source of truth for every file in `generated/`. It pins the
Semgrep version, the CodeQL CLI version, and the exact commit SHA of every target
repository, and it writes `MANIFEST.json` recording all of them plus a SHA-256 of
each fixture.

This exists so that a failing round-trip test six months from now can be diagnosed.
Without provenance you cannot tell a parser regression from a fixture that was
always malformed, and you end up debugging the wrong thing.

### The one thing that cannot be pinned

Semgrep registry rulesets are mutable — `p/security-audit` has no version in its
URL. `generate.sh` hashes the resolved rule YAML into `MANIFEST.json` instead. **If
a regenerated fixture differs, check that hash first.** A changed ruleset hash
explains the diff; an unchanged one means the difference is Semgrep's output format
or our code.

### Regeneration

```bash
./evals/fixtures/generate.sh              # everything (slow: CodeQL builds a DB per repo)
./evals/fixtures/generate.sh semgrep      # Semgrep half only
```

**Run it on Linux.** On Windows, Semgrep emits backslash-separated URIs
(`"uri": "probe\\vuln.py"`), so the corpus would differ from what is committed for
reasons unrelated to either scanner. The `fixtures` workflow runs it on a Linux
runner; that is the supported path.

Regenerate whenever a scanner version is bumped. A diff in the output **is the
point** — that is format drift, and catching it here rather than in a user's repo is
the whole reason the corpus is pinned and committed.

`generate.sh` scrubs absolute host paths out of `originalUriBaseIds` and artifact
locations, and drops invocation timestamps. Otherwise every regeneration on a
different machine would produce a diff carrying no information.

## Targets

| Repo | Language | Why |
| --- | --- | --- |
| `pallets/flask` | Python | Decorator-heavy routing; our first supported language |
| `expressjs/express` | JavaScript | Callback and middleware chains produce long `codeFlows` |
| `google/gson` | Java | Deep package nesting stresses path handling |
| `gorilla/mux` | Go | Different SARIF shape again, and no `codeFlows` from Semgrep |

CodeQL runs on Python and JavaScript only — the two that need no compiler, which
keeps a full regeneration inside a coffee break.

## Handcrafted fixtures

SARIF is JSON and cannot carry comments, so what each file probes is recorded here.
`vendor-extensions.sarif` is the exception: it uses a `$comment` key deliberately,
because unknown-top-level-key preservation is one of the things it tests.

| File | What it probes |
| --- | --- |
| `empty-results.sarif` | Empty `results` array; a run with no `results` key at all; a driver with no `rules` array. Three states that are easy to conflate. |
| `minimal-regions.sarif` | No `region`; `startLine` only; `startLine` + `startColumn` with no end bounds; no `locations` key; empty `locations` array; a byte-offset region with no line at all. |
| `codeflows.sarif` | Absent `codeFlows`; empty `codeFlows`; two flows where the second has two `threadFlows`, non-zero `nestingLevel`, and `executionOrder`. |
| `unicode-and-odd-paths.sarif` | Non-ASCII and CJK path segments; the same path written with `\u` escapes; Windows backslash separators; percent-encoded space and `#`; absolute `file:` URI; a `../../../../etc/passwd` traversal attempt; control characters, quotes, and an astral-plane emoji in messages. |
| `vendor-extensions.sarif` | Unknown keys at every depth — top level, driver, rule descriptor, result, location, `physicalLocation`. Tool `extensions` alongside the driver. `partialFingerprints` carrying a vendor key that must not be touched. |
| `multiple-runs.sarif` | Three runs in one file, including a failed invocation, and the same `ruleId` at the same location in two different runs — which must stay two findings. |
| `uri-base-id-indirection.sarif` | A three-level `uriBaseId` chain (`MODULE` → `REPO` → `SRCROOT`); `artifactLocation` with only an `index`; a plain relative URI in the same run; and a `uriBaseId` that is never defined, which must fail loudly rather than resolve to a guess. |
| `absent-null-empty.sarif` | The D2 canonicalization edge, directly: absent vs. `null` vs. empty for the same keys; integral floats, `-0.0`, exponent form, and an integer past 2^53; an empty message string; and a finding that arrived already suppressed upstream, which we must neither drop nor overwrite. |

The traversal path in `unicode-and-odd-paths.sarif` and the undefined `uriBaseId` in
`uri-base-id-indirection.sarif` are the two entries that are about safety rather than
format. A SARIF file is untrusted input.

## Schema deviations

Real scanner output sometimes fails the official SARIF 2.1.0 schema. Those cases are
recorded in [`SCHEMA_DEVIATIONS.md`](SCHEMA_DEVIATIONS.md) with the tool version and
a JSON pointer to the offending node.

Input is never mutated to satisfy a validator. Losslessness is our contract;
schema-validity is upstream's.
