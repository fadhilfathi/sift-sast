# Known SARIF schema deviations

Fixtures that fail validation against the official SARIF 2.1.0 JSON schema
(vendored at `tests/schema/sarif-schema-2.1.0.json`), and why we keep them.

**Input is never mutated to make it validate.** Rewriting a user's document to
satisfy a validator is a silent modification, which is the exact failure the
lossless contract exists to prevent. Losslessness is ours; schema-validity is the
document author's.

Every fixture here is still covered by the round-trip property test. What the
schema test asserts is narrower and more useful: **a round trip must not change
the set of violations.** A valid document stays valid, and an invalid one gets no
worse.

## Real scanner output

**No deviations.** All twelve generated fixtures — Semgrep 1.176.0 and CodeQL
v2.26.4 across `pallets/flask`, `expressjs/express`, `google/gson`, and
`gorilla/mux` — validate cleanly.

This was not the expected result. The premise going in was that real output
routinely violates the schema, and for these tools at these versions it does not.
The finding is recorded rather than the assumption, and `test_no_undeclared_invalid_fixtures`
fails the build if a future scanner version changes it.

## Handcrafted fixtures

Both entries are deliberate. They exist to probe behavior the schema does not
permit but that we must still handle correctly.

| Fixture | JSON pointer | Validator message | Why it stays |
| --- | --- | --- | --- |
| `handcrafted/absent-null-empty.sarif` | `/runs/0/results/2/level` | `None is not one of ['none', 'note', 'warning', 'error']` | Absent, `null`, and empty are three distinct states. The round trip must return exactly the one it was given, so we need a document that contains explicit nulls. |
| `handcrafted/absent-null-empty.sarif` | `/runs/0/results/2/locations/0/physicalLocation/region/endColumn` | `None is not of type 'integer'` | Same reason, at a nested numeric field. |
| `handcrafted/vendor-extensions.sarif` | `/` | `Additional properties are not allowed ('$comment', 'x-vendor-top-level' were unexpected)` | See below. |
| `handcrafted/vendor-extensions.sarif` | `/runs/0/results/0` | `Additional properties are not allowed ('x-unknown-on-result' was unexpected)` | Unknown keys on a result. |
| `handcrafted/vendor-extensions.sarif` | `/runs/0/results/0/locations/0/physicalLocation` | `Additional properties are not allowed ('x-unknown-on-physical-location' was unexpected)` | Unknown keys nested inside a location. |

### The `additionalProperties: false` finding

The official schema **forbids unknown keys** outside the designated `properties`
bags. Tools emit them anyway, and we must round-trip whatever we are handed — so
this fixture has to exist and has to be invalid.

It also settles a design question from the other direction. SIFT writes its own
data into the `properties` bag and nowhere else (decision D1). That choice was
made to avoid interfering with GitHub's alert matching; the schema turns out to
require it independently. Anything SIFT emits at the top level, on a result, or on
a location would make our own output schema-invalid.

## Adding an entry

1. Confirm it is genuinely upstream's output, not our emitter's. If our emitter
   produced it, that is a bug to fix, not a deviation to record.
2. Record the exact tool version. A deviation is version-specific and may vanish
   on the next scanner bump.
3. Quote the validator's message verbatim. A paraphrase is not diagnosable later.
4. Add the filename to `KNOWN_INVALID` in `tests/test_schema.py`, with the reason.
