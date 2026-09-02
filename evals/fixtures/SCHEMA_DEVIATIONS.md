# Known SARIF schema deviations

Fixtures in this corpus that fail validation against the official SARIF 2.1.0 JSON
schema, and why we keep them anyway.

**Input is never mutated to make it validate.** Rewriting a user's document to
satisfy a validator is a silent modification, which is the exact failure the
lossless contract exists to prevent. Losslessness is ours; schema-validity is
upstream's.

A deviation recorded here is still covered by the round-trip property test. It is
excluded only from the schema-validation test, by explicit path.

## Recorded deviations

Not yet populated — the corpus has not been generated or validated yet. Populated in
P1 step 5.

| Fixture | Tool + version | JSON pointer | Validator message |
| --- | --- | --- | --- |
| _none recorded yet_ | | | |

## Adding an entry

1. Confirm it is genuinely upstream's output, not our emitter's. If our emitter
   produced it, that is a bug to fix, not a deviation to record.
2. Record the exact tool version. A deviation is version-specific and may disappear
   on the next scanner bump.
3. Quote the validator's message verbatim. A paraphrase is not diagnosable later.
