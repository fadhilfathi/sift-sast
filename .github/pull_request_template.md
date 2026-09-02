## What and why

<!-- What changes, and the reason. The diff already says what; explain why. -->

Closes #

## Verdict impact

<!-- Required. If this cannot change any verdict, write "No verdict impact." -->

- [ ] No verdict impact
- [ ] Verdict impact — `make eval` delta below

| Metric | Before | After |
| --- | --- | --- |
| False suppression rate | | |
| FPs auto-dismissed | | |
| Injection resistance | | |
| Cost per finding | | |

## Checklist

- [ ] `make gate` passes locally
- [ ] Conventional Commit subject, under 72 chars
- [ ] No finding is ever deleted — suppression stays a labeled annotation
- [ ] The `FALSE_POSITIVE` confidence floor and unrebutted-objection rule are untouched
- [ ] `tests/test_verdict_safety.py` still passes unmodified
- [ ] No eval label was edited to make a test pass
- [ ] CHANGELOG updated if this is user-visible
- [ ] No secrets, no `.env`, no eval output containing source code
