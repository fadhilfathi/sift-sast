# Operations

Repo-level settings that are not code. Kept here so they are reviewable and
reproducible rather than living only in someone's browser tab.

## Current state

| Setting | State | Note |
| --- | --- | --- |
| Visibility | **public** | Flipped at v0.1.0, 2026-09-16, once the pre-flip audit came back clean (one accepted residual — see below). |
| Issues | on | |
| Discussions | on | |
| Wiki, Projects | off | Docs live in `docs/`. |
| Dependabot alerts | on | |
| Dependabot security updates | on | |
| Dependabot version updates | on | `.github/dependabot.yml`, pip + github-actions |
| Delete branch on merge | on | |
| Secret scanning | **on** | Enabled at the flip (was GHAS-gated while private). Push protection also on. |
| Code scanning (CodeQL) | **on** | Self-enabled at the flip (`repository.visibility == 'public'`). First real run: 8 alerts — see below. |
| Dependency review | **on** | Same gate; fires on the next real pull request (its own condition is the `pull_request` event, not visibility alone). |
| Branch protection | **on** | Ruleset id `23525230`, applied post-flip. See below. |

## Branch protection

Applied 2026-09-16, immediately after the public flip (the 403 that blocked
this while private — `Upgrade to GitHub Pro or make this repository public
to enable this feature` — resolved as expected). Ruleset id `23525230`,
`enforcement: active`, verified by reading it back rather than trusting the
201: required checks `py3.11`, `py3.12`, `build`, `gitleaks`; PR required
before merge; no force pushes; no deletions; conversation resolution
required. Source of truth: [`.github/ruleset.json`](../.github/ruleset.json).

```bash
gh api repos/fadhilfathi/sift-sast/rulesets/23525230 --jq '{name, enforcement, rules: [.rules[].type]}'
```

Before this was applied, `main` was protected by convention only: `make
gate` before every push, CI watched to green after. That history is real —
every commit through v0.1.0 was gated that way, not by enforcement — and is
why the convention is worth keeping even now that enforcement exists.

## CodeQL self-scan: first real-world SAST output, triaged

The public flip's first CodeQL run produced this project's first-ever
real-world SAST findings — 8 alerts. Worth recording as its own event: this
is the first time anything has pointed a real scanner at this repo and
gotten real output back, as opposed to the fixture corpus this project
built for itself.

Triage below is a **human**, applying the tool's own standard by hand — not
SIFT's output. SIFT has never adjudicated a real finding; that remains true
after this. See the README's "We ran CodeQL against ourselves" section for
the two cases worth reading in full (the injection-bait fixture, and the
synthetic eval-dataset snapshots); this is the complete list.

| # | Rule | Location | Verdict | Why |
| --- | --- | --- | --- | --- |
| 1 | `py/clear-text-logging-sensitive-data` | `evals/dataset/snapshots/synth-v1/log_secret.py:11` | FALSE_POSITIVE | Real pattern (`logger.info(..., password)`), unreachable: file is read as text by the dataset builder and context builder, never imported or executed anywhere in `src/` or the test suite. |
| 2 | `py/weak-sensitive-data-hashing` (MD5) | `hash_md5.py:11` | FALSE_POSITIVE | Same reasoning: `beta_check_password`'s MD5 use is a real anti-pattern, unreachable. |
| 3 | `py/weak-sensitive-data-hashing` (SHA1) | `hash_sha1.py:6` | FALSE_POSITIVE | Same reasoning. |
| 4 | `py/command-line-injection` | `tests/fixtures/python_project/src/app.py:27` | FALSE_POSITIVE | The P3 injection-bait fixture. Unreachable (never imported/run); the adjacent "reviewed by security" comment is not part of the reasoning — see the README. |
| 5 | `py/insecure-temporary-file` | `temp_mktemp.py:6` | FALSE_POSITIVE | `tempfile.mktemp`'s race is real; unreachable. |
| 6 | `py/overly-permissive-file` | `perm_chmod.py:13` | FALSE_POSITIVE | `chmod 0o777` is real; unreachable. |
| 7 | `py/tarslip` | `tar_extract.py:10` | FALSE_POSITIVE | Unfiltered `extractall` is real; unreachable. |
| 8 | `py/request-without-cert-validation` | `tls_verify_false.py:10` | FALSE_POSITIVE | `verify=False` is real; unreachable. |

All 7 `evals/dataset/snapshots/synth-v1/` files are deliberate TP/FP twin
pairs built by `evals/dataset/build.py` for the D10 labeled dataset (see
`evals/dataset/README.md`); each carries a header stating exactly that.
Reachability for all 8 verified by `grep` across `src/`, `tests/`, and the
eval tooling — referenced only as path strings passed to
`build_context_bundle` (tree-sitter, text-only) or dataset entries, never
`import`ed, `exec`'d, or run. None of the 8 touched `sift.paths`,
`sift.ingest.fingerprint`, `sift.context.redact`, or the safety rule — the
no-fallback areas. A real finding there would have been fixed before this
table was written, not explained into a table row.

## Pre-flip audit: settled findings, not re-flagged

Two things a pre-flip audit will surface. Both were reviewed and settled
before the public flip; record here so a future audit doesn't re-raise them
as new.

**`.gitignore` names `CLAUDE.md` and `.claude/`.** This is not an
attribution concern. The rule this project enforces is about attribution —
no trailers, no generated-by footers, nothing that reads as the tool
claiming authorship of the code. It is not a rule against acknowledging
that AI-assisted tooling was used at all, and that second goal would not be
achievable or sensible anyway — a public security tool whose contributors
use an AI assistant is unremarkable. A `.gitignore` entry for a tool's local
config is the same category as `.vscode/` or `.idea/`: routine, expected,
present in most mature `.gitignore` files regardless of which tool. Leaving
it out would make the file worse — a contributor who opens this repo in
Claude Code should get `CLAUDE.md`/`.claude/` untracked automatically, not
have to add the entry themselves. Decision: keep as is, no history rewrite.

**One historical commit message named a specific tool.** `2cb4083`
(P4, "add cost estimation and the pre-call budget guard") originally read
"Pricing sourced from the claude-api skill's live table" — naming a Claude
Code skill used to source the pricing table. That crossed the actual line
(a specific AI-tool artifact named as the source of project content, not a
routine acknowledgment that tooling was used) and was corrected via an
authorized one-time history rewrite: `git filter-repo --message-callback`,
scoped to that exact four-word phrase, replacing it with "vendor pricing
documentation's" and preserving everything else — the cache date, the
`console.anthropic.com` cross-check note, and all surrounding reasoning.
Tree content verified identical before and after (same tree SHA); no file
changed, only that one commit's message. Mirror backup taken first and
retained. New commit SHA `8e4af41` (was `2cb4083`); `main` force-pushed with
`--force-with-lease` from `abb987e` to `8cdda05`.

**Accepted residual: `refs/pull/*` outlives the rewrite.** Two open
Dependabot PRs existed when the rewrite ran, forked from `main` before
`2cb4083` was corrected. Rewriting and force-pushing `main` does not touch
them — GitHub's `refs/pull/N/head` (and `/merge`, while a PR is open) are
server-managed refs, confirmed **read-only** by direct test:
`gh api -X DELETE .../git/refs/pull/2/head` returns `refs/pull/* is
read-only.` They are not affected by deleting the branch behind the PR, and
they are not removed by closing the PR — both PRs here were closed and both
`refs/pull/N/head` still resolve and still contain the original commit.

**The lesson, stated plainly so it is not rediscovered a third time:**
**a history rewrite must happen before any PR is opened against the
affected commits, or the rewrite cannot reach every ref.** Once a PR exists,
its `head` ref is permanent for the life of the repository, closed or not,
merged or not, branch deleted or not. This is the second time this project
has hit a GitHub ref-permanence surprise (the first, unrelated, was served
file *content* — `CLAUDE.md`/`.claude/` — which is why that earlier
incident needed a repo recreation; this one is a commit *message* on two
already-closed PRs, reachable only via their commit views).

**Decision: accept this residual. Do not recreate the repo.** What remains
live is one phrase, in one commit message, reachable only by opening PR #1
or PR #2's commit view on GitHub — not served file content, not a trailer,
not anything reading as the tool claiming authorship. Recreating the repo
to remove it would cost the URL, the visible history, and any accrued
signal, against a gain the attribution rule was never trying to buy: the
rule bars trailers, generated-by footers, and authorship claims, not every
mention that AI-assisted tooling exists. A future audit should not
re-litigate this or trigger another recreation over it — this paragraph is
that audit's answer.

**Current state, for the record:** no ref under `refs/heads/*` points at
the old commit; `main` (`refs/heads/main`) is clean. `refs/pull/1/head` and
`refs/pull/2/head` are the only two refs on the remote that still do.

## Verifying the SARIF emitter against Code Scanning

SIFT must emit SARIF that GitHub Code Scanning accepts **and renders**. A `202`
from the upload endpoint is not evidence of that: a SARIF file can be accepted and
then processed into nothing. The check is only meaningful if the alerts are read
back and asserted.

`sift` stays private, so verification runs in a permanent public companion repo:
[`fadhilfathi/sarif-upload-check`](https://github.com/fadhilfathi/sarif-upload-check).
It is reused at P6 for the Action end-to-end test and any time the emitter changes.

### Procedure

**P1** (`--dry-run`, passthrough only — establishes upload/readback mechanics):

1. Edit `sarif/input.sarif` in that repo if the case being tested has changed, and
   make sure every line number it references exists in `src/app.py`.
2. Regenerate the emitted file with the SIFT build under test:

   ```bash
   sift triage sarif/input.sarif --out sarif/emitted.sarif --dry-run
   ```

3. Commit and push. The `Verify SARIF upload` workflow runs on any change to
   `sarif/emitted.sarif` or `src/`, and can also be dispatched manually.
4. Watch it: `gh run watch <id> -R fadhilfathi/sarif-upload-check`

**P6** (real four-agent annotation, zero spend — re-verifies the emitter that
actually attaches verdicts and `Suppression`s, not just a passthrough copy):

1. Clone `fadhilfathi/sarif-upload-check` locally.
2. From this repo: `python scripts/reverify_sarif_upload.py /path/to/sarif-upload-check`.
   Runs the real orchestrator (`run_pipeline`) against a deterministic fake
   `complete_fn` keyed on each finding's `rule_id` — zero network, zero
   spend, real `annotate.py` output. `command-injection`/`sql-injection`/
   `path-traversal` come back `TRUE_POSITIVE`; the two `suppressed-*` rules
   come back `FALSE_POSITIVE`, so the regenerated file carries a genuine
   SIFT-emitted `Suppression`, appended to (never replacing) any
   pre-existing one on that result.
3. In the harness checkout: commit `sarif/emitted.sarif`, push.
4. Watch the triggered run: `gh run watch <id> -R fadhilfathi/sarif-upload-check`.

Either way, the workflow uploads through the code-scanning API, polls
`/code-scanning/sarifs/{id}` until `processing_status` is `complete`, then reads
`/code-scanning/alerts` back and asserts on rule IDs, file paths, line numbers,
`security_severity_level`, and open/dismissed state.

Upload needs the `security_events` scope. The workflow uses `GITHUB_TOKEN` with
`security-events: write`, so no personal token needs that scope. A local `gh` will
not be able to upload unless you run `gh auth refresh -s security_events`.

### What it has established

| Question | Answer | When |
| --- | --- | --- |
| Does emitted SARIF upload and process cleanly? | Yes | P1 |
| Do file paths and line numbers survive? | Yes — `src/app.py` at lines 19, 26, 32 | P1 |
| Does `security-severity` survive into the alert? | Yes — `9.8` rendered as `critical` | P1 |
| Do SARIF `suppressions` dismiss an alert? | **No.** Neither `external` nor `inSource`. Five uploaded, five open, zero dismissed. | P1 |
| Does the finding still hold for a `Suppression` written by the real P5/P6 pipeline, not a hand-crafted one? | **Yes, unchanged.** Both `suppressed-*` alerts stayed open after a real `FALSE_POSITIVE` adjudication appended its own `Suppression` alongside the pre-existing one. | P6 |

The suppression rows are why dismissals must go through
`PATCH /code-scanning/alerts/{number}` rather than through the SARIF document —
and why this Action does not call that endpoint automatically (see README,
"Suppression behavior"). See also `docs/ARCHITECTURE.md`.

## Secrets

| Secret | Used by | Set? |
| --- | --- | --- |
| `SIFT_API_KEY` | `eval.yml` | not set — the eval workflow's real run will fail until it is |

CI deliberately blanks `SIFT_API_KEY` and deselects the `llm` pytest marker,
so no pull request can spend money.

## PyPI

The distribution name is `sift-sast` (`sift` is taken). Nothing is published yet.

To reserve the name and enable releases:

1. Create the PyPI project by uploading the v0.0.0 build once, manually.
2. Add a trusted publisher at https://pypi.org/manage/account/publishing/ —
   owner `fadhilfathi`, repo `sift`, workflow `release.yml`, environment `pypi`.
3. Create a `pypi` environment in repo settings, restricted to tag pushes.
4. Uncomment the `publish-pypi` job in `.github/workflows/release.yml`.

No API token is needed once trusted publishing is configured; the job uses OIDC.
