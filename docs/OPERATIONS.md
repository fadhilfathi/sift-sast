# Operations

Repo-level settings that are not code. Kept here so they are reviewable and
reproducible rather than living only in someone's browser tab.

## Current state

| Setting | State | Note |
| --- | --- | --- |
| Visibility | private | Flips public at v0.1.0, once the README carries measured numbers. |
| Issues | on | |
| Discussions | on | |
| Wiki, Projects | off | Docs live in `docs/`. |
| Dependabot alerts | on | |
| Dependabot security updates | on | |
| Dependabot version updates | on | `.github/dependabot.yml`, pip + github-actions |
| Delete branch on merge | on | |
| Secret scanning | **unavailable** | Needs a public repo or GHAS. The `gitleaks` job covers it meanwhile, scanning full history on every run. |
| Code scanning (CodeQL) | **unavailable** | Needs a public repo or GHAS. The job is gated on `repository.visibility == 'public'` and enables itself on the flip. |
| Dependency review | **unavailable** | Same gate, same reason. |
| Branch protection | **unavailable** | Needs GitHub Pro or a public repo. See below. |

## Branch protection

`gh api -X PUT repos/fadhilfathi/sift-sast/branches/main/protection` and the rulesets
API both return:

```
403 Upgrade to GitHub Pro or make this repository public to enable this feature.
```

The intended ruleset is committed at [`.github/ruleset.json`](../.github/ruleset.json):
required checks `py3.11`, `py3.12`, `build`, `gitleaks`; PR required before merge;
linear history; no force pushes; no deletions; conversation resolution required.

Apply it the moment the repo goes public or the account upgrades:

```bash
gh api -X POST repos/fadhilfathi/sift-sast/rulesets --input .github/ruleset.json
gh api repos/fadhilfathi/sift-sast/rulesets --jq '.[]|{id,name,enforcement}'
```

Until then `main` is protected by convention only: `make gate` before every push,
and CI watched to green after. That is weaker than enforcement. Do not treat a
green badge as a substitute for running the gate locally.

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
