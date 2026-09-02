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

`gh api -X PUT repos/fadhilfathi/sift/branches/main/protection` and the rulesets
API both return:

```
403 Upgrade to GitHub Pro or make this repository public to enable this feature.
```

The intended ruleset is committed at [`.github/ruleset.json`](../.github/ruleset.json):
required checks `py3.11`, `py3.12`, `build`, `gitleaks`; PR required before merge;
linear history; no force pushes; no deletions; conversation resolution required.

Apply it the moment the repo goes public or the account upgrades:

```bash
gh api -X POST repos/fadhilfathi/sift/rulesets --input .github/ruleset.json
gh api repos/fadhilfathi/sift/rulesets --jq '.[]|{id,name,enforcement}'
```

Until then `main` is protected by convention only: `make gate` before every push,
and CI watched to green after. That is weaker than enforcement. Do not treat a
green badge as a substitute for running the gate locally.

## Verifying the SARIF emitter against Code Scanning

SIFT must emit SARIF that GitHub Code Scanning accepts **and renders**. A `202`
from the upload endpoint is not evidence of that: a SARIF file can be accepted and
then processed into nothing. The check is only meaningful if the alerts are read
back and asserted.

`sift` stays private, so verification runs in a permanent public companion repo:
[`fadhilfathi/sarif-upload-check`](https://github.com/fadhilfathi/sarif-upload-check).
It is reused at P6 for the Action end-to-end test and any time the emitter changes.

### Procedure

1. Edit `sarif/input.sarif` in that repo if the case being tested has changed, and
   make sure every line number it references exists in `src/app.py`.
2. Regenerate the emitted file with the SIFT build under test:

   ```bash
   sift triage sarif/input.sarif --out sarif/emitted.sarif --dry-run
   ```

3. Commit and push. The `Verify SARIF upload` workflow runs on any change to
   `sarif/emitted.sarif` or `src/`, and can also be dispatched manually.
4. Watch it: `gh run watch <id> -R fadhilfathi/sarif-upload-check`

The workflow uploads through the code-scanning API, polls
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

The last row is why dismissals in P6 must go through
`PATCH /code-scanning/alerts/{number}` rather than through the SARIF document. See
`docs/ARCHITECTURE.md`.

## Secrets

| Secret | Used by | Set? |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | `eval.yml` | not set — the eval workflow's real run will fail until it is |

CI deliberately blanks `ANTHROPIC_API_KEY` and deselects the `llm` pytest marker,
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
