#!/usr/bin/env bash
# Regenerate the SARIF fixture corpus. This script is the source of truth for
# where every generated fixture came from.
#
# Run on Linux. Do not run on Windows: Semgrep emits backslash-separated URIs
# there ("probe\\vuln.py"), so the output would differ from the committed corpus
# for reasons that have nothing to do with the scanners.
#
#   ./evals/fixtures/generate.sh              # everything
#   ./evals/fixtures/generate.sh semgrep      # skip the slow CodeQL half
#
# Fixtures are committed. This script exists so that six months from now a
# failing round-trip test can be diagnosed as a parser regression rather than a
# fixture that was always malformed. Regenerate on a scanner upgrade: a diff in
# the output is format drift, which is exactly what we want to see.

set -euo pipefail

# ---------------------------------------------------------------- pinned versions
SEMGREP_VERSION="1.176.0"
CODEQL_VERSION="v2.26.4"

# Semgrep registry rulesets are mutable — there is no version in the URL. We
# cannot pin them, so we hash the resolved rule YAML into MANIFEST.json instead.
# A changed hash on regeneration means the ruleset drifted, and that is the
# first thing to check when a regenerated fixture differs.
SEMGREP_RULESETS=("p/security-audit" "p/default")

# repo|commit SHA|language
TARGETS=(
  "pallets/flask|d318b683471101618febed18996405ad26462110|python"
  "expressjs/express|023767fe9872e029271df1418f73401bff20ff40|javascript"
  "google/gson|b3f4ca20087f9066de4c340522ff84e0558e1ad1|java"
  "gorilla/mux|db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265|go"
)

# CodeQL builds a database per repo. Restricted to the two languages that need
# no compiler, to keep a full regeneration inside a coffee break.
CODEQL_LANGUAGES=("python" "javascript")
CODEQL_SUITES=("code-scanning" "security-extended")

# ---------------------------------------------------------------- layout
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/generated"
WORK="${TMPDIR:-/tmp}/sift-fixtures"
MANIFEST="$HERE/MANIFEST.json"
WHICH="${1:-all}"

mkdir -p "$OUT" "$WORK"

log() { printf '\033[36m==>\033[0m %s\n' "$*" >&2; }

# Semgrep records the absolute scan path in `originalUriBaseIds`, and CodeQL
# records the checkout directory. Both would embed this machine's paths into the
# corpus and produce a diff on every regeneration on a different host.
scrub() {
  python3 - "$1" "$2" <<'PY'
import json, pathlib, sys

path, root = pathlib.Path(sys.argv[1]), sys.argv[2]
doc = json.loads(path.read_text(encoding="utf-8"))

for run in doc.get("runs", []):
    for base in run.get("originalUriBaseIds", {}).values():
        if isinstance(base, dict) and "uri" in base:
            base["uri"] = "file:///src/"
    for art in run.get("artifacts", []):
        loc = art.get("location", {})
        if isinstance(loc.get("uri"), str):
            loc["uri"] = loc["uri"].replace(root, "").lstrip("/")
    # Wall-clock timestamps are not part of the format we are testing.
    for inv in run.get("invocations", []):
        inv.pop("startTimeUtc", None)
        inv.pop("endTimeUtc", None)

path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
PY
}

fetch_repo() {
  local repo="$1" sha="$2" dest="$WORK/${repo//\//_}"
  if [ ! -d "$dest/.git" ]; then
    log "clone $repo"
    git clone --quiet --filter=blob:none --no-checkout "https://github.com/$repo.git" "$dest"
  fi
  git -C "$dest" fetch --quiet --depth 1 origin "$sha"
  git -C "$dest" checkout --quiet --force "$sha"
  echo "$dest"
}

# ---------------------------------------------------------------- semgrep
run_semgrep() {
  for target in "${TARGETS[@]}"; do
    IFS='|' read -r repo sha lang <<<"$target"
    local src slug
    src="$(fetch_repo "$repo" "$sha")"
    slug="${repo//\//-}"

    for ruleset in "${SEMGREP_RULESETS[@]}"; do
      local name="semgrep-${slug}-${ruleset//\//-}.sarif"
      log "semgrep $ruleset -> $name"
      # --metrics=off keeps the run from phoning home about a fixture build.
      ( cd "$src" && uvx "semgrep==$SEMGREP_VERSION" scan \
          --config "$ruleset" --sarif --quiet --metrics=off \
          --timeout 120 --max-target-bytes 2000000 . ) > "$OUT/$name"
      scrub "$OUT/$name" "$src"
    done
  done
}

# ---------------------------------------------------------------- codeql
ensure_codeql() {
  local dir="$WORK/codeql-$CODEQL_VERSION"
  if [ ! -x "$dir/codeql/codeql" ]; then
    log "download CodeQL CLI $CODEQL_VERSION"
    mkdir -p "$dir"
    curl -fsSL -o "$dir/bundle.tar.zst" \
      "https://github.com/github/codeql-action/releases/download/codeql-bundle-$CODEQL_VERSION/codeql-bundle-linux64.tar.zst"
    tar --zstd -xf "$dir/bundle.tar.zst" -C "$dir"
  fi
  echo "$dir/codeql/codeql"
}

run_codeql() {
  local codeql
  codeql="$(ensure_codeql)"

  for target in "${TARGETS[@]}"; do
    IFS='|' read -r repo sha lang <<<"$target"
    # shellcheck disable=SC2076
    [[ " ${CODEQL_LANGUAGES[*]} " =~ " $lang " ]] || continue

    local src slug db
    src="$(fetch_repo "$repo" "$sha")"
    slug="${repo//\//-}"
    db="$WORK/db-$slug"

    if [ ! -d "$db" ]; then
      log "codeql database create $slug ($lang)"
      "$codeql" database create "$db" --language="$lang" --source-root="$src" --quiet
    fi

    for suite in "${CODEQL_SUITES[@]}"; do
      local name="codeql-${slug}-${suite}.sarif"
      log "codeql analyze $suite -> $name"
      "$codeql" database analyze "$db" "$lang-$suite.qls" \
        --format=sarif-latest --output="$OUT/$name" --quiet
      scrub "$OUT/$name" "$src"
    done
  done
}

# ---------------------------------------------------------------- manifest
write_manifest() {
  log "write MANIFEST.json"
  python3 - "$MANIFEST" "$OUT" "$HERE/handcrafted" "$SEMGREP_VERSION" "$CODEQL_VERSION" \
      "${SEMGREP_RULESETS[*]}" "${TARGETS[*]}" <<'PY'
import hashlib, json, pathlib, subprocess, sys, urllib.request

manifest, out, hand, semgrep_v, codeql_v, rulesets, targets = sys.argv[1:8]

def digest(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()

# Registry rulesets are mutable. Hashing the resolved YAML is the only pin
# available: a changed hash explains a changed fixture.
ruleset_hashes = {}
for name in rulesets.split():
    url = f"https://semgrep.dev/c/{name}"
    with urllib.request.urlopen(url, timeout=60) as r:  # noqa: S310
        ruleset_hashes[name] = digest(r.read())

files = {}
for d in (pathlib.Path(out), pathlib.Path(hand)):
    for p in sorted(d.glob("*.sarif")):
        raw = p.read_bytes()
        doc = json.loads(raw)
        files[f"{d.name}/{p.name}"] = {
            "sha256": digest(raw),
            "bytes": len(raw),
            "runs": len(doc.get("runs", [])),
            "results": sum(len(r.get("results", [])) for r in doc.get("runs", [])),
        }

pathlib.Path(manifest).write_text(
    json.dumps(
        {
            "note": "Written by generate.sh. Do not edit by hand.",
            "generator": subprocess.run(
                ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False
            ).stdout.strip()
            or "unknown",
            "semgrep": {"version": semgrep_v, "rulesets": ruleset_hashes},
            "codeql": {"version": codeql_v},
            "targets": [
                dict(zip(("repo", "sha", "language"), t.split("|"), strict=True))
                for t in targets.split()
            ],
            "fixtures": files,
        },
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
print(f"{len(files)} fixtures recorded")
PY
}

# ---------------------------------------------------------------- main
case "$WHICH" in
  all)      run_semgrep; run_codeql ;;
  semgrep)  run_semgrep ;;
  codeql)   run_codeql ;;
  manifest) ;;
  *) echo "usage: $0 [all|semgrep|codeql|manifest]" >&2; exit 2 ;;
esac

write_manifest
log "done. corpus in $OUT"
