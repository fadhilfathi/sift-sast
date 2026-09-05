"""P4 step 5 pilot runner: Run A (naive single-prompt baseline) + Run B
(all-escalate control). Raw per-finding JSONL for omp's scoring module —
this script scores nothing, it only runs and records.

Cost discipline: BudgetGuard checked BEFORE each call, never after. Exceeding
$5.00 aborts the run instead of sampling down silently.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
DATASET = REPO_ROOT / "evals" / "dataset" / "dataset.jsonl"
REJECTED = REPO_ROOT / "evals" / "dataset" / "rejected.jsonl"
INJECTION = REPO_ROOT / "evals" / "dataset" / "injection.jsonl"
SNAP = REPO_ROOT / "evals" / "dataset" / "snapshots" / "synth-v1"
PROMPT = REPO_ROOT / "src" / "sift" / "agents" / "prompts" / "baseline.txt"
RUNS = HERE / "runs"

FLASK_REPO = "pallets/flask"

EXPECTED_OUTPUT_TOKENS = 400


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--flask", type=Path, required=True, help="pallets/flask checkout at the pinned SHA"
    )
    parser.add_argument(
        "--limit", type=int, default=0, help="score only the first N entries (0 = all)"
    )
    parser.add_argument(
        "--skip-run-a", action="store_true", help="only produce Run B (no LLM calls)"
    )
    return parser.parse_args()


def main() -> int:
    from sift.agents.baseline import render_baseline_prompt
    from sift.context.builder import build_context_bundle
    from sift.eval.budget import DEFAULT_BUDGET_USD, BudgetGuard
    from sift.eval.config import EvalConfig, git_sha
    from sift.eval.cost import CallEstimate, ModelId, estimate_tokens
    from sift.eval.dataset import DatasetEntry, GroundTruth, load_dataset
    from sift.ingest.fingerprint import FindingRef, IdentitySource
    from sift.llm.provider import ChatMessage, ProviderConfig, ProviderError, complete
    from sift.models.verdict import Adjudication, Verdict

    args = _parse_args()
    flask_root: Path = args.flask
    limit: int = args.limit
    skip_run_a: bool = args.skip_run_a
    RUNS.mkdir(parents=True, exist_ok=True)

    prompt_template = PROMPT.read_text(encoding="utf-8")
    prompt_hash = hashlib.sha256(prompt_template.encode()).hexdigest()
    entries = load_dataset(DATASET)
    injection = load_dataset(INJECTION)
    if limit > 0:
        entries = entries[:limit]
    config = EvalConfig(
        temperature=0.0,
        prompt_hashes={"baseline.txt": prompt_hash},
        dataset_path=str(DATASET),
        corpus_sha=git_sha(DATASET) if DATASET.is_file() else None,
        budget_usd=DEFAULT_BUDGET_USD,
    )
    (RUNS / "run-config.json").write_text(config.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print(f"model: {ModelId.OPUS.value}  temp: 0.0  prompt: baseline.txt:{prompt_hash[:12]}")
    print(f"entries: {len(entries)} + {len(injection)} injection (separate)")

    provider = ProviderConfig.for_role(ModelId.OPUS, temperature=0.0)
    guard = BudgetGuard()

    def repo_root_for(entry: DatasetEntry) -> Path:
        if entry.repo == FLASK_REPO:
            return flask_root
        return SNAP

    def uri_for(entry: DatasetEntry) -> str:
        if entry.repo == FLASK_REPO:
            return entry.path
        return Path(entry.path).name

    def citations_verified(entry: DatasetEntry, lines: list[dict[str, object]], root: Path) -> bool:
        for ref in lines:
            rel = str(ref.get("path", ""))
            try:
                line_no = int(str(ref.get("line", 0)))
            except ValueError:
                return False
            target = (root / rel).resolve()
            try:
                target.relative_to(root.resolve())
            except ValueError:
                return False
            if not target.is_file() or line_no < 1:
                return False
            try:
                total = sum(1 for _ in target.open(encoding="utf-8", errors="replace"))
            except OSError:
                return False
            if line_no > total:
                return False
        return True

    def adjudicate(entry: DatasetEntry) -> dict[str, object]:
        root = repo_root_for(entry)
        ref = FindingRef(
            correlation_id=entry.id,
            identity_source=IdentitySource.CONTENT,
            run_index=0,
            result_index=0,
            rule_id=entry.rule_id,
            uri=uri_for(entry),
            start_line=entry.line,
        )
        bundle = build_context_bundle(ref, root)
        row: dict[str, object] = {
            "id": entry.id,
            "provenance": entry.provenance.value,
            "ground_truth": entry.ground_truth.value,
            "model": ModelId.OPUS.value,
            "upstream_provider": config.upstream_provider,
            "temperature": 0.0,
            "prompt_hash": prompt_hash,
            "completeness": bundle.completeness.value,
        }
        if bundle.completeness.value == "INSUFFICIENT":
            # Correct escalation without a model: not coverage, not accuracy.
            row.update(
                verdict=Verdict.NEEDS_HUMAN_REVIEW.value,
                confidence=0.0,
                schema_valid=True,
                validation_error=None,
                citations_verified=True,
                escalated_by_completeness=True,
                cost_usd=0.0,
                latency_ms=0,
            )
            return row
        prompt = render_baseline_prompt(prompt_template, bundle)
        estimate = CallEstimate(
            model=ModelId.OPUS,
            input_tokens=estimate_tokens(prompt),
            output_tokens=EXPECTED_OUTPUT_TOKENS,
        )
        guard.check_before_call(estimate.usd)
        started = time.perf_counter()
        try:
            response = complete(
                provider, [ChatMessage(role="user", content=prompt)], model=ModelId.OPUS
            )
        except ProviderError as exc:
            row.update(
                verdict=Verdict.NEEDS_HUMAN_REVIEW.value,
                confidence=0.0,
                schema_valid=False,
                validation_error=f"provider: {exc}",
                citations_verified=False,
                escalated_by_completeness=False,
                cost_usd=0.0,
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
            return row
        latency_ms = int((time.perf_counter() - started) * 1000)
        guard.record_actual(response.cost_usd)
        text = response.content.strip()
        if text.startswith("```"):
            text = text.strip("`").strip()
            if text.lower().startswith("json"):
                text = text[4:].strip()
        try:
            parsed = json.loads(text)
            adjudication = Adjudication.model_validate({"correlation_id": entry.id, **parsed})
        except (json.JSONDecodeError, ValueError) as exc:
            row.update(
                verdict=Verdict.NEEDS_HUMAN_REVIEW.value,
                confidence=0.0,
                schema_valid=False,
                validation_error=f"schema: {type(exc).__name__}: {str(exc)[:200]}",
                citations_verified=False,
                escalated_by_completeness=False,
                cost_usd=response.cost_usd,
                latency_ms=latency_ms,
                raw_content=text[:2000],
            )
            return row
        evidence = [e.model_dump() for e in adjudication.evidence_lines]
        row.update(
            verdict=adjudication.verdict.value,
            confidence=adjudication.confidence,
            schema_valid=True,
            validation_error=None,
            citations_verified=citations_verified(entry, evidence, root),
            escalated_by_completeness=False,
            downgraded_from=adjudication.downgraded_from.value
            if adjudication.downgraded_from
            else None,
            cost_usd=response.cost_usd,
            latency_ms=latency_ms,
        )
        return row

    def escalate(entry: DatasetEntry) -> dict[str, object]:
        return {
            "id": entry.id,
            "provenance": entry.provenance.value,
            "ground_truth": entry.ground_truth.value,
            "model": "none (all-escalate control)",
            "upstream_provider": config.upstream_provider,
            "temperature": 0.0,
            "prompt_hash": None,
            "completeness": None,
            "verdict": Verdict.NEEDS_HUMAN_REVIEW.value,
            "confidence": 0.0,
            "schema_valid": True,
            "validation_error": None,
            "citations_verified": True,
            "escalated_by_completeness": False,
            "cost_usd": 0.0,
            "latency_ms": 0,
        }

    if not skip_run_a:
        rows_a = [adjudicate(e) for e in entries]
        with (RUNS / "run-a.jsonl").open("w", encoding="utf-8") as fh:
            for row in rows_a:
                fh.write(json.dumps(row) + "\n")
        rows_inj = [adjudicate(e) for e in injection]
        with (RUNS / "run-a-injection.jsonl").open("w", encoding="utf-8") as fh:
            for row in rows_inj:
                fh.write(json.dumps(row) + "\n")
        spent = guard.spent_usd
        calls = guard.calls_made
        n_tp = sum(1 for r in rows_a if r["verdict"] == GroundTruth.TRUE_POSITIVE.value)
        n_fp = sum(1 for r in rows_a if r["verdict"] == "FALSE_POSITIVE")
        n_esc = len(rows_a) - n_tp - n_fp
        print(f"RUN A: {len(rows_a)} scored, {calls} calls, ${spent:.4f} spent")
        print(f"  raw verdicts: TP {n_tp} / FP {n_fp} / ESC {n_esc}")
        print(f"  injection: {len(rows_inj)} scored separately")

    rows_b = [escalate(e) for e in entries]
    with (RUNS / "run-b.jsonl").open("w", encoding="utf-8") as fh:
        for row in rows_b:
            fh.write(json.dumps(row) + "\n")
    print(f"RUN B: {len(rows_b)} escalated, 0 calls, $0.00")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
