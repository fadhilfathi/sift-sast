"""SIFT command line interface."""

from __future__ import annotations

import asyncio
import json
from collections import Counter
from pathlib import Path
from typing import Annotated

import typer

from sift import __version__, ingest, prefilter
from sift.context.builder import build_context_bundle
from sift.emit import sarif as emit_sarif
from sift.emit.annotate import annotate_adjudicated, annotate_prefiltered
from sift.emit.pr_comment import render_pr_comment
from sift.emit.report import build_run_report, write_run_report
from sift.eval.budget import DEFAULT_BUDGET_USD, BudgetExceededError, BudgetGuard
from sift.eval.config import EvalConfig, git_sha, hash_prompt_dir
from sift.eval.cost import ModelId
from sift.eval.dataset import load_dataset, load_rejected
from sift.eval.harness import dry_run_estimate
from sift.ingest.fingerprint import FindingRef
from sift.llm.provider import ProviderConfigError, complete
from sift.models.context import FileClass
from sift.models.verdict import TriageResult
from sift.orchestrator.dry_run import pipeline_dry_run_estimate
from sift.orchestrator.pipeline import build_pipeline_config, run_pipeline
from sift.prefilter import Disposition

#: The prompts shipped inside the installed package - resolved relative to
#: this module's own location, never the caller's working directory, so
#: `uvx --from sift-sast sift triage ...` finds them regardless of cwd.
DEFAULT_PROMPTS_DIR = Path(__file__).resolve().parent / "agents" / "prompts"

app = typer.Typer(
    name="sift",
    help="Triage SARIF findings with AST-grounded context and multi-agent adjudication.",
    no_args_is_help=True,
    add_completion=False,
)

DryRun = Annotated[bool, typer.Option("--dry-run", help="Estimate cost and calls, spend nothing.")]

POLICY_EXPLANATION = """SIFT classifies each finding's file as SOURCE, TEST, GENERATED, VENDORED,
FIXTURE, or UNKNOWN. By default that classification is evidence handed to the
adjudicator. It dismisses nothing on its own.

The reason is that none of those classes is reliably not-a-vulnerability:

  VENDORED   Log4Shell was vendored. A vulnerable dependency is a real
             vulnerability; the fix is an upgrade, not a dismissal.
  GENERATED  The code still ships and still runs. The fix belongs in the
             generator, which makes it harder to action, not less real.
  TEST       Hardcoded credentials in tests are real credentials, and test
             helpers get imported by production code.
  FIXTURE    The classic home of a committed private key.

Dismissing any of them here would be a silent dismissal with no model and no
human in the loop, which is the failure mode this tool exists to prevent.

If you accept that risk for your own repository, opt in explicitly:

  sift triage results.sarif --dry-run --resolve-class VENDORED

Every run prints how many findings each class would have removed, so the choice
is made against numbers rather than a guess."""


def _todo(phase: str) -> None:
    """Fail loudly rather than pretend. A silent no-op in a security tool is a lie."""
    # ASCII only: the Windows console defaults to cp1252 and mangles an em dash.
    typer.secho(f"not implemented yet - lands in {phase}", fg=typer.colors.YELLOW, err=True)
    raise typer.Exit(code=2)


@app.command()
def version() -> None:
    """Print the SIFT version."""
    typer.echo(__version__)


@app.command()
def triage(
    sarif: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="Input SARIF 2.1.0 file.")
    ],
    repo: Annotated[
        Path, typer.Option(exists=True, file_okay=False, help="Repository root.")
    ] = Path(),
    out: Annotated[Path, typer.Option(help="Annotated SARIF output path.")] = Path("sift.sarif"),
    dry_run: DryRun = False,
    resolve_class: Annotated[
        list[FileClass] | None,
        typer.Option(
            "--resolve-class",
            help=(
                "Dismiss findings in this file class without a model. Repeatable. "
                "Off by default on purpose - see `sift explain-policy`."
            ),
        ),
    ] = None,
    analyst_model: Annotated[
        ModelId, typer.Option(help="Model tier for Reachability/Exploitability/Adversary.")
    ] = ModelId.HAIKU,
    adjudicator_model: Annotated[
        ModelId,
        typer.Option(
            help="Model tier for the Adjudicator. Never lower this to save cost - CONTRIBUTING.md."
        ),
    ] = ModelId.OPUS,
    budget: Annotated[
        float, typer.Option(help="Hard spend ceiling in USD, checked before each finding.")
    ] = DEFAULT_BUDGET_USD,
    prompts: Annotated[Path, typer.Option(help="Prompt template directory.")] = DEFAULT_PROMPTS_DIR,
    report_out: Annotated[Path, typer.Option(help="JSON run report path.")] = Path(
        "sift-report.json"
    ),
    comment_out: Annotated[Path, typer.Option(help="Markdown PR comment path.")] = Path(
        "sift-comment.md"
    ),
) -> None:
    """Triage a SARIF file: pre-filter, build context, adjudicate, emit.

    `--dry-run` runs Stage 1 and Stage 2 for real (both deterministic, free)
    and estimates Stage 3's cost without calling a model. Without it, Stage 3
    runs for real and needs `SIFT_API_KEY` set.
    """
    try:
        log, source = ingest.load(sarif)
    except ingest.SarifParseError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    findings = ingest.results_of(log)
    by_source = Counter(ref.identity_source.value for ref in findings)
    degraded = sum(1 for ref in findings if not ref.stable)

    typer.echo(f"{sarif}  ->  {out}")
    typer.echo(f"  runs:     {len(log.runs)}")
    typer.echo(f"  findings: {len(findings)}")
    for name, count in by_source.most_common():
        typer.echo(f"    {name:28} {count}")
    if degraded:
        typer.secho(
            f"  {degraded} finding(s) have a positional identity and will detach on any "
            f"line shift.",
            fg=typer.colors.YELLOW,
        )

    prefilter_report = prefilter.run(
        findings, repo_root=repo, resolve_classes=frozenset(resolve_class or ())
    )
    typer.echo("\n  stage 1 - deterministic pre-filter, no model calls")
    for name, count in sorted(prefilter_report.by_disposition.items()):
        typer.echo(f"    {name:28} {count}")
    typer.echo(
        f"    settled without a model:     {prefilter_report.resolved_without_a_model:.1%}"
        f"  ({prefilter_report.total - prefilter_report.adjudicate_count}/{prefilter_report.total})"
    )
    if prefilter_report.resolvable_by_class and not resolve_class:
        offer = ", ".join(
            f"{k}={v}" for k, v in sorted(prefilter_report.resolvable_by_class.items())
        )
        typer.echo(f"    could be dismissed by class: {offer}  (not dismissed; see below)")

    refs_by_id: dict[str, FindingRef] = {
        d.ref.correlation_id: d.ref for d in prefilter_report.decisions
    }
    survivors = [d for d in prefilter_report.decisions if d.disposition is Disposition.ADJUDICATE]

    typer.echo("\n  stage 2 - context builder (tree-sitter, no LLM)")
    bundles = {d.ref.correlation_id: build_context_bundle(d.ref, repo) for d in survivors}
    typer.echo(f"    bundles built: {len(bundles)}")

    if not dry_run:
        try:
            config = build_pipeline_config(
                prompts_dir=prompts,
                repo_root=repo,
                analyst_model=analyst_model,
                adjudicator_model=adjudicator_model,
                prompt_hashes=hash_prompt_dir(prompts),
            )
        except ProviderConfigError as exc:
            typer.secho(str(exc), fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1) from exc
    else:
        config = build_pipeline_config(
            prompts_dir=prompts,
            repo_root=repo,
            analyst_model=analyst_model,
            adjudicator_model=adjudicator_model,
            prompt_hashes=hash_prompt_dir(prompts),
            api_key="dry-run-placeholder",
        )

    typer.echo("\n  stage 3 - adjudication (4 agents per finding)")
    results: dict[str, TriageResult] = {}
    exceeded = False
    if dry_run:
        estimate = pipeline_dry_run_estimate(list(bundles.values()), config)
        typer.echo(f"    calls:      {estimate.call_count}")
        typer.echo(f"    cost:       ${estimate.usd:.4f}   (budget ${budget:.2f})")
        typer.secho("    no model called; nothing adjudicated", fg=typer.colors.YELLOW)
        exceeded = estimate.usd > budget
    else:
        guard = BudgetGuard(limit_usd=budget)
        for correlation_id, bundle in bundles.items():
            if exceeded:
                break
            # Coarse-grained per finding, not per LLM call: run_pipeline makes
            # its own 4 calls atomically and does not expose a hook between
            # them. Estimating and checking per finding is still "before each
            # call" at the granularity this orchestrator actually offers.
            call_estimate = pipeline_dry_run_estimate([bundle], config).usd
            try:
                guard.check_before_call(call_estimate)
            except BudgetExceededError:
                exceeded = True
                break
            triage_result = asyncio.run(
                run_pipeline(
                    correlation_id=correlation_id,
                    bundle=bundle,
                    config=config,
                    complete_fn=complete,
                )
            )
            guard.record_actual(triage_result.cost_usd)
            results[correlation_id] = triage_result
        typer.echo(f"    adjudicated: {len(results)}/{len(bundles)}")
        typer.echo(f"    cost:        ${guard.spent_usd:.4f}   (budget ${budget:.2f})")
        if exceeded:
            typer.secho(
                "    BUDGET EXCEEDED - remaining findings escalated, not adjudicated",
                fg=typer.colors.RED,
            )

    for decision in prefilter_report.decisions:
        ref = decision.ref
        run = log.runs[ref.run_index]
        result = run.results[ref.result_index]
        maybe_triage_result = results.get(ref.correlation_id)
        if maybe_triage_result is not None:
            run.results[ref.result_index] = annotate_adjudicated(
                result, ref, decision, maybe_triage_result
            )
        elif decision.disposition is Disposition.ADJUDICATE and not dry_run:
            skipped = decision.model_copy(
                update={
                    "resolved_by": "triage:budget-exhausted",
                    "justification": (
                        "budget exceeded before this finding could be adjudicated; "
                        "escalate to a human"
                    ),
                }
            )
            run.results[ref.result_index] = annotate_prefiltered(result, ref, skipped)
        else:
            run.results[ref.result_index] = annotate_prefiltered(result, ref, decision)

    written = emit_sarif.write(log, out, source=source)
    typer.echo(f"\n  wrote {written:,} bytes to {out}")

    run_report = build_run_report(
        total_findings=len(findings),
        resolved_by_prefilter=prefilter_report.total - prefilter_report.adjudicate_count,
        results=list(results.values()),
        config=config,
    )
    write_run_report(run_report, report_out)
    typer.echo(f"  wrote run report to {report_out}")

    comment = render_pr_comment(
        [(refs_by_id[cid], r) for cid, r in results.items()],
        total_cost_usd=run_report.total_cost_usd,
        dry_run=dry_run,
    )
    comment_out.write_text(comment, encoding="utf-8")
    typer.echo(f"  wrote PR comment to {comment_out}")

    if exceeded and dry_run:
        typer.secho("ESTIMATED COST EXCEEDS BUDGET", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


context_app = typer.Typer(
    name="context",
    help="Inspect the deterministic ContextBundle before any model sees it.",
    no_args_is_help=True,
)
app.add_typer(context_app)


@context_app.command(name="dump")
def context_dump(
    sarif: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="Input SARIF 2.1.0 file.")
    ],
    repo: Annotated[
        Path, typer.Option(exists=True, file_okay=False, help="Repository root.")
    ] = Path(),
    out: Annotated[Path | None, typer.Option(help="Write JSON here instead of stdout.")] = None,
    limit: Annotated[int, typer.Option(help="Build a bundle for at most this many findings.")] = 20,
) -> None:
    """Build and dump ContextBundles for human review. No model calls.

    Each entry carries the bundle exactly as stored, and separately
    `as_sent_to_model`: every span rendered through `CodeSpan.as_untrusted_block()`
    - the only form P5 prompt assembly may read. Reviewing both together is
    what decision D9 asks for: catching a leaky delimiter design here, before
    any prompt exists to leak through.
    """
    try:
        log, _ = ingest.load(sarif)
    except ingest.SarifParseError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    findings = ingest.results_of(log)[:limit]
    entries = []
    completeness_counts: Counter[str] = Counter()
    reason_counts: Counter[str] = Counter()

    for finding in findings:
        bundle = build_context_bundle(finding, repo)
        completeness_counts[bundle.completeness.value] += 1
        reason_counts.update(r.value for r in bundle.completeness_reasons)
        entries.append(
            {
                "correlation_id": finding.correlation_id,
                "bundle": bundle.model_dump(mode="json"),
                "as_sent_to_model": [span.as_untrusted_block() for span in bundle.all_spans()],
            }
        )

    payload = json.dumps(entries, indent=2, ensure_ascii=False)
    if out is not None:
        out.write_text(payload, encoding="utf-8")
        typer.echo(f"wrote {len(entries)} bundle(s) to {out}", err=True)
    else:
        typer.echo(payload)

    typer.echo(f"\n  {len(entries)} bundle(s) built, no model calls", err=True)
    for name, count in sorted(completeness_counts.items()):
        typer.echo(f"    {name:14} {count}", err=True)
    if reason_counts:
        typer.echo("  reasons:", err=True)
        for name, count in reason_counts.most_common():
            typer.echo(f"    {name:28} {count}", err=True)


@app.command(name="eval")
def run_eval(
    dataset: Annotated[Path, typer.Option(help="Labeled dataset JSONL (D10 schema).")] = Path(
        "evals/dataset/dataset.jsonl"
    ),
    rejected: Annotated[
        Path, typer.Option(help="Rejected-candidates JSONL, for the D10 rejection rate.")
    ] = Path("evals/dataset/rejected.jsonl"),
    prompts: Annotated[
        Path, typer.Option(help="Directory of prompt files, hashed into the report's config.")
    ] = Path("src/sift/agents/prompts"),
    report: Annotated[Path, typer.Option(help="Markdown report path.")] = Path("evals/REPORT.md"),
    budget: Annotated[
        float, typer.Option(help="Hard abort budget in USD, checked before each call.")
    ] = DEFAULT_BUDGET_USD,
    temperature: Annotated[
        float, typer.Option(help="Sampling temperature, stamped into config.")
    ] = 0.0,
    dry_run: DryRun = False,
) -> None:
    """Run the labeled eval suite and write the metrics report.

    Without --dry-run this exits 2: P4 step 5 (the naive baseline that
    actually calls a model) is not built yet, and reporting a real eval score
    with no baseline prompt to have produced it would be an unmeasured metric.
    """
    entries = load_dataset(dataset)
    rejected_entries = load_rejected(rejected)
    config = EvalConfig(
        temperature=temperature,
        prompt_hashes=hash_prompt_dir(prompts),
        dataset_path=str(dataset),
        corpus_sha=git_sha(dataset) if dataset.is_file() else None,
        budget_usd=budget,
    )

    if dry_run:
        estimate = dry_run_estimate(entries, config)
        typer.echo(f"dataset:    {dataset}")
        typer.echo(f"  labeled:  {len(entries)}    rejected: {len(rejected_entries)}")
        typer.echo(f"model:      {config.baseline_model.value}   temperature: {config.temperature}")
        typer.echo(f"prompts:    {config.prompt_hashes or '(none yet)'}")
        typer.echo(f"calls:      {estimate.call_count}")
        typer.echo(f"cost:       ${estimate.usd:.4f}   (budget ${budget:.2f})")
        if not entries:
            typer.secho(
                "  no labeled dataset yet (P4 step 4) - cost is $0.00 because there is "
                "nothing to score, not because a real run would be free",
                fg=typer.colors.YELLOW,
            )
        if estimate.usd > budget:
            typer.secho(
                "ESTIMATED COST EXCEEDS BUDGET - a real run would abort before finishing",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
        return

    _todo("P4 step 5 (baseline scoring) - needs the dataset, a baseline prompt, and SIFT_API_KEY")


@app.command(name="explain-policy")
def explain_policy() -> None:
    """Why the pre-filter dismisses nothing by file class."""
    typer.echo(POLICY_EXPLANATION)


@app.command()
def cost(
    report: Annotated[Path, typer.Option(help="Markdown report to read.")] = Path(
        "evals/REPORT.md"
    ),
) -> None:
    """Token spend and latency from the last eval run."""
    if not report.is_file():
        typer.secho(
            f"no report at {report} yet - run `sift eval` first", fg=typer.colors.YELLOW, err=True
        )
        raise typer.Exit(code=1)
    typer.echo(report.read_text(encoding="utf-8"))


if __name__ == "__main__":
    app()
