"""SIFT command line interface."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Annotated

import typer

from sift import __version__, ingest, prefilter
from sift.context.builder import build_context_bundle
from sift.emit import sarif as emit_sarif
from sift.models.context import FileClass

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
) -> None:
    """Triage a SARIF file and emit annotated SARIF.

    Without --dry-run this exits 2: adjudication lands in P5, and reporting a
    successful triage that never adjudicated anything would be a lie.
    """
    if not dry_run:
        _todo("P5 (agents). --dry-run works today: parse, fingerprint, and emit")

    try:
        log, source = ingest.load(sarif)
    except ingest.SarifParseError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    findings = ingest.results_of(log)
    written = emit_sarif.write(log, out, source=source)

    by_source = Counter(ref.identity_source.value for ref in findings)
    degraded = sum(1 for ref in findings if not ref.stable)

    typer.echo(f"{sarif}  ->  {out}  ({written:,} bytes)")
    typer.echo(f"  runs:     {len(log.runs)}")
    typer.echo(f"  findings: {len(findings)}")
    for name, count in by_source.most_common():
        typer.echo(f"    {name:28} {count}")
    if degraded:
        # Not a warning about this run failing — a warning that these findings
        # will detach from their verdicts the next time a line moves above them.
        typer.secho(
            f"  {degraded} finding(s) have a positional identity and will detach on any "
            f"line shift. The context builder resolves this in P3.",
            fg=typer.colors.YELLOW,
        )

    report = prefilter.run(
        findings,
        repo_root=repo,
        resolve_classes=frozenset(resolve_class or ()),
    )
    typer.echo("\n  stage 1 - deterministic pre-filter, no model calls")
    for name, count in sorted(report.by_disposition.items()):
        typer.echo(f"    {name:28} {count}")
    typer.echo(f"    {'file classes':28} {report.by_class}")
    if report.cross_run_overlap:
        typer.echo(
            f"    {'same id in >1 run':28} {report.cross_run_overlap} (reported, not merged)"
        )
    typer.echo(
        f"    settled without a model:     {report.resolved_without_a_model:.1%}"
        f"  ({report.total - report.adjudicate_count}/{report.total})"
    )
    if report.resolvable_by_class and not resolve_class:
        # Shown so the policy choice is made against numbers rather than a guess.
        offer = ", ".join(f"{k}={v}" for k, v in sorted(report.resolvable_by_class.items()))
        typer.echo(f"    could be dismissed by class: {offer}  (not dismissed; see below)")
    typer.echo("  LLM calls: 0    cost: $0.00    (no adjudication in P1)")
    typer.secho("  no verdicts written; output is a passthrough copy", fg=typer.colors.YELLOW)


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
    report: Annotated[Path, typer.Option(help="Markdown report path.")] = Path("evals/REPORT.md"),
    dry_run: DryRun = False,
) -> None:
    """Run the labeled eval suite and write the metrics report."""
    _todo("P4")


@app.command(name="explain-policy")
def explain_policy() -> None:
    """Why the pre-filter dismisses nothing by file class."""
    typer.echo(POLICY_EXPLANATION)


@app.command()
def cost() -> None:
    """Token spend and latency from the last eval run."""
    _todo("P4")


if __name__ == "__main__":
    app()
