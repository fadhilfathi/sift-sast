"""SIFT command line interface."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Annotated

import typer

from sift import __version__, ingest, prefilter
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
