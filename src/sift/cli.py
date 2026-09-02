"""SIFT command line interface."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Annotated

import typer

from sift import __version__, ingest
from sift.emit import sarif as emit_sarif

app = typer.Typer(
    name="sift",
    help="Triage SARIF findings with AST-grounded context and multi-agent adjudication.",
    no_args_is_help=True,
    add_completion=False,
)

DryRun = Annotated[bool, typer.Option("--dry-run", help="Estimate cost and calls, spend nothing.")]


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
    typer.echo("  LLM calls: 0    cost: $0.00    (no adjudication in P1)")
    typer.secho("  no verdicts written; output is a passthrough copy", fg=typer.colors.YELLOW)


@app.command(name="eval")
def run_eval(
    report: Annotated[Path, typer.Option(help="Markdown report path.")] = Path("evals/REPORT.md"),
    dry_run: DryRun = False,
) -> None:
    """Run the labeled eval suite and write the metrics report."""
    _todo("P4")


@app.command()
def cost() -> None:
    """Token spend and latency from the last eval run."""
    _todo("P4")


if __name__ == "__main__":
    app()
