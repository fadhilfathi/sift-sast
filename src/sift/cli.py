"""SIFT command line interface."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from sift import __version__

app = typer.Typer(
    name="sift",
    help="Triage SARIF findings with AST-grounded context and multi-agent adjudication.",
    no_args_is_help=True,
    add_completion=False,
)

DryRun = Annotated[bool, typer.Option("--dry-run", help="Estimate cost and calls, spend nothing.")]


def _todo(phase: str) -> None:
    """Fail loudly rather than pretend. A silent no-op in a security tool is a lie."""
    typer.secho(f"not implemented yet — lands in {phase}", fg=typer.colors.YELLOW, err=True)
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
    """Triage a SARIF file and emit annotated SARIF."""
    _todo("P1 (ingest/emit) through P5 (agents)")


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
