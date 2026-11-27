"""Read-only development CLI for comparing exported security telemetry."""

from pathlib import Path
from typing import Annotated

import typer

from .correlation import correlate_jsonl
from .ingest import DefenseInputError

defense_app = typer.Typer(
    help="Import and correlate bounded security lab evidence (development only).",
    no_args_is_help=True,
)


@defense_app.command("correlate")
def correlate_command(
    artex: Annotated[Path, typer.Option("--artex", help="Reviewed ARTEX JSONL export")],
    suricata: Annotated[Path, typer.Option("--suricata", help="Suricata EVE JSONL")],
    wazuh: Annotated[Path, typer.Option("--wazuh", help="Wazuh alerts JSONL")],
    output: Annotated[Path, typer.Option("--output")] = Path(
        "evidence/defense/correlation-report.json"
    ),
    window_seconds: Annotated[
        int, typer.Option("--window-seconds", min=1, max=3600)
    ] = 90,
) -> None:
    """Produce candidate correlations without claiming detection effectiveness."""
    try:
        report = correlate_jsonl(artex, suricata, wazuh, window_seconds)
        output.parent.mkdir(parents=True, exist_ok=True)
        # A development export; do not overwrite an existing report.
        with output.open("x", encoding="utf-8") as handle:
            output.chmod(0o600)
            handle.write(report.model_dump_json(indent=2) + "\n")
    except (DefenseInputError, OSError) as exc:
        typer.echo(f"Defense correlation refused: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"Report: {output}")
    typer.echo(f"Actions: {len(report.correlations)}")
    typer.echo(
        f"Candidate correlations: {sum(c.attribution == 'candidate' for c in report.correlations)}"
    )
    typer.echo("Verdict: INCONCLUSIVE (candidate attribution only)")
