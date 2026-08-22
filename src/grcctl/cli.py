from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from .doctor import collect_doctor, human_bytes

app = typer.Typer(
    name="grcctl",
    help="GRC Engineering OS control and assurance CLI.",
    no_args_is_help=True,
)

console = Console()

OutputPath = Annotated[
    Path,
    typer.Option(
        "--output",
        "-o",
        help="Evidence output path.",
    ),
]


@app.callback()
def root() -> None:
    """GRC Engineering OS control and assurance platform."""


@app.command()
def doctor(
    output: OutputPath = Path("evidence/system-baseline.json"),
) -> None:
    """Validate the GRC Engineering OS development environment."""
    evidence = collect_doctor(output)

    table = Table(title="GRC Engineering OS — System Verification")
    table.add_column("Component", style="cyan")
    table.add_column("Result")

    table.add_row("Operating system", evidence.platform.operating_system)
    table.add_row("Architecture", evidence.platform.architecture)
    table.add_row("Kernel", evidence.platform.kernel)
    table.add_row("Logical CPUs", str(evidence.resources.logical_cpus))
    table.add_row(
        "Memory",
        human_bytes(evidence.resources.memory_total_bytes),
    )
    table.add_row(
        "Disk available",
        human_bytes(evidence.resources.disk_available_bytes),
    )

    for tool in evidence.tools:
        status = "[green]available[/green]" if tool.available else "[red]missing[/red]"
        version = tool.version or "unknown"
        table.add_row(tool.name, f"{status} — {version}")

    rootless = (
        "[green]enabled[/green]" if evidence.podman_rootless else "[red]disabled[/red]"
    )
    table.add_row("Rootless Podman", rootless)

    console.print(table)
    console.print(f"Evidence: [bold]{output}[/bold]")
    console.print(f"SHA-256: [bold]{evidence.evidence_hash}[/bold]")

    if evidence.ready:
        console.print("\n[bold green]Status: READY[/bold green]")
        return

    console.print("\n[bold red]Status: NOT READY[/bold red]")
    raise typer.Exit(code=1)
