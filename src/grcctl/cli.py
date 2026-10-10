from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from .doctor import collect_doctor, human_bytes
from .evidence import verify_evidence_file

app = typer.Typer(
    name="grcctl",
    help="GRC Engineering OS control and assurance CLI.",
    no_args_is_help=True,
)

evidence_app = typer.Typer(
    help="Create and validate assurance evidence.",
    no_args_is_help=True,
)

app.add_typer(evidence_app, name="evidence")

console = Console()

OutputPath = Annotated[
    Path,
    typer.Option(
        "--output",
        "-o",
        help="Evidence output path.",
    ),
]

EvidencePath = Annotated[
    Path,
    typer.Argument(help="Evidence file to verify."),
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


@evidence_app.command("verify")
def evidence_verify(path: EvidencePath) -> None:
    """Verify evidence structure and cryptographic integrity."""
    result = verify_evidence_file(path)

    table = Table(title="GRC Engineering OS — Evidence Verification")
    table.add_column("Test", style="cyan")
    table.add_column("Result")

    schema_status = (
        "[green]valid[/green]" if result.schema_valid else "[red]invalid[/red]"
    )
    integrity_status = (
        "[green]valid[/green]" if result.integrity_valid else "[red]invalid[/red]"
    )

    table.add_row("Evidence file", result.evidence_path)
    table.add_row("Schema", schema_status)
    table.add_row("Integrity", integrity_status)
    table.add_row("Stored hash", result.stored_hash or "unavailable")
    table.add_row(
        "Calculated hash",
        result.calculated_hash or "unavailable",
    )

    console.print(table)

    if result.valid:
        console.print("\n[bold green]Status: VERIFIED[/bold green]")
        return

    if result.error:
        console.print(f"\n[red]{result.error}[/red]")

    console.print("[bold red]Status: VERIFICATION FAILED[/bold red]")
    raise typer.Exit(code=1)


scan_app = typer.Typer(
    help="Assess infrastructure and technical artifacts.",
    no_args_is_help=True,
)

app.add_typer(scan_app, name="scan")

TerraformPlanPath = Annotated[
    Path,
    typer.Argument(help="Terraform/OpenTofu JSON plan to assess."),
]

FailOnFindings = Annotated[
    bool,
    typer.Option(
        "--fail-on-findings",
        help="Return exit code 1 when findings are detected.",
    ),
]


@scan_app.command("terraform")
def scan_terraform(
    plan: TerraformPlanPath,
    output: OutputPath = Path("evidence/terraform-assessment.json"),
    fail_on_findings: FailOnFindings = False,
) -> None:
    """Assess a Terraform/OpenTofu JSON plan."""
    from .plugins.tf_assure import (
        TerraformPlanError,
        scan_terraform_plan,
    )

    try:
        assessment = scan_terraform_plan(plan, output)
    except (OSError, TerraformPlanError) as exc:
        console.print(f"[bold red]Assessment failed:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    table = Table(title="GRC Engineering OS — Terraform Assurance")
    table.add_column("Severity")
    table.add_column("Rule", style="cyan")
    table.add_column("Resource")
    table.add_column("Finding")

    styles = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
    }

    for finding in assessment.findings:
        style = styles.get(finding.severity, "white")
        table.add_row(
            f"[{style}]{finding.severity.upper()}[/{style}]",
            finding.rule_id,
            finding.resource,
            finding.title,
        )

    console.print(table)
    console.print(
        f"\nResources assessed: [bold]{assessment.summary.resources_scanned}[/bold]"
    )
    console.print(f"Findings: [bold]{assessment.summary.findings_total}[/bold]")
    console.print(f"Evidence: [bold]{output}[/bold]")
    console.print(f"SHA-256: [bold]{assessment.evidence_hash}[/bold]")

    if assessment.findings:
        console.print("\n[bold yellow]Status: FINDINGS DETECTED[/bold yellow]")
        if fail_on_findings:
            raise typer.Exit(code=1)
        return

    console.print("\n[bold green]Status: PASSED[/bold green]")


assurance_app = typer.Typer(
    help="Evaluate scoped Control Verification Procedures (CVPs).",
    no_args_is_help=True,
)
app.add_typer(assurance_app, name="assurance")

AssuranceInputPath = Annotated[
    Path,
    typer.Argument(help="CVP input JSON; artifact paths resolve within its directory."),
]


@assurance_app.command("evaluate")
def assurance_evaluate(
    input_path: AssuranceInputPath,
    output: OutputPath = Path("evidence/cvp-assessment.json"),
    vault_root: Annotated[
        Path,
        typer.Option(
            "--vault-root",
            help="Local vault used to resolve stable artifact IDs.",
        ),
    ] = Path("evidence/vault"),
) -> None:
    """Evaluate a bounded claim against local files or vault artifact IDs."""
    from .assurance import AssessmentInputError, evaluate_file

    try:
        report = evaluate_file(input_path, output, vault_root=vault_root)
    except (AssessmentInputError, OSError) as exc:
        console.print(f"[red]Assessment input error: {exc}[/red]")
        raise typer.Exit(code=2) from exc

    console.print(f"Verdict: [bold]{report.verdict.upper()}[/bold]")
    console.print(f"Procedure: {report.procedure.id}")
    console.print(f"Scope: {report.procedure.scope}")
    for reason in report.reasons:
        console.print(f"- {reason}")
    console.print(f"Evidence record: {output}")
    console.print(f"SHA-256: {report.evidence_hash}")
    console.print(
        "[dim]Hash consistency is not proof of origin or organizational compliance.[/dim]"
    )


vault_app = typer.Typer(
    help="Store and check local, content-addressed evidence (development only).",
    no_args_is_help=True,
)
app.add_typer(vault_app, name="vault")


@vault_app.command("ingest")
def vault_ingest(
    source: Annotated[Path, typer.Argument(help="Local regular file to preserve.")],
    kind: Annotated[str, typer.Option("--kind")] = "technical-artifact",
    root: Annotated[Path, typer.Option("--root")] = Path("evidence/vault"),
) -> None:
    """Preserve source bytes and unverified operator metadata in a local vault."""
    from .vault import LocalEvidenceVault, VaultError

    try:
        record = LocalEvidenceVault(root).ingest(source, kind=kind)
    except (VaultError, OSError) as exc:
        console.print(f"[red]Vault ingestion error: {exc}[/red]")
        raise typer.Exit(code=2) from exc
    console.print("[green]STORED[/green] — locally, not source-attested")
    console.print(f"Artifact ID: {record.artifact_id}")
    console.print(f"SHA-256: {record.sha256}")
    console.print(f"Bytes: {record.size_bytes}")


@vault_app.command("verify")
def vault_verify(
    artifact_id: Annotated[str, typer.Argument(help="Vault artifact UUID.")],
    root: Annotated[Path, typer.Option("--root")] = Path("evidence/vault"),
) -> None:
    """Compare stored artifact bytes with their recorded SHA-256 digest."""
    from .vault import LocalEvidenceVault, VaultError

    try:
        result = LocalEvidenceVault(root).verify(artifact_id)
    except (VaultError, OSError) as exc:
        console.print(f"[red]Vault verification error: {exc}[/red]")
        raise typer.Exit(code=2) from exc

    console.print(f"Artifact: {result.artifact_id}")
    console.print(f"Integrity: {result.status.upper()}")
    console.print(f"Detail: {result.detail}")
    console.print("[dim]This is a local integrity check, not provenance proof.[/dim]")
    if not result.valid:
        raise typer.Exit(code=1)


@vault_app.command("list")
def vault_list(
    root: Annotated[Path, typer.Option("--root")] = Path("evidence/vault"),
    limit: Annotated[int, typer.Option("--limit")] = 20,
) -> None:
    """List locally preserved artifact metadata without exposing contents."""
    from .vault import LocalEvidenceVault, VaultError

    try:
        artifacts = LocalEvidenceVault(root).list_artifacts(limit=limit)
    except (VaultError, OSError) as exc:
        console.print(f"[red]Vault listing error: {exc}[/red]")
        raise typer.Exit(code=2) from exc

    table = Table(title="Kulprit Local Evidence Vault")
    table.add_column("Artifact ID")
    table.add_column("Kind")
    table.add_column("Filename")
    table.add_column("SHA-256 (prefix)")
    for artifact in artifacts:
        table.add_row(
            artifact.artifact_id,
            artifact.kind,
            artifact.filename,
            artifact.sha256[:12],
        )
    console.print(table)
    console.print(f"{len(artifacts)} local ingestion records")


@assurance_app.command("publish")
def assurance_publish(
    report_path: Annotated[Path, typer.Argument(help="Completed CVP report JSON.")],
    vault_root: Annotated[Path, typer.Option("--vault-root")] = Path("evidence/vault"),
) -> None:
    """Recheck evidence and preserve an assessment-to-evidence publication."""
    from .assurance.catalog import CatalogError, LocalAssuranceCatalog
    from .vault import VaultError

    try:
        publication = LocalAssuranceCatalog(vault_root).publish(report_path)
    except (CatalogError, VaultError, OSError) as exc:
        console.print(f"[red]Publication refused: {exc}[/red]")
        raise typer.Exit(code=2) from exc
    console.print("[green]PUBLISHED[/green] — local metadata, unsigned")
    console.print(f"Publication ID: {publication.publication_id}")
    console.print(f"Assessment: {publication.assessment_id}")
    console.print(f"CVP: {publication.procedure_id}")
    console.print(f"Verdict: {publication.verdict.upper()}")


@assurance_app.command("history")
def assurance_history(
    procedure_id: Annotated[str, typer.Argument(help="Control procedure ID.")],
    vault_root: Annotated[Path, typer.Option("--vault-root")] = Path("evidence/vault"),
) -> None:
    """List saved assessment runs for a particular CVP."""
    from .assurance.catalog import LocalAssuranceCatalog
    from .vault import VaultError

    try:
        records = LocalAssuranceCatalog(vault_root).history(procedure_id)
    except (VaultError, OSError) as exc:
        console.print(f"[red]History error: {exc}[/red]")
        raise typer.Exit(code=2) from exc
    table = Table(title="Local Assurance History")
    table.add_column("Published at")
    table.add_column("CVP")
    table.add_column("Verdict")
    table.add_column("Publication ID")
    for entry in records:
        table.add_row(
            entry.published_at,
            entry.procedure_id,
            entry.verdict,
            entry.publication_id,
        )
    console.print(table)


@assurance_app.command("evidence-usage")
def assurance_evidence_usage(
    artifact_id: Annotated[str, typer.Argument(help="Vault ingestion UUID.")],
    vault_root: Annotated[Path, typer.Option("--vault-root")] = Path("evidence/vault"),
) -> None:
    """Find published CVP assessments referencing an evidence ingestion."""
    from .assurance.catalog import LocalAssuranceCatalog
    from .vault import VaultError

    try:
        links = LocalAssuranceCatalog(vault_root).evidence_usage(artifact_id)
    except (VaultError, OSError) as exc:
        console.print(f"[red]Evidence lookup error: {exc}[/red]")
        raise typer.Exit(code=2) from exc
    table = Table(title="Evidence-to-CVP Links")
    table.add_column("Publication ID")
    table.add_column("Evidence ID")
    table.add_column("Kind")
    for link in links:
        table.add_row(link.publication_id, link.evidence_id, link.kind)
    console.print(table)
