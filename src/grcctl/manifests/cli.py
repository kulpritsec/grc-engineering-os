"""CLI boundary for portable verification and additive local linkage."""

from pathlib import Path
from typing import Annotated

import typer

from .codec import ManifestError, parse_contract, read_bounded
from .models import SignedManifest, VerificationContext
from .store import consume_file, link_manifest, read_inputs
from .verifier import verify_manifest

app = typer.Typer(help="Verify signed collection statements (development only).")
ManifestPath = Annotated[Path, typer.Argument(help="Signed manifest JSON.")]
TrustPath = Annotated[Path, typer.Option("--trust", help="External trust policy JSON.")]
ContextPath = Annotated[
    Path, typer.Option("--context", help="Expected execution context JSON.")
]
VerificationTime = Annotated[
    str,
    typer.Option(
        "--at", help="Explicit verification time in UTC, YYYY-MM-DDTHH:MM:SSZ."
    ),
]


@app.command("verify")
def verify(
    manifest: ManifestPath,
    trust: TrustPath,
    context: ContextPath,
    at: VerificationTime,
    bundle: Annotated[
        Path,
        typer.Option("--bundle", help="Directory of files named by artifact UUID."),
    ],
    seen_registry: Annotated[Path | None, typer.Option("--seen-registry")] = None,
) -> None:
    """Authenticate a portable bundle independently of its producer and Vault."""
    try:
        raw, policy = read_inputs(manifest, trust)
        expected = parse_contract(read_bounded(context), VerificationContext)
        parsed = parse_contract(raw, SignedManifest)
        paths = {
            a.artifact_id: bundle / a.artifact_id for a in parsed.payload.artifacts
        }
        check = verify_manifest(raw, policy, paths, context=expected, verified_at=at)
        if seen_registry is not None:
            check = consume_file(seen_registry, check)
    except (ManifestError, ValueError) as exc:
        typer.echo(f"Manifest input error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(check.model_dump_json(indent=2))
    if not check.authenticated:
        raise typer.Exit(code=1)


@app.command("link")
def link(
    manifest: ManifestPath,
    trust: TrustPath,
    context: ContextPath,
    at: VerificationTime,
    vault_root: Annotated[Path, typer.Option("--vault-root")],
    publication_id: Annotated[str | None, typer.Option("--publication-id")] = None,
) -> None:
    """Record authentication beside preserved evidence or an existing publication."""
    try:
        raw, policy = read_inputs(manifest, trust)
        expected = parse_contract(read_bounded(context), VerificationContext)
        check = link_manifest(
            vault_root,
            raw,
            policy,
            context=expected,
            verified_at=at,
            publication_id=publication_id,
        )
    except (ManifestError, ValueError) as exc:
        typer.echo(f"Manifest linkage refused: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(check.model_dump_json(indent=2))


@app.command("demo")
def demo(
    output: Annotated[
        Path, typer.Argument(help="New directory for synthetic demonstration.")
    ],
    at: VerificationTime,
) -> None:
    """Create synthetic bundle, demo trust policy and ephemeral signing key."""
    from ..vault import VaultError
    from .demo import create_demo

    try:
        create_demo(output, at)
    except (ManifestError, ValueError, OSError, VaultError) as exc:
        typer.echo(f"Synthetic demo failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        "Synthetic demo created; review trust.json separately. No private key saved."
    )
