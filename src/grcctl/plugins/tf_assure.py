import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..doctor import hash_payload
from ..models import (
    ControlMapping,
    Finding,
    ScanSummary,
    TerraformScanEvidence,
)
from ..version import __version__

JsonObject = dict[str, Any]

PUBLIC_NETWORKS = {"0.0.0.0/0", "::/0"}
ADMIN_PORTS = {22, 3389}
PUBLIC_ACCESS_FLAGS = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)


class TerraformPlanError(ValueError):
    """Raised when a Terraform/OpenTofu plan cannot be assessed."""


def _mapping(framework: str, control_id: str) -> ControlMapping:
    return ControlMapping(framework=framework, control_id=control_id)


def _active_resources(plan: JsonObject) -> list[JsonObject]:
    raw_changes = plan.get("resource_changes")

    if not isinstance(raw_changes, list):
        raise TerraformPlanError("Plan does not contain resource_changes.")

    resources: list[JsonObject] = []

    for resource in raw_changes:
        if not isinstance(resource, dict):
            continue

        change = resource.get("change", {})
        actions = change.get("actions", []) if isinstance(change, dict) else []

        if actions == ["delete"]:
            continue

        resources.append(resource)

    return resources


def _after(resource: JsonObject) -> JsonObject:
    change = resource.get("change", {})

    if not isinstance(change, dict):
        return {}

    after = change.get("after", {})
    return after if isinstance(after, dict) else {}


def _scan_security_groups(resources: list[JsonObject]) -> list[Finding]:
    findings: list[Finding] = []

    for resource in resources:
        if resource.get("type") != "aws_security_group":
            continue

        after = _after(resource)
        ingress_rules = after.get("ingress", [])

        if not isinstance(ingress_rules, list):
            continue

        for ingress in ingress_rules:
            if not isinstance(ingress, dict):
                continue

            cidrs = ingress.get("cidr_blocks", [])
            ipv6_cidrs = ingress.get("ipv6_cidr_blocks", [])

            networks = {
                str(cidr)
                for cidr in (
                    (cidrs if isinstance(cidrs, list) else [])
                    + (ipv6_cidrs if isinstance(ipv6_cidrs, list) else [])
                )
            }

            exposed_networks = sorted(networks & PUBLIC_NETWORKS)

            if not exposed_networks:
                continue

            protocol = str(ingress.get("protocol", "")).lower()
            from_port = ingress.get("from_port")
            to_port = ingress.get("to_port")
            exposed_ports: list[int] = []

            if protocol == "-1":
                exposed_ports = sorted(ADMIN_PORTS)
            elif (
                protocol in {"tcp", "6"}
                and isinstance(from_port, int)
                and isinstance(to_port, int)
            ):
                exposed_ports = sorted(
                    port for port in ADMIN_PORTS if from_port <= port <= to_port
                )

            if not exposed_ports:
                continue

            findings.append(
                Finding(
                    rule_id="GRCOS-AWS-NET-001",
                    title="Administrative service exposed to the internet",
                    severity="high",
                    resource=str(resource.get("address", "unknown")),
                    message=(
                        f"Administrative port(s) {exposed_ports} are reachable "
                        f"from {exposed_networks}."
                    ),
                    remediation=(
                        "Restrict ingress to approved administrative networks, "
                        "a VPN, or a managed access service."
                    ),
                    mappings=[
                        _mapping("CIS Controls v8", "12.2"),
                        _mapping("NIST SP 800-53 Rev. 5", "SC-7"),
                    ],
                    evidence={
                        "public_networks": exposed_networks,
                        "administrative_ports": exposed_ports,
                        "protocol": protocol,
                    },
                )
            )
            break

    return findings


def _scan_public_access_blocks(
    resources: list[JsonObject],
) -> list[Finding]:
    findings: list[Finding] = []

    for resource in resources:
        if resource.get("type") != "aws_s3_bucket_public_access_block":
            continue

        after = _after(resource)
        disabled = [flag for flag in PUBLIC_ACCESS_FLAGS if after.get(flag) is False]

        if not disabled:
            continue

        findings.append(
            Finding(
                rule_id="GRCOS-AWS-S3-001",
                title="S3 public-access protections disabled",
                severity="high",
                resource=str(resource.get("address", "unknown")),
                message=(
                    "The following public-access protections are explicitly "
                    f"disabled: {', '.join(disabled)}."
                ),
                remediation=(
                    "Enable all four S3 public-access block settings unless "
                    "an approved exception exists."
                ),
                mappings=[
                    _mapping("CIS Controls v8", "3.3"),
                    _mapping("NIST SP 800-53 Rev. 5", "AC-3"),
                ],
                evidence={"disabled_settings": disabled},
            )
        )

    return findings


def _scan_s3_buckets(resources: list[JsonObject]) -> list[Finding]:
    findings: list[Finding] = []

    encryption_resource_present = any(
        resource.get("type") == "aws_s3_bucket_server_side_encryption_configuration"
        for resource in resources
    )

    for resource in resources:
        if resource.get("type") != "aws_s3_bucket":
            continue

        after = _after(resource)
        address = str(resource.get("address", "unknown"))

        if after.get("force_destroy") is True:
            findings.append(
                Finding(
                    rule_id="GRCOS-AWS-S3-003",
                    title="Destructive bucket deletion enabled",
                    severity="medium",
                    resource=address,
                    message=(
                        "force_destroy is enabled, allowing bucket deletion "
                        "with contained objects."
                    ),
                    remediation=(
                        "Disable force_destroy for evidence repositories and "
                        "use an approved retention and disposal workflow."
                    ),
                    mappings=[
                        _mapping("CIS Controls v8", "11.3"),
                        _mapping("NIST SP 800-53 Rev. 5", "CP-9"),
                    ],
                    evidence={"force_destroy": True},
                )
            )

        inline_encryption = after.get("server_side_encryption_configuration")

        if not encryption_resource_present and not inline_encryption:
            findings.append(
                Finding(
                    rule_id="GRCOS-AWS-S3-002",
                    title="No explicit managed encryption configuration",
                    severity="medium",
                    resource=address,
                    message=(
                        "No explicit Terraform-managed S3 server-side "
                        "encryption configuration was detected."
                    ),
                    remediation=(
                        "Declare an "
                        "aws_s3_bucket_server_side_encryption_configuration "
                        "resource using an approved encryption standard."
                    ),
                    mappings=[
                        _mapping("CIS Controls v8", "3.11"),
                        _mapping("NIST SP 800-53 Rev. 5", "SC-28"),
                    ],
                    evidence={"detection_type": "configuration-presence heuristic"},
                )
            )

    return findings


def scan_terraform_plan(
    plan_path: Path,
    output_path: Path,
) -> TerraformScanEvidence:
    try:
        raw_plan = plan_path.read_bytes()
        plan = json.loads(raw_plan)
    except json.JSONDecodeError as exc:
        raise TerraformPlanError(f"Plan contains invalid JSON: {exc}") from exc

    if not isinstance(plan, dict):
        raise TerraformPlanError("Terraform plan must be a JSON object.")

    format_version = plan.get("format_version")

    if not isinstance(format_version, str):
        raise TerraformPlanError("Plan format_version is missing.")

    if not format_version.startswith("1."):
        raise TerraformPlanError(f"Unsupported plan format version: {format_version}")

    resources = _active_resources(plan)

    findings = [
        *_scan_security_groups(resources),
        *_scan_public_access_blocks(resources),
        *_scan_s3_buckets(resources),
    ]

    severity_counts = {
        severity: sum(finding.severity == severity for finding in findings)
        for severity in ("critical", "high", "medium", "low")
    }

    evidence = TerraformScanEvidence(
        collected_at=datetime.now(UTC),
        input_path=str(plan_path),
        input_sha256=hashlib.sha256(raw_plan).hexdigest(),
        plan_format_version=format_version,
        scanner={
            "name": "grcctl-tf-assure",
            "version": __version__,
        },
        summary=ScanSummary(
            resources_scanned=len(resources),
            findings_total=len(findings),
            by_severity=severity_counts,
        ),
        findings=findings,
    )

    hash_input = evidence.model_dump(
        mode="json",
        exclude={"evidence_hash"},
    )
    evidence.evidence_hash = hash_payload(hash_input)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        evidence.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    output_path.chmod(0o600)

    return evidence
