import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..doctor import hash_payload
from ..models import (
    ControlMapping,
    Finding,
    RuleResult,
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

RULE_IDS = (
    "GRCOS-AWS-NET-001",
    "GRCOS-AWS-S3-001",
    "GRCOS-AWS-S3-002",
    "GRCOS-AWS-S3-003",
)
# Ingress declared outside aws_security_group is not inspected by NET-001.
STANDALONE_INGRESS_TYPES = {
    "aws_security_group_rule",
    "aws_vpc_security_group_ingress_rule",
}


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


def _after_unknown(resource: JsonObject) -> JsonObject:
    change = resource.get("change", {})

    if not isinstance(change, dict):
        return {}

    unknown = change.get("after_unknown", {})
    return unknown if isinstance(unknown, dict) else {}


def _has_unknown(value: object) -> bool:
    """Terraform marks values known only after apply with nested ``true``."""
    if value is True:
        return True
    if isinstance(value, dict):
        return any(_has_unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_unknown(item) for item in value)
    return False


def _of_type(resources: list[JsonObject], resource_type: str) -> list[JsonObject]:
    return [resource for resource in resources if resource.get("type") == resource_type]


def _address(resource: JsonObject) -> str:
    return str(resource.get("address", "unknown"))


def _rule_result(
    rule_id: str,
    findings: list[Finding],
    applicable: list[JsonObject],
    undetermined: list[str],
    pass_notes: list[str] | None = None,
) -> RuleResult:
    """Fail on any finding; pass only when every applicable value is known."""
    evaluated = sorted(_address(resource) for resource in applicable)
    failed = sorted({f.resource for f in findings if f.rule_id == rule_id})

    if failed:
        return RuleResult(
            rule_id=rule_id,
            outcome="fail",
            resources_evaluated=evaluated,
            notes=[f"Findings on: {', '.join(failed)}.", *undetermined],
        )

    if not applicable:
        undetermined = ["No applicable resources in the plan.", *undetermined]

    if undetermined:
        return RuleResult(
            rule_id=rule_id,
            outcome="unknown",
            resources_evaluated=evaluated,
            notes=undetermined,
        )

    return RuleResult(
        rule_id=rule_id,
        outcome="pass",
        resources_evaluated=evaluated,
        notes=[
            "Pass covers only the listed planned resources and known values.",
            *(pass_notes or []),
        ],
    )


def _undetermined_ingress(resource: JsonObject) -> list[str]:
    address = _address(resource)

    if _has_unknown(_after_unknown(resource).get("ingress")):
        return [f"{address}: ingress is known only after apply."]

    ingress_rules = _after(resource).get("ingress")

    if not isinstance(ingress_rules, list):
        return [f"{address}: ingress is not a known list."]

    notes: list[str] = []

    for ingress in ingress_rules:
        if not isinstance(ingress, dict):
            notes.append(f"{address}: ingress entry is not an object.")
            continue

        cidrs = ingress.get("cidr_blocks", [])
        ipv6_cidrs = ingress.get("ipv6_cidr_blocks", [])

        if not isinstance(cidrs, list) or not isinstance(ipv6_cidrs, list):
            notes.append(f"{address}: ingress networks are not known lists.")
            continue

        if not {str(cidr) for cidr in cidrs + ipv6_cidrs} & PUBLIC_NETWORKS:
            continue

        protocol = ingress.get("protocol")

        if not isinstance(protocol, str):
            notes.append(f"{address}: public ingress protocol is not known.")
        elif protocol.lower() in {"tcp", "6"} and not (
            isinstance(ingress.get("from_port"), int)
            and isinstance(ingress.get("to_port"), int)
        ):
            notes.append(f"{address}: public TCP ingress ports are not known.")

    return notes


def _rule_results(
    resources: list[JsonObject], findings: list[Finding]
) -> list[RuleResult]:
    groups = _of_type(resources, "aws_security_group")
    blocks = _of_type(resources, "aws_s3_bucket_public_access_block")
    buckets = _of_type(resources, "aws_s3_bucket")

    network_notes = [note for group in groups for note in _undetermined_ingress(group)]
    standalone = sorted(
        _address(resource)
        for resource in resources
        if resource.get("type") in STANDALONE_INGRESS_TYPES
    )

    if standalone:
        network_notes.append(
            f"Standalone ingress rules are not evaluated: {', '.join(standalone)}."
        )

    block_notes: list[str] = []

    for block in blocks:
        unknown = _after_unknown(block)
        after = _after(block)
        undetermined = [
            flag
            for flag in PUBLIC_ACCESS_FLAGS
            if _has_unknown(unknown.get(flag)) or not isinstance(after.get(flag), bool)
        ]

        if undetermined:
            block_notes.append(
                f"{_address(block)}: not explicitly known: {', '.join(undetermined)}."
            )

    if len(buckets) > len(blocks):
        block_notes.append(
            f"{len(buckets)} bucket(s) but {len(blocks)} public access block(s)."
        )

    deletion_notes = [
        f"{_address(bucket)}: force_destroy is not explicitly known."
        for bucket in buckets
        if _has_unknown(_after_unknown(bucket).get("force_destroy"))
        or not isinstance(_after(bucket).get("force_destroy"), bool)
    ]

    return [
        _rule_result("GRCOS-AWS-NET-001", findings, groups, network_notes),
        _rule_result(
            "GRCOS-AWS-S3-001",
            findings,
            blocks,
            block_notes,
            ["Bucket-to-block references are not resolved."],
        ),
        _rule_result(
            "GRCOS-AWS-S3-002",
            findings,
            buckets,
            [
                (
                    "Configuration-presence heuristic cannot positively verify "
                    "per-bucket encryption."
                )
            ],
        ),
        _rule_result("GRCOS-AWS-S3-003", findings, buckets, deletion_notes),
    ]


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
        rule_results=_rule_results(resources, findings),
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
