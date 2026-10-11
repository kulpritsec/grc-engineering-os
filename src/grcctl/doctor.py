import hashlib
import json
import platform
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import psutil

from .models import DoctorEvidence, PlatformInfo, ResourceInfo, ToolStatus
from .version import __version__


def read_os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    path = Path("/etc/os-release")

    if not path.exists():
        return values

    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in line or line.startswith("#"):
            continue

        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')

    return values


def command_status(name: str, command: list[str]) -> ToolStatus:
    executable = shutil.which(command[0])

    if executable is None:
        return ToolStatus(name=name, available=False)

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        output = result.stdout.strip() or result.stderr.strip()
        version = output.splitlines()[0] if output else "unknown"

        return ToolStatus(
            name=name,
            available=result.returncode == 0,
            version=version,
            path=executable,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ToolStatus(name=name, available=False, path=executable)


def podman_is_rootless() -> bool:
    if shutil.which("podman") is None:
        return False

    try:
        result = subprocess.run(
            [
                "podman",
                "info",
                "--format",
                "{{.Host.Security.Rootless}}",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        return result.returncode == 0 and result.stdout.strip().lower() == "true"
    except (OSError, subprocess.TimeoutExpired):
        return False


def hash_payload(payload: dict[str, object]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(canonical).hexdigest()


def collect_doctor(output_path: Path) -> DoctorEvidence:
    os_release = read_os_release()
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    tools = [
        ToolStatus(
            name="python",
            available=True,
            version=platform.python_version(),
            path=sys.executable,
        ),
        command_status("git", ["git", "--version"]),
        command_status("podman", ["podman", "--version"]),
        command_status("uv", ["uv", "--version"]),
    ]

    rootless = podman_is_rootless()
    ready = all(tool.available for tool in tools) and rootless

    evidence = DoctorEvidence(
        collected_at=datetime.now(UTC),
        platform=PlatformInfo(
            operating_system=os_release.get(
                "PRETTY_NAME",
                platform.system(),
            ),
            version=os_release.get("VERSION_ID", "unknown"),
            architecture=platform.machine(),
            kernel=platform.release(),
        ),
        resources=ResourceInfo(
            logical_cpus=psutil.cpu_count(logical=True) or 0,
            memory_total_bytes=memory.total,
            disk_total_bytes=disk.total,
            disk_available_bytes=disk.free,
        ),
        tools=tools,
        podman_rootless=rootless,
        ready=ready,
        provenance={
            "collector": "grcctl-doctor",
            "collector_version": __version__,
        },
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


def human_bytes(value: int) -> str:
    amount = float(value)

    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:.1f} {unit}"
        amount /= 1024

    return f"{amount:.1f} TiB"
