from __future__ import annotations

import logging
import platform
import socket
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


def _run_powershell(command: str) -> str:
    """Run a PowerShell command and return stdout. Returns empty string on any error."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True,
            text=True,
            timeout=20,
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("PowerShell identity command failed: %s", exc)
        return ""


def collect_identity() -> dict[str, Any]:
    hostname = socket.gethostname()
    fqdn = socket.getfqdn()

    serial_number = _run_powershell(
        "(Get-CimInstance Win32_BIOS | Select-Object -ExpandProperty SerialNumber)"
    )
    device_id = _run_powershell(
        "(Get-CimInstance Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID)"
    )
    domain = _run_powershell(
        "(Get-CimInstance Win32_ComputerSystem | Select-Object -ExpandProperty Domain)"
    )

    # Collect local Administrators group members for CE A2 (user access control)
    local_admins_raw = _run_powershell(
        "(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty Name) -join ','"
    )
    local_admins = [
        name.strip() for name in local_admins_raw.split(",") if name.strip()
    ] if local_admins_raw else []

    return {
        "hostname": hostname,
        "fqdn": fqdn,
        "os_family": "Windows",
        "os_version": platform.platform(),
        "domain": domain or None,
        "serial_number": serial_number or None,
        "device_id": device_id or None,
        "local_admins": local_admins,
    }
