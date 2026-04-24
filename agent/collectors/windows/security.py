from __future__ import annotations

import json
import logging
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


def _run_powershell_json(command: str) -> Any:
    """
    Run a PowerShell command that pipes to ConvertTo-Json.
    Returns parsed JSON (list or dict), or None on empty/error output.
    Never raises — callers should treat None as "data unavailable".
    """
    wrapped = f"{command} | ConvertTo-Json -Depth 5"
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", wrapped],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.debug("PowerShell command timed out or not found: %s", exc)
        return None

    output = result.stdout.strip()
    if not output or output.lower() == "null":
        return None

    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        logger.debug("PowerShell JSON parse error (%s): %s", exc, output[:200])
        return None


def _to_list(value: Any) -> list:
    """Coerce a PS result to a list; return [] for None/empty-dict (cmdlet returned nothing)."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict) and not value:
        return []
    return [value]


def collect_security() -> dict[str, Any]:
    defender = _run_powershell_json(
        "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled"
    )
    firewall = _run_powershell_json(
        "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction"
    )
    bitlocker = _run_powershell_json(
        "Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionMethod"
    )
    hotfixes = _run_powershell_json("Get-HotFix | Select-Object HotFixID,InstalledOn")

    return {
        "defender": defender or {},
        "firewall_profiles": _to_list(firewall),
        "bitlocker": _to_list(bitlocker),
        "hotfixes": _to_list(hotfixes),
    }
