from __future__ import annotations

import json
import logging
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


def _run_powershell_json(command: str) -> list[dict[str, Any]]:
    """
    Run a PowerShell command piped through ConvertTo-Json.
    Returns a list of dicts; returns [] on any error, empty output, or null result.
    """
    wrapped = f"{command} | ConvertTo-Json -Depth 4"
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", wrapped],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("PowerShell software command failed: %s", exc)
        return []

    output = result.stdout.strip()
    if not output or output.lower() == "null":
        return []

    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        logger.debug("PowerShell software JSON parse error: %s", exc)
        return []

    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    return []


def collect_software() -> list[dict[str, Any]]:
    cmd = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
        r"""
        $paths = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $results = foreach ($path in $paths) {
            try {
                Get-ItemProperty $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
            } catch {}
        }
        $results | ConvertTo-Json -Depth 2 -Compress
        """
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout.strip()
        if not output or output.lower() == "null":
            logger.warning("Software collector: empty output. stderr: %s", result.stderr[:200])
            return []
        data = json.loads(output)
        if isinstance(data, dict):
            data = [data]
        normalized = []
        for item in data:
            name = item.get("DisplayName")
            if name:
                normalized.append({
                    "name": name,
                    "version": item.get("DisplayVersion"),
                    "publisher": item.get("Publisher"),
                    "install_date": item.get("InstallDate"),
                })
        return normalized
    except Exception as exc:
        logger.warning("Software collector failed: %s", exc)
        return []