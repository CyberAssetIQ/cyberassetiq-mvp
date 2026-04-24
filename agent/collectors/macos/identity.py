from __future__ import annotations

import platform
import socket
import subprocess


def collect_identity() -> dict:
    serial = ""
    try:
        result = subprocess.run(
            ["system_profiler", "SPHardwareDataType"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        for line in result.stdout.splitlines():
            if "Serial Number" in line:
                serial = line.split(":")[-1].strip()
                break
    except Exception:
        pass

    return {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "os_family": "macOS",
        "os_version": platform.platform(),
        "domain": None,
        "serial_number": serial,
        "device_id": None,
    }
