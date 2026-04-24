from __future__ import annotations

import platform
import socket
from pathlib import Path


def collect_identity() -> dict:
    machine_id = None
    path = Path("/etc/machine-id")
    if path.exists():
        machine_id = path.read_text().strip()

    return {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "os_family": "Linux",
        "os_version": platform.platform(),
        "domain": None,
        "serial_number": None,
        "device_id": machine_id,
    }
