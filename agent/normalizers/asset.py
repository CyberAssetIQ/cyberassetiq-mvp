from __future__ import annotations

import time
from typing import Any


def normalize_asset_snapshot(
    tenant_id: str,
    agent_id: str,
    identity: dict[str, Any],
    network: dict[str, Any],
) -> dict[str, Any]:
    return {
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "timestamp": int(time.time()),
        "asset": {
            "hostname": identity.get("hostname"),
            "fqdn": identity.get("fqdn"),
            "os_family": identity.get("os_family"),
            "os_version": identity.get("os_version"),
            "domain": identity.get("domain"),
            "serial_number": identity.get("serial_number"),
            "device_id": identity.get("device_id"),
            "ips": network.get("ips", []),
            "macs": network.get("macs", []),
        },
    }
