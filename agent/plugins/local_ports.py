from __future__ import annotations

from typing import Any

import psutil


def collect_local_ports() -> list[dict[str, Any]]:
    findings = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == psutil.CONN_LISTEN:
            findings.append(
                {
                    "type": "listening_port",
                    "local_ip": conn.laddr.ip if conn.laddr else None,
                    "local_port": conn.laddr.port if conn.laddr else None,
                    "pid": conn.pid,
                    "protocol": "tcp/udp",
                    "status": conn.status,
                }
            )
    return findings
