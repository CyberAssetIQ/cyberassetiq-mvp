from __future__ import annotations

import logging
import platform
import time
from typing import Any

from core.cache import LocalQueue
from core.health import build_health_snapshot
from core.transport import BackendClient
from normalizers.asset import normalize_asset_snapshot
from normalizers.compliance import normalize_security_posture
from normalizers.vulnerability import normalize_local_findings
from plugins.local_ports import collect_local_ports
from plugins.secret_scan import get_scan_paths, scan_paths

logger = logging.getLogger(__name__)


def _get_collectors():
    system = platform.system()
    if system == "Windows":
        from collectors.windows.identity import collect_identity
        from collectors.windows.software import collect_software
        from collectors.windows.security import collect_security
        from collectors.windows.network import collect_network
    elif system == "Linux":
        from collectors.linux.identity import collect_identity
        from collectors.linux.software import collect_software
        from collectors.linux.security import collect_security
        from collectors.linux.network import collect_network
    elif system == "Darwin":
        from collectors.macos.identity import collect_identity
        from collectors.macos.software import collect_software
        from collectors.macos.security import collect_security
        from collectors.macos.network import collect_network
    else:
        raise RuntimeError(f"Unsupported platform: {system}")
    return collect_identity, collect_software, collect_security, collect_network


def flush_queue(queue: LocalQueue, backend: BackendClient) -> None:
    for row_id, payload_type, payload, _ in queue.get_batch():
        try:
            if payload_type == "heartbeat":
                backend.send_heartbeat(payload)
            else:
                backend.send_payload(payload_type, payload)
            queue.delete(row_id)
        except Exception as exc:
            logger.warning("Failed sending queued %s: %s", payload_type, exc)
            queue.increment_retry(row_id)
            break


def run_cycle(config, backend: BackendClient, queue: LocalQueue, mode: str = "full") -> dict[str, Any]:
    collect_identity, collect_software, collect_security, collect_network = _get_collectors()

    identity = collect_identity()
    network = collect_network()
    security = collect_security() if mode in {"full", "security", "run_scan_full", "run_scan_security"} else {}
    software = collect_software() if mode in {"full", "software", "run_scan_full", "run_scan_software"} else []

    agent_id = config.agent_id or "unregistered-agent"

    asset_snapshot = normalize_asset_snapshot(
        tenant_id=config.tenant_id,
        agent_id=agent_id,
        identity=identity,
        network=network,
    )

    software_inventory = {
        "tenant_id": config.tenant_id,
        "agent_id": agent_id,
        "software": software,
        "timestamp": int(time.time()),
    }

    security_posture = normalize_security_posture(
        tenant_id=config.tenant_id,
        agent_id=agent_id,
        security=security,
        identity=identity,
    )

    findings = collect_local_ports() if mode in {"full", "findings", "run_scan_full", "run_scan_findings"} else []
    if mode in {"full", "findings", "run_scan_full", "run_scan_findings"}:
        secret_paths = get_scan_paths(platform.system())
        secret_findings = scan_paths(secret_paths, use_ml=True)
        findings.extend(secret_findings)

    local_findings = normalize_local_findings(
        tenant_id=config.tenant_id,
        agent_id=agent_id,
        findings=findings,
    )

    heartbeat = build_health_snapshot(agent_id)
    heartbeat["tenant_id"] = config.tenant_id

    payloads: list[tuple[str, dict[str, Any]]] = [("asset_snapshot", asset_snapshot), ("heartbeat", heartbeat)]
    if software:
        payloads.append(("software_inventory", software_inventory))
    if security:
        payloads.append(("security_posture", security_posture))
    if findings:
        payloads.append(("local_findings", local_findings))

    for payload_type, payload in payloads:
        queue.enqueue(payload_type, payload)

    flush_queue(queue, backend)

    return {
        "mode": mode,
        "hostname": identity.get("hostname"),
        "software_count": len(software),
        "findings_count": len(findings),
        "security_collected": bool(security),
        "uploaded_payloads": [kind for kind, _ in payloads],
        "timestamp": int(time.time()),
    }
