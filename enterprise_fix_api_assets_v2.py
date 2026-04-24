from pathlib import Path
from datetime import datetime
import re

path = Path("backend/api/routes/assets.py")
text = path.read_text(encoding="utf-8")

backup = path.with_suffix(f".py.bak_enterprise_assets_v2_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
backup.write_text(text, encoding="utf-8")

pattern = r'''@router\.get\(""\)
def list_assets\([\s\S]*?\n\):\n    """[\s\S]*?Open CVE counts are fetched in a single aggregated query — not per-row\.\n    """[\s\S]*?    return \{\n        "total": total,[\s\S]*?    \}\n\n'''

replacement = '''@router.get("")
def list_assets(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    os_family: str | None = Query(None, description="Filter by OS family (e.g. Windows, Linux, Darwin)"),
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    """
    Enterprise Agent Asset Inventory.

    Source of truth:
    - agents table = enrolled CyberAssetIQ agents
    - canonical_assets = enrichment only
    - vulnerability_findings = CVE count only

    This endpoint must NEVER return network-only assets.
    Network assets belong in:
    - /api/network-scan/assets
    - /api/assets/unified

    This prevents false demo/business issues where Nmap-discovered IPs
    appear as installed agent assets.
    """

    query = db.query(Agent).filter(Agent.tenant_id == auth.tenant_id)

    if os_family:
        query = query.filter(Agent.os_family == os_family)

    total = query.count()
    agents = query.order_by(Agent.id.desc()).offset(offset).limit(limit).all()
    agent_ids = [a.agent_id for a in agents]

    canonical_by_agent = {}
    cve_counts = {}

    if agent_ids:
        canonical_rows = (
            db.query(CanonicalAsset)
            .filter(
                CanonicalAsset.tenant_id == auth.tenant_id,
                CanonicalAsset.agent_id.in_(agent_ids),
            )
            .all()
        )
        canonical_by_agent = {a.agent_id: a for a in canonical_rows}

        cve_rows = (
            db.query(VulnerabilityFinding.agent_id, func.count(VulnerabilityFinding.id))
            .filter(
                VulnerabilityFinding.tenant_id == auth.tenant_id,
                VulnerabilityFinding.agent_id.in_(agent_ids),
                VulnerabilityFinding.status == "open",
            )
            .group_by(VulnerabilityFinding.agent_id)
            .all()
        )
        cve_counts = {agent_id: count for agent_id, count in cve_rows}

    items = []

    for agent in agents:
        asset = canonical_by_agent.get(agent.agent_id)

        ips = asset.ips if asset and asset.ips else []
        macs = asset.macs if asset and asset.macs else []

        primary_ip = None
        if asset:
            primary_ip = asset.primary_ip or (ips[0] if ips else None)

        last_seen_epoch = (
            agent.last_seen_epoch
            or (asset.last_heartbeat_epoch if asset else None)
            or (asset.agent_last_seen_epoch if asset else None)
            or (asset.last_snapshot_epoch if asset else None)
        )

        items.append({
            "id": asset.id if asset else agent.id,
            "tenant_id": agent.tenant_id,
            "agent_id": agent.agent_id,
            "hostname": (asset.hostname if asset and asset.hostname else agent.hostname),
            "fqdn": asset.fqdn if asset else None,
            "os_family": (asset.os_family if asset and asset.os_family else agent.os_family),
            "os_version": asset.os_version if asset else None,
            "domain": asset.domain if asset else None,
            "serial_number": asset.serial_number if asset else None,
            "device_id": asset.device_id if asset else None,
            "ips": ips,
            "macs": macs,
            "ip": primary_ip,
            "ip_address": primary_ip,
            "primary_ip": primary_ip,
            "last_snapshot_epoch": asset.last_snapshot_epoch if asset else None,
            "last_seen_epoch": last_seen_epoch,
            "agent_last_seen_epoch": agent.last_seen_epoch,
            "last_heartbeat_epoch": asset.last_heartbeat_epoch if asset else agent.last_seen_epoch,
            "status": agent.status,
            "open_cve_count": cve_counts.get(agent.agent_id, 0),
            "cve_count": cve_counts.get(agent.agent_id, 0),

            # Explicit source-of-truth fields for frontend and audit confidence.
            "source": "agent",
            "asset_source": "agent",
            "source_of_truth": "agent",
            "management_state": "managed",
            "asset_state": "managed",
            "agent_installed": True,
            "is_agent_enrolled": True,
            "is_network_only": False,
        })

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": items,
    }


'''

new_text, count = re.subn(pattern, replacement, text, count=1)

if count != 1:
    raise SystemExit("Could not replace list_assets function safely. No changes made.")

path.write_text(new_text, encoding="utf-8")
print(f"Enterprise /api/assets V2 applied. Backup: {backup}")