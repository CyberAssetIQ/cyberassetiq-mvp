from pathlib import Path
from datetime import datetime
import re

path = Path("backend/api/routes/assets.py")
text = path.read_text(encoding="utf-8")

backup = path.with_suffix(f".py.bak_unified_source_truth_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
backup.write_text(text, encoding="utf-8")

pattern = r'''@router\.get\("/unified"\)
def list_unified_assets_route\([\s\S]*?\n\):\n    """[\s\S]*?managed-only filter\.\n    """[\s\S]*?    return \{\n        "total": total,[\s\S]*?    \}\n\n'''

replacement = '''@router.get("/unified")
def list_unified_assets_route(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    managed_only: bool = Query(False, description="Return only agent-managed assets"),
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    """
    Enterprise Unified Asset View.

    Source-of-truth rules:
    - Real enrolled agents come from agents table.
    - Network-only assets must remain network/unmanaged.
    - A network:* row must not be marked managed simply because a stale flag says so.
    - If a network IP is already inside a managed agent asset, suppress the duplicate.
    """

    real_agents = (
        db.query(Agent)
        .filter(Agent.tenant_id == auth.tenant_id)
        .all()
    )
    real_agent_ids = {a.agent_id for a in real_agents}

    managed_agent_assets = (
        db.query(CanonicalAsset)
        .filter(
            CanonicalAsset.tenant_id == auth.tenant_id,
            CanonicalAsset.agent_id.in_(real_agent_ids) if real_agent_ids else False,
        )
        .all()
    )

    managed_ips = set()
    for asset in managed_agent_assets:
        if asset.primary_ip:
            managed_ips.add(str(asset.primary_ip))
        for ip in asset.ips or []:
            managed_ips.add(str(ip))

    raw_assets = list_unified_assets(db, auth.tenant_id)
    cleaned = []

    for item in raw_assets:
        a = dict(item)
        agent_id = str(a.get("agent_id") or a.get("id") or "")
        uid = str(a.get("uid") or "")
        ip = (
            a.get("ip")
            or a.get("primary_ip")
            or a.get("ip_address")
            or ((a.get("ips") or [None])[0])
        )
        ip = str(ip) if ip else None

        is_real_agent = (
            agent_id in real_agent_ids
            or uid in real_agent_ids
            or str(a.get("matched_agent_id") or "") in real_agent_ids
        )

        is_network_id = (
            agent_id.startswith("network:")
            or agent_id.startswith("net-")
            or uid.startswith("network:")
            or uid.startswith("net-")
            or str(a.get("source") or "").lower() == "network"
        )

        # Suppress duplicate network row when its IP is already covered by a real agent asset.
        if (not is_real_agent) and is_network_id and ip in managed_ips:
            continue

        if is_real_agent:
            a["managed"] = True
            a["is_managed"] = True
            a["agent_installed"] = True
            a["source"] = "agent"
            a["source_types"] = ["agent"] + [
                s for s in (a.get("source_types") or []) if s not in ("agent", "network_scan")
            ]
            a["status"] = a.get("status") or "managed"
            a["asset_source"] = "agent"
            a["source_of_truth"] = "agent"
        else:
            # Hard protection: network-only rows stay network/unmanaged.
            a["managed"] = False
            a["is_managed"] = False
            a["agent_installed"] = False
            a["source"] = "network"
            a["source_types"] = ["network"]
            a["asset_source"] = "network"
            a["source_of_truth"] = "network_scan"
            a["matched_agent_id"] = None
            a["status"] = "unmanaged"

        cleaned.append(a)

    if managed_only:
        cleaned = [a for a in cleaned if a.get("managed") is True]

    total = len(cleaned)
    page = cleaned[offset: offset + limit]

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": page,
        "summary": {
            "total_assets": total,
            "managed_assets": len([a for a in cleaned if a.get("managed") is True]),
            "unmanaged_assets": len([a for a in cleaned if a.get("managed") is not True]),
        },
    }


'''

new_text, count = re.subn(pattern, replacement, text, count=1)

if count != 1:
    raise SystemExit("Could not replace /api/assets/unified safely. No changes made.")

path.write_text(new_text, encoding="utf-8")
print(f"Enterprise unified source-of-truth fix applied. Backup: {backup}")