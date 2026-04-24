from pathlib import Path
from datetime import datetime

path = Path("backend/api/routes/assets.py")
text = path.read_text(encoding="utf-8")

backup = path.with_suffix(f".py.bak_agent_ip_enrichment_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
backup.write_text(text, encoding="utf-8")

old = """    managed_ips = set()
    for asset in managed_agent_assets:
        if asset.primary_ip:
            managed_ips.add(str(asset.primary_ip))
        for ip in asset.ips or []:
            managed_ips.add(str(ip))

    raw_assets = list_unified_assets(db, auth.tenant_id)"""

new = """    managed_ips = set()
    managed_asset_by_agent_id = {}
    for asset in managed_agent_assets:
        managed_asset_by_agent_id[asset.agent_id] = asset
        if asset.primary_ip:
            managed_ips.add(str(asset.primary_ip))
        for ip in asset.ips or []:
            managed_ips.add(str(ip))

    raw_assets = list_unified_assets(db, auth.tenant_id)"""

text = text.replace(old, new)

old2 = """        if is_real_agent:
            a["managed"] = True"""

new2 = """        if is_real_agent:
            agent_lookup_id = (
                agent_id
                if agent_id in managed_asset_by_agent_id
                else str(a.get("uid") or a.get("matched_agent_id") or "")
            )
            asset_row = managed_asset_by_agent_id.get(agent_lookup_id)

            if asset_row:
                real_ips = asset_row.ips or []
                best_agent_ip = _best_display_ip(real_ips, asset_row.primary_ip)

                a["hostname"] = asset_row.hostname or a.get("hostname")
                a["os_family"] = asset_row.os_family or a.get("os_family")
                a["os_version"] = asset_row.os_version or a.get("os_version")
                a["fqdn"] = asset_row.fqdn or a.get("fqdn")
                a["serial_number"] = asset_row.serial_number or a.get("serial_number")
                a["device_id"] = asset_row.device_id or a.get("device_id")
                a["ips"] = ([best_agent_ip] + [str(x) for x in real_ips if str(x) != str(best_agent_ip)]) if best_agent_ip else real_ips
                a["macs"] = asset_row.macs or a.get("macs") or []
                a["ip"] = best_agent_ip
                a["ip_address"] = best_agent_ip
                a["primary_ip"] = best_agent_ip

            a["managed"] = True"""

text = text.replace(old2, new2)

path.write_text(text, encoding="utf-8")
print(f"Unified agent IP enrichment fix applied. Backup: {backup}")