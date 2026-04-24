from pathlib import Path
from datetime import datetime

path = Path("backend/api/routes/assets.py")
text = path.read_text(encoding="utf-8")

backup = path.with_suffix(f".py.bak_unified_display_cleanup_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
backup.write_text(text, encoding="utf-8")

# Add helper after router = APIRouter()
marker = "router = APIRouter()\n"
helper = r'''
def _best_display_ip(ips: list[str] | None, fallback: str | None = None) -> str | None:
    """
    Prefer real LAN/private IPv4 over link-local, Docker, VMware, Hyper-V and IPv6.
    This is display logic only; full IP list remains available in asset detail.
    """
    candidates = [str(x) for x in (ips or []) if x]
    if fallback:
        candidates.insert(0, str(fallback))

    def score(ip: str) -> int:
        if ip.startswith("192.168.0."):
            return 100
        if ip.startswith("192.168."):
            return 90
        if ip.startswith("10."):
            return 80
        if ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.") or ip.startswith("172.19.") or ip.startswith("172.2") or ip.startswith("172.3"):
            return 60
        if ip.startswith("169.254."):
            return 5
        if ":" in ip:
            return 1
        return 50

    if not candidates:
        return None

    return sorted(candidates, key=score, reverse=True)[0]


'''
if helper not in text:
    text = text.replace(marker, marker + helper)

# In unified route, force real agent source display cleanly
text = text.replace(
'''            a["source"] = "agent"
            a["source_types"] = ["agent"] + [
                s for s in (a.get("source_types") or []) if s not in ("agent", "network_scan")
            ]''',
'''            a["source"] = "agent"
            a["display_source"] = "agent"
            a["source_types"] = ["agent"]'''
)

# Preserve manual assets instead of converting them to network
text = text.replace(
'''        else:
            # Hard protection: network-only rows stay network/unmanaged.
            a["managed"] = False
            a["is_managed"] = False
            a["agent_installed"] = False
            a["source"] = "network"
            a["source_types"] = ["network"]
            a["asset_source"] = "network"
            a["source_of_truth"] = "network_scan"
            a["matched_agent_id"] = None
            a["status"] = "unmanaged"''',
'''        else:
            existing_source = str(a.get("source") or a.get("asset_source") or a.get("source_of_truth") or "").lower()
            is_manual = existing_source == "manual" or str(a.get("uid") or "").startswith("manual:")

            # Hard protection: network-only rows stay network/unmanaged.
            a["managed"] = False
            a["is_managed"] = False
            a["agent_installed"] = False
            a["source"] = "manual" if is_manual else "network"
            a["display_source"] = "manual" if is_manual else "network"
            a["source_types"] = ["manual"] if is_manual else ["network"]
            a["asset_source"] = "manual" if is_manual else "network"
            a["source_of_truth"] = "manual" if is_manual else "network_scan"
            a["matched_agent_id"] = None
            a["status"] = "unmanaged"'''
)

# Before cleaned.append(a), normalise display IP for all rows
text = text.replace(
'''        cleaned.append(a)''',
'''        # Enterprise display IP: prefer meaningful LAN IP over link-local/virtual adapter IPs.
        ips_for_display = a.get("ips") or []
        if isinstance(ips_for_display, str):
            ips_for_display = [ips_for_display]
        best_ip = _best_display_ip(ips_for_display, a.get("primary_ip") or a.get("ip") or a.get("ip_address"))
        if best_ip:
            a["ip"] = best_ip
            a["ip_address"] = best_ip
            a["primary_ip"] = best_ip

        cleaned.append(a)''',
    1
)

path.write_text(text, encoding="utf-8")
print(f"Unified display cleanup applied. Backup: {backup}")