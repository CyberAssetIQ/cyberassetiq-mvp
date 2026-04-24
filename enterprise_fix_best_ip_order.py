from pathlib import Path
from datetime import datetime

path = Path("backend/api/routes/assets.py")
text = path.read_text(encoding="utf-8")

backup = path.with_suffix(f".py.bak_best_ip_order_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
backup.write_text(text, encoding="utf-8")

old = '''        if best_ip:
            a["ip"] = best_ip
            a["ip_address"] = best_ip
            a["primary_ip"] = best_ip

        cleaned.append(a)'''

new = '''        if best_ip:
            a["ip"] = best_ip
            a["ip_address"] = best_ip
            a["primary_ip"] = best_ip

            # Ensure UI tables that use ips[0] also display the best LAN IP.
            existing_ips = a.get("ips") or []
            if isinstance(existing_ips, str):
                existing_ips = [existing_ips]
            existing_ips = [str(x) for x in existing_ips if x]
            reordered_ips = [best_ip] + [x for x in existing_ips if x != best_ip]
            a["ips"] = reordered_ips

        cleaned.append(a)'''

if old not in text:
    raise SystemExit("Target best_ip block not found. No changes made.")

path.write_text(text.replace(old, new), encoding="utf-8")
print(f"Best IP ordering fix applied. Backup: {backup}")