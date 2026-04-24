from pathlib import Path
from datetime import datetime
import re

path = Path("backend/static/index.html")
text = path.read_text(encoding="utf-8")

backup = path.with_suffix(f".html.bak_unified_ui_ip_priority_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
backup.write_text(text, encoding="utf-8")

# In renderUnifiedTable, make all displayed IP logic prefer backend-selected primary IP.
text = text.replace(
    "const ip = (a.ips||[])[0] || a.ip || a.primary_ip || '—';",
    "const ip = a.primary_ip || a.ip || a.ip_address || ((a.ips||[])[0]) || '—';"
)

text = text.replace(
    "const ip = (a.ips || [])[0] || a.ip || a.primary_ip || '—';",
    "const ip = a.primary_ip || a.ip || a.ip_address || ((a.ips||[])[0]) || '—';"
)

text = text.replace(
    "const ip = a.ips?.[0] || a.ip || a.primary_ip || '—';",
    "const ip = a.primary_ip || a.ip || a.ip_address || a.ips?.[0] || '—';"
)

path.write_text(text, encoding="utf-8")
print(f"Unified UI IP priority patch applied. Backup: {backup}")