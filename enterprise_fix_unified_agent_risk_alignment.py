from pathlib import Path
from datetime import datetime

path = Path("backend/api/routes/assets.py")
text = path.read_text(encoding="utf-8")

backup = path.with_suffix(f".py.bak_unified_agent_risk_alignment_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
backup.write_text(text, encoding="utf-8")

old = '''    raw_assets = list_unified_assets(db, auth.tenant_id)
    cleaned = []'''

new = '''    unified_cve_counts = {}
    if real_agent_ids:
        cve_rows = (
            db.query(VulnerabilityFinding.agent_id, func.count(VulnerabilityFinding.id))
            .filter(
                VulnerabilityFinding.tenant_id == auth.tenant_id,
                VulnerabilityFinding.agent_id.in_(real_agent_ids),
                VulnerabilityFinding.status == "open",
            )
            .group_by(VulnerabilityFinding.agent_id)
            .all()
        )
        unified_cve_counts = {agent_id: count for agent_id, count in cve_rows}

    raw_assets = list_unified_assets(db, auth.tenant_id)
    cleaned = []'''

if old not in text:
    raise SystemExit("Could not find unified raw_assets block.")

text = text.replace(old, new)

old2 = '''            a["managed"] = True
            a["is_managed"] = True
            a["agent_installed"] = True'''

new2 = '''            authoritative_cve_count = unified_cve_counts.get(agent_lookup_id, 0)

            a["open_cve_count"] = authoritative_cve_count
            a["cve_count"] = authoritative_cve_count
            a["risk_score"] = (
                95 if authoritative_cve_count >= 500 else
                85 if authoritative_cve_count >= 100 else
                70 if authoritative_cve_count >= 25 else
                50 if authoritative_cve_count >= 5 else
                20 if authoritative_cve_count >= 1 else
                0
            )
            a["risk_level"] = (
                "CRITICAL" if authoritative_cve_count >= 500 else
                "HIGH" if authoritative_cve_count >= 25 else
                "MEDIUM" if authoritative_cve_count >= 5 else
                "LOW" if authoritative_cve_count >= 1 else
                "INFO"
            )

            a["managed"] = True
            a["is_managed"] = True
            a["agent_installed"] = True'''

if old2 not in text:
    raise SystemExit("Could not find managed agent block.")

text = text.replace(old2, new2, 1)

path.write_text(text, encoding="utf-8")
print(f"Unified agent risk aligned with /api/assets. Backup: {backup}")