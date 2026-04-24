from pathlib import Path
from datetime import datetime

path = Path("backend/api/routes/assets.py")
text = path.read_text(encoding="utf-8")

backup = path.with_suffix(f".py.bak_agent_risk_score_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
backup.write_text(text, encoding="utf-8")

old = '''            "open_cve_count": cve_counts.get(agent.agent_id, 0),
            "cve_count": cve_counts.get(agent.agent_id, 0),'''

new = '''            "open_cve_count": cve_counts.get(agent.agent_id, 0),
            "cve_count": cve_counts.get(agent.agent_id, 0),
            "risk_score": (
                95 if cve_counts.get(agent.agent_id, 0) >= 500 else
                85 if cve_counts.get(agent.agent_id, 0) >= 100 else
                70 if cve_counts.get(agent.agent_id, 0) >= 25 else
                50 if cve_counts.get(agent.agent_id, 0) >= 5 else
                20 if cve_counts.get(agent.agent_id, 0) >= 1 else
                0
            ),
            "risk_level": (
                "CRITICAL" if cve_counts.get(agent.agent_id, 0) >= 500 else
                "HIGH" if cve_counts.get(agent.agent_id, 0) >= 25 else
                "MEDIUM" if cve_counts.get(agent.agent_id, 0) >= 5 else
                "LOW" if cve_counts.get(agent.agent_id, 0) >= 1 else
                "INFO"
            ),'''

if old not in text:
    raise SystemExit("Target CVE block not found. No changes made.")

path.write_text(text.replace(old, new), encoding="utf-8")
print(f"Agent asset risk score added. Backup: {backup}")