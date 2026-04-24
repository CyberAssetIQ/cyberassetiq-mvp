from __future__ import annotations

import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("DATABASE_URL", f"sqlite:///{ROOT / 'cyberassetiq.db'}")

from db.session import SessionLocal  # noqa: E402
from models.agent import Agent  # noqa: E402
from models.asset import CanonicalAsset  # noqa: E402
from models.darkweb import DarkWebFinding, DarkWebSourceItem, DarkWebWatchlist  # noqa: E402
from models.network import NetworkDiscoveredAsset, NetworkScanJob  # noqa: E402
from models.telemetry import CanonicalSoftware, VulnerabilityFinding  # noqa: E402


def seed_demo(tenant_id: str = "tenant-001") -> None:
    now = int(time.time())
    db = SessionLocal()
    try:
        for model in [VulnerabilityFinding, CanonicalSoftware, DarkWebFinding, DarkWebSourceItem, DarkWebWatchlist, NetworkDiscoveredAsset, NetworkScanJob, CanonicalAsset, Agent]:
            db.query(model).filter(getattr(model, "tenant_id") == tenant_id).delete(synchronize_session=False)
        db.commit()

        db.add_all([
            Agent(tenant_id=tenant_id, agent_id=f"agent-{tenant_id}-hr001", hostname="HR-Laptop-01", os_family="Windows", status="active", last_seen_epoch=now - 300),
            Agent(tenant_id=tenant_id, agent_id=f"agent-{tenant_id}-fin001", hostname="Finance-Server-01", os_family="Windows", status="active", last_seen_epoch=now - 600),
        ])
        db.commit()

        hr = CanonicalAsset(
            tenant_id=tenant_id,
            agent_id=f"agent-{tenant_id}-hr001",
            hostname="HR-Laptop-01",
            fqdn="HR-Laptop-01.acme.com",
            os_family="Windows",
            os_version="11 Pro",
            domain="acme.com",
            serial_number="HR001",
            device_id="dev-hr001",
            ips=["192.168.1.10"],
            macs=["AA-BB-CC-DD-EE-10"],
            last_snapshot_epoch=now - 600,
            security_posture_json={
                "defender": {"AMServiceEnabled": True, "AntivirusEnabled": True, "RealTimeProtectionEnabled": True},
                "firewall_profiles": [{"Name": "Domain", "Enabled": False}, {"Name": "Private", "Enabled": True}],
                "bitlocker": [{"MountPoint": "C:", "ProtectionStatus": "Off"}],
            },
        )
        fin = CanonicalAsset(
            tenant_id=tenant_id,
            agent_id=f"agent-{tenant_id}-fin001",
            hostname="Finance-Server-01",
            fqdn="Finance-Server-01.acme.com",
            os_family="Windows",
            os_version="Server 2022",
            domain="acme.com",
            serial_number="FIN001",
            device_id="dev-fin001",
            ips=["192.168.1.20"],
            macs=["AA-BB-CC-DD-EE-20"],
            last_snapshot_epoch=now - 3600,
            security_posture_json={
                "defender": {"AMServiceEnabled": True, "AntivirusEnabled": False, "RealTimeProtectionEnabled": False},
                "firewall_profiles": [{"Name": "Domain", "Enabled": True}],
                "bitlocker": [{"MountPoint": "C:", "ProtectionStatus": "On"}],
            },
        )
        db.add_all([hr, fin])
        db.commit()

        db.add_all([
            CanonicalSoftware(tenant_id=tenant_id, agent_id=hr.agent_id, asset_id=hr.id, name="Google Chrome", version="122.0", publisher="Google"),
            CanonicalSoftware(tenant_id=tenant_id, agent_id=hr.agent_id, asset_id=hr.id, name="AnyDesk", version="8.0", publisher="AnyDesk"),
            CanonicalSoftware(tenant_id=tenant_id, agent_id=fin.agent_id, asset_id=fin.id, name="OpenSSL", version="1.1.1", publisher="OpenSSL"),
            CanonicalSoftware(tenant_id=tenant_id, agent_id=fin.agent_id, asset_id=fin.id, name="Apache HTTP Server", version="2.4.57", publisher="Apache"),
        ])
        db.add_all([
            VulnerabilityFinding(tenant_id=tenant_id, agent_id=fin.agent_id, software_name="OpenSSL", software_version="1.1.1", cve_id="CVE-2023-5678", severity="CRITICAL", cvss_score=9.8, description="Demo critical issue", published="2024-03-01", status="open"),
            VulnerabilityFinding(tenant_id=tenant_id, agent_id=fin.agent_id, software_name="Apache HTTP Server", software_version="2.4.57", cve_id="CVE-2024-1234", severity="HIGH", cvss_score=8.4, description="Demo high issue", published="2024-06-10", status="open"),
            VulnerabilityFinding(tenant_id=tenant_id, agent_id=hr.agent_id, software_name="AnyDesk", software_version="8.0", cve_id="CVE-2024-9999", severity="MEDIUM", cvss_score=6.1, description="Demo medium issue", published="2024-11-15", status="open"),
        ])
        db.commit()

        job = NetworkScanJob(tenant_id=tenant_id, requested_by="founder@cyberassetiq.com", target="192.168.1.0/24", status="completed", engine="demo", summary_json={"discovered_count": 3})
        db.add(job)
        db.commit()
        db.add_all([
            NetworkDiscoveredAsset(tenant_id=tenant_id, scan_job_id=job.id, ip_address="192.168.1.10", hostname="HR-Laptop-01", mac_address="AA:BB:CC:DD:EE:10", vendor="Dell", os_guess="Windows 11", device_type="windows_host", open_ports=[{"port": 3389, "service": "ms-wbt-server", "state": "open"}], risk_hint="medium", raw_metadata_json={"engine": "demo"}),
            NetworkDiscoveredAsset(tenant_id=tenant_id, scan_job_id=job.id, ip_address="192.168.1.20", hostname="Finance-Server-01", mac_address="AA:BB:CC:DD:EE:20", vendor="HPE", os_guess="Windows Server", device_type="windows_host", open_ports=[{"port": 443, "service": "https", "state": "open"}, {"port": 445, "service": "microsoft-ds", "state": "open"}], risk_hint="high", raw_metadata_json={"engine": "demo"}),
            NetworkDiscoveredAsset(tenant_id=tenant_id, scan_job_id=job.id, ip_address="192.168.1.50", hostname="Lobby-Printer", mac_address="AA:BB:CC:DD:EE:50", vendor="HP", os_guess="Embedded", device_type="printer", open_ports=[{"port": 9100, "service": "jetdirect", "state": "open"}], risk_hint="medium", raw_metadata_json={"engine": "demo"}),
        ])
        watch = DarkWebWatchlist(tenant_id=tenant_id, watch_type="email", watch_value="admin@acme.com", label="Admin identity", severity="high", is_active=True)
        source = DarkWebSourceItem(tenant_id=tenant_id, source_ref="pastebin-demo-001", source_name="Demo Paste", source_type="manual_ingest", title="Admin creds dump", content_text="admin@acme.com:Summer2024! leaked from old VPN export", raw_metadata_json={})
        db.add_all([watch, source])
        db.commit()
        db.add(DarkWebFinding(tenant_id=tenant_id, watchlist_id=watch.id, source_item_id=source.id, finding_type="email", matched_value="admin@acme.com", context_snippet="admin@acme.com:Summer2024! leaked from old VPN export", severity="high", status="open", raw_metadata_json={"source_name": "Demo Paste", "title": "Admin creds dump", "linked_domains": ["acme.com"], "link_strategies": ["email-domain"]}))
        db.commit()
        print(f"Seeded demo data for {tenant_id}")
    finally:
        db.close()


if __name__ == "__main__":
    seed_demo(os.getenv("CYBERASSETIQ_DEFAULT_TENANT", "tenant-001"))
