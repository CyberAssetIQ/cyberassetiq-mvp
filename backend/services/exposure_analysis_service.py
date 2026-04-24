from __future__ import annotations
from sqlalchemy.orm import Session
from models.network import NetworkDiscoveredAsset
from models.network_extensions import ExtensionServiceJob, ExposureFinding

RISKY_PORTS = {
    21: ("FTP exposed", "MEDIUM"),
    23: ("Telnet exposed", "HIGH"),
    80: ("HTTP service exposed", "LOW"),
    443: ("HTTPS service exposed", "LOW"),
    445: ("SMB exposed", "HIGH"),
    3389: ("RDP exposed", "HIGH"),
    5900: ("VNC exposed", "HIGH"),
    5985: ("WinRM exposed", "MEDIUM"),
    5986: ("WinRM TLS exposed", "MEDIUM"),
    9200: ("Elasticsearch exposed", "CRITICAL"),
    27017: ("MongoDB exposed", "CRITICAL"),
}

def _set_job(job, *, status=None, stage=None, pct=None, current_target=None, findings=None, summary=None):
    if status is not None: job.status = status
    if stage is not None: job.current_stage = stage
    if pct is not None: job.progress_percent = pct
    if current_target is not None: job.current_target = current_target
    if findings is not None: job.findings_count = findings
    if summary is not None: job.summary_json = summary

def run_exposure_analysis_job(db: Session, *, tenant_id: str, target: str | None, requested_by: str | None, job_id: int) -> dict:
    job = db.query(ExtensionServiceJob).filter(ExtensionServiceJob.id == job_id).first()
    if not job: return {"status": "missing_job"}
    _set_job(job, status="running", stage="loading_assets", pct=10, summary={"service": "Exposure Check"})
    db.commit()
    assets = db.query(NetworkDiscoveredAsset).filter(NetworkDiscoveredAsset.tenant_id == tenant_id, NetworkDiscoveredAsset.is_active == True).all()
    findings = 0
    total = len(assets)
    for idx, asset in enumerate(assets, start=1):
        pct = 15 if total == 0 else min(95, 15 + int((idx / total) * 75))
        _set_job(job, stage="analysing_assets", pct=pct, current_target=asset.ip_address)
        db.commit()
        raw_ports = asset.open_ports or []
        ports: list[int] = []
        for p in raw_ports:
            port = p.get("port") if isinstance(p, dict) else p
            if isinstance(port, int): ports.append(port)
        for port in ports:
            if port not in RISKY_PORTS: continue
            title, severity = RISKY_PORTS[port]
            db.add(ExposureFinding(tenant_id=tenant_id, job_id=job_id, asset_id=asset.id, ip_address=asset.ip_address,
                finding_type="risky_open_port", severity=severity, title=title,
                description=f"{asset.ip_address} exposes port {port}.",
                remediation="Validate business need, restrict the port, or place behind access controls.",
                evidence_json={"port": port, "hostname": asset.hostname, "device_type": asset.device_type}))
            findings += 1
        if (asset.critical_cve_count or 0) > 0 and not asset.agent_installed:
            db.add(ExposureFinding(tenant_id=tenant_id, job_id=job_id, asset_id=asset.id, ip_address=asset.ip_address,
                finding_type="unmanaged_critical_asset", severity="HIGH", title="Unmanaged asset with critical CVEs",
                description=f"{asset.ip_address} is unmanaged and has critical vulnerabilities.",
                remediation="Validate ownership, install agent if appropriate, and prioritise remediation.",
                evidence_json={"critical_cve_count": asset.critical_cve_count}))
            findings += 1
    db.commit()
    _set_job(job, status="completed", stage="completed", pct=100, findings=findings,
        summary={"service": "Exposure Check", "finding_count": findings, "asset_count": total, "progress": {"phase": "Completed", "pct": 100}})
    db.commit()
    return {"status": "completed", "finding_count": findings}
